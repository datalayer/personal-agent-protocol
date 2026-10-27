# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Live-session actions: one implementation each, for Studio, a REPL, and `pap commands run`.

`PapCliPlugin.provide_slash_commands` registers every action of `ACTIONS` in
whichever registry the host hands it — Reactor's command registry (a palette,
Studio, `pap commands run <id>`) or a REPL's slash-command registry — and all of
them call `invoke_action`, which runs the same coroutine the `pap` command of the
same name runs. Each answers the versioned JSON of that command's `--json`.

An action runs in the personal agent the `pap` commands run (`cli_host`), for the
configured tenant, and never asks for input: no action enters a credential.

Read-only actions run as asked. An action that changes or ends what the user
holds (`needs_approval`) first asks the host's approval surface
(`pap.approvalSurface`); without one, or when it says anything but yes, nothing is
done (`approval_required`, `not_approved`). It stays available, as a CLI-only
command, from `pap`. Configuration, raw credential entry (signing keys, sign-in
callbacks, passwords and codes), starting Sessions and signing in, sending
messages, calling APIs, and approving operations are not live-session actions.
"""

from __future__ import annotations

import contextlib
import json
import re
import shlex
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, cast

import httpx
from reactor import PluginPlatform  # type: ignore[import-untyped]

from .accounts import AccountTokenClient, AccountTokenContext
from .apis import conversation_endpoint
from .cli_host import CliRuntime, InputSource, NotConfiguredError, SessionRecord
from .conversations import ConversationClient, StreamReconnected, TextDelta
from .discovery import DiscoveryClient
from .errors import PersonalAgentProtocolError
from .identity import AgentIdentityClient
from .models import ConversationEvent, DiscoveredCompany, Operation
from .operations import OperationsClient, operations_endpoint
from .reactor import APPROVAL_SURFACES, ApprovalRequest, ApprovalSurface, optional_contribution
from .requirements import load_ledger
from .sessions import SessionToken, Who
from .transport import DpopHttpClient

if TYPE_CHECKING:
    from .cli_host import HostFactory

#: Where the actions are listed in a palette or `/help`.
CATEGORY = "Personal Agent Protocol"


class ActionUsageError(PersonalAgentProtocolError):
    """An unknown action, or arguments it does not take (`pap commands run` exit code 2)."""


class ApprovalRequiredError(PersonalAgentProtocolError):
    """A destructive action without the user's approval: nothing was done (exit code 6)."""


# The steps the actions and the `pap` commands share -------------------------------------


async def discover_company(
    domain: str,
    *,
    reactor: PluginPlatform | None = None,
    http_client: httpx.AsyncClient | None = None,
) -> dict[str, object]:
    """Return a stable, non-secret discovery summary (`pap company discover --json`)."""

    async with DiscoveryClient(reactor=reactor, http_client=http_client) as client:
        company = await client.discover(domain)
    document = company.document
    metadata = company.oauth_metadata
    return {
        "schema_version": 1,
        "verified": metadata is not None,
        "domain": document.organization.domain,
        "organization": document.organization.name,
        "protocol_version": document.protocol_version,
        "issuer": metadata.issuer if metadata else None,
        # Direct and Device from the issuer's grants, Mediated from poppy.json (§4.4).
        "sign_in": [
            name
            for name, offered in (
                ("direct", metadata is not None and metadata.offers_direct),
                ("device", metadata is not None and metadata.offers_device),
                ("mediated", document.auth is not None and document.auth.mediated is not None),
            )
            if offered
        ],
        "apis": [item.type for item in document.apis],
        "conversation_protocols": (
            [item.type for item in document.agent.protocols] if document.agent else []
        ),
        "web": document.web is not None,
        "extensions": {name: item.version for name, item in sorted(document.extensions.items())},
    }


async def company_of(runtime: CliRuntime, domain: str) -> DiscoveredCompany:
    return await DiscoveryClient(reactor=runtime.reactor).discover(domain)


def who_of(record: SessionRecord) -> Who:
    return {
        "tenant_id": record.tenant_id,
        "issuer": record.issuer,
    }


async def session_token(runtime: CliRuntime, record: SessionRecord) -> SessionToken:
    secret = await runtime.secrets.get(record.token_reference)
    if secret is None:
        raise NotConfiguredError("no_session_token", "The Session's token is gone: renew it")
    return SessionToken(
        access_token=secret,
        token_type=cast(Any, record.token_type),
        expires_in=3600,
        scope=record.scope,
        session_key=record.session_key,
        signed_in=record.signed_in,
    )


def session_view(record: SessionRecord) -> dict[str, Any]:
    return {"session": record.public()}


def operation_view(operation: Operation) -> dict[str, Any]:
    return {"operation": operation.model_dump(mode="json")}


def account_context(record: SessionRecord) -> AccountTokenContext:
    return AccountTokenContext(
        token_endpoint=record.token_endpoint,
        issuer=record.issuer,
        client_id=record.client_id,
        tenant_id=record.tenant_id,
        pairwise_user_id=record.pairwise_user_id,
        revocation_endpoint=record.revocation_endpoint,
    )


async def conversation_client(
    runtime: CliRuntime, record: SessionRecord
) -> tuple[ConversationClient, str]:
    company = await company_of(runtime, record.domain)
    endpoint = conversation_endpoint(company.document)
    if endpoint is None:
        raise NotConfiguredError("no_conversations", "The company lists no poppy agent")
    client = ConversationClient(
        transport=DpopHttpClient(reactor=runtime.reactor, http_client=runtime.http)
    )
    return client, endpoint


async def operations_client(
    runtime: CliRuntime, record: SessionRecord
) -> tuple[OperationsClient, str, str]:
    company = await company_of(runtime, record.domain)
    identity = AgentIdentityClient(reactor=runtime.reactor, http_client=runtime.http)
    metadata = await identity.fetch_metadata(record.client_id)
    endpoint = operations_endpoint(company.document, metadata)
    if endpoint is None:
        raise NotConfiguredError("no_operations", "Operations v1 is not negotiated")
    client = OperationsClient(
        transport=DpopHttpClient(reactor=runtime.reactor, http_client=runtime.http)
    )
    return client, endpoint, company.document.organization.name


# The implementations: each `pap` command of the same name runs these ----------------------


async def show_sessions(runtime: CliRuntime, session: str | None = None) -> dict[str, Any]:
    """`pap sessions show`: the tenant's Sessions, opaque references only."""

    if session is not None:
        return session_view(runtime.session(session))
    return {"sessions": [record.public() for record in runtime.sessions()]}


async def end_session(runtime: CliRuntime, session: str) -> dict[str, Any]:
    """`pap sessions end`: forget a Session; its Account Token is kept (§4.9)."""

    record = runtime.session(session)
    await runtime.secrets.delete(record.token_reference)
    await runtime.secrets.delete(f"mcp:{record.session_key}")
    del runtime.state.sessions[session]
    runtime.state.save()
    return {"ended": session, "account_reference": record.account_reference}


async def disconnect(runtime: CliRuntime, session: str) -> dict[str, Any]:
    """`pap auth disconnect`: revoke the Account Token; Sessions continue signed out."""

    record = runtime.session(session)
    if record.account_reference is None:
        raise NotConfiguredError("not_signed_in", "This Session holds no Account Token")
    await AccountTokenClient(reactor=runtime.reactor, http_client=runtime.http).revoke(
        record.account_reference, context=account_context(record)
    )
    for other in runtime.sessions():
        if other.account_reference == record.account_reference:
            other.account_reference = None
            other.signed_in = False
            other.scope = ""
    runtime.state.save()
    return session_view(record)


async def read_events(
    runtime: CliRuntime, session: str, conversation_id: str, cursor: str | None = None
) -> dict[str, Any]:
    """`pap conversations events`: one page of events (§7.5)."""

    record = runtime.session(session)
    client, endpoint = await conversation_client(runtime, record)
    page = await client.read_events(
        endpoint,
        conversation_id,
        token=await session_token(runtime, record),
        cursor=cursor,
        **who_of(record),
    )
    return page.model_dump(mode="json")


async def follow_events(
    runtime: CliRuntime,
    session: str,
    conversation_id: str,
    last_event_id: str | None = None,
    max_events: int = 50,
    on_text: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """`pap conversations follow`: stream events (SSE) until closed or `max_events` (§7.6).

    Text pieces go to `on_text` for display, if given, and are never acted on.
    """

    record = runtime.session(session)
    client, endpoint = await conversation_client(runtime, record)
    events: list[dict[str, Any]] = []
    stream = client.stream(
        endpoint,
        conversation_id,
        token=await session_token(runtime, record),
        last_event_id=last_event_id,
        max_reconnects=0,
        **who_of(record),
    )
    with contextlib.suppress(PersonalAgentProtocolError):
        async with contextlib.aclosing(stream) as items:
            async for item in items:
                if isinstance(item, TextDelta):
                    if on_text is not None:
                        on_text(item.text)
                elif isinstance(item, ConversationEvent):
                    events.append(item.model_dump(mode="json", exclude_none=True))
                    if len(events) >= max_events:
                        break
                elif isinstance(item, StreamReconnected):
                    break
    return {"conversation_id": conversation_id, "events": events}


async def show_operation(runtime: CliRuntime, session: str, operation_id: str) -> dict[str, Any]:
    """`pap operations show`: read an operation by its ID (Operations §6)."""

    record = runtime.session(session)
    client, endpoint, _ = await operations_client(runtime, record)
    operation = await client.read(
        endpoint, operation_id, token=await session_token(runtime, record), **who_of(record)
    )
    return operation_view(operation)


async def cancel_operation(runtime: CliRuntime, session: str, operation_id: str) -> dict[str, Any]:
    """`pap operations cancel`: decline a proposal, or ask to stop one (Operations §7)."""

    record = runtime.session(session)
    client, endpoint, _ = await operations_client(runtime, record)
    operation = await client.cancel(
        endpoint, operation_id, token=await session_token(runtime, record), **who_of(record)
    )
    runtime.state.approvals.pop(operation_id, None)
    runtime.state.save()
    return operation_view(operation)


def list_requirements(
    role: str | None = None,
    level: str | None = None,
    status: str | None = None,
    source: str | None = None,
) -> dict[str, Any]:
    """`pap requirements list`: ledger entries, filtered."""

    ledger = load_ledger()
    items = ledger.select(role=role, level=level, status=status, source=source)
    return {"profile": ledger.profile, "requirements": [item.as_dict() for item in items]}


def show_requirement(requirement_id: str) -> dict[str, Any]:
    """`pap requirements show`: one ledger entry (`KeyError` when there is none)."""

    return {"requirement": load_ledger().get(requirement_id).as_dict()}


# The actions ------------------------------------------------------------------------------


@dataclass(frozen=True)
class ActionArgument:
    """One argument: given by name (`name=value`) or by position, always as text."""

    name: str
    description: str
    required: bool = True


Run = Callable[[CliRuntime, Mapping[str, str]], Awaitable[dict[str, Any]]]


@dataclass(frozen=True)
class SessionAction:
    """A live-session action: what a palette and `/help` show, and what runs."""

    id: str
    name: str
    description: str
    run: Run
    arguments: tuple[ActionArgument, ...] = ()
    #: Changes or ends what the user holds: the host's approval surface is asked first.
    needs_approval: bool = False
    #: The plain words an approval surface shows, formatted with the arguments.
    summary: str = ""
    emoji: str = ""


def _positive(value: str, name: str) -> int:
    if not value.isdigit() or int(value) < 1:
        raise ActionUsageError("invalid_arguments", f"{name} is a positive whole number")
    return int(value)


async def _discover(runtime: CliRuntime, values: Mapping[str, str]) -> dict[str, Any]:
    summary = await discover_company(values["domain"], reactor=runtime.reactor)
    return {key: value for key, value in summary.items() if key != "schema_version"}


async def _show_requirement(_: CliRuntime, values: Mapping[str, str]) -> dict[str, Any]:
    try:
        return show_requirement(values["requirement_id"])
    except KeyError as error:
        raise ActionUsageError(
            "unknown_requirement", f"No requirement {values['requirement_id']}"
        ) from error


async def _list_requirements(_: CliRuntime, values: Mapping[str, str]) -> dict[str, Any]:
    return list_requirements(**values)


async def _follow(runtime: CliRuntime, values: Mapping[str, str]) -> dict[str, Any]:
    limit = _positive(values.get("max_events", "50"), "max_events")
    return await follow_events(
        runtime,
        values["session"],
        values["conversation_id"],
        last_event_id=values.get("last_event_id"),
        max_events=min(limit, 500),
    )


SESSION = ActionArgument("session", "The Session (`pap sessions show` lists them).")
CONVERSATION = ActionArgument("conversation_id", "The conversation.")
OPERATION = ActionArgument("operation_id", "The operation.")

#: Every live-session action, by ID.
ACTIONS: dict[str, SessionAction] = {
    action.id: action
    for action in (
        SessionAction(
            "pap.company.discover",
            "Discover PAP company",
            "Discover and verify one PAP company domain.",
            _discover,
            (ActionArgument("domain", "The company's domain."),),
            emoji="🔎",
        ),
        SessionAction(
            "pap.sessions.show",
            "Show PAP Sessions",
            "The Sessions this agent holds: opaque references, never tokens.",
            lambda runtime, values: show_sessions(runtime, values.get("session")),
            (ActionArgument("session", "Only this Session.", required=False),),
            emoji="🪪",
        ),
        SessionAction(
            "pap.conversations.events",
            "Read conversation events",
            "Read one page of a conversation's events.",
            lambda runtime, values: read_events(
                runtime, values["session"], values["conversation_id"], values.get("cursor")
            ),
            (
                SESSION,
                CONVERSATION,
                ActionArgument("cursor", "Read after this event.", required=False),
            ),
            emoji="💬",
        ),
        SessionAction(
            "pap.conversations.follow",
            "Follow a conversation",
            "Stream a conversation's events until it closes or max_events (at most 500).",
            _follow,
            (
                SESSION,
                CONVERSATION,
                ActionArgument("last_event_id", "Resume after this event.", required=False),
                ActionArgument("max_events", "Stop after this many events (50).", required=False),
            ),
            emoji="📡",
        ),
        SessionAction(
            "pap.operations.show",
            "Show an operation",
            "Read an operation by its ID: its state, revision, and summary.",
            lambda runtime, values: show_operation(
                runtime, values["session"], values["operation_id"]
            ),
            (SESSION, OPERATION),
            emoji="🧾",
        ),
        SessionAction(
            "pap.requirements.list",
            "List PAP requirements",
            "The normative requirement ledger, filtered.",
            _list_requirements,
            tuple(
                ActionArgument(name, description, required=False)
                for name, description in (
                    ("role", "personal-agent or company."),
                    ("level", "MUST, MUST NOT, SHOULD, …"),
                    ("status", "implemented, open, …"),
                    ("source", "spec, operations, guide."),
                )
            ),
            emoji="📜",
        ),
        SessionAction(
            "pap.requirements.show",
            "Show a PAP requirement",
            "One ledger entry: its text, implementation, tests, and cases.",
            _show_requirement,
            (ActionArgument("requirement_id", "The requirement, e.g. OPS-6-02."),),
            emoji="📜",
        ),
        SessionAction(
            "pap.operations.cancel",
            "Cancel an operation",
            "Decline a proposal, or ask the company to stop one in progress.",
            lambda runtime, values: cancel_operation(
                runtime, values["session"], values["operation_id"]
            ),
            (SESSION, OPERATION),
            needs_approval=True,
            summary="Cancel operation {operation_id} at the company.",
            emoji="✋",
        ),
        SessionAction(
            "pap.sessions.end",
            "End a PAP Session",
            "Stop using a Session and forget its token; its Account Token is kept.",
            lambda runtime, values: end_session(runtime, values["session"]),
            (SESSION,),
            needs_approval=True,
            summary="End Session {session} and forget its token.",
            emoji="🚪",
        ),
        SessionAction(
            "pap.auth.disconnect",
            "Sign out of a company",
            "Revoke the Account Token: every Session using it continues signed out.",
            lambda runtime, values: disconnect(runtime, values["session"]),
            (SESSION,),
            needs_approval=True,
            summary="Sign out: revoke the Account Token of Session {session}.",
            emoji="🔒",
        ),
    )
}


def parse_arguments(action: SessionAction, argument: object) -> dict[str, str]:
    """An action's arguments, from a mapping, JSON text, or words (`name=value` or by position).

    Studio passes a mapping, a REPL the text after the command, `pap commands run`
    its words. Unknown names, non-text values, and missing required ones are refused.
    """

    names = [item.name for item in action.arguments]
    if argument is None:
        given: dict[str, object] = {}
    elif isinstance(argument, Mapping):
        given = dict(argument)
    elif isinstance(argument, str) and argument.strip().startswith("{"):
        given = _json_object(argument)
    elif isinstance(argument, str | Sequence):
        words = shlex.split(argument) if isinstance(argument, str) else list(argument)
        given = _from_words(action, names, words)
    else:
        raise ActionUsageError("invalid_arguments", "Arguments are a mapping or text")
    if set(given) - set(names):
        raise ActionUsageError("invalid_arguments", f"{action.id} takes {_takes(names)}")
    values: dict[str, str] = {}
    for name, value in given.items():
        if isinstance(value, bool) or not isinstance(value, str | int):
            raise ActionUsageError("invalid_arguments", f"{name} is text")
        values[name] = str(value)
    missing = [item.name for item in action.arguments if item.required and item.name not in values]
    if missing:
        raise ActionUsageError("invalid_arguments", f"{action.id} needs {', '.join(missing)}")
    return values


def _json_object(text: str) -> dict[str, object]:
    try:
        parsed = json.loads(text)
    except ValueError as error:
        raise ActionUsageError("invalid_arguments", "Arguments are not JSON") from error
    if not isinstance(parsed, dict):
        raise ActionUsageError("invalid_arguments", "Arguments are not a JSON object")
    return parsed


def _from_words(
    action: SessionAction, names: list[str], words: Sequence[object]
) -> dict[str, object]:
    """`name=value` words by name, the others by position into the arguments left."""

    given: dict[str, object] = {}
    positional = iter(names)
    for word in words:
        if not isinstance(word, str):
            raise ActionUsageError("invalid_arguments", "Arguments are text")
        name, sep, value = word.partition("=")
        if sep and name in names:
            given[name] = value
            continue
        slot = next((n for n in positional if n not in given), None)
        if slot is None:
            raise ActionUsageError("invalid_arguments", f"{action.id} takes {_takes(names)}")
        given[slot] = word
    return given


def _takes(names: list[str]) -> str:
    return ", ".join(names) if names else "no arguments"


#: What an approval's summary may quote: an opaque Session or operation ID, nothing else.
_QUOTABLE = re.compile(r"[A-Za-z0-9_-]{1,256}")


async def _approved(runtime: CliRuntime, action: SessionAction, values: Mapping[str, str]) -> None:
    """Ask the host's approval surface; anything but `True` means nothing is done.

    The summary the user approves quotes only validated identifiers: an argument
    carrying other text (a line break, words that read like another action) is
    refused before anything is shown, so the user approves what is done.
    """

    if any(_QUOTABLE.fullmatch(value) is None for value in values.values()):
        raise ActionUsageError("invalid_arguments", "Arguments are opaque identifiers")

    try:
        surface = optional_contribution(runtime.reactor, APPROVAL_SURFACES, "approval surface")
    except RuntimeError as error:
        raise ApprovalRequiredError(
            "approval_surface_ambiguous", "Two approval surfaces at one order: nothing was done"
        ) from error
    if surface is None:
        raise ApprovalRequiredError(
            "approval_required",
            f"{action.id} needs the user's approval and this host has no approval surface: "
            f"run it from the pap command line",
        )
    request = ApprovalRequest(
        action_id=action.id,
        action_name=action.name,
        summary=action.summary.format(**values),
        arguments=dict(values),
        tenant_id=runtime.tenant_id,
    )
    try:
        answer = await cast(ApprovalSurface, surface).approve(request)
    except Exception as error:
        raise ApprovalRequiredError(
            "approval_failed", "The approval surface failed: nothing was done"
        ) from error
    if answer is not True:
        raise ApprovalRequiredError("not_approved", "The user did not approve: nothing was done")


async def invoke_action(
    action_id: str, argument: object, *, host: HostFactory, tenant: str
) -> dict[str, Any]:
    """Run one action in a fresh personal-agent runtime of `tenant`, never asking for input."""

    action = ACTIONS.get(action_id)
    if action is None:
        raise ActionUsageError("unknown_action", f"No live-session action {action_id}")
    values = parse_arguments(action, argument)
    async with host(InputSource(no_input=True)) as runtime:
        runtime.tenant_id = tenant
        if action.needs_approval:
            await _approved(runtime, action, values)
        payload = await action.run(runtime, values)
    return {"schema_version": 1, **payload}
