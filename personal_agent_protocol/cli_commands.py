# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""The `pap` protocol command groups: thin adapters over the public SDK.

`PapCliPlugin.provide_cli` adds them. Each command builds one personal-agent
runtime (`cli_host`), calls SDK services, and prints either friendly text or
versioned JSON (`--json`, `schema_version: 1`, no terminal decoration).

Protected input — the agent's signing key, the Direct Sign-In callback (it
carries a code), Mediated Sign-In credentials and one-time codes — is never a
command-line option. It is typed at a hidden prompt, or read from stdin
(`--stdin`) or a file descriptor (`--input-fd N`), one value per line; with
`--no-input` a command that needs it stops with exit code 4. Tokens are kept
in the Reactor token store; only opaque references are printed.

Exit codes (`pap exit-codes`):

| Code | Meaning |
| --- | --- |
| 0 | Done. |
| 1 | The company refused, or the protocol failed (its error code is printed). |
| 2 | Usage error: an unknown command, option, or value. |
| 3 | Not configured: no signing key, no `client_id` or `domain`, or an unknown Session. |
| 4 | Input required, but `--no-input` was given or no terminal is attached. |
| 5 | Still pending: the user has not finished signing in before `--timeout`. |
| 6 | Not approved: no approval for this exact operation ID and revision, or the terms changed. |
| 130 | Interrupted. |
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import sys
from collections.abc import Awaitable, Callable
from enum import IntEnum
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

import typer
from pydantic import SecretStr

from .accounts import AccountTokenClient, AccountTokenContext
from .apis import ApiClient, conversation_endpoint
from .auth import DirectSignInClient
from .cli_host import (
    CliRuntime,
    InputRequiredError,
    InputSource,
    NotConfiguredError,
    SessionRecord,
)
from .conversations import ConversationClient, StreamReconnected, TextDelta, generate_message_id
from .device import DeviceSignInClient
from .discovery import DiscoveryClient
from .errors import PersonalAgentProtocolError
from .identity import AgentIdentityClient
from .mcp import McpClient, mcp_api
from .mediated import MediatedSignInClient
from .models import ConversationEvent, DiscoveredCompany, Message, Operation
from .operations import OperationsClient, UserApproval, approve, operations_endpoint
from .pairwise import resolve_pairwise_user_id
from .reactor import SIGNERS
from .requirements import load_ledger
from .sessions import SessionClient, SessionToken, Who
from .transport import DpopHttpClient

if TYPE_CHECKING:
    from .cli_plugin import PapCliPlugin


class ExitCode(IntEnum):
    OK = 0
    REFUSED = 1
    USAGE = 2
    NOT_CONFIGURED = 3
    INPUT_REQUIRED = 4
    PENDING = 5
    NOT_APPROVED = 6
    INTERRUPTED = 130


EXIT_CODES: dict[int, str] = {
    ExitCode.OK: "Done.",
    ExitCode.REFUSED: "The company refused, or the protocol failed (its error code is printed).",
    ExitCode.USAGE: "Usage error: an unknown command, option, or value.",
    ExitCode.NOT_CONFIGURED: (
        "Not configured: no signing key, no client_id or domain, or an unknown Session."
    ),
    ExitCode.INPUT_REQUIRED: "Input required, but --no-input was given or no terminal is attached.",
    ExitCode.PENDING: "Still pending: the user has not finished signing in before --timeout.",
    ExitCode.NOT_APPROVED: (
        "Not approved: no approval for this exact operation ID and revision, or the terms changed."
    ),
    ExitCode.INTERRUPTED: "Interrupted.",
}


class PendingError(PersonalAgentProtocolError):
    """The user has not finished yet (exit code 5)."""


class NotApprovedError(PersonalAgentProtocolError):
    """No approval for this exact operation and revision (exit code 6)."""


_EXIT_FOR = (
    (InputRequiredError, ExitCode.INPUT_REQUIRED),
    (NotConfiguredError, ExitCode.NOT_CONFIGURED),
    (PendingError, ExitCode.PENDING),
    (NotApprovedError, ExitCode.NOT_APPROVED),
)

PROFILE = typer.Option(None, "--profile", help="Configuration profile (domain, client_id).")
JSON = typer.Option(False, "--json", help="Print versioned JSON (schema_version 1).")
NO_INPUT = typer.Option(
    False, "--no-input", help="Never prompt; stop with exit code 4 when input is needed."
)
STDIN = typer.Option(False, "--stdin", help="Read protected input from stdin, one per line.")
INPUT_FD = typer.Option(
    None, "--input-fd", help="Read protected input from this file descriptor.", min=0
)
USER = typer.Option("default", "--user", help="The local user the agent acts for.")
HUMAN = typer.Option(False, "--human", help="The text is the user's own words (sender human).")
SCOPE = typer.Option(None, "--scope", help="A scope to request (repeat for more).")
BODY_FILE = typer.Option(None, "--body-file", help="A JSON body; - reads stdin.")
CASE = typer.Option(None, "--case", help="Only this case (repeatable).")
REQUIREMENT = typer.Option(None, "--requirement", help="Only cases showing this requirement.")
SUITE = typer.Option(None, "--suite", help="Only this suite (repeatable).")
OUTPUT = typer.Option(None, "--output", help="Write the report to this file.")
REPORT_FILE = typer.Argument(..., help="A JSON report from `run --format json`.")


def _emit(payload: dict[str, Any], json_output: bool, render: Callable[[dict], None]) -> None:
    if json_output:
        typer.echo(json.dumps({"schema_version": 1, **payload}, indent=2, sort_keys=True))
    else:
        render(payload)


def _fail(error: BaseException, code: int) -> typer.Exit:
    typer.secho(str(error), fg=typer.colors.RED, err=True)
    return typer.Exit(code=int(code))


class Runner:
    """Run one command's coroutine in a runtime, mapping failures to exit codes."""

    def __init__(self, plugin: PapCliPlugin) -> None:
        self.plugin = plugin

    def __call__(
        self,
        work: Callable[[CliRuntime], Awaitable[dict[str, Any]]],
        *,
        json_output: bool,
        render: Callable[[dict], None],
        no_input: bool = False,
        stdin: bool = False,
        input_fd: int | None = None,
    ) -> None:
        source = InputSource(no_input=no_input, stdin=stdin, fd=input_fd)

        async def main() -> dict[str, Any]:
            async with self.plugin.host(source) as runtime:
                return await work(runtime)

        try:
            payload = asyncio.run(main())
        except KeyboardInterrupt as error:
            raise _fail(PersonalAgentProtocolError("interrupted", "Interrupted"), 130) from error
        except typer.Exit:
            raise
        except PersonalAgentProtocolError as error:
            code = next((c for kind, c in _EXIT_FOR if isinstance(error, kind)), ExitCode.REFUSED)
            raise _fail(error, code) from error
        except RuntimeError as error:
            if "signer" in str(error):
                missing = NotConfiguredError(
                    "no_signing_key", "No signing key: run `pap agent key import`"
                )
                raise _fail(missing, ExitCode.NOT_CONFIGURED) from error
            raise
        _emit(payload, json_output, render)


# Shared steps --------------------------------------------------------------------------


async def _company(runtime: CliRuntime, domain: str) -> DiscoveredCompany:
    return await DiscoveryClient(reactor=runtime.reactor).discover(domain)


def _who(record: SessionRecord) -> Who:
    return {
        "tenant_id": record.tenant_id,
        "pairwise_user_id": record.pairwise_user_id,
        "issuer": record.issuer,
    }


async def _token(runtime: CliRuntime, record: SessionRecord) -> SessionToken:
    secret = await runtime.secrets.get(record.token_reference)
    if secret is None:
        raise NotConfiguredError("no_session_token", "The Session's token is gone: renew it")
    return SessionToken(
        access_token=secret,
        token_type=cast(Any, record.token_type),
        expires_in=3600,
        scope=record.scope,
        session_id=record.session_id,
        signed_in=record.signed_in,
    )


async def _keep(
    runtime: CliRuntime,
    record: SessionRecord,
    token: SessionToken,
    *,
    account_reference: str | None = None,
) -> None:
    """The new token replaces the old from now on (§4.3); the record says what it is."""

    await runtime.secrets.put(record.token_reference, token.access_token)
    if token.refresh_token is not None:
        account_reference = account_reference or f"account:{record.session_id}"
        await runtime.secrets.put(account_reference, token.refresh_token)
    if account_reference is not None:
        record.account_reference = account_reference
    record.signed_in = token.signed_in
    record.scope = token.scope
    record.expires_at = runtime.expires_at(token.expires_in)
    runtime.state.sessions[record.session_id] = record
    runtime.state.save()


def _session_view(record: SessionRecord) -> dict[str, Any]:
    return {"session": record.public()}


def _render_session(payload: dict) -> None:
    session = payload["session"]
    state = "signed in" if session["signed_in"] else "signed out"
    typer.echo(f"{session['session_id']} at {session['company']} ({session['domain']}): {state}")
    if session["scope"]:
        typer.echo(f"scope: {session['scope']}")
    typer.echo(f"token: {session['token_reference']}")
    if session.get("account_reference"):
        typer.echo(f"account token: {session['account_reference']}")


def _account_context(record: SessionRecord) -> AccountTokenContext:
    return AccountTokenContext(
        token_endpoint=record.token_endpoint,
        issuer=record.issuer,
        client_id=record.client_id,
        tenant_id=record.tenant_id,
        pairwise_user_id=record.pairwise_user_id,
        revocation_endpoint=record.revocation_endpoint,
    )


def _scopes(scope: list[str] | None, company: DiscoveredCompany, kind: str) -> tuple[str, ...]:
    if scope:
        return tuple(scope)
    auth = company.document.auth
    option = getattr(auth, kind, None) if auth is not None else None
    if option is None or not option.scopes:
        raise NotConfiguredError("no_scopes", f"The company offers no {kind} sign-in scopes")
    return tuple(option.scopes)


def _operation_view(operation: Operation) -> dict[str, Any]:
    return {"operation": operation.model_dump(mode="json")}


def _render_operation(payload: dict) -> None:
    operation = payload["operation"]
    typer.echo(
        f"{operation['operation_id']} revision {operation['revision']}: {operation['state']}"
    )
    typer.echo(operation["summary"])
    if operation.get("result"):
        typer.echo(f"Result: {operation['result']['summary']}")


def _message(reactor: Any, text: str, human: bool) -> Message:
    return Message(id=generate_message_id(reactor), sender="human" if human else "agent", text=text)


def _render_page(payload: dict) -> None:
    for event in payload.get("events", []):
        message = event.get("message")
        if message:
            who = f"{message.get('role', '?')}/{message.get('sender')}"
            typer.echo(f"[{who}] {message.get('text') or json.dumps(message.get('data'))}")
            if message.get("operation"):
                operation = message["operation"]
                typer.echo(
                    f"  operation {operation['operation_id']} revision {operation['revision']}: "
                    f"{operation['summary']}"
                )
        else:
            typer.echo(f"({event['type']})")
    if "status" in payload:
        typer.echo(f"status: {payload['status']} · responder: {payload['responder']}")


def add_protocol_groups(cli: typer.Typer, plugin: PapCliPlugin) -> None:  # noqa: C901
    """Add sessions, auth, api, conversations, operations, requirements, conformance."""

    run = Runner(plugin)
    sessions = typer.Typer(name="sessions", help="Start, renew, show, and end PAP Sessions.")
    auth = typer.Typer(name="auth", help="Sign a Session in, or sign out (the user signs in).")
    api = typer.Typer(name="api", help="Call a company's OpenAPI or MCP API in a Session.")
    conversations = typer.Typer(name="conversations", help="Talk with the company agent.")
    operations = typer.Typer(name="operations", help="Show, approve, confirm, cancel operations.")
    requirements = typer.Typer(name="requirements", help="The normative requirement ledger.")
    conformance = typer.Typer(name="conformance", help="Run and report the conformance suite.")
    key = typer.Typer(name="key", help="The agent's signing key (imported, never printed).")

    def settings(profile: str | None) -> dict[str, Any]:
        return {name: item.value for name, item in plugin.config.resolve(profile).items()}

    # sessions --------------------------------------------------------------------------

    @sessions.command("start")
    def sessions_start(
        domain: str | None = typer.Argument(None, help="The company's domain."),
        user: str = USER,
        profile: str | None = PROFILE,
        json_output: bool = JSON,
        no_input: bool = NO_INPUT,
    ) -> None:
        """Start a signed-out Session at a company (§4.2)."""

        configured = settings(profile)
        selected = domain or configured.get("domain")
        client_id = configured.get("client_id")

        async def work(runtime: CliRuntime) -> dict[str, Any]:
            if not selected:
                raise NotConfiguredError("no_domain", "Give DOMAIN or `pap config set domain`")
            if not client_id:
                raise NotConfiguredError("no_client_id", "Run `pap config set client_id URL`")
            if not runtime.reactor.get_contributions(SIGNERS):
                raise NotConfiguredError(
                    "no_signing_key", "No signing key: run `pap agent key import`"
                )
            company = await _company(runtime, str(selected))
            metadata = company.oauth_metadata
            if metadata is None:
                raise NotConfiguredError("no_sessions", "The company offers no Sessions")
            pairwise = await resolve_pairwise_user_id(
                runtime.reactor,
                tenant_id=runtime.tenant_id,
                local_user_id=user,
                company_issuer=metadata.issuer,
            )
            token = await SessionClient(reactor=runtime.reactor, http_client=runtime.http).start(
                client_id=str(client_id),
                pairwise_user_id=pairwise,
                issuer=metadata.issuer,
                token_endpoint=metadata.token_endpoint,
                tenant_id=runtime.tenant_id,
            )
            record = SessionRecord(
                session_id=token.session_id,
                domain=company.document.organization.domain,
                company=company.document.organization.name,
                issuer=metadata.issuer,
                token_endpoint=metadata.token_endpoint,
                revocation_endpoint=metadata.revocation_endpoint,
                client_id=str(client_id),
                tenant_id=runtime.tenant_id,
                user=user,
                pairwise_user_id=pairwise,
                token_reference=f"session:{token.session_id}",
                signed_in=token.signed_in,
                scope=token.scope,
                expires_at=runtime.expires_at(token.expires_in),
            )
            await _keep(runtime, record, token)
            return _session_view(record)

        run(work, json_output=json_output, render=_render_session, no_input=no_input)

    @sessions.command("renew")
    def sessions_renew(
        session_id: str = typer.Argument(...),
        json_output: bool = JSON,
        no_input: bool = NO_INPUT,
    ) -> None:
        """Get a new Session Token: with the Account Token when signed in (§4.2, §4.8)."""

        async def work(runtime: CliRuntime) -> dict[str, Any]:
            record = runtime.state.session(session_id)
            if record.account_reference is not None:
                result = await AccountTokenClient(
                    reactor=runtime.reactor, http_client=runtime.http
                ).refresh(
                    record.account_reference,
                    context=_account_context(record),
                    session_id=session_id,
                )
                if result.status == "signed_in" and result.token is not None:
                    await _keep(runtime, record, result.token)
                    return _session_view(record)
                record.account_reference = None  # gone at the company: continue signed out
            token = await SessionClient(reactor=runtime.reactor, http_client=runtime.http).renew(
                client_id=record.client_id,
                pairwise_user_id=record.pairwise_user_id,
                issuer=record.issuer,
                token_endpoint=record.token_endpoint,
                tenant_id=record.tenant_id,
                session_id=session_id,
            )
            await _keep(runtime, record, token)
            return _session_view(record)

        run(work, json_output=json_output, render=_render_session, no_input=no_input)

    @sessions.command("show")
    def sessions_show(
        session_id: str | None = typer.Argument(None),
        json_output: bool = JSON,
    ) -> None:
        """Show the Sessions this agent holds (opaque references, never tokens)."""

        async def work(runtime: CliRuntime) -> dict[str, Any]:
            if session_id is not None:
                return _session_view(runtime.state.session(session_id))
            return {"sessions": [record.public() for record in runtime.state.sessions.values()]}

        def render(payload: dict) -> None:
            if "session" in payload:
                _render_session(payload)
                return
            for session in payload["sessions"]:
                _render_session({"session": session})

        run(work, json_output=json_output, render=render)

    @sessions.command("end")
    def sessions_end(session_id: str = typer.Argument(...), json_output: bool = JSON) -> None:
        """Stop using a Session; its Account Token is kept for new ones (§4.9)."""

        async def work(runtime: CliRuntime) -> dict[str, Any]:
            record = runtime.state.session(session_id)
            await runtime.secrets.delete(record.token_reference)
            await runtime.secrets.delete(f"mcp:{session_id}")
            del runtime.state.sessions[session_id]
            runtime.state.save()
            return {"ended": session_id, "account_reference": record.account_reference}

        def render(payload: dict) -> None:
            typer.echo(f"Ended {payload['ended']}.")
            if payload["account_reference"]:
                typer.echo(f"Account token kept: {payload['account_reference']}")

        run(work, json_output=json_output, render=render)

    # auth ------------------------------------------------------------------------------

    @auth.command("direct")
    def auth_direct(
        session_id: str = typer.Argument(...),
        scope: list[str] | None = SCOPE,
        redirect_uri: str | None = typer.Option(None, "--redirect-uri"),
        json_output: bool = JSON,
        no_input: bool = NO_INPUT,
        stdin: bool = STDIN,
        input_fd: int | None = INPUT_FD,
    ) -> None:
        """Direct Sign-In: the user signs in on the company's page in their own browser.

        Paste the URL your browser lands on (it carries a one-time code) at the
        prompt, or give it on stdin or a file descriptor.
        """

        async def work(runtime: CliRuntime) -> dict[str, Any]:
            record = runtime.state.session(session_id)
            company = await _company(runtime, record.domain)
            metadata = company.oauth_metadata
            if metadata is None or metadata.authorization_endpoint is None:
                raise NotConfiguredError("no_direct", "The company offers no Direct Sign-In")
            target = redirect_uri
            if target is None:
                identity = AgentIdentityClient(reactor=runtime.reactor, http_client=runtime.http)
                registered = (await identity.fetch_metadata(record.client_id)).redirect_uris
                if not registered:
                    raise NotConfiguredError("no_redirect_uri", "The agent lists no redirect_uris")
                target = registered[0]
            client = DirectSignInClient(reactor=runtime.reactor, http_client=runtime.http)
            await client.begin(
                authorization_endpoint=metadata.authorization_endpoint,
                token_endpoint=metadata.token_endpoint,
                issuer=metadata.issuer,
                client_id=record.client_id,
                redirect_uri=target,
                scopes=_scopes(scope, company, "direct"),
                tenant_id=record.tenant_id,
                pairwise_user_id=record.pairwise_user_id,
                session_id=session_id,
            )
            callback = runtime.input.read("Callback URL", secret=True)
            result = await client.complete(callback.get_secret_value())
            await _keep(runtime, record, result.token)
            return {**_session_view(record), "missing_scopes": list(result.missing_scopes)}

        run(
            work,
            json_output=json_output,
            render=_render_session,
            no_input=no_input,
            stdin=stdin,
            input_fd=input_fd,
        )

    @auth.command("device")
    def auth_device(
        session_id: str = typer.Argument(...),
        scope: list[str] | None = SCOPE,
        timeout: float = typer.Option(600.0, "--timeout", help="Seconds to wait for the user."),
        json_output: bool = JSON,
        no_input: bool = NO_INPUT,
    ) -> None:
        """Device Sign-In: show the link and code; the user signs in on any device."""

        async def work(runtime: CliRuntime) -> dict[str, Any]:
            record = runtime.state.session(session_id)
            company = await _company(runtime, record.domain)
            metadata = company.oauth_metadata
            if metadata is None or metadata.device_authorization_endpoint is None:
                raise NotConfiguredError("no_device", "The company offers no Device Sign-In")
            client = DeviceSignInClient(reactor=runtime.reactor, http_client=runtime.http)
            started = await client.begin(
                device_authorization_endpoint=metadata.device_authorization_endpoint,
                token_endpoint=metadata.token_endpoint,
                issuer=metadata.issuer,
                client_id=record.client_id,
                scopes=_scopes(scope, company, "device"),
                tenant_id=record.tenant_id,
                pairwise_user_id=record.pairwise_user_id,
                session_id=session_id,
            )
            link = started.verification_uri_complete or started.verification_uri
            typer.echo(f"Sign in at {link} with the code {started.user_code}.", err=True)
            waited = 0.0
            while waited <= timeout:
                await runtime.sleep(started.poll_interval)
                waited += started.poll_interval
                polled = await client.poll(started.reference)
                if polled.status == "complete" and polled.token is not None:
                    await _keep(
                        runtime,
                        record,
                        polled.token,
                        account_reference=polled.account_token_reference,
                    )
                    return {**_session_view(record), "missing_scopes": list(polled.missing_scopes)}
            raise PendingError("authorization_pending", "The user has not signed in yet")

        run(work, json_output=json_output, render=_render_session, no_input=no_input)

    @auth.command("mediated")
    def auth_mediated(
        session_id: str = typer.Argument(...),
        scope: list[str] | None = SCOPE,
        json_output: bool = JSON,
        no_input: bool = NO_INPUT,
        stdin: bool = STDIN,
        input_fd: int | None = INPUT_FD,
    ) -> None:
        """Mediated Sign-In: the user's credentials go only to the company's endpoint.

        The company's fields (and a one-time code, if it sends one) are asked
        for at a hidden prompt, or read one per line from stdin or a descriptor.
        """

        async def work(runtime: CliRuntime) -> dict[str, Any]:
            record = runtime.state.session(session_id)
            company = await _company(runtime, record.domain)
            auth_document = company.document.auth
            if auth_document is None or auth_document.mediated is None:
                raise NotConfiguredError("no_mediated", "The company offers no Mediated Sign-In")
            client = MediatedSignInClient(reactor=runtime.reactor, http_client=runtime.http)
            token = await _token(runtime, record)
            result = await client.sign_in(
                mediated=auth_document.mediated,
                organization=company.document.organization,
                issuer=record.issuer,
                scopes=_scopes(scope, company, "mediated"),
                token=token,
                tenant_id=record.tenant_id,
                pairwise_user_id=record.pairwise_user_id,
            )
            while result.status == "code_required" and result.reference is not None:
                result = await client.submit_code(result.reference, token=token, **_who(record))
            if result.status != "complete" or result.token is None:
                raise PersonalAgentProtocolError(
                    f"sign_in_{result.status}", "Mediated Sign-In did not complete"
                )
            await _keep(
                runtime, record, result.token, account_reference=result.account_token_reference
            )
            return {**_session_view(record), "missing_scopes": list(result.missing_scopes)}

        run(
            work,
            json_output=json_output,
            render=_render_session,
            no_input=no_input,
            stdin=stdin,
            input_fd=input_fd,
        )

    @auth.command("disconnect")
    def auth_disconnect(session_id: str = typer.Argument(...), json_output: bool = JSON) -> None:
        """Sign out: revoke the Account Token; Sessions continue signed out (§4.9)."""

        async def work(runtime: CliRuntime) -> dict[str, Any]:
            record = runtime.state.session(session_id)
            if record.account_reference is None:
                raise NotConfiguredError("not_signed_in", "This Session holds no Account Token")
            await AccountTokenClient(reactor=runtime.reactor, http_client=runtime.http).revoke(
                record.account_reference, context=_account_context(record)
            )
            for other in runtime.state.sessions.values():
                if other.account_reference == record.account_reference:
                    other.account_reference = None
                    other.signed_in = False
                    other.scope = ""
            runtime.state.save()
            return _session_view(record)

        run(work, json_output=json_output, render=_render_session)

    # api -------------------------------------------------------------------------------

    @api.command("openapi")
    def api_openapi(
        session_id: str = typer.Argument(...),
        method: str = typer.Argument(..., help="GET, POST, …"),
        path: str = typer.Argument(..., help="A path on the company's origin, or its URL."),
        body_file: Path | None = BODY_FILE,
        json_output: bool = JSON,
    ) -> None:
        """Call the company's OpenAPI API with the Session's DPoP token (§6)."""

        async def work(runtime: CliRuntime) -> dict[str, Any]:
            record = runtime.state.session(session_id)
            url = path if path.startswith("https://") else f"https://{record.domain}{path}"
            body: Any = None
            if body_file is not None:
                raw = sys.stdin.read() if str(body_file) == "-" else body_file.read_text()
                body = json.loads(raw)
            answer = await ApiClient(
                transport=DpopHttpClient(reactor=runtime.reactor, http_client=runtime.http)
            ).call(
                method.upper(),
                url,
                token=await _token(runtime, record),
                body=body if body is not None or method.upper() == "GET" else {},
                **_who(record),
            )
            if answer.operation is not None:
                return {"status": answer.status, **_operation_view(answer.operation)}
            return {"status": answer.status, "body": answer.body}

        def render(payload: dict) -> None:
            if "operation" in payload:
                typer.echo("Proposed, not done until confirmed:")
                _render_operation(payload)
            else:
                typer.echo(json.dumps(payload["body"], indent=2))

        run(work, json_output=json_output, render=render)

    @api.command("mcp")
    def api_mcp(  # noqa: C901 - signed in or out, list or call
        session_id: str = typer.Argument(...),
        tool: str | None = typer.Argument(None, help="The tool to call; omitted, list them."),
        arguments: str = typer.Option("{}", "--arguments", help="The tool's JSON arguments."),
        json_output: bool = JSON,
    ) -> None:
        """Call the company's MCP server with a Bearer token for its url only (§4.3)."""

        async def work(runtime: CliRuntime) -> dict[str, Any]:
            record = runtime.state.session(session_id)
            company = await _company(runtime, record.domain)
            server = mcp_api(company.document)
            if server is None:
                raise NotConfiguredError("no_mcp", "The company lists no MCP server")
            if record.account_reference is not None:
                result = await AccountTokenClient(
                    reactor=runtime.reactor, http_client=runtime.http
                ).bearer_for_mcp(
                    record.account_reference,
                    context=_account_context(record),
                    session_id=session_id,
                    resource=server.url,
                )
                bearer = result.token
            else:
                bearer = None
            if bearer is None:
                bearer = await SessionClient(
                    reactor=runtime.reactor, http_client=runtime.http
                ).bearer_for_mcp(
                    client_id=record.client_id,
                    pairwise_user_id=record.pairwise_user_id,
                    issuer=record.issuer,
                    token_endpoint=record.token_endpoint,
                    tenant_id=record.tenant_id,
                    session_id=session_id,
                    resource=server.url,
                )
            await runtime.secrets.put(f"mcp:{session_id}", bearer.access_token)
            client = McpClient(http_client=runtime.http, token=bearer, url=server.url)
            if tool is None:
                return {"tools": await client.list_tools()}
            answer = await client.call_tool(tool, json.loads(arguments))
            payload: dict[str, Any] = {
                "content": answer.content,
                "structured_content": answer.structured_content,
                "is_error": answer.is_error,
            }
            if answer.operation is not None:
                payload.update(_operation_view(answer.operation))
            return payload

        def render(payload: dict) -> None:
            if "tools" in payload:
                for item in payload["tools"]:
                    typer.echo(f"{item['name']}: {item.get('description', '')}")
                return
            for item in payload["content"]:
                if item.get("type") == "text":
                    typer.echo(item.get("text", ""))
            if "operation" in payload:
                _render_operation(payload)

        run(work, json_output=json_output, render=render)

    # conversations ---------------------------------------------------------------------

    async def _conversation(runtime: CliRuntime, record: SessionRecord) -> tuple[Any, str]:
        company = await _company(runtime, record.domain)
        endpoint = conversation_endpoint(company.document)
        if endpoint is None:
            raise NotConfiguredError("no_conversations", "The company lists no poppy agent")
        client = ConversationClient(
            transport=DpopHttpClient(reactor=runtime.reactor, http_client=runtime.http)
        )
        return client, endpoint

    @conversations.command("start")
    def conversations_start(
        session_id: str = typer.Argument(...),
        text: str = typer.Argument(...),
        human: bool = HUMAN,
        wait: int | None = typer.Option(None, "--wait", help="Seconds to wait for a reply."),
        json_output: bool = JSON,
    ) -> None:
        """Start a conversation with its first message (§7.3)."""

        async def work(runtime: CliRuntime) -> dict[str, Any]:
            record = runtime.state.session(session_id)
            client, endpoint = await _conversation(runtime, record)
            answer = await client.start(
                endpoint,
                _message(runtime.reactor, text, human),
                token=await _token(runtime, record),
                wait=wait,
                **_who(record),
            )
            return cast(dict[str, Any], answer.model_dump(mode="json"))

        run(work, json_output=json_output, render=_render_receipt_or_page)

    @conversations.command("send")
    def conversations_send(
        session_id: str = typer.Argument(...),
        conversation_id: str = typer.Argument(...),
        text: str = typer.Argument(...),
        human: bool = HUMAN,
        wait: int | None = typer.Option(None, "--wait", help="Seconds to wait for a reply."),
        json_output: bool = JSON,
    ) -> None:
        """Send another message (§7.3); its ID makes a retry safe."""

        async def work(runtime: CliRuntime) -> dict[str, Any]:
            record = runtime.state.session(session_id)
            client, endpoint = await _conversation(runtime, record)
            answer = await client.send(
                endpoint,
                conversation_id,
                _message(runtime.reactor, text, human),
                token=await _token(runtime, record),
                wait=wait,
                **_who(record),
            )
            return cast(dict[str, Any], answer.model_dump(mode="json"))

        run(work, json_output=json_output, render=_render_receipt_or_page)

    @conversations.command("events")
    def conversations_events(
        session_id: str = typer.Argument(...),
        conversation_id: str = typer.Argument(...),
        cursor: str | None = typer.Option(None, "--cursor", help="Read after this event."),
        json_output: bool = JSON,
    ) -> None:
        """Read one page of events (§7.5)."""

        async def work(runtime: CliRuntime) -> dict[str, Any]:
            record = runtime.state.session(session_id)
            client, endpoint = await _conversation(runtime, record)
            page = await client.read_events(
                endpoint,
                conversation_id,
                token=await _token(runtime, record),
                cursor=cursor,
                **_who(record),
            )
            return cast(dict[str, Any], page.model_dump(mode="json"))

        run(work, json_output=json_output, render=_render_page)

    @conversations.command("follow")
    def conversations_follow(
        session_id: str = typer.Argument(...),
        conversation_id: str = typer.Argument(...),
        last_event_id: str | None = typer.Option(None, "--last-event-id"),
        max_events: int = typer.Option(50, "--max-events", min=1),
        json_output: bool = JSON,
    ) -> None:
        """Stream events (SSE) until the conversation closes or --max-events (§7.6).

        Text pieces are shown as they arrive and are never acted on.
        """

        async def work(runtime: CliRuntime) -> dict[str, Any]:
            record = runtime.state.session(session_id)
            client, endpoint = await _conversation(runtime, record)
            events: list[dict[str, Any]] = []
            stream = client.stream(
                endpoint,
                conversation_id,
                token=await _token(runtime, record),
                last_event_id=last_event_id,
                max_reconnects=0,
                **_who(record),
            )
            with contextlib.suppress(PersonalAgentProtocolError):
                async with contextlib.aclosing(stream) as items:
                    async for item in items:
                        if isinstance(item, TextDelta):
                            if not json_output:
                                typer.echo(f"… {item.text}", err=True)
                        elif isinstance(item, ConversationEvent):
                            events.append(item.model_dump(mode="json", exclude_none=True))
                            if len(events) >= max_events:
                                break
                        elif isinstance(item, StreamReconnected):
                            break
            return {"conversation_id": conversation_id, "events": events}

        run(work, json_output=json_output, render=_render_page)

    @conversations.command("handoff")
    def conversations_handoff(
        session_id: str = typer.Argument(...),
        conversation_id: str = typer.Argument(...),
        json_output: bool = JSON,
    ) -> None:
        """Ask for a person at the company (§7.9)."""

        async def work(runtime: CliRuntime) -> dict[str, Any]:
            record = runtime.state.session(session_id)
            client, endpoint = await _conversation(runtime, record)
            receipt = await client.handoff(
                endpoint, conversation_id, token=await _token(runtime, record), **_who(record)
            )
            return cast(dict[str, Any], receipt.model_dump(mode="json"))

        run(work, json_output=json_output, render=_render_receipt_or_page)

    @conversations.command("direct")
    def conversations_direct(
        session_id: str = typer.Argument(...),
        parent_id: str = typer.Argument(..., help="The conversation it continues."),
        text: str = typer.Argument(..., help="The user's own words."),
        json_output: bool = JSON,
    ) -> None:
        """Open a Direct Conversation: the user talks with the company (§7.10)."""

        async def work(runtime: CliRuntime) -> dict[str, Any]:
            record = runtime.state.session(session_id)
            client, endpoint = await _conversation(runtime, record)
            answer = await client.start_direct(
                endpoint,
                parent_id,
                _message(runtime.reactor, text, True),
                token=await _token(runtime, record),
                **_who(record),
            )
            return cast(dict[str, Any], answer.model_dump(mode="json"))

        run(work, json_output=json_output, render=_render_receipt_or_page)

    @conversations.command("close")
    def conversations_close(
        session_id: str = typer.Argument(...),
        conversation_id: str = typer.Argument(...),
        json_output: bool = JSON,
    ) -> None:
        """Close the conversation; what it started is not cancelled (§7.12)."""

        async def work(runtime: CliRuntime) -> dict[str, Any]:
            record = runtime.state.session(session_id)
            client, endpoint = await _conversation(runtime, record)
            receipt = await client.close(
                endpoint, conversation_id, token=await _token(runtime, record), **_who(record)
            )
            return cast(dict[str, Any], receipt.model_dump(mode="json"))

        run(work, json_output=json_output, render=_render_receipt_or_page)

    # operations ------------------------------------------------------------------------

    async def _operations(runtime: CliRuntime, record: SessionRecord) -> tuple[Any, str, str]:
        company = await _company(runtime, record.domain)
        identity = AgentIdentityClient(reactor=runtime.reactor, http_client=runtime.http)
        metadata = await identity.fetch_metadata(record.client_id)
        endpoint = operations_endpoint(company.document, metadata)
        if endpoint is None:
            raise NotConfiguredError("no_operations", "Operations v1 is not negotiated")
        client = OperationsClient(
            transport=DpopHttpClient(reactor=runtime.reactor, http_client=runtime.http)
        )
        return client, endpoint, company.document.organization.name

    @operations.command("show")
    def operations_show(
        session_id: str = typer.Argument(...),
        operation_id: str = typer.Argument(...),
        json_output: bool = JSON,
    ) -> None:
        """Read an operation by its ID (Operations §6)."""

        async def work(runtime: CliRuntime) -> dict[str, Any]:
            record = runtime.state.session(session_id)
            client, endpoint, _ = await _operations(runtime, record)
            operation = await client.read(
                endpoint, operation_id, token=await _token(runtime, record), **_who(record)
            )
            return _operation_view(operation)

        run(work, json_output=json_output, render=_render_operation)

    @operations.command("approve")
    def operations_approve(
        session_id: str = typer.Argument(...),
        operation_id: str = typer.Argument(...),
        revision: int = typer.Option(..., "--revision", min=1, help="The exact revision."),
        json_output: bool = JSON,
        no_input: bool = NO_INPUT,
    ) -> None:
        """Show the company's name and the summary, and take the user's approval here.

        The user types the operation ID to approve this exact revision; no
        message, option, or other text ever counts as approval (Operations §5.1).
        """

        async def work(runtime: CliRuntime) -> dict[str, Any]:
            record = runtime.state.session(session_id)
            client, endpoint, company_name = await _operations(runtime, record)
            operation = await client.read(
                endpoint, operation_id, token=await _token(runtime, record), **_who(record)
            )
            if operation.revision != revision:
                raise NotApprovedError(
                    "revision_changed", f"The current revision is {operation.revision}"
                )
            if no_input:
                raise InputRequiredError("input_required", "The user approves at the prompt")
            typer.echo(f"{company_name} asks to:", err=True)
            typer.echo(f"  {operation.summary}", err=True)
            typer.echo(f"  (operation {operation_id}, revision {revision})", err=True)
            answer = typer.prompt("Type the operation ID to approve", err=True)
            if answer.strip() != operation_id:
                raise NotApprovedError("not_approved", "The user did not approve")
            approval = approve(operation)
            runtime.state.approvals[operation_id] = {
                **approval.model_dump(mode="json"),
                "session_id": session_id,
            }
            runtime.state.save()
            return {"approved": {"operation_id": operation_id, "revision": revision}}

        def render(payload: dict) -> None:
            approved = payload["approved"]
            typer.echo(f"Approved {approved['operation_id']} revision {approved['revision']}.")

        run(work, json_output=json_output, render=render, no_input=no_input)

    @operations.command("confirm")
    def operations_confirm(
        session_id: str = typer.Argument(...),
        operation_id: str = typer.Argument(...),
        revision: int = typer.Option(..., "--revision", min=1, help="The exact revision."),
        json_output: bool = JSON,
    ) -> None:
        """Confirm the exact operation ID and revision the user approved (Operations §5.2)."""

        async def work(runtime: CliRuntime) -> dict[str, Any]:
            record = runtime.state.session(session_id)
            approved = runtime.state.approvals.get(operation_id)
            if approved is None or approved.get("revision") != revision:
                raise NotApprovedError(
                    "not_approved", "No approval for this operation ID and revision"
                )
            client, endpoint, _ = await _operations(runtime, record)
            token = await _token(runtime, record)
            operation = await client.read(endpoint, operation_id, token=token, **_who(record))
            approval = UserApproval.model_validate(
                {key: approved[key] for key in ("operation_id", "revision", "digest")}
            )
            try:
                outcome = await client.confirm(
                    endpoint, operation, approval=approval, token=token, **_who(record)
                )
            except PersonalAgentProtocolError as error:
                if error.code in {"approval_mismatch", "not_proposed"}:
                    raise NotApprovedError(error.code, "Approve the current revision") from error
                raise
            if outcome.status == "terms_changed":
                raise NotApprovedError("terms_changed", "The terms changed: approve them again")
            if outcome.status == "approval_required":
                raise NotApprovedError("user_approval_required", "The user must approve")
            runtime.state.approvals.pop(operation_id, None)
            runtime.state.save()
            payload = _operation_view(cast(Operation, outcome.operation))
            return {**payload, "status": outcome.status, "retry_after": outcome.retry_after}

        run(work, json_output=json_output, render=_render_operation)

    @operations.command("cancel")
    def operations_cancel(
        session_id: str = typer.Argument(...),
        operation_id: str = typer.Argument(...),
        json_output: bool = JSON,
    ) -> None:
        """Decline a proposal, or ask the company to stop one in progress (Operations §7)."""

        async def work(runtime: CliRuntime) -> dict[str, Any]:
            record = runtime.state.session(session_id)
            client, endpoint, _ = await _operations(runtime, record)
            operation = await client.cancel(
                endpoint, operation_id, token=await _token(runtime, record), **_who(record)
            )
            runtime.state.approvals.pop(operation_id, None)
            runtime.state.save()
            return _operation_view(operation)

        run(work, json_output=json_output, render=_render_operation)

    # requirements ----------------------------------------------------------------------

    @requirements.command("list")
    def requirements_list(
        role: str | None = typer.Option(None, "--role", help="personal-agent or company."),
        level: str | None = typer.Option(None, "--level", help="MUST, MUST NOT, SHOULD, …"),
        status: str | None = typer.Option(None, "--status", help="implemented, open, …"),
        source: str | None = typer.Option(None, "--source", help="spec, operations, guide."),
        json_output: bool = JSON,
    ) -> None:
        """List ledger entries, filtered."""

        ledger = load_ledger()
        items = ledger.select(role=role, level=level, status=status, source=source)
        payload = {"profile": ledger.profile, "requirements": [i.as_dict() for i in items]}

        def render(value: dict) -> None:
            for item in value["requirements"]:
                typer.echo(
                    f"{item['id']:<22} {item['level']:<10} {item['status']:<14} {item['role']}"
                )

        _emit(payload, json_output, render)

    @requirements.command("show")
    def requirements_show(
        requirement_id: str = typer.Argument(...), json_output: bool = JSON
    ) -> None:
        """Show one ledger entry: its text, implementation, tests, and cases."""

        try:
            item = load_ledger().get(requirement_id)
        except KeyError as error:
            raise _fail(
                NotConfiguredError("unknown_requirement", f"No requirement {requirement_id}"),
                ExitCode.USAGE,
            ) from error

        def render(value: dict) -> None:
            entry = value["requirement"]
            typer.echo(f"{entry['id']} ({entry['source']} §{entry['section']}, {entry['role']})")
            typer.echo(entry["text"])
            typer.echo(
                f"status: {entry['status']}"
                + (f" — {entry['reason']}" if "reason" in entry else "")
            )
            for label in ("implementation", "tests", "conformance"):
                for value_ in entry[label]:
                    typer.echo(f"{label}: {value_}")

        _emit({"requirement": item.as_dict()}, json_output, render)

    # conformance -----------------------------------------------------------------------

    @conformance.command("run")
    def conformance_run(
        demo: bool = typer.Option(
            False, "--demo", help="Run against the in-process Manzanita reference company."
        ),
        tls: bool = typer.Option(False, "--tls", help="With --demo: over real TCP and TLS."),
        case_id: list[str] | None = CASE,
        requirement: list[str] | None = REQUIREMENT,
        suite: list[str] | None = SUITE,
        output_format: str = typer.Option("text", "--format", help="text, json, or junit."),
        output: Path | None = OUTPUT,
    ) -> None:
        """Run the personal-agent conformance suite (Python agent against a company)."""

        from .conformance import run_conformance, select_cases

        if not demo:
            raise _fail(
                NotConfiguredError(
                    "no_target",
                    "Only --demo is runnable from the CLI; use personal_agent_protocol."
                    "conformance with your company's driver and scenario",
                ),
                ExitCode.NOT_CONFIGURED,
            )
        if output_format not in {"text", "json", "junit"}:
            raise typer.BadParameter("choose text, json, or junit", param_hint="--format")

        async def main() -> Any:
            from .demo.conformance import ManzanitaConformance

            world = ManzanitaConformance()
            cases = select_cases(
                ids=case_id or (), requirements=requirement or (), suites=suite or ()
            )
            if tls:
                from .demo.sockets import served_over_tls

                async with served_over_tls(world.network):
                    return await run_conformance(world.context(), cases=cases)
            return await run_conformance(world.context(), cases=cases)

        report = asyncio.run(main())
        _write_report(report, output_format, output)
        if not report.passed:
            raise typer.Exit(code=int(ExitCode.REFUSED))

    @conformance.command("report")
    def conformance_report(
        report_file: Path = REPORT_FILE,
        output_format: str = typer.Option("text", "--format", help="text, json, or junit."),
        output: Path | None = OUTPUT,
    ) -> None:
        """Print or convert a saved JSON report."""

        from .conformance import ConformanceReport

        if output_format not in {"text", "json", "junit"}:
            raise typer.BadParameter("choose text, json, or junit", param_hint="--format")
        report = ConformanceReport.from_json(json.loads(report_file.read_text()))
        _write_report(report, output_format, output)
        if not report.passed:
            raise typer.Exit(code=int(ExitCode.REFUSED))

    # agent key -------------------------------------------------------------------------

    @key.command("import")
    def key_import(
        kid: str = typer.Option("key-1", "--kid", help="The key ID published in the JWKS."),
        json_output: bool = JSON,
        no_input: bool = NO_INPUT,
        stdin: bool = STDIN,
        input_fd: int | None = INPUT_FD,
    ) -> None:
        """Import the agent's private signing key (PEM) from protected input."""

        async def work(runtime: CliRuntime) -> dict[str, Any]:
            if runtime.input.fd is None and not runtime.input.stdin:
                raise InputRequiredError(
                    "input_required", "Give the PEM on --stdin or --input-fd, never as an option"
                )
            pem = SecretStr("\n".join(runtime.input.lines()) + "\n")
            try:
                identity = runtime.keys.import_signing_key(pem, kid=kid)
            except ValueError as error:
                raise PersonalAgentProtocolError("invalid_key", str(error)) from error
            return {"key": identity}

        def render(payload: dict) -> None:
            key_ = payload["key"]
            typer.echo(f"Imported {key_['key_reference']} ({key_['alg']}, {key_['thumbprint']}).")

        run(
            work,
            json_output=json_output,
            render=render,
            no_input=no_input,
            stdin=stdin,
            input_fd=input_fd,
        )

    @key.command("show")
    def key_show(json_output: bool = JSON) -> None:
        """Show the signing key's reference and public thumbprint (never the key)."""

        async def work(runtime: CliRuntime) -> dict[str, Any]:
            identity = runtime.keys.signing_identity()
            if identity is None:
                raise NotConfiguredError("no_signing_key", "Run `pap agent key import`")
            return {"key": identity}

        def render(payload: dict) -> None:
            key_ = payload["key"]
            typer.echo(f"{key_['key_reference']} ({key_['alg']}, {key_['thumbprint']})")

        run(work, json_output=json_output, render=render)

    @cli.command("exit-codes")
    def exit_codes(json_output: bool = JSON) -> None:
        """Every exit code the pap protocol commands use."""

        payload = {"exit_codes": {str(int(code)): text for code, text in EXIT_CODES.items()}}

        def render(value: dict) -> None:
            for code, text in value["exit_codes"].items():
                typer.echo(f"{code:>3}  {text}")

        _emit(payload, json_output, render)

    for group in (sessions, auth, api, conversations, operations, requirements, conformance):
        cli.add_typer(group)
    plugin.agent_group.add_typer(key)


def _render_receipt_or_page(payload: dict) -> None:
    if "events" in payload:
        typer.echo(f"conversation {payload['conversation_id']}")
        _render_page(payload)
        return
    typer.echo(
        f"conversation {payload['conversation_id']}: {payload['status']} "
        f"· responder: {payload['responder']}"
    )


def _write_report(report: Any, output_format: str, output: Path | None) -> None:
    if output_format == "json":
        text = json.dumps(report.to_json(), indent=2)
    elif output_format == "junit":
        text = report.to_junit()
    else:
        lines = [
            f"{r.outcome:<8} {r.id}" + (f"  ({r.message})" if r.message else "")
            for r in report.results
        ]
        counts = report.counts()
        lines.append(
            f"{counts['passed']} passed, {counts['failed']} failed, {counts['skipped']} skipped"
        )
        text = "\n".join(lines)
    if output is not None:
        output.write_text(text + "\n", encoding="utf-8")
    else:
        typer.echo(text)
