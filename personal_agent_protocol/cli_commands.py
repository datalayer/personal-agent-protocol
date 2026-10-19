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
| 6 | Not approved: not this exact operation ID and revision, or a live-session action. |
| 130 | Interrupted. |
"""

from __future__ import annotations

import asyncio
import hmac
import json
import sys
from collections.abc import Awaitable, Callable
from enum import IntEnum
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

import typer
from pydantic import SecretStr

from .accounts import AccountTokenClient
from .actions import (
    ActionUsageError,
    ApprovalRequiredError,
    account_context,
    cancel_operation,
    company_of,
    conversation_client,
    disconnect,
    end_session,
    follow_events,
    list_requirements,
    operation_view,
    operations_client,
    read_events,
    session_token,
    session_view,
    show_operation,
    show_requirement,
    show_sessions,
    who_of,
)
from .apis import ApiClient
from .auth import DirectSignInClient
from .cli_host import (
    CliRuntime,
    InputRequiredError,
    InputSource,
    NotConfiguredError,
    SessionRecord,
    approval_key,
    approval_mac,
)
from .conversations import generate_message_id
from .device import DeviceSignInClient
from .errors import PersonalAgentProtocolError
from .identity import AgentIdentityClient
from .mcp import McpClient, fetch_mcp_server_metadata, mcp_api
from .mediated import MediatedSignInClient
from .models import DiscoveredCompany, Message, Operation
from .operations import UserApproval, approve
from .pairwise import resolve_pairwise_user_id
from .reactor import (
    APPROVAL_SURFACES,
    SIGNERS,
    TOKEN_STORES,
    ApprovalRequest,
    ApprovalSurface,
    first_contribution,
    optional_contribution,
)
from .sessions import SessionClient, SessionToken
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
        "Not approved: no approval for this exact operation ID and revision, or the terms changed;"
        " or a live-session action the host's approval surface did not approve."
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
    (ApprovalRequiredError, ExitCode.NOT_APPROVED),
    (ActionUsageError, ExitCode.USAGE),
)


def user_terminal() -> bool:
    """Whether the user is at a terminal: standard input and error both a TTY."""

    return sys.stdin.isatty() and sys.stderr.isatty()


def exit_code_for(error: PersonalAgentProtocolError) -> ExitCode:
    """The exit code a refused or failed command ends with."""

    return next((code for kind, code in _EXIT_FOR if isinstance(error, kind)), ExitCode.REFUSED)


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
            tenant = self.plugin.tenant()
            async with self.plugin.host(source) as runtime:
                # Every command sees and makes only its tenant's Sessions.
                runtime.tenant_id = tenant
                return await work(runtime)

        try:
            payload = asyncio.run(main())
        except KeyboardInterrupt as error:
            raise _fail(PersonalAgentProtocolError("interrupted", "Interrupted"), 130) from error
        except typer.Exit:
            raise
        except PersonalAgentProtocolError as error:
            raise _fail(error, exit_code_for(error)) from error
        except RuntimeError as error:
            if "signer" in str(error):
                missing = NotConfiguredError(
                    "no_signing_key", "No signing key: run `pap agent key import`"
                )
                raise _fail(missing, ExitCode.NOT_CONFIGURED) from error
            raise
        _emit(payload, json_output, render)


# Shared steps --------------------------------------------------------------------------


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


def _render_session(payload: dict) -> None:
    session = payload["session"]
    state = "signed in" if session["signed_in"] else "signed out"
    typer.echo(f"{session['session_id']} at {session['company']} ({session['domain']}): {state}")
    if session["scope"]:
        typer.echo(f"scope: {session['scope']}")
    typer.echo(f"token: {session['token_reference']}")
    if session.get("account_reference"):
        typer.echo(f"account token: {session['account_reference']}")


def _scopes(scope: list[str] | None, company: DiscoveredCompany, kind: str) -> tuple[str, ...]:
    if scope:
        return tuple(scope)
    auth = company.document.auth
    option = getattr(auth, kind, None) if auth is not None else None
    if option is None or not option.scopes:
        raise NotConfiguredError("no_scopes", f"The company offers no {kind} sign-in scopes")
    return tuple(option.scopes)


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
            company = await company_of(runtime, str(selected))
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
            return session_view(record)

        run(work, json_output=json_output, render=_render_session, no_input=no_input)

    @sessions.command("renew")
    def sessions_renew(
        session_id: str = typer.Argument(...),
        json_output: bool = JSON,
        no_input: bool = NO_INPUT,
    ) -> None:
        """Get a new Session Token: with the Account Token when signed in (§4.2, §4.8)."""

        async def work(runtime: CliRuntime) -> dict[str, Any]:
            record = runtime.session(session_id)
            if record.account_reference is not None:
                result = await AccountTokenClient(
                    reactor=runtime.reactor, http_client=runtime.http
                ).refresh(
                    record.account_reference,
                    context=account_context(record),
                    session_id=session_id,
                )
                if result.status == "signed_in" and result.token is not None:
                    await _keep(runtime, record, result.token)
                    return session_view(record)
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
            return session_view(record)

        run(work, json_output=json_output, render=_render_session, no_input=no_input)

    @sessions.command("show")
    def sessions_show(
        session_id: str | None = typer.Argument(None),
        json_output: bool = JSON,
    ) -> None:
        """Show the Sessions this agent holds (opaque references, never tokens)."""

        async def work(runtime: CliRuntime) -> dict[str, Any]:
            return await show_sessions(runtime, session_id)

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
            return await end_session(runtime, session_id)

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
            record = runtime.session(session_id)
            company = await company_of(runtime, record.domain)
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
            await _keep(
                runtime, record, result.token, account_reference=result.account_token_reference
            )
            return {**session_view(record), "missing_scopes": list(result.missing_scopes)}

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
            record = runtime.session(session_id)
            company = await company_of(runtime, record.domain)
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
                organization=company.document.organization,
                poppy_domains=metadata.poppy_domains,
            )
            link = started.verification_uri_complete or started.verification_uri
            # The company that asks, by name and domain, with the link and code (§4.6).
            typer.echo(
                f"Sign in to {started.organization_name} ({started.organization_domain}) "
                f"at {link} with the code {started.user_code}.",
                err=True,
            )
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
                    return {**session_view(record), "missing_scopes": list(polled.missing_scopes)}
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
            record = runtime.session(session_id)
            company = await company_of(runtime, record.domain)
            auth_document = company.document.auth
            if auth_document is None or auth_document.mediated is None:
                raise NotConfiguredError("no_mediated", "The company offers no Mediated Sign-In")
            client = MediatedSignInClient(reactor=runtime.reactor, http_client=runtime.http)
            token = await session_token(runtime, record)
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
                result = await client.submit_code(result.reference, token=token, **who_of(record))
            if result.status != "complete" or result.token is None:
                raise PersonalAgentProtocolError(
                    f"sign_in_{result.status}", "Mediated Sign-In did not complete"
                )
            await _keep(
                runtime, record, result.token, account_reference=result.account_token_reference
            )
            return {**session_view(record), "missing_scopes": list(result.missing_scopes)}

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
            return await disconnect(runtime, session_id)

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
            record = runtime.session(session_id)
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
                token=await session_token(runtime, record),
                body=body if body is not None or method.upper() == "GET" else {},
                **who_of(record),
            )
            if answer.operation is not None:
                return {"status": answer.status, **operation_view(answer.operation)}
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
        """Call the company's MCP server with a token issued for its url only (§4.3).

        DPoP with proofs when its protected resource metadata says it supports
        DPoP, a Bearer token otherwise.
        """

        async def work(runtime: CliRuntime) -> dict[str, Any]:
            record = runtime.session(session_id)
            company = await company_of(runtime, record.domain)
            server = mcp_api(company.document)
            if server is None:
                raise NotConfiguredError("no_mcp", "The company lists no MCP server")
            served = await fetch_mcp_server_metadata(runtime.http, server.url, issuer=record.issuer)
            token = None
            if record.account_reference is not None:
                result = await AccountTokenClient(
                    reactor=runtime.reactor, http_client=runtime.http
                ).token_for_mcp(
                    record.account_reference,
                    context=account_context(record),
                    session_id=session_id,
                    resource=server.url,
                    dpop=served.supports_dpop,
                )
                token = result.token
            if token is None:
                token = await SessionClient(
                    reactor=runtime.reactor, http_client=runtime.http
                ).token_for_mcp(
                    client_id=record.client_id,
                    pairwise_user_id=record.pairwise_user_id,
                    issuer=record.issuer,
                    token_endpoint=record.token_endpoint,
                    tenant_id=record.tenant_id,
                    session_id=session_id,
                    resource=server.url,
                    dpop=served.supports_dpop,
                )
            await runtime.secrets.put(f"mcp:{session_id}", token.access_token)
            client = McpClient(
                http_client=runtime.http,
                token=token,
                url=server.url,
                reactor=runtime.reactor,
                who=who_of(record),
            )
            if tool is None:
                return {"tools": await client.list_tools()}
            answer = await client.call_tool(tool, json.loads(arguments))
            payload: dict[str, Any] = {
                "content": answer.content,
                "structured_content": answer.structured_content,
                "is_error": answer.is_error,
            }
            if answer.operation is not None:
                payload.update(operation_view(answer.operation))
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
            record = runtime.session(session_id)
            client, endpoint = await conversation_client(runtime, record)
            answer = await client.start(
                endpoint,
                _message(runtime.reactor, text, human),
                token=await session_token(runtime, record),
                wait=wait,
                **who_of(record),
            )
            return answer.model_dump(mode="json")

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
            record = runtime.session(session_id)
            client, endpoint = await conversation_client(runtime, record)
            answer = await client.send(
                endpoint,
                conversation_id,
                _message(runtime.reactor, text, human),
                token=await session_token(runtime, record),
                wait=wait,
                **who_of(record),
            )
            return answer.model_dump(mode="json")

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
            return await read_events(runtime, session_id, conversation_id, cursor)

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

        def show(text: str) -> None:
            if not json_output:
                typer.echo(f"… {text}", err=True)

        async def work(runtime: CliRuntime) -> dict[str, Any]:
            return await follow_events(
                runtime,
                session_id,
                conversation_id,
                last_event_id=last_event_id,
                max_events=max_events,
                on_text=show,
            )

        run(work, json_output=json_output, render=_render_page)

    @conversations.command("handoff")
    def conversations_handoff(
        session_id: str = typer.Argument(...),
        conversation_id: str = typer.Argument(...),
        json_output: bool = JSON,
    ) -> None:
        """Ask for a person at the company (§7.9)."""

        async def work(runtime: CliRuntime) -> dict[str, Any]:
            record = runtime.session(session_id)
            client, endpoint = await conversation_client(runtime, record)
            receipt = await client.handoff(
                endpoint,
                conversation_id,
                token=await session_token(runtime, record),
                **who_of(record),
            )
            return receipt.model_dump(mode="json")

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
            record = runtime.session(session_id)
            client, endpoint = await conversation_client(runtime, record)
            answer = await client.start_direct(
                endpoint,
                parent_id,
                _message(runtime.reactor, text, True),
                token=await session_token(runtime, record),
                **who_of(record),
            )
            return answer.model_dump(mode="json")

        run(work, json_output=json_output, render=_render_receipt_or_page)

    @conversations.command("close")
    def conversations_close(
        session_id: str = typer.Argument(...),
        conversation_id: str = typer.Argument(...),
        json_output: bool = JSON,
    ) -> None:
        """Close the conversation; what it started is not cancelled (§7.12)."""

        async def work(runtime: CliRuntime) -> dict[str, Any]:
            record = runtime.session(session_id)
            client, endpoint = await conversation_client(runtime, record)
            receipt = await client.close(
                endpoint,
                conversation_id,
                token=await session_token(runtime, record),
                **who_of(record),
            )
            return receipt.model_dump(mode="json")

        run(work, json_output=json_output, render=_render_receipt_or_page)

    # operations ------------------------------------------------------------------------

    @operations.command("show")
    def operations_show(
        session_id: str = typer.Argument(...),
        operation_id: str = typer.Argument(...),
        json_output: bool = JSON,
    ) -> None:
        """Read an operation by its ID (Operations §6)."""

        async def work(runtime: CliRuntime) -> dict[str, Any]:
            return await show_operation(runtime, session_id, operation_id)

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
            record = runtime.session(session_id)
            client, endpoint, company_name = await operations_client(runtime, record)
            operation = await client.read(
                endpoint, operation_id, token=await session_token(runtime, record), **who_of(record)
            )
            if operation.revision != revision:
                raise NotApprovedError(
                    "revision_changed", f"The current revision is {operation.revision}"
                )
            if no_input:
                raise InputRequiredError("input_required", "The user approves at the prompt")
            surface = optional_contribution(runtime.reactor, APPROVAL_SURFACES, "approval surface")
            if surface is not None:
                # The host's own approval surface asks the user.
                answer = await cast(ApprovalSurface, surface).approve(
                    ApprovalRequest(
                        action_id="operations.approve",
                        action_name="Approve an operation",
                        summary=f"{company_name} asks to: {operation.summary}",
                        arguments={"operation_id": operation_id, "revision": str(revision)},
                        tenant_id=runtime.tenant_id,
                    )
                )
                if answer is not True:
                    raise NotApprovedError("not_approved", "The user did not approve")
            else:
                if not user_terminal():
                    # Approval is the user's, typed at their terminal: never piped input,
                    # which a script or a model's tool could write (Operations §5.1).
                    raise InputRequiredError(
                        "input_required", "The user approves at a terminal, not from piped input"
                    )
                typer.echo(f"{company_name} asks to:", err=True)
                typer.echo(f"  {operation.summary}", err=True)
                typer.echo(f"  (operation {operation_id}, revision {revision})", err=True)
                typed = typer.prompt("Type the operation ID to approve", err=True)
                if typed.strip() != operation_id:
                    raise NotApprovedError("not_approved", "The user did not approve")
            approval = approve(operation)
            stored = {**approval.model_dump(mode="json"), "session_id": session_id}
            store = first_contribution(runtime.reactor, TOKEN_STORES, "token store")
            # Bound to a key in the protected token store: an approval written into
            # state.json by anything else does not verify at confirm.
            stored["mac"] = approval_mac(await approval_key(store), stored)
            runtime.state.approvals[operation_id] = stored
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
            record = runtime.session(session_id)
            approved = runtime.state.approvals.get(operation_id)
            if approved is None or approved.get("revision") != revision:
                raise NotApprovedError(
                    "not_approved", "No approval for this operation ID and revision"
                )
            store = first_contribution(runtime.reactor, TOKEN_STORES, "token store")
            mac = approval_mac(await approval_key(store), approved)
            if (
                approved.get("session_id") != session_id
                or not isinstance(approved.get("mac"), str)
                or not hmac.compare_digest(approved["mac"], mac)
            ):
                raise NotApprovedError(
                    "not_approved", "This approval was not made here: approve at the prompt"
                )
            client, endpoint, _ = await operations_client(runtime, record)
            token = await session_token(runtime, record)
            operation = await client.read(endpoint, operation_id, token=token, **who_of(record))
            approval = UserApproval.model_validate(
                {key: approved[key] for key in ("operation_id", "revision", "digest")}
            )
            try:
                outcome = await client.confirm(
                    endpoint, operation, approval=approval, token=token, **who_of(record)
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
            payload = operation_view(cast(Operation, outcome.operation))
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
            return await cancel_operation(runtime, session_id, operation_id)

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

        payload = list_requirements(role=role, level=level, status=status, source=source)

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
            payload = show_requirement(requirement_id)
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

        _emit(payload, json_output, render)

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
