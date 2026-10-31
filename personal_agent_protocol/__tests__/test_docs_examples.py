# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Every Python code example in the README and the docs runs, as written.

Each ```python block of `README.md` and `docs/docs/**/*.mdx` is executed against
reference companies on an in-process network (`demo.kit`): `example.com`,
`shop.example`, `auth.example.com` and `auth.company.example` are Manzanita
under those names, `northwind.example` is the bank, and the personal agent is
`https://agent.example/agent.json`. A block that is a fragment gets the names it
uses (`reactor`, `metadata`, `session`, …) from its case below, made by really
discovering, starting a Session or signing in; a block's own clients (a bare
`DiscoveryClient()`, an `httpx.AsyncClient()`) reach the same network. A
top-level `asyncio.run(f())` runs as `await f()` in the test's loop. Each case
then checks what the example did. A block without a case fails: a new example
needs one. The ```json blocks are parsed by the wire model they show.
"""

from __future__ import annotations

import ast
import contextlib
import io
import json
import re
import types
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import SecretStr
from reactor import PluginManifest  # type: ignore[import-untyped]

import personal_agent_protocol
from personal_agent_protocol import (
    PAIRWISE_USER_ID_STORES,
    RATE_LIMIT_BUDGETS,
    DeviceSignInClient,
    DiscoveryClient,
    MediatedSignInClient,
    OperationsClient,
    ProtectedInputField,
    ProtectedInputRequest,
    SessionClient,
    SessionHttpClient,
    SqlitePairwiseUserIdStore,
    StreamReconnected,
    TextDelta,
    resolve_pairwise_user_id,
    terms_differences,
)
from personal_agent_protocol import discovery as discovery_module
from personal_agent_protocol import identity as identity_module
from personal_agent_protocol import reactor as reactor_module
from personal_agent_protocol.apis import ApiClient
from personal_agent_protocol.company import (
    CompanyConfig,
    MemoryCompanyStore,
    build_company,
    company_app,
)
from personal_agent_protocol.conversations import ConversationClient, generate_message_id
from personal_agent_protocol.demo import northwind as northwind_demo
from personal_agent_protocol.demo.kit import (
    AgentIdentity,
    ClockPlugin,
    InProcessNetwork,
    MutableClock,
    PersonalAgentHost,
    ScriptedApprovals,
    ScriptedBrowser,
    ScriptedInput,
    _Routing,
    personal_agent_reactor,
)
from personal_agent_protocol.demo.manzanita import ADA, ADA_CODE, ManzanitaPlugin
from personal_agent_protocol.models import Author, ClientMetadata, DiscoveryDocument, Message
from personal_agent_protocol.reactor import first_contribution, resolve_addresses

ROOT = Path(__file__).parents[2]
SOURCES = [ROOT / "README.md", *sorted((ROOT / "docs" / "docs").rglob("*.mdx"))]
FENCE = re.compile(r"^```(?P<language>\w+)[^\n]*\n(?P<code>.*?)^```", re.MULTILINE | re.DOTALL)
TENANT = "application-42"
LOCAL_USER = "local-user-42"
SCOPES = ("orders:read", "orders:write", "orders:return")
COMPANIES = {
    "example.com": "Example Company",
    "shop.example": "Example Shop",
    "auth.example.com": "Example Auth",
    "auth.company.example": "Example Company Auth",
}


def _blocks(language: str) -> dict[str, str]:
    found: dict[str, str] = {}
    for path in SOURCES:
        index = 0
        for match in FENCE.finditer(path.read_text()):
            if match["language"] == language:
                found[f"{path.relative_to(ROOT)}#{index}"] = match["code"]
                index += 1
    return found


PYTHON = _blocks("python")
JSON = _blocks("json")


class ApprovingBrowser(ScriptedBrowser):
    """The user's browser: opens the consent page, and the user approves at once.

    The company's redirect is what the example calls `incoming_callback_url`.
    """

    def __init__(self, docs: Docs) -> None:
        super().__init__(docs.http)
        self.docs = docs

    async def open(self, authorization_url: SecretStr) -> None:
        await super().open(authorization_url)
        host = httpx.URL(authorization_url.get_secret_value()).host
        callback = await self.docs.companies[host].approve_authorization(
            self.request_id, account_id="acct_ada"
        )
        self.docs.namespace["incoming_callback_url"] = callback


class Contributor:
    def __init__(self, point: object, value: object) -> None:
        self.point, self.value = point, value

    def provide_contributions(self, contributions: object) -> None:
        contributions.contribute(self.point, self.value, contribution_id="docs")  # type: ignore[attr-defined]


class Docs:
    """The world the examples run in."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        self.namespace: dict[str, Any] = {}
        self.monkeypatch = monkeypatch
        self.tmp_path = tmp_path
        self.clock = MutableClock()
        self.network = network = InProcessNetwork()

        class NetworkClient(httpx.AsyncClient):
            """`httpx.AsyncClient()` in an example reaches the in-process network."""

            def __init__(self, *args: Any, **kwargs: Any) -> None:
                kwargs.setdefault("transport", _Routing(network))
                super().__init__(*args, **kwargs)

        monkeypatch.setattr(httpx, "AsyncClient", NetworkClient)
        built = reactor_module.build_pap_reactor

        def build_pap_reactor(**kwargs: Any) -> Any:
            # A Reactor an example builds resolves the network's names, not the internet's.
            if kwargs.get("address_resolver", resolve_addresses) is resolve_addresses:
                kwargs["address_resolver"] = network.resolve
            return built(**kwargs)

        for module in (reactor_module, personal_agent_protocol, discovery_module, identity_module):
            monkeypatch.setattr(module, "build_pap_reactor", build_pap_reactor)

        self.agent = AgentIdentity(domain="agent.example", name="Example Agent")
        network.add(self.agent.domain, self.agent.website())
        self.companies = {domain: self._company(domain, name) for domain, name in COMPANIES.items()}
        self.northwind, self.bank = northwind_demo.northwind(network, self.clock)
        self.companies[northwind_demo.DOMAIN] = self.northwind
        self.http = network.client()
        self.browser = ApprovingBrowser(self)
        self.host = PersonalAgentHost(
            self.agent,
            self.clock,
            protected_input=ScriptedInput(dict(ADA), {"code": ADA_CODE}),
            approvals=ScriptedApprovals(always=True),
            browser=self.browser,
        )
        pairwise = SqlitePairwiseUserIdStore(tmp_path / "pairwise.sqlite3")
        self.reactor = personal_agent_reactor(
            self.host,
            network=network,
            http_client=self.http,
            plugins=[
                (
                    PluginManifest(name="pairwise", version="1"),
                    Contributor(PAIRWISE_USER_ID_STORES, pairwise),
                )
            ],
        )
        self.transport = SessionHttpClient(reactor=self.reactor, http_client=self.http)

    def _company(self, domain: str, name: str) -> Any:
        config = CompanyConfig(
            name=name,
            domain=domain,
            scopes=SCOPES,
            scope_descriptions={scope: f"The {scope} scope" for scope in SCOPES},
            write_scopes=("orders:write",),
            mediated_fields=(("email", "Email", False), ("password", "Password", True)),
        )
        service = build_company(
            config,
            http_client=self.network.client(),
            address_resolver=self.network.resolve,
            plugins=[
                (PluginManifest(name="manzanita", version="1"), ManzanitaPlugin()),
                (PluginManifest(name="clock", version="1"), ClockPlugin(self.clock)),
            ],
        )
        self.network.add(domain, company_app(service))
        return service

    # The steps the fragments start after ----------------------------------------------

    async def discovered(self, domain: str) -> Any:
        return await DiscoveryClient(reactor=self.reactor, http_client=self.http).discover(domain)

    async def pairwise(self, domain: str) -> str:
        """The User ID at the company, which names the user in its Sessions."""

        issuer = (await self.discovered(domain)).oauth_metadata.issuer
        return await resolve_pairwise_user_id(
            self.reactor, tenant_id=TENANT, local_user_id=LOCAL_USER, company_issuer=issuer
        )

    async def signed_out(self, domain: str) -> Any:
        company = await self.discovered(domain)
        return await SessionClient(reactor=self.reactor, http_client=self.http).start(
            client_id=self.agent.client_id,
            pairwise_user_id=await self.pairwise(domain),
            issuer=company.oauth_metadata.issuer,
            tenant_id=TENANT,
        )

    async def signed_in(self, domain: str, scopes: tuple[str, ...]) -> tuple[Any, Any, str]:
        """A Session and a Device Sign-In: its access token and refresh token reference."""

        metadata = (await self.discovered(domain)).oauth_metadata
        session = await self.signed_out(domain)
        device = DeviceSignInClient(reactor=self.reactor, http_client=self.http)
        started = await device.begin(
            device_authorization_endpoint=metadata.device_authorization_endpoint,
            token_endpoint=metadata.token_endpoint,
            issuer=metadata.issuer,
            client_id=self.agent.client_id,
            scopes=scopes,
            tenant_id=TENANT,
            organization=(await self.discovered(domain)).document.organization,
            protected_resources=metadata.protected_resources,
        )
        account = "acct_ada_northwind" if domain == northwind_demo.DOMAIN else "acct_ada"
        await self.companies[domain].approve_device(started.user_code, account_id=account)
        self.clock.advance(started.poll_interval)
        done = await device.poll(started.reference)
        assert done.status == "complete" and done.token is not None
        return session, done.token, str(done.refresh_token_reference)


Check = Callable[[dict[str, Any], str], Awaitable[None]]
Case = Callable[[Docs], Awaitable[tuple[dict[str, Any], Check]]]
CASES: dict[str, Case] = {}


def case(*keys: str) -> Callable[[Case], Case]:
    def register(function: Case) -> Case:
        for key in keys:
            CASES[key] = function
        return function

    return register


async def _nothing(namespace: dict[str, Any], out: str) -> None:
    return None


# Discovery and identity ------------------------------------------------------------------


@case("README.md#0", "docs/docs/getting-started/index.mdx#0", "docs/docs/sdk/python.mdx#0")
async def _discover_example_com(docs: Docs) -> tuple[dict[str, Any], Check]:
    async def check(namespace: dict[str, Any], out: str) -> None:
        assert "Example Company" in out

    return {}, check


@case("docs/docs/guides/cryptography.mdx#0")
async def _operator_signer(docs: Docs) -> tuple[dict[str, Any], Check]:
    async def check(namespace: dict[str, Any], out: str) -> None:
        assert namespace["signer"].key is namespace["key"]

    return {}, check


@case("docs/docs/guides/personal-agent.mdx#0")
async def _discover_top_level(docs: Docs) -> tuple[dict[str, Any], Check]:
    async def check(namespace: dict[str, Any], out: str) -> None:
        assert "Example Company" in out and "https://example.com/oauth/token" in out

    return {}, check


@case("README.md#1")
async def _discover_with_host(docs: Docs) -> tuple[dict[str, Any], Check]:
    contributed: list[str] = []

    class MySecurityPlugin:
        def provide_contributions(self, contributions: object) -> None:
            contributed.append("my-security")

    async def check(namespace: dict[str, Any], out: str) -> None:
        await namespace["discover_with_host"]()
        assert contributed == ["my-security"]

    return {"my_security_plugin": MySecurityPlugin()}, check


@case("docs/docs/sdk/python.mdx#1")
async def _agent_identity(docs: Docs) -> tuple[dict[str, Any], Check]:
    async def check(namespace: dict[str, Any], out: str) -> None:
        assert "Example Agent" in out and "key-1" in out

    return {}, check


@case("docs/docs/guides/operational-limits.mdx#0")
async def _cached_discovery(docs: Docs) -> tuple[dict[str, Any], Check]:
    fetched: list[str] = []
    app = docs.network.apps["shop.example"]

    async def counting(scope: Any, receive: Any, send: Any) -> None:
        if scope.get("path") == "/.well-known/poppy.json":
            fetched.append(scope["path"])
        await app(scope, receive, send)

    docs.network.add("shop.example", counting)

    async def check(namespace: dict[str, Any], out: str) -> None:
        assert namespace["company"].document.organization.domain == "shop.example"
        assert fetched == ["/.well-known/poppy.json"]  # the second came from pap.cache

    return {"reactor": docs.reactor}, check


@case("docs/docs/guides/operational-limits.mdx#1")
async def _shared_budget(docs: Docs) -> tuple[dict[str, Any], Check]:
    async def check(namespace: dict[str, Any], out: str) -> None:
        budget = first_contribution(namespace["reactor"], RATE_LIMIT_BUDGETS, "budget")
        assert type(budget).__name__ == "RedisBudget"

    return {}, check


# Sessions ---------------------------------------------------------------------------------


@case("docs/docs/guides/personal-agent.mdx#1", "docs/docs/sdk/python.mdx#2")
async def _session_start(docs: Docs) -> tuple[dict[str, Any], Check]:
    company = await docs.discovered("example.com")

    async def check(namespace: dict[str, Any], out: str) -> None:
        assert namespace["session"].client_id == "https://agent.example/agent.json"
        assert namespace["session"].sub.startswith("usr_")

    return {"reactor": docs.reactor, "http": docs.http, "company": company}, check


@case("docs/docs/guides/sessions.mdx#0")
async def _sessions(docs: Docs) -> tuple[dict[str, Any], Check]:
    async def check(namespace: dict[str, Any], out: str) -> None:
        session = namespace["session"]
        assert session.handle == f"ses_{session.sid}"
        assert session.issuer == "https://auth.company.example"

    return {"reactor": docs.reactor}, check


# Sign-in ----------------------------------------------------------------------------------


@case("docs/docs/guides/direct-sign-in.mdx#0")
async def _direct_sign_in(docs: Docs) -> tuple[dict[str, Any], Check]:
    async def check(namespace: dict[str, Any], out: str) -> None:
        assert "('orders:read',) ()" in out
        assert namespace["refresh_reference"]

    return {"reactor": docs.reactor}, check


@case("docs/docs/guides/device-sign-in.mdx#0")
async def _device_sign_in(docs: Docs) -> tuple[dict[str, Any], Check]:
    company = await docs.discovered("shop.example")
    shown: list[str] = []
    scheduled: list[Any] = []

    async def check(namespace: dict[str, Any], out: str) -> None:
        assert (
            shown[0].startswith("https://shop.example/")
            and shown[1] == namespace["started"].user_code
        )
        assert namespace["result"].status == "pending" and scheduled

    return {
        "DeviceSignInClient": DeviceSignInClient,
        "reactor": docs.reactor,
        "http": docs.http,
        "metadata": company.oauth_metadata,
        "company": company,
        "show_to_user": shown.append,
        "schedule_at": scheduled.append,
    }, check


@case("docs/docs/guides/mediated-sign-in.mdx#0")
async def _protected_input(docs: Docs) -> tuple[dict[str, Any], Check]:
    async def native_secure_form(request: ProtectedInputRequest) -> dict[str, SecretStr]:
        return {field.name: SecretStr(f"typed {field.name}") for field in request.fields}

    async def check(namespace: dict[str, Any], out: str) -> None:
        request = ProtectedInputRequest(
            purpose="credentials",
            company_name="Example Shop",
            company_domain="shop.example",
            issuer="https://shop.example",
            fields=(ProtectedInputField(name="password", label="Password", secret=True),),
        )
        answer = await namespace["PasswordSheet"]().collect(request)
        assert answer["password"].get_secret_value() == "typed password"

    return {"SecretStr": SecretStr, "native_secure_form": native_secure_form}, check


@case("docs/docs/guides/mediated-sign-in.mdx#1")
async def _mediated_sign_in(docs: Docs) -> tuple[dict[str, Any], Check]:
    company = await docs.discovered("shop.example")

    async def check(namespace: dict[str, Any], out: str) -> None:
        assert namespace["result"].status == "complete"
        assert namespace["result"].token.scopes == ("orders:read",)

    return {
        "MediatedSignInClient": MediatedSignInClient,
        "reactor": docs.reactor,
        "http": docs.http,
        "company": company,
        "client_id": (await docs.signed_out("shop.example")).client_id,
    }, check


@case("docs/docs/guides/account-tokens.mdx#0")
async def _account_tokens(docs: Docs) -> tuple[dict[str, Any], Check]:
    company = await docs.discovered("shop.example")
    _, _, reference = await docs.signed_in("shop.example", ("orders:read",))
    asked: list[str] = []

    async def check(namespace: dict[str, Any], out: str) -> None:
        assert namespace["result"].status == "signed_in" and asked == []
        assert namespace["result"].token.scopes == ("orders:read",)

    return {
        "reactor": docs.reactor,
        "http": docs.http,
        "metadata": company.oauth_metadata,
        "refresh_token_reference": reference,
        "ask_the_user_to_sign_in_again": lambda: asked.append("again"),
        "continue_signed_out": lambda: asked.append("signed out"),
    }, check


# Conversations and operations ----------------------------------------------------------


@case("docs/docs/guides/conversations.mdx#0")
async def _stream(docs: Docs) -> tuple[dict[str, Any], Check]:
    company = await docs.discovered("shop.example")
    session = await docs.signed_out("shop.example")
    endpoint = company.document.agent.protocols[0].endpoint
    conversations = ConversationClient(transport=docs.transport)
    message = Message(
        id=generate_message_id(docs.reactor), author=Author(type="human"), text="Hello"
    )
    page = await conversations.start(endpoint, message, session=session, wait=0)
    await conversations.close(endpoint, page.conversation_id, session=session)
    handled: list[Any] = []

    class Ui:
        def show_typing(self, message_id: str, text: str) -> None: ...

        def drop_partial(self, message_ids: Any) -> None: ...

    async def check(namespace: dict[str, Any], out: str) -> None:
        assert [event.type for event in handled][:1] == ["message"]

    return {
        "conversations": conversations,
        "endpoint": endpoint,
        "conversation_id": page.conversation_id,
        "session": session,
        "ui": Ui(),
        "handle_event": handled.append,
        "TextDelta": TextDelta,
        "StreamReconnected": StreamReconnected,
    }, check


async def _proposed(docs: Docs, domain: str) -> dict[str, Any]:
    """A signed-in Session and an operation its company proposed (an exchange)."""

    session, token, _ = await docs.signed_in(domain, ("orders:read", "orders:write"))
    proposed = await ApiClient(transport=docs.transport).call(
        "POST",
        f"https://{domain}/api/orders/ord_7Hk2/exchanges",
        session=session,
        token=token,
        body={},
    )
    return {"session": session, "token": token, "operation": proposed.operation}


@case("docs/docs/guides/operations.mdx#0")
async def _operations_client(docs: Docs) -> tuple[dict[str, Any], Check]:
    async def check(namespace: dict[str, Any], out: str) -> None:
        assert namespace["negotiated"] is True
        assert isinstance(namespace["operations"], OperationsClient)

    return {
        "reactor": docs.reactor,
        "discovered": await docs.discovered("shop.example"),
        "my_client_metadata": ClientMetadata.model_validate(docs.agent.metadata),
    }, check


@case("docs/docs/guides/operations.mdx#1")
async def _approve(docs: Docs) -> tuple[dict[str, Any], Check]:
    proposed = await _proposed(docs, "shop.example")
    surface = docs.host.approvals
    assert surface is not None

    async def check(namespace: dict[str, Any], out: str) -> None:
        assert namespace["sent"].status == "answered"
        assert namespace["sent"].answer.body["summary"].startswith("Exchanged")
        assert surface.asked[0].summary == proposed["operation"].summary

    return {
        **proposed,
        "api": ApiClient(transport=docs.transport),
        "url": "https://shop.example/api/orders/ord_7Hk2/exchanges",
        "body": {},
        "organization": (await docs.discovered("shop.example")).document.organization,
        "tenant_id": "tenant",
        "operations": OperationsClient(reactor=docs.reactor),
    }, check


@case("docs/docs/guides/operations.mdx#2")
async def _terms_check(docs: Docs) -> tuple[dict[str, Any], Check]:
    proposed = await _proposed(docs, "shop.example")

    return {"operation": proposed["operation"], "terms_differences": terms_differences}, _nothing


@case("docs/docs/guides/operations.mdx#3")
async def _confirm_display(docs: Docs) -> tuple[dict[str, Any], Check]:
    proposed = await _proposed(docs, "shop.example")
    operation = proposed["operation"]

    async def check(namespace: dict[str, Any], out: str) -> None:
        from personal_agent_protocol.ui import PAP_CONFIRM_TYPE

        shown = namespace["meta"]["reactor.ui/display"]
        assert shown["type"] == PAP_CONFIRM_TYPE and shown["data"]["summary"] == operation.summary
        assert namespace["said"].startswith(
            f"shop.example asks you to approve: {operation.summary}"
        )
        assert "ses_docs" not in json.dumps(namespace["display"].model_view())

    return {
        "operation": operation,
        "session_key": "ses_docs",
        "terms_differences": terms_differences,
    }, check


# Companies --------------------------------------------------------------------------------


@case("docs/docs/guides/company.mdx#0")
async def _company(docs: Docs) -> tuple[dict[str, Any], Check]:
    async def check(namespace: dict[str, Any], out: str) -> None:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=namespace["app"]),
            base_url="https://manzanita.example",
        ) as client:
            document = (await client.get("/.well-known/poppy.json")).json()
        assert document["organization"] == {
            "name": "Manzanita Outfitters",
            "domain": "manzanita.example",
        }

    return {
        "http": docs.http,
        "manifest": PluginManifest(name="manzanita", version="1"),
        "my_company_plugin": ManzanitaPlugin(),
    }, check


@case("docs/docs/guides/company.mdx#1")
async def _store_kit(docs: Docs) -> tuple[dict[str, Any], Check]:
    async def check(namespace: dict[str, Any], out: str) -> None:
        await namespace["test_my_store_conforms"]()

    return {"MyDatabaseStore": lambda url: MemoryCompanyStore(), "url": "memory://"}, check


@case("docs/docs/guides/company.mdx#2")
async def _hosted_pages(docs: Docs) -> tuple[dict[str, Any], Check]:
    async def check(namespace: dict[str, Any], out: str) -> None:
        assert "{request_id}" in namespace["config"].consent_page

    return {"CompanyConfig": CompanyConfig}, check


@case("docs/docs/guides/company.mdx#3")
async def _aliases(docs: Docs) -> tuple[dict[str, Any], Check]:
    async def check(namespace: dict[str, Any], out: str) -> None:
        import httpx

        from personal_agent_protocol.company import build_company

        config = namespace["config"]
        async with httpx.AsyncClient() as http:
            service = build_company(config, http_client=http)
            assert (
                service.discovery_document("orders.example.com")["organization"]["domain"]
                == "orders.example.com"
            )
            resources = service.oauth_metadata()["protected_resources"]
            assert f"https://{config.domain}" in resources
            assert "https://orders.example.com" in resources

    return {"CompanyConfig": CompanyConfig}, check


# CLI and extensions -----------------------------------------------------------------------


@case("docs/docs/guides/cli.mdx#0")
async def _cli_plugin(docs: Docs) -> tuple[dict[str, Any], Check]:
    async def check(namespace: dict[str, Any], out: str) -> None:
        import typer
        from typer.testing import CliRunner

        manifest, implementation = namespace["plugin"]()
        assert manifest.name == "acme.pap.cli"
        cli = typer.Typer()

        @cli.callback()
        def main() -> None: ...

        implementation.provide_cli(cli)
        result = CliRunner().invoke(cli, ["acme", "inspect"])
        assert result.exit_code == 0 and "Acme inspection" in result.output

    return {}, check


@case("docs/docs/guides/cli.mdx#1")
async def _live_session_actions(docs: Docs) -> tuple[dict[str, Any], Check]:
    from personal_agent_protocol.cli_host import NotConfiguredError

    # The CLI's personal agent keeps its state and profile under the test's directory.
    docs.monkeypatch.setenv("XDG_STATE_HOME", str(docs.tmp_path / "state"))
    docs.monkeypatch.setenv("XDG_CONFIG_HOME", str(docs.tmp_path / "config"))
    asked: list[tuple[str, str]] = []

    class Studio:
        async def confirm(self, *, title: str, text: str) -> bool:
            asked.append((title, text))
            return True

    async def check(namespace: dict[str, Any], out: str) -> None:
        assert out.strip() == "[]"
        assert "pap.sessions.end" in namespace["repl"]
        # Approved by Studio's dialog, then: no such Session.
        with pytest.raises(NotConfiguredError):
            await namespace["platform"].execute_command(
                "pap.sessions.end", {"session": "ses_docs_0000000000000"}
            )
        assert asked == [
            ("End a PAP Session", "End Session ses_docs_0000000000000 and forget its token.")
        ]

    return {"studio": Studio()}, check


@case("docs/docs/guides/telemetry.mdx#0")
async def _telemetry(docs: Docs) -> tuple[dict[str, Any], Check]:
    pytest.importorskip("opentelemetry.sdk")
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    # The host's tracer provider, as the example's `trace.get_tracer` finds it.
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    docs.monkeypatch.setattr(trace, "get_tracer", provider.get_tracer)

    async def check(namespace: dict[str, Any], out: str) -> None:
        (span,) = exporter.get_finished_spans()
        assert span.name == "pap.discovery.discover"
        assert dict(span.attributes or {}) == {
            "pap.company.domain": "example.com",
            "pap.company.issuer": "https://example.com",
            "pap.stage": "discovery",
            "pap.outcome": "ok",
        }

    return {}, check


@case("docs/docs/guides/extensions.mdx#0")
async def _negotiation(docs: Docs) -> tuple[dict[str, Any], Check]:
    return {}, _nothing


# The runner -------------------------------------------------------------------------------


async def run(code: str, namespace: dict[str, Any]) -> str:
    """Run one example in `namespace`, top-level `await` allowed; what it printed."""

    source = re.sub(r"^asyncio\.run\((.+)\)$", r"await \1", code, flags=re.MULTILINE)
    compiled = compile(source, "<docs example>", "exec", flags=ast.PyCF_ALLOW_TOP_LEVEL_AWAIT)
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        result = eval(compiled, namespace)  # noqa: S307 - the docs' own examples
        if isinstance(result, types.CoroutineType):
            await result
    return out.getvalue()


def test_every_python_example_has_a_case() -> None:
    assert PYTHON, "no Python examples were found"
    assert sorted(PYTHON) == sorted(CASES)


@pytest.mark.asyncio
@pytest.mark.parametrize("key", sorted(PYTHON))
async def test_the_python_example_runs(
    key: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    docs = Docs(monkeypatch, tmp_path)
    given, check = await CASES[key](docs)
    namespace: dict[str, Any] = {"__name__": "docs_example", **given}
    docs.namespace = namespace
    out = await run(PYTHON[key], namespace)
    await check(namespace, out)


@pytest.mark.parametrize("key", sorted(JSON))
def test_the_json_example_is_valid(key: str) -> None:
    value = json.loads(JSON[key])
    if "protocol_version" in value:
        DiscoveryDocument.model_validate(value)
    else:
        DiscoveryDocument.model_validate(
            {
                "protocol_version": "0.3",
                "organization": {"name": "Example", "domain": "example.com"},
                "auth": {"issuer": "https://example.com", "scopes": {"a:read": "Read a"}},
                "agent": {"protocols": [{"type": "poppy", "endpoint": "https://example.com/c"}]},
                **value,
            }
        )


# The Pydantic AI examples ----------------------------------------------------------------

EXAMPLES = sorted((ROOT / "examples" / "pydantic-ai").glob("*/app.py"))
#: What a model would pass the examples' tools that take arguments.
TOOL_ARGUMENTS = {
    "discover_pap_company": ("example.com",),
    "inspect_pap_agent": ("https://agent.example/agent.json",),
    "explain_session_jwt": ("POST", "https://shop.example/poppy/conversations"),
}


@pytest.mark.asyncio
@pytest.mark.parametrize("path", EXAMPLES, ids=lambda path: path.parent.name)
async def test_every_tool_of_the_pydantic_ai_example_runs(
    path: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    pytest.importorskip("pydantic_ai")
    import runpy

    Docs(monkeypatch, tmp_path)  # the network the tools reach
    namespace = runpy.run_path(str(path), run_name="pap_example")
    tools = {
        name: tool
        for toolset in namespace["agent"].toolsets
        for name, tool in getattr(toolset, "tools", {}).items()
    }
    assert tools, f"{path.parent.name} gives its agent no tool"
    for name, tool in tools.items():
        result = tool.function(*TOOL_ARGUMENTS.get(name, ()))
        if hasattr(result, "__await__"):
            result = await result
        json.dumps(result, default=str)
        assert result, f"{name} returned nothing"
