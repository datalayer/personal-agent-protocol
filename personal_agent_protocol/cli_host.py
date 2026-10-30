# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""The personal agent the `pap` command line runs: its Reactor host and local state.

Every protocol command builds one `CliRuntime`: a PAP Reactor host whose
replaceable parts are contributions, defaulting to local files under
`$XDG_STATE_HOME/pap` (mode 0600, written atomically):

- `pap.tokenStore` — `FileSecretStore`: Session, Account, and Bearer tokens
  behind opaque references (`secrets.json`). A keyring plugin replaces it
  with a lower `order`.
- `pap.signer`, `pap.sessionSigner` and `pap.dpopProver` — `FileKeyStore`: the agent's
  signing key (imported once, from protected input) and one delegated key per
  user and company (`keys.json`).
- `pap.pairwiseUserIdStore` — SQLite (`pairwise.sqlite3`).
- `pap.protectedInput` — `TerminalInput`: a hidden prompt, stdin, or a file
  descriptor, never a command-line option; `--no-input` refuses to ask.
- `pap.browserHandoff` — the user's own browser (`webbrowser`), the URL also
  printed to stderr.

Installed plugins under the `personal_agent_protocol.plugins` entry-point
group are discovered after these defaults, so a host can replace any of them.
What is not secret — Sessions, conversations' Sessions, approvals — is kept in
`state.json`, and only opaque references are ever printed.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import fcntl
import hashlib
import hmac
import json
import os
import secrets
import sys
import tempfile
import webbrowser
from collections.abc import AsyncIterator, Awaitable, Callable, Iterable, Iterator
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Literal, cast

import httpx
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from pydantic import SecretStr
from reactor import PluginManifest, PluginPlatform  # type: ignore[import-untyped]

from .crypto import (
    ContributedSigner,
    DelegatedKey,
    DelegatedSessionSigner,
    DpopKey,
    JoseDpopProver,
    JoseSigner,
    dpop_key_from,
    jwk_thumbprint,
    new_dpop_key,
)
from .errors import PersonalAgentProtocolError
from .json import loads_strict
from .pairwise import SqlitePairwiseUserIdStore
from .reactor import (
    AUTHORIZATION_STATE_STORES,
    BROWSER_HANDOFFS,
    CLOCKS,
    DPOP_PROVERS,
    PAIRWISE_USER_ID_STORES,
    PROTECTED_INPUTS,
    SESSION_SIGNERS,
    SIGNERS,
    TOKEN_STORES,
    AddressResolver,
    Clock,
    ProtectedInputRequest,
    build_pap_reactor,
    first_contribution,
    resolve_addresses,
)
from .sessions import PapSession

HOST_PLUGIN_GROUP = "personal_agent_protocol.plugins"


class InputRequiredError(PersonalAgentProtocolError):
    """Protected input is needed, and `--no-input` (or no terminal) forbids asking."""


class NotConfiguredError(PersonalAgentProtocolError):
    """The command needs local setup first: a key, a profile value, or a known Session."""


def default_state_dir() -> Path:
    root = os.environ.get("XDG_STATE_HOME")
    base = Path(root).expanduser() if root else Path.home() / ".local" / "state"
    return base / "pap"


def _write_private(path: Path, document: object) -> None:
    """Atomically replace `path` with JSON readable only by its owner."""

    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(dir=path.parent, prefix=".pap-", suffix=".json")
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(document, stream, indent=2, sort_keys=True)
            stream.write("\n")
        os.chmod(temporary, 0o600)
        Path(temporary).replace(path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


def _read(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    value = loads_strict(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError(f"{path.name} must hold a JSON object")
    return value


@contextlib.contextmanager
def _locked(path: Path) -> Iterator[None]:
    """Hold an exclusive lock on `path`'s lock file: one read-modify-write at a time.

    Two `pap` processes changing the same file (a refresh rotating an Account
    Token while another command stores one) would otherwise each write back
    what they read, and one change would be lost.
    """

    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(path.with_name(f".{path.name}.lock"), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


#: The token-store reference of the key that binds the user's approvals in `state.json`.
APPROVAL_KEY_REFERENCE = "pap:approval-key"


class FileSecretStore:
    """`pap.tokenStore`: secrets behind opaque references, in one owner-only file.

    Each change reads, changes, and writes the file under an exclusive lock.
    """

    def __init__(self, path: Path) -> None:
        self.path = path

    async def put(self, reference: str, token: SecretStr) -> None:
        with _locked(self.path):
            values = _read(self.path)
            values[reference] = token.get_secret_value()
            _write_private(self.path, values)

    async def get(self, reference: str) -> SecretStr | None:
        value = _read(self.path).get(reference)
        return SecretStr(value) if isinstance(value, str) else None

    async def delete(self, reference: str) -> None:
        with _locked(self.path):
            values = _read(self.path)
            if values.pop(reference, None) is not None:
                _write_private(self.path, values)

    async def get_or_create(self, reference: str, make: Callable[[], str]) -> SecretStr:
        """The secret at `reference`, created once (under the lock) when absent."""

        with _locked(self.path):
            values = _read(self.path)
            value = values.get(reference)
            if not isinstance(value, str):
                value = make()
                values[reference] = value
                _write_private(self.path, values)
        return SecretStr(value)

    def references(self) -> list[str]:
        return sorted(_read(self.path))


class MemoryStateStore:
    """`pap.authorizationStateStore`: one-use sign-in state, for one command's lifetime."""

    def __init__(self, now: Callable[[], datetime]) -> None:
        self.now = now
        self.values: dict[str, tuple[object, datetime]] = {}

    async def put(self, reference: str, value: object, *, expires_at: datetime) -> None:
        self.values[reference] = (value, expires_at)

    async def take(self, reference: str) -> object | None:
        value, expires_at = self.values.pop(reference, (None, None))
        if expires_at is not None and self.now() > expires_at:
            return None
        return value


class FileKeyStore:
    """The agent's signing key and its per-user delegated keys, private to the owner."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def import_signing_key(self, pem: SecretStr, *, kid: str) -> dict[str, str]:
        """Keep the agent's private signing key; answer only its public identity."""

        key = serialization.load_pem_private_key(pem.get_secret_value().encode(), password=None)
        if isinstance(key, ec.EllipticCurvePrivateKey) and isinstance(key.curve, ec.SECP256R1):
            algorithm = "ES256"
        elif isinstance(key, rsa.RSAPrivateKey) and key.key_size >= 2048:
            algorithm = "PS384"
        else:
            raise ValueError("the signing key must be P-256 (ES256) or RSA of 2048 bits or more")
        with _locked(self.path):
            document = _read(self.path)
            document["signing"] = {"kid": kid, "alg": algorithm, "pem": pem.get_secret_value()}
            _write_private(self.path, document)
        return self.signing_identity() or {}

    def signing_identity(self) -> dict[str, str] | None:
        """The signing key's reference, algorithm, and public JWK thumbprint — no secret."""

        signing = _read(self.path).get("signing")
        if not isinstance(signing, dict):
            return None
        public = _public_jwk(self._private(signing["pem"]))
        return {
            "key_reference": f"key:{signing['kid']}",
            "kid": signing["kid"],
            "alg": signing["alg"],
            "thumbprint": _thumbprint(public),
        }

    def signer(self) -> JoseSigner | None:
        signing = _read(self.path).get("signing")
        if not isinstance(signing, dict):
            return None
        return JoseSigner(
            self._private(signing["pem"]), algorithm=signing["alg"], key_id=signing["kid"]
        )

    # `DelegatedKeyCustody` (crypto.py): one delegated key per User ID (§5.2), kept in the
    # key file under tenant, issuer and User ID until it rotates.

    async def current(self, *, tenant_id: str, issuer: str, sub: str) -> DelegatedKey | None:
        stored = _read(self.path).get("delegated", {}).get(f"{tenant_id}|{issuer}|{sub}")
        if stored is None:
            return None
        private = cast(ec.EllipticCurvePrivateKey, self._private(stored["pem"]))
        public = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(private.public_key()))
        return DelegatedKey(
            private_key=private,
            public_jwk=public,
            thumbprint=jwk_thumbprint(public),
            delegation=SecretStr(stored["delegation"]),
            client_id=stored["client_id"],
            issued_at=datetime.fromisoformat(stored["issued_at"]),
            expires_at=datetime.fromisoformat(stored["expires_at"]),
        )

    async def replace(self, *, tenant_id: str, issuer: str, sub: str, key: DelegatedKey) -> None:
        with _locked(self.path):
            document = _read(self.path)
            document.setdefault("delegated", {})[f"{tenant_id}|{issuer}|{sub}"] = {
                "pem": key.private_key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                ).decode(),
                "delegation": key.delegation.get_secret_value(),
                "client_id": key.client_id,
                "issued_at": key.issued_at.isoformat(),
                "expires_at": key.expires_at.isoformat(),
            }
            _write_private(self.path, document)

    async def forget(self, *, tenant_id: str, issuer: str, sub: str) -> None:
        with _locked(self.path):
            document = _read(self.path)
            name = f"{tenant_id}|{issuer}|{sub}"
            if document.get("delegated", {}).pop(name, None) is not None:
                _write_private(self.path, document)

    @staticmethod
    def _private(pem: str) -> Any:
        return serialization.load_pem_private_key(pem.encode(), password=None)


class FileDpopKeys:
    """`DpopKeyCustody` in the key file: one DPoP key per Company for a tenant (§4.5).

    Kept there so a token stays bound across the CLI's runs.
    """

    def __init__(self, keys: FileKeyStore) -> None:
        self.path = keys.path

    async def key_for(self, *, tenant_id: str, issuer: str) -> DpopKey:
        with _locked(self.path):
            document = _read(self.path)
            kept = document.setdefault("dpop", {})
            stored = kept.get(f"{tenant_id}|{issuer}")
            if stored is not None:
                return dpop_key_from(
                    cast(ec.EllipticCurvePrivateKey, FileKeyStore._private(stored["pem"]))
                )
            key = new_dpop_key()
            kept[f"{tenant_id}|{issuer}"] = {
                "pem": key.private_key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                ).decode()
            }
            _write_private(self.path, document)
            return key

    async def forget(self, *, tenant_id: str, issuer: str) -> None:
        with _locked(self.path):
            document = _read(self.path)
            if document.get("dpop", {}).pop(f"{tenant_id}|{issuer}", None) is not None:
                _write_private(self.path, document)


def _public_jwk(key: Any) -> dict[str, Any]:
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return cast(dict[str, Any], json.loads(jwt.algorithms.ECAlgorithm.to_jwk(key.public_key())))
    return cast(dict[str, Any], json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key())))


def _thumbprint(jwk_value: dict[str, Any]) -> str:
    return jwk_thumbprint(jwk_value)


@dataclass
class InputSource:
    """Where protected input comes from for this command: never an option's value."""

    no_input: bool = False
    stdin: bool = False
    fd: int | None = None
    _lines: list[str] | None = None

    def lines(self) -> list[str]:
        if self._lines is None:
            if self.fd is not None:
                with os.fdopen(self.fd, encoding="utf-8", closefd=False) as stream:
                    self._lines = stream.read().splitlines()
            elif self.stdin:
                self._lines = sys.stdin.read().splitlines()
            else:
                self._lines = []
        return self._lines

    def read(self, label: str, *, secret: bool) -> SecretStr:
        if self.fd is not None or self.stdin:
            lines = self.lines()
            if not lines:
                raise InputRequiredError("input_required", f"{label} was not provided")
            return SecretStr(lines.pop(0))
        if self.no_input or not sys.stdin.isatty():
            raise InputRequiredError(
                "input_required", f"{label} is needed: use --stdin or --input-fd, or a terminal"
            )
        import typer

        return SecretStr(typer.prompt(label, hide_input=secret, err=True))


class TerminalInput:
    """`pap.protectedInput`: the user's own terminal (or stdin / a descriptor)."""

    def __init__(self, source: InputSource) -> None:
        self.source = source

    async def collect(self, request: ProtectedInputRequest) -> dict[str, SecretStr]:
        if request.sent_to:
            sys.stderr.write(f"{request.company_name} sent a code to {request.sent_to}.\n")
        return {
            item.name: self.source.read(f"{request.company_name} {item.label}", secret=item.secret)
            for item in request.fields
        }


class UserBrowser:
    """`pap.browserHandoff`: the user's own browser; the URL is never logged."""

    def __init__(self, open_browser: bool = True) -> None:
        self.open_browser = open_browser

    async def open(self, authorization_url: SecretStr) -> None:
        url = authorization_url.get_secret_value()
        sys.stderr.write(f"Open this page to sign in:\n  {url}\n")
        if self.open_browser:
            with contextlib.suppress(webbrowser.Error):
                webbrowser.open(url)


@dataclass
class SessionRecord:
    """A Session the CLI holds: everything but its tokens, which are in the token store.

    `id` is the CLI's handle for it, `ses_` and its first `sid`. `token_reference`
    is where its access token is kept once signed in.
    """

    id: str
    sid: str
    domain: str
    company: str
    issuer: str
    token_endpoint: str
    revocation_endpoint: str
    client_id: str
    tenant_id: str
    user: str
    pairwise_user_id: str
    token_reference: str
    signed_in: bool
    scope: str
    expires_at: str
    refresh_reference: str | None = None
    agent_id: str | None = None
    #: How its access token is sent (§4.5).
    token_type: Literal["Bearer", "DPoP"] = "Bearer"  # noqa: S105 - an OAuth token type
    #: The issuer's `dpop_signing_alg_values_supported`, for its refreshes (§4.5).
    dpop_signing_algs: list[str] | None = None

    def public(self) -> dict[str, Any]:
        """What may be printed: opaque references, never a token or the User ID."""

        value = asdict(self)
        value.pop("pairwise_user_id")
        return value


def approval_mac(key: SecretStr, approval: dict[str, Any]) -> str:
    """The MAC binding a stored approval to the user's approval key.

    It covers the operation ID, revision, and Session: an approval
    written into `state.json` by anything that cannot read the protected token
    store (another program, a tool a model runs) does not verify.
    """

    covered = json.dumps(
        [approval.get(name) for name in ("operation_id", "revision", "session")],
        separators=(",", ":"),
    )
    mac = hmac.new(key.get_secret_value().encode(), covered.encode(), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(mac).rstrip(b"=").decode()


async def approval_key(store: FileSecretStore | Any) -> SecretStr:
    """The approval key, kept in the protected token store, created on first use."""

    if isinstance(store, FileSecretStore):
        return await store.get_or_create(APPROVAL_KEY_REFERENCE, lambda: secrets.token_urlsafe(32))
    existing = await store.get(APPROVAL_KEY_REFERENCE)
    if existing is not None:
        return cast(SecretStr, existing)
    created = SecretStr(secrets.token_urlsafe(32))
    await store.put(APPROVAL_KEY_REFERENCE, created)
    return created


@dataclass
class CliState:
    """The non-secret local state: Sessions, operations to approve, user approvals.

    `operations` keeps each operation as the company returned it, with the request
    that returned it, sent again exactly with the approval (Operations 6).
    """

    path: Path
    sessions: dict[str, SessionRecord] = field(default_factory=dict)
    approvals: dict[str, dict[str, Any]] = field(default_factory=dict)
    operations: dict[str, dict[str, Any]] = field(default_factory=dict)

    @classmethod
    def load(cls, path: Path) -> CliState:
        document = _read(path)
        sessions = {
            key: SessionRecord(**value) for key, value in document.get("sessions", {}).items()
        }
        return cls(
            path=path,
            sessions=sessions,
            approvals=document.get("approvals", {}),
            operations=document.get("operations", {}),
        )

    def save(self) -> None:
        with _locked(self.path):
            _write_private(
                self.path,
                {
                    "schema_version": 1,
                    "sessions": {key: asdict(value) for key, value in self.sessions.items()},
                    "approvals": self.approvals,
                    "operations": self.operations,
                },
            )

    def session(self, session: str) -> SessionRecord:
        record = self.sessions.get(session)
        if record is None:
            raise NotConfiguredError("unknown_session", "No such Session: run `pap sessions start`")
        return record


@dataclass
class CliRuntime:
    """One command's personal agent: its Reactor, HTTP client, stores, and state."""

    reactor: PluginPlatform
    http: httpx.AsyncClient
    address_resolver: AddressResolver
    secrets: FileSecretStore
    keys: FileKeyStore
    state: CliState
    input: InputSource
    tenant_id: str = "pap-cli"
    #: How a command waits (Device Sign-In polling); a test or demo may move a clock.
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep
    #: The Sessions this command used: a new `sid` after `invalid_session` is kept.
    live: dict[str, PapSession] = field(default_factory=dict)

    def expires_at(self, expires_in: int) -> str:
        return (datetime.now(timezone.utc) + timedelta(seconds=expires_in)).isoformat()

    def session(self, session: str) -> SessionRecord:
        """A Session of this runtime's tenant, by its handle; another tenant's looks unknown."""

        record = self.state.sessions.get(session)
        if record is None or record.tenant_id != self.tenant_id:
            raise NotConfiguredError("unknown_session", "No such Session: run `pap sessions start`")
        return record

    def sessions(self) -> list[SessionRecord]:
        """The Sessions of this runtime's tenant only."""

        return [r for r in self.state.sessions.values() if r.tenant_id == self.tenant_id]

    def session_of(self, record: SessionRecord) -> PapSession:
        """The record's Session; a new `sid` from `invalid_session` (§5.5) is saved at the end."""

        session = self.live.get(record.id)
        if session is None:
            session = PapSession(
                sid=record.sid,
                sub=record.pairwise_user_id,
                issuer=record.issuer,
                client_id=record.client_id,
                tenant_id=record.tenant_id,
                agent_id=record.agent_id,
            )
            self.live[record.id] = session
        return session

    def keep_restarted_sessions(self) -> None:
        """Save the `sid` of each Session the company made the agent start again."""

        changed = False
        for handle, session in self.live.items():
            record = self.state.sessions.get(handle)
            if record is not None and record.sid != session.sid:
                record.sid = session.sid
                changed = True
        if changed:
            self.state.save()


class CliHostPlugin:
    """The CLI's default contributions, each replaceable by an installed plugin."""

    def __init__(self, runtime: CliRuntime, *, open_browser: bool) -> None:
        self.runtime = runtime
        self.open_browser = open_browser

    def provide_contributions(self, contributions: object) -> None:
        contribute = contributions.contribute  # type: ignore[attr-defined]
        runtime = self.runtime

        def now() -> datetime:
            # Whichever clock the host contributes, read when it is needed.
            return cast(Clock, first_contribution(runtime.reactor, CLOCKS, "clock")).now()

        contribute(TOKEN_STORES, runtime.secrets, contribution_id="file", order=100)
        contribute(
            AUTHORIZATION_STATE_STORES, MemoryStateStore(now), contribution_id="memory", order=100
        )
        contribute(
            SESSION_SIGNERS,
            DelegatedSessionSigner(
                runtime.keys, signer=ContributedSigner(runtime.reactor), now=now
            ),
            contribution_id="file",
            order=100,
        )
        # Below the SDK's in-memory default: a token stays bound across the CLI's runs.
        contribute(
            DPOP_PROVERS,
            JoseDpopProver(FileDpopKeys(runtime.keys), now=now),
            contribution_id="file",
            order=50,
        )
        signer = runtime.keys.signer()
        if signer is not None:
            contribute(SIGNERS, signer, contribution_id="file", order=100)
        contribute(
            PAIRWISE_USER_ID_STORES,
            SqlitePairwiseUserIdStore(runtime.state.path.parent / "pairwise.sqlite3"),
            contribution_id="sqlite",
            order=100,
        )
        contribute(
            PROTECTED_INPUTS, TerminalInput(runtime.input), contribution_id="terminal", order=100
        )
        contribute(
            BROWSER_HANDOFFS, UserBrowser(self.open_browser), contribution_id="browser", order=100
        )


HostFactory = Callable[[InputSource], "contextlib.AbstractAsyncContextManager[CliRuntime]"]


def local_host(
    state_dir: Path | None = None,
    *,
    timeout: float = 10.0,
    open_browser: bool = True,
    address_resolver: AddressResolver = resolve_addresses,
    http_factory: Callable[[], httpx.AsyncClient] | None = None,
    discover_plugins: bool = True,
    plugins: Iterable[tuple[PluginManifest, object]] = (),
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
) -> HostFactory:
    """The default host: local files, the network, and installed host plugins.

    `plugins` are registered after the defaults (a demo's clock, a keyring);
    `sleep` is how Device Sign-In polling waits.
    """

    @contextlib.asynccontextmanager
    async def build(source: InputSource) -> AsyncIterator[CliRuntime]:
        root = state_dir or default_state_dir()
        http = (http_factory or (lambda: httpx.AsyncClient(timeout=timeout)))()
        try:
            platform, _ = build_pap_reactor(http_client=http, address_resolver=address_resolver)
            runtime = CliRuntime(
                reactor=platform,
                http=http,
                address_resolver=address_resolver,
                secrets=FileSecretStore(root / "secrets.json"),
                keys=FileKeyStore(root / "keys.json"),
                state=CliState.load(root / "state.json"),
                input=source,
                sleep=sleep,
            )
            platform.register_plugin(
                PluginManifest(name="personal-agent-protocol.cli-host", version="1"),
                CliHostPlugin(runtime, open_browser=open_browser),
            )
            for manifest, implementation in plugins:
                platform.register_plugin(manifest, implementation)
            if discover_plugins:
                platform.discover(HOST_PLUGIN_GROUP)
            yield runtime
        finally:
            await http.aclose()

    return build
