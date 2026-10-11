# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""PAP Operations extension v1: exact approval, one record, at most once.

An operation is something a company proposes (from an API's `202`, an MCP
tool's `structuredContent`, a conversation `message`, or its website) and
performs only once it is confirmed at `{endpoint}/{operation_id}/confirm`.

What this client guarantees on the personal agent's side:

- **Negotiation.** Operations are used only when the company's `poppy.json`
  and the agent's client metadata both list `operations` version 1.
- **Exact approval.** A user approval names one `operation_id` and one
  `revision` (`approve()` after the host showed the summary); a confirmation
  for any other revision is refused locally, and only the latest revision can
  be confirmed at the company. `terms_changed` returns the new revision and
  what changed, to show the user before asking again.
- **Standing permissions.** Confirming with `standing_permission` needs the
  Reactor `pap.standingPermissionStore` to reserve a use whose company,
  account, action, and every limit cover the revision's terms; the use is
  released when the company refuses, kept when it confirms. A revision that
  requires the user's approval is never confirmed this way.
- **Recovery.** A confirm whose answer was lost is read back by the same ID;
  an operation is never re-proposed or assumed failed while it is unknown.
- **Disclosure.** `result.summary` is returned as the company wrote it.

Nothing here reads conversation text as approval: a message never confirms.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, replace
from datetime import datetime
from decimal import Decimal, InvalidOperation
from typing import Any, Literal, Protocol, cast, runtime_checkable
from urllib.parse import urlsplit

import httpx
from reactor import PluginPlatform  # type: ignore[import-untyped]

from .errors import PersonalAgentProtocolError, ProtocolValidationError, TransportError
from .json import loads_strict
from .models import ClientMetadata, DiscoveryDocument, Message, Operation, ProtocolModel
from .reactor import CLOCKS, STANDING_PERMISSION_STORES, Clock, first_contribution
from .sessions import SessionToken
from .transport import DpopHttpClient

OPERATIONS_EXTENSION = "operations"
OPERATIONS_VERSION = "1"
FINAL_STATES = frozenset({"succeeded", "failed", "cancelled", "expired"})
_IDENTIFIER = re.compile(r"^[A-Za-z0-9_-]{1,256}$")


class OperationError(PersonalAgentProtocolError):
    """An operation could not be read, confirmed, or cancelled."""


def operations_endpoint(document: DiscoveryDocument, metadata: ClientMetadata) -> str | None:
    """The company's operations endpoint when both sides list version 1, else `None`."""

    company = document.extensions.get(OPERATIONS_EXTENSION)
    agent = metadata.extensions.get(OPERATIONS_EXTENSION)
    if company is None or agent is None:
        return None
    if company.version != OPERATIONS_VERSION or agent.version != OPERATIONS_VERSION:
        return None
    endpoint = (company.model_extra or {}).get("endpoint")
    return endpoint if isinstance(endpoint, str) and endpoint.startswith("https://") else None


def operation_from(payload: object) -> Operation:
    """The one operation object, from whichever channel carried it (Operations §4).

    Accepts an API's `202` body (`{"operation": …}`), an MCP tool result
    (`{"structuredContent": {"operation": …}}`), a conversation message
    (`{"operation": …}`, or a `Message`), or the operation itself.
    """

    candidate: object = payload
    if isinstance(payload, Message):
        candidate = payload.operation
    elif isinstance(payload, dict):
        structured = payload.get("structuredContent")
        if isinstance(structured, dict) and "operation" in structured:
            candidate = structured["operation"]
        elif "operation" in payload:
            candidate = payload["operation"]
    if isinstance(candidate, Operation):
        return candidate
    if candidate is None:
        raise ValueError("the payload carries no operation")
    return Operation.model_validate(candidate)


def operation_page(operation: Operation, company_domain: str) -> str:
    """The operation's `url`, once checked to be the company's own HTTPS page (§4.4, §5).

    The personal agent opens it in its own browser joined to the Session
    (`BrowserSessionClient.join(return_to=...)`), never in the user's. What
    is confirmed there is the same operation, read back by its ID.
    """

    if operation.url is None:
        raise OperationError("no_operation_page", "The company gave no page for this operation")
    parsed = urlsplit(operation.url)
    host = (parsed.hostname or "").lower()
    domain = company_domain.lower().removeprefix("www.")
    if parsed.scheme != "https" or not (host == domain or host.endswith(f".{domain}")):
        raise OperationError(
            "foreign_operation_page", "An operation's page must be on the company's own domain"
        )
    return operation.url


def terms_digest(operation: Operation) -> str:
    """A digest of exactly what a revision says: its summary and its terms."""

    canonical = json.dumps(
        {"summary": operation.summary, "terms": operation.terms or {}},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


class UserApproval(ProtocolModel):
    """The user approved this revision, as it was shown to them."""

    operation_id: str
    revision: int
    digest: str


def approve(operation: Operation) -> UserApproval:
    """Record the user's approval of the revision the host just showed them."""

    if operation.state != "proposed":
        raise OperationError("not_proposed", "Only a proposed operation can be approved")
    return UserApproval(
        operation_id=operation.operation_id,
        revision=operation.revision,
        digest=terms_digest(operation),
    )


@dataclass(frozen=True)
class TermLimit:
    """A bound on one term, named by its dotted path in `terms`.

    `maximum` compares as a decimal (amounts are strings on the wire);
    `allowed` lists the only values accepted. A limit names a term the
    revision must carry: a missing term is a question for the user.
    """

    path: str
    maximum: Decimal | None = None
    allowed: frozenset[str] | None = None


@dataclass(frozen=True)
class StandingPermission:
    """What the user allowed in advance: one company, account, and action."""

    reference: str
    company: str
    account: str
    action: str
    limits: tuple[TermLimit, ...]
    expires_at: datetime
    uses_remaining: int | None = None


@dataclass(frozen=True)
class StandingPermissionRequest:
    company: str
    account: str
    action: str
    operation: Operation


@runtime_checkable
class StandingPermissionStore(Protocol):
    """Reserve, commit, and release uses of standing permissions.

    `reserve` returns an opaque reservation when a permission in effect
    covers the request (its company, account, action, every limit), holding
    one use for a limited-use permission; `commit` spends it once the company
    confirmed; `release` gives it back when the company refused.
    """

    async def reserve(self, request: StandingPermissionRequest, *, now: datetime) -> str | None: ...

    async def commit(self, reservation: str) -> None: ...

    async def release(self, reservation: str) -> None: ...


def _term(terms: dict[str, Any], path: str) -> Any:
    value: Any = terms
    for part in path.split("."):
        if not isinstance(value, dict) or part not in value:
            raise KeyError(path)
        value = value[part]
    return value


def covers(
    permission: StandingPermission, request: StandingPermissionRequest, now: datetime
) -> bool:
    """Whether a standing permission covers this revision, term by term."""

    if (
        permission.company != request.company
        or permission.account != request.account
        or permission.action != request.action
        or now >= permission.expires_at
        or permission.uses_remaining == 0
        or request.operation.user_approval_required
    ):
        return False
    terms = request.operation.terms or {}
    for limit in permission.limits:
        try:
            value = _term(terms, limit.path)
        except KeyError:
            return False
        if limit.allowed is not None and str(value) not in limit.allowed:
            return False
        if limit.maximum is not None:
            try:
                if Decimal(str(value)) > limit.maximum:
                    return False
            except InvalidOperation:
                return False
    return True


class InMemoryStandingPermissionStore:
    """A single-process store of standing permissions, for examples and tests."""

    def __init__(self, permissions: tuple[StandingPermission, ...] = ()) -> None:
        self.permissions = {permission.reference: permission for permission in permissions}
        self.reservations: dict[str, str] = {}

    async def reserve(self, request: StandingPermissionRequest, *, now: datetime) -> str | None:
        for reference, permission in self.permissions.items():
            if covers(permission, request, now):
                if permission.uses_remaining is not None:
                    self.permissions[reference] = _replace_uses(
                        permission, permission.uses_remaining - 1
                    )
                reservation = f"rsv_{len(self.reservations) + 1}_{request.operation.operation_id}"
                self.reservations[reservation] = reference
                return reservation
        return None

    async def commit(self, reservation: str) -> None:
        self.reservations.pop(reservation, None)

    async def release(self, reservation: str) -> None:
        reference = self.reservations.pop(reservation, None)
        permission = self.permissions.get(reference) if reference else None
        if permission is not None and permission.uses_remaining is not None:
            self.permissions[permission.reference] = _replace_uses(
                permission, permission.uses_remaining + 1
            )


def _replace_uses(permission: StandingPermission, uses: int) -> StandingPermission:
    return replace(permission, uses_remaining=uses)


class ConfirmOutcome(ProtocolModel):
    """What a confirmation did.

    `confirmed`: the company accepted the revision (`operation.state` is final,
    or `in_progress` with `retry_after`). `terms_changed`: a newer revision
    (`operation`) to show the user, with the `changed` term paths.
    `approval_required`: the company wants the user's own approval.
    `not_confirmed`: the operation was already cancelled or expired, returned
    as it is; nothing was confirmed or performed.
    """

    status: Literal["confirmed", "terms_changed", "approval_required", "not_confirmed"]
    operation: Operation | None = None
    changed: tuple[str, ...] = ()
    retry_after: int | None = None


class OperationsClient:
    """Read, confirm, and cancel operations at a negotiated endpoint."""

    def __init__(self, *, transport: DpopHttpClient, max_response_bytes: int = 256 * 1024) -> None:
        if max_response_bytes <= 0:
            raise ValueError("max_response_bytes must be positive")
        self.transport = transport
        self.reactor: PluginPlatform = transport.reactor
        self.max_response_bytes = max_response_bytes

    async def read(
        self,
        endpoint: str,
        operation_id: str,
        *,
        token: SessionToken,
        tenant_id: str,
        pairwise_user_id: str,
        issuer: str,
    ) -> Operation:
        response = await self._request(
            "GET", endpoint, operation_id, None, token, tenant_id, pairwise_user_id, issuer
        )
        payload = self._payload(response)
        if response.status_code != 200:
            raise self._error(response, payload)
        return self._operation(payload, operation_id)

    async def confirm(
        self,
        endpoint: str,
        operation: Operation,
        *,
        approval: UserApproval | None = None,
        standing: tuple[str, str, str] | None = None,
        token: SessionToken,
        tenant_id: str,
        pairwise_user_id: str,
        issuer: str,
    ) -> ConfirmOutcome:
        """Confirm the revision the user approved, or one a standing permission covers.

        `approval` is `approve(operation)` for this exact revision. `standing`
        is `(company, account, action)` to look up a standing permission. A
        lost answer is recovered by reading the same operation back.
        """

        approved_by, held = await self._authorize(operation, approval, standing)
        body = json.dumps(
            {"revision": operation.revision, "approved_by": approved_by}, separators=(",", ":")
        ).encode()
        try:
            response = await self._request(
                "POST",
                endpoint,
                f"{operation.operation_id}/confirm",
                body,
                token,
                tenant_id,
                pairwise_user_id,
                issuer,
            )
        except TransportError:
            # The answer was lost: the company may have performed it. Read it back.
            current = await self.read(
                endpoint,
                operation.operation_id,
                token=token,
                tenant_id=tenant_id,
                pairwise_user_id=pairwise_user_id,
                issuer=issuer,
            )
            await _settle(held, spent=current.state != "proposed")
            if current.state == "proposed":
                raise OperationError(
                    "confirm_not_received", "The confirmation did not reach the company; retry it"
                ) from None
            return ConfirmOutcome(status="confirmed", operation=current)

        payload = self._payload(response)
        await _settle(held, spent=response.status_code == 200)
        if response.status_code == 200:
            confirmed = self._operation(payload, operation.operation_id)
            if confirmed.confirmation is None and confirmed.state in {"cancelled", "expired"}:
                # A repeated or late confirm is safe: the record comes back unchanged.
                return ConfirmOutcome(status="not_confirmed", operation=confirmed)
            if confirmed.revision != operation.revision or confirmed.confirmation is None:
                raise OperationError(
                    "invalid_operation", "The company confirmed a revision other than the one sent"
                )
            retry_after = response.headers.get("retry-after")
            return ConfirmOutcome(
                status="confirmed",
                operation=confirmed,
                retry_after=int(retry_after) if retry_after and retry_after.isdigit() else None,
            )
        error = payload.get("error") if isinstance(payload, dict) else None
        if error == "terms_changed" and isinstance(payload, dict):
            current = self._operation(payload.get("operation"), operation.operation_id)
            return ConfirmOutcome(
                status="terms_changed",
                operation=current,
                changed=_changed_paths(operation, current),
            )
        if error == "user_approval_required":
            return ConfirmOutcome(status="approval_required", operation=operation)
        raise self._error(response, payload)

    async def _authorize(
        self,
        operation: Operation,
        approval: UserApproval | None,
        standing: tuple[str, str, str] | None,
    ) -> tuple[Literal["user", "standing_permission"], _Held | None]:
        if (approval is None) == (standing is None):
            raise OperationError(
                "approval_required",
                "Confirm with exactly one of a user approval or a standing permission",
            )
        if operation.state != "proposed":
            raise OperationError("not_proposed", "Only a proposed operation can be confirmed")
        if approval is not None:
            if (
                approval.operation_id != operation.operation_id
                or approval.revision != operation.revision
                or approval.digest != terms_digest(operation)
            ):
                raise OperationError(
                    "approval_mismatch", "The user approved a different revision than this one"
                )
            return "user", None
        if operation.user_approval_required:
            raise OperationError(
                "user_approval_required", "This revision needs the user's own approval"
            )
        store = cast(
            StandingPermissionStore,
            first_contribution(
                self.reactor, STANDING_PERMISSION_STORES, "standing permission store"
            ),
        )
        clock = cast(Clock, first_contribution(self.reactor, CLOCKS, "clock"))
        company, account, action = cast(tuple[str, str, str], standing)
        reservation = await store.reserve(
            StandingPermissionRequest(
                company=company, account=account, action=action, operation=operation
            ),
            now=clock.now(),
        )
        if reservation is None:
            raise OperationError(
                "no_standing_permission",
                "No standing permission covers this revision: ask the user",
            )
        return "standing_permission", _Held(store, reservation)

    async def cancel(
        self,
        endpoint: str,
        operation_id: str,
        *,
        token: SessionToken,
        tenant_id: str,
        pairwise_user_id: str,
        issuer: str,
    ) -> Operation:
        """Cancel: a proposal becomes `cancelled`; one in progress stops if it can."""

        response = await self._request(
            "POST",
            endpoint,
            f"{operation_id}/cancel",
            b"{}",
            token,
            tenant_id,
            pairwise_user_id,
            issuer,
        )
        payload = self._payload(response)
        if response.status_code != 200:
            raise self._error(response, payload)
        return self._operation(payload, operation_id)

    async def _request(
        self,
        method: str,
        endpoint: str,
        path: str,
        body: bytes | None,
        token: SessionToken,
        tenant_id: str,
        pairwise_user_id: str,
        issuer: str,
    ) -> httpx.Response:
        if not _IDENTIFIER.fullmatch(path.split("/", 1)[0]):
            raise ProtocolValidationError("invalid_identifier", "operation ID is invalid")
        headers = {"Accept": "application/json"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        return await self.transport.request(
            method,
            f"{endpoint.rstrip('/')}/{path}",
            token=token,
            tenant_id=tenant_id,
            pairwise_user_id=pairwise_user_id,
            issuer=issuer,
            headers=headers,
            content=body,
        )

    def _payload(self, response: httpx.Response) -> object:
        if len(response.content) > self.max_response_bytes:
            raise OperationError("response_too_large", "operation response exceeded limit")
        try:
            return loads_strict(response.content) if response.content else {}
        except (ValueError, ProtocolValidationError) as exc:
            raise OperationError("invalid_json", "operation response was not JSON") from exc

    @staticmethod
    def _operation(payload: object, operation_id: str) -> Operation:
        candidate = payload.get("operation", payload) if isinstance(payload, dict) else payload
        try:
            operation = Operation.model_validate(candidate)
        except ValueError as exc:
            raise OperationError("invalid_operation", "operation was malformed") from exc
        if operation.operation_id != operation_id:
            raise OperationError("invalid_operation", "the company answered for another operation")
        return operation

    @staticmethod
    def _error(response: httpx.Response, payload: object) -> OperationError:
        code = payload.get("error") if isinstance(payload, dict) else None
        details: dict[str, object] = {}
        if code == "extension_required" and isinstance(payload, dict):
            extension = payload.get("extension")
            if isinstance(extension, str):
                details["extension"] = extension
        retry_after = response.headers.get("retry-after")
        if response.status_code == 429 and retry_after:
            details["retry_after"] = retry_after
        return OperationError(
            code if isinstance(code, str) else "operation_request_failed",
            "the operation request was refused",
            status_code=response.status_code,
            details=details or None,
        )


@dataclass(frozen=True)
class _Held:
    store: StandingPermissionStore
    reservation: str


async def _settle(held: _Held | None, *, spent: bool) -> None:
    """Spend a reserved use once the company confirmed; give it back otherwise."""

    if held is None:
        return
    if spent:
        await held.store.commit(held.reservation)
    else:
        await held.store.release(held.reservation)


def _changed_paths(before: Operation, after: Operation) -> tuple[str, ...]:
    def flatten(value: Any, prefix: str = "") -> dict[str, Any]:
        if isinstance(value, dict):
            flat: dict[str, Any] = {}
            for key, item in value.items():
                flat.update(flatten(item, f"{prefix}{key}."))
            return flat
        return {prefix.rstrip("."): value}

    old = flatten(before.terms or {})
    new = flatten(after.terms or {})
    changed = sorted(path for path in old.keys() | new.keys() if old.get(path) != new.get(path))
    if before.summary != after.summary:
        changed.insert(0, "summary")
    return tuple(changed)
