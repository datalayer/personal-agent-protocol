# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Replacing a User ID at a Company (§5.1; guides, *Choosing user IDs*).

A User ID is stable, but not permanent. A Personal Agent MAY replace one User's ID at
one Company:

- **when the User asks**, such as by clearing their data for the Company, as a browser
  lets them delete one site's cookies and site data;
- **on its own**, once 28 days have passed since it last used a Session with the ID
  (`USER_ID_UNUSED_AFTER`), and never while it holds a refresh token for the User there,
  however long the ID has gone unused.

Apart from anonymous browsing and a change of the Company's identifier, it replaces User
IDs in no other case: a Company counts its Users and limits each one by them.

`replace_user_id` does it in the order §5.1 asks:

1. **The current ID, between tasks.** It refuses an ID that is no longer the User's at
   the Company (`user_id_stale`), one replacement at a time, and while a Session uses the
   ID (`UserIdData.in_use`).
2. **Sign out first.** With a refresh token for the User at the Company, the account
   would link the old ID and the new one: every refresh token is revoked, and the
   replacement stops if the Company doesn't acknowledge one.
3. **Discard the old ID's identifiers and keys**: the DPoP key and the delegated key in
   their custodies, then what only the host holds (`UserIdData.discard`): the User's
   Agent IDs, `sid`s, the agent's browser's cookies and other site data for the Company,
   the IDs the Company gave it, such as `conversation_id`s and operation IDs, and
   responses it cached that the Company varied by Session or User.
4. **A new ID**, last, from the `pap.pairwiseUserIdStore`. Nothing used or received
   under the old ID is sent under the new one, and the Company sees a new User: carts,
   conversations and other state don't carry over.

```python
replaced = await replace_user_id(
    reactor,
    user=UserIdAtCompany(
        tenant_id=tenant, local_user_id=user, company=company.identifier, pairwise_user_id=old
    ),
    data=host_data,                       # the host's `UserIdData`
    dpop_keys=dpop_keys, delegated_keys=delegated_keys,
    reason="user_request",
    accounts=refresh, context=context, refresh_token_references=references,
)
session = await sessions.start(pairwise_user_id=replaced.pairwise_user_id, ...)
```

The User may keep their own records of what they did at the Company, such as an order
number they need for a return, as long as the agent doesn't send them to the Company
under the new ID.
"""

from __future__ import annotations

import asyncio
import weakref
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Literal, Protocol, cast, runtime_checkable

from reactor import PluginPlatform  # type: ignore[import-untyped]

from .accounts import RefreshTokenClient, RefreshTokenContext
from .crypto import DelegatedKeyCustody, DpopKeyCustody
from .errors import PersonalAgentProtocolError
from .reactor import (
    CLOCKS,
    PAIRWISE_USER_ID_STORES,
    TOKEN_STORES,
    Clock,
    TokenStore,
    first_contribution,
)

#: How long an ID goes unused before a Personal Agent may replace it on its own (§5.1):
#: 28 days since it last used a Session with it, and only with no refresh token held.
USER_ID_UNUSED_AFTER = timedelta(days=28)

#: Why an ID is replaced (§5.1): the User asked, or it went unused.
ReplacementReason = Literal["user_request", "unused"]


class UserIdError(PersonalAgentProtocolError):
    """A User ID was not replaced: `user_id_stale`, `user_id_in_use`,
    `refresh_token_held`, `user_id_recently_used`, `sign_out_failed`. The store's ID is
    unchanged."""


@dataclass(frozen=True)
class UserIdAtCompany:
    """One User's ID at one Company: who (`tenant_id`, `local_user_id`), where (`company`,
    the Company's identifier: its issuer, or `https://{organization.domain}` without one)
    and the User ID itself, `pairwise_user_id`."""

    tenant_id: str
    local_user_id: str
    company: str
    pairwise_user_id: str


@runtime_checkable
class UserIdData(Protocol):
    """What the host holds under a User ID that the SDK can't reach (§5.1).

    `in_use` says whether a task is using the ID now: a Session with it is open in a
    task the agent is working on. An ID is replaced between tasks, never in the middle
    of one. The SDK can't see the host's tasks, so the reservation is the host's: while
    `replace_user_id` is awaited for a User at a Company, the host starts no task and no
    sign-in for them there, and takes up again with the ID `replace_user_id` returns, or
    the old one when it raised. `replace_user_id` itself runs one replacement at a time
    for a User at a Company, and refuses an ID that is no longer theirs.

    `discard` removes everything the host kept under the ID, so none of it is ever sent
    to the Company again: the User's Agent IDs, the Sessions and their `sid`s, access
    tokens, the agent's browser's cookies and other site data for the Company, the IDs
    the Company gave (conversation and operation IDs, carts), and responses cached that
    the Company varied by Session or User (`TasksClient.forget`, `ServiceTokens.forget`).
    It raises when it couldn't: the ID is then not replaced.
    """

    async def in_use(self, user: UserIdAtCompany) -> bool: ...

    async def discard(self, user: UserIdAtCompany) -> None: ...


@runtime_checkable
class ReplaceablePairwiseUserIdStore(Protocol):
    """A `pap.pairwiseUserIdStore` that can replace one User's ID at one Company (§5.1):
    `SqlitePairwiseUserIdStore` with a new random ID, `DerivedPairwiseUserIds` by its
    counter."""

    async def get_or_create(
        self, *, tenant_id: str, local_user_id: str, company_issuer: str
    ) -> str: ...

    async def replace(
        self, *, tenant_id: str, local_user_id: str, company_issuer: str, expected: str
    ) -> str:
        """The new ID, when the store's ID is `expected`; `LookupError` and no change
        when it is another one, atomically."""
        ...


@dataclass(frozen=True)
class ReplacedUserId:
    """A replacement that was made: the new User ID, and what signing out did first."""

    pairwise_user_id: str
    #: Whether the agent held a refresh token for the User at the Company, and signed out.
    signed_out: bool
    #: How many refresh tokens it revoked.
    revoked: int


def may_replace_unused(*, last_used: datetime, now: datetime, holds_refresh_token: bool) -> bool:
    """Whether a Personal Agent may replace an ID on its own (§5.1): 28 days have passed
    since it last used a Session with it, and it holds no refresh token for the User at
    the Company. A signed-in User keeps their ID until they clear the Company, however
    long it has gone unused; after they sign out, the 28 days apply. Use one rule for
    every User, so the change singles no one out."""

    return not holds_refresh_token and now - last_used >= USER_ID_UNUSED_AFTER


async def replace_user_id(
    reactor: PluginPlatform,
    *,
    user: UserIdAtCompany,
    data: UserIdData,
    dpop_keys: DpopKeyCustody,
    delegated_keys: DelegatedKeyCustody,
    reason: ReplacementReason,
    last_used: datetime | None = None,
    refresh_token_references: Iterable[str] = (),
    accounts: RefreshTokenClient | None = None,
    context: RefreshTokenContext | None = None,
) -> ReplacedUserId:
    """Replace `user`'s ID at the Company, and return the new one (§5.1).

    `reason` is `user_request` when the User asked, such as by clearing their data for
    the Company, and `unused` when the agent ages the ID out on its own: then
    `last_used` says when it last used a Session with the ID, and the replacement is
    refused before 28 days (`user_id_recently_used`) and while a refresh token is held
    (`refresh_token_held`).

    `refresh_token_references` are all the refresh tokens the agent holds for the User at
    the Company, from every sign-in. When one is still stored, the agent signs out first
    (§5.5) with `accounts` and `context`, and stops (`sign_out_failed`) unless the
    Company acknowledged every revocation.

    `dpop_keys` and `delegated_keys` are the custodies the host's `pap.dpopProver` and
    `pap.sessionSigner` keep the User's keys in: the old ID's are forgotten. `data` is
    the host's (`UserIdData`). The new ID comes last, from a `pap.pairwiseUserIdStore`
    that can `replace`; until then the old ID is still the User's, so a step that fails
    replaces nothing.
    """

    store = first_contribution(reactor, PAIRWISE_USER_ID_STORES, "pairwise user ID store")
    if not isinstance(store, ReplaceablePairwiseUserIdStore):
        raise TypeError("the pairwise user ID store can't replace an ID: it has no replace()")
    who = {
        "tenant_id": user.tenant_id,
        "local_user_id": user.local_user_id,
        "company_issuer": user.company,
    }
    # One replacement at a time for a User at a Company in this process; the store's own
    # check of the ID it replaces covers other processes.
    key = (user.tenant_id, user.local_user_id, user.company)
    lock = _REPLACING.get(key)
    if lock is None:
        lock = _REPLACING[key] = asyncio.Lock()
    async with lock:
        if await store.get_or_create(**who) != user.pairwise_user_id:
            # Replaced already, or never the User's: nothing is checked or cleared for an
            # ID that isn't the current one.
            raise _stale()
        references = tuple(dict.fromkeys(refresh_token_references))
        held: list[str] = []
        if references:
            tokens = cast(TokenStore, first_contribution(reactor, TOKEN_STORES, "token store"))
            held = [ref for ref in references if await tokens.get(ref) is not None]
        if reason == "unused":
            _check_unused(reactor, last_used, held)
        elif reason != "user_request":
            raise ValueError("a User ID is replaced when the User asks, or once it went unused")
        if await data.in_use(user):
            raise UserIdError("user_id_in_use", "A User ID is replaced between tasks")
        revoked = await _sign_out(held, accounts, context) if held else 0
        keys = {"tenant_id": user.tenant_id, "issuer": user.company, "sub": user.pairwise_user_id}
        await dpop_keys.forget(**keys)
        await delegated_keys.forget(**keys)
        await data.discard(user)
        try:
            replaced = await store.replace(**who, expected=user.pairwise_user_id)
        except LookupError as exc:
            raise _stale() from exc
    if replaced == user.pairwise_user_id:
        raise RuntimeError("the pairwise user ID store returned the ID it was to replace")
    return ReplacedUserId(pairwise_user_id=replaced, signed_out=bool(held), revoked=revoked)


#: The replacements under way in this process, one at a time for a User at a Company: a
#: lock is kept only while a caller holds or waits for it.
_REPLACING: weakref.WeakValueDictionary[tuple[str, str, str], asyncio.Lock] = (
    weakref.WeakValueDictionary()
)


def _stale() -> UserIdError:
    return UserIdError(
        "user_id_stale", "The User ID to replace is no longer the User's ID at the Company"
    )


def _check_unused(reactor: PluginPlatform, last_used: datetime | None, held: list[str]) -> None:
    """The rule for an ID the agent replaces on its own (§5.1): no refresh token held,
    and 28 days since a Session last used it."""

    if last_used is None:
        raise ValueError("an unused ID is replaced by when it was last used (last_used)")
    if held:
        raise UserIdError(
            "refresh_token_held",
            "A User ID isn't replaced on the agent's own while it holds a refresh token",
        )
    now = cast(Clock, first_contribution(reactor, CLOCKS, "clock")).now()
    if not may_replace_unused(last_used=last_used, now=now, holds_refresh_token=False):
        raise UserIdError(
            "user_id_recently_used",
            "A User ID is replaced on the agent's own only after 28 days unused",
        )


async def _sign_out(
    held: list[str], accounts: RefreshTokenClient | None, context: RefreshTokenContext | None
) -> int:
    """Sign out before the ID is replaced (§5.1, §5.5): every refresh token revoked, or
    `sign_out_failed`. How many were."""

    if accounts is None or context is None:
        raise ValueError(
            "the agent holds a refresh token for the User: signing out first needs "
            "accounts and context"
        )
    try:
        result = await accounts.sign_out(held, context=context)
    except PersonalAgentProtocolError as exc:
        raise UserIdError(
            "sign_out_failed", "The agent could not sign out before replacing the User ID"
        ) from exc
    if not result.signed_out:
        raise UserIdError(
            "sign_out_failed", "The agent could not sign out before replacing the User ID"
        )
    return result.revoked


__all__ = [
    "USER_ID_UNUSED_AFTER",
    "ReplaceablePairwiseUserIdStore",
    "ReplacedUserId",
    "ReplacementReason",
    "UserIdAtCompany",
    "UserIdData",
    "UserIdError",
    "may_replace_unused",
    "replace_user_id",
]
