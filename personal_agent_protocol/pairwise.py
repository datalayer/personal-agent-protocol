# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Durable pairwise user identifiers for one tenant and verified company (§5.1).

A User ID is stable, but not permanent: a Personal Agent may replace one User's ID at a
Company when the User asks, and on its own once it went unused for 28 days with no
refresh token held (`user_ids.replace_user_id`). Both ways of choosing IDs the guides
describe can do it:

- **A random ID, stored** (`SqlitePairwiseUserIdStore`): `replace` stores a new random
  ID in its place, and the old one is gone. The store also remembers when an ID was
  last used (`mark_used`, `last_used`), which the 28 days are counted from.
- **A keyed hash** (`derive_pairwise_user_id`, `DerivedPairwiseUserIds`): HMAC-SHA256
  of the internal user ID and the Company's identifier with a secret key. The key never
  changes, since that would replace every ID at once; one User's ID at one Company is
  replaced by a counter for that User and Company, included in what is hashed and
  increased (`SqlitePairwiseCounters`).
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol, runtime_checkable
from urllib.parse import urlsplit

from pydantic import SecretBytes
from reactor import PluginPlatform  # type: ignore[import-untyped]

from .reactor import PAIRWISE_USER_ID_STORES, PairwiseUserIdStore, first_contribution
from .sessions import RandomBytes, generate_pairwise_user_id
from .urls import browser_safe


def _key_part(value: str, label: str) -> str:
    if not value or len(value) > 256 or "\x00" in value:
        raise ValueError(f"{label} must contain between 1 and 256 safe characters")
    return value


def _issuer(value: str) -> str:
    parsed = urlsplit(value)
    if (
        not browser_safe(value)
        or parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("company issuer must be an HTTPS issuer without query or fragment")
    return value


class SqlitePairwiseUserIdStore:
    """Atomically persist random pairwise IDs in a local SQLite database."""

    def __init__(
        self,
        database: str | Path,
        *,
        random_bytes: RandomBytes | None = None,
        timeout_seconds: float = 5.0,
    ) -> None:
        if str(database) == ":memory:":
            raise ValueError("use a file-backed SQLite database for durable pairwise IDs")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self._database = str(database)
        self._random_bytes = random_bytes
        self._timeout = timeout_seconds

    async def get_or_create(
        self,
        *,
        tenant_id: str,
        local_user_id: str,
        company_issuer: str,
    ) -> str:
        """Return one stable random ID for the exact tenant, user, and issuer."""

        key = _key(tenant_id, local_user_id, company_issuer)
        return await asyncio.to_thread(self._get_or_create_sync, key)

    async def replace(
        self,
        *,
        tenant_id: str,
        local_user_id: str,
        company_issuer: str,
    ) -> str:
        """Replace the User's ID at the Company with a new random one, and return it
        (§5.1). The old ID is gone from the store, and when it was last used with it.

        Only as the last step of `user_ids.replace_user_id`, which signs out first and
        discards what the old ID held: an ID is never replaced while it is in use.
        """

        key = _key(tenant_id, local_user_id, company_issuer)
        return await asyncio.to_thread(self._replace_sync, key)

    async def mark_used(
        self,
        *,
        tenant_id: str,
        local_user_id: str,
        company_issuer: str,
        at: datetime,
    ) -> None:
        """Remember that a Session used the User's ID at the Company at `at` (§5.1): the
        28 days after which an unused ID may be replaced are counted from the latest."""

        key = _key(tenant_id, local_user_id, company_issuer)
        await asyncio.to_thread(self._mark_used_sync, key, _timestamp(at))

    async def last_used(
        self,
        *,
        tenant_id: str,
        local_user_id: str,
        company_issuer: str,
    ) -> datetime | None:
        """When a Session last used the User's ID at the Company, or `None` when the
        store has no ID for them or it was never marked used."""

        key = _key(tenant_id, local_user_id, company_issuer)
        return await asyncio.to_thread(self._last_used_sync, key)

    def _new_id(self) -> str:
        if self._random_bytes is None:
            return generate_pairwise_user_id()
        return generate_pairwise_user_id(self._random_bytes)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self._database,
            timeout=self._timeout,
            isolation_level=None,
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS pap_pairwise_user_ids (
                tenant_id TEXT NOT NULL,
                local_user_id TEXT NOT NULL,
                company_issuer TEXT NOT NULL,
                pairwise_user_id TEXT NOT NULL UNIQUE,
                PRIMARY KEY (tenant_id, local_user_id, company_issuer)
            )
            """
        )
        columns = {row[1] for row in connection.execute("PRAGMA table_info(pap_pairwise_user_ids)")}
        if "last_used_at" not in columns:
            # A database made before 1.1.0: the column is added once, empty.
            try:
                connection.execute("ALTER TABLE pap_pairwise_user_ids ADD COLUMN last_used_at REAL")
            except sqlite3.OperationalError as exc:
                # Another connection added it between the two statements.
                if "duplicate column" not in str(exc).lower():
                    raise
        return connection

    def _insert(self, database: sqlite3.Connection, key: tuple[str, str, str]) -> str:
        for _ in range(5):
            identifier = self._new_id()
            cursor = database.execute(
                """
                INSERT OR IGNORE INTO pap_pairwise_user_ids (
                    tenant_id, local_user_id, company_issuer, pairwise_user_id
                ) VALUES (?, ?, ?, ?)
                """,
                (*key, identifier),
            )
            if cursor.rowcount == 1:
                return identifier
        raise RuntimeError("could not allocate a unique pairwise user ID")

    def _get_or_create_sync(self, key: tuple[str, str, str]) -> str:
        with closing(self._connect()) as connection, connection as database:
            database.execute("BEGIN IMMEDIATE")
            row = database.execute(_SELECT_ID, key).fetchone()
            if row is not None:
                return str(row[0])
            return self._insert(database, key)

    def _replace_sync(self, key: tuple[str, str, str]) -> str:
        with closing(self._connect()) as connection, connection as database:
            database.execute("BEGIN IMMEDIATE")
            database.execute(
                """
                DELETE FROM pap_pairwise_user_ids
                WHERE tenant_id = ? AND local_user_id = ? AND company_issuer = ?
                """,
                key,
            )
            return self._insert(database, key)

    def _mark_used_sync(self, key: tuple[str, str, str], at: float) -> None:
        with closing(self._connect()) as connection, connection as database:
            database.execute("BEGIN IMMEDIATE")
            database.execute(
                """
                UPDATE pap_pairwise_user_ids
                SET last_used_at = MAX(COALESCE(last_used_at, ?), ?)
                WHERE tenant_id = ? AND local_user_id = ? AND company_issuer = ?
                """,
                (at, at, *key),
            )

    def _last_used_sync(self, key: tuple[str, str, str]) -> datetime | None:
        with closing(self._connect()) as connection, connection as database:
            row = database.execute(
                """
                SELECT last_used_at
                FROM pap_pairwise_user_ids
                WHERE tenant_id = ? AND local_user_id = ? AND company_issuer = ?
                """,
                key,
            ).fetchone()
        if row is None or row[0] is None:
            return None
        return datetime.fromtimestamp(float(row[0]), tz=timezone.utc)


_SELECT_ID = """
    SELECT pairwise_user_id
    FROM pap_pairwise_user_ids
    WHERE tenant_id = ? AND local_user_id = ? AND company_issuer = ?
"""


def _key(tenant_id: str, local_user_id: str, company_issuer: str) -> tuple[str, str, str]:
    return (
        _key_part(tenant_id, "tenant_id"),
        _key_part(local_user_id, "local_user_id"),
        _issuer(company_issuer),
    )


def _timestamp(at: datetime) -> float:
    if at.tzinfo is None:
        raise ValueError("a time an ID was used at is timezone-aware")
    return at.timestamp()


# A keyed hash (guides, *Choosing user IDs*) ------------------------------------------------

#: The shortest key `derive_pairwise_user_id` takes: 256 bits.
PAIRWISE_KEY_MIN_BYTES = 32


def derive_pairwise_user_id(
    key: SecretBytes | bytes,
    *,
    tenant_id: str,
    local_user_id: str,
    company_issuer: str,
    counter: int = 0,
) -> str:
    """The User ID a keyed hash gives one User at one Company (§5.1; guides, *Choosing
    user IDs*): HMAC-SHA256, with a secret `key`, of the tenant, the internal user ID,
    the Company's identifier (its issuer, or its HTTPS domain without one) and `counter`.

    The same inputs always give the same ID, so nothing is stored but the key and the
    counters. Never change the key: that replaces every User's ID at once, which §5.1
    doesn't allow. To replace one User's ID at one Company, increase that User's
    `counter` for that Company (`DerivedPairwiseUserIds.replace`).

    `local_user_id` is an internal identifier, never personal information such as an
    email address, phone number or name, nor a hash of it: a User ID MUST NOT be derived
    from personal information, keyed or not (§5.1).
    """

    secret = key.get_secret_value() if isinstance(key, SecretBytes) else key
    if len(secret) < PAIRWISE_KEY_MIN_BYTES:
        raise ValueError(f"the key has at least {PAIRWISE_KEY_MIN_BYTES} bytes")
    if isinstance(counter, bool) or counter < 0:
        raise ValueError("counter is zero or more")
    parts = (*_key(tenant_id, local_user_id, company_issuer), str(counter))
    # Each part with its length, so no two inputs hash the same bytes.
    message = b"".join(
        len(part.encode()).to_bytes(4, "big") + part.encode() for part in ("pap-user-id", *parts)
    )
    digest = hmac.new(secret, message, hashlib.sha256).digest()
    return "usr_" + base64.urlsafe_b64encode(digest).decode().rstrip("=")


@runtime_checkable
class PairwiseCounters(Protocol):
    """One counter for each User and Company, zero until increased: what a keyed hash
    includes to replace one User's ID (guides, *Choosing user IDs*). Durable, and shared
    by every process that derives IDs: a counter that went back would bring an old ID back.
    """

    async def get(self, *, tenant_id: str, local_user_id: str, company_issuer: str) -> int: ...

    async def increase(self, *, tenant_id: str, local_user_id: str, company_issuer: str) -> int: ...


class SqlitePairwiseCounters:
    """`PairwiseCounters` in a local SQLite database, increased atomically."""

    def __init__(self, database: str | Path, *, timeout_seconds: float = 5.0) -> None:
        if str(database) == ":memory:":
            raise ValueError("use a file-backed SQLite database for durable counters")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self._database = str(database)
        self._timeout = timeout_seconds

    async def get(self, *, tenant_id: str, local_user_id: str, company_issuer: str) -> int:
        key = _key(tenant_id, local_user_id, company_issuer)
        return await asyncio.to_thread(self._sync, key, 0)

    async def increase(self, *, tenant_id: str, local_user_id: str, company_issuer: str) -> int:
        key = _key(tenant_id, local_user_id, company_issuer)
        return await asyncio.to_thread(self._sync, key, 1)

    def _sync(self, key: tuple[str, str, str], by: int) -> int:
        connection = sqlite3.connect(self._database, timeout=self._timeout, isolation_level=None)
        with closing(connection), connection as database:
            database.execute(
                """
                CREATE TABLE IF NOT EXISTS pap_pairwise_counters (
                    tenant_id TEXT NOT NULL,
                    local_user_id TEXT NOT NULL,
                    company_issuer TEXT NOT NULL,
                    counter INTEGER NOT NULL,
                    PRIMARY KEY (tenant_id, local_user_id, company_issuer)
                )
                """
            )
            database.execute("BEGIN IMMEDIATE")
            if by:
                database.execute(
                    """
                    INSERT INTO pap_pairwise_counters VALUES (?, ?, ?, ?)
                    ON CONFLICT (tenant_id, local_user_id, company_issuer)
                    DO UPDATE SET counter = counter + excluded.counter
                    """,
                    (*key, by),
                )
            row = database.execute(
                """
                SELECT counter FROM pap_pairwise_counters
                WHERE tenant_id = ? AND local_user_id = ? AND company_issuer = ?
                """,
                key,
            ).fetchone()
            return 0 if row is None else int(row[0])


class DerivedPairwiseUserIds:
    """A `pap.pairwiseUserIdStore` that derives each ID with a keyed hash, and replaces
    one User's ID at one Company by increasing its counter (§5.1; guides, *Choosing
    user IDs*). The key is the host's secret, kept for as long as the IDs are."""

    def __init__(self, key: SecretBytes | bytes, *, counters: PairwiseCounters) -> None:
        secret = key if isinstance(key, SecretBytes) else SecretBytes(key)
        if len(secret.get_secret_value()) < PAIRWISE_KEY_MIN_BYTES:
            raise ValueError(f"the key has at least {PAIRWISE_KEY_MIN_BYTES} bytes")
        self._key = secret
        self._counters = counters

    async def get_or_create(
        self, *, tenant_id: str, local_user_id: str, company_issuer: str
    ) -> str:
        who = {
            "tenant_id": tenant_id,
            "local_user_id": local_user_id,
            "company_issuer": company_issuer,
        }
        return derive_pairwise_user_id(self._key, **who, counter=await self._counters.get(**who))

    async def replace(self, *, tenant_id: str, local_user_id: str, company_issuer: str) -> str:
        """Increase the User's counter at the Company, and return the ID it now gives:
        only as the last step of `user_ids.replace_user_id`."""

        who = {
            "tenant_id": tenant_id,
            "local_user_id": local_user_id,
            "company_issuer": company_issuer,
        }
        return derive_pairwise_user_id(
            self._key, **who, counter=await self._counters.increase(**who)
        )


async def resolve_pairwise_user_id(
    reactor: PluginPlatform,
    *,
    tenant_id: str,
    local_user_id: str,
    company_issuer: str,
) -> str:
    """Resolve the active Reactor store and return its stable pairwise ID."""

    store = first_contribution(
        reactor,
        PAIRWISE_USER_ID_STORES,
        "pairwise user ID store",
    )
    if not isinstance(store, PairwiseUserIdStore):
        raise TypeError("PAP pairwise user ID store has an invalid contract")
    return await store.get_or_create(
        tenant_id=tenant_id,
        local_user_id=local_user_id,
        company_issuer=company_issuer,
    )
