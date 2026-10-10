# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Durable pairwise user identifiers for one tenant and verified company."""

from __future__ import annotations

import asyncio
import sqlite3
from contextlib import closing
from pathlib import Path
from urllib.parse import urlsplit

from reactor import PluginPlatform  # type: ignore[import-untyped]

from .reactor import PAIRWISE_USER_ID_STORES, PairwiseUserIdStore, first_contribution
from .sessions import RandomBytes, generate_pairwise_user_id


def _key_part(value: str, label: str) -> str:
    if not value or len(value) > 256 or "\x00" in value:
        raise ValueError(f"{label} must contain between 1 and 256 safe characters")
    return value


def _issuer(value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
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

        key = (
            _key_part(tenant_id, "tenant_id"),
            _key_part(local_user_id, "local_user_id"),
            _issuer(company_issuer),
        )
        return await asyncio.to_thread(self._get_or_create_sync, key)

    def _new_id(self) -> str:
        if self._random_bytes is None:
            return generate_pairwise_user_id()
        return generate_pairwise_user_id(self._random_bytes)

    def _get_or_create_sync(self, key: tuple[str, str, str]) -> str:
        connection = sqlite3.connect(
            self._database,
            timeout=self._timeout,
            isolation_level=None,
        )
        with closing(connection), connection as database:
            database.execute(
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
            database.execute("BEGIN IMMEDIATE")
            row = database.execute(
                """
                SELECT pairwise_user_id
                FROM pap_pairwise_user_ids
                WHERE tenant_id = ? AND local_user_id = ? AND company_issuer = ?
                """,
                key,
            ).fetchone()
            if row is not None:
                return str(row[0])

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
