# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""The exact PAP version this SDK implements.

`PROTOCOL_PROFILE` is the version (§1), `PROTOCOL_REVISION` the date of the
upstream specification page it was implemented from, and the Operations
extension version is `operations.OPERATIONS_VERSION`. The TypeScript SDK
exports the same three values; `protocol/requirements.yaml`,
`protocol/UPSTREAM.md` and the compatibility page state them too, and a test
holds all of them equal.

`DRAFT_PROTOCOL_VERSION` is version 1.0, a draft until upstream published and
froze it on 2026-11-14, and `DRAFT_PROTOCOL_REVISION` the date of the text
implemented: since 0.37, 1.0 as published (commit 8c02b42). The names stay from
the draft. Since 0.36 it is `DEFAULT_PROTOCOL_VERSION`, the version a Personal
Agent or a Company uses unless it asks for others (`protocol_versions`): 0.4 as
published stays available, used only when named.
"""

from __future__ import annotations

#: The Personal Agent Protocol version implemented: 0.4 as published, the 1.0 release candidate.
PROTOCOL_PROFILE = "0.4"
#: The upstream specification revision implemented: the day 0.4 was published (commit 4803900).
PROTOCOL_REVISION = "2026-11-10"

#: Protocol version 1.0, the default since 0.36 (named while it was the draft).
DRAFT_PROTOCOL_VERSION = "1.0"
#: The 1.0 text implemented: 1.0 as published and frozen on 2026-11-14 (commit 8c02b42).
DRAFT_PROTOCOL_REVISION = "2026-11-14"
#: The version used unless a Personal Agent or a Company names others: 1.0.
DEFAULT_PROTOCOL_VERSION = DRAFT_PROTOCOL_VERSION

__all__ = [
    "DEFAULT_PROTOCOL_VERSION",
    "DRAFT_PROTOCOL_REVISION",
    "DRAFT_PROTOCOL_VERSION",
    "PROTOCOL_PROFILE",
    "PROTOCOL_REVISION",
]
