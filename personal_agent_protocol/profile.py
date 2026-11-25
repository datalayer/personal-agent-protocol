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

`PUBLISHED_PROTOCOL_VERSION` is version 1.0, as upstream published and froze it on
2026-11-14 (commit 8c02b42, `PUBLISHED_PROTOCOL_REVISION`). `DRAFT_PROTOCOL_VERSION` is
draft 1.1, which adds to 1.0 without breaking it (§3.4), and `DRAFT_PROTOCOL_REVISION`
the date of the draft text implemented (commit 589743a): a draft can change until
upstream publishes it. Since 1.1.0 the draft is `DEFAULT_PROTOCOL_VERSION`, the version
a Personal Agent or a Company uses unless it asks for others (`protocol_versions`): 1.0
and 0.4 as published stay available, used only when named. From 1.0 each side sends
only what the other's version defines (§3.4), so nothing of 1.1 goes to a peer at 1.0.
"""

from __future__ import annotations

#: The Personal Agent Protocol version implemented: 0.4 as published, the 1.0 release candidate.
PROTOCOL_PROFILE = "0.4"
#: The upstream specification revision implemented: the day 0.4 was published (commit 4803900).
PROTOCOL_REVISION = "2026-11-10"

#: Protocol version 1.0 as published, available when named.
PUBLISHED_PROTOCOL_VERSION = "1.0"
#: The 1.0 text implemented: 1.0 as published and frozen on 2026-11-14 (commit 8c02b42).
PUBLISHED_PROTOCOL_REVISION = "2026-11-14"
#: Draft 1.1, the default since 1.1.0.
DRAFT_PROTOCOL_VERSION = "1.1"
#: The draft 1.1 text implemented: upstream on 2026-11-18 (commit 589743a).
DRAFT_PROTOCOL_REVISION = "2026-11-18"
#: The version used unless a Personal Agent or a Company names others: draft 1.1.
DEFAULT_PROTOCOL_VERSION = DRAFT_PROTOCOL_VERSION

__all__ = [
    "DEFAULT_PROTOCOL_VERSION",
    "DRAFT_PROTOCOL_REVISION",
    "DRAFT_PROTOCOL_VERSION",
    "PROTOCOL_PROFILE",
    "PROTOCOL_REVISION",
    "PUBLISHED_PROTOCOL_REVISION",
    "PUBLISHED_PROTOCOL_VERSION",
]
