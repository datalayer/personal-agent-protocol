# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""The exact PAP draft this SDK implements.

`PROTOCOL_PROFILE` is the draft (§1), `PROTOCOL_REVISION` the date of the
upstream specification page it was implemented from, and the Operations
extension version is `operations.OPERATIONS_VERSION`. The TypeScript SDK
exports the same three values; `protocol/requirements.yaml`,
`protocol/UPSTREAM.md` and the compatibility page state them too, and a test
holds all of them equal.
"""

from __future__ import annotations

#: The Personal Agent Protocol version implemented: draft 0.4, as of upstream commit 46beb21.
PROTOCOL_PROFILE = "0.4"
#: The upstream specification revision implemented: the date of commit 46beb21.
PROTOCOL_REVISION = "2026-11-06"

__all__ = ["PROTOCOL_PROFILE", "PROTOCOL_REVISION"]
