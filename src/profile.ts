/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

// The exact PAP version this SDK implements, as in Python's personal_agent_protocol.profile.
// PROTOCOL_PROFILE is the version, PROTOCOL_REVISION the date of the upstream
// specification page it was implemented from; the Operations extension version is
// OPERATIONS_VERSION (operations.ts). A test holds both SDKs and the docs equal.

/** The Personal Agent Protocol version implemented: 0.4 as published, the 1.0 release candidate. */
export const PROTOCOL_PROFILE = "0.4";
/** The upstream specification revision implemented: the day 0.4 was published (commit 4803900). */
export const PROTOCOL_REVISION = "2026-11-10";

// DRAFT_PROTOCOL_VERSION is version 1.0, a draft until upstream published and froze it on
// 2026-11-14, and DRAFT_PROTOCOL_REVISION the date of the text implemented: since 0.37, 1.0 as
// published (commit 8c02b42). The names stay from the draft. Since 0.36 it is
// DEFAULT_PROTOCOL_VERSION, the version a Personal Agent or a Company uses unless it asks for
// others (`protocolVersions`): 0.4 as published stays available, used only when named.

/** Protocol version 1.0, the default since 0.36 (named while it was the draft). */
export const DRAFT_PROTOCOL_VERSION = "1.0";
/** The 1.0 text implemented: 1.0 as published and frozen on 2026-11-14 (commit 8c02b42). */
export const DRAFT_PROTOCOL_REVISION = "2026-11-14";
/** The version used unless a Personal Agent or a Company names others: 1.0. */
export const DEFAULT_PROTOCOL_VERSION = DRAFT_PROTOCOL_VERSION;
