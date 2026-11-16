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

// DRAFT_PROTOCOL_VERSION is the 1.0 draft. Since 0.36 it is DEFAULT_PROTOCOL_VERSION, the
// version a Personal Agent or a Company uses unless it asks for others (`protocolVersions`):
// 0.4 as published stays available, used only when named.

/** The draft protocol version, the 1.0 draft: the default since 0.36. */
export const DRAFT_PROTOCOL_VERSION = "1.0";
/** The draft's revision implemented: lookalike domains, its first fix (commit c71f515). */
export const DRAFT_PROTOCOL_REVISION = "2026-11-11";
/** The version used unless a Personal Agent or a Company names others: the 1.0 draft. */
export const DEFAULT_PROTOCOL_VERSION = DRAFT_PROTOCOL_VERSION;
