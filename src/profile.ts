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

// PUBLISHED_PROTOCOL_VERSION is version 1.0, as upstream published and froze it on 2026-11-14
// (commit 8c02b42, PUBLISHED_PROTOCOL_REVISION). It is DEFAULT_PROTOCOL_VERSION, the version a
// Personal Agent or a Company uses and announces unless it asks for others
// (`protocolVersions`). DRAFT_PROTOCOL_VERSION is upstream's unpublished draft 1.1, which adds
// to 1.0 without breaking it (§3.4), and DRAFT_PROTOCOL_REVISION the date of the draft text
// implemented (commit 589743a): it can change until upstream publishes it, and is used only
// when named, as 0.4 is. From 1.0 each side sends only what the other's version defines (§3.4),
// so nothing of 1.1 goes to a peer at 1.0.

/** Protocol version 1.0 as published, the default. */
export const PUBLISHED_PROTOCOL_VERSION = "1.0";
/** The 1.0 text implemented: 1.0 as published and frozen on 2026-11-14 (commit 8c02b42). */
export const PUBLISHED_PROTOCOL_REVISION = "2026-11-14";
/** Upstream's draft 1.1, unpublished: available when named, and it may change. */
export const DRAFT_PROTOCOL_VERSION = "1.1";
/** The draft 1.1 text implemented: upstream on 2026-11-18 (commit 589743a). */
export const DRAFT_PROTOCOL_REVISION = "2026-11-18";
/** The version used unless a Personal Agent or a Company names others: 1.0 as published. */
export const DEFAULT_PROTOCOL_VERSION = PUBLISHED_PROTOCOL_VERSION;
