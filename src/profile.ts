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

// DRAFT_PROTOCOL_VERSION is the 1.0 draft, which a Personal Agent or a Company uses only when it
// asks for it (`protocolVersions`): a draft can still change in ways that aren't backward
// compatible, so the SDK announces PROTOCOL_PROFILE unless told otherwise.

/** The draft protocol version a Personal Agent or a Company can opt into: the 1.0 draft. */
export const DRAFT_PROTOCOL_VERSION = "1.0";
/** The draft's revision implemented: lookalike domains, its first fix (commit c71f515). */
export const DRAFT_PROTOCOL_REVISION = "2026-11-11";
