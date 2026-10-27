/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

/**
 * Joining the personal agent's own browser to a PAP Session (§5, §9.6).
 *
 * The browser loads `web.browser_session_endpoint` with a GET and gets a form holding a
 * one-time `code`, tied to that browser by a `SameSite=Strict` cookie. The personal agent
 * signs a DPoP proof with the Session Key, the code as its `nonce`, and the browser
 * submits code and proof; the company answers with the Session's cookie. The code is
 * read from the agent's own browser only, by host code the model cannot read (§9.2):
 * never from a message or another page.
 */

import type { ReactorPlatformView } from "@datalayer/reactor";

import { BrowserSessionError } from "./errors.js";
import { BrowserJoins, Clocks, DpopProofProviders, firstContribution } from "./reactor.js";
import { SecretValue } from "./secret.js";

/** A join code carries at least 128 random bits (§5): 22 base64url characters or more. */
const MIN_CODE_LENGTH = 22;

function httpsUrl(value: string, label: string): URL {
  let url: URL;
  try {
    url = new URL(value);
  } catch (cause) {
    throw new BrowserSessionError("invalid_url", `${label} must be an HTTPS URL`, { cause });
  }
  if (url.protocol !== "https:" || !url.hostname || url.username || url.password) {
    throw new BrowserSessionError("invalid_url", `${label} must be an HTTPS URL`);
  }
  return url;
}

/** Safe status once the browser has submitted the join form. */
export interface BrowserSessionStart {
  readonly endpoint: string;
  readonly joinedAt: Date;
}

export interface BrowserJoinOptions {
  readonly browserSessionEndpoint: string;
  readonly tenantId: string;
  readonly issuer: string;
  /** The Session the browser joins, signed in or out: its Session Key's thumbprint. */
  readonly sessionKey: string;
}

/** Join the agent's own browser to a Session with a proof over a one-time code. */
export class BrowserSessionClient {
  readonly #reactor: ReactorPlatformView;

  constructor(options: { readonly reactor: ReactorPlatformView }) {
    this.#reactor = options.reactor;
  }

  /**
   * Load the join form, sign its code with the Session Key, submit it (§5).
   *
   * The proof's `htm` is POST, its `htu` the endpoint, its `nonce` the code; it has no
   * `ath`.
   */
  async join(options: BrowserJoinOptions): Promise<BrowserSessionStart> {
    const endpoint = httpsUrl(options.browserSessionEndpoint, "browserSessionEndpoint");
    const clock = firstContribution(this.#reactor, Clocks, "clock");
    const browser = firstContribution(this.#reactor, BrowserJoins, "browser join");
    const prover = firstContribution(this.#reactor, DpopProofProviders, "DPoP proof provider");
    const code = await browser.loadJoinForm(endpoint);
    if (code.reveal().length < MIN_CODE_LENGTH) {
      throw new BrowserSessionError(
        "invalid_join_code",
        "The join page's code is too short to be one-time",
      );
    }
    const proof = await prover.create({
      method: "POST",
      url: options.browserSessionEndpoint,
      tenantId: options.tenantId,
      issuer: options.issuer,
      sessionKey: options.sessionKey,
      nonce: code.reveal(),
    });
    await browser.submitJoinForm(proof);
    return { endpoint: options.browserSessionEndpoint, joinedAt: clock.now() };
  }
}

/** The `nonce` a join proof carries: the code itself (§5, RFC 9449 §8). */
export function joinProofNonce(code: SecretValue | string): string {
  return code instanceof SecretValue ? code.reveal() : code;
}
