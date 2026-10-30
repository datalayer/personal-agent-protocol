/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

/**
 * Joining the personal agent's own browser to a PAP Session (§6, §10.6).
 *
 * 1. The browser loads `web.browser_session_endpoint` with a GET and gets a form holding a
 *    one-time `code`, tied to that browser by a `SameSite=Strict` cookie.
 * 2. The personal agent authorizes the code in a request of its own:
 *    `POST {browser_session_endpoint}/authorize` with `{"code": ...}`, the Session header of
 *    the Session the browser joins and, signed in, its access token. The company answers `204`.
 * 3. The browser submits the form, the code alone; the company answers with the Session's
 *    cookie. The access token never passes through the browser.
 *
 * The code is read from the agent's own browser only, by host code the model cannot read
 * (§10.2): never from a message or another page. Only a browser the personal agent controls
 * joins, never the User's own (§6).
 *
 * A join with a token signs the browser in, in place of any login it had; one without leaves
 * the login the browser has, and ends the sign-in of an earlier join (§6).
 */

import type { ReactorPlatformView } from "@datalayer/reactor";

import { BrowserSessionError, TransportError } from "./errors.js";
import { BrowserJoins, Clocks, firstContribution } from "./reactor.js";
import type { AccessToken, PapSession } from "./sessions.js";
import type { SessionFetchClient } from "./transport.js";

/** A join code carries at least 128 random bits (§6): 22 base64url characters or more. */
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
  /** The Session the browser joins. */
  readonly session: PapSession;
  /** Signed in with it, signed out without. */
  readonly token?: AccessToken | undefined;
}

/** Join the agent's own browser to a Session: load, authorize, submit (§6). */
export class BrowserSessionClient {
  readonly #reactor: ReactorPlatformView;
  readonly #transport: SessionFetchClient;

  constructor(options: {
    readonly reactor: ReactorPlatformView;
    readonly transport: SessionFetchClient;
  }) {
    this.#reactor = options.reactor;
    this.#transport = options.transport;
  }

  /**
   * Join the agent's browser to the Session, signed in with `token` or signed out (§6).
   *
   * The code is authorized at `{endpoint}/authorize` with the Session header and the access
   * token; a code the company refuses there is a `BrowserSessionError`, and the agent starts
   * again at step 1.
   */
  async join(options: BrowserJoinOptions): Promise<BrowserSessionStart> {
    const endpoint = httpsUrl(options.browserSessionEndpoint, "browserSessionEndpoint");
    const clock = firstContribution(this.#reactor, Clocks, "clock");
    const browser = firstContribution(this.#reactor, BrowserJoins, "browser join");
    const code = await browser.loadJoinForm(endpoint);
    if (code.reveal().length < MIN_CODE_LENGTH) {
      throw new BrowserSessionError(
        "invalid_join_code",
        "The join page's code is too short to be one-time",
      );
    }
    let response: Response;
    try {
      response = await this.#transport.request(
        "POST",
        `${options.browserSessionEndpoint.replace(/\/+$/, "")}/authorize`,
        {
          session: options.session,
          token: options.token,
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ code: code.reveal() }),
        },
      );
    } catch (cause) {
      if (!(cause instanceof TransportError)) throw cause;
      throw new BrowserSessionError(cause.code, "Authorizing the join code failed", { cause });
    }
    await response.body?.cancel().catch(() => undefined);
    if (response.status !== 204) {
      throw new BrowserSessionError(
        "join_not_authorized",
        "The company refused to authorize the join code",
        { statusCode: response.status },
      );
    }
    await browser.submitJoinForm();
    return { endpoint: options.browserSessionEndpoint, joinedAt: clock.now() };
  }
}
