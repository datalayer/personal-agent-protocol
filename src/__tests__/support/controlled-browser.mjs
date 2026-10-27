/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

// The personal agent's own browser (`pap.browserJoin`), never the user's (§5): the port
// of Python's personal_agent_protocol.demo.kit.ControlledBrowser. It has its own cookie
// jar: it loads the join form, reads the one-time code from that page alone, submits the
// code with the agent's proof, follows the company's redirects, and remembers the page it
// landed on. Nothing here is part of the SDK: a host owns it.

import { BrowserSessionError, SecretValue } from "../../../lib/index.js";

const HIDDEN = /<input type="hidden" name="([^"]+)" value="([^"]*)">/g;
const REDIRECTS = new Set([301, 302, 303, 307, 308]);

function setCookies(headers) {
  if (typeof headers.getSetCookie === "function") return headers.getSetCookie();
  const value = headers.get("set-cookie");
  return value ? [value] : [];
}

export class ControlledBrowser {
  constructor(fetch) {
    this.fetch = fetch; // its own fetch, and below its own cookie jar
    this.cookies = new Map(); // host → Map(name → value)
    this.page = undefined;
  }

  /** `pap.browserJoin`: load the join form; its one-time code, from that page alone. */
  async loadJoinForm(endpoint) {
    this.page = await this.#follow(String(endpoint), { method: "GET", headers: {} }, false);
    const fields = Object.fromEntries([...this.page.text.matchAll(HIDDEN)].map((match) => [match[1], match[2]]));
    if (this.page.status !== 200 || !fields.code) {
      throw new BrowserSessionError("invalid_join_form", "The join page holds no code");
    }
    this.join = { endpoint: String(endpoint), code: fields.code };
    return new SecretValue(fields.code);
  }

  /** `pap.browserJoin`: submit the code and the proof, and follow where the company sends it. */
  async submitJoinForm(proof) {
    if (this.join === undefined) throw new BrowserSessionError("invalid_join_form", "No join form was loaded");
    const { endpoint, code } = this.join;
    this.join = undefined;
    this.page = await this.#follow(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ code, proof: proof.reveal() }).toString(),
    });
  }

  /** A form POST from this browser, its cookies sent; the answer itself, never followed. */
  async postForm(url, fields) {
    return this.#follow(String(url), {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(fields).toString(),
    }, false);
  }

  async get(url) {
    this.page = await this.#follow(url, { method: "GET", headers: {} });
    return this.page;
  }

  /**
   * Press a button on the company's page: a same-origin form POST. As a browser does, it
   * sends the page's hidden fields (its CSRF token among them) with the button's.
   */
  async submit(url, form) {
    const origin = new URL(url).origin;
    const hidden = this.page === undefined ? {} : Object.fromEntries([...this.page.text.matchAll(HIDDEN)].map((match) => [match[1], match[2]]));
    this.page = await this.#follow(url, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", Origin: origin, "Sec-Fetch-Site": "same-origin" },
      body: new URLSearchParams({ ...hidden, ...form }).toString(),
    });
    return this.page;
  }

  async #follow(url, init, redirects = true) {
    const history = [];
    let current = new URL(url);
    let request = init;
    for (let hop = 0; hop < 5; hop += 1) {
      const jar = this.cookies.get(current.host);
      const headers = { ...request.headers };
      if (jar?.size) headers.Cookie = [...jar].map(([name, value]) => `${name}=${value}`).join("; ");
      const response = await this.fetch(current.toString(), { ...request, headers, redirect: "manual" });
      for (const line of setCookies(response.headers)) {
        const [pair] = line.split(";", 1);
        const at = pair.indexOf("=");
        if (at <= 0) continue;
        if (!this.cookies.has(current.host)) this.cookies.set(current.host, new Map());
        this.cookies.get(current.host).set(pair.slice(0, at).trim(), pair.slice(at + 1).trim());
      }
      const location = response.headers.get("location");
      if (!redirects || !REDIRECTS.has(response.status) || !location) {
        return { status: response.status, url: current.toString(), headers: response.headers, text: await response.text(), history };
      }
      await response.body?.cancel().catch(() => undefined);
      history.push({ status: response.status, headers: response.headers });
      current = new URL(location, current);
      if (response.status === 303 || ((response.status === 301 || response.status === 302) && request.method === "POST")) {
        request = { method: "GET", headers: {} };
      }
    }
    throw new Error("too many redirects");
  }
}
