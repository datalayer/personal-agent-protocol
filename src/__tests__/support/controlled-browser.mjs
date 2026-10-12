// The personal agent's own browser (`pap.browserFormPost`), never the user's (§5): the
// port of Python's personal_agent_protocol.demo.kit.ControlledBrowser. It has its own
// cookie jar, posts the browser assertion as a form, follows the company's redirects,
// and remembers the page it landed on. Nothing here is part of the SDK: a host owns it.

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

  /** `pap.browserFormPost`: post the fields as a form and follow where the company sends it. */
  async post(url, fields) {
    const body = new URLSearchParams(Object.entries(fields).map(([name, value]) => [name, value.reveal()]));
    this.page = await this.#follow(String(url), {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
    });
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

  async #follow(url, init) {
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
      if (!REDIRECTS.has(response.status) || !location) {
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
