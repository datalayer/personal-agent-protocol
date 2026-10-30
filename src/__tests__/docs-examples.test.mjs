/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

// Every TypeScript code example in the README and the docs runs, as written (as
// Python's test_docs_examples.py runs the Python ones).
//
// Each ```typescript (or ```ts) block of README.md and docs/docs/**/*.mdx has its types
// stripped (node:module stripTypeScriptTypes), its imports bound to the SDK's entries,
// and runs against reference companies on an in-process network: example.com,
// shop.example, auth.example.com and auth.company.example are Manzanita under those
// names, and the personal agent is https://agent.example/agent.json. A block that is a
// fragment gets the names it uses (reactor, metadata, session, …) from its case below,
// made by really discovering, starting a Session or signing in; its own default `fetch`
// reaches the same network. Each case then checks what the example did. A block without
// a case fails: a new example needs one.
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { stripTypeScriptTypes } from "node:module";
import test from "node:test";

import * as portable from "../../lib/index.js";
import * as server from "../../lib/server.js";
import { ADA, ADA_CODE, manzanita } from "../../lib/demo/manzanita.js";
import { ControlledBrowser } from "./support/controlled-browser.mjs";
import { MutableClock, agentHost, agentIdentity, inProcessFetch } from "./support/world.mjs";

const ROOT = new URL("../../", import.meta.url);
const TENANT = "application-42";
const SCOPES = ["orders:read", "orders:write", "orders:return"];
const SCOPE_DESCRIPTIONS = {
  "orders:read": "See your orders",
  "orders:write": "Exchange or return items in your orders",
  "orders:return": "Return items",
};
const COMPANIES = {
  "example.com": "Example Company",
  "shop.example": "Example Shop",
  "auth.example.com": "Example Auth",
  "auth.company.example": "Example Company Auth",
};
const MODULES = {
  "@datalayer/personal-agent-protocol": portable,
  "@datalayer/personal-agent-protocol/server": server,
};

function mdxFiles(directory) {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const child = new URL(entry.name + (entry.isDirectory() ? "/" : ""), directory);
    if (entry.isDirectory()) return mdxFiles(child);
    return entry.name.endsWith(".mdx") ? [child] : [];
  });
}

const SOURCES = [new URL("README.md", ROOT), ...mdxFiles(new URL("docs/docs/", ROOT)).sort()];
const BLOCKS = {};
for (const url of SOURCES) {
  const relative = url.pathname.slice(ROOT.pathname.length);
  let index = 0;
  for (const match of readFileSync(url, "utf8").matchAll(/^```(\w+)[^\n]*\n([\s\S]*?)^```/gm)) {
    if (match[1] === "typescript" || match[1] === "ts") BLOCKS[`${relative}#${index++}`] = match[2];
  }
}

/** The world the examples run in. */
async function docsWorld() {
  const clock = new MutableClock();
  const sites = {};
  const fetch = inProcessFetch(sites);
  const identity = await agentIdentity({ domain: "agent.example", name: "Example Agent" });
  sites["agent.example"] = identity.documents;
  const companies = {};
  for (const [domain, name] of Object.entries(COMPANIES)) {
    const { service } = manzanita({ fetch, clock, config: { name, domain, scopes: SCOPES, scopeDescriptions: SCOPE_DESCRIPTIONS, writeScopes: ["orders:write"] } });
    sites[domain] = companies[domain] = service;
  }
  const host = await agentHost({ identity, fetch, clock, answers: [{ ...ADA }, { code: ADA_CODE }] });
  const pairwise = new Map();
  await host.reactor.install({
    name: "docs-pairwise",
    contributes: [
      {
        point: portable.PairwiseUserIdStores,
        value: {
          async getOrCreate({ tenantId, localUserId, companyIssuer }) {
            const key = JSON.stringify([tenantId, localUserId, companyIssuer]);
            if (!pairwise.has(key)) pairwise.set(key, `usr_docs_${pairwise.size}`);
            return pairwise.get(key);
          },
        },
        options: { id: "docs" },
      },
    ],
  });
  const reactor = host.reactor;
  const scope = {};
  // The user's browser: opens the consent page, and the user approves at once. The
  // company's redirect is what the example calls `incomingCallbackUrl`.
  const open = host.browser.open.bind(host.browser);
  host.browser.open = async (url) => {
    await open(url);
    const company = companies[new URL(url.reveal()).hostname];
    scope.incomingCallbackUrl = await company.approveAuthorization(host.browser.requestId, { accountId: "acct_ada" });
  };
  const transport = new portable.SessionFetchClient({ reactor, fetch });
  const discovered = (domain) => portable.discoverCompany(domain, { reactor });
  async function who(domain) {
    const issuer = (await discovered(domain)).oauthMetadata.issuer;
    const pairwiseUserId = await portable.resolvePairwiseUserId(reactor, {
      tenantId: TENANT,
      localUserId: "local-user-42",
      companyIssuer: issuer,
    });
    return { tenantId: TENANT, pairwiseUserId, issuer };
  }
  async function signedOut(domain) {
    const { issuer, pairwiseUserId } = await who(domain);
    return new portable.SessionClient({ reactor, fetch }).start({
      clientId: identity.clientId,
      pairwiseUserId,
      issuer,
      tenantId: TENANT,
    });
  }
  async function signedIn(domain, scopes) {
    const company = await discovered(domain);
    const metadata = company.oauthMetadata;
    const session = await signedOut(domain);
    const device = new portable.DeviceSignInClient({ reactor, fetch });
    const started = await device.begin({
      deviceAuthorizationEndpoint: metadata.device_authorization_endpoint,
      tokenEndpoint: metadata.token_endpoint,
      issuer: metadata.issuer,
      clientId: identity.clientId,
      scopes,
      tenantId: TENANT,
      organization: company.document.organization,
      protectedResources: metadata.protected_resources,
    });
    await companies[domain].approveDevice(started.userCode, { accountId: "acct_ada" });
    clock.advance(started.pollInterval);
    const done = await device.poll(started.reference);
    assert.equal(done.status, "complete");
    return { session, token: done.token, reference: done.refreshTokenReference };
  }
  /** A signed-in Session and an operation its company returned (an exchange). */
  async function proposed(domain) {
    const { session, token } = await signedIn(domain, ["orders:read", "orders:write"]);
    const answer = await new portable.ApiClient({ transport }).call("POST", `https://${domain}/api/orders/ord_7Hk2/exchanges`, { session, token, body: {} });
    return { session, token, operation: answer.operation };
  }
  return { clock, fetch, identity, companies, host, reactor, scope, transport, discovered, who, signedOut, signedIn, proposed };
}

const CASES = {};
const nothing = async () => {};
function example(keys, prepare) {
  for (const key of [keys].flat()) CASES[key] = prepare;
}

// Discovery and identity ------------------------------------------------------------------

example(["README.md#0", "docs/docs/getting-started/index.mdx#0"], async () => [
  {},
  async (_, out) => assert.ok(out.some((line) => line.includes("Example Company"))),
]);

example("README.md#1", async () => {
  const mySecurityPlugin = { name: "my-security", contributes: [] };
  return [{ mySecurityPlugin }, async (values) => assert.equal(values.company.document.organization.domain, "example.com")];
});

example(["README.md#2", "docs/docs/sdk/typescript.mdx#4"], async () => [
  {},
  async (values) => {
    assert.equal(typeof values.__imports.JoseSigner, "function");
    assert.equal(typeof values.__imports.NodeUrlSafetyPolicy, "function");
  },
]);

example("docs/docs/sdk/typescript.mdx#0", async () => {
  const checked = [];
  const serverDnsPolicy = { async assertSafe(url) { checked.push(url.hostname); } };
  return [{ serverDnsPolicy }, async (values) => {
    assert.equal(values.company.document.organization.name, "Example Company");
    assert.ok(checked.includes("example.com"));
  }];
});

example("docs/docs/sdk/typescript.mdx#1", async (w) => [
  { reactor: w.reactor, discoverCompany: portable.discoverCompany },
  async (values) => assert.equal(values.company.document.organization.domain, "example.com"),
]);

example("docs/docs/sdk/typescript.mdx#2", async (w) => [
  { reactor: w.reactor, controller: new AbortController() },
  async (values) => {
    assert.equal(values.metadata.client_name, "Example Agent");
    assert.equal(values.jwks.keys[0].kid, "key-1");
  },
]);

example("docs/docs/sdk/typescript.mdx#3", async (w) => [
  { reactor: w.reactor },
  async (values, out) => {
    assert.equal(values.session.clientId, "https://agent.example/agent.json");
    assert.ok(values.session.sub.startsWith("usr_"));
    assert.equal(values.session.handle, `ses_${values.session.sid}`);
    assert.deepEqual(out, [`${values.session.sid} ${values.session.handle}`]);
  },
]);

example("docs/docs/guides/operational-limits.mdx#0", async (w) => [
  { reactor: w.reactor },
  async (values) => assert.equal(values.company.document.organization.domain, "shop.example"),
]);

// Sessions and sign-in ----------------------------------------------------------------------

example("docs/docs/guides/sessions.mdx#0", async (w) => [
  { reactor: w.reactor },
  async (values) => {
    assert.equal(values.session.handle, `ses_${values.session.sid}`);
    assert.equal(values.session.issuer, "https://auth.company.example");
  },
]);

example("docs/docs/guides/direct-sign-in.mdx#0", async (w) => [
  { reactor: w.reactor, fetch: w.fetch, request: { signal: new AbortController().signal } },
  async (values, out) => {
    assert.deepEqual(values.result.grantedScopes, ["orders:read"]);
    assert.ok(values.refreshReference.startsWith("refresh_"));
    assert.ok(out[0].endsWith(' ["orders:read"] []'));
  },
]);

example("docs/docs/guides/device-sign-in.mdx#0", async (w) => {
  const company = await w.discovered("shop.example");
  const metadata = company.oauthMetadata;
  const shown = [];
  return [
    {
      DeviceSignInClient: portable.DeviceSignInClient,
      reactor: w.reactor,
      fetch: w.fetch,
      company,
      metadata,
      renderHumanHandoff: (...values) => shown.push(values),
      abortSignal: new AbortController().signal,
    },
    async (values) => {
      assert.ok(shown[0][0].startsWith("https://shop.example/"));
      assert.equal(shown[0][1], values.started.userCode);
      assert.equal(values.result.status, "pending");
    },
  ];
});

example("docs/docs/guides/mediated-sign-in.mdx#0", async (w) => {
  const company = await w.discovered("shop.example");
  return [
    {
      MediatedSignInClient: portable.MediatedSignInClient,
      reactor: w.reactor,
      fetch: w.fetch,
      company,
      clientId: w.identity.clientId,
      scopes: ["orders:read"],
    },
    async (values) => {
      assert.equal(values.result.status, "complete");
      assert.deepEqual(values.result.token.scopes, ["orders:read"]);
    },
  ];
});

example("docs/docs/guides/account-tokens.mdx#0", async (w) => {
  const metadata = (await w.discovered("shop.example")).oauthMetadata;
  const { issuer, tenantId } = await w.who("shop.example");
  const { reference } = await w.signedIn("shop.example", ["orders:read"]);
  const asked = [];
  return [
    {
      RefreshTokenClient: portable.RefreshTokenClient,
      reactor: w.reactor,
      fetch: w.fetch,
      refreshTokenReference: reference,
      tokenEndpoint: metadata.token_endpoint,
      revocationEndpoint: metadata.revocation_endpoint,
      issuer,
      clientId: w.identity.clientId,
      tenantId,
      token: undefined,
      askTheUserToSignInAgain: () => asked.push("again"),
      continueSignedOut: () => asked.push("signed out"),
    },
    async (values) => {
      assert.equal(values.result.status, "signed_in");
      assert.deepEqual(values.result.token.scopes, ["orders:read"]);
      assert.deepEqual(asked, []);
    },
  ];
});

// Conversations and operations ----------------------------------------------------------

example("docs/docs/guides/conversations.mdx#0", async (w) => {
  const company = await w.discovered("shop.example");
  const session = await w.signedOut("shop.example");
  const endpoint = company.document.agent.protocols[0].endpoint;
  const conversations = new portable.ConversationClient({ reactor: w.reactor, transport: w.transport });
  const message = { id: conversations.generateMessageId(), author: { type: "human" }, text: "Hello" };
  const page = await conversations.start(endpoint, message, { session, wait: 0 });
  await conversations.close(endpoint, page.conversation_id, { session });
  const handled = [];
  return [
    {
      conversations,
      endpoint,
      conversationId: page.conversation_id,
      session,
      ui: { showTyping() {}, dropPartial() {} },
      handleEvent: (event) => handled.push(event),
    },
    async () => assert.equal(handled[0].type, "message"),
  ];
});

example("docs/docs/guides/operations.mdx#0", async (w) => {
  const proposed = await w.proposed("shop.example");
  return [
    {
      ...proposed,
      api: new portable.ApiClient({ transport: w.transport }),
      url: "https://shop.example/api/orders/ord_7Hk2/exchanges",
      body: {},
      organization: (await w.discovered("shop.example")).document.organization,
      tenantId: TENANT,
      operations: new portable.OperationsClient({ reactor: w.reactor }),
    },
    async (values) => {
      assert.equal(values.sent.status, "answered");
      assert.ok(values.sent.answer.body.summary.startsWith("Exchanged"));
      assert.equal(w.host.approvals.asked[0].summary, proposed.operation.summary);
    },
  ];
});

example("docs/docs/guides/operations.mdx#1", async () => {
  const shown = JSON.parse(readFileSync(new URL("protocol/fixtures/pap-confirm-display.json", ROOT), "utf8"));
  return [
    { result: { _meta: { "reactor.ui/display": shown } } },
    async (values) => {
      assert.deepEqual(values.asked, shown.data);
    },
  ];
});

// OpenAPI, MCP and the website ----------------------------------------------------------

example("docs/docs/sdk/typescript.mdx#5", async (w) => {
  const { session, token } = await w.signedIn("shop.example", ["orders:read", "orders:write"]);
  return [
    { reactor: w.reactor, session, token },
    async (values, out) => {
      assert.equal(values.orders.status, 200);
      assert.equal(values.orders.body.orders[0].order_id, "ord_7Hk2");
      assert.equal(values.proposed.status, 403);
      assert.ok(values.proposed.operation.operation_id);
      assert.ok(out[0].startsWith("403 "));
    },
  ];
});

example("docs/docs/sdk/typescript.mdx#6", async (w) => {
  const company = await w.discovered("shop.example");
  const metadata = company.oauthMetadata;
  const { issuer, tenantId } = await w.who("shop.example");
  const { session, reference } = await w.signedIn("shop.example", ["orders:read", "orders:write"]);
  return [
    {
      reactor: w.reactor,
      company,
      session,
      refreshTokenReference: reference,
      tokenEndpoint: metadata.token_endpoint,
      clientId: w.identity.clientId,
      issuer,
      tenantId,
    },
    async (values) => {
      assert.equal(values.mcpUrl, "https://shop.example/mcp");
      assert.equal(values.refreshed.token.resource, values.mcpUrl);
      assert.equal(values.refreshed.token.tokenType, "Bearer");
      assert.deepEqual(values.tools.map((tool) => tool.name), ["list_orders", "exchange_jacket"]);
      assert.ok(values.result.operation.operation_id);
    },
  ];
});

example("docs/docs/examples/browser-session.mdx#0", async (w) => {
  const company = await w.discovered("shop.example");
  const { session, token } = await w.signedIn("shop.example", ["orders:read", "orders:write"]);
  const browser = new ControlledBrowser(w.fetch);
  await w.reactor.install({
    name: "docs-controlled-browser",
    contributes: [{ point: portable.BrowserJoins, value: browser, options: { id: "controlled-browser" } }],
  });
  return [
    { reactor: w.reactor, company, session, token, browser },
    async () => {
      // The browser holds the Session's cookie, and the company knows it for that Session.
      const cookie = browser.cookies.get("shop.example").get("__Host-poppy_session");
      const joined = await w.companies["shop.example"].webSession(cookie);
      assert.equal(joined.sid, session.sid);
      assert.equal(joined.accountId, "acct_ada");
    },
  ];
});

example("docs/docs/sdk/typescript.mdx#7", async () => [
  {},
  async (values, out) => {
    assert.equal(values.config.web, true);
    assert.deepEqual(out, ["https://shop.example/poppy/browser-session"]);
  },
]);

// Companies and extensions --------------------------------------------------------------

example("docs/docs/guides/company.mdx#0", async () => {
  const ran = [];
  return [
    {
      MyDatabaseStore: class extends server.MemoryCompanyStore {},
      url: "memory://",
      test: (name, body) => ran.push([name, body()]),
    },
    async () => {
      assert.equal(ran.length, 1);
      await ran[0][1]; // the store kit passed
    },
  ];
});

example("docs/docs/guides/telemetry.mdx#0", async () => {
  const spans = [];
  const tracer = {
    startSpan(name, options) {
      spans.push({ name, attributes: options.attributes });
      return { setStatus() {}, end() {} };
    },
  };
  return [{ tracer }, async (values) => {
    assert.equal(values.company.document.organization.domain, "example.com");
    assert.deepEqual(spans, [{
      name: "pap.discovery.discover",
      attributes: {
        "pap.company.domain": "example.com",
        "pap.company.issuer": "https://example.com",
        "pap.stage": "discovery",
        "pap.outcome": "ok",
      },
    }]);
    values.reactor.stop();
  }];
});

example("docs/docs/guides/extensions.mdx#0", async () => [
  {},
  async (values) => assert.deepEqual(values.negotiated, { operations: "2" }),
]);

// The runner -------------------------------------------------------------------------------

const AsyncFunction = (async () => {}).constructor;

/** One example as a function of its scope: imports bound, top-level names returned. */
function compile(code) {
  let js = stripTypeScriptTypes(code);
  js = js.replace(/import\s*\{([^}]*)\}\s*from\s*['"]([^'"]+)['"];?/g, (_, names, specifier) => {
    const bound = names.replace(/\bas\b/g, ":");
    return `const {${bound}} = __import(${JSON.stringify(specifier)}, ${JSON.stringify(names)});`;
  });
  const declared = [...js.matchAll(/^(?:const|let)\s+(\w+)\s*=/gm)].map((match) => match[1]);
  const body = `with (__scope) {\n${js}\nreturn { ${declared.join(", ")} };\n}`;
  return new AsyncFunction("__scope", "__import", body);
}

test("every TypeScript example has a case", () => {
  assert.ok(Object.keys(BLOCKS).length > 0, "no TypeScript examples were found");
  assert.deepEqual(Object.keys(BLOCKS).sort(), Object.keys(CASES).sort());
});

for (const [key, code] of Object.entries(BLOCKS)) {
  test(`the TypeScript example runs: ${key}`, async () => {
    const w = await docsWorld();
    const [given, check] = await (CASES[key] ?? nothing)(w);
    const out = [];
    const imports = {};
    Object.assign(w.scope, given, {
      console: { log: (...values) => out.push(values.map((value) => (typeof value === "string" ? value : JSON.stringify(value))).join(" ")) },
    });
    const bind = (specifier, names) => {
      const module = MODULES[specifier];
      assert.ok(module, `an example imports ${specifier}`);
      for (const name of names.split(",").map((part) => part.trim().split(/\s+as\s+/)[0]).filter(Boolean)) {
        assert.ok(name in module, `${specifier} exports ${name}`);
        imports[name] = module[name];
      }
      return module;
    };
    const fetch = globalThis.fetch;
    globalThis.fetch = w.fetch; // an example's default fetch reaches the in-process network
    let values;
    try {
      values = await compile(code)(w.scope, bind);
    } finally {
      globalThis.fetch = fetch;
    }
    await check({ ...given, ...values, __imports: imports }, out);
    w.reactor.stop();
  });
}
