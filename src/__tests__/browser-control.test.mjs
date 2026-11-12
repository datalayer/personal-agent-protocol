/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

// The Browser Control extension, version 1: marks, control, the controller value.
import assert from "node:assert/strict";
import test from "node:test";
import vm from "node:vm";

import {
  BROWSER_CONTROL_EXTENSION,
  BROWSER_CONTROL_VERSION,
  BROWSER_SIGN_IN_SCOPE,
  BrowserControl,
  BrowserControlError,
  BrowserSessionClient,
  DeviceSignInClient,
  SessionClient,
  SessionFetchClient,
  browserControlNegotiated,
  controllerScript,
  controllerUpdateScript,
  discoverCompany,
  negotiateExtensions,
  onCompanyHost,
  pageMarks,
  userStepKind,
} from "../../lib/index.js";
import { manzanita } from "../../lib/demo/manzanita.js";
import { ControlledBrowser } from "./support/controlled-browser.mjs";
import { MutableClock, agentHost, agentIdentity, inProcessFetch } from "./support/world.mjs";

const PICKUP_PAGE = "https://manzanita.example/orders/ord_7Hk2/pickup";
const BROWSE = ["orders:read", "orders:write", BROWSER_SIGN_IN_SCOPE];

const CHECK_IN = `
<form id="checkin" action="/bookings/bkg_4Rt9/check-in" method="post"
      data-poppy-user-step="submission">
  <label>Seat <select name="seat"><option>12C</option></select></label>
  <label>Passport <input name="passport_number" data-poppy-user-step="interaction"></label>
  <button type="submit">Check in</button>
  <button type="button" name="help">Help</button>
</form>
<input name="newsletter" type="checkbox" form="checkin">
<input name="orphan" form="missing">
<form action="/search"><input name="q"><button>Search</button></form>
<form action="/account" data-poppy-user-step="interaction">
  <input name="email"><input type="submit" value="Save">
</form>
<button data-poppy-user-step="submission" name="pay">Pay</button>
<a href="/x" data-poppy-user-step="interaction">not a control</a>
<script>const markup = '<input name="in_script">';</script>
<!-- <input name="in_comment"> -->
`;

test("a value other than the two, or submission off a form, is interaction", () => {
  assert.equal(userStepKind(undefined, { onForm: true }), undefined);
  assert.equal(userStepKind("submission", { onForm: true }), "submission");
  assert.equal(userStepKind("submission", { onForm: false }), "interaction");
  assert.equal(userStepKind("interaction", { onForm: true }), "interaction");
  for (const value of ["", "later", "SUBMISSIONS"]) assert.equal(userStepKind(value, { onForm: true }), "interaction");
});

test("marks add up and cover what section 4 says", () => {
  const marks = pageMarks(CHECK_IN);
  const [checkin, search, account] = marks.forms;
  assert.deepEqual([checkin.mark, search.mark, account.mark], ["submission", undefined, "interaction"]);
  assert.ok(marks.marked);
  const control = (name) => {
    const found = marks.control({ name });
    assert.ok(found !== undefined, name);
    return found;
  };
  // A submission form: its controls can be filled in, submitting it is the User's.
  assert.ok(marks.mayChange(control("seat")));
  assert.equal(marks.maySubmit(checkin), false);
  const submit = marks.controls.find((c) => c.form === checkin.index && c.submits);
  assert.equal(marks.mayChange(submit), false);
  assert.ok(marks.mayChange(control("help"))); // a plain button submits nothing
  // A marked control inside it is the User's too: marks add up.
  assert.equal(marks.mayChange(control("passport_number")), false);
  // A control outside the form that names it in `form` is the form's own.
  assert.equal(control("newsletter").form, checkin.index);
  assert.ok(marks.mayChange(control("newsletter")));
  // A `form` attribute naming no form leaves the control without an owner.
  assert.equal(control("orphan").form, undefined);
  // An unmarked form is the agent's.
  assert.ok(marks.mayChange(control("q")) && marks.maySubmit(search));
  // An interaction form: neither its controls nor submitting it.
  assert.equal(marks.mayChange(control("email")), false);
  assert.equal(marks.maySubmit(account), false);
  // `submission` on anything but a form counts as interaction.
  assert.equal(control("pay").mark, "interaction");
  assert.equal(marks.mayChange(control("pay")), false);
  assert.equal(marks.userSteps()[0], "submitting the form to /bookings/bkg_4Rt9/check-in");
  // Script text and comments are not markup.
  assert.equal(marks.control({ name: "in_script" }), undefined);
  assert.equal(marks.control({ name: "in_comment" }), undefined);
  assert.equal(pageMarks("<form><input name=a></form>").marked, false);
  // A form inside a form is ignored, as HTML's parser does.
  const nested = pageMarks('<form id=a><form id=b data-poppy-user-step=submission><input name=x></form>');
  assert.equal(nested.forms.length, 1);
  assert.equal(nested.control({ name: "x" }).form, 0);
});

test("only the User ends their control, and the model waits for nothing", () => {
  const changes = [];
  const control = new BrowserControl({ onChange: (value) => changes.push(value) });
  const marks = pageMarks(CHECK_IN);
  const checkin = marks.forms[0];
  assert.equal(control.controller, "agent");
  control.checkChange(marks, marks.control({ name: "seat" }));
  assert.throws(() => control.checkSubmit(marks, checkin), (error) => error instanceof BrowserControlError && error.code === "user_step");
  assert.throws(() => control.checkChange(marks, marks.control({ name: "passport_number" })), BrowserControlError);
  assert.ok(control.offer(marks).length > 0);
  control.handToUser();
  assert.equal(control.controller, "user");
  assert.deepEqual(changes, ["user"]);
  // While the User holds control nothing the model asks for is done, marked or not.
  assert.throws(
    () => control.checkChange(marks, marks.control({ name: "q" })),
    (error) => error instanceof BrowserControlError && error.code === "user_has_control",
  );
  assert.throws(() => control.checkModelAction(), BrowserControlError);
  control.handBack();
  assert.equal(control.controller, "agent");
  assert.deepEqual(changes, ["user", "agent"]);
  control.handToUser();
  control.cancel();
  assert.deepEqual(changes, ["user", "agent", "user", "agent"]);
});

/** A page in a fake browser: `navigator`, `location` and `window` on `host`. */
function pageContext(host) {
  const context = { navigator: {}, location: { hostname: host }, Symbol, Object };
  context.window = context;
  return vm.createContext(context);
}

test("navigator.poppy is only on the company's hosts, read-only, set by the host's software", () => {
  assert.ok(onCompanyHost("manzanita.example", "manzanita.example"));
  assert.ok(onCompanyHost("shop.manzanita.example", "Manzanita.Example"));
  assert.equal(onCompanyHost("evilmanzanita.example", "manzanita.example"), false);
  assert.equal(onCompanyHost("manzanita.example.evil", "manzanita.example"), false);
  const script = controllerScript("Manzanita.Example", "chan_1");
  assert.throws(() => controllerUpdateScript("chan_1", "model"), RangeError);

  const page = pageContext("shop.manzanita.example");
  vm.runInContext(script, page);
  assert.equal(vm.runInContext("navigator.poppy.controller", page), "agent");
  // The page can't change it.
  vm.runInContext('"use strict"; try { navigator.poppy.controller = "user"; } catch {}', page);
  vm.runInContext('try { navigator.poppy = { controller: "user" }; } catch {}', page);
  assert.equal(vm.runInContext("navigator.poppy.controller", page), "agent");
  // Running the script again changes nothing.
  vm.runInContext(script, page);
  vm.runInContext(controllerUpdateScript("chan_1", "user"), page);
  assert.equal(vm.runInContext("navigator.poppy.controller", page), "user");
  // A value other than the two is ignored; another channel reaches nothing.
  vm.runInContext('window[Symbol.for("chan_1")]("model")', page);
  vm.runInContext(controllerUpdateScript("chan_2", "agent"), page);
  assert.equal(vm.runInContext("navigator.poppy.controller", page), "user");
  vm.runInContext(controllerUpdateScript("chan_1", "agent"), page);
  assert.equal(vm.runInContext("navigator.poppy?.controller ?? ''", page), "agent");

  // Another website can't tell the browser is a personal agent's.
  const other = pageContext("evilmanzanita.example");
  vm.runInContext(script, other);
  assert.equal(vm.runInContext("navigator.poppy", other), undefined);
  vm.runInContext(controllerUpdateScript("chan_1", "user"), other);
  assert.equal(vm.runInContext("navigator.poppy", other), undefined);
});

async function world({ extensions } = {}) {
  const clock = new MutableClock();
  const sites = {};
  const fetch = inProcessFetch(sites);
  const identity = await agentIdentity({ domain: "atlas.example", name: "Atlas", ...(extensions ? { extensions } : {}) });
  sites["atlas.example"] = identity.documents;
  const { service: shop, plugin } = manzanita({ fetch, clock });
  sites["manzanita.example"] = shop;
  const browser = new ControlledBrowser(fetch);
  const host = await agentHost({ identity, fetch, clock, controlledBrowser: browser });
  const reactor = host.reactor;
  const company = await discoverCompany("manzanita.example", { reactor });
  const session = await new SessionClient({ reactor, fetch }).start({
    clientId: identity.clientId,
    pairwiseUserId: "usr_ada_at_manzanita_000000",
    issuer: company.oauthMetadata.issuer,
    tenantId: "atlas-demo",
    extensions: negotiateExtensions(company.document.extensions, identity.supportedExtensions),
  });
  return { clock, fetch, identity, shop, plugin, reactor, browser, company, session };
}

test("the company lists Browser Control and the join carries the declaration", async () => {
  const w = await world({ extensions: ["operations", BROWSER_CONTROL_EXTENSION] });
  const document = w.company.document;
  assert.deepEqual(document.extensions[BROWSER_CONTROL_EXTENSION], [{ version: BROWSER_CONTROL_VERSION }]);
  assert.equal(w.session.extensions[BROWSER_CONTROL_EXTENSION], "1");
  assert.ok(browserControlNegotiated(document, w.session));
  const metadata = w.company.oauthMetadata;
  const device = new DeviceSignInClient({ reactor: w.reactor, fetch: w.fetch });
  const started = await device.begin({
    deviceAuthorizationEndpoint: metadata.device_authorization_endpoint,
    tokenEndpoint: metadata.token_endpoint,
    issuer: metadata.issuer,
    clientId: w.identity.clientId,
    scopes: BROWSE,
    tenantId: "atlas-demo",
    organization: document.organization,
  });
  await w.shop.approveDevice(started.userCode, { accountId: "acct_ada" });
  w.clock.advance(started.pollInterval);
  const { token } = await device.poll(started.reference);
  await new BrowserSessionClient({ reactor: w.reactor, transport: new SessionFetchClient({ reactor: w.reactor, fetch: w.fetch }) }).join({
    browserSessionEndpoint: document.web.browser_session_endpoint,
    session: w.session,
    token,
  });
  const joined = await w.shop.webSession(w.browser.cookies.get("manzanita.example").get("__Host-poppy_session"));
  assert.equal(joined.extensions[BROWSER_CONTROL_EXTENSION], "1");

  // Manzanita's pickup form is the User's step: the agent fills in the store and stops.
  const page = await w.browser.get(PICKUP_PAGE);
  const marks = pageMarks(page.text);
  const form = marks.forms[0];
  const control = new BrowserControl();
  control.checkChange(marks, marks.control({ name: "store" }));
  assert.throws(() => control.checkSubmit(marks, form), BrowserControlError);
  assert.throws(() => control.checkChange(marks, marks.control({ name: "id_last4" })), BrowserControlError);
  // The User takes control and submits; the page sends navigator.poppy.controller.
  control.handToUser();
  const done = await w.browser.submit(PICKUP_PAGE, { store: "Bend", id_last4: "1234", controller: control.controller });
  assert.equal(done.status, 200);
  assert.ok(done.text.includes("ready in Bend"));
  assert.deepEqual(w.plugin.website.pickups, [{ store: "Bend", controller: "user" }]);
  control.handBack();
});

test("a company without the extension is not negotiated", async () => {
  const w = await world();
  const document = w.company.document;
  const { [BROWSER_CONTROL_EXTENSION]: _listed, ...rest } = document.extensions;
  assert.equal(browserControlNegotiated({ ...document, extensions: rest }, w.session), false);
  // Atlas doesn't implement it: nothing declared, though Manzanita lists it.
  assert.equal(browserControlNegotiated(document, w.session), false);
  const visitor = new ControlledBrowser(w.fetch);
  const page = await visitor.get(PICKUP_PAGE);
  assert.ok(page.text.includes('data-poppy-user-step="submission"'));
});
