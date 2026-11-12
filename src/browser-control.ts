/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

/**
 * PAP Browser Control extension, version 1: steps the Company leaves to the User.
 *
 * A Company marks the steps it wants the User to take themselves with the
 * `data-poppy-user-step` attribute (Browser Control 4). A personal agent that declares the
 * extension, in a browser joined to a Session:
 *
 * - leaves a marked step to the User: it doesn't change or activate a control a mark covers,
 *   or submit a form a mark covers, and doesn't remove or change marks (`PageMarks`, read from
 *   the page's HTML with `pageMarks`);
 * - tells the User the step is theirs and offers them control of the browser; while the User
 *   holds control its model's browser actions are refused, only the User ends it, and nothing
 *   waits on the User (`BrowserControl`);
 * - provides `navigator.poppy.controller`, `"user"` or `"agent"`, on the Company's own hosts
 *   only (`controllerScript`, `controllerUpdateScript`).
 *
 * The SDK drives no browser: the host's browser runs the scripts and asks `PageMarks` and
 * `BrowserControl` before each action its model takes. Marks are signals and the controller
 * value is not a guarantee (Browser Control 8): the Company's servers still decide.
 */

import { PersonalAgentProtocolError } from "./errors.js";
import { companyExtension, type DiscoveryDocument } from "./models.js";
import type { PapSession } from "./sessions.js";

export const BROWSER_CONTROL_EXTENSION = "browser-control";
/** The version this SDK implements (Browser Control 3). */
export const BROWSER_CONTROL_VERSION = "1";
/** The attribute that marks a step for the User (Browser Control 4). */
export const USER_STEP_ATTRIBUTE = "data-poppy-user-step";

/** Who controls the browser, as `navigator.poppy.controller` says (Browser Control 6). */
export type Controller = "user" | "agent";
/** What a mark asks: the User changes or activates (`interaction`), or submits. */
export type UserStepKind = "interaction" | "submission";

/** The HTML elements a form owns, its listed elements (HTML Standard, *form owner*). */
const LISTED = new Set(["button", "fieldset", "input", "object", "output", "select", "textarea"]);
/** The input types that submit their form when activated. */
const SUBMIT_INPUTS = new Set(["submit", "image"]);

/** A browser action the extension asks the personal agent not to take. */
export class BrowserControlError extends PersonalAgentProtocolError {
  constructor(code: string, message: string) {
    super(code, message);
    this.name = "BrowserControlError";
  }
}

/**
 * Whether the Company lists `browser-control` version 1 with a browser-session endpoint, and
 * the Session declares it (Browser Control 3).
 */
export function browserControlNegotiated(document: DiscoveryDocument, session: PapSession): boolean {
  return (
    companyExtension(document, BROWSER_CONTROL_EXTENSION, BROWSER_CONTROL_VERSION) !== undefined &&
    document.web?.browser_session_endpoint !== undefined &&
    session.extensions[BROWSER_CONTROL_EXTENSION] === BROWSER_CONTROL_VERSION
  );
}

/**
 * What a `data-poppy-user-step` value asks, or `undefined` without one (Browser Control 4). A
 * value other than `interaction` or `submission`, or `submission` on anything but a form,
 * counts as `interaction`.
 */
export function userStepKind(value: string | undefined, options: { readonly onForm: boolean }): UserStepKind | undefined {
  if (value === undefined) return undefined;
  if (value.trim().toLowerCase() === "submission" && options.onForm) return "submission";
  return "interaction";
}

/** A form on the page: its position, `id`, `action`, `method`, and its mark. */
export interface PageForm {
  readonly index: number;
  readonly id: string | undefined;
  readonly action: string | undefined;
  readonly method: string;
  readonly mark: UserStepKind | undefined;
}

/**
 * A listed element (`input`, `select`, `button`, …) and the form that owns it: `form` is the
 * owner's index, the form it is in or the one its `form` attribute names; `undefined` for a
 * control no form owns.
 */
export interface PageControl {
  readonly index: number;
  readonly tag: string;
  readonly name: string | undefined;
  readonly id: string | undefined;
  readonly type: string | undefined;
  readonly form: number | undefined;
  readonly mark: UserStepKind | undefined;
  /** Whether activating it submits its form: a submit button or a submit input. */
  readonly submits: boolean;
}

/**
 * The marked steps of one page, read from its HTML (Browser Control 4). Marks add up: a
 * control inside a `submission` form can be marked `interaction` too, and a marked control
 * doesn't mark the rest of its form.
 */
export class PageMarks {
  readonly forms: readonly PageForm[];
  readonly controls: readonly PageControl[];

  constructor(forms: readonly PageForm[] = [], controls: readonly PageControl[] = []) {
    this.forms = forms;
    this.controls = controls;
  }

  /** Whether the page marks any step for the User. */
  get marked(): boolean {
    return this.forms.some((form) => form.mark !== undefined) || this.controls.some((c) => c.mark !== undefined);
  }

  form(index: number | undefined): PageForm | undefined {
    return index === undefined ? undefined : this.forms.find((form) => form.index === index);
  }

  /**
   * Whether the agent may change or activate this control (Browser Control 4, 5): not when it
   * is marked, when its form is marked `interaction`, or when activating it submits a form a
   * mark covers. A `submission` form's other controls it may fill in.
   */
  mayChange(control: PageControl): boolean {
    if (control.mark !== undefined) return false;
    const owner = this.form(control.form);
    if (owner?.mark === "interaction") return false;
    return !(control.submits && owner !== undefined && owner.mark !== undefined);
  }

  /** Whether the agent may submit this form: not when a mark covers it. */
  maySubmit(form: PageForm): boolean {
    return form.mark === undefined;
  }

  /** The first control with this `name` or `id`, in `form` when given. */
  control(options: { readonly name?: string; readonly id?: string; readonly form?: number }): PageControl | undefined {
    return this.controls.find(
      (control) =>
        (options.form === undefined || control.form === options.form) &&
        ((options.name !== undefined && control.name === options.name) ||
          (options.id !== undefined && control.id === options.id)),
    );
  }

  /**
   * The marked steps in words for the User: which step is theirs (Browser Control 5). Names
   * and actions come from the page, content from the Company (spec 10.1).
   */
  userSteps(): readonly string[] {
    const steps: string[] = [];
    for (const form of this.forms) {
      if (form.mark === "submission") steps.push(`submitting the form to ${form.action || "this page"}`);
      else if (form.mark === "interaction") {
        steps.push(`filling in and submitting the form to ${form.action || "this page"}`);
      }
    }
    for (const control of this.controls) {
      if (control.mark !== undefined) {
        steps.push(`the ${control.tag} ${control.name || control.id || control.tag}`);
      }
    }
    return steps;
  }
}

const ENTITIES: Readonly<Record<string, string>> = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " " };

function decodeEntities(value: string): string {
  return value.replace(/&(#x[0-9a-f]+|#[0-9]+|[a-z]+);/gi, (whole, name: string) => {
    if (name[0] === "#") {
      const code = name[1] === "x" || name[1] === "X" ? parseInt(name.slice(2), 16) : parseInt(name.slice(1), 10);
      return Number.isFinite(code) ? String.fromCodePoint(code) : whole;
    }
    return ENTITIES[name.toLowerCase()] ?? whole;
  });
}

const TAG = /<(\/?)([A-Za-z][A-Za-z0-9-]*)((?:\s+[^\s"'>/=]+(?:\s*=\s*(?:"[^"]*"|'[^']*'|[^\s"'=<>`]+))?)*)\s*\/?>|<!--[\s\S]*?-->/g;
const ATTRIBUTE = /([^\s"'>/=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g;
/** Elements whose content is text, not markup. */
const RAW_TEXT = new Set(["script", "style", "textarea", "title"]);

function attributes(text: string): Map<string, string | undefined> {
  const found = new Map<string, string | undefined>();
  for (const match of text.matchAll(ATTRIBUTE)) {
    const name = (match[1] as string).toLowerCase();
    if (found.has(name)) continue; // the first one wins, as in HTML
    const raw = match[2] ?? match[3] ?? match[4];
    found.set(name, raw === undefined ? undefined : decodeEntities(raw));
  }
  return found;
}

/** The mark's value; an attribute without one is an empty value, still a mark. */
function markValue(values: Map<string, string | undefined>): string | undefined {
  if (!values.has(USER_STEP_ATTRIBUTE)) return undefined;
  return values.get(USER_STEP_ATTRIBUTE) ?? "";
}

/**
 * The forms, controls and marks of a page's HTML (Browser Control 4).
 *
 * A form's controls are the ones it owns: those inside it, and those outside it whose `form`
 * attribute names its `id`; a control whose `form` attribute names no form on the page has no
 * owner. A form inside a form is ignored, as HTML's parser does. The host's browser reads the
 * live page; this reads the HTML it was given, so marks a script adds later are the host's to
 * read again.
 */
export function pageMarks(html: string): PageMarks {
  const forms: PageForm[] = [];
  const pending: { index: number; tag: string; values: Map<string, string | undefined>; inside: number | undefined }[] = [];
  let open: number | undefined;
  TAG.lastIndex = 0;
  for (;;) {
    const match = TAG.exec(html);
    if (match === null) break;
    if (match[2] === undefined) continue; // a comment
    const closing = match[1] === "/";
    const tag = match[2].toLowerCase();
    if (closing) {
      if (tag === "form") open = undefined;
      continue;
    }
    const values = attributes(match[3] ?? "");
    if (tag === "form") {
      if (open === undefined) {
        const index = forms.length;
        forms.push({
          index,
          id: values.get("id"),
          action: values.get("action"),
          method: (values.get("method") || "get").toLowerCase(),
          mark: userStepKind(markValue(values), { onForm: true }),
        });
        open = index;
      }
    } else if (LISTED.has(tag)) {
      pending.push({ index: pending.length, tag, values, inside: open });
    }
    if (RAW_TEXT.has(tag)) {
      // Skip to the element's end tag: its content is not markup.
      const end = html.toLowerCase().indexOf(`</${tag}`, TAG.lastIndex);
      TAG.lastIndex = end === -1 ? html.length : end;
    }
  }
  const byId = new Map<string, number>();
  for (const form of forms) if (form.id && !byId.has(form.id)) byId.set(form.id, form.index);
  const controls: PageControl[] = pending.map(({ index, tag, values, inside }) => {
    let owner = inside;
    if (values.has("form")) {
      const named = values.get("form");
      owner = named ? byId.get(named) : undefined;
    }
    const type = values.get("type");
    const submits =
      tag === "button" ? (type || "submit").toLowerCase() === "submit" : tag === "input" && SUBMIT_INPUTS.has((type || "").toLowerCase());
    return {
      index,
      tag,
      name: values.get("name"),
      id: values.get("id"),
      type,
      form: owner,
      mark: userStepKind(markValue(values), { onForm: false }),
      submits,
    };
  });
  return new PageMarks(forms, controls);
}

/**
 * Whether `host` is `organization.domain` or one of its subdomains: the only pages that get
 * `navigator.poppy` (Browser Control 6).
 */
export function onCompanyHost(host: string, organizationDomain: string): boolean {
  const name = host.toLowerCase().replace(/\.$/, "");
  const domain = organizationDomain.toLowerCase().replace(/\.$/, "");
  return name === domain || name.endsWith(`.${domain}`);
}

/**
 * The script that provides `navigator.poppy.controller` (Browser Control 6).
 *
 * The host's browser runs it in every document before the page's own scripts. It defines
 * `navigator.poppy` only on the hosts of `organizationDomain` and its subdomains, so other
 * websites can't tell the browser is a personal agent's; the value is read-only for the page,
 * and starts as `"agent"`. `channel` is a random name the host keeps, never shown to the
 * model: the host's software, not its model, changes the value with
 * `controllerUpdateScript(channel, …)`.
 */
export function controllerScript(organizationDomain: string, channel: string): string {
  const domain = JSON.stringify(organizationDomain.toLowerCase().replace(/\.$/, ""));
  const key = JSON.stringify(channel);
  return (
    "(() => {" +
    `const domain = ${domain};` +
    "const host = location.hostname.toLowerCase();" +
    'if (host !== domain && !host.endsWith("." + domain)) return;' +
    'if ("poppy" in navigator) return;' +
    'let controller = "agent";' +
    "const poppy = Object.freeze(Object.create(Object.prototype, {" +
    "controller: { get: () => controller, enumerable: true }," +
    "}));" +
    'Object.defineProperty(navigator, "poppy", { value: poppy, enumerable: true });' +
    `Object.defineProperty(window, Symbol.for(${key}), {` +
    'value: (value) => { if (value === "user" || value === "agent") controller = value; },' +
    "});" +
    "})();"
  );
}

/** The script the host runs in the page as soon as control changes (Browser Control 6). */
export function controllerUpdateScript(channel: string, controller: Controller): string {
  if (controller !== "user" && controller !== "agent") throw new RangeError("the controller is user or agent");
  return (
    `(() => { const set = window[Symbol.for(${JSON.stringify(channel)})];` +
    ` if (typeof set === 'function') set(${JSON.stringify(controller)}); })();`
  );
}

/**
 * Who controls the personal agent's browser, and what its model may do there.
 *
 * `controller` starts as `agent`. `handToUser` gives the User control, when the host offers
 * it and the User takes it; while they hold it `checkModelAction` refuses every browser action
 * from the model (the website's own scripts keep running), and only `handBack` or `cancel`,
 * which the host calls from the User's own interface, ends it: no timeout, page change or
 * Company message does (Browser Control 5). Each change is passed to `onChange`, for the host
 * to run `controllerUpdateScript` in its pages. Nothing here waits for the User.
 */
export class BrowserControl {
  #controller: Controller = "agent";
  readonly #onChange: ((controller: Controller) => void) | undefined;
  /** The steps the agent told the User are theirs, for the host's own record. */
  readonly offered: string[] = [];

  constructor(options: { readonly onChange?: (controller: Controller) => void } = {}) {
    this.#onChange = options.onChange;
  }

  get controller(): Controller {
    return this.#controller;
  }

  /** The page's marked steps, to tell the User they are theirs and offer control. */
  offer(marks: PageMarks): readonly string[] {
    const steps = marks.userSteps();
    this.offered.push(...steps);
    return steps;
  }

  /** The User takes control: `navigator.poppy.controller` is `"user"` at once. */
  handToUser(): void {
    this.#set("user");
  }

  /** The User hands control back; the agent looks at the page again before going on. */
  handBack(): void {
    this.#set("agent");
  }

  /** The User cancels their control: the same as handing it back. */
  cancel(): void {
    this.#set("agent");
  }

  /** Refuse a browser action from the model while the User holds control. */
  checkModelAction(): void {
    if (this.#controller === "user") {
      throw new BrowserControlError("user_has_control", "The User holds control of the browser");
    }
  }

  /**
   * Refuse changing or activating a control a mark covers, or any action while the User holds
   * control (Browser Control 5).
   */
  checkChange(marks: PageMarks, control: PageControl): void {
    this.checkModelAction();
    if (!marks.mayChange(control)) {
      throw new BrowserControlError("user_step", "The Company marked this step for the User to take");
    }
  }

  /** Refuse submitting a form a mark covers, by any means (Browser Control 5). */
  checkSubmit(marks: PageMarks, form: PageForm): void {
    this.checkModelAction();
    if (!marks.maySubmit(form)) {
      throw new BrowserControlError("user_step", "The Company marked submitting this form for the User");
    }
  }

  #set(controller: Controller): void {
    if (controller === this.#controller) return;
    this.#controller = controller;
    this.#onChange?.(controller);
  }
}
