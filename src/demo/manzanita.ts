/**
 * Manzanita Outfitters: a fictional company, assembled from Reactor contributions.
 *
 * The port of the Python `personal_agent_protocol.demo.manzanita`, for tests
 * and the language pairings: a user wants to return a jacket that is not
 * warm enough. Manzanita offers Direct, Device and Mediated Sign-In, a company
 * agent, an OpenAPI API, and the Operations extension. Its parts are
 * contributions:
 *
 * - `ManzanitaAccounts` (`pap.company.accounts`): one account, Ada's, with a
 *   password and a one-time code.
 * - `ManzanitaAgent` (`pap.company.agent`): reads the order once signed in
 *   (`authorization` until then) and proposes the exchange as an operation.
 * - `ManzanitaApi` (`pap.company.api`): orders, and consequential calls that
 *   propose operations (`202`).
 * - `ManzanitaMcp` (`pap.company.mcp`): the same orders and exchange, as MCP
 *   tools (§6, Operations §4.2).
 * - `ExchangeExecutor` (`pap.company.operationExecutor`): performs the
 *   exchange, once. Gift wrap, a return that fails partway, and a repair whose
 *   carrier never answers show the other ends of an operation.
 *
 * Not part of either published entry: tests import it from `lib/demo/`.
 */

import { timingSafeEqual } from "node:crypto";

import type { PlatformInput } from "@datalayer/reactor";

import {
  ApiResults,
  CompanyAccounts,
  CompanyAgents,
  CompanyApis,
  CompanyConfig,
  CompanyMcps,
  CompanyStores,
  OperationExecutors,
  OperationFailed,
  OperationOutcomeUnknown,
  ToolResults,
  buildCompany,
  type AccountDirectory,
  type CompanyConfigOptions,
  type ApiCall,
  type ApiResult,
  type Authenticated,
  type CompanyAgent,
  type CompanyApi,
  type CompanyMcp,
  type CompanyService,
  type CompanyStore,
  type OperationExecutor,
  type ProposedOperation,
  type Reply,
  type ToolResult,
  type Turn,
} from "../company/index.js";
import type { Operation, OperationResult } from "../models.js";
import { Clocks, type Clock, type PapCoreOptions } from "../reactor.js";
import type { SecretValue } from "../secret.js";

export const DOMAIN = "manzanita.example";
export const ADA = { email: "ada@example.com", password: "correct horse battery staple" } as const;
export const ADA_CODE = "246810";
export const ORDER = {
  order_id: "ord_7Hk2",
  item: "Ridge Jacket, size M",
  status: "delivered",
} as const;

export const CONFIG_OPTIONS: CompanyConfigOptions = {
  name: "Manzanita Outfitters",
  domain: DOMAIN,
  scopes: ["orders:read", "orders:write"],
  writeScopes: ["orders:write"],
  mediatedFields: [
    ["email", "Email", false],
    ["password", "Password", true],
  ],
  customScopes: { "orders:read": "See your orders", "orders:write": "Exchange and return items" },
};
export const CONFIG = new CompanyConfig(CONFIG_OPTIONS);

function same(value: string, expected: string): boolean {
  const a = Buffer.from(value);
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}

/** Ada's account: her password, then a code sent to her email. */
export class ManzanitaAccounts implements AccountDirectory {
  async authenticate(
    credentials: Readonly<Record<string, SecretValue>>,
  ): Promise<Authenticated | undefined> {
    const email = credentials.email;
    const password = credentials.password;
    if (
      email === undefined ||
      password === undefined ||
      email.reveal() !== ADA.email ||
      !same(password.reveal(), ADA.password)
    ) {
      return undefined;
    }
    return { accountId: "acct_ada", codeReference: "code_ada", sentTo: "a•••@example.com" };
  }

  async checkCode(codeReference: string, code: SecretValue): Promise<boolean> {
    return codeReference === "code_ada" && same(code.reveal(), ADA_CODE);
  }
}

export const EXCHANGE: ProposedOperation = {
  action: "orders.exchange",
  summary:
    "Exchange the Ridge Jacket (M) from order ord_7Hk2 for the " +
    "insulated Ridge Jacket (M), USD 70.00 more.",
  terms: {
    order_id: "ord_7Hk2",
    price_difference: { amount: "70.00", currency: "USD" },
  },
  userApprovalRequired: true,
};

/** What each consequential API path proposes (Operations §4.1). */
export const PROPOSALS: Readonly<Record<string, ProposedOperation>> = {
  exchanges: EXCHANGE,
  "gift-wrap": {
    action: "orders.gift_wrap",
    summary: "Gift-wrap order ord_7Hk2 before it ships again, USD 5.00.",
    terms: { order_id: "ord_7Hk2", price: { amount: "5.00", currency: "USD" } },
  },
  returns: {
    action: "orders.return",
    summary: "Return the Ridge Jacket (M) from order ord_7Hk2 for a refund of USD 180.00.",
    terms: { order_id: "ord_7Hk2", refund: { amount: "180.00", currency: "USD" } },
    userApprovalRequired: true,
  },
  repairs: {
    action: "orders.repair",
    summary: "Send the Ridge Jacket (M) from order ord_7Hk2 for a zip repair, free.",
    terms: { order_id: "ord_7Hk2", price: { amount: "0.00", currency: "USD" } },
    userApprovalRequired: true,
  },
};

/** Manzanita's company agent: a few rules, enough to show the protocol. */
export class ManzanitaAgent implements CompanyAgent {
  async respond(turn: Turn): Promise<readonly Reply[]> {
    const text = (turn.text ?? "").toLowerCase();
    if (turn.accountId === undefined) {
      if (text.includes("order") || text.includes("jacket") || text.includes("exchange")) {
        return [
          { text: "I can look that up once you sign in to your Manzanita account." },
          { authorization: ["sign_in_required", "orders:read orders:write"] },
        ];
      }
      return [{ text: "Hello from Manzanita Outfitters. Ask me about an order." }];
    }
    if (text.includes("exchange") || text.includes("warmer")) {
      if (!turn.scopes.includes("orders:write")) {
        return [{ authorization: ["insufficient_scope", "orders:write"] }];
      }
      return [
        {
          text: "The insulated Ridge Jacket is in stock. Here is the exchange.",
          operation: EXCHANGE,
        },
      ];
    }
    return [{ text: "Your order ord_7Hk2: Ridge Jacket, size M, delivered.", data: { ...ORDER } }];
  }
}

/** Manzanita's OpenAPI API: orders, and changes proposed as operations. */
export class ManzanitaApi implements CompanyApi {
  readonly description = "Orders and exchanges";

  openapi(): Record<string, unknown> {
    return {
      openapi: "3.1.0",
      info: { title: "Manzanita Outfitters", version: "1" },
      paths: {
        "/api/orders": { get: { summary: "Your orders (orders:read)" } },
        "/api/orders/{order_id}/exchanges": {
          post: { summary: "Propose an exchange (orders:write): 202 and an operation" },
        },
        "/api/orders/{order_id}/gift-wrap": {
          post: { summary: "Propose gift wrap (orders:write): 202 and an operation" },
        },
        "/api/orders/{order_id}/returns": {
          post: { summary: "Propose a return (orders:write): 202 and an operation" },
        },
        "/api/orders/{order_id}/repairs": {
          post: { summary: "Propose a repair (orders:write): 202 and an operation" },
        },
      },
    };
  }

  async handle(call: ApiCall): Promise<ApiResult> {
    if (call.method === "GET" && call.path === "/orders") {
      if (call.accountId === undefined) return ApiResults.signInRequired("orders:read");
      if (!call.scopes.includes("orders:read")) return ApiResults.insufficientScope("orders:read");
      return { body: { orders: [{ ...ORDER }] } };
    }
    const prefix = `/orders/${ORDER.order_id}/`;
    if (call.method === "POST" && call.path.startsWith(prefix)) {
      const proposal = PROPOSALS[call.path.slice(prefix.length)];
      if (proposal === undefined) return ApiResults.notFound();
      if (call.accountId === undefined) return ApiResults.signInRequired("orders:write");
      if (!call.scopes.includes("orders:write")) {
        return ApiResults.insufficientScope("orders:write");
      }
      return { operation: proposal };
    }
    return ApiResults.notFound();
  }
}

/** Manzanita's MCP server: the same orders and exchange, as tools (§6, Operations §4.2). */
export class ManzanitaMcp implements CompanyMcp {
  readonly description = "Orders and exchanges, as MCP tools";

  tools(): Record<string, unknown>[] {
    return [
      {
        name: "list_orders",
        description: "Your orders (orders:read).",
        inputSchema: { type: "object", properties: {} },
      },
      {
        name: "exchange_jacket",
        description: "Propose the insulated jacket in exchange (orders:write).",
        inputSchema: { type: "object", properties: {} },
      },
    ];
  }

  async call(name: string, _args: Readonly<Record<string, unknown>>, call: ApiCall): Promise<ToolResult> {
    if (name === "list_orders") {
      if (call.accountId === undefined) return ToolResults.signInRequired("orders:read");
      if (!call.scopes.includes("orders:read")) return ToolResults.insufficientScope("orders:read");
      return {
        text: "Order ord_7Hk2: Ridge Jacket, size M, delivered.",
        structured: { orders: [{ ...ORDER }] },
      };
    }
    if (name === "exchange_jacket") {
      if (call.accountId === undefined) return ToolResults.signInRequired("orders:write");
      if (!call.scopes.includes("orders:write")) return ToolResults.insufficientScope("orders:write");
      return { operation: EXCHANGE };
    }
    return { text: `Unknown tool ${name}.`, isError: true };
  }
}

/** Perform an exchange once: the operation ID is the downstream idempotency key. */
export class ExchangeExecutor implements OperationExecutor {
  readonly action = "orders.exchange";
  readonly performed: string[] = [];

  async perform(operation: Operation, _accountId: string): Promise<OperationResult> {
    this.performed.push(operation.operation_id);
    const terms = (operation.terms ?? {}) as Record<string, unknown>;
    const difference = (terms.price_difference ?? {}) as Record<string, unknown>;
    const amount = `${String(difference.currency ?? "USD")} ${String(difference.amount ?? "0.00")}`;
    return {
      summary:
        "Exchanged the Ridge Jacket (M) for the insulated Ridge Jacket (M). " +
        `${amount} charged to the card ending 4242; a return label was emailed.`,
      data: { order_id: terms.order_id, charged: difference },
    };
  }
}

export class GiftWrapExecutor implements OperationExecutor {
  readonly action = "orders.gift_wrap";
  readonly performed: string[] = [];

  async perform(operation: Operation, _accountId: string): Promise<OperationResult> {
    this.performed.push(operation.operation_id);
    return {
      summary: "Order ord_7Hk2 will be gift-wrapped. USD 5.00 charged to the card ending 4242.",
    };
  }
}

/** A return that fails partway: the label exists, the refund did not go through. */
export class ReturnExecutor implements OperationExecutor {
  readonly action = "orders.return";
  readonly performed: string[] = [];

  async perform(operation: Operation, _accountId: string): Promise<OperationResult> {
    this.performed.push(operation.operation_id);
    throw new OperationFailed({
      summary:
        "A return label for the Ridge Jacket (M) was emailed, but the refund of " +
        "USD 180.00 could not be issued; no money moved.",
      data: { return_label: "rtn_8Lp3", refunded: null },
    });
  }
}

/** A repair booked with a carrier that never answers: the outcome is unknown. */
export class RepairExecutor implements OperationExecutor {
  readonly action = "orders.repair";
  readonly performed: string[] = [];

  async perform(operation: Operation, _accountId: string): Promise<OperationResult> {
    this.performed.push(operation.operation_id);
    throw new OperationOutcomeUnknown("the carrier did not answer");
  }
}

/** Manzanita's contributions, and the executors a test inspects. */
export class ManzanitaPlugin {
  readonly executor = new ExchangeExecutor();
  readonly giftWrap = new GiftWrapExecutor();
  readonly returns = new ReturnExecutor();
  readonly repairs = new RepairExecutor();

  plugin(): PlatformInput {
    return {
      name: "manzanita",
      version: "1",
      contributes: [
        { point: CompanyAccounts, value: new ManzanitaAccounts(), options: { id: "accounts" } },
        { point: CompanyAgents, value: new ManzanitaAgent(), options: { id: "agent" } },
        { point: OperationExecutors, value: this.executor, options: { id: "exchange" } },
        { point: OperationExecutors, value: this.giftWrap, options: { id: "gift-wrap" } },
        { point: OperationExecutors, value: this.returns, options: { id: "returns" } },
        { point: OperationExecutors, value: this.repairs, options: { id: "repairs" } },
        { point: CompanyApis, value: new ManzanitaApi(), options: { id: "api" } },
        { point: CompanyMcps, value: new ManzanitaMcp(), options: { id: "mcp" } },
      ],
    } as PlatformInput;
  }
}

export interface ManzanitaOptions extends PapCoreOptions {
  /** One clock for every party, so a test can skip a polling interval. */
  readonly clock?: Clock;
  /** Changes to Manzanita's configuration, e.g. hosted sign-in pages. */
  readonly config?: Partial<CompanyConfigOptions>;
  /**
   * Where Manzanita keeps its state: building it again over the same store is
   * Manzanita restarted (or another replica of it).
   */
  readonly store?: CompanyStore;
}

/** Build Manzanita; serve it with `companyRequestListener` at `manzanita.example`. */
export function manzanita(
  options: ManzanitaOptions = {},
): { readonly service: CompanyService; readonly plugin: ManzanitaPlugin } {
  const { clock, config, store, ...core } = options;
  const plugin = new ManzanitaPlugin();
  const plugins: PlatformInput[] = [plugin.plugin()];
  if (store !== undefined) {
    plugins.push({
      name: "manzanita-store",
      version: "1",
      contributes: [{ point: CompanyStores, value: store, options: { id: "given-store", order: 0 } }],
    } as PlatformInput);
  }
  if (clock !== undefined) {
    plugins.push({
      name: "manzanita-clock",
      version: "1",
      contributes: [{ point: Clocks, value: clock, options: { id: "demo-clock" } }],
    } as PlatformInput);
  }
  const service = buildCompany(
    config === undefined ? CONFIG : new CompanyConfig({ ...CONFIG_OPTIONS, ...config }),
    { ...core, plugins },
  );
  return { service, plugin };
}
