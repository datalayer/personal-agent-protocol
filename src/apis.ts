// What a discovery document advertises, as in Python's personal_agent_protocol.apis:
// the API types this SDK speaks, the `poppy` conversation endpoint, and the OpenAPI
// description. Unknown API and protocol types are skipped, never an error (§3.3, §6).
import type { ApiDescriptor, DiscoveryDocument } from "./models.js";

/** The API types this SDK speaks. */
export const KNOWN_API_TYPES: ReadonlySet<string> = new Set(["openapi", "mcp"]);

/** The advertised APIs of a type this SDK speaks, in the company's order. */
export function knownApis(document: DiscoveryDocument): readonly ApiDescriptor[] {
  return (document.apis ?? []).filter((api) => KNOWN_API_TYPES.has(api.type));
}

/** The `poppy` conversation endpoint, skipping protocol types this SDK does not speak. */
export function conversationEndpoint(document: DiscoveryDocument): string | undefined {
  return document.agent?.protocols.find((protocol) => protocol.type === "poppy")?.endpoint;
}

/** The company's OpenAPI description, when it advertises one. */
export function openapiUrl(document: DiscoveryDocument): string | undefined {
  return (document.apis ?? []).find((api) => api.type === "openapi")?.url;
}
