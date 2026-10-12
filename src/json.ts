/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

import { ProtocolValidationError } from "./errors.js";

/** Parse JSON while rejecting duplicate object member names at every depth. */
export function parseJsonStrict(source: string): unknown {
  return new StrictJsonParser(source).parse();
}

class StrictJsonParser {
  #offset = 0;

  constructor(private readonly source: string) {}

  parse(): unknown {
    this.#skipWhitespace();
    const value = this.#parseValue();
    this.#skipWhitespace();
    if (this.#offset !== this.source.length) {
      this.#invalid("Unexpected content after the JSON value");
    }
    return value;
  }

  #parseValue(): unknown {
    const character = this.source[this.#offset];
    if (character === "{") return this.#parseObject();
    if (character === "[") return this.#parseArray();
    if (character === '"') return this.#parseString();
    if (character === "t") return this.#parseLiteral("true", true);
    if (character === "f") return this.#parseLiteral("false", false);
    if (character === "n") return this.#parseLiteral("null", null);
    if (character === "-" || (character !== undefined && /[0-9]/.test(character))) {
      return this.#parseNumber();
    }
    this.#invalid("Expected a JSON value");
  }

  #parseObject(): Record<string, unknown> {
    this.#offset += 1;
    this.#skipWhitespace();
    const result: Record<string, unknown> = {};
    const names = new Set<string>();
    if (this.#consume("}")) return result;

    while (true) {
      if (this.source[this.#offset] !== '"') {
        this.#invalid("Expected a JSON object member name");
      }
      const name = this.#parseString();
      if (names.has(name)) {
        throw new ProtocolValidationError(
          "duplicate_json_member",
          `JSON object contains duplicate member ${JSON.stringify(name)}`,
        );
      }
      names.add(name);
      this.#skipWhitespace();
      if (!this.#consume(":")) this.#invalid("Expected ':' after an object member name");
      this.#skipWhitespace();
      // Defined, never assigned: a member named `__proto__` is a member, as in
      // JSON.parse and Python, and never the parsed object's prototype.
      Object.defineProperty(result, name, {
        value: this.#parseValue(),
        enumerable: true,
        writable: true,
        configurable: true,
      });
      this.#skipWhitespace();
      if (this.#consume("}")) return result;
      if (!this.#consume(",")) this.#invalid("Expected ',' or '}' in a JSON object");
      this.#skipWhitespace();
    }
  }

  #parseArray(): unknown[] {
    this.#offset += 1;
    this.#skipWhitespace();
    const result: unknown[] = [];
    if (this.#consume("]")) return result;

    while (true) {
      result.push(this.#parseValue());
      this.#skipWhitespace();
      if (this.#consume("]")) return result;
      if (!this.#consume(",")) this.#invalid("Expected ',' or ']' in a JSON array");
      this.#skipWhitespace();
    }
  }

  #parseString(): string {
    const start = this.#offset;
    this.#offset += 1;
    while (this.#offset < this.source.length) {
      const character = this.source[this.#offset];
      if (character === '"') {
        this.#offset += 1;
        const encoded = this.source.slice(start, this.#offset);
        try {
          return JSON.parse(encoded) as string;
        } catch (cause) {
          this.#invalid("Invalid JSON string", cause);
        }
      }
      if (character === "\\") {
        this.#offset += 1;
        if (this.#offset >= this.source.length) this.#invalid("Unterminated JSON escape");
        if (this.source[this.#offset] === "u") {
          const digits = this.source.slice(this.#offset + 1, this.#offset + 5);
          if (!/^[0-9a-fA-F]{4}$/.test(digits)) this.#invalid("Invalid Unicode escape");
          this.#offset += 4;
        } else if (!'"\\/bfnrt'.includes(this.source[this.#offset] ?? "")) {
          this.#invalid("Invalid JSON escape");
        }
      } else if (character === undefined || character.charCodeAt(0) < 0x20) {
        this.#invalid("Invalid control character in JSON string");
      }
      this.#offset += 1;
    }
    this.#invalid("Unterminated JSON string");
  }

  #parseNumber(): number {
    const remainder = this.source.slice(this.#offset);
    const match = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(remainder);
    if (!match) this.#invalid("Invalid JSON number");
    this.#offset += match[0].length;
    const value = Number(match[0]);
    if (!Number.isFinite(value)) this.#invalid("JSON number is outside the supported range");
    return value;
  }

  #parseLiteral<T>(encoded: string, value: T): T {
    if (!this.source.startsWith(encoded, this.#offset)) {
      this.#invalid("Invalid JSON literal");
    }
    this.#offset += encoded.length;
    return value;
  }

  #skipWhitespace(): void {
    while (
      this.#offset < this.source.length &&
      " \t\r\n".includes(this.source[this.#offset] ?? "")
    ) {
      this.#offset += 1;
    }
  }

  #consume(character: string): boolean {
    if (this.source[this.#offset] !== character) return false;
    this.#offset += 1;
    return true;
  }

  #invalid(message: string, cause?: unknown): never {
    throw new ProtocolValidationError("invalid_json", message, {
      cause,
    });
  }
}
