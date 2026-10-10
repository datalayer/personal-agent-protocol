import { ProtocolValidationError } from "./errors.js";

/** Redacted wrapper for credentials and other protocol secrets. */
export class SecretValue {
  readonly #value: string;

  constructor(value: string) {
    if (!value) {
      throw new ProtocolValidationError("invalid_secret", "Secret value must not be empty");
    }
    this.#value = value;
  }

  reveal(): string {
    return this.#value;
  }

  toString(): string {
    return "[REDACTED]";
  }

  toJSON(): string {
    return "[REDACTED]";
  }
}
