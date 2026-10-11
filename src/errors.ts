/** Safe base error for Personal Agent Protocol failures. */
export class PersonalAgentProtocolError extends Error {
  readonly code: string;
  readonly statusCode: number | undefined;
  readonly details: Readonly<Record<string, unknown>>;

  constructor(
    code: string,
    message: string,
    options: {
      statusCode?: number;
      details?: Readonly<Record<string, unknown>>;
      cause?: unknown;
    } = {},
  ) {
    super(message, { cause: options.cause });
    this.name = "PersonalAgentProtocolError";
    this.code = code;
    this.statusCode = options.statusCode;
    this.details = options.details ?? {};
  }

  override toString(): string {
    return `${this.code}: ${this.message}`;
  }
}

export class ProtocolValidationError extends PersonalAgentProtocolError {
  constructor(
    code: string,
    message: string,
    options: { cause?: unknown } = {},
  ) {
    super(code, message, options);
    this.name = "ProtocolValidationError";
  }
}

export class DiscoveryError extends PersonalAgentProtocolError {
  constructor(
    code: string,
    message: string,
    options: { statusCode?: number; cause?: unknown } = {},
  ) {
    super(code, message, options);
    this.name = "DiscoveryError";
  }
}

export class IdentityError extends PersonalAgentProtocolError {
  constructor(
    code: string,
    message: string,
    options: { statusCode?: number; cause?: unknown } = {},
  ) {
    super(code, message, options);
    this.name = "IdentityError";
  }
}

export class AuthorizationError extends PersonalAgentProtocolError {
  constructor(
    code: string,
    message: string,
    options: { statusCode?: number; cause?: unknown } = {},
  ) {
    super(code, message, options);
    this.name = "AuthorizationError";
  }
}

export class SessionError extends PersonalAgentProtocolError {
  constructor(
    code: string,
    message: string,
    options: {
      statusCode?: number;
      details?: Readonly<Record<string, unknown>>;
      cause?: unknown;
    } = {},
  ) {
    super(code, message, options);
    this.name = "SessionError";
  }
}

export class ProofError extends PersonalAgentProtocolError {
  constructor(
    code: string,
    message: string,
    options: { cause?: unknown } = {},
  ) {
    super(code, message, options);
    this.name = "ProofError";
  }
}

export class BrowserSessionError extends PersonalAgentProtocolError {
  constructor(
    code: string,
    message: string,
    options: { cause?: unknown } = {},
  ) {
    super(code, message, options);
    this.name = "BrowserSessionError";
  }
}

export class TransportError extends PersonalAgentProtocolError {
  constructor(
    code: string,
    message: string,
    options: {
      statusCode?: number;
      details?: Readonly<Record<string, unknown>>;
      cause?: unknown;
    } = {},
  ) {
    super(code, message, options);
    this.name = "TransportError";
  }
}

export class ConversationError extends PersonalAgentProtocolError {
  constructor(
    code: string,
    message: string,
    options: {
      statusCode?: number;
      details?: Readonly<Record<string, unknown>>;
      cause?: unknown;
    } = {},
  ) {
    super(code, message, options);
    this.name = "ConversationError";
  }
}
