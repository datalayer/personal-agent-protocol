# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Safe, typed errors raised by the Personal Agent Protocol SDK."""

from __future__ import annotations

from typing import Any


class PersonalAgentProtocolError(Exception):
    """Base error whose string representation never includes response bodies."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        status_code: int | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code
        self.details = details or {}

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


class ProtocolValidationError(PersonalAgentProtocolError):
    """A protocol document is malformed or internally inconsistent."""


class DiscoveryError(PersonalAgentProtocolError):
    """Discovery could not be completed safely."""


class IdentityError(PersonalAgentProtocolError):
    """Personal-agent metadata or public keys could not be verified safely."""


class AuthorizationError(PersonalAgentProtocolError):
    """An authorization flow failed without exposing callback secrets."""


class SessionError(PersonalAgentProtocolError):
    """A session request failed without exposing response secrets."""


class ProofError(PersonalAgentProtocolError):
    """A signed assertion or proof-of-possession value is invalid."""


class BrowserSessionError(PersonalAgentProtocolError):
    """A browser-session handoff or assertion failed safely."""


class TransportError(PersonalAgentProtocolError):
    """An authenticated PAP resource request failed safely."""


class ConversationError(PersonalAgentProtocolError):
    """A PAP conversation request failed without exposing its body."""
