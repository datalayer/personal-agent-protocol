# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Feedback: telling a company what its users couldn't do through the protocol (§8).

A company that wants to know lists `feedback.endpoint` in its poppy.json.
When a user's task can't be done — not with the Company Agent, not with its
APIs, not on its website in a browser session — the personal agent MAY send
one `FeedbackReport` for that task with the Session's token and a DPoP proof:

```python
endpoint = feedback_endpoint(company.document)
if endpoint is not None:
    await FeedbackClient(transport=transport).report(
        endpoint,
        FeedbackReport(task="Pay with a gift card", description="..."),
        token=token, **who,
    )
```

The report describes the task, never the user: no names, contact details,
order or account numbers (SHOULD NOT), and never a secret (MUST NOT). The
Session already tells the company which personal agent and which user sent
it. Errors are reported, never retried here: send one report per task, not
one per attempt.
"""

from __future__ import annotations

import json

import httpx
from pydantic import ConfigDict, Field

from .errors import PersonalAgentProtocolError
from .json import loads_strict
from .models import Alternative, DiscoveryDocument, ProtocolModel
from .refusals import refusal_code, refusal_details
from .sessions import AccessToken, PapSession
from .transport import SessionHttpClient

#: The longest `task` a report carries (§8).
FEEDBACK_TASK_MAX_LENGTH = 200
#: The longest `description` a report carries (§8).
FEEDBACK_DESCRIPTION_MAX_LENGTH = 2000


class FeedbackError(PersonalAgentProtocolError):
    """The company refused a feedback report: `invalid_request`, `rate_limited`, a token error."""


class FeedbackReport(ProtocolModel):
    """One report of a task the company offers no way to do through the protocol (§8).

    Exactly these two fields: nothing about the user, no identifiers, no secret.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    task: str = Field(min_length=1, max_length=FEEDBACK_TASK_MAX_LENGTH)
    description: str = Field(min_length=1, max_length=FEEDBACK_DESCRIPTION_MAX_LENGTH)


def feedback_endpoint(document: DiscoveryDocument) -> str | None:
    """The company's feedback endpoint, when it asks for feedback."""

    return document.feedback.endpoint if document.feedback is not None else None


class FeedbackClient:
    """Send feedback reports with a Session Token, signed in or out, and a DPoP proof."""

    def __init__(
        self, *, transport: SessionHttpClient, max_response_bytes: int = 16 * 1024
    ) -> None:
        if max_response_bytes <= 0:
            raise ValueError("max_response_bytes must be positive")
        self.transport = transport
        self.max_response_bytes = max_response_bytes

    async def report(
        self,
        endpoint: str,
        report: FeedbackReport,
        *,
        session: PapSession,
        token: AccessToken | None = None,
    ) -> Alternative | None:
        """`POST {feedback.endpoint}`: accepted, or answered with a way to do it (§8.3).

        `202` with no body returns `None`; `200` with an alternative (§8.2) returns it,
        as content from the company, its references for the caller to filter with
        `Alternative.usable_references`. Anything else is a `FeedbackError`. Don't
        report a task the company lists as excluded (§8.1).

        A refusal is never retried here: a 429 carries its `Retry-After` in
        `details["retry_after"]`, and the caller waits at least that long (§4.3).
        """

        response = await self.transport.request(
            "POST",
            endpoint,
            session=session,
            token=token,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            content=json.dumps(report.model_dump(mode="json"), separators=(",", ":")).encode(),
        )
        if response.status_code == 202:
            return None
        payload = self._payload(response)
        if response.status_code == 200:
            try:
                return Alternative.model_validate(payload)
            except ValueError as exc:
                raise FeedbackError(
                    "invalid_alternative",
                    "the company answered with a malformed alternative",
                    status_code=200,
                ) from exc
        # In the JSON body, or a token error in WWW-Authenticate (§3.3, §7).
        code = refusal_code(response, payload, "feedback_request_failed")
        raise FeedbackError(
            code if isinstance(code, str) else "feedback_request_failed",
            "the company refused the feedback report",
            status_code=response.status_code,
            details=refusal_details(response, payload) or None,
        )

    def _payload(self, response: httpx.Response) -> object:
        if not response.content or len(response.content) > self.max_response_bytes:
            return None
        try:
            return loads_strict(response.content)
        except (ValueError, PersonalAgentProtocolError):
            return None


__all__ = [
    "FEEDBACK_DESCRIPTION_MAX_LENGTH",
    "FEEDBACK_TASK_MAX_LENGTH",
    "FeedbackClient",
    "FeedbackError",
    "FeedbackReport",
    "feedback_endpoint",
]
