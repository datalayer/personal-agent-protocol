# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Feedback: telling a company what its users couldn't do through the protocol (§9.3).

A company that wants to know lists `feedback.endpoint` in its tasks response,
which the agent gets per Session from `tasks.endpoint` (§9, `TasksClient`).
When a user's task can't be done — not with the Company Agent, not with its
APIs, not on its website in a browser session — the personal agent MAY send
one `FeedbackReport` for that task, with the Session header and, signed in, the access
token:

```python
tasks = await TasksClient(transport=transport).get(company.document, session=session)
endpoint = tasks.feedback_endpoint
if endpoint is not None:
    await FeedbackClient(transport=transport).report(
        endpoint,
        FeedbackReport(task="Pay with a gift card", description="..."),
        token=token, **who,
    )
```

From 1.1 a company can list the tasks it already knows can't be done
(`SessionTasks.listed_tasks`, each an `id` and a `task` phrase). When the user's task
matches one, the agent reports its ID instead of describing it, and may gather the IDs
of a Session into one report, sent before the Session ends:

```python
matched = [listed.id for listed in tasks.listed_tasks if is_the_users_task(listed.task)]
if matched:
    await FeedbackClient(transport=transport).report(
        endpoint, FeedbackReport.listed(*matched), session=session
    )
```

A report has one form or the other, never both. A free-text report describes the
task, never the user: no names, contact details, order or account numbers (SHOULD
NOT), and never a secret (MUST NOT). The Session already tells the company which
personal agent and which user sent it. Errors are reported, never retried here: report
each task once, not once per attempt.
"""

from __future__ import annotations

import json

import httpx
from pydantic import (
    ConfigDict,
    Field,
    SerializerFunctionWrapHandler,
    model_serializer,
    model_validator,
)

from .errors import PersonalAgentProtocolError
from .json import loads_strict
from .models import (
    LISTED_TASK_ID,
    LISTED_TASKS_SINCE,
    Alternative,
    ProtocolModel,
    version_defines,
)
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
    """One report of what the company offers no way to do through the protocol (§9.3).

    In one of two forms, never both: `task` and `description`, a task in free text
    (nothing about the user, no identifiers, no secret), or, from 1.1, `task_ids`, the
    IDs of one or more tasks the company lists in `feedback.tasks`, each once
    (`FeedbackReport.listed`).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    task: str | None = Field(default=None, min_length=1, max_length=FEEDBACK_TASK_MAX_LENGTH)
    description: str | None = Field(
        default=None, min_length=1, max_length=FEEDBACK_DESCRIPTION_MAX_LENGTH
    )
    task_ids: tuple[str, ...] | None = None

    @model_validator(mode="after")
    def validate_form(self) -> FeedbackReport:
        free_text = self.task is not None or self.description is not None
        if self.task_ids is None:
            if self.task is None or self.description is None:
                raise ValueError("a report has task_ids, or task and description")
            return self
        if free_text:
            raise ValueError("a report has task_ids, or task and description, not both")
        if not self.task_ids:
            raise ValueError("task_ids names at least one listed task")
        if len(set(self.task_ids)) != len(self.task_ids):
            raise ValueError("task_ids names each listed task once")
        if any(not LISTED_TASK_ID.fullmatch(task_id) for task_id in self.task_ids):
            raise ValueError("a listed task's ID is lowercase letters, digits, - and _")
        return self

    @classmethod
    def listed(cls, *task_ids: str) -> FeedbackReport:
        """A report of listed tasks, by their IDs from `SessionTasks.listed_tasks` (§9.3)."""

        return cls(task_ids=tuple(task_ids))

    @model_serializer(mode="wrap")
    def _one_form(self, handler: SerializerFunctionWrapHandler) -> dict[str, object]:
        # The one form the report has, and nothing of the other: `model_dump` is the body.
        return {name: value for name, value in handler(self).items() if value is not None}

    def body(self) -> dict[str, object]:
        """The request body: the one form the report has, and nothing else."""

        return self.model_dump(mode="json")


class FeedbackClient:
    """Send feedback reports in a Session, signed in or out."""

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
        """`POST {feedback.endpoint}`: accepted, or answered with a way to do it (§9.3).

        `202` with no body returns `None`; `200` with an alternative (§9.2) returns it,
        as content from the company, its references for the caller to filter with
        `Alternative.usable_references`. Anything else is a `FeedbackError`. Don't
        report a task the company lists as excluded (§9.1).

        A report of listed tasks (`task_ids`) is 1.1's: `ValueError` in a Session that
        names an earlier version, which sends a Company nothing its version doesn't
        define (§3.4). The company answers it with `202`, and ignores IDs it no longer
        lists.

        A refusal is never retried here: a 429 carries its `Retry-After` in
        `details["retry_after"]`, and the caller waits at least that long (§5.6).
        """

        if report.task_ids is not None and not version_defines(
            session.protocol_version, LISTED_TASKS_SINCE
        ):
            raise ValueError(
                f"listed tasks are reported by ID from {LISTED_TASKS_SINCE}: this Session "
                f"names {session.protocol_version}"
            )

        response = await self.transport.request(
            "POST",
            endpoint,
            session=session,
            token=token,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            content=json.dumps(report.body(), separators=(",", ":")).encode(),
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
]
