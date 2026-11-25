# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Task coverage per Session: excluded tasks, skills, the feedback endpoint and, from 1.1,
the tasks listed for feedback (§9).

A Company that lists excluded tasks, publishes skills or takes feedback names one
`tasks.endpoint` in its poppy.json. The Personal Agent sends `GET {tasks.endpoint}` with
the Session header and no access token, also in a signed-in Session, before it starts on
a task in that Session:

```python
tasks = await TasksClient(transport=transport).get(company.document, session=session)
for excluded in tasks.excluded_tasks:      # the agent's judgment whether the task is one
    ...
for skill in tasks.skills:                 # each `url` resolved against tasks.endpoint
    content = await discovery.fetch_skill(skill)
if tasks.feedback_endpoint is not None:    # a Session header destination (§5.2)
    await FeedbackClient(transport=transport).report(
        tasks.feedback_endpoint, report, session=session
    )
```

What this client guarantees:

- **One Session.** A response is kept for the Session it was fetched in, for as long as
  its caching headers allow, and never used in another: the cache is keyed by the
  endpoint, the `client_id`, the `sid` and the User ID, and `SessionTasks.session` names
  the `sid` it belongs to.
- **No access token.** The response describes what the Company offers, not the User's
  account, so the request is always signed out.
- **No redirect.** The transport refuses one: nothing is sent to the new URL (§3).
- **Carrying on.** With no response (no endpoint, a network failure, a refusal, a body
  that is not a tasks response) the agent carries on as if the Company listed no excluded
  tasks, published no skills and took no feedback: `SessionTasks.available` is `False`.
  `invalid_session` and `version_unsupported` are raised: they say the agent's own header
  is wrong, and are the same at every endpoint (§3.4, §5.3).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

from pydantic import ValidationError

from .caching import CacheBounds, cache_lifetime
from .errors import PersonalAgentProtocolError, TransportError
from .json import loads_strict
from .models import (
    LISTED_TASKS_SINCE,
    DiscoveredCompany,
    DiscoveryDocument,
    ExcludedTask,
    ListedTask,
    SkillEntry,
    TasksResponse,
    version_defines,
)
from .sessions import PapSession
from .transport import SessionHttpClient, session_error


class TasksError(PersonalAgentProtocolError):
    """The tasks endpoint refused the Session header: `invalid_session`, `version_unsupported`."""


@dataclass(frozen=True)
class SessionTasks:
    """A Company's tasks response in one Session (§9): never used in another.

    `available` is `False` when the Company names no tasks endpoint or gave no response;
    everything is then empty, and the agent carries on.
    """

    #: The `sid` of the Session the response was fetched in.
    session: str
    #: `tasks.endpoint`, the base a skill's `url` resolves against (§9.4); `None` without one.
    endpoint: str | None = None
    response: TasksResponse = field(default_factory=TasksResponse)
    available: bool = False

    @property
    def excluded_tasks(self) -> list[ExcludedTask]:
        """The tasks the Company chose not to offer through the protocol (§9.1)."""

        return list(self.response.excluded_tasks)

    @property
    def skills(self) -> list[SkillEntry]:
        """The Company's skills this SDK can use (§9.4), each `url` resolved against
        `tasks.endpoint`."""

        return [] if self.endpoint is None else self.response.usable_skills(self.endpoint)

    @property
    def feedback_endpoint(self) -> str | None:
        """Where to report a task that can't be done (§9.3), when the Company takes feedback."""

        feedback = self.response.feedback
        return None if feedback is None else feedback.endpoint

    @property
    def listed_tasks(self) -> list[ListedTask]:
        """The tasks the Company already knows can't be done, each with the ID to report
        it by (§9.3): `feedback.tasks`, at most 50. Whether the User's task is one of
        them is the agent's judgment, since each `task` is a phrase; a match is reported
        with `FeedbackReport.listed(id, ...)`, not described in free text. Always empty
        before 1.1, which defines them: for a Session that names 1.0, or a Company whose
        document is 1.0."""

        feedback = self.response.feedback
        return [] if feedback is None else list(feedback.tasks)


def _without_listed_tasks(payload: object) -> object:
    """A tasks response without `feedback.tasks`, as a version before 1.1 reads it."""

    if not isinstance(payload, dict) or not isinstance(payload.get("feedback"), dict):
        return payload
    feedback = {name: value for name, value in payload["feedback"].items() if name != "tasks"}
    return {**payload, "feedback": feedback}


def tasks_endpoint(document: DiscoveryDocument) -> str | None:
    """The Company's tasks endpoint, when its poppy.json names one (§3.1)."""

    return None if document.tasks is None else document.tasks.endpoint


class TasksClient:
    """Get a Company's tasks response in a Session, and keep it for that Session only."""

    def __init__(
        self,
        *,
        transport: SessionHttpClient,
        bounds: CacheBounds | None = None,
        max_response_bytes: int = 1024 * 1024,
    ) -> None:
        if max_response_bytes <= 0:
            raise ValueError("max_response_bytes must be positive")
        self.transport = transport
        self.bounds = bounds or CacheBounds()
        self.max_response_bytes = max_response_bytes
        self._kept: dict[tuple[str, str, str, str], tuple[datetime, SessionTasks]] = {}

    async def get(
        self,
        company: DiscoveredCompany | DiscoveryDocument,
        *,
        session: PapSession,
        fresh: bool = False,
    ) -> SessionTasks:
        """`GET {tasks.endpoint}` in `session`, or the response kept for it (§9).

        Call it before starting on a task in the Session. `fresh` reads it again whatever
        was kept. The request carries the Session header and never an access token.
        """

        document = company.document if isinstance(company, DiscoveredCompany) else company
        endpoint = tasks_endpoint(document)
        if endpoint is None:
            return SessionTasks(session=session.sid)
        now = self.transport._now()
        kept = None if fresh else self._kept.get(self._key(endpoint, session))
        if kept is not None and kept[0] > now:
            return kept[1]
        try:
            response = await self.transport.request(
                "GET", endpoint, session=session, headers={"Accept": "application/json"}
            )
        except TransportError:
            # No response (a redirect refused included): as if nothing were listed.
            return SessionTasks(session=session.sid, endpoint=endpoint)
        refused = session_error(response)
        if refused is not None:
            # `session_ended` got its one new Session in the transport; what is left says
            # this agent's header is wrong, here as at any endpoint.
            raise TasksError(
                refused, "the tasks endpoint refused the Session header", status_code=400
            )
        tasks = SessionTasks(session=session.sid, endpoint=endpoint)
        if response.status_code == 200 and len(response.content) <= self.max_response_bytes:
            try:
                payload = loads_strict(response.content)
                if not (
                    version_defines(session.protocol_version, LISTED_TASKS_SINCE)
                    and version_defines(document.protocol_version, LISTED_TASKS_SINCE)
                ):
                    # Listed tasks are 1.1's: at 1.0 the field is one this version doesn't
                    # define, and is ignored (§3.4).
                    payload = _without_listed_tasks(payload)
                tasks = SessionTasks(
                    session=session.sid,
                    endpoint=endpoint,
                    response=TasksResponse.model_validate(payload),
                    available=True,
                )
            except (ValueError, ValidationError, PersonalAgentProtocolError):
                pass
        lifetime = cache_lifetime(dict(response.headers), self.bounds) if tasks.available else None
        key = self._key(endpoint, session)
        if lifetime is None:
            self._kept.pop(key, None)
        else:
            self._kept[key] = (now + timedelta(seconds=lifetime), tasks)
        return tasks

    def forget(self, session: PapSession) -> None:
        """Drop what was kept for a Session, when it ends."""

        for key in [key for key in self._kept if key[1:] == self._key("", session)[1:]]:
            del self._kept[key]

    @staticmethod
    def _key(endpoint: str, session: PapSession) -> tuple[str, str, str, str]:
        return (endpoint, session.client_id, session.sid, session.sub)


__all__ = ["SessionTasks", "TasksClient", "TasksError", "tasks_endpoint"]
