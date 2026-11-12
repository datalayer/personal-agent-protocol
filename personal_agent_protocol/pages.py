# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Website pages fetched without a browser: the Session header, always signed out (§5.2).

A personal agent that fetches a page of a company's website with its own HTTP client,
such as a help article, sends the Session header with it (SHOULD), so the company can
tell which personal agent and Session the request is from:

```python
page = await PageClient(transport=transport).fetch(
    "https://shop.example/help/returns", session=session, company=company.document
)
if page.invalid_session:
    ...  # a mistake in this agent's header: look into it; the page is still there
```

What this client guarantees:

- **Only the company's own host.** The header goes with an HTTPS URL whose host is
  exactly `organization.domain`, the host that served `poppy.json`: never to another
  host on the company's domain, a subdomain, or anyone else.
- **Pages, not documents.** Discovery and description documents and OAuth endpoints
  never carry the header, on that host either (§5.2): a `/.well-known/` URL, a
  description URL the company lists in `apis`, a version's document, and, given the
  discovered company, its issuer's endpoints are fetched without it.
- **Never an access token.** The Session JWT has no `ath` and the request is signed
  out, even when a browser joined to the Session is signed in. `fetch` takes no token.
- **A new JWT per redirect, or none.** A redirect is followed by hand: the next URL
  gets a Session JWT signed for it while its host is still `organization.domain`, and
  is fetched without the header otherwise. Every hop is HTTPS and passes the host's
  URL safety policy.
- **`invalid_session` is reported.** A page that verifies the header answers a failed
  check with `invalid_session` (§5.3). `fetch` says so (`invalid_session`) and, with
  `again_without_header`, fetches the page once more without the header. It never
  leaves the header out on its own to look like a person.

A headless browser is a browser: it joins the Session (`BrowserSessionClient`) and
sends no header. `web.disabled` asks agents not to use a browser on the website; it
does not cover these fetches (§6).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import cast
from urllib.parse import urljoin, urlsplit

import httpx

from .errors import TransportError
from .models import DiscoveredCompany, DiscoveryDocument
from .reactor import (
    URL_SAFETY_POLICIES,
    ApprovedUrl,
    UrlSafetyPolicy,
    optional_contribution,
    send_bounded,
)
from .refusals import REDIRECT_STATUSES
from .sessions import PapSession
from .transport import SessionHttpClient, session_error, session_headers


@dataclass(frozen=True)
class FetchedPage:
    """A website page as the agent's own HTTP client got it. Content from the company
    (§10.1): data for the agent, never instructions."""

    #: The URL that answered, after any redirects.
    url: str
    status_code: int
    headers: dict[str, str]
    content: bytes
    #: Whether the request that got this response carried the Session header.
    session_header_sent: bool
    #: Whether the company answered the header with `invalid_session`: a mistake in this
    #: agent's header, as at any endpoint (§5.3).
    invalid_session: bool = False


def page_carries_session(url: str, domain: str) -> bool:
    """Whether a page fetch carries the Session header (§5.2): an HTTPS URL whose host is
    exactly `organization.domain`, compared ignoring case, on the default port."""

    parsed = urlsplit(url)
    try:
        port = parsed.port
    except ValueError:
        return False
    return (
        parsed.scheme == "https"
        and (parsed.hostname or "").lower() == domain.lower().rstrip(".")
        and port in {None, 443}
        and not parsed.username
        and not parsed.password
    )


def _document_key(url: str) -> str | None:
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname:
        return None
    return f"{parsed.hostname.lower()}{parsed.path or '/'}"


def document_urls(company: DiscoveredCompany | DiscoveryDocument) -> frozenset[str]:
    """The company's discovery and description documents and OAuth endpoints, by host and
    path: none of them carries the Session header (§5.2). `/.well-known/` paths are
    recognized apart, by their path."""

    discovered = company if isinstance(company, DiscoveredCompany) else None
    document = discovered.document if discovered is not None else cast(DiscoveryDocument, company)
    metadata = None if discovered is None else discovered.oauth_metadata
    urls: list[str | None] = [
        None if discovered is None else discovered.discovery_url,
        *(api.url for api in document.apis),
        *document.supported_versions.values(),
    ]
    if metadata is not None:
        urls += [
            metadata.token_endpoint,
            metadata.revocation_endpoint,
            metadata.authorization_endpoint,
            metadata.device_authorization_endpoint,
        ]
    keys = (_document_key(url) for url in urls if isinstance(url, str))
    return frozenset(key for key in keys if key is not None)


def _is_document(url: str, documents: frozenset[str]) -> bool:
    key = _document_key(url)
    return key is None or urlsplit(url).path.startswith("/.well-known/") or key in documents


class PageClient:
    """Fetch a company's website pages without a browser, in a Session, signed out."""

    def __init__(
        self,
        *,
        transport: SessionHttpClient,
        max_redirects: int = 5,
        max_response_bytes: int = 2 * 1024 * 1024,
    ) -> None:
        if max_redirects < 0 or max_response_bytes <= 0:
            raise ValueError("max_redirects and max_response_bytes must be positive")
        self.transport = transport
        self.max_redirects = max_redirects
        self.max_response_bytes = max_response_bytes

    async def fetch(
        self,
        url: str,
        *,
        session: PapSession,
        company: DiscoveredCompany | DiscoveryDocument,
        again_without_header: bool = False,
    ) -> FetchedPage:
        """`GET url`, with the Session header wherever §5.2 says it goes.

        `company` is the Session's company: its `organization.domain` decides which
        URLs carry the header, and its documents and OAuth endpoints never do. A URL
        elsewhere is fetched too, without it: that is an ordinary fetch of a public page.
        """

        document = company.document if isinstance(company, DiscoveredCompany) else company
        where = (document.organization.domain, document_urls(company))
        page = await self._follow(url, session=session, where=where, with_header=True)
        if page.invalid_session and again_without_header:
            again = await self._follow(url, session=session, where=where, with_header=False)
            return FetchedPage(
                url=again.url,
                status_code=again.status_code,
                headers=again.headers,
                content=again.content,
                session_header_sent=False,
                invalid_session=True,
            )
        return page

    async def _follow(
        self,
        url: str,
        *,
        session: PapSession,
        where: tuple[str, frozenset[str]],
        with_header: bool,
    ) -> FetchedPage:
        domain, documents = where
        current = url
        for _ in range(self.max_redirects + 1):
            await self._assert_safe(current)
            carries = (
                with_header
                and page_carries_session(current, domain)
                and not _is_document(current, documents)
            )
            headers = {"Accept": "text/html, text/plain;q=0.9, */*;q=0.5"}
            if carries:
                # A new Session JWT for this URL, no access token: no `ath`, signed out.
                headers.update(
                    await session_headers(
                        self.transport.reactor, "GET", current, session=session, token=None
                    )
                )
            try:
                response = await send_bounded(
                    self.transport.http,
                    self.transport.http.build_request("GET", current, headers=headers),
                    max_bytes=self.max_response_bytes,
                )
            except httpx.HTTPError as exc:
                raise TransportError("request_failed", "The page could not be fetched") from exc
            if response.status_code in REDIRECT_STATUSES:
                location = response.headers.get("location")
                if not location:
                    raise TransportError("invalid_redirect", "A redirect names no location")
                current = urljoin(current, location)
                continue
            if len(response.content) > self.max_response_bytes:
                raise TransportError("response_too_large", "The page exceeds the size limit")
            return FetchedPage(
                url=current,
                status_code=response.status_code,
                headers=dict(response.headers),
                content=response.content,
                session_header_sent=carries,
                invalid_session=carries and session_error(response) == "invalid_session",
            )
        raise TransportError("too_many_redirects", "The page redirected too many times")

    async def _assert_safe(self, url: str) -> None:
        parsed = urlsplit(url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise TransportError("invalid_url", "A page is fetched from an HTTPS URL")
        policy = optional_contribution(self.transport.reactor, URL_SAFETY_POLICIES, "URL policy")
        if policy is None:
            return
        approved = await cast(UrlSafetyPolicy, policy).assert_safe(url)
        if not isinstance(approved, ApprovedUrl) or approved.url != url:
            raise TypeError("PAP URL safety policy must return the ApprovedUrl it checked")


__all__ = ["FetchedPage", "PageClient", "page_carries_session"]
