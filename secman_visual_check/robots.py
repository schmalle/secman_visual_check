"""Optional robots.txt enforcement (opt-in via --respect-robots)."""

from __future__ import annotations

import asyncio
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit
from urllib.robotparser import RobotFileParser

#: Bounded the same way status.py bounds its own walk — a robots.txt fetch
#: must not become an unbounded loop.
_MAX_REDIRECTS = 5
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_ALLOWED_SCHEMES = frozenset({"http", "https"})


class RobotsCache:
    """Fetches and caches robots.txt per origin.

    Fail-open: an origin whose robots.txt cannot be fetched — including one
    whose redirect is refused by the SSRF guard below — is treated as
    allowing everything, matching how crawlers conventionally behave.
    """

    def __init__(
        self,
        user_agent: str = "*",
        timeout_s: float = 10.0,
        block_private_redirects: bool = True,
        client: Any = None,
    ) -> None:
        self.user_agent = user_agent
        self.timeout_s = timeout_s
        #: A compromised or malicious target can point its own robots.txt at
        #: 169.254.169.254, 127.0.0.1, or another internal address via a 3xx;
        #: on by default. See ssrf_guard.py — this is the same threat model
        #: status.py and capture.py already guard against, applied here too.
        self.block_private_redirects = block_private_redirects
        #: Swappable for tests; a real client is opened per fetch otherwise.
        self._client = client
        self._parsers: dict[str, RobotFileParser | None] = {}
        self._lock = asyncio.Lock()

    async def allowed(self, url: str) -> bool:
        parser = await self._parser_for(url)
        if parser is None:
            return True
        return parser.can_fetch(self.user_agent, url)

    async def _parser_for(self, url: str) -> RobotFileParser | None:
        parts = urlsplit(url)
        origin = urlunsplit((parts.scheme, parts.netloc, "", "", ""))
        async with self._lock:
            if origin in self._parsers:
                return self._parsers[origin]

        parser = await self._fetch(f"{origin}/robots.txt")
        async with self._lock:
            self._parsers[origin] = parser
        return parser

    async def _fetch(self, robots_url: str) -> RobotFileParser | None:
        """Fetch robots.txt, walking redirects by hand.

        Deliberately not ``follow_redirects=True``: httpx's automatic
        follower gives no hook to inspect a hop before taking it, and a
        malicious or compromised target could otherwise point its own
        robots.txt at an internal/loopback/link-local address (e.g. cloud
        instance metadata) via a plain 3xx — exactly the SSRF shape
        ssrf_guard.py exists to close for status.py and capture.py. The
        initial request (the operator's own target) is never blocked; only a
        redirect that lands on a different, private host is.
        """
        import httpx

        from .ssrf_guard import is_unsafe_redirect

        client = self._client
        owns_client = client is None
        if client is None:
            client = httpx.AsyncClient(follow_redirects=False, timeout=self.timeout_s)

        current = robots_url
        seen = {current}
        try:
            for _ in range(_MAX_REDIRECTS + 1):
                try:
                    response = await client.get(current)
                except Exception:
                    return None

                if response.status_code not in _REDIRECT_STATUSES:
                    if response.status_code >= 400:
                        return None
                    parser = RobotFileParser()
                    parser.parse(response.text.splitlines())
                    return parser

                location = response.headers.get("location")
                if not location:
                    return None
                nxt = urljoin(current, location)
                scheme = (urlsplit(nxt).scheme or "").lower()
                if scheme not in _ALLOWED_SCHEMES:
                    return None
                if nxt in seen:
                    return None
                if self.block_private_redirects and await is_unsafe_redirect(
                    robots_url, nxt
                ):
                    return None
                seen.add(nxt)
                current = nxt
            return None
        except Exception:
            return None
        finally:
            if owns_client:
                await client.aclose()
