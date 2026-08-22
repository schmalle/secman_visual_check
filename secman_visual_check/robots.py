"""Optional robots.txt enforcement (opt-in via --respect-robots)."""

from __future__ import annotations

import asyncio
from urllib.parse import urljoin, urlsplit, urlunsplit
from urllib.robotparser import RobotFileParser

from .ssrf_guard import is_unsafe_redirect

#: robots.txt redirect chains are pathological past a handful of hops; this
#: also bounds how many times the SSRF check below runs per fetch.
_MAX_REDIRECTS = 5
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


class RobotsCache:
    """Fetches and caches robots.txt per origin.

    Fail-open: an origin whose robots.txt cannot be fetched is treated as
    allowing everything, matching how crawlers conventionally behave.
    """

    def __init__(
        self, user_agent: str = "*", timeout_s: float = 10.0, transport: object | None = None
    ) -> None:
        self.user_agent = user_agent
        self.timeout_s = timeout_s
        #: Swappable for tests (an ``httpx.MockTransport``); ``None`` uses the
        #: real network, same contract as the other fetchers in this codebase.
        self.transport = transport
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
        """Fetch one origin's robots.txt, walking redirects by hand.

        A monitored target's own ``robots.txt`` is exactly the kind of
        server-controlled response ``ssrf_guard`` exists for: a compromised or
        malicious target can answer with a 3xx at ``169.254.169.254`` or
        another internal address, and a client that follows redirects
        automatically (as this one used to, via ``follow_redirects=True``)
        would issue that request with no restriction at all — the same gap
        ``status.py`` and ``capture.py`` close for their own requests. The
        walk here mirrors ``status.py``'s: bounded, and every hop off the
        original host is checked before it is followed.
        """
        import httpx

        try:
            async with httpx.AsyncClient(
                timeout=self.timeout_s, follow_redirects=False, transport=self.transport
            ) as client:
                current = robots_url
                seen = {current}
                for _ in range(_MAX_REDIRECTS + 1):
                    response = await client.get(current)
                    if response.status_code not in _REDIRECT_STATUSES:
                        break
                    location = response.headers.get("location")
                    if not location:
                        return None
                    nxt = urljoin(current, location)
                    scheme = (urlsplit(nxt).scheme or "").lower()
                    if scheme not in ("http", "https") or nxt in seen:
                        return None
                    if await is_unsafe_redirect(robots_url, nxt):
                        return None
                    seen.add(nxt)
                    current = nxt
                else:
                    return None
        except Exception:
            return None

        if response.status_code >= 400:
            return None

        parser = RobotFileParser()
        parser.parse(response.text.splitlines())
        return parser
