"""Optional robots.txt enforcement (opt-in via --respect-robots)."""

from __future__ import annotations

import asyncio
from urllib.parse import urljoin, urlsplit, urlunsplit
from urllib.robotparser import RobotFileParser

from .ssrf_guard import is_unsafe_redirect

#: A robots.txt redirect chain has no legitimate reason to be long.
_MAX_ROBOTS_REDIRECTS = 5
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


class RobotsCache:
    """Fetches and caches robots.txt per origin.

    Fail-open: an origin whose robots.txt cannot be fetched is treated as
    allowing everything, matching how crawlers conventionally behave.
    """

    def __init__(self, user_agent: str = "*", timeout_s: float = 10.0) -> None:
        self.user_agent = user_agent
        self.timeout_s = timeout_s
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
        """Fetch and parse one origin's robots.txt.

        Redirects are walked by hand, with ``follow_redirects=False``, rather
        than left to httpx's own default — the target host's robots.txt is
        otherwise an unguarded path to redirect this scanner at an internal
        or cloud-metadata address (``169.254.169.254``, ``127.0.0.1``, ...),
        exactly the SSRF shape ``ssrf_guard.py`` closes for the status check
        and the browser capture. Nothing in the response is ever exposed in a
        report, but making the request at all is the thing being blocked, so
        every hop is checked with the same guard before it is followed.
        """
        import httpx

        current = robots_url
        seen = {robots_url}
        response = None
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout_s, follow_redirects=False
            ) as client:
                for _ in range(_MAX_ROBOTS_REDIRECTS + 1):
                    response = await client.get(current)
                    if response.status_code not in _REDIRECT_STATUSES:
                        break
                    location = response.headers.get("location")
                    if not location:
                        return None
                    nxt = urljoin(current, location)
                    if urlsplit(nxt).scheme not in ("http", "https"):
                        return None
                    if nxt in seen or await is_unsafe_redirect(robots_url, nxt):
                        return None
                    seen.add(nxt)
                    current = nxt
                else:
                    # Too many hops for a robots.txt to legitimately need.
                    return None
        except Exception:
            return None

        if response is None or response.status_code >= 400:
            return None

        parser = RobotFileParser()
        parser.parse(response.text.splitlines())
        return parser
