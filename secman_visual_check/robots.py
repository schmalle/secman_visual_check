"""Optional robots.txt enforcement (opt-in via --respect-robots)."""

from __future__ import annotations

import asyncio
from urllib.parse import urljoin, urlsplit, urlunsplit
from urllib.robotparser import RobotFileParser

from .ssrf_guard import is_unsafe_redirect

#: Same shape as status.py's walk: a robots.txt host is exactly as capable of
#: redirecting the scanner at an internal address as any other target, so the
#: hop count is bounded and every hop is checked, not just the first request.
_MAX_REDIRECTS = 10


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
        """GET ``robots_url``, walking redirects by hand.

        Redirects are *not* auto-followed by the httpx client: a compromised
        or malicious target could otherwise point ``robots.txt`` at
        169.254.169.254 or another internal address and have this fetch
        follow it unconditionally, exactly the SSRF shape ``ssrf_guard.py``
        exists to close for the browser capture and the status check. Same
        policy here: a cross-host redirect onto a private/loopback/link-local
        address is refused; anything else is followed, up to
        :data:`_MAX_REDIRECTS` hops.
        """
        import httpx

        current = robots_url
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout_s, follow_redirects=False
            ) as client:
                for _ in range(_MAX_REDIRECTS + 1):
                    response = await client.get(current)
                    if response.status_code not in (301, 302, 303, 307, 308):
                        break
                    location = response.headers.get("location")
                    if not location:
                        return None
                    nxt = urljoin(current, location)
                    if urlsplit(nxt).scheme not in ("http", "https"):
                        return None
                    if await is_unsafe_redirect(robots_url, nxt):
                        return None
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
