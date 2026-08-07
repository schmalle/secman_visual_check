"""Optional robots.txt enforcement (opt-in via --respect-robots)."""

from __future__ import annotations

import asyncio
from urllib.parse import urljoin, urlsplit, urlunsplit
from urllib.robotparser import RobotFileParser

from .ssrf_guard import is_unsafe_redirect

_ALLOWED_SCHEMES = frozenset({"http", "https"})
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
#: Matches StatusCheckOptions.max_redirects' default order of magnitude —
#: robots.txt fetches don't need their own tunable, just a sane bound.
_MAX_REDIRECTS = 10


class RobotsCache:
    """Fetches and caches robots.txt per origin.

    Fail-open: an origin whose robots.txt cannot be fetched is treated as
    allowing everything, matching how crawlers conventionally behave.
    """

    def __init__(
        self,
        user_agent: str = "*",
        timeout_s: float = 10.0,
        block_private_redirects: bool = True,
        client: object | None = None,
    ) -> None:
        self.user_agent = user_agent
        self.timeout_s = timeout_s
        #: Same SSRF threat model as status.py/capture.py: a compromised target
        #: can point its robots.txt at a redirect landing on a private/loopback/
        #: link-local/metadata address on a different host. See ssrf_guard.py.
        self.block_private_redirects = block_private_redirects
        #: Test-only injection point, mirroring UrlStatusChecker(options, client=...) —
        #: lets tests drive a MockTransport instead of a real socket.
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
        import httpx

        client = self._client
        owns_client = client is None
        if owns_client:
            client = httpx.AsyncClient(timeout=self.timeout_s, follow_redirects=False)

        try:
            current = robots_url
            seen = {current}
            response = None
            for _ in range(_MAX_REDIRECTS + 1):
                response = await client.get(current)
                if response.status_code not in _REDIRECT_STATUSES:
                    break
                location = response.headers.get("location")
                if not location:
                    return None
                nxt = urljoin(current, location)
                if (urlsplit(nxt).scheme or "").lower() not in _ALLOWED_SCHEMES:
                    return None
                if nxt in seen:
                    return None
                if self.block_private_redirects and await is_unsafe_redirect(
                    robots_url, nxt
                ):
                    return None
                seen.add(nxt)
                current = nxt
            else:
                return None
        except Exception:
            return None
        finally:
            if owns_client:
                await client.aclose()

        if response is None or response.status_code >= 400:
            return None

        parser = RobotFileParser()
        parser.parse(response.text.splitlines())
        return parser
