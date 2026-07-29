"""HTTP status and redirect pre-check, run against every target before capture.

Deliberately a separate request rather than a reuse of Playwright's navigation
response: the browser follows redirects internally, answers from its cache, runs
service workers and honours storage state, so it can only ever tell us where a
target *ended up*. This walks the chain by hand with ``follow_redirects=False``,
so the first response — and every ``Location`` after it — is recorded verbatim,
which is what a non-browser client actually sees.
"""

from __future__ import annotations

import asyncio
import hashlib
import time
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

from .capture import CaptureOptions
from .models import RedirectHop, UrlStatus, utcnow

DEFAULT_TIMEOUT_S = 15.0
DEFAULT_MAX_REDIRECTS = 10
DEFAULT_EXPECT: tuple[int, ...] = (200,)
DEFAULT_CONCURRENCY = 8
#: 5 MiB. Past this the body is hashed up to the cap and marked truncated — a
#: change checker should not download an ISO to notice a heading moved.
DEFAULT_CHECKSUM_MAX_BYTES = 5 * 1024 * 1024

#: Statuses where a HEAD answer says more about the server's HEAD support than
#: about the resource, so the hop is retried with GET.
_HEAD_UNSUPPORTED = frozenset({400, 403, 405, 406, 501})
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_ALLOWED_SCHEMES = frozenset({"http", "https"})


@dataclass
class StatusCheckOptions:
    enabled: bool = True
    #: ``auto`` tries HEAD and falls back to GET; ``head``/``get`` pin the method.
    method: str = "auto"
    timeout_s: float = DEFAULT_TIMEOUT_S
    max_redirects: int = DEFAULT_MAX_REDIRECTS
    expect_statuses: tuple[int, ...] = DEFAULT_EXPECT
    max_concurrency: int = DEFAULT_CONCURRENCY
    #: Hash the response body of targets that answer as expected, so a later run
    #: can tell "still up" from "still up and unchanged". On by default: it costs
    #: one extra GET per healthy target, and a status check that cannot tell you
    #: the content changed is answering a less useful question.
    checksum: bool = True
    checksum_max_bytes: int = DEFAULT_CHECKSUM_MAX_BYTES
    user_agent: str | None = None
    extra_headers: dict[str, str] = field(default_factory=dict)
    basic_auth: tuple[str, str] | None = None
    verify_tls: bool = True

    @classmethod
    def from_capture(cls, capture: CaptureOptions, **overrides: object) -> "StatusCheckOptions":
        """Inherit the browser's identity so both requests look like one client."""
        options = cls(
            timeout_s=capture.timeout_ms / 1000.0,
            user_agent=capture.user_agent,
            extra_headers=dict(capture.extra_headers),
            basic_auth=capture.basic_auth,
            verify_tls=not capture.ignore_https_errors,
        )
        for key, value in overrides.items():
            if not hasattr(options, key):  # pragma: no cover - programming error
                raise TypeError(f"unknown StatusCheckOptions field {key!r}")
            setattr(options, key, value)
        return options


class UrlStatusChecker:
    """Async context manager around one pooled httpx client.

    ``check()`` never raises: a target that cannot be reached is a result, not an
    error, and a DNS failure must not take down a thousand-target scan.
    """

    def __init__(self, options: StatusCheckOptions, client: object | None = None) -> None:
        self.options = options
        self._client = client
        self._owns_client = client is None
        self._semaphore: asyncio.Semaphore | None = None

    async def __aenter__(self) -> "UrlStatusChecker":
        if self._client is None:
            import httpx

            headers = dict(self.options.extra_headers)
            if self.options.user_agent:
                headers["User-Agent"] = self.options.user_agent
            self._client = httpx.AsyncClient(
                follow_redirects=False,
                timeout=self.options.timeout_s,
                verify=self.options.verify_tls,
                headers=headers,
                auth=self.options.basic_auth,
            )
        self._semaphore = asyncio.Semaphore(max(1, self.options.max_concurrency))
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if self._owns_client and self._client is not None:
            try:
                await self._client.aclose()  # type: ignore[attr-defined]
            except Exception:  # pragma: no cover - teardown best effort
                pass
        self._client = None

    async def check(self, url: str) -> UrlStatus:
        if self._client is None:
            raise RuntimeError("UrlStatusChecker must be used as an async context manager")
        semaphore = self._semaphore
        if semaphore is None:  # pragma: no cover - defensive
            return await self._check(url)
        async with semaphore:
            return await self._check(url)

    async def _check(self, url: str) -> UrlStatus:
        import httpx

        options = self.options
        status = UrlStatus(
            url=url,
            expected_statuses=tuple(options.expect_statuses),
            checked_at=utcnow(),
        )
        started = time.monotonic()
        current = url
        method = "GET" if options.method == "get" else "HEAD"
        seen = {url}

        # Checked up front so that any InvalidURL raised below can only be about a
        # redirect target, never about the target we were handed.
        if (urlsplit(url).scheme or "").lower() not in _ALLOWED_SCHEMES:
            status.state = "unreachable"
            status.error = f"not an HTTP(S) URL: {url[:120]}"
            status.elapsed_s = time.monotonic() - started
            return status

        try:
            while True:
                hop_started = time.monotonic()
                response, used_method = await self._request(method, current)
                hop = RedirectHop(
                    url=current,
                    status=response.status_code,
                    location=response.headers.get("location"),
                    elapsed_s=time.monotonic() - hop_started,
                )
                status.chain.append(hop)
                if status.first_status is None:
                    status.first_status = hop.status
                    status.method = used_method
                status.final_status = hop.status
                status.final_url = current

                if hop.status not in _REDIRECT_STATUSES:
                    break
                if not hop.location:
                    status.state = "redirect_broken"
                    status.error = f"HTTP {hop.status} without a Location header"
                    break
                if len(status.chain) > options.max_redirects:
                    # ``--status-max-redirects 0`` means "record the first response
                    # and stop", which is a deliberate choice, not a broken chain.
                    if options.max_redirects > 0:
                        status.state = "redirect_broken"
                        status.error = f"stopped after {options.max_redirects} redirect(s)"
                    break

                nxt = urljoin(current, hop.location)
                scheme = (urlsplit(nxt).scheme or "").lower()
                if scheme not in _ALLOWED_SCHEMES:
                    status.state = "redirect_broken"
                    status.error = f"redirect to a non-HTTP target: {hop.location[:120]}"
                    break
                if nxt in seen:
                    status.state = "redirect_broken"
                    status.error = f"redirect loop at {nxt}"
                    break

                seen.add(nxt)
                current = nxt
                status.final_url = nxt
                # RFC 9110: 303 turns the request into a GET; the others keep it.
                if hop.status == 303:
                    method = "GET"
        except httpx.InvalidURL as exc:
            # httpx assembles the redirect request eagerly even when told not to
            # follow it, so a Location it cannot parse — ``mailto:``, a bare
            # ``example.com``, a control character — arrives as an exception
            # instead of a response. The 3xx itself is lost with it; the target
            # URL was validated above, so this can only be the server's doing.
            status.state = "redirect_broken"
            status.error = f"unusable redirect target: {exc}"[:300]
        except httpx.HTTPError as exc:
            status.state = "unreachable"
            status.error = _short_error(exc)
        except Exception as exc:  # pragma: no cover - unexpected client failure
            status.state = "unreachable"
            status.error = f"{type(exc).__name__}: {exc}"[:300]

        if status.state == "unknown":
            status.state = _classify(status)

        # Only worth a body fetch once we know the target answered as asked: a
        # 404's error page changes for reasons nobody wants to be alerted about.
        if options.checksum and status.ok and status.final_url:
            await self._add_checksum(status)

        status.elapsed_s = time.monotonic() - started
        return status

    async def _add_checksum(self, status: UrlStatus) -> None:
        """Hash the body of the final response, up to the size cap."""
        import httpx

        client = self._client
        assert client is not None
        digest = hashlib.sha256()
        size = 0
        limit = self.options.checksum_max_bytes

        try:
            async with client.stream("GET", status.final_url) as response:
                status.content_type = response.headers.get("content-type")
                if response.status_code not in status.expected_statuses:
                    # The target changed answer between the walk and this fetch.
                    status.content_type = None
                    return
                async for chunk in response.aiter_bytes():
                    if limit and size + len(chunk) > limit:
                        digest.update(chunk[: limit - size])
                        size = limit
                        status.content_truncated = True
                        break
                    digest.update(chunk)
                    size += len(chunk)
        except httpx.HTTPError as exc:
            # The status verdict already stands; a failed body read only costs
            # us the checksum, so it is recorded rather than promoted to an error.
            status.content_type = None
            status.content_checksum = None
            status.content_length = None
            status.content_truncated = False
            _append_error(status, f"checksum unavailable: {_short_error(exc)}")
            return
        except Exception as exc:  # pragma: no cover - unexpected client failure
            _append_error(status, f"checksum unavailable: {type(exc).__name__}")
            return

        if size == 0 and not status.content_truncated:
            # No body at all — a 204, a HEAD-like response, an empty file. There
            # is nothing to checksum, and hashing "" would look like content.
            status.content_length = 0
            return
        status.content_checksum = digest.hexdigest()
        status.content_length = size

    async def _request(self, method: str, url: str):
        """One hop. Returns ``(response, method_used)``.

        A GET is streamed and abandoned once the headers land, so a status check
        never downloads a body — the point is the status line, not the page.
        """
        client = self._client
        assert client is not None

        if method == "HEAD":
            response = await client.head(url)
            if self.options.method == "auto" and response.status_code in _HEAD_UNSUPPORTED:
                return await self._stream_get(url), "GET"
            return response, "HEAD"
        return await self._stream_get(url), "GET"

    async def _stream_get(self, url: str):
        """A GET whose body is never read.

        The response is closed on the way out of the ``with``; only the status
        line and headers are touched afterwards, and those survive closing.
        """
        client = self._client
        assert client is not None
        async with client.stream("GET", url) as response:
            return response


def _classify(status: UrlStatus) -> str:
    """Map a completed walk onto a :data:`~.models.STATUS_STATES` member."""
    code = status.final_status
    if code is None:
        return "unreachable"
    if code in status.expected_statuses:
        return "redirect" if status.redirect_count else "ok"
    if code in _REDIRECT_STATUSES:
        # Only reachable with --status-max-redirects 0: the first response is a
        # redirect we were told not to follow.
        return "redirect"
    if 400 <= code < 500:
        return "client_error"
    if code >= 500:
        return "server_error"
    # A 1xx or a 2xx nobody asked for — a 204 where 200 was expected. Calling
    # that "ok" while ok is False would be a contradiction on screen.
    return "unexpected_status"


def _append_error(status: UrlStatus, message: str) -> None:
    """Add a note without discarding whatever the walk already recorded."""
    status.error = f"{status.error}; {message}" if status.error else message
    status.error = status.error[:300]


def _short_error(exc: BaseException) -> str:
    message = str(exc).strip().splitlines()
    first = message[0] if message else ""
    return f"{type(exc).__name__}: {first}"[:300] if first else type(exc).__name__
