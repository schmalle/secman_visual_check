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
from .ssrf_guard import is_unsafe_connected_addr, is_unsafe_redirect

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
    #: A compromised or malicious *target* can redirect the scanner at
    #: 169.254.169.254, 127.0.0.1, or other internal addresses; on by
    #: default, blocks such a redirect unless it stays on the same host the
    #: operator targeted. See ssrf_guard.py.
    block_private_redirects: bool = True

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

            # Basic-Auth and custom headers are deliberately NOT set here: a
            # client-level default is attached to every request the client
            # makes, including hops that land on a different host after a
            # redirect. They are instead attached per-request in
            # `_scoped_kwargs`, only when the request stays on the host the
            # operator targeted.
            headers = {}
            if self.options.user_agent:
                headers["User-Agent"] = self.options.user_agent
            self._client = httpx.AsyncClient(
                follow_redirects=False,
                timeout=self.options.timeout_s,
                verify=self.options.verify_tls,
                headers=headers,
            )
        self._semaphore = asyncio.Semaphore(max(1, self.options.max_concurrency))
        return self

    def _scoped_kwargs(self, target_url: str, original_host: str) -> dict:
        """Basic-Auth/custom headers only for a request that stays on the
        host the operator targeted — otherwise a redirect (or a checksum
        fetch of a final URL that ended up on a different host) would
        silently carry credentials meant for one origin to another."""
        if (urlsplit(target_url).hostname or "").lower() != original_host:
            return {"auth": None}
        kwargs: dict[str, object] = {}
        if self.options.extra_headers:
            kwargs["headers"] = dict(self.options.extra_headers)
        if self.options.basic_auth:
            kwargs["auth"] = self.options.basic_auth
        return kwargs

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
        original_host = (urlsplit(url).hostname or "").lower()

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
                response, used_method, remote_ip = await self._request(method, current, original_host)
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

                if options.block_private_redirects and is_unsafe_connected_addr(
                    url, current, remote_ip
                ):
                    # is_unsafe_redirect() below vets a redirect's *target* before
                    # we connect to it, from this process's own DNS lookup — which
                    # a hostile target's nameserver can answer differently than
                    # the one httpx's own, independent resolution used moments
                    # later for the actual connection (DNS-rebinding TOCTOU).
                    # remote_ip is the address httpx *actually* connected to for
                    # *this* hop, read while the stream was still open (see
                    # ssrf_guard.is_unsafe_connected_addr and `_connected_ip`
                    # below); nothing left to race. Deliberately checked before
                    # final_status/final_url are updated below, so a rebound
                    # response — even a 200 — never becomes the walk's trusted
                    # answer or feeds `status.ok`.
                    status.state = "redirect_broken"
                    status.error = (
                        "blocked: response served from a disallowed private/"
                        "internal address (post-connect SSRF check)"
                    )
                    break

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
                if options.block_private_redirects and await is_unsafe_redirect(url, nxt):
                    status.state = "redirect_broken"
                    status.error = f"blocked: redirect to a private/internal address: {hop.location[:120]}"
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
            await self._add_checksum(status, original_host, url)

        status.elapsed_s = time.monotonic() - started
        return status

    async def _add_checksum(self, status: UrlStatus, original_host: str, original_url: str) -> None:
        """Hash the body of the final response, up to the size cap."""
        import httpx

        client = self._client
        assert client is not None
        digest = hashlib.sha256()
        size = 0
        limit = self.options.checksum_max_bytes
        scoped = self._scoped_kwargs(status.final_url, original_host)

        try:
            async with client.stream("GET", status.final_url, **scoped) as response:
                # This is a brand-new connection, separate from whichever hop
                # in the redirect walk above landed on status.final_url — a
                # DNS-rebinding nameserver gets a fresh chance to answer this
                # lookup differently than it answered the walk's. Same
                # post-connect closer as the walk, applied to this fetch's own
                # connection (see ssrf_guard.is_unsafe_connected_addr).
                if self.options.block_private_redirects and is_unsafe_connected_addr(
                    original_url, status.final_url, _connected_ip(response)
                ):
                    status.content_type = None
                    _append_error(status, "checksum unavailable: blocked (post-connect SSRF check)")
                    return
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

    async def _request(self, method: str, url: str, original_host: str):
        """One hop. Returns ``(response, method_used, remote_ip)``.

        A GET is streamed and abandoned once the headers land, so a status check
        never downloads a body — the point is the status line, not the page.
        Both HEAD and GET go through :meth:`_stream` (never a bare
        ``client.head()``/``client.get()``) so ``remote_ip`` — the address the
        connection actually used — can be read while it is still open; see
        ``_connected_ip``.
        """
        if method == "HEAD":
            response, remote_ip = await self._stream("HEAD", url, original_host)
            if self.options.method == "auto" and response.status_code in _HEAD_UNSUPPORTED:
                response, remote_ip = await self._stream("GET", url, original_host)
                return response, "GET", remote_ip
            return response, "HEAD", remote_ip
        response, remote_ip = await self._stream("GET", url, original_host)
        return response, "GET", remote_ip

    async def _stream(self, http_method: str, url: str, original_host: str):
        """Send one request whose body is never read. Returns ``(response,
        remote_ip)``.

        The response is closed on the way out of the ``with``; the status line
        and headers are touched afterwards and survive that, but a stream's
        ``network_stream`` extra info does not — httpx releases the underlying
        connection back to the pool once the block exits, and a released
        connection reports no ``server_addr``. ``remote_ip`` is therefore
        captured here, before exit, not by the caller.
        """
        client = self._client
        assert client is not None
        scoped = self._scoped_kwargs(url, original_host)
        async with client.stream(http_method, url, **scoped) as response:
            return response, _connected_ip(response)


def _connected_ip(response) -> str | None:
    """The address a stream's connection actually used, read while the
    stream that produced ``response`` is still open.

    httpx exposes this via ``response.extensions["network_stream"]`` — but
    only until the connection is released back to the pool, which happens the
    moment a ``client.stream(...)`` block exits (or a non-streaming call like
    ``client.head()``/``client.get()`` returns). Callers must therefore call
    this from *inside* the ``async with client.stream(...)`` block, same as
    capture.py reads Chromium's ``response.server_addr()`` right after
    ``page.goto()`` returns. See ssrf_guard.is_unsafe_connected_addr.
    """
    network_stream = response.extensions.get("network_stream")
    if network_stream is None:
        return None
    try:
        addr = network_stream.get_extra_info("server_addr")
    except Exception:  # pragma: no cover - backend-specific, best effort
        return None
    if not addr:
        return None
    return addr[0]


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
