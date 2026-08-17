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
from .ssrf_guard import UnsafeAddressError, is_unsafe_redirect, resolve_pinned_address

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


class _BlockedHop(Exception):
    """A hop's resolved address(es) were validated and rejected at the exact
    moment of pinning — see ``UrlStatusChecker._resolve_hop``. Caught in
    ``_check`` and turned into the same ``redirect_broken`` / ``blocked: ...``
    verdict ``is_unsafe_redirect`` produces, so this is not a new outcome —
    only a second, later chance to catch a hop that changed address between
    the pre-check earlier in the loop and the connection itself."""


def _pin_request(request, ip: str) -> None:
    """Redirect ``request``'s TCP connection target to ``ip`` in place,
    while leaving the ``Host`` header (already set by ``build_request`` from
    the original hostname) untouched and pinning TLS SNI/certificate-hostname
    validation to that same original hostname via httpx's ``sni_hostname``
    request extension.

    This is what actually closes the DNS-rebinding race for status.py: the
    address handed to httpx here is the *exact* one ``resolve_pinned_address``
    just validated — httpcore's connection pool connects straight to
    ``request.url.host`` (see ``httpcore._async.connection.AsyncHTTPConnection.
    _connect``), so once this runs there is no further hostname resolution
    before the socket connects.
    """
    original_host = request.url.host
    request.extensions = {**request.extensions, "sni_hostname": original_host}
    request.url = request.url.copy_with(host=ip)


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

    def __init__(
        self,
        options: StatusCheckOptions,
        client: object | None = None,
        transport: object | None = None,
    ) -> None:
        self.options = options
        self._client = client
        self._owns_client = client is None
        # Only ever consulted when we're building our own client (below):
        # lets tests exercise the real client-construction + pinning code
        # path against a fake transport instead of the network, without
        # touching the pinning logic itself. Production never sets this.
        self._transport = transport
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
            client_kwargs: dict[str, object] = dict(
                follow_redirects=False,
                timeout=self.options.timeout_s,
                verify=self.options.verify_tls,
                headers=headers,
            )
            if self._transport is not None:
                client_kwargs["transport"] = self._transport
            self._client = httpx.AsyncClient(**client_kwargs)
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
                response, used_method = await self._request(method, current, original_host)
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
        except _BlockedHop as exc:
            # Caught here rather than where it's raised (inside _resolve_hop,
            # called from _request/_add_checksum) so it lands in the same
            # verdict as the `is_unsafe_redirect` check a few lines above:
            # this only ever fires when a hop's address changed *between*
            # that pre-check and the pinning resolution that immediately
            # precedes the real connection — the exact DNS-rebinding window
            # this module closes. See ssrf_guard.resolve_pinned_address.
            status.state = "redirect_broken"
            status.error = f"blocked: {exc}"[:300]
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
            await self._add_checksum(status, original_host)

        status.elapsed_s = time.monotonic() - started
        return status

    async def _add_checksum(self, status: UrlStatus, original_host: str) -> None:
        """Hash the body of the final response, up to the size cap."""
        import httpx

        client = self._client
        assert client is not None
        digest = hashlib.sha256()
        size = 0
        limit = self.options.checksum_max_bytes
        scoped = self._scoped_kwargs(status.final_url, original_host)

        try:
            request, auth = await self._build_and_maybe_pin(client, "GET", status.final_url, scoped, original_host)
            response = await client.send(request, auth=auth, stream=True)
            try:
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
            finally:
                await response.aclose()
        except _BlockedHop as exc:
            # The final URL's address changed to a blocked one between the
            # walk resolving it and this fetch pinning it — the status verdict
            # already stands (see docstring above), so this only costs the
            # checksum, same shape as a transport failure below.
            status.content_type = None
            status.content_checksum = None
            status.content_length = None
            status.content_truncated = False
            _append_error(status, f"checksum unavailable: blocked: {exc}")
            return
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

    async def _resolve_hop(self, url: str, original_host: str) -> str | None:
        """Resolve (and, for a cross-host hop, validate) ``url``'s host once,
        returning the address the upcoming connection should be pinned to.

        Returns ``None`` to mean "don't pin, let httpx resolve normally" —
        either the host is empty, or our own lookup failed (a DNS failure is
        the request's own problem to surface, not a block; httpx's own
        connect attempt will report it the usual way). ``getaddrinfo``
        resolves a literal IP host locally with no network round trip, so
        there is no separate literal-IP case to special-case here.

        Same-host hops (including the very first request) are never
        blocked, mirroring ``is_unsafe_redirect``'s same-host exemption —
        that exemption exists because the operator chose this host
        deliberately, address and all. A cross-host hop is validated by
        ``ssrf_guard.resolve_pinned_address`` against the SSRF blocklist
        using this exact resolution — see its docstring for why reusing
        this one resolution, rather than validating and then separately
        connecting, is what closes the DNS-rebinding race. It raises
        :class:`~.ssrf_guard.UnsafeAddressError` if every address is
        blocked, which the caller (``_build_and_maybe_pin``) turns into
        :class:`_BlockedHop`.
        """
        host = (urlsplit(url).hostname or "")
        if not host:
            return None
        exempt = host.lower() == original_host
        validate = not exempt and self.options.block_private_redirects
        try:
            return await resolve_pinned_address(host, validate=validate)
        except (OSError, asyncio.TimeoutError):
            return None

    async def _build_and_maybe_pin(self, client, method: str, url: str, scoped: dict, original_host: str):
        """Build the request for one hop, pinning its connection to a
        freshly-resolved, validated address when this checker owns a real
        network client.

        Pinning is skipped for an injected client (``self._owns_client`` is
        False) — a test double transport (``httpx.MockTransport`` and
        friends) has no real socket to pin and matches requests by the URL
        it's given, so rewriting the host there would break test doubles for
        no security benefit; production runs always build their own client
        and always go through this path.

        Returns ``(request, auth)`` — ``auth`` is ``build_request()``'s one
        omission from ``scoped`` (it's a ``send()``-time parameter in
        httpx, not a request-construction one), so it's carried back
        separately for the caller to pass into ``client.send(..., auth=...)``.
        """
        build_kwargs = {key: value for key, value in scoped.items() if key != "auth"}
        request = client.build_request(method, url, **build_kwargs)
        if self._owns_client:
            try:
                ip = await self._resolve_hop(url, original_host)
            except UnsafeAddressError as exc:
                raise _BlockedHop(str(exc)) from exc
            if ip is not None:
                _pin_request(request, ip)
        return request, scoped.get("auth")

    async def _request(self, method: str, url: str, original_host: str):
        """One hop. Returns ``(response, method_used)``.

        A GET is streamed and abandoned once the headers land, so a status check
        never downloads a body — the point is the status line, not the page.
        """
        client = self._client
        assert client is not None
        scoped = self._scoped_kwargs(url, original_host)

        if method == "HEAD":
            request, auth = await self._build_and_maybe_pin(client, "HEAD", url, scoped, original_host)
            response = await client.send(request, auth=auth)
            if self.options.method == "auto" and response.status_code in _HEAD_UNSUPPORTED:
                return await self._stream_get(url, original_host), "GET"
            return response, "HEAD"
        return await self._stream_get(url, original_host), "GET"

    async def _stream_get(self, url: str, original_host: str):
        """A GET whose body is never read.

        The response is closed right after sending; only the status line and
        headers are touched afterwards, and those survive closing.
        """
        client = self._client
        assert client is not None
        scoped = self._scoped_kwargs(url, original_host)
        request, auth = await self._build_and_maybe_pin(client, "GET", url, scoped, original_host)
        response = await client.send(request, auth=auth, stream=True)
        await response.aclose()
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
