"""The HTTP status/redirect pre-check: the walk, the classification, the fallbacks."""

import asyncio

import httpx
import pytest

from secman_visual_check.capture import CaptureOptions
from secman_visual_check.status import StatusCheckOptions, UrlStatusChecker


def run_check(handler, url="https://example.com/", **option_overrides):
    """Drive UrlStatusChecker.check against a mocked transport.

    Mirrors UrlStatusChecker.__aenter__'s own client construction: Basic-Auth
    and extra_headers are NOT baked in at the client level (a client-level
    default would apply to every hop, including a redirect to a different
    host) — UrlStatusChecker attaches them per-request itself, scoped to the
    host the operator targeted. Only User-Agent, which carries no
    origin-specific privilege, is a client-level default here.
    """
    options = StatusCheckOptions(**option_overrides)

    async def main():
        headers = {}
        if options.user_agent:
            headers["User-Agent"] = options.user_agent
        client = httpx.AsyncClient(
            transport=httpx.MockTransport(handler),
            follow_redirects=False,
            headers=headers,
        )
        async with UrlStatusChecker(options, client=client) as checker:
            try:
                return await checker.check(url)
            finally:
                await client.aclose()

    return asyncio.run(main())


def responder(routes, default=404):
    """A handler answering from a ``{url: (status, location)}`` table."""

    def handler(request):
        status, location = routes.get(str(request.url), (default, None))
        headers = {"Location": location} if location else {}
        return httpx.Response(status, headers=headers)

    return handler


def test_plain_200_is_ok_with_a_single_chain_entry():
    status = run_check(responder({"https://example.com/": (200, None)}))

    assert status.state == "ok"
    assert status.ok is True
    assert status.first_status == 200
    assert status.final_status == 200
    assert status.redirect_count == 0
    assert len(status.chain) == 1
    assert status.label == "200 ok"


def test_redirect_records_the_raw_first_status_and_the_final_one():
    status = run_check(
        responder(
            {
                "http://old.example.com/": (301, "https://old.example.com/"),
                "https://old.example.com/": (200, None),
            }
        ),
        url="http://old.example.com/",
    )

    assert status.state == "redirect"
    assert status.ok is True
    assert status.first_status == 301
    assert status.final_status == 200
    assert status.final_url == "https://old.example.com/"
    assert status.redirect_count == 1
    assert status.chain[0].location == "https://old.example.com/"
    assert status.label == "301->200 redirect"


def test_relative_location_is_resolved_against_the_current_url():
    status = run_check(
        responder(
            {
                "https://example.com/old": (302, "/new"),
                "https://example.com/new": (200, None),
            }
        ),
        url="https://example.com/old",
    )

    assert status.final_url == "https://example.com/new"
    assert status.state == "redirect"


def test_chain_longer_than_the_cap_is_reported_as_broken():
    routes = {f"https://example.com/{i}": (302, f"/{i + 1}") for i in range(10)}
    status = run_check(routes and responder(routes), url="https://example.com/0", max_redirects=2)

    assert status.state == "redirect_broken"
    assert status.ok is False
    assert "stopped after 2" in status.error
    # Two hops followed, plus the third response that ended it.
    assert len(status.chain) == 3


def test_redirect_loop_is_detected_rather_than_followed_forever():
    status = run_check(
        responder(
            {
                "https://example.com/a": (302, "https://example.com/b"),
                "https://example.com/b": (302, "https://example.com/a"),
            }
        ),
        url="https://example.com/a",
    )

    assert status.state == "redirect_broken"
    assert "redirect loop" in status.error


def test_redirect_to_a_non_http_scheme_stops_the_walk():
    status = run_check(responder({"https://example.com/": (302, "ftp://example.com/x")}))

    assert status.state == "redirect_broken"
    assert status.ok is False
    assert "non-HTTP" in status.error


def test_redirect_to_an_unparseable_location_stops_the_walk():
    # httpx builds the redirect request eagerly, so these never come back as a
    # response at all — the checker has to recognise the exception instead.
    for location in ("mailto:someone@example.com", "javascript:alert(1)"):
        status = run_check(responder({"https://example.com/": (302, location)}))

        assert status.state == "redirect_broken", location
        assert "unusable redirect target" in status.error


def test_redirect_to_cloud_metadata_address_is_blocked():
    status = run_check(
        responder({"https://example.com/": (302, "http://169.254.169.254/latest/meta-data/")})
    )

    assert status.state == "redirect_broken"
    assert status.ok is False
    assert "blocked" in status.error
    assert "private/internal" in status.error


def test_redirect_to_loopback_on_a_different_host_is_blocked():
    status = run_check(responder({"https://example.com/": (302, "http://127.0.0.1:8080/admin")}))

    assert status.state == "redirect_broken"
    assert "blocked" in status.error


def test_redirect_to_a_public_host_pins_the_resolved_address(monkeypatch):
    """DNS-rebinding regression guard: the connection for a cross-host
    redirect must use the exact address ssrf_guard.check_redirect validated,
    not re-resolve the hostname — otherwise a nameserver that answers this
    lookup with a public IP and the connection's own lookup moments later
    with a private one defeats the guard entirely."""
    import secman_visual_check.ssrf_guard as ssrf_guard

    class FakeLoop:
        async def getaddrinfo(self, host, port):
            return [(None, None, None, "", ("93.184.216.34", 0))]

    monkeypatch.setattr(ssrf_guard.asyncio, "get_event_loop", lambda: FakeLoop())

    seen = []

    def handler(request):
        seen.append(request)
        if str(request.url) == "https://example.com/":
            return httpx.Response(302, headers={"Location": "https://other-public-site.example/"})
        # The second hop and the checksum GET that follows it: httpx must
        # have connected to the pinned IP, never re-resolved
        # "other-public-site.example" itself.
        return httpx.Response(200, content=b"hello world")

    status = run_check(handler)

    assert status.state == "redirect"
    assert status.ok is True
    assert status.final_url == "https://other-public-site.example/"
    assert status.content_checksum is not None
    # hop1 (unpinned, the operator's own target) + hop2 + the checksum GET
    # (both of the latter pinned to the resolved address, since the checksum
    # fetch is a second, independent request against status.final_url that
    # must reuse the walk's pin rather than re-resolving and reopening the
    # DNS-rebinding gap this whole fix closes).
    assert len(seen) == 3
    pinned_requests = seen[1:]
    assert all(r.url.host == "93.184.216.34" for r in pinned_requests)
    assert all(r.headers["host"] == "other-public-site.example" for r in pinned_requests)


def test_redirect_to_a_private_address_can_be_allowed_explicitly():
    # --allow-private-redirects: an operator scanning their own internal
    # infrastructure via a known redirector must be able to opt back in.
    status = run_check(
        responder(
            {
                "https://example.com/": (302, "http://10.0.0.5/"),
                "http://10.0.0.5/": (200, None),
            }
        ),
        block_private_redirects=False,
    )

    assert status.state == "redirect"
    assert status.ok is True
    assert status.final_url == "http://10.0.0.5/"


def test_redirect_within_the_same_host_is_never_blocked_regardless_of_address():
    status = run_check(
        responder(
            {
                "https://example.com/a": (302, "https://example.com/b"),
                "https://example.com/b": (200, None),
            }
        ),
        url="https://example.com/a",
    )

    assert status.state == "redirect"
    assert status.ok is True


def test_basic_auth_and_custom_headers_do_not_reach_a_cross_host_redirect_target():
    seen = {}

    def handler(request):
        if request.url.host == "example.com":
            return httpx.Response(302, headers={"Location": "https://attacker.example/steal"})
        seen["auth"] = request.headers.get("authorization")
        seen["custom"] = request.headers.get("x-scan")
        return httpx.Response(200)

    status = run_check(
        handler,
        extra_headers={"X-Scan": "yes"},
        basic_auth=("alice", "hunter2"),
    )

    assert status.state == "redirect"
    assert seen["auth"] is None
    assert seen["custom"] is None


def test_basic_auth_and_custom_headers_reach_a_same_host_redirect_target():
    seen = {}

    def handler(request):
        if request.url.path == "/a":
            return httpx.Response(302, headers={"Location": "/b"})
        seen["auth"] = request.headers.get("authorization")
        seen["custom"] = request.headers.get("x-scan")
        return httpx.Response(200)

    run_check(
        handler,
        url="https://example.com/a",
        extra_headers={"X-Scan": "yes"},
        basic_auth=("alice", "hunter2"),
    )

    assert seen["auth"] is not None and seen["auth"].startswith("Basic ")
    assert seen["custom"] == "yes"


def test_checksum_fetch_does_not_carry_credentials_to_a_different_final_host():
    seen = {}

    def handler(request):
        if request.url.host == "example.com":
            return httpx.Response(302, headers={"Location": "https://other-public-site.example/"})
        seen["auth"] = request.headers.get("authorization")
        return httpx.Response(200, content=b"hello")

    run_check(handler, basic_auth=("alice", "hunter2"))

    assert seen["auth"] is None


def test_a_non_http_target_is_rejected_before_any_request_is_made():
    def handler(request):  # pragma: no cover - must never run
        raise AssertionError("no request should be sent")

    status = run_check(handler, url="ftp://example.com/file")

    assert status.state == "unreachable"
    assert "not an HTTP(S) URL" in status.error


def test_redirect_without_a_location_header_is_broken():
    status = run_check(responder({"https://example.com/": (301, None)}))

    assert status.state == "redirect_broken"
    assert "without a Location" in status.error


def test_client_and_server_errors_are_classified_separately():
    missing = run_check(responder({"https://example.com/": (404, None)}))
    down = run_check(responder({"https://example.com/": (503, None)}))

    assert missing.state == "client_error"
    assert down.state == "server_error"
    assert missing.ok is False and down.ok is False


def test_a_2xx_nobody_asked_for_is_not_called_ok():
    status = run_check(responder({"https://example.com/": (204, None)}))

    assert status.state == "unexpected_status"
    assert status.ok is False
    assert status.label == "204 unexpected_status"


def test_status_expect_widens_what_counts_as_ok():
    status = run_check(
        responder({"https://example.com/": (401, None)}),
        expect_statuses=(200, 401),
    )

    assert status.state == "ok"
    assert status.ok is True


def test_max_redirects_zero_records_the_first_response_without_calling_it_broken():
    status = run_check(
        responder({"https://example.com/": (301, "https://example.com/new")}),
        max_redirects=0,
    )

    assert status.state == "redirect"
    assert status.ok is False
    assert status.error is None
    assert len(status.chain) == 1


def test_transport_failure_becomes_unreachable_and_never_propagates():
    def handler(request):
        raise httpx.ConnectError("Name or service not known", request=request)

    status = run_check(handler)

    assert status.state == "unreachable"
    assert status.ok is False
    assert "ConnectError" in status.error


def test_head_falls_back_to_get_when_the_server_refuses_head():
    seen = []

    def handler(request):
        seen.append(request.method)
        if request.method == "HEAD":
            return httpx.Response(405)
        return httpx.Response(200)

    # checksum=False so the assertion sees the walk alone: an enabled checksum
    # appends its own body GET to every healthy target.
    status = run_check(handler, checksum=False)

    assert seen == ["HEAD", "GET"]
    assert status.method == "GET"
    assert status.state == "ok"


def test_method_get_never_issues_a_head():
    seen = []

    def handler(request):
        seen.append(request.method)
        return httpx.Response(200)

    status = run_check(handler, method="get", checksum=False)

    assert seen == ["GET"]
    assert status.method == "GET"


def test_method_head_never_falls_back():
    seen = []

    def handler(request):
        seen.append(request.method)
        return httpx.Response(405)

    status = run_check(handler, method="head")

    assert seen == ["HEAD"]
    assert status.state == "client_error"
    assert status.final_status == 405


def test_303_switches_the_rest_of_the_chain_to_get():
    seen = []

    def handler(request):
        seen.append((request.method, str(request.url)))
        if str(request.url).endswith("/form"):
            return httpx.Response(303, headers={"Location": "/result"})
        return httpx.Response(200)

    run_check(handler, url="https://example.com/form")

    assert seen[0][0] == "HEAD"
    assert seen[1] == ("GET", "https://example.com/result")


def test_headers_user_agent_and_basic_auth_reach_the_request():
    seen = {}

    def handler(request):
        seen["ua"] = request.headers.get("user-agent")
        seen["custom"] = request.headers.get("x-scan")
        seen["auth"] = request.headers.get("authorization")
        return httpx.Response(200)

    run_check(
        handler,
        user_agent="secman-scanner/1.0",
        extra_headers={"X-Scan": "yes"},
        basic_auth=("alice", "hunter2"),
    )

    assert seen["ua"] == "secman-scanner/1.0"
    assert seen["custom"] == "yes"
    assert seen["auth"].startswith("Basic ")


def test_from_capture_inherits_the_browser_identity():
    capture = CaptureOptions(
        timeout_ms=45_000,
        user_agent="browser/1.0",
        extra_headers={"X-Env": "staging"},
        basic_auth=("bob", "pw"),
        ignore_https_errors=True,
    )

    options = StatusCheckOptions.from_capture(capture, enabled=False, method="get")

    assert options.timeout_s == 45.0
    assert options.user_agent == "browser/1.0"
    assert options.extra_headers == {"X-Env": "staging"}
    assert options.basic_auth == ("bob", "pw")
    assert options.verify_tls is False
    assert options.enabled is False
    assert options.method == "get"


def test_from_capture_rejects_an_unknown_override():
    with pytest.raises(TypeError):
        StatusCheckOptions.from_capture(CaptureOptions(), nonsense=True)


def test_concurrency_is_capped_by_max_concurrency():
    in_flight = 0
    peak = 0

    async def handler(request):
        nonlocal in_flight, peak
        in_flight += 1
        peak = max(peak, in_flight)
        await asyncio.sleep(0.01)
        in_flight -= 1
        return httpx.Response(200)

    options = StatusCheckOptions(max_concurrency=2)

    async def main():
        client = httpx.AsyncClient(
            transport=httpx.MockTransport(handler), follow_redirects=False
        )
        async with UrlStatusChecker(options, client=client) as checker:
            try:
                await asyncio.gather(
                    *(checker.check(f"https://example.com/{i}") for i in range(6))
                )
            finally:
                await client.aclose()

    asyncio.run(main())

    assert peak <= 2


def test_to_dict_carries_the_chain_and_the_verdict():
    status = run_check(
        responder(
            {
                "https://example.com/a": (301, "/b"),
                "https://example.com/b": (200, None),
            }
        ),
        url="https://example.com/a",
    )

    payload = status.to_dict()

    assert payload["state"] == "redirect"
    assert payload["ok"] is True
    assert payload["first_status"] == 301
    assert payload["final_status"] == 200
    assert payload["redirect_count"] == 1
    assert payload["expected_statuses"] == [200]
    assert [hop["status"] for hop in payload["chain"]] == [301, 200]
    assert payload["chain"][0]["location"] == "/b"
    assert payload["checked_at"].endswith("+00:00")


def test_check_outside_the_context_manager_is_a_programming_error():
    checker = UrlStatusChecker(StatusCheckOptions())

    with pytest.raises(RuntimeError):
        asyncio.run(checker.check("https://example.com/"))


# --------------------------------------------------------------------------- #
# Body checksum
# --------------------------------------------------------------------------- #


def body_responder(body, status_code=200, content_type="text/html"):
    def handler(request):
        if request.method == "HEAD":
            return httpx.Response(status_code, headers={"content-type": content_type})
        return httpx.Response(status_code, content=body, headers={"content-type": content_type})

    return handler


def test_checksum_is_computed_by_default():
    status = run_check(body_responder(b"<h1>hi</h1>"))

    assert status.content_checksum is not None
    assert status.content_length == len(b"<h1>hi</h1>")


def test_no_checksum_is_computed_when_turned_off():
    status = run_check(body_responder(b"<h1>hi</h1>"), checksum=False)

    assert status.content_checksum is None
    assert status.content_length is None


def test_turning_the_checksum_off_issues_no_body_request():
    """The point of --no-status-checksum is the saved bandwidth, not just the field."""
    seen = []

    def handler(request):
        seen.append(request.method)
        return httpx.Response(200, content=b"<h1>hi</h1>")

    run_check(handler, checksum=False)

    assert seen == ["HEAD"]


def test_checksum_hashes_the_body_of_a_healthy_target():
    import hashlib

    body = b"<h1>hi</h1>"
    status = run_check(body_responder(body), checksum=True)

    assert status.content_checksum == hashlib.sha256(body).hexdigest()
    assert status.content_length == len(body)
    assert status.content_type == "text/html"
    assert status.content_truncated is False


def test_the_same_body_hashes_the_same_and_a_changed_one_does_not():
    first = run_check(body_responder(b"same"), checksum=True)
    again = run_check(body_responder(b"same"), checksum=True)
    changed = run_check(body_responder(b"different"), checksum=True)

    assert first.content_checksum == again.content_checksum
    assert first.content_checksum != changed.content_checksum


def test_no_checksum_for_a_target_that_did_not_answer_as_expected():
    # A 404's error page changes for reasons nobody wants to be alerted about.
    status = run_check(body_responder(b"not found", status_code=404), checksum=True)

    assert status.state == "client_error"
    assert status.content_checksum is None


def test_an_empty_body_records_a_length_but_no_checksum():
    status = run_check(body_responder(b""), checksum=True)

    assert status.state == "ok"
    assert status.content_length == 0
    assert status.content_checksum is None


def test_a_body_over_the_cap_is_hashed_up_to_it_and_marked_truncated():
    import hashlib

    body = b"x" * 5000
    status = run_check(body_responder(body), checksum=True, checksum_max_bytes=1000)

    assert status.content_truncated is True
    assert status.content_length == 1000
    assert status.content_checksum == hashlib.sha256(body[:1000]).hexdigest()


def test_the_checksum_follows_the_redirect_chain_to_its_end():
    import hashlib

    body = b"<h1>arrived</h1>"

    def handler(request):
        if str(request.url).endswith("/old"):
            return httpx.Response(301, headers={"Location": "/new"})
        if request.method == "HEAD":
            return httpx.Response(200)
        return httpx.Response(200, content=body)

    status = run_check(handler, url="https://example.com/old", checksum=True)

    assert status.state == "redirect"
    assert status.content_checksum == hashlib.sha256(body).hexdigest()


def test_a_failed_body_read_costs_the_checksum_not_the_verdict():
    calls = []

    def handler(request):
        calls.append(request.method)
        if request.method == "HEAD":
            return httpx.Response(200)
        raise httpx.ReadTimeout("body read timed out", request=request)

    status = run_check(handler, checksum=True)

    assert status.state == "ok"  # the status verdict still stands
    assert status.ok is True
    assert status.content_checksum is None
    assert "checksum unavailable" in status.error


def test_a_target_that_changes_answer_between_the_walk_and_the_body_read():
    seen = []

    def handler(request):
        seen.append(request.method)
        if request.method == "HEAD":
            return httpx.Response(200)
        return httpx.Response(503)

    status = run_check(handler, checksum=True)

    assert status.state == "ok"
    assert status.content_checksum is None
    assert status.content_type is None


def test_checksum_appears_in_to_dict():
    payload = run_check(body_responder(b"body"), checksum=True).to_dict()

    assert len(payload["content_checksum"]) == 64
    assert payload["content_length"] == 4
    assert payload["content_type"] == "text/html"
    assert payload["content_truncated"] is False
