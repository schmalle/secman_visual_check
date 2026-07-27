"""Upload findings to a SecMan backend, over the REST API or the MCP endpoint.

SecMan (https://github.com/schmalle/secman) tracks vulnerabilities as
``(asset, vulnerabilityId, criticality)`` triples. A visual finding is not a CVE,
so each one is mapped to a *stable synthetic* vulnerability id derived from the
page it was found on and the finding's category — see :func:`vulnerability_id`.
Stability is what makes re-scanning idempotent: the same exposure on the same
page keeps the same id across runs, so SecMan's ``(asset, cve)`` upsert refreshes
the row instead of adding a second one.

Duplicates are suppressed in three layers:

1. Within one upload, findings that collapse to the same
   ``(hostname, vulnerability id)`` are merged, keeping the highest severity.
2. Before writing, the backend is asked which ids the asset already has; those
   are skipped (disable with ``allow_existing``).
3. Whatever still reaches the backend hits its own ``(asset, cve)`` upsert, so a
   race or a stale read updates a row rather than duplicating it.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Sequence, TextIO
from urllib.parse import urlparse

from .models import ScanReport, Severity

DEFAULT_BACKEND_URL = "http://localhost:8080"
DEFAULT_ID_PREFIX = "SECMAN-VISUAL"
DEFAULT_OWNER = "secman-visual-check"
DEFAULT_MIN_SEVERITY = Severity.MEDIUM
DEFAULT_TIMEOUT_S = 30.0

MCP_PROTOCOL_VERSION = "2024-11-05"
CLIENT_NAME = "secman_visual_check"

# SecMan's criticality scale has no "info" level; anything below low lands on LOW.
CRITICALITY_BY_SEVERITY = {
    Severity.CRITICAL: "CRITICAL",
    Severity.HIGH: "HIGH",
    Severity.MEDIUM: "MEDIUM",
    Severity.LOW: "LOW",
    Severity.INFO: "LOW",
}

# Pagination guard: existing-id lookups walk pages until exhausted; never forever.
_MAX_PAGES = 50
_PAGE_SIZE = 500

_RETRY_STATUSES = frozenset({408, 425, 429, 500, 502, 503, 504, 529})


class SecmanError(RuntimeError):
    """Raised when SecMan cannot be reached, rejects us, or answers unusably."""


# --------------------------------------------------------------------------- #
# Mapping findings onto SecMan's vulnerability model
# --------------------------------------------------------------------------- #


def asset_name(url: str, override: str | None = None) -> str:
    """The SecMan asset a finding belongs to: the target's host.

    Port is deliberately excluded — an asset is a machine, and two services on
    one host belong to the same inventory entry. The port still participates in
    the finding id, so findings on :8080 and :443 stay distinct.
    """
    if override:
        return override
    host = urlparse(url).hostname
    if not host:
        raise SecmanError(f"cannot derive a SecMan asset name from {url!r}")
    return host.lower()


def vulnerability_id(url: str, category: str, prefix: str = DEFAULT_ID_PREFIX) -> str:
    """A stable id for "this category of exposure, on this page".

    Derived from host, port, path, query and category — never from the model's
    wording, which changes between runs and would mint a new id every scan.
    """
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    port = f":{parsed.port}" if parsed.port else ""
    path = parsed.path or "/"
    query = f"?{parsed.query}" if parsed.query else ""
    slug = re.sub(r"[^A-Z0-9]+", "-", (category or "finding").upper()).strip("-") or "FINDING"
    digest = hashlib.sha256(
        f"{host}{port}{path}{query}|{(category or '').strip().lower()}".encode("utf-8")
    ).hexdigest()[:10]
    return f"{prefix}-{slug}-{digest}".upper()


@dataclass(frozen=True)
class UploadItem:
    """One finding, already shaped the way SecMan wants it."""

    hostname: str
    vulnerability_id: str
    criticality: str
    severity: Severity
    url: str
    category: str
    title: str

    @property
    def key(self) -> tuple[str, str]:
        return (self.hostname.lower(), self.vulnerability_id)

    def payload(self, owner: str = DEFAULT_OWNER) -> dict[str, Any]:
        """The request body for ``/api/vulnerabilities/cli-add`` and ``add_vulnerability``."""
        return {
            "hostname": self.hostname,
            "cve": self.vulnerability_id,
            "criticality": self.criticality,
            "daysOpen": 0,
            "owner": owner,
        }


#: Terminal states an item can end in. ``planned`` only occurs in a dry run and
#: means "would have been written"; ``skipped`` always means "SecMan has it".
UPLOAD_STATUSES = ("created", "updated", "planned", "skipped", "failed")


@dataclass
class UploadOutcome:
    """What happened to one item — one of :data:`UPLOAD_STATUSES`."""

    item: UploadItem
    status: str
    detail: str = ""

    @property
    def written(self) -> bool:
        return self.status in ("created", "updated")


@dataclass
class UploadSummary:
    transport: str
    endpoint: str
    dry_run: bool
    outcomes: list[UploadOutcome] = field(default_factory=list)
    merged: int = 0
    below_threshold: int = 0
    existing_lookup_error: str | None = None

    def count(self, status: str) -> int:
        return sum(1 for o in self.outcomes if o.status == status)

    @property
    def failures(self) -> list[UploadOutcome]:
        return [o for o in self.outcomes if o.status == "failed"]

    def to_dict(self) -> dict[str, Any]:
        return {
            "transport": self.transport,
            "endpoint": self.endpoint,
            "dry_run": self.dry_run,
            "merged_duplicates": self.merged,
            "below_threshold": self.below_threshold,
            "existing_lookup_error": self.existing_lookup_error,
            "counts": {status: self.count(status) for status in UPLOAD_STATUSES},
            "items": [
                {
                    "hostname": o.item.hostname,
                    "vulnerabilityId": o.item.vulnerability_id,
                    "criticality": o.item.criticality,
                    "url": o.item.url,
                    "category": o.item.category,
                    "title": o.item.title,
                    "status": o.status,
                    "detail": o.detail,
                }
                for o in self.outcomes
            ],
        }


def build_items(
    report: dict[str, Any] | ScanReport,
    *,
    min_severity: Severity = DEFAULT_MIN_SEVERITY,
    id_prefix: str = DEFAULT_ID_PREFIX,
    asset_override: str | None = None,
) -> tuple[list[UploadItem], int]:
    """Turn a scan report into upload items.

    Accepts a :class:`ScanReport` or the parsed JSON of one, so findings from an
    earlier run can be uploaded without rescanning. Returns
    ``(items, dropped_below_threshold)``.
    """
    data = report.to_dict() if isinstance(report, ScanReport) else report
    results = data.get("results")
    if not isinstance(results, list):
        raise SecmanError("report has no 'results' list; is this a secman_visual_check report?")

    items: list[UploadItem] = []
    dropped = 0
    for result in results:
        if not isinstance(result, dict):
            continue
        url = str(result.get("url") or "").strip()
        analysis = result.get("analysis")
        if not url or not isinstance(analysis, dict):
            continue
        for raw in analysis.get("findings") or []:
            if not isinstance(raw, dict):
                continue
            title = str(raw.get("title") or "").strip()
            if not title:
                continue
            severity = Severity.parse(raw.get("severity"), Severity.MEDIUM)
            if severity.rank < min_severity.rank:
                dropped += 1
                continue
            category = str(raw.get("category") or "other").strip() or "other"
            items.append(
                UploadItem(
                    hostname=asset_name(url, asset_override),
                    vulnerability_id=vulnerability_id(url, category, id_prefix),
                    criticality=CRITICALITY_BY_SEVERITY[severity],
                    severity=severity,
                    url=url,
                    category=category,
                    title=title,
                )
            )
    return items, dropped


def merge_duplicates(items: Sequence[UploadItem]) -> tuple[list[UploadItem], int]:
    """Collapse items that map to the same SecMan row, keeping the worst severity.

    The same exposure often shows up on several pages of one host, and the model
    can emit two findings in one category for a single page. Both collapse to one
    ``(asset, cve)`` row, so sending both would be a self-inflicted duplicate.
    """
    kept: dict[tuple[str, str], UploadItem] = {}
    merged = 0
    for item in items:
        current = kept.get(item.key)
        if current is None:
            kept[item.key] = item
            continue
        merged += 1
        if item.severity.rank > current.severity.rank:
            kept[item.key] = item
    return list(kept.values()), merged


# --------------------------------------------------------------------------- #
# Transports
# --------------------------------------------------------------------------- #


class SecmanUploader:
    """Common shape for the two transports."""

    transport = "?"

    @property
    def endpoint(self) -> str:  # pragma: no cover - trivial
        raise NotImplementedError

    def connect(self) -> None:
        """Authenticate / handshake. Raises SecmanError on refusal."""

    def existing_vulnerability_ids(
        self, hostnames: Iterable[str], id_prefix: str
    ) -> set[tuple[str, str]]:
        """``(hostname, vulnerability id)`` pairs SecMan already holds."""
        raise NotImplementedError

    def upload(self, item: UploadItem, owner: str) -> tuple[str, str]:
        """Write one finding. Returns ``(status, detail)`` with status created/updated."""
        raise NotImplementedError

    def close(self) -> None:
        """Release the HTTP connection pool."""


class _HttpxBacked(SecmanUploader):
    """Shared httpx plumbing: client construction and retry policy."""

    def __init__(
        self,
        base_url: str,
        *,
        timeout: float = DEFAULT_TIMEOUT_S,
        verify: bool = True,
        headers: dict[str, str] | None = None,
        client: Any = None,
        max_retries: int = 2,
        retry_backoff: float = 1.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.max_retries = max(0, max_retries)
        self.retry_backoff = retry_backoff
        if client is not None:
            self._client = client
        else:
            import httpx

            self._client = httpx.Client(
                base_url=self.base_url,
                timeout=httpx.Timeout(timeout),
                verify=verify,
                follow_redirects=True,
                headers=headers or {},
            )

    def close(self) -> None:
        closer = getattr(self._client, "close", None)
        if closer:
            closer()

    def _send(self, method: str, path: str, **kwargs: Any):
        """One request with retries on transient statuses and transport errors."""
        import httpx

        delay = self.retry_backoff
        attempt = 0
        while True:
            try:
                response = self._client.request(method, path, **kwargs)
            except httpx.HTTPError as exc:
                if attempt >= self.max_retries:
                    raise SecmanError(f"{method} {path} failed: {exc}") from exc
                attempt += 1
                time.sleep(delay)
                delay *= 2
                continue

            if response.status_code in _RETRY_STATUSES and attempt < self.max_retries:
                attempt += 1
                time.sleep(delay)
                delay *= 2
                continue
            return response

    @staticmethod
    def _json(response) -> Any:
        try:
            return response.json()
        except Exception as exc:  # noqa: BLE001 - any decoder failure is the same problem
            raise SecmanError(
                f"SecMan returned non-JSON (HTTP {response.status_code}): {response.text[:200]}"
            ) from exc

    @staticmethod
    def _detail(response) -> str:
        try:
            payload = response.json()
        except Exception:  # noqa: BLE001
            return response.text[:200]
        if isinstance(payload, dict):
            return str(payload.get("error") or payload.get("message") or payload)[:200]
        return str(payload)[:200]


class HttpUploader(_HttpxBacked):
    """Direct REST client for ``POST /api/vulnerabilities/cli-add``.

    Authenticates either with a JWT you already hold (``Authorization: Bearer``)
    or by logging in at ``/api/auth/login``, which returns the JWT in the
    ``secman_auth`` cookie that httpx then replays.
    """

    transport = "http"

    def __init__(
        self,
        base_url: str,
        *,
        token: str | None = None,
        username: str | None = None,
        password: str | None = None,
        **kwargs: Any,
    ) -> None:
        headers = {"Accept": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        super().__init__(base_url, headers=headers, **kwargs)
        self.token = token
        self.username = username
        self.password = password

    @property
    def endpoint(self) -> str:
        return f"{self.base_url}/api/vulnerabilities/cli-add"

    def connect(self) -> None:
        if self.token or not self.username:
            return
        response = self._send(
            "POST",
            "/api/auth/login",
            json={"username": self.username, "password": self.password or ""},
        )
        if response.status_code >= 400:
            raise SecmanError(
                f"SecMan login failed (HTTP {response.status_code}): {self._detail(response)}"
            )
        payload = self._json(response)
        if isinstance(payload, dict) and payload.get("mfaRequired"):
            raise SecmanError(
                "SecMan requires MFA for this account. Use an automation account without "
                "MFA, or pass an existing JWT with --secman-token."
            )

    def existing_vulnerability_ids(
        self, hostnames: Iterable[str], id_prefix: str
    ) -> set[tuple[str, str]]:
        found: set[tuple[str, str]] = set()
        for hostname in sorted({h.lower() for h in hostnames}):
            for page in range(_MAX_PAGES):
                response = self._send(
                    "GET",
                    "/api/vulnerabilities/current",
                    params={
                        "system": hostname,
                        # Anything SecMan does not recognise here means "no exception
                        # filter"; the default is not_excepted, which would hide an
                        # excepted finding and make us upload it again.
                        "exceptionStatus": "all",
                        "page": page,
                        "size": _PAGE_SIZE,
                    },
                )
                if response.status_code >= 400:
                    raise SecmanError(
                        f"Could not list existing vulnerabilities for {hostname} "
                        f"(HTTP {response.status_code}): {self._detail(response)}"
                    )
                payload = self._json(response)
                content = (payload or {}).get("content") or []
                for row in content:
                    if not isinstance(row, dict):
                        continue
                    # `system` is a substring match, so other hosts can come back.
                    name = str(row.get("assetName") or "").lower()
                    vuln_id = row.get("vulnerabilityId")
                    if name == hostname and vuln_id:
                        found.add((name, str(vuln_id)))
                if not payload.get("hasNext"):
                    break
        return found

    def upload(self, item: UploadItem, owner: str) -> tuple[str, str]:
        response = self._send(
            "POST", "/api/vulnerabilities/cli-add", json=item.payload(owner)
        )
        if response.status_code >= 400:
            raise SecmanError(
                f"HTTP {response.status_code}: {self._detail(response)}"
            )
        payload = self._json(response)
        if not isinstance(payload, dict):
            raise SecmanError(f"unexpected cli-add response: {str(payload)[:200]}")
        operation = str(payload.get("operation") or "").upper()
        status = "created" if operation == "CREATED" else "updated"
        return status, str(payload.get("message") or "")


class McpUploader(_HttpxBacked):
    """JSON-RPC 2.0 client for SecMan's MCP endpoint.

    Authenticates with an MCP API key plus the delegated user's email; SecMan
    requires both headers on ``tools/call`` and computes effective permissions as
    ``api key permissions ∩ delegated user's role permissions``.
    """

    transport = "mcp"

    def __init__(
        self,
        base_url: str,
        *,
        api_key: str,
        user_email: str,
        **kwargs: Any,
    ) -> None:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-MCP-API-Key": api_key,
            "X-MCP-User-Email": user_email,
        }
        super().__init__(base_url, headers=headers, **kwargs)
        self.user_email = user_email
        self._path = "/mcp" if not self.base_url.endswith("/mcp") else ""
        self._next_id = 0

    @property
    def endpoint(self) -> str:
        return f"{self.base_url}{self._path}"

    def _rpc(self, method: str, params: dict[str, Any] | None = None) -> Any:
        self._next_id += 1
        body: dict[str, Any] = {"jsonrpc": "2.0", "id": self._next_id, "method": method}
        if params is not None:
            body["params"] = params
        response = self._send("POST", self._path or "/", json=body)
        if response.status_code >= 400:
            raise SecmanError(
                f"MCP {method} failed (HTTP {response.status_code}): {self._detail(response)}"
            )
        payload = self._json(response)
        if not isinstance(payload, dict):
            raise SecmanError(f"MCP {method} returned {str(payload)[:200]}")
        error = payload.get("error")
        if error:
            message = error.get("message") if isinstance(error, dict) else error
            raise SecmanError(f"MCP {method} error: {message}")
        return payload.get("result")

    def _notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        body: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            body["params"] = params
        self._send("POST", self._path or "/", json=body)

    def _call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        result = self._rpc("tools/call", {"name": name, "arguments": arguments})
        if not isinstance(result, dict):
            raise SecmanError(f"MCP tool {name} returned {str(result)[:200]}")
        if result.get("isError"):
            raise SecmanError(f"MCP tool {name} reported an error: {str(result)[:200]}")
        # SecMan serialises the tool's structured result into a single text block.
        for part in result.get("content") or []:
            if isinstance(part, dict) and part.get("type") == "text":
                try:
                    decoded = json.loads(part.get("text") or "")
                except json.JSONDecodeError as exc:
                    raise SecmanError(
                        f"MCP tool {name} returned unparseable content: {part.get('text', '')[:200]}"
                    ) from exc
                if isinstance(decoded, dict):
                    return decoded
        raise SecmanError(f"MCP tool {name} returned no text content")

    def connect(self) -> None:
        self._rpc(
            "initialize",
            {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": CLIENT_NAME, "version": _client_version()},
            },
        )
        self._notify("notifications/initialized")

    def existing_vulnerability_ids(
        self, hostnames: Iterable[str], id_prefix: str
    ) -> set[tuple[str, str]]:
        wanted = {h.lower() for h in hostnames}
        found: set[tuple[str, str]] = set()
        for page in range(_MAX_PAGES):
            payload = self._call_tool(
                "get_vulnerabilities",
                {
                    # cveId is a case-insensitive partial match: our shared prefix
                    # narrows the scan to ids this tool created.
                    "cveId": id_prefix,
                    "includeExcepted": True,
                    "page": page,
                    "pageSize": _PAGE_SIZE,
                },
            )
            rows = payload.get("vulnerabilities") or []
            for row in rows:
                if not isinstance(row, dict):
                    continue
                name = str(row.get("assetName") or "").lower()
                vuln_id = row.get("vulnerabilityId")
                if name in wanted and vuln_id:
                    found.add((name, str(vuln_id)))
            total_pages = payload.get("totalPages")
            if not rows or (isinstance(total_pages, int) and page + 1 >= total_pages):
                break
        return found

    def upload(self, item: UploadItem, owner: str) -> tuple[str, str]:
        payload = item.payload(owner)
        result = self._call_tool(
            "add_vulnerability",
            {
                "hostname": payload["hostname"],
                "cve": payload["cve"],
                "criticality": payload["criticality"],
                "daysOpen": payload["daysOpen"],
                "owner": payload["owner"],
            },
        )
        status = "created" if result.get("vulnerabilityCreated") else "updated"
        return status, str(result.get("message") or "")


def _client_version() -> str:
    from . import __version__

    return __version__


# --------------------------------------------------------------------------- #
# Options and orchestration
# --------------------------------------------------------------------------- #


@dataclass
class SecmanOptions:
    """Everything the upload needs, resolved from CLI flags and the environment."""

    transport: str = "http"
    base_url: str = DEFAULT_BACKEND_URL
    dry_run: bool = False
    # http auth
    token: str | None = None
    username: str | None = None
    password: str | None = None
    # mcp auth
    api_key: str | None = None
    user_email: str | None = None
    # mapping
    min_severity: Severity = DEFAULT_MIN_SEVERITY
    owner: str = DEFAULT_OWNER
    id_prefix: str = DEFAULT_ID_PREFIX
    asset_name: str | None = None
    # behaviour
    allow_existing: bool = False
    timeout: float = DEFAULT_TIMEOUT_S
    verify_tls: bool = True

    @property
    def has_credentials(self) -> bool:
        if self.transport == "mcp":
            return bool(self.api_key and self.user_email)
        return bool(self.token or self.username)

    def validate(self) -> None:
        """Fail fast on unusable configuration, before a scan is started.

        A dry run may go without credentials — it just cannot check the backend
        for findings that already exist.
        """
        if self.transport not in ("http", "mcp"):
            raise ValueError(f"unknown SecMan transport {self.transport!r}")
        if not self.base_url:
            raise ValueError("--secman-url is required")
        if self.has_credentials or self.dry_run:
            return
        if self.transport == "mcp":
            raise ValueError(
                "SecMan MCP upload needs --secman-api-key (or $SECMAN_MCP_API_KEY) and "
                "--secman-user-email (or $SECMAN_MCP_USER_EMAIL)"
            )
        raise ValueError(
            "SecMan upload needs --secman-token (or $SECMAN_TOKEN), or "
            "--secman-username/--secman-password (or $SECMAN_USERNAME/$SECMAN_PASSWORD)"
        )

    def build_uploader(self) -> SecmanUploader:
        if self.transport == "mcp":
            return McpUploader(
                self.base_url,
                api_key=self.api_key or "",
                user_email=self.user_email or "",
                timeout=self.timeout,
                verify=self.verify_tls,
            )
        return HttpUploader(
            self.base_url,
            token=self.token,
            username=self.username,
            password=self.password,
            timeout=self.timeout,
            verify=self.verify_tls,
        )


def upload_findings(
    report: dict[str, Any] | ScanReport,
    options: SecmanOptions,
    uploader: SecmanUploader | None = None,
) -> UploadSummary:
    """Map, de-duplicate and upload a report's findings. Never raises per item.

    Pass ``uploader`` to reuse an existing connection (or a fake, in tests);
    otherwise one is built from ``options`` and closed again before returning.
    """
    items, below = build_items(
        report,
        min_severity=options.min_severity,
        id_prefix=options.id_prefix,
        asset_override=options.asset_name,
    )
    items, merged = merge_duplicates(items)
    items.sort(key=lambda i: (i.hostname, -i.severity.rank, i.vulnerability_id))

    owned = uploader is None
    # A dry run without credentials cannot talk to SecMan at all — that is the
    # offline mode, and it still prints exactly what would be sent.
    if uploader is None and (options.has_credentials or not options.dry_run):
        uploader = options.build_uploader()

    summary = UploadSummary(
        transport=options.transport,
        endpoint=uploader.endpoint if uploader else f"{options.base_url} (not contacted)",
        dry_run=options.dry_run,
        merged=merged,
        below_threshold=below,
    )

    try:
        existing: set[tuple[str, str]] = set()
        if uploader is not None:
            uploader.connect()
            if not options.allow_existing and items:
                try:
                    existing = uploader.existing_vulnerability_ids(
                        {i.hostname for i in items}, options.id_prefix
                    )
                except SecmanError as exc:
                    # Losing the pre-check is not fatal: SecMan still upserts on
                    # (asset, cve), so nothing duplicates. Say so and continue.
                    summary.existing_lookup_error = str(exc)

        for item in items:
            if item.key in existing:
                summary.outcomes.append(
                    UploadOutcome(item, "skipped", "already present in SecMan")
                )
                continue
            if options.dry_run or uploader is None:
                summary.outcomes.append(
                    UploadOutcome(item, "planned", "would be uploaded")
                )
                continue
            try:
                status, detail = uploader.upload(item, options.owner)
            except SecmanError as exc:
                summary.outcomes.append(UploadOutcome(item, "failed", str(exc)))
                continue
            summary.outcomes.append(UploadOutcome(item, status, detail))
            # Guard against two items racing to the same row within this run.
            existing.add(item.key)
    finally:
        if owned and uploader is not None:
            uploader.close()

    return summary


def load_report_json(path: str | Path) -> dict[str, Any]:
    """Read a report.json written by an earlier run."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as exc:
        raise SecmanError(f"cannot read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise SecmanError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise SecmanError(f"{path} does not contain a scan report object")
    return data


def write_upload_report(summary: UploadSummary, stream: TextIO | None = None) -> None:
    """Print the upload result in the same shape as the scan's console report."""
    out = stream or sys.stdout
    mode = "dry run (nothing written)" if summary.dry_run else "upload"
    print("", file=out)
    print("=" * 72, file=out)
    print(f"SecMan {mode} — {summary.transport} — {summary.endpoint}", file=out)
    print("=" * 72, file=out)

    if not summary.outcomes:
        print("No findings to upload.", file=out)
    for outcome in summary.outcomes:
        item = outcome.item
        print(
            f"  [{outcome.status}] {item.hostname}  {item.vulnerability_id}  "
            f"{item.criticality}",
            file=out,
        )
        print(f"      {item.title}  ({item.category})", file=out)
        print(f"      {item.url}", file=out)
        if outcome.detail:
            print(f"      {outcome.detail}", file=out)

    print("", file=out)
    counts = ", ".join(
        f"{summary.count(s)} {s}" for s in UPLOAD_STATUSES if summary.count(s) or s != "planned"
    )
    print(f"SecMan: {counts}", file=out)
    if summary.merged:
        print(
            f"  {summary.merged} duplicate finding(s) merged into existing rows before upload",
            file=out,
        )
    if summary.below_threshold:
        print(
            f"  {summary.below_threshold} finding(s) below the severity threshold were not sent",
            file=out,
        )
    if summary.existing_lookup_error:
        print(
            f"  could not pre-check for existing findings ({summary.existing_lookup_error}); "
            "relied on SecMan's own (asset, cve) upsert instead",
            file=out,
        )
