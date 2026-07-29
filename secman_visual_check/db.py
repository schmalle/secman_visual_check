"""Optional MariaDB mirror of the status-check results.

Reports are files; a database is what you query. This writes one row per scan
run, one per checked target and one per redirect hop, so "which hosts started
answering 500 this week" is a ``SELECT`` rather than a pile of JSON.

Entirely optional and entirely fail-soft: the driver lives behind the ``db``
extra, and a database that is down degrades to a printed line — a scan's findings
are never lost because a bookkeeping write failed. See ``db/install.sh`` for the
schema and a least-privilege database user.
"""

from __future__ import annotations

import hashlib
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Sequence, TextIO
from urllib.parse import unquote, urlsplit

from .models import ScanReport

DEFAULT_DB_NAME = "secman_visual_check"
DEFAULT_TABLE_PREFIX = "svc_"
DEFAULT_CONNECT_TIMEOUT_S = 10.0

#: Table names cannot be bound as parameters, so the prefix is the one value that
#: reaches SQL by interpolation. It is validated before it ever gets there.
_PREFIX_RE = re.compile(r"^[A-Za-z0-9_]{0,16}$")

_URL_MAX = 2048
_ERROR_MAX = 512

DRIVER_MISSING = (
    "PyMySQL is not installed or cannot be imported. "
    "Run: pip install 'secman-visual-check[db]'"
)

#: The review lifecycle of a URL, carried across runs in ``<prefix>url_state``.
#:
#: ``NEW``          never reviewed — or reviewed once and changed since.
#: ``OK``           reviewed and unchanged since. Only an operator sets this.
#: ``NOT_CHECKED``  known to us, but the last run reached no verdict.
FLAG_NEW = "NEW"
FLAG_OK = "OK"
FLAG_NOT_CHECKED = "NOT_CHECKED"
URL_FLAGS = (FLAG_OK, FLAG_NOT_CHECKED, FLAG_NEW)


def parse_flag(value: str) -> str:
    """Accept ``ok``, ``NOT CHECKED``, ``not-checked`` … and return the canonical form."""
    candidate = value.strip().upper().replace(" ", "_").replace("-", "_")
    if candidate not in URL_FLAGS:
        raise ValueError(
            f"unknown flag {value!r}; expected one of {', '.join(URL_FLAGS)}"
        )
    return candidate


class DatabaseError(RuntimeError):
    """Raised when the database cannot be reached or rejects a write."""


@dataclass
class DbOptions:
    enabled: bool = False
    host: str = "127.0.0.1"
    port: int = 3306
    user: str = ""
    password: str = ""
    database: str = DEFAULT_DB_NAME
    table_prefix: str = DEFAULT_TABLE_PREFIX
    connect_timeout: float = DEFAULT_CONNECT_TIMEOUT_S
    charset: str = "utf8mb4"
    fail_on_error: bool = False

    @classmethod
    def from_url(cls, url: str, **overrides: Any) -> "DbOptions":
        """Parse ``mysql://user:pass@host:3306/dbname``."""
        parts = urlsplit(url)
        if parts.scheme not in ("mysql", "mariadb"):
            raise ValueError(
                f"--db-url must start with mysql:// or mariadb://, got {parts.scheme or url!r}"
            )
        if not parts.hostname:
            raise ValueError("--db-url is missing a host")
        options = cls(
            host=parts.hostname,
            port=parts.port or 3306,
            user=unquote(parts.username or ""),
            password=unquote(parts.password or ""),
            database=(parts.path or "").lstrip("/") or DEFAULT_DB_NAME,
        )
        for key, value in overrides.items():
            if not hasattr(options, key):  # pragma: no cover - programming error
                raise TypeError(f"unknown DbOptions field {key!r}")
            setattr(options, key, value)
        return options

    def validate(self) -> None:
        """Fail fast on unusable configuration, before a scan is started."""
        if not _PREFIX_RE.match(self.table_prefix):
            raise ValueError(
                f"invalid --db-table-prefix {self.table_prefix!r}; "
                "letters, digits and underscores only, max 16 characters"
            )
        if not self.enabled:
            return
        if not self.host:
            raise ValueError("--db-host is required when storing results in the database")
        if not self.database:
            raise ValueError("--db-name is required when storing results in the database")
        if not self.user:
            raise ValueError(
                "database storage needs --db-user (or $SECMAN_DB_USER), or a --db-url "
                "carrying the credentials"
            )

    @property
    def dsn(self) -> str:
        """A safe-to-print identifier. Never contains the password."""
        who = f"{self.user}@" if self.user else ""
        return f"{who}{self.host}:{self.port}/{self.database}"

    def table(self, name: str) -> str:
        return f"{self.table_prefix}{name}"


@dataclass
class FlagChange:
    """One URL's lifecycle transition during a run."""

    url: str
    flag: str
    previous: str | None = None
    reason: str = ""

    @property
    def is_new_url(self) -> bool:
        return self.previous is None

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "flag": self.flag,
            "previous": self.previous,
            "reason": self.reason,
        }


@dataclass
class DbWriteSummary:
    enabled: bool
    dsn: str
    runs_written: int = 0
    checks_written: int = 0
    hops_written: int = 0
    #: Only transitions — a URL whose flag did not move is not listed.
    flag_changes: list[FlagChange] = field(default_factory=list)
    error: str | None = None
    skipped_reason: str | None = None

    @property
    def new_urls(self) -> list[FlagChange]:
        return [c for c in self.flag_changes if c.is_new_url]

    @property
    def changed_content(self) -> list[FlagChange]:
        return [c for c in self.flag_changes if c.reason == "content changed"]

    def flag_counts(self) -> dict[str, int]:
        counts = {flag: 0 for flag in URL_FLAGS}
        for change in self.flag_changes:
            counts[change.flag] = counts.get(change.flag, 0) + 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "dsn": self.dsn,
            "runs_written": self.runs_written,
            "checks_written": self.checks_written,
            "hops_written": self.hops_written,
            "flag_changes": [c.to_dict() for c in self.flag_changes],
            "error": self.error,
            "skipped_reason": self.skipped_reason,
        }


def pymysql_available() -> bool:
    """Whether the driver can actually be imported.

    Not just ``ImportError``: a driver whose own dependencies are broken can fail
    in stranger ways — PyMySQL pulls in ``cryptography``, whose Rust extension
    raises a ``BaseException`` subclass when its bindings are missing. An
    unusable driver has to look the same as an absent one, or a bookkeeping
    feature nobody asked for takes the whole scan down.
    """
    try:
        import pymysql  # noqa: F401
    except (KeyboardInterrupt, SystemExit):
        # Not ours to swallow.
        raise
    except BaseException:
        return False
    return True


class StatusStore:
    """Writes one scan report as a single transaction.

    Pass ``connection`` to reuse an open connection (or a fake, in tests);
    otherwise one is opened from ``options`` by :meth:`connect`.
    """

    def __init__(self, options: DbOptions, connection: Any = None) -> None:
        self.options = options
        self._connection = connection
        self._owns_connection = connection is None

    def connect(self) -> None:
        if self._connection is not None:
            return
        if not pymysql_available():
            raise DatabaseError(DRIVER_MISSING)
        import pymysql

        options = self.options
        try:
            self._connection = pymysql.connect(
                host=options.host,
                port=options.port,
                user=options.user,
                password=options.password,
                database=options.database,
                charset=options.charset,
                connect_timeout=options.connect_timeout,
                autocommit=False,
            )
        except Exception as exc:
            raise DatabaseError(f"cannot connect to {options.dsn}: {_short(exc)}") from exc

    def write_report(self, report: ScanReport) -> DbWriteSummary:
        if self._connection is None:
            raise DatabaseError("StatusStore.connect() must be called before write_report()")

        options = self.options
        summary = DbWriteSummary(enabled=True, dsn=options.dsn)
        connection = self._connection
        now = (report.finished_at or report.started_at).replace(tzinfo=None)
        try:
            with connection.cursor() as cursor:
                run_id = self._insert_run(cursor, report)
                summary.runs_written = 1
                for result in report.results:
                    status = result.status_check
                    if status is None:
                        # Still tracked: a URL we did not check is exactly what
                        # NOT_CHECKED is for, and losing it from the inventory
                        # would silently shrink the thing being watched.
                        change = self._upsert_state(cursor, result, now)
                        if change is not None:
                            summary.flag_changes.append(change)
                        continue
                    status_id = self._insert_status(cursor, run_id, result)
                    summary.checks_written += 1
                    summary.hops_written += self._insert_hops(cursor, status_id, status.chain)
                    change = self._upsert_state(cursor, result, now)
                    if change is not None:
                        summary.flag_changes.append(change)
            connection.commit()
        except DatabaseError:
            _rollback(connection)
            raise
        except Exception as exc:
            _rollback(connection)
            raise DatabaseError(f"database write failed: {_short(exc)}") from exc
        return summary

    def _insert_run(self, cursor: Any, report: ScanReport) -> int:
        table = self.options.table("scan_run")
        cursor.execute(
            f"INSERT INTO {table} "
            "(run_uuid, tool_version, model, started_at, finished_at, target_count) "
            "VALUES (%s, %s, %s, %s, %s, %s)",
            (
                _run_uuid(report),
                report.tool_version[:32],
                report.model[:128],
                report.started_at.replace(tzinfo=None),
                (report.finished_at or report.started_at).replace(tzinfo=None),
                len(report.results),
            ),
        )
        return int(cursor.lastrowid)

    def _insert_status(self, cursor: Any, run_id: int, result: Any) -> int:
        status = result.status_check
        table = self.options.table("url_status")
        url = status.url[:_URL_MAX]
        cursor.execute(
            f"INSERT INTO {table} "
            "(run_id, url, url_hash, hostname, state, is_ok, method, first_status, "
            " final_status, final_url, redirect_count, elapsed_ms, error, browser_status, "
            " max_severity, checked_at) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (
                run_id,
                url,
                hashlib.sha256(status.url.encode("utf-8")).hexdigest(),
                _hostname(status.url),
                status.state,
                1 if status.ok else 0,
                status.method[:8],
                status.first_status,
                status.final_status,
                status.final_url[:_URL_MAX] if status.final_url else None,
                status.redirect_count,
                int(status.elapsed_s * 1000),
                status.error[:_ERROR_MAX] if status.error else None,
                result.capture.status if result.capture else None,
                result.max_severity.value,
                status.checked_at.replace(tzinfo=None),
            ),
        )
        return int(cursor.lastrowid)

    def _insert_hops(self, cursor: Any, status_id: int, chain: Any) -> int:
        if not chain:
            return 0
        table = self.options.table("redirect_hop")
        rows = [
            (
                status_id,
                index,
                hop.url[:_URL_MAX],
                hop.status,
                hop.location[:_URL_MAX] if hop.location else None,
                int(hop.elapsed_s * 1000),
            )
            for index, hop in enumerate(chain)
        ]
        cursor.executemany(
            f"INSERT INTO {table} "
            "(status_id, hop_index, url, status_code, location, elapsed_ms) "
            "VALUES (%s, %s, %s, %s, %s, %s)",
            rows,
        )
        return len(rows)

    def set_flags(self, assignments: Sequence[tuple[str, str]]) -> list[FlagChange]:
        """Set each ``(url, flag)`` by hand, inserting the URL if it is unknown."""
        if self._connection is None:
            raise DatabaseError("StatusStore.connect() must be called before set_flags()")

        table = self.options.table("url_state")
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        changes: list[FlagChange] = []
        connection = self._connection
        try:
            with connection.cursor() as cursor:
                for url, raw_flag in assignments:
                    flag = parse_flag(raw_flag)
                    url_hash = hashlib.sha256(url.encode("utf-8")).hexdigest()
                    cursor.execute(
                        f"SELECT flag FROM {table} WHERE url_hash = %s", (url_hash,)
                    )
                    row = cursor.fetchone()
                    if row is None:
                        cursor.execute(
                            f"INSERT INTO {table} "
                            "(url, url_hash, hostname, flag, flag_set_at, flag_source, "
                            " first_seen_at, last_changed_at) "
                            "VALUES (%s, %s, %s, %s, %s, 'operator', %s, %s)",
                            (url[:_URL_MAX], url_hash, _hostname(url), flag, now, now, now),
                        )
                        changes.append(FlagChange(url, flag, None, "set by operator"))
                        continue
                    previous = _field(row, 0, "flag")
                    cursor.execute(
                        f"UPDATE {table} SET flag = %s, flag_set_at = %s, "
                        "flag_source = 'operator' WHERE url_hash = %s",
                        (flag, now, url_hash),
                    )
                    changes.append(FlagChange(url, flag, previous, "set by operator"))
            connection.commit()
        except DatabaseError:
            _rollback(connection)
            raise
        except ValueError:
            _rollback(connection)
            raise
        except Exception as exc:
            _rollback(connection)
            raise DatabaseError(f"could not set flags: {_short(exc)}") from exc
        return changes

    def _upsert_state(self, cursor: Any, result: Any, now: datetime) -> "FlagChange | None":
        """Carry one URL's flag, checksum and dates forward. Returns a transition, if any.

        The rules, in order:

        1. A URL we have never seen is inserted as ``NEW``, with ``first_seen_at``
           and ``last_changed_at`` set to now.
        2. A URL whose checksum differs from the stored one goes back to ``NEW``
           and its ``last_changed_at`` moves. This is the point of the checksum:
           an ``OK`` verdict describes the content that was reviewed, so it
           cannot survive that content changing.
        3. A URL we could not establish a verdict for drops to ``NOT_CHECKED`` —
           but only from ``OK``, and only if a scanner set that ``OK``. A
           ``NEW`` URL stays ``NEW``: it still needs review, and a run that
           could not reach it is no reason to drop it off the queue. An
           operator's flag is a human decision that one unreachable run does
           not overturn either.
        4. Otherwise the flag stands. Nothing here ever sets ``OK``: only an
           operator does, via ``--db-set-flag``.
        """
        status = result.status_check
        url = str(result.url)
        table = self.options.table("url_state")
        url_hash = hashlib.sha256(url.encode("utf-8")).hexdigest()

        cursor.execute(
            f"SELECT flag, flag_source, content_checksum, change_count, "
            f"flag_set_at, last_changed_at FROM {table} WHERE url_hash = %s",
            (url_hash,),
        )
        row = cursor.fetchone()

        checksum = status.content_checksum if status else None
        state = status.state if status else None
        final_status = status.final_status if status else None
        checked_at = status.checked_at.replace(tzinfo=None) if status else None

        if row is None:
            cursor.execute(
                f"INSERT INTO {table} "
                "(url, url_hash, hostname, flag, flag_set_at, flag_source, "
                " content_checksum, content_length, content_type, last_state, last_status, "
                " first_seen_at, last_changed_at, last_checked_at, change_count) "
                "VALUES (%s, %s, %s, %s, %s, 'scanner', %s, %s, %s, %s, %s, %s, %s, %s, 0)",
                (
                    url[:_URL_MAX],
                    url_hash,
                    _hostname(url),
                    FLAG_NEW,
                    now,
                    checksum,
                    status.content_length if status else None,
                    _content_type(status),
                    state,
                    final_status,
                    now,
                    now,
                    checked_at,
                ),
            )
            return FlagChange(url=url, flag=FLAG_NEW, previous=None, reason="first seen")

        previous_flag = _field(row, 0, "flag")
        flag_source = _field(row, 1, "flag_source")
        stored_checksum = _field(row, 2, "content_checksum")
        change_count = int(_field(row, 3, "change_count") or 0)
        flag_set_at = _field(row, 4, "flag_set_at")
        last_changed_at = _field(row, 5, "last_changed_at")

        content_changed = bool(checksum and stored_checksum and checksum != stored_checksum)
        if content_changed:
            flag, reason = FLAG_NEW, "content changed"
        elif (status is None or not status.ok) and previous_flag == FLAG_OK:
            # Only OK is worth retracting. NEW already means "needs review", and
            # an operator's OK is a human decision that one unreachable run does
            # not overturn — only a content change does.
            if flag_source == "operator":
                flag, reason = previous_flag, ""
            else:
                flag, reason = FLAG_NOT_CHECKED, "no verdict this run"
        else:
            flag, reason = previous_flag, ""

        flag_moved = flag != previous_flag
        cursor.execute(
            f"UPDATE {table} SET "
            " url = %s, hostname = %s, flag = %s, flag_set_at = %s, flag_source = %s,"
            # COALESCE keeps the last known content when this run produced no
            # checksum — an unreachable target must not erase what we knew.
            " content_checksum = COALESCE(%s, content_checksum),"
            " content_length = COALESCE(%s, content_length),"
            " content_type = COALESCE(%s, content_type),"
            " last_state = %s, last_status = %s,"
            " last_changed_at = %s, last_checked_at = %s, change_count = %s "
            "WHERE url_hash = %s",
            (
                url[:_URL_MAX],
                _hostname(url),
                flag,
                now if flag_moved else flag_set_at,
                "scanner" if flag_moved else flag_source,
                checksum,
                status.content_length if status else None,
                _content_type(status),
                state,
                final_status,
                now if content_changed else last_changed_at,
                checked_at,
                change_count + 1 if content_changed else change_count,
                url_hash,
            ),
        )
        if not flag_moved:
            # Content can change without the flag moving — a URL already sitting
            # at NEW that changed again. Still worth reporting.
            if content_changed:
                return FlagChange(
                    url=url, flag=flag, previous=previous_flag, reason="content changed"
                )
            return None
        return FlagChange(url=url, flag=flag, previous=previous_flag, reason=reason)

    def close(self) -> None:
        if self._owns_connection and self._connection is not None:
            try:
                self._connection.close()
            except Exception:  # pragma: no cover - teardown best effort
                pass
        self._connection = None


def set_flags(
    assignments: Sequence[tuple[str, str]],
    options: DbOptions,
    store: "StatusStore | None" = None,
) -> list[FlagChange]:
    """Set flags by hand: ``[("https://example.com/", "OK"), ...]``.

    This is the operator's half of the lifecycle. The scanner never writes
    ``OK`` — it can tell you a URL answers and that its content has not moved,
    but not that somebody looked at it and was happy. Flags set here are marked
    ``operator`` so a later run that cannot reach the URL does not quietly
    downgrade them to ``NOT_CHECKED``.

    Raises :class:`DatabaseError`; unlike :func:`store_report` this is a
    deliberate command, so a failure is worth surfacing.
    """
    owned = store is None
    store = store or StatusStore(options)
    try:
        store.connect()
        return store.set_flags(assignments)
    finally:
        if owned:
            store.close()


def store_report(
    report: ScanReport,
    options: DbOptions,
    store: StatusStore | None = None,
) -> DbWriteSummary:
    """Write the report's status checks. Never raises.

    A database problem is reported, not propagated: the scan already succeeded
    and its reports are already on disk.
    """
    if not options.enabled:
        return DbWriteSummary(enabled=False, dsn=options.dsn, skipped_reason="not enabled")

    owned = store is None
    store = store or StatusStore(options)
    try:
        store.connect()
        return store.write_report(report)
    except DatabaseError as exc:
        # A missing driver is a skip, not a failure: the user asked for an
        # optional extra they have not installed, which is not a broken scan.
        if str(exc) == DRIVER_MISSING:
            return DbWriteSummary(enabled=True, dsn=options.dsn, skipped_reason=DRIVER_MISSING)
        return DbWriteSummary(enabled=True, dsn=options.dsn, error=str(exc))
    except Exception as exc:  # pragma: no cover - defensive
        return DbWriteSummary(enabled=True, dsn=options.dsn, error=_short(exc))
    finally:
        if owned:
            store.close()


def write_db_report(summary: DbWriteSummary, stream: TextIO | None = None) -> None:
    """Print the database result in the same shape as the scan's console report."""
    out = stream or sys.stdout
    if not summary.enabled:
        return
    print("", file=out)
    if summary.skipped_reason:
        print(f"Database: skipped — {summary.skipped_reason}", file=out)
        return
    if summary.error:
        print(f"Database: write to {summary.dsn} failed — {summary.error}", file=out)
        return
    print(
        f"Database: {summary.dsn} — {summary.checks_written} status row(s), "
        f"{summary.hops_written} redirect hop(s)",
        file=out,
    )
    if not summary.flag_changes:
        return
    counts = ", ".join(
        f"{count} {flag}" for flag, count in summary.flag_counts().items() if count
    )
    print(f"  flags moved: {counts}", file=out)
    for change in summary.flag_changes:
        arrow = f"{change.previous} -> {change.flag}" if change.previous else change.flag
        print(f"    [{arrow}] {change.url}  ({change.reason})", file=out)


def write_flag_report(changes: Sequence[FlagChange], stream: TextIO | None = None) -> None:
    """Print the result of an explicit ``--db-set-flag`` run."""
    out = stream or sys.stdout
    print("", file=out)
    print("=" * 72, file=out)
    print(f"URL flags — {len(changes)} updated", file=out)
    print("=" * 72, file=out)
    for change in changes:
        arrow = f"{change.previous} -> {change.flag}" if change.previous else change.flag
        print(f"  [{arrow}] {change.url}", file=out)


def _run_uuid(report: ScanReport) -> str:
    """A stable id for one run, derived from its own contents.

    Deterministic on purpose: re-storing the same report is then a duplicate-key
    error rather than a silent second copy.
    """
    seed = f"{report.started_at.isoformat()}|{report.tool_version}|{len(report.results)}"
    digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()
    return f"{digest[:8]}-{digest[8:12]}-{digest[12:16]}-{digest[16:20]}-{digest[20:32]}"


def _hostname(url: str) -> str:
    return (urlsplit(url).hostname or "")[:255].lower()


def _content_type(status: Any) -> str | None:
    if status is None or not status.content_type:
        return None
    return status.content_type.split(";")[0].strip()[:128]


def _field(row: Any, index: int, name: str) -> Any:
    """Read a column from a tuple or a dict cursor row.

    PyMySQL's default cursor yields tuples, but a caller who configured
    ``DictCursor`` should not get a confusing IndexError.
    """
    if isinstance(row, dict):
        return row.get(name)
    return row[index]


def _rollback(connection: Any) -> None:
    try:
        connection.rollback()
    except Exception:  # pragma: no cover - best effort
        pass


def _short(exc: BaseException) -> str:
    message = str(exc).strip().splitlines()
    first = message[0] if message else ""
    return f"{type(exc).__name__}: {first}"[:300] if first else type(exc).__name__
