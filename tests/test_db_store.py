"""The optional MariaDB mirror: what it writes, and how it degrades."""

import builtins
import io
import re
from datetime import datetime, timezone

import pytest

from secman_visual_check import db as db_module
from secman_visual_check.db import (
    DatabaseError,
    DbOptions,
    DbWriteSummary,
    StatusStore,
    store_report,
    write_db_report,
)
from secman_visual_check.models import (
    PageCapture,
    RedirectHop,
    ScanReport,
    ScanResult,
    UrlStatus,
)


class FakeCursor:
    """Records every statement and hands out increasing lastrowid values.

    SELECTs against the url_state table are answered from ``recorder.state``,
    a ``{url_hash: row}`` map standing in for what an earlier run left behind.
    """

    def __init__(self, recorder, fail_on=None):
        self.recorder = recorder
        self.fail_on = fail_on
        self.lastrowid = 0
        self._result = None

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False

    def execute(self, sql, params=None):
        if self.fail_on and self.fail_on in sql:
            raise RuntimeError("server has gone away")
        self.recorder.statements.append((sql, params))
        if sql.lstrip().upper().startswith("SELECT"):
            self._result = self.recorder.state.get(params[0])
            return
        self._result = None
        self.recorder.next_id += 1
        self.lastrowid = self.recorder.next_id

    def fetchone(self):
        return self._result

    def executemany(self, sql, rows):
        if self.fail_on and self.fail_on in sql:
            raise RuntimeError("server has gone away")
        self.recorder.statements.append((sql, list(rows)))


class FakeConnection:
    def __init__(self, fail_on=None, state=None):
        self.statements = []
        self.state = dict(state or {})
        self.next_id = 0
        self.commits = 0
        self.rollbacks = 0
        self.closed = False
        self._fail_on = fail_on

    def cursor(self):
        return FakeCursor(self, self._fail_on)

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1

    def close(self):
        self.closed = True


def make_status(url, state="ok", chain=None, **overrides):
    status = UrlStatus(
        url=url,
        state=state,
        method="HEAD",
        first_status=200,
        final_status=200,
        final_url=url,
        chain=chain if chain is not None else [RedirectHop(url=url, status=200)],
        checked_at=datetime(2026, 7, 29, 9, 14, 2, tzinfo=timezone.utc),
    )
    for key, value in overrides.items():
        setattr(status, key, value)
    return status


def make_report():
    redirect = make_status(
        "http://old.example.com/",
        state="redirect",
        first_status=301,
        chain=[
            RedirectHop(
                url="http://old.example.com/",
                status=301,
                location="https://old.example.com/",
            ),
            RedirectHop(url="https://old.example.com/", status=200),
        ],
    )
    return ScanReport(
        results=[
            ScanResult(
                url="https://example.com/",
                status_check=make_status("https://example.com/"),
                capture=PageCapture(url="https://example.com/", status=200),
            ),
            ScanResult(url="http://old.example.com/", status_check=redirect),
            # No status check at all: nothing to store for this one.
            ScanResult(url="https://skipped.example/", skipped_reason="robots.txt"),
        ],
        tool_version="0.2.0",
        model="mock/vision",
    )


_WRITE_RE = re.compile(r"(?:INSERT INTO|UPDATE)\s+(\w+)", re.IGNORECASE)


def written_tables(connection):
    """Tables touched by a write, in order. SELECTs are ignored."""
    tables = []
    for sql, _ in connection.statements:
        match = _WRITE_RE.search(sql)
        if match:
            tables.append(match.group(1))
    return tables


def options(**overrides):
    base = {"enabled": True, "user": "scanner", "database": "svc_test"}
    base.update(overrides)
    return DbOptions(**base)


def test_write_report_inserts_one_run_one_status_per_check_and_every_hop():
    connection = FakeConnection()
    store = StatusStore(options(), connection=connection)

    summary = store.write_report(make_report())

    assert summary.runs_written == 1
    assert summary.checks_written == 2  # the skipped target has no status check
    assert summary.hops_written == 3  # 1 + 2
    assert connection.commits == 1
    assert connection.rollbacks == 0

    assert written_tables(connection) == [
        "svc_scan_run",
        "svc_url_status",
        "svc_redirect_hop",
        "svc_url_state",
        "svc_url_status",
        "svc_redirect_hop",
        "svc_url_state",
        # The robots-skipped target has no status row, but is still inventoried.
        "svc_url_state",
    ]


def test_status_rows_carry_the_browser_status_for_comparison():
    connection = FakeConnection()
    StatusStore(options(), connection=connection).write_report(make_report())

    status_rows = [params for sql, params in connection.statements if "url_status" in sql]
    # The first target was captured by the browser, the second was not.
    assert status_rows[0][13] == 200
    assert status_rows[1][13] is None


def test_hops_are_linked_to_the_status_row_that_owns_them():
    connection = FakeConnection()
    StatusStore(options(), connection=connection).write_report(make_report())

    hop_batches = [params for sql, params in connection.statements if "redirect_hop" in sql]
    # (status_id, hop_index, url, status_code, location, elapsed_ms)
    first_ids = {row[0] for row in hop_batches[0]}
    second_ids = {row[0] for row in hop_batches[1]}

    assert len(first_ids) == 1 and len(second_ids) == 1
    assert first_ids != second_ids
    assert [row[1] for row in hop_batches[1]] == [0, 1]
    assert hop_batches[1][0][4] == "https://old.example.com/"


def test_a_failing_statement_rolls_back_and_raises():
    connection = FakeConnection(fail_on="url_status")
    store = StatusStore(options(), connection=connection)

    with pytest.raises(DatabaseError):
        store.write_report(make_report())

    assert connection.rollbacks == 1
    assert connection.commits == 0


def test_store_report_folds_the_error_into_the_summary_instead_of_raising():
    connection = FakeConnection(fail_on="scan_run")

    summary = store_report(make_report(), options(), StatusStore(options(), connection))

    assert summary.enabled is True
    assert summary.error is not None
    assert summary.runs_written == 0


def test_store_report_is_a_no_op_when_disabled():
    summary = store_report(make_report(), options(enabled=False))

    assert summary.enabled is False
    assert summary.skipped_reason == "not enabled"


def test_missing_driver_is_a_skip_not_a_failure(monkeypatch):
    monkeypatch.setattr(db_module, "pymysql_available", lambda: False)

    summary = store_report(make_report(), options())

    assert summary.error is None
    assert summary.skipped_reason == db_module.DRIVER_MISSING
    assert "secman-visual-check[db]" in summary.skipped_reason


def test_a_driver_whose_own_dependencies_are_broken_counts_as_missing(monkeypatch):
    """PyMySQL pulls in cryptography, which can fail with a non-Exception."""

    class Panic(BaseException):
        pass

    real_import = builtins.__import__

    def exploding_import(name, *args, **kwargs):
        if name == "pymysql":
            raise Panic("Python API call failed")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", exploding_import)

    assert db_module.pymysql_available() is False


def test_an_interrupt_during_the_driver_import_is_not_swallowed(monkeypatch):
    real_import = builtins.__import__

    def interrupting_import(name, *args, **kwargs):
        if name == "pymysql":
            raise KeyboardInterrupt
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", interrupting_import)

    with pytest.raises(KeyboardInterrupt):
        db_module.pymysql_available()


def test_table_prefix_reaches_every_statement():
    connection = FakeConnection()
    StatusStore(options(table_prefix="scan_"), connection=connection).write_report(
        make_report()
    )

    assert all("scan_" in sql for sql, _ in connection.statements)
    assert not any("svc_" in sql for sql, _ in connection.statements)


def test_a_prefix_that_could_carry_sql_is_rejected_before_it_reaches_sql():
    with pytest.raises(ValueError, match="table-prefix"):
        options(table_prefix="a; DROP TABLE x; --").validate()

    with pytest.raises(ValueError, match="table-prefix"):
        options(table_prefix="way_too_long_a_prefix_here").validate()


def test_validate_requires_credentials_only_when_enabled():
    DbOptions(enabled=False).validate()  # nothing to check

    with pytest.raises(ValueError, match="--db-user"):
        DbOptions(enabled=True).validate()


def test_from_url_parses_a_mysql_dsn():
    parsed = DbOptions.from_url("mysql://scanner:s3cret@db.internal:3307/results")

    assert (parsed.host, parsed.port) == ("db.internal", 3307)
    assert (parsed.user, parsed.password) == ("scanner", "s3cret")
    assert parsed.database == "results"


def test_from_url_rejects_a_foreign_scheme():
    with pytest.raises(ValueError, match="mysql://"):
        DbOptions.from_url("postgres://user@host/db")


def test_from_url_error_never_echoes_the_credentials_in_a_malformed_dsn():
    """``url`` is frequently a secret just resolved from a ``pass://``
    reference (see ``--db-url``): the whole DSN, credentials included, is
    exactly what an operator puts behind a reference to keep it off argv and
    logs. A missing-scheme paste mistake (e.g. the leading ``mysql://`` was
    dropped) must not turn right around and print those credentials in the
    exception raised for it — that exception is printed unredacted by the
    CLI's early option-validation error handler."""
    malformed = "//scanner:s3cret@db.internal:3306/results"

    with pytest.raises(ValueError) as excinfo:
        DbOptions.from_url(malformed)

    message = str(excinfo.value)
    assert "s3cret" not in message
    assert malformed not in message


def test_the_password_appears_neither_in_the_dsn_nor_in_the_printed_report():
    parsed = DbOptions.from_url(
        "mysql://scanner:s3cret@db.internal:3306/results", enabled=True
    )
    stream = io.StringIO()

    write_db_report(DbWriteSummary(enabled=True, dsn=parsed.dsn, checks_written=2), stream)

    assert "s3cret" not in parsed.dsn
    assert "s3cret" not in stream.getvalue()
    assert "scanner@db.internal:3306/results" in stream.getvalue()


def test_write_db_report_says_nothing_when_the_database_is_off():
    stream = io.StringIO()

    write_db_report(DbWriteSummary(enabled=False, dsn="unused"), stream)

    assert stream.getvalue() == ""


def test_write_db_report_reports_a_failure():
    stream = io.StringIO()

    write_db_report(DbWriteSummary(enabled=True, dsn="h:3306/d", error="boom"), stream)

    assert "failed" in stream.getvalue()
    assert "boom" in stream.getvalue()


def test_write_report_before_connect_is_a_programming_error():
    with pytest.raises(DatabaseError, match="connect"):
        StatusStore(options()).write_report(make_report())


def test_the_run_uuid_is_derived_from_the_report_so_a_re_store_collides():
    report = make_report()

    first = db_module._run_uuid(report)
    second = db_module._run_uuid(report)

    assert first == second
    assert len(first) == 36


# --------------------------------------------------------------------------- #
# URL lifecycle flags and change tracking
# --------------------------------------------------------------------------- #


def state_row(flag="OK", source="scanner", checksum="aaa", changes=0):
    """A row as the SELECT in _upsert_state returns it."""
    return (flag, source, checksum, changes, PAST, PAST)


PAST = datetime(2026, 1, 1, 0, 0, 0)


def url_hash(url):
    import hashlib

    return hashlib.sha256(url.encode("utf-8")).hexdigest()


def one_url_report(url="https://example.com/", **status_kwargs):
    status = make_status(url, **status_kwargs) if status_kwargs is not None else None
    return ScanReport(results=[ScanResult(url=url, status_check=status)], tool_version="0.2.0")


def state_writes(connection):
    return [
        (sql, params)
        for sql, params in connection.statements
        if "url_state" in sql and not sql.lstrip().upper().startswith("SELECT")
    ]


def test_an_unknown_url_is_inserted_as_new():
    connection = FakeConnection()

    summary = StatusStore(options(), connection=connection).write_report(
        one_url_report(content_checksum="abc123")
    )

    assert [c.flag for c in summary.flag_changes] == ["NEW"]
    assert summary.flag_changes[0].reason == "first seen"
    assert summary.flag_changes[0].is_new_url is True
    assert summary.new_urls == summary.flag_changes

    sql, params = state_writes(connection)[0]
    assert "INSERT INTO" in sql
    assert params[3] == "NEW"
    assert params[5] == "abc123"


def test_a_changed_checksum_sends_an_ok_url_back_to_new():
    url = "https://example.com/"
    connection = FakeConnection(
        state={url_hash(url): state_row(flag="OK", source="operator", checksum="old")}
    )

    summary = StatusStore(options(), connection=connection).write_report(
        one_url_report(url, content_checksum="new")
    )

    assert [(c.previous, c.flag, c.reason) for c in summary.flag_changes] == [
        ("OK", "NEW", "content changed")
    ]
    assert summary.changed_content == summary.flag_changes


def test_an_unchanged_checksum_leaves_the_flag_alone():
    url = "https://example.com/"
    connection = FakeConnection(
        state={url_hash(url): state_row(flag="OK", source="operator", checksum="same")}
    )

    summary = StatusStore(options(), connection=connection).write_report(
        one_url_report(url, content_checksum="same")
    )

    assert summary.flag_changes == []
    _, params = state_writes(connection)[0]
    assert params[2] == "OK"


def test_content_changing_twice_still_reports_even_though_the_flag_stays_new():
    url = "https://example.com/"
    connection = FakeConnection(
        state={url_hash(url): state_row(flag="NEW", checksum="first")}
    )

    summary = StatusStore(options(), connection=connection).write_report(
        one_url_report(url, content_checksum="second")
    )

    assert [(c.flag, c.reason) for c in summary.flag_changes] == [("NEW", "content changed")]


def test_a_target_with_no_verdict_drops_from_ok_to_not_checked():
    url = "https://example.com/"
    connection = FakeConnection(state={url_hash(url): state_row(flag="OK")})
    report = ScanReport(
        results=[ScanResult(url=url, skipped_reason="robots.txt")], tool_version="0.2.0"
    )

    summary = StatusStore(options(), connection=connection).write_report(report)

    assert [(c.previous, c.flag) for c in summary.flag_changes] == [("OK", "NOT_CHECKED")]


def test_a_new_url_stays_new_when_a_run_reaches_no_verdict():
    """NEW already means "needs review"; an unreachable run must not clear that."""
    url = "https://example.com/"
    connection = FakeConnection(state={url_hash(url): state_row(flag="NEW")})
    report = ScanReport(
        results=[ScanResult(url=url, skipped_reason="robots.txt")], tool_version="0.2.0"
    )

    summary = StatusStore(options(), connection=connection).write_report(report)

    assert summary.flag_changes == []
    _, params = state_writes(connection)[0]
    assert params[2] == "NEW"


def test_an_operator_flag_survives_a_run_that_reached_no_verdict():
    url = "https://example.com/"
    connection = FakeConnection(
        state={url_hash(url): state_row(flag="OK", source="operator")}
    )
    report = ScanReport(
        results=[ScanResult(url=url, skipped_reason="robots.txt")], tool_version="0.2.0"
    )

    summary = StatusStore(options(), connection=connection).write_report(report)

    assert summary.flag_changes == []
    _, params = state_writes(connection)[0]
    assert params[2] == "OK"
    assert params[4] == "operator"  # source is not rewritten to 'scanner'


def test_a_scanner_flag_is_downgraded_by_a_run_that_reached_no_verdict():
    url = "https://example.com/"
    connection = FakeConnection(
        state={url_hash(url): state_row(flag="OK", source="scanner")}
    )

    summary = StatusStore(options(), connection=connection).write_report(
        one_url_report(url, state="unreachable", final_status=None)
    )

    assert [(c.previous, c.flag) for c in summary.flag_changes] == [("OK", "NOT_CHECKED")]


def test_an_unreachable_run_does_not_erase_the_last_known_checksum():
    url = "https://example.com/"
    connection = FakeConnection(state={url_hash(url): state_row(checksum="kept")})

    StatusStore(options(), connection=connection).write_report(
        one_url_report(url, state="unreachable", final_status=None)
    )

    sql, params = state_writes(connection)[0]
    assert "COALESCE(%s, content_checksum)" in sql
    assert params[5] is None  # nothing to write, so COALESCE keeps the stored value


def test_set_flags_inserts_an_unknown_url_as_an_operator_decision():
    connection = FakeConnection()

    changes = StatusStore(options(), connection=connection).set_flags(
        [("https://example.com/", "ok")]
    )

    assert [(c.previous, c.flag) for c in changes] == [(None, "OK")]
    sql, params = state_writes(connection)[0]
    assert "INSERT INTO" in sql
    assert params[3] == "OK"
    assert connection.commits == 1


def test_set_flags_updates_a_known_url_and_marks_it_operator_set():
    url = "https://example.com/"
    connection = FakeConnection(state={url_hash(url): ("NEW",)})

    changes = StatusStore(options(), connection=connection).set_flags([(url, "OK")])

    assert [(c.previous, c.flag) for c in changes] == [("NEW", "OK")]
    sql, _ = state_writes(connection)[0]
    assert "flag_source = 'operator'" in sql


def test_set_flags_rejects_an_unknown_flag():
    connection = FakeConnection()

    with pytest.raises(ValueError, match="unknown flag"):
        StatusStore(options(), connection=connection).set_flags(
            [("https://example.com/", "MAYBE")]
        )

    assert connection.rollbacks == 1
    assert connection.commits == 0


def test_parse_flag_normalises_spelling():
    assert db_module.parse_flag("ok") == "OK"
    assert db_module.parse_flag("NOT CHECKED") == "NOT_CHECKED"
    assert db_module.parse_flag("not-checked") == "NOT_CHECKED"
    assert db_module.parse_flag(" new ") == "NEW"


def test_flag_changes_appear_in_the_printed_database_report():
    stream = io.StringIO()
    summary = DbWriteSummary(enabled=True, dsn="h:3306/d", checks_written=1)
    summary.flag_changes = [
        db_module.FlagChange("https://example.com/", "NEW", "OK", "content changed")
    ]

    write_db_report(summary, stream)
    out = stream.getvalue()

    assert "flags moved: 1 NEW" in out
    assert "[OK -> NEW] https://example.com/  (content changed)" in out


def test_write_flag_report_lists_every_assignment():
    stream = io.StringIO()

    db_module.write_flag_report(
        [
            db_module.FlagChange("https://a.example/", "OK", "NEW", "set by operator"),
            db_module.FlagChange("https://b.example/", "OK", None, "set by operator"),
        ],
        stream,
    )
    out = stream.getvalue()

    assert "URL flags — 2 updated" in out
    assert "[NEW -> OK] https://a.example/" in out
    assert "[OK] https://b.example/" in out
