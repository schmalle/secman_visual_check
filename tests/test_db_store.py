"""The optional MariaDB mirror: what it writes, and how it degrades."""

import builtins
import io
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
    """Records every statement and hands out increasing lastrowid values."""

    def __init__(self, recorder, fail_on=None):
        self.recorder = recorder
        self.fail_on = fail_on
        self.lastrowid = 0

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False

    def execute(self, sql, params=None):
        if self.fail_on and self.fail_on in sql:
            raise RuntimeError("server has gone away")
        self.recorder.statements.append((sql, params))
        self.recorder.next_id += 1
        self.lastrowid = self.recorder.next_id

    def executemany(self, sql, rows):
        if self.fail_on and self.fail_on in sql:
            raise RuntimeError("server has gone away")
        self.recorder.statements.append((sql, list(rows)))


class FakeConnection:
    def __init__(self, fail_on=None):
        self.statements = []
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

    tables = [sql.split()[2] for sql, _ in connection.statements]
    assert tables == [
        "svc_scan_run",
        "svc_url_status",
        "svc_redirect_hop",
        "svc_url_status",
        "svc_redirect_hop",
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
