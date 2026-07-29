"""The URL lifecycle driven through a real SQL engine.

The other database tests assert on the statements ``StatusStore`` emits. These
run those same statements against SQLite, so the *behaviour* is checked rather
than the wording: does an OK flag survive a second run, does a changed checksum
clear it, do the dates move when they should.

SQLite is a stand-in, not the target — MariaDB is what ships. A thin shim
translates ``%s`` placeholders and the schema mirrors ``db/schema.sql`` with the
types SQLite understands. What that leaves untested is the DDL itself; what it
covers is every branch of the flag logic, against an engine that really does
enforce uniqueness, defaults and NULL handling.
"""

import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from secman_visual_check.db import DbOptions, StatusStore
from secman_visual_check.models import ScanReport, ScanResult, UrlStatus

SCHEMA = """
CREATE TABLE svc_scan_run (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_uuid TEXT NOT NULL UNIQUE,
  tool_version TEXT NOT NULL DEFAULT '',
  model TEXT NOT NULL DEFAULT '',
  started_at TEXT NOT NULL,
  finished_at TEXT,
  target_count INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE svc_url_status (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id INTEGER NOT NULL,
  url TEXT NOT NULL, url_hash TEXT NOT NULL, hostname TEXT NOT NULL DEFAULT '',
  state TEXT NOT NULL, is_ok INTEGER NOT NULL DEFAULT 0, method TEXT NOT NULL DEFAULT '',
  first_status INTEGER, final_status INTEGER, final_url TEXT,
  redirect_count INTEGER NOT NULL DEFAULT 0, elapsed_ms INTEGER NOT NULL DEFAULT 0,
  error TEXT, browser_status INTEGER, max_severity TEXT NOT NULL DEFAULT 'info',
  checked_at TEXT NOT NULL
);
CREATE TABLE svc_redirect_hop (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  status_id INTEGER NOT NULL, hop_index INTEGER NOT NULL,
  url TEXT NOT NULL, status_code INTEGER, location TEXT,
  elapsed_ms INTEGER NOT NULL DEFAULT 0,
  UNIQUE (status_id, hop_index)
);
CREATE TABLE svc_url_state (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  url TEXT NOT NULL, url_hash TEXT NOT NULL UNIQUE, hostname TEXT NOT NULL DEFAULT '',
  flag TEXT NOT NULL DEFAULT 'NEW', flag_set_at TEXT NOT NULL,
  flag_source TEXT NOT NULL DEFAULT 'scanner',
  content_checksum TEXT, content_length INTEGER, content_type TEXT,
  last_state TEXT, last_status INTEGER,
  first_seen_at TEXT NOT NULL, last_changed_at TEXT, last_checked_at TEXT,
  change_count INTEGER NOT NULL DEFAULT 0
);
"""


class ShimCursor:
    """A SQLite cursor that accepts MySQL's ``%s`` placeholders."""

    def __init__(self, cursor):
        self._cursor = cursor

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False

    def execute(self, sql, params=None):
        self._cursor.execute(sql.replace("%s", "?"), params or ())

    def executemany(self, sql, rows):
        self._cursor.executemany(sql.replace("%s", "?"), rows)

    def fetchone(self):
        return self._cursor.fetchone()

    @property
    def lastrowid(self):
        return self._cursor.lastrowid


class ShimConnection:
    def __init__(self, connection):
        self._connection = connection

    def cursor(self):
        return ShimCursor(self._connection.cursor())

    def commit(self):
        self._connection.commit()

    def rollback(self):
        self._connection.rollback()

    def close(self):
        self._connection.close()


@pytest.fixture
def store():
    raw = sqlite3.connect(":memory:")
    raw.executescript(SCHEMA)
    yield StatusStore(
        DbOptions(enabled=True, user="u", database="d"), connection=ShimConnection(raw)
    )
    raw.close()


URL = "https://example.com/page"
START = datetime(2026, 7, 1, tzinfo=timezone.utc)


def report(checksum=None, state="ok", run=0, checked=True):
    status = None
    if checked:
        status = UrlStatus(
            url=URL,
            state=state,
            first_status=200,
            final_status=200 if state == "ok" else None,
            final_url=URL,
            content_checksum=checksum,
            content_length=len(checksum or "") or None,
            checked_at=START + timedelta(days=run),
        )
    started = START + timedelta(days=run)
    return ScanReport(
        results=[ScanResult(url=URL, status_check=status)],
        started_at=started,
        finished_at=started,
        tool_version="0.3.0",
    )


def row(store):
    cursor = store._connection.cursor()
    cursor.execute(
        "SELECT flag, flag_source, content_checksum, first_seen_at, last_changed_at, "
        "last_checked_at, change_count FROM svc_url_state WHERE url = %s",
        (URL,),
    )
    keys = (
        "flag",
        "source",
        "checksum",
        "first_seen",
        "last_changed",
        "last_checked",
        "changes",
    )
    return dict(zip(keys, cursor.fetchone()))


def test_a_first_sighting_is_new_and_stamps_both_dates(store):
    changes = store.write_report(report(checksum="aaa")).flag_changes

    assert [(c.previous, c.flag, c.reason) for c in changes] == [(None, "NEW", "first seen")]
    state = row(store)
    assert state["flag"] == "NEW"
    assert state["checksum"] == "aaa"
    assert state["first_seen"] == state["last_changed"] == "2026-07-01 00:00:00"
    assert state["changes"] == 0


def test_an_operator_ok_survives_later_runs_that_find_no_change(store):
    store.write_report(report(checksum="aaa"))
    store.set_flags([(URL, "OK")])

    changes = store.write_report(report(checksum="aaa", run=1)).flag_changes

    assert changes == []
    state = row(store)
    assert state["flag"] == "OK"
    assert state["source"] == "operator"
    # Looked at again, but nothing about it changed.
    assert state["last_checked"] == "2026-07-01 00:00:00"[:10].replace("01", "02") + " 00:00:00"
    assert state["last_changed"] == "2026-07-01 00:00:00"
    assert state["changes"] == 0


def test_a_changed_checksum_clears_the_ok_flag_and_moves_the_change_date(store):
    store.write_report(report(checksum="aaa"))
    store.set_flags([(URL, "OK")])

    changes = store.write_report(report(checksum="bbb", run=5)).flag_changes

    assert [(c.previous, c.flag, c.reason) for c in changes] == [
        ("OK", "NEW", "content changed")
    ]
    state = row(store)
    assert state["flag"] == "NEW"
    assert state["source"] == "scanner"  # the scanner overrode the operator
    assert state["checksum"] == "bbb"
    assert state["first_seen"] == "2026-07-01 00:00:00"  # initial addition never moves
    assert state["last_changed"] == "2026-07-06 00:00:00"
    assert state["changes"] == 1


def test_repeated_changes_accumulate(store):
    store.write_report(report(checksum="a"))
    store.write_report(report(checksum="b", run=1))
    store.write_report(report(checksum="c", run=2))

    assert row(store)["changes"] == 2


def test_an_unreachable_run_keeps_the_last_known_checksum(store):
    store.write_report(report(checksum="aaa"))

    store.write_report(report(state="unreachable", run=1))

    state = row(store)
    assert state["checksum"] == "aaa"
    assert state["flag"] == "NEW"  # already NEW; nothing to downgrade
    assert state["changes"] == 0


def test_a_run_with_no_verdict_downgrades_a_scanner_flag_only(store):
    store.write_report(report(checksum="aaa"))
    store.set_flags([(URL, "NOT_CHECKED")])  # operator-set, so protected
    store.write_report(report(state="unreachable", run=1))
    assert row(store)["flag"] == "NOT_CHECKED"

    # A scanner-set flag has no such protection.
    store._connection.cursor().execute(
        "UPDATE svc_url_state SET flag = 'OK', flag_source = 'scanner' WHERE url = %s",
        (URL,),
    )
    store.write_report(report(state="unreachable", run=2))

    assert row(store)["flag"] == "NOT_CHECKED"


def test_an_unchecked_target_is_still_inventoried(store):
    changes = store.write_report(report(checked=False)).flag_changes

    assert [(c.previous, c.flag) for c in changes] == [(None, "NEW")]
    assert row(store)["flag"] == "NEW"


def test_set_flags_on_an_unknown_url_inserts_it(store):
    store.set_flags([(URL, "OK")])

    state = row(store)
    assert (state["flag"], state["source"]) == ("OK", "operator")
    assert state["first_seen"] is not None


def test_two_runs_write_two_status_rows_but_one_state_row(store):
    store.write_report(report(checksum="aaa"))
    store.write_report(report(checksum="aaa", run=1))

    cursor = store._connection.cursor()
    cursor.execute("SELECT COUNT(*) FROM svc_url_status", ())
    assert cursor.fetchone()[0] == 2
    cursor.execute("SELECT COUNT(*) FROM svc_url_state", ())
    assert cursor.fetchone()[0] == 1


def test_storing_the_same_report_twice_is_rejected_by_the_run_uuid(store):
    same = report(checksum="aaa")
    store.write_report(same)

    from secman_visual_check.db import DatabaseError

    with pytest.raises(DatabaseError):
        store.write_report(same)
