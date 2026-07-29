-- Schema for the optional MariaDB mirror of secman-visual-check status results.
--
-- Apply with db/install.sh, or by hand:
--   mysql -u root -p secman_visual_check < db/schema.sql
--
-- Table names carry the svc_ prefix that matches --db-table-prefix's default.
-- If you change the prefix, run the file through install.sh (which substitutes
-- it) rather than editing it here.

CREATE TABLE IF NOT EXISTS svc_scan_run (
  id           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  run_uuid     CHAR(36)        NOT NULL,
  tool_version VARCHAR(32)     NOT NULL DEFAULT '',
  model        VARCHAR(128)    NOT NULL DEFAULT '',
  started_at   DATETIME(3)     NOT NULL,
  finished_at  DATETIME(3)     NULL,
  target_count INT UNSIGNED    NOT NULL DEFAULT 0,
  PRIMARY KEY (id),
  -- Derived from the run's own contents, so storing one report twice is a
  -- duplicate-key error rather than a silent second copy.
  UNIQUE KEY uq_scan_run_uuid (run_uuid),
  KEY ix_scan_run_started (started_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS svc_url_status (
  id             BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  run_id         BIGINT UNSIGNED NOT NULL,
  url            VARCHAR(2048)   NOT NULL,
  -- sha256(url): the URL itself is far too long for an index.
  url_hash       CHAR(64)        NOT NULL,
  hostname       VARCHAR(255)    NOT NULL DEFAULT '',
  state          VARCHAR(24)     NOT NULL,
  -- Redundant with `state` on purpose: "everything currently not OK" then hits
  -- an index instead of an IN (...) list.
  is_ok          TINYINT(1)      NOT NULL DEFAULT 0,
  method         VARCHAR(8)      NOT NULL DEFAULT '',
  first_status   SMALLINT        NULL,
  final_status   SMALLINT        NULL,
  final_url      VARCHAR(2048)   NULL,
  redirect_count SMALLINT        NOT NULL DEFAULT 0,
  elapsed_ms     INT UNSIGNED    NOT NULL DEFAULT 0,
  error          VARCHAR(512)    NULL,
  -- What Chromium saw, for comparison: a divergence is itself a signal.
  browser_status SMALLINT        NULL,
  max_severity   VARCHAR(16)     NOT NULL DEFAULT 'info',
  checked_at     DATETIME(3)     NOT NULL,
  PRIMARY KEY (id),
  KEY ix_url_status_run (run_id),
  KEY ix_url_status_url (url_hash, checked_at),
  KEY ix_url_status_host (hostname, checked_at),
  KEY ix_url_status_state (state, checked_at),
  CONSTRAINT fk_url_status_run FOREIGN KEY (run_id)
    REFERENCES svc_scan_run (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS svc_redirect_hop (
  id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  status_id   BIGINT UNSIGNED NOT NULL,
  hop_index   SMALLINT        NOT NULL,
  url         VARCHAR(2048)   NOT NULL,
  status_code SMALLINT        NULL,
  -- The raw Location header, exactly as sent: it may be relative.
  location    VARCHAR(2048)   NULL,
  elapsed_ms  INT UNSIGNED    NOT NULL DEFAULT 0,
  PRIMARY KEY (id),
  UNIQUE KEY uq_hop (status_id, hop_index),
  CONSTRAINT fk_hop_status FOREIGN KEY (status_id)
    REFERENCES svc_url_status (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
