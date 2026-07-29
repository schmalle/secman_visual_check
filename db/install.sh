#!/usr/bin/env bash
#
# Create the MariaDB database, an application user and the schema used by
# secman-visual-check --db-store.
#
# The schema is applied as an administrative user; the application user gets
# DML rights only, so a scanner cannot alter or drop its own tables.
#
# Usage:
#   DB_PASSWORD=... db/install.sh
#   DB_ROOT_PASSWORD=... DB_HOST=db.internal DB_PASSWORD=... db/install.sh
#
# Environment:
#   DB_ROOT_USER      administrative user used to create things (default: root)
#   DB_ROOT_PASSWORD  its password (default: empty, e.g. socket auth)
#   DB_HOST           server host (default: 127.0.0.1)
#   DB_PORT           server port (default: 3306)
#   DB_NAME           database to create (default: secman_visual_check)
#   DB_USER           application user to create (default: secman_visual)
#   DB_PASSWORD       its password (required)
#   DB_USER_HOST      host the application user may connect from (default: %)
#   TABLE_PREFIX      table name prefix (default: svc_)

set -euo pipefail

DB_ROOT_USER="${DB_ROOT_USER:-root}"
DB_ROOT_PASSWORD="${DB_ROOT_PASSWORD:-}"
DB_HOST="${DB_HOST:-127.0.0.1}"
DB_PORT="${DB_PORT:-3306}"
DB_NAME="${DB_NAME:-secman_visual_check}"
DB_USER="${DB_USER:-secman_visual}"
DB_PASSWORD="${DB_PASSWORD:-}"
DB_USER_HOST="${DB_USER_HOST:-%}"
TABLE_PREFIX="${TABLE_PREFIX:-svc_}"

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
schema_file="$script_dir/schema.sql"

if [[ -z "$DB_PASSWORD" ]]; then
  echo "error: DB_PASSWORD is required (the password for the application user)" >&2
  exit 1
fi
if [[ ! "$DB_NAME" =~ ^[A-Za-z0-9_]+$ ]]; then
  echo "error: DB_NAME must be letters, digits and underscores only" >&2
  exit 1
fi
if [[ ! "$DB_USER" =~ ^[A-Za-z0-9_]+$ ]]; then
  echo "error: DB_USER must be letters, digits and underscores only" >&2
  exit 1
fi
if [[ ! "$TABLE_PREFIX" =~ ^[A-Za-z0-9_]{0,16}$ ]]; then
  echo "error: TABLE_PREFIX must be letters, digits and underscores only, max 16" >&2
  exit 1
fi
if [[ ! -f "$schema_file" ]]; then
  echo "error: cannot find $schema_file" >&2
  exit 1
fi

mysql_args=(--host="$DB_HOST" --port="$DB_PORT" --user="$DB_ROOT_USER" --protocol=TCP)
if [[ -n "$DB_ROOT_PASSWORD" ]]; then
  # Passed via the environment so it never appears in the process list.
  export MYSQL_PWD="$DB_ROOT_PASSWORD"
fi

echo "==> creating database $DB_NAME on $DB_HOST:$DB_PORT"
mysql "${mysql_args[@]}" <<SQL
CREATE DATABASE IF NOT EXISTS \`$DB_NAME\`
  CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
SQL

echo "==> creating application user $DB_USER@$DB_USER_HOST (DML only, no DDL)"
mysql "${mysql_args[@]}" <<SQL
CREATE USER IF NOT EXISTS '$DB_USER'@'$DB_USER_HOST'
  IDENTIFIED BY '$(printf '%s' "$DB_PASSWORD" | sed "s/'/''/g")';
GRANT SELECT, INSERT, UPDATE, DELETE ON \`$DB_NAME\`.* TO '$DB_USER'@'$DB_USER_HOST';
FLUSH PRIVILEGES;
SQL

echo "==> applying schema (table prefix: $TABLE_PREFIX)"
if [[ "$TABLE_PREFIX" == "svc_" ]]; then
  mysql "${mysql_args[@]}" --database="$DB_NAME" < "$schema_file"
else
  sed "s/\bsvc_/${TABLE_PREFIX}/g" "$schema_file" \
    | mysql "${mysql_args[@]}" --database="$DB_NAME"
fi

cat <<EOF

Done. Point the scanner at it with:

  export SECMAN_DB_URL='mysql://$DB_USER:<password>@$DB_HOST:$DB_PORT/$DB_NAME'
  pip install 'secman-visual-check[db]'
  secman-visual-check --db-store https://example.com

or with the individual flags:

  secman-visual-check --db-store \\
    --db-host $DB_HOST --db-port $DB_PORT \\
    --db-user $DB_USER --db-password '<password>' \\
    --db-name $DB_NAME --db-table-prefix $TABLE_PREFIX \\
    https://example.com
EOF
