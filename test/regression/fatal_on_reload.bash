#!/usr/bin/env bash

set -euf -o pipefail

# pgbouncer-config <tmpdir> <second-database>
function pgbouncer-config() {
  cat <<EOF
[databases]
* =
$2

[pgbouncer]
logfile = $1/pgbouncer.log
pidfile = $1/pgbouncer.pid

unix_socket_dir = $1

auth_type = trust
auth_file = $1/userlist.txt

verbose = 1
EOF
}

# userlist <user>
function userlist() {
  cat <<EOF
"$1" "whatever_we_trust"
EOF
}

# postgresql-conf <tmpdir>
function postgresql-conf() {
  cat <<EOF
unix_socket_directories = '$1'
port = 5432
listen_addresses = ''
log_filename = '$1/postgresql.log'
EOF
}

TMPDIR="$(mktemp -d -t pgbouncer-regression)"
PGUSER="$(whoami)"
export PGDATABASE="postgres"

function cleanup() {
  (sleep 2 && pg_ctl -D "${TMPDIR}/testdb" stop -m fast) || rm -rfv "${TMPDIR}"
}

trap cleanup EXIT

pgbouncer-config "${TMPDIR}" "; postgres = user=${PGUSER}" > "${TMPDIR}/pgbouncer.ini"
userlist "$PGUSER" > "${TMPDIR}/userlist.txt"

initdb "${TMPDIR}/testdb"
postgresql-conf "${TMPDIR}" >> "${TMPDIR}/testdb/postgresql.conf"
pg_ctl -D "${TMPDIR}/testdb" start

./pgbouncer -d "${TMPDIR}/pgbouncer.ini" >/dev/null 2>&1 && sleep 2

psql -h "${TMPDIR}" -p 6432 --tuples-only -c "select NOW()" | xargs
pgbouncer-config "${TMPDIR}" "postgres = user=${PGUSER}" > "${TMPDIR}/pgbouncer.ini"
pkill -HUP -F "${TMPDIR}/pgbouncer.pid" && sleep 1

psql -h "${TMPDIR}" -p 6432 --tuples-only -c "select NOW()" || echo "psql failed, as expected"
sleep 1

cat "${TMPDIR}/pgbouncer.log"
