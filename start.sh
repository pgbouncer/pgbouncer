#!/bin/bash -x
set -euo pipefail

PGB_DIR="/home/pgbouncer"
INI="${PGB_DIR}/pgbouncer.ini"
USERLIST="${PGB_DIR}/userlist.txt"

# Auto-generate conf if it doesn't exist
if [ ! -f ${INI} ]; then
cat <<- END > $INI
[databases]
    global_db = host=${GLOBAL_DB_HOST} port=${GLOBAL_DB_PORT} user=${GLOBAL_DB_USERNAME} password=${GLOBAL_DB_PASSWORD} dbname=${GLOBAL_DB_NAME}
    main_db = host=${MAIN_DB_HOST} port=${MAIN_DB_PORT} user=${MAIN_DB_USERNAME} password=${MAIN_DB_PASSWORD} dbname=${MAIN_DB_NAME}
[pgbouncer]
    listen_port = ${PGB_LISTEN_PORT:-5432}
    listen_addr = ${PGB_LISTEN_ADDR:-0.0.0.0}
    auth_type = md5
    default_pool_size = ${default_pool_size:-20}
    log_connections = ${log_connections:-1}
    log_disconnections = ${log_disconnections:-1}
    log_pooler_errors = ${log_pooler_errors:-1}
    routing_rules_py_module_file = ${routing_rules_py_module_file:-/home/pgbouncer/routing_rules.py}
    log_stats = ${log_stats:-1}
    auth_file = $USERLIST
    logfile = $PGB_DIR/pgbouncer.log
    pidfile = $PGB_DIR/pgbouncer.pid
    admin_users = admin
END
  cat $INI
fi

echo ${PGB_USERLIST} > $USERLIST

chmod 0600 $INI
chmod 0600 $USERLIST
pgbouncer $INI ${VERBOSE:-}
