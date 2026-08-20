#!/bin/bash
#
# pgbouncer	Start the PgBouncer PostgreSQL pooler.
#
# The variables below are NOT to be changed.  They are there to make the
# script more readable.

NAME=pgbouncer
DAEMON=/usr/bin/$NAME
PIDFILE=/var/run/$NAME.pid
CONF=/etc/$NAME.ini
OPTS="-d $CONF"
# note: SSD is required only at startup of the daemon.
SSD=`command -v start-stop-daemon`
ENV="env -i LANG=C PATH=/bin:/usr/bin:/usr/local/bin"

trap "" 1

# Check if configuration exists
test -f $CONF || exit 0

case "$1" in
  start)
    echo -n "Starting server: $NAME"
    $ENV $SSD --start --pidfile $PIDFILE --exec $DAEMON -- $OPTS > /dev/null
    ;;

  stop)
    echo -n "Stopping server: $NAME"
    start-stop-daemon --stop --pidfile $PIDFILE
    ;;

  reload | force-reload)
    echo -n "Reloading $NAME configuration"
    start-stop-daemon --stop --pidfile $PIDFILE --signal HUP
    ;;

  restart)
    $0 stop
    $0 start
    ;;

  *)
    echo "Usage: /etc/init.d/$NAME {start|stop|reload|restart}"
    exit 1
    ;;
esac

if [ $? -eq 0 ]; then
	echo .
	exit 0
else
	echo " failed"
	exit 1
fi
