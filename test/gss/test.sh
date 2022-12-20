#! /bin/sh

cd $(dirname $0)

export PGDATA=$PWD/pgdata
export PGHOST=localhost
export PGPORT=6667
export EF_ALLOW_MALLOC_0=1
export LC_ALL=C
export POSIXLY_CORRECT=1

mkdir -p tmp

BOUNCER_LOG=test.log
BOUNCER_INI=test.ini
BOUNCER_PID=test.pid
BOUNCER_PORT=`sed -n '/^listen_port/s/listen_port.*=[^0-9]*//p' $BOUNCER_INI`
BOUNCER_EXE="$BOUNCER_EXE_PREFIX ../../pgbouncer"

KRB5_REALM=EXAMPLE.COM

LOGDIR=log
PG_PORT=6666
PG_LOG=$LOGDIR/pg.log

sed -i "s/FQDN/$(hostname -f)/g" $BOUNCER_INI

pgctl() {
	pg_ctl -w -o "-p $PG_PORT" -D $PGDATA $@ >>$PG_LOG 2>&1
}

ulimit -c unlimited

SED_ERE_OP='-E'
case `uname` in
Linux)
	SED_ERE_OP='-r'
	;;
esac

pg_majorversion=$(initdb --version | sed -n $SED_ERE_OP 's/.* ([0-9]+).*/\1/p')
if test $pg_majorversion -ge 10; then
	pg_supports_scram=true
else
	pg_supports_scram=false
fi

stopit() {
	local pid
	if test -f "$1"; then
		pid=`head -n1 "$1"`
		kill $pid
		while kill -0 $pid 2>/dev/null; do sleep 0.1; done
		rm -f "$1"
	fi
}

stopit test.pid
stopit pgdata/postmaster.pid

mkdir -p $LOGDIR
rm -f $BOUNCER_LOG $PG_LOG
rm -rf $PGDATA

if [ ! -d $PGDATA ]; then
	echo "initdb"
	mkdir $PGDATA
	initdb -A trust --nosync >> $PG_LOG
	echo "unix_socket_directories = '/tmp'" >> pgdata/postgresql.conf
	echo "port = $PG_PORT" >> pgdata/postgresql.conf
	# We need to make the log go to stderr so that the tests can
	# check what is being logged.  This should be the default, but
	# some packagings change the default configuration.
	echo "logging_collector = off" >> pgdata/postgresql.conf
	echo "log_destination = stderr" >> pgdata/postgresql.conf
	echo "log_connections = on" >> pgdata/postgresql.conf
	echo "log_disconnections = on" >> pgdata/postgresql.conf
	cp pgdata/postgresql.conf pgdata/postgresql.conf.orig
	cp pgdata/pg_hba.conf pgdata/pg_hba.conf.orig
	cp pgdata/pg_ident.conf pgdata/pg_ident.conf.orig

	cp /krb5.keytab pgdata/krb5.keytab
        chmod 600 pgdata/krb5.keytab

	echo '"bouncer" "zzz"' > tmp/userlist.txt

	chmod 600 tmp/userlist.txt
fi

pgctl start

echo "createdb"
psql -X -p $PG_PORT -l | grep p0 > /dev/null || {
	psql -X -o /dev/null -p $PG_PORT -c "create user bouncer" template1
	createdb -p $PG_PORT p0
	createdb -p $PG_PORT p1
}

reconf_bouncer() {
	cp test.ini tmp/test.ini
	for ln in "$@"; do
		echo "$ln" >> tmp/test.ini
	done
	test -f test.pid && kill `cat test.pid`
	sleep 1
	$BOUNCER_EXE -v -v -v -d tmp/test.ini
}

reconf_pgsql() {
	cp pgdata/postgresql.conf.orig pgdata/postgresql.conf
	for ln in "$@"; do
		echo "$ln" >> pgdata/postgresql.conf
	done
	pgctl stop
	pgctl start
	sleep 1
}


#
#  fw hacks
#

#
# util functions
#

complete() {
	test -f $BOUNCER_PID && kill `cat $BOUNCER_PID` >/dev/null 2>&1
	pgctl -m fast stop
	rm -f $BOUNCER_PID
}

die() {
	echo $@
	complete
	exit 1
}

admin() {
	psql -X -h /tmp -U pgbouncer -d pgbouncer -c "$@;" || die "Cannot contact bouncer!"
}

runtest() {
	local status

	$BOUNCER_EXE -d $BOUNCER_INI
	until psql -X -h /tmp -U pgbouncer -d pgbouncer -c "show version" 2>/dev/null 1>&2; do sleep 0.1; done

	printf "`date` running $1 ... "
	eval $1 >$LOGDIR/$1.out 2>&1
	status=$?

	# Detect fatal errors from PgBouncer (which are internal
	# errors), but not those from PostgreSQL (which could be
	# normal, such as authentication failures)
	if grep 'FATAL @' $BOUNCER_LOG >> $LOGDIR/$1.out; then
		status=1
	fi

	if [ $status -eq 0 ]; then
		echo "ok"
	elif [ $status -eq 77 ]; then
		echo "skipped"
		status=0
	else
		echo "FAILED"
		cat $LOGDIR/$1.out | sed 's/^/# /'
	fi
	date >> $LOGDIR/$1.out

	# allow background processing to complete
	wait

	stopit test.pid
	mv $BOUNCER_LOG $LOGDIR/$1.log

	return $status
}

psql_pg() {
	psql -X -U bouncer -h 127.0.0.1 -p $PG_PORT "$@"
}

psql_bouncer() {
	PGUSER=bouncer PGPASSWORD=zzz psql -X "$@"
}

test_server_gss() {
	reconf_bouncer "server_gssencmode = require"
#	reconf_bouncer "server_gssencmode = prefer"
#	reconf_bouncer "server_gssencmode = disable"
	echo "hostgssenc all all 0.0.0.0/0 gss include_realm=0 krb_realm=EXAMPLE.COM" > pgdata/pg_hba.conf
	echo "hostgssenc all all ::/0 gss include_realm=0 krb_realm=EXAMPLE.COM" >> pgdata/pg_hba.conf
	reconf_pgsql "krb_server_keyfile = '$PGDATA/krb5.keytab'"
        psql_bouncer -q -d p0 -c 'SELECT pid, gss_authenticated, encrypted, principal from pg_stat_gssapi where pid = pg_backend_pid();' | tee tmp/test.tmp1
        grep -Eq 't.*t.*bouncer@EXAMPLE.COM' tmp/test.tmp1
        rc=$?
        return $rc
}

testlist="
test_server_gss
"
if [ $# -gt 0 ]; then
	testlist="$*"
fi

total_status=0
for test in $testlist
do
	runtest $test
	status=$?
	if [ $status -ne 0 ]; then
		total_status=1
	fi
done

complete

exit $total_status

# vim: sts=0 sw=8 noet nosmarttab:
