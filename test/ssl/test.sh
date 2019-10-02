#! /bin/sh

cd $(dirname $0)

rm -rf TestCA1

(
./newca.sh TestCA1 C=QQ O=Org1 CN="TestCA1"
./newsite.sh TestCA1 localhost C=QQ O=Org1 L=computer OU=db
./newsite.sh TestCA1 bouncer C=QQ O=Org1 L=computer OU=Dev
./newsite.sh TestCA1 random C=QQ O=Org1 L=computer OU=Dev
) > /dev/null

export PGDATA=$PWD/pgdata
export PGHOST=localhost
export PGPORT=6667
export EF_ALLOW_MALLOC_0=1

mkdir -p tmp

BOUNCER_LOG=test.log
BOUNCER_INI=test.ini
BOUNCER_PID=test.pid
BOUNCER_PORT=`sed -n '/^listen_port/s/listen_port.*=[^0-9]*//p' $BOUNCER_INI`
BOUNCER_EXE="$BOUNCER_EXE_PREFIX ../../pgbouncer"

LOGDIR=log
PG_PORT=6666
PG_LOG=$LOGDIR/pg.log

pgctl() {
	pg_ctl -w -o "-p $PG_PORT" -D $PGDATA $@ >>$PG_LOG 2>&1
}

ulimit -c unlimited

# System configuration checks
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
	initdb --nosync >> $PG_LOG 2>&1
	sed -r -i "/unix_socket_director/s:.*(unix_socket_director.*=).*:\\1 '/tmp':" pgdata/postgresql.conf
	echo "port = $PG_PORT" >> pgdata/postgresql.conf
	echo "log_connections = on" >> pgdata/postgresql.conf
	echo "log_disconnections = on" >> pgdata/postgresql.conf
	cp pgdata/postgresql.conf pgdata/postgresql.conf.orig
	cp pgdata/pg_hba.conf pgdata/pg_hba.conf.orig
	cp pgdata/pg_ident.conf pgdata/pg_ident.conf.orig

	cp -p TestCA1/sites/01-localhost.crt pgdata/server.crt
	cp -p TestCA1/sites/01-localhost.key pgdata/server.key
	cp -p TestCA1/ca.crt pgdata/root.crt

	echo '"bouncer" "zzz"' > tmp/userlist.txt

	chmod 600 pgdata/server.key
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
	psql -X -h /tmp -U pgbouncer pgbouncer -c "$@;" || die "Cannot contact bouncer!"
}

runtest() {
	local status

	$BOUNCER_EXE -d $BOUNCER_INI
	until psql -X -h /tmp -U pgbouncer -d pgbouncer -c "show version" 2>/dev/null 1>&2; do sleep 0.1; done

	printf "`date` running $1 ... "
	echo "# $1 begin" >>$BOUNCER_LOG
	eval $1 >$LOGDIR/$1.log 2>&1
	status=$?
	if [ $status -eq 0 ]; then
		echo "ok"
	elif [ $status -eq 77 ]; then
		echo "skipped"
		status=0
	else
		echo "FAILED"
		cat $LOGDIR/$1.log | sed 's/^/# /'
	fi
	date >> $LOGDIR/$1.log

	# allow background processing to complete
	wait

	stopit test.pid
	echo "# $1 end" >>$BOUNCER_LOG

	return $status
}

psql_pg() {
	psql -X -U bouncer -h 127.0.0.1 -p $PG_PORT "$@"
}

psql_bouncer() {
	PGUSER=bouncer PGPASSWORD=zzz psql -X "$@"
}

# server_lifetime
test_server_ssl() {
	reconf_bouncer "auth_type = trust" "server_tls_sslmode = require"
	echo "hostssl all all 127.0.0.1/32 trust" > pgdata/pg_hba.conf
	reconf_pgsql "ssl=on" "ssl_ca_file='root.crt'"
	psql_bouncer -q -d p0 -c "select 'ssl-connect'" | tee tmp/test.tmp0
	grep -q "ssl-connect"  tmp/test.tmp0
	rc=$?
	return $rc
}

test_server_ssl_verify() {
	reconf_bouncer "auth_type = trust" \
		"server_tls_sslmode = verify-full" \
		"server_tls_ca_file = TestCA1/ca.crt"

	echo "hostssl all all 127.0.0.1/32 trust" > pgdata/pg_hba.conf
	reconf_pgsql "ssl=on" "ssl_ca_file='root.crt'"
	psql_bouncer -q -d p0 -c "select 'ssl-full-connect'" | tee tmp/test.tmp1
	grep -q "ssl-full-connect"  tmp/test.tmp1
	rc=$?
	return $rc
}

test_server_ssl_pg_auth() {
	reconf_bouncer "auth_type = trust" \
		"server_tls_sslmode = verify-full" \
		"server_tls_ca_file = TestCA1/ca.crt" \
		"server_tls_key_file = TestCA1/sites/02-bouncer.key" \
		"server_tls_cert_file = TestCA1/sites/02-bouncer.crt"

	echo "hostssl all all 127.0.0.1/32 cert" > pgdata/pg_hba.conf
	reconf_pgsql "ssl=on" "ssl_ca_file='root.crt'"
	psql_bouncer -q -d p0 -c "select 'ssl-cert-connect'" | tee tmp/test.tmp2
	grep "ssl-cert-connect"  tmp/test.tmp2
	rc=$?
	return $rc
}

test_client_ssl() {
	reconf_bouncer "auth_type = trust" "server_tls_sslmode = prefer" \
		"client_tls_sslmode = require" \
		"client_tls_key_file = TestCA1/sites/01-localhost.key" \
		"client_tls_cert_file = TestCA1/sites/01-localhost.crt"
	echo "host all all 127.0.0.1/32 trust" > pgdata/pg_hba.conf
	reconf_pgsql "ssl=on" "ssl_ca_file='root.crt'"
	psql_bouncer -q -d "dbname=p0 sslmode=require" -c "select 'client-ssl-connect'" | tee tmp/test.tmp
	grep -q "client-ssl-connect"  tmp/test.tmp
	rc=$?
	return $rc
}

test_client_ssl() {
	reconf_bouncer "auth_type = trust" "server_tls_sslmode = prefer" \
		"client_tls_sslmode = require" \
		"client_tls_key_file = TestCA1/sites/01-localhost.key" \
		"client_tls_cert_file = TestCA1/sites/01-localhost.crt"
	echo "host all all 127.0.0.1/32 trust" > pgdata/pg_hba.conf
	reconf_pgsql "ssl=on" "ssl_ca_file='root.crt'"
	psql_bouncer -q -d "dbname=p0 sslmode=verify-full sslrootcert=TestCA1/ca.crt" -c "select 'client-ssl-connect'" | tee tmp/test.tmp 2>&1
	grep -q "client-ssl-connect"  tmp/test.tmp
	rc=$?
	return $rc
}

test_client_ssl_auth() {
	reconf_bouncer "auth_type = cert" "server_tls_sslmode = prefer" \
		"client_tls_sslmode = verify-full" \
		"client_tls_ca_file = TestCA1/ca.crt" \
		"client_tls_key_file = TestCA1/sites/01-localhost.key" \
		"client_tls_cert_file = TestCA1/sites/01-localhost.crt"
	echo "host all all 127.0.0.1/32 trust" > pgdata/pg_hba.conf
	reconf_pgsql "ssl=on" "ssl_ca_file='root.crt'"
	psql_bouncer -q -d "dbname=p0 sslmode=require sslkey=TestCA1/sites/02-bouncer.key sslcert=TestCA1/sites/02-bouncer.crt" \
		-c "select 'client-ssl-connect'" | tee tmp/test.tmp 2>&1
	grep -q "client-ssl-connect"  tmp/test.tmp
	rc=$?
	return $rc
}

test_client_ssl_scram() {
	$pg_supports_scram || return 77

	reconf_bouncer "auth_type = scram-sha-256" "server_tls_sslmode = prefer" \
		"client_tls_sslmode = require" \
		"client_tls_key_file = TestCA1/sites/01-localhost.key" \
		"client_tls_cert_file = TestCA1/sites/01-localhost.crt"
	reconf_pgsql "ssl=on" "ssl_ca_file='root.crt'"
	psql_bouncer -q -d "dbname=p0 sslmode=verify-full sslrootcert=TestCA1/ca.crt" -c "select 'client-ssl-connect'" | tee tmp/test.tmp 2>&1
	grep -q "client-ssl-connect"  tmp/test.tmp
	rc=$?
	return $rc
}

testlist="
test_server_ssl
test_server_ssl_verify
test_server_ssl_pg_auth
test_client_ssl
test_client_ssl_auth
test_client_ssl_scram
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
