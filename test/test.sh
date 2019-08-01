#!/bin/bash

# Notes:
# - uses iptables and -F with some tests, probably not very friendly to your firewall

cd $(dirname $0)

export PATH=/usr/lib/postgresql/9.4/bin:$PATH
export PGDATA=$PWD/pgdata
export PGHOST=localhost
export PGPORT=6667
export EF_ALLOW_MALLOC_0=1
export LANG=C

BOUNCER_LOG=test.log
BOUNCER_INI=test.ini
BOUNCER_PID=test.pid
BOUNCER_PORT=`sed -n '/^listen_port/s/listen_port.*=[^0-9]*//p' $BOUNCER_INI`
BOUNCER_EXE="../pgbouncer"

LOGDIR=log
PG_PORT=6666
PG_LOG=$LOGDIR/pg.log

pgctl() {
	pg_ctl -o "-p $PG_PORT" -D $PGDATA $@ >>$PG_LOG 2>&1
}

ulimit -c unlimited

which initdb > /dev/null || {
	echo "initdb not found, need postgres tools in PATH"
	exit 1
}

# System configuration checks
if ! grep -q "^\"${USER}\"" userlist.txt; then
	cp userlist.txt userlist.txt.bak
	echo "\"${USER}\" \"01234\"" >> userlist.txt
fi

echo "Testing for sudo access."
sudo true && CAN_SUDO=1

if test -n "$CAN_SUDO"; then
	case `uname` in
	Darwin|OpenBSD)
		sudo pfctl -a pgbouncer -F all -q 2>&1 | grep -q "pfctl:" && {
			cat <<-EOF
			Please enable PF and add the following rule to /etc/pf.conf
			
			  anchor "pgbouncer/*"
			
			EOF
			exit 1
		}
		;;
	esac
fi

# System configuration checks
SED_ERE_OP='-E'
case `uname` in
Linux)
	SED_ERE_OP='-r'
	;;
esac

stopit() {
	test -f "$1" && { kill `head -n1 "$1"`; rm -f "$1"; }
}

stopit test.pid
stopit pgdata/postmaster.pid

mkdir -p $LOGDIR
rm -f $BOUNCER_LOG $PG_LOG
rm -rf $PGDATA

if [ ! -d $PGDATA ]; then
	mkdir $PGDATA
	initdb >> $PG_LOG 2>&1
	sed $SED_ERE_OP -i "/unix_socket_director/s:.*(unix_socket_director.*=).*:\\1 '/tmp':" pgdata/postgresql.conf
fi

pgctl start
sleep 5

echo "Creating databases"
psql -X -p $PG_PORT -l | grep p0 > /dev/null || {
	psql -X -o /dev/null -p $PG_PORT -c "create user bouncer" template1
	createdb -p $PG_PORT p0
	createdb -p $PG_PORT p1
	createdb -p $PG_PORT p3
}

psql -X -p $PG_PORT -d p0 -c "select * from pg_user" | grep pswcheck > /dev/null || {
	psql -X -o /dev/null -p $PG_PORT -c "create user pswcheck with superuser createdb password 'pgbouncer-check';" p0 || exit 1
	psql -X -o /dev/null -p $PG_PORT -c "create user someuser with password 'anypasswd';" p0 || exit 1
}

echo "Starting bouncer"
$BOUNCER_EXE -d $BOUNCER_INI
sleep 1

#
#  fw hacks
#

fw_drop_port() {
	case `uname` in
	Linux)
		sudo iptables -A OUTPUT -p tcp --dport $1 -j DROP;;
	Darwin|OpenBSD)
		echo "block drop out proto tcp from any to 127.0.0.1 port $1" \
		    | sudo pfctl -a pgbouncer -f -;;
	*)
		echo "Unknown OS"; exit 1;;
	esac
}
fw_reject_port() {
	case `uname` in
	Linux)
		sudo iptables -A OUTPUT -p tcp --dport $1 -j REJECT --reject-with tcp-reset;;
	Darwin|OpenBSD)
		echo "block return-rst out proto tcp from any to 127.0.0.1 port $1" \
		    | sudo pfctl -a pgbouncer -f -;;
	*)
		echo "Unknown OS"; exit 1;;
	esac
}

fw_reset() {
	case `uname` in
	Linux)
		sudo iptables -F OUTPUT;;
	Darwin|OpenBSD)
		sudo pfctl -a pgbouncer -F all;;
	*)
		echo "Unknown OS"; exit 1;;
	esac
}

#
# util functions
#

complete() {
	test -f $BOUNCER_PID && kill `cat $BOUNCER_PID` >/dev/null 2>&1
	pgctl -m fast stop
	rm -f $BOUNCER_PID
	test -e userlist.txt.bak && mv userlist.txt.bak userlist.txt
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

	printf "`date` running $1 ... "
	eval $1 >$LOGDIR/$1.log 2>&1
	status=$?
	if [ $status -eq 0 ]; then
		echo "ok"
	elif [ $status -eq 77 ]; then
		echo "skipped"
	else
		echo "FAILED"
		cat $LOGDIR/$1.log | sed 's/^/# /'
	fi
	date >> $LOGDIR/$1.log

	# allow background processing to complete
	wait
	# start with fresh config
	kill -HUP `cat $BOUNCER_PID`

	return $status
}

# server_lifetime
test_server_lifetime() {
	admin "set server_lifetime=2"
	psql -X -c "select now()" p0
	sleep 3

	rc=`psql -X -p $PG_PORT -tAqc "select count(1) from pg_stat_activity where usename='bouncer' and datname='p0'" p0`
	psql -X -c "select now()" p0
	return $rc
}

# server_idle_timeout
test_server_idle_timeout() {
	admin "set server_idle_timeout=2"
	psql -X -c "select now()" p0
	sleep 3
	rc=`psql -X -p $PG_PORT -tAq -c "select count(1) from pg_stat_activity where usename='bouncer' and datname='p0'" p0`
	psql -X -c "select now()" p0
	return $rc
}

# query_timeout
test_query_timeout() {
	admin "set query_timeout=3"
	psql -X -c "select pg_sleep(5)" p0 && return 1
	return 0
}

# idle_transaction_timeout
test_idle_transaction_timeout() {
	admin "set pool_mode=transaction"
	admin "set idle_transaction_timeout=2"

	psql -X --set ON_ERROR_STOP=1 p0 <<-PSQL_EOF
	begin;
	\! sleep 3
	select now();
	PSQL_EOF
	test $? -eq 0 && return 1

	# test for GH issue #125
	psql -X --set ON_ERROR_STOP=1 p0 <<-PSQL_EOF
	begin;
	select pg_sleep(1);
	\! sleep 2
	select now();
	PSQL_EOF
	test $? -ne 0 && return 1

	return 0
}

# client_idle_timeout
test_client_idle_timeout() {
	admin "set client_idle_timeout=2"
	psql -X --set ON_ERROR_STOP=1 p0 <<-PSQL_EOF
	select now();
	\! sleep 3
	select now();
	PSQL_EOF
	test $? -eq 0 && return 1
	return 0
}

# server_login_retry
test_server_login_retry() {
	admin "set query_timeout=10"
	admin "set server_login_retry=1"

	(pgctl -m fast stop; sleep 3; pgctl start) &
	sleep 1
	psql -X -c "select now()" p0
	rc=$?
	wait
	return $rc
}

# server_connect_timeout
test_server_connect_timeout_establish() {
	psql -X -p $PG_PORT -c "alter system set pre_auth_delay to '60s'" p0
	kill -HUP `head -n1 pgdata/postmaster.pid`
	sleep 1

	admin "set query_timeout=3"
	admin "set server_connect_timeout=2"
	psql -X -c "select now()" p0
	# client will always see query_timeout, need to grep for connect timeout
	grep "closing because: connect timeout" $BOUNCER_LOG
	rc=$?

	rm -f pgdata/postgresql.auto.conf
	kill -HUP `head -n1 pgdata/postmaster.pid`
	sleep 1

	return $rc
}

# server_connect_timeout - block with iptables
test_server_connect_timeout_reject() {
	test -z $CAN_SUDO && return 77
	admin "set query_timeout=5"
	admin "set server_connect_timeout=3"
	fw_drop_port $PG_PORT
	psql -X -c "select now()" p0
	fw_reset
	# client will always see query_timeout, need to grep for connect timeout
	grep "closing because: connect failed" $BOUNCER_LOG
}

# server_check_delay
test_server_check_delay() {
	test -z $CAN_SUDO && return 77

	admin "set server_check_delay=2"
	admin "set server_login_retry=3"
	admin "set query_timeout=10"

	psql -X -c "select now()" p0
	fw_reject_port $PG_PORT
	sleep 3
	psql -X -tAq -c "select 1" p0 >$LOGDIR/test.tmp &
	sleep 1
	fw_reset
	echo `date` rules flushed
	wait
	echo `date` done waiting

	test "`cat $LOGDIR/test.tmp`" = "1"
}

# max_client_conn
test_max_client_conn() {
	admin "set max_client_conn=5"
	admin "show config"

	for i in {1..4}; do
		psql -X -c "select now() as sleeping from pg_sleep(3);" p1 &
	done

	# last conn allowed
	psql -X -c "select now() as last_conn" p1 || return 1

	# exhaust it
	psql -X -c "select now() as sleeping from pg_sleep(3);" p1 &
	sleep 1

	# shouldn't be allowed
	psql -X -c "select now() as exhausted" p1 && return 1

	# should be ok
	echo 'waiting for clients to complete ...'
	wait
	psql -X -c "select now() as ok" p1 || return 1

	return 0
}

# - max pool size
test_pool_size() {
	docount() {
		for i in {1..10}; do
			psql -X -c "select pg_sleep(0.5)" $1 &
		done
		wait
		cnt=`psql -X -tAq -c "select count(1) from pg_stat_activity where usename='bouncer' and datname='$1'" $1`
		echo $cnt
	}

	test `docount p0` -ne 2 && return 1
	test `docount p1` -ne 5 && return 1

	return 0
}

# test online restart while clients running
test_online_restart() {
# max_client_conn=10
# default_pool_size=5
	for i in {1..5}; do
		echo "`date` attempt $i"

		for j in {1..5}; do
			psql -X -c "select now() as sleeping from pg_sleep(2)" p1 &
		done

		pid1=`cat $BOUNCER_PID`
		echo "old bouncer is $pid1"
		$BOUNCER_EXE -d -R  $BOUNCER_INI
		sleep 2
		pid2=`cat $BOUNCER_PID`
		echo "new bouncer is $pid2"
		[ $pid1 = $pid2 ] && return 1
	done
	return 0
}

# test pause/resume
test_pause_resume() {
	rm -f $LOGDIR/test.tmp
	for i in {1..50}; do
		psql -X -tAq -c 'select 1 from pg_sleep(0.1)' p0 >>$LOGDIR/test.tmp
	done &

	for i in {1..5}; do
		admin "pause"
		sleep 1
		admin "resume"
		sleep 1
	done

	wait
	test `wc -l <$LOGDIR/test.tmp` -eq 50
}

# test suspend/resume
test_suspend_resume() {
	rm -f $LOGDIR/test.tmp
	for i in {1..50}; do
		psql -X -tAq -c 'select 1 from pg_sleep(0.1)' p0 >>$LOGDIR/test.tmp
	done &

	for i in {1..5}; do
		psql -X -h /tmp -p $BOUNCER_PORT -d pgbouncer -U pgbouncer <<-PSQL_EOF
		suspend;
		\! sleep 1
		resume;
		\! sleep 1
		PSQL_EOF
	done

	wait
	test `wc -l <$LOGDIR/test.tmp` -eq 50
}

# test enable/disable
test_enable_disable() {
	rm -f $LOGDIR/test.tmp
	psql -X -tAq -c "select 'enabled 1'" >>$LOGDIR/test.tmp p0 2>&1

	admin "disable p0"
	psql -X -tAq -c "select 'disabled 1'" >>$LOGDIR/test.tmp p0 2>&1
	admin "enable p0"
	psql -X -tAq -c "select 'enabled 2'" >>$LOGDIR/test.tmp p0 2>&1

	grep -q "enabled 1" $LOGDIR/test.tmp || return 1
	grep -q "enabled 2" $LOGDIR/test.tmp || return 1
	grep -q "disabled 1" $LOGDIR/test.tmp && return 1
	grep -q "does not allow" $LOGDIR/test.tmp || return 1
	return 0
}

# test pool database restart
test_database_restart() {
	admin "set server_login_retry=1"

	psql -X -c "select now() as p0_before_restart" p0
	pgctl -m fast restart
	echo `date` restart 1
	psql -X -c "select now() as p0_after_restart" p0 || return 1


	# do with some more clients
	for i in {1..5}; do
		psql -X -c "select pg_sleep($i)" p0 &
		psql -X -c "select pg_sleep($i)" p1 &
	done

	pgctl -m fast restart
	echo `date` restart 2

	wait
	psql -X -c "select now() as p0_after_restart" p0 || return 1

	# connect to clear server_login_retry state
	psql -X -c "select now() as p1_after_restart" p1

	return 0
}

# test connect string change
test_database_change() {
	admin "set server_lifetime=2"

	db1=`psql -X -tAq -c "select current_database()" p1`

	cp test.ini test.ini.bak
	sed '/^p1 =/s/dbname=p1/dbname=p0/g' test.ini >test2.ini
	mv test2.ini test.ini

	kill -HUP `cat $BOUNCER_PID`

	sleep 3
	db2=`psql -X -tAq -c "select current_database()" p1`

	echo "db1=$db1 db2=$db2"
	cp test.ini.bak test.ini
	rm test.ini.bak

	admin "show databases"
	admin "show pools"

	test "$db1" = "p1" -a "$db2" = "p0"
}

# test reconnect
test_reconnect() {
	bp1=`psql -X -tAq -c "select pg_backend_pid()" p1`
	admin "reconnect p1"
	sleep 1
	bp2=`psql -X -tAq -c "select pg_backend_pid()" p1`
	echo "bp1=$bp1 bp2=$bp2"
	test "$bp1" != "$bp2"
}

# test server_fast_close
test_fast_close() {
	(
		echo "select pg_backend_pid();"
		sleep 2
		echo "select pg_backend_pid();"
		echo "\q"
	) | psql -X -tAq -f- -d p3 >$LOGDIR/testout.tmp 2>$LOGDIR/testerr.tmp &
	sleep 1
	admin "set server_fast_close = 1"
	admin "reconnect p3"
	wait

	admin "show databases"
	admin "show pools"
	admin "show servers"

	# If this worked correctly, the session will be closed between
	# the two queries, so the second query will fail and leave an
	# error.
	test `wc -l <$LOGDIR/testout.tmp` -eq 1 && test `wc -l <$LOGDIR/testerr.tmp` -ge 1
}

# test wait_close
test_wait_close() {
	(
		echo "select pg_backend_pid();"
		sleep 3
		echo "select pg_backend_pid();"
		echo "\q"
	) | psql -X -tAq -f- -d p3 &
	psql_pid=$!
	sleep 1
	admin "reconnect p3"
	admin "wait_close p3"
	sleep 1  # give psql a moment to exit

	# psql should no longer be running now.  (Without the
	# wait_close it would still be running.)
	kill -0 $psql_pid
	psql_running=$?

	wait

	admin "show databases"
	admin "show pools"
	admin "show servers"

	test $psql_running -ne 0
}

# test auth_user
test_auth_user() {
	admin "set auth_type='md5'"
	curuser=`psql -X -d "dbname=authdb user=someuser password=anypasswd" -tAq -c "select current_user;"`
	echo "curuser=$curuser"
	test "$curuser" = "someuser" || return 1

	curuser2=`psql -X -d "dbname=authdb user=nouser password=anypasswd" -tAq -c "select current_user;"`
	echo "curuser2=$curuser2"
	test "$curuser2" = "" || return 1

	curuser2=`psql -X -d "dbname=authdb user=someuser password=badpasswd" -tAq -c "select current_user;"`
	echo "curuser2=$curuser2"
	test "$curuser2" = "" || return 1

	admin "show databases"
	admin "show pools"

	return 0
}

testlist="
test_server_login_retry
test_auth_user
test_client_idle_timeout
test_server_lifetime
test_server_idle_timeout
test_query_timeout
test_idle_transaction_timeout
test_server_connect_timeout_establish
test_server_connect_timeout_reject
test_server_check_delay
test_max_client_conn
test_pool_size
test_online_restart
test_pause_resume
test_suspend_resume
test_enable_disable
test_database_restart
test_database_change
test_reconnect
test_fast_close
test_wait_close
"

if [ $# -gt 0 ]; then
	testlist=$@
fi

total_status=0
for test in $testlist
do
	runtest $test
	status=$?
	if [ $status -eq 1 ]; then
		total_status=1
	fi
done

complete

exit $total_status

# vim: sts=0 sw=8 noet nosmarttab:
