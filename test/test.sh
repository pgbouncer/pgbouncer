#!/bin/sh

# Notes:
# - uses iptables and -F with some tests, probably not very friendly to your firewall
# - uses nc (netcat) with some tests, skips if not in path
# - assumes postgres 8.2 fix your path so that it comes first

export PATH=/usr/lib/postgresql/8.4/bin:$PATH
export PGDATA=$PWD/pgdata
export PGHOST=localhost
export PGPORT=6667
export EF_ALLOW_MALLOC_0=1

BOUNCER_LOG=test.log
BOUNCER_INI=test.ini
BOUNCER_PID=test.pid
BOUNCER_PORT=`sed -n '/^listen_port/s/listen_port.*=[^0-9]*//p' $BOUNCER_INI`
BOUNCER_EXE="./pgbouncer"

LOGDIR=log
NC_PORT=6668
PG_PORT=6666
PG_LOG=$LOGDIR/pg.log

pgctl() {
	pg_ctl -o "-p $PG_PORT" -D $PGDATA $@ >>$PG_LOG 2>&1
}

ulimit -c unlimited

mkdir -p $LOGDIR
rm -f $BOUNCER_LOG $PG_LOG
# rm -r $PGDATA

if [ ! -d $PGDATA ]; then
	mkdir $PGDATA
	initdb >> $PG_LOG 2>&1
	sed -i "/unix_socket_directory/s:.*unix_socket_directory.*:unix_socket_directory = '/tmp':" pgdata/postgresql.conf
fi

pgctl start
sleep 5

psql -p $PG_PORT -l |grep p0 > /dev/null || {
	psql -p $PG_PORT -c "create user bouncer" template1
	createdb -p $PG_PORT p0
	createdb -p $PG_PORT p1
}

$BOUNCER_EXE -d $BOUNCER_INI
sleep 1

#
#  fw hacks
#

fw_drop_port() {
	case `uname` in
	Linux)
		sudo iptables -A OUTPUT -p tcp --dport $1 -j DROP;;
	Darwin)
		sudo ipfw add 100 drop tcp from any to 127.0.0.1 dst-port $1;;
	*)
		echo "Unknown OS";;
	esac
}
fw_reject_port() {
	case `uname` in
	Linux)
		sudo iptables -A OUTPUT -p tcp --dport $1 -j REJECT --reject-with tcp-reset;;
	Darwin)
		sudo ipfw add 100 reset tcp from any to 127.0.0.1 dst-port $1;;
	*)
		echo "Unknown OS";;
	esac
}

fw_reset() {
	case `uname` in
	Linux)
		sudo iptables -F OUTPUT;;
	Darwin)
		sudo ipfw del 100;;
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
}

die() {
	echo $@
	complete
	exit 1
}

admin() {
	psql -h /tmp -U pgbouncer pgbouncer -c "$@;" || die "Cannot contact bouncer!"
}

runtest() {
	echo -n "`date` running $1 ... "
	eval $1 >$LOGDIR/$1.log 2>&1
	if [ $? -eq 0 ]; then
		echo "ok"
	else
		echo "FAILED"
	fi
	date >> $LOGDIR/$1.log

	# allow background processing to complete
	wait
	# start with fresh config
	kill -HUP `cat $BOUNCER_PID`
}

# server_lifetime
test_server_lifetime() {
	admin "set server_lifetime=2"
	psql -c "select now()" p0
	sleep 3

	rc=`psql -p $PG_PORT -tAqc "select count(1) from pg_stat_activity where usename='bouncer' and datname='p0'" p0`
	psql -c "select now()" p0
	return $rc
}

# server_idle_timeout
test_server_idle_timeout() {
	admin "set server_idle_timeout=2"
	psql -c "select now()" p0
	sleep 3
	rc=`psql -p $PG_PORT -tAqc "select count(1) from pg_stat_activity where usename='bouncer' and datname='p0'" p0`
	psql -c "select now()" p0
	return $rc
}

# query_timeout
test_query_timeout() {
	admin "set query_timeout=3"
	psql -c "select pg_sleep(5)" p0 && return 1
	return 0
}

# client_idle_timeout
test_client_idle_timeout() {
	admin "set client_idle_timeout=2"
	psql --set ON_ERROR_STOP=1 p0 <<-PSQL_EOF
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
	psql -c "select now()" p0
	rc=$?
	wait
	return $rc
}

# server_connect_timeout - uses netcat to start dummy server
test_server_connect_timeout_establish() {
	which nc >/dev/null || return 1

	echo nc -q 5 -l $NC_PORT
	nc -l -q 5 $NC_PORT >/dev/null &
	sleep 2
	admin "set query_timeout=3"
	admin "set server_connect_timeout=2"
	psql -c "select now()" p2
	# client will always see query_timeout, need to grep for connect timeout
	grep "closing because: connect timeout" $BOUNCER_LOG 
	rc=$?
	# didnt seem to die otherwise
	killall nc
	return $rc
}

# server_connect_timeout - block with iptables
test_server_connect_timeout_reject() {
	test -z $CAN_SUDO && return 1
	admin "set query_timeout=5"
	admin "set server_connect_timeout=3"
	fw_drop_port $PG_PORT
	psql -c "select now()" p0
	fw_reset
	# client will always see query_timeout, need to grep for connect timeout
	grep "closing because: connect failed" $BOUNCER_LOG
}

# server_check_delay
test_server_check_delay() {
	test -z $CAN_SUDO && return 1

	admin "set server_check_delay=2"
	admin "set server_login_retry=3"
	admin "set query_timeout=10"

	psql p0 -c "select now()"
	fw_reject_port $PG_PORT
	sleep 3
	psql -tAq p0 -c "select 1" >$LOGDIR/test.tmp &
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

	for i in `seq 1 4`; do
		psql p1 -c "select now() as sleeping from pg_sleep(3);" &
	done

	# last conn allowed
	psql p1 -c "select now() as last_conn" || return 1

	# exhaust it
	psql p1 -c "select now() as sleeping from pg_sleep(3);"  &
	sleep 1

	# shouldn't be allowed
	psql p1 -c "select now() as exhausted"  && return 1

	# should be ok
	echo 'waiting for clients to complete ...'
	wait
	psql p1 -c "select now() as ok"  || return 1

	return 0
}

# - max pool size
test_pool_size() {
	
	docount() {
		for i in `seq 10`; do
			psql $1 -c "select pg_sleep(0.5)"  &
		done
		wait
		cnt=`psql -tAqc "select count(1) from pg_stat_activity where usename='bouncer' and datname='$1'" $1`
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
	for i in `seq 1 5`; do 
		echo "`date` attempt $i"

		for j in `seq 1 5`; do 
			psql -c "select now() as sleeping from pg_sleep(2)" p1  &
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
	for i in `seq 1 50`; do
		psql -tAq p0 -c 'select 1 from pg_sleep(0.1)' >>$LOGDIR/test.tmp
	done &

	for i in `seq 1 5`; do
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
	for i in `seq 1 50`; do
		psql -tAq p0 -c 'select 1 from pg_sleep(0.1)' >>$LOGDIR/test.tmp
	done &

	for i in `seq 1 5`; do
		psql -h /tmp -p $BOUNCER_PORT pgbouncer -U pgbouncer <<-PSQL_EOF
		suspend;
		\! sleep 1
		resume;
		\! sleep 1
		PSQL_EOF
	done

	wait
	test `wc -l <$LOGDIR/test.tmp` -eq 50
}

# test pool database restart
test_database_restart() {
	admin "set server_login_retry=1"

	psql p0 -c "select now() as p0_before_restart"
	pgctl -m fast restart
	echo `date` restart 1
	psql p0 -c "select now() as p0_after_restart" || return 1


	# do with some more clients
	for i in `seq 1 5`; do
		psql p0 -c "select pg_sleep($i)" &
		psql p1 -c "select pg_sleep($i)" &
	done

	pgctl -m fast restart
	echo `date` restart 2

	wait
	psql p0 -c "select now() as p0_after_restart" || return 1
}

# test connect string change
test_database_change() {
	admin "set server_lifetime=2"

	db1=`psql -tAq p1 -c "select current_database()"`

	cp test.ini test.ini.bak
	sed 's/\(p1 = port=6666 host=127.0.0.1 dbname=\)\(p1\)/\1p0/g' test.ini >test2.ini
	mv test2.ini test.ini

	kill -HUP `cat $BOUNCER_PID`

	sleep 3
	db2=`psql -tAq p1 -c "select current_database()"`

	echo "db1=$db1 db2=$db2"
	cp test.ini.bak test.ini
	rm test.ini.bak

	admin "show databases"
	admin "show pools"

	test $db1 = "p1" -a $db2 = "p0"
}

echo "Testing for sudo access."
sudo true && CAN_SUDO=1

testlist="
test_server_login_retry
test_client_idle_timeout
test_server_lifetime
test_server_idle_timeout
test_query_timeout
test_server_connect_timeout_establish
test_server_connect_timeout_reject
test_server_check_delay
test_max_client_conn
test_pool_size
test_online_restart
test_pause_resume
test_suspend_resume
test_database_restart
test_database_change
"

if [ $# -gt 0 ]; then
	testlist=$@
fi

for test in $testlist
do
	runtest $test
done

complete

# vim: sts=0 sw=8 noet nosmarttab:
