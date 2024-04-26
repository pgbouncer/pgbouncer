import subprocess
from contextlib import closing, contextmanager
from pathlib import Path

try:
    from contextlib import asynccontextmanager
except ImportError:
    # Fallback for python3.6
    from contextlib2 import asynccontextmanager

import asyncio
import os
import platform
import re
import shlex
import signal
import socket
import sys
import time
import typing
from tempfile import gettempdir

import filelock
import psycopg
import psycopg.sql
from psycopg import sql

TEST_DIR = Path(os.path.dirname(os.path.realpath(__file__)))
os.chdir(TEST_DIR)

PGDATA = TEST_DIR / "pgdata"
PGHOST = "127.0.0.1"

BOUNCER_LOG = TEST_DIR / "test.log"
BOUNCER_INI = TEST_DIR / "test.ini"
BOUNCER_AUTH = TEST_DIR / "userlist.txt"
BOUNCER_PID = TEST_DIR / "test.pid"
BOUNCER_PORT = 6667
BOUNCER_EXE = TEST_DIR / "../pgbouncer"
NEW_CA_SCRIPT = TEST_DIR / "ssl" / "newca.sh"
NEW_SITE_SCRIPT = TEST_DIR / "ssl" / "newsite.sh"
ENABLE_VALGRIND = bool(os.environ.get("ENABLE_VALGRIND"))
HAVE_IPV6_LOCALHOST = bool(os.environ.get("HAVE_IPV6_LOCALHOST"))
USE_SUDO = bool(os.environ.get("USE_SUDO"))
START_OPENLDAP_SCRIPT = TEST_DIR / "start_openldap_server.sh"

# The tests require that psql can connect to the PgBouncer admin
# console.  On platforms that have getpeereid(), this works by
# connecting as user pgbouncer over the Unix socket.  On other
# platforms, we have to rely on "trust" authentication, but then we
# have to skip any tests that use authentication methods other than
# "trust".
if os.name == "nt":
    USE_UNIX_SOCKETS = False
    HAVE_GETPEEREID = False

    # psycopg only supports WindowsSelectorEventLoopPolicy
    from asyncio import WindowsSelectorEventLoopPolicy

    asyncio.set_event_loop_policy(WindowsSelectorEventLoopPolicy())
    WINDOWS = True
else:
    USE_UNIX_SOCKETS = True
    HAVE_GETPEEREID = True
    WINDOWS = False

LINUX = False
MACOS = False
FREEBSD = False
OPENBSD = False

if platform.system() == "Linux":
    LINUX = True
elif platform.system() == "Darwin":
    MACOS = True
elif platform.system() == "FreeBSD":
    FREEBSD = True
elif platform.system() == "OpenBSD":
    OPENBSD = True

BSD = MACOS or FREEBSD or OPENBSD


def eprint(*args, **kwargs):
    """eprint prints to stderr"""

    print(*args, file=sys.stderr, **kwargs)


def run(command, *args, check=True, shell=None, silent=False, **kwargs):
    """run runs the given command and prints it to stderr"""

    if shell is None:
        shell = isinstance(command, str)

    if not shell:
        command = list(map(str, command))

    if not silent:
        if shell:
            eprint(f"+ {command}")
        else:
            # We could normally use shlex.join here, but it's not available in
            # Python 3.6 which we still like to support
            unsafe_string_cmd = " ".join(map(shlex.quote, command))
            eprint(f"+ {unsafe_string_cmd}")
    if silent:
        kwargs.setdefault("stdout", subprocess.DEVNULL)
    return subprocess.run(command, *args, check=check, shell=shell, **kwargs)


def sudo(command, *args, shell=None, **kwargs):
    """
    A version of run that prefixes the command with sudo when the process is
    not already run as root
    """
    effective_user_id = os.geteuid()

    if effective_user_id == 0:
        return run(command, *args, shell=shell, **kwargs)

    if shell is None:
        shell = isinstance(command, str)

    if shell:
        return run(f"sudo {command}", *args, shell=shell, **kwargs)
    else:
        return run(["sudo", *command], *args, shell=shell, **kwargs)


def capture(command, *args, stdout=subprocess.PIPE, encoding="utf-8", **kwargs):
    return run(command, *args, stdout=stdout, encoding=encoding, **kwargs).stdout


def get_pg_major_version():
    full_version_string = capture("initdb --version", silent=True)
    major_version_string = re.search("[0-9]+", full_version_string)
    assert major_version_string is not None
    return int(major_version_string.group(0))


PG_MAJOR_VERSION = get_pg_major_version()


def get_max_password_length():
    with open("../include/bouncer.h", encoding="utf-8") as f:
        match = re.search(r"#define MAX_PASSWORD\s+([0-9].*)", f.read())
        assert match is not None
        max_password_length = int(match.group(1))
        assert max_password_length >= 996

    if max_password_length > 996 and PG_MAJOR_VERSION < 14:
        return 996
    return max_password_length


PKT_BUF_SIZE = 4096
MAX_PASSWORD_LENGTH = get_max_password_length()
LONG_PASSWORD = "a" * (MAX_PASSWORD_LENGTH - 1)

PG_SUPPORTS_SCRAM = PG_MAJOR_VERSION >= 10

# psycopg.Pipeline.is_supported() does not work on rocky:8 in CI, so we create
# our own check here that works on all our supported systems
LIBPQ_SUPPORTS_PIPELINING = psycopg.pq.version() >= 140000


def get_tls_support():
    with open("../config.mak", encoding="utf-8") as f:
        match = re.search(r"tls_support = (\w+)", f.read())
        assert match is not None
        return match.group(1) == "yes"


TLS_SUPPORT = get_tls_support()


def get_ldap_support():
    with open("../config.mak", encoding="utf-8") as f:
        match = re.search(r"ldap_support = (\w+)", f.read())
        assert match is not None
        return match.group(1) == "yes"


LDAP_SUPPORT = get_ldap_support()

# this is out of ephemeral port range for many systems hence
# it is a lower change that it will conflict with "in-use" ports
PORT_LOWER_BOUND = 10200

# ephemeral port start on many Linux systems
PORT_UPPER_BOUND = 32768

next_port = PORT_LOWER_BOUND


def cleanup_test_leftovers(*nodes):
    """
    Cleaning up test leftovers needs to be done in a specific order, because
    some of these leftovers depend on others having been removed. They might
    even depend on leftovers on other nodes being removed. So this takes a list
    of nodes, so that we can clean up all test leftovers globally in the
    correct order.
    """
    for node in nodes:
        node.cleanup_subscriptions()

    for node in nodes:
        node.cleanup_publications()

    for node in nodes:
        node.cleanup_replication_slots()

    for node in nodes:
        node.cleanup_schemas()

    for node in nodes:
        node.cleanup_users()


class PortLock:
    def __init__(self):
        global next_port
        while True:
            next_port += 1
            if next_port >= PORT_UPPER_BOUND:
                next_port = PORT_LOWER_BOUND

            self.lock = filelock.FileLock(Path(gettempdir()) / f"port-{next_port}.lock")
            try:
                self.lock.acquire(timeout=0)
            except filelock.Timeout:
                continue

            with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
                try:
                    s.bind(("127.0.0.1", next_port))
                    self.port = next_port
                    break
                except Exception:
                    continue

    def release(self):
        self.lock.release()


def notice_handler(diag: psycopg.errors.Diagnostic):
    print(f"{diag.severity}: {diag.message_primary}")
    if diag.message_detail:
        print(f"DETAIL: {diag.message_detail}")
    if diag.message_hint:
        print(f"HINT: {diag.message_hint}")
    if diag.context:
        print(f"CONTEXT: {diag.context}")


class QueryRunner:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.default_db = "postgres"
        self.default_user = "postgres"

        # Used to track objects that we want to clean up at the end of a test
        self.subscriptions = set()
        self.publications = set()
        self.replication_slots = set()
        self.schemas = set()
        self.users = set()

    def set_default_connection_options(self, options):
        """Sets the default connection options on the given options dictionary"""
        options.setdefault("dbname", self.default_db)
        options.setdefault("user", self.default_user)
        options.setdefault("host", self.host)
        options.setdefault("port", self.port)
        if ENABLE_VALGRIND:
            # If valgrind is enabled PgBouncer is a significantly slower to
            # respond to connection requests, so we wait a little longer.
            options.setdefault("connect_timeout", 20)
        else:
            options.setdefault("connect_timeout", 3)
        # Always required for Ubuntu 18.04, but also needed for any tests
        # involving the varcache_change database. The difference between the
        # client_encoding specified in the config and client_encoding by the
        # client will force a varcache change when a connection is given.
        options.setdefault("client_encoding", "UTF8")
        return options

    def make_conninfo(self, **kwargs) -> str:
        self.set_default_connection_options(kwargs)
        return psycopg.conninfo.make_conninfo(**kwargs)

    def conn(self, *, autocommit=True, **kwargs):
        """Open a psycopg connection to this server"""
        self.set_default_connection_options(kwargs)
        conn = psycopg.connect(
            autocommit=autocommit,
            **kwargs,
        )
        conn.add_notice_handler(notice_handler)
        return conn

    def aconn(self, *, autocommit=True, **kwargs):
        """Open an asynchronous psycopg connection to this server"""
        self.set_default_connection_options(kwargs)
        return psycopg.AsyncConnection.connect(
            autocommit=autocommit,
            **kwargs,
        )

    @contextmanager
    def cur(self, autocommit=True, **kwargs):
        """Open an psycopg cursor to this server

        The connection and the cursors automatically close once you leave the
        "with" block
        """
        with self.conn(
            autocommit=autocommit,
            **kwargs,
        ) as conn:
            with conn.cursor() as cur:
                yield cur

    @asynccontextmanager
    async def acur(self, **kwargs):
        """Open an asynchronous psycopg cursor to this server

        The connection and the cursors automatically close once you leave the
        "async with" block
        """
        async with await self.aconn(**kwargs) as conn:
            async with conn.cursor() as cur:
                yield cur

    def sql(self, query, params=None, **kwargs):
        """Run an SQL query

        This opens a new connection and closes it once the query is done
        """
        with self.cur(**kwargs) as cur:
            cur.execute(query, params=params)
            try:
                return cur.fetchall()
            except psycopg.ProgrammingError as e:
                if "the last operation didn't produce a result" == str(e):
                    return None
                raise

    def sql_value(self, query, params=None, **kwargs):
        """Run an SQL query that returns a single cell and return this value

        This opens a new connection and closes it once the query is done
        """
        with self.cur(**kwargs) as cur:
            cur.execute(query, params=params)
            result = cur.fetchall()
            assert len(result) == 1
            assert len(result[0]) == 1
            value = result[0][0]
            return value

    def asql(self, query, **kwargs):
        """Run an SQL query in asynchronous task

        This opens a new connection and closes it once the query is done
        """
        return asyncio.ensure_future(self.asql_coroutine(query, **kwargs))

    async def asql_coroutine(
        self, query, params=None, **kwargs
    ) -> typing.Optional[typing.List[typing.Any]]:
        async with self.acur(**kwargs) as cur:
            await cur.execute(query, params=params)
            try:
                return await cur.fetchall()
            except psycopg.ProgrammingError as e:
                if "the last operation didn't produce a result" == str(e):
                    return None
                raise

    def psql(self, query, **kwargs):
        """Run an SQL query using psql instead of psycopg

        This opens a new connection and closes it once the query is done
        """

        self.set_default_connection_options(kwargs)
        connect_options = " ".join([f"{k}={v}" for k, v in kwargs.items()])

        run(["psql", f"port={self.port} {connect_options}", "-c", query], shell=False)

    @contextmanager
    def transaction(self, **kwargs):
        with self.cur(**kwargs) as cur:
            with cur.connection.transaction():
                yield cur

    def sleep(self, duration=3, **kwargs):
        """Run pg_sleep"""
        return self.sql(f"select pg_sleep({duration})", **kwargs)

    def asleep(self, duration=3, times=1, sequentially=False, **kwargs):
        """Run pg_sleep asynchronously in a task.

        times:
            You can create a single task that opens multiple connections, which
            run pg_sleep concurrently. The asynchronous task will only complete
            once all these pg_sleep calls are finished.
        sequentially:
            Instead of running all pg_sleep calls spawned by providing
            times > 1 concurrently, this will run them sequentially.
        """
        return asyncio.ensure_future(
            self.asleep_coroutine(
                duration=duration, times=times, sequentially=sequentially, **kwargs
            )
        )

    async def asleep_coroutine(self, duration=3, times=1, sequentially=False, **kwargs):
        """This is the coroutine that the asleep task runs internally"""
        if not sequentially:
            await asyncio.gather(
                *[
                    self.asql(f"select pg_sleep({duration})", **kwargs)
                    for _ in range(times)
                ]
            )
        else:
            for _ in range(times):
                await self.asql(f"select pg_sleep({duration})", **kwargs)

    def test(self, **kwargs):
        """Test if you can connect"""
        return self.sql("select 1", **kwargs)

    def atest(self, **kwargs):
        """Test if you can connect asynchronously"""
        return self.asql("select 1", **kwargs)

    def psql_test(self, **kwargs):
        """Test if you can connect with psql instead of psycopg"""
        return self.psql("select 1", **kwargs)

    @contextmanager
    def enable_firewall(self):
        """Enables the firewall for the platform that you are running

        Normally this should not be called directly, and instead drop_traffic
        or reject_traffic should be used.
        """
        fw_token = None
        if BSD:
            if MACOS:
                command_stderr = sudo(
                    f"pfctl -E", stderr=subprocess.PIPE, text=True
                ).stderr
                match = re.search(r"^Token : (\d+)", command_stderr, flags=re.MULTILINE)
                assert match is not None
                fw_token = match.group(1)
            sudo(
                'bash -c "'
                f"echo 'anchor \\\"port_{self.port}\\\"'"
                f' | pfctl -a pgbouncer_test -f -"'
            )
        try:
            yield
        finally:
            if MACOS:
                sudo(f"pfctl -X {fw_token}")

    @contextmanager
    def drop_traffic(self):
        """Drops all TCP packets to this query runner"""
        with self.enable_firewall():
            if LINUX:
                sudo(
                    "iptables --append OUTPUT "
                    "--protocol tcp "
                    f"--destination {self.host} "
                    f"--destination-port {self.port} "
                    "--jump DROP "
                )
            elif BSD:
                sudo(
                    "bash -c '"
                    f'echo "block drop out proto tcp from any to {self.host} port {self.port}"'
                    f"| pfctl -a pgbouncer_test/port_{self.port} -f -'"
                )
            else:
                raise Exception("This OS cannot run this test")
            try:
                yield
            finally:
                if LINUX:
                    sudo(
                        "iptables --delete OUTPUT "
                        "--protocol tcp "
                        f"--destination {self.host} "
                        f"--destination-port {self.port} "
                        "--jump DROP "
                    )
                elif BSD:
                    sudo(f"pfctl -a pgbouncer_test/port_{self.port} -F all")

    @contextmanager
    def reject_traffic(self):
        """Rejects all traffic to this query runner with a TCP RST message"""
        with self.enable_firewall():
            if LINUX:
                sudo(
                    "iptables --append OUTPUT "
                    "--protocol tcp "
                    f"--destination {self.host} "
                    f"--destination-port {self.port} "
                    "--jump REJECT "
                    "--reject-with tcp-reset"
                )
            elif BSD:
                sudo(
                    "bash -c '"
                    f'echo "block return-rst out out proto tcp from any to {self.host} port {self.port}"'
                    f"| pfctl -a pgbouncer_test/port_{self.port} -f -'"
                )
            else:
                raise Exception("This OS cannot run this test")
            try:
                yield
            finally:
                if LINUX:
                    sudo(
                        "iptables --delete OUTPUT "
                        "--protocol tcp "
                        f"--destination {self.host} "
                        f"--destination-port {self.port} "
                        "--jump REJECT "
                        "--reject-with tcp-reset"
                    )
                elif BSD:
                    sudo(f"pfctl -a pgbouncer_test/port_{self.port} -F all")

    @contextmanager
    def add_latency(self):
        """Adds one second of latency to all packets to this query runner"""
        if not LINUX:
            raise Exception("This OS cannot run this test")
        sudo(
            f"tc filter add dev lo parent 1:0 protocol ip prio {self.port} u32 match ip dport {self.port} 0xffff flowid 1:2"
        )
        try:
            yield
        finally:
            sudo(f"tc filter del dev lo parent 1: prio {self.port}")
            pass

    def create_user(self, name, args: typing.Optional[psycopg.sql.Composable] = None):
        self.users.add(name)
        if args is None:
            args = sql.SQL("")
        self.sql(sql.SQL("CREATE USER {} {}").format(sql.Identifier(name), args))

    def create_schema(self, name, dbname=None):
        dbname = dbname or self.default_db
        self.schemas.add((dbname, name))
        self.sql(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(name)))

    def create_publication(self, name: str, args: psycopg.sql.Composable, dbname=None):
        dbname = dbname or self.default_db
        self.publications.add((dbname, name))
        self.sql(sql.SQL("CREATE PUBLICATION {} {}").format(sql.Identifier(name), args))

    def create_logical_replication_slot(self, name, plugin):
        self.replication_slots.add(name)
        self.sql(
            "SELECT pg_catalog.pg_create_logical_replication_slot(%s,%s)",
            (name, plugin),
        )

    def create_physical_replication_slot(self, name):
        self.replication_slots.add(name)
        self.sql(
            "SELECT pg_catalog.pg_create_physical_replication_slot(%s)",
            (name,),
        )

    def create_subscription(self, name: str, args: psycopg.sql.Composable, dbname=None):
        dbname = dbname or self.default_db
        self.subscriptions.add((dbname, name))
        self.sql(
            sql.SQL("CREATE SUBSCRIPTION {} {}").format(sql.Identifier(name), args)
        )

    def cleanup_users(self):
        for user in self.users:
            self.sql(sql.SQL("DROP USER IF EXISTS {}").format(sql.Identifier(user)))

    def cleanup_schemas(self):
        for dbname, schema in self.schemas:
            self.sql(
                sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(
                    sql.Identifier(schema)
                ),
                dbname=dbname,
            )

    def cleanup_publications(self):
        for dbname, publication in self.publications:
            self.sql(
                sql.SQL("DROP PUBLICATION IF EXISTS {}").format(
                    sql.Identifier(publication)
                ),
                dbname=dbname,
            )

    def cleanup_replication_slots(self):
        for slot in self.replication_slots:
            start = time.time()
            while True:
                try:
                    self.sql(
                        "SELECT pg_drop_replication_slot(slot_name) FROM pg_replication_slots WHERE slot_name = %s",
                        (slot,),
                    )
                except psycopg.errors.ObjectInUse:
                    if time.time() < start + 10:
                        time.sleep(0.5)
                        continue
                    raise
                break

    def cleanup_subscriptions(self):
        for dbname, subscription in self.subscriptions:
            try:
                self.sql(
                    sql.SQL("ALTER SUBSCRIPTION {} DISABLE").format(
                        sql.Identifier(subscription)
                    ),
                    dbname=dbname,
                )
            except psycopg.errors.UndefinedObject:
                # Subscription didn't exist already
                continue
            self.sql(
                sql.SQL("ALTER SUBSCRIPTION {} SET (slot_name = NONE)").format(
                    sql.Identifier(subscription)
                ),
                dbname=dbname,
            )
            self.sql(
                sql.SQL("DROP SUBSCRIPTION {}").format(sql.Identifier(subscription)),
                dbname=dbname,
            )

    def debug(self):
        print("Connect manually to:\n   ", repr(self.make_conninfo()))
        print("Press Enter to continue running the test...")
        input()

    def psql_debug(self, **kwargs):
        conninfo = self.make_conninfo(**kwargs)
        run(
            ["psql", conninfo],
            silent=True,
        )


class Proxy(QueryRunner):
    def __init__(self, pg):
        self.port_lock = PortLock()
        super().__init__("127.0.0.1", self.port_lock.port)
        self.connections = {}
        self.pg = pg
        self.cursors = {}
        self.restarted = False
        self.process: typing.Optional[subprocess.Popen] = None

    def start(self):
        command = [
            "socat",
            f"tcp-listen:{self.port_lock.port},reuseaddr,fork",
            f"tcp:localhost:{self.pg.port_lock.port}",
        ]
        self.process = subprocess.Popen(" ".join(command), shell=True)

    def stop(self):
        self.process.kill()

    def cleanup(self):
        self.stop()
        self.port_lock.release()

    def restart(self):
        self.restarted = True
        self.stop()
        self.start()


class Postgres(QueryRunner):
    def __init__(self, pgdata):
        self.port_lock = PortLock()
        super().__init__("127.0.0.1", self.port_lock.port)
        self.pgdata = pgdata
        self.log_path = self.pgdata / "pg.log"
        self.connections = {}
        self.cursors = {}
        self.restarted = False

    def initdb(self):
        run(
            f"initdb -A trust --nosync --username postgres --pgdata {self.pgdata}",
            stdout=subprocess.DEVNULL,
        )

        with self.conf_path.open(mode="a") as pgconf:
            if USE_UNIX_SOCKETS:
                pgconf.write("unix_socket_directories = '/tmp'\n")
            pgconf.write("log_connections = on\n")
            pgconf.write("log_disconnections = on\n")
            pgconf.write("logging_collector = off\n")

            # Allow CREATE SUBSCRIPTION to work
            pgconf.write("wal_level = 'logical'\n")
            # Faster logical replication status update so tests with logical replication
            # run faster
            pgconf.write("wal_receiver_status_interval = 1\n")

            # Faster logical replication apply worker launch so tests with logical
            # replication run faster. This is used in ApplyLauncherMain in
            # src/backend/replication/logical/launcher.c.
            pgconf.write("wal_retrieve_retry_interval = '250ms'\n")

            # Make sure there's enough logical replication resources for our
            # tests
            if PG_MAJOR_VERSION >= 10:
                pgconf.write("max_logical_replication_workers = 5\n")
            pgconf.write("max_wal_senders = 5\n")
            pgconf.write("max_replication_slots = 10\n")
            pgconf.write("max_worker_processes = 20\n")

            # We need to make the log go to stderr so that the tests can
            # check what is being logged.  This should be the default, but
            # some packagings change the default configuration.
            pgconf.write("log_destination = stderr\n")
            # This makes tests run faster and we don't care about crash safety
            # of our test data.
            pgconf.write("fsync = false\n")

            # Use a consistent value across postgres versions, so test results
            # are the same.
            pgconf.write("extra_float_digits = 1\n")

            # Make sure this is consistent across platforms
            pgconf.write("datestyle = 'iso, mdy'\n")

            # Make PostgreSQL listen on both IPv4 and IPv6 (if supported)
            if HAVE_IPV6_LOCALHOST:
                pgconf.write("listen_addresses='127.0.0.1,::1'\n")

    def pgctl(self, command, **kwargs):
        run(f"pg_ctl -w --pgdata {self.pgdata} {command}", **kwargs)

    def apgctl(self, command, **kwargs):
        return asyncio.create_subprocess_shell(
            f"pg_ctl -w --pgdata {self.pgdata} {command}", **kwargs
        )

    def start(self):
        try:
            self.pgctl(f'-o "-p {self.port}" -l {self.log_path} start')
        except Exception:
            print("\n\nPG_LOG\n")
            with self.log_path.open() as f:
                print(f.read())
            raise

    def stop(self):
        self.pgctl("-m fast stop", check=False)

    def cleanup(self):
        self.stop()
        self.port_lock.release()

    def restart(self):
        self.restarted = True
        self.stop()
        self.start()

    def reload(self):
        if WINDOWS:
            # SIGHUP and thus reload don't exist on Windows
            self.restart()
        else:
            self.pgctl("reload")
        time.sleep(1)

    async def arestart(self):
        process = await self.apgctl("-m fast restart")
        await process.communicate()

    def nossl_access(self, dbname, auth_type, user="all"):
        """Prepends a local non-SSL access to the HBA file"""
        with self.hba_path.open() as pghba:
            old_contents = pghba.read()
        with self.hba_path.open(mode="w") as pghba:
            if USE_UNIX_SOCKETS:
                pghba.write(f"local {dbname}   {user}                {auth_type}\n")
            pghba.write(f"hostnossl  {dbname}   {user}  127.0.0.1/32  {auth_type}\n")
            pghba.write(f"hostnossl  {dbname}   {user}  ::1/128       {auth_type}\n")
            pghba.write(old_contents)

    def ssl_access(self, dbname, auth_type, user="all"):
        """Prepends a local SSL access rule to the HBA file"""
        with self.hba_path.open() as pghba:
            old_contents = pghba.read()
        with self.hba_path.open(mode="w") as pghba:
            pghba.write(f"hostssl  {dbname}   {user}  127.0.0.1/32  {auth_type}\n")
            pghba.write(f"hostssl  {dbname}   {user}  ::1/128       {auth_type}\n")
            pghba.write(old_contents)

    @property
    def hba_path(self):
        return self.pgdata / "pg_hba.conf"

    @property
    def conf_path(self):
        return self.pgdata / "postgresql.conf"

    def commit_hba(self):
        """Mark the current HBA contents as non-resettable by reset_hba"""
        with self.hba_path.open() as pghba:
            old_contents = pghba.read()
        with self.hba_path.open(mode="w") as pghba:
            pghba.write("# committed-rules\n")
            pghba.write(old_contents)

    def reset_hba(self):
        """Remove any HBA rules that were added after the last call to commit_hba"""
        with self.hba_path.open() as f:
            hba_contents = f.read()
        committed = hba_contents[hba_contents.find("# committed-rules\n") :]
        with self.hba_path.open("w") as f:
            f.write(committed)

    def connection_count(self, dbname=None, users=("bouncer",)):
        """Returns the number of connections that are active

        You can pass values for dbname and users to only count connections
        for a certain database and/or user(s).
        """
        dbname_filter = ""
        if dbname:
            dbname_filter = f" and datname='{dbname}'"
        return self.sql_value(
            f"select count(1) from pg_stat_activity where usename = ANY(%s) {dbname_filter}",
            params=(list(users),),
        )

    async def delayed_start(self, delay=1):
        """Start Postgres after a delay

        NOTE: The sleep is asynchronous, but while waiting for Postgres to
        start the pg_ctl start command will block the event loop. This is
        currently acceptable for our usage of this method in the existing
        tests and this way it was easiest to implement. However, it seems
        totally reasonable to change this behaviour in the future if necessary.
        """
        await asyncio.sleep(delay)
        self.start()

    def configure(self, config):
        """Configure specific Postgres settings using ALTER SYSTEM SET

        NOTE: after configuring a call to reload or restart is needed for the
        settings to become effective.
        """
        self.sql(f"alter system set {config}")

    @contextmanager
    def log_contains(self, re_string, times=None):
        """Checks if during this with block the log matches re_string

        re_string:
            The regex to search for.
        times:
            If None, any number of matches is accepted. If a number, only that
            specific number of matches is accepted.
        """
        with self.log_path.open() as f:
            f.seek(0, os.SEEK_END)
            yield
            content = f.read()
            if times is None:
                assert re.search(re_string, content)
            else:
                match_count = len(re.findall(re_string, content))
                assert match_count == times


class Bouncer(QueryRunner):
    def __init__(
        self,
        pg: Postgres,
        config_dir: Path,
        base_ini_path=BOUNCER_INI,
        base_auth_path=BOUNCER_AUTH,
        port=None,
    ):
        if port:
            self.port_lock = None
            super().__init__("127.0.0.1", port)
        else:
            self.port_lock = PortLock()
            super().__init__("127.0.0.1", self.port_lock.port)

        self.process: typing.Optional[subprocess.Popen] = None
        self.aprocess: typing.Optional[asyncio.subprocess.Process] = None
        config_dir.mkdir()
        self.config_dir = config_dir
        self.ini_path = self.config_dir / "test.ini"
        self.log_path = self.config_dir / "test.log"
        self.auth_path = self.config_dir / "userlist.txt"
        self.default_db = "p0"
        self.pg = pg

        if USE_UNIX_SOCKETS:
            if LINUX:
                # On Linux we do so_reuseport tests with multiple pgbouncer
                # processes listening on the same port. This requires that each
                # of the pgbouncer processes should have a unique
                # unix_socket_dir. We use the known-unique config_dir for this.
                # You would expect we could do the same for other platforms
                # too. But UNIX sockets cannot have paths longer than 103
                # characters on and the config_dir chosen by pytest on MacOS
                # exceeds this limit. So we use /tmp everywhere except for
                # Linux.
                self.admin_host = str(self.config_dir)
            else:
                self.admin_host = "/tmp"
        else:
            self.admin_host = "127.0.0.1"

        self.admin_runner = QueryRunner(self.admin_host, self.port)
        self.admin_runner.default_db = "pgbouncer"
        self.admin_runner.default_user = "pgbouncer"

        with open(base_auth_path) as base_auth:
            with self.auth_path.open("w") as auth:
                auth.write(base_auth.read())
                auth.write(f'"longpass" "{LONG_PASSWORD}"\n')
                auth.flush()

        with open(base_ini_path) as base_ini:
            with self.ini_path.open("w") as ini:
                ini.write(base_ini.read().replace("port=6666", f"port={pg.port}"))
                ini.write("\n")
                ini.write(f"logfile = {self.log_path}\n")
                ini.write(f"auth_file = {self.auth_path}\n")
                ini.write("pidfile = \n")
                # Uncomment for much more noise but, more detailed debugging
                # ini.write("verbose = 3\n")

                if not USE_UNIX_SOCKETS:
                    ini.write(f"unix_socket_dir = \n")
                    ini.write(f"admin_users = pgbouncer\n")
                else:
                    ini.write(f"unix_socket_dir = {self.admin_host}\n")
                ini.write(f"listen_port = {self.port}\n")

                ini.flush()

    def base_command(self):
        """returns the basecommand that is used to run PgBouncer

        This includes valgrind and all its arguments when ENABLE_VALGRIND is
        set
        """
        if ENABLE_VALGRIND:
            valgrind_log_file = self.config_dir / "valgrind.%p.log"
            return [
                "valgrind",
                "--quiet",
                "--leak-check=full",
                "--show-reachable=no",
                "--track-origins=yes",
                "--error-markers=VALGRIND-ERROR-BEGIN,VALGRIND-ERROR-END",
                f"--log-file={valgrind_log_file}",
                str(BOUNCER_EXE),
            ]
        return [str(BOUNCER_EXE)]

    async def start(self):
        # Due to using WindowsSelectorEventLoopPolicy for support with psycopg
        # we cannot use asyncio subprocesses. Since this eventloop does not
        # support it. We fall back to regular subprocesses.
        if WINDOWS:
            self.process = subprocess.Popen(
                [*self.base_command(), "--quiet", self.ini_path], close_fds=True
            )
        else:
            self.aprocess = await asyncio.create_subprocess_exec(
                *self.base_command(), "--quiet", str(self.ini_path), close_fds=True
            )
        await self.wait_until_running()

    async def wait_until_running(self):
        tries = 1
        while True:
            try:
                await self.aadmin("show version")
            except psycopg.Error:
                if tries > 50:
                    self.print_logs()
                    raise
                tries += 1
                time.sleep(0.1)
                continue
            break

    def admin(self, query, **kwargs):
        """Run an SQL query on the PgBouncer admin database"""
        return self.admin_runner.sql(query, **kwargs)

    def admin_value(self, query, **kwargs):
        """Run an SQL query on the PgBouncer admin database that returns only a
        single cell and return this value"""
        return self.admin_runner.sql_value(query, **kwargs)

    def aadmin(self, query, **kwargs):
        """Run an SQL query on the PgBouncer admin database in an asynchronous
        task"""
        return self.admin_runner.asql(query, **kwargs)

    def running(self):
        if self.process:
            return self.process.poll() is None
        if self.aprocess:
            return self.aprocess.returncode is None
        return False

    async def wait_for_exit(self):
        if self.process is not None:
            self.process.communicate()
            self.process.wait()
        if self.aprocess is not None:
            await self.aprocess.communicate()
            await self.aprocess.wait()
        self.process = None
        self.aprocess = None

    async def stop(self):
        if not WINDOWS:
            self.sigquit()
        else:
            # Windows does not have SIGQUIT, so call terminate() twice to
            # trigger fast exit
            if self.process is not None:
                self.process.terminate()
                self.process.terminate()
            if self.aprocess is not None:
                self.aprocess.terminate()
                self.aprocess.terminate()

        await self.wait_for_exit()

    async def reboot(self):
        """Starts a new PgBouncer with the --reboot flag

        This new PgBouncer process will replace the current process and take
        over its non-SSL sockets.
        """
        assert self.aprocess is not None or self.process is not None
        if self.aprocess:
            old_process = self.aprocess
            old_pid = old_process.pid
            self.aprocess = await asyncio.create_subprocess_exec(
                *self.base_command(),
                "--reboot",
                "--quiet",
                str(self.ini_path),
                close_fds=True,
            )
            await old_process.communicate()
            await old_process.wait()
            await self.wait_until_running()
            assert self.aprocess.pid != old_pid
        if self.process:
            old_process = self.process
            old_pid = old_process.pid
            self.process = subprocess.Popen(
                [*self.base_command(), "--reboot", "--quiet", self.ini_path],
                close_fds=True,
            )
            old_process.communicate()
            old_process.wait()
            await self.wait_until_running()
            assert self.process.pid != old_pid

    def send_signal(self, sig):
        if self.aprocess:
            self.aprocess.send_signal(sig)
        if self.process:
            self.process.send_signal(sig)

    def sighup(self):
        self.send_signal(signal.SIGHUP)
        time.sleep(1)

    def sigterm(self):
        self.send_signal(signal.SIGTERM)

    def sigint(self):
        self.send_signal(signal.SIGINT)

    def sigquit(self):
        self.send_signal(signal.SIGQUIT)

    def sigusr2(self):
        self.send_signal(signal.SIGUSR2)

    def print_logs(self):
        print(f"\n\nBOUNCER_LOG {self.config_dir}\n")

        log_contents = ""
        try:
            with self.log_path.open() as f:
                log_contents = f.read()
                print(log_contents)
        except Exception:
            pass

        # Most reliable way to detect Assert failures. Otherwise we might miss
        # Assert failures at the end of the test run.
        assert not re.search("FATAL.*Assert", log_contents)
        # None of our tests should have a query in progress on the server when
        # the client disconnects. If this fails it almost certainly indicates a
        # bug in our outstanding request tracking.
        assert "client disconnected with query in progress" not in log_contents

        if ENABLE_VALGRIND:
            failed_valgrind = False
            for valgrind_log in self.config_dir.glob("valgrind.*.log"):
                with valgrind_log.open() as f:
                    contents = f.read()
                    if "VALGRIND-ERROR" in contents:
                        failed_valgrind = True
                        print(f"\n\nVALGRIND LOG {valgrind_log}\n")
                        print(contents)
            assert not failed_valgrind

    async def cleanup(self):
        try:
            cleanup_test_leftovers(self)
            await self.stop()
        finally:
            self.print_logs()

        if self.port_lock:
            self.port_lock.release()

    def write_ini(self, config):
        """Writes a config to the ini file of this PgBouncer

        It appends a newline automatically. To apply these changes PgBouncer
        still needs to be reloaded or restarted. To reload in a cross platform
        way you need can use admin("reload").
        """
        with self.ini_path.open("a") as f:
            f.write(config + "\n")

    @contextmanager
    def log_contains(self, re_string, times=None):
        """Checks if during this with block the log matches re_string

        re_string:
            The regex to search for.
        times:
            If None, any number of matches is accepted. If a number, only that
            specific number of matches is accepted.
        """
        with self.log_path.open() as f:
            f.seek(0, os.SEEK_END)
            yield
            content = f.read()
            if times is None:
                assert re.search(re_string, content)
            else:
                match_count = len(re.findall(re_string, content))
                assert match_count == times

    @contextmanager
    def run_with_config(self, config):
        """Run the pgbouncer instance with provided config and restore the
        previous config after execution

        config:
            A new pgbouncer config in ini format
        """
        with self.ini_path.open("r") as f:
            config_old = f.read()

        with self.ini_path.open("w") as f:
            f.write(config)

        try:
            self.admin("RELOAD")
            yield self
        finally:
            # Code to release resource, e.g.:
            with self.ini_path.open("w") as f:
                f.write(config_old)
            self.admin("RELOAD")


class OpenLDAP:
    def __init__(self, config_dir):
        self.port_lock = PortLock()
        self.config_dir = config_dir
        self.slapd_pid_file = self.config_dir / "ldap" / "slapd.pid"

    def startup(self):
        run(f"{START_OPENLDAP_SCRIPT} {self.config_dir} {self.port_lock.port}")

    @property
    def ldap_port(self):
        return self.port_lock.port

    def stop(self):
        with self.slapd_pid_file.open("r") as pid_file:
            pid = pid_file.read()
        os.kill(int(pid), signal.SIGTERM)

    def cleanup(self):
        self.stop()
        self.port_lock.release()
