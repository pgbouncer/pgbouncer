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
import signal
import socket
import sys
import time
import typing
from tempfile import gettempdir

import filelock
import psycopg

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


def run(command, *args, check=True, shell=True, silent=False, **kwargs):
    """run runs the given command and prints it to stderr"""

    if not silent:
        eprint(f"+ {command} ")
    if silent:
        kwargs.setdefault("stdout", subprocess.DEVNULL)
    return subprocess.run(command, *args, check=check, shell=shell, **kwargs)


def sudo(command, *args, shell=True, **kwargs):
    """
    A version of run that prefixes the command with sudo when the process is
    not already run as root
    """
    effective_user_id = os.geteuid()
    if effective_user_id == 0:
        return run(command, *args, shell=shell, **kwargs)
    if shell:
        return run(f"sudo {command}", *args, shell=shell, **kwargs)
    else:
        return run(["sudo", *command])


def get_pg_major_version():
    full_version_string = run(
        "initdb --version", stdout=subprocess.PIPE, encoding="utf-8", silent=True
    ).stdout
    major_version_string = re.search("[0-9]+", full_version_string)
    assert major_version_string is not None
    return int(major_version_string.group(0))


PG_MAJOR_VERSION = get_pg_major_version()


def get_max_password_length():
    with open("../include/bouncer.h", encoding="utf-8") as f:
        match = re.search(r"#define MAX_PASSWORD\s+([0-9])", f.read())
        assert match is not None
        max_password_length = int(match.group(1))

    if max_password_length > 996 and PG_MAJOR_VERSION < 14:
        return 996
    return max_password_length


MAX_PASSWORD_LENGTH = get_max_password_length()
LONG_PASSWORD = "a" * MAX_PASSWORD_LENGTH

PG_SUPPORTS_SCRAM = PG_MAJOR_VERSION >= 10


def get_tls_support():
    with open("../config.mak", encoding="utf-8") as f:
        match = re.search(r"tls_support = (\w+)", f.read())
        assert match is not None
        return match.group(1) == "yes"


TLS_SUPPORT = get_tls_support()


# this is out of ephemeral port range for many systems hence
# it is a lower change that it will conflict with "in-use" ports
PORT_LOWER_BOUND = 10200

# ephemeral port start on many Linux systems
PORT_UPPER_BOUND = 32768

next_port = PORT_LOWER_BOUND


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


class QueryRunner:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.default_db = "postgres"
        self.default_user = "postgres"

    def set_default_connection_options(self, options):
        options.setdefault("dbname", self.default_db)
        options.setdefault("user", self.default_user)
        if ENABLE_VALGRIND:
            # If valgrind is enabled PgBouncer is a significantly slower to
            # respond to connection requests, so we wait a little longer.
            options.setdefault("connect_timeout", 20)
        else:
            options.setdefault("connect_timeout", 3)
        # needed for Ubuntu 18.04
        options.setdefault("client_encoding", "UTF8")

    def conn(self, *, autocommit=True, **kwargs):
        """Open a psycopg connection to this server"""
        self.set_default_connection_options(kwargs)
        return psycopg.connect(
            autocommit=autocommit,
            host=self.host,
            port=self.port,
            **kwargs,
        )

    def aconn(self, *, autocommit=True, **kwargs):
        """Open an asynchronous psycopg connection to this server"""
        self.set_default_connection_options(kwargs)
        return psycopg.AsyncConnection.connect(
            autocommit=autocommit,
            host=self.host,
            port=self.port,
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

    def test(self, query="select 1", **kwargs):
        """Test if you can connect"""
        return self.sql(query, **kwargs)

    def atest(self, query="select 1", **kwargs):
        """Test if you can connect asynchronously"""
        return self.asql(query, **kwargs)

    def psql_test(self, query="select 1", **kwargs):
        """Test if you can connect with psql instead of psycopg"""
        return self.psql(query, **kwargs)

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


class Postgres(QueryRunner):
    def __init__(self, pgdata):
        self.port_lock = PortLock()
        super().__init__("127.0.0.1", self.port_lock.port)
        self.pgdata = pgdata
        self.log_path = self.pgdata / "pg.log"
        self.connections = {}
        self.cursors = {}

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
            # We need to make the log go to stderr so that the tests can
            # check what is being logged.  This should be the default, but
            # some packagings change the default configuration.
            pgconf.write("log_destination = stderr\n")
            # This makes tests run faster and we don't care about crash safety
            # of our test data.
            pgconf.write("fsync = false\n")

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

    def nossl_access(self, dbname, auth_type):
        """Prepends a local non-SSL access to the HBA file"""
        with self.hba_path.open() as pghba:
            old_contents = pghba.read()
        with self.hba_path.open(mode="w") as pghba:
            if USE_UNIX_SOCKETS:
                pghba.write(f"local {dbname}   all                {auth_type}\n")
            pghba.write(f"hostnossl  {dbname}   all  127.0.0.1/32  {auth_type}\n")
            pghba.write(f"hostnossl  {dbname}   all  ::1/128       {auth_type}\n")
            pghba.write(old_contents)

    def ssl_access(self, dbname, auth_type):
        """Prepends a local SSL access rule to the HBA file"""
        with self.hba_path.open() as pghba:
            old_contents = pghba.read()
        with self.hba_path.open(mode="w") as pghba:
            pghba.write(f"hostssl  {dbname}   all  127.0.0.1/32  {auth_type}\n")
            pghba.write(f"hostssl  {dbname}   all  ::1/128       {auth_type}\n")
            pghba.write(old_contents)

    @property
    def hba_path(self):
        return self.pgdata / "pg_hba.conf"

    @property
    def conf_path(self):
        return self.pgdata / "postgresql.conf"

    def commit_hba(self):
        """Mark the current HBA contents as non-resetable by reset_hba"""
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


class Bouncer(QueryRunner):
    def __init__(
        self,
        pg: Postgres,
        config_dir: Path,
        base_ini_path=BOUNCER_INI,
        base_auth_path=BOUNCER_AUTH,
    ):
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

    async def stop(self):
        if self.process is not None:
            self.process.terminate()
            self.process.communicate()
            self.process.wait()
        if self.aprocess is not None:
            self.aprocess.terminate()
            await self.aprocess.communicate()
            await self.aprocess.wait()
        self.process = None
        self.aprocess = None

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

    def sighup(self):
        if self.aprocess:
            self.aprocess.send_signal(signal.SIGHUP)
        if self.process:
            self.process.send_signal(signal.SIGHUP)
        time.sleep(1)

    def print_logs(self):
        print("\n\nBOUNCER_LOG\n")
        try:
            with self.log_path.open() as f:
                print(f.read())
        except Exception:
            pass

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
        await self.stop()
        self.print_logs()

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
