from pathlib import Path
import subprocess
from contextlib import contextmanager, closing

try:
    from contextlib import asynccontextmanager
except ImportError:
    # Fallback for python3.6
    from contextlib2 import asynccontextmanager

import psycopg
import os
import re
import sys
import shutil
import time
import asyncio
import socket
from tempfile import TemporaryDirectory


TEST_DIR = Path(os.path.dirname(os.path.realpath(__file__)))
os.chdir(TEST_DIR)

PGDATA = TEST_DIR / "pgdata"
PGHOST = "127.0.0.1"
PGPORT = 6667

BOUNCER_LOG = TEST_DIR / "test.log"
BOUNCER_INI = TEST_DIR / "test.ini"
BOUNCER_PID = TEST_DIR / "test.pid"
BOUNCER_PORT = 6667
BOUNCER_EXE = TEST_DIR / "../pgbouncer"

LOGDIR = TEST_DIR / "log"
PG_PORT = 6666
PG_LOG = LOGDIR / "pg.log"

PG_CONF = PGDATA / "postgresql.conf"
PG_HBA = PGDATA / "pg_hba.conf"

# The tests require that psql can connect to the PgBouncer admin
# console.  On platforms that have getpeereid(), this works by
# connecting as user pgbouncer over the Unix socket.  On other
# platforms, we have to rely on "trust" authentication, but then we
# have to skip any tests that use authentication methods other than
# "trust".
if os.name == "nt":
    USE_UNIX_SOCKETS = False
    HAVE_GETPEEREID = False
    from asyncio import WindowsSelectorEventLoopPolicy
    asyncio.set_event_loop_policy(WindowsSelectorEventLoopPolicy())
else:
    USE_UNIX_SOCKETS = True
    HAVE_GETPEEREID = True


def eprint(*args, **kwargs):
    """eprint prints to stderr"""

    print(*args, file=sys.stderr, **kwargs)


def run(command, *args, check=True, shell=True, **kwargs):
    """run runs the given command and prints it to stderr"""

    eprint(f"+ {command} ")
    return subprocess.run(command, *args, check=check, shell=shell, **kwargs)

next_port = 49152
PORT_UPPER_BOUND = 65536

def get_free_port():
    global next_port
    if next_port < PORT_UPPER_BOUND:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
            try:
                s.bind(("127.0.0.1", next_port))
                port = next_port
                next_port += 1
                return port
            except:
                next_port += 1
    # we couldn't find a port
    raise Exception("Couldn't find a port to use")

class QueryRunner:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.connections = {}
        self.cursors = {}
        self.default_db = "postgres"
        self.default_user = "postgres"

    def aconn(self, dbname=None, user=None, autocommit=True):
        if dbname is None:
            dbname = self.default_db

        if user is None:
            user = self.default_user

        return psycopg.AsyncConnection.connect(
            f"dbname={dbname} user={user} host={self.host} port={self.port}",
            autocommit=autocommit,
        )

    def conn(self, dbname=None, user=None, cached=True, autocommit=True, connect_timeout=3):
        if dbname is None:
            dbname = self.default_db

        if user is None:
            user = self.default_user

        if not cached or not autocommit:
            return psycopg.connect(
                f"dbname={dbname} user={user} host={self.host} port={self.port} connect_timeout={connect_timeout}",
                autocommit=autocommit,
            )
        conn = self.connections.get((dbname, user))
        if conn:
            return conn

        conn = self.conn(dbname, user, cached=False)
        self.connections[(dbname, user)] = conn
        return conn

    @contextmanager
    def cur(self, dbname=None, user=None, autocommit=True, connect_timeout=3):
        with self.conn(dbname, user, cached=False, autocommit=autocommit, connect_timeout=connect_timeout) as conn:
            with conn.cursor() as cur:
                yield cur

    @asynccontextmanager
    async def acur(self, dbname=None, user=None, autocommit=True):
        async with await self.aconn(dbname, user, autocommit=autocommit) as conn:
            async with conn.cursor() as cur:
                yield cur

    async def asql(self, query, dbname=None, user=None):
        async with self.acur(dbname, user) as cur:
            await cur.execute(query)

    def sql(self, query, dbname=None, user=None):
        cur = self.cursors.get((dbname, user))
        if not cur:
            cur = self.conn(dbname, user).cursor()
            self.cursors[(dbname, user)] = cur
        return cur.execute(query)

    def sql_oneshot(self, query, dbname=None, user=None, connect_timeout=3):
        with self.cur(dbname, user, connect_timeout=connect_timeout) as cur:
            cur.execute(query)

    def cleanup(self):
        for cur in self.cursors.values():
            cur.close()
        for conn in self.connections.values():
            conn.close()
        self.cursors = {}
        self.connections = {}

    @contextmanager
    def transaction(self, dbname=None, user=None):
        with self.cur(dbname, user) as cur:
            with cur.connection.transaction():
                yield cur


class Postgres(QueryRunner):
    def __init__(self, pgdata, port, log_path):
        super().__init__("127.0.0.1", port)
        self.pgdata = pgdata
        self.log_path = log_path
        self.connections = {}
        self.cursors = {}

    def initdb(self):
        self.cleanup()
        run(
            f"initdb -A trust --nosync --username postgres --pgdata {PGDATA}",
            stdout=subprocess.DEVNULL,
        )

        with self.conf_path.open(mode="a") as pgconf:
            if USE_UNIX_SOCKETS:
                pgconf.write("unix_socket_directories = '/tmp'\n")
            pgconf.write("log_connections = on\n")
            pgconf.write("logging_collector = off\n")
            # We need to make the log go to stderr so that the tests can
            # check what is being logged.  This should be the default, but
            # some packagings change the default configuration.
            pgconf.write("log_destination = stderr\n")

    def pgctl(self, command, **kwargs):
        run(f"pg_ctl -w --pgdata {self.pgdata} {command}", **kwargs)

    def start(self):
        try:
            self.pgctl(f'-o "-p {self.port}" -l {self.log_path} start')
        except:
            print("\n\nPG_LOG\n")
            with self.log_path.open() as f:
                print(f.read())
            print("\n\nPG_CONF\n")
            with self.conf_path.open() as f:
                print(f.read())
            raise

    def stop(self):
        self.pgctl("-m fast stop", check=False)

    def cleanup(self):
        super().cleanup()

        if not self.pgdata.exists():
            return

        self.stop()
        shutil.rmtree(self.pgdata)

    def allow_local_access(self, dbname, auth_type):
        with self.hba_path.open(mode="a") as pghba:
            if USE_UNIX_SOCKETS:
                pghba.write(f"local {dbname}   all                {auth_type}\n")
            pghba.write(f"host  {dbname}   all  127.0.0.1/32  {auth_type}\n")
            pghba.write(f"host  {dbname}   all  ::1/128       {auth_type}\n")

    @property
    def hba_path(self):
        return self.pgdata / "pg_hba.conf"

    @property
    def conf_path(self):
        return self.pgdata / "postgresql.conf"

    def connection_count(self):
        result = self.sql(
            "select count(1) from pg_stat_activity where usename='bouncer'"
        )
        row = result.fetchone()
        assert row is not None
        return row[0]

    async def delayed_start(self, delay=1):
        await asyncio.sleep(delay)
        self.start()


class Bouncer(QueryRunner):
    def __init__(self, port, base_ini_path=BOUNCER_INI):
        super().__init__("127.0.0.1", port)
        self.process = None
        self.temp_dir = TemporaryDirectory(prefix='pgbouncer-test-')
        self.temp_dir_path = Path(self.temp_dir.name)
        self.ini_path = self.temp_dir_path / 'test.ini'
        self.log_path = self.temp_dir_path / 'test.log'

        if USE_UNIX_SOCKETS:
            self.admin_host = '/tmp'
        else:
            self.admin_host = '127.0.0.1'

        self.admin_runner = QueryRunner(self.admin_host, port)
        self.admin_runner.default_db = "pgbouncer"
        self.admin_runner.default_user = "pgbouncer"

        with open(base_ini_path) as base_ini:
            with self.ini_path.open('w') as ini:
                ini.write(base_ini.read())
                ini.write("\n")
                ini.write(f"logfile = {self.log_path}\n")

                if not USE_UNIX_SOCKETS:
                    ini.write(f"unix_socket_dir = ''\n")
                    ini.write(f"admin_users = pgbouncer\n")
                else:
                    ini.write(f"unix_socket_dir = {self.admin_host}\n")


                ini.flush()


    def start(self):
        self.process = subprocess.Popen([BOUNCER_EXE, "--quiet", self.ini_path], close_fds=True)
        tries = 1
        while True:
            try:
                self.admin_oneshot("show version")
            except psycopg.Error:
                if tries > 50:
                    raise
                self.print_logs()
                tries += 1
                time.sleep(0.1)
                continue
            break

    def admin(self, query):
        self.admin_runner.sql(query)

    def admin_oneshot(self, query, connect_timeout=3):
        return self.admin_runner.sql_oneshot(query, connect_timeout=connect_timeout)

    def stop(self):
        if self.process is None:
            return

        self.process.terminate()
        self.process.communicate()
        self.process.wait()
        self.process = None

    def print_logs(self):
        print("\n\nBOUNCER_LOG\n")
        try:
            with self.log_path.open() as f:
                print(f.read())
        except Exception:
            pass


    def cleanup(self):
        super().cleanup()
        self.admin_runner.cleanup()
        self.stop()
        self.print_logs()

        self.temp_dir.cleanup()

    @contextmanager
    def log_contains(self, re_string):
        with self.log_path.open() as f:
            f.seek(0, os.SEEK_END)
            yield
            content = f.read()
            assert re.search(re_string, content)
