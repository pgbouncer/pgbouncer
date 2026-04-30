"""Load balancing test utilities.

Provides a mini-language interpreter for testing connection distribution
across multiple backend hosts.

Scenario language:
    +N       create N connections
    +N<x>    create N connections and assert each lands on host <x>
    -N<x>    close N connections from host <x> (a, b, ...)
    =N<x>    assert host <x> has N connections
    R        reboot (online restart / takeover)
    (...)    grouping (execute contents once)
    N*(...)  repeat sub-sequence N times
    # ...    comment (to end of line)

Servers are assigned letters a, b, c, ... in discovery order.
"""

import asyncio
import warnings
from .utils import Bouncer


def get_server_addrs(bouncer, database):
    """Get list of server addresses from SHOW SERVERS."""
    with bouncer.admin_runner.cur() as cur:
        cur.execute("SHOW SERVERS")
        cols = [desc[0] for desc in cur.description]
        results = cur.fetchall()
        db_idx, addr_idx = cols.index("database"), cols.index("addr")
        return [r[addr_idx] for r in results if r[db_idx] == database]


def get_server_addr_by_pid(bouncer, database, remote_pid):
    """Get server address for a specific backend PID."""
    with bouncer.admin_runner.cur() as cur:
        cur.execute("SHOW SERVERS")
        cols = [desc[0] for desc in cur.description]
        results = cur.fetchall()
        db_idx = cols.index("database")
        addr_idx = cols.index("addr")
        pid_idx = cols.index("remote_pid")
        for r in results:
            if r[db_idx] == database and r[pid_idx] == remote_pid:
                return r[addr_idx]
        return None


class BouncerConnectionChecker:
    """Interpreter for test scenario mini-language."""

    def __init__(self, pg, tmp_path, database="pool_lb_test"):
        self.pg = pg
        self.tmp_path = tmp_path
        self.bouncer = None
        self.database = database
        self.conns = []
        self.ops = []
        self.addr_to_letter = {}
        self.letter_to_addr = {}
        self.assertion_count = 0
        self.last_op_type = None

    async def _ensure_bouncer(self):
        if self.bouncer is None:
            self.bouncer = Bouncer(self.pg, self.tmp_path / "bouncer")
            with self.bouncer.ini_path.open("r") as f:
                ini_content = f.read()
            db_entry = (
                f"{self.database} = host=127.0.0.1,::1 port={self.pg.port} dbname=p0 "
                f"pool_size=20 pool_mode=session load_balance_hosts=round-robin\n"
            )
            # Increase max_client_conn for tests that create many connections
            ini_content = ini_content.replace("max_client_conn = 10", "max_client_conn = 50")
            ini_content = ini_content.replace("[databases]\n", f"[databases]\n{db_entry}")
            with self.bouncer.ini_path.open("w") as f:
                f.write(ini_content)
            await self.bouncer.start()

    def _get_host_letter(self, addr):
        if addr not in self.addr_to_letter:
            letter = chr(ord('a') + len(self.addr_to_letter))
            self.addr_to_letter[addr] = letter
            self.letter_to_addr[letter] = addr
        return self.addr_to_letter[addr]

    def _refresh_conn_hosts(self):
        """Update host letters for any new addresses seen in SHOW SERVERS."""
        addrs = get_server_addrs(self.bouncer, self.database)
        for addr in addrs:
            self._get_host_letter(addr)

    def _assert(self, condition, msg):
        if not condition:
            raise AssertionError(f"{' '.join(self.ops)} {msg}")

    def connect(self, n, expected_host=None):
        if expected_host:
            self.ops.append(f"+{n}{expected_host}")
            self.last_op_type = "assert"
            self.assertion_count += 1
        else:
            self.ops.append(f"+{n}")
            self.last_op_type = "connect"
        for i in range(n):
            conn = self.bouncer.conn(dbname=self.database, user="bouncer")
            with conn.cursor() as cur:
                cur.execute("SELECT pg_backend_pid()")
                backend_pid = cur.fetchone()[0]
            # Look up server address by backend PID
            addr = get_server_addr_by_pid(self.bouncer, self.database, backend_pid)
            if addr:
                self._get_host_letter(addr)
            self.conns.append((conn, addr))
            if expected_host:
                expected_addr = self.letter_to_addr.get(expected_host)
                self._assert(expected_addr is not None, f"-> unknown host '{expected_host}'")
                actual_letter = self.addr_to_letter.get(addr)
                self._assert(
                    addr == expected_addr,
                    f"-> connection {i + 1} expected on {expected_host}, got {actual_letter}"
                )

    def disconnect(self, n, host_letter):
        self.ops.append(f"-{n}{host_letter}")
        self.last_op_type = "disconnect"
        host_addr = self.letter_to_addr.get(host_letter)
        self._assert(host_addr is not None, f"-> unknown host '{host_letter}'")
        closed, remaining = 0, []
        for conn, addr in self.conns:
            if addr == host_addr and closed < n:
                conn.close()
                closed += 1
            else:
                remaining.append((conn, addr))
        self.conns = remaining
        self._assert(closed == n, f"-> wanted {n} from {host_letter}, found {closed}")

    def assert_host_count(self, n, host_letter):
        self.last_op_type = "assert"
        self.assertion_count += 1
        self._refresh_conn_hosts()
        host_addr = self.letter_to_addr.get(host_letter)
        if host_addr is None and n == 0:
            return
        self._assert(host_addr is not None, f"-> unknown host '{host_letter}'")
        actual = sum(1 for _, addr in self.conns if addr == host_addr)
        self._assert(actual == n, f"-> expected {n} on {host_letter}, got {actual}")

    async def reboot(self):
        self.ops.append("R")
        self.last_op_type = "reboot"
        await self.bouncer.reboot()
        await asyncio.sleep(0.5)
        for conn, _ in self.conns:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
        self._refresh_conn_hosts()

    async def cleanup(self):
        for conn, _ in self.conns:
            conn.close()
        self.conns = []
        if self.bouncer:
            await self.bouncer.cleanup()
            self.bouncer = None

    async def run(self, code):
        """Parse and execute a scenario string."""
        self.conns = []
        self.ops = []
        self.addr_to_letter = {}
        self.letter_to_addr = {}
        self.assertion_count = 0
        self.last_op_type = None
        await self._ensure_bouncer()
        try:
            await self._eval(code, 0, len(code))
            if self.assertion_count == 0:
                raise ValueError(f"scenario has no assertions: {code}")
            if self.last_op_type != "assert":
                warnings.warn(f"scenario does not end with assertion: {code}")
        finally:
            for conn, _ in self.conns:
                conn.close()
            self.conns = []

    async def _eval(self, code, pos, end):
        while pos < end:
            # Skip whitespace and comments
            while pos < end:
                if code[pos].isspace():
                    pos += 1
                elif code[pos] == '#':
                    # Skip to end of line
                    while pos < end and code[pos] != '\n':
                        pos += 1
                else:
                    break
            if pos >= end:
                break
            c = code[pos]
            if c == '+':
                n, pos = self._num(code, pos + 1, end)
                if pos < end and code[pos].isalpha():
                    self.connect(n, code[pos]); pos += 1
                else:
                    self.connect(n)
            elif c == '-':
                n, pos = self._num(code, pos + 1, end)
                self.disconnect(n, code[pos]); pos += 1
            elif c == '=':
                n, pos = self._num(code, pos + 1, end)
                self.assert_host_count(n, code[pos]); pos += 1
            elif c == 'R':
                await self.reboot(); pos += 1
            elif c == '(':
                close = self._match_paren(code, pos, end)
                await self._eval(code, pos + 1, close)
                pos = close + 1
            elif c.isdigit():
                n, pos = self._num(code, pos, end)
                assert code[pos:pos+2] == '*(', f"parse error at {pos}"
                close = self._match_paren(code, pos + 1, end)
                for _ in range(n):
                    await self._eval(code, pos + 2, close)
                pos = close + 1
            else:
                raise ValueError(f"parse error at {pos}")
        return pos

    def _num(self, code, pos, end):
        start = pos
        while pos < end and code[pos].isdigit():
            pos += 1
        return int(code[start:pos]), pos

    def _match_paren(self, code, pos, end):
        depth = 1
        pos += 1
        while pos < end and depth:
            if code[pos] == '(': depth += 1
            elif code[pos] == ')': depth -= 1
            pos += 1
        return pos - 1


def scenario(fn):
    """Decorator for mini-language test scenarios.

    Usage:
        @scenario
        def test_name():
            '''Docstring describing the test'''
            return "+4 =2a =2b"
    """
    async def wrapper(pg, tmp_path):
        runner = BouncerConnectionChecker(pg, tmp_path)
        code = fn()
        try:
            await runner.run(code)
        finally:
            await runner.cleanup()
    wrapper.__name__ = fn.__name__
    wrapper.__doc__ = fn.__doc__
    return wrapper
