# USDT / DTrace static tracepoints

PgBouncer can be built with static userland tracepoints (USDT), the same
mechanism PostgreSQL exposes through its `--enable-dtrace` option. They let
external tracing tools (bpftrace, `perf`, SystemTap, DTrace) observe internal
events -- most usefully, which backend connection a client transaction was
linked to -- without changing the bytes sent to PostgreSQL and without relying
on fragile uprobe offsets.

The probes compile to a single `nop` plus an ELF note. When no tracer is
attached, each probe's `_ENABLED()` guard skips even the argument formatting,
so the runtime cost is effectively zero. When the feature is not built in at
all, the probe call sites expand to nothing.

## Building

The feature is **off by default**. Enabling it needs the `dtrace` tool. On
Linux that is provided by `systemtap-sdt-dev` (Debian/Ubuntu) or
`systemtap-sdt-devel` (RHEL/Fedora). On platforms with a native DTrace
(macOS, FreeBSD, illumos) the system `dtrace` is used.

meson:

    meson setup build -Ddtrace=enabled
    ninja -C build

autoconf:

    ./configure --enable-dtrace
    make

When disabled, a dummy `probes.h` of empty macros is generated instead, so the
source always compiles with or without the tool present.

## Probes

Provider: `pgbouncer`. All addresses are rendered as strings; ports are
integers; durations are unsigned microseconds.

| Probe | Arguments |
|-------|-----------|
| `client__connect` | client_addr, client_port |
| `client__disconnect` | client_addr, client_port, dbname, username, reason |
| `client__login__attempt` | client_addr, client_port, dbname, username, auth_method |
| `client__login__success` | client_addr, client_port, dbname, username, auth_method |
| `client__login__failure` | client_addr, client_port, dbname, username, auth_method, reason |
| `client__wait__start` | client_addr, client_port, dbname, username |
| `client__wait__end` | client_addr, client_port, dbname, username, duration |
| `client__query__start` | client_addr, client_port, dbname, username |
| `client__query__ready` | client_addr, client_port, dbname, username, duration |
| `client__server__linked` | client_addr, client_port, server_addr, server_port, dbname, username |
| `client__server__unlinked` | client_addr, client_port, server_addr, server_port, dbname, username |
| `server__connect` | server_addr, server_port, dbname, username |
| `server__ready` | server_addr, server_port, dbname, username, duration |
| `server__disconnect` | server_addr, server_port, dbname, username, reason |

`client__server__linked` / `client__server__unlinked` are balanced for query
connections: every link reported is eventually unlinked. Cancel-request links
are not reported.

Note on pairing:

* A client that is closed before finishing login produces a
  `client__login__failure` and a `client__disconnect` but no
  `client__login__success`.
* `server__disconnect` also fires for connection attempts that failed before
  `server__connect` (e.g. connect timeouts), so a disconnect may have no
  matching connect.
* `server__connect` fires when the socket connects; `server__ready`
  fires only once the backend is authenticated, the startup parameters are in,
  and any `connect_query` has run — i.e. the connection is ready to serve
  clients. Its `ready_us` is measured from when the connection was
  launched, so it covers TCP/TLS connect, authentication, startup parameters,
  and any `connect_query`. A backend that fails during login reports
  `server__disconnect` but no `server__ready`.

### Admin / control-command probes

These fire when an operator issues a process-control command on the admin
console. `client_addr` / `client_port` / `username` identify the admin
connection that issued it (`unix:...` for a Unix-socket connection; the admin
console is always the `pgbouncer` database, which is why the connection db is
not carried). `dbname` is the target database, or `""` when the command applies
to all databases. Read-only commands (`SHOW` / `SELECT`) are deliberately not
traced.

| Probe | Arguments |
|-------|-----------|
| `admin__pause` | client_addr, client_port, username, dbname |
| `admin__resume` | client_addr, client_port, username, dbname |
| `admin__reload` | client_addr, client_port, username |
| `admin__shutdown` | client_addr, client_port, username, mode |
| `admin__reconnect` | client_addr, client_port, username, dbname |
| `admin__kill` | client_addr, client_port, username, dbname |
| `admin__kill_client` | client_addr, client_port, username, id |
| `admin__disable` | client_addr, client_port, username, dbname |
| `admin__enable` | client_addr, client_port, username, dbname |
| `admin__wait_close` | client_addr, client_port, username, dbname |

## Listing the probes

    # with the binary built
    bpftrace -l 'usdt:/path/to/pgbouncer:*'

    # or straight from the ELF notes
    readelf -n /path/to/pgbouncer | grep -A2 stapsdt

## Example: tie a client transaction to its PostgreSQL backend

The headline use case. In transaction pooling the client-to-server mapping
exists only inside PgBouncer; this prints it as it changes.

```
#!/usr/bin/env bpftrace
// trace-link.bt  —  run as root:  bpftrace trace-link.bt -p $(pgrep -x pgbouncer)

usdt:/usr/local/bin/pgbouncer:pgbouncer:client__server__linked
{
    printf("LINK   %s:%d -> %s:%d  db=%s user=%s\n",
           str(arg0), arg1, str(arg2), arg3, str(arg4), str(arg5));
}

usdt:/usr/local/bin/pgbouncer:pgbouncer:client__server__unlinked
{
    printf("UNLINK %s:%d -> %s:%d  db=%s user=%s\n",
           str(arg0), arg1, str(arg2), arg3, str(arg4), str(arg5));
}
```

## Example: per-query latency by database and user

```
usdt:/usr/local/bin/pgbouncer:pgbouncer:client__query__ready
{
    @us[str(arg2), str(arg3)] = hist(arg4);   // dbname, username -> duration
}
```

## Example: pool-wait latency (queueing from pool exhaustion)

```
usdt:/usr/local/bin/pgbouncer:pgbouncer:client__wait__end
{
    @waited_us[str(arg2)] = hist(arg4);       // dbname -> duration
}
```

## Example: backend establishment latency (time until ready)

```
usdt:/usr/local/bin/pgbouncer:pgbouncer:server__ready
{
    @ready_us[str(arg2)] = hist(arg4);        // dbname -> duration
}
```
