# Security policy

## Reporting a vulnerability

Please report security issues privately through GitHub Security Advisories:
https://github.com/pgbouncer/pgbouncer/security/advisories/new

Do not open a public issue for them. Bugs that are not vulnerabilities
according to the threat model below are welcome as normal GitHub issues. If
you're unsure whether an issue is a vulnerability, report it privately.

## Threat model

PgBouncer is a connection pooler for PostgreSQL. It sits between clients and
PostgreSQL servers and speaks the PostgreSQL wire protocol on both sides. It
is usually deployed so that many clients, often from less trusted networks,
share a small number of server connections.

### Who is trusted

**Unauthenticated clients** are fully untrusted. Anyone who can reach the
listen port (default 6432, TCP or Unix socket) controls everything sent before
authentication completes: SSLRequest, GSSENCRequest, StartupMessage,
CancelRequest, and the SCRAM, MD5 or plaintext password exchange. This is the
most important attack surface.

**Authenticated clients** are still untrusted. A client must not be able to
read data of clients in other pools (a different user or database), corrupt
PgBouncer's memory, or act as a different user or database than the one it
authenticated as. Because server connections are shared in transaction and
statement pooling mode, the protocol tracking PgBouncer does there is security
relevant: prepared statement rewriting, parameter tracking, COPY, pipelining
and cancel request routing.

**Admin console users** in `admin_users` are trusted once authenticated.
Users in `stats_users` are not: they may only run the read-only `SHOW`
commands, and are otherwise as untrusted as any other authenticated client.
The admin console itself, the virtual `pgbouncer` database, is reachable by
any client, so running `SHOW` commands without being in either list, or
running any other admin command (`PAUSE`, `KILL`, `SET`, `RELOAD`,
`SHUTDOWN`, ...) without being in `admin_users`, is a vulnerability.

**PostgreSQL servers** are mostly trusted, including the results of
`auth_query`. A malicious or compromised server should still not be able to
corrupt PgBouncer's memory.

**DNS, LDAP and PAM backends** are semi-trusted in the same way: wrong answers
are acceptable, memory corruption is not.

**Configuration** (pgbouncer.ini, `auth_file`, `auth_hba_file`,
`auth_ident_file`) and the command line are written by the administrator and
fully trusted. That does not mean only the defaults matter: every valid
configuration should be safe against the clients and servers described above.

The **operating system user** running PgBouncer is fully trusted too. It can
already read the configuration and log into the admin console without a
password, by connecting over the Unix socket as the `pgbouncer` user.

**Peers** configured in the `[peers]` section don't trust each other any more
than they trust other clients. A cancel request forwarded by a peer looks
exactly like one sent by a client, and PgBouncer only ever sends a peer cancel
requests that were meant for that peer.

### Severity

Critical:
- Memory corruption that an unauthenticated client can trigger.
- Authentication bypass, or ending up connected as a different user or
  database than the one that was authenticated.
- Memory corruption by an authenticated client that is controlled enough to
  plausibly lead to code execution.

High:
- Other memory corruption by an authenticated client.
- Running admin console commands that need `admin_users` as a user that is
  not in it, including `stats_users`.
- Leaking data across pools, i.e. to a client connected as a different user
  or to a different database. Leaking within a pool is often a normal bug
  instead, see "Out of scope".
- Out of bounds reads that leak secrets such as passwords or SCRAM keys.
- A crash an unauthenticated client can trigger, because it drops every pooled
  connection. Assertion failures count as crashes: production builds have no
  assertions and keep running with a broken invariant instead.

Medium:
- Resource exhaustion or hangs an unauthenticated client can cause.
- Small out of bounds reads that leak nothing sensitive.
- Memory corruption that only a malicious PostgreSQL server can trigger.
- Passwords, SCRAM keys or other secrets ending up in the log at the default
  `verbose = 0` level.

Low:
- Resource exhaustion or hangs that need an authenticated client.

### Out of scope

These are not vulnerabilities. Some of them are still normal bugs, which can
be reported as public issues:

- Crashes (including assertion failures) that need an authenticated client.
  The exception is a crash that can be chained into something worse, such as
  memory corruption or leaking another client's data; rate that by what it
  leads to.
- Session state leaking between clients in the same pool (same user and
  database), such as settings like `enable_seqscan` or `application_name`
  carrying over from one client to the next. Those clients already share
  server connections and the same database permissions.
- Bugs triggered by the contents of the configuration files or the command
  line themselves, such as memory corruption when parsing an invalid
  pgbouncer.ini or auth_file. Vulnerabilities that only exist with
  non-default settings are in scope though: if a valid configuration lets a
  client attack PgBouncer, that is a vulnerability.
- Anything an `admin_users` member can do, even when it reaches beyond
  PgBouncer itself, because admins are as trusted as the configuration. For
  example, `SET` can change `auth_type`, `auth_query` or `logfile` at
  runtime, which lets an admin log in as any database user, run arbitrary SQL
  as `auth_user`, or append to any file the PgBouncer OS user can write.
- Weaknesses inherent to an authentication method the administrator enabled,
  such as `trust`, `plain` or `md5`.
- Attacks that only work because TLS is not configured or not required, such
  as sniffing or tampering with plaintext connections.
- Secrets ending up in the log when `verbose` is 1 or higher. Those debug
  logs are meant for troubleshooting and can contain passwords, SCRAM
  secrets and query text.
- Resource usage that stays within limits like `max_client_conn`, `pkt_buf`
  or `max_packet_size` as configured.
- Bugs in the test suite and the build tooling.

## Reproducing issues

The most useful reproducer is a new test that can be put into test/ as is;
test/README.md describes how the tests work.
