# PgBouncer security self-assessment

Conducted by the PgBouncer maintainers, who are listed on the
[Governance](https://github.com/pgbouncer/pgbouncer/wiki/Governance) page.

This self-assessment is an internal analysis of PgBouncer's security by the
PgBouncer maintainers. It describes what PgBouncer protects, where its
attack surface is, how the code defends it, and where the known gaps are.
It is not a security audit of PgBouncer, nor an independent assessment or
attestation of its security health. It is meant to give users an initial
understanding of PgBouncer's security, its security practices and plans,
and where to find existing security documentation, and it can serve as the
starting point for a future joint assessment or external audit.

It builds on the [security policy](../SECURITY.md), which defines the trust
model, the severity of each kind of vulnerability, and what is out of scope.
This document does not repeat those rules; it maps them onto the code.

The assessment covers the PgBouncer server in this repository, including
`lib/` and the code copied from PostgreSQL, and the project's build and
release pipeline. It does not cover the website repository
([pgbouncer.github.io](https://github.com/pgbouncer/pgbouncer.github.io)),
bugs in the test suite and build scripts, third-party dependencies such as
OpenSSL and libevent beyond how PgBouncer uses them, or downstream packages
and container images.

The assessment describes PgBouncer as of the date below. It is reviewed
when a new feature or a breaking change affects the attack surface, and at
least once a year.

## Metadata

| | |
| -- | -- |
| Assessment stage | Complete |
| Last reviewed | 2026-11-02, against master after the 1.26.1 release |
| Software | <https://github.com/pgbouncer/pgbouncer> |
| Security provider | No. PgBouncer is a connection pooler. It authenticates clients, but security is not its primary function. |
| Languages | C (the server), Python (the test suite) |
| SBOM | None published; see [Dependencies](#dependencies). |

### Security links

| Doc | URL |
| -- | -- |
| Security policy and threat model | [SECURITY.md](../SECURITY.md) |
| Security Insights | [security-insights.yml](../security-insights.yml) |
| Configuration reference | [doc/config.md](config.md), <https://www.pgbouncer.org/config.html> |
| Dependency policy | [CONTRIBUTING.md](../CONTRIBUTING.md#dependencies) |
| Governance | <https://github.com/pgbouncer/pgbouncer/wiki/Governance> |
| Release process | <https://github.com/pgbouncer/pgbouncer/wiki/Making-a-release> |
| Past vulnerabilities | [NEWS.md](../NEWS.md), <https://www.pgbouncer.org/changelog.html> |

## Overview

PgBouncer is a lightweight connection pooler for PostgreSQL. It accepts
many client connections, authenticates them itself, and multiplexes them
onto a small number of server connections, speaking the PostgreSQL wire
protocol on both sides.

### Background

PostgreSQL uses one process per connection, so deployments with many
short-lived or idle clients put a pooler in front of the database. In
session pooling mode a client keeps one server connection for its whole
session. In transaction and statement pooling mode, server connections are
handed to a different client after each transaction or statement. That is
where most of PgBouncer's value comes from, and also where its protocol
tracking becomes security relevant: State left behind by one client must not
become visible to a client of a different pool.

PgBouncer is a single-threaded, event-driven process (libevent). A single
crash or hang stops service for every client and database it serves, which
is why SECURITY.md rates unauthenticated crashes and hangs higher than a
per-connection server might.

### Goals

The security guarantees PgBouncer aims to provide are those in the threat
model in SECURITY.md. In summary:

- A client that has not authenticated cannot corrupt memory, crash or hang
  PgBouncer, or get past authentication.
- An authenticated client can act only as the user and database it
  authenticated as. It cannot read data of clients in other pools, corrupt
  memory, or run admin commands.
- `stats_users` can run only the read-only `SHOW` commands.
- A malicious PostgreSQL server, DNS, LDAP, or PAM backend cannot corrupt
  PgBouncer's memory.
- Every valid configuration is safe against the untrusted actors in the
  [Actors](#actors) table, not just the defaults.

### Non-goals

These are listed under "Out of scope" in SECURITY.md. The ones a reader is
most likely to assume are in scope:

- Isolating clients within the same pool from each other's session state.
- Protecting against the administrator, an `admin_users` member, or the OS
  user, all of whom can already do anything PgBouncer can.
- Making a weak setup safe: `trust`, `plain`, and `md5` authentication, or
  connections without TLS. The defaults are `auth_type = md5`,
  `client_tls_sslmode = disable`, and `server_tls_sslmode = prefer`
  (`src/main.c`), so a default installation sends passwords and data in
  plain text. Administrators who need confidentiality must configure TLS,
  and verify the server certificate to prevent server impersonation (T7).
- Robustness against invalid configuration files.

## System design

### Actors

All actors except the external backends run inside one PgBouncer process.
There is no isolation between them in memory: A memory corruption bug
anywhere compromises the whole process, including stored credentials. The
isolation between clients is purely logical, enforced by the pool and
protocol state handling.

| Actor | Trust (see [SECURITY.md](../SECURITY.md#who-is-trusted)) | Code |
| -- | -- | -- |
| Unauthenticated client | Untrusted | `src/client.c` (`handle_client_startup()`), `src/proto.c`, `src/sbuf.c`, `src/pktbuf.c` |
| Authenticated client | Untrusted | `src/client.c` (`handle_client_work()`), `src/prepare.c` |
| Admin console user (`admin_users`) | Trusted | `src/admin.c` |
| Stats console user (`stats_users`) | Untrusted, `SHOW` only | `src/admin.c` |
| PostgreSQL server | Mostly trusted, must not corrupt memory | `src/server.c`, `src/varcache.c`, client side of `src/scram.c` |
| Peer PgBouncer (`[peers]`) | Untrusted, like a client | cancel forwarding in `src/objects.c` |
| DNS, LDAP, PAM backends | Semi-trusted | `src/dnslookup.c`, `src/ldapauth.c`, `src/pam.c` |
| Administrator (configuration, command line) | Fully trusted | `src/loader.c`, `src/hba.c`, `src/main.c` |
| OS user running PgBouncer | Fully trusted | `admin_pre_login()` in `src/admin.c` |

LDAP and PAM authentication run in worker threads (`pam_auth_worker()`
in `src/pam.c`, `ldap_auth_worker()` in `src/ldapauth.c`) so that a
slow backend does not block the event loop. Results are handed back to
the main thread through a shared request structure.

### Actions

**Client login.** A client connects to the listen socket (TCP if
`listen_addr` is set, plus a Unix socket). `get_header()` (`src/proto.c:39`)
frames each packet and rejects lengths above `max_packet_size`
(`src/proto.c:120`). `handle_client_startup()` (`src/client.c:1223`) then
runs a state machine: SSLRequest (TLS handshake through `lib/usual/tls/`),
GSSENCRequest (always refused), StartupMessage, and the password, SASL, or
cancel packet. Out-of-order packets, such as a password before the startup
packet or a second startup packet, disconnect the client. The startup
packet's `options` parameter is parsed by `set_startup_options()`
(`src/client.c:858`).

**Authentication.** Depending on `auth_type` and `auth_hba_file`
(`src/hba.c`), PgBouncer checks the client with SCRAM-SHA-256
(`src/scram.c`), MD5 or plaintext passwords (`check_client_passwd()`,
`src/client.c:75`), TLS client certificates (`login_via_cert()`), Unix
socket peer credentials (`login_as_unix_peer()`), LDAP, or
PAM. Passwords come from `auth_file` or from `auth_query`, which
PgBouncer runs as `auth_user` with the user name sent as a bound
parameter, never interpolated into the SQL (`start_auth_query()`,
`src/client.c:167`). For unknown users, SCRAM runs a mock exchange
with a deterministic fake salt (`build_mock_scram_secret()`,
`src/scram.c:886`), so the exchange does not reveal whether a user
exists.

**Server login.** When a pool needs a new server connection, PgBouncer
resolves the server's host name (`src/dnslookup.c`) and connects. Depending
on `server_tls_sslmode` (default `prefer`), it sends an SSLRequest and
starts TLS (`handle_sslchar()`, `src/server.c:741`), optionally presenting
a client certificate (`server_tls_cert_file`, `server_tls_key_file`). Only
`verify-ca` and `verify-full` check the server's certificate. It then sends
a StartupMessage and answers the server's authentication request in
`answer_authreq()` (`src/proto.c:667`): cleartext password, MD5, or
SCRAM-SHA-256, with PgBouncer as the SCRAM client (`src/scram.c:291-558`).
The credentials come from the forced user in `[databases]`, `auth_file`,
or `auth_query`. If PgBouncer only has a SCRAM secret and no password, it
uses the ClientKey and ServerKey from the client's own SCRAM login
(SCRAM pass-through, `src/client.c:1376`). In a SCRAM exchange, PgBouncer
checks that SASL messages arrive in order, bounds the iteration count, and
verifies the server's signature (`verify_server_signature()`,
`src/scram.c:558`), which proves that the server knows the password's
secret. PgBouncer accepts whichever method the server asks for (see
[Known gaps](#known-gaps-and-planned-work)).

**Pooling.** After login the client is attached to the pool for its
database and user. In transaction and statement mode, PgBouncer tracks
transaction boundaries, COPY, pipelined extended-protocol messages, and
`ParameterStatus` changes (`src/varcache.c`) so it knows when a server
connection can be released and which settings to restore. With
`max_prepared_statements` set, it rewrites the names of protocol-level
prepared statements so clients sharing a server connection don't see each
other's statements (`src/prepare.c`).

**Cancellation.** Each client gets a random 8-byte cancel key
(`get_random_bytes()`, `src/proto.c:391`). With peering enabled, two bytes
carry the peer id and two bits a forwarding TTL, leaving 45 random bits. A
CancelRequest is matched against client keys and forwarded to the server
running that client's query, or to the peer named in the key
(`src/objects.c`, around `accept_cancel_request_for_peer()`).

**Admin console.** Any client can connect to the virtual `pgbouncer`
database. `admin_post_login()` (`src/admin.c:1593`) admits only users
in `admin_users` or `stats_users`, and `admin_pre_login()`
(`src/admin.c:1543`) admits the OS user over the Unix socket.
Commands are matched with regular expressions and dispatched through
`cmd_list` (`src/admin.c:1430`). Each command that needs admin rights
checks `admin->admin_user` itself; see "Known gaps".

## Security functions and features

### Critical

These are not configurable and protect every deployment. Changes to them
should be reviewed with the threat model in mind.

- **Packet framing and buffering** (`src/proto.c`, `src/sbuf.c`,
  `src/pktbuf.c`, `lib/usual/mbuf.c`). Every byte from the network passes
  through here first. Length checks against `max_packet_size` and buffer
  growth arithmetic have produced several past CVEs.
- **Pre-authentication state machine** (`handle_client_startup()`,
  `src/client.c:1223`). Enforces packet order during login and decides when
  a client counts as authenticated.
- **SCRAM-SHA-256** (`src/scram.c`, `src/common/scram-common.c`,
  `src/common/saslprep.c`). Parses attacker-controlled messages from
  clients, and server-controlled messages when PgBouncer logs into
  PostgreSQL.
- **Pool assignment** (`set_pool()`, `src/client.c:532`). Binds a client to
  exactly the user and database it authenticated as.
- **Protocol state tracking in transaction and statement mode**
  (`handle_client_work()`, `src/server.c`, `src/varcache.c`,
  `src/prepare.c`). Errors here can hand one client's state or results to
  another.
- **Cancel key generation and routing** (`src/proto.c:391`,
  `src/objects.c`). A guessable or misrouted key lets a client cancel other
  clients' queries.
- **Admin console authorization** (`src/admin.c`). Separates admins,
  `stats_users`, and everyone else.

### Security relevant

These depend on configuration.

- **TLS** for clients and servers (`client_tls_*`, `server_tls_*`, built
  on `lib/usual/tls/` and OpenSSL), including client certificate
  authentication.
- **Authentication method and HBA rules** (`auth_type`, `auth_hba_file`,
  `auth_ident_file`, `src/hba.c`).
- **`auth_query` and `auth_user`.** The query runs with `auth_user`'s
  privileges against the server; see T3.
- **Resource limits** (`max_client_conn`, `max_packet_size`, `pkt_buf`,
  `client_login_timeout`, `max_prepared_statements`). They bound what one
  client can consume.
- **Unix socket permissions** (`unix_socket_mode`, default `0777`, and
  `unix_socket_group`). Any local user can connect by default, and is then
  subject to authentication like a TCP client.
- **Log verbosity.** With `verbose = 1` or higher, logs can contain
  secrets.

## Threats

This section describes the main threats to PgBouncer. The severities
are those defined in [SECURITY.md](../SECURITY.md#severity). Each
entry names the mitigations in the code and the remaining gaps, which
are described further under [Known
gaps](#known-gaps-and-planned-work).

**T1. Memory corruption, crash, or hang before authentication.** Any client
that can reach the listen port sends malformed or oversized packets,
out-of-order startup messages, or crafted SCRAM messages.

- Impact: Critical for memory corruption, High for a crash, Medium for a
  hang.
- Mitigations: `get_header()` checks every packet length against
  `max_packet_size`; `handle_client_startup()` disconnects clients that send
  packets out of order; `client_login_timeout` (default 60 seconds)
  disconnects clients that don't finish logging in. CI runs the test suite
  under ASan, UBSan, and Valgrind.
- Gaps: These parsers are not fuzzed. Five of the twelve CVEs fixed in 2025
  and 2026 were in this code (see the appendix).

**T2. Authentication bypass or impersonation.** A client tries to get past
authentication, or to end up connected as a different user than the one it
authenticated as, by skipping or repeating login steps or by confusing the
SCRAM state.

- Impact: Critical.
- Mitigations: The startup state machine in `handle_client_startup()`; SCRAM
  nonce and proof verification in `src/scram.c`; `set_pool()` binds the
  client to the user and database it authenticated as.
- Gaps: CVE-2026-107350 (a second StartupMessage during SCRAM let a client
  log in as another user) shows how subtle the state machine is. Weaknesses
  of `trust`, `plain`, and `md5` are out of scope.

**T3. SQL execution through `auth_query`.** An unauthenticated client
influences the query that PgBouncer runs as `auth_user` to look up
passwords.

- Impact: Critical. `auth_user` usually has access to all password hashes.
- Mitigations: The user name is sent as a bound parameter, never
  interpolated. Since CVE-2025-12819, PgBouncer does not apply the
  client's startup parameters to the connection that runs `auth_query`
  (`find_server()`, `src/objects.c`). Since CVE-2025-2291, the default
  query checks `VALID UNTIL`.
- Gaps: The default query uses unqualified names and relies on that
  isolation. Custom queries should schema-qualify names as defense in
  depth.

**T4. Data leaking across pools.** An authenticated client tries to see
results, prepared statements, or session state of a client connected as a
different user or to a different database.

- Impact: High.
- Mitigations: Each server connection belongs to one pool, i.e. one
  database and user, and never moves to another pool. Protocol tracking
  releases a server connection only at transaction or statement boundaries,
  and `src/prepare.c` renames protocol-level prepared statements.
- Gaps: Protocol tracking is complex (pipelining, COPY, the extended
  protocol). Errors in it usually affect clients of the same pool, which
  SECURITY.md treats as normal bugs, not vulnerabilities.

**T5. Admin commands run by non-admins.** A `stats_users` member, or any
user that can reach the admin console, runs a command that needs
`admin_users`.

- Impact: High.
- Mitigations: `admin_post_login()` admits only `admin_users` and
  `stats_users`, and `admin_pre_login()` admits the OS user. Each
  restricted command checks `admin->admin_user`.
- Gaps: There is no central check and no test for it (see Known gaps).

**T6. Cancelling other clients' queries.** Anyone who can reach the listen
port, including a peer PgBouncer, sends CancelRequests with guessed keys.
The protocol does not authenticate cancel requests.

- Impact: Queries of other clients, in any pool, are cancelled. SECURITY.md
  doesn't rate this case explicitly.
- Mitigations: Cancel keys are 64 random bits from `get_random_bytes()`.
  With peering, 45 bits are random, and a TTL in the key stops requests
  from being forwarded between peers forever.
- Gaps: With peering enabled, keys have fewer random bits.

**T7. Server impersonation and credential theft.** An attacker on the
network path, or one who controls DNS, poses as the PostgreSQL server.

- Impact: The attacker reads and changes query data, and obtains any
  plaintext passwords PgBouncer stores for server logins, for example in
  `auth_file` or `[databases]`.
- Mitigations: `server_tls_sslmode = verify-full` (or `verify-ca`) checks
  the server's certificate. In a SCRAM exchange, PgBouncer verifies the
  server's signature.
- Gaps: The default `server_tls_sslmode` is `prefer`, which does not verify
  the certificate. Without verification, authentication can be downgraded
  even when TLS is required (see Known gaps).

**T8. Malicious server or backend.** A compromised PostgreSQL server, DNS
resolver, LDAP server, or PAM module sends crafted responses.

- Impact: Medium for memory corruption that only a server can trigger.
- Mitigations: SCRAM client-side parsing checks message order and bounds
  the iteration count at 1,000,000 (`SCRAM_MAX_ITERATIONS`). CI runs TSan
  with LDAP and PAM enabled, since they run in worker threads.
- Gaps: Three CVEs fixed in 2026 came from malicious servers.

**T9. Resource exhaustion.** Clients open many connections, send large
packets, or create many prepared statements.

- Impact: Medium when an unauthenticated client can cause it, Low when it
  needs an authenticated client.
- Mitigations: `max_client_conn` (default 100),
  `max_db_client_connections`, `max_user_client_connections`,
  `client_login_timeout`, `max_packet_size`, `pkt_buf`, and
  `max_prepared_statements`.
- Gaps: There is no limit per source address, so a single client can use
  up `max_client_conn`. Resource usage within configured limits is out of
  scope.

**T10. Secrets disclosure.** An attacker obtains passwords, SCRAM secrets,
or SCRAM keys held by PgBouncer.

- Impact: High for an out-of-bounds read that leaks secrets, Medium for
  secrets in the log at the default `verbose = 0`.
- Mitigations: SECURITY.md treats secrets in the log at the default
  `verbose = 0` as a vulnerability. The `auth_file`, the configuration, and
  TLS keys are protected by file permissions set by the administrator.
- Gaps: All secrets, including SCRAM keys cached for pass-through, live in
  the one process's memory, so any memory corruption bug (T1, T8) can expose
  them.

## Secure development practices

### Development pipeline

- **Contributions** come in as GitHub pull requests and are reviewed and
  merged by a maintainer or committer ([CONTRIBUTING.md](../CONTRIBUTING.md),
  [Governance](https://github.com/pgbouncer/pgbouncer/wiki/Governance)).
  There is no DCO or CLA, and commits don't have to be signed.
- **Who can merge and release.** The three active maintainers and two
  maintainers emeriti have admin access, and one committer has write
  access. The maintainers emeriti keep admin access as a backup, in case
  the active maintainers become unavailable. New maintainers and
  committers are added by consensus of the active maintainers, who must be
  confident of the candidate's identity (Governance page).
- **Branch protection.** Repository rulesets on the default branch forbid
  deleting it, force pushes, and merge commits, for everyone. Changes must
  come in through a pull request, merged by squash or rebase, and must
  pass six required status checks: the Linux `valgrind`, `cares-pam-ldap`,
  and `no-evdns-no-openssl` builds, macOS, Windows, and formatting and
  linting. Maintainers and committers can bypass these rules when needed.
- **Review is not enforced.** The process expects review, but the pull
  request rule requires no approving review. Not every CI job is a
  required check: Notably, the `Linux (autoconf)` job, which builds the
  release tarball, is not.
- **CI** (`.github/workflows/pgbouncer-ci.yml`) builds and runs the
  test suite on Linux (Ubuntu), macOS, and Windows, with both meson
  and autoconf. On master, on manual dispatch, and on pull requests
  labeled `ci-full`, it also runs builds on further platforms, with
  ASan and UBSan, TSan (with LDAP and PAM enabled), and Clang's static
  analyzer (`scan-build`). `scan-build` findings don't fail the build;
  maintainers review them periodically and handle them as described in
  [SECURITY.md](../SECURITY.md#static-analysis). A Valgrind build runs
  on every push and pull request. Formatting and linting are checked on
  every change.
- **Tests** are in `test/` (pytest against real PostgreSQL servers, plus
  C tests such as `hba_test`). They cover authentication methods, TLS,
  admin commands, cancellation, peering, prepared statements, and limits.
- **CI workflow hardening.** Workflows have read-only `contents`
  permission, and none is triggered by `pull_request_target` or
  `workflow_run`, so code from pull requests never runs with write
  access. Some actions in the workflows are referenced by version tag
  rather than commit hash. The RHEL and Alpine jobs download pandoc
  with `wget` without checking a checksum. pandoc is only used to
  build the documentation, and those jobs don't produce release
  artifacts; the release tarball is built in the Ubuntu autoconf job,
  which installs pandoc from the distribution's packages.

### Dependencies

PgBouncer links against OpenSSL, libevent, and optionally c-ares, LDAP,
PAM, and systemd, as installed on the build system. Source releases pin or
bundle none of them. Code copied from PostgreSQL (`src/common/`,
`include/common/`) and uthash is treated as PgBouncer code. `lib/`
(libusual, including the TLS layer in `lib/usual/tls/`, originally derived
from OpenBSD's libtls) is maintained as part of PgBouncer. Details are in
[SECURITY.md](../SECURITY.md#dependencies).

No software composition analysis (SCA) or dependency vulnerability
scanner runs in CI. Source releases contain no third-party packages
for such a tool to check. The Windows zip, the only binary release,
links statically against MSYS2's OpenSSL and libevent, which are
updated only with new PgBouncer releases and are not scanned.

### Build and release

Releases follow the
[release process](https://github.com/pgbouncer/pgbouncer/wiki/Making-a-release).
CI builds both release artifacts, the source tarball (autoconf `dist`) and
the Windows zip (statically linked against MSYS2's OpenSSL and libevent),
from the release pull request. A maintainer downloads them from the CI run,
commits the tarball to the website repository (the canonical download
location, with a published SHA-256 checksum), squash-merges the pull
request, tags the result, and attaches both files to a GitHub release.

Gaps:

- The artifacts are built from the pull request branch, but the tag is put
  on the squash-merge commit created afterwards. The process requires the
  branch to be rebased, so the trees should match, but nothing checks it.
- The artifacts pass through a maintainer's machine, and nothing
  cryptographically links the published file to the CI run. The SHA-256
  checksum is published alongside the file, so it detects corruption, not
  substitution. Releases are not signed and have no provenance attestation
  or SBOM. Possible future work: Publish from CI with GitHub artifact
  attestations or Sigstore signatures.

### Communication channels

- **Internal:** the maintainers communicate by private email, including
  about security reports that are not yet public. Day-to-day development
  discussion happens in GitHub issues and pull requests.
- **Inbound:** GitHub issues and pull requests for bugs and features,
  GitHub Security Advisories for vulnerabilities (SECURITY.md).
- **Outbound:** release posts on <https://www.pgbouncer.org/>, GitHub
  releases, and news items on the PostgreSQL website (release process).

### Ecosystem

PgBouncer is a widely used connection pooler for PostgreSQL, packaged by
the major Linux distributions and by the PostgreSQL project's own apt and
yum repositories. Kubernetes operators such as
[CloudNativePG](https://github.com/cloudnative-pg/cloudnative-pg/blob/main/docs/src/connection_pooling.md)
deploy it as their connection pooler, configured with `auth_query`.
It is likely also used by PostgreSQL hosting providers, though the project
has no complete picture of where and how. Because it often sits in front
of databases that serve many clients, a vulnerability in PgBouncer can
affect many downstream deployments at once, which typically upgrade
through their distribution, operator, or provider rather than directly from
the project.

## Security issue resolution

### Responsible disclosure process

Vulnerabilities are reported privately through GitHub Security Advisories,
stay private until the release with the fix is published, and get a CVE
identifier. The maintainers aim to reply within 5 business days, and to
assess validity, severity, and affected versions within 14 business days
after that. The full policy is in
[SECURITY.md](../SECURITY.md#disclosure-policy).

### Incident response

The active maintainers handle reports (Governance page). Fixes are
developed privately, released as a bug fix release of the latest feature
release series, which is the only supported series, and announced through
the outbound channels above. Nobody outside the maintainers and the
reporter gets advance notice, including packagers: They learn about a fix
when the release is published.

There is no fixed workflow yet for developing fixes privately. Depending on
the maintainer, they are developed in GitHub's temporary private forks
attached to the security advisory or in local branches. The process is
evolving as the number of security reports grows. See "Known gaps and
planned work".

## Project compliance

PgBouncer does not claim compliance with any security standard (such as
PCI-DSS, ISO 27001, or GDPR).

The project tracks the [OpenSSF OSPS
Baseline](https://baseline.openssf.org/), targeting maturity level 3,
with a weekly scan (`.github/workflows/osps-baseline.yml`).

PgBouncer does not yet have an
[OpenSSF Best Practices](https://www.bestpractices.dev/) badge. Work on the
[passing badge](https://www.bestpractices.dev/en/projects/15902/passing) is
in progress. The higher levels (silver and gold) are not currently planned.

## Known gaps and planned work

### Design and code

- **Admin rights are checked in each command handler.** The rule that
  `stats_users` may run only `SHOW` is not enforced in one place. Each
  command that needs admin rights starts with an
  `if (!admin->admin_user)` check (`src/admin.c`, multiple places), and the
  command table `cmd_list` doesn't record which commands need it. A new
  command that forgets the check can be run by `stats_users`, which
  SECURITY.md rates High. This has happened: `KILL_CLIENT` shipped without
  the check (CVE-2026-6667, fixed in 1.25.2 by 97b5634). No test checks
  that `stats_users` are refused restricted commands, and the fix for
  CVE-2026-6667 didn't add one. Possible future work: a "needs admin" flag
  in `cmd_list` checked by `exec_cmd()`, and a test that runs every
  restricted command as a `stats_users` member.
- **Server authentication can be downgraded.** PgBouncer answers
  whichever authentication request the server sends, including a request
  for a cleartext password, and accepts AuthenticationOk without any
  exchange (`answer_authreq()`, `src/proto.c:667`). There is no setting
  like libpq's `require_auth`, and SCRAM channel binding is not supported.
  So unless `server_tls_sslmode` is `verify-full` (or `verify-ca` with a
  suitable CA), anyone who can impersonate the server can obtain plaintext
  passwords that PgBouncer stores, for example in `auth_file` or
  `[databases]`, even when the real server uses SCRAM. This is close to the
  "TLS not configured or not required" case that SECURITY.md lists as out
  of scope, but applies even when TLS is required. Possible future work: a
  `require_auth`-like setting for server connections, and SCRAM channel
  binding (SCRAM-SHA-256-PLUS) on both sides.
- **No fuzzing.** The parsers an unauthenticated client can reach are not
  fuzzed: `get_header()` (`src/proto.c:39`), `set_startup_options()` and
  `read_escaped_token()` (`src/client.c:817-950`), the SCRAM message
  parsers (`read_client_first_message()` and `read_client_final_message()`,
  `src/scram.c:622`, `:708`), and cancel requests. SECURITY.md rates bugs
  there Critical or High, and half the CVEs fixed so far in 2026 were in
  this code. The sanitizer and Valgrind CI builds only find errors on
  the inputs the tests send. Possible future work: libFuzzer harnesses
  for these entry points, possibly through OSS-Fuzz.

### Process

- **Review is not enforced by the repository.** See "Development pipeline"
  above.
- **Released artifacts are not tied to the CI run that built them.** See
  "Build and release" above.
- **No consistent workflow for private security fixes.** Fixes are
  developed in temporary private forks or local branches, depending on the
  maintainer (see "Incident response"). Neither runs CI before the fix is
  public: GitHub Actions does not run in temporary private forks. Possible
  future work: Agree on one workflow, including how a fix is tested on
  all CI platforms before release.

### Other planned work

- **Update or replace the TLS layer.** `lib/usual/tls/` was derived from
  OpenBSD's libtls and has not tracked it since. The plan is to update it,
  or replace it, for example by using the OpenSSL API directly.
- **Compiler options.** Adopt the warning and hardening flags from the
  OpenSSF
  [Compiler Options Hardening Guide for C and C++](https://best.openssf.org/Compiler-Hardening-Guides/Compiler-Options-Hardening-Guide-for-C-and-C++.html).
- **Compiler annotations.** Annotate the C code following the OpenSSF
  [Compiler Annotations for C and C++](https://best.openssf.org/Compiler-Hardening-Guides/Compiler-Annotations-for-C-and-C++.html)
  guide, so the compiler can check more of the code's assumptions.
- **FIPS 140.** Test in CI that PgBouncer works with OpenSSL in FIPS mode.
- **Tests for under-tested authentication methods.** PAM authentication
  has no tests, and peer authentication has a single test
  (`test_peer_auth_ident_map` in `test/test_auth.py`).

## Appendix

### Known issues over time

Every fixed vulnerability has a CVE identifier and is described in the
release notes ([NEWS.md](../NEWS.md),
<https://www.pgbouncer.org/changelog.html>). This section summarizes them
instead of listing them.

As of the last review, 12 vulnerabilities were fixed in releases 1.24.1
through 1.26.1 (2025 and 2026), after only a handful in the years before.
By the trust boundary they cross:

- **Unauthenticated client, packet and startup parsing (5).** Integer
  overflows in buffer growth and packet parsing, an infinite loop in
  startup `options` parsing, and a missing nonce check in SCRAM, leading to
  crashes or hangs.
- **Authentication logic (3).** Logging in as a different SCRAM user, SQL
  execution through a client-supplied `search_path` in `auth_query`, and
  `auth_query` ignoring password expiry.
- **Malicious PostgreSQL server (3).** A stack overflow, a null pointer
  dereference, and an unbounded SCRAM iteration count.
- **Admin console authorization (1).** `KILL_CLIENT` without an admin check.
