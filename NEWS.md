PgBouncer changelog
===================

PgBouncer 1.16.x
----------------

**2021-11-11  -  PgBouncer 1.16.1  -  "Test of depth against quiet efficiency"**

This is a minor release with a security fix.

* Make PgBouncer acting as a server reject extraneous data after an
  SSL or GSS encryption handshake.

  A man-in-the-middle with the ability to inject data into the TCP
  connection could stuff some cleartext data into the start of a
  supposedly encryption-protected database session.  This could be
  abused to send faked SQL commands to the server, although that would
  only work if PgBouncer did not demand any authentication data.
  (However, a PgBouncer setup relying on SSL certificate
  authentication might well not do so.)  (CVE-2021-3935)

**2021-08-09  -  PgBouncer 1.16.0  -  "Fended off a jaguar"**

- Features
  * Support hot reloading of TLS settings.  When the configuration
    file is reloaded, changed TLS settings automatically take effect.
  * Add support for abstract Unix-domain sockets.  Prefix a
    Unix-domain socket path with `@` to use a socket in the abstract
    namespace.  This matches the corresponding PostgreSQL 14 feature.
  * The maximum lengths of passwords and user names have been
    increased to 996 and 128, respectively.  Various cloud services
    require this.
  * The minimum pool size can now be set per database, similar to the
    regular pool size and the reserve pool size.
  * The number of pending query cancellations is shown in `SHOW
    POOLS`.

- Fixes
  * Configuration parsing now has tighter error handling in many
    places.  Where previously it might have logged an error and
    proceeded, those configuration errors would now result in startup
    failures.  This is what always should have happened, but some code
    didn't do this right.  Some users might discover that their
    configurations have been faulty all along and will not work
    anymore.
  * Query cancel handling has been fixed.  Under some circumstances,
    cancel requests would seemingly get stuck for a long time.  This
    should no longer happen.  In fact, cancel requests can now exceed
    the pool size by a factor of two, so they really shouldn't get
    stuck
    anymore. ([#542](https://github.com/pgbouncer/pgbouncer/pull/542),
    [#543](https://github.com/pgbouncer/pgbouncer/pull/543))
  * Mixed use of md5 and scram via hba has been fixed.
  * The build with c-ares on Windows has been fixed.
  * The dreaded "FIXME: query end, but query_start == 0" messages have
    been fixed.  We now know why they happen, and you shouldn't see
    them anymore. ([#565](https://github.com/pgbouncer/pgbouncer/pull/565))
  * Fix reloading of `default_pool_size`, `min_pool_size`, and
    `res_pool_size`.  Reloading these settings previously didn't work.

- Cleanups
  * Cirrus CI is now
    [used](https://cirrus-ci.com/github/pgbouncer/pgbouncer) instead
    of Travis CI.
  * As usual, many tests have been added.
  * The "unclean server" log message has been clarified a bit.  It now
    says "client disconnect while server was not ready" or "client
    disconnect before everything was sent to the server".  The former
    can happen if the client connection is closed when the server has
    a transaction block open, which confused some users.
  * You can no longer use "pgbouncer" as a database name.  This name
    is reserved for the admin console, and using it as a normal
    database name never really worked right.  This is now explicitly
    prohibited.
  * Errors sent to clients before the connection is closed are now
    labeled as FATAL instead of just ERROR.  Some clients were
    confused
    otherwise. ([#564](https://github.com/pgbouncer/pgbouncer/pull/564))
  * Fix compiler warnings with GCC 11.
    ([#623](https://github.com/pgbouncer/pgbouncer/issues/623))

PgBouncer 1.15.x
----------------

**2020-11-19  -  PgBouncer 1.15.0  -  "Ich hab noch einen Koffer in Berlin"**

- Features
  * Improve authentication failure reporting.  The authentication
    failure messages sent to the client now only state that
    authentication failed but give no further details.  Details are
    available in the PgBouncer log.  Also, if the requested user does
    not exist, the authentication is still processed to the end and
    will result in the same generic failure message.  All this
    prevents clients from probing the PgBouncer instance for user
    names and other authentication-related insights.  This is similar
    to how PostgreSQL behaves.
  * Don't log anything if client disconnects immediately.  This avoids
    log spam when monitoring systems just open a TCP/IP connection but
    don't send anything before disconnecting.
  * Use systemd journal for logging when in use.  When we detect that
    stderr is going to the systemd journal, we use systemd native
    functions for log output.  This avoids printing duplicate
    timestamp and pid, thus making the log a bit cleaner.  Also, this
    adds metadata such as the severity to the logs, so that if the
    journal gets sent on to syslog, the messages have useful metadata
    attached.
  * A subset of the test suite can now be run under Windows.
  * `SHOW CONFIG` now also shows the default values of the settings.

- Fixes
  * Fix the `so_reuseport` option on FreeBSD.  The original code in
    PgBouncer 1.12.0 didn't actually work on FreeBSD.
    ([#504](https://github.com/pgbouncer/pgbouncer/pull/504))
  * Repair compilation on systems with older systemd versions.  This
    was broken in 1.14.0.
    ([#505](https://github.com/pgbouncer/pgbouncer/issues/505))
  * The makefile target to build Windows binary zip packages has been
    repaired.
  * Long command-line options now also work on Windows.
  * Fix the behavior of the global `auth_user` setting.  The old
    behavior was confusing and fragile as it depended on the order in
    the configuration file.  This is no longer the
    case. ([#391](https://github.com/pgbouncer/pgbouncer/issues/391),
    [#393](https://github.com/pgbouncer/pgbouncer/issues/393))

- Cleanups
  * Improve test stability and portability.
  * Modernize Autoconf-related code.
  * Disable deprecation compiler warnings from OpenSSL 3.0.0.

PgBouncer 1.14.x
----------------

**2020-06-11  -  PgBouncer 1.14.0  -  "La ritrovata magia"**

- Features
  * Add SCRAM authentication pass-through.  This allows using
    encrypted SCRAM secrets in PgBouncer (either in `userlist.txt` or
    from `auth_query`) for logging into servers.
  * Add support for systemd socket activation.  This is especially
    useful to let systemd handle the creation of the Unix-domain
    sockets on systems where access to `/var/run/postgresql` is
    restricted.
  * Add support for Unix-domain sockets on Windows.

- Cleanups
  * Add an alternative smaller sample configuration file
    `pgbouncer-minimal.ini` for testing or deployment.

PgBouncer 1.13.x
----------------

**2020-04-27  -  PgBouncer 1.13.0  -  "My favourite game"**

- Features
  * Add configuration setting `tcp_user_timeout`, to set the
    corresponding socket option.
  * `client_tls_protocols` and `server_tls_protocols` now default to
    `secure`, which means only TLS 1.2 and TLS 1.3 are enabled.  Older
    versions are still supported, they are just not turned on by
    default.
  * Add support for systemd service notifications.  Right now, this
    allows using `Type=notify` service units.  More integration is
    planned for future versions.

- Fixes
  * Fix multiline log messages
    ([libusual #24](https://github.com/libusual/libusual/pull/24))
  * Handle null user names returned from `auth_query` properly
    ([#340](https://github.com/pgbouncer/pgbouncer/pull/340))

- Cleanups
  * The Debian packaging files under `debian` have been removed.  It
    is recommended to use the packages from https://apt.postgresql.org/.
  * Numerous fixes and improvements in the test suite
  * The tests no longer try to use sudo by default.  This can now be
    activated explicitly by setting the environment variable
    `USE_SUDO`.
  * The libevent API use was updated to use version 2 style interfaces
    and to no longer use deprecated interfaces from version 1.

PgBouncer 1.12.x
----------------

**2019-10-17  -  PgBouncer 1.12.0  -  "It's about learning and getting better"**

This release contains a variety of minor enhancements and fixes.

- Features
  * Add a setting to turn on the `SO_REUSEPORT` socket option.  On
    some operating systems, this allows running multiple PgBouncer
    instances on the same host listening on the same port and having
    the kernel distribute the connections automatically.
  * Add a setting to use a `resolv.conf` file separate from the
    operating system.  This allows setting custom DNS servers and
    perhaps other DNS options.
  * Send the output of `SHOW VERSION` as a normal result row instead
    of a NOTICE message.  This makes it easier to consume and is
    consistent with other `SHOW` commands.

- Fixes
  * Send statistics columns as `numeric` instead of `bigint`.  This
    avoids some client libraries failing on values that overflow the
    `bigint`
    range. ([#360](https://github.com/pgbouncer/pgbouncer/pull/360),
    [#401](https://github.com/pgbouncer/pgbouncer/pull/401))
  * Fix issue with PAM users losing their
    password. ([#285](https://github.com/pgbouncer/pgbouncer/issues/285))
  * Accept SCRAM channel binding enabled clients.  Previously, a
    client supporting channel binding (that is, PostgreSQL 11+) would
    get a connection failure when connecting to PgBouncer in certain
    situations.  (PgBouncer does not support channel binding.  This
    change just fixes support for clients that offer it.)
  * Fix compilation with newer versions of musl-libc (used by Alpine
    Linux).

- Cleanups
  * Add `make check` target.  This allows running all the tests from a
    single command.
  * Remove references to the PostgreSQL wiki.  All information is now
    either in the PgBouncer documentation or on the web site.
  * Remove support for Libevent version 1.x.  Libevent 2.x is now
    required.  Libevent is now detected using pkg-config.
  * Fix compiler warnings on macOS and Windows.  The build on these
    platforms should now be free of warnings.
  * Fix some warnings from LLVM scan-build.

PgBouncer 1.11.x
----------------

**2019-08-27  -  PgBouncer 1.11.0  -  "Instinct for Greatness"**

- Features
  * Add support for SCRAM authentication for clients and servers.  A
    new authentication type `scram-sha-256` is added.
  * Handle `auth_type=password` when the stored password is md5, like
    a PostgreSQL server
    would. ([#129](https://github.com/pgbouncer/pgbouncer/pull/129))
  * Add option `log_stats` to disable printing stats to
    log. ([#287](https://github.com/pgbouncer/pgbouncer/pull/287))
  * Add time zone to log timestamps.
  * Put PID into [brackets] in log prefix.
- Fixes
  * Fix OpenSSL configure test when running against newer OpenSSL with
    `-Werror`.
  * Fix wait time computation with `auth_user`.  This would either
    crash or report garbage values for wait
    time. ([#393](https://github.com/pgbouncer/pgbouncer/pull/393))
  * Handle GSSENCRequest packet, added in PostgreSQL 12.  It doesn't
    do anything right now, but it avoids confusing error messages
    about "bad packet header".
- Cleanups
  * Many improvements in the test suite and several new tests
  * Fix several compiler warnings on Windows.
  * Expand documentation of the `[users]` section and add to example
    config
    file. ([#330](https://github.com/pgbouncer/pgbouncer/pull/330))

PgBouncer 1.10.x
----------------

**2019-07-01  -  PgBouncer 1.10.0  -  "Afraid of the World"**

- Features
  * Add support for enabling and disabling TLS 1.3.  (TLS 1.3 was
    already supported, depending on the OpenSSL library, but now the
    configuration settings to pick the TLS protocol versions also
    support it.)
- Fixes
  * Fix TLS 1.3 support.  This was broken with OpenSSL 1.1.1 and
    1.1.1a (but not before or after).
  * Fix a rare crash in `SHOW FDS`
    ([#311](https://github.com/pgbouncer/pgbouncer/issues/311)).
  * Fix an issue that could lead to prolonged downtime if many cancel
    requests arrive
    ([#329](https://github.com/pgbouncer/pgbouncer/issues/329)).
  * Avoid "unexpected response from login query" after a postgres
    reload
    ([#220](https://github.com/pgbouncer/pgbouncer/issues/220)).
  * Fix `idle_transaction_timeout` calculation
    ([#125](https://github.com/pgbouncer/pgbouncer/issues/125)).  The
    bug would lead to premature timeouts in specific situations.
- Cleanups
  * Make various log and error messages more precise.
  * Fix issues found by Coverity (none had a significant impact in
    practice).
  * Improve and document all test scripts.
  * Add additional SHOW commands to the documentation.
  * Convert the documentation from rst to Markdown.
  * Python scripts in the source tree are all compatible with Python 3
    now.

PgBouncer 1.9.x
---------------

**2018-08-13  -  PgBouncer 1.9.0  -  "Chaos Survival"**

- Features
  * RECONNECT command
  * WAIT_CLOSE command
  * Fast close - Disconnect a server in session pool mode immediately if
    it is in "close_needed" (reconnect) mode.
  * Add close_needed column to SHOW SERVERS
- Fixes
  * Avoid double-free in parse_filename
  * Avoid NULL pointer deref in parse_line
- Cleanups
  * Port mkauth.py to Python 3
  * Improve signals documentation
  * Improve quick start documentation
  * Document SET command
  * Correct list of required software
  * Fix -Wimplicit-fallthrough warnings
  * Add missing documentation for various SHOW fields
  * Document reconnect behavior on reload and DNS change
  * Document that KILL requires RESUME afterwards
  * Clarify documentation of server_lifetime
  * Typos and capitalization fixes in messages and docs
  * Fix psql invocation in tests
  * Various other test setup improvements

PgBouncer 1.8.x
---------------

**2017-12-20  -  PgBouncer 1.8.1  -  "Ground-and-pound Mentality"**

- Fixes
  * Include file `include/pam.h` into distribution tarball.  This
    prevented the 1.8 tarball from building at all.

**2017-12-19  -  PgBouncer 1.8  -  "Confident at the Helm"**

- Features
  * Support PAM authentication.  (Enable with `--with-pam`.)
  * Add `paused` and `disabled` fields to `SHOW DATABASES` output.
  * Add `maxwait_us` field to `SHOW POOLS` output.
  * Add `wait` and `wait_us` fields to `SHOW` commands output.
  * Add new commands `SHOW STATS_TOTALS` and `SHOW STATS_AVERAGES`.
  * Track queries and transactions separately in `SHOW STATS`.  The
    fields `total_requests`, `avg_req`, and
    `avg_query` have been replaced by new fields.
  * Add `wait_time` to `SHOW STATS`.
- Fixes
  * Updated libusual supports OpenSSL 1.1.
  * Do not attempt to use TLS on Unix sockets.
  * When parsing `pg_hba.conf`, keep parsing after erroneous lines instead of rejecting the whole file.
    ([#118](https://github.com/pgbouncer/pgbouncer/issues/118))
  * Several other hba parsing fixes.
  * Fix race condition when canceling query.
    ([#141](https://github.com/pgbouncer/pgbouncer/issues/141))
- Cleanups
  * `auth_user` setting is now also allowed globally, not only per database.
    ([#142](https://github.com/pgbouncer/pgbouncer/issues/142))
  * Set console client and server encoding to `UTF8`.

PgBouncer 1.7.x
---------------

**2016-02-26  -  PgBouncer 1.7.2  -  "Finally Airborne"**

- Fixes
  * Fix crash on stale pidfile removal.  Problem introduced in 1.7.1.
  * Disable cleanup - it breaks takeover and is not useful
    for production loads.  Problem introduced in 1.7.1.
  * After takeover, wait until pidfile is gone before booting.
    Slow shutdown due to memory cleanup exposed existing race.
    ([#113](https://github.com/pgbouncer/pgbouncer/issues/113))
- Cleanups
  * Make build reproducible by dropping DBGVER handling.
    ([#112](https://github.com/pgbouncer/pgbouncer/issues/112))
  * Antimake: Sort file list from $(wildcard), newer gmake does not
    sort it anymore.
    ([#111](https://github.com/pgbouncer/pgbouncer/issues/111))
  * Show libssl version in log.
  * deb: Turn on full hardening.

**2016-02-18  -  PgBouncer 1.7.1  -  "Forward To Five Friends Or Else"**

WARNING: Since version 1.7, `server_reset_query` is not executed when
database is in transaction-pooling mode.  Seems this was not highlighted
enough in 1.7 announcement.  If your apps depend on that happening, use
`server_reset_query_always` to restore previous behaviour.

Otherwise main work of this release was to track down TLS-related memory
leak, which turned out to not exist.  Instead there is libssl build in
Debian/wheezy which has 600k overhead per connection (without leaking)
instead expected 20-30k.  Something to keep an eye on when using TLS.

- Fixes
  * TLS: Rename sslmode "disabled" to "disable" as that is what
    PostgreSQL uses.
  * TLS: `client_tls_sslmode=verify-ca/-full` now reject
    connections without client certificate.
    ([#104](https://github.com/pgbouncer/pgbouncer/issues/104))
  * TLS: `client_tls_sslmode=allow/require` do validate client
    certificate if sent.  Previously they left cert validation
    unconfigured so connections with client cert failed.
    ([#105](https://github.com/pgbouncer/pgbouncer/issues/105))
  * Fix memleak when freeing database.
  * Fix potential memleak in tls_handshake().
  * Fix EOF handling in tls_handshake().
  * Fix too small memset in asn1_time_parse compat.
  * Fix non-TLS (`--without-openssl`) build.
    ([#101](https://github.com/pgbouncer/pgbouncer/issues/101))
  * Fix various issues with Windows build.
    ([#100](https://github.com/pgbouncer/pgbouncer/issues/100))
- Cleanups
  * TLS: Use SSL_MODE_RELEASE_BUFFERS to decrease memory usage
    of inactive connections.
  * Clean allocated memory on exit.  Helps to run memory-leak checkers.
  * Improve `server_reset_query` documentation.
    ([#110](https://github.com/pgbouncer/pgbouncer/issues/110))
  * Add TLS options to sample config.

**2015-12-18  -  PgBouncer 1.7  -  "Colors Vary After Resurrection"**

- Features
  * Support TLS connections.  OpenSSL/LibreSSL is used
    as backend implementation.
  * Support authentication via TLS client certificate.
  * Support "peer" authentication on Unix sockets.
  * Support Host Based Access control file, like
    [pg_hba.conf](http://www.postgresql.org/docs/9.4/static/auth-pg-hba-conf.html)
    in Postgres.  This allows to configure TLS for network connections and "peer"
    authentication for local connections.
- Cleanups
  * Set `query_wait_timeout` to 120s by default.  Current default
    (0) causes infinite queueing, which is not useful.  That
    means if client has pending query and has not been
    assigned to server connection, the client connection will
    be dropped.
  * Disable `server_reset_query_always` by default.  Now reset
    query is used only in pools that are in session mode.
  * Increase pkt_buf to 4096 bytes.  Improves performance with TLS.
    The behaviour is probably load-specific, but it should be
    safe to do as since v1.2 the packet buffers are split
    from connections and used lazily from pool.
  * Support pipelining count expected ReadyForQuery packets.
    This avoids releasing server too early.  Fixes
    [#52](https://github.com/pgbouncer/pgbouncer/issues/52).
  * Improved sbuf_loopcnt logic - socket is guarateed to be
    reprocessed even if there are no event from socket.
    Required for TLS as it has it's own buffering.
  * Adapt system tests to work with modern BSD and MacOS.
    (Eric Radman)
  * Remove **crypt** auth.  It's obsolete and not supported
    by PostgreSQL since 8.4.
  * Fix plain "--with-cares" configure option - without argument
    it was broken.

PgBouncer 1.6.x
---------------

**2015-09-03  -  PgBouncer 1.6.1  -  "Studio Audience Approves"**

- Features
  * New setting: `server_reset_query_always`.  When set,
    disables `server_reset_query` use on non-session pools.
    PgBouncer introduces per-pool pool_mode, but session-pooling
    and transaction-pooling should not use same reset query.
    In fact, transaction-pooling should not use any reset query.

    It is set in 1.6.x, but will be disabled in 1.7.

- Fixes
  * [SECURITY]  Remove invalid assignment of `auth_user`. (#69)
    When `auth_user` is set and client asks non-existing username,
    client will log in as `auth_user`.  Not good.

    [CVE-2015-6817](https://access.redhat.com/security/cve/cve-2015-6817)

  * Skip NoticeResponce in handle_auth_response.  Otherwise verbose
    log levels on server cause login failures.

  * console: Fill `auth_user` when auth_type=any.  Otherwise
    logging can crash (#67).

  * Various portability fixes (OpenBSD, Solaris, OSX).

**2015-08-01  -  PgBouncer 1.6  -  "Zombies of the future"**

- Features

  * Load user password hash from postgres database.
    New parameters:

    auth_user
        user to use for connecting same db and fetching user info.
        Can be set per-database too.

    auth_query
        SQL query to run under auth_user.
        Default: "SELECT usename, passwd FROM pg_shadow WHERE usename=$1"

    (Cody Cutrer)

  * Pooling mode can be configured both per-database and per-user.
    (Cody Cutrer)

  * Per-database and per-user connection limits: max_db_connections and
    max_user_connections.
    (Cody Cutrer / Pavel Stehule)

  * Add DISABLE/ENABLE commands to prevent new connections.
    (William Grant)

  * New DNS backend: c-ares.  Only DNS backend that supports all
    interesting features:  /etc/hosts with refresh, SOA lookup,
    large replies (via TCP/EDNS+UDP), IPv6.  It is the preferred
    backend now, and probably will be **only** backend in the future,
    as it's pointless to support zoo of inadequate libraries.

    SNAFU: c-ares versions <= 1.10 have bug which breaks CNAME-s support
    when IPv6 has been enabled.  (Fixed upstream.)  As a workaround,
    c-ares <= 1.10 is used IPv4-only.  So PgBouncer will drop other backends
    only when c-ares >1.10 (still unreleased) has been out some time...

  * Show remote_pid in SHOW CLIENTS/SERVERS.  Available for clients that
    connect over unix sockets and both tcp and unix socket server.
    In case of tcp-server, the pid is taken from cancel key.

  * Add separate config param (dns_nxdomain_ttl) for controlling
    negative dns caching.
    (Cody Cutrer)

  * Add the client host IP address and port to application_name.
    This is enabled by a config parameter application_name_add_host
    which defaults to 'off'.
    (Andrew Dunstan)

  * Config files have '%include FILENAME' directive to allow configuration
    to be split into several files.
    (Andrew Dunstan)

- Cleanups

  * log: wrap ipv6 address with []
  * log: On connect to server, show local ip and port
  * win32: use gnu-style for long args: --foo
  * Allow numbers in hostname, always try to parse with inet_pton
  * Fix deallocate_all() in FAQ
  * Fix incorrect keyword in example config file
    (Magnus Hagander)
  * Allow comments (with ';') in auth files.
    (Guillaume Aubert)
  * Fix spelling mistakes in log messages and comments.
    (Dmitriy Olshevskiy)

- Fixes

  * fix launching new connections during maintenance
    (Cody Cutrer)
  * don't load auth file twice at boot
    (Cody Cutrer)
  * Proper invalidation for autodbs
  * ipv6: Set IPV6_V6ONLY on listen socket.
  * win32: Don't set SO_REUSEADDR on listen socket.
  * Fix IPv6 address memcpy
  * Fix cancellation of of waiting clients.
    (Mathieu Fenniak)
  * Small bug fix, must check calloc result
    (Heikki Linnakangas)
  * Add newline at the end of the PID file
    (Peter Eisentraut)
  * Don't allow new server connections when PAUSE <db> was issued.
    (Petr Jelinek)
  * Fix 'bad packet' during login when header is delayed.
    (Michał Trojnara, Marko Kreen)
  * Fix errors detected by Coverty.
    (Euler Taveira)
  * Disable server_idle_timeout when server count gets below min_pool (#60)
    (Marko Kreen)

PgBouncer 1.5.x
---------------

**2015-04-09  -  PgBouncer 1.5.5  -  "Play Dead To Win"**

- Fixes
  * Fix remote crash - invalid packet order causes lookup of NULL
    pointer.  Not exploitable, just DoS.

**2012-11-28  -  PgBouncer 1.5.4  -  "No Leaks, Potty-Training Successful"**

- Fixes
  * DNS: Fix memory leak in getaddrinfo_a() backend.
  * DNS: Fix memory leak in udns backend.
  * DNS: Fix stats calculation.
  * DNS: Improve error message handling for getaddrinfo_a().
  * Fix win32 compile.
  * Fix compiler dependency support check in configure.
  * Few documentation fixes.

**2012-09-12  -  PgBouncer 1.5.3  -  "Quantum Toaster"**

- Critical fix

  * Too long database names can lead to crash, which
    is remotely triggerable if autodbs are enabled.

    The original checks assumed all names come from config files,
    thus using fatal() was fine, but when autodbs are enabled
    - by '*' in [databases] section - the database name can come
    from network thus making remote shutdown possible.

    [CVE-2012-4575](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-4575)

- Minor Features

  * max_packet_size - config parameter to tune maximum packet size
    that is allowed through.  Default is kept same: (2G-1), but now
    it can be made smaller.
  * In case of unparseable packet header, show it in hex in log and
    error message.

- Fixes

  * AntiMake: it used $(relpath) and $(abspath) to manupulate pathnames,
    but the result was build failure when source tree path contained
    symlinks.  The code is now changed to work on plain strings only.
  * console: now SET can be used to set empty string values.
  * config.txt: show that all timeouts can be set in floats.
    This is well-hidden feature introduced in 1.4.

**2012-05-29  -  PgBouncer 1.5.2  -  "Don't Chew, Just Swallow"**

- Fixes
  * Due to mistake, reserve_pool_timeout was taken in microseconds,
    not seconds, effectively activating reserve pool immediately
    when pool got full.  Now use it as seconds, as was intended.
    (Noticed by Keyur Govande)

**2012-04-17  -  PgBouncer 1.5.1  -  "Abort, Retry, Ignore?"**

- Features
  * Parameters to tune permissions on unix socket:
    unix_socket_mode=0777, unix_socket_group=''.
- Fixes
  * Allow empty string for server-side variable - this is
    needed to get "application_name" properly working, as it's
    the only parameter that does not have server-side default.
  * If connect string changes, require refresh of server parameters.
    Previously PgBouncer continued with old parameters,
    which breaks in case of Postgres upgrade.
  * If autodb connect string changes, drop old connections.
  * cf_setint: Use strtol() instead atoi() to parse integer config
    parameters.  It allows hex, octal and better error detection.
  * Use sigqueue() to detect union sigval existence - fixes
    compilation on HPUX.
  * Remove 'git' command from Makefile, it throws random errors
    in case of plain-tarball build.
  * Document stats_period parameter.  This tunes the period for
    stats output.
  * Require Asciidoc >= 8.4, seems docs are not compatible with
    earlier versions anymore.
  * Stop trying to retry on EINTR from close().

**2012-01-05  -  PgBouncer 1.5  -  "Bouncing Satisified Clients Since 2007"**

If you use more than 8 IPs behind one DNS name, you now need to
use EDNS0 protocol to query.  Only getaddrinfo_a()/getaddrinfo()
and UDNS backends support it, libevent 1.x/2.x does not.
To enable it for libc, add 'options edns0' to /etc/resolv.conf.

GNU Make 3.81+ is required for building.

- Features
  * Detect DNS reply changes and invalidate connections to IPs no longer
    present in latest reply.
    (Petr Jelinek)
  * DNS zone serial based hostname invalidation.  When option
    dns_zone_check_period is set, all DNS zones will be queried
    for SOA, and when serial has changed, all hostnames
    will be queried.  This is needed to get deterministic
    connection invalidation, because invalidation on lookup
    is useless when no lookups are performed.
    Works only with new UDNS backend.
  * New SHOW DNS_HOSTS, SHOW DNS_ZONES commands to examine DNS cache.
  * New param: min_pool_size - avoids dropping all connections
    when there is no load.
    (Filip Rembiałkowski)
  * idle_in_transaction_timeout - kill transaction if idle too long.
    Not set by default.
  * New libudns backend for DNS lookups.  More featureful than evdns.
    Use --with-udns to activate.  Does not work with IPv6 yet.
  * KILL command, to immediately kill all connections for one database.
    (Michael Tharp)
  * Move to Antimake build system to have better looking Makefiles.
    Now GNU Make 3.81+ is required for building.
- Fixes
  * DNS now works with IPv6 hostnames.
  * Don't change connection state when NOTIFY arrives from server.
  * Various documentation fixes.
    (Dan McGee)
  * Console: Support ident quoting with "".  Originally we did not
    have any commands that took database names, so no quoting was needed.
  * Console: allow numbers at the stard of word regex.  Trying
    to use strict parser makes things too complex here.
  * Don't expire auto DBs that are paused.
    (Michael Tharp)
  * Create auto databases as needed when doing PAUSE.
    (Michael Tharp)
  * Fix wrong log message issued by RESUME command.
    (Peter Eisentraut)
  * When user= without password= is in database connect string,
    password will be taken from userlist.
  * Parse '*' properly in takeover code.
  * autogen.sh: work with older autoconf/automake.
  * Fix run-as-service crash on win32 due to bad basename() from
    mingw/msvc runtime.  Now compat basename() is always used.

PgBouncer 1.4.x
---------------

**2011-06-16  -  PgBouncer 1.4.2  -  "Strike-First Algorithm"**

Affected OS-es: \*BSD, Solaris, Win32.

- Portability Fixes
  * Give CFLAGS to linker.  Needed when using pthread-based
    getaddrinfo_a() fallback.
  * lib/find_modules.sh: Replace split() with index()+substr().
    This should make it work with older AWKs.
  * <usual/endian.h>: Ignore system htoX/Xtoh defines.  There
    may be only subset of macros defined.
  * <usual/signal.h>: Separate compat sigval from compat sigevent
  * <usual/socket.h>: Include <sys/uio.h> to get iovec
  * <usual/time.h>: Better function autodetection on win32
  * <usual/base_win32.h>: Remove duplicate sigval/sigevent declaration

**2011-04-01  -  PgBouncer 1.4.1  -  "It Was All An Act"**

- Features

  * Support listening/connect for IPv6 addresses.
    (Hannu Krosing)
  * Multiple listen addresses in 'listen_addr'.  For each getaddrinfo()
    is called, so names can also be used.
  * console: Send PgBouncer version as 'server_version' to client.

- Important Fixes

  * Disable getaddrinfo_a() on glibc < 2.9 as it crashes on older versions.

    Notable affected OS'es: RHEL/CentOS 5.x (glibc 2.5), Ubuntu 8.04 (glibc 2.7).
    Also Debian/lenny (glibc 2.7) which has non-crashing getaddrinfo_a()
    but we have no good way to detect it.

    Please use libevent 2.x on such OS'es, fallback getaddrinfo_a() is not
    meant for production systems.  And read new 'DNS lookup support' section
    in README to see how DNS backend is picked.

    (Hubert Depesz Lubaczewski, Dominique Hermsdorff, David Sommerseth)

  * Default to --enable-evdns if libevent 2.x is used.

  * Turn on tcp_keepalive by default, as that's what Postgres also does.
    (Hubert Depesz Lubaczewski)

  * Set default server_reset_query to DISCARD ALL to be compatible
    with Postgres by default.

  * win32: Fix crashes with NULL unix socket addr.
    (Hiroshi Saito)

  * Fix autodb cleanup: old cleanup code was mixing up databases and pools:
    as soon as one empty pool was found, the database was tagged as 'idle',
    potentially later killing database with active users.

    Reported-By: Hubert Depesz Lubaczewski

- Fixes

  * Make compat getaddrinfo_a() non-blocking, by using single parallel
    thread to do lookups.
  * Enable pthread compilation if compat getaddrinfo_a is used.
  * release_server missed setting ->last_lifetime_disconnect on lifetime disconnect.
    (Emmanuel Courreges)
  * win32: fix auth file on DOS line endings - load_file() did not take
    account of file shringage when loading.
    (Rich Schaaf)
  * <usual/endian.h>: add autoconf detection for enc/dec functions
    so it would not create conflicts on BSD.
    (James Pye)
  * Don't crash when config file does not exist.
    (Lou Picciano)
  * Don't crash on DNS lookup failure when logging on noise level (-v -v).
    (Hubert Depesz Lubaczewski, Dominique Hermsdorff)
  * Use backticks instead of $(cmd) in find_modules.sh to make it more portable.
    (Lou Picciano)
  * Use 'awk' instead of 'sed' in find_modules.sh to make it more portable.
    (Giorgio Valoti)
  * Log active async DNS backend info on startup.
  * Fix --disable-evdns to mean 'no' instead 'yes'.
  * Mention in docs that -R requires unix_socket_dir.
  * Discuss server_reset_query in faq.txt.
  * Restore lost memset in slab allocator
  * Various minor portability fixes in libusual.

**2011-01-11  -  PgBouncer 1.4  -  "Gore Code"**

- Features

  * Async DNS lookup - instead of resolving hostnames at reload time,
    the names are now resolved at connect time, with configurable caching.
    (See dns_max_ttl parameter.)

    By default it uses getaddrinfo_a() (glibc) as backend, if it does not
    exist, then getaddrinfo_a() is emulated via blocking(!) getaddrinfo().

    When --enable-evdns argument to configure, libevent's evdns is used
    as backend.  It is not used by default, because libevent 1.3/1.4
    contain buggy implementation.  Only evdns in libevent 2.0 seems OK.

  * New config var: syslog_ident, to tune syslog name.

  * Proper support for `application_name` startup parameter.

  * Command line long options (Guillaume Lelarge)

  * Solaris portability fixes (Hubert Depesz Lubaczewski)

  * New config var: disable_pqexec.  Highly-paranoid environments
    can disable Simple Query Protocol with that.  Requires apps
    that use only Extended Query Protocol.

  * Postgres compat: if database name is empty in startup packet,
    use user name as database.

- Fixes

  * DateStyle and TimeZone server params need to use exact case.
  * Console: send datetime, timezone and stdstr server params to client.

- Internal cleanups

  * Use libusual library for low-level utility functions.
  * Remove fixed-length limit from server params.

PgBouncer 1.3.x
---------------

**2010-09-09  -  PgBouncer 1.3.4  -  "Bouncer is always right"**

- Fixes
  * Apply fast-fail logic at connect time.  So if server is failing,
    the clients get error when connecting.
  * Don't tag automatically generated databases for checking on reload time,
    otherwise they get killed, because they don't exist in config.
  * Ignore application_name parameter by default.  This avoids the need
    for all Postgres 9.0 users to add it into ignore_startup_parameters=
    themselves.
  * Correct pg_auth quoting.  '\' is not used there.
  * Better error reporting on console, show incoming query to user.
  * Support OS'es (OpenBSD) where tv_sec is not time_t.
  * Avoid too noisy warnings on gcc 4.5.

**2010-05-10  -  PgBouncer 1.3.3  -  "NSFW"**

- Improvements
  * Make listen(2) argument configurable: listen_backlog.  This is
    useful on OS'es, where system max allowed is configurable.
  * Improve disconnect messages to show what username or dbname caused
    login to fail.
- Fixes
  * Move fast-fail relaunch logic around.  Old one was annoying in case of
    permanently broken databases or users, by trying to retry even if
    there is no clients who want to login.
  * Make logging functions keep old errno, otherwise pgbouncer may act funny
    on higher loglevels and logging problems.
  * Increase the size of various startup-related buffers to handle
    EDB more noisy startup.
  * Detect V2 protocol startup request and give clear reason for disconnect.

**2010-03-15  -  PgBouncer 1.3.2  -  "Boomerang Bullet"**

- Fixes

  * New config var 'query_wait_timeout'.  If client does not get
    server connection in this many seconds, it will be killed.

  * If no server connection in pool and last connect failed, then
    don't put client connections on hold but send error immediately.

    This together with previous fix avoids unnecessary stalls if
    a database has gone down.

  * Track libevent state in sbuf.c to avoid double event_del().  Although
    it usually is safe, it does not seem to work 100%.  Now we should always
    know whether it has been called or not.

  * Disable maintenance during SUSPEND.  Otherwise with short timeouts
    the old bouncer could close few connections after sending them over.

  * Apply client_login_timeout to clients waiting for welcome packet
    (first server connection).  Otherwise they can stay waiting
    infinitely, unless there is query_timeout set.

  * win32: Add switch -U/-P to -regservice to let user pick account
    to run service under.  Old automatic choice between Local Service and
    Local System was not reliable enough.

  * console: Remove \0 from end of text columns.  It was hard to notice,
    as C clients were fine with it.

  * Documentation improvements.  (Greg Sabino Mullane)

  * Clarify few login-related log messages.

  * Change logging level for pooler-sent errors (usually on disconnect) from INFO
    to WARNING, as they signify problems.

  * Change log message for query_timeout to "query timeout".

**2009-07-06  -  PgBouncer 1.3.1  -  "Now fully conforming to NSA monitoring requirements"**

- Fixes
  * Fix problem with sbuf_loopcnt which could make connections hang.
    If query or result length is nearby of multiple of (pktlen*sbuf_loopcnt)
    [10k by default], it could stay waiting for more data which will not
    appear.
  * Make database reconfigure immediate.  Currently old connections
    could be reused after SIGHUP.
  * Fix SHOW DATABASES which was broken due to column addition.
  * Console access was disabled when "auth_type=any" as pgbouncer dropped username.
    Fix: if "auth_type=any", allow any user to console as admin.
  * Fix bad CUSTOM_ALIGN macro.  Luckily it's unused if OS already
    defines ALIGN macro thus seems the bug has not happened in wild.
  * win32: call WSAStartup() always, not only in daemon mode
    as config parsing wants to resolve hosts.
  * win32: put quotes around config filename in service
    cmdline to allow spaces in paths.  Executable path
    does not seem to need it due to some win32 magic.
  * Add STATS to SHOW HELP text.
  * doc/usage.txt: the time units in console results are in
    microseconds, not milliseconds.

**2009-02-18  -  PgBouncer 1.3 -  "New Ki-Smash Finishing Move"**

- Features

  * IANA has assigned port 6432 to be official port for PgBouncer.
    Thus the default port number has changed to 6432.  Existing
    individual users do not need to change, but if you distribute
    packages of PgBouncer, please change the package default
    to official port.

  * Dynamic database creation (David Galoyan)

    Now you can define database with name "*".  If defined, it's connect
    string will be used for all undefined databases.  Useful mostly
    for test / dev environments.

  * Windows support (Hiroshi Saito)

    PgBouncer runs on Windows 2000+ now.  Command line usage stays same,
    except it cannot run as daemon and cannot do online reboot.
    To run as service, define parameter service_name in config. Then:

        > pgbouncer.exe config.ini -regservice
        > net start SERVICE_NAME

    To stop and unregister:

        > net stop SERVICE_NAME
        > pgbouncer.exe config.ini -unregservice

    To use Windows Event Log, event DLL needs to be registered first:

        > regsrv32 pgbevent.dll

    Afterwards you can set "syslog = 1" in config.

- Minor features

  * Database names in config file can now be quoted with standard SQL
    ident quoting, to allow non-standard characters in db names.

  * New tunables: 'reserve_pool_size' and 'reserve_pool_timeout'.
    In case there are clients in pool that have waited more that
    'reserve_pool_timeout' seconds, 'reserve_pool_size' specifies
    the number of connections that can be added to pool.  It can also
    set per-pool with 'reserve_pool' connection variable.

  * New tunable 'sbuf_loopcnt' to limit time spent on one socket.

    In some situations - eg SMP server, local Postgres and fast network -
    pgbouncer can run recv()->send() loop many times without blocking
    on either side.  But that means other connections will stall for
    a long time.  To make processing more fair, limit the times
    of doing recv()->send() one socket.  If count reaches limit,
    just proceed processing other sockets.  The processing for
    that socket will resume on next event loop.

    Thanks to Alexander Schöcke for report and testing.

  * crypt() authentication is now optional, as it was removed from Postgres.
    If OS does not provide it, pgbouncer works fine without it.

  * Add milliseconds to log timestamps.

  * Replace old MD5 implementation with more compact one.

  * Update ISC licence with the FSF clarification.

- Fixes

  * In case event_del() reports failure, just proceed with cleanup.
    Previously pgbouncer retried it, in case the failure was due ENOMEM.
    But this has caused log floods with inifinite repeats, so it seems
    libevent does not like it.

    Why event_del() report failure first time is still mystery.

  * --enable-debug now just toggles whether debug info is stripped from binary.
    It no longer plays with -fomit-frame-pointer as it's dangerous.

  * Fix include order, as otherwise system includes could come before
    internal ones.  Was problem for new md5.h include file.

  * Include COPYRIGHT file in .tgz...

PgBouncer 1.2.x
---------------

**2008-08-08  -  PgBouncer 1.2.3  -  "Carefully Selected Bytes"**

- Fixes
  * Disable SO_ACCEPTFILTER code for BSDs which did not work.
  * Include example etc/userlist.txt in tgz.
  * Use '$(MAKE)' instead 'make' for recursion (Jørgen Austvik)
  * Define _GNU_SOURCE as glibc is useless otherwise.
  * Let the libevent 1.1 pass link test so we can later report "1.3b+ needed"
  * Detect stale pidfile and remove it.

Thanks to Devrim GÜNDÜZ and Bjoern Metzdorf for problem reports and testing.

**2008-08-06  -  PgBouncer 1.2.2  -  "Barf-bag Included"**

- Fixes
  * Remove 'drop_on_error', it was a bad idea.  It was added as workaround
    for broken plan cache behaviour in Postgres, but can cause damage
    in common case when some queries always return error.

**2008-08-04  -  PgBouncer 1.2.1  -  "Waterproof"**

- Features
  * New parameter 'drop_on_error' - if server throws error the connection
    will not be reused but dropped after client finished with it.  This is
    needed to refresh plan cache.  Automatic refresh does not work even in 8.3.
    Defaults to 1.
- Fixes
  * SHOW SOCKETS/CLIENTS/SERVERS: Don't crash if socket has no buffer.
  * Fix infinite loop on SUSPEND if suspend_timeout triggers.
- Minor cleanups
  * Use <sys/uio.h> for 'struct iovec'.
  * Cancel shutdown (from SIGINT) on RESUME/SIGUSR2,
    otherwise it will trigger on next PAUSE.
  * Proper log message if console operation is canceled.

**2008-07-29  -  PgBouncer 1.2  -  "Ordinary Magic Flute"**

PgBouncer 1.2 now requires libevent version 1.3b or newer.
Older libevent versions crash with new restart code.

- Features

  * Command line option (-u) and config parameter (user=) to support user
    switching at startup.  Also now pgbouncer refuses to run as root.

    (Jacob Coby)

  * More descriptive usage text (-h).  (Jacob Coby)

  * New database option: connect_query to allow run a query on new
    connections before they are taken into use.

    (Teodor Sigaev)

  * New config var 'ignore_startup_parameters' to allow and ignore
    extra parameters in startup packet.  By default only 'database'
    and 'user' are allowed, all others raise error.  This is needed
    to tolerate overenthusiastic JDBC wanting to unconditionally
    set 'extra_float_digits=2' in startup packet.

  * Logging to syslog: new parameters syslog=0/1 and
    syslog_facility=daemon/user/local0.

  * Less scary online restart (-R)

    - Move FD loading before fork, so it logs to console and can be canceled by ^C

    - Keep SHUTDOWN after fork, so ^C would be safe

    - A connect() is attempted to unix socket to see if anyone is listening.
      Now -R can be used even when no previous process was running.  If there
      is previous process, but -R is not used, startup fails.

  * New console commands:

    - SHOW TOTALS that shows stats summary (as goes to log) plus mem usage.

    - SHOW ACTIVE_SOCKETS - like show sockets; but filter only active ones.

- Less visible features

  * suspend_timeout - drop stalled conns and long logins. This brings
    additional safety to reboot.

  * When remote database throws error on logging in, notify clients.

  * Removing a database from config and reloading works - all connections
    are killed and the database is removed.

  * Fake some parameters on console SHOW/SET commands to be more Postgres-like.
    That was needed to allow psycopg to connect to console.
    (client_encoding/default_transaction_isolation/datestyle/timezone)

  * Make server_lifetime=0 disconnect server connection immediately
    after first use.  Previously "0" made PgBouncer ignore server age.
    As this behavior was undocumented, there should not be any users
    depending on it.

  * Internal improvements:

    - Packet buffers are allocated lazily and reused.  This should bring
      huge decrease in memory usage.  This also makes realistic to use
      big pktbuf with lot of connections.

    - Lot's of error handling improvements, PgBouncer should now
      survive OOM situations gracefully.

    - Use slab allocator for memory management.

    - Lots of code cleanups.

- Fixes

  * Only single accept() was issued per event loop which could
    cause connection backlog when having high amount of connection
    attempts.  Now the listening socket is always drained fully,
    which should fix this.
  * Handle EINTR from connect().
  * Make configure.ac compatible with autoconf 2.59.
  * Solaris compatibility fixes (Magne Mæhre)

PgBouncer 1.1.x
---------------

**2007-12-10  -  PgBouncer 1.1.2  -  "The Hammer"**

- Features
  * Disconnects because of server_lifetime are now separated by
    (server_lifetime / pool_size) seconds.  This avoids pgbouncer
    causing reconnect floods.
- Fixes
  * Online upgrade 1.0 -> 1.1 problems:
    - 1.0 does not track server parameters, so they stay NULL
      but 1.1 did not expect it and crashed.
    - If server params are unknown, but client ones are set,
      then issue a SET for them, instead complaining.
  * Remove temp debug statements that were accidentally left
    in code on INFO level, so they polluted logs.
  * Unbroke debian/changelog
- Cleanup
  * reorder struct SBuf fields to get better alignment for buffer.

**2007-10-26  -  PgBouncer 1.1.1  -  "Breakdancing Bee"**

- Fixes
  * Server parameter cache could stay uninitialized, which caused
    unnecessary SET of them.  This caused problem on 8.1 which
    does not allow touching standard_conforming_strings.
    (Thanks to Dimitri Fontaine for report & testing.)
  * Some doc fixes.
  * Include doc/fixman.py in .tgz.

**2007-10-09  -  PgBouncer 1.1  -  "Mad-Hat Toolbox"**

- Features

  * Keep track of following server parameters:

        client_encoding  datestyle, timezone, standard_conforming_strings

  * Database connect string enhancements:

    - Accept hostname in host=
    - Accept custom unix socket location in host=
    - Accept quoted values: password=' asd''foo'

  * New config var: server_reset_query, to be sent immidiately after release
  * New config var: server_round_robin, to switch between LIFO and RR.
  * Cancel pkt sent for idle connection does not drop it anymore.
  * Cancel with ^C from psql works for SUSPEND / PAUSE.
  * Print FD limits on startup.
  * When suspending, try to hit packet boundary ASAP.
  * Add 'timezone' to database parameters.
  * Use longlived logfile fd.  Reopened on SIGHUP / RELOAD;
  * Local connection endpoint info in SHOW SERVERS/CLIENTS/SOCKETS.

- Code cleanup

  * More debug log messages include socket info.
  * Magic number removal and error message cleanup. (David Fetter)
  * Wrapper struct for current pkt info.  Removes lot of compexity.

- Fixes

  * Detect invalid pkt headers better.
  * auth_file modification check was broken, which made pgbouncer
    reload it too often.

PgBouncer 1.0.x
---------------

**2007-06-18  -  PgBouncer 1.0.8  -  "Undead Shovel Jutsu"**

- Fixes
  * Fix crash in cancel packet handling. (^C from psql)
- Features
  * PAUSE <db>; RESUME <db>; works now.
  * Cleanup of console command parsing.
  * Disable expensive in-list assert check.

**2007-04-19  -  PgBouncer 1.0.7  -  "With Vitamin A-Z"**

- Fixes
  * Several error/notice packets with send() blocking between
    triggered assert.  Fix it by removing flushing logic altogether.
    As pgbouncer does not actively buffer anything, its not needed.
    It was a remnant from the time when buffering was pushed to
    kernel with MSG_MORE.
  * Additionally avoid calling recv() logic when sending unblocks.
  * List search code for admin_users and stats_users
    mishandled partial finds.  Fix it.
  * Standardise UNIX socket peer UID finding to getpeereid().

**2007-04-12  -  PgBouncer 1.0.6  -  "Daily Dose"**

- Fixes
  * The "Disable maintenance during the takeover" fix could
    disable maintenance altogether.  Fix it.
  * Compilation fix for FreeBSD, <sys/ucred.h> requires <sys/param.h> there.
    Thanks go to Robert Gogolok for report.

**2007-04-11  -  PgBouncer 1.0.5  -  "Enough for today"**

- Fixes
  * Fix online-restart bugs:
    - Set ->ready for idle servers.
    - Remove obsolete code from use_client_socket()
    - Disable maintenance during the takeover.

**2007-04-11  -  PgBouncer 1.0.4  -  "Last 'last' bug"**

- Fixes
  * Notice from idle server tagged server dirty.
    release_server() did not expect it.  Fix it
    by dropping them.

**2007-04-11  -  PgBouncer 1.0.3  -  "Fearless Fork"**

- Fixes
  * Some error handling was missing in login path, so dying
    connection there could trigger asserts.
  * Cleanup of asserts in sbuf.c to catch problems earlier.
  * Create core when Assert() triggers.

- New stuff
  * New config vars: log_connections, log_disconnections,
    log_pooler_errors to turn on/off noise.
  * Config var: client_login_timeout to kill dead connections
    in login phase that could stall SUSPEND and thus online restart.

**2007-03-28  -  PgBouncer 1.0.2  -  "Supersonic Spoon"**

- Fixes
  * libevent may report a deleted event inside same loop.
    Avoid socket reuse for one loop.
  * release_server() from disconnect_client() didnt look
    it the packet was actually sent.

**2007-03-15  -  PgBouncer 1.0.1  -  "Alien technology"**

- Fixes
  * Mixed usage of cached and non-cached time, plus unsiged usec_t typedef
    created spurious query_timeout errors.
  * Fix rare case when socket woken up from send-wait could stay stalling.
  * More fair queueing of server connections.  Before, a new query could
    get a server connections before older one.
  * Delay server release until everything is guaranteed to be sent.

- Features
  * SHOW SOCKETS command to have detailed info about state state.
  * Put PgSocket ptr to log, to help tracking one connection.
  * In console, allow SELECT in place of SHOW.
  * Various code cleanups.

**2007-03-13  -  PgBouncer 1.0  -  "Tuunitud bemm"**

- First public release.
