
pgbouncer.ini
#############

Description
===========

The configuration file is in "ini" format. Section names are between "[" and "]".  Lines
starting with ";" or "#" are taken as comments and ignored. The characters ";"
and "#" are not recognized when they appear later in the line.


Generic settings
================

logfile
-------

Specifies log file. Log file is kept open so after rotation ``kill -HUP``
or on console ``RELOAD;`` should be done.
Note: On Windows machines, the service must be stopped and started.

Default: not set.

pidfile
-------

Specifies the pid file. Without a pidfile, daemonization is not allowed.

Default: not set.

listen_addr
-----------

Specifies list of addresses, where to listen for TCP connections.
You may also use ``*`` meaning "listen on all addresses". When not set,
only Unix socket connections are allowed.

Addresses can be specified numerically (IPv4/IPv6) or by name.

Default: not set

listen_port
-----------

Which port to listen on. Applies to both TCP and Unix sockets.

Default: 6432

unix_socket_dir
---------------

Specifies location for Unix sockets. Applies to both listening socket and
server connections. If set to an empty string, Unix sockets are disabled.
Required for online reboot (-R) to work.
Note: Not supported on Windows machines.

Default: /tmp

unix_socket_mode
----------------

File system mode for Unix socket.

Default: 0777

unix_socket_group
-----------------

Group name to use for Unix socket.

Default: not set

user
----

If set, specifies the Unix user to change to after startup. Works only if
PgBouncer is started as root or if it's already running as given user.

Note: Not supported on Windows machines.

Default: not set

auth_file
---------

The name of the file to load user names and passwords from. The file format
is the same as the PostgreSQL 8.x pg_auth/pg_pwd file, so this setting can be
pointed directly to one of those backend files.  Since version 9.0, PostgreSQL
does not use such text file, so it must be generated manually.  See
section `Authentication file format`_ below about details.

Default: not set.


auth_hba_file
-------------

HBA configuration file to use when `auth_type`_ is ``hba``.
Supported from version 1.7 onwards.

Default: not set

auth_type
---------

How to authenticate users.

pam
    PAM is used to authenticate users, `auth_file`_ is ignored. This method is not
    compatible with databases using `auth_user`_ option. Service name reported to
    PAM is "pgbouncer". Also, `pam` is still not supported in HBA configuration file.

hba
    Actual auth type is loaded from `auth_hba_file`_.  This allows different
    authentication methods different access paths.  Example: connection
    over Unix socket use ``peer`` auth method, connection over TCP
    must use TLS. Supported from version 1.7 onwards.

cert
    Client must connect over TLS connection with valid client cert.
    Username is then taken from CommonName field from certificate.

md5
    Use MD5-based password check. `auth_file`_ may contain both MD5-encrypted
    or plain-text passwords.  This is the default authentication method.

plain
    Clear-text password is sent over wire.  Deprecated.

trust
    No authentication is done. Username must still exist in `auth_file`_.

any
    Like the ``trust`` method, but the username given is ignored. Requires that all
    databases are configured to log in as specific user.  Additionally, the console
    database allows any user to log in as admin.

auth_query
----------

Query to load user's password from database.

Direct access to pg_shadow requires admin rights.  It's preferable to
use non-admin user that calls SECURITY DEFINER function instead.

Note that the query is run inside target database, so if a function
is used it needs to be installed into each database.

Default: ``SELECT usename, passwd FROM pg_shadow WHERE usename=$1``

.. _auth_user:

auth_user
---------

If ``auth_user`` is set, any user not specified in auth_file will be
queried through the ``auth_query`` query from pg_shadow in the database
using ``auth_user``. Auth_user's password will be taken from ``auth_file``.

Direct access to pg_shadow requires admin rights.  It's preferable to
use non-admin user that calls SECURITY DEFINER function instead.

Default: not set.

pool_mode
---------

Specifies when a server connection can be reused by other clients.

session
    Server is released back to pool after client disconnects.  Default.

transaction
    Server is released back to pool after transaction finishes.

statement
    Server is released back to pool after query finishes. Long transactions
    spanning multiple statements are disallowed in this mode.

max_client_conn
---------------

Maximum number of client connections allowed.  When increased then the file
descriptor limits should also be increased.  Note that actual number of file
descriptors used is more than max_client_conn.  Theoretical maximum used is::

  max_client_conn + (max_pool_size * total_databases * total_users)

if each user connects under its own username to server.  If a database user
is specified in connect string (all users connect under same username),
the theoretical maximum is::

  max_client_conn + (max_pool_size * total_databases)

The theoretical maximum should be never reached, unless somebody deliberately
crafts special load for it.  Still, it means you should set the number of
file descriptors to a safely high number.

Search for ``ulimit`` in your favorite shell man page.
Note: ``ulimit`` does not apply in a Windows environment.

Default: 100

default_pool_size
-----------------

How many server connections to allow per user/database pair. Can be overridden in
the per-database configuration.

Default: 20

min_pool_size
-------------

Add more server connections to pool if below this number.
Improves behavior when usual load comes suddenly back after period
of total inactivity.

Default: 0 (disabled)

reserve_pool_size
-----------------

How many additional connections to allow to a pool. 0 disables.

Default: 0 (disabled)

reserve_pool_timeout
--------------------

If a client has not been serviced in this many seconds, pgbouncer enables
use of additional connections from reserve pool.  0 disables.

Default: 5.0

max_db_connections
------------------

Do not allow more than this many connections per-database (regardless of pool - i.e.
user). It should be noted that when you hit the limit, closing a client connection
to one pool will not immediately allow a server connection to be established for
another pool, because the server connection for the first pool is still open.
Once the server connection closes (due to idle timeout), a new server connection
will immediately be opened for the waiting pool.

Default: unlimited

max_user_connections
--------------------

Do not allow more than this many connections per-user (regardless of pool - i.e.
user). It should be noted that when you hit the limit, closing a client connection
to one pool will not immediately allow a server connection to be established for
another pool, because the server connection for the first pool is still open.
Once the server connection closes (due to idle timeout), a new server connection
will immediately be opened for the waiting pool.

server_round_robin
------------------

By default, pgbouncer reuses server connections in LIFO (last-in, first-out) manner,
so that few connections get the most load.  This gives best performance if you have
a single server serving a database.  But if there is TCP round-robin behind a database
IP, then it is better if pgbouncer also uses connections in that manner, thus
achieving uniform load.

Default: 0

ignore_startup_parameters
-------------------------

By default, PgBouncer allows only parameters it can keep track of in startup
packets - ``client_encoding``, ``datestyle``, ``timezone`` and ``standard_conforming_strings``.

All others parameters will raise an error.  To allow others parameters, they can be
specified here, so that pgbouncer knows that they are handled by admin and it can ignore them.

Default: empty

disable_pqexec
--------------

Disable Simple Query protocol (PQexec).  Unlike Extended Query protocol, Simple Query
allows multiple queries in one packet, which allows some classes of SQL-injection
attacks.  Disabling it can improve security.  Obviously this means only clients that
exclusively use Extended Query protocol will stay working.

Default: 0

application_name_add_host
-------------------------

Add the client host address and port to the application name setting set on connection start.
This helps in identifying the source of bad queries etc.  This logic applies
only on start of connection, if application_name is later changed with SET,
pgbouncer does not change it again.

Default: 0

conffile
--------

Show location of current config file.  Changing it will make PgBouncer use another
config file for next ``RELOAD`` / ``SIGHUP``.

Default: file from command line.

service_name
------------

Used on win32 service registration.

Default: pgbouncer

job_name
--------

Alias for `service_name`_.


Log settings
============

syslog
------

Toggles syslog on/off
As for windows environment, eventlog is used instead.

Default: 0

syslog_ident
------------

Under what name to send logs to syslog.

Default: pgbouncer (program name)

syslog_facility
---------------

Under what facility to send logs to syslog.
Possibilities: ``auth``, ``authpriv``, ``daemon``, ``user``, ``local0-7``.

Default: daemon

log_connections
---------------

Log successful logins.

Default: 1

log_disconnections
------------------

Log disconnections with reasons.

Default: 1

log_pooler_errors
-----------------

Log error messages pooler sends to clients.

Default: 1

stats_period
------------

Period for writing aggregated stats into log.

Default: 60

verbose
-------

Increase verbosity.  Mirrors "-v" switch on command line.
Using "-v -v" on command line is same as `verbose=2` in config.

Default: 0


Console access control
======================

admin_users
-----------

Comma-separated list of database users that are allowed to connect and
run all commands on console.  Ignored when `auth_type`_ is ``any``,
in which case any username is allowed in as admin.

Default: empty

stats_users
-----------

Comma-separated list of database users that are allowed to connect and
run read-only queries on console. That means all SHOW commands except
SHOW FDS.

Default: empty.


Connection sanity checks, timeouts
==================================

server_reset_query
------------------

Query sent to server on connection release, before making it
available to other clients.  At that moment no transaction is in
progress so it should not include ``ABORT`` or ``ROLLBACK``.

The query is supposed to clean any changes made to database session
so that next client gets connection in well-defined state.  Default is
``DISCARD ALL`` which cleans everything, but that leaves next client
no pre-cached state.  It can be made lighter, e.g. ``DEALLOCATE ALL``
to just drop prepared statements, if application does not break when
some state is kept around.

When transaction pooling is used, the `server_reset_query`_ is not used,
as clients must not use any session-based features as each transaction
ends up in different connection and thus gets different session state.

Default: DISCARD ALL

server_reset_query_always
-------------------------

Whether `server_reset_query`_ should be run in all pooling modes.  When this
setting is off (default), the `server_reset_query`_ will be run only in pools
that are in sessions-pooling mode.  Connections in transaction-pooling mode
should not have any need for reset query.

It is workaround for broken setups that run apps that use session features
over transaction-pooled pgbouncer.  Is changes non-deterministic breakage
to deterministic breakage - client always lose their state after each
transaction.

Default: 0

server_check_delay
------------------

How long to keep released connections available for immediate re-use, without running
sanity-check queries on it. If 0 then the query is ran always.

Default: 30.0

server_check_query
------------------

Simple do-nothing query to check if the server connection is alive.

If an empty string, then sanity checking is disabled.

Default: SELECT 1;

server_lifetime
---------------

The pooler will try to close server connections that have been connected longer
than this. Setting it to 0 means the connection is to be used only once,
then closed. [seconds]

Default: 3600.0

server_idle_timeout
-------------------

If a server connection has been idle more than this many seconds it will be dropped.
If 0 then timeout is disabled.  [seconds]

Default: 600.0

server_connect_timeout
----------------------

If connection and login won't finish in this amount of time, the connection
will be closed. [seconds]

Default: 15.0

server_login_retry
------------------

If login failed, because of failure from connect() or authentication that
pooler waits this much before retrying to connect. [seconds]

Default: 15.0

client_login_timeout
--------------------

If a client connects but does not manage to login in this amount of time, it
will be disconnected. Mainly needed to avoid dead connections stalling
SUSPEND and thus online restart. [seconds]

Default: 60.0

autodb_idle_timeout
-------------------

If the automatically created (via "*") database pools have
been unused this many seconds, they are freed.  The negative
aspect of that is that their statistics are also forgotten.  [seconds]

Default: 3600.0

dns_max_ttl
-----------

How long the DNS lookups can be cached.  If a DNS lookup returns
several answers, pgbouncer will robin-between them in the meantime.
Actual DNS TTL is ignored.  [seconds]

Default: 15.0

dns_nxdomain_ttl
----------------

How long error and NXDOMAIN DNS lookups can be cached. [seconds]

Default: 15.0


dns_zone_check_period
---------------------

Period to check if zone serial has changed.

PgBouncer can collect DNS zones from host names (everything after first dot)
and then periodically check if zone serial changes.
If it notices changes, all host names under that zone
are looked up again.  If any host IP changes, its connections
are invalidated.

Works only with UDNS and c-ares backends (``--with-udns`` or ``--with-cares`` to configure).

Default: 0.0 (disabled)


TLS settings
============

client_tls_sslmode
------------------

TLS mode to use for connections from clients.  TLS connections
are disabled by default.  When enabled, `client_tls_key_file`_
and `client_tls_cert_file`_ must be also configured to set up
key and cert PgBouncer uses to accept client connections.

disable
    Plain TCP.  If client requests TLS, it's ignored.  Default.

allow
    If client requests TLS, it is used.  If not, plain TCP is used.
    If client uses client-certificate, it is not validated.

prefer
    Same as ``allow``.

require
    Client must use TLS.  If not, client connection is rejected.
    If client uses client-certificate, it is not validated.

verify-ca
    Client must use TLS with valid client certificate.

verify-full
    Same as ``verify-ca``.

client_tls_key_file
-------------------

Private key for PgBouncer to accept client connections.

Default: not set.

client_tls_cert_file
--------------------

Certificate for private key.  Clients can validate it.

Default: not set.

client_tls_ca_file
------------------

Root certificate file to validate client certificates.

Default: unset.

client_tls_protocols
--------------------

Which TLS protocol versions are allowed.  Allowed values: ``tlsv1.0``, ``tlsv1.1``, ``tlsv1.2``.
Shortcuts: ``all`` (tlsv1.0,tlsv1.1,tlsv1.2), ``secure`` (tlsv1.2), ``legacy`` (all).

Default: ``all``

client_tls_ciphers
------------------

Default is the same as the Postgres default

Default: ``HIGH:MEDIUM:+3DES:!aNULL``

client_tls_ecdhcurve
--------------------

Elliptic Curve name to use for ECDH key exchanges.

Allowed values: ``none`` (DH is disabled), ``auto`` (256-bit ECDH), curve name.

Default: ``auto``

client_tls_dheparams
--------------------

DHE key exchange type.

Allowed values: ``none`` (DH is disabled), ``auto`` (2048-bit DH), ``legacy`` (1024-bit DH).

Default: ``auto``

server_tls_sslmode
------------------

TLS mode to use for connections to PostgreSQL servers.
TLS connections are disabled by default.

disable
    Plain TCP.  TCP is not event requested from server.  Default.

allow
    FIXME: if server rejects plain, try TLS?

prefer
    TLS connection is always requested first from PostgreSQL,
    when refused connection will be established over plain TCP.
    Server certificate is not validated.

require
    Connection must go over TLS.  If server rejects it,
    plain TCP is not attempted.  Server certificate is not validated.

verify-ca
    Connection must go over TLS and server certificate must be valid
    according to `server_tls_ca_file`_.  Server host name is not checked
    against certificate.

verify-full
    Connection must go over TLS and server certificate must be valid
    according to `server_tls_ca_file`_.  Server host name must match
    certificate info.

server_tls_ca_file
------------------

Root certificate file to validate PostgreSQL server certificates.

Default: unset.

server_tls_key_file
-------------------

Private key for PgBouncer to authenticate against PostgreSQL server.

Default: not set.

server_tls_cert_file
--------------------

Certificate for private key.  PostgreSQL server can validate it.

Default: not set.

server_tls_protocols
--------------------

Which TLS protocol versions are allowed.  Allowed values: ``tlsv1.0``, ``tlsv1.1``, ``tlsv1.2``.
Shortcuts: ``all`` (tlsv1.0,tlsv1.1,tlsv1.2), ``secure`` (tlsv1.2), ``legacy`` (all).

Default: ``all``

server_tls_ciphers
------------------

Default: ``fast``


Dangerous timeouts
==================

Setting following timeouts cause unexpected errors.

query_timeout
-------------

Queries running longer than that are canceled. This should be used only with
slightly smaller server-side statement_timeout, to apply only for network
problems. [seconds]

Default: 0.0 (disabled)

query_wait_timeout
------------------

Maximum time queries are allowed to spend waiting for execution. If the query
is not assigned to a server during that time, the client is disconnected. This
is used to prevent unresponsive servers from grabbing up connections. [seconds]

It also helps when server is down or database rejects connections for any reason.
If this is disabled, clients will be queued infinitely.

Default: 120

client_idle_timeout
-------------------

Client connections idling longer than this many seconds are closed. This should
be larger than the client-side connection lifetime settings, and only used
for network problems. [seconds]

Default: 0.0 (disabled)

idle_transaction_timeout
------------------------

If client has been in "idle in transaction" state longer,
it will be disconnected.  [seconds]

Default: 0.0 (disabled)


Low-level network settings
==========================

pkt_buf
-------

Internal buffer size for packets. Affects size of TCP packets sent and general
memory usage. Actual libpq packets can be larger than this so, no need to set it
large.

Default: 4096

max_packet_size
---------------

Maximum size for PostgreSQL packets that PgBouncer allows through.  One packet
is either one query or one result set row.  Full result set can be larger.

Default: 2147483647

listen_backlog
--------------

Backlog argument for listen(2).  Determines how many new unanswered connection
attempts are kept in queue.  When queue is full, further new connections are dropped.

Default: 128

sbuf_loopcnt
------------

How many times to process data on one connection, before proceeding.
Without this limit, one connection with a big result set can stall
PgBouncer for a long time.  One loop processes one `pkt_buf`_ amount of data.
0 means no limit.

Default: 5

suspend_timeout
---------------

How many seconds to wait for buffer flush during SUSPEND or reboot (-R).
Connection is dropped if flush does not succeed.

Default: 10

tcp_defer_accept
----------------

For details on this and other tcp options, please see ``man 7 tcp``.

Default: 45 on Linux, otherwise 0

tcp_socket_buffer
-----------------

Default: not set

tcp_keepalive
--------------

Turns on basic keepalive with OS defaults.

On Linux, the system defaults are **tcp_keepidle=7200**, **tcp_keepintvl=75**,
**tcp_keepcnt=9**.  They are probably similar on other OS-es.

Default: 1

tcp_keepcnt
-----------

Default: not set

tcp_keepidle
------------

Default: not set

tcp_keepintvl
-------------

Default: not set


Section [databases]
===================

This contains key=value pairs where key will be taken as a database name and
value as a libpq connect-string style list of key=value pairs. As actual libpq is not
used, so not all features from libpq can be used (service=, .pgpass).

Database name can contain characters ``_0-9A-Za-z`` without quoting.
Names that contain other chars need to be quoted with standard SQL
ident quoting: double quotes where "" is taken as single quote.

"*" acts as fallback database: if the exact name does not exist,
its value is taken as connect string for requested database.
Such automatically created database entries are cleaned up
if they stay idle longer then the time specified in `autodb_idle_timeout`_
parameter.

dbname
------

Destination database name.

Default: same as client-side database name.

host
----

Host name or IP address to connect to.  Host names are resolved
on connect time, the result is cached per ``dns_max_ttl`` parameter.
If DNS returns several results, they are used in round-robin
manner.

Default: not set, meaning to use a Unix socket.

port
----

Default: 5432

user, password
--------------

If ``user=`` is set, all connections to the destination database will be
done with the specified user, meaning that there will be only one pool
for this database.

Otherwise PgBouncer tries to log into the destination database with client
username, meaning that there will be one pool per user.

The length for ``password`` is limited to 128 characters maximum.

auth_user
---------

Override of the global ``auth_user`` setting, if specified.

pool_size
---------

Set maximum size of pools for this database.  If not set,
the default_pool_size is used.

connect_query
-------------

Query to be executed after a connection is established, but before
allowing the connection to be used by any clients. If the query raises errors,
they are logged but ignored otherwise.

pool_mode
---------

Set the pool mode specific to this database. If not set,
the default pool_mode is used.

max_db_connections
------------------

Configure a database-wide maximum (i.e. all pools within the database will
not have more than this many server connections).

client_encoding
---------------

Ask specific ``client_encoding`` from server.

datestyle
---------

Ask specific ``datestyle`` from server.

timezone
--------

Ask specific **timezone** from server.


Section [users]
===============

This contains key=value pairs where key will be taken as a user name and
value as a libpq connect-string style list of key=value pairs. As actual libpq is not
used, so not all features from libpq can be used.


pool_mode
---------

Set the pool mode to be used for all connections from this user. If not set, the
database or default pool_mode is used.


Include directive
=================

The PgBouncer config file can contain include directives, which specify
another config file to read and process. This allows for splitting the
configuration file into physically separate parts. The include directives look
like this::

  %include filename

If the file name is not absolute path it is taken as relative to current
working directory.

Authentication file format
==========================

PgBouncer needs its own user database. The users are loaded from a text
file in following format::

  "username1" "password" ...
  "username2" "md5abcdef012342345" ...

There should be at least 2 fields, surrounded by double quotes. The first
field is the username and the second is either a plain-text or a MD5-hidden
password.  PgBouncer ignores the rest of the line.

This file format is equivalent to text files used by PostgreSQL 8.x
for authentication info, thus allowing PgBouncer to work directly
on PostgreSQL authentication files in data directory.

Since PostgreSQL 9.0, the text files are not used anymore.  Thus the
auth file needs to be generated.   See `./etc/mkauth.py` for sample script
to generate auth file from `pg_shadow` table.

PostgreSQL MD5-hidden password format::

  "md5" + md5(password + username)

So user `admin` with password `1234` will have MD5-hidden password
`md545f2603610af569b6155c45067268c6b`.

HBA file format
===============

It follows the format of PostgreSQL pg_hba.conf file -
http://www.postgresql.org/docs/9.4/static/auth-pg-hba-conf.html

There are following differences:

* Supported record types: `local`, `host`, `hostssl`, `hostnossl`.
* Database field: Supports `all`, `sameuser`, `@file`, multiple names.  Not supported: `replication`, `samerole`, `samegroup`.
* Username field: Supports `all`, `@file`, multiple names.  Not supported: `+groupname`.
* Address field: Supported IPv4, IPv6.  Not supported: DNS names, domain prefixes.
* Auth-method field:  Supported methods: `trust`, `reject`, `md5`, `password`, `peer`, `cert`.
  Not supported: `gss`, `sspi`, `ident`, `ldap`, `radius`, `pam`.
  Also username map (`map=`) parameter is not supported.

Example
=======

Minimal config::

  [databases]
  template1 = host=127.0.0.1 dbname=template1 auth_user=someuser

  [pgbouncer]
  pool_mode = session
  listen_port = 6543
  listen_addr = 127.0.0.1
  auth_type = md5
  auth_file = users.txt
  logfile = pgbouncer.log
  pidfile = pgbouncer.pid
  admin_users = someuser
  stats_users = stat_collector

Database defaults::

  [databases]

  ; foodb over Unix socket
  foodb =

  ; redirect bardb to bazdb on localhost
  bardb = host=127.0.0.1 dbname=bazdb

  ; access to destination database will go with single user
  forcedb = host=127.0.0.1 port=300 user=baz password=foo client_encoding=UNICODE datestyle=ISO

Example of secure function for auth_query::

  CREATE OR REPLACE FUNCTION pgbouncer.user_lookup(in i_username text, out uname text, out phash text)
  RETURNS record AS $$
  BEGIN
      SELECT usename, passwd FROM pg_catalog.pg_shadow
      WHERE usename = i_username INTO uname, phash;
      RETURN;
  END;
  $$ LANGUAGE plpgsql SECURITY DEFINER;
  REVOKE ALL ON FUNCTION pgbouncer.user_lookup(text) FROM public, pgbouncer;
  GRANT EXECUTE ON FUNCTION pgbouncer.user_lookup(text) TO pgbouncer;


See also
========

pgbouncer(1) - man page for general usage, console commands.

https://pgbouncer.github.io/

https://wiki.postgresql.org/wiki/PgBouncer
