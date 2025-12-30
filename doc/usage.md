# pgbouncer


## Synopsis

    pgbouncer [-d][-R][-v][-u user] <pgbouncer.ini>
    pgbouncer -V|-h

On Windows, the options are:

    pgbouncer.exe [-v][-u user] <pgbouncer.ini>
    pgbouncer.exe -V|-h

Additional options for setting up a Windows service:

    pgbouncer.exe --regservice   <pgbouncer.ini>
    pgbouncer.exe --unregservice <pgbouncer.ini>

## Description

**pgbouncer** is a PostgreSQL connection pooler. Any target application
can be connected to **pgbouncer** as if it were a PostgreSQL server,
and **pgbouncer** will create a connection to the actual server, or it
will reuse one of its existing connections.

The aim of **pgbouncer** is to lower the performance impact of opening
new connections to PostgreSQL.

In order not to compromise transaction semantics for connection
pooling, **pgbouncer** supports several types of pooling when
rotating connections:

Session pooling

:   Most polite method. When a client connects, a server connection will
    be assigned to it for the whole duration the client stays connected. When
    the client disconnects, the server connection will be put back into the pool.
    This is the default method.

Transaction pooling

:   A server connection is assigned to a client only during a transaction.
    When PgBouncer notices that transaction is over, the server connection
    will be put back into the pool.

Statement pooling

:   Most aggressive method. The server connection will be put back into the
    pool immediately after a query completes. Multi-statement
    transactions are disallowed in this mode as they would break.

The administration interface of **pgbouncer** consists of some new
`SHOW` commands available when connected to a special "virtual"
database **pgbouncer**.

## Quick-start

Basic setup and usage is as follows.

1. Create a pgbouncer.ini file.  Details in **pgbouncer(5)**.  Simple example:

        [databases]
        template1 = host=localhost port=5432 dbname=template1

        [pgbouncer]
        listen_port = 6432
        listen_addr = localhost
        auth_type = md5
        auth_file = userlist.txt
        logfile = pgbouncer.log
        pidfile = pgbouncer.pid
        admin_users = someuser

2. Create a `userlist.txt` file that contains the users allowed in:

        "someuser" "same_password_as_in_server"

3. Launch **pgbouncer**:

        $ pgbouncer -d pgbouncer.ini

4. Have your application (or the **psql** client) connect to
   **pgbouncer** instead of directly to the PostgreSQL server:

        $ psql -p 6432 -U someuser template1

5. Manage **pgbouncer** by connecting to the special administration
   database **pgbouncer** and issuing `SHOW HELP;` to begin:

        $ psql -p 6432 -U someuser pgbouncer
        pgbouncer=# SHOW HELP;
        NOTICE:  Console usage
        DETAIL:
          SHOW [HELP|CONFIG|DATABASES|FDS|POOLS|CLIENTS|SERVERS|SOCKETS|LISTS|VERSION|...]
          SET key = arg
          RELOAD
          PAUSE
          SUSPEND
          RESUME
          SHUTDOWN
          [...]

6. If you made changes to the pgbouncer.ini file, you can reload it with:

        pgbouncer=# RELOAD;

## Command line switches

`-d`, `--daemon`
:   Run in the background. Without it, the process will run in the foreground.

    In daemon mode, setting `pidfile` as well as `logfile` or `syslog`
    is required.  No log messages will be written to stderr after
    going into the background.

    Note: Does not work on Windows; **pgbouncer** need to run as service there.

`-R`, `--reboot`
:   **DEPRECATED: Instead of this option use a rolling restart with multiple
    pgbouncer processes listening on the same port using so_reuseport instead**
    Do an online restart. That means connecting to the running process,
    loading the open sockets from it, and then using them.  If there
    is no active process, boot normally.
    Note: Works only if OS supports Unix sockets and the `unix_socket_dir`
    is not disabled in configuration.  Does not work on Windows.
    Does not work with TLS connections, they are dropped.

`-u` _USERNAME_, `--user=`_USERNAME_
:   Switch to the given user on startup.

`-v`, `--verbose`
:   Increase verbosity.  Can be used multiple times.

`-q`, `--quiet`
:   Be quiet: do not log to stderr.  This does not affect
    logging verbosity, only that stderr is not to be used.
    For use in init.d scripts.

`-V`, `--version`
:   Show version.

`-h`, `--help`
:   Show short help.

`--regservice`
:   Win32: Register PgBouncer to run as Windows service.  The **service_name**
    configuration parameter value is used as the name to register under.

`--unregservice`
:   Win32: Unregister Windows service.

## Admin console

The console is available by connecting as normal to the
database **pgbouncer**:

    $ psql -p 6432 pgbouncer

Only users listed in the configuration parameters **admin_users** or **stats_users**
are allowed to log in to the console.  (Except when `auth_type=any`, then
any user is allowed in as a stats_user.)

Additionally, the user name **pgbouncer** is allowed to log in without password,
if the login comes via the Unix socket and the client has same Unix user UID
as the running process.

The admin console currently only supports the simple query protocol.
Some drivers use the extended query protocol for all commands; these
drivers will not work for this.

### Show commands

The **SHOW** commands output information. Each command is described below.

#### SHOW STATS [db]

Shows statistics.  In this and related commands, the total figures are
since process start, the averages are updated every `stats_period`.

If database name is given only stats for that single database are shown.

database
:   Statistics are presented per database.

total_xact_count
:   Total number of SQL transactions pooled by **pgbouncer**.

total_query_count
:   Total number of SQL commands pooled by **pgbouncer**.

total_server_assignment_count
:   Total times a server was assigned to a client

total_received
:   Total volume in bytes of network traffic received by **pgbouncer**.

total_sent
:   Total volume in bytes of network traffic sent by **pgbouncer**.

total_xact_time
:   Total number of microseconds spent by **pgbouncer** when connected
    to PostgreSQL in a transaction, either idle in transaction or
    executing queries.

total_query_time
:   Total number of microseconds spent by **pgbouncer** when actively
    connected to PostgreSQL, executing queries.

total_wait_time
:   Time spent by clients waiting for a server, in microseconds. Updated
    when a client connection is assigned a backend connection.

total_client_parse_count
:   Total number of prepared statements created by clients. Only applicable
    in named prepared statement tracking mode, see `max_prepared_statements`.

total_server_parse_count
:   Total number of prepared statements created by **pgbouncer** on a server. Only
    applicable in named prepared statement tracking mode, see `max_prepared_statements`.

total_bind_count
:   Total number of prepared statements readied for execution by clients and forwarded
    to PostgreSQL by **pgbouncer**. Only applicable in named prepared statement tracking
    mode, see `max_prepared_statements`.

avg_xact_count
:   Average transactions per second in last stat period.

avg_query_count
:   Average queries per second in last stat period.

avg_server_assignment_count
:   Average number of times a server as assigned to a client per second in the
    last stat period.

avg_recv
:   Average received (from clients) bytes per second.

avg_sent
:   Average sent (to clients) bytes per second.

avg_xact_time
:   Average transaction duration, in microseconds.

avg_query_time
:   Average query duration, in microseconds.

avg_wait_time
:   Time spent by clients waiting for a server, in microseconds (average
    of the wait times for clients assigned a backend during the current
    `stats_period`).

avg_client_parse_count
:   Average number of prepared statements created by clients. Only applicable
    in named prepared statement tracking mode, see `max_prepared_statements`.

avg_server_parse_count
:   Average number of prepared statements created by **pgbouncer** on a server. Only
    applicable in named prepared statement tracking mode, see `max_prepared_statements`.

avg_bind_count
:   Average number of prepared statements readied for execution by clients and forwarded
    to PostgreSQL by **pgbouncer**. Only applicable in named prepared statement tracking
    mode, see `max_prepared_statements`.

#### SHOW STATS_TOTALS [db]

Subset of **SHOW STATS** showing the total values (**total_**).


#### SHOW STATS_AVERAGES [db]

Subset of **SHOW STATS** showing the average values (**avg_**).

#### SHOW TOTALS

Like **SHOW STATS** but aggregated across all databases.

#### SHOW SERVERS [id]

type
:   S, for server.

user
:   User name **pgbouncer** uses to connect to server.

database
:   Database name.

replication
:   If server connection uses replication. Can be **none**, **logical** or **physical**.

state
:   State of the PgBouncer server connection, one of **active**,
    **idle**, **used**, **tested**, **new**, **active_cancel**,
    **being_canceled**.

addr
:   IP address of PostgreSQL server.

port
:   Port of PostgreSQL server.

local_addr
:   Connection start address on local machine.

local_port
:   Connection start port on local machine.

connect_time
:   When the connection was made.

request_time
:   When last request was issued.

wait
:   Not used for server connections.

wait_us
:   Not used for server connections.

close_needed
:   1 if the connection will be closed as soon as possible,
    because a configuration file reload or DNS update changed the
    connection information or **RECONNECT** was issued.

ptr
:   Address of internal object for this connection.

link
:   Address of client connection the server is paired with.

remote_pid
:   PID of backend server process.  In case connection is made over
    Unix socket and OS supports getting process ID info, its
    OS PID.  Otherwise it's extracted from cancel packet the server sent,
    which should be the PID in case the server is PostgreSQL, but it's a random
    number in case the server it is another PgBouncer.

tls
:   A string with TLS connection information, or empty if not using TLS.

application_name
:   A string containing the `application_name` set on the linked client connection,
    or empty if this is not set, or if there is no linked connection.

prepared_statements
:  The amount of prepared statements that are prepared on the server. This
   number is limited by the `max_prepared_statements` setting.

id
:   Unique ID for server.


#### SHOW CLIENTS [id]

type
:   C, for client.

user
:   Client connected user.

database
:   Database name.

replication
:   If client connection uses replication. Can be **none**, **logical** or **physical**.

state
:   State of the client connection, one of **active** (Client connections that are linked to server connections),
    **idle** (Client connections with no queries waiting to be processed), **waiting**,
    **active_cancel_req**, or **waiting_cancel_req**.

addr
:   IP address of client.

port
:   Source port of client.

local_addr
:   Connection end address on local machine.

local_port
:   Connection end port on local machine.

connect_time
:   Timestamp of connect time.

request_time
:   Timestamp of latest client request.

wait
:   Current waiting time in seconds.

wait_us
:   Microsecond part of the current waiting time.

close_needed
:   not used for clients

ptr
:   Address of internal object for this connection.

link
:   Address of server connection the client is paired with.

remote_pid
:   Process ID, in case client connects over Unix socket
    and OS supports getting it.

tls
:   A string with TLS connection information, or empty if not using TLS.

application_name
:   A string containing the `application_name` set by the client
    for this connection, or empty if this was not set.

prepared_statements
:  The amount of prepared statements that the client has prepared

id
:   Unique ID for client.

#### SHOW POOLS

A new pool entry is made for each couple of (database, user).

database
:   Database name.

user
:   User name.

cl_active
:   Client connections that are either linked to server connections or are idle with no queries waiting to be processed.

cl_waiting
:   Client connections that have sent queries but have not yet got a server connection.

cl_active_cancel_req
:   Client connections that have forwarded query cancellations to the server and
    are waiting for the server response.

cl_waiting_cancel_req
:   Client connections that have not forwarded query cancellations to the server yet.

sv_active
:   Server connections that are linked to a client.

sv_active_cancel
:   Server connections that are currently forwarding a cancel request.

sv_being_canceled
:   Servers that normally could become idle but are waiting to do so until
    all in-flight cancel requests have completed that were sent to cancel
    a query on this server.

sv_idle
:   Server connections that are unused and immediately usable for client queries.

sv_used
:   Server connections that have been idle for more than `server_check_delay`,
    so they need `server_check_query` to run on them before they can be used again.

sv_tested
:   Server connections that are currently running either `server_reset_query`
    or `server_check_query`.

sv_login
:   Server connections currently in the process of logging in.

maxwait
:   How long the first (oldest) client in the queue has waited, in seconds.
    If this starts increasing, then the current pool of servers does
    not handle requests quickly enough.  The reason may be either an overloaded
    server or just too small of a **pool_size** setting.

maxwait_us
:   Microsecond part of the maximum waiting time.

pool_mode
:   The pooling mode in use.

load_balance_hosts
:   The load_balance_hosts in use if the pool's host contains a comma-separated list.

#### SHOW PEER_POOLS [peer_id]

A new peer_pool entry is made for each configured peer.

database
:   ID of the configured peer entry.

cl_active_cancel_req
:   Client connections that have forwarded query cancellations to the server and
    are waiting for the server response.

cl_waiting_cancel_req
:   Client connections that have not forwarded query cancellations to the server yet.

sv_active_cancel
:   Server connections that are currently forwarding a cancel request.

sv_login
:   Server connections currently in the process of logging in.

#### SHOW LISTS

Show following internal information, in columns (not rows):

databases
:   Count of databases.

users
:   Count of users.

pools
:   Count of pools.

free_clients
:   Count of free clients. These are clients that are disconnected, but
    PgBouncer keeps the memory around that was allocated for them so it can be
    reused for a future clients to avoid allocations.

used_clients
:   Count of used clients.

login_clients
:   Count of clients in **login** state.

free_servers
:   Count of free servers. These are servers that are disconnected, but
    PgBouncer keeps the memory around that was allocated for them so it can be
    reused for a future servers to avoid allocations.

used_servers
:   Count of used servers.

dns_names
:   Count of DNS names in the cache.

dns_zones
:   Count of DNS zones in the cache.

dns_queries
:   Count of in-flight DNS queries.

dns_pending
:   not used

#### SHOW USERS [user]

name
:   The user name

pool_size
:   The user's override pool_size. or NULL if not set.

reserve_pool_size
:   The user's override reserve_pool_size. or NULL if not set.

pool_mode
:   The user's override pool_mode, or NULL if not set.

max_user_connections
:   The user's max_user_connections setting. If this setting is not set
    for this specific user, then the default value will be displayed.

current_connections
:   Current number of server connections that this user has open to all servers.

max_user_client_connections
:   The user's max_user_client_connections setting. If this setting is not set
    for this specific user, then the default value will be displayed.

current_client_connections
:   Current number of client connections that this user has open to PgBouncer.

#### SHOW DATABASES [db]

name
:   Name of configured database entry.

host
:   Host PgBouncer connects to.

port
:   Port PgBouncer connects to.

database
:   Actual database name PgBouncer connects to.

force_user
:   When the user is part of the connection string, the connection between
    PgBouncer and PostgreSQL is forced to the given user, whatever the
    client user.

pool_size
:   Maximum number of server connections.

min_pool_size
:   Minimum number of server connections.

reserve_pool_size
:   Maximum number of additional connections for this database.

server_lifetime
:   The maximum lifetime of a server connection for this database

pool_mode
:   The database's override pool_mode, or NULL if the default will be used instead.

load_balance_hosts
:   The database's load_balance_hosts if the host contains a comma-separated list.

max_connections
:   Maximum number of allowed server connections for this database, as set by
    **max_db_connections**, either globally or per database.

current_connections
:   Current number of server connections for this database.

max_client_connections
:   Maximum number of allowed client connections for this PgBouncer instance, as set by max_db_client_connections per database.

current_client_connections
:   Current number of client connections for this database.

paused
:   1 if this database is currently paused, else 0.

disabled
:   1 if this database is currently disabled, else 0.

#### SHOW PEERS [peer_id]

peer_id
:   ID of the configured peer entry.

host
:   Host PgBouncer connects to.

port
:   Port PgBouncer connects to.

pool_size
:   Maximum number of server connections that can be made to this peer

#### SHOW FDS [fd]

Internal command - shows list of file descriptors in use with internal state attached to them.

When the connected user has the user name "pgbouncer", connects through the Unix socket
and has same the UID as the running process, the actual FDs are passed over the connection.
This mechanism is used to do an online restart.
Note: This does not work on Windows.

This command also blocks the internal event loop, so it should not be used
while PgBouncer is in use.

fd
:   File descriptor numeric value.

task
:   One of **pooler**, **client** or **server**.

user
:   User of the connection using the FD.

database
:   Database of the connection using the FD.

addr
:   IP address of the connection using the FD, **unix** if a Unix socket
    is used.

port
:   Port used by the connection using the FD.

cancel
:   Cancel key for this connection.

link
:   fd for corresponding server/client.  NULL if idle.

#### SHOW SOCKETS [id], SHOW ACTIVE_SOCKETS

Shows low-level information about sockets or only active sockets.
This includes the information shown under **SHOW CLIENTS** and **SHOW
SERVERS** as well as other more low-level information.

#### SHOW CONFIG [name]

Show the current configuration settings, one per row, with the following
columns:

key
:   Configuration variable name

value
:   Configuration value

default
:   Configuration default value

changeable
:   Either **yes** or **no**, shows if the variable can be changed while running.
    If **no**, the variable can be changed only at boot time.  Use
    **SET** to change a variable at run time.

#### SHOW MEM [name]

Shows low-level information about the current sizes of various
internal memory allocations.  The information presented is subject to
change.

#### SHOW DNS_HOSTS

Show host names in DNS cache.

hostname
:   Host name.

ttl
:   How many seconds until next lookup.

addrs
:   Comma separated list of addresses.

#### SHOW DNS_ZONES

Show DNS zones in cache.

zonename
:   Zone name.

serial
:   Current serial.

count
:   Host names belonging to this zone.


#### SHOW VERSION

Show the PgBouncer version string.

#### SHOW STATE

Show the PgBouncer state settings. Current states are active, paused and suspended.

### Process controlling commands

#### PAUSE [db]

PgBouncer tries to disconnect from all servers. Disconnecting each server connection
waits for that server connection to be released according to the server pool's pooling
mode (in transaction pooling mode, the transaction must complete, in statement mode,
the statement must complete, and in session pooling mode the client must disconnect).
The command will not return before all server connections have been disconnected.
To be used at the time of database restart.

If database name is given, only that database will be paused.

New client connections to a paused database will wait until **RESUME**
is called.

#### DISABLE db

Reject all new client connections on the given database.

#### ENABLE db

Allow new client connections after a previous **DISABLE** command.

#### RECONNECT [db]

Close each open server connection for the given database, or all
databases, after it is released (according to the pooling mode), even
if its lifetime is not up yet.  New server connections can be made
immediately and will connect as necessary according to the pool size
settings.

This command is useful when the server connection setup has changed,
for example to perform a gradual switchover to a new server.  It is
*not* necessary to run this command when the connection string in
pgbouncer.ini has been changed and reloaded (see **RELOAD**) or when
DNS resolution has changed, because then the equivalent of this
command will be run automatically.  This command is only necessary if
something downstream of PgBouncer routes the connections.

After this command is run, there could be an extended period where
some server connections go to an old destination and some server
connections go to a new destination.  This is likely only sensible
when switching read-only traffic between read-only replicas, or when
switching between nodes of a multimaster replication setup.  If all
connections need to be switched at the same time, **PAUSE** is
recommended instead.  To close server connections without waiting (for
example, in emergency failover rather than gradual switchover
scenarios), also consider **KILL**.

#### KILL [db]

Immediately drop all client and server connections on the given database or all
databases, excluding the admin database.

New client connections to a killed database will wait until **RESUME**
is called.

#### KILL_CLIENT id

Immediately kill specified client connection along with any server
connections for the given client. The client to kill, is identified
by the `id` value that can be found using the `SHOW CLIENTS` command.

An example command will look something like `KILL_CLIENT 1234`.

#### SUSPEND

All socket buffers are flushed and PgBouncer stops listening for data on them.
The command will not return before all buffers are empty.  To be used at the time
of PgBouncer online reboot.

New client connections to a suspended database will wait until
**RESUME** is called.

#### RESUME [db]

Resume work from previous **KILL**, **PAUSE**, or **SUSPEND** command.

#### SHUTDOWN

The PgBouncer process will exit.

#### SHUTDOWN WAIT_FOR_SERVERS

Stop accepting new connections and shutdown after all servers are released.
This is basically the same as issuing **PAUSE** and **SHUTDOWN**, except that
this also stops accepting new connections while waiting for the **PAUSE** as
well as eagerly disconnecting clients that are waiting to receive a server
connection. Please note that UNIX sockets will remain open during the shutdown
but will only accept connections to the PgBouncer admin console.

#### SHUTDOWN WAIT_FOR_CLIENTS

Stop accepting new connections and shutdown the process once all existing
clients have disconnected. Please note that UNIX sockets will remain open
during the shutdown but will only accept connections to the pgbouncer
admin console. This command can be used to do zero-downtime rolling
restart of two PgBouncer processes using the following procedure:

1. Have two or more PgBouncer processes running on the same port using
   `so_reuseport` ([configuring peering](/config.html#section-peers) is
   recommended, but not required). To achieve zero downtime when
   restarting we'll restart these processes one-by-one, thus leaving the
   others running to accept connections while one is being restarted.
2. Pick a process to restart first, let's call it A.
3. Run `SHUTDOWN WAIT_FOR_CLIENTS` (or send `SIGTERM`) to process A.
4. Cause all clients to reconnect. Possibly by waiting some time until the
   client side pooler causes reconnects due to its `server_idle_timeout`
   (or similar config). Or if no client side pooler is used, possibly by
   restarting the clients. Once all clients have reconnected. Process A
   will exit automatically, because no clients are connected to it anymore.
5. Start process A again.
6. Repeat step 3, 4 and 5 for each of the remaining processes, one-by-one
   until you restarted all processes.


#### RELOAD

The PgBouncer process will reload its configuration files and update
changeable settings.  This includes the main configuration file as
well as the files specified by the settings `auth_file` and
`auth_hba_file`.

PgBouncer notices when a configuration file reload changes the
connection parameters of a database definition.  An existing server
connection to the old destination will be closed when the server
connection is next released (according to the pooling mode), and new
server connections will immediately use the updated connection
parameters.

#### WAIT_CLOSE [db]

Wait until all server connections, either of the specified database or
of all databases, have cleared the "close_needed" state (see **SHOW
SERVERS**).  This can be called after a **RECONNECT** or **RELOAD** to
wait until the respective configuration change has been fully
activated, for example in switchover scripts.

### Other commands

#### SET key = arg

Changes a configuration setting (see also **SHOW CONFIG**).  For example:

    SET log_connections = 1;
    SET server_check_query = 'select 2';

(Note that this command is run on the PgBouncer admin console and sets
PgBouncer settings.  A **SET** command run on another database will be
passed to the PostgreSQL backend like any other SQL command.)

### Signals

SIGHUP
:   Reload config. Same as issuing the command **RELOAD** on the console.

SIGTERM
:   Super safe shutdown. Wait for all existing clients to disconnect, but don't
    accept new connections. This is the same as issuing
    **SHUTDOWN WAIT_FOR_CLIENTS** on the console. If this signal is received while
    there is already a shutdown in progress, then an "immediate shutdown" is
    triggered instead of a "super safe shutdown". In PgBouncer versions earlier
    than 1.23.0, this signal would cause an "immediate shutdown".

SIGINT
:   Safe shutdown. Same as issuing **SHUTDOWN WAIT_FOR_SERVERS** on the console.
    If this signal is received while there is already a shutdown in progress,
    then an "immediate shutdown" is triggered instead of a "safe shutdown".

SIGQUIT
:   Immediate shutdown. Same as issuing **SHUTDOWN** on the console.

SIGUSR1
:   Same as issuing **PAUSE** on the console.

SIGUSR2
:   Same as issuing **RESUME** on the console.

### Libevent settings

From the Libevent documentation:

> It is possible to disable support for epoll, kqueue, devpoll, poll
> or select by setting the environment variable EVENT_NOEPOLL,
> EVENT_NOKQUEUE, EVENT_NODEVPOLL, EVENT_NOPOLL or EVENT_NOSELECT,
> respectively.
>
> By setting the environment variable EVENT_SHOW_METHOD, libevent
> displays the kernel notification method that it uses.

## See also

pgbouncer(5) - man page of configuration settings descriptions

<https://www.pgbouncer.org/>
