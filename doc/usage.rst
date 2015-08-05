
pgbouncer
#########

Synopsis
========

::

  pgbouncer [-d][-R][-v][-u user] <pgbouncer.ini>
  pgbouncer -V|-h

On Windows computers, the options are::

  pgbouncer.exe [-v][-u user] <pgbouncer.ini>
  pgbouncer.exe -V|-h

Additional options for setting up a Windows service::

  pgbouncer.exe --regservice   <pgbouncer.ini>
  pgbouncer.exe --unregservice <pgbouncer.ini>

DESCRIPTION
===========

+pgbouncer+ is a PostgreSQL connection pooler. Any target application
can be connected to +pgbouncer+ as if it were a PostgreSQL server,
and +pgbouncer+ will create a connection to the actual server, or it 
will reuse one of its existing connections.

The aim of +pgbouncer+ is to lower the performance impact of opening
new connections to PostgreSQL.

In order not to compromise transaction semantics for connection
pooling, +pgbouncer+ supports several types of pooling when
rotating connections:

Session pooling
  Most polite method. When client connects, a server connection will
  be assigned to it for the whole duration the client stays connected. When
  the client disconnects, the server connection will be put back into the pool.
  This is the default method.

Transaction pooling
  A server connection is assigned to client only during a transaction.
  When PgBouncer notices that transaction is over, the server connection 
  will be put back into the pool.

Statement pooling
  Most aggressive method. The server connection will be put back into
  pool immediately after a query completes. Multi-statement
  transactions are disallowed in this mode as they would break.

The administration interface of +pgbouncer+ consists of some new
+SHOW+ commands available when connected to a special 'virtual'
database +pgbouncer+.

Quick-start
===========

Basic setup and usage as following.

1. Create a pgbouncer.ini file.  Details in +pgbouncer(5)+.  Simple example::

    [databases]
    template1 = host=127.0.0.1 port=5432 dbname=template1
    
    [pgbouncer]
    listen_port = 6543
    listen_addr = 127.0.0.1
    auth_type = md5
    auth_file = users.txt
    logfile = pgbouncer.log
    pidfile = pgbouncer.pid
    admin_users = someuser
 
2. Create a users.txt file::

    "someuser" "same_password_as_in_server"

3. Launch +pgbouncer+::

     $ pgbouncer -d pgbouncer.ini

4. Have your application (or the +psql+ client) connect to
   +pgbouncer+ instead of directly to PostgreSQL server::

    $ psql -p 6543 -U someuser template1

5. Manage +pgbouncer+ by connecting to the special administration
   database +pgbouncer+ and issuing +show help;+ to begin::

      $ psql -p 6543 -U someuser pgbouncer
      pgbouncer=# show help;
      NOTICE:  Console usage
      DETAIL:
        SHOW [HELP|CONFIG|DATABASES|FDS|POOLS|CLIENTS|SERVERS|SOCKETS|LISTS|VERSION]
        SET key = arg
        RELOAD
        PAUSE
        SUSPEND
        RESUME
        SHUTDOWN

  6. If you made changes to the pgbouncer.ini file, you can reload it with::

      pgbouncer=# RELOAD;

Command line switches
=====================

``-d``
      Run in background. Without it the process will run in foreground.
      Note: Does not work on Windows, +pgbouncer+ need to run as service there.

``-R``
      Do an online restart. That means connecting to the running process, 
      loading the open sockets from it, and then using them.  If there 
      is no active process, boot normally.
      Note: Works only if OS supports Unix sockets and the `unix_socket_dir`
      is not disabled in config.  Does not work on Windows machines.
      Does not work with TLS connections, they are dropped.

``-u user``
      Switch to the given user on startup.

``-v``
      Increase verbosity.  Can be used multiple times.

``-q``
      Be quiet - do not log to stdout.  Note this does not affect
      logging verbosity, only that stdout is not to be used.
      For use in init.d scripts.

``-V``
      Show version.

``-h``
      Show short help.

``--regservice``
      Win32: Register pgbouncer to run as Windows service.  The +service_name+
      config parameter value is used as name to register under.

``--unregservice``
      Win32: Unregister Windows service.

Admin console
=============

The console is available by connecting as normal to the 
database +pgbouncer+::

  $ psql -p 6543 pgbouncer

Only users listed in configuration parameters +admin_users+ or +stats_users+
are allowed to login to the console.  (Except when `auth_mode=any`, then
any user is allowed in as a stats_user.)

Additionally, the username +pgbouncer+ is allowed to log in without password,
if the login comes via Unix socket and the client has same Unix user uid
as the running process.

Show commands
~~~~~~~~~~~~~

The +SHOW+ commands output information. Each command is described below.

SHOW STATS;
-----------

Shows statistics.

``database``
  Statistics are presented per database.

``total_requests``
  Total number of +SQL+ requests pooled by +pgbouncer+.

``total_received``
  Total volume in bytes of network traffic received by +pgbouncer+.

``total_sent``
  Total volume in bytes of network traffic sent by +pgbouncer+.

``total_query_time``
  Total number of microseconds spent by +pgbouncer+ when actively
  connected to PostgreSQL.

``avg_req``
  Average requests per second in last stat period.

``avg_recv``
  Average received (from clients) bytes per second.

``avg_sent``
  Average sent (to clients) bytes per second.

``avg_query``
  Average query duration in microseconds.

SHOW SERVERS;
-------------

``type``
  S, for server.

``user``
  Username +pgbouncer+ uses to connect to server.

``database``
  Database name.

``state``
  State of the pgbouncer server connection, one of +active+, +used+ or
  +idle+.

``addr``
  IP address of PostgreSQL server.

``port``
  Port of PostgreSQL server.

``local_addr``
  Connection start address on local machine.

``local_port``
  Connection start port on local machine.

``connect_time``
  When the connection was made.

``request_time``
  When last request was issued.

``ptr``
  Address of internal object for this connection.
  Used as unique ID.

``link``
  Address of client connection the server is paired with.

``remote_pid``
  Pid of backend server process.  In case connection is made over
  unix socket and OS supports getting process ID info, it's
  OS pid.  Otherwise it's extracted from cancel packet server sent,
  which should be PID in case server is Postgres, but it's a random
  number in case server it another PgBouncer.

SHOW CLIENTS;
-------------

``type``
  C, for client.

``user``
  Client connected user.

``database``
  Database name.

``state``
  State of the client connection, one of +active+, +used+, +waiting+
  or +idle+.

``addr``
  IP address of client.

``port``
  Port client is connected to.

``local_addr``
  Connection end address on local machine.

``local_port``
  Connection end port on local machine.

``connect_time``
  Timestamp of connect time.

``request_time``
  Timestamp of latest client request.

``ptr``
  Address of internal object for this connection.
  Used as unique ID.

``link``
  Address of server connection the client is paired with.

``remote_pid``
  Process ID, in case client connects over UNIX socket
  and OS supports getting it.

SHOW POOLS;
-----------

A new pool entry is made for each couple of (database, user).

``database``
  Database name.

``user``
  User name.

``cl_active``
  Client connections that are linked to server connection and can process queries.

``cl_waiting``
  Client connections have sent queries but have not yet got a server connection.

``sv_active``
  Server connections that linked to client.

``sv_idle``
  Server connections that unused and immediately usable for client queries.

``sv_used``
  Server connections that have been idle more than `server_check_delay`,
  so they needs `server_check_query` to run on it before it can be used.

``sv_tested``
  Server connections that are currently running either `server_reset_query`
  or `server_check_query`.

``sv_login``
  Server connections currently in logging in process.

``maxwait``
  How long the first (oldest) client in queue has waited, in seconds.
  If this starts increasing, then the current pool of servers does
  not handle requests quick enough.  Reason may be either overloaded
  server or just too small of a +pool_size+ setting.

``pool_mode``
  The pooling mode in use.

SHOW LISTS;
-----------

Show following internal information, in columns (not rows):

``databases``
  Count of databases.

``users``
  Count of users.

``pools``
  Count of pools.

``free_clients``
  Count of free clients.

``used_clients``
  Count of used clients.

``login_clients``
  Count of clients in +login+ state.

``free_servers``
  Count of free servers.

``used_servers``
  Count of used servers.

SHOW USERS;
-----------

``name``
  The user name

``pool_mode``
  The user's override pool_mode, or NULL if the default will be used instead.

SHOW DATABASES;
---------------

``name``
  Name of configured database entry.

``host``
  Host pgbouncer connects to.

``port``
  Port pgbouncer connects to.

``database``
  Actual database name pgbouncer connects to.

``force_user``
  When user is part of the connection string, the connection between
  pgbouncer and PostgreSQL is forced to the given user, whatever the
  client user.

``pool_size``
  Maximum number of server connections.

``pool_mode``
  The database's override pool_mode, or NULL if the default will be used instead.

SHOW FDS;
---------

Internal command - shows list of fds in use with internal state attached to them.

When the connected user has username "pgbouncer", connects through Unix socket
and has same UID as running process, the actual fds are passed over the connection.
This mechanism is used to do an online restart.
Note: This does not work on Windows machines.

This command also blocks internal event loop, so it should not be used
while PgBouncer is in use.

``fd``
  File descriptor numeric value.

``task``
  One of +pooler+, +client+ or +server+.

``user``
  User of the connection using the FD.

``database``
  Database of the connection using the FD.

``addr``
  IP address of the connection using the FD, +unix+ if a unix socket
  is used.

``port``
  Port used by the connection using the FD.

``cancel``
  Cancel key for this connection.

``link``
  fd for corresponding server/client.  NULL if idle.

SHOW CONFIG;
------------

Show the current configuration settings, one per row, with following
columns:

``key``
  Configuration variable name

``value``
  Configuration value

``changeable``
  Either +yes+ or +no+, shows if the variable can be changed while running.
  If +no+, the variable can be changed only boot-time.

SHOW DNS_HOSTS;
---------------

Show hostnames in DNS cache.

``hostname``
  Host name.

``ttl``
  How meny seconds until next lookup.

``addrs``
  Comma separated list of addresses.

SHOW DNS_ZONES
--------------

Show DNS zones in cache.

``zonename``
  Zone name.

``serial``
  Current serial.

``count``
  Hostnames belonging to this zone.


Process controlling commands
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

PAUSE [db];
-----------

PgBouncer tries to disconnect from all servers, first waiting for all queries
to complete. The command will not return before all queries are finished.  To be used
at the time of database restart.

If database name is given, only that database will be paused.

DISABLE db;
-----------

Reject all new client connections on the given database.

ENABLE db;
----------

Allow new client connections after a previous +DISABLE+ command.

KILL db;
--------

Immediately drop all client and server connections on given database.

SUSPEND;
--------

All socket buffers are flushed and PgBouncer stops listening for data on them.
The command will not return before all buffers are empty.  To be used at the time
of PgBouncer online reboot.

RESUME [db];
------------

Resume work from previous +PAUSE+ or +SUSPEND+ command.

SHUTDOWN;
---------

The PgBouncer process will exit.

RELOAD;
-------

The PgBouncer process will reload its configuration file and update
changeable settings.

Signals
~~~~~~~

``SIGHUP``
  Reload config. Same as issuing command +RELOAD;+ on console.

``SIGINT``
  Safe shutdown. Same as issuing +PAUSE;+ and +SHUTDOWN;+ on console.

``SIGTERM``
  Immediate shutdown.  Same as issuing +SHUTDOWN;+ on console.

Libevent settings
~~~~~~~~~~~~~~~~~

From libevent docs::

  It is possible to disable support for epoll, kqueue, devpoll, poll
  or select by setting the environment variable EVENT_NOEPOLL,
  EVENT_NOKQUEUE, EVENT_NODEVPOLL, EVENT_NOPOLL or EVENT_NOSELECT,
  respectively.

  By setting the environment variable EVENT_SHOW_METHOD, libevent
  displays the kernel notification method that it uses.

See also
========

pgbouncer(5) - manpage of configuration settings descriptions.

https://pgbouncer.github.io/

https://wiki.postgresql.org/wiki/PgBouncer

