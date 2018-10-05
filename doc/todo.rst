PgBouncer TODO list
===================

Highly visible missing features
-------------------------------

Significant amount of users feel the need for those.

* Protocol-level plan cache.

* LISTEN/NOTIFY.  Requires strict SQL format.

Waiting for contributors...

Problems / cleanups
-------------------

* Bad naming in data strctures:

  * PgSocket->auth_user [vs. PgDatabase->auth_user]
  * PgSocket->db [vs. PgPool->db]

* other per-user settings

* Maintenance order vs. lifetime_kill_gap:
  http://lists.pgfoundry.org/pipermail/pgbouncer-general/2011-February/000679.html

* per_loop_maint/per_loop_activate take too much time in case
  of moderate load and lots of pools.  Perhaps active_pool_list
  would help, which contains only pools touched in current loop.

* new states for clients: idle and in-query.  That allows to apply
  client_idle_timeout and query_timeout without walking all clients
  on maintenance time.

* check if SQL error codes are correct

* removing user should work - kill connections

* keep stats about error counts

* cleanup of logging levels, to make log more useful

* to test:

  - signal flood
  - no mem / no fds handling

* fix high-freq maintenance timer - it's only needed when
  PAUSE/RESUME/shutdown is issued.

* Get rid of SBUF_SMALL_PKT logic - it makes processing code complex.
  Needs a new sbuf_prepare_*() to notify sbuf about short data.
  [Plain 'false' from handler postpones processing to next event loop.]

* units for config parameters.

Dubious/complicated features
----------------------------

* Load-balancing / failover.  Both are already solved via DNS.
  Adding load-balancing config in pgbouncer might be good idea.
  Adding failover decision-making is not...

* User-based route.  Simplest would be to move db info to pool
  and fill username into dns.

* some preliminary notification that fd limit is full

* Move all "look-at-full-packet" situations to SBUF_EV_PKT_CALLBACK

* `pool_mode = plproxy` - use postgres in full-duplex mode for autocommit
  queries, multiplexing several queries into one connection.  Should result
  in more efficient CPU usage of server.

* SMP: spread sockets over per-cpu threads.  Needs confirmation that
  single-threadedness can be problem.  It can also be that only
  accept() + login handling of short connection is problem
  that could be solved by just having threads for login handling,
  which would be lot simpler or just deciding that it is not
  worth fixing.
