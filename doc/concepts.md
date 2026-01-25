# PgBouncer Concepts Guide

This document explains the key concepts and architecture of PgBouncer for developers and users who want to understand how the codebase works.

## Table of Contents

1. [What is PgBouncer?](#what-is-pgbouncer)
2. [Connection Pooling Modes](#connection-pooling-modes)
3. [Core Data Structures](#core-data-structures)
4. [Socket States](#socket-states)
5. [The Pool](#the-pool)
6. [Event-Driven Architecture](#event-driven-architecture)
7. [Stream Buffer (SBuf)](#stream-buffer-sbuf)
8. [The Janitor](#the-janitor)
9. [Authentication](#authentication)
10. [Prepared Statements](#prepared-statements)
11. [Peering](#peering)
12. [Admin Console](#admin-console)
13. [Configuration Architecture](#configuration-architecture)

---

## What is PgBouncer?

PgBouncer is a lightweight connection pooler for PostgreSQL. It sits between your application and the PostgreSQL server, managing a pool of database connections that can be reused by multiple clients.

**Why use connection pooling?**

Opening a new PostgreSQL connection is expensive—it involves:
- TCP handshake
- SSL/TLS negotiation (if enabled)
- Authentication
- Backend process forking on the PostgreSQL server

PgBouncer eliminates this overhead by maintaining persistent connections to PostgreSQL and multiplexing client requests over them.

**Key benefits:**
- Reduces connection overhead for applications
- Limits the number of connections to PostgreSQL (which has per-connection memory overhead)
- Enables thousands of clients to share a smaller pool of database connections

---

## Connection Pooling Modes

PgBouncer supports three pooling modes that determine when a server connection can be reused by another client:

### Session Pooling (default)

```
Client connects → Gets server connection → Keeps it until disconnect
```

- Server connection is assigned when client connects
- Released back to pool only when client disconnects
- Most compatible mode—supports all PostgreSQL features
- Least efficient for connection reuse

**Use when:** Your application uses session-level features (temporary tables, session variables, `LISTEN/NOTIFY`, etc.)

### Transaction Pooling

```
Client connects → Gets server for transaction → Released after COMMIT/ROLLBACK
```

- Server connection assigned only during a transaction
- Released immediately after transaction ends
- Different queries from the same client may go to different server connections

**Use when:** Your application doesn't rely on session state between transactions. This is the most common mode for web applications.

**Restrictions:**
- No `SET` commands that affect session state (use `track_extra_parameters` for allowed ones)
- No `LISTEN/NOTIFY`
- No temporary tables (outside transactions)
- No prepared statements without `max_prepared_statements` configured

### Statement Pooling

```
Client connects → Gets server per query → Released after each statement
```

- Most aggressive mode
- Server released after each individual SQL statement
- Multi-statement transactions are **disallowed**

**Use when:** All your queries are single-statement and don't need transactions.

---

## Core Data Structures

Understanding these structures is essential for navigating the codebase.

### PgSocket

Defined in `include/bouncer.h`, `PgSocket` represents both client and server connections. The same structure is used for both, distinguished by state values.

```c
struct PgSocket {
    struct List head;           /* list header for pool list */
    PgSocket *link;             /* the dest of packets (paired client/server) */
    PgPool *pool;               /* parent pool */
    PgCredentials *login_user_credentials;
    
    SocketState state;          /* current state - determines which list it's in */
    
    bool ready;                 /* server: accepts new query */
    bool idle_tx;               /* server: idling in transaction */
    bool close_needed;          /* server: must be closed ASAP */
    
    uint8_t cancel_key[8];      /* cancellation key */
    
    SBuf sbuf;                  /* stream buffer for I/O */
    // ... more fields
};
```

**Key insight:** The `state` field determines which list the socket belongs to and whether it's a client or server socket (`is_server_socket(sk)` macro checks if `state >= SV_FREE`).

### PgPool

A pool contains connections for one **database + user** combination.

```c
struct PgPool {
    PgDatabase *db;                 /* database configuration */
    PgCredentials *user_credentials; /* user for this pool */
    
    /* Client lists */
    struct StatList active_client_list;    /* clients with active server link */
    struct StatList waiting_client_list;   /* clients waiting for a server */
    
    /* Server lists */
    struct StatList active_server_list;    /* servers linked to clients */
    struct StatList idle_server_list;      /* servers ready for new clients */
    struct StatList used_server_list;      /* servers needing reset before reuse */
    struct StatList tested_server_list;    /* servers running reset query */
    struct StatList new_server_list;       /* servers in login phase */
    
    PgStats stats;              /* statistics for this pool */
    // ...
};
```

Each pool has separate lists for different socket states. The janitor moves sockets between these lists as their state changes.

### PgDatabase

Represents a database entry from the `[databases]` section in the config file.

```c
struct PgDatabase {
    char name[MAX_DBNAME];      /* database name clients connect to */
    char *host;                 /* PostgreSQL server host */
    int port;
    int pool_size;              /* max connections per pool */
    int pool_mode;              /* session/transaction/statement */
    PgCredentials *forced_user_credentials;  /* if set, all connections use this user */
    // ...
};
```

### PgCredentials and PgGlobalUser

`PgCredentials` holds authentication data for a user:

```c
struct PgCredentials {
    char name[MAX_USERNAME];
    char passwd[MAX_PASSWORD];
    PgGlobalUser *global_user;  /* points to global settings */
    // SCRAM keys, etc.
};
```

`PgGlobalUser` holds global configuration and connection tracking:

```c
struct PgGlobalUser {
    PgCredentials credentials;
    int pool_mode;
    int pool_size;
    int max_user_connections;
    int connection_count;       /* current server connections */
    // ...
};
```

---

## Socket States

Sockets move through various states tracked by the `SocketState` enum. Each state corresponds to a specific list in a pool.

### Client States

| State | List | Description |
|-------|------|-------------|
| `CL_FREE` | `free_client_list` | Freed, memory kept for reuse |
| `CL_LOGIN` | `login_client_list` | Authentication in progress |
| `CL_WAITING` | `pool->waiting_client_list` | Waiting for a server connection |
| `CL_ACTIVE` | `pool->active_client_list` | Linked to a server, processing queries |
| `CL_WAITING_CANCEL` | `pool->waiting_cancel_req_list` | Waiting to send cancel request |
| `CL_ACTIVE_CANCEL` | `pool->active_cancel_req_list` | Cancel request in flight |


State transitions for the client state of each socket should follow the sequence
```
CL_LOGIN (CL_WAITING CL_ACTIVE)*  CL_FREE
```

### Server States

| State | List | Description |
|-------|------|-------------|
| `SV_FREE` | `free_server_list` | Freed, memory kept for reuse |
| `SV_LOGIN` | `pool->new_server_list` | Connecting/authenticating to PostgreSQL |
| `SV_IDLE` | `pool->idle_server_list` | Ready to be assigned to a client |
| `SV_ACTIVE` | `pool->active_server_list` | Linked to a client, processing queries |
| `SV_USED` | `pool->used_server_list` | Just released, needs check before reuse |
| `SV_TESTED` | `pool->tested_server_list` | Running `server_check_query` or `server_reset_query` |
| `SV_BEING_CANCELED` | `pool->being_canceled_server_list` | Waiting for in-flight cancel to complete |

The server state transitions should follow
```
SV_LOGIN (SV_IDLE SV_ACTIVE SV_USED SV_TESTED SV_IDLE)*
```

---

## The Pool

A pool is the central concept in PgBouncer. It manages the relationship between clients and servers for a specific database+user combination.

### Pool Sizing

- `pool_size` (or `default_pool_size`): Maximum server connections in the pool
- `min_pool_size`: Minimum connections to maintain (helps with burst traffic)
- `reserve_pool_size`: Extra connections allowed when `reserve_pool_timeout` is exceeded

### Client-Server Pairing

When a client needs a server:

1. **Check for idle servers:** If `idle_server_list` is not empty, grab one
2. **Launch new connection:** If under `pool_size`, create a new server connection
3. **Wait:** Client moves to `waiting_client_list`
4. **Eviction (optional):** May evict connections from other pools if limits allow

The pairing is stored in `PgSocket->link`—the client's `link` points to the server, and vice versa.

### Connection Lifecycle


1. Client connects to PgBouncer
2. PgBouncer authenticates client
3. Client placed in waiting_client_list (or gets idle server immediately)
4. When server available: client and server are "linked"
5. Query flows: client → PgBouncer → server → PgBouncer → client
6. Based on pool_mode, server is released back to pool
7. Client can get same or different server for next query/transaction


---

## Event-Driven Architecture

PgBouncer uses **libevent** for asynchronous I/O handling. This allows a single thread to manage thousands of connections efficiently.

### Main Event Loop

```c
// In main.c
event_base_dispatch(pgb_event_base);
```

The event loop waits for:
- Socket readability (data available to read)
- Socket writability (can send data)
- Timeouts (periodic maintenance)

### Event Handlers

Each `PgSocket` has an associated libevent structure in its `SBuf`:

```c
struct SBuf {
    struct event ev;    /* libevent handle */
    // ...
};
```

When data arrives on a socket, the corresponding callback is invoked, which eventually calls the protocol handler (`sbuf_cb_t`).

### Single-Threaded Design

PgBouncer is intentionally single-threaded:
- Simpler code (no locks needed)
- Efficient for I/O-bound workloads
- For multi-core usage, run multiple PgBouncer instances with `so_reuseport`

---

## Stream Buffer (SBuf)

The `SBuf` (Stream Buffer) is PgBouncer's I/O abstraction layer, defined in `include/sbuf.h`.

### Purpose

- Manages socket I/O (read/write buffers)
- Handles packet framing (PostgreSQL protocol packets)
- Supports TLS encryption
- Provides flow control (pause/resume)

### Key Operations

```c
// Initialize a stream buffer
void sbuf_init(SBuf *sbuf, sbuf_cb_t proto_fn);

// Accept incoming connection
bool sbuf_accept(SBuf *sbuf, int sock, bool is_unix);

// Connect to remote server
bool sbuf_connect(SBuf *sbuf, const struct sockaddr *sa, ...);

// Pause/resume reading
bool sbuf_pause(SBuf *sbuf);
void sbuf_continue(SBuf *sbuf);

// Prepare to forward data to another sbuf
void sbuf_prepare_send(SBuf *sbuf, SBuf *dst, unsigned amount);
```

### Packet Handling

When a complete packet arrives:

1. SBuf calls the protocol callback (`sbuf_cb_t`)
2. Callback inspects packet header
3. Callback decides: forward to destination, skip, or handle internally
4. SBuf executes the decision

### IOBuf

`IOBuf` is the actual data buffer that holds bytes read from or waiting to be written to a socket:

```c
struct iobuf {
    unsigned done_pos;      /* bytes already sent */
    unsigned parse_pos;     /* bytes parsed (ready to send) */
    unsigned recv_pos;      /* bytes received (includes unparsed) */
    uint8_t buf[FLEX_ARRAY]; /* actual data buffer */
};
```


IOBuf uses a **lazy allocation with slab caching** approach:

1. **Lazy allocation:** The `IOBuf` is not allocated when the `SBuf` is created. It's only allocated on-demand when actual data needs to be read:

```c
struct SBuf {
    IOBuf *io;          /* data buffer, lazily allocated */
    // ...
};
```

2. **Slab allocator:** IOBufs are managed through a slab cache (`iobuf_cache`), which pre-allocates memory in chunks and recycles freed objects. This avoids the overhead of frequent `malloc()`/`free()` calls for these frequently-used, fixed-size buffers.

3. **Eager release:** When the buffer becomes empty (all data sent), it's immediately returned to the slab cache:

   ```c
   if (release && iobuf_empty(io)) {
       slab_free(iobuf_cache, io);
       sbuf->io = NULL;
   }
   ```

4. **Buffer compaction:** Before allocating new space, `iobuf_try_resync()` attempts to compact existing data by moving unparsed bytes to the start of the buffer, reclaiming space from already-sent data.

The buffer size is controlled by the `pkt_buf` configuration option (default: 4096 bytes).

---

## The Janitor

The janitor (`src/janitor.c`) performs periodic maintenance tasks. It runs **3 times per second** by default.

### Key Responsibilities

1. **Connection management:**
   - Close idle servers exceeding `server_idle_timeout`
   - Close servers exceeding `server_lifetime`
   - Launch new connections to meet `min_pool_size`

2. **Client timeout enforcement:**
   - `query_timeout`: Kill queries running too long
   - `query_wait_timeout`: Disconnect clients waiting too long for a server
   - `client_idle_timeout`: Disconnect idle clients
   - `idle_transaction_timeout`: Kill idle-in-transaction sessions

3. **Server health checks:**
   - Run `server_check_query` on servers idle longer than `server_check_delay`
   - Run `server_reset_query` on released connections (session mode)

4. **Pool maintenance:**
   - Clean up auto-created databases after `autodb_idle_timeout`
   - Handle pause/resume state
   - Manage DNS updates

### Code Flow

```c
// Simplified janitor flow
static void do_full_maint(int sock, short flags, void *arg) {
    // For each pool:
    per_loop_maint(pool);       // timeouts, checks
    
    // Global tasks:
    cleanup_inactive_autodatabases();
    reuse_just_freed_objects();
    
    // Reschedule
    evtimer_add(&full_maint_ev, &full_maint_period);
}
```

---

## Authentication

PgBouncer handles authentication on both sides: clients authenticating to PgBouncer, and PgBouncer authenticating to PostgreSQL.

### Client Authentication

Configured via `auth_type`:

| Type | Description |
|------|-------------|
| `trust` | No password required |
| `md5` | MD5 password hash |
| `scram-sha-256` | SCRAM-SHA-256 (most secure) |
| `cert` | TLS client certificate |
| `hba` | Use `auth_hba_file` rules |
| `pam` | PAM authentication |
| `ldap` | LDAP authentication |

### Password Sources

1. **auth_file:** Static file with usernames and passwords/hashes
2. **auth_query:** Query a database to look up passwords dynamically
3. **auth_user:** User that runs the `auth_query`

### Server Authentication

PgBouncer uses credentials from:
1. Password specified in `[databases]` section
2. Password from `auth_file` for the user
3. SCRAM keys cached from previous authentications

### SCRAM Pass-Through

When both client and server use SCRAM, PgBouncer can cache SCRAM keys to avoid storing plain-text passwords. This is tracked in `PgCredentials`:

```c
struct PgCredentials {
    uint8_t scram_ClientKey[32];
    uint8_t scram_ServerKey[32];
    bool use_scram_keys;
    // ...
};
```

---

## Prepared Statements

In transaction/statement pooling, prepared statements are tricky because a client might prepare a statement on one server but need to execute it on another.

### The Problem

```sql
-- Client prepares on Server A
PREPARE my_stmt AS SELECT * FROM users WHERE id = $1;

-- Transaction ends, server released
-- Next transaction might get Server B
-- Server B doesn't have 'my_stmt'!
```

### PgBouncer's Solution

When `max_prepared_statements > 0`:

1. **Track prepared statements:** PgBouncer intercepts `Parse` messages and tracks which statements clients have prepared
2. **Internal naming:** PgBouncer gives each unique query an internal name (`PGBOUNCER_{id}`)
3. **Transparent re-preparation:** If a client executes a statement that isn't prepared on the current server, PgBouncer prepares it first
4. **LRU cache:** Each server maintains an LRU cache of prepared statements (size = `max_prepared_statements`)

### Data Structures

```c
// Per-client: what the client has prepared
PgClientPreparedStatement *client_prepared_statements;

// Per-server: what's actually prepared on PostgreSQL  
PgServerPreparedStatement *server_prepared_statements;

// Global: maps query strings to internal IDs
PgPreparedStatement *prepared_statements;
```

### Limitations

- Only works for protocol-level prepared statements (not SQL `PREPARE`)
- `DEALLOCATE ALL` and `DISCARD ALL` clear tracked statements
- Schema changes can cause "cached plan must not change result type" errors

---

## Peering

Peering allows multiple PgBouncer instances to work together, primarily for:
- Multi-core scalability (via `so_reuseport`)
- Query cancellation across instances

### The Cancellation Problem

PostgreSQL uses out-of-band cancel requests (separate TCP connection). With load balancing:

```
1. Client sends query through LB → PgBouncer A → PostgreSQL
2. Client sends cancel through LB → PgBouncer B (different instance!)
3. PgBouncer B doesn't know about the query
```

### Solution: Peer Forwarding

Configure peers in `[peers]` section:

```ini
[peers]
1 = host=/tmp/pgbouncer1
2 = host=/tmp/pgbouncer2

[pgbouncer]
peer_id = 1  # Unique ID for this instance
```

Each cancel key encodes which peer originated it. When a cancel arrives at the wrong peer, it's forwarded to the correct one (up to 3 hops).

### peer_id Encoding

```c
// Cancel keys include a TTL in the last 2 bits
#define CANCELLATION_TTL_MASK 0x03
```

The `peer_id` is encoded in the cancel key so PgBouncer knows where to forward unrecognized cancellations.

---

## Admin Console

PgBouncer provides an admin interface via a special "database" named `pgbouncer`.

### Connecting

```bash
psql -p 6432 -U admin_user pgbouncer
```

### Key Commands

| Command | Description |
|---------|-------------|
| `SHOW POOLS` | Display pool statistics |
| `SHOW STATS` | Show query/transaction statistics |
| `SHOW SERVERS` | List server connections |
| `SHOW CLIENTS` | List client connections |
| `SHOW CONFIG` | Show current configuration |
| `PAUSE [db]` | Pause a database (wait for transactions to finish) |
| `RESUME [db]` | Resume after pause |
| `RELOAD` | Reload configuration file |
| `SHUTDOWN` | Stop PgBouncer |

### Access Control

- `admin_users`: Can run all commands
- `stats_users`: Can only run `SHOW` commands (read-only)

### Implementation

The admin console is implemented in `src/admin.c`. It uses a simplified query parser and returns results as PostgreSQL protocol messages.

---

## Configuration Architecture

### File Format

PgBouncer uses INI-style configuration:

```ini
[databases]
mydb = host=localhost port=5432 dbname=mydb

[pgbouncer]
listen_port = 6432
pool_mode = transaction
max_client_conn = 1000

[users]
admin = pool_mode=session
```

### Configuration Sections

| Section | Purpose |
|---------|---------|
| `[databases]` | Database connection definitions |
| `[pgbouncer]` | Global settings |
| `[users]` | Per-user overrides |
| `[peers]` | Peer PgBouncer instances |

### Precedence

Settings can be specified at multiple levels:

1. **Command-line arguments** (highest priority)
2. **Per-user settings** (`[users]` section)
3. **Per-database settings** (`[databases]` section)  
4. **Global settings** (`[pgbouncer]` section)
5. **Compiled defaults** (lowest priority)

### Runtime Changes

Some settings can be changed at runtime:
- Via `SET` command in admin console
- Via `RELOAD` command (re-reads config file)

Check `changeable` column in `SHOW CONFIG` output.

### Include Directive

Split configuration across files:

```ini
%include /etc/pgbouncer/databases.ini
%include /etc/pgbouncer/users.ini
```

---

## Key Source Files

| File | Purpose |
|------|---------|
| `src/main.c` | Entry point, event loop setup |
| `src/objects.c` | Data structure management (pools, sockets) |
| `src/client.c` | Client connection handling |
| `src/server.c` | Server connection handling |
| `src/pooler.c` | Listen socket management |
| `src/janitor.c` | Periodic maintenance |
| `src/admin.c` | Admin console |
| `src/loader.c` | Configuration loading |
| `src/sbuf.c` | Stream buffer I/O |
| `src/proto.c` | PostgreSQL protocol handling |
| `src/prepare.c` | Prepared statement tracking |
| `include/bouncer.h` | Main data structures |

---

## Glossary

| Term | Definition |
|------|------------|
| **Pool** | Collection of connections for one database+user combination |
| **Client** | Application connecting to PgBouncer |
| **Server** | PostgreSQL backend connection |
| **Link** | Pairing between a client and server socket |
| **SBuf** | Stream Buffer - I/O abstraction |
| **Janitor** | Periodic maintenance routine |
| **Peer** | Another PgBouncer instance in a cluster |
| **Cancel Key** | Token used for query cancellation |
| **VarCache** | Cache of session parameter values |

---

## Further Reading

- [PgBouncer Homepage](https://www.pgbouncer.org/)
- [GitHub Repository](https://github.com/pgbouncer/pgbouncer)
- [PostgreSQL Protocol Documentation](https://www.postgresql.org/docs/current/protocol.html)
- Configuration reference: `doc/config.md`
- Usage reference: `doc/usage.md`
