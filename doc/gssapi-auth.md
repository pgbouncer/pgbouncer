# GSSAPI (Kerberos) Authentication in PgBouncer

## Overview

PgBouncer supports GSSAPI/Kerberos authentication in both directions:

- **Client → pgbouncer (acceptor)**: connecting clients present Kerberos service
  tickets. pgbouncer validates the ticket using its keytab, maps the
  authenticated principal to a local username via `gss_localname()` and the
  site's `auth_to_local` rules in `krb5.conf`, and verifies the result matches
  the username the client claimed in the startup packet.

- **pgbouncer → postgres (initiator)**: when the backend requests GSSAPI
  authentication, pgbouncer authenticates using its own pool service-account
  identity. By default it uses whatever TGT already exists in the process
  credential cache (KCM, FILE:, or any other standard ccache). No client
  credentials are ever forwarded.

No passwords are used anywhere.

## Trust model and authorization boundary

pgbouncer is the **authentication boundary**. It verifies each client's
Kerberos identity and logs the authenticated principal. Postgres trusts the
pool service account (e.g., `pgbouncer@EXAMPLE.COM`) and applies authorization
at that role's level.

```
  [alice@workstation]          [pgbouncer]               [postgres]
        |                          |                          |
        |  StartupMessage          |                          |
        |  user=alice, db=mydb ───>                           |
        |                          |                          |
        |  AuthenticationGSS(7) <──|                          |
        |                          |                          |
        |  GSSResponse (AP-REQ) ───>                          |
        |   (svc ticket for        |  gss_accept_sec_context()|
        |    postgres/<pgb-host>)  |                          |
        |                          |  gss_localname():        |
        |  AuthenticationOk <──────|  alice@EXAMPLE.COM       |
        |                          |   -> alice               |
        |                          |  (matches claimed "alice")|
        |                          |                          |
        |  query ──────────────────>  StartupMessage          |
        |                          |  user=pgbouncer, db=mydb─>
        |                          |                          |
        |                          |  AuthenticationGSS(7) <──|
        |                          |                          |
        |                          |  GSSResponse (AP-REQ) ───>
        |                          |   (svc ticket for        |
        |                          |    postgres/<pg-host>)   |
        |                          |  gss_init_sec_context()  |
        |                          |                          |
        |                          |  AuthenticationOk <──────|
        |                          |                          |
        |  result <────────────────────────────────── query ──>
```

Postgres sees all connections as the `pgbouncer` role. The `pgbouncer` role is
granted the necessary database permissions. This is not a limitation — it is
the correct design for a connection pooler:

- **Connection pooling works by decoupling client identity from server
  connection identity.** A pool of server connections is maintained and reused
  across many clients. If each server connection carried an individual user's
  Kerberos identity, connections could not be shared, eliminating the benefit
  of pooling.
- **The database permissions model follows from this.** Grant what the
  `pgbouncer` role needs. Every client who passes Kerberos authentication to
  pgbouncer inherits those permissions — which is exactly the access policy for
  a shared database.
- **Audit trail is at pgbouncer, not postgres.** pgbouncer logs the full
  authenticated principal (e.g., `alice@EXAMPLE.COM`) on every login.
  Postgres logs queries attributed to `pgbouncer`. This is expected and correct.

### No credential delegation

pgbouncer requests **only** `GSS_C_MUTUAL_FLAG` when calling
`gss_init_sec_context()` for backend connections. `GSS_C_DELEG_FLAG` and
`GSS_C_DELEG_POLICY_FLAG` are never set.

Credential delegation — forwarding a client's TGT so pgbouncer could
authenticate to postgres *as the client* — is deliberately not used:

- It destroys connection reuse: each user's forwarded credential is distinct,
  so connections cannot be shared across users.
- It stores high-value credentials (user TGTs) in the pgbouncer process; a
  compromise exposes every active user.
- It requires the client's TGT to be forwardable and the pgbouncer SPN to be
  flagged `ok-as-delegate` in the KDC.

### Username mapping

`gss_localname()` maps authenticated principals to local usernames by applying
the `auth_to_local` rules from `krb5.conf`. This is the authoritative,
site-policy-respecting mapping; no ad-hoc realm stripping is performed.

Example mappings (configured via `auth_to_local` rules in `krb5.conf`):

| Authenticated principal | Mapped local name |
|---|---|
| `alice@EXAMPLE.COM` | `alice` |
| `alice/admin@EXAMPLE.COM` | `alice` |
| `bob@EXAMPLE.COM` | `bob` |

The mapped name must exactly match the username in the startup packet. The
specific mapping rules depend on your site's `krb5.conf` configuration. Common
`auth_to_local` rules strip the realm and optional instance components:

```
[realms]
    EXAMPLE.COM = {
        auth_to_local = RULE:[1:$1@$0](.*@EXAMPLE\.COM)s/@.*//
        auth_to_local = DEFAULT
    }
```

`gss_localname()` requires MIT Kerberos >= 1.7 (2009), which is verified at
configure time.

#### Relationship to postgres HBA options

PostgreSQL maps GSSAPI principals with the `include_realm`, `krb_realm`, and
`map=` (pg_ident) HBA options. pgbouncer instead delegates principal mapping to
`gss_localname()` / `auth_to_local` in `krb5.conf`, keeping it under a single,
centralized, site-controlled policy rather than split across pg_ident. The
postgres options are handled as follows on a GSSAPI HBA line:

- `include_realm=` is redundant with `auth_to_local` and is ignored with a
  warning, so a GSSAPI `pg_hba.conf` line can be copied over unchanged.
- `krb_realm=` and `map=` *restrict* which principals may authenticate. Silently
  ignoring them would grant more access than the administrator wrote, so a line
  carrying either is rejected (fail closed). Express the equivalent restriction
  as an `auth_to_local` rule in `krb5.conf` and remove the option.

## Build

```sh
./autogen.sh
./configure --with-gssapi
make
```

Requires MIT Kerberos headers and `libgssapi_krb5`. On Debian/Ubuntu:

```sh
apt install libkrb5-dev
```

Confirm GSSAPI compiled in by checking `configure` output:

```
Results:
  gssapi  = yes
```

## Configuration

### pgbouncer.ini

**Minimal configuration** (ccache-based, default for most environments):

```ini
[pgbouncer]
; Authentication method for incoming clients.
; "hba" selects per-database from an auth_hba_file.
auth_type = gssapi

; Keytab for the host-based service SPN that clients acquire tickets for:
;   postgres/<pgbouncer-canonical-fqdn>@REALM
; This is the only required keytab.  pgbouncer uses the process's existing
; TGT (from KCM, FILE:, or any ccache) to authenticate to postgres backends.
auth_gssapi_keytab = /etc/pgbouncer/pgbouncer.keytab

pool_mode = transaction
server_reset_query = DISCARD ALL

[databases]
; IMPORTANT: user= must match the pool service account principal exactly
; as mapped by postgres's pg_ident.conf.
; Without user=pgbouncer, pgbouncer sends the client's username in the
; backend startup message but the GSSAPI identity is the pool account;
; postgres rejects the mismatch.
mydb = host=postgres.example.com dbname=mydb user=pgbouncer
```

**Optional overrides**:

```ini
; Override: acquire backend credentials from a keytab instead of the ccache.
; Use this only when the pgbouncer process cannot maintain a live TGT through
; standard credential management (KCM, kinit, sssd, etc.).
; When set, MIT Kerberos reads keys from this file and acquires a TGT directly.
; The server keytab (auth_gssapi_keytab) must NOT be used here: it contains the
; host-based service SPN, which is the wrong identity for the initiator role.
;auth_gssapi_client_keytab = /etc/pgbouncer/pgbouncer-client.keytab

; Kerberos service name used when constructing the backend service principal.
; Must match krbsrvname in postgresql.conf (default: "postgres").
; The SPN sent is "<service_name>@<host>", resolved to
; <service_name>/<canonical-host>@REALM.
;auth_gssapi_service_name = postgres
```

### HBA-based per-database authentication

To apply different auth methods per database:

```ini
[pgbouncer]
auth_type = hba
auth_hba_file = /etc/pgbouncer/pg_hba.conf
```

```
# /etc/pgbouncer/pg_hba.conf
host  mydb  all  0.0.0.0/0  gssapi
```

**Divergence from PostgreSQL pg_hba.conf**: PostgreSQL supports GSSAPI-specific
HBA options `include_realm`, `krb_realm`, and `map=`. pgbouncer does not
implement these; principal-to-username mapping is handled entirely by
`auth_to_local` rules in `krb5.conf` via `gss_localname()`. `include_realm=` is
redundant with that and is ignored with a warning, so lines using only it copy
over unchanged. `krb_realm=` and `map=` are *restrictive*, so ignoring them would
grant more access than written; a GSSAPI line carrying either is rejected (fail
closed). Move the restriction into an `auth_to_local` rule and remove the option.

## Keytab provisioning

### Required: acceptor keytab

The host-based service principal that libpq clients acquire tickets for:

```
postgres/<pgbouncer-canonical-fqdn>@REALM
```

The FQDN must be the **canonical** name after DNS CNAME resolution. If
`rdns = no` is set in `krb5.conf` (recommended), only forward CNAME resolution
is used — not PTR (reverse) lookups. If clients connect via a DNS alias that
CNAMEs to the pgbouncer host, the SPN must match the final canonical name, not
the alias.

Create the principal and extract a keytab (adjust for your KDC tooling):

```sh
kadmin -q "addprinc -randkey postgres/<pgbouncer-fqdn>@REALM"
kadmin -q "ktadd -k /etc/pgbouncer/pgbouncer.keytab postgres/<pgbouncer-fqdn>@REALM"
chown pgbouncer:pgbouncer /etc/pgbouncer/pgbouncer.keytab
chmod 600 /etc/pgbouncer/pgbouncer.keytab
```

Verify:
```sh
klist -k -t /etc/pgbouncer/pgbouncer.keytab
```

This is the **only keytab required** in environments where the pgbouncer process
already has a TGT (via KCM, kinit, sssd, or any other standard mechanism).
pgbouncer uses that TGT to acquire service tickets for postgres backends, exactly
as any other Kerberos client would.

### Optional: pool service account keytab

Only needed when the pgbouncer process cannot maintain a live TGT through
standard credential management. The principal it should contain:

```
pgbouncer@REALM
```

Create and extract:

```sh
kadmin -q "addprinc -randkey pgbouncer@REALM"
kadmin -q "ktadd -k /etc/pgbouncer/pgbouncer-client.keytab pgbouncer@REALM"
chown pgbouncer:pgbouncer /etc/pgbouncer/pgbouncer-client.keytab
chmod 600 /etc/pgbouncer/pgbouncer-client.keytab
```

Configure with `auth_gssapi_client_keytab = /etc/pgbouncer/pgbouncer-client.keytab`.

**Important**: this file must be separate from the acceptor keytab.
`auth_gssapi_keytab` contains the host-based service SPN
(`postgres/<host>@REALM`), which is the wrong identity for the initiator role.
The two keytabs hold credentials for completely different roles and must never
be substituted for each other.

## Postgres backend setup

### pg_hba.conf

Allow GSSAPI authentication for the pool service account:

```
host all all 0.0.0.0/0 gss map=gssmap
```

### pg_ident.conf

Map the pool account's Kerberos principal to the postgres role:

```
gssmap  /^(.*)@EXAMPLE\.COM$  \1
```

This maps `pgbouncer@EXAMPLE.COM` to the postgres role `pgbouncer`. Adjust the
regex to match your realm and principal naming conventions.

### Pool service account role

```sql
CREATE ROLE pgbouncer LOGIN;
GRANT CONNECT ON DATABASE mydb TO pgbouncer;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO pgbouncer;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO pgbouncer;
```

All clients who authenticate to pgbouncer via Kerberos inherit the permissions
of the `pgbouncer` role. This is the correct model for shared databases.

## Testing

### Step 1: confirm direct client → postgres GSSAPI works

Before introducing pgbouncer, verify that your Kerberos environment and postgres
configuration are working end to end:

```sh
klist   # confirm a valid TGT is present
psql "host=<postgres-fqdn> dbname=mydb user=alice sslmode=disable"
klist   # should now show postgres/<postgres-fqdn>@REALM service ticket
```

### Step 2: confirm pgbouncer's TGT and postgres SPN reachability

As the user account pgbouncer runs under:

```sh
klist   # should show a valid TGT for the pool service account
kvno postgres/<postgres-fqdn>@REALM
```

`klist` confirms the process has a live TGT — pgbouncer will use this to
acquire service tickets for postgres backends automatically.

`kvno` failing with "Server not found in Kerberos database" means the postgres
SPN does not exist in the KDC; address that before proceeding.

If using `auth_gssapi_client_keytab` (no live TGT), test keytab-based
acquisition instead:

```sh
kinit -k -t /etc/pgbouncer/pgbouncer-client.keytab pgbouncer@REALM
kvno postgres/<postgres-fqdn>@REALM
```

### Step 3: start pgbouncer

```sh
./pgbouncer -v /etc/pgbouncer/pgbouncer.ini
```

### Step 4: connect as a user

```sh
# No password. libpq uses GSSAPI automatically when the server requests it.
psql "host=<pgbouncer-fqdn> dbname=mydb user=alice sslmode=disable"
```

Expected pgbouncer log:
```
LOG C-alice@...: GSSAPI: authenticated principal: alice@EXAMPLE.COM
LOG C-alice@...: GSSAPI: principal mapped to local user "alice"
```

Expected postgres log (for the backend connection):
```
LOG  connection received: host=<pgbouncer-ip> user=pgbouncer database=mydb
```

### Step 5: confirm no passwords were involved

```sh
klist   # client side: shows postgres/<pgbouncer-fqdn>@REALM ticket
```

```sql
-- In the psql session:
SELECT current_user;   -- "pgbouncer" — the pool service account
SELECT session_user;   -- "pgbouncer"
```

## Troubleshooting

| Error | Cause |
|---|---|
| `GSSAPI: failed to acquire server credentials from keytab /path` | Wrong keytab path, wrong principal name, or file not readable by pgbouncer user |
| `gss_accept_sec_context: No key table entry for...` | Client's ticket was issued for a SPN not in the acceptor keytab. Confirm the pgbouncer FQDN matches the SPN after CNAME resolution. |
| `GSSAPI: principal mapping failed` | `gss_localname()` could not map the authenticated principal. Check `auth_to_local` rules in `krb5.conf`. |
| `GSSAPI: local name "alice" does not match claimed username "ALICE"` | Case mismatch between `auth_to_local` output and the postgres role name. Add an explicit rule or fix the role name. |
| Backend auth fails: `FATAL: password authentication failed for user "alice"` | `user=pgbouncer` is missing from the `[databases]` entry. pgbouncer sent the client username in the startup message but authenticated via GSSAPI as the pool account; postgres rejected the mismatch. |
| `GSSAPI: failed to acquire initiator credentials from default credential cache` | pgbouncer has no TGT. Ensure the process's ccache (KCM, FILE:, etc.) is populated, or configure `auth_gssapi_client_keytab`. |
| `Server not found in Kerberos database` | The postgres service SPN `postgres/<host>@REALM` does not exist in the KDC. |

## Security notes

- Keytab files must be `chmod 600`, owned by the pgbouncer process user. Anyone
  who can read the server keytab can impersonate the pgbouncer service; anyone
  who can read the client keytab can authenticate to postgres as the pool
  account.
- pgbouncer logs the full authenticated Kerberos principal at INFO level on
  every successful client login when `log_connections = on` (the default).
  Ensure `log_connections` is not disabled in environments where this audit
  trail is required.
- `GSS_C_DELEG_FLAG` is never set. pgbouncer holds no user credentials; a
  compromised pgbouncer process cannot be used to impersonate clients to other
  services.

## Limitations

- **`server_gssencmode = prefer` falls back only on refusal, not on handshake
  failure.** If the backend answers `N`, or pgbouncer has no usable initiator
  credentials, pgbouncer falls back to SSL or plain text. But if the backend
  accepts (`G`) and the GSSAPI handshake then fails (for example, a credential
  expires mid-connect), the connection attempt fails rather than retrying
  without encryption. This matches the existing behavior of
  `server_tls_sslmode = prefer`.
