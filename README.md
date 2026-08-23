# kilovault-cli

Standalone CLI for kilovault secret management, written in Go.

## Building

```bash
make build
# or
go build -o kilovault ./cmd/kilovault
```

Binary will be created at `./kilovault`

## Installing

```bash
make install
# Installs to $GOPATH/bin
```

## Security Model

**Token Generation**
- Tokens are generated **locally on your machine**, not on the server
- Only your machine needs `JWT_SECRET` (to verify you're authorized)
- Server only needs `JWT_SECRET` (to verify token signatures)
- If server is compromised, attacker cannot generate new tokens

**Workflow**
```bash
# 1. Generate token locally (one-time)
kilovault token local -j $JWT_SECRET -u user123 -e 3600 --save

# 2. Use saved token for all operations
kilovault get -k mykey                 # Uses saved token
kilovault set -k mykey -v value        # Uses saved token
kilovault admin list -t $ADMIN_TOKEN
```

## Configuration

### Endpoint/URL

Resolved in this priority order:
1. **Flag**: `-e` / `--endpoint` global flag
2. **Environment**: `KILOVAULT_URL` env var
3. **Config file**: `~/.config/kilovault/config.json` (endpoint field)
4. **Default**: `http://localhost:5096`

Set via flag:
```bash
kilovault -e http://your-server:5096 get mykey
```

Set via environment:
```bash
export KILOVAULT_URL=http://your-server:5096
```

Set in config file:
```bash
kilovault config set endpoint http://your-server:5096
```

### Authentication Token

Token generated locally with `token local` command, then resolved in this priority order:
1. **Flag**: `-t` / `--token` flag
2. **Environment**: `KILOVAULT_USER_TOKEN` env var
3. **Config file**: `~/.config/kilovault/config.json` (token field)

Save generated token:
```bash
kilovault token local -u user123 -j $JWT_SECRET --save
```

Set in config file:
```bash
kilovault config set token <token-value>
```

### Config Directory

Auto-created at `~/.config/kilovault/` (mode 0700) on first use.

Manage config:
```bash
kilovault config show        # Show all config
kilovault config set endpoint http://localhost:5096
kilovault config get endpoint
kilovault config clear endpoint
```

### Token Generation

Generate tokens locally on your machine (not on server):

```bash
# Generate token with JWT_SECRET
kilovault token local -j <jwt_secret> -u <userId> [-e <seconds>] [-p <json-perms>]

# Generate and save token to config
kilovault token local -S -j $JWT_SECRET -u user123 -e 3600

# With permissions
kilovault token local -j $JWT_SECRET -p '{"vault.get":true,"vault.set":true}' -u user123

# Via environment variable
export JWT_SECRET="your-jwt-secret"
kilovault token local -S -u user123 -e 3600
```

**Note:** `-u`/`--user` is required; flags can be given in any order.

### Token Structure (for generating tokens without the CLI)

Tokens are plain HMAC-SHA256 JWTs — no external library or the CLI itself
is required to mint them. This is useful if another tool (e.g. Terraform,
given access to the same `JWT_SECRET`) needs to generate many tokens
programmatically, such as provisioning per-service credentials as part of
cloud infra deployment.

**Format:** `base64url(header) + "." + base64url(payload) + "." + base64url(signature)`

- **header** — JSON, always exactly:
  ```json
  {"alg":"HS256","typ":"JWT"}
  ```
  (The server's verifier never actually reads `alg`/`typ` — it always
  verifies as HMAC-SHA256 — but send this header for interoperability
  with standard JWT tooling.)

- **payload** — JSON with these claims:
  | Claim | Type | Required | Meaning |
  |---|---|---|---|
  | `sub` | string | yes | User ID this token authenticates as |
  | `permissions` | object of `string -> bool` | yes (can be `{}`) | See permissions table below |
  | `iat` | number (unix seconds) | yes | Issued-at time |
  | `exp` | number (unix seconds) | no | Expiry; omit for a non-expiring token |

- **signature** — `HMAC_SHA256(secret, headerB64 + "." + payloadB64)`,
  raw bytes then base64url-encoded.

- **base64url encoding**: standard base64 with `+`→`-`, `/`→`_`, and
  **no `=` padding**, for both parts and the signature.

**Permission strings** are matched exactly (no hierarchy — `admin` does
*not* imply `vault.get`/`vault.set`, and vice versa):

| Permission | Grants |
|---|---|
| `vault.get` | `get` (read own vault value) |
| `vault.set` | `set` (write own vault value) |
| `admin` | all `admin *` subcommands and `admin history`/`admin cleanup` |

A token needs `"permissions": {"admin": true}` to use any `admin`
subcommand, and separately `"vault.get"`/`"vault.set"` for the
non-admin `get`/`set` commands.

**Signing secret** is the same `JWT_SECRET` used by `kilovault token
local -j`. Keep it out of Terraform state/logs (mark outputs
`sensitive`, avoid `local-exec` echoing it) — anyone with it can mint a
token for any user with any permissions.

Reference implementation: `pkg/client/jwt.go` (`GenerateToken`) is the
canonical signer this CLI uses; match its behavior exactly to guarantee
interop.

### Vault Operations

All key/value arguments are flags, not positional arguments — this avoids a
class of silent-drop bugs where a flag placed after a positional argument
is never parsed (see "Encryption Secret" below for why this matters).

```bash
# Get secret (uses saved token)
kilovault get -k mykey

# Set secret (uses saved token)
kilovault set -k mykey -v mysecret

# With specific token
kilovault get -k mykey -t <token>

# With environment token
export KILOVAULT_USER_TOKEN=mytoken
kilovault get -k mykey
```

### Encryption Secret

Optional client-side AES-256-GCM encryption: when a secret is supplied,
`set`/`admin set` encrypt the value locally before sending it, and
`get`/`admin get` decrypt it locally after receiving it. **The secret never
leaves your machine** — the server only ever sees ciphertext.

Resolved in this priority order (same pattern as the auth token):
1. **Flag**: `-s` / `--secret`
2. **Environment**: `KILOVAULT_SECRET`
3. **Config file**: `secret` field, via `kilovault config set secret <value>`

```bash
kilovault set -k mykey -v "sensitive value" -s "my-secret"
kilovault get -k mykey -s "my-secret"

export KILOVAULT_SECRET="my-secret"
kilovault set -k mykey -v "sensitive value"
kilovault get -k mykey
```

If no secret is supplied, `set`/`get` behave exactly as before (plaintext).
A value previously stored without encryption is still readable without a
secret. If a value is encrypted and no secret (or the wrong secret) is
supplied to `get`, the command fails with an error rather than printing
ciphertext or garbage.

### Attribute Edits

Add, replace, or remove individual attributes inside a JSON-object vault
value without hand-editing the whole blob. The CLI fetches the current
value, decrypts it locally (same secret handling as `get`/`set`), applies
all `--set`/`--remove` edits to it in memory, and writes the result back
with a single `set` — the server never sees plaintext or intermediate
state.

```bash
# Add/replace a top-level attribute
kilovault attr -k user1 --set active=true

# Nested dot-path, and multiple edits in one call (applied atomically —
# either everything succeeds and is written, or nothing is)
kilovault attr -k user1 --set profile.name=Jordan --remove profile.oldField

# Array elements are addressed by numeric index; setting index == length
# appends, removing an index splices it out
kilovault attr -k user1 --set tags.0=admin --remove tags.1

# With an encryption secret, same as get/set
kilovault attr -k user1 --set active=false -s "my-secret"
```

Notes:
- `--set path=value`: `value` is parsed as JSON first (`true`, `123`,
  `"quoted string"`, `{"a":1}`, `[1,2]`); anything that isn't valid JSON is
  stored as a plain string.
- If `-k` doesn't exist yet, it's created starting from `{}`. If it exists
  but isn't valid JSON, or a path doesn't already exist for
  `--remove`/a non-leaf `--set` segment, the command errors out and writes
  nothing.
- `--remove` is applied before `--set` when both are given in the same
  call (fixed order — the CLI can't otherwise tell which flag came first
  on the command line).
- Removes/sets are flag-based only — there's no `$EDITOR`/interactive mode,
  so decrypted plaintext never touches disk.

### System Status

```bash
kilovault status
```

### Admin Commands

```bash
# List all keys
kilovault admin list -t <admin-token>

# List keys for specific user
kilovault admin list -u <userId> -t <admin-token>

# Get key for any user (add -s <secret> to decrypt an encrypted value)
kilovault admin get -u <userId> -k <key> -t <admin-token>

# Set key for any user (add -s <secret> to encrypt client-side)
kilovault admin set -u <userId> -k <key> -v <value> -t <admin-token>

# Delete key for any user
kilovault admin delete -u <userId> -k <key> -t <admin-token>

# Get vault history
kilovault admin history -t <admin-token>
kilovault admin history -u <userId> -t <admin-token>

# Cleanup old history
kilovault admin cleanup -t <admin-token>
```

### Automatic Boot Sync via systemd

On a Linux host, `kilovault` can install itself as a systemd service that
fetches a configured set of vault keys at every boot and writes them to
local files other applications on that host can read — without those
applications ever touching the network or the auth token themselves.

This section documents the full contract so infrastructure tooling (e.g.
a Terraform module) can provision a host correctly by reading this file
alone.

**Two new commands:**

- `kilovault install-service` — run once, as root. Sets up everything
  needed for the sync to run automatically on every future boot:
  - Creates the `kilovault-consumers` system group (if missing).
  - Creates a dedicated `kilovault` system user (if missing), whose
    **primary group is `kilovault-consumers`** — this is what makes
    every file `fetch` writes automatically group-readable by consumers,
    with no separate ACL step.
  - Creates `/var/lib/kilovault/.config/kilovault/` (mode `0700`, owned
    by the `kilovault` user) — left empty, ready for config to be
    written into it afterward.
  - Installs and enables (but does **not** start) the
    `kilovault-fetch.service` systemd unit.
  - Idempotent: safe to re-run (e.g. after a binary upgrade); never
    touches an existing `config.json`.
- `kilovault fetch` — the boot-time logic itself, invoked by the
  installed unit. Not meant to be run interactively. Reads the
  `sync-keys` config (below), fetches each key, and writes the three
  output files described below. Fails loudly (non-zero exit) if the
  server is unreachable, a configured key isn't set, or decryption
  fails — it never writes partial output.

**Provisioning sequence (e.g. from Terraform):**

1. Deliver the `kilovault` binary to the host (e.g. downloaded from the
   release bucket for a pinned version tag) and make it executable.
2. Run `kilovault install-service` as root.
3. As the `kilovault` user, populate its config — same `config set`
   command used for interactive use, run for this user's config file
   instead of your own:
   ```bash
   sudo -u kilovault kilovault config set endpoint https://your-kilovault-endpoint
   sudo -u kilovault kilovault config set token <scoped-vault.get-only-token>
   sudo -u kilovault kilovault config set secret <decryption-secret>   # only if values are encrypted
   sudo -u kilovault kilovault config set sync-keys '[{"key":"db_password","as":"DB_PASSWORD"},{"key":"api_key"}]'
   ```
   The token here **must be a scoped token** (e.g. `vault.get` only, for
   one `userId`) minted the same way described in "Token Structure"
   above — never the master `JWT_SECRET`. `JWT_SECRET` should stay in
   whatever secret store mints tokens (e.g. Terraform state) and should
   never land on this host.
4. **Start the service once, immediately** —
   `install-service` only *enables* the unit for future boots; it
   deliberately does not start it, since config doesn't exist until this
   step:
   ```bash
   systemctl start kilovault-fetch.service
   ```
5. Add any local accounts that need to read the synced values (an app's
   own service user, or `root` for `ansible-pull`) to the
   `kilovault-consumers` group:
   ```bash
   usermod -aG kilovault-consumers <consumer-user>
   ```

After that, every subsequent boot runs `fetch` automatically — no
further provisioning steps needed unless the token or `sync-keys` value
changes, in which case re-run step 3 and `systemctl restart
kilovault-fetch.service` to apply it immediately.

**`sync-keys` config value** — a JSON array of `{key, as}` entries. `key`
is the vault key name to fetch; `as` is optional and overrides the local
output name (env var name / YAML key / Ansible fact name) — if omitted,
`key` is used for both. Every resolved output name must be a valid
env-var name (`^[A-Za-z_][A-Za-z0-9_]*$`), and output names must be
unique across the list.

```bash
kilovault config set sync-keys '[{"key":"db_password","as":"DB_PASSWORD"},{"key":"api_key"}]'
```

**Output files** — written to systemd's runtime directory for this
service, `/run/kilovault/`, owned `kilovault:kilovault-consumers`, mode
`0640`. By design, **none of this survives a reboot**: systemd creates
`/run/kilovault` fresh (tmpfs) on every service start and removes it on
stop, so a restart always forces a clean re-fetch from the server rather
than leaving stale secret material on disk.

- `/run/kilovault/env.yaml` — flat `name: value` YAML mapping.
- `/run/kilovault/.env` — `NAME="value"` per line, dotenv-compatible
  quoting/escaping (works with godotenv, python-dotenv, `docker run
  --env-file`, etc.).
- `/run/kilovault/kilovault.fact` — Ansible custom facts, JSON. To have
  Ansible (including `ansible-pull`) pick this up automatically as
  `ansible_local.kilovault.*`, point its `fact_path` at this directory —
  in `ansible.cfg`:
  ```ini
  [defaults]
  fact_path = /run/kilovault
  ```
