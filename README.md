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
- Only your machine needs `AUTH_SECRET` (to verify you're authorized)
- Server only needs `JWT_SECRET` (to verify token signatures)
- If server is compromised, attacker cannot generate new tokens

**Workflow**
```bash
# 1. Generate token locally (one-time)
kilovault token local -j $JWT_SECRET -u user123 -e 3600 --save

# 2. Use saved token for all operations
kilovault get mykey           # Uses saved token
kilovault set mykey value     # Uses saved token
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
3. **File**: `~/.config/kilovault/user_token.jwt`

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
