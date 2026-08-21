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

Resolved in this priority order:
1. **Flag**: `-t` / `--token` flag
2. **Environment**: `KILOVAULT_USER_TOKEN` env var
3. **File**: `~/.config/kilovault/user_token.jwt`

Save token from auth:
```bash
kilovault auth user123 -s mysecret --save
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

### Vault Operations

```bash
# Get secret (uses saved token or env token)
kilovault get mykey

# Set secret (uses saved token or env token)
kilovault set mykey mysecret

# Get with specific token
kilovault get mykey -t <token>

# Set with env token
export KILOVAULT_USER_TOKEN=mytoken
kilovault get mykey
```

### System Status

```bash
kilovault status
```

### Authentication

```bash
kilovault auth <userId> -s <secret> [-p <json-perms>] [-e <seconds>] [-S]

# Get token (prints to stdout)
kilovault auth user123 -s mysecret -e 3600

# Get token and save to ~/.config/kilovault/user_token.jwt
kilovault auth user123 -s mysecret -e 3600 --save

# With permissions
kilovault auth user123 -s mysecret -p '{"vault.get":true}'
```

### Admin Commands

```bash
# List all keys
kilovault admin list -t <admin-token>

# List keys for specific user
kilovault admin list <userId> -t <admin-token>

# Get key for any user
kilovault admin get <userId> <key> -t <admin-token>

# Set key for any user
kilovault admin set <userId> <key> <value> -t <admin-token>

# Delete key for any user
kilovault admin delete <userId> <key> -t <admin-token>

# Get vault history
kilovault admin history -t <admin-token>
kilovault admin history <userId> -t <admin-token>

# Cleanup old history
kilovault admin cleanup -t <admin-token>
```
