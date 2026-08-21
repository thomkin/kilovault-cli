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

## Usage

Set `KILOVAULT_URL` environment variable (default: `http://localhost:5096`):

```bash
export KILOVAULT_URL=http://your-server:5096
```

### Vault Operations

```bash
# Get secret
kilovault get mykey

# Set secret
kilovault set mykey mysecret

# Get with specific token
kilovault get mykey -t <token>
```

### System Status

```bash
kilovault status
```

### Authentication

```bash
kilovault auth <userId> -s <secret> [-p <json-perms>] [-e <seconds>]

# Example
kilovault auth user123 -s mysecret -e 3600
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
