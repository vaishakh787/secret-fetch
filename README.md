# secret-fetch

A minimal CLI tool written in Go for fetching, listing, and watching secrets from HashiCorp Vault.

Built to demonstrate hands-on experience with the core tech stack of [swarm-external-secrets](https://github.com/sugar-org/swarm-external-secrets) — using the same Go packages, patterns, and design principles.

## Commands

### get — fetch a secret value
```bash
# single field
secret-fetch get --path database/mysql --field password --token root

# all fields as JSON
secret-fetch get --path database/mysql --output json --token root
```

### list — list all secrets under a path
```bash
secret-fetch list --path database --token root
```

### watch — poll for secret changes in real time

Uses SHA256 hash comparison to detect changes — the same pattern as `CheckSecretChanged()` in `swarm-external-secrets`.
```bash
secret-fetch watch --path database/mysql --field password --interval 5s --token root
```

## Quick demo

**Terminal 1 — start Vault and run secret-fetch:**
```bash
vault server -dev -dev-root-token-id=root &
sleep 2
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=root
vault kv put secret/database/mysql password=supersecret username=admin

# fetch single field
./secret-fetch get --path database/mysql --field password --token root

# fetch all fields as JSON
./secret-fetch get --path database/mysql --output json --token root

# list secrets
./secret-fetch list --path database --token root

# watch for changes
./secret-fetch watch --path database/mysql --field password --interval 5s --token root
```

**Terminal 2 — rotate the secret while watch is running:**
```bash
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=root
vault kv put secret/database/mysql password=newpassword123 username=admin
```

**Watch output:**
```
[2026-03-29 21:43:11] watching secret: database/mysql
[2026-03-29 21:43:16] no change detected
[2026-03-29 21:43:21] no change detected
[2026-03-29 21:43:41] SECRET CHANGED
  new value: newpassword123
[2026-03-29 21:43:46] no change detected
```

## All flags

| Flag | Description | Default |
|---|---|---|
| `--addr` | Vault server address | `http://127.0.0.1:8200` |
| `--token` | Vault token | — |
| `--auth` | Auth method: `token` or `approle` | `token` |
| `--role-id` | AppRole role ID | — |
| `--secret-id` | AppRole secret ID | — |
| `--path` | Secret path (required) | — |
| `--field` | Field to extract | auto-detect |
| `--mount` | KV mount path | `secret` |
| `--output` | Output format: `value` or `json` | `value` |
| `--interval` | Watch poll interval | `10s` |
| `--ca-file` | Path to CA certificate file | — |
| `--ca-bundle` | Raw PEM CA bundle string | — |
| `--client-cert` | PEM client certificate for mTLS | — |
| `--client-key` | PEM client key for mTLS | — |
| `--insecure` | Skip TLS verification | `false` |
| `--debug` | Enable debug logging | `false` |

## Go packages used

| Package | Usage |
|---|---|
| `github.com/hashicorp/vault/api` | Vault SDK — token + AppRole auth, KV v2 reads and list |
| `crypto/sha256` | Hash-based change detection for rotation monitoring |
| `crypto/tls`, `crypto/x509`, `encoding/pem` | CABundle parsing, mTLS client cert loading |
| `net/http` | Custom TLS transport injection |
| `context` | Timeout and cancellation on all operations |
| `encoding/json` | Structured JSON output |
| `time` | Configurable poll interval via `time.Ticker` |
| `github.com/sirupsen/logrus` | Structured logging |

## Connection to swarm-external-secrets

The provider abstraction (`providers/vault.go`, `providers/tls.go`) mirrors the structure of `swarm-external-secrets/providers/`. The `watch` subcommand implements the same SHA256-based rotation detection loop as `startMonitoring()` in `driver.go`.
