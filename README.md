# secret-fetch

A minimal CLI tool for fetching secrets from HashiCorp Vault, demonstrating
the core Go patterns used in [swarm-external-secrets](https://github.com/sugar-org/swarm-external-secrets).

## Usage
```bash
# token auth
secret-fetch --path database/mysql --field password --token hvs.xxx

# approle auth
secret-fetch --path database/mysql --field password \\
             --auth approle --role-id <id> --secret-id <id>

# with CA file
secret-fetch --path database/mysql --field password \\
             --token hvs.xxx --ca-file /path/to/ca.pem
```

## Quick demo
```bash
vault server -dev -dev-root-token-id=root &
vault kv put secret/database/mysql password=supersecret username=admin
./secret-fetch --path database/mysql --field password --token root
```
