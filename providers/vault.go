package providers

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"time"

	"github.com/hashicorp/vault/api"
	log "github.com/sirupsen/logrus"
)

type VaultConfig struct {
	Address    string
	Token      string
	RoleID     string
	SecretID   string
	AuthMethod string
	MountPath  string
	TLS        TLSConfig
}

type VaultProvider struct {
	client *api.Client
	config *VaultConfig
}

func NewVaultProvider(cfg *VaultConfig) (*VaultProvider, error) {
	vaultCfg := api.DefaultConfig()
	vaultCfg.Address = cfg.Address
	if cfg.TLS.CABundle != "" || cfg.TLS.CAFile != "" || cfg.TLS.ClientCert != "" || cfg.TLS.Insecure {
		tlsCfg, err := BuildTLSConfig(cfg.TLS)
		if err != nil {
			return nil, fmt.Errorf("failed to configure TLS: %w", err)
		}
		vaultCfg.HttpClient = &http.Client{Transport: &http.Transport{TLSClientConfig: tlsCfg}}
		log.Info("TLS configured successfully")
	}
	client, err := api.NewClient(vaultCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create Vault client: %w", err)
	}
	p := &VaultProvider{client: client, config: cfg}
	if err := p.authenticate(); err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}
	return p, nil
}

func (v *VaultProvider) authenticate() error {
	switch v.config.AuthMethod {
	case "token", "":
		if v.config.Token == "" {
			return fmt.Errorf("--token is required for token auth")
		}
		v.client.SetToken(v.config.Token)
		log.Infof("Authenticated with Vault using token method")
	case "approle":
		if v.config.RoleID == "" || v.config.SecretID == "" {
			return fmt.Errorf("--role-id and --secret-id are required for approle auth")
		}
		resp, err := v.client.Logical().Write("auth/approle/login", map[string]interface{}{
			"role_id": v.config.RoleID, "secret_id": v.config.SecretID,
		})
		if err != nil {
			return fmt.Errorf("approle login failed: %w", err)
		}
		if resp.Auth == nil {
			return fmt.Errorf("no auth info returned from approle login")
		}
		v.client.SetToken(resp.Auth.ClientToken)
		log.Infof("Authenticated with Vault using approle method")
	default:
		return fmt.Errorf("unsupported auth method: %s (supported: token, approle)", v.config.AuthMethod)
	}
	return nil
}

func (v *VaultProvider) FetchSecret(ctx context.Context, path, field, mountPath string) (string, error) {
	data, err := v.fetchData(ctx, path, mountPath)
	if err != nil {
		return "", err
	}
	if field != "" {
		val, ok := data[field]
		if !ok {
			available := make([]string, 0, len(data))
			for k := range data {
				available = append(available, k)
			}
			return "", fmt.Errorf("field %q not found; available fields: %v", field, available)
		}
		return fmt.Sprintf("%v", val), nil
	}
	for _, f := range []string{"value", "password", "secret", "data"} {
		if val, ok := data[f]; ok {
			return fmt.Sprintf("%v", val), nil
		}
	}
	for _, val := range data {
		if str, ok := val.(string); ok {
			return str, nil
		}
	}
	return "", fmt.Errorf("no suitable value found at path: %s", path)
}

func (v *VaultProvider) FetchSecretAllFields(ctx context.Context, path, mountPath string) (map[string]interface{}, error) {
	return v.fetchData(ctx, path, mountPath)
}

func (v *VaultProvider) ListSecrets(ctx context.Context, path, mountPath string) ([]string, error) {
	if mountPath == "" {
		mountPath = "secret"
	}
	listPath := fmt.Sprintf("%s/metadata/%s", mountPath, path)
	log.Infof("Listing secrets at Vault path: %s", listPath)
	secret, err := v.client.Logical().ListWithContext(ctx, listPath)
	if err != nil {
		return nil, fmt.Errorf("failed to list secrets: %w", err)
	}
	if secret == nil {
		return nil, fmt.Errorf("no secrets found at path: %s", path)
	}
	keysRaw, ok := secret.Data["keys"]
	if !ok {
		return nil, fmt.Errorf("no keys returned at path: %s", path)
	}
	rawSlice, ok := keysRaw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected keys format at path: %s", path)
	}
	keys := make([]string, 0, len(rawSlice))
	for _, k := range rawSlice {
		keys = append(keys, fmt.Sprintf("%v", k))
	}
	return keys, nil
}

func (v *VaultProvider) fetchData(ctx context.Context, path, mountPath string) (map[string]interface{}, error) {
	if mountPath == "" {
		mountPath = "secret"
	}
	secretPath := fmt.Sprintf("%s/data/%s", mountPath, path)
	log.Infof("Fetching secret from Vault path: %s", secretPath)
	secret, err := v.client.Logical().ReadWithContext(ctx, secretPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read secret from Vault: %w", err)
	}
	if secret == nil {
		return nil, fmt.Errorf("secret not found at path: %s", secretPath)
	}
	if kv2, ok := secret.Data["data"]; ok {
		return kv2.(map[string]interface{}), nil
	}
	return secret.Data, nil
}

// WatchSecret polls a secret at the given interval and calls onChange when the value changes.
// It uses SHA256 hashing to detect changes — the same pattern as CheckSecretChanged()
// in swarm-external-secrets.
func (v *VaultProvider) WatchSecret(ctx context.Context, path, field, mountPath string, interval time.Duration, onChange func(newValue string)) error {
	data, err := v.fetchData(ctx, path, mountPath)
	if err != nil {
		return fmt.Errorf("initial fetch failed: %w", err)
	}

	current, err := extractField(data, field)
	if err != nil {
		return err
	}
	lastHash := hashValue(current)

	log.Infof("Watching secret: %s (field: %s, interval: %s)", path, field, interval)
	fmt.Printf("[%s] watching secret: %s\n", timestamp(), path)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			fmt.Printf("[%s] watch stopped\n", timestamp())
			return nil
		case <-ticker.C:
			data, err := v.fetchData(ctx, path, mountPath)
			if err != nil {
				fmt.Printf("[%s] error fetching secret: %v\n", timestamp(), err)
				continue
			}
			val, err := extractField(data, field)
			if err != nil {
				fmt.Printf("[%s] error extracting field: %v\n", timestamp(), err)
				continue
			}
			currentHash := hashValue(val)
			if currentHash != lastHash {
				fmt.Printf("[%s] SECRET CHANGED\n", timestamp())
				lastHash = currentHash
				onChange(val)
			} else {
				fmt.Printf("[%s] no change detected\n", timestamp())
			}
		}
	}
}

func hashValue(s string) string {
	h := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", h)
}

func timestamp() string {
	return time.Now().Format("2006-01-02 15:04:05")
}

func extractField(data map[string]interface{}, field string) (string, error) {
	if field != "" {
		val, ok := data[field]
		if !ok {
			available := make([]string, 0, len(data))
			for k := range data {
				available = append(available, k)
			}
			return "", fmt.Errorf("field %q not found; available: %v", field, available)
		}
		return fmt.Sprintf("%v", val), nil
	}
	for _, f := range []string{"value", "password", "secret", "data"} {
		if val, ok := data[f]; ok {
			return fmt.Sprintf("%v", val), nil
		}
	}
	for _, val := range data {
		if str, ok := val.(string); ok {
			return str, nil
		}
	}
	return "", fmt.Errorf("no suitable value found")
}
