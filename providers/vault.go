package providers

import (
	"context"
	"fmt"
	"net/http"

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
	if cfg.TLS.CABundle != "" || cfg.TLS.CAFile != "" ||
		cfg.TLS.ClientCert != "" || cfg.TLS.Insecure {
		tlsCfg, err := BuildTLSConfig(cfg.TLS)
		if err != nil {
			return nil, fmt.Errorf("failed to configure TLS: %w", err)
		}
		vaultCfg.HttpClient = &http.Client{
			Transport: &http.Transport{TLSClientConfig: tlsCfg},
		}
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
		data := map[string]interface{}{
			"role_id":   v.config.RoleID,
			"secret_id": v.config.SecretID,
		}
		resp, err := v.client.Logical().Write("auth/approle/login", data)
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
	if mountPath == "" {
		mountPath = "secret"
	}
	secretPath := fmt.Sprintf("%s/data/%s", mountPath, path)
	log.Infof("Fetching secret from Vault path: %s", secretPath)
	secret, err := v.client.Logical().ReadWithContext(ctx, secretPath)
	if err != nil {
		return "", fmt.Errorf("failed to read secret from Vault: %w", err)
	}
	if secret == nil {
		return "", fmt.Errorf("secret not found at path: %s", secretPath)
	}
	var data map[string]interface{}
	if kv2, ok := secret.Data["data"]; ok {
		data = kv2.(map[string]interface{})
	} else {
		data = secret.Data
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
	return "", fmt.Errorf("no suitable value found at path: %s", secretPath)
}
