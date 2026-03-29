package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/vaishakh787/secret-fetch/providers"
	log "github.com/sirupsen/logrus"
)

func main() {
	addr       := flag.String("addr",        "http://127.0.0.1:8200", "Vault server address")
	token      := flag.String("token",       "",                       "Vault token (token auth)")
	roleID     := flag.String("role-id",     "",                       "AppRole role ID")
	secretID   := flag.String("secret-id",   "",                       "AppRole secret ID")
	authMethod := flag.String("auth",        "token",                  "Auth method: token | approle")
	path       := flag.String("path",        "",                       "Secret path (e.g. database/mysql)")
	field      := flag.String("field",       "",                       "Field to extract (e.g. password)")
	mountPath  := flag.String("mount",       "secret",                 "KV mount path")
	caFile     := flag.String("ca-file",     "",                       "Path to CA certificate file")
	caBundle   := flag.String("ca-bundle",   "",                       "Raw PEM CA bundle string")
	clientCert := flag.String("client-cert", "",                       "PEM client certificate (mTLS)")
	clientKey  := flag.String("client-key",  "",                       "PEM client key (mTLS)")
	insecure   := flag.Bool("insecure",      false,                    "Skip TLS verification")
	debug      := flag.Bool("debug",         false,                    "Enable debug logging")
	flag.Parse()

	if *debug {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.WarnLevel)
	}

	if *path == "" {
		fmt.Fprintln(os.Stderr, "error: --path is required")
		flag.Usage()
		os.Exit(1)
	}

	cfg := &providers.VaultConfig{
		Address:    *addr,
		Token:      *token,
		RoleID:     *roleID,
		SecretID:   *secretID,
		AuthMethod: *authMethod,
		MountPath:  *mountPath,
		TLS: providers.TLSConfig{
			CAFile:     *caFile,
			CABundle:   *caBundle,
			ClientCert: *clientCert,
			ClientKey:  *clientKey,
			Insecure:   *insecure,
		},
	}

	provider, err := providers.NewVaultProvider(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	value, err := provider.FetchSecret(ctx, *path, *field, *mountPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(value)
}
