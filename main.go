package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/vaishakh787/secret-fetch/providers"
	log "github.com/sirupsen/logrus"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}
	switch os.Args[1] {
	case "get":
		runGet(os.Args[2:])
	case "list":
		runList(os.Args[2:])
	case "watch":
		runWatch(os.Args[2:])
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("secret-fetch - CLI tool for fetching secrets from HashiCorp Vault\n\nUsage:\n  secret-fetch get   --path <path> [flags]   Fetch a secret value\n  secret-fetch list  --path <path> [flags]   List secrets at a path\n  secret-fetch watch --path <path> [flags]   Watch a secret for changes\n\nExamples:\n  secret-fetch get   --path database/mysql --field password --token root\n  secret-fetch get   --path database/mysql --output json --token root\n  secret-fetch list  --path database --token root\n  secret-fetch watch --path database/mysql --field password --interval 5s --token root")
}

func commonFlags(fs *flag.FlagSet) (*string, *string, *string, *string, *string, *string, *string, *string, *bool, *bool) {
	addr       := fs.String("addr",      "http://127.0.0.1:8200", "Vault server address")
	token      := fs.String("token",     "",                       "Vault token")
	roleID     := fs.String("role-id",   "",                       "AppRole role ID")
	secretID   := fs.String("secret-id", "",                       "AppRole secret ID")
	authMethod := fs.String("auth",      "token",                  "Auth method: token | approle")
	caFile     := fs.String("ca-file",   "",                       "Path to CA certificate file")
	caBundle   := fs.String("ca-bundle", "",                       "Raw PEM CA bundle string")
	mountPath  := fs.String("mount",     "secret",                 "KV mount path")
	insecure   := fs.Bool("insecure",    false,                    "Skip TLS verification")
	debug      := fs.Bool("debug",       false,                    "Enable debug logging")
	return addr, token, roleID, secretID, authMethod, caFile, caBundle, mountPath, insecure, debug
}

func buildProvider(addr, token, roleID, secretID, authMethod, caFile, caBundle, mountPath string, insecure, debug bool) (*providers.VaultProvider, error) {
	if debug {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.WarnLevel)
	}
	cfg := &providers.VaultConfig{
		Address: addr, Token: token, RoleID: roleID, SecretID: secretID,
		AuthMethod: authMethod, MountPath: mountPath,
		TLS: providers.TLSConfig{CAFile: caFile, CABundle: caBundle, Insecure: insecure},
	}
	return providers.NewVaultProvider(cfg)
}

func runGet(args []string) {
	fs := flag.NewFlagSet("get", flag.ExitOnError)
	addr, token, roleID, secretID, authMethod, caFile, caBundle, mountPath, insecure, debug := commonFlags(fs)
	path   := fs.String("path",   "", "Secret path (required)")
	field  := fs.String("field",  "", "Field to extract")
	output := fs.String("output", "value", "Output format: value | json")
	_ = fs.Parse(args)
	if *path == "" {
		fmt.Fprintln(os.Stderr, "error: --path is required")
		os.Exit(1)
	}
	provider, err := buildProvider(*addr, *token, *roleID, *secretID, *authMethod, *caFile, *caBundle, *mountPath, *insecure, *debug)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if *output == "json" {
		data, err := provider.FetchSecretAllFields(ctx, *path, *mountPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		out, _ := json.MarshalIndent(data, "", "  ")
		fmt.Println(string(out))
		return
	}
	value, err := provider.FetchSecret(ctx, *path, *field, *mountPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(value)
}

func runList(args []string) {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	addr, token, roleID, secretID, authMethod, caFile, caBundle, mountPath, insecure, debug := commonFlags(fs)
	path := fs.String("path", "", "Path to list secrets under (required)")
	_ = fs.Parse(args)
	if *path == "" {
		fmt.Fprintln(os.Stderr, "error: --path is required")
		os.Exit(1)
	}
	provider, err := buildProvider(*addr, *token, *roleID, *secretID, *authMethod, *caFile, *caBundle, *mountPath, *insecure, *debug)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	keys, err := provider.ListSecrets(ctx, *path, *mountPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	for _, k := range keys {
		fmt.Println(k)
	}
}

func runWatch(args []string) {
	fs := flag.NewFlagSet("watch", flag.ExitOnError)
	addr, token, roleID, secretID, authMethod, caFile, caBundle, mountPath, insecure, debug := commonFlags(fs)
	path     := fs.String("path",     "",    "Secret path (required)")
	field    := fs.String("field",    "",    "Field to watch")
	interval := fs.Duration("interval", 10*time.Second, "Poll interval (e.g. 5s, 1m)")
	_ = fs.Parse(args)

	if *path == "" {
		fmt.Fprintln(os.Stderr, "error: --path is required")
		os.Exit(1)
	}

	provider, err := buildProvider(*addr, *token, *roleID, *secretID, *authMethod, *caFile, *caBundle, *mountPath, *insecure, *debug)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = provider.WatchSecret(ctx, *path, *field, *mountPath, *interval, func(newValue string) {
		fmt.Printf("  new value: %s\n", newValue)
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

