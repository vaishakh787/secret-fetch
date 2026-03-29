package providers

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

type TLSConfig struct {
	CABundle   string
	CAFile     string
	ClientCert string
	ClientKey  string
	Insecure   bool
}

func BuildTLSConfig(cfg TLSConfig) (*tls.Config, error) {
	tlsCfg := &tls.Config{
		InsecureSkipVerify: cfg.Insecure,
	}
	bundle := cfg.CABundle
	if bundle == "" && cfg.CAFile != "" {
		data, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA file: %w", err)
		}
		bundle = string(data)
	}
	if bundle != "" {
		pool, err := parseCABundle(bundle)
		if err != nil {
			return nil, fmt.Errorf("failed to parse CA bundle: %w", err)
		}
		tlsCfg.RootCAs = pool
	}
	if cfg.ClientCert != "" && cfg.ClientKey != "" {
		cert, err := tls.X509KeyPair([]byte(cfg.ClientCert), []byte(cfg.ClientKey))
		if err != nil {
			return nil, fmt.Errorf("failed to load client cert/key: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}
	return tlsCfg, nil
}

func parseCABundle(bundle string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	data := []byte(bundle)
	found := 0
	for len(data) > 0 {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: %w", err)
		}
		pool.AddCert(cert)
		found++
	}
	if found == 0 {
		return nil, fmt.Errorf("no valid certificates found in CA bundle")
	}
	return pool, nil
}
