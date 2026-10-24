package config

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestTunnelModeDefaultsAndValidation(t *testing.T) {
	for _, mode := range []string{"", "legacy", " Legacy "} {
		got, err := normalizeTunnelMode(mode)
		if err != nil || got != TunnelLegacy {
			t.Fatalf("%q: %q %v", mode, got, err)
		}
	}
	if _, err := normalizeTunnelMode("max"); err == nil {
		t.Fatal("unknown mode accepted")
	}
	cfg := defaultClientConfig()
	cfg.Domains = []string{"test.example"}
	cfg.EncryptionKey = "secret"
	cfg.TunnelMode = TunnelCottenMax
	if err := validateCottenMaxClient(cfg); err != nil {
		t.Fatalf("existing shared credential must be sufficient: %v", err)
	}
	cfg.CottenMaxServerPublicKey = base64.StdEncoding.EncodeToString(make([]byte, 32))
	if err := validateCottenMaxClient(cfg); err != nil {
		t.Fatal(err)
	}
	cfg.QueryRateLimitPerSecond = 500
	if err := validateCottenMaxClient(cfg); err == nil || !strings.Contains(err.Error(), "QUERY_RATE_LIMIT") {
		t.Fatal("unsupported query cap silently accepted")
	}
	cfg.QueryRateLimitPerSecond = 0
	cfg.ResolverTransport = "dot"
	if err := validateCottenMaxClient(cfg); err != nil {
		t.Fatal(err)
	}
	cfg.ResolverTLSInsecureSkipVerify = true
	if err := validateCottenMaxClient(cfg); err == nil {
		t.Fatal("unauthenticated DoT accepted")
	}
	cfg.ResolverTLSPin = "test pin"
	if err := validateCottenMaxClient(cfg); err != nil {
		t.Fatal(err)
	}
	for _, transport := range []string{"doh", "doh3", "doq"} {
		cfg.ResolverTransport = transport
		if err := validateCottenMaxClient(cfg); err != nil {
			t.Fatalf("encrypted carrier %s rejected: %v", transport, err)
		}
	}
	cfg.StandbyDomains = []string{"backup.example"}
	if err := validateCottenMaxClient(cfg); err != nil {
		t.Fatal(err)
	}
}
