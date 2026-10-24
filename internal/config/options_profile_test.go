package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestMaxProfileKeepsConfiguredDomainPriority(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client.toml")
	text := `TUNNEL_MODE = "cottenmax"
ENCRYPTION_KEY = "existing-key"
DOMAINS = ["a.io", "longer-primary-alternative.example", "A.IO."]
STANDBY_DOMAINS = ["third.io"]
RESOLVER_DISCOVERY_ENABLED = true
RESOLVER_DISCOVERY_CANDIDATES = ["127.0.0.1:5300"]
`
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadClientConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(cfg.Domains, []string{"a.io", "longer-primary-alternative.example"}) {
		t.Fatalf("priority changed: %v", cfg.Domains)
	}
	if cfg.CottenMaxMaxPathWindow != 256 || cfg.CottenMaxMaxInflight != 256 || cfg.CottenMaxHoldMilliseconds != 500 || cfg.QNameLabelJitter || cfg.DNSPaddingBlockSize != 0 || cfg.ResolverHTTP3Fallback {
		t.Fatalf("default fast path changed: %+v", cfg)
	}
}

func TestBundledClientOptionTemplatesLoadInBothModes(t *testing.T) {
	for _, name := range []string{"client_config.toml.simple", "client_config.speed.toml", "client_config.survival.toml", "client_config.tcp-survival.toml"} {
		for _, mode := range []string{TunnelLegacy, TunnelCottenMax} {
			t.Run(name+"/"+mode, func(t *testing.T) {
				raw, err := os.ReadFile(filepath.Join("..", "..", name))
				if err != nil {
					t.Fatal(err)
				}
				text := strings.ReplaceAll(string(raw), `ENCRYPTION_KEY = ""`, `ENCRYPTION_KEY = "existing-key"`)
				text = strings.ReplaceAll(text, `TUNNEL_MODE = "legacy"`, `TUNNEL_MODE = "`+mode+`"`)
				dir := t.TempDir()
				path := filepath.Join(dir, "client.toml")
				if err := os.WriteFile(filepath.Join(dir, "client_resolvers.txt"), []byte("127.0.0.1:5300\n"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(text), 0600); err != nil {
					t.Fatal(err)
				}
				cfg, err := LoadClientConfig(path)
				if err != nil {
					t.Fatal(err)
				}
				expectedTransport := "auto"
				expectedLabel := 63
				if name == "client_config.tcp-survival.toml" {
					expectedTransport = "tcp"
				}
				if name == "client_config.survival.toml" {
					expectedLabel = 42
				}
				if cfg.ResolverTransport != expectedTransport || cfg.QNameLabelLength != expectedLabel {
					t.Fatalf("preset behavior changed: transport=%s labels=%d", cfg.ResolverTransport, cfg.QNameLabelLength)
				}
			})
		}
	}
}
