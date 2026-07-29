package client

import (
	"os"
	"path/filepath"
	"testing"

	"cottendns-go/internal/config"
)

func writeFreshStartFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	configPath := filepath.Join(dir, "client_config.toml")
	if err := os.WriteFile(configPath, []byte(`
DOMAINS = ["v.example.com"]
ENCRYPTION_KEY = "test-key"
DATA_ENCRYPTION_METHOD = 3
STARTUP_MODE = "logs"
FAST_CONNECT = true
`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "client_resolvers.txt"), []byte("1.1.1.1\n8.8.8.8\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return configPath
}

func TestBootstrapFromLogsIgnoresCacheAndUsesCurrentResolvers(t *testing.T) {
	configPath := writeFreshStartFixture(t)
	app, err := BootstrapFromLogs(configPath, []ResolverCacheEntry{{
		IP:          "9.9.9.9",
		Port:        53,
		Domain:      "v.example.com",
		UploadMTU:   180,
		DownloadMTU: 1200,
	}}, config.ClientConfigOverrides{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.closeResolverCacheLog)

	if app.cfg.StartupMode != "resolvers" {
		t.Fatalf("legacy logs mode was not normalized: %q", app.cfg.StartupMode)
	}
	if app.connectionsHavePreknownMTU {
		t.Fatal("cache metadata unexpectedly armed preknown-MTU startup")
	}
	if len(app.connections) != 2 {
		t.Fatalf("connection catalog length=%d, want current resolver list length 2", len(app.connections))
	}
	seen := map[string]bool{}
	for _, conn := range app.connections {
		seen[conn.Resolver] = true
		if conn.Resolver == "9.9.9.9" {
			t.Fatal("cached resolver leaked into the fresh resolver catalog")
		}
	}
	if !seen["1.1.1.1"] || !seen["8.8.8.8"] {
		t.Fatalf("current resolver list was not preserved: %#v", seen)
	}
}

func TestBootstrapFromLogsIgnoresCacheForEmbeddingOverride(t *testing.T) {
	configPath := writeFreshStartFixture(t)
	overrides := config.ClientConfigOverrides{
		Resolvers: []config.ResolverAddress{{IP: "4.4.4.4", Port: 53}},
	}
	app, err := BootstrapFromLogs(configPath, []ResolverCacheEntry{{
		IP:          "9.9.9.9",
		Port:        53,
		Domain:      "v.example.com",
		UploadMTU:   180,
		DownloadMTU: 1200,
	}}, overrides)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.closeResolverCacheLog)

	if len(app.connections) != 1 || app.connections[0].Resolver != "4.4.4.4" {
		t.Fatalf("embedding resolver source was replaced by cache: %+v", app.connections)
	}
	if app.connectionsHavePreknownMTU {
		t.Fatal("embedding path unexpectedly trusted cached resolver state")
	}
}
