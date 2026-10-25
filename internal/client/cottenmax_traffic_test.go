package client

import (
	"os"
	"path/filepath"
	"testing"

	"cottendns-go/internal/config"
)

// Exercise TOML -> finalized config -> runtime adapter, rather than testing a
// second copy of the mapping. Construction is lazy and sends no DNS packets.
func TestCottenMaxTrafficProfileRuntimePropagation(t *testing.T) {
	for _, tc := range []struct {
		profile string
		window  int
	}{
		{"full", 256},
		{"low", 32},
	} {
		t.Run(tc.profile, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "client_config.toml")
			body := "TUNNEL_MODE = \"cottenmax\"\nDOMAINS = [\"a.test\"]\nENCRYPTION_KEY = \"secret\"\nCOTTENMAX_TRAFFIC_PROFILE = \"" + tc.profile + "\"\n"
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "client_resolvers.txt"), []byte("127.0.0.1\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := config.LoadClientConfig(path)
			if err != nil {
				t.Fatal(err)
			}
			c := &Client{cfg: cfg}
			max, err := c.newCottenMaxEngine()
			if err != nil {
				t.Fatal(err)
			}
			defer max.Close()
			if max.TrafficProfile() != tc.profile {
				t.Fatalf("runtime profile=%q, want %q", max.TrafficProfile(), tc.profile)
			}
			stats := max.DomainStats()
			if len(stats) != 1 || stats[0].MaxInflight != tc.window {
				t.Fatalf("%s profile did not reach Max engine: %+v", tc.profile, stats)
			}
		})
	}
}
