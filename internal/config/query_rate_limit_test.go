package config

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadClientConfigUserDefinedQueryRates(t *testing.T) {
	for _, rate := range []float64{0, 0.5, 6, 500, 1000, 10000} {
		for _, key := range []string{
			"QUERY_RATE_LIMIT_PER_SECOND",
			"QUERY_RATE_LIMIT_PER_RESOLVER_PER_SECOND",
			"QUERY_RATE_LIMIT_PER_DOMAIN_PER_SECOND",
		} {
			t.Run(fmt.Sprintf("%s=%g", key, rate), func(t *testing.T) {
				dir := t.TempDir()
				path := filepath.Join(dir, "client_config.toml")
				contents := fmt.Sprintf(`DOMAINS = ["tunnel.example"]
DATA_ENCRYPTION_METHOD = 1
ENCRYPTION_KEY = "secret"
%s = %g
`, key, rate)
				if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "client_resolvers.txt"), []byte("1.1.1.1\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				cfg, err := LoadClientConfig(path)
				if err != nil {
					t.Fatal(err)
				}
				for scope, got := range map[string]float64{
					"QUERY_RATE_LIMIT_PER_SECOND":              cfg.QueryRateLimitPerSecond,
					"QUERY_RATE_LIMIT_PER_RESOLVER_PER_SECOND": cfg.QueryRateLimitPerResolverPerSecond,
					"QUERY_RATE_LIMIT_PER_DOMAIN_PER_SECOND":   cfg.QueryRateLimitPerDomainPerSecond,
				} {
					want := 0.0
					if scope == key {
						want = rate
					}
					if got != want {
						t.Fatalf("%s = %g, want %g", scope, got, want)
					}
				}
				if cfg.QueryRateLimited() != (rate > 0) {
					t.Fatalf("QueryRateLimited() = %v for rate %g", cfg.QueryRateLimited(), rate)
				}
			})
		}
	}
}
