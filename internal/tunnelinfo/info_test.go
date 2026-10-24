package tunnelinfo

import (
	"strings"
	"testing"

	"cottendns-go/internal/config"
)

func TestClientGuidanceReflectsModeOptionsWithoutLeakingCredentials(t *testing.T) {
	cfg := config.ClientConfig{
		TunnelMode: config.TunnelCottenMax, ResolverTransport: "doh3",
		EncryptionKey: "private-tunnel-secret", SOCKS5Pass: "private-proxy-password",
		ResolverTLSPin: "private-resolver-pin", CottenMaxServerPublicKey: "optional-key-pin",
		ResolverDiscoveryEnabled: true, ResolverDiscoveryCacheFile: "private-cache-path",
		DNSPaddingBlockSize: 128, QNameLabelJitter: true,
	}
	text := strings.Join(Client(cfg), "\n")
	for _, want := range []string{"CottenMax beta", "doh3", "same client profile", "update the CottenDNS server first", "legacy", "discovery on", "cache on", "padding 128 bytes", "label jitter on", "QNAME loss guard off", "QUERY_RATE_LIMIT_*", "optional Max server public-key pin"} {
		if !strings.Contains(text, want) {
			t.Errorf("guidance missing %q: %s", want, text)
		}
	}
	for _, secret := range []string{cfg.EncryptionKey, cfg.SOCKS5Pass, cfg.ResolverTLSPin, cfg.CottenMaxServerPublicKey, cfg.ResolverDiscoveryCacheFile} {
		if strings.Contains(text, secret) {
			t.Errorf("guidance exposed %q", secret)
		}
	}
	cfg.TunnelMode = config.TunnelLegacy
	text = strings.Join(Client(cfg), "\n")
	if !strings.Contains(text, "Mode: Normal CottenDNS") || !strings.Contains(text, "CottenMax beta is optional") {
		t.Fatal(text)
	}
	if strings.Contains(text, "Options: discovery") {
		t.Fatal("normal guidance presents Max-only options as active")
	}
}

func TestServerGuidanceDistinguishesSharedAndCompatibilityIdentities(t *testing.T) {
	cfg := config.ServerConfig{TunnelMode: config.TunnelLegacy}
	text := strings.Join(Server(cfg), "\n")
	for _, want := range []string{"Normal CottenDNS + CottenMax beta", "same DNS listener", "server TUNNEL_MODE setting does not disable normal", "no separate Max key", "skipped long domains", "HTTP3/DoQ are client-to-resolver options", "Existing server DoT/DoH listeners are configured separately", "Guide: COTTENMAX_OPTIONS.md"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q", want)
		}
	}
	cfg.CottenMaxKeyFile = "private-identity-path"
	text = strings.Join(Server(cfg), "\n")
	if !strings.Contains(text, "Compatibility Max identity override") {
		t.Fatal(text)
	}
	if strings.Contains(text, "no separate Max key") || strings.Contains(text, cfg.CottenMaxKeyFile) {
		t.Fatal("compatibility identity guidance is misleading or discloses its path")
	}
}
