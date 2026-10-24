package config

import (
	"flag"
	"io"
	"strings"
	"testing"
)

func TestModeFlagHelpAndOverridesRetainTheirMeaning(t *testing.T) {
	clientFlags := flag.NewFlagSet("client", flag.ContinueOnError)
	clientFlags.SetOutput(io.Discard)
	client, err := NewClientConfigFlagBinder(clientFlags)
	if err != nil {
		t.Fatal(err)
	}
	if help := clientFlags.Lookup("tunnel-mode").Usage; !strings.Contains(help, "same domain/key") || !strings.Contains(help, "updated server required") {
		t.Fatal(help)
	}
	if help := clientFlags.Lookup("dns-padding-block-size").Usage; !strings.Contains(help, "encrypted resolver transport only") {
		t.Fatal(help)
	}
	if err := clientFlags.Parse([]string{"--tunnel-mode=cottenmax", "--resolver-transport=doq"}); err != nil {
		t.Fatal(err)
	}
	cfg := defaultClientConfig()
	if err := applyClientConfigOverrideValues(&cfg, client.Overrides().Values); err != nil {
		t.Fatal(err)
	}
	if cfg.TunnelMode != TunnelCottenMax || cfg.ResolverTransport != "doq" {
		t.Fatal("CLI mode/transport overrides changed semantics")
	}
	serverFlags := flag.NewFlagSet("server", flag.ContinueOnError)
	serverFlags.SetOutput(io.Discard)
	if _, err := NewServerConfigFlagBinder(serverFlags); err != nil {
		t.Fatal(err)
	}
	if help := serverFlags.Lookup("tunnel-mode").Usage; !strings.Contains(help, "accepts normal CottenDNS and CottenMax beta together") {
		t.Fatal(help)
	}
}
