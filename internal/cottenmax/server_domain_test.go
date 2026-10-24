package cottenmax

import (
	"context"
	"net"
	"strings"
	"testing"
)

func TestValidateServerDomainAndStrictServerAPI(t *testing.T) {
	boundary := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 56)
	for _, domain := range []string{"test.example", "TEST.EXAMPLE.", boundary} {
		if err := ValidateServerDomain(domain); err != nil {
			t.Fatalf("compatible domain %q: %v", domain, err)
		}
	}
	key, err := SharedIdentity("same-existing-key")
	if err != nil {
		t.Fatal(err)
	}
	for _, domain := range []string{"", boundary + "c", strings.Repeat("a", 64) + ".example", "bad..example", "bad\t.example"} {
		if err := ValidateServerDomain(domain); err == nil {
			t.Fatalf("invalid Max domain accepted: %q", domain)
		}
		server, err := NewServer(context.Background(), ServerConfig{Domains: []string{"test.example", domain}, Key: key, Secret: "same-existing-key", Dial: func(context.Context, string) (net.Conn, error) { return nil, nil }})
		if err == nil {
			server.Close()
			t.Fatalf("strict API silently accepted invalid domain: %q", domain)
		}
	}
}
