package cottenmax

import (
	"testing"
	"time"
)

// The client starts without any active resolver. The only allowed discovery
// candidate is the local authenticated fixture; bundled/system addresses are
// filtered before a socket can send to them.
func TestCottenMaxZeroResolverDiscoveryUsesControlledLocalCandidate(t *testing.T) {
	cfg, queries := testServer(t, impairment{})
	local := cfg.Resolvers[0]
	cfg.Resolvers = nil
	cfg.Discovery = Discovery{Enabled: true, Candidates: []string{local}, Want: 1, Concurrency: 1, Pace: time.Millisecond, AcceptResolver: func(candidate string) bool { return candidate == local }}
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	domainEcho(t, client, false)
	if queries.Load() == 0 || !client.Established() {
		t.Fatal("discovery did not authenticate controlled resolver")
	}
	for _, path := range client.PathStats() {
		if path.Resolver != local {
			t.Fatalf("unexpected discovered endpoint: %+v", path)
		}
	}
}
