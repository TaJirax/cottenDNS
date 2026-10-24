package cottenmax

import (
	"testing"
	"time"
)

func TestCottenMaxRecoversHalfOpenTCP(t *testing.T) {
	s, cfg := routeServer(t, nil, nil)
	cfg.TCP = "only"
	r := newRouteResolver(t, routePolicy{server: s})
	c, conn := routeClient(t, cfg, r)
	if err := routeEcho(conn, 8<<10); err != nil {
		t.Fatal(err)
	}
	// Successful held polls must not churn connections or turn into a retry loop.
	before := r.tcpQueries.Load()
	time.Sleep(3500 * time.Millisecond)
	if n := r.tcpConnections.Load(); n != 1 {
		t.Fatalf("healthy held polls used %d connections, want one", n)
	}
	if n := r.tcpQueries.Load() - before; n > 40 {
		t.Fatalf("idle stream sent %d queries; held polling stopped working", n)
	}
	r.policy.Store(&routePolicy{server: s, dropTCPThrough: r.tcpConnections.Load()})
	start := time.Now()
	before = r.tcpQueries.Load()
	if err := routeEcho(conn, 32<<10); err != nil {
		t.Fatalf("same stream failed after half-open TCP route: %v; paths=%+v", err, c.PathStats())
	}
	if n := r.tcpConnections.Load(); n != 2 {
		t.Fatalf("half-open recovery used %d connections, want one replacement", n)
	}
	if r.udpQueries.Load() != 0 {
		t.Fatal("TCP-only recovery sent UDP traffic")
	}
	t.Logf("same stream recovered in %s with %d queries", time.Since(start).Round(time.Millisecond), r.tcpQueries.Load()-before)
}
