package cottenmax

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestCottenMaxCapacityReturnsAfterResolverRouteImproves(t *testing.T) {
	s, cfg := routeServer(t, nil, nil)
	r := newRouteResolver(t, routePolicy{server: s, maxName: 101})
	c, conn := routeClient(t, cfg, r)
	if err := routeEcho(conn, 64<<10); err != nil {
		t.Fatal(err)
	}
	// Let both initial padded probes expire while ordinary short queries work.
	time.Sleep(time.Second)
	r.policy.Store(&routePolicy{server: s})
	deadline := time.Now().Add(18 * time.Second)
	for time.Now().Before(deadline) && c.PathStats()[0].NameLen <= 101 {
		time.Sleep(50 * time.Millisecond)
	}
	if c.PathStats()[0].NameLen <= 101 {
		t.Fatal("changed route stayed permanently at the short query size")
	}
	if err := routeEcho(conn, 64<<10); err != nil {
		t.Fatal(err)
	}
	// A restrictive forwarder returning must still be handled safely.
	r.policy.Store(&routePolicy{server: s, maxName: 101})
	if err := routeEcho(conn, 64<<10); err != nil {
		t.Fatal(err)
	}
	if c.PathStats()[0].NameLen > 101 {
		t.Fatal("short-name fallback stopped working after a successful re-probe")
	}
}

func TestCottenMaxResolverACLRefusesRecursion(t *testing.T) {
	s, cfg := routeServer(t, nil, nil)
	restricted := newRouteResolver(t, routePolicy{server: s, refuseAll: true})
	// This models the observable result of an egress/interface ACL change,
	// not a measurement of a real Iranian resolver or a particular country.
	cfg.Resolvers = []string{restricted.udp.LocalAddr().String()}
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 1200*time.Millisecond)
	conn, err := c.Dial(ctx, "echo.example:443")
	cancel()
	if err == nil {
		conn.Close()
		c.Close()
		t.Fatal("ACL refusal was mistaken for tunnel connectivity")
	}
	if c.Established() {
		t.Fatal("REFUSED established a session")
	}
	c.Close()
	cfg.Resolvers = nil
	alternate := newRouteResolver(t, routePolicy{server: s, delay: 15 * time.Millisecond})
	_, conn = routeClient(t, cfg, restricted, alternate)
	if err := routeEcho(conn, 64<<10); err != nil {
		t.Fatalf("independent working path did not bypass refused recursion: %v", err)
	}
}

func TestCottenMaxRecursiveEgressAddressChanges(t *testing.T) {
	s, cfg := routeServer(t, nil, nil)
	authority, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	var first, second atomic.Int64
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		for {
			n, from, err := authority.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if from.IP.Equal(net.IPv4(127, 0, 0, 1)) {
				first.Add(1)
			} else {
				second.Add(1)
			}
			s.DispatchUDP(buf[:n], authority, from)
		}
	}()
	t.Cleanup(func() { authority.Close(); <-done })
	// Two loopback IPs emulate a recursive forwarder's changing egress IP.
	probe, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2)})
	if err != nil {
		t.Fatalf("cannot bind second synthetic egress address: %v", err)
	}
	probe.Close()
	forward := func(ip net.IP) func([]byte) ([]byte, bool) {
		return func(q []byte) ([]byte, bool) {
			pc, err := net.DialUDP("udp4", &net.UDPAddr{IP: ip}, authority.LocalAddr().(*net.UDPAddr))
			if err != nil {
				return nil, false
			}
			defer pc.Close()
			_ = pc.SetDeadline(time.Now().Add(2 * time.Second))
			if _, err := pc.Write(q); err != nil {
				return nil, false
			}
			b := make([]byte, 4096)
			n, err := pc.Read(b)
			return b[:n], err == nil
		}
	}
	r := newRouteResolver(t, routePolicy{exchange: forward(net.IPv4(127, 0, 0, 1))})
	_, conn := routeClient(t, cfg, r)
	if err := routeEcho(conn, 32<<10); err != nil {
		t.Fatal(err)
	}
	r.policy.Store(&routePolicy{exchange: forward(net.IPv4(127, 0, 0, 2))})
	if err := routeEcho(conn, 32<<10); err != nil {
		t.Fatalf("source-IP change broke the same authenticated stream: %v", err)
	}
	if first.Load() == 0 || second.Load() == 0 {
		t.Fatal("test did not exercise both egress IPs")
	}
}

func TestCottenMaxDifferentBackendWithSameSigningKey(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	original, cfg := routeServer(t, key, nil)
	replacement, _ := routeServer(t, key, nil)
	r := newRouteResolver(t, routePolicy{server: original})
	c, conn := routeClient(t, cfg, r)
	if err := routeEcho(conn, 8<<10); err != nil {
		t.Fatal(err)
	}
	r.policy.Store(&routePolicy{server: replacement})
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	_, err = conn.Write([]byte("backend changed"))
	if err == nil {
		_, err = io.ReadFull(conn, make([]byte, 1))
	}
	if err == nil {
		t.Fatal("existing stream silently migrated to a backend with no session state")
	}
	if e, ok := err.(net.Error); ok && e.Timeout() {
		t.Fatalf("signed unknown-session reply did not terminate the old stream: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	newConn, err := c.Dial(ctx, "echo.example:443")
	if err != nil {
		t.Fatalf("new authenticated session could not use replacement backend: %v", err)
	}
	defer newConn.Close()
	if err := routeEcho(newConn, 32<<10); err != nil {
		t.Fatal(err)
	}
}

func TestCottenMaxLearnsSuddenResolverLatencyIncrease(t *testing.T) {
	s, cfg := routeServer(t, nil, nil)
	r := newRouteResolver(t, routePolicy{server: s})
	c, conn := routeClient(t, cfg, r)
	if err := routeEcho(conn, 8<<10); err != nil {
		t.Fatal(err)
	}
	r.policy.Store(&routePolicy{server: s, delay: 350 * time.Millisecond})
	if err := routeEcho(conn, 8<<10); err != nil {
		t.Fatalf("same stream failed after the RTT jump: %v; paths=%+v", err, c.PathStats())
	}
	if c.PathStats()[0].RTT < 250*time.Millisecond {
		t.Fatalf("path did not learn the slower RTT: %+v", c.PathStats())
	}
}
