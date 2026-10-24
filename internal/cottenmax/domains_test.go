package cottenmax

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"cottendns-go/internal/dnsparser"
)

type domainTestServer struct {
	blocked [2]atomic.Bool
	queries [2]atomic.Int64
}

// The same resolver delegates two domains to the same authenticated server.
// Blocking one zone models a domain-specific censorship/delegation failure.
func newDomainTestServer(t *testing.T, dialers ...func(context.Context, string) (net.Conn, error)) (ClientConfig, *domainTestServer) {
	t.Helper()
	const secret = "one existing CottenDNS credential"
	key, err := SharedIdentity(secret)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	server, err := NewServer(ctx, ServerConfig{Domains: []string{"primary.example", "backup.example"}, Key: key, Secret: secret,
		MaxSessions: 16, MaxStreams: 16, Dial: func(ctx context.Context, target string) (net.Conn, error) {
			if len(dialers) > 0 {
				return dialers[0](ctx, target)
			}
			a, b := net.Pipe()
			go func() { defer b.Close(); _, _ = io.Copy(b, b) }()
			return a, nil
		}})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		cancel()
		server.Close()
		t.Fatal(err)
	}
	state := &domainTestServer{}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buffer := make([]byte, 4096)
		for {
			n, address, err := pc.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			query, err := dnsparser.ParseDNSRequestLite(buffer[:n])
			if err != nil || !query.HasQuestion {
				continue
			}
			index := 0
			if strings.HasSuffix(strings.TrimSuffix(strings.ToLower(query.FirstQuestion.Name), "."), "."+Zone("backup.example")) {
				index = 1
			}
			state.queries[index].Add(1)
			if !state.blocked[index].Load() {
				server.DispatchUDP(buffer[:n], pc, address)
			}
		}
	}()
	t.Cleanup(func() { cancel(); pc.Close(); server.Close(); wg.Wait() })
	return ClientConfig{Domain: "primary.example", Domains: []string{"backup.example"}, Secret: secret,
		Resolvers: []string{pc.LocalAddr().String()}, TCP: "off", FailoverAfter: 200 * time.Millisecond}, state
}

func domainEcho(t *testing.T, client *Client, transparent bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	var conn net.Conn
	var err error
	if transparent {
		conn, err = client.DialStream(ctx, "echo.example:443")
	} else {
		conn, err = client.Dial(ctx, "echo.example:443")
	}
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write([]byte("same credential")); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, len("same credential"))
	if _, err := io.ReadFull(conn, reply); err != nil || string(reply) != "same credential" {
		t.Fatalf("domain echo mismatch: %q, %v", reply, err)
	}
}

func TestDomainFailoverBlockedPrimaryAndPreferredBackup(t *testing.T) {
	for _, transparent := range []bool{false, true} {
		t.Run(map[bool]string{false: "confirmed", true: "transparent"}[transparent], func(t *testing.T) {
			cfg, state := newDomainTestServer(t)
			state.blocked[0].Store(true)
			client, err := NewClient(cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			domainEcho(t, client, transparent)
			if state.queries[0].Load() == 0 || state.queries[1].Load() == 0 {
				t.Fatal("both the configured primary and fallback were not tried")
			}
			client.failover.mu.Lock()
			preferred := client.failover.preferred
			client.failover.mu.Unlock()
			if preferred != 1 || !client.Established() {
				t.Fatal("working authenticated fallback was not retained")
			}
			domainEcho(t, client, transparent)
		})
	}
}

func TestDomainFailoverHealthyPrimaryLeavesBackupUnopened(t *testing.T) {
	cfg, state := newDomainTestServer(t)
	cfg.Domains = []string{"PRIMARY.EXAMPLE.", "backup.example", "Backup.Example."}
	var primaryDiscovery, backupDiscovery atomic.Int64
	cfg.DiscoveryForDomain = func(domain string) Discovery {
		if domain == "primary.example" {
			primaryDiscovery.Add(1)
		} else if domain == "backup.example" {
			backupDiscovery.Add(1)
		}
		return Discovery{}
	}
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	domainEcho(t, client, false)
	domainEcho(t, client, true)
	if state.queries[1].Load() != 0 {
		t.Fatal("healthy primary triggered backup traffic")
	}
	if primaryDiscovery.Load() != 1 || backupDiscovery.Load() != 0 {
		t.Fatal("discovery factory did not preserve lazy per-domain setup")
	}
	client.failover.mu.Lock()
	defer client.failover.mu.Unlock()
	if len(client.failover.domains) != 2 || client.failover.domains[1].engine != nil {
		t.Fatal("backup was not deduplicated and kept lazy")
	}
}

func TestDomainFailoverHealthyTransparentStreamRetainsPipelining(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{}, 1)
	cfg, state := newDomainTestServer(t, func(ctx context.Context, _ string) (net.Conn, error) {
		started <- struct{}{}
		select {
		case <-release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		a, b := net.Pipe()
		go func() { defer b.Close(); _, _ = io.Copy(b, b) }()
		return a, nil
	})
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := client.DialStream(ctx, "echo.example:443")
	if err != nil {
		t.Fatalf("healthy transparent dial waited for backend confirmation: %v", err)
	}
	defer conn.Close()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("pipelined OPEN never reached the server")
	}
	conn.SetDeadline(time.Now().Add(time.Second))
	if _, err := conn.Write([]byte("early")); err != nil {
		t.Fatal(err)
	}
	close(release)
	reply := make([]byte, 5)
	if _, err := io.ReadFull(conn, reply); err != nil || string(reply) != "early" {
		t.Fatalf("pipelined data lost: %q, %v", reply, err)
	}
	if state.queries[1].Load() != 0 {
		t.Fatal("backend delay unnecessarily activated standby")
	}
}

func TestDomainFailoverCancellationAndShutdown(t *testing.T) {
	for _, closeClient := range []bool{false, true} {
		t.Run(map[bool]string{false: "caller-cancel", true: "close"}[closeClient], func(t *testing.T) {
			cfg, state := newDomainTestServer(t)
			state.blocked[0].Store(true)
			state.blocked[1].Store(true)
			cfg.FailoverAfter = 10 * time.Second
			client, err := NewClient(cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := make(chan error, 1)
			go func() {
				conn, err := client.Dial(ctx, "echo.example:443")
				if conn != nil {
					conn.Close()
				}
				result <- err
			}()
			deadline := time.After(2 * time.Second)
			for state.queries[0].Load() == 0 {
				select {
				case <-deadline:
					t.Fatal("primary never sent a handshake")
				case <-time.After(time.Millisecond):
				}
			}
			expected := context.Canceled
			if closeClient {
				client.Close()
				expected = net.ErrClosed
			} else {
				cancel()
			}
			select {
			case err := <-result:
				if !errors.Is(err, expected) {
					t.Fatalf("expected %v; got %v", expected, err)
				}
			case <-time.After(time.Second):
				t.Fatal("dial did not stop after cancellation/shutdown")
			}
			if state.queries[1].Load() != 0 {
				t.Fatal("cancellation created an unwanted backup session")
			}
		})
	}
}

func TestDomainFailoverAllDomainsUnavailableIsBounded(t *testing.T) {
	cfg, state := newDomainTestServer(t)
	state.blocked[0].Store(true)
	state.blocked[1].Store(true)
	cfg.FailoverAfter = 100 * time.Millisecond
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err = client.Dial(ctx, "echo.example:443")
	if err == nil || !strings.Contains(err.Error(), "all tunnel domains failed") || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected bounded aggregate timeout; got %v", err)
	}
	if ctx.Err() != nil || client.Established() || state.queries[1].Load() == 0 {
		t.Fatal("per-domain timeout did not bound both failed attempts")
	}
}

func TestDomainFailoverDNSExchangeUsesSameCredential(t *testing.T) {
	cfg, state := newDomainTestServer(t, func(_ context.Context, target string) (net.Conn, error) {
		if target != DNSTarget {
			return nil, errors.New("unexpected service")
		}
		a, b := net.Pipe()
		go func() {
			defer b.Close()
			query, err := ReadDNSFrame(b)
			if err == nil {
				query[2] |= 0x80
				WriteDNSFrame(b, query)
			}
		}()
		return a, nil
	})
	state.blocked[0].Store(true)
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	query, err := dnsparser.BuildTXTQuestionPacket("ordinary.example", 1, 1232)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	reply, err := client.ExchangeDNS(ctx, query)
	if err != nil || len(reply) != len(query) || reply[0] != query[0] || reply[1] != query[1] {
		t.Fatalf("fallback DNS response mismatch: %v", err)
	}
}

func TestDomainFailoverConcurrentNewStreamsShareLazyBackup(t *testing.T) {
	cfg, state := newDomainTestServer(t)
	state.blocked[0].Store(true)
	cfg.FailoverAfter = 300 * time.Millisecond
	var sockets atomic.Int64
	var primaryDiscovery, backupDiscovery atomic.Int64
	cfg.DiscoveryForDomain = func(domain string) Discovery {
		if domain == "primary.example" {
			primaryDiscovery.Add(1)
		} else if domain == "backup.example" {
			backupDiscovery.Add(1)
		}
		return Discovery{}
	}
	cfg.ListenPacket = func(ctx context.Context, network, address string) (net.PacketConn, error) {
		sockets.Add(1)
		var lc net.ListenConfig
		return lc.ListenPacket(ctx, network, address)
	}
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	const workers = 8
	result := make(chan error, workers)
	for range workers {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			conn, err := client.Dial(ctx, "echo.example:443")
			if err != nil {
				result <- err
				return
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(2 * time.Second))
			_, err = conn.Write([]byte("x"))
			if err == nil {
				reply := []byte{0}
				_, err = io.ReadFull(conn, reply)
				if err == nil && reply[0] != 'x' {
					err = errors.New("concurrent echo mismatch")
				}
			}
			result <- err
		}()
	}
	for range workers {
		if err := <-result; err != nil {
			t.Fatal(err)
		}
	}
	if sockets.Load() != 2 {
		t.Fatalf("expected primary plus one lazy backup socket; got %d", sockets.Load())
	}
	if primaryDiscovery.Load() != 1 || backupDiscovery.Load() != 1 {
		t.Fatal("concurrent dials did not isolate/cache domain discovery setup")
	}
}

func TestDomainFailoverWrongServerPinNeverEstablishesBackup(t *testing.T) {
	cfg, state := newDomainTestServer(t)
	state.blocked[0].Store(true)
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cfg.PublicKey = base64.StdEncoding.EncodeToString(public)
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := client.DialStream(ctx, "echo.example:443")
	if conn != nil {
		conn.Close()
	}
	if err == nil || client.Established() || state.queries[1].Load() == 0 {
		t.Fatal("fallback bypassed authentication or failed to try the backup")
	}
}

func TestDomainFailoverCloseCancelsLazySocketCreation(t *testing.T) {
	cfg, state := newDomainTestServer(t)
	state.blocked[0].Store(true)
	cfg.FailoverAfter = 100 * time.Millisecond
	var sockets atomic.Int64
	opening := make(chan struct{})
	cfg.ListenPacket = func(ctx context.Context, network, address string) (net.PacketConn, error) {
		if sockets.Add(1) == 2 {
			close(opening)
			<-ctx.Done()
			return nil, ctx.Err()
		}
		var lc net.ListenConfig
		return lc.ListenPacket(ctx, network, address)
	}
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	result := make(chan error, 1)
	go func() {
		conn, err := client.Dial(context.Background(), "echo.example:443")
		if conn != nil {
			conn.Close()
		}
		result <- err
	}()
	select {
	case <-opening:
	case <-time.After(2 * time.Second):
		t.Fatal("backup socket was not attempted")
	}
	client.Close()
	select {
	case err := <-result:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("expected closed client; got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("closing client did not cancel lazy socket creation")
	}
}

func TestDomainFailoverValidationAndSingleDomainFastPath(t *testing.T) {
	for _, domains := range [][]string{
		{""}, {"a..example"}, {strings.Repeat("a", 34) + ".example"}, {"\u212a.example"},
		{"a.example", "b.example", "c.example", "d.example", "e.example", "f.example", "g.example", "h.example"},
	} {
		_, err := normalizeFailoverDomains("primary.example", domains)
		if err == nil {
			t.Fatalf("accepted invalid/excess standby domains: %q", domains)
		}
	}
	cfg, _ := newDomainTestServer(t)
	cfg.Domains = []string{"PRIMARY.EXAMPLE."}
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if client.failover != nil {
		t.Fatal("single-domain clients entered the failover path")
	}
	domainEcho(t, client, true)
}
