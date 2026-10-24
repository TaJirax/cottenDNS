package cottenmax

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"cottendns-go/internal/dnsparser"
)

type impairment struct {
	loss, shortNames, inject, shrinking bool
	delay                               time.Duration // propagation delay in each direction
}

// All traffic stays on loopback. Exchange exercises the same bounded adapter
// used by DNS-over-TCP, while UDP tests below also cover DispatchUDP.
func testServer(t *testing.T, imp impairment, dialers ...func(context.Context, string) (net.Conn, error)) (ClientConfig, *atomic.Int64) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	s, err := NewServer(ctx, ServerConfig{Domains: []string{"test.example"}, Key: key, Secret: "test credential",
		MaxSessions: 16, MaxStreams: 16,
		Dial: func(ctx context.Context, target string) (net.Conn, error) {
			if len(dialers) > 0 {
				return dialers[0](ctx, target)
			}
			a, b := net.Pipe()
			go func() { defer b.Close(); _, _ = io.Copy(b, b) }()
			return a, nil
		},
	})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		cancel()
		s.Close()
		t.Fatal(err)
	}
	var queries atomic.Int64
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		b := make([]byte, 4096)
		for {
			n, addr, err := pc.ReadFromUDP(b)
			if err != nil {
				return
			}
			q := queries.Add(1)
			if imp.loss && q%11 == 0 {
				continue
			}
			msg := append([]byte(nil), b[:n]...)
			parsed, _ := dnsparser.ParseDNSRequestLite(msg)
			if (imp.shortNames || (imp.shrinking && q > 40)) && len(parsed.FirstQuestion.Name) > 101 {
				continue
			}
			if imp.inject {
				forged := append([]byte(nil), msg...)
				forged[2], forged[3] = 0x81, 0x83 // unauthenticated NXDOMAIN before real answer
				_, _ = pc.WriteToUDP(forged, addr)
			}
			if !imp.loss && imp.delay == 0 {
				s.DispatchUDP(msg, pc, addr)
				continue
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				if imp.delay > 0 {
					select {
					case <-time.After(imp.delay):
					case <-ctx.Done():
						return
					}
				}
				response, _ := s.Exchange(msg)
				if imp.loss && q%13 == 0 {
					return
				} // downstream loss independent of query loss
				wait := imp.delay
				if imp.loss && q%3 == 0 {
					wait += 8 * time.Millisecond
				}
				if wait > 0 {
					select {
					case <-time.After(wait):
					case <-ctx.Done():
						return
					}
				}
				if len(response) > 0 {
					_, _ = pc.WriteToUDP(response, addr)
				}
			}()
		}
	}()
	t.Cleanup(func() { cancel(); pc.Close(); s.Close(); wg.Wait() })
	return ClientConfig{Domain: "test.example", PublicKey: base64.StdEncoding.EncodeToString(pub), Secret: "test credential", Resolvers: []string{pc.LocalAddr().String()}, TCP: "off", Hold: 500 * time.Millisecond}, &queries
}

func TestCottenMaxRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name string
		imp  impairment
	}{
		{"clean", impairment{}}, {"loss_and_reordering", impairment{loss: true}},
		{"loss_and_reordering_30ms_RTT", impairment{loss: true, delay: 15 * time.Millisecond}},
		{"loss_and_reordering_300ms_RTT", impairment{loss: true, delay: 150 * time.Millisecond}},
		{"101_character_names_30ms_RTT", impairment{shortNames: true, delay: 15 * time.Millisecond}},
		{"101_character_names", impairment{shortNames: true}}, {"forged_answers", impairment{inject: true}},
		{"name_limit_shrinks_during_transfer", impairment{shrinking: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, queries := testServer(t, tc.imp)
			c, err := NewClient(cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			conn, err := c.Dial(ctx, "echo.example:443")
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(45 * time.Second))
			payload := make([]byte, 64<<10)
			if _, err := rand.Read(payload); err != nil {
				t.Fatal(err)
			}
			written := make(chan error, 1)
			go func() { _, err := io.Copy(conn, bytes.NewReader(payload)); written <- err }()
			got := make([]byte, len(payload))
			if n, err := io.ReadFull(conn, got); err != nil {
				t.Fatalf("received %d/%d bytes after %d queries; paths=%+v: %v", n, len(got), queries.Load(), c.PathStats(), err)
			}
			if err := <-written; err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, payload) {
				t.Fatal("payload corruption")
			}
			t.Logf("64 KiB upload + download: %d queries", queries.Load())
		})
	}
}

func TestCottenMaxRejectsWrongCredentials(t *testing.T) {
	for _, wrongPin := range []bool{false, true} {
		t.Run(map[bool]string{false: "shared_secret", true: "pinned_key"}[wrongPin], func(t *testing.T) {
			cfg, _ := testServer(t, impairment{})
			if wrongPin {
				pub, _, _ := ed25519.GenerateKey(rand.Reader)
				cfg.PublicKey = base64.StdEncoding.EncodeToString(pub)
			} else {
				cfg.Secret = "wrong credential"
			}
			c, err := NewClient(cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			defer cancel()
			if conn, err := c.Dial(ctx, "echo.example:443"); err == nil {
				conn.Close()
				t.Fatal("wrong credentials opened a stream")
			}
		})
	}
}

func TestCottenMaxHeldPollsReduceIdleQueries(t *testing.T) {
	counts := make([]int64, 2)
	for i, hold := range []time.Duration{0, 500 * time.Millisecond} {
		cfg, queries := testServer(t, impairment{})
		cfg.Hold = hold
		c, err := NewClient(cfg)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		conn, err := c.Dial(ctx, "echo.example:443")
		cancel()
		if err != nil {
			c.Close()
			t.Fatal(err)
		}
		before := queries.Load()
		time.Sleep(200 * time.Millisecond)
		counts[i] = queries.Load() - before
		conn.Close()
		c.Close()
	}
	if counts[1] >= counts[0] {
		t.Fatalf("held polls did not reduce idle queries: off=%d on=%d", counts[0], counts[1])
	}
	t.Logf("idle queries in 200ms: hold off=%d, hold on=%d", counts[0], counts[1])
}

func TestCottenMaxKeyPersistenceAndAdmission(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity")
	a, err := LoadKey(path)
	if err != nil {
		t.Fatal(err)
	}
	b, err := LoadKey(path)
	if err != nil || !bytes.Equal(a, b) {
		t.Fatalf("server identity changed: %v", err)
	}
	if err := os.WriteFile(path, []byte("broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKey(path); err == nil {
		t.Fatal("malformed identity replaced")
	}
	signed := signTarget("secret", "example.com:443")
	if got, err := verifyTarget("secret", signed); err != nil || got != "example.com:443" {
		t.Fatal("valid stream descriptor rejected")
	}
	for _, bad := range []string{signed + "x", "@example.com:443", "example.com:443"} {
		if _, err := verifyTarget("secret", bad); err == nil {
			t.Fatal("forged descriptor accepted")
		}
	}
}

type captureHelloConn struct {
	net.PacketConn
	mu    sync.Mutex
	hello []byte
}

func (p *captureHelloConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	q, err := dnsparser.ParseDNSRequestLite(b)
	if err == nil {
		name := strings.TrimSuffix(strings.ToLower(q.FirstQuestion.Name), "."+Zone("test.example"))
		payload, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.ReplaceAll(name, ".", "")))
		if len(payload) == 34 && payload[0] == 0 && payload[1] == 0 {
			p.mu.Lock()
			p.hello = bytes.Clone(payload[2:])
			p.mu.Unlock()
		}
	}
	return p.PacketConn.WriteTo(b, addr)
}

func TestCottenMaxFreshEphemeralKeyPerClient(t *testing.T) {
	cfg, _ := testServer(t, impairment{})
	var hellos [][]byte
	for i := 0; i < 2; i++ {
		var captured *captureHelloConn
		cfg.ListenPacket = func(ctx context.Context, network, address string) (net.PacketConn, error) {
			var lc net.ListenConfig
			pc, err := lc.ListenPacket(ctx, network, address)
			if err != nil {
				return nil, err
			}
			captured = &captureHelloConn{PacketConn: pc}
			return captured, nil
		}
		c, err := NewClient(cfg)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		conn, err := c.Dial(ctx, "echo.example:443")
		cancel()
		if err != nil {
			c.Close()
			t.Fatal(err)
		}
		captured.mu.Lock()
		hellos = append(hellos, bytes.Clone(captured.hello))
		captured.mu.Unlock()
		conn.Close()
		c.Close()
	}
	if len(hellos[0]) != 32 || len(hellos[1]) != 32 || bytes.Equal(hellos[0], hellos[1]) {
		t.Fatal("session handshake reused its ephemeral public key")
	}
}

func TestCottenMaxDoesNotDowngradeToLegacy(t *testing.T) {
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	var queries atomic.Int64
	var legacy atomic.Bool
	done := make(chan struct{})
	go func() {
		defer close(done)
		b := make([]byte, 4096)
		for {
			n, addr, err := pc.ReadFromUDP(b)
			if err != nil {
				return
			}
			queries.Add(1)
			parsed, err := dnsparser.ParseDNSRequestLite(b[:n])
			if err != nil || !strings.HasSuffix(strings.ToLower(parsed.FirstQuestion.Name), "."+Zone("test.example")) {
				legacy.Store(true)
			}
			// A legacy server can return a DNS answer, but no authenticated max data.
			msg := bytes.Clone(b[:n])
			msg[2], msg[3] = 0x81, 0x80
			_, _ = pc.WriteToUDP(msg, addr)
		}
	}()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	c, err := NewClient(ClientConfig{Domain: "test.example", PublicKey: base64.StdEncoding.EncodeToString(pub), Secret: "secret", Resolvers: []string{pc.LocalAddr().String()}, TCP: "off"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if conn, err := c.Dial(ctx, "example.com:443"); err == nil {
		conn.Close()
		t.Fatal("legacy-only server authenticated as max")
	}
	c.Close()
	pc.Close()
	<-done
	if queries.Load() == 0 || legacy.Load() {
		t.Fatalf("queries=%d legacy fallback=%v", queries.Load(), legacy.Load())
	}
}
