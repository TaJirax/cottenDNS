//go:build e2e && maxperf

package e2e

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"cottendns-go/internal/client"
	"cottendns-go/internal/config"
	"cottendns-go/internal/cottenmax"
	DnsParser "cottendns-go/internal/dnsparser"
	"cottendns-go/internal/logger"
	"cottendns-go/internal/security"
	"cottendns-go/internal/udpserver"
	"github.com/getlantern/soar"
)

// countedResolver preserves question bytes and rewrites DNS IDs, as a recursive
// resolver does. Delay applies independently in each direction. The ID mapping
// is bounded by the 16-bit DNS ID space; cancellation stops delayed writes.
func countedResolver(t *testing.T, upstream *net.UDPAddr, delay time.Duration, profiles ...string) (string, *atomic.Int64) {
	t.Helper()
	down, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	up, err := net.DialUDP("udp4", nil, upstream)
	if err != nil {
		down.Close()
		t.Fatal(err)
	}
	type pending struct {
		// Packet mapping entries below are bounded by the 16-bit DNS ID space.
		id   uint16
		addr *net.UDPAddr
	}
	_ = down.SetReadBuffer(8 << 20)
	_ = down.SetWriteBuffer(8 << 20)
	_ = up.SetReadBuffer(8 << 20)
	_ = up.SetWriteBuffer(8 << 20)
	var mu sync.Mutex
	mapping := make(map[uint16]pending)
	var sequence uint16
	var count atomic.Int64
	var responses atomic.Int64
	profile := ""
	if len(profiles) > 0 {
		profile = profiles[0]
	}
	tokens, lastTokenTime := 64.0, time.Now()
	var wg sync.WaitGroup
	wg.Add(2)
	ctx, cancel := context.WithCancel(context.Background())
	forward := func(write func([]byte), data []byte) {
		if delay == 0 {
			write(data)
			return
		}
		// Timers model independent propagation, rather than serializing packets
		// behind one artificial sleep in the resolver's read loop.
		time.AfterFunc(delay, func() {
			if ctx.Err() == nil {
				write(data)
			}
		})
	}
	go func() {
		defer wg.Done()
		b := make([]byte, 65535)
		for {
			n, addr, err := down.ReadFromUDP(b)
			if err != nil {
				return
			}
			if n < 12 {
				continue
			}
			index := count.Add(1)
			if profile == "loss" && index%29 == 0 {
				continue
			}
			if profile == "short-names" {
				parsed, err := DnsParser.ParseDNSRequestLite(b[:n])
				if err != nil || !parsed.HasQuestion || len(parsed.FirstQuestion.Name) > 101 {
					continue
				}
			}
			if profile == "rate-limited" {
				now := time.Now()
				tokens = min(64, tokens+now.Sub(lastTokenTime).Seconds()*1000)
				lastTokenTime = now
				if tokens < 1 {
					continue
				}
				tokens--
			}
			msg := bytes.Clone(b[:n])
			mu.Lock()
			sequence++
			id := sequence
			mapping[id] = pending{binary.BigEndian.Uint16(msg), addr}
			mu.Unlock()
			binary.BigEndian.PutUint16(msg, id)
			forward(func(b []byte) { _, _ = up.Write(b) }, msg)
		}
	}()
	go func() {
		defer wg.Done()
		b := make([]byte, 65535)
		for {
			n, err := up.Read(b)
			if err != nil {
				return
			}
			if n < 12 {
				continue
			}
			if profile == "loss" && responses.Add(1)%31 == 0 {
				continue
			}
			mu.Lock()
			p, ok := mapping[binary.BigEndian.Uint16(b)]
			mu.Unlock()
			if !ok {
				continue
			}
			msg := bytes.Clone(b[:n])
			binary.BigEndian.PutUint16(msg, p.id)
			forward(func(b []byte) { _, _ = down.WriteToUDP(b, p.addr) }, msg)
		}
	}()
	t.Cleanup(func() { cancel(); down.Close(); up.Close(); wg.Wait() })
	return down.LocalAddr().String(), &count
}

type maxMeasurement struct {
	cold, warm time.Duration
	queries    int64
}

func measureMode(t *testing.T, mode string, delay time.Duration, profiles ...string) maxMeasurement {
	t.Helper()
	work := t.TempDir()
	serverPort, clientPort, echoPort := freeUDPPort(t), freeTCPPort(t), startEchoServer(t)
	secret := strings.Repeat("a", 16)
	identity := filepath.Join(work, "identity")
	key, err := cottenmax.LoadKey(identity)
	if err != nil {
		t.Fatal(err)
	}
	pub := base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
	serverPath := filepath.Join(work, "server.toml")
	configMode := mode
	if mode == "soar" {
		configMode = config.TunnelLegacy
	}
	serverText := fmt.Sprintf(`TUNNEL_MODE = %q
COTTENMAX_KEY_FILE = %q
CONFIG_PRESET = "speed"
DOMAIN = ["a.io"]
PROTOCOL_TYPE = "TCP"
UDP_HOST = "127.0.0.1"
UDP_PORT = %d
UDP_IPV6_ENABLED = false
TCP_LISTENER_ENABLED = false
FORWARD_IP = "127.0.0.1"
FORWARD_PORT = %d
DATA_ENCRYPTION_METHOD = 3
LOG_LEVEL = "ERROR"
`, configMode, identity, serverPort, echoPort)
	if err := os.WriteFile(serverPath, []byte(serverText), 0o600); err != nil {
		t.Fatal(err)
	}
	scfg, err := config.LoadServerConfig(serverPath)
	if err != nil {
		t.Fatal(err)
	}
	codec, err := security.NewCodec(3, secret)
	if err != nil {
		t.Fatal(err)
	}
	slog := logger.New("max-comparison-server", "ERROR")
	srv := udpserver.New(scfg, slog, codec)
	srv.SetCottenMaxSecret(secret)
	ctx, cancel := context.WithCancel(context.Background())
	serverDone := make(chan error, 1)
	if mode == "soar" {
		pc, err := net.ListenPacket("udp4", fmt.Sprintf("127.0.0.1:%d", serverPort))
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			serverDone <- soar.Serve(ctx, pc, soar.ServerConfig{Zone: cottenmax.Zone("a.io"), PrivateKey: key, Dial: (&net.Dialer{}).DialContext})
		}()
	} else {
		go func() { serverDone <- srv.Run(ctx) }()
	}
	t.Cleanup(func() {
		cancel()
		select {
		case <-serverDone:
		case <-time.After(5 * time.Second):
			t.Error("server shutdown timeout")
		}
		slog.Close()
	})
	// Server initialization is outside the measured client cold start.
	time.Sleep(50 * time.Millisecond)
	resolver, queries := countedResolver(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: serverPort}, delay, profiles...)
	if err := os.WriteFile(filepath.Join(work, "client_resolvers.txt"), []byte(resolver+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	clientPath := filepath.Join(work, "client.toml")
	clientText := fmt.Sprintf(`TUNNEL_MODE = %q
COTTENMAX_SERVER_PUBLIC_KEY = %q
CONFIG_PRESET = "speed"
DOMAINS = ["a.io"]
PROTOCOL_TYPE = "TCP"
LISTEN_IP = "127.0.0.1"
LISTEN_PORT = %d
ENCRYPTION_KEY = %q
DATA_ENCRYPTION_METHOD = 3
RESOLVER_TRANSPORT = "udp"
LOCAL_DNS_ENABLED = false
MIN_UPLOAD_MTU = 40
MIN_DOWNLOAD_MTU = 200
MAX_UPLOAD_MTU = 142
MAX_DOWNLOAD_MTU = 1232
MTU_TEST_TIMEOUT_RESOLVERS = 0.5
UPLOAD_COMPRESSION_TYPE = 0
DOWNLOAD_COMPRESSION_TYPE = 0
UPLOAD_PACKET_DUPLICATION_COUNT = 1
DOWNLOAD_PACKET_DUPLICATION_COUNT = 1
UPLOAD_SETUP_PACKET_DUPLICATION_COUNT = 1
DOWNLOAD_SETUP_PACKET_DUPLICATION_COUNT = 1
LOG_LEVEL = "ERROR"
`, configMode, pub, clientPort, secret)
	if err := os.WriteFile(clientPath, []byte(clientText), 0o600); err != nil {
		t.Fatal(err)
	}
	// Test-only tuning experiments. Production configuration never reads this
	// environment variable, and the independent Soar/legacy controls are unchanged.
	if mode == config.TunnelCottenMax {
		variant := os.Getenv("COTTENMAX_EXPERIMENT_VARIANT")
		extra := ""
		switch variant {
		case "", "default":
		case "qname-guard":
			extra = "COTTENMAX_QNAME_LOSS_GUARD = true\n"
		case "window64":
			extra = "COTTENMAX_MAX_PATH_WINDOW = 64\nCOTTENMAX_MAX_INFLIGHT = 64\n"
		case "window128":
			extra = "COTTENMAX_MAX_PATH_WINDOW = 128\nCOTTENMAX_MAX_INFLIGHT = 128\n"
		case "window512":
			extra = "COTTENMAX_MAX_PATH_WINDOW = 512\nCOTTENMAX_MAX_INFLIGHT = 512\n"
		case "hold100":
			extra = "COTTENMAX_HOLD_MILLISECONDS = 100\n"
		case "hold1000":
			extra = "COTTENMAX_HOLD_MILLISECONDS = 1000\n"
		case "window128-hold100":
			extra = "COTTENMAX_MAX_PATH_WINDOW = 128\nCOTTENMAX_MAX_INFLIGHT = 128\nCOTTENMAX_HOLD_MILLISECONDS = 100\n"
		default:
			t.Fatalf("unknown experiment variant %q", variant)
		}
		if extra != "" {
			if err := os.WriteFile(clientPath, []byte(clientText+extra), 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	cfg, err := config.LoadClientConfig(clientPath)
	if err != nil {
		t.Fatal(err)
	}
	clog := logger.New("max-comparison-client", "ERROR")
	app := client.New(cfg, clog, codec)
	if err := app.BuildConnectionMap(); err != nil {
		t.Fatal(err)
	}
	clientDone := make(chan error, 1)
	started := time.Now()
	if mode == "soar" {
		c, err := soar.NewClient(soar.Config{Zone: cottenmax.Zone("a.io"), ServerKey: ed25519.PublicKey(key.Public().(ed25519.PublicKey)), Resolvers: []string{resolver}, TCP: "off"})
		if err != nil {
			t.Fatal(err)
		}
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", clientPort))
		if err != nil {
			c.Close()
			t.Fatal(err)
		}
		context.AfterFunc(ctx, func() { ln.Close(); c.Close() })
		go func() {
			for {
				local, err := ln.Accept()
				if err != nil {
					clientDone <- nil
					return
				}
				go func() {
					defer local.Close()
					remote, err := c.DialContext(ctx, "tcp", fmt.Sprintf("127.0.0.1:%d", echoPort))
					if err != nil {
						return
					}
					defer remote.Close()
					done := make(chan struct{})
					go func() {
						_, _ = io.Copy(remote, local)
						if cw, ok := remote.(interface{ CloseWrite() error }); ok {
							_ = cw.CloseWrite()
						}
						close(done)
					}()
					_, _ = io.Copy(local, remote)
					local.Close()
					<-done
				}()
			}
		}()
	} else {
		go func() { clientDone <- app.Run(ctx) }()
	}
	t.Cleanup(func() {
		cancel()
		select {
		case <-clientDone:
		case <-time.After(5 * time.Second):
			t.Error("client shutdown timeout")
		}
		clog.Close()
	})
	addr := fmt.Sprintf("127.0.0.1:%d", clientPort)
	var first net.Conn
	for time.Since(started) < 20*time.Second {
		first, err = net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			break
		}
		select {
		case runErr := <-clientDone:
			t.Fatalf("client stopped: %v", runErr)
		default:
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	roundtrip := func(conn net.Conn, size int) {
		t.Helper()
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
		payload := make([]byte, size)
		if _, err := rand.Read(payload); err != nil {
			t.Fatal(err)
		}
		written := make(chan error, 1)
		go func() { _, err := io.Copy(conn, bytes.NewReader(payload)); written <- err }()
		got := make([]byte, size)
		if _, err := io.ReadFull(conn, got); err != nil {
			t.Fatal(err)
		}
		if err := <-written; err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(payload, got) {
			t.Fatal("payload mismatch")
		}
	}
	roundtrip(first, 2<<10)
	out := maxMeasurement{cold: time.Since(started)}
	before := queries.Load()
	var samples []time.Duration
	for i := 0; i < 3; i++ {
		start := time.Now()
		conn, err := net.DialTimeout("tcp", addr, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		roundtrip(conn, 100<<10)
		samples = append(samples, time.Since(start))
	}
	slices.Sort(samples)
	out.warm = samples[1]
	out.queries = (queries.Load() - before) / 3
	return out
}

// No speed assertions: scheduler noise and machine load affect local timings.
// Keep the complete byte-integrity assertions and report both modes honestly.
func TestCottenMaxLocalComparison(t *testing.T) {
	for _, delay := range []time.Duration{0, 15 * time.Millisecond, 75 * time.Millisecond} {
		for _, mode := range []string{config.TunnelLegacy, config.TunnelCottenMax, "soar"} {
			if mode == "soar" && delay > 15*time.Millisecond {
				continue // the upstream comparison already takes ~25s at 30ms RTT
			}
			t.Run(fmt.Sprintf("rtt=%s/%s", 2*delay, mode), func(t *testing.T) {
				m := measureMode(t, mode, delay)
				t.Logf("RESULT mode=%s rtt=%s cold_2KiB=%s warm_100KiB_echo_p50=%s queries_per_echo=%d", mode, 2*delay, m.cold.Round(time.Millisecond), m.warm.Round(time.Millisecond), m.queries)
			})
		}
	}
}

// Same byte-exact workload and resolver for all three modes. Counters include
// dropped requests. Rates are observations, not machine-dependent assertions.
func TestCottenMaxImpairedComparison(t *testing.T) {
	for _, profile := range []string{"loss", "short-names", "rate-limited"} {
		for _, mode := range []string{config.TunnelLegacy, config.TunnelCottenMax, "soar"} {
			t.Run(profile+"/"+mode, func(t *testing.T) {
				m := measureMode(t, mode, 15*time.Millisecond, profile)
				t.Logf("RESULT scenario=%s mode=%s rtt=30ms cold_2KiB=%s warm_100KiB_echo_p50=%s queries_per_echo=%d", profile, mode, m.cold.Round(time.Millisecond), m.warm.Round(time.Millisecond), m.queries)
			})
		}
	}
}
