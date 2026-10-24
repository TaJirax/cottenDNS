package cottenmax

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"cottendns-go/internal/dnsparser"
)

type routePolicy struct {
	server                       *Server
	dropAll, dropUDP, forgedOnly bool
	inject, otherSource, corrupt bool
	refuseTXT                    bool
	refuseAll                    bool
	dropTCPThrough               int64
	exchange                     func([]byte) ([]byte, bool)
	maxName, maxAnswer           int
	delay                        time.Duration
}

// routeResolver changes forwarding policy without changing the address seen
// by the client. Both listeners and all test traffic stay on loopback.
type routeResolver struct {
	policy                 atomic.Pointer[routePolicy]
	udp, other             *net.UDPConn
	tcp                    net.Listener
	udpQueries, tcpQueries atomic.Int64
	tcpConnections         atomic.Int64
	ctx                    context.Context
	cancel                 context.CancelFunc
	wg                     sync.WaitGroup
	slots                  chan struct{}
}

func newRouteResolver(t *testing.T, policy routePolicy) *routeResolver {
	t.Helper()
	var ln net.Listener
	var pc *net.UDPConn
	var err error
	for range 128 {
		port := 20000 + mrand.IntN(40000)
		ln, err = net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			continue
		}
		pc, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
		if err == nil {
			break
		}
		ln.Close()
	}
	if err != nil {
		t.Fatalf("allocate shared UDP/TCP test port: %v", err)
	}
	other, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		pc.Close()
		ln.Close()
		t.Fatal(err)
	}
	_ = pc.SetReadBuffer(1 << 20)
	_ = pc.SetWriteBuffer(1 << 20)
	ctx, cancel := context.WithCancel(context.Background())
	r := &routeResolver{udp: pc, other: other, tcp: ln, ctx: ctx, cancel: cancel, slots: make(chan struct{}, 512)}
	r.policy.Store(&policy)
	r.wg.Add(2)
	go func() {
		defer r.wg.Done()
		buf := make([]byte, 4096)
		for {
			n, from, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			r.udpQueries.Add(1)
			r.dispatch(bytes.Clone(buf[:n]), false, func(b []byte, alternate bool) {
				socket := pc
				if alternate {
					socket = other
				}
				_, _ = socket.WriteToUDP(b, from)
			})
		}
	}()
	go func() {
		defer r.wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			connectionID := r.tcpConnections.Add(1)
			r.wg.Add(1)
			go func() {
				defer r.wg.Done()
				defer conn.Close()
				stop := context.AfterFunc(ctx, func() { conn.Close() })
				defer stop()
				var writeMu sync.Mutex
				for {
					var hdr [2]byte
					if _, err := io.ReadFull(conn, hdr[:]); err != nil {
						return
					}
					msg := make([]byte, int(binary.BigEndian.Uint16(hdr[:])))
					if _, err := io.ReadFull(conn, msg); err != nil {
						return
					}
					r.tcpQueries.Add(1)
					if connectionID <= r.policy.Load().dropTCPThrough {
						continue // Simulate a half-open route; new connections remain usable.
					}
					r.dispatch(msg, true, func(b []byte, _ bool) {
						frame := binary.BigEndian.AppendUint16(nil, uint16(len(b)))
						frame = append(frame, b...)
						writeMu.Lock()
						defer writeMu.Unlock()
						_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
						_, _ = conn.Write(frame)
					})
				}
			}()
		}
	}()
	t.Cleanup(func() { cancel(); ln.Close(); pc.Close(); other.Close(); r.wg.Wait() })
	return r
}

func (r *routeResolver) dispatch(msg []byte, tcp bool, send func([]byte, bool)) {
	select {
	case r.slots <- struct{}{}:
	default:
		return
	}
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		defer func() { <-r.slots }()
		p := r.policy.Load()
		if p.dropAll || p.dropUDP && !tcp {
			return
		}
		q, err := dnsparser.ParseDNSRequestLite(msg)
		if err != nil {
			return
		}
		if p.maxName > 0 && len(q.FirstQuestion.Name) > p.maxName {
			return
		}
		errorAnswer := func(code byte, tc bool) {
			b := bytes.Clone(msg)
			b[2], b[3] = 0x81, 0x80|code
			if tc {
				b[2] |= 2
			}
			send(b, p.otherSource)
		}
		if p.refuseTXT && q.FirstQuestion.Type == 16 {
			errorAnswer(5, false)
			return
		}
		if p.refuseAll {
			errorAnswer(5, false)
			return
		}
		if p.inject || p.forgedOnly {
			for _, code := range []byte{3, 2, 5, 0} {
				errorAnswer(code, false)
			}
			errorAnswer(0, true)
		}
		if p.forgedOnly || p.server == nil && p.exchange == nil {
			return
		}
		if p.delay > 0 {
			select {
			case <-time.After(p.delay):
			case <-r.ctx.Done():
				return
			}
		}
		var b []byte
		if p.exchange != nil {
			b, _ = p.exchange(msg)
		} else {
			b, _ = p.server.Exchange(msg)
		}
		if len(b) == 0 || p.maxAnswer > 0 && len(b) > p.maxAnswer {
			return
		}
		if p.corrupt && len(b) > 12 {
			b[len(b)-12] ^= 1
		} // last payload byte before OPT
		select {
		case <-r.ctx.Done():
			return
		default:
		}
		send(b, p.otherSource)
	}()
}

func routeServer(t *testing.T, key ed25519.PrivateKey, serve func(net.Conn)) (*Server, ClientConfig) {
	t.Helper()
	if key == nil {
		_, k, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		key = k
	}
	ctx, cancel := context.WithCancel(context.Background())
	s, err := NewServer(ctx, ServerConfig{Domains: []string{"test.example"}, Key: key, Secret: "route-test-secret", MaxSessions: 16, MaxStreams: 32,
		Dial: func(context.Context, string) (net.Conn, error) {
			a, b := net.Pipe()
			go func() {
				defer b.Close()
				stop := context.AfterFunc(ctx, func() { b.Close() })
				defer stop()
				if serve != nil {
					serve(b)
				} else {
					_, _ = io.Copy(b, b)
				}
			}()
			return a, nil
		}})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); s.Close() })
	return s, ClientConfig{Domain: "test.example", PublicKey: base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey)), Secret: "route-test-secret", TCP: "off", Hold: 500 * time.Millisecond}
}

func routeClient(t *testing.T, cfg ClientConfig, resolvers ...*routeResolver) (*Client, net.Conn) {
	t.Helper()
	for _, r := range resolvers {
		cfg.Resolvers = append(cfg.Resolvers, r.udp.LocalAddr().String())
	}
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	conn, err := c.Dial(ctx, "echo.example:443")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return c, conn
}

func routeEcho(conn net.Conn, size int) error {
	_ = conn.SetDeadline(time.Now().Add(12 * time.Second))
	want := make([]byte, size)
	if _, err := rand.Read(want); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { _, err := io.Copy(conn, bytes.NewReader(want)); done <- err }()
	got := make([]byte, len(want))
	if _, err := io.ReadFull(conn, got); err != nil {
		conn.Close()
		<-done
		return err
	}
	if err := <-done; err != nil {
		return err
	}
	if !bytes.Equal(want, got) {
		return io.ErrUnexpectedEOF
	}
	return nil
}

func TestCottenMaxResolverRerouting(t *testing.T) {
	for _, mode := range []string{"blackhole", "forged_answers", "different_authority"} {
		t.Run(mode, func(t *testing.T) {
			s, cfg := routeServer(t, nil, nil)
			rogue, _ := routeServer(t, nil, nil)
			a := newRouteResolver(t, routePolicy{server: s})
			b := newRouteResolver(t, routePolicy{dropAll: true})
			c, conn := routeClient(t, cfg, a, b)
			if err := routeEcho(conn, 8<<10); err != nil {
				t.Fatal(err)
			}
			before := a.udpQueries.Load()
			switch mode {
			case "blackhole":
				a.policy.Store(&routePolicy{dropAll: true})
			case "forged_answers":
				a.policy.Store(&routePolicy{forgedOnly: true})
			case "different_authority":
				a.policy.Store(&routePolicy{server: rogue})
			}
			b.policy.Store(&routePolicy{server: s, delay: 15 * time.Millisecond})
			start := time.Now()
			if err := routeEcho(conn, 100<<10); err != nil {
				t.Fatalf("existing stream did not survive rerouting: %v; paths=%+v", err, c.PathStats())
			}
			t.Logf("same stream survived %s: %s; old-path queries=%d backup queries=%d", mode, time.Since(start).Round(time.Millisecond), a.udpQueries.Load()-before, b.udpQueries.Load())
		})
	}
}

func TestCottenMaxRedirectedRepliesAndForgery(t *testing.T) {
	s, cfg := routeServer(t, nil, nil)
	bad := newRouteResolver(t, routePolicy{forgedOnly: true})
	good := newRouteResolver(t, routePolicy{server: s, inject: true, otherSource: true, delay: 15 * time.Millisecond})
	c, conn := routeClient(t, cfg, bad, good)
	if err := routeEcho(conn, 100<<10); err != nil {
		t.Fatal(err)
	}
	for _, p := range c.PathStats() {
		if p.Resolver == bad.udp.LocalAddr().String() && p.Verified {
			t.Fatal("forged DNS replies verified an unusable path")
		}
	}
}

func TestCottenMaxAutoTCPAfterUDPReroute(t *testing.T) {
	s, cfg := routeServer(t, nil, nil)
	cfg.TCP = "auto"
	r := newRouteResolver(t, routePolicy{server: s})
	c, conn := routeClient(t, cfg, r)
	if err := routeEcho(conn, 8<<10); err != nil {
		t.Fatal(err)
	}
	r.policy.Store(&routePolicy{server: s, dropUDP: true})
	if err := routeEcho(conn, 64<<10); err != nil {
		t.Fatalf("TCP fallback after a previously healthy UDP path failed: %v; paths=%+v", err, c.PathStats())
	}
	if r.tcpQueries.Load() == 0 {
		t.Fatal("rerouted UDP never activated TCP")
	}
}

func TestCottenMaxAllRoutesIntercepted(t *testing.T) {
	for _, mode := range []string{"forged", "refused", "blackhole"} {
		t.Run(mode, func(t *testing.T) {
			_, cfg := routeServer(t, nil, nil)
			policy := routePolicy{forgedOnly: true}
			switch mode {
			case "refused":
				policy = routePolicy{refuseAll: true}
			case "blackhole":
				policy = routePolicy{dropAll: true}
			}
			a := newRouteResolver(t, policy)
			b := newRouteResolver(t, policy)
			cfg.Resolvers = []string{a.udp.LocalAddr().String(), b.udp.LocalAddr().String()}
			c, err := NewClient(cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 600*time.Millisecond)
			defer cancel()
			if conn, err := c.Dial(ctx, "echo.example:443"); err == nil {
				conn.Close()
				t.Fatal("all-intercepted routes falsely connected")
			}
			if c.Established() {
				t.Fatal("unusable routes established a session")
			}
			if n := a.udpQueries.Load() + b.udpQueries.Load(); n > 8 {
				t.Fatalf("unusable routes triggered %d queries before cancellation", n)
			}
			if a.tcpQueries.Load()+b.tcpQueries.Load() != 0 {
				t.Fatal("UDP-only failure changed transport")
			}
		})
	}
}

func TestCottenMaxRecoversAfterTemporaryResolverOutage(t *testing.T) {
	s, cfg := routeServer(t, nil, nil)
	r := newRouteResolver(t, routePolicy{server: s})
	c, conn := routeClient(t, cfg, r)
	if err := routeEcho(conn, 8<<10); err != nil {
		t.Fatal(err)
	}
	r.policy.Store(&routePolicy{dropAll: true})
	restore := time.AfterFunc(800*time.Millisecond, func() { r.policy.Store(&routePolicy{server: s}) })
	defer restore.Stop()
	if err := routeEcho(conn, 64<<10); err != nil {
		t.Fatalf("temporary outage broke the existing stream: %v; paths=%+v", err, c.PathStats())
	}
}

func TestCottenMaxConcurrentStreamsAndClose(t *testing.T) {
	s, cfg := routeServer(t, nil, nil)
	r := newRouteResolver(t, routePolicy{server: s, inject: true, delay: 10 * time.Millisecond})
	c, first := routeClient(t, cfg, r)
	first.Close()
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, err := c.Dial(ctx, "echo.example:443")
			if err != nil {
				errs <- err
				return
			}
			defer conn.Close()
			errs <- routeEcho(conn, 32<<10)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := c.Dial(ctx, "echo.example:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	readDone := make(chan error, 1)
	go func() { _, err := conn.Read(make([]byte, 1)); readDone <- err }()
	c.Close()
	select {
	case err := <-readDone:
		if err == nil {
			t.Fatal("closed client returned successful idle read")
		}
	case <-time.After(time.Second):
		t.Fatal("close left stream blocked")
	}
}

func TestCottenMaxRejectsRedirectedAuthorityAndCorruption(t *testing.T) {
	for _, corrupt := range []bool{false, true} {
		t.Run(map[bool]string{false: "wrong_authority", true: "corrupt_payload"}[corrupt], func(t *testing.T) {
			s, cfg := routeServer(t, nil, nil)
			if !corrupt {
				s, _ = routeServer(t, nil, nil)
			}
			r := newRouteResolver(t, routePolicy{server: s, corrupt: corrupt})
			cfg.Resolvers = []string{r.udp.LocalAddr().String()}
			c, err := NewClient(cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 600*time.Millisecond)
			defer cancel()
			if conn, err := c.Dial(ctx, "echo.example:443"); err == nil {
				conn.Close()
				t.Fatal("unauthenticated rerouting established a stream")
			}
			if c.Established() {
				t.Fatal("unauthenticated response established a session")
			}
		})
	}
}

func TestCottenMaxResolverRecordAndAnswerLimits(t *testing.T) {
	t.Run("TXT_refused_AAAA_available", func(t *testing.T) {
		s, cfg := routeServer(t, nil, nil)
		r := newRouteResolver(t, routePolicy{server: s, refuseTXT: true, maxName: 101})
		c, conn := routeClient(t, cfg, r)
		if err := routeEcho(conn, 64<<10); err != nil {
			t.Fatal(err)
		}
		if c.PathStats()[0].RecordType != "AAAA" {
			t.Fatal("TXT refusal did not activate AAAA carrier")
		}
	})
	t.Run("answers_shrink_to_512", func(t *testing.T) {
		want := make([]byte, 256<<10)
		if _, err := rand.Read(want); err != nil {
			t.Fatal(err)
		}
		secondPhase := make(chan struct{})
		defer func() {
			select {
			case <-secondPhase:
			default:
				close(secondPhase)
			}
		}()
		s, cfg := routeServer(t, nil, func(conn net.Conn) {
			_, _ = io.Copy(conn, bytes.NewReader(want[:len(want)/2]))
			select {
			case <-secondPhase:
			case <-time.After(20 * time.Second):
				return
			}
			_, _ = io.Copy(conn, bytes.NewReader(want[len(want)/2:]))
		})
		r := newRouteResolver(t, routePolicy{server: s, delay: 15 * time.Millisecond})
		c, conn := routeClient(t, cfg, r)
		_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
		got := make([]byte, len(want))
		if _, err := io.ReadFull(conn, got[:len(got)/2]); err != nil {
			t.Fatal(err)
		}
		if c.PathStats()[0].AnswerLimit <= 512 {
			t.Fatal("test did not establish a larger answer size before rerouting")
		}
		r.policy.Store(&routePolicy{server: s, maxAnswer: 512, delay: 15 * time.Millisecond})
		close(secondPhase)
		if _, err := io.ReadFull(conn, got[len(got)/2:]); err != nil {
			t.Fatalf("512-byte answer path failed: %v; paths=%+v", err, c.PathStats())
		}
		if !bytes.Equal(want, got) {
			t.Fatal("download corrupted under answer-size policing")
		}
	})
}
