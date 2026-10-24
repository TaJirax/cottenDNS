package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"cottendns-go/internal/config"
	"cottendns-go/internal/cottenmax"
	"cottendns-go/internal/resolvertransport"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// Each local recursive transport forwards the actual DNS wire query to the
// full Max server. Same domain/credential, no separate Max signing key/profile.
func TestCottenMaxEncryptedResolverTransports(t *testing.T) {
	for _, mode := range []string{"doh", "doh3", "doq"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			key, err := cottenmax.SharedIdentity("same-cotten-key")
			if err != nil {
				t.Fatal(err)
			}
			backend, err := cottenmax.NewServer(ctx, cottenmax.ServerConfig{Domains: []string{"test.example"}, Key: key, Secret: "same-cotten-key", MaxSessions: 8, MaxStreams: 16, Dial: func(context.Context, string) (net.Conn, error) {
				a, b := net.Pipe()
				go func() {
					defer b.Close()
					stop := context.AfterFunc(ctx, func() { b.Close() })
					defer stop()
					io.Copy(b, b)
				}()
				return a, nil
			}})
			if err != nil {
				t.Fatal(err)
			}
			defer backend.Close()
			cert, err := generateTestCert()
			if err != nil {
				t.Fatal(err)
			}
			leaf, err := x509.ParseCertificate(cert.Certificate[0])
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
			pin := base64.StdEncoding.EncodeToString(sum[:])
			cfg := config.ClientConfig{ResolverTransport: mode, ResolverTLSPin: pin, ResolverTLSServerName: "resolver.test", ResolverDoHPath: "/dns-query", DNSPaddingBlockSize: 128}
			normalQuery := []byte{0x2a, 0x5e, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 6, 'n', 'o', 'r', 'm', 'a', 'l', 0, 0, 1, 0, 1}
			forward := func(q []byte) ([]byte, error) {
				if len(q)%128 != 0 {
					t.Errorf("query not padded: %d", len(q))
				}
				if len(q) >= len(normalQuery) && bytes.Equal(q[12:len(normalQuery)], normalQuery[12:]) {
					response := append([]byte(nil), q...)
					response[2] |= 0x80
					return response, nil
				}
				response, ok := backend.Exchange(q)
				if !ok {
					return nil, errors.New("Max backend rejected DNS query")
				}
				return response, nil
			}
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				query, _ := io.ReadAll(r.Body)
				response, err := forward(query)
				if err != nil {
					http.Error(w, err.Error(), 500)
					return
				}
				w.Header().Set("Content-Type", resolvertransport.ContentType)
				w.Write(response)
			})
			if mode == "doh" {
				server := httptest.NewUnstartedServer(handler)
				server.EnableHTTP2 = true
				server.StartTLS()
				defer server.Close()
				cfg.ResolverDoHPort = server.Listener.Addr().(*net.TCPAddr).Port
				leaf = server.Certificate()
				sum = sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
				cfg.ResolverTLSPin = base64.StdEncoding.EncodeToString(sum[:])
			} else if mode == "doh3" {
				udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				server := &http3.Server{TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}}, Handler: handler}
				done := make(chan error, 1)
				go func() { done <- server.Serve(udp) }()
				defer func() { server.Close(); udp.Close(); <-done }()
				cfg.ResolverDoHPort = udp.LocalAddr().(*net.UDPAddr).Port
			} else {
				listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"doq"}}, nil)
				if err != nil {
					t.Fatal(err)
				}
				cfg.ResolverDoQPort = listener.Addr().(*net.UDPAddr).Port
				var wg sync.WaitGroup
				wg.Add(1)
				go func() {
					defer wg.Done()
					for {
						conn, err := listener.Accept(ctx)
						if err != nil {
							return
						}
						wg.Add(1)
						go func() {
							defer wg.Done()
							defer conn.CloseWithError(0, "")
							for {
								stream, err := conn.AcceptStream(ctx)
								if err != nil {
									return
								}
								wg.Add(1)
								go func() {
									defer wg.Done()
									defer stream.CancelRead(3)
									var size [2]byte
									if _, err := io.ReadFull(stream, size[:]); err != nil {
										return
									}
									q := make([]byte, int(binary.BigEndian.Uint16(size[:])))
									if _, err := io.ReadFull(stream, q); err != nil {
										return
									}
									response, err := forward(q)
									if err != nil {
										return
									}
									framed := make([]byte, 2+len(response))
									binary.BigEndian.PutUint16(framed[:2], uint16(len(response)))
									copy(framed[2:], response)
									stream.Write(framed)
									stream.Close()
								}()
							}
						}()
					}
				}()
				defer func() { cancel(); listener.Close(); wg.Wait() }()
			}
			app := &Client{cfg: cfg, rxChannel: make(chan asyncReadPacket, 1)}
			app.setActiveTransport(resolverTransportFromName(mode))
			defer app.closeSharedEncryptedDNSClient()
			// The normal engine's synchronous probes and asynchronous data plane use
			// the same verified transport pool and retain each original DNS ID.
			probe, err := app.newQueryTransport("127.0.0.1:53")
			if err != nil {
				t.Fatal(err)
			}
			response, err := probe.exchange(normalQuery, 2*time.Second)
			probe.Close()
			if err != nil || len(response) < len(normalQuery) || !bytes.Equal(response[:2], normalQuery[:2]) {
				t.Fatalf("normal query transport: %x %v", response, err)
			}
			data := newDoHDataManager(app)
			data.Start(ctx)
			data.Send("", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53}, normalQuery, 0, time.Now())
			select {
			case reply := <-app.rxChannel:
				if len(reply.data) < len(normalQuery) || !bytes.Equal(reply.data[:2], normalQuery[:2]) {
					t.Fatal("normal data plane lost DNS ID")
				}
				app.putRuntimeUDPBuffer(reply.data)
			case <-time.After(2 * time.Second):
				t.Fatal("normal data transport did not deliver response")
			}
			data.Stop()
			engine, err := cottenmax.NewClient(cottenmax.ClientConfig{Domain: "test.example", Secret: "same-cotten-key", Resolvers: []string{"127.0.0.1:53"}, TCP: "off", Hold: 100 * time.Millisecond, ListenPacket: app.newCottenMaxEncryptedPacketConn})
			if err != nil {
				t.Fatal(err)
			}
			defer engine.Close()
			dialctx, stop := context.WithTimeout(ctx, 3*time.Second)
			defer stop()
			conn, err := engine.Dial(dialctx, "echo.example:443")
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			payload := bytes.Repeat([]byte("encrypted-max-content"), 2048)
			go func() {
				_, err := conn.Write(payload)
				if err != nil {
					t.Errorf("write: %v", err)
				}
			}()
			answer := make([]byte, len(payload))
			if _, err := io.ReadFull(conn, answer); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(answer, payload) {
				t.Fatal("encrypted transport corrupted stream")
			}

			// Secondary engines are created using a short per-dial context. The
			// context expires immediately on success; their DNS socket must remain
			// alive for subsequent stream traffic and later dials.
			fallback, err := cottenmax.NewClient(cottenmax.ClientConfig{Domain: "blocked.example", Domains: []string{"test.example"}, Secret: "same-cotten-key", Resolvers: []string{"127.0.0.1:53"}, TCP: "off", FailoverAfter: 120 * time.Millisecond, ListenPacket: app.newCottenMaxEncryptedPacketConn})
			if err != nil {
				t.Fatal(err)
			}
			defer fallback.Close()
			for i := 0; i < 2; i++ {
				attempt, cancel := context.WithTimeout(ctx, 3*time.Second)
				stream, err := fallback.Dial(attempt, "echo.example:443")
				cancel()
				if err != nil {
					t.Fatalf("encrypted fallback dial%d: %v", i, err)
				}
				stream.SetDeadline(time.Now().Add(time.Second))
				message := []byte("traffic after creation context cancellation")
				if _, err := stream.Write(message); err != nil {
					t.Fatal(err)
				}
				received := make([]byte, len(message))
				_, err = io.ReadFull(stream, received)
				stream.Close()
				if err != nil || !bytes.Equal(received, message) {
					t.Fatalf("encrypted fallback stream%d: %q %v", i, received, err)
				}
			}
		})
	}
}

func TestEncryptedPacketConnCloseAndDeadlines(t *testing.T) {
	entered := make(chan struct{}, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { entered <- struct{}{}; <-r.Context().Done() }))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	transport, err := resolvertransport.New("doh", resolvertransport.Options{TLSConfig: &tls.Config{RootCAs: roots}, DoHPort: server.Listener.Addr().(*net.TCPAddr).Port})
	if err != nil {
		t.Fatal(err)
	}
	p := newEncryptedPacketConn(context.Background(), transport, 10*time.Second)
	defer p.Close()
	p.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	if _, _, err := p.ReadFrom(make([]byte, 512)); err == nil {
		t.Fatal("ignored read deadline")
	}
	p.SetReadDeadline(time.Time{})
	q := []byte{0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 'a', 0, 0, 1, 0, 1}
	if _, err := p.WriteTo(q, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53}); err != nil {
		t.Fatal(err)
	}
	<-entered
	done := make(chan error, 1)
	go func() { _, _, err := p.ReadFrom(make([]byte, 512)); done <- err }()
	p.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("closed read succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("close did not interrupt read")
	}
	if _, err := p.WriteTo(q, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53}); err == nil {
		t.Fatal("write succeeded after close")
	}
}

// Closing one Max domain's engine must not destroy the resolver connection
// pool needed by the next domain. The owning Client closes it on final exit.
func TestCottenMaxEncryptedPoolSurvivesPacketConnClose(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q, _ := io.ReadAll(r.Body)
		q[2] |= 0x80
		w.Header().Set("Content-Type", resolvertransport.ContentType)
		w.Write(q)
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	leaf := server.Certificate()
	hash := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	c := &Client{cfg: config.ClientConfig{ResolverTransport: "doh", ResolverDoHPort: server.Listener.Addr().(*net.TCPAddr).Port, ResolverTLSPin: base64.StdEncoding.EncodeToString(hash[:])}}
	defer c.closeSharedEncryptedDNSClient()
	q := []byte{0, 8, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 'a', 0, 0, 1, 0, 1}
	var pool *resolvertransport.Client
	for i := 0; i < 2; i++ {
		pc, err := c.newCottenMaxEncryptedPacketConn(context.Background(), "udp", ":0")
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			pool = c.encryptedDNS
		} else if pool != c.encryptedDNS {
			t.Fatal("domain failover replaced resolver pool")
		}
		pc.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := pc.WriteTo(q, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53}); err != nil {
			t.Fatal(err)
		}
		buffer := make([]byte, 512)
		n, _, err := pc.ReadFrom(buffer)
		if err != nil || n < len(q) || !bytes.Equal(buffer[:2], q[:2]) {
			t.Fatalf("domain %d exchange: %v", i, err)
		}
		pc.Close()
	}
	c.closeSharedEncryptedDNSClient()
	if _, err := pool.Exchange(context.Background(), "127.0.0.1:53", q); err == nil {
		t.Fatal("final owner close left pool usable")
	}
}

func TestEncryptedQueryTransportCloseCancelsOnlyOwnedExchange(t *testing.T) {
	entered := make(chan struct{}, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q, _ := io.ReadAll(r.Body)
		if q[1] == 1 {
			entered <- struct{}{}
			<-r.Context().Done()
			return
		}
		q[2] |= 0x80
		w.Header().Set("Content-Type", resolvertransport.ContentType)
		w.Write(q)
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	sum := sha256.Sum256(server.Certificate().RawSubjectPublicKeyInfo)
	c := &Client{cfg: config.ClientConfig{ResolverTransport: "doh", ResolverDoHPort: server.Listener.Addr().(*net.TCPAddr).Port, ResolverTLSPin: base64.StdEncoding.EncodeToString(sum[:])}}
	c.setActiveTransport(transportDoH)
	defer c.closeSharedEncryptedDNSClient()
	first, err := c.newQueryTransport("127.0.0.1:53")
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	q := []byte{0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 'a', 0, 0, 1, 0, 1}
	done := make(chan error, 1)
	go func() { _, err := first.exchange(q, 10*time.Second); done <- err }()
	<-entered
	first.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("closed exchange succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("query Close did not cancel owned exchange")
	}
	second, err := c.newQueryTransport("127.0.0.1:53")
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	q[1] = 2
	answer, err := second.exchange(q, time.Second)
	if err != nil || len(answer) < 12 || answer[1] != 2 {
		t.Fatalf("closing first exchange destroyed shared resolver pool: %x %v", answer, err)
	}
}
