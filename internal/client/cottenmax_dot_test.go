package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"cottendns-go/internal/config"
	"cottendns-go/internal/cottenmax"
	"cottendns-go/internal/logger"
)

// A local authenticated DNS-over-TLS resolver forwards to the full Max adapter.
func TestCottenMaxDoT(t *testing.T) {
	for _, trust := range []string{"pinned", "padded_shaped", "half_open", "wrong_pin", "untrusted_certificate", "blocked_handshake"} {
		t.Run(trust, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			pub, key, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			backend, err := cottenmax.NewServer(ctx, cottenmax.ServerConfig{Domains: []string{"test.example"}, Key: key, Secret: "secret", MaxSessions: 8, MaxStreams: 16,
				Dial: func(context.Context, string) (net.Conn, error) {
					a, b := net.Pipe()
					go func() {
						defer b.Close()
						stop := context.AfterFunc(ctx, func() { b.Close() })
						defer stop()
						_, _ = io.Copy(b, b)
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
			if trust == "wrong_pin" {
				pin = base64.StdEncoding.EncodeToString(make([]byte, 32))
			}
			if trust == "untrusted_certificate" {
				pin = ""
			}
			ln, err := tls.Listen("tcp4", "127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}})
			if err != nil {
				t.Fatal(err)
			}
			var wg sync.WaitGroup
			var dnsQueries, connections, plainQueries atomic.Int64
			var halfOpen atomic.Bool
			var droppedQueries atomic.Int64
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					conn, err := ln.Accept()
					if err != nil {
						return
					}
					connectionID := connections.Add(1)
					wg.Add(1)
					go func(connectionID int64) {
						defer wg.Done()
						defer conn.Close()
						stop := context.AfterFunc(ctx, func() { conn.Close() })
						defer stop()
						if trust == "blocked_handshake" {
							<-ctx.Done()
							return
						}
						var writeMu sync.Mutex
						for {
							msg, err := readTCPDNSFramed(conn)
							if err != nil {
								return
							}
							dnsQueries.Add(1)

							if trust == "padded_shaped" {
								if len(msg)%128 != 0 {
									t.Errorf("DoT query is not padded to128bytes: %d", len(msg))
								}
								var labels []int
								for pos := 12; pos < len(msg) && msg[pos] != 0; {
									n := int(msg[pos])
									if n > 63 || pos+1+n > len(msg) {
										t.Error("invalid shaped QName")
										break
									}
									labels = append(labels, n)
									pos += 1 + n
								}
								// The reserved zone is _max.test.example (three fixed labels).
								if len(labels) < 4 {
									t.Error("missing Max payload labels")
								}
								for _, n := range labels[:max(0, len(labels)-3)] {
									if n > 32 {
										t.Errorf("configured label bound ignored: %d", n)
									}
								}
							}
							if connectionID == 1 && halfOpen.Load() {
								droppedQueries.Add(1)
								continue
							}
							wg.Add(1)
							go func() {
								defer wg.Done()
								response, _ := backend.Exchange(msg)
								if connectionID == 1 && halfOpen.Load() {
									droppedQueries.Add(1)
									return
								}
								writeMu.Lock()
								defer writeMu.Unlock()
								_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
								_ = writeTCPDNSFramed(conn, response)
							}()
						}
					}(connectionID)
				}
			}()
			plain, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				buf := make([]byte, 4096)
				for {
					_, _, err := plain.ReadFromUDP(buf)
					if err != nil {
						return
					}
					plainQueries.Add(1)
				}
			}()
			t.Cleanup(func() { cancel(); ln.Close(); plain.Close(); wg.Wait() })
			cfg := config.ClientConfig{TunnelMode: config.TunnelCottenMax, Domains: []string{"test.example"}, EncryptionKey: "secret",
				CottenMaxServerPublicKey: base64.StdEncoding.EncodeToString(pub), CottenMaxHoldMilliseconds: 500,
				ResolverTransport: "dot", ResolverIPMode: "ipv4", ResolverDoTPort: ln.Addr().(*net.TCPAddr).Port,
				ResolverTLSPin: pin, ResolverTLSServerName: "resolver.test", Resolvers: []config.ResolverAddress{{IP: "127.0.0.1", Port: plain.LocalAddr().(*net.UDPAddr).Port}},
				ListenIP: "127.0.0.1", ListenPort: 0, ProtocolType: "TCP", MaxActiveStreams: 16}
			if trust == "padded_shaped" {
				cfg.DNSPaddingBlockSize = 128
				cfg.QNameLabelLength = 32
				cfg.QNameLabelJitter = true
			}
			log := logger.New("max-dot-test", "ERROR")
			defer log.Close()
			app := New(cfg, log, nil)
			done := make(chan error, 1)
			go func() { done <- app.Run(ctx) }()
			t.Cleanup(func() {
				cancel()
				select {
				case err := <-done:
					if err != nil {
						t.Error(err)
					}
				case <-time.After(2 * time.Second):
					t.Error("client did not stop")
				}
			})
			limit := time.Now().Add(time.Second)
			for app.cottenMax.Load() == nil && time.Now().Before(limit) {
				time.Sleep(time.Millisecond)
			}
			engine := app.cottenMax.Load()
			if engine == nil {
				t.Fatal("Max engine did not start")
			}
			dialCtx, stop := context.WithTimeout(ctx, 800*time.Millisecond)
			defer stop()
			conn, err := engine.Dial(dialCtx, "echo.example:443")
			if trust != "pinned" && trust != "padded_shaped" && trust != "half_open" {
				if err == nil {
					conn.Close()
					t.Fatal("untrusted resolver certificate accepted")
				}
				if dnsQueries.Load() != 0 || engine.Established() {
					t.Fatal("tunnel traffic passed an untrusted TLS peer")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				transfer := func(size int, timeout time.Duration) {
					t.Helper()
					_ = conn.SetDeadline(time.Now().Add(timeout))
					want := make([]byte, size)
					if _, err := rand.Read(want); err != nil {
						t.Fatal(err)
					}
					written := make(chan error, 1)
					go func() { _, err := io.Copy(conn, bytes.NewReader(want)); written <- err }()
					got := make([]byte, len(want))
					if _, err := io.ReadFull(conn, got); err != nil {
						conn.Close()
						<-written
						t.Fatal(err)
					}
					if err := <-written; err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(want, got) {
						t.Fatal("DoT stream corrupted")
					}
				}
				transfer(64<<10, 5*time.Second)
				if connections.Load() != 1 || dnsQueries.Load() < 2 {
					t.Fatal("DoT did not reuse a pipelined TLS connection")
				}
				if trust == "half_open" {
					// Keep accepting DNS frames on the established TLS socket while
					// silently discarding them. A replacement connection reaches the
					// same backend so the existing authenticated tunnel can continue.
					halfOpen.Store(true)
					started := time.Now()
					transfer(32<<10, 12*time.Second)
					if elapsed := time.Since(started); elapsed >= 12*time.Second {
						t.Fatalf("half-open DoT recovery took %s", elapsed)
					}
					if connections.Load() != 2 || droppedQueries.Load() == 0 {
						t.Fatalf("half-open recovery used %d TLS connections and dropped %d queries", connections.Load(), droppedQueries.Load())
					}
				}
			}
			if plainQueries.Load() != 0 {
				t.Fatal("explicit DoT leaked plaintext UDP queries")
			}
		})
	}
}
