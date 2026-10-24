package client

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"cottendns-go/internal/config"
	"cottendns-go/internal/cottenmax"
	"cottendns-go/internal/logger"
)

func cottenMaxProxyFixture(t *testing.T) (*Client, context.Context) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { echo.Close() })
	go func() {
		for {
			conn, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
		}
	}()
	backend, err := cottenmax.NewServer(ctx, cottenmax.ServerConfig{Domains: []string{"test.example"}, Key: key, Secret: "secret", MaxSessions: 16, MaxStreams: 16,
		Dial: func(ctx context.Context, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", echo.Addr().String())
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		b := make([]byte, 4096)
		for {
			n, a, err := pc.ReadFromUDP(b)
			if err != nil {
				return
			}
			backend.DispatchUDP(b[:n], pc, a)
		}
	}()
	engine, err := cottenmax.NewClient(cottenmax.ClientConfig{Domain: "test.example", PublicKey: base64.StdEncoding.EncodeToString(pub), Secret: "secret", Resolvers: []string{pc.LocalAddr().String()}, TCP: "off", Hold: 500 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	log := logger.New("max-proxy-test", "ERROR")
	c := New(config.ClientConfig{TunnelMode: config.TunnelCottenMax, LocalHandshakeTimeoutSeconds: 2, MaxActiveStreams: 16}, log, nil)
	c.cottenMax.Store(engine)
	t.Cleanup(func() {
		cancel()
		engine.Close()
		pc.Close()
		backend.Close()
		<-done
		log.Close()
	})
	return c, ctx
}

func TestCottenMaxProxyInterfaces(t *testing.T) {
	for _, mode := range []string{"socks5", "socks4a", "http_connect", "http_plain", "udp_rejected"} {
		t.Run(mode, func(t *testing.T) {
			c, ctx := cottenMaxProxyFixture(t)
			app, local := net.Pipe()
			defer app.Close()
			_ = app.SetDeadline(time.Now().Add(5 * time.Second))
			finished := make(chan struct{})
			go func() {
				defer close(finished)
				if strings.HasPrefix(mode, "http") {
					c.HandleHTTPProxy(ctx, local)
				} else {
					c.HandleSOCKS5(ctx, local)
				}
			}()
			if strings.HasPrefix(mode, "socks") || mode == "udp_rejected" {
				if mode == "socks4a" {
					_, _ = app.Write(append([]byte{4, 1, 1, 187, 0, 0, 0, 1, 0}, []byte("example.com\x00")...))
					var reply [8]byte
					if _, err := io.ReadFull(app, reply[:]); err != nil || reply[1] != SOCKS4_REPLY_GRANTED {
						t.Fatalf("SOCKS4a reply=%x err=%v", reply, err)
					}
				} else {
					_, _ = app.Write([]byte{5, 1, 0})
					var greeting [2]byte
					if _, err := io.ReadFull(app, greeting[:]); err != nil || greeting != [2]byte{5, 0} {
						t.Fatalf("SOCKS5 greeting %x: %v", greeting, err)
					}
					cmd := byte(1)
					if mode == "udp_rejected" {
						cmd = 3
					}
					req := append([]byte{5, cmd, 0, 3, 11}, []byte("example.com")...)
					req = append(req, 1, 187)
					_, _ = app.Write(req)
					var reply [10]byte
					if _, err := io.ReadFull(app, reply[:]); err != nil {
						t.Fatal(err)
					}
					if mode == "udp_rejected" {
						if reply[1] != 7 {
							t.Fatalf("UDP association accepted: %x", reply)
						}
						return
					}
					if reply[1] != 0 {
						t.Fatalf("SOCKS5 connect failed: %x", reply)
					}
				}
			} else if mode == "http_connect" {
				_, _ = io.WriteString(app, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
				br := bufio.NewReader(app)
				line, err := br.ReadString('\n')
				if err != nil || !strings.Contains(line, "200") {
					t.Fatalf("CONNECT: %q %v", line, err)
				}
				if line, err = br.ReadString('\n'); err != nil || line != "\r\n" {
					t.Fatalf("CONNECT headers: %q %v", line, err)
				}
			} else {
				_, _ = io.WriteString(app, "GET http://example.com/test HTTP/1.1\r\nHost: example.com\r\n\r\n")
				line, err := bufio.NewReader(app).ReadString('\n')
				if err != nil || line != "GET /test HTTP/1.1\r\n" {
					t.Fatalf("plain HTTP rewrite: %q %v", line, err)
				}
				return
			}
			payload := []byte("CottenMax proxy roundtrip")
			written := make(chan error, 1)
			go func() { _, err := app.Write(payload); written <- err }()
			got := make([]byte, len(payload))
			if _, err := io.ReadFull(app, got); err != nil {
				t.Fatal(err)
			}
			if err := <-written; err != nil || !bytes.Equal(payload, got) {
				t.Fatalf("echo %q: %v", got, err)
			}
			app.Close()
			select {
			case <-finished:
			case <-time.After(time.Second):
				t.Fatal("proxy did not finish after local close")
			}
		})
	}
}
