package soar_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"testing"
	"time"

	engine "cottendns-go/internal/cottenmax/engine"
	upstream "github.com/getlantern/soar"
)

// Exercise both directions against the independently pinned dependency, so
// transport scheduling changes cannot silently change the experimental wire.
func TestCottenMaxUpstreamWireCompatibility(t *testing.T) {
	for _, forkClient := range []bool{true, false} {
		name := "upstream_client_local_server"
		if forkClient {
			name = "local_client_upstream_server"
		}
		t.Run(name, func(t *testing.T) {
			pub, key, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			origin, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer origin.Close()
			go func() {
				c, err := origin.Accept()
				if err != nil {
					return
				}
				defer c.Close()
				stop := context.AfterFunc(ctx, func() { c.Close() })
				defer stop()
				_, _ = io.Copy(c, c)
			}()
			pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			const zone = "cottenmax-v1.a.io"
			done := make(chan error, 1)
			go func() {
				dial := (&net.Dialer{}).DialContext
				if forkClient {
					done <- upstream.Serve(ctx, pc, upstream.ServerConfig{Zone: zone, PrivateKey: key, Dial: dial})
				} else {
					done <- engine.Serve(ctx, pc, engine.ServerConfig{Zone: zone, PrivateKey: key, Dial: dial})
				}
			}()
			t.Cleanup(func() {
				cancel()
				pc.Close()
				select {
				case <-done:
				case <-time.After(3 * time.Second):
					t.Error("server did not stop")
				}
			})
			var c interface {
				DialContext(context.Context, string, string) (net.Conn, error)
				Close() error
			}
			if forkClient {
				c, err = engine.NewClient(engine.Config{Zone: zone, ServerKey: pub, Resolvers: []string{pc.LocalAddr().String()}, TCP: "off", MaxPathWindow: 128})
			} else {
				c, err = upstream.NewClient(upstream.Config{Zone: zone, ServerKey: pub, Resolvers: []string{pc.LocalAddr().String()}, TCP: "off"})
			}
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			dialCtx, stop := context.WithTimeout(ctx, 5*time.Second)
			defer stop()
			conn, err := c.DialContext(dialCtx, "tcp", origin.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
			want := make([]byte, 100<<10)
			if _, err := rand.Read(want); err != nil {
				t.Fatal(err)
			}
			written := make(chan error, 1)
			go func() { _, err := io.Copy(conn, bytes.NewReader(want)); written <- err }()
			got := make([]byte, len(want))
			if _, err := io.ReadFull(conn, got); err != nil {
				t.Fatal(err)
			}
			if err := <-written; err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(want, got) {
				t.Fatal("cross-version transfer corrupted bytes")
			}
		})
	}
}
