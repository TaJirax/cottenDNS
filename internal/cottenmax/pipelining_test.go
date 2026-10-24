package cottenmax

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

func TestTransparentStreamPipelinesWhileProxyDialWaits(t *testing.T) {
	for _, confirmed := range []bool{false, true} {
		name := "transparent"
		if confirmed {
			name = "confirmed-proxy"
		}
		t.Run(name, func(t *testing.T) {
			release, started := make(chan struct{}), make(chan struct{}, 1)
			cfg, _ := testServer(t, impairment{}, func(ctx context.Context, _ string) (net.Conn, error) {
				started <- struct{}{}
				select {
				case <-release:
				case <-ctx.Done():
					return nil, ctx.Err()
				}
				a, b := net.Pipe()
				go func() { defer b.Close(); io.Copy(b, b) }()
				return a, nil
			})
			c, err := NewClient(cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			result := make(chan net.Conn, 1)
			failures := make(chan error, 1)
			go func() {
				var conn net.Conn
				var err error
				if confirmed {
					conn, err = c.Dial(ctx, "example.com:443")
				} else {
					conn, err = c.DialStream(ctx, "example.com:443")
				}
				if err != nil {
					failures <- err
				} else {
					result <- conn
				}
			}()
			select {
			case <-started:
			case err := <-failures:
				t.Fatal(err)
			case <-ctx.Done():
				t.Fatal("server dial never started")
			}
			var conn net.Conn
			if confirmed {
				select {
				case early := <-result:
					early.Close()
					t.Fatal("proxy reported success before backend dial")
				case err := <-failures:
					t.Fatal(err)
				case <-time.After(25 * time.Millisecond):
				}
				close(release)
				select {
				case conn = <-result:
				case err := <-failures:
					t.Fatal(err)
				case <-ctx.Done():
					t.Fatal("confirmed dial did not finish")
				}
			} else {
				select {
				case conn = <-result:
				case err := <-failures:
					t.Fatal(err)
				case <-ctx.Done():
					t.Fatal("transparent dial waited for backend confirmation")
				}
				conn.SetDeadline(time.Now().Add(time.Second))
				if _, err := conn.Write([]byte("early")); err != nil {
					t.Fatal(err)
				}
				close(release)
				reply := make([]byte, 5)
				if _, err := io.ReadFull(conn, reply); err != nil || string(reply) != "early" {
					t.Fatalf("pipelined bytes lost: %q %v", reply, err)
				}
			}
			conn.Close()
		})
	}
}
