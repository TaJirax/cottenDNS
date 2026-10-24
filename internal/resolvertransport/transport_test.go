package resolvertransport

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func testCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "resolver.test"}, DNSNames: []string{"resolver.test"}, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, roots
}
func testQuery(id uint16) []byte {
	q := []byte{0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 4, 't', 'e', 's', 't', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0, 0, 1, 0, 1}
	binary.BigEndian.PutUint16(q[:2], id)
	return q
}
func testAnswer(q []byte) []byte { a := append([]byte(nil), q...); a[2] |= 0x80; return a }
func addressPort(t *testing.T, address string) int {
	t.Helper()
	_, p, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	n, err := strconv.Atoi(p)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestDoHValidationAndCancellation(t *testing.T) {
	var behavior atomic.Int32
	entered := make(chan struct{}, 4)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q, _ := io.ReadAll(r.Body)
		if r.Method != "POST" || r.Header.Get("Content-Type") != ContentType {
			t.Error("invalid DoH request")
		}
		w.Header().Set("Content-Type", ContentType)
		switch behavior.Load() {
		case 1:
			w.Header().Set("Content-Type", "text/plain")
		case 2:
			if len(q) > 0 {
				q[0] ^= 0xff
			}
		case 3:
			entered <- struct{}{}
			<-r.Context().Done()
			return
		case 4:
			http.Redirect(w, r, "http://127.0.0.1:1/dns-query", http.StatusTemporaryRedirect)
			return
		case 5:
			w.Write(make([]byte, 65536))
			return
		}
		w.Write(testAnswer(q))
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	client, err := New("doh", Options{TLSConfig: &tls.Config{RootCAs: roots}, DoHPort: addressPort(t, server.Listener.Addr().String())})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	original := testQuery(0x7ac2)
	answer, err := client.Exchange(context.Background(), "127.0.0.1:53", original)
	if err != nil || !bytes.Equal(answer, testAnswer(original)) {
		t.Fatalf("valid exchange: %x %v", answer, err)
	}
	for _, mode := range []int32{1, 2, 4, 5} {
		behavior.Store(mode)
		if _, err := client.Exchange(context.Background(), "127.0.0.1:53", original); err == nil {
			t.Fatalf("accepted invalid response mode %d", mode)
		}
	}
	behavior.Store(3)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := client.Exchange(ctx, "127.0.0.1:53", original); done <- err }()
	<-entered
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancellation succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("DoH cancellation stuck")
	}
	untrusted, _ := New("doh", Options{DoHPort: addressPort(t, server.Listener.Addr().String())})
	defer untrusted.Close()
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := untrusted.Exchange(ctx, "127.0.0.1:53", original); err == nil {
		t.Fatal("accepted untrusted certificate")
	}
}

func TestHTTP3VerifiedConcurrentAndFallback(t *testing.T) {
	cert, roots := testCertificate(t)
	var h3Requests atomic.Int64
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http3.Server{TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}}, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 3 {
			t.Error("not HTTP/3")
		}
		q, _ := io.ReadAll(r.Body)
		h3Requests.Add(1)
		w.Header().Set("Content-Type", ContentType)
		w.Write(testAnswer(q))
	})}
	done := make(chan error, 1)
	go func() { done <- server.Serve(udp) }()
	defer func() { server.Close(); udp.Close(); <-done }()
	port := addressPort(t, udp.LocalAddr().String())
	client, err := New("doh3", Options{TLSConfig: &tls.Config{RootCAs: roots, ServerName: "resolver.test"}, DoHPort: port})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(id uint16) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			q := testQuery(id)
			a, err := client.Exchange(ctx, "127.0.0.1:53", q)
			if err != nil || !bytes.Equal(a, testAnswer(q)) {
				t.Errorf("HTTP3 exchange id%d: %x %v", id, a, err)
			}
		}(uint16(i + 1))
	}
	wg.Wait()
	if h3Requests.Load() != 20 {
		t.Fatalf("HTTP3 requests=%d", h3Requests.Load())
	}
	bad, _ := New("doh3", Options{DoHPort: port})
	defer bad.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := bad.Exchange(ctx, "127.0.0.1:53", testQuery(2)); err == nil {
		t.Fatal("HTTP3 accepted untrusted certificate")
	}

	// Only TCP/TLS is available. Fallback is an explicit option and caches the
	// failed h3 attempt briefly so every query does not repeat its startup cost.
	tlsServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", ContentType)
		w.Write(testAnswer(q))
	}))
	tlsServer.EnableHTTP2 = true
	tlsServer.StartTLS()
	defer tlsServer.Close()
	tlsRoots := x509.NewCertPool()
	tlsRoots.AddCert(tlsServer.Certificate())
	fallback, _ := New("doh3", Options{TLSConfig: &tls.Config{RootCAs: tlsRoots}, DoHPort: addressPort(t, tlsServer.Listener.Addr().String()), HTTP3Fallback: true})
	defer fallback.Close()
	for i := 0; i < 2; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		start := time.Now()
		q := testQuery(uint16(40 + i))
		a, err := fallback.Exchange(ctx, "127.0.0.1:53", q)
		cancel()
		if err != nil || !bytes.Equal(a, testAnswer(q)) {
			t.Fatalf("encrypted h3 fallback: %v", err)
		}
		if i == 1 && time.Since(start) > time.Second {
			t.Fatal("repeated QUIC startup despite recent failure")
		}
	}
}

func TestDoQIDsConcurrencyReuseCancellationAndClose(t *testing.T) {
	cert, roots := testCertificate(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"doq"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var connections, queries atomic.Int64
	var block, wrongID atomic.Bool
	entered := make(chan struct{}, 64)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := listener.Accept(ctx)
			if err != nil {
				return
			}
			connections.Add(1)
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
						if len(q) < 12 || q[0] != 0 || q[1] != 0 {
							t.Error("DoQ query ID must be zero")
						}
						queries.Add(1)
						if block.Load() {
							entered <- struct{}{}
							<-stream.Context().Done()
							return
						}
						a := testAnswer(q)
						if wrongID.Load() {
							a[0] = 1
						}
						wire := make([]byte, 2+len(a))
						binary.BigEndian.PutUint16(wire[:2], uint16(len(a)))
						copy(wire[2:], a)
						stream.Write(wire)
						stream.Close()
					}()
				}
			}()
		}
	}()
	defer func() { cancel(); listener.Close(); wg.Wait() }()
	port := addressPort(t, listener.Addr().String())
	client, err := New("doq", Options{TLSConfig: &tls.Config{RootCAs: roots, ServerName: "resolver.test"}, DoQPort: port})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	var calls sync.WaitGroup
	for i := 1; i <= 32; i++ {
		calls.Add(1)
		go func(id uint16) {
			defer calls.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			q := testQuery(id)
			a, err := client.Exchange(ctx, "127.0.0.1:53", q)
			if err != nil || !bytes.Equal(a, testAnswer(q)) || binary.BigEndian.Uint16(q[:2]) != id {
				t.Errorf("DoQ id%d: %x %v", id, a, err)
			}
		}(uint16(i))
	}
	calls.Wait()
	if connections.Load() != 1 || queries.Load() != 32 {
		t.Fatalf("connections %d queries %d", connections.Load(), queries.Load())
	}
	wrongID.Store(true)
	if _, err := client.Exchange(ctx, "127.0.0.1:53", testQuery(45)); err == nil {
		t.Fatal("accepted nonzero DoQ reply ID")
	}
	wrongID.Store(false)
	block.Store(true)
	queryctx, stop := context.WithCancel(ctx)
	finished := make(chan error, 1)
	go func() { _, err := client.Exchange(queryctx, "127.0.0.1:53", testQuery(50)); finished <- err }()
	<-entered
	stop()
	select {
	case err := <-finished:
		if err == nil {
			t.Fatal("cancelled DoQ succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("DoQ cancellation stuck")
	}
	go func() { _, err := client.Exchange(ctx, "127.0.0.1:53", testQuery(51)); finished <- err }()
	<-entered
	client.Close()
	select {
	case err := <-finished:
		if err == nil {
			t.Fatal("closed DoQ succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("DoQ close stuck")
	}
	bad, _ := New("doq", Options{DoQPort: port})
	defer bad.Close()
	queryctx, stop = context.WithTimeout(ctx, time.Second)
	defer stop()
	if _, err := bad.Exchange(queryctx, "127.0.0.1:53", testQuery(99)); err == nil {
		t.Fatal("DoQ accepted untrusted certificate")
	}
}

func TestResolverBootstrapRequiresNumericIP(t *testing.T) {
	client, _ := New("doh", Options{})
	defer client.Close()
	if _, err := client.Exchange(context.Background(), "resolver.test:53", testQuery(1)); err == nil {
		t.Fatal("implicit system DNS bootstrap allowed")
	}
}

func TestDoHCustomEndpointQueryIsPreserved(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/custom/dns-query" || r.URL.Query().Get("token") != "local-test" {
			t.Errorf("configured DoH endpoint changed: %s", r.URL.String())
		}
		q, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", ContentType)
		w.Write(testAnswer(q))
	}))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	c, err := New("doh", Options{TLSConfig: &tls.Config{RootCAs: roots}, DoHPort: addressPort(t, server.Listener.Addr().String()), DoHPath: "/custom/dns-query?token=local-test"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	q := testQuery(7)
	answer, err := c.Exchange(ctx, "127.0.0.1:53", q)
	if err != nil || !bytes.Equal(answer, testAnswer(q)) {
		t.Fatalf("configured endpoint exchange: %x %v", answer, err)
	}
}
