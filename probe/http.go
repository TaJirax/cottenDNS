// Package probe verifies an actual authenticated CottenDNS tunnel and HTTPS
// egress. Credentials stay in memory or private temporary files, never argv.
package probe

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"cottendns-go/internal/client"
	"cottendns-go/internal/config"
	"golang.org/x/net/proxy"
)

type Config struct {
	Domain    string      `json:"domain"`
	Key       string      `json:"key"`
	Resolvers []string    `json:"-"`
	Transport string      `json:"-"`
	URL       string      `json:"-"`
	TLSConfig *tls.Config `json:"-"`
}

func CheckHTTP(parent context.Context, in Config) (int, error) {
	u, err := url.Parse(in.URL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return 0, errors.New("probe requires an HTTPS destination")
	}
	if len(in.Key) < 32 || len(in.Domain) < 3 || len(in.Resolvers) == 0 {
		return 0, errors.New("missing Cotten probe credentials or resolvers")
	}
	if in.Transport != "udp" && in.Transport != "tcp" && in.Transport != "auto" {
		return 0, errors.New("invalid Cotten DNS transport")
	}
	work, err := os.MkdirTemp("", "whitedns-cotten-check-")
	if err != nil {
		return 0, err
	}
	defer os.RemoveAll(work)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	address := listener.Addr().String()
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	text := fmt.Sprintf(`PROTOCOL_TYPE = "SOCKS5"
LISTEN_IP = "127.0.0.1"
LISTEN_PORT = %d
SOCKS5_AUTH = false
DOMAINS = [%q]
ENCRYPTION_KEY = %q
DATA_ENCRYPTION_METHOD = 5
LEGACY_SESSION_ID = false
TERMINAL_UI = "plain"
STARTUP_MODE = "resolvers"
RESOLVER_TRANSPORT = %q
QUERY_TYPES = ["TXT"]
MIN_UPLOAD_MTU = 80
MAX_UPLOAD_MTU = 142
MIN_DOWNLOAD_MTU = 16
MAX_DOWNLOAD_MTU = 1500
MTU_TEST_RETRIES_RESOLVERS = 0
MTU_TEST_TIMEOUT_RESOLVERS = 2.0
MTU_TEST_PARALLELISM_RESOLVERS = 2
FAST_CONNECT = true
UPLOAD_PACKET_DUPLICATION_COUNT = 1
DOWNLOAD_PACKET_DUPLICATION_COUNT = 1
UPLOAD_SETUP_PACKET_DUPLICATION_COUNT = 1
DOWNLOAD_SETUP_PACKET_DUPLICATION_COUNT = 1
RECHECK_INACTIVE_SERVERS_ENABLED = false
AUTO_DISABLE_TIMEOUT_SERVERS = false
LOG_LEVEL = "ERROR"
LOG_DIR = %q
`, port, in.Domain, in.Key, in.Transport, work)
	configPath, resolverPath := filepath.Join(work, "client.toml"), filepath.Join(work, "resolvers.txt")
	if err = os.WriteFile(configPath, []byte(text), 0600); err != nil {
		return 0, err
	}
	if err = os.WriteFile(resolverPath, []byte(strings.Join(in.Resolvers, "\n")+"\n"), 0600); err != nil {
		return 0, err
	}
	app, err := client.Bootstrap(configPath, config.ClientConfigOverrides{ResolversFilePath: &resolverPath})
	if err != nil {
		return 0, errors.New("Cotten probe configuration failed")
	}
	app.Log().SwapConsoleWriter(io.Discard)
	ctx, cancel := context.WithCancel(parent)
	done := make(chan error, 1)
	go func() { done <- app.Run(ctx) }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
		}
	}()
	dialer, err := proxy.SOCKS5("tcp", address, nil, &net.Dialer{Timeout: 5 * time.Second})
	if err != nil {
		return 0, err
	}
	contextDialer := dialer.(proxy.ContextDialer)
	transport := &http.Transport{TLSClientConfig: in.TLSConfig, DisableKeepAlives: true, DialContext: func(ctx context.Context, network, target string) (net.Conn, error) {
		for {
			if app.StatusSnapshot().Phase == "connected" {
				conn, err := contextDialer.DialContext(ctx, network, target)
				if err == nil {
					return conn, nil
				}
				var op *net.OpError
				if !errors.As(err, &op) || op.Op != "dial" {
					return nil, err
				}
			}
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(50 * time.Millisecond):
			}
		}
	}}
	defer transport.CloseIdleConnections()
	httpClient := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, "GET", in.URL, nil)
	if err != nil {
		return 0, err
	}
	response, err := httpClient.Do(req)
	if err != nil {
		return 0, errors.New("Cotten tunnel HTTPS test failed; check DNS transport and outbound access")
	}
	defer response.Body.Close()
	if _, err = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10)); err != nil {
		return response.StatusCode, errors.New("Cotten HTTPS response incomplete")
	}
	if response.StatusCode < 200 || response.StatusCode >= 400 {
		return response.StatusCode, errors.New("Cotten HTTPS destination returned an unsuccessful status")
	}
	return response.StatusCode, nil
}
