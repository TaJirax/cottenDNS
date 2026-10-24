//go:build e2e

package e2e

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"cottendns-go/internal/cottenmax"
)

func cottenMaxSettings(t *testing.T) (server, client string) {
	t.Helper()
	keyPath := filepath.Join(t.TempDir(), "cottenmax_identity")
	key, err := cottenmax.LoadKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	pub := base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
	return fmt.Sprintf("TUNNEL_MODE = \"cottenmax\"\nCOTTENMAX_KEY_FILE = %q\n", keyPath),
		fmt.Sprintf("TUNNEL_MODE = \"cottenmax\"\nCOTTENMAX_SERVER_PUBLIC_KEY = %q\nLOCAL_DNS_ENABLED = false\n", pub)
}

func directCottenMaxResolver(t *testing.T, addr *net.UDPAddr) []string {
	return []string{addr.String()}
}

func TestCottenMaxBinaryModes(t *testing.T) {
	for _, transport := range []string{"udp", "tcp", "dot"} {
		for _, host := range []string{"127.0.0.1", "::1"} {
			t.Run(transport+"/"+host, func(t *testing.T) {
				if host == "::1" {
					requireIPv6Loopback(t)
				}
				server, client := cottenMaxSettings(t)
				if transport == "dot" {
					tlsServer, tlsClient := cottenMaxTLSSettings(t)
					server += tlsServer
					client += tlsClient
				}
				client += fmt.Sprintf("RESOLVER_TRANSPORT = %q\nTERMINAL_UI = \"plain\"\nSTARTUP_MODE = \"resolvers\"\n", transport)
				runTunnelEchoVia(t, 3, 3, server, `["TXT"]`, client, host, tunnelBins{}, directCottenMaxResolver)
			})
		}
	}
}

func cottenMaxTLSSettings(t *testing.T) (string, string) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"a.io"}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}), 0600); err != nil {
		t.Fatal(err)
	}
	port := freeTCPPort(t)
	sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	return fmt.Sprintf("DOT_LISTENER_ENABLED = true\nDOT_LISTEN_HOST = \"\"\nDOT_LISTEN_PORT = %d\nTLS_CERT_FILE = %q\nTLS_KEY_FILE = %q\n", port, certPath, keyPath),
		fmt.Sprintf("RESOLVER_DOT_PORT = %d\nRESOLVER_TLS_SERVER_NAME = \"a.io\"\nRESOLVER_TLS_PIN = %q\n", port, base64.StdEncoding.EncodeToString(sum[:]))
}

// The pre-change binaries are deliberately independent of the current source.
// Build/save them before experimenting; see docs/COTTENMAX_EXPERIMENT.md.
func TestCottenMaxLegacyCompatibility(t *testing.T) {
	dir := os.Getenv("COTTENMAX_BASELINE_DIR")
	if dir == "" {
		dir = filepath.Join(repoRoot(t), ".bench", "cottenmax", "baseline")
	}
	oldServer, oldClient := filepath.Join(dir, binName("server")), filepath.Join(dir, binName("client"))
	for _, path := range []string{oldServer, oldClient} {
		if _, err := os.Stat(path); err != nil {
			t.Skipf("pre-change baseline binary missing: %s", path)
		}
	}
	t.Run("new_legacy_client_old_server", func(t *testing.T) {
		runTunnelEchoVia(t, 3, 3, "", `["TXT"]`, "TUNNEL_MODE = \"legacy\"\nSTARTUP_MODE = \"resolvers\"\nTERMINAL_UI = \"plain\"\n", "127.0.0.1", tunnelBins{server: oldServer}, directCottenMaxResolver)
	})
	t.Run("old_client_new_cottenmax_server", func(t *testing.T) {
		server, _ := cottenMaxSettings(t)
		runTunnelEchoVia(t, 3, 3, server, `["TXT"]`, "STARTUP_MODE = \"resolvers\"\nTERMINAL_UI = \"plain\"\n", "127.0.0.1", tunnelBins{client: oldClient}, directCottenMaxResolver)
	})
	t.Run("new_legacy_client_new_cottenmax_server", func(t *testing.T) {
		server, _ := cottenMaxSettings(t)
		runTunnelEchoVia(t, 3, 3, server, `["TXT"]`, "TUNNEL_MODE = \"legacy\"\nSTARTUP_MODE = \"resolvers\"\nTERMINAL_UI = \"plain\"\n", "127.0.0.1", tunnelBins{}, directCottenMaxResolver)
	})
	t.Run("old_one_byte_client_new_cottenmax_server", func(t *testing.T) {
		server, _ := cottenMaxSettings(t)
		runTunnelEchoVia(t, 3, 3, server, `["TXT"]`, "LEGACY_SESSION_ID = true\nSTARTUP_MODE = \"resolvers\"\nTERMINAL_UI = \"plain\"\n", "127.0.0.1", tunnelBins{client: oldClient}, directCottenMaxResolver)
	})
}

// Both modes use the same default server config and generated encrypt_key.txt.
// No COTTENMAX_KEY_FILE or COTTENMAX_SERVER_PUBLIC_KEY is supplied.
func TestCottenMaxSharedCredentialModes(t *testing.T) {
	for _, transport := range []string{"udp", "tcp"} {
		t.Run(transport, func(t *testing.T) {
			runTunnelEchoVia(t, 3, 3, "", `["TXT"]`, fmt.Sprintf(`TUNNEL_MODE = "cottenmax"
RESOLVER_TRANSPORT = %q
STARTUP_MODE = "resolvers"
TERMINAL_UI = "plain"
`, transport), "127.0.0.1", tunnelBins{}, directCottenMaxResolver)
		})
	}
}
