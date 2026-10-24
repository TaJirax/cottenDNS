//go:build e2e

package e2e

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"cottendns-go/internal/config"
)

// Existing mode/compatibility tests start a fresh server for each client. This
// regression keeps ONE legacy-default server alive and untouched while the
// SAME client profile switches legacy -> Max -> legacy over UDP and then TCP. Its legacy cipher is
// fixed (auto-detection off), and no additional Max identity/pin is configured.
func TestCottenMaxSwitchModesSameRunningServer(t *testing.T) {
	runCottenMaxModeSwitch(t, false)
}

// The optional real-router variant also proves that the unchanged parent-zone
// route carries Max's reserved subtree. Core-only checkouts need no Router repo.
func TestCottenMaxSwitchModesSameRunningServerViaRouter(t *testing.T) {
	if os.Getenv("COTTEN_ROUTER_DIR") == "" {
		t.Skip("set COTTEN_ROUTER_DIR to exercise the same mode switches through CottenRouter")
	}
	runCottenMaxModeSwitch(t, true)
}

type modeSwitchProcess struct {
	cmd  *exec.Cmd
	log  *safeBuf
	done chan struct{}
	once sync.Once
}

func startModeSwitchProcess(t *testing.T, binary, work, cfg string) *modeSwitchProcess {
	t.Helper()
	p := &modeSwitchProcess{cmd: exec.Command(binary, "--config", cfg), log: &safeBuf{}, done: make(chan struct{})}
	p.cmd.Dir, p.cmd.Stdout, p.cmd.Stderr = work, p.log, p.log
	if err := p.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { _ = p.cmd.Wait(); close(p.done) }()
	t.Cleanup(p.stop)
	return p
}

func (p *modeSwitchProcess) stop() {
	p.once.Do(func() {
		_ = p.cmd.Process.Kill()
		select {
		case <-p.done:
		case <-time.After(5 * time.Second):
		}
	})
}

func (p *modeSwitchProcess) assertRunning(t *testing.T) {
	t.Helper()
	select {
	case <-p.done:
		t.Fatalf("the unchanged server process exited:\n%s", p.log.String())
	default:
	}
}

func omitModeSwitchAssignment(text, key string) string {
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		name, _, ok := strings.Cut(line, "=")
		if ok && strings.TrimSpace(name) == key {
			lines[i] = ""
		}
	}
	return strings.Join(lines, "\n")
}

func runCottenMaxModeSwitch(t *testing.T, throughRouter bool) {
	t.Helper()
	root := repoRoot(t)
	serverBin := cachedBinary(t, root, "./cmd/server", "server")
	clientBin := cachedBinary(t, root, "./cmd/client", "client")
	work := t.TempDir()
	serverPort, clientPort := freeDNSPortForHost(t, "127.0.0.1"), freeTCPPort(t)
	echoPort := startEchoServer(t)
	serverPath, clientPath := filepath.Join(work, "server_config.toml"), filepath.Join(work, "client_config.toml")
	keyPath := filepath.Join(work, "encrypt_key.txt")
	// Omit TUNNEL_MODE entirely: normal legacy mode is the server default.
	serverText := omitModeSwitchAssignment(lastKeyWins(shippedTemplate(t, "server_config.toml.simple")+fmt.Sprintf(`
DOMAIN = ["a.io"]
PROTOCOL_TYPE = "TCP"
UDP_HOST = "127.0.0.1"
UDP_PORT = %d
UDP_IPV6_ENABLED = false
TCP_IPV6_ENABLED = false
TCP_LISTENER_ENABLED = true
DATA_ENCRYPTION_METHOD = 3
ENCRYPTION_AUTO_DETECT = false
ENCRYPTION_KEY_FILE = "encrypt_key.txt"
FORWARD_IP = "127.0.0.1"
FORWARD_PORT = %d
MIN_VPN_LABEL_LENGTH = 1
LOG_LEVEL = "INFO"
`, serverPort, echoPort)), "TUNNEL_MODE")
	if err := os.WriteFile(serverPath, []byte(serverText), 0600); err != nil {
		t.Fatal(err)
	}
	serverCfg, err := config.LoadServerConfig(serverPath)
	if err != nil || serverCfg.TunnelMode != config.TunnelLegacy || serverCfg.CottenMaxKeyFile != "" || serverCfg.EncryptionAutoDetect || serverCfg.DataEncryptionMethod != 3 {
		t.Fatalf("test must use a legacy-default server with a fixed legacy cipher and no Max identity: %v", err)
	}
	server := startModeSwitchProcess(t, serverBin, work, serverPath)
	if err := waitForFile(keyPath, 20*time.Second); err != nil {
		t.Fatalf("server credential not generated: %v\n%s", err, server.log.String())
	}
	originalKey, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	key := strings.TrimSpace(string(originalKey))
	resolver := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: serverPort}
	if throughRouter {
		resolver = startRouter(t, resolver)
	}
	if err := os.WriteFile(filepath.Join(work, "client_resolvers.txt"), []byte(resolver.String()+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, transport := range []string{"udp", "tcp"} {
		t.Run(transport, func(t *testing.T) {
			clientBase := lastKeyWins(shippedTemplate(t, "client_config.toml.simple") + fmt.Sprintf(`
TUNNEL_MODE = "legacy"
DOMAINS = ["a.io"]
ENCRYPTION_KEY = %q
DATA_ENCRYPTION_METHOD = 3
PROTOCOL_TYPE = "TCP"
LISTEN_IP = "127.0.0.1"
LISTEN_PORT = %d
RESOLVER_TRANSPORT = %q
QUERY_TYPES = ["TXT"]
LOCAL_DNS_ENABLED = false
HTTP_PROXY_ENABLED = false
STARTUP_MODE = "resolvers"
TERMINAL_UI = "plain"
MIN_UPLOAD_MTU = 80
MAX_UPLOAD_MTU = 142
MIN_DOWNLOAD_MTU = 16
MAX_DOWNLOAD_MTU = 4000
MTU_TEST_RETRIES_RESOLVERS = 0
MTU_TEST_TIMEOUT_RESOLVERS = 1.0
MTU_TEST_PARALLELISM_RESOLVERS = 1
MTU_TEST_RETRIES_LOGS = 0
MTU_TEST_TIMEOUT_LOGS = 1.0
UPLOAD_COMPRESSION_TYPE = 0
DOWNLOAD_COMPRESSION_TYPE = 0
LOG_LEVEL = "INFO"
`, key, clientPort, transport))
			for index, mode := range []string{"legacy", "cottenmax", "legacy"} {
				t.Run(fmt.Sprintf("%d_%s", index+1, mode), func(t *testing.T) {
					server.assertRunning(t)
					// The same file/profile is reused. This is the only changed key.
					clientText := strings.Replace(clientBase, "TUNNEL_MODE = \"legacy\"", "TUNNEL_MODE = "+fmt.Sprintf("%q", mode), 1)
					if err := os.WriteFile(clientPath, []byte(clientText), 0600); err != nil {
						t.Fatal(err)
					}
					clientCfg, err := config.LoadClientConfig(clientPath)
					if err != nil || clientCfg.TunnelMode != mode || clientCfg.EncryptionKey != key || len(clientCfg.Domains) != 1 || clientCfg.Domains[0] != "a.io" || clientCfg.CottenMaxServerPublicKey != "" || clientCfg.DataEncryptionMethod != 3 {
						t.Fatalf("mode switch changed shared profile/credential or added a Max pin: %v", err)
					}
					client := startModeSwitchProcess(t, clientBin, work, clientPath)
					defer client.stop()
					if err := waitForPattern(client.log, "is listening", 30*time.Second); err != nil {
						t.Fatalf("client did not become ready: %v\nclient:\n%s\nserver:\n%s", err, client.log.String(), server.log.String())
					}
					modeSwitchEcho(t, clientPort, client.log, server.log)
					server.assertRunning(t)
					currentConfig, configErr := os.ReadFile(serverPath)
					currentKey, keyErr := os.ReadFile(keyPath)
					if configErr != nil || keyErr != nil || !bytes.Equal(currentConfig, []byte(serverText)) || !bytes.Equal(currentKey, originalKey) {
						t.Fatal("the server configuration or original encryption key changed during the mode switch")
					}
					if err := filepath.WalkDir(work, func(path string, entry fs.DirEntry, err error) error {
						if err != nil {
							return err
						}
						name := strings.ToLower(entry.Name())
						if !entry.IsDir() && (strings.HasSuffix(name, ".pub") || strings.Contains(name, "cottenmax")) {
							return fmt.Errorf("unexpected separate Max identity file: %s", path)
						}
						return nil
					}); err != nil {
						t.Fatal(err)
					}
					t.Logf("server PID %d stayed running: %s, same a.io domain/key, 65536 exact bytes", server.cmd.Process.Pid, mode)
				})
			}
		})
	}
}

func modeSwitchEcho(t *testing.T, port int, clientLog, serverLog *safeBuf) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(port)), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	payload := make([]byte, 64<<10)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	written := make(chan error, 1)
	go func() { _, err := io.Copy(conn, bytes.NewReader(payload)); written <- err }()
	reply := make([]byte, len(payload))
	if n, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("read %d/%d bytes: %v\nclient:\n%s\nserver:\n%s", n, len(reply), err, clientLog.String(), serverLog.String())
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reply, payload) {
		t.Fatal("mode-switch echo changed payload bytes")
	}
}
