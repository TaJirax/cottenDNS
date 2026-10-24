//go:build e2e

// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================
// deployment_test.go — the path users actually run: shipped config templates on
// both sides, the server configured the way CottenRouter configures it, and the
// real CottenRouter (built from a sibling checkout, COTTEN_ROUTER_DIR overrides)
// between the resolver and the server. Opt-in like the matrices:
//
//	COTTEN_RESOLVER_MATRIX=1 go test -tags e2e -run Deployment -parallel 8 -timeout 60m ./test/e2e/
// ==============================================================================

package e2e

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// routerServerEdits mirrors CottenRouter's configure() for a fresh cottendns
// install (DOMAIN, UDP_HOST and UDP_PORT are set by the harness).
const routerServerEdits = `
MAX_PACKET_SIZE = 16384
MAX_DNS_RESPONSE_BYTES = 16384
TCP_LISTENER_ENABLED = true
TCP_IPV6_HOST = "::1"
UDP_IPV6_HOST = "::1"
DOT_LISTENER_ENABLED = false
DOH_LISTENER_ENABLED = false`

func shippedTemplate(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repoRoot(t), name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(data)
}

func routerBinary(t *testing.T) string {
	t.Helper()
	dir := os.Getenv("COTTEN_ROUTER_DIR")
	if dir == "" {
		dir = filepath.Join(repoRoot(t), "..", "CottenRouter")
	}
	if _, err := os.Stat(filepath.Join(dir, "cmd", "cottenrouter")); err != nil {
		t.Skipf("CottenRouter checkout not found at %s (set COTTEN_ROUTER_DIR)", dir)
	}
	return cachedBinary(t, dir, "./cmd/cottenrouter", "cottenrouter")
}

// startRouter runs CottenRouter on loopback with one route, a.io -> backend,
// using the example config's default limits.
func startRouter(t *testing.T, backend *net.UDPAddr) *net.UDPAddr {
	t.Helper()
	bin := routerBinary(t)
	port := freeUDPPortForHost(t, "127.0.0.1")
	cfg := filepath.Join(t.TempDir(), "cottenrouter.json")
	listen := fmt.Sprintf("127.0.0.1:%d", port)
	if err := os.WriteFile(cfg, []byte(fmt.Sprintf(`{
  "listen_udp": %q,
  "listen_tcp": %q,
  "admin_listen": "127.0.0.1:%d",
  "query_timeout_ms": 10000,
  "max_packet_size": 16384,
  "max_tcp_message_size": 16384,
  "max_pending_per_backend": 8192,
  "max_tcp_connections": 256,
  "unmatched_action": "drop",
  "routes": [{"name": "cottendns", "domains": ["a.io"], "backend": %q, "tcp_backend": %q}]
}`, listen, listen, freeTCPPort(t), backend.String(), backend.String())), 0644); err != nil {
		t.Fatalf("write router cfg: %v", err)
	}
	log := &safeBuf{}
	cmd := exec.Command(bin, "serve", "-config", cfg)
	cmd.Stdout, cmd.Stderr = log, log
	if err := cmd.Start(); err != nil {
		t.Fatalf("start router: %v", err)
	}
	exited := make(chan struct{})
	go func() { _ = cmd.Wait(); close(exited) }()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		if t.Failed() {
			t.Logf("--- router log ---\n%s", log.String())
		}
	})
	select { // no readiness line: it binds at once or exits
	case <-exited:
		t.Fatalf("router exited:\n%s", log.String())
	case <-time.After(500 * time.Millisecond):
	}
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}
}

func viaRouter(sims ...resolverSim) func(t *testing.T, server *net.UDPAddr) []string {
	return func(t *testing.T, server *net.UDPAddr) []string {
		return viaSims(sims...)(t, startRouter(t, server))
	}
}

// Shipped templates with the router in front, for every Android preset and
// encryption method, behind clean and realistic resolvers; and without the
// router, to tell router effects from template effects.
func TestDeployment(t *testing.T) {
	requireMatrix(t)
	bins := tunnelBins{
		serverBase: shippedTemplate(t, "server_config.toml.simple") + routerServerEdits,
		clientBase: shippedTemplate(t, "client_config.toml.simple"),
	}
	presets := map[string]string{
		"default-txt": `["TXT"]`,
		"speed":       `["TXT", "HTTPS"]`,
		"survival":    `["TXT", "CNAME", "HTTPS", "A"]`,
		"txt-aaaa":    `["TXT", "AAAA"]`,
		"all":         `["TXT", "CNAME", "NULL", "HTTPS", "AAAA"]`,
	}
	for _, path := range []string{"router", "direct"} {
		for _, simName := range []string{"clean", "realistic"} {
			sim := resolverSim{}
			if simName == "realistic" {
				sim = realistic
			}
			resolvers := viaSims(sim)
			if path == "router" {
				resolvers = viaRouter(sim)
			}
			for _, preset := range sortedKeys(presets) {
				qtypes := presets[preset]
				for _, client := range []int{1, 3} { // Android default XOR, AES-128-GCM
					t.Run(fmt.Sprintf("%s/%s/%s/client=%d", path, simName, preset, client), func(t *testing.T) {
						t.Parallel()
						runTunnelEchoVia(t, 3, client, "", qtypes, "", "127.0.0.1", bins, resolvers)
					})
				}
			}
		}
	}
}

// Every core commit since the last release before encrypted downstream
// replies, each as users run it: its own client, server and shipped templates,
// the server configured like CottenRouter does, the router in front.
var bisectCommits = []string{"530ffbf", "cdf084f", "276f7a1", "8538df8", "1753ef3", "7b4f1e1", "48d6c81"}

func TestDeploymentBisect(t *testing.T) {
	requireMatrix(t)
	listenTimeout = 90 * time.Second
	drop := resolverSim{nx: "drop"}
	scenarios := []struct {
		name string
		sims []resolverSim
	}{
		{"clean", []resolverSim{{}}},
		{"realistic", []resolverSim{realistic}},
		{"rebind+realism", []resolverSim{func() resolverSim { r := realistic; r.filter = rebindRanges; return r }()}},
		{"loss10", []resolverSim{{loss: 0.10}}},
		{"nx-drop4+clean1", []resolverSim{drop, drop, drop, drop, {}}},
		{"nx-race", []resolverSim{{nx: "race"}}},
	}
	presets := []struct{ name, qtypes string }{
		{"default-txt", `["TXT"]`},
		{"survival", `["TXT", "CNAME", "HTTPS", "A"]`},
		{"all", `["TXT", "CNAME", "NULL", "HTTPS", "AAAA"]`},
	}
	for _, commit := range bisectCommits {
		for _, sc := range scenarios {
			for _, preset := range presets {
				sims, qtypes := sc.sims, preset.qtypes
				t.Run(commit+"/"+sc.name+"/"+preset.name, func(t *testing.T) {
					t.Parallel()
					old := releaseBinaries(t, commit)
					dir := filepath.Dir(old.server)
					bins := old
					bins.serverBase = readOr(t, filepath.Join(dir, "server_config.toml.simple")) + routerServerEdits
					bins.clientBase = readOr(t, filepath.Join(dir, "client_config.toml.simple"))
					start := time.Now()
					runTunnelEchoVia(t, 3, 1, "", qtypes, "", "127.0.0.1", bins, viaRouter(sims...))
					t.Logf("connected and echoed in %s", time.Since(start).Round(time.Second))
				})
			}
		}
	}
}

func readOr(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

// androidPresetLines is what WhiteDNS Android 1.6.5 (CottenDnsSettingsRenderer)
// writes for each preset, with the screenshot's background scan of 55.
var androidPresetLines = map[string]struct{ qtypes, lines string }{
	"default": {`["TXT"]`, androidCommon + `CONFIG_PRESET = "default"
LEGACY_SESSION_ID = false
RESOLVER_TRANSPORT = "auto"
QNAME_LABEL_LENGTH = 63
` + androidNative("0.95", 4096, 1, "0.0")},
	"speed": {`["TXT", "HTTPS"]`, androidCommon + `CONFIG_PRESET = "speed"
LEGACY_SESSION_ID = false
RESOLVER_TRANSPORT = "auto"
QNAME_LABEL_LENGTH = 63
` + androidNative("0.95", 4096, 1, "0.0")},
	"survival": {`["TXT", "CNAME", "HTTPS", "A"]`, androidCommon + `CONFIG_PRESET = "survival"
LEGACY_SESSION_ID = false
RESOLVER_TRANSPORT = "auto"
QNAME_LABEL_LENGTH = 42
` + androidNative("0.97", 1232, 5, "0.5")},
	"master-storm-compatible": {`["TXT"]`, androidCommon + `CONFIG_PRESET = "default"
LEGACY_SESSION_ID = true
RESOLVER_TRANSPORT = "udp"
QNAME_LABEL_LENGTH = 63
ADAPTIVE_DUPLICATION = false
DUPLICATION_PREFER_DISTINCT_DOMAINS = false
DNS_EDNS_COOKIE = false
MTU_ADAPTIVE_GROUPING = false
MTU_PROBE_SAMPLES = 1
MTU_MAX_LOSS = 0.0
`},
}

const androidCommon = `TERMINAL_UI = "plain"
RESOLVER_IP_MODE = "auto"
QUERY_RATE_LIMIT_PER_SECOND = 0
QUERY_RATE_LIMIT_PER_RESOLVER_PER_SECOND = 0
QUERY_RATE_LIMIT_PER_DOMAIN_PER_SECOND = 0
QUERY_TIMING_JITTER = 0.0
FAST_CONNECT = true
MTU_BACKGROUND_PARALLELISM = 55
RESOLVER_RATE_LIMIT_ENABLED = true
DNS_RANDOMIZE_QUERY_ID = true
DNS_QNAME_CASE_RANDOMIZATION = false
RESOLVER_IGNORE_INJECTED_NXDOMAIN = true
`

func androidNative(target string, edns, samples int, maxLoss string) string {
	return fmt.Sprintf(`ADAPTIVE_DUPLICATION = true
DUPLICATION_PREFER_DISTINCT_DOMAINS = true
ADAPTIVE_DUPLICATION_TARGET_DELIVERY = %s
DNS_EDNS_COOKIE = true
EDNS_UDP_SIZE = %d
MTU_PROBE_SAMPLES = %d
MTU_MAX_LOSS = %s
MTU_ADAPTIVE_GROUPING = true
MTU_GROUP_GAP_RATIO = 0.25
`, target, edns, samples, maxLoss)
}

// The 1.6.5 engine with each Android preset (AES-128-GCM, as in the user's
// profile) against servers from before and after encrypted downstream
// replies, through CottenRouter, each server on its own shipped template.
func TestDeploymentAndroidPresetsVsServers(t *testing.T) {
	requireMatrix(t)
	listenTimeout = 90 * time.Second
	clientBase := shippedTemplate(t, "client_config.toml.simple")
	for _, server := range []string{"c0fb100", "530ffbf", "cdf084f", "f4a2277", "1f3cc52"} {
		for _, preset := range sortedKeys(androidPresetLines) {
			for _, simName := range []string{"clean", "realistic"} {
				sim := resolverSim{}
				if simName == "realistic" {
					sim = realistic
				}
				p := androidPresetLines[preset]
				t.Run(server+"/"+preset+"/"+simName, func(t *testing.T) {
					t.Parallel()
					old := releaseBinaries(t, server)
					bins := tunnelBins{server: old.server, clientBase: clientBase,
						serverBase: readOr(t, filepath.Join(filepath.Dir(old.server), "server_config.toml.simple")) + routerServerEdits}
					runTunnelEchoVia(t, 3, 3, "", p.qtypes, p.lines, "127.0.0.1", bins, viaRouter(sim))
				})
			}
		}
	}
}
