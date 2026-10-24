//go:build e2e

// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================
// encryption_matrix_test.go — every DATA_ENCRYPTION_METHOD pairing through a
// realistic resolver (auto-detect on and off, base64 replies), and this tree's
// client and server against earlier releases, from before AES-GCM defaults and
// auto-detect up to after encrypted downstream replies. Opt-in like the
// resolver matrix:
//
//	COTTEN_RESOLVER_MATRIX=1 go test -tags e2e -run EncryptionMatrix -parallel 8 -timeout 90m ./test/e2e/
// ==============================================================================

package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
)

var (
	releaseMu   sync.Mutex
	releaseBins = map[string]tunnelBins{}
)

// releaseBinaries builds client and server at commit from a detached worktree,
// once per test process.
func releaseBinaries(t *testing.T, commit string) tunnelBins {
	t.Helper()
	releaseMu.Lock()
	defer releaseMu.Unlock()
	if bins, ok := releaseBins[commit]; ok {
		return bins
	}
	root := repoRoot(t)
	dir, err := os.MkdirTemp("", "cottendns-e2e-"+commit)
	if err != nil {
		t.Fatalf("release dir: %v", err)
	}
	src := filepath.Join(dir, "src")
	if out, err := exec.Command("git", "-C", root, "worktree", "add", "--detach", src, commit).CombinedOutput(); err != nil {
		t.Fatalf("worktree %s: %v\n%s", commit, err, out)
	}
	defer exec.Command("git", "-C", root, "worktree", "remove", "--force", src).Run()
	bins := tunnelBins{server: filepath.Join(dir, binName("server")), client: filepath.Join(dir, binName("client"))}
	buildBinary(t, src, "./cmd/server", bins.server)
	buildBinary(t, src, "./cmd/client", bins.client)
	for _, name := range []string{"server_config.toml.simple", "client_config.toml.simple"} {
		if data, err := os.ReadFile(filepath.Join(src, name)); err == nil {
			_ = os.WriteFile(filepath.Join(dir, name), data, 0644)
		}
	}
	releaseBins[commit] = bins
	return bins
}

func TestEncryptionMatrixMethods(t *testing.T) {
	requireMatrix(t)
	const qtypes = `["TXT", "CNAME", "A", "AAAA"]`
	for s := 0; s <= 5; s++ {
		for c := 0; c <= 5; c++ {
			for _, auto := range []bool{true, false} {
				if !auto && s != c && c != (s+1)%6 {
					continue // auto-detect off: same method, plus one mismatch per server method
				}
				serverExtra := fmt.Sprintf("ENCRYPTION_AUTO_DETECT = %v", auto)
				t.Run(fmt.Sprintf("server=%d/client=%d/auto=%v", s, c, auto), func(t *testing.T) {
					t.Parallel()
					runTunnelEchoVia(t, s, c, serverExtra, qtypes, "", "127.0.0.1", tunnelBins{}, viaSims(realistic))
				})
			}
		}
		t.Run(fmt.Sprintf("server=%d/client=%d/base64", s, s), func(t *testing.T) {
			t.Parallel()
			runTunnelEchoVia(t, s, s, "", qtypes, "BASE_ENCODE_DATA = true", "127.0.0.1", tunnelBins{}, viaSims(realistic))
		})
	}
}

// Releases users may still run, oldest first: a360409 (Jul 23, AES-GCM default
// and auto-detect), b8b8c7e, fdf09a6, c0fb100, 530ffbf (last before encrypted
// downstream replies), cdf084f (adds them), f4a2277 (Android 1.6.4).
var compatReleases = []string{"a360409", "b8b8c7e", "fdf09a6", "c0fb100", "530ffbf", "cdf084f", "f4a2277"}

func TestEncryptionMatrixReleases(t *testing.T) {
	requireMatrix(t)
	type pair struct{ server, client int }
	pairs := []pair{{0, 0}, {1, 1}, {2, 2}, {3, 3}, {4, 4}, {5, 5}, {3, 1} /* templates: server 3, Android/client 1 */}
	for _, release := range compatReleases {
		for _, dir := range []string{"new-client+old-server", "old-client+new-server", "old-client+old-server"} {
			for _, p := range pairs {
				for _, cs := range []struct {
					name, qtypes string
					sim          resolverSim
				}{
					{"clean-txt", `["TXT"]`, resolverSim{}},
					{"realistic-txt", `["TXT"]`, realistic},
					{"realistic-survival", `["TXT", "CNAME", "HTTPS", "A"]`, realistic},
				} {
					qtypes, sim := cs.qtypes, cs.sim
					t.Run(fmt.Sprintf("%s/%s/server=%d,client=%d/%s", release, dir, p.server, p.client, cs.name), func(t *testing.T) {
						t.Parallel()
						old := releaseBinaries(t, release)
						bins := tunnelBins{server: old.server}
						switch dir {
						case "old-client+new-server":
							bins = tunnelBins{client: old.client}
						case "old-client+old-server": // control: how that release behaved on its own
							bins = old
						}
						runTunnelEchoVia(t, p.server, p.client, "", qtypes, "", "127.0.0.1", bins, viaSims(sim))
					})
				}
			}
		}
	}
}
