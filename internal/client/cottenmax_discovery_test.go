package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"cottendns-go/internal/config"
)

func discoveryTestClient(t *testing.T) *Client {
	t.Helper()
	return &Client{cfg: config.ClientConfig{
		Domains: []string{"Tunnel.Example."}, EncryptionKey: "test-existing-server-key",
		ConfigDir: t.TempDir(), ResolverTransport: "udp", ResolverIPMode: "ipv4",
		ResolverDiscoveryCacheFile: "resolver-cache.json", ResolverDiscoveryNetworkID: "test-network",
		ResolverDoTPort: 853, ResolverDoHPort: 443, ResolverDoHPath: "/dns-query",
	}}
}

func TestCottenMaxDiscoveryIsOptInAndRetainsPacing(t *testing.T) {
	c := discoveryTestClient(t)
	d := c.cottenMaxDiscovery(nil)
	if d.Enabled || d.Cache != nil {
		t.Fatal("disabled discovery created a cache")
	}
	c.cfg.ResolverDiscoveryEnabled = true
	c.cfg.ResolverDiscoveryCacheFile = ""
	c.cfg.ResolverDiscoveryWant = 4
	c.cfg.ResolverDiscoveryConcurrency = 2
	c.cfg.ResolverDiscoveryPaceMilliseconds = 65
	c.cfg.ResolverDiscoveryCandidates = []string{"192.0.2.1:5353", "[2001:db8::1]:53", "not-a-resolver"}
	d = c.cottenMaxDiscovery([]string{"192.0.2.1:53", "192.0.2.1:5353"})
	if d.Cache != nil || d.Want != 4 || d.Concurrency != 2 || d.Pace != 65*time.Millisecond {
		t.Fatalf("discovery settings not retained: %+v", d)
	}
	if !reflect.DeepEqual(d.Candidates, []string{"192.0.2.1:53", "192.0.2.1:5353"}) {
		t.Fatalf("family/endpoint filtering: %v", d.Candidates)
	}
	if d.AcceptResolver == nil || !d.AcceptResolver("192.0.2.2:853") || d.AcceptResolver("[2001:db8::2]:853") {
		t.Fatal("discovered and bundled candidates must respect the selected family")
	}
	entries, err := os.ReadDir(c.cfg.ConfigDir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("startup wrote files: %v, %v", entries, err)
	}
}

func TestCottenMaxDiscoveryScopeIsolation(t *testing.T) {
	c := discoveryTestClient(t)
	base := c.cottenMaxDiscoveryScope()
	changes := map[string]func(*config.ClientConfig){
		"domain":            func(c *config.ClientConfig) { c.Domains = []string{"other.example"} },
		"credential":        func(c *config.ClientConfig) { c.EncryptionKey += "other" },
		"server pin":        func(c *config.ClientConfig) { c.CottenMaxServerPublicKey = "old-explicit-pin" },
		"transport":         func(c *config.ClientConfig) { c.ResolverTransport = "dot" },
		"family":            func(c *config.ClientConfig) { c.ResolverIPMode = "ipv6" },
		"network label":     func(c *config.ClientConfig) { c.ResolverDiscoveryNetworkID = "other-network" },
		"TLS name":          func(c *config.ClientConfig) { c.ResolverTLSServerName = "dns.example" },
		"TLS pin":           func(c *config.ClientConfig) { c.ResolverTLSPin = "new-pin" },
		"TLS verification":  func(c *config.ClientConfig) { c.ResolverTLSInsecureSkipVerify = true },
		"DoT port":          func(c *config.ClientConfig) { c.ResolverDoTPort = 8853 },
		"DoQ port":          func(c *config.ClientConfig) { c.ResolverDoQPort = 8853 },
		"HTTP3 fallback":    func(c *config.ClientConfig) { c.ResolverHTTP3Fallback = !c.ResolverHTTP3Fallback },
		"encrypted padding": func(c *config.ClientConfig) { c.DNSPaddingBlockSize = 128 },
		"DoH path":          func(c *config.ClientConfig) { c.ResolverDoHPath = "/other" },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			copy := &Client{cfg: c.cfg}
			change(&copy.cfg)
			if copy.cottenMaxDiscoveryScope() == base {
				t.Fatal("cache scope crossed profile boundary")
			}
		})
	}
	c.cfg.Domains = []string{"tunnel.example"}
	if c.cottenMaxDiscoveryScope() != base {
		t.Fatal("equivalent domain spelling changed scope")
	}
}

func TestCottenMaxDiscoveryCachesAreIsolatedPerFailoverDomain(t *testing.T) {
	c := discoveryTestClient(t)
	c.cfg.ResolverDiscoveryEnabled = true
	a := c.cottenMaxDiscoveryForDomain("a.example", nil).Cache.(*cottenMaxResolverCache)
	b := c.cottenMaxDiscoveryForDomain("b.example", nil).Cache.(*cottenMaxResolverCache)
	if a.path == b.path || a.scope == b.scope {
		t.Fatal("different failover domains share a cache")
	}
	a.Store([]string{"192.0.2.1:53"})
	b.Store([]string{"192.0.2.2:53"})
	if got := a.Load(); !reflect.DeepEqual(got, []string{"192.0.2.1:53"}) {
		t.Fatalf("first domain cache=%v", got)
	}
	if got := b.Load(); !reflect.DeepEqual(got, []string{"192.0.2.2:53"}) {
		t.Fatalf("second domain cache=%v", got)
	}
	if c.cfg.Domains[0] != "Tunnel.Example." || c.cfg.ResolverDiscoveryCacheFile != "resolver-cache.json" {
		t.Fatal("per-domain cache mutated the configured profile")
	}
}

func TestCottenMaxDiscoveryCacheRoundTripAndExpiry(t *testing.T) {
	c := discoveryTestClient(t)
	c.cfg.ResolverDiscoveryEnabled = true
	cache := c.cottenMaxDiscovery(nil).Cache.(*cottenMaxResolverCache)
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	cache.now = func() time.Time { return now }
	cache.Store([]string{"192.0.2.1:53", "192.0.2.1:5353", "192.0.2.1", "[2001:db8::1]:53", "bad"})
	want := []string{"192.0.2.1:53", "192.0.2.1:5353"}
	if got := cache.Load(); !reflect.DeepEqual(got, want) {
		t.Fatalf("cache=%v, want=%v", got, want)
	}
	raw, err := os.ReadFile(cache.path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(c.cfg.EncryptionKey)) || bytes.Contains(raw, []byte(c.cfg.ResolverDiscoveryNetworkID)) || bytes.Contains(raw, []byte(c.cfg.Domains[0])) {
		t.Fatal("cache exposes raw profile identifiers")
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(cache.path)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatalf("cache permissions = %v, error %v", info, err)
		}
	}
	// Replacements must work on Windows as well as Unix.
	cache.Store([]string{"192.0.2.2:853"})
	if got := cache.Load(); !reflect.DeepEqual(got, []string{"192.0.2.2:853"}) {
		t.Fatalf("cache replacement=%v", got)
	}
	now = now.Add(cottenMaxDiscoveryCacheTTL)
	if got := cache.Load(); len(got) != 0 {
		t.Fatal("expired cache accepted")
	}
	now = now.Add(-cottenMaxDiscoveryCacheTTL - 6*time.Minute)
	if got := cache.Load(); len(got) != 0 {
		t.Fatal("future-dated cache accepted")
	}
	files, err := filepath.Glob(filepath.Join(filepath.Dir(cache.path), ".cottenmax-resolvers-*"))
	if err != nil || len(files) != 0 {
		t.Fatalf("temporary cache files leaked: %v %v", files, err)
	}
}

func TestCottenMaxDiscoveryCacheRejectsInvalidScopeAndData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.json")
	now := time.Now()
	cache := &cottenMaxResolverCache{path: path, scope: "test-scope", family: "ipv4", now: func() time.Time { return now }}
	good := cottenMaxResolverCacheFile{Version: cottenMaxDiscoveryCacheVersion, Scope: cache.scope, StoredAt: now, Resolvers: []string{"192.0.2.1:53"}}
	tests := map[string]func() []byte{
		"malformed":     func() []byte { return []byte("{") },
		"oversized":     func() []byte { return []byte(strings.Repeat(" ", cottenMaxDiscoveryCacheBytes+1)) },
		"wrong scope":   func() []byte { v := good; v.Scope = "other"; b, _ := json.Marshal(v); return b },
		"wrong version": func() []byte { v := good; v.Version++; b, _ := json.Marshal(v); return b },
		"missing time":  func() []byte { v := good; v.StoredAt = time.Time{}; b, _ := json.Marshal(v); return b },
		"too many entries": func() []byte {
			v := good
			v.Resolvers = make([]string, cottenMaxDiscoveryCacheEntries+1)
			b, _ := json.Marshal(v)
			return b
		},
	}
	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(path, data(), 0600); err != nil {
				t.Fatal(err)
			}
			if got := cache.Load(); len(got) != 0 {
				t.Fatalf("invalid cache accepted: %v", got)
			}
		})
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if got := cache.Load(); len(got) != 0 {
		t.Fatal("directory treated as cache")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(filepath.Dir(path), "real-cache")
	raw, _ := json.Marshal(good)
	if err := os.WriteFile(target, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err == nil {
		if got := cache.Load(); len(got) != 0 {
			t.Fatal("symlink treated as cache")
		}
	}
}

func TestCottenMaxDiscoveryCacheBoundsAndConcurrentReaders(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.json")
	cache := &cottenMaxResolverCache{path: path, scope: "test-scope", family: "ipv4"}
	input := make([]string, cottenMaxDiscoveryCacheEntries*2)
	for i := range input {
		input[i] = fmt.Sprintf("192.0.2.1:%d", i+1)
	}
	cache.Store(input)
	if got := cache.Load(); len(got) != cottenMaxDiscoveryCacheEntries {
		t.Fatalf("cache is not bounded: %d", len(got))
	}
	cache.Store([]string{"192.0.2.2:53"})
	reader := &cottenMaxResolverCache{path: path, scope: cache.scope, family: cache.family}
	var wg sync.WaitGroup
	for n := 0; n < 4; n++ {
		wg.Add(1)
		go func(write bool) {
			defer wg.Done()
			for i := 0; i < 12; i++ {
				if write {
					cache.Store([]string{"192.0.2.2:53"})
				}
				if got := reader.Load(); !reflect.DeepEqual(got, []string{"192.0.2.2:53"}) {
					t.Errorf("concurrent cache=%v", got)
					return
				}
			}
		}(n%2 == 0)
	}
	wg.Wait()
}

func TestCottenMaxDiscoveryCacheStoreDoesNotFollowSymlink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.json")
	target := filepath.Join(dir, "unrelated-user-file")
	sentinel := []byte("unrelated file must stay unchanged")
	if err := os.WriteFile(target, sentinel, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	cache := &cottenMaxResolverCache{path: path, scope: "test-scope", family: "ipv4"}
	cache.Store([]string{"192.0.2.1:53"})
	raw, err := os.ReadFile(target)
	if err != nil || !bytes.Equal(raw, sentinel) {
		t.Fatalf("cache write followed symlink: %q %v", raw, err)
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		t.Fatalf("cache did not replace symlink with regular file: %v %v", info, err)
	}
	if got := cache.Load(); !reflect.DeepEqual(got, []string{"192.0.2.1:53"}) {
		t.Fatalf("replacement cache=%v", got)
	}
}

func TestResolverPortDiversitySurvivesConnectionMap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resolvers.txt")
	if err := os.WriteFile(path, []byte("192.0.2.1:53\n192.0.2.1:5353\n192.0.2.1:53\n"), 0600); err != nil {
		t.Fatal(err)
	}
	resolvers, _, err := config.LoadClientResolvers(path)
	if err != nil {
		t.Fatal(err)
	}
	c := &Client{
		cfg:      config.ClientConfig{Domains: []string{"t.example"}, Resolvers: resolvers},
		balancer: NewBalancer(BalancingRoundRobin), resolverAddrCache: make(map[string]*net.UDPAddr),
	}
	if err := c.BuildConnectionMap(); err != nil {
		t.Fatal(err)
	}
	if len(c.connections) != 2 || c.connections[0].Key == c.connections[1].Key {
		t.Fatalf("resolver ports merged at runtime: %#v", c.connections)
	}
}
