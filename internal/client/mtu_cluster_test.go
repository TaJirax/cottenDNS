// ==============================================================================
// CottenpickDNS
// Author: tajirax
// Github: https://github.com/TaJirax/cottenpickDNS
// Year: 2026
// ==============================================================================

package client

import (
	"context"
	"errors"
	"testing"
	"time"

	"cottenpickdns-go/internal/config"
)

func TestClusterConnectionsByMTU_GapBanding(t *testing.T) {
	conns := []Connection{
		{ResolverLabel: "a", IsValid: true, DownloadMTUBytes: 4000, UploadMTUBytes: 200},
		{ResolverLabel: "b", IsValid: true, DownloadMTUBytes: 3900, UploadMTUBytes: 180},
		{ResolverLabel: "c", IsValid: true, DownloadMTUBytes: 1000, UploadMTUBytes: 120},
		{ResolverLabel: "d", IsValid: true, DownloadMTUBytes: 950, UploadMTUBytes: 110},
		{ResolverLabel: "invalid", IsValid: false, DownloadMTUBytes: 4000},
		{ResolverLabel: "zero", IsValid: true, DownloadMTUBytes: 0},
	}

	groups := clusterConnectionsByMTU(conns, 0.25)
	if len(groups) != 2 {
		t.Fatalf("expected 2 groups, got %d: %+v", len(groups), groups)
	}

	// Largest-capacity group first.
	if groups[0].DownloadMTU != 3900 {
		t.Errorf("group[0] download MTU = %d, want 3900 (min of the high band)", groups[0].DownloadMTU)
	}
	if groups[0].UploadMTU != 180 {
		t.Errorf("group[0] upload MTU = %d, want 180 (min of the high band)", groups[0].UploadMTU)
	}
	if len(groups[0].Members) != 2 {
		t.Errorf("group[0] members = %d, want 2", len(groups[0].Members))
	}
	if groups[1].DownloadMTU != 950 {
		t.Errorf("group[1] download MTU = %d, want 950", groups[1].DownloadMTU)
	}
	if len(groups[1].Members) != 2 {
		t.Errorf("group[1] members = %d, want 2", len(groups[1].Members))
	}
}

func TestClusterConnectionsByMTU_SingleGroupWhenClose(t *testing.T) {
	conns := []Connection{
		{IsValid: true, DownloadMTUBytes: 4000, UploadMTUBytes: 200},
		{IsValid: true, DownloadMTUBytes: 3950, UploadMTUBytes: 190},
		{IsValid: true, DownloadMTUBytes: 3800, UploadMTUBytes: 195},
	}
	groups := clusterConnectionsByMTU(conns, 0.25)
	if len(groups) != 1 {
		t.Fatalf("expected 1 group for closely-spaced MTUs, got %d", len(groups))
	}
	if groups[0].DownloadMTU != 3800 {
		t.Errorf("group download MTU = %d, want 3800 (group min)", groups[0].DownloadMTU)
	}
}

func TestClusterConnectionsByMTU_Empty(t *testing.T) {
	if g := clusterConnectionsByMTU(nil, 0.25); g != nil {
		t.Fatalf("expected nil for no connections, got %+v", g)
	}
	conns := []Connection{{IsValid: false, DownloadMTUBytes: 4000}}
	if g := clusterConnectionsByMTU(conns, 0.25); g != nil {
		t.Fatalf("expected nil when no valid connections, got %+v", g)
	}
}

func TestSelectMTUOperatingPoint_DropsSlowOutliers(t *testing.T) {
	// 40 fast resolvers (4000) + 10 slow (1000). score(4000)=160000 beats
	// score(1000)=50000, so the optimizer runs at 4000 and the 10 slow ones are
	// excluded from the pool.
	conns := make([]Connection, 0, 50)
	for i := 0; i < 40; i++ {
		conns = append(conns, Connection{IsValid: true, UploadMTUBytes: 200, DownloadMTUBytes: 4000})
	}
	for i := 0; i < 10; i++ {
		conns = append(conns, Connection{IsValid: true, UploadMTUBytes: 120, DownloadMTUBytes: 1000})
	}

	u, d, pool := selectMTUOperatingPoint(conns)
	if d != 4000 {
		t.Errorf("download operating MTU = %d, want 4000", d)
	}
	if u != 200 {
		t.Errorf("upload operating MTU = %d, want 200 (min of the fast pool)", u)
	}
	if pool != 40 {
		t.Errorf("pool size = %d, want 40", pool)
	}
}

func TestSelectMTUOperatingPoint_KeepsCrowdOverOutlier(t *testing.T) {
	// 1 very-fast resolver (8000) + 50 at 1000. score(8000)=8000 loses to
	// score(1000)=51000, so the crowd wins and nobody is dropped.
	conns := make([]Connection, 0, 51)
	conns = append(conns, Connection{IsValid: true, UploadMTUBytes: 300, DownloadMTUBytes: 8000})
	for i := 0; i < 50; i++ {
		conns = append(conns, Connection{IsValid: true, UploadMTUBytes: 120, DownloadMTUBytes: 1000})
	}

	_, d, pool := selectMTUOperatingPoint(conns)
	if d != 1000 {
		t.Errorf("download operating MTU = %d, want 1000 (crowd)", d)
	}
	if pool != 51 {
		t.Errorf("pool size = %d, want 51 (everyone)", pool)
	}
}

func TestSelectMTUOperatingPoint_IgnoresInvalidAndZero(t *testing.T) {
	conns := []Connection{
		{IsValid: false, UploadMTUBytes: 200, DownloadMTUBytes: 9000},
		{IsValid: true, UploadMTUBytes: 0, DownloadMTUBytes: 4000},
		{IsValid: true, UploadMTUBytes: 150, DownloadMTUBytes: 2000},
	}
	u, d, pool := selectMTUOperatingPoint(conns)
	if d != 2000 || u != 150 || pool != 1 {
		t.Errorf("got u=%d d=%d pool=%d, want u=150 d=2000 pool=1", u, d, pool)
	}
}

func TestRebuildValidIndices_PrefersPrimaryKeepsBackup(t *testing.T) {
	// Primaries present -> only primaries are selectable.
	conns := []Connection{
		{Key: "p1", IsValid: true},
		{Key: "b1", IsValid: true, Backup: true},
		{Key: "p2", IsValid: true},
		{Key: "dead", IsValid: false},
	}
	idx := rebuildValidIndices(conns)
	if len(idx) != 2 {
		t.Fatalf("expected 2 primary indices, got %d (%v)", len(idx), idx)
	}
	for _, i := range idx {
		if conns[i].Backup || !conns[i].IsValid {
			t.Errorf("selected non-primary connection %q", conns[i].Key)
		}
	}

	// No primaries -> backups become selectable (failover).
	conns2 := []Connection{
		{Key: "b1", IsValid: true, Backup: true},
		{Key: "b2", IsValid: true, Backup: true},
		{Key: "dead", IsValid: false},
	}
	idx2 := rebuildValidIndices(conns2)
	if len(idx2) != 2 {
		t.Fatalf("expected 2 backup indices on failover, got %d", len(idx2))
	}
}

func TestReclassifyBackups_PromotesSurvivorsAtLowerMTU(t *testing.T) {
	// One fast resolver (4000) + two slow (1000). Initially the fast one is the
	// sole primary and the slow ones are backups.
	conns := []*Connection{
		{Key: "fast", IsValid: true, UploadMTUBytes: 200, DownloadMTUBytes: 4000},
		{Key: "slow1", IsValid: true, Backup: true, UploadMTUBytes: 120, DownloadMTUBytes: 1000},
		{Key: "slow2", IsValid: true, Backup: true, UploadMTUBytes: 120, DownloadMTUBytes: 1000},
	}
	b := NewBalancer(BalancingRoundRobin)
	b.SetConnections(conns)
	if got := b.ValidCount(); got != 1 {
		t.Fatalf("initial active pool = %d, want 1 (only the fast primary)", got)
	}

	// The fast resolver dies; re-derive over survivors (the two slow ones).
	b.SetConnectionValidity("fast", false)
	all := b.AllValidConnectionsIncludingBackup()
	u, d, n := selectMTUOperatingPoint(all)
	if d != 1000 || n != 2 {
		t.Fatalf("operating point over survivors = (u=%d d=%d n=%d), want d=1000 n=2", u, d, n)
	}
	b.ReclassifyBackups(func(cc Connection) bool {
		return cc.DownloadMTUBytes < d || cc.UploadMTUBytes < u
	})

	if got := b.ValidCount(); got != 2 {
		t.Fatalf("after promotion active pool = %d, want 2 (both slow resolvers)", got)
	}
}

func TestEvaluateMTUCandidate_LossAware(t *testing.T) {
	// 4 samples, accept threshold 25% loss => at most 1 of 4 may fail.
	c := &Client{cfg: config.ClientConfig{MTUProbeSamples: 4, MTUMaxLoss: 0.25}}

	// Fail exactly 1 of 4 -> loss 25% -> accepted.
	calls := 0
	ok, _, loss := c.evaluateMTUCandidate(context.Background(), 200, func(int, bool) (bool, time.Duration, error) {
		calls++
		return calls != 2, time.Millisecond, nil // 2nd probe fails
	})
	if !ok {
		t.Errorf("expected accept at 25%% loss with threshold 25%%, got reject (loss=%.2f)", loss)
	}
	if loss != 0.25 {
		t.Errorf("loss = %.2f, want 0.25", loss)
	}

	// Fail 2 of 4 -> loss 50% -> rejected.
	calls = 0
	ok, _, loss = c.evaluateMTUCandidate(context.Background(), 200, func(int, bool) (bool, time.Duration, error) {
		calls++
		return calls > 2, time.Millisecond, nil // first 2 fail
	})
	if ok {
		t.Errorf("expected reject at 50%% loss, got accept")
	}
	if loss != 0.5 {
		t.Errorf("loss = %.2f, want 0.5", loss)
	}
}

func TestEvaluateMTUCandidate_LegacyRetry(t *testing.T) {
	// Samples<=1 keeps legacy behavior: accept if any of mtuTestRetries succeed.
	c := &Client{cfg: config.ClientConfig{MTUProbeSamples: 1}, mtuTestRetries: 3}

	calls := 0
	ok, _, loss := c.evaluateMTUCandidate(context.Background(), 200, func(_ int, isRetry bool) (bool, time.Duration, error) {
		calls++
		if calls < 3 {
			return false, 0, errors.New("transient")
		}
		return true, time.Millisecond, nil // 3rd attempt succeeds
	})
	if !ok {
		t.Errorf("expected legacy accept after retries, got reject")
	}
	if loss != 0 {
		t.Errorf("legacy loss = %.2f, want 0 on success", loss)
	}
	if calls != 3 {
		t.Errorf("expected 3 attempts, got %d", calls)
	}
}
