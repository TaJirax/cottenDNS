package client

import (
	"testing"
	"time"

	"cottendns-go/internal/config"
	Enums "cottendns-go/internal/enums"
)

func TestPathControllerSuppressesOnlyAdaptiveCopiesDuringCongestion(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{
		UploadPacketDuplicationCount:        1,
		AdaptiveDuplication:                 true,
		AdaptiveDuplicationTargetDelivery:   0.95,
		DownloadPacketDuplicationCount:      1,
		UploadSetupPacketDuplicationCount:   1,
		DownloadSetupPacketDuplicationCount: 1,
	}, "a")
	c.uploadLoss.lastPerMille.Store(500)
	c.txChannel = make(chan rawOutboundTask, 4)
	uncongested := c.runtimePathControlDecision(Enums.PACKET_STREAM_DATA)
	if uncongested.copies != 5 {
		t.Fatalf("uncongested adaptive copies=%d, want 5", uncongested.copies)
	}
	c.txChannel <- rawOutboundTask{}

	plan := c.runtimePathControlDecision(Enums.PACKET_STREAM_DATA)
	if !plan.congested {
		t.Fatal("queue pressure was not detected")
	}
	if plan.copies != 1 {
		t.Fatalf("congested adaptive copies=%d, want configured base 1", plan.copies)
	}
	t.Logf("congestion controller reduced adaptive copies %d -> %d (%.0f%% fewer)",
		uncongested.copies, plan.copies,
		100*(1-float64(plan.copies)/float64(uncongested.copies)))

	c.cfg.UploadPacketDuplicationCount = 3
	plan = c.runtimePathControlDecision(Enums.PACKET_STREAM_DATA)
	if plan.copies != 3 {
		t.Fatalf("explicit base was reduced during congestion: copies=%d, want 3", plan.copies)
	}
}

func TestLegacyPathControllerModePreservesAdaptiveBehavior(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{
		PathControllerMode:                  "legacy",
		ComparablePathStriping:              true,
		UploadPacketDuplicationCount:        1,
		AdaptiveDuplication:                 true,
		AdaptiveDuplicationTargetDelivery:   0.95,
		DownloadPacketDuplicationCount:      1,
		UploadSetupPacketDuplicationCount:   1,
		DownloadSetupPacketDuplicationCount: 1,
	}, "a")
	c.uploadLoss.lastPerMille.Store(500)
	c.txChannel = make(chan rawOutboundTask, 4)
	c.txChannel <- rawOutboundTask{}

	plan := c.runtimePathControlDecision(Enums.PACKET_STREAM_DATA)
	if plan.copies != 5 {
		t.Fatalf("legacy adaptive copies=%d, want historical loss-driven 5", plan.copies)
	}
	if plan.allowComparableStrip {
		t.Fatal("legacy mode must bypass comparable-path striping")
	}
}

func TestPathControllerSharesDownloadBudgetWithFEC(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{
		UploadPacketDuplicationCount:        1,
		DownloadPacketDuplicationCount:      7,
		UploadSetupPacketDuplicationCount:   1,
		DownloadSetupPacketDuplicationCount: 8,
	}, "a", "b", "c", "d", "e", "f", "g")
	c.lastFECReceived.Store(c.now().UnixNano())

	plan := c.runtimePathControlDecision(Enums.PACKET_STREAM_DATA_ACK)
	if !plan.fecActive {
		t.Fatal("recent FEC was not included in the shared redundancy decision")
	}
	if plan.copies != 2 {
		t.Fatalf("FEC-coordinated download copies=%d, want 2", plan.copies)
	}
	if plan.allowHealthyExplore {
		t.Fatal("healthy exploration must not stack on active FEC")
	}
}

func TestDirectionalDeliveryFailureDoesNotPoisonOppositeDirection(t *testing.T) {
	c := newAutoTransportPolicyClient()
	c.syncedUploadMTU = 200
	c.syncedDownloadMTU = 1200
	now := time.Now()
	for i := 0; i < 4; i++ {
		c.noteResolverTransportSuccessForPacket(
			"resolver-a",
			transportUDP,
			50*time.Millisecond,
			Enums.PACKET_STREAM_DATA,
			now.Add(time.Duration(i)*time.Millisecond),
		)
	}
	c.resolverTransportMu.Lock()
	before := pathEstimatedGoodputForPacket(
		pathScoreFor(c.resolverTransportStateLocked("resolver-a"), transportUDP),
		Enums.PACKET_STREAM_DATA,
	)
	c.resolverTransportMu.Unlock()
	c.noteResolverTransportFailureForPacket(
		"resolver-a",
		transportUDP,
		Enums.PACKET_STREAM_DATA_ACK,
		now.Add(time.Second),
	)

	c.resolverTransportMu.Lock()
	score := *pathScoreFor(c.resolverTransportStateLocked("resolver-a"), transportUDP)
	c.resolverTransportMu.Unlock()
	if score.uploadRuntimeSamples != 4 || score.uploadRuntimeDelivery != 1 {
		t.Fatalf("upload evidence changed after download failure: samples=%d delivery=%f",
			score.uploadRuntimeSamples, score.uploadRuntimeDelivery)
	}
	if score.downloadRuntimeSamples != 1 || score.downloadRuntimeDelivery >= 1 {
		t.Fatalf("download failure was not isolated: samples=%d delivery=%f",
			score.downloadRuntimeSamples, score.downloadRuntimeDelivery)
	}
	after := pathEstimatedGoodputForPacket(&score, Enums.PACKET_STREAM_DATA)
	if after != before {
		t.Fatalf("download failure changed upload score: before=%f after=%f", before, after)
	}
	t.Logf("unified directional score retained %.0f%% after opposite-direction failure", 100*after/before)
}

func TestLegacyModeRestoresSharedDirectionalPenalty(t *testing.T) {
	c := newAutoTransportPolicyClient()
	c.cfg.PathControllerMode = "legacy"
	c.syncedUploadMTU = 200
	c.syncedDownloadMTU = 1200
	now := time.Now()
	for i := 0; i < 4; i++ {
		c.noteResolverTransportSuccessForPacket(
			"resolver-a",
			transportUDP,
			50*time.Millisecond,
			Enums.PACKET_STREAM_DATA,
			now.Add(time.Duration(i)*time.Millisecond),
		)
	}
	c.resolverTransportMu.Lock()
	before := pathEstimatedGoodputForPacket(
		pathScoreFor(c.resolverTransportStateLocked("resolver-a"), transportUDP),
		Enums.PACKET_STREAM_DATA,
	)
	c.resolverTransportMu.Unlock()
	c.noteResolverTransportFailureForPacket(
		"resolver-a",
		transportUDP,
		Enums.PACKET_STREAM_DATA_ACK,
		now.Add(time.Second),
	)
	c.resolverTransportMu.Lock()
	after := pathEstimatedGoodputForPacket(
		pathScoreFor(c.resolverTransportStateLocked("resolver-a"), transportUDP),
		Enums.PACKET_STREAM_DATA,
	)
	c.resolverTransportMu.Unlock()
	if after >= before {
		t.Fatalf("legacy shared evidence did not penalize upload: before=%f after=%f", before, after)
	}
	t.Logf("legacy shared score retained %.1f%% after opposite-direction failure", 100*after/before)
}

func prepareComparableStripeClient(t *testing.T) *Client {
	t.Helper()
	c := buildTestClientWithResolvers(config.ClientConfig{
		ResolverTransport:                   "auto",
		ComparablePathStriping:              true,
		UploadPacketDuplicationCount:        1,
		DownloadPacketDuplicationCount:      1,
		UploadSetupPacketDuplicationCount:   1,
		DownloadSetupPacketDuplicationCount: 1,
	}, "a", "b")
	now := time.Now()
	for i := range c.connections {
		key := c.connections[i].Key
		rtt := 50*time.Millisecond + time.Duration(i)*5*time.Millisecond
		c.noteResolverTransportProbe(key, transportUDP, mtuConnectionProbeResult{
			UploadBytes: 200, DownloadBytes: 1200, ResolveTime: rtt,
		}, true, now)
		for sample := 0; sample < 4; sample++ {
			c.noteResolverTransportSuccessForPacket(
				key,
				transportUDP,
				rtt,
				Enums.PACKET_STREAM_DATA,
				now.Add(time.Duration(sample)*time.Millisecond),
			)
		}
	}
	return c
}

func TestComparableHealthyPathsAreStripedWithoutDuplication(t *testing.T) {
	c := prepareComparableStripeClient(t)
	counts := map[string]int{}
	now := time.Now()
	const packets = 1000
	for i := 0; i < packets; i++ {
		control := c.runtimePathControlDecision(Enums.PACKET_STREAM_DATA)
		paths := c.selectJointRuntimePathsControlled(
			Enums.PACKET_STREAM_DATA,
			0,
			100,
			control,
			now,
		)
		if len(paths) != 1 {
			t.Fatalf("striping emitted %d copies, want exactly 1", len(paths))
		}
		counts[paths[0].connection.Key]++
	}
	if counts["a"] == 0 || counts["b"] == 0 {
		t.Fatalf("comparable paths were not both used: %v", counts)
	}
	secondaryShare := float64(counts["b"]) / packets
	if secondaryShare < 0.35 || secondaryShare > 0.55 {
		t.Fatalf("unexpected weighted stripe distribution: counts=%v secondary=%.1f%%",
			counts, secondaryShare*100)
	}
	t.Logf("single-copy weighted stripe distribution: primary=%d secondary=%d (secondary %.1f%%)",
		counts["a"], counts["b"], secondaryShare*100)
}

func TestStripingRejectsLowConfidenceAndSlowPaths(t *testing.T) {
	c := prepareComparableStripeClient(t)
	c.resolverTransportMu.Lock()
	state := c.resolverTransportStateLocked("b")
	score := pathScoreFor(state, transportUDP)
	score.uploadRuntimeSamples = transportSpeedSampleThreshold - 1
	score.uploadRTTEWMA = 200 * time.Millisecond
	c.resolverTransportMu.Unlock()

	now := time.Now()
	for i := 0; i < 32; i++ {
		control := c.runtimePathControlDecision(Enums.PACKET_STREAM_DATA)
		paths := c.selectJointRuntimePathsControlled(
			Enums.PACKET_STREAM_DATA,
			0,
			100,
			control,
			now,
		)
		if len(paths) != 1 || paths[0].connection.Key != "a" {
			t.Fatalf("untrusted path entered stripe at iteration %d: %+v", i, paths)
		}
	}
}
