package client

import (
	"fmt"
	"testing"
	"time"

	Enums "cottendns-go/internal/enums"
)

func prepareAvailabilityDemotedFleet(c *Client, count int, now time.Time) {
	c.connections = make([]Connection, count)
	c.connectionsByKey = make(map[string]int, count)
	for i := 0; i < count; i++ {
		key := fmt.Sprintf("resolver-%02d", i)
		c.connections[i] = Connection{
			Key:              key,
			Resolver:         fmt.Sprintf("192.0.2.%d", i+1),
			ResolverLabel:    fmt.Sprintf("192.0.2.%d:53", i+1),
			Domain:           "v.example.test",
			IsValid:          true,
			UploadMTUBytes:   180,
			DownloadMTUBytes: 1200,
		}
		c.connectionsByKey[key] = i
		state := c.resolverTransportStateLocked(key)
		state.preferred = transportTCP
		state.availabilityDemoted = true
		state.lastSwitch = now.Add(-transportSpeedSwitchCooldown - time.Second)
		udp := pathScoreFor(state, transportUDP)
		udp.probed = true
		udp.viable = false
		tcp := pathScoreFor(state, transportTCP)
		tcp.probed = true
		tcp.viable = true
		tcp.uploadMTU = 180
		tcp.downloadMTU = 1200
	}
}

func probeResult(upload, download int, rtt time.Duration) mtuConnectionProbeResult {
	return mtuConnectionProbeResult{UploadBytes: upload, DownloadBytes: download, ResolveTime: rtt}
}

// A transient UDP probe failure must not strand a resolver on TCP forever.
// Demotion costs one failed probe, so restoration has to be reachable by the
// same kind of evidence — the background sweep re-proving UDP viable.
func TestAvailabilityDemotionToTCPIsReversedWhenUDPRecovers(t *testing.T) {
	c := newAutoTransportPolicyClient()
	now := time.Now()

	// Startup scan: UDP fails, TCP succeeds.
	c.noteResolverTransportProbe("r", transportUDP, mtuConnectionProbeResult{}, false, now)
	c.noteResolverTransportProbe("r", transportTCP, probeResult(200, 1200, 40*time.Millisecond), true, now)
	if got := c.preferredResolverTransport("r"); got != transportTCP {
		t.Fatalf("after failed UDP probe preferred=%v, want TCP", got)
	}

	// Background sweep proves UDP usable again.
	later := now.Add(transportSwitchCooldown + time.Second)
	c.noteResolverTransportProbe("r", transportUDP, probeResult(200, 1200, 45*time.Millisecond), true, later)
	if got := c.preferredResolverTransport("r"); got != transportUDP {
		t.Fatalf("UDP recovered but preferred=%v, want a return to UDP", got)
	}
}

// A promotion earned on measured speed is not an availability demotion and must
// survive later UDP probes, otherwise the two rules fight each other.
func TestSpeedPromotionIsNotReversedByProbeEvidence(t *testing.T) {
	c := newAutoTransportPolicyClient()
	now := time.Now()
	c.noteResolverTransportProbe("r", transportUDP, probeResult(200, 1200, 200*time.Millisecond), true, now)
	c.noteResolverTransportProbe("r", transportTCP, probeResult(200, 1200, 10*time.Millisecond), true, now)
	if got := c.preferredResolverTransport("r"); got != transportUDP {
		t.Fatalf("probe RTT alone moved the data plane: preferred=%v, want UDP", got)
	}

	// Give both directions enough runtime evidence for a real speed promotion.
	at := now
	for i := 0; i < transportSpeedSampleThreshold; i++ {
		at = at.Add(time.Millisecond)
		c.noteResolverTransportSuccessForPacket("r", transportUDP, 200*time.Millisecond, Enums.PACKET_STREAM_DATA, at)
		c.noteResolverTransportSuccessForPacket("r", transportUDP, 200*time.Millisecond, Enums.PACKET_STREAM_DATA_ACK, at)
	}
	at = at.Add(transportSpeedSwitchCooldown + time.Second)
	for i := 0; i < transportSpeedSampleThreshold; i++ {
		at = at.Add(time.Millisecond)
		c.noteResolverTransportSuccessForPacket("r", transportTCP, 5*time.Millisecond, Enums.PACKET_STREAM_DATA, at)
		c.noteResolverTransportSuccessForPacket("r", transportTCP, 5*time.Millisecond, Enums.PACKET_STREAM_DATA_ACK, at)
	}
	if got := c.preferredResolverTransport("r"); got != transportTCP {
		t.Fatalf("measured-faster TCP was not promoted: preferred=%v", got)
	}

	at = at.Add(transportSwitchCooldown + time.Second)
	c.noteResolverTransportProbe("r", transportUDP, probeResult(200, 1200, 200*time.Millisecond), true, at)
	if got := c.preferredResolverTransport("r"); got != transportTCP {
		t.Fatalf("probe evidence undid a speed promotion: preferred=%v, want TCP", got)
	}
}

// A continuously busy session must be able to walk a fleet back from an
// availability-only TCP demotion. This models the reported 48-resolver ratchet:
// 47 resolvers start on TCP, no idle MTU sweep occurs, and authenticated UDP
// canaries win twice for each resolver.
func TestBusyForegroundRestoresDemotedFleetWithinBoundedBudget(t *testing.T) {
	const fleet = 48
	c := newAutoTransportPolicyClient()
	start := time.Now()
	prepareAvailabilityDemotedFleet(c, fleet, start)

	canaries := 0
	totalFrames := int(transportRestoreFramesPerExplore) * fleet * int(transportRestoreSuccessThreshold)
	for frame := 1; frame <= totalFrames; frame++ {
		now := start.Add(time.Duration(frame) * time.Millisecond)
		c.runtimeOriginalSends.Store(uint64(frame))
		restore, ok := c.availabilityRestorePath(Enums.PACKET_STREAM_SYN, now)
		if !ok {
			continue
		}
		canaries++
		c.noteResolverTransportSuccess(
			restore.connection.Key,
			restore.transport,
			20*time.Millisecond,
			now,
		)
	}

	if want := fleet * int(transportRestoreSuccessThreshold); canaries != want {
		t.Fatalf("restore canaries=%d, want %d", canaries, want)
	}
	for _, conn := range c.connections {
		if got := c.preferredResolverTransport(conn.Key); got != transportUDP {
			t.Fatalf("%s remained on %v after authenticated UDP recovery", conn.Key, got)
		}
	}
	overhead := float64(canaries) / float64(totalFrames)
	if overhead > 0.016 {
		t.Fatalf("worst-case restoration overhead %.4f exceeds 1.6%%", overhead)
	}
}

func TestAvailabilityRestoreRunsUnderLoadButStopsNearQueueExhaustion(t *testing.T) {
	c := newAutoTransportPolicyClient()
	now := time.Now()
	prepareAvailabilityDemotedFleet(c, 1, now)
	c.txChannel = make(chan rawOutboundTask, 8)
	c.runtimeOriginalSends.Store(transportRestoreFramesPerExplore)

	// Ordinary healthy exploration stops at 25%; availability restoration is
	// still safe here because it reuses a duplicate in the common path.
	for i := 0; i < 2; i++ {
		c.txChannel <- rawOutboundTask{}
	}
	if _, ok := c.availabilityRestorePath(Enums.PACKET_STREAM_SYN, now); !ok {
		t.Fatal("moderate foreground load suppressed availability restoration")
	}

	c.transportRestoreBudgetSends.Store(0)
	c.runtimeOriginalSends.Store(transportRestoreFramesPerExplore)
	for i := len(c.txChannel); i < 6; i++ {
		c.txChannel <- rawOutboundTask{}
	}
	if _, ok := c.availabilityRestorePath(Enums.PACKET_STREAM_SYN, now.Add(transportProbeInterval)); ok {
		t.Fatal("restoration added work at 75% queue occupancy")
	}
}

func TestAvailabilityRestoreNeedsTwoWinsAndFailureResetsEvidence(t *testing.T) {
	c := newAutoTransportPolicyClient()
	now := time.Now()
	prepareAvailabilityDemotedFleet(c, 1, now)

	c.noteResolverTransportSuccess("resolver-00", transportUDP, 20*time.Millisecond, now)
	if got := c.preferredResolverTransport("resolver-00"); got != transportTCP {
		t.Fatalf("one lucky UDP reply restored preference: got %v", got)
	}
	c.noteResolverTransportFailure("resolver-00", transportUDP, now.Add(time.Second))
	c.noteResolverTransportSuccess("resolver-00", transportUDP, 20*time.Millisecond, now.Add(2*time.Second))
	if got := c.preferredResolverTransport("resolver-00"); got != transportTCP {
		t.Fatalf("failure did not reset restoration evidence: got %v", got)
	}
	c.noteResolverTransportSuccess("resolver-00", transportUDP, 20*time.Millisecond, now.Add(3*time.Second))
	if got := c.preferredResolverTransport("resolver-00"); got != transportUDP {
		t.Fatalf("two consecutive authenticated UDP wins did not restore preference: got %v", got)
	}
}

func TestAvailabilityRestoreReusesExistingDuplicateBeforeAddingBandwidth(t *testing.T) {
	c := newAutoTransportPolicyClient()
	now := time.Now()
	prepareAvailabilityDemotedFleet(c, 3, now)
	c.balancer = NewBalancer(BalancingRoundRobinDefault)
	c.balancer.SetConnections([]*Connection{
		&c.connections[0], &c.connections[1], &c.connections[2],
	})
	c.cfg.UploadSetupPacketDuplicationCount = 3
	c.cfg.DownloadSetupPacketDuplicationCount = 3
	c.runtimeOriginalSends.Store(transportRestoreFramesPerExplore)

	control := c.runtimePathControlDecision(Enums.PACKET_STREAM_SYN)
	paths := c.selectJointRuntimePathsControlled(
		Enums.PACKET_STREAM_SYN,
		0,
		32,
		control,
		now,
	)
	if len(paths) != 3 {
		t.Fatalf("restore changed three-copy query count: got %d paths", len(paths))
	}
	restorePaths := 0
	for _, path := range paths {
		if path.hedge && path.transport == transportUDP {
			restorePaths++
		}
	}
	if restorePaths != 1 {
		t.Fatalf("restoration paths=%d, want one substituted UDP canary: %+v", restorePaths, paths)
	}

	// With no duplicate to reuse, exactly one bounded sibling is added.
	c.transportRestoreBudgetSends.Store(0)
	c.runtimeOriginalSends.Store(transportRestoreFramesPerExplore)
	c.cfg.UploadSetupPacketDuplicationCount = 1
	c.cfg.DownloadSetupPacketDuplicationCount = 1
	paths = c.selectJointRuntimePathsControlled(
		Enums.PACKET_STREAM_SYN,
		0,
		32,
		c.runtimePathControlDecision(Enums.PACKET_STREAM_SYN),
		now.Add(transportProbeInterval),
	)
	if len(paths) != 2 || !paths[1].hedge {
		t.Fatalf("single-copy restoration did not add exactly one bounded sibling: %+v", paths)
	}
}
