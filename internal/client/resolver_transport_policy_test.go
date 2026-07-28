package client

import (
	"context"
	"net"
	"sort"
	"testing"
	"time"

	"cottendns-go/internal/config"
	DnsParser "cottendns-go/internal/dnsparser"
	Enums "cottendns-go/internal/enums"
)

func newAutoTransportPolicyClient() *Client {
	c := &Client{
		cfg:                config.ClientConfig{ResolverTransport: "auto"},
		connectionsByKey:   make(map[string]int),
		resolverTransports: make(map[string]*resolverTransportState),
	}
	c.setActiveTransport(transportUDP)
	return c
}

func TestPerResolverTransportOverrides(t *testing.T) {
	c := newAutoTransportPolicyClient()
	c.cfg.ResolverTransportPaths = map[string]string{
		"192.0.2.1":    "tcp",
		"192.0.2.2:53": "dot",
		"key-c":        "doh",
	}
	c.connections = []Connection{
		{Key: "key-a", Resolver: "192.0.2.1", ResolverLabel: "192.0.2.1:53"},
		{Key: "key-b", Resolver: "192.0.2.2", ResolverLabel: "192.0.2.2:53"},
		{Key: "key-c", Resolver: "192.0.2.3", ResolverLabel: "192.0.2.3:53"},
	}
	c.connectionsByKey = map[string]int{"key-a": 0, "key-b": 1, "key-c": 2}

	cases := map[string][]resolverTransport{
		"key-a": {transportTCP},
		"key-b": {transportDoT, transportUDP, transportTCP},
		"key-c": {transportDoH, transportUDP, transportTCP},
	}
	for key, want := range cases {
		got := c.resolverTransportCandidates(key)
		if len(got) != len(want) {
			t.Fatalf("%s candidates=%v, want=%v", key, got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("%s candidates=%v, want=%v", key, got, want)
			}
		}
	}
}

func TestInitialAndBackgroundMTUProbeSupportAllTransports(t *testing.T) {
	c := newAutoTransportPolicyClient()
	c.syncedUploadMTU = 100
	c.syncedDownloadMTU = 1000
	c.mtuTestRetries = 1
	c.cfg.ResolverTransportPaths = map[string]string{
		"udp": "udp",
		"tcp": "tcp",
		"dot": "dot",
		"doh": "doh",
	}
	c.connections = []Connection{
		{Key: "udp", ResolverLabel: "192.0.2.1:53"},
		{Key: "tcp", ResolverLabel: "192.0.2.2:53"},
		{Key: "dot", ResolverLabel: "192.0.2.3:53"},
		{Key: "doh", ResolverLabel: "192.0.2.4:53"},
	}
	c.connectionsByKey = map[string]int{"udp": 0, "tcp": 1, "dot": 2, "doh": 3}

	initialSeen := map[resolverTransport]bool{}
	c.probeConnectionMTUOverFn = func(_ context.Context, _ *Connection, _ int, transport resolverTransport) (mtuConnectionProbeResult, mtuRejectReason) {
		initialSeen[transport] = true
		return mtuConnectionProbeResult{
			UploadBytes: 100, UploadChars: 100, DownloadBytes: 1000,
			ResolveTime: 50 * time.Millisecond,
		}, mtuRejectNone
	}
	for i := range c.connections {
		if _, reason := c.probeConnectionMTU(context.Background(), &c.connections[i], 100); reason != mtuRejectNone {
			t.Fatalf("initial probe rejected %s", c.connections[i].Key)
		}
	}
	for _, transport := range []resolverTransport{transportUDP, transportTCP, transportDoT, transportDoH} {
		if !initialSeen[transport] {
			t.Errorf("initial MTU scan did not exercise %s", transport)
		}
	}

	var backgroundSeen []string
	c.probeSessionMTUOverFn = func(_ context.Context, conn *Connection, transport resolverTransport) (mtuConnectionProbeResult, bool) {
		backgroundSeen = append(backgroundSeen, conn.Key+":"+transport.String())
		return mtuConnectionProbeResult{UploadBytes: 100, DownloadBytes: 1000, ResolveTime: 60 * time.Millisecond}, true
	}
	for i := range c.connections {
		if !c.recheckResolverConnection(context.Background(), &c.connections[i]) {
			t.Fatalf("background probe rejected %s", c.connections[i].Key)
		}
	}
	sort.Strings(backgroundSeen)
	for _, want := range []string{"doh:DoH", "dot:DoT", "tcp:TCP/53", "udp:UDP/53"} {
		idx := sort.SearchStrings(backgroundSeen, want)
		if idx >= len(backgroundSeen) || backgroundSeen[idx] != want {
			t.Errorf("background MTU scan missing %s; got=%v", want, backgroundSeen)
		}
	}
}

func TestBackgroundDiscoveryRetainsNarrowTransportMTUs(t *testing.T) {
	c := newAutoTransportPolicyClient()
	c.cfg.MaxUploadMTU = 250
	c.connections = []Connection{{
		Key: "resolver-a", Domain: "tunnel.example", Resolver: "192.0.2.20",
		ResolverLabel: "192.0.2.20:53", IsValid: true,
	}}
	c.connectionsByKey = map[string]int{"resolver-a": 0}

	var scanned []resolverTransport
	c.probeConnectionMTUOverFn = func(
		_ context.Context,
		_ *Connection,
		maxUpload int,
		transport resolverTransport,
	) (mtuConnectionProbeResult, mtuRejectReason) {
		if maxUpload != 250 {
			t.Fatalf("background max upload=%d, want 250", maxUpload)
		}
		scanned = append(scanned, transport)
		upload := 64
		if transport == transportTCP {
			upload = 96
		}
		return mtuConnectionProbeResult{
			UploadBytes: upload, DownloadBytes: 600, ResolveTime: 40 * time.Millisecond,
		}, mtuRejectNone
	}

	c.refreshResolverTransportPath(context.Background(), &c.connections[0])
	c.refreshResolverTransportPath(context.Background(), &c.connections[0])
	if len(scanned) != 2 || scanned[0] != transportUDP || scanned[1] != transportTCP {
		t.Fatalf("background scan did not rotate UDP/TCP: %v", scanned)
	}

	c.resolverTransportMu.Lock()
	state := c.resolverTransportStateLocked("resolver-a")
	udp, tcp := *pathScoreFor(state, transportUDP), *pathScoreFor(state, transportTCP)
	c.resolverTransportMu.Unlock()
	if !udp.viable || udp.uploadMTU != 64 || !tcp.viable || tcp.uploadMTU != 96 {
		t.Fatalf("narrow MTUs were not retained: udp=%+v tcp=%+v", udp, tcp)
	}
}

func TestBackgroundDiscoveryYieldsToForegroundWithoutPenalizingPath(t *testing.T) {
	c := newAutoTransportPolicyClient()
	c.cfg.MaxUploadMTU = 250
	c.connections = []Connection{{
		Key: "resolver-a", Domain: "tunnel.example", Resolver: "192.0.2.20",
		ResolverLabel: "192.0.2.20:53", IsValid: true,
	}}
	c.connectionsByKey = map[string]int{"resolver-a": 0}
	now := time.Now()
	c.noteResolverTransportProbe("resolver-a", transportUDP, mtuConnectionProbeResult{
		UploadBytes: 180, DownloadBytes: 900, ResolveTime: 50 * time.Millisecond,
	}, true, now)

	started := make(chan struct{})
	c.probeConnectionMTUOverFn = func(
		ctx context.Context,
		_ *Connection,
		_ int,
		_ resolverTransport,
	) (mtuConnectionProbeResult, mtuRejectReason) {
		close(started)
		<-ctx.Done()
		return mtuConnectionProbeResult{}, mtuRejectUpload
	}
	done := make(chan struct{})
	go func() {
		c.refreshResolverTransportPath(context.Background(), &c.connections[0])
		close(done)
	}()
	<-started
	c.runtimeOriginalSends.Add(1)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("background discovery did not yield when foreground traffic resumed")
	}

	c.resolverTransportMu.Lock()
	score := *pathScoreFor(c.resolverTransportStateLocked("resolver-a"), transportUDP)
	c.resolverTransportMu.Unlock()
	if !score.viable || score.uploadMTU != 180 || score.downloadMTU != 900 {
		t.Fatalf("preempted background scan damaged the existing path score: %+v", score)
	}
}

func TestBackgroundDiscoveryAcceptsNilContext(t *testing.T) {
	c := newAutoTransportPolicyClient()
	c.cfg.MaxUploadMTU = 250
	c.connections = []Connection{{
		Key: "resolver-a", Domain: "tunnel.example", Resolver: "192.0.2.20",
		ResolverLabel: "192.0.2.20:53", IsValid: true,
	}}
	c.connectionsByKey = map[string]int{"resolver-a": 0}
	c.probeConnectionMTUOverFn = func(
		ctx context.Context,
		_ *Connection,
		_ int,
		_ resolverTransport,
	) (mtuConnectionProbeResult, mtuRejectReason) {
		if ctx == nil {
			t.Fatal("background probe received a nil context")
		}
		return mtuConnectionProbeResult{
			UploadBytes: 100, DownloadBytes: 1000, ResolveTime: 50 * time.Millisecond,
		}, mtuRejectNone
	}

	c.refreshResolverTransportPath(nil, &c.connections[0])
	c.resolverTransportMu.Lock()
	score := *pathScoreFor(c.resolverTransportStateLocked("resolver-a"), transportUDP)
	c.resolverTransportMu.Unlock()
	if !score.probed || !score.viable {
		t.Fatalf("nil-context background discovery did not retain its result: %+v", score)
	}
}

func TestAutoTransportStartupKeepsViableUDPDespiteFasterTCPProbe(t *testing.T) {
	c := newAutoTransportPolicyClient()
	now := time.Now()
	c.noteResolverTransportProbe("resolver-a", transportUDP, mtuConnectionProbeResult{
		UploadBytes: 200, DownloadBytes: 1200, ResolveTime: 180 * time.Millisecond,
	}, true, now)
	c.noteResolverTransportProbe("resolver-a", transportTCP, mtuConnectionProbeResult{
		UploadBytes: 220, DownloadBytes: 1400, ResolveTime: 40 * time.Millisecond,
	}, true, now.Add(time.Millisecond))

	if got := c.chooseResolverTransport(
		"resolver-a",
		Enums.PacketPriorityNormal,
		now.Add(transportSwitchCooldown+time.Second),
	).primary; got != transportUDP {
		t.Fatalf("one faster TCP startup probe displaced viable UDP: got %s", got)
	}

	c.resolverTransportMu.Lock()
	state := c.resolverTransportStateLocked("resolver-a")
	got, _, ok := c.bestPacketTransportLocked(
		"resolver-a",
		state,
		Enums.PACKET_STREAM_DATA,
		100,
	)
	c.resolverTransportMu.Unlock()
	if !ok || got != transportUDP {
		t.Fatalf("bulk router bypassed viable preferred UDP: got=%s ok=%v", got, ok)
	}
}

func TestAutoMTUSyncUsesFirstViableUDPNotFasterTCP(t *testing.T) {
	c := newAutoTransportPolicyClient()
	c.probeConnectionMTUOverFn = func(
		_ context.Context,
		_ *Connection,
		_ int,
		transport resolverTransport,
	) (mtuConnectionProbeResult, mtuRejectReason) {
		if transport == transportUDP {
			return mtuConnectionProbeResult{
				UploadBytes: 160, DownloadBytes: 900, ResolveTime: 180 * time.Millisecond,
			}, mtuRejectNone
		}
		return mtuConnectionProbeResult{
			UploadBytes: 240, DownloadBytes: 1500, ResolveTime: 30 * time.Millisecond,
		}, mtuRejectNone
	}

	got, reason := c.probeConnectionMTU(
		context.Background(),
		&Connection{Key: "resolver-a", ResolverLabel: "192.0.2.53:53"},
		250,
	)
	if reason != mtuRejectNone {
		t.Fatalf("auto MTU probe rejected viable UDP: %v", reason)
	}
	if got.UploadBytes != 160 || got.DownloadBytes != 900 {
		t.Fatalf("auto MTU sync selected faster TCP result instead of viable UDP: %+v", got)
	}
	if preferred := c.preferredResolverTransport("resolver-a"); preferred != transportUDP {
		t.Fatalf("auto MTU sync did not retain UDP preference: %s", preferred)
	}
}

func TestAutoTransportStartupUsesTCPWhenUDPProbeFails(t *testing.T) {
	c := newAutoTransportPolicyClient()
	now := time.Now()
	c.noteResolverTransportProbe(
		"resolver-a",
		transportUDP,
		mtuConnectionProbeResult{},
		false,
		now,
	)
	c.noteResolverTransportProbe("resolver-a", transportTCP, mtuConnectionProbeResult{
		UploadBytes: 200, DownloadBytes: 1200, ResolveTime: 80 * time.Millisecond,
	}, true, now.Add(time.Millisecond))

	if got := c.chooseResolverTransport(
		"resolver-a",
		Enums.PacketPriorityNormal,
		now.Add(time.Second),
	).primary; got != transportTCP {
		t.Fatalf("failed UDP did not fall back to viable TCP: got %s", got)
	}
}

func TestAutoTransportKeepsPoisonedFastUDP(t *testing.T) {
	c := newAutoTransportPolicyClient()
	now := time.Now()
	c.noteResolverTransportPoison("resolver-a", transportUDP)
	for i := 0; i < 4; i++ {
		c.noteResolverTransportSuccess("resolver-a", transportUDP, 80*time.Millisecond, now.Add(time.Duration(i)*time.Second))
	}
	if got := c.chooseResolverTransport("resolver-a", Enums.PacketPriorityNormal, now.Add(5*time.Second)).primary; got != transportUDP {
		t.Fatalf("poison alone moved a healthy UDP path: got %s", got)
	}
	if got := c.chooseResolverTransport("resolver-a", Enums.PacketPriorityCritical, now.Add(5*time.Second)); !got.hedge {
		t.Fatal("poison should make the next control packet compare the alternate path")
	}
	if got := c.chooseResolverTransport("resolver-a", Enums.PacketPriorityCritical, now.Add(8*time.Second)); got.hedge {
		t.Fatal("one poison signal caused repeated bandwidth-consuming hedges")
	}
}

func TestHealthyAutoTransportDoesNotProbeOnForegroundTraffic(t *testing.T) {
	c := newAutoTransportPolicyClient()
	now := time.Now()
	for i := 0; i < 10; i++ {
		got := c.chooseResolverTransport(
			"resolver-a",
			Enums.PacketPriorityCritical,
			now.Add(time.Duration(i)*transportProbeInterval),
		)
		if got.hedge {
			t.Fatalf("healthy control traffic was duplicated at sample %d", i)
		}
	}
}

func TestHealthyAutoTransportUsesBoundedForegroundExploration(t *testing.T) {
	c := newAutoTransportPolicyClient()
	now := time.Now()
	c.runtimeOriginalSends.Store(transportForegroundFramesPerExplore)
	first := c.chooseResolverTransport("resolver-a", Enums.PacketPriorityCritical, now)
	if !first.hedge {
		t.Fatal("accrued foreground budget did not compare an alternate transport")
	}
	if second := c.chooseResolverTransport(
		"resolver-a",
		Enums.PacketPriorityCritical,
		now.Add(transportProbeInterval+time.Second),
	); second.hedge {
		t.Fatal("foreground exploration budget was charged more than once")
	}
	if other := c.chooseResolverTransport(
		"resolver-b",
		Enums.PacketPriorityCritical,
		now.Add(transportProbeInterval+time.Second),
	); other.hedge {
		t.Fatal("another resolver multiplied the client-wide exploration budget")
	}
	if got := c.transportExplorationCount.Load(); got != 1 {
		t.Fatalf("exploration count=%d, want 1", got)
	}

	c.runtimeOriginalSends.Add(transportForegroundFramesPerExplore)
	if next := c.chooseResolverTransport(
		"resolver-b",
		Enums.PacketPriorityCritical,
		now.Add(2*transportProbeInterval+time.Second),
	); !next.hedge {
		t.Fatal("next client-wide exploration budget was not usable by another resolver")
	}
}

func TestHealthyAutoTransportExplorationStopsWhenQueueBusy(t *testing.T) {
	c := newAutoTransportPolicyClient()
	c.txChannel = make(chan rawOutboundTask, 8)
	for i := 0; i < cap(c.txChannel)/4; i++ {
		c.txChannel <- rawOutboundTask{}
	}
	c.runtimeOriginalSends.Store(transportForegroundFramesPerExplore)
	if got := c.chooseResolverTransport(
		"resolver-a",
		Enums.PacketPriorityCritical,
		time.Now(),
	); got.hedge {
		t.Fatal("healthy alternate exploration competed with a busy foreground queue")
	}
}

func TestSuccessfulUDPReplyClearsTruncationStreak(t *testing.T) {
	c := newAutoTransportPolicyClient()
	now := time.Now().Add(-10 * time.Second)
	c.noteResolverTransportTruncation("resolver-a", transportUDP, now)
	c.noteResolverTransportTruncation("resolver-a", transportUDP, now.Add(time.Second))
	c.noteResolverTransportSuccess("resolver-a", transportUDP, 80*time.Millisecond, now.Add(2*time.Second))
	c.noteResolverTransportTruncation("resolver-a", transportUDP, now.Add(3*time.Second))
	c.noteResolverTransportTruncation("resolver-a", transportUDP, now.Add(4*time.Second))
	if got := c.preferredResolverTransport("resolver-a"); got != transportUDP {
		t.Fatalf("isolated UDP truncation bursts displaced a path with valid replies: got %s", got)
	}
}

func TestAutoTransportSwitchesOnlyFailingResolver(t *testing.T) {
	c := newAutoTransportPolicyClient()
	now := time.Now()
	c.noteResolverTransportFailure("resolver-a", transportUDP, now)
	c.noteResolverTransportFailure("resolver-a", transportUDP, now.Add(4*time.Second))

	if got := c.chooseResolverTransport("resolver-a", Enums.PacketPriorityNormal, now.Add(5*time.Second)).primary; got != transportTCP {
		t.Fatalf("failing resolver did not switch to TCP: got %s", got)
	}
	if got := c.chooseResolverTransport("resolver-b", Enums.PacketPriorityNormal, now.Add(5*time.Second)).primary; got != transportUDP {
		t.Fatalf("unrelated resolver was switched globally: got %s", got)
	}
}

func TestPoisonPlusTimeoutSwitchesImmediately(t *testing.T) {
	c := newAutoTransportPolicyClient()
	now := time.Now()
	c.nowFn = func() time.Time { return now.Add(20 * time.Millisecond) }
	c.noteResolverTransportPoison("resolver-a", transportUDP)
	c.noteResolverTransportFailure("resolver-a", transportUDP, now)
	if got := c.chooseResolverTransport("resolver-a", Enums.PacketPriorityNormal, now.Add(time.Second)).primary; got != transportTCP {
		t.Fatalf("poisoned UDP timeout did not fast-switch to TCP: got %s", got)
	}
}

func TestExpiredPoisonDoesNotMakeFutureTransientFailureHard(t *testing.T) {
	c := newAutoTransportPolicyClient()
	now := time.Now()
	c.nowFn = func() time.Time { return now }
	c.noteResolverTransportPoison("resolver-a", transportUDP)

	now = now.Add(transportPoisonMemory + time.Second)
	c.noteResolverTransportFailure("resolver-a", transportUDP, now)
	if got := c.chooseResolverTransport("resolver-a", Enums.PacketPriorityNormal, now).primary; got != transportUDP {
		t.Fatalf("stale poison made one later timeout switch paths: got %s", got)
	}

	now = now.Add(transportSwitchCooldown + time.Second)
	c.noteResolverTransportFailure("resolver-a", transportUDP, now)
	if got := c.chooseResolverTransport("resolver-a", Enums.PacketPriorityNormal, now).primary; got != transportTCP {
		t.Fatalf("two current failures did not switch paths: got %s", got)
	}
}

func TestResolverPathTimeoutUsesStableRTTHistory(t *testing.T) {
	c := newAutoTransportPolicyClient()
	c.tunnelPacketTimeout = 5 * time.Second
	now := time.Now()
	for i := 0; i < transportSpeedSampleThreshold; i++ {
		c.noteResolverTransportSuccess(
			"resolver-a",
			transportUDP,
			100*time.Millisecond,
			now.Add(time.Duration(i)*time.Second),
		)
	}
	if got := c.resolverPathRequestTimeout("resolver-a", transportUDP); got != 1500*time.Millisecond {
		t.Fatalf("adaptive path timeout=%s, want 1.5s", got)
	}

	for i := 0; i < transportSpeedSampleThreshold; i++ {
		c.noteResolverTransportSuccess(
			"resolver-b",
			transportUDP,
			time.Second,
			now.Add(time.Duration(i)*time.Second),
		)
	}
	if got := c.resolverPathRequestTimeout("resolver-b", transportUDP); got != 5*time.Second {
		t.Fatalf("slow path timeout=%s, want configured 5s cap", got)
	}
}

func TestAutoTransportMovesOffSlowUDP(t *testing.T) {
	c := newAutoTransportPolicyClient()
	now := time.Now().Add(-10 * time.Second)
	for i := 0; i < transportSpeedSampleThreshold; i++ {
		at := now.Add(time.Duration(i) * time.Second)
		c.noteResolverTransportSuccess("resolver-a", transportTCP, 100*time.Millisecond, at)
		c.noteResolverTransportSuccess("resolver-a", transportUDP, 250*time.Millisecond, at)
	}
	if got := c.chooseResolverTransport("resolver-a", Enums.PacketPriorityNormal, time.Now()).primary; got != transportTCP {
		t.Fatalf("slow UDP remained preferred despite a consistently faster TCP path: got %s", got)
	}
}

func TestAsymmetricControlPathDoesNotDisplaceFasterUDPDataPath(t *testing.T) {
	c := newAutoTransportPolicyClient()
	now := time.Now().Add(-transportSpeedSwitchCooldown - time.Second)
	for i := 0; i < transportSpeedSampleThreshold; i++ {
		at := now.Add(time.Duration(i) * time.Second)
		c.noteResolverTransportSuccessForPacket(
			"resolver-a", transportUDP, 80*time.Millisecond, Enums.PACKET_STREAM_DATA, at,
		)
		c.noteResolverTransportSuccessForPacket(
			"resolver-a", transportUDP, 80*time.Millisecond, Enums.PACKET_STREAM_DATA_ACK, at,
		)
		c.noteResolverTransportSuccessForPacket(
			"resolver-a", transportTCP, 140*time.Millisecond, Enums.PACKET_STREAM_DATA, at,
		)
		c.noteResolverTransportSuccessForPacket(
			"resolver-a", transportTCP, 20*time.Millisecond, Enums.PACKET_STREAM_DATA_ACK, at,
		)
	}
	if got := c.preferredResolverTransport("resolver-a"); got != transportUDP {
		t.Fatalf("fast TCP control replies displaced a faster UDP upload path: got %s", got)
	}
}

func TestComparableDirectionalEvidencePromotesFasterTCP(t *testing.T) {
	c := newAutoTransportPolicyClient()
	now := time.Now().Add(-transportSpeedSwitchCooldown - time.Second)
	for i := 0; i < transportSpeedSampleThreshold; i++ {
		at := now.Add(time.Duration(i) * time.Second)
		for _, packetType := range []uint8{Enums.PACKET_STREAM_DATA, Enums.PACKET_STREAM_DATA_ACK} {
			c.noteResolverTransportSuccessForPacket(
				"resolver-a", transportUDP, 180*time.Millisecond, packetType, at,
			)
			c.noteResolverTransportSuccessForPacket(
				"resolver-a", transportTCP, 40*time.Millisecond, packetType, at,
			)
		}
	}
	if got := c.preferredResolverTransport("resolver-a"); got != transportTCP {
		t.Fatalf("faster TCP with comparable two-direction evidence was not promoted: got %s", got)
	}
}

func TestSpeedPromotionDoesNotFlapImmediatelyAfterFailureFailover(t *testing.T) {
	c := newAutoTransportPolicyClient()
	now := time.Now()
	c.noteResolverTransportFailure("resolver-a", transportUDP, now)
	c.noteResolverTransportFailure("resolver-a", transportUDP, now.Add(transportSwitchCooldown+time.Second))
	if got := c.preferredResolverTransport("resolver-a"); got != transportTCP {
		t.Fatalf("failure failover selected %s, want TCP", got)
	}

	for i := 0; i < transportSpeedSampleThreshold; i++ {
		at := now.Add(5*time.Second + time.Duration(i)*time.Second)
		c.noteResolverTransportSuccess("resolver-a", transportTCP, 300*time.Millisecond, at)
		c.noteResolverTransportSuccess("resolver-a", transportUDP, 50*time.Millisecond, at)
	}
	if got := c.preferredResolverTransport("resolver-a"); got != transportTCP {
		t.Fatalf("speed samples flapped transport during recovery cooldown: got %s", got)
	}

	at := now.Add(transportSwitchCooldown + transportSpeedSwitchCooldown + time.Second)
	c.noteResolverTransportSuccess("resolver-a", transportUDP, 50*time.Millisecond, at)
	if got := c.preferredResolverTransport("resolver-a"); got != transportUDP {
		t.Fatalf("recovered faster UDP was not restored after stable cooldown: got %s", got)
	}
}

func TestExplicitTransportNeverHedges(t *testing.T) {
	c := newAutoTransportPolicyClient()
	c.cfg.ResolverTransport = "udp"
	got := c.chooseResolverTransport("resolver-a", Enums.PacketPriorityCritical, time.Now())
	if got.primary != transportUDP || got.hedge {
		t.Fatalf("explicit UDP changed behavior: %+v", got)
	}
}

func TestHedgedResponseIsClaimedOnlyOnce(t *testing.T) {
	c := newAutoTransportPolicyClient()
	c.resolverPending = make(map[resolverSampleKey]resolverSample)
	addr := &net.UDPAddr{IP: net.ParseIP("192.0.2.53"), Port: 53}
	packet, err := DnsParser.BuildTXTQuestionPacket("payload.tunnel.example", Enums.DNS_RECORD_TYPE_TXT, 4096)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	c.trackResolverFrameOver(encodedOutboundDatagram{
		addr: addr, serverKey: "resolver-a", packet: packet,
		transport: transportUDP, mayHaveSibling: true,
	}, "udp-local", transportUDP, now)
	c.trackResolverFrameOver(encodedOutboundDatagram{
		addr: addr, serverKey: "resolver-a", packet: packet,
		transport: transportTCP, mayHaveSibling: true,
	}, "tcp-local", transportTCP, now)

	if !c.trackResolverSuccessOver(packet, addr, "tcp-local", transportTCP, now.Add(50*time.Millisecond)) {
		t.Fatal("first hedged response was not claimed")
	}
	if c.trackResolverSuccessOver(packet, addr, "udp-local", transportUDP, now.Add(80*time.Millisecond)) {
		t.Fatal("slower duplicate hedged response was claimed twice")
	}
	if len(c.resolverPending) != 0 {
		t.Fatalf("hedged sibling remained pending: %d", len(c.resolverPending))
	}
}

func TestJointPathSelectionUsesNarrowBackupForSmallPackets(t *testing.T) {
	c := newAutoTransportPolicyClient()
	c.syncedUploadMTU = 220
	c.syncedDownloadMTU = 1200
	c.connections = []Connection{
		{
			Key: "wide", Domain: "wide.tunnel.example", Resolver: "192.0.2.1",
			ResolverLabel: "192.0.2.1:53", IsValid: true,
			UploadMTUBytes: 220, DownloadMTUBytes: 1200, MTUResolveTime: 180 * time.Millisecond,
		},
		{
			Key: "narrow", Domain: "narrow.tunnel.example", Resolver: "192.0.2.2",
			ResolverLabel: "192.0.2.2:53", IsValid: true, Backup: true,
			UploadMTUBytes: 70, DownloadMTUBytes: 900, MTUResolveTime: 30 * time.Millisecond,
		},
	}
	c.connectionsByKey = map[string]int{"wide": 0, "narrow": 1}
	c.balancer = NewBalancer(BalancingRoundRobinDefault)
	c.balancer.SetConnections([]*Connection{&c.connections[0], &c.connections[1]})

	now := time.Now()
	c.noteResolverTransportProbe("wide", transportUDP, mtuConnectionProbeResult{
		UploadBytes: 220, DownloadBytes: 1200, ResolveTime: 180 * time.Millisecond,
	}, true, now)
	c.noteResolverTransportProbe("narrow", transportUDP, mtuConnectionProbeResult{
		UploadBytes: 70, DownloadBytes: 900, ResolveTime: 30 * time.Millisecond,
	}, true, now)

	small := c.selectJointRuntimePaths(Enums.PACKET_STREAM_DATA_ACK, 0, 0, 1, now)
	if len(small) == 0 || small[0].connection.Key != "narrow" {
		t.Fatalf("small control packet did not use fast narrow backup: %+v", small)
	}

	large := c.selectJointRuntimePaths(Enums.PACKET_STREAM_DATA, 0, 180, 1, now)
	if len(large) == 0 || large[0].connection.Key != "wide" {
		t.Fatalf("large data packet used an MTU-ineligible path: %+v", large)
	}
}

func TestJointPathSelectionChoosesTransportByPacketSize(t *testing.T) {
	c := newAutoTransportPolicyClient()
	c.connections = []Connection{{
		Key: "resolver-a", Domain: "tunnel.example", Resolver: "192.0.2.10",
		ResolverLabel: "192.0.2.10:53", IsValid: true,
		UploadMTUBytes: 220, DownloadMTUBytes: 1200,
	}}
	c.connectionsByKey = map[string]int{"resolver-a": 0}
	c.balancer = NewBalancer(BalancingRoundRobinDefault)
	c.balancer.SetConnections([]*Connection{&c.connections[0]})

	now := time.Now()
	c.noteResolverTransportProbe("resolver-a", transportUDP, mtuConnectionProbeResult{
		UploadBytes: 70, DownloadBytes: 900, ResolveTime: 25 * time.Millisecond,
	}, true, now)
	c.noteResolverTransportProbe("resolver-a", transportTCP, mtuConnectionProbeResult{
		UploadBytes: 220, DownloadBytes: 1200, ResolveTime: 90 * time.Millisecond,
	}, true, now)

	small := c.selectJointRuntimePaths(Enums.PACKET_STREAM_DATA, 0, 30, 1, now)
	if len(small) == 0 || small[0].transport != transportUDP {
		t.Fatalf("small packet did not use faster narrow UDP: %+v", small)
	}

	large := c.selectJointRuntimePaths(Enums.PACKET_STREAM_DATA, 0, 180, 1, now)
	if len(large) == 0 || large[0].transport != transportTCP {
		t.Fatalf("large packet did not move to wide TCP: %+v", large)
	}
}

func TestJointDuplicationPrefersDifferentResolverNetworks(t *testing.T) {
	c := newAutoTransportPolicyClient()
	c.dupPreferDistinctDomains = true
	c.connections = []Connection{
		{
			Key: "a", Domain: "tunnel.example", Resolver: "192.0.2.10",
			ResolverLabel: "192.0.2.10:53", IsValid: true,
			UploadMTUBytes: 200, DownloadMTUBytes: 1200,
		},
		{
			Key: "b", Domain: "tunnel.example", Resolver: "192.0.2.20",
			ResolverLabel: "192.0.2.20:53", IsValid: true,
			UploadMTUBytes: 200, DownloadMTUBytes: 1200,
		},
		{
			Key: "c", Domain: "tunnel.example", Resolver: "198.51.100.30",
			ResolverLabel: "198.51.100.30:53", IsValid: true,
			UploadMTUBytes: 200, DownloadMTUBytes: 1200,
		},
	}
	c.connectionsByKey = map[string]int{"a": 0, "b": 1, "c": 2}
	c.balancer = NewBalancer(BalancingRoundRobinDefault)
	c.balancer.SetConnections([]*Connection{
		&c.connections[0], &c.connections[1], &c.connections[2],
	})

	now := time.Now()
	for i := range c.connections {
		c.noteResolverTransportProbe(c.connections[i].Key, transportUDP, mtuConnectionProbeResult{
			UploadBytes: 200, DownloadBytes: 1200, ResolveTime: 50 * time.Millisecond,
		}, true, now)
	}

	selected := c.selectJointRuntimePaths(Enums.PACKET_STREAM_DATA, 0, 100, 2, now)
	if len(selected) != 2 {
		t.Fatalf("selected=%d, want 2", len(selected))
	}
	first := resolverNetworkGroup(selected[0].connection)
	second := resolverNetworkGroup(selected[1].connection)
	if first == second {
		t.Fatalf("duplication stayed in one resolver network: %+v", selected)
	}
}

func TestRuntimeDeliveryEvidencePenalizesIntermittentLoss(t *testing.T) {
	score := &resolverPathScore{
		probed:        true,
		viable:        true,
		uploadMTU:     200,
		downloadMTU:   1200,
		uploadRTTEWMA: 100 * time.Millisecond,
		rttEWMA:       100 * time.Millisecond,
	}
	for i := 0; i < transportSpeedSampleThreshold; i++ {
		noteRuntimeDelivery(score, true)
	}
	clean := pathEstimatedGoodputForPacket(score, Enums.PACKET_STREAM_DATA)
	for i := 0; i < 4; i++ {
		noteRuntimeDelivery(score, false)
		noteRuntimeDelivery(score, true)
	}
	lossy := pathEstimatedGoodputForPacket(score, Enums.PACKET_STREAM_DATA)
	if lossy >= clean*0.85 {
		t.Fatalf("intermittent foreground loss was underweighted: clean=%v lossy=%v", clean, lossy)
	}
	for i := 0; i < 24; i++ {
		noteRuntimeDelivery(score, true)
	}
	recovered := pathEstimatedGoodputForPacket(score, Enums.PACKET_STREAM_DATA)
	if recovered <= lossy || recovered < clean*0.95 {
		t.Fatalf("clean recovery stayed penalized: clean=%v lossy=%v recovered=%v", clean, lossy, recovered)
	}
}

func TestRuntimeDeliveryPriorDoesNotOverreactToFirstTimeout(t *testing.T) {
	score := &resolverPathScore{
		probed:        true,
		viable:        true,
		uploadMTU:     200,
		uploadRTTEWMA: 100 * time.Millisecond,
	}
	noteRuntimeDelivery(score, false)
	noteRuntimeDelivery(score, true)
	noteRuntimeDelivery(score, true)
	if score.runtimeDelivery < 0.85 {
		t.Fatalf("one startup timeout collapsed delivery score to %.3f", score.runtimeDelivery)
	}
}
