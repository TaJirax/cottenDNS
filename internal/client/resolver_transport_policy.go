package client

import (
	"fmt"
	"net"
	"slices"
	"strings"
	"time"

	Enums "cottendns-go/internal/enums"
	VpnProto "cottendns-go/internal/vpnproto"
)

const (
	transportFailureSwitchThreshold     = 2
	transportSpeedSampleThreshold       = 3
	transportSpeedSwitchRatio           = 1.20
	transportProbeInterval              = 2 * time.Second
	transportSwitchCooldown             = 3 * time.Second
	transportSpeedSwitchCooldown        = 10 * time.Second
	transportPoisonMemory               = 2 * time.Minute
	transportTruncationThreshold        = 3
	transportForegroundFramesPerExplore = uint64(1024)
	// One restoration race per 64 original DNS frames is a worst-case 1.56%
	// query budget when no existing duplicate can be reused. With normal
	// duplication the canary replaces one copy and costs no additional query.
	transportRestoreFramesPerExplore = uint64(64)
	transportRestoreSuccessThreshold = uint8(2)
)

type resolverPathScore struct {
	rttEWMA                 time.Duration
	rttVariation            time.Duration
	uploadRTTEWMA           time.Duration
	downloadRTTEWMA         time.Duration
	successes               uint32
	uploadSuccesses         uint32
	downloadSuccesses       uint32
	failures                uint32
	failureStreak           uint8
	uploadFailureStreak     uint8
	downloadFailureStreak   uint8
	truncations             uint32
	truncationStreak        uint8
	poisonEvents            uint32
	lastPoison              time.Time
	lastTruncation          time.Time
	probed                  bool
	viable                  bool
	uploadMTU               int
	downloadMTU             int
	uploadLoss              float64
	downloadLoss            float64
	runtimeDelivery         float64
	runtimeSamples          uint32
	uploadRuntimeDelivery   float64
	downloadRuntimeDelivery float64
	uploadRuntimeSamples    uint32
	downloadRuntimeSamples  uint32
	directionalEvidence     bool
	lastSuccess             time.Time
	lastFailure             time.Time
}

type resolverTransportState struct {
	preferred             resolverTransport
	paths                 [4]resolverPathScore
	lastProbe             time.Time
	lastSwitch            time.Time
	lastBackgroundScan    time.Time
	probeCursor           int
	backgroundCursor      int
	backgroundProbeActive bool
	// availabilityDemoted marks a preferred-transport change that was forced by
	// the configured-first path measuring unusable, not earned on speed. Only
	// such a demotion may be reversed by later probe evidence.
	availabilityDemoted bool
	// restoreSuccesses counts authenticated configured-first wins while an
	// availability demotion is active. Two wins avoid restoring on one lucky
	// packet; a failure resets the evidence.
	restoreSuccesses uint8
}

type resolverTransportDecision struct {
	primary   resolverTransport
	secondary resolverTransport
	hedge     bool
}

type resolverRuntimePath struct {
	connection         Connection
	transport          resolverTransport
	score              float64
	directionalSamples uint32
	directionalRTT     time.Duration
	hedge              bool
}

func validResolverTransport(transport resolverTransport) bool {
	return transport >= transportUDP && transport <= transportDoH
}

func (c *Client) resolverTransportPolicyName(serverKey string) string {
	if c == nil {
		return "udp"
	}
	conn, hasConnection := c.GetConnectionByKey(serverKey)
	candidates := []string{serverKey}
	if hasConnection {
		candidates = append(candidates, conn.ResolverLabel, conn.Resolver)
		if host, _, err := net.SplitHostPort(conn.ResolverLabel); err == nil {
			candidates = append(candidates, host)
		}
	}
	for _, candidate := range candidates {
		if policy, ok := c.cfg.ResolverTransportPaths[strings.TrimSpace(candidate)]; ok {
			return policy
		}
	}
	policy := strings.ToLower(strings.TrimSpace(c.cfg.ResolverTransport))
	if policy == "" {
		return "auto"
	}
	return policy
}

func (c *Client) resolverTransportCandidates(serverKey string) []resolverTransport {
	return resolverTransportChain(c.resolverTransportPolicyName(serverKey))
}

func (c *Client) perResolverAutoTransport() bool {
	if c == nil {
		return false
	}
	for _, conn := range c.connections {
		if len(c.resolverTransportCandidates(conn.Key)) > 1 {
			return true
		}
	}
	return len(resolverTransportChain(c.cfg.ResolverTransport)) > 1
}

func (c *Client) resolverTransportPolicyKey(serverKey string) string {
	if conn, ok := c.GetConnectionByKey(serverKey); ok && conn.ResolverLabel != "" {
		return conn.ResolverLabel
	}
	return serverKey
}

func (c *Client) resolverTransportStateLocked(serverKey string) *resolverTransportState {
	serverKey = c.resolverTransportPolicyKey(serverKey)
	if c.resolverTransports == nil {
		c.resolverTransports = make(map[string]*resolverTransportState)
	}
	state := c.resolverTransports[serverKey]
	if state == nil {
		candidates := c.resolverTransportCandidates(serverKey)
		preferred := c.activeTransport()
		if len(candidates) > 0 {
			preferred = candidates[0]
		}
		state = &resolverTransportState{preferred: preferred}
		directional := c.cfg.PathControllerMode != "legacy"
		for i := range state.paths {
			state.paths[i].directionalEvidence = directional
		}
		c.resolverTransports[serverKey] = state
	}
	return state
}

func pathScoreFor(state *resolverTransportState, transport resolverTransport) *resolverPathScore {
	if state == nil || !validResolverTransport(transport) {
		return nil
	}
	return &state.paths[int(transport)]
}

func (c *Client) pathSupportsSession(score *resolverPathScore) bool {
	if score == nil {
		return false
	}
	// Cached/log-based startup may not have measured the alternate yet. Keep it
	// available for a control hedge or emergency failover; the first result will
	// immediately replace this optimistic state. A path that was actually
	// probed and failed is never selected.
	if !score.probed {
		return true
	}
	if !score.viable {
		return false
	}
	if c.syncedUploadMTU > 0 && score.uploadMTU > 0 && score.uploadMTU < c.syncedUploadMTU {
		return false
	}
	if c.syncedDownloadMTU > 0 && score.downloadMTU > 0 && score.downloadMTU < c.syncedDownloadMTU {
		return false
	}
	return true
}

// requiredUploadProbeMTU translates a runtime packet into the payload size used
// by MTU_UP probes. Probe results describe the MTU request payload, while native
// packet headers vary slightly by type, so compare equivalent raw sizes.
func requiredUploadProbeMTU(packetType uint8, payloadSize int) int {
	if payloadSize < 0 {
		payloadSize = 0
	}
	required := payloadSize + VpnProto.HeaderRawSize(packetType) - VpnProto.HeaderRawSize(Enums.PACKET_MTU_UP_REQ)
	if required < 1 {
		return 1
	}
	return required
}

func pathSupportsPacket(score *resolverPathScore, packetType uint8, payloadSize int) bool {
	if score == nil {
		return false
	}
	if !score.probed {
		return true
	}
	if !score.viable {
		return false
	}
	required := requiredUploadProbeMTU(packetType, payloadSize)
	return score.uploadMTU <= 0 || score.uploadMTU >= required
}

func pathEstimatedGoodput(score *resolverPathScore) float64 {
	if score == nil || !score.probed || !score.viable {
		return 0
	}
	mtu := score.downloadMTU
	if mtu <= 0 {
		mtu = 1
	}
	delivery := 1 - score.downloadLoss
	if score.runtimeSamples >= transportSpeedSampleThreshold {
		delivery = score.runtimeDelivery
	}
	if delivery < 0.01 {
		delivery = 0.01
	}
	rttMillis := float64(score.rttEWMA) / float64(time.Millisecond)
	if rttMillis < 1 {
		rttMillis = 1
	}
	return float64(mtu) * delivery / rttMillis
}

func pathEstimatedGoodputForPacket(score *resolverPathScore, packetType uint8) float64 {
	if score == nil || !score.probed || !score.viable {
		return 0
	}
	mtu, loss, rtt := score.uploadMTU, score.uploadLoss, score.uploadRTTEWMA
	if packetUsesDownloadPath(packetType) {
		mtu, loss = score.downloadMTU, score.downloadLoss
		rtt = score.downloadRTTEWMA
	}
	if mtu <= 0 {
		mtu = 1
	}
	delivery := 1 - loss
	directionalDelivery, directionalSamples := score.runtimeDelivery, score.runtimeSamples
	if score.directionalEvidence {
		directionalDelivery, directionalSamples = score.uploadRuntimeDelivery, score.uploadRuntimeSamples
		if packetUsesDownloadPath(packetType) {
			directionalDelivery, directionalSamples = score.downloadRuntimeDelivery, score.downloadRuntimeSamples
		}
	}
	if directionalSamples >= transportSpeedSampleThreshold {
		delivery = score.runtimeDelivery
		if score.directionalEvidence {
			delivery = directionalDelivery
		}
	} else if score.runtimeSamples >= transportSpeedSampleThreshold {
		delivery = score.runtimeDelivery
	}
	if delivery < 0.01 {
		delivery = 0.01
	}
	if rtt <= 0 {
		rtt = score.rttEWMA
	}
	rttMillis := float64(rtt) / float64(time.Millisecond)
	if rttMillis < 1 {
		rttMillis = 1
	}
	value := float64(mtu) * delivery / rttMillis
	// Until a path has three authenticated foreground samples in this
	// direction, retain it as usable but keep one lucky response from outranking
	// a mature path. The penalty disappears smoothly as evidence arrives.
	if directionalSamples < transportSpeedSampleThreshold {
		value *= 0.85 + 0.05*float64(directionalSamples)
	}
	directionalFailureStreak := score.failureStreak
	if score.directionalEvidence {
		directionalFailureStreak = score.uploadFailureStreak
		if packetUsesDownloadPath(packetType) {
			directionalFailureStreak = score.downloadFailureStreak
		}
	}
	if directionalFailureStreak > 0 {
		value /= 1 + float64(directionalFailureStreak*2)
	}
	return value
}

func packetUsesDownloadPath(packetType uint8) bool {
	switch packetType {
	case Enums.PACKET_STREAM_DATA_ACK, Enums.PACKET_STREAM_DATA_NACK, Enums.PACKET_PING:
		return true
	default:
		return false
	}
}

func updateDirectionalRTT(current *time.Duration, sample time.Duration) {
	if current == nil {
		return
	}
	if sample < 0 {
		sample = 0
	}
	if *current == 0 {
		*current = sample
		return
	}
	*current = (*current*7 + sample) / 8
}

func noteRuntimeDelivery(score *resolverPathScore, delivered bool) {
	if score == nil {
		return
	}
	sample := 0.0
	if delivered {
		sample = 1
	}
	if score.runtimeSamples == 0 {
		// Begin from a healthy neutral prior. Starting at zero after the first
		// timeout would punish a newly-recovered path for many packets and could
		// turn one startup loss into an unnecessary transport switch.
		score.runtimeDelivery = 1
	}
	// An eighth-weight EWMA reacts within a few packets to sustained loss but
	// retains enough history that one delayed DNS response cannot steer the
	// resolver pool. It is learned from foreground traffic, not probes.
	score.runtimeDelivery = score.runtimeDelivery*0.875 + sample*0.125
	if score.runtimeSamples < ^uint32(0) {
		score.runtimeSamples++
	}
}

func noteDirectionalRuntimeDelivery(delivery *float64, samples *uint32, delivered bool) {
	if delivery == nil || samples == nil {
		return
	}
	sample := 0.0
	if delivered {
		sample = 1
	}
	if *samples == 0 {
		*delivery = 1
	}
	*delivery = *delivery*0.875 + sample*0.125
	if *samples < ^uint32(0) {
		(*samples)++
	}
}

func noteRuntimeDeliveryForPacket(score *resolverPathScore, delivered bool, packetType uint8, bidirectional bool) {
	noteRuntimeDelivery(score, delivered)
	if score == nil {
		return
	}
	if bidirectional || !packetUsesDownloadPath(packetType) {
		noteDirectionalRuntimeDelivery(&score.uploadRuntimeDelivery, &score.uploadRuntimeSamples, delivered)
	}
	if bidirectional || packetUsesDownloadPath(packetType) {
		noteDirectionalRuntimeDelivery(&score.downloadRuntimeDelivery, &score.downloadRuntimeSamples, delivered)
	}
}

// pathNeedsHedgeLocked reports whether fresh passive evidence warrants one
// alternate-path race. Healthy traffic does not probe merely because a timer
// elapsed: that spent scarce DNS capacity and could reduce foreground speed.
func pathNeedsHedgeLocked(state *resolverTransportState, transport resolverTransport, now time.Time) bool {
	if state == nil {
		return false
	}
	score := pathScoreFor(state, transport)
	if score == nil {
		return false
	}
	freshAfterLastProbe := func(observed time.Time) bool {
		return !observed.IsZero() && (state.lastProbe.IsZero() || observed.After(state.lastProbe))
	}
	if score.failureStreak > 0 && freshAfterLastProbe(score.lastFailure) {
		return true
	}
	if score.truncationStreak > 0 && freshAfterLastProbe(score.lastTruncation) {
		return true
	}
	if freshAfterLastProbe(score.lastPoison) {
		age := now.Sub(score.lastPoison)
		return age >= 0 && age <= transportPoisonMemory
	}
	return false
}

// healthyExplorationAvailableLocked permits a tiny amount of real-path
// comparison without a timer-driven health tax. One existing control packet
// may be duplicated after 1,024 original frames (about 0.1%), and only while
// foreground queues have headroom. This is enough to discover a materially
// faster TCP/DoT/DoH path without competing with congested user traffic.
func (c *Client) healthyExplorationAvailableLocked(state *resolverTransportState) bool {
	if c == nil || state == nil {
		return false
	}
	foreground := c.runtimeOriginalSends.Load()
	chargedThrough := c.transportExploreBudgetSends.Load()
	if foreground < chargedThrough+transportForegroundFramesPerExplore {
		return false
	}
	if c.runtimeQueuesCongested() {
		return false
	}
	return true
}

// runtimeQueuesSeverelyCongested keeps restoration available during sustained
// foreground traffic while still refusing to add work near queue exhaustion.
// Ordinary healthy exploration remains more conservative at 25% occupancy.
func (c *Client) runtimeQueuesSeverelyCongested() bool {
	if c == nil {
		return true
	}
	severe := func(length, capacity int) bool {
		return capacity > 0 && length*4 >= capacity*3
	}
	if severe(len(c.txChannel), cap(c.txChannel)) ||
		severe(len(c.encodedTXChannel), cap(c.encodedTXChannel)) ||
		severe(len(c.rxChannel), cap(c.rxChannel)) {
		return true
	}
	c.resolverStatsMu.RLock()
	pending := len(c.resolverPending)
	c.resolverStatsMu.RUnlock()
	return pending*4 >= resolverPendingSoftCap*3
}

// availabilityRestorePath selects one configured-first transport that was
// demoted for availability. Unlike healthy exploration, it deliberately allows
// a previously failed/non-viable path: otherwise only the idle full-MTU sweep
// could ever prove that path recovered. The returned path carries an existing
// authenticated control frame, so poison cannot manufacture recovery evidence.
func (c *Client) availabilityRestorePath(packetType uint8, now time.Time) (resolverRuntimePath, bool) {
	if c == nil || Enums.DefaultPacketPriority(packetType) > Enums.PacketPriorityHigh ||
		c.runtimeQueuesSeverelyCongested() {
		return resolverRuntimePath{}, false
	}
	foreground := c.runtimeOriginalSends.Load()
	chargedThrough := c.transportRestoreBudgetSends.Load()
	if foreground < chargedThrough+transportRestoreFramesPerExplore {
		return resolverRuntimePath{}, false
	}
	// Reserve the global ticket before scanning. This both prevents concurrent
	// dispatchers from multiplying the budget and charges a no-op scan when the
	// fleet has nothing to restore, so healthy traffic does not rescan every
	// control frame after the first 64 sends.
	if !c.transportRestoreBudgetSends.CompareAndSwap(chargedThrough, foreground) {
		return resolverRuntimePath{}, false
	}

	connections := c.connections
	if c.balancer != nil {
		connections = c.balancer.AllValidConnectionsIncludingBackup()
	}
	if len(connections) == 0 {
		return resolverRuntimePath{}, false
	}
	eligible := make([]Connection, 0, len(connections))
	for _, conn := range connections {
		if conn.IsValid && conn.Key != "" && !c.isRuntimeDisabledResolver(conn.Key) {
			eligible = append(eligible, conn)
		}
	}
	if len(eligible) == 0 {
		return resolverRuntimePath{}, false
	}

	c.resolverTransportMu.Lock()
	defer c.resolverTransportMu.Unlock()
	start := int(c.transportRestoreCursor.Load() % uint64(len(eligible)))
	for offset := 0; offset < len(eligible); offset++ {
		index := (start + offset) % len(eligible)
		conn := eligible[index]
		state := c.resolverTransportStateLocked(conn.Key)
		candidates := c.resolverTransportCandidates(conn.Key)
		if !state.availabilityDemoted || state.backgroundProbeActive || len(candidates) < 2 ||
			state.preferred == candidates[0] ||
			now.Sub(state.lastSwitch) < transportSwitchCooldown ||
			(!state.lastProbe.IsZero() && now.Sub(state.lastProbe) < transportProbeInterval) {
			continue
		}

		state.lastProbe = now
		c.transportRestoreCursor.Store(uint64(index + 1))
		c.transportRestoreCount.Add(1)
		return resolverRuntimePath{
			connection: conn,
			transport:  candidates[0],
			score:      fallbackConnectionPathScore(conn, packetType),
			hedge:      true,
		}, true
	}
	return resolverRuntimePath{}, false
}

func fallbackConnectionPathScore(conn Connection, packetType uint8) float64 {
	mtu, loss := conn.UploadMTUBytes, conn.UploadMTULoss
	switch packetType {
	case Enums.PACKET_STREAM_DATA_ACK, Enums.PACKET_STREAM_DATA_NACK, Enums.PACKET_PING:
		mtu, loss = conn.DownloadMTUBytes, conn.DownloadMTULoss
	}
	if mtu <= 0 {
		mtu = 1
	}
	delivery := 1 - loss
	if delivery < 0.01 {
		delivery = 0.01
	}
	rttMillis := float64(conn.MTUResolveTime) / float64(time.Millisecond)
	if rttMillis < 1 {
		rttMillis = 1
	}
	return float64(mtu) * delivery / rttMillis
}

// resolverNetworkGroup is a cheap failure-domain approximation used only for
// duplicate placement. A /24 for IPv4 and /48 for IPv6 keeps copies away from
// the same nearby resolver network when alternatives exist. It deliberately
// falls back to the resolver key: routing never rejects a path merely because
// an address cannot be parsed.
func resolverNetworkGroup(conn Connection) string {
	if conn.networkGroup != "" {
		return conn.networkGroup
	}
	host := strings.TrimSpace(conn.Resolver)
	if host == "" {
		host = strings.TrimSpace(conn.ResolverLabel)
		if parsedHost, _, err := net.SplitHostPort(host); err == nil {
			host = parsedHost
		}
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil {
		return "key:" + conn.Key
	}
	if v4 := ip.To4(); v4 != nil {
		return fmt.Sprintf("v4:%d.%d.%d", v4[0], v4[1], v4[2])
	}
	ip = ip.To16()
	if ip == nil {
		return "key:" + conn.Key
	}
	return fmt.Sprintf(
		"v6:%02x%02x:%02x%02x:%02x%02x",
		ip[0], ip[1], ip[2], ip[3], ip[4], ip[5],
	)
}

// bestPacketTransportLocked selects a resolver's best transport for the actual
// packet size. Unlike session-level selection, this deliberately permits a
// measured narrow path when the current packet fits it.
func (c *Client) bestPacketTransportLocked(
	serverKey string,
	state *resolverTransportState,
	packetType uint8,
	payloadSize int,
) (resolverTransport, float64, bool) {
	// The configured/preferred transport owns normal traffic while it remains
	// usable. In particular, an auto policy starts on UDP and a single startup
	// MTU probe must not move the data plane to TCP merely because that probe
	// completed faster. Runtime success samples are responsible for proving a
	// meaningful speed advantage and updating state.preferred. An alternate is
	// still selected immediately when the preferred path cannot carry this
	// concrete packet, preserving packet-size-aware routing and hard failover.
	preferred := pathScoreFor(state, state.preferred)
	if pathSupportsPacket(preferred, packetType, payloadSize) &&
		(preferred.probed ||
			(packetType != Enums.PACKET_STREAM_DATA && packetType != Enums.PACKET_STREAM_RESEND)) {
		value := pathEstimatedGoodputForPacket(preferred, packetType)
		if !preferred.probed {
			value = 0.0001
		}
		return state.preferred, value, true
	}

	var (
		best      resolverTransport
		bestScore = -1.0
		found     bool
	)
	for _, transport := range c.resolverTransportCandidates(serverKey) {
		path := pathScoreFor(state, transport)
		if !path.probed &&
			(packetType == Enums.PACKET_STREAM_DATA || packetType == Enums.PACKET_STREAM_RESEND) {
			// Never infer bulk capacity on an unmeasured transport. Startup's
			// emergency legacy fallback remains available when no measured path
			// exists, while normal joint routing keeps bulk off unknown MTUs.
			continue
		}
		if !pathSupportsPacket(path, packetType, payloadSize) {
			continue
		}
		value := pathEstimatedGoodputForPacket(path, packetType)
		// Unmeasured configured paths remain emergency candidates but never
		// outrank a measured healthy path.
		if !path.probed {
			value = 0.0001
		}
		if !found || value > bestScore {
			best, bestScore, found = transport, value, true
		}
	}
	return best, bestScore, found
}

// selectJointRuntimePaths scores resolver and transport together. Backup
// resolvers participate whenever the concrete packet fits their measured MTU,
// which converts narrow paths into useful capacity without lowering the global
// session MTU or penalizing bulk traffic on clean paths.
func (c *Client) selectJointRuntimePaths(
	packetType uint8,
	streamID uint16,
	payloadSize int,
	count int,
	now time.Time,
) []resolverRuntimePath {
	control := c.runtimePathControlDecision(packetType)
	control.copies = max(1, count)
	if control.copies > 1 {
		control.allowHealthyExplore = false
		control.allowComparableStrip = false
	}
	return c.selectJointRuntimePathsControlled(packetType, streamID, payloadSize, control, now)
}

func (c *Client) selectJointRuntimePathsControlled(
	packetType uint8,
	streamID uint16,
	payloadSize int,
	control runtimePathControl,
	now time.Time,
) []resolverRuntimePath {
	if c == nil || c.balancer == nil {
		return nil
	}
	count := control.copies
	if count < 1 {
		count = 1
	}

	connections := c.balancer.AllValidConnectionsIncludingBackup()
	// AllValidConnectionsIncludingBackup returns a private slice, so compact it
	// in place before taking resolverTransportMu. Runtime-disable inspection uses
	// resolverHealthMu; keeping the two locks unnested prevents future lock-order
	// inversions without restoring the old temporary-slice allocation.
	eligible := connections[:0]
	for _, conn := range connections {
		if conn.IsValid && conn.Key != "" && !c.isRuntimeDisabledResolver(conn.Key) {
			eligible = append(eligible, conn)
		}
	}
	connections = eligible
	paths := make([]resolverRuntimePath, 0, len(connections))

	preferredKey := ""
	if streamID != 0 &&
		(packetType == Enums.PACKET_STREAM_DATA || packetType == Enums.PACKET_STREAM_RESEND) {
		if stream, ok := c.getStream(streamID); ok && stream != nil {
			stream.resolverMu.Lock()
			preferredKey = stream.PreferredServerKey
			stream.resolverMu.Unlock()
		}
	}

	c.resolverTransportMu.Lock()
	for _, conn := range connections {
		state := c.resolverTransportStateLocked(conn.Key)
		transport, score, ok := c.bestPacketTransportLocked(conn.Key, state, packetType, payloadSize)
		if !ok {
			continue
		}
		if score <= 0.0001 {
			score = fallbackConnectionPathScore(conn, packetType)
		}
		if conn.Key == preferredKey {
			// Mild stickiness prevents reordering for statistically equivalent
			// paths while still allowing a meaningfully faster path to win.
			score *= 1.10
		}
		paths = append(paths, resolverRuntimePath{
			connection:         conn,
			transport:          transport,
			score:              score,
			directionalSamples: directionalPathSamples(pathScoreFor(state, transport), packetType),
			directionalRTT:     directionalPathRTT(pathScoreFor(state, transport), packetType),
		})
	}
	c.resolverTransportMu.Unlock()

	slices.SortStableFunc(paths, func(a, b resolverRuntimePath) int {
		if a.score == b.score {
			return strings.Compare(a.connection.Key, b.connection.Key)
		}
		if a.score > b.score {
			return -1
		}
		return 1
	})
	if len(paths) == 0 {
		return nil
	}

	// Spread successive bulk packets only across paths whose authenticated
	// foreground evidence says they are close in both delivered score and RTT.
	// ARQ already tolerates reordering, while these guards avoid feeding an
	// unknown or materially slower path merely to achieve nominal multipath.
	if control.allowComparableStrip && len(paths) > 1 {
		primary := paths[0]
		candidateIndexes := []int{0}
		weights := []uint64{100}
		totalWeight := uint64(100)
		for i := 1; i < len(paths) && len(candidateIndexes) < 4; i++ {
			if !comparableStripeCandidate(primary, paths[i], packetType) {
				continue
			}
			weight := uint64(paths[i].score / primary.score * 100)
			if weight < 1 {
				weight = 1
			}
			candidateIndexes = append(candidateIndexes, i)
			weights = append(weights, weight)
			totalWeight += weight
		}
		if len(candidateIndexes) > 1 {
			// Multiplicative stepping distributes weighted choices immediately;
			// a plain sequential ticket would send a long burst over the first
			// path before reaching the next weight range.
			ticket := ((c.pathStripeCursor.Add(1) - 1) * 0x9e3779b97f4a7c15) % totalWeight
			chosen := 0
			for i, weight := range weights {
				if ticket < weight {
					chosen = candidateIndexes[i]
					break
				}
				ticket -= weight
			}
			if chosen > 0 {
				paths[0], paths[chosen] = paths[chosen], paths[0]
				c.pathStripeCount.Add(1)
			}
		}
	}

	selected := make([]resolverRuntimePath, 0, count+1)
	hasResolver := func(key string) bool {
		for i := range selected {
			if selected[i].connection.Key == key {
				return true
			}
		}
		return false
	}
	hasDomain := func(domain string) bool {
		for i := range selected {
			if selected[i].connection.Domain == domain {
				return true
			}
		}
		return false
	}
	hasNetwork := func(network string) bool {
		for i := range selected {
			if resolverNetworkGroup(selected[i].connection) == network {
				return true
			}
		}
		return false
	}
	appendPath := func(path resolverRuntimePath) bool {
		if hasResolver(path.connection.Key) {
			return false
		}
		selected = append(selected, path)
		return true
	}

	if c.dupPreferDistinctDomains && count > 1 {
		for _, path := range paths {
			if len(selected) >= count {
				break
			}
			if hasDomain(path.connection.Domain) {
				continue
			}
			if hasNetwork(resolverNetworkGroup(path.connection)) {
				continue
			}
			appendPath(path)
		}
		// A deployment commonly has one tunnel domain but resolvers spread over
		// several networks. Preserve that diversity before filling from a shared
		// subnet, even when domain diversity is impossible.
		for _, path := range paths {
			if len(selected) >= count {
				break
			}
			if hasNetwork(resolverNetworkGroup(path.connection)) {
				continue
			}
			appendPath(path)
		}
	}
	for _, path := range paths {
		if len(selected) >= count {
			break
		}
		appendPath(path)
	}

	// Recovery races remain limited to control traffic. The globally bounded
	// healthy exploration sample may use a real data frame so speed promotion
	// compares equivalent upload traffic instead of extrapolating from ACKs.
	if len(selected) > 0 {
		primary := selected[0]
		c.resolverTransportMu.Lock()
		state := c.resolverTransportStateLocked(primary.connection.Key)
		recoveryHedge := control.allowRecoveryHedge &&
			pathNeedsHedgeLocked(state, primary.transport, now)
		healthyExplore := control.allowHealthyExplore &&
			c.healthyExplorationAvailableLocked(state)
		if (recoveryHedge || healthyExplore) &&
			(state.lastProbe.IsZero() || now.Sub(state.lastProbe) >= transportProbeInterval) {
			for _, alternate := range c.resolverTransportCandidates(primary.connection.Key) {
				if alternate == primary.transport ||
					!pathSupportsPacket(pathScoreFor(state, alternate), packetType, payloadSize) {
					continue
				}
				selected = append(selected, resolverRuntimePath{
					connection: primary.connection,
					transport:  alternate,
					score:      primary.score,
					hedge:      true,
				})
				state.lastProbe = now
				if healthyExplore {
					c.transportExploreBudgetSends.Store(c.runtimeOriginalSends.Load())
					c.transportExplorationCount.Add(1)
				}
				break
			}
		}
		c.resolverTransportMu.Unlock()
	}

	// A failed startup/configured-first path cannot pass pathSupportsPacket, and
	// the full MTU sweep intentionally waits for idle. Use a sparse real-traffic
	// canary so continuous transfers can still restore UDP. Reuse the last
	// duplicate when possible (zero extra queries); only a single-copy control
	// frame receives one bounded additional sibling.
	if !control.fecActive {
		hasHedge := false
		for _, path := range selected {
			if path.hedge {
				hasHedge = true
				break
			}
		}
		if !hasHedge {
			if restore, ok := c.availabilityRestorePath(packetType, now); ok {
				if len(selected) > 1 {
					selected[len(selected)-1] = restore
				} else if len(selected) == 1 {
					selected = append(selected, restore)
				}
			}
		}
	}
	return selected
}

func (c *Client) alternateResolverTransportForPacket(
	serverKey string,
	exclude resolverTransport,
	packetType uint8,
	payloadSize int,
) (resolverTransport, bool) {
	c.resolverTransportMu.Lock()
	defer c.resolverTransportMu.Unlock()
	state := c.resolverTransportStateLocked(serverKey)
	var (
		best      resolverTransport
		bestScore = -1.0
		found     bool
	)
	for _, transport := range c.resolverTransportCandidates(serverKey) {
		if transport == exclude {
			continue
		}
		score := pathScoreFor(state, transport)
		if !pathSupportsPacket(score, packetType, payloadSize) {
			continue
		}
		value := pathEstimatedGoodputForPacket(score, packetType)
		if !score.probed {
			value = 0.0001
		}
		if !found || value > bestScore {
			best, bestScore, found = transport, value, true
		}
	}
	return best, found
}

func (c *Client) bestResolverTransportLocked(serverKey string, state *resolverTransportState) resolverTransport {
	candidates := c.resolverTransportCandidates(serverKey)
	if len(candidates) == 0 {
		return c.activeTransport()
	}
	best := candidates[0]
	bestScore := -1.0
	for _, transport := range candidates {
		score := pathScoreFor(state, transport)
		if !c.pathSupportsSession(score) {
			continue
		}
		value := pathEstimatedGoodput(score)
		if score.failureStreak >= transportFailureSwitchThreshold {
			value *= 0.05
		}
		if value > bestScore {
			best, bestScore = transport, value
		}
	}
	if bestScore < 0 {
		for _, transport := range candidates {
			if transport == state.preferred {
				return transport
			}
		}
		return candidates[0]
	}
	return best
}

func (c *Client) chooseResolverTransport(serverKey string, priority int, now time.Time) resolverTransportDecision {
	c.resolverTransportMu.Lock()
	defer c.resolverTransportMu.Unlock()
	state := c.resolverTransportStateLocked(serverKey)
	candidates := c.resolverTransportCandidates(serverKey)
	if len(candidates) <= 1 {
		if len(candidates) == 1 {
			state.preferred = candidates[0]
		}
		return resolverTransportDecision{primary: state.preferred}
	}

	// Do not re-rank a healthy preferred path from startup probe RTT alone.
	// noteResolverTransportSuccess performs speed promotion only after both
	// paths have enough comparable runtime samples. Selection here is limited
	// to availability/failure recovery.
	current := pathScoreFor(state, state.preferred)
	if !c.pathSupportsSession(current) || current.failureStreak >= transportFailureSwitchThreshold {
		best := c.bestResolverTransportLocked(serverKey, state)
		if best != state.preferred &&
			(!current.viable || now.Sub(state.lastSwitch) >= transportSwitchCooldown) {
			previous := state.preferred
			state.preferred = best
			state.lastSwitch = now
			if len(candidates) > 0 {
				switch {
				case best == candidates[0]:
					state.availabilityDemoted = false
					state.restoreSuccesses = 0
				case previous == candidates[0]:
					state.availabilityDemoted = true
					state.restoreSuccesses = 0
				}
			}
			c.transportSwitchCount.Add(1)
		}
	}
	decision := resolverTransportDecision{primary: state.preferred}

	// A fresh passive warning may race one control/setup packet over an
	// alternate. Healthy-path comparison has a separate 0.1% foreground budget
	// and is suppressed whenever queues are busy.
	recoveryHedge := pathNeedsHedgeLocked(state, decision.primary, now)
	healthyExplore := c.healthyExplorationAvailableLocked(state)
	if priority <= Enums.PacketPriorityHigh &&
		(recoveryHedge || healthyExplore) &&
		(state.lastProbe.IsZero() || now.Sub(state.lastProbe) >= transportProbeInterval) {
		for attempts := 0; attempts < len(candidates); attempts++ {
			state.probeCursor = (state.probeCursor + 1) % len(candidates)
			alternate := candidates[state.probeCursor]
			if alternate == decision.primary || !c.pathSupportsSession(pathScoreFor(state, alternate)) {
				continue
			}
			decision.secondary = alternate
			decision.hedge = true
			state.lastProbe = now
			if healthyExplore {
				c.transportExploreBudgetSends.Store(c.runtimeOriginalSends.Load())
				c.transportExplorationCount.Add(1)
			}
			break
		}
	}
	return decision
}

func updatePathRTT(score *resolverPathScore, rtt time.Duration) {
	if score == nil {
		return
	}
	if rtt < 0 {
		rtt = 0
	}
	if score.rttEWMA == 0 {
		score.rttEWMA = rtt
		score.rttVariation = rtt / 2
		return
	}
	// RTT itself stays current on every authenticated reply. Variation changes
	// more slowly, so sample it every fourth runtime success (and every probe,
	// whose success counter is zero). This keeps the response hot path tiny and
	// prevents one jitter spike from oversteering failure deadlines.
	if score.successes == 0 || score.successes&3 == 0 {
		delta := score.rttEWMA - rtt
		if delta < 0 {
			delta = -delta
		}
		score.rttVariation = (score.rttVariation*3 + delta) / 4
	}
	score.rttEWMA = (score.rttEWMA*7 + rtt) / 8
}

func (c *Client) noteResolverTransportProbe(
	serverKey string,
	transport resolverTransport,
	result mtuConnectionProbeResult,
	ok bool,
	now time.Time,
) {
	if c == nil || serverKey == "" || !validResolverTransport(transport) {
		return
	}
	c.resolverTransportMu.Lock()
	defer c.resolverTransportMu.Unlock()
	state := c.resolverTransportStateLocked(serverKey)
	score := pathScoreFor(state, transport)
	score.probed = true
	score.viable = ok
	if ok {
		score.uploadMTU = result.UploadBytes
		score.downloadMTU = result.DownloadBytes
		score.uploadLoss = result.UploadLoss
		score.downloadLoss = result.DownloadLoss
		score.failureStreak = 0
		score.uploadFailureStreak = 0
		score.downloadFailureStreak = 0
		score.truncationStreak = 0
		score.lastSuccess = now
		updatePathRTT(score, result.ResolveTime)
		updateDirectionalRTT(&score.uploadRTTEWMA, result.ResolveTime)
		updateDirectionalRTT(&score.downloadRTTEWMA, result.ResolveTime)
	} else {
		score.lastFailure = now
	}
	// Probe results establish viability and MTU, not a speed verdict. Auto mode
	// must give its first candidate (UDP) real traffic before a faster TCP probe
	// can displace it. Move only when the current preferred path was measured
	// unusable; runtime samples or explicit failures handle later promotions.
	candidates := c.resolverTransportCandidates(serverKey)
	current := pathScoreFor(state, state.preferred)
	switch {
	case !c.pathSupportsSession(current):
		best := c.bestResolverTransportLocked(serverKey, state)
		if best != state.preferred {
			previous := state.preferred
			state.preferred = best
			state.lastSwitch = now
			if len(candidates) > 0 {
				switch {
				case best == candidates[0]:
					state.availabilityDemoted = false
					state.restoreSuccesses = 0
				case previous == candidates[0]:
					state.availabilityDemoted = true
					state.restoreSuccesses = 0
				}
			}
			c.transportSwitchCount.Add(1)
		}
	case state.availabilityDemoted && len(candidates) > 0 && state.preferred != candidates[0]:
		// Demotion costs one failed probe; without this, restoration was
		// impossible. Speed promotion is the only other route back, and it
		// requires runtime successes on the challenger — which a path that
		// carries no traffic can never accumulate. So a single transient UDP
		// probe loss moved a resolver to TCP permanently, even though the
		// background sweep keeps proving UDP viable again. Availability-driven
		// demotions are now reversed by availability-driven evidence; a
		// promotion earned on measured speed is left alone.
		if first := pathScoreFor(state, candidates[0]); first.probed && first.viable &&
			c.pathSupportsSession(first) &&
			now.Sub(state.lastSwitch) >= transportSwitchCooldown {
			state.preferred = candidates[0]
			state.lastSwitch = now
			state.availabilityDemoted = false
			state.restoreSuccesses = 0
			c.transportSwitchCount.Add(1)
		}
	}
}

// noteResolverTransportSuccess is retained for synchronous setup/probe paths
// that do not expose a packet class. Such a completed exchange proves both
// request and response delivery.
func (c *Client) noteResolverTransportSuccess(serverKey string, transport resolverTransport, rtt time.Duration, now time.Time) {
	c.noteResolverTransportSuccessClass(serverKey, transport, rtt, 0, true, now)
}

func (c *Client) noteResolverTransportSuccessForPacket(
	serverKey string,
	transport resolverTransport,
	rtt time.Duration,
	packetType uint8,
	now time.Time,
) {
	c.noteResolverTransportSuccessClass(serverKey, transport, rtt, packetType, false, now)
}

func (c *Client) noteResolverTransportSuccessClass(
	serverKey string,
	transport resolverTransport,
	rtt time.Duration,
	packetType uint8,
	bidirectional bool,
	now time.Time,
) {
	if c == nil || serverKey == "" || !validResolverTransport(transport) {
		return
	}
	c.resolverTransportMu.Lock()
	defer c.resolverTransportMu.Unlock()
	state := c.resolverTransportStateLocked(serverKey)
	score := pathScoreFor(state, transport)
	score.probed = true
	score.viable = true
	if score.uploadMTU == 0 {
		score.uploadMTU = max(1, c.syncedUploadMTU)
	}
	if score.downloadMTU == 0 {
		score.downloadMTU = max(1, c.syncedDownloadMTU)
	}
	score.successes++
	noteRuntimeDeliveryForPacket(score, true, packetType, bidirectional)
	if bidirectional || !packetUsesDownloadPath(packetType) {
		score.uploadSuccesses++
		score.uploadFailureStreak = 0
		updateDirectionalRTT(&score.uploadRTTEWMA, rtt)
	}
	if bidirectional || packetUsesDownloadPath(packetType) {
		score.downloadSuccesses++
		score.downloadFailureStreak = 0
		updateDirectionalRTT(&score.downloadRTTEWMA, rtt)
	}
	score.failureStreak = 0
	score.truncationStreak = 0
	score.lastSuccess = now
	updatePathRTT(score, rtt)

	candidates := c.resolverTransportCandidates(serverKey)
	if state.availabilityDemoted && len(candidates) > 0 &&
		state.preferred != candidates[0] && transport == candidates[0] {
		if state.restoreSuccesses < 255 {
			state.restoreSuccesses++
		}
		if state.restoreSuccesses >= transportRestoreSuccessThreshold &&
			now.Sub(state.lastSwitch) >= transportSpeedSwitchCooldown {
			state.preferred = candidates[0]
			state.lastSwitch = now
			state.availabilityDemoted = false
			state.restoreSuccesses = 0
			c.transportSwitchCount.Add(1)
			return
		}
	}

	// Preferred-path replies normally add telemetry only. Reconsider promotion
	// when a challenger delivers new evidence, or exactly when the preferred
	// path first becomes comparable. This keeps fleet-wide scoring out of the
	// per-response hot path.
	if transport == state.preferred &&
		score.uploadSuccesses != transportSpeedSampleThreshold &&
		score.downloadSuccesses != transportSpeedSampleThreshold {
		return
	}
	if now.Sub(state.lastSwitch) < transportSpeedSwitchCooldown {
		return
	}
	current := pathScoreFor(state, state.preferred)
	if current == nil ||
		current.uploadSuccesses < transportSpeedSampleThreshold ||
		current.downloadSuccesses < transportSpeedSampleThreshold {
		return
	}
	currentUpload := pathEstimatedGoodputForPacket(current, Enums.PACKET_STREAM_DATA)
	currentDownload := pathEstimatedGoodputForPacket(current, Enums.PACKET_STREAM_DATA_ACK)
	best := state.preferred
	bestCombined := currentUpload * currentDownload
	for _, candidate := range c.resolverTransportCandidates(serverKey) {
		if candidate == state.preferred {
			continue
		}
		challenger := pathScoreFor(state, candidate)
		if !c.pathSupportsSession(challenger) ||
			challenger.uploadSuccesses < transportSpeedSampleThreshold ||
			challenger.downloadSuccesses < transportSpeedSampleThreshold {
			continue
		}
		upload := pathEstimatedGoodputForPacket(challenger, Enums.PACKET_STREAM_DATA)
		download := pathEstimatedGoodputForPacket(challenger, Enums.PACKET_STREAM_DATA_ACK)
		// A resolver transport is shared by both directions. Promote it for
		// speed only when both directions improve materially; an asymmetric
		// control-path win must never slow the upload data plane.
		if upload <= currentUpload*transportSpeedSwitchRatio ||
			download <= currentDownload*transportSpeedSwitchRatio {
			continue
		}
		if combined := upload * download; combined > bestCombined {
			best, bestCombined = candidate, combined
		}
	}
	if best != state.preferred {
		state.preferred = best
		state.lastSwitch = now
		// Earned on measured speed in both directions: probe evidence must not
		// pull it back to the configured-first transport.
		state.availabilityDemoted = false
		state.restoreSuccesses = 0
		c.transportSwitchCount.Add(1)
	}
}

func (c *Client) noteResolverTransportFailure(serverKey string, transport resolverTransport, now time.Time) {
	c.noteResolverTransportFailureClass(serverKey, transport, 0, true, now)
}

func (c *Client) noteResolverTransportFailureForPacket(
	serverKey string,
	transport resolverTransport,
	packetType uint8,
	now time.Time,
) {
	c.noteResolverTransportFailureClass(serverKey, transport, packetType, false, now)
}

func (c *Client) noteResolverTransportFailureClass(
	serverKey string,
	transport resolverTransport,
	packetType uint8,
	bidirectional bool,
	now time.Time,
) {
	if c == nil || serverKey == "" || !validResolverTransport(transport) {
		return
	}
	c.resolverTransportMu.Lock()
	defer c.resolverTransportMu.Unlock()
	state := c.resolverTransportStateLocked(serverKey)
	score := pathScoreFor(state, transport)
	score.failures++
	noteRuntimeDeliveryForPacket(score, false, packetType, bidirectional)
	score.lastFailure = now
	candidates := c.resolverTransportCandidates(serverKey)
	if state.availabilityDemoted && len(candidates) > 0 && transport == candidates[0] {
		state.restoreSuccesses = 0
	}
	if score.failureStreak < 255 {
		score.failureStreak++
	}
	if bidirectional || !packetUsesDownloadPath(packetType) {
		if score.uploadFailureStreak < 255 {
			score.uploadFailureStreak++
		}
	}
	if bidirectional || packetUsesDownloadPath(packetType) {
		if score.downloadFailureStreak < 255 {
			score.downloadFailureStreak++
		}
	}
	// Make the next eligible control packet perform one useful alternate race.
	// pathNeedsHedgeLocked prevents periodic duplication after that evidence has
	// been consumed.
	state.lastProbe = time.Time{}
	requiredFailures := uint8(transportFailureSwitchThreshold)
	if !score.lastPoison.IsZero() {
		poisonAge := now.Sub(score.lastPoison)
		// Timeout observations carry their scheduled deadline, which can be a
		// few milliseconds earlier than the wall-clock poison arrival processed
		// beside it. Treat that ordering as simultaneous, not stale/future.
		if poisonAge < 0 {
			poisonAge = 0
		}
		if poisonAge <= transportPoisonMemory {
			requiredFailures = 1
		}
	}
	if state.preferred != transport || score.failureStreak < requiredFailures ||
		now.Sub(state.lastSwitch) < transportSwitchCooldown {
		return
	}
	best := c.bestResolverTransportLocked(serverKey, state)
	if best == transport {
		for _, candidate := range c.resolverTransportCandidates(serverKey) {
			if candidate != transport && c.pathSupportsSession(pathScoreFor(state, candidate)) {
				best = candidate
				break
			}
		}
	}
	if best != transport && c.pathSupportsSession(pathScoreFor(state, best)) {
		state.preferred = best
		state.lastSwitch = now
		if len(candidates) > 0 && transport == candidates[0] {
			state.availabilityDemoted = true
			state.restoreSuccesses = 0
		}
		c.transportSwitchCount.Add(1)
	}
}

// noteResolverTransportTruncation treats TC=1 as a capacity observation, not
// proof that UDP is dead. The affected request is replayed immediately, while
// UDP remains preferred unless truncation repeats without an intervening valid
// reply. This preserves UDP speed through occasional oversized DNS answers.
func (c *Client) noteResolverTransportTruncation(serverKey string, transport resolverTransport, now time.Time) {
	if c == nil || serverKey == "" || !validResolverTransport(transport) {
		return
	}
	c.resolverTransportMu.Lock()
	defer c.resolverTransportMu.Unlock()
	state := c.resolverTransportStateLocked(serverKey)
	score := pathScoreFor(state, transport)
	score.truncations++
	score.lastTruncation = now
	if score.truncationStreak < 255 {
		score.truncationStreak++
	}
	state.lastProbe = time.Time{}
	if state.preferred != transport || score.truncationStreak < transportTruncationThreshold {
		return
	}
	for _, candidate := range c.resolverTransportCandidates(serverKey) {
		if candidate == transport {
			continue
		}
		alternate := pathScoreFor(state, candidate)
		if !alternate.probed || alternate.viable {
			state.preferred = candidate
			state.lastSwitch = now
			state.lastProbe = time.Time{}
			candidates := c.resolverTransportCandidates(serverKey)
			if len(candidates) > 0 && transport == candidates[0] {
				state.availabilityDemoted = true
				state.restoreSuccesses = 0
			}
			c.transportSwitchCount.Add(1)
			return
		}
	}
}

func (c *Client) noteResolverTransportPoison(serverKey string, transport resolverTransport) {
	if c == nil || serverKey == "" || !validResolverTransport(transport) {
		return
	}
	c.resolverTransportMu.Lock()
	defer c.resolverTransportMu.Unlock()
	state := c.resolverTransportStateLocked(serverKey)
	score := pathScoreFor(state, transport)
	score.poisonEvents++
	score.lastPoison = c.now()
	// Poison alone is not failure: if the authenticated answer still wins
	// quickly, the poisoned environment remains usable. Force a prompt alternate
	// comparison; timeout/RTT decides whether to leave the path.
	state.lastProbe = time.Time{}
}

func (c *Client) preferredResolverTransport(serverKey string) resolverTransport {
	return c.chooseResolverTransport(serverKey, Enums.PacketPriorityNormal, c.now()).primary
}

func (c *Client) orderedResolverTransports(serverKey string) []resolverTransport {
	c.resolverTransportMu.Lock()
	defer c.resolverTransportMu.Unlock()
	state := c.resolverTransportStateLocked(serverKey)
	candidates := c.resolverTransportCandidates(serverKey)
	out := make([]resolverTransport, 0, len(candidates))
	if validResolverTransport(state.preferred) {
		out = append(out, state.preferred)
	}
	for _, transport := range candidates {
		if transport != state.preferred {
			out = append(out, transport)
		}
	}
	return out
}

func (c *Client) runtimeTransportsNeeded() map[resolverTransport]bool {
	needed := make(map[resolverTransport]bool)
	if c == nil || len(c.connections) == 0 {
		for _, transport := range resolverTransportChain(c.cfg.ResolverTransport) {
			needed[transport] = true
		}
		return needed
	}
	for _, conn := range c.connections {
		for _, transport := range c.resolverTransportCandidates(conn.Key) {
			needed[transport] = true
		}
	}
	return needed
}

func (c *Client) transportBackgroundScanInterval() time.Duration {
	if c == nil || c.cfg.ResolverTransportBackgroundScanIntervalSec <= 0 {
		return 30 * time.Second
	}
	return time.Duration(c.cfg.ResolverTransportBackgroundScanIntervalSec * float64(time.Second))
}

func (c *Client) resolverTransportSummary() string {
	if c == nil {
		return "unknown"
	}
	if !c.perResolverAutoTransport() {
		return c.activeTransport().String()
	}
	var counts [4]int
	c.resolverTransportMu.Lock()
	for _, conn := range c.connections {
		if !conn.IsValid {
			continue
		}
		transport := c.resolverTransportStateLocked(conn.Key).preferred
		if validResolverTransport(transport) {
			counts[int(transport)]++
		}
	}
	c.resolverTransportMu.Unlock()
	return fmt.Sprintf("adaptive UDP=%d TCP=%d DoT=%d DoH=%d",
		counts[transportUDP], counts[transportTCP], counts[transportDoT], counts[transportDoH])
}
