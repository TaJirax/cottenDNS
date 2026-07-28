package client

import (
	"time"

	Enums "cottendns-go/internal/enums"
)

const (
	pathStripeMinimumScoreRatio = 0.85
	pathStripeMaximumRTTRatio   = 1.35
)

// runtimePathControl is the single per-packet decision shared by duplication,
// FEC coordination, exploration, recovery hedging and optional path striping.
// It changes no wire fields. Congestion suppresses only automatically-added
// copies; the established download-FEC cap still prevents stacked redundancy.
type runtimePathControl struct {
	copies               int
	congested            bool
	fecActive            bool
	allowHealthyExplore  bool
	allowRecoveryHedge   bool
	allowComparableStrip bool
}

func (c *Client) runtimeQueuesCongested() bool {
	if c == nil {
		return false
	}
	busy := func(length, capacity int) bool {
		return capacity > 0 && length >= max(1, capacity/4)
	}
	return busy(len(c.txChannel), cap(c.txChannel)) ||
		busy(len(c.encodedTXChannel), cap(c.encodedTXChannel)) ||
		busy(len(c.rxChannel), cap(c.rxChannel))
}

func (c *Client) runtimePathControlDecision(packetType uint8) runtimePathControl {
	if c == nil {
		return runtimePathControl{copies: 1}
	}

	base := c.configuredPacketDuplicationCount(packetType)
	copies := base
	if c.cfg.AdaptiveDuplication {
		if lossPM := c.runtimeLossPerMille(); lossPM > 0 {
			copies = duplicationForLoss(
				base,
				float64(lossPM)/1000.0,
				c.cfg.AdaptiveDuplicationTargetDelivery,
			)
		}
	}

	priority := Enums.DefaultPacketPriority(packetType)
	fecActive := packetUsesDownloadPath(packetType) && c.fecRecentlyActive()
	if fecActive && copies > 2 {
		c.pathRedundancySuppressed.Add(uint64(copies - 2))
		copies = 2
	}
	if copies < 1 {
		copies = 1
	}

	if c.cfg.PathControllerMode == "legacy" {
		return runtimePathControl{
			copies:              copies,
			fecActive:           fecActive,
			allowHealthyExplore: true,
			allowRecoveryHedge:  priority <= Enums.PacketPriorityHigh,
		}
	}

	congested := c.runtimeQueuesCongested()
	// Preserve every explicit user-requested copy. During queue pressure, only
	// remove copies that adaptive duplication added automatically; otherwise
	// redundancy can deepen the very congestion it is trying to repair.
	if congested && priority > Enums.PacketPriorityHigh && copies > base {
		c.pathRedundancySuppressed.Add(uint64(copies - base))
		copies = base
	}

	bulkUpload := packetType == Enums.PACKET_STREAM_DATA || packetType == Enums.PACKET_STREAM_RESEND

	return runtimePathControl{
		copies:              copies,
		congested:           congested,
		fecActive:           fecActive,
		allowHealthyExplore: !congested && !fecActive && copies == 1,
		allowRecoveryHedge:  priority <= Enums.PacketPriorityHigh,
		allowComparableStrip: c.cfg.ComparablePathStriping &&
			bulkUpload && copies == 1 && !congested,
	}
}

func directionalPathSamples(score *resolverPathScore, packetType uint8) uint32 {
	if score == nil {
		return 0
	}
	if !score.directionalEvidence {
		return score.runtimeSamples
	}
	if packetUsesDownloadPath(packetType) {
		return score.downloadRuntimeSamples
	}
	return score.uploadRuntimeSamples
}

func directionalPathRTT(score *resolverPathScore, packetType uint8) time.Duration {
	if score == nil {
		return 0
	}
	if !score.directionalEvidence {
		return score.rttEWMA
	}
	rtt := score.uploadRTTEWMA
	if packetUsesDownloadPath(packetType) {
		rtt = score.downloadRTTEWMA
	}
	if rtt <= 0 {
		rtt = score.rttEWMA
	}
	return rtt
}

func comparableStripeCandidate(primary, candidate resolverRuntimePath, _ uint8) bool {
	if primary.directionalSamples < transportSpeedSampleThreshold ||
		candidate.directionalSamples < transportSpeedSampleThreshold {
		return false
	}
	if candidate.score < primary.score*pathStripeMinimumScoreRatio {
		return false
	}
	primaryRTT := primary.directionalRTT
	candidateRTT := candidate.directionalRTT
	if primaryRTT <= 0 || candidateRTT <= 0 {
		return false
	}
	ratio := float64(candidateRTT) / float64(primaryRTT)
	if ratio < 1 {
		ratio = 1 / ratio
	}
	return ratio <= pathStripeMaximumRTTRatio
}
