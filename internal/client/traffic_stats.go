// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================
// Package client provides the core logic for the CottenDns client.
// This file (traffic_stats.go) implements the periodic traffic speed and total
// bytes reporter that prints to the console log window.
// ==============================================================================

package client

import (
	"context"
	"fmt"
	"time"
)

// formatBytes formats a raw byte count into a human-readable size string.
func formatBytes(n uint64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.2f GB", float64(n)/float64(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.2f MB", float64(n)/float64(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.2f KB", float64(n)/float64(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}

// formatSpeed formats a bytes-per-second value into a human-readable speed string.
func formatSpeed(bytesPerSec float64) string {
	switch {
	case bytesPerSec >= float64(1<<30):
		return fmt.Sprintf("%.2f GB/s", bytesPerSec/float64(1<<30))
	case bytesPerSec >= float64(1<<20):
		return fmt.Sprintf("%.2f MB/s", bytesPerSec/float64(1<<20))
	case bytesPerSec >= float64(1<<10):
		return fmt.Sprintf("%.2f KB/s", bytesPerSec/float64(1<<10))
	default:
		return fmt.Sprintf("%.0f B/s", bytesPerSec)
	}
}

type trafficStatsSnapshot struct {
	upBytesPerSecond   uint64
	upTotal            uint64
	downBytesPerSecond uint64
	downTotal          uint64
	lossPerMille       uint64
	activeResolvers    int
	transportSummary   string
	explorations       uint64
	restorations       uint64
	switches           uint64
	stripes            uint64
	redundancySaved    uint64
	txQueue            int
	encodedTXQueue     int
	rxQueue            int
	rxDrops            uint64
	txDrops            uint64
	recoveries         uint64
	streamDialFailures uint64
	streamWriteFailure uint64
}

// formatTrafficStatsMachineLine is the stable embedding boundary consumed by
// Android and other native clients. Raw counters avoid locale/unit parsing, and
// Machinef makes the line available even when the human log level is WARN or
// ERROR. This is local stdout/file telemetry only; it sends no tunnel traffic.
func formatTrafficStatsMachineLine(stats trafficStatsSnapshot) string {
	return fmt.Sprintf(
		"WD_STATS up_bps=%d up_total=%d down_bps=%d down_total=%d loss_pm=%d resolvers=%d transport=%q explore=%d restore=%d switch=%d stripe=%d saved=%d queue_tx=%d queue_encoded=%d queue_rx=%d drop_rx=%d drop_tx=%d recoveries=%d stream_dial_fail=%d stream_write_fail=%d",
		stats.upBytesPerSecond,
		stats.upTotal,
		stats.downBytesPerSecond,
		stats.downTotal,
		stats.lossPerMille,
		stats.activeResolvers,
		stats.transportSummary,
		stats.explorations,
		stats.restorations,
		stats.switches,
		stats.stripes,
		stats.redundancySaved,
		stats.txQueue,
		stats.encodedTXQueue,
		stats.rxQueue,
		stats.rxDrops,
		stats.txDrops,
		stats.recoveries,
		stats.streamDialFailures,
		stats.streamWriteFailure,
	)
}

// runTrafficStatsReporter periodically logs upload/download speed and session
// totals to the console. It runs as a goroutine inside the async runtime and
// exits when ctx is cancelled.
func (c *Client) runTrafficStatsReporter(ctx context.Context) {
	interval := c.cfg.StatsReportInterval()
	if interval <= 0 {
		return
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	var lastTX, lastRX uint64
	lastTime := time.Now()

	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			currentTX := c.txTotalBytes.Load()
			currentRX := c.rxTotalBytes.Load()

			elapsed := now.Sub(lastTime).Seconds()
			var upSpeed, downSpeed float64
			if elapsed > 0 {
				upSpeed = float64(currentTX-lastTX) / elapsed
				downSpeed = float64(currentRX-lastRX) / elapsed
			}

			lastTX = currentTX
			lastRX = currentRX
			lastTime = now

			if c.log != nil {
				lossPM := c.tunnelLossPerMille()
				activeResolvers := c.balancer.ValidCount()
				c.log.Machinef("%s", formatTrafficStatsMachineLine(trafficStatsSnapshot{
					upBytesPerSecond:   uint64(upSpeed),
					upTotal:            currentTX,
					downBytesPerSecond: uint64(downSpeed),
					downTotal:          currentRX,
					lossPerMille:       lossPM,
					activeResolvers:    activeResolvers,
					transportSummary:   c.resolverTransportSummary(),
					explorations:       c.transportExplorationCount.Load(),
					restorations:       c.transportRestoreCount.Load(),
					switches:           c.transportSwitchCount.Load(),
					stripes:            c.pathStripeCount.Load(),
					redundancySaved:    c.pathRedundancySuppressed.Load(),
					txQueue:            len(c.txChannel),
					encodedTXQueue:     len(c.encodedTXChannel),
					rxQueue:            len(c.rxChannel),
					rxDrops:            c.rxDroppedPackets.Load(),
					txDrops:            c.txAdmissionDrops.Load(),
					recoveries:         c.transportRecoveryCount.Load(),
					streamDialFailures: c.streamDialFailures.Load(),
					streamWriteFailure: c.streamWriteFailures.Load(),
				}))
				c.log.Infof(
					"\U0001F4CA <cyan>↑</cyan> <yellow>%s</yellow> <gray>(Total: %s)</gray> <magenta>|</magenta> <cyan>↓</cyan> <yellow>%s</yellow> <gray>(Total: %s)</gray> <magenta>|</magenta> <cyan>loss</cyan> <yellow>%.1f%%</yellow> <magenta>|</magenta> <cyan>resolvers</cyan> <yellow>%d</yellow> <magenta>|</magenta> <cyan>transport</cyan> <yellow>%s</yellow> <magenta>|</magenta> <cyan>path-events</cyan> <yellow>explore=%d restore=%d switch=%d stripe=%d saved=%d</yellow> <magenta>|</magenta> <cyan>queues</cyan> <yellow>%d/%d/%d</yellow> <magenta>|</magenta> <cyan>drops</cyan> <yellow>rx=%d tx=%d</yellow> <magenta>|</magenta> <cyan>recoveries</cyan> <yellow>%d</yellow> <magenta>|</magenta> <cyan>stream-fail</cyan> <yellow>dial=%d write=%d</yellow>",
					formatSpeed(upSpeed),
					formatBytes(currentTX),
					formatSpeed(downSpeed),
					formatBytes(currentRX),
					float64(lossPM)/10.0,
					activeResolvers,
					c.resolverTransportSummary(),
					c.transportExplorationCount.Load(), c.transportRestoreCount.Load(), c.transportSwitchCount.Load(),
					c.pathStripeCount.Load(), c.pathRedundancySuppressed.Load(),
					len(c.txChannel), len(c.encodedTXChannel), len(c.rxChannel),
					c.rxDroppedPackets.Load(), c.txAdmissionDrops.Load(),
					c.transportRecoveryCount.Load(),
					c.streamDialFailures.Load(), c.streamWriteFailures.Load(),
				)
			}
		}
	}
}
