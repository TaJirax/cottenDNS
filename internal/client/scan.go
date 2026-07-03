// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================
// Package client provides the core logic for the CottenDns client.
// This file (scan.go) implements resolver scan-only mode: it runs the normal
// MTU scan to classify resolvers, emits machine-readable WD_SCAN telemetry
// consumed by embedding clients (e.g. the WhiteDNS Android scan screen), and
// exits without starting the local SOCKS/DNS listeners, session, or tunnel.
// ==============================================================================
package client

import (
	"context"
	"errors"
)

// ResolverScanSummary reports the outcome of a resolver scan.
type ResolverScanSummary struct {
	Total    int
	Valid    int
	Rejected int
}

// RunResolverScan performs a blocking resolver scan and returns without starting
// the tunnel runtime. It reuses the standard MTU scan (which already emits
// WD_PROGRESS) to classify every resolver-domain pair, then emits per-resolver
// WD_SCAN valid/rejected events and a final completion summary.
func (c *Client) RunResolverScan(ctx context.Context) (ResolverScanSummary, error) {
	defer c.closeResolverCacheLog()

	total := len(c.connections)
	summary := ResolverScanSummary{Total: total}
	if total == 0 {
		c.logResolverScanComplete(summary)
		return summary, nil
	}

	// Reuse the real MTU scan to populate per-connection validity and MTU.
	// ErrNoValidConnections is an expected scan outcome, not a hard failure.
	if err := c.RunInitialMTUTests(ctx); err != nil && !errors.Is(err, ErrNoValidConnections) {
		return summary, err
	}
	if err := ctx.Err(); err != nil {
		return summary, err
	}

	for idx := range c.connections {
		conn := c.connections[idx]
		if conn.ResolverLabel == "" {
			continue
		}
		if conn.UploadMTUBytes > 0 && conn.DownloadMTUBytes > 0 {
			c.logResolverScanValid(conn)
		} else {
			c.logResolverScanRejected(conn)
		}
	}

	validConns, _, _, _ := summarizeValidMTUConnections(c.connections)
	summary.Valid = len(validConns)
	summary.Rejected = total - summary.Valid

	c.logResolverScanComplete(summary)
	return summary, nil
}

func (c *Client) logResolverScanValid(conn Connection) {
	if c == nil || c.log == nil || conn.ResolverLabel == "" {
		return
	}
	c.log.Machinef("WD_SCAN event=valid resolver=%s", conn.ResolverLabel)
}

func (c *Client) logResolverScanRejected(conn Connection) {
	if c == nil || c.log == nil || conn.ResolverLabel == "" {
		return
	}
	c.log.Machinef("WD_SCAN event=rejected resolver=%s", conn.ResolverLabel)
}

func (c *Client) logResolverScanComplete(summary ResolverScanSummary) {
	if c == nil || c.log == nil {
		return
	}
	c.log.Machinef(
		"WD_SCAN event=complete total=%d valid=%d rejected=%d",
		summary.Total,
		summary.Valid,
		summary.Rejected,
	)
}
