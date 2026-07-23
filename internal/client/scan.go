package client

import (
	"context"
	"errors"
)

type ResolverScanSummary struct {
	Total    int
	Valid    int
	Rejected int
}

// RunResolverScan classifies resolvers without starting listeners or a session.
func (c *Client) RunResolverScan(ctx context.Context) (ResolverScanSummary, error) {
	defer c.closeResolverCacheLog()
	summary := ResolverScanSummary{Total: len(c.connections)}
	if summary.Total == 0 {
		c.logResolverScanComplete(summary)
		return summary, nil
	}
	// Scan-only must classify the complete fleet even when the profile normally
	// enables Fast Connect.
	fastConnect := c.cfg.FastConnect
	c.cfg.FastConnect = false
	err := c.RunInitialMTUTests(ctx)
	c.cfg.FastConnect = fastConnect
	if err != nil && !errors.Is(err, ErrNoValidConnections) {
		return summary, err
	}
	if err := ctx.Err(); err != nil {
		return summary, err
	}
	for _, conn := range c.connections {
		if conn.ResolverLabel == "" || c.log == nil {
			continue
		}
		if conn.UploadMTUBytes > 0 && conn.DownloadMTUBytes > 0 {
			c.log.Machinef("WD_SCAN event=valid resolver=%s", conn.ResolverLabel)
		} else {
			c.log.Machinef("WD_SCAN event=rejected resolver=%s", conn.ResolverLabel)
		}
	}
	valid, _, _, _ := summarizeValidMTUConnections(c.connections)
	summary.Valid = len(valid)
	summary.Rejected = summary.Total - summary.Valid
	c.logResolverScanComplete(summary)
	return summary, nil
}

func (c *Client) logResolverScanComplete(summary ResolverScanSummary) {
	if c == nil || c.log == nil {
		return
	}
	c.log.Machinef("WD_SCAN event=complete total=%d valid=%d rejected=%d",
		summary.Total, summary.Valid, summary.Rejected)
}
