// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================
// Package client provides the core logic for the CottenDns client.
// This file (resolver_runtime_state.go) emits the machine-readable WD_RESOLVERS
// status line consumed by embedding clients (e.g. the WhiteDNS Android app) to
// render live resolver state. It is emitted on resolver-set changes and on a
// periodic heartbeat, with duplicate suppression in between.
// ==============================================================================
package client

import (
	"fmt"
	"slices"
	"strings"
	"time"
)

const resolverRuntimeStateHeartbeatInterval = 30 * time.Second

// logResolverRuntimeState emits a WD_RESOLVERS line describing the currently
// active and MTU-valid resolvers. It is a no-op without a logger and suppresses
// unchanged lines until the heartbeat interval elapses.
func (c *Client) logResolverRuntimeState() {
	if c == nil || c.log == nil {
		return
	}
	active, standby, valid := c.resolverRuntimeSnapshot()
	line := c.resolverRuntimeStateLogLine(active, standby, valid)
	if !c.shouldEmitResolverRuntimeState(line, c.now()) {
		return
	}
	c.log.Machinef("%s", line)
}

func (c *Client) resolverRuntimeStateLogLine(active []string, standby []string, valid []string) string {
	return fmt.Sprintf(
		"WD_RESOLVERS active=%s standby=%s valid=%s",
		formatResolverRuntimeList(active),
		formatResolverRuntimeList(standby),
		formatResolverRuntimeList(valid),
	)
}

func (c *Client) shouldEmitResolverRuntimeState(line string, now time.Time) bool {
	if c == nil || line == "" {
		return false
	}
	c.resolverRuntimeLogMu.Lock()
	defer c.resolverRuntimeLogMu.Unlock()

	isHeartbeatDue := c.lastResolverRuntimeLogAt.IsZero() ||
		now.Sub(c.lastResolverRuntimeLogAt) >= resolverRuntimeStateHeartbeatInterval
	if line == c.lastResolverRuntimeLog && !isHeartbeatDue {
		return false
	}

	c.lastResolverRuntimeLog = line
	c.lastResolverRuntimeLogAt = now
	return true
}

func (c *Client) resolverRuntimeSnapshot() (active []string, standby []string, valid []string) {
	if c == nil {
		return nil, nil, nil
	}
	active = make([]string, 0, len(c.connections))
	valid = make([]string, 0, len(c.connections))

	for _, conn := range c.connections {
		if conn.Key == "" || conn.ResolverLabel == "" {
			continue
		}
		if conn.UploadMTUBytes > 0 && conn.DownloadMTUBytes > 0 {
			valid = append(valid, conn.ResolverLabel)
		}
		if conn.IsValid {
			active = append(active, conn.ResolverLabel)
		}
	}

	slices.Sort(active)
	slices.Sort(valid)
	return active, nil, valid
}

func formatResolverRuntimeList(values []string) string {
	if len(values) == 0 {
		return "-"
	}
	return strings.Join(values, ",")
}
