// ==============================================================================
// CottenpickDNS
// Author: tajirax
// Github: https://github.com/TaJirax/cottenpickDNS
// Year: 2026
// ==============================================================================
// mtu_cluster.go — Layer 2 of the adaptive per-group MTU strategy: cluster the
// valid resolvers into groups that share a similar viable MTU range, so a future
// Layer 3 can run each group at the largest MTU it can sustain instead of
// forcing the global minimum on everyone.
//
// Clustering is 1-D gap-based banding over each resolver's viable *download* MTU
// (the session-limiting, server-driven direction): the valid connections are
// sorted by download MTU and a new group is cut wherever the gap between two
// consecutive values exceeds gapRatio of the larger value. Each group's applied
// MTU is the minimum within the group, so every member can sustain it.
//
// This is intentionally read-only today: clusterConnectionsByMTU is a pure
// function and the result is logged/stored but does not yet drive routing.
// ==============================================================================

package client

import "sort"

// mtuGroup is a cluster of resolver connections that share a similar viable MTU
// range. UploadMTU/DownloadMTU are the safe (minimum) values across the group's
// members, so every member can carry them.
type mtuGroup struct {
	UploadMTU   int
	DownloadMTU int
	Members     []Connection
}

// clusterConnectionsByMTU groups valid connections into MTU bands. It considers
// only connections with IsValid set and a positive download MTU. The returned
// groups are sorted by DownloadMTU descending (largest-capacity group first).
// The input slice is not mutated.
//
// gapRatio is the relative gap (0..1) that starts a new band: a new group begins
// when (next-prev) > gapRatio*next over the ascending-sorted download MTUs. A
// non-positive gapRatio falls back to 0.25.
func clusterConnectionsByMTU(conns []Connection, gapRatio float64) []mtuGroup {
	if gapRatio <= 0 {
		gapRatio = 0.25
	}

	valid := make([]Connection, 0, len(conns))
	for _, conn := range conns {
		if conn.IsValid && conn.DownloadMTUBytes > 0 {
			valid = append(valid, conn)
		}
	}
	if len(valid) == 0 {
		return nil
	}

	sort.SliceStable(valid, func(i, j int) bool {
		return valid[i].DownloadMTUBytes < valid[j].DownloadMTUBytes
	})

	var groups []mtuGroup
	current := []Connection{valid[0]}
	for i := 1; i < len(valid); i++ {
		prev := valid[i-1].DownloadMTUBytes
		next := valid[i].DownloadMTUBytes
		gap := next - prev
		if float64(gap) > gapRatio*float64(next) {
			groups = append(groups, buildMTUGroup(current))
			current = []Connection{valid[i]}
			continue
		}
		current = append(current, valid[i])
	}
	groups = append(groups, buildMTUGroup(current))

	// Largest-capacity group first.
	sort.SliceStable(groups, func(i, j int) bool {
		return groups[i].DownloadMTU > groups[j].DownloadMTU
	})
	return groups
}

// selectMTUOperatingPoint chooses the throughput-optimal session MTU over the
// valid connections (Layer 3, "best-group" strategy). For every distinct viable
// download MTU D it forms the pool of resolvers that can sustain D and scores it
// as D × len(pool); the winning D balances per-packet size against resolver
// count, so a few slow resolvers cannot throttle the session and a single fast
// outlier cannot strand the crowd. It returns the chosen upload/download MTU
// (the safe minimum within the winning pool) and the pool size. Returns zeros
// when there is nothing to choose from.
func selectMTUOperatingPoint(conns []Connection) (uploadMTU, downloadMTU, poolSize int) {
	type cand struct{ upload, download int }
	cands := make([]cand, 0, len(conns))
	for _, c := range conns {
		if c.IsValid && c.DownloadMTUBytes > 0 && c.UploadMTUBytes > 0 {
			cands = append(cands, cand{c.UploadMTUBytes, c.DownloadMTUBytes})
		}
	}
	if len(cands) == 0 {
		return 0, 0, 0
	}

	seen := make(map[int]struct{}, len(cands))
	bestScore := -1
	for _, candidate := range cands {
		d := candidate.download
		if _, dup := seen[d]; dup {
			continue
		}
		seen[d] = struct{}{}

		pool := 0
		minUpload := 0
		for _, c := range cands {
			if c.download < d {
				continue
			}
			pool++
			if minUpload == 0 || c.upload < minUpload {
				minUpload = c.upload
			}
		}
		score := d * pool
		// Prefer higher score; tie-break toward the larger MTU (faster per packet).
		if score > bestScore || (score == bestScore && d > downloadMTU) {
			bestScore = score
			downloadMTU = d
			uploadMTU = minUpload
			poolSize = pool
		}
	}
	return uploadMTU, downloadMTU, poolSize
}

// buildMTUGroup computes a group's safe (minimum) upload/download MTU across its
// members. Upload MTU ignores members reporting 0 (upload not measured), but
// falls back to the minimum seen so the value is never larger than any member.
func buildMTUGroup(members []Connection) mtuGroup {
	g := mtuGroup{Members: members}
	for i, m := range members {
		if i == 0 || m.DownloadMTUBytes < g.DownloadMTU {
			g.DownloadMTU = m.DownloadMTUBytes
		}
		if m.UploadMTUBytes > 0 {
			if g.UploadMTU == 0 || m.UploadMTUBytes < g.UploadMTU {
				g.UploadMTU = m.UploadMTUBytes
			}
		}
	}
	return g
}
