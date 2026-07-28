package client

import (
	"fmt"
	"testing"
	"time"

	Enums "cottendns-go/internal/enums"
)

// BenchmarkResolverTransportDecisionHealthy measures the foreground cost of
// auto-transport selection and exposes unintended duplicate health traffic as
// a custom metric. Advancing beyond the probe interval each iteration makes a
// periodic-probe implementation visible without sleeping.
func BenchmarkResolverTransportDecisionHealthy(b *testing.B) {
	c := newAutoTransportPolicyClient()
	now := time.Now()
	hedges := 0
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if c.chooseResolverTransport(
			"resolver-a",
			Enums.PacketPriorityCritical,
			now.Add(time.Duration(i)*3*time.Second),
		).hedge {
			hedges++
		}
	}
	b.StopTimer()
	b.ReportMetric(float64(hedges)/float64(b.N), "hedges/op")
}

func BenchmarkResolverTransportPassiveSuccess(b *testing.B) {
	c := newAutoTransportPolicyClient()
	now := time.Now()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.noteResolverTransportSuccess(
			"resolver-a",
			transportUDP,
			80*time.Millisecond+time.Duration(i&15)*time.Millisecond,
			now,
		)
	}
}

func BenchmarkRuntimePathControlClean(b *testing.B) {
	c := newAutoTransportPolicyClient()
	c.cfg.UploadPacketDuplicationCount = 1
	c.cfg.DownloadPacketDuplicationCount = 1
	c.cfg.UploadSetupPacketDuplicationCount = 1
	c.cfg.DownloadSetupPacketDuplicationCount = 1
	c.cfg.AdaptiveDuplication = true
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		plan := c.runtimePathControlDecision(Enums.PACKET_STREAM_DATA)
		if plan.copies != 1 {
			b.Fatalf("copies=%d, want 1", plan.copies)
		}
	}
}

func BenchmarkJointRuntimePathSelectionSixteenResolvers(b *testing.B) {
	c := newAutoTransportPolicyClient()
	c.dupPreferDistinctDomains = true
	c.connections = make([]Connection, 16)
	c.connectionsByKey = make(map[string]int, len(c.connections))
	pointers := make([]*Connection, len(c.connections))
	now := time.Now()
	for i := range c.connections {
		key := fmt.Sprintf("resolver-%02d", i)
		ip := fmt.Sprintf("192.0.%d.%d", i/2, 10+i)
		c.connections[i] = Connection{
			Key: key, Domain: fmt.Sprintf("tunnel-%d.example", i%4),
			Resolver: ip, ResolverLabel: ip + ":53", IsValid: true,
			UploadMTUBytes: 200, DownloadMTUBytes: 1200,
			MTUResolveTime: 50*time.Millisecond + time.Duration(i)*time.Millisecond,
		}
		c.connections[i].networkGroup = resolverNetworkGroup(c.connections[i])
		c.connectionsByKey[key] = i
		pointers[i] = &c.connections[i]
	}
	c.balancer = NewBalancer(BalancingRoundRobinDefault)
	c.balancer.SetConnections(pointers)
	for i := range c.connections {
		c.noteResolverTransportProbe(c.connections[i].Key, transportUDP, mtuConnectionProbeResult{
			UploadBytes: 200, DownloadBytes: 1200,
			ResolveTime: c.connections[i].MTUResolveTime,
		}, true, now)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if selected := c.selectJointRuntimePaths(
			Enums.PACKET_STREAM_DATA,
			0,
			100,
			2,
			now,
		); len(selected) != 2 {
			b.Fatalf("selected=%d, want 2", len(selected))
		}
	}
}
