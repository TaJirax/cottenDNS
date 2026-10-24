package client

import (
	"context"
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"

	dnsCache "cottendns-go/internal/dnscache"
	dnsParser "cottendns-go/internal/dnsparser"
	VpnProto "cottendns-go/internal/vpnproto"
)

func deliveryQuery(id uint16) []byte {
	query := []byte{0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 5, 'f', 'i', 'r', 's', 't', 4, 't', 'e', 's', 't', 0, 0, 1, 0, 1}
	binary.BigEndian.PutUint16(query[:2], id)
	return query
}

func deliveryClient(t *testing.T) *Client {
	c := createTestClient(t)
	c.log = nil
	c.sessionReady = true
	t.Cleanup(c.clearPendingDNSQueries)
	return c
}

func deliverDNS(t *testing.T, c *Client, query []byte, sn uint16) {
	t.Helper()
	response, err := dnsParser.BuildEmptyNoErrorResponse(query)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.HandleDNSQueryRes(VpnProto.Packet{SequenceNum: sn, TotalFragments: 1, Payload: response}); err != nil {
		t.Fatal(err)
	}
}

func TestDNSDeliveryPreservesEachWaiterAndReusedBuffer(t *testing.T) {
	c := deliveryClient(t)
	responses := make(chan []byte, 64)
	for i := 0; i < 32; i++ {
		query := deliveryQuery(uint16(i + 1))
		if i%2 == 1 {
			query[3] |= 0x10
		}
		c.ProcessDNSQuery(query, nil, func(p []byte) { responses <- p })
		for j := range query {
			query[j] = 0xff
		}
	}
	deliverDNS(t, c, deliveryQuery(999), 12)
	for i := 0; i < 32; i++ {
		select {
		case response := <-responses:
			id := binary.BigEndian.Uint16(response[:2])
			if id != uint16(i+1) {
				t.Fatalf("wrong ID %d", id)
			}
			if (response[3]&0x10 != 0) != (i%2 == 1) {
				t.Fatal("query flags lost")
			}
		case <-time.After(time.Second):
			t.Fatal("coalesced waiter did not receive response")
		}
	}
	deliverDNS(t, c, deliveryQuery(999), 13)
	select {
	case <-responses:
		t.Fatal("duplicate delivery")
	default:
	}
	if c.pendingDNS.total != 0 || len(c.pendingDNS.groups) != 0 {
		t.Fatal("completed callbacks retained")
	}
}

func TestDNSDeliveryConcurrentCachePublication(t *testing.T) {
	c := deliveryClient(t)
	const count = 32
	responses := make(chan uint16, count)
	start := make(chan struct{})
	var workers sync.WaitGroup
	for i := 0; i < count; i++ {
		workers.Add(1)
		go func(id uint16) {
			defer workers.Done()
			<-start
			c.ProcessDNSQuery(deliveryQuery(id), nil, func(p []byte) { responses <- binary.BigEndian.Uint16(p[:2]) })
		}(uint16(i + 1))
	}
	close(start)
	deliverDNS(t, c, deliveryQuery(500), 14)
	workers.Wait()
	seen := make(map[uint16]bool)
	for i := 0; i < count; i++ {
		select {
		case id := <-responses:
			if seen[id] {
				t.Fatal("duplicate response")
			}
			seen[id] = true
		case <-time.After(time.Second):
			t.Fatal("reply raced past callback registration")
		}
	}
}

func TestDNSDeliveryReassemblesBeforeReply(t *testing.T) {
	c := deliveryClient(t)
	query := deliveryQuery(55)
	responses := make(chan []byte, 2)
	c.ProcessDNSQuery(query, nil, func(p []byte) { responses <- p })
	response, _ := dnsParser.BuildEmptyNoErrorResponse(query)
	mid := len(response) / 2
	for _, part := range []struct {
		id   uint8
		data []byte
	}{{1, response[mid:]}, {0, response[:mid]}} {
		if err := c.HandleDNSQueryRes(VpnProto.Packet{SequenceNum: 16, FragmentID: part.id, TotalFragments: 2, Payload: part.data}); err != nil {
			t.Fatal(err)
		}
		if part.id == 1 {
			select {
			case <-responses:
				t.Fatal("partial reply delivered")
			default:
			}
		}
	}
	select {
	case p := <-responses:
		if binary.BigEndian.Uint16(p[:2]) != 55 {
			t.Fatal("wrong reassembled ID")
		}
	case <-time.After(time.Second):
		t.Fatal("assembled reply not delivered")
	}
}

func TestDNSDeliveryTimeoutAndResetReleaseWaiters(t *testing.T) {
	c := deliveryClient(t)
	c.cfg.DNSResponseFragmentTimeoutSeconds = .01
	responses := make(chan []byte, 2)
	c.ProcessDNSQuery(deliveryQuery(21), nil, func(p []byte) { responses <- p })
	select {
	case p := <-responses:
		if p[3]&15 != 2 {
			t.Fatal("timeout should send SERVFAIL")
		}
	case <-time.After(time.Second):
		t.Fatal("pending callback never expired")
	}
	c.pendingDNS.mu.Lock()
	retained := c.pendingDNS.total
	c.pendingDNS.mu.Unlock()
	if retained != 0 {
		t.Fatal("expired callback retained")
	}
	c.cfg.DNSResponseFragmentTimeoutSeconds = 60
	c.ProcessDNSQuery(deliveryQuery(22), nil, func(p []byte) { responses <- p })
	c.resetRuntimeBindings(false)
	if c.pendingDNS.total != 0 || len(c.pendingDNS.groups) != 0 || c.localDNSCache.HasPending() {
		t.Fatal("session reset retained pending queries")
	}
}

func TestDNSDeliveryBoundedWaiters(t *testing.T) {
	c := deliveryClient(t)
	responses := make(chan []byte, maxPendingDNSWaitersPerQuestion+2)
	for i := 0; i < maxPendingDNSWaitersPerQuestion+1; i++ {
		c.ProcessDNSQuery(deliveryQuery(uint16(i)), nil, func(p []byte) { responses <- p })
	}
	select {
	case p := <-responses:
		if p[3]&15 != 2 {
			t.Fatal("overflow should send SERVFAIL")
		}
	case <-time.After(time.Second):
		t.Fatal("overflow silently retained callback")
	}
	if c.pendingDNS.total != maxPendingDNSWaitersPerQuestion {
		t.Fatal("waiter limit exceeded")
	}
	deliverDNS(t, c, deliveryQuery(0), 18)
	for i := 0; i < maxPendingDNSWaitersPerQuestion; i++ {
		select {
		case p := <-responses:
			if p[3]&15 != 0 {
				t.Fatal("accepted waiter failed")
			}
		case <-time.After(time.Second):
			t.Fatal("accepted waiter lost")
		}
	}
}

func TestDNSDeliveryCallbacksCanReenterCache(t *testing.T) {
	c := deliveryClient(t)
	responses := make(chan bool, 1)
	c.ProcessDNSQuery(deliveryQuery(8), nil, func([]byte) { responses <- c.ProcessDNSQuery(deliveryQuery(9), nil, nil) })
	done := make(chan struct{})
	go func() { deliverDNS(t, c, deliveryQuery(8), 19); close(done) }()
	select {
	case hit := <-responses:
		if !hit {
			t.Fatal("cache not published before callback")
		}
	case <-time.After(time.Second):
		t.Fatal("callback holds delivery lock")
	}
	<-done
}

func TestDNSDeliveryWithoutLocalCache(t *testing.T) {
	c := deliveryClient(t)
	c.localDNSCache = nil
	responses := make(chan []byte, 1)
	c.ProcessDNSQuery(deliveryQuery(77), nil, func(p []byte) { responses <- p })
	deliverDNS(t, c, deliveryQuery(77), 20)
	select {
	case p := <-responses:
		if binary.BigEndian.Uint16(p[:2]) != 77 {
			t.Fatal("wrong ID")
		}
	case <-time.After(time.Second):
		t.Fatal("delivery depends on caching")
	}
}

func TestDNSDeliveryActualUDPListener(t *testing.T) {
	c := createTestClient(t)
	c.sessionReady = true
	t.Cleanup(c.clearPendingDNSQueries)
	listener := NewDNSListener(c)
	if err := listener.Start(context.Background(), "127.0.0.1", 0); err != nil {
		t.Fatal(err)
	}
	defer listener.Stop()
	conn, err := net.DialUDP("udp", nil, listener.conns[0].LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	query := deliveryQuery(0x4321)
	if _, err := conn.Write(query); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		c.pendingDNS.mu.Lock()
		registered := c.pendingDNS.total > 0
		c.pendingDNS.mu.Unlock()
		if registered {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("listener did not register query")
		}
		time.Sleep(time.Millisecond)
	}
	deliverDNS(t, c, query, 21)
	conn.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		t.Fatal("first UDP request required a retry:", err)
	}
	if n < 12 || binary.BigEndian.Uint16(buffer[:2]) != 0x4321 {
		t.Fatal("wrong UDP response")
	}
}

func TestDNSCacheMissDeliversFirstResponse(t *testing.T) {
	c := createTestClient(t)
	c.sessionReady = true
	query := deliveryQuery(0x1234)
	responses := make(chan []byte, 2)
	if c.ProcessDNSQuery(query, nil, func(p []byte) { responses <- p }) {
		t.Fatal("cold lookup was a cache hit")
	}
	response, err := dnsParser.BuildEmptyNoErrorResponse(query)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.HandleDNSQueryRes(VpnProto.Packet{SequenceNum: 11, TotalFragments: 1, Payload: response}); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.localDNSCache.GetReady(dnsCache.BuildKey("first.test", 1, 1), query, time.Now()); !ok {
		t.Fatal("response did not populate cache")
	}
	select {
	case got := <-responses:
		if binary.BigEndian.Uint16(got[:2]) != 0x1234 {
			t.Fatalf("wrong transaction ID: %x", got[:2])
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("response entered cache but the first request received nothing")
	}
}
