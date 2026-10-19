package client

import (
	"bytes"
	"testing"
	"time"

	dnsCache "cottendns-go/internal/dnscache"
)

func TestFirstDNSRequestReceivesDelayedTunnelResponse(t *testing.T) {
	c := &Client{localDNSCache: dnsCache.New(16, time.Minute, time.Second)}
	key := dnsCache.BuildKey("example.com", 1, 1)
	query := []byte{0x12, 0x34, 0, 0}
	result := make(chan []byte, 1)
	c.waitDNSReply(key, query, func(reply []byte) { result <- reply })
	query[0] = 0xff // the socket read buffer may already be reused
	c.localDNSCache.SetReady(key, "example.com", 1, 1, []byte{0, 0, 0x80, 0}, time.Now())
	select {
	case reply := <-result:
		if !bytes.Equal(reply, []byte{0x12, 0x34, 0x80, 0}) {
			t.Fatal("reply lost original transaction ID", reply)
		}
	case <-time.After(time.Second):
		t.Fatal("first request still requires a retransmission")
	}
}

func TestDNSReplyWaitersAreBounded(t *testing.T) {
	c := &Client{localDNSCache: dnsCache.New(16, time.Minute, time.Second)}
	c.dnsReplyWaiters.Store(128)
	c.waitDNSReply("pending", []byte{1, 2}, func([]byte) { t.Error("admitted excess waiter") })
	if c.dnsReplyWaiters.Load() != 128 {
		t.Fatal("waiter limit changed")
	}
}
