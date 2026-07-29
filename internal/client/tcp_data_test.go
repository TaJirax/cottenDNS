package client

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	Enums "cottendns-go/internal/enums"
)

func TestTCPDataSendBackpressuresInsteadOfDropping(t *testing.T) {
	c := &Client{}
	m := newTCPDataManager(c)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.ctx = ctx
	m.dataQ = make(chan tcpDataJob, 1)
	m.dataQ <- tcpDataJob{}

	result := make(chan bool, 1)
	go func() {
		result <- m.Send(encodedOutboundDatagram{
			addr:     &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53},
			packet:   []byte{0, 1, 2},
			priority: Enums.PacketPriorityNormal,
		}, time.Now())
	}()

	select {
	case <-result:
		t.Fatal("send returned while the TCP data queue was full")
	case <-time.After(25 * time.Millisecond):
	}

	<-m.dataQ
	select {
	case ok := <-result:
		if !ok {
			t.Fatal("send failed after queue capacity became available")
		}
	case <-time.After(time.Second):
		t.Fatal("send did not resume after queue capacity became available")
	}
	if got := c.txAdmissionDrops.Load(); got != 0 {
		t.Fatalf("backpressure counted an admission drop: %d", got)
	}
}

func TestTCPDataSendUnblocksOnShutdown(t *testing.T) {
	m := newTCPDataManager(&Client{})
	ctx, cancel := context.WithCancel(context.Background())
	m.ctx = ctx
	m.dataQ = make(chan tcpDataJob, 1)
	m.dataQ <- tcpDataJob{}

	result := make(chan bool, 1)
	go func() {
		result <- m.Send(encodedOutboundDatagram{
			addr:     &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53},
			packet:   []byte{0, 1, 2},
			priority: Enums.PacketPriorityNormal,
		}, time.Now())
	}()
	time.Sleep(25 * time.Millisecond)
	cancel()

	select {
	case ok := <-result:
		if ok {
			t.Fatal("send succeeded after runtime shutdown")
		}
	case <-time.After(time.Second):
		t.Fatal("blocked send did not stop with its runtime")
	}
}

func TestTCPDataStripesScaleOnlyUnderPressure(t *testing.T) {
	m := newTCPDataManager(&Client{})
	if got := m.desiredStripeCount(); got != tcpDataBaseStripes {
		t.Fatalf("idle stripes=%d want=%d", got, tcpDataBaseStripes)
	}

	fill := func(target int) {
		for len(m.dataQ) < target {
			m.dataQ <- tcpDataJob{}
		}
	}
	fill(cap(m.dataQ) / 4)
	if got := m.desiredStripeCount(); got != 4 {
		t.Fatalf("quarter-pressure stripes=%d want=4", got)
	}
	fill(cap(m.dataQ) / 2)
	if got := m.desiredStripeCount(); got != 6 {
		t.Fatalf("half-pressure stripes=%d want=6", got)
	}
	fill(cap(m.dataQ) * 3 / 4)
	if got := m.desiredStripeCount(); got != tcpDataMaxStripes {
		t.Fatalf("high-pressure stripes=%d want=%d", got, tcpDataMaxStripes)
	}
}

func TestTCPDataInflightWindowBackpressuresAndReleases(t *testing.T) {
	dc := &tcpDataConn{
		inflight: make(chan struct{}, 2),
		closed:   make(chan struct{}),
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if !dc.acquire(ctx) || !dc.acquire(ctx) {
		t.Fatal("failed to fill inflight window")
	}

	acquired := make(chan bool, 1)
	go func() { acquired <- dc.acquire(ctx) }()
	select {
	case <-acquired:
		t.Fatal("acquired beyond the inflight window")
	case <-time.After(25 * time.Millisecond):
	}

	dc.release()
	select {
	case ok := <-acquired:
		if !ok {
			t.Fatal("waiting sender did not acquire the released slot")
		}
	case <-time.After(time.Second):
		t.Fatal("waiting sender did not resume")
	}
}

type partialWriteConn struct {
	net.Conn
	maxWrite int
	written  bytes.Buffer
}

func (c *partialWriteConn) Write(p []byte) (int, error) {
	if len(p) > c.maxWrite {
		p = p[:c.maxWrite]
	}
	return c.written.Write(p)
}

func TestWriteTCPDNSFramedHandlesPartialWrites(t *testing.T) {
	conn := &partialWriteConn{maxWrite: 3}
	msg := []byte("sustained-media-payload")
	if err := writeTCPDNSFramed(conn, msg); err != nil {
		t.Fatal(err)
	}
	got := conn.written.Bytes()
	if len(got) != len(msg)+2 {
		t.Fatalf("framed length=%d want=%d", len(got), len(msg)+2)
	}
	if binary.BigEndian.Uint16(got[:2]) != uint16(len(msg)) {
		t.Fatalf("length prefix=%d want=%d", binary.BigEndian.Uint16(got[:2]), len(msg))
	}
	if !bytes.Equal(got[2:], msg) {
		t.Fatal("partial writes corrupted the DNS message")
	}
}
