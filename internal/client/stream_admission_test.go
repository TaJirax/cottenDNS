package client

import (
	"testing"
	"time"

	"cottendns-go/internal/config"
)

// admissibleClient builds a client that passes every admission gate: session
// ready, one valid resolver, no stall.
func admissibleClient(t *testing.T) *Client {
	t.Helper()
	c := buildTestClientWithResolvers(config.ClientConfig{
		StreamQueueInitialCapacity: 8,
		OrphanQueueInitialCapacity: 4,
	}, "resolver-a")
	c.sessionReady = true
	c.resetTunnelActivity(c.now())
	return c
}

func TestShouldAdmitNewLocalStreamHappyPath(t *testing.T) {
	c := admissibleClient(t)
	if ok, reason := c.shouldAdmitNewLocalStream(c.now()); !ok {
		t.Fatalf("expected admission, got refusal: %s", reason)
	}
}

func TestShouldAdmitNewLocalStreamRejectsWhenSessionNotReady(t *testing.T) {
	c := admissibleClient(t)
	c.sessionReady = false
	if ok, _ := c.shouldAdmitNewLocalStream(c.now()); ok {
		t.Fatal("expected refusal when session is not ready")
	}
}

func TestShouldAdmitNewLocalStreamRejectsWhenNoValidResolvers(t *testing.T) {
	c := admissibleClient(t)
	c.balancer.SetConnectionValidity("resolver-a", false)
	if ok, _ := c.shouldAdmitNewLocalStream(c.now()); ok {
		t.Fatal("expected refusal when no resolvers are valid")
	}
}

func TestShouldAdmitNewLocalStreamRejectsWhenTunnelStalled(t *testing.T) {
	c := admissibleClient(t)
	c.tunnelPacketTimeout = 4 * time.Second
	now := c.now()
	// A send with no response, older than the admission window, is a stall.
	window := c.streamAdmissionNoResponseWindow()
	c.lastTunnelSendUnix.Store(now.Add(-2 * window).UnixNano())
	c.lastTunnelResponseUnix.Store(now.Add(-3 * window).UnixNano())
	if ok, reason := c.shouldAdmitNewLocalStream(now); ok {
		t.Fatal("expected refusal when the tunnel is stalled")
	} else if reason == "" {
		t.Fatal("expected a non-empty stall reason")
	}
}

func TestRecordTunnelResponseClearsStall(t *testing.T) {
	c := admissibleClient(t)
	c.tunnelPacketTimeout = 4 * time.Second
	now := c.now()
	window := c.streamAdmissionNoResponseWindow()
	c.lastTunnelSendUnix.Store(now.Add(-2 * window).UnixNano())
	c.lastTunnelResponseUnix.Store(now.Add(-3 * window).UnixNano())
	if stalled, _ := c.tunnelResponseStalled(now); !stalled {
		t.Fatal("precondition: expected a stall")
	}
	// A fresh response must clear the stall immediately.
	c.recordTunnelResponse(now)
	if stalled, _ := c.tunnelResponseStalled(now); stalled {
		t.Fatal("recordTunnelResponse should clear the stall")
	}
}
