package soar

import (
	"context"
	"crypto/ed25519"
	"net"
	"testing"
	"time"
)

func TestCottenMaxLateAuthenticatedAnswerLearnsChangedRTT(t *testing.T) {
	now := time.Now()
	p := &path{verified: true, hasRTT: true, srtt: time.Millisecond, rttvar: time.Millisecond, cwnd: 1, consec: 5, lastSuccess: now.Add(-time.Second), outN: 1, outcomes: [outcomeWindow]bool{true}}
	cs := &clientSession{session: newSession(true, streamConfig{}, &packetCipher{}, &packetCipher{}), established: true}
	z, _ := parseZone(testZone)
	request, _ := parseQuery(appendQuery(nil, 7, []byte("probe"), z, typeTXT, 1232), z)
	q := &pendingQuery{txn: 7, p: p, sess: cs, pn: 0, question: request.question, sent: now.Add(-500 * time.Millisecond), deadline: now.Add(-300 * time.Millisecond), expired: true}
	c := &Client{cfg: Config{MaxPathWindow: 32}, paths: []*path{p}, pending: map[uint16]*pendingQuery{7: q}, wakeCh: make(chan struct{}, 1)}
	plain := []byte{0, 0, frPing, frPadding, 0, 0}
	payload := (&packetCipher{}).sealDown(0, 0, plain)
	forged := append([]byte(nil), payload...)
	forged[len(forged)-1] ^= 1
	c.onAnswer(appendAnswer(nil, request, rcodeOK, forged))
	if p.rto() != 200*time.Millisecond || p.consec != 5 || len(c.pending) != 1 {
		t.Fatal("unauthenticated late reply changed the path estimate")
	}
	c.onAnswer(appendAnswer(nil, request, rcodeOK, payload))
	if p.rto() < 500*time.Millisecond || !p.lastSuccess.After(now.Add(-100*time.Millisecond)) || p.consec != 0 {
		t.Fatalf("valid late reply did not update the changed path: rto=%s last=%s consecutive=%d", p.rto(), p.lastSuccess, p.consec)
	}
	if p.inflight != 0 || p.cwnd != 1 || p.outN != 1 {
		t.Fatal("late reply double-counted delivery or congestion credit")
	}
}

func TestCottenMaxLateHelloLearnsSlowPath(t *testing.T) {
	priv, eph, _, reply, _, _ := vecSession(t)
	now := time.Now()
	p := &path{cwnd: 1, outN: 1, outcomes: [outcomeWindow]bool{true}}
	cs := &clientSession{eph: eph, ready: make(chan struct{})}
	q := &pendingQuery{txn: 1, p: p, sess: cs, sent: now.Add(-2 * time.Second), expired: true, hello: true}
	c := &Client{cfg: Config{ServerKey: priv.Public().(ed25519.PublicKey)}, sess: cs, pending: map[uint16]*pendingQuery{1: q}}
	c.onHelloLocked(q, reply, now)
	if !cs.established || !p.verified || p.rto() < 2*time.Second {
		t.Fatal("late signed hello failed to establish and measure the slow path")
	}
	if p.inflight != 0 || p.cwnd != 1 || p.outN != 1 {
		t.Fatal("late hello double-counted delivery credit")
	}
}

func TestCottenMaxTCPFallbackAfterVerifiedUDPStalls(t *testing.T) {
	c := gapClient(t, Config{Resolvers: []string{"127.0.0.1:1"}, TCP: "auto",
		DialTCP: func(ctx context.Context, _, _ string) (net.Conn, error) { <-ctx.Done(); return nil, ctx.Err() },
	})
	c.mu.Lock()
	defer c.mu.Unlock()
	p := c.paths[0]
	p.verified, p.hasRTT, p.srtt, p.consec = true, true, 30*time.Millisecond, 3
	p.lastSuccess = time.Now()
	c.addTCPSiblingsLocked()
	if len(c.paths) != 1 {
		t.Fatal("ordinary losses immediately activated TCP")
	}
	p.lastSuccess = time.Now().Add(-2 * time.Second)
	c.addTCPSiblingsLocked()
	c.addTCPSiblingsLocked()
	if len(c.paths) != 2 || c.paths[1].tcp == nil {
		t.Fatal("stalled verified UDP did not get exactly one TCP sibling")
	}
}

func TestCottenMaxCloseCancelsTCPDial(t *testing.T) {
	started, cancelled := make(chan struct{}), make(chan struct{})
	c := gapClient(t, Config{Resolvers: []string{"127.0.0.1:1"}, TCP: "only",
		DialTCP: func(ctx context.Context, _, _ string) (net.Conn, error) {
			close(started)
			<-ctx.Done()
			close(cancelled)
			return nil, ctx.Err()
		},
	})
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("dial did not start")
	}
	c.Close()
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("close left resolver dial running")
	}
}

func TestCottenMaxRechecksNameSizeAfterRouteChanges(t *testing.T) {
	c := gapClient(t, Config{Resolvers: []string{"127.0.0.1:1"}, TCP: "off"})
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	p := c.paths[0]
	p.inflight = 2
	for range 2 {
		c.failLocked(&pendingQuery{p: p, probe: true}, now, false)
	}
	p.onSuccess(now.Add(time.Millisecond), 30*time.Millisecond, c.cfg.MaxPathWindow)
	p.successes = 3
	cs := establish(c)
	c.sendDataLocked(cs, p, now.Add(9*time.Second), false)
	for _, q := range c.pending {
		if q.probe {
			t.Fatal("name-size retry ignored its backoff")
		}
	}
	c.sendDataLocked(cs, p, now.Add(11*time.Second), false)
	probes := 0
	for _, q := range c.pending {
		if q.probe {
			probes++
		}
	}
	if probes != 1 {
		t.Fatalf("recovered route received %d large-name probes, want one", probes)
	}
}

func TestCottenMaxNameProbeBackoffStaysBounded(t *testing.T) {
	p := &path{nameLen: 101, successes: 3}
	now := time.Now()
	for _, delay := range []time.Duration{10 * time.Second, 40 * time.Second, 160 * time.Second, 640 * time.Second, 30 * time.Minute, 30 * time.Minute} {
		p.probing = false
		p.backoffNameProbe(now)
		if p.nameRetryAt.Sub(now) != delay {
			t.Fatalf("backoff=%s, want %s", p.nameRetryAt.Sub(now), delay)
		}
		if p.beginNameProbe(now.Add(delay-time.Nanosecond), 253) {
			t.Fatal("probe before backoff expired")
		}
		if !p.beginNameProbe(now.Add(delay), 253) {
			t.Fatal("probe not allowed when backoff expired")
		}
		if p.beginNameProbe(now.Add(delay), 253) {
			t.Fatal("more than one probe in flight")
		}
		now = now.Add(delay)
	}
}
