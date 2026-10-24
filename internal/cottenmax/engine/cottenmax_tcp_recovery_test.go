package soar

import (
	"io"
	"net"
	"reflect"
	"slices"
	"sync/atomic"
	"testing"
	"time"
)

// No link goroutine is started: the scheduler's clock and socket state are
// controlled independently, without timing-sensitive real network delays.
type cottenMaxRecoveryConn struct {
	closeStarted chan struct{}
	allowClose   <-chan struct{}
	closeCalls   atomic.Int32
}

func (c *cottenMaxRecoveryConn) Read([]byte) (int, error)    { return 0, io.EOF }
func (c *cottenMaxRecoveryConn) Write(b []byte) (int, error) { return len(b), nil }
func (c *cottenMaxRecoveryConn) Close() error {
	if c.closeCalls.Add(1) == 1 {
		close(c.closeStarted)
	}
	if c.allowClose != nil {
		<-c.allowClose
	}
	return nil
}
func (*cottenMaxRecoveryConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (*cottenMaxRecoveryConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (*cottenMaxRecoveryConn) SetDeadline(time.Time) error      { return nil }
func (*cottenMaxRecoveryConn) SetReadDeadline(time.Time) error  { return nil }
func (*cottenMaxRecoveryConn) SetWriteDeadline(time.Time) error { return nil }

func cottenMaxRecoveryLink() (*tcpLink, *cottenMaxRecoveryConn) {
	conn := &cottenMaxRecoveryConn{closeStarted: make(chan struct{})}
	l := &tcpLink{conn: conn, out: make(chan []byte, 8), done: make(chan struct{})}
	l.up.Store(true)
	return l, conn
}

func TestCottenMaxTCPReconnectWaitsForProgressDeadline(t *testing.T) {
	for _, tc := range []struct {
		name string
		srtt time.Duration
	}{
		{"low-latency", 30 * time.Millisecond},
		{"high-latency", 3 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			start := time.Now()
			l, conn := cottenMaxRecoveryLink()
			p := &path{tcp: l, hasRTT: true, srtt: tc.srtt, timeouts: 3, unanswered: start}
			c := &Client{cfg: Config{Hold: 500 * time.Millisecond}, paths: []*path{p}}
			limit := max(3*p.rto()+c.cfg.Hold, 3*time.Second)
			c.reconnectStalledTCPLocked(start.Add(limit - time.Nanosecond))
			if !l.up.Load() || conn.closeCalls.Load() != 0 {
				t.Fatal("socket reset before the hold-aware progress deadline")
			}
			c.reconnectStalledTCPLocked(start.Add(limit))
			if l.up.Load() {
				t.Fatal("stalled socket still advertised as usable")
			}
			select {
			case <-conn.closeStarted:
			case <-time.After(time.Second):
				t.Fatal("stalled socket was not closed")
			}
			c.reconnectStalledTCPLocked(start.Add(limit + time.Second))
			if conn.closeCalls.Load() != 1 {
				t.Fatal("one stalled socket received repeated close requests")
			}
		})
	}
}

func TestCottenMaxTCPProgressClockStartsAfterIdle(t *testing.T) {
	start := time.Now()
	l, conn := cottenMaxRecoveryLink()
	p := &path{tcp: l, qtype: typeTXT, lastSuccess: start.Add(-time.Hour), timeouts: 3}
	z, err := parseZone(testZone)
	if err != nil {
		t.Fatal(err)
	}
	c := &Client{z: z, paths: []*path{p}, pending: make(map[uint16]*pendingQuery)}
	c.reconnectStalledTCPLocked(start)
	if !l.up.Load() {
		t.Fatal("idle connection was reset without outstanding traffic")
	}
	c.sendLocked(p, &pendingQuery{p: p}, []byte("probe"), start, time.Second)
	c.sendLocked(p, &pendingQuery{p: p}, []byte("probe"), start.Add(time.Second), time.Second)
	if !p.unanswered.Equal(start) {
		t.Fatal("progress clock did not retain the first send after idle")
	}
	c.reconnectStalledTCPLocked(start.Add(2 * time.Second))
	if !l.up.Load() || conn.closeCalls.Load() != 0 {
		t.Fatal("old last-success time caused immediate reconnect after idle")
	}
	progress := start.Add(2 * time.Second)
	p.observeAuthenticated(progress, 30*time.Millisecond)
	if p.timeouts != 0 || !p.unanswered.Equal(progress) {
		t.Fatal("authenticated progress did not refresh outstanding-query clock")
	}
	p.inflight = 0
	p.observeAuthenticated(progress.Add(time.Second), 30*time.Millisecond)
	if !p.unanswered.IsZero() {
		t.Fatal("connection with no live queries retained a stall clock")
	}
}

func TestCottenMaxTCPHeldPollsCountOnlyAtDeadline(t *testing.T) {
	now := time.Now()
	l, conn := cottenMaxRecoveryLink()
	p := &path{tcp: l, hasRTT: true, srtt: 30 * time.Millisecond, maxAnswered: 100,
		inflight: 3, cwnd: 8, nameLen: 101, unanswered: now.Add(-4 * time.Second)}
	c := &Client{cfg: Config{SafeQName: 101, Hold: 500 * time.Millisecond},
		paths: []*path{p}, pending: make(map[uint16]*pendingQuery)}
	deadline := now.Add(600 * time.Millisecond)
	for txn := uint16(1); txn <= 3; txn++ {
		c.pending[txn] = &pendingQuery{p: p, poll: true, seq: uint64(txn),
			sent: now.Add(-100 * time.Millisecond), deadline: deadline}
	}
	c.expireLocked(deadline.Add(-time.Nanosecond))
	c.reconnectStalledTCPLocked(deadline.Add(-time.Nanosecond))
	if p.timeouts != 0 || p.inflight != 3 || !l.up.Load() || conn.closeCalls.Load() != 0 {
		t.Fatal("reordered held polls caused premature timeout or reconnect")
	}
	c.expireLocked(deadline)
	if p.timeouts != 3 || p.inflight != 0 {
		t.Fatal("genuine held-poll deadline failures were not counted")
	}
	c.reconnectStalledTCPLocked(deadline)
	if l.up.Load() {
		t.Fatal("actual deadline failures did not reconnect a stalled socket")
	}
}

func TestCottenMaxTCPFastLossDoesNotCountAsTimeout(t *testing.T) {
	now := time.Now()
	l, conn := cottenMaxRecoveryLink()
	p := &path{tcp: l, hasRTT: true, srtt: 30 * time.Millisecond, maxAnswered: 100,
		inflight: 3, cwnd: 8, nameLen: 101, unanswered: now.Add(-4 * time.Second)}
	c := &Client{cfg: Config{SafeQName: 101}, paths: []*path{p}, pending: make(map[uint16]*pendingQuery)}
	for txn := uint16(1); txn <= 3; txn++ {
		c.pending[txn] = &pendingQuery{p: p, seq: uint64(txn),
			sent: now.Add(-100 * time.Millisecond), deadline: now.Add(100 * time.Millisecond)}
	}
	c.expireLocked(now)
	if p.consec != 3 || p.inflight != 0 || p.timeouts != 0 {
		t.Fatal("fast loss did not remain distinct from actual query deadline failures")
	}
	c.reconnectStalledTCPLocked(now)
	c.expireLocked(now.Add(200 * time.Millisecond))
	c.reconnectStalledTCPLocked(now.Add(200 * time.Millisecond))
	if !l.up.Load() || conn.closeCalls.Load() != 0 || p.timeouts != 0 {
		t.Fatal("reordered data replies caused TCP connection churn")
	}
}

func TestCottenMaxTCPLinkDownAccountsOnceAndDiscardsQueue(t *testing.T) {
	now := time.Now()
	l, _ := cottenMaxRecoveryLink()
	l.up.Store(false)
	l.out <- []byte("old query 1")
	l.out <- []byte("old query 2")
	p := &path{tcp: l, inflight: 2, cwnd: 8, nameLen: 101, verified: true,
		consec: 4, timeouts: 3, unanswered: now.Add(-4 * time.Second), suspended: now.Add(15 * time.Second)}
	other := &path{inflight: 1, verified: true}
	c := &Client{cfg: Config{SafeQName: 101}, paths: []*path{p, other},
		pending: make(map[uint16]*pendingQuery), wakeCh: make(chan struct{}, 1)}
	cs := establish(c)
	cs.lostQ = []uint64{7}
	old := &pendingQuery{p: p, sess: cs, pn: 7, expired: true, deadline: now.Add(-time.Second)}
	first := &pendingQuery{p: p, sess: cs, pn: 8, deadline: now.Add(time.Second)}
	second := &pendingQuery{p: p, sess: cs, pn: 9, deadline: now.Add(time.Second)}
	untouched := &pendingQuery{p: other, deadline: now.Add(time.Minute)}
	c.pending[1], c.pending[2], c.pending[3], c.pending[4] = old, first, second, untouched
	c.linkDown(l)
	if !first.expired || !second.expired || p.inflight != 0 || p.consec != 6 {
		t.Fatal("link down did not immediately account for all old live queries")
	}
	got := slices.Clone(cs.lostQ)
	slices.Sort(got)
	if !reflect.DeepEqual(got, []uint64{7, 8, 9}) {
		t.Fatalf("lost packet accounting = %v", got)
	}
	if untouched.expired || other.inflight != 1 || len(l.out) != 0 {
		t.Fatal("old queue survived or another path's query was affected")
	}
	if !p.suspended.IsZero() || !p.unanswered.IsZero() || p.timeouts != 0 || p.cwnd > 8 || p.cwnd < 1 {
		t.Fatal("old suspension survived, or congestion accounting was discarded")
	}
	l.up.Store(true)
	if !p.usable(time.Now()) {
		t.Fatal("replacement connection remained suspended by old losses")
	}
	c.expireLocked(now.Add(time.Second))
	if p.inflight != 0 || p.consec != 6 || len(cs.lostQ) != 3 {
		t.Fatal("later expiration double-counted old-connection failures")
	}
}

func TestCottenMaxTCPBlockedCloseDoesNotHoldClientLock(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	l, conn := cottenMaxRecoveryLink()
	conn.allowClose = release
	now := time.Now()
	p := &path{tcp: l, timeouts: 3, unanswered: now.Add(-10 * time.Second)}
	c := &Client{paths: []*path{p}}
	returned := make(chan struct{})
	go func() {
		c.mu.Lock()
		c.reconnectStalledTCPLocked(now)
		c.mu.Unlock()
		close(returned)
	}()
	select {
	case <-conn.closeStarted:
	case <-time.After(time.Second):
		t.Fatal("socket close did not start")
	}
	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("blocked custom Close held the client scheduler lock")
	}
	healthyProgress := make(chan struct{})
	go func() {
		c.mu.Lock()
		(&path{}).observeAuthenticated(now, 30*time.Millisecond)
		c.mu.Unlock()
		close(healthyProgress)
	}()
	select {
	case <-healthyProgress:
	case <-time.After(time.Second):
		t.Fatal("another path could not process progress during blocked Close")
	}
}
