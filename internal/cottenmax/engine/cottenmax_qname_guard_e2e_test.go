package soar

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// qnameGuardGateConn changes an actual UDP resolver path in place. No DNS
// response is forged and no client proof, RTT, cap or session clock is edited.
type qnameGuardGateConn struct {
	net.PacketConn
	maxName          atomic.Int64
	outage           atomic.Bool
	longDropped      atomic.Int64
	outageDropped    atomic.Int64
	mediumReplies    atomic.Int64
	mediumWhileLarge atomic.Int64
	client           atomic.Pointer[Client]
}

func qnameGuardWireNameLen(msg []byte) int {
	end, err := skipName(msg, hdrLen)
	if err != nil {
		return 0
	}
	return end - hdrLen - 2
}

func (p *qnameGuardGateConn) WriteTo(msg []byte, to net.Addr) (int, error) {
	if p.outage.Load() {
		p.outageDropped.Add(1)
		return len(msg), nil
	}
	if qnameGuardWireNameLen(msg) > int(p.maxName.Load()) {
		p.longDropped.Add(1)
		return len(msg), nil
	}
	return p.PacketConn.WriteTo(msg, to)
}

func (p *qnameGuardGateConn) ReadFrom(dst []byte) (int, net.Addr, error) {
	for {
		n, from, err := p.PacketConn.ReadFrom(dst)
		if err != nil {
			return n, from, err
		}
		if p.outage.Load() {
			p.outageDropped.Add(1)
			continue
		}
		name := qnameGuardWireNameLen(dst[:n])
		// Also discard old long-question replies queued before the policy change.
		if name > int(p.maxName.Load()) {
			p.longDropped.Add(1)
			continue
		}
		if name > 101 && name <= 150 {
			p.mediumReplies.Add(1)
			if c := p.client.Load(); c != nil {
				c.mu.Lock()
				if len(c.paths) > 0 && c.paths[0].nameLen > 150 {
					p.mediumWhileLarge.Add(1)
				}
				c.mu.Unlock()
			}
		}
		return n, from, nil
	}
}

func qnameGuardEcho(conn net.Conn, input []byte) error {
	written := make(chan error, 1)
	go func() { _, err := io.Copy(conn, bytes.NewReader(input)); written <- err }()
	got := make([]byte, len(input))
	_, err := io.ReadFull(conn, got)
	if err != nil {
		conn.Close()
		<-written
		return fmt.Errorf("read %d-byte echo: %w", len(input), err)
	}
	if err := <-written; err != nil {
		return fmt.Errorf("write echo: %w", err)
	}
	if !bytes.Equal(input, got) {
		return fmt.Errorf("echo payload corrupted (%d bytes)", len(input))
	}
	return nil
}

func qnameGuardWait(ctx context.Context, predicate func() bool) bool {
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		if predicate() {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-tick.C:
		}
	}
}

func qnameGuardE2EClient(t *testing.T) (*Client, net.Conn, *qnameGuardGateConn, *clientSession) {
	t.Helper()
	srv, pub := startServer(t)
	origin := startOrigin(t)
	var gate *qnameGuardGateConn
	c, err := NewClient(Config{Zone: testZone, ServerKey: pub, Resolvers: []string{srv}, TCP: "off",
		SafeQName: 101, MaxQName: 253, Hold: 50 * time.Millisecond, MaxPathWindow: 32, MaxInflight: 64,
		QNameLossGuard: true,
		ListenPacket: func(ctx context.Context, network, address string) (net.PacketConn, error) {
			var listen net.ListenConfig
			pc, err := listen.ListenPacket(ctx, network, address)
			if err != nil {
				return nil, err
			}
			gate = &qnameGuardGateConn{PacketConn: pc}
			gate.maxName.Store(253)
			return gate, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	gate.client.Store(c)
	t.Cleanup(func() { c.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := c.DialContext(ctx, "tcp", origin)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	if _, err := io.WriteString(conn, "echo\n"); err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 6; attempt++ {
		warm := make([]byte, 16<<10)
		if _, err := rand.Read(warm); err != nil {
			t.Fatal(err)
		}
		if err := qnameGuardEcho(conn, warm); err != nil {
			t.Fatal(err)
		}
		c.mu.Lock()
		p := c.paths[0]
		fresh := p.nameLen == 253 && p.lastLargeNameLen >= 251 && !p.lastLargeNameAuth.IsZero() && time.Since(p.lastLargeNameAuth) < p.rto()
		cs := c.sess
		c.mu.Unlock()
		if fresh {
			return c, conn, gate, cs
		}
	}
	t.Fatal("warmup did not obtain a fresh authenticated near-253-character exchange")
	return nil, nil, nil, nil
}

// Send a bounded real authenticated control query through the existing build,
// seal, send, server-parse and response-authentication paths. Padding its QNAME
// near140 keeps genuine medium-size replies arriving while full data queries
// are blocked by150. This exercises the adversarial condition naturally short
// idle polls alone cannot cover. It does not edit the learned cap or proof.
func qnameGuardMediumControl(c *Client) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cs := c.sess
	if cs == nil || !cs.established || len(c.pending) >= maxPending {
		return
	}
	p := c.paths[0]
	if p.inflight >= c.cfg.MaxInflight {
		return
	}
	now := time.Now()
	cs.mu.Lock()
	if cs.closed {
		cs.mu.Unlock()
		return
	}
	pn, plain, _, _ := cs.build([]byte{0}, minPlain, now, 0)
	target := c.z.maxPayload(140) - 4 - tagLen
	for len(plain) < target {
		plain = append(plain, frPadding)
	}
	payload := cs.seal.sealUp(cs.sid, pn, plain)
	cs.mu.Unlock()
	if cs.unanswered.IsZero() {
		cs.unanswered = now
	}
	c.sendLocked(p, &pendingQuery{p: p, sess: cs, pn: pn, poll: true, class: 0}, payload, now, p.rto())
}

func TestCottenMaxQNameGuardPartialLimitStillRecoversRealStream(t *testing.T) {
	c, conn, gate, originalSession := qnameGuardE2EClient(t)
	c.mu.Lock()
	proof := c.paths[0].lastLargeNameAuth
	rto := c.paths[0].rto()
	c.mu.Unlock()
	cutover := time.Now()
	gate.maxName.Store(150)
	beforeMedium := gate.mediumReplies.Load()
	beforeMediumWhileLarge := gate.mediumWhileLarge.Load()
	data := make([]byte, 64<<10)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	transfer := make(chan error, 1)
	go func() { transfer <- qnameGuardEcho(conn, data) }()
	stopMedium, mediumDone := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(mediumDone)
		tick := time.NewTicker(10 * time.Millisecond)
		defer tick.Stop()
		for {
			qnameGuardMediumControl(c)
			select {
			case <-stopMedium:
				return
			case <-tick.C:
			}
		}
	}()
	t.Cleanup(func() { close(stopMedium); <-mediumDone })
	ctx, cancel := context.WithTimeout(context.Background(), rto+3*time.Second)
	defer cancel()
	var fallbackAt time.Time
	if !qnameGuardWait(ctx, func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.paths[0].nameLen <= c.cfg.SafeQName {
			fallbackAt = time.Now()
			return true
		}
		return false
	}) {
		t.Fatalf("partial150-character limit kept large cap alive beyond proof expiry; path=%+v", c.PathStats())
	}
	select {
	case err := <-transfer:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("existing stream did not finish a byte-exact echo after partial-limit fallback")
	}
	c.mu.Lock()
	lastAuth, sameSession := c.paths[0].lastSuccess, c.sess == originalSession
	c.mu.Unlock()
	if gate.longDropped.Load() == 0 || gate.mediumReplies.Load() <= beforeMedium || gate.mediumWhileLarge.Load() <= beforeMediumWhileLarge {
		t.Fatal("test did not exercise both dropped long queries and delivered medium replies")
	}
	if !lastAuth.After(cutover) || !sameSession {
		t.Fatal("recovery did not retain the original authenticated session")
	}
	t.Logf("partial-limit fallback %s after original proof (RTO %s), dropped=%d medium-replies=%d; same64KiB stream byte-exact", fallbackAt.Sub(proof), rto, gate.longDropped.Load(), gate.mediumReplies.Load()-beforeMedium)
}

func TestCottenMaxQNameGuardOutageRestoreKeepsRealStream(t *testing.T) {
	c, conn, gate, originalSession := qnameGuardE2EClient(t)
	gate.outage.Store(true)
	data := make([]byte, 32<<10)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	transfer := make(chan error, 1)
	go func() { transfer <- qnameGuardEcho(conn, data) }()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if !qnameGuardWait(ctx, func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.paths[0].nameLen <= c.cfg.SafeQName
	}) {
		t.Fatalf("outage did not restore safe-size fallback before bounded timeout: %+v", c.PathStats())
	}
	if gate.outageDropped.Load() == 0 {
		t.Fatal("outage did not drop actual protocol traffic")
	}
	gate.outage.Store(false)
	select {
	case err := <-transfer:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("restored path did not complete original32KiB stream")
	}
	c.mu.Lock()
	sameSession := c.sess == originalSession
	c.mu.Unlock()
	if !sameSession {
		t.Fatal("short outage unexpectedly required a different session")
	}
	t.Logf("outage restored; dropped=%d; original32KiB stream byte-exact", gate.outageDropped.Load())
}
