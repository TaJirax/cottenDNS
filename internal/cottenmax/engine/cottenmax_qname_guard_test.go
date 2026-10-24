package soar

import (
	"bytes"
	"testing"
	"time"
)

// These tests drive the existing authenticated answer/failure paths directly;
// no sockets, traffic generators, external resolvers or sleep are used.
func qnameGuardFixture(t *testing.T, payloadBytes int, expired bool, jitter ...bool) (*Client, *path, *pendingQuery, *query, []byte) {
	t.Helper()
	z, err := parseZone(testZone)
	if err != nil {
		t.Fatal(err)
	}
	if len(jitter) > 0 {
		z.labelJitter = jitter[0]
	}
	if payloadBytes < 0 {
		payloadBytes = z.maxPayload(253)
	}
	request, err := parseQuery(appendQuery(nil, 7, bytes.Repeat([]byte{42}, payloadBytes), z, typeTXT, 1232), z)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	p := &path{verified: true, nameLen: 253, hasRTT: true, srtt: 30 * time.Millisecond, rttvar: 5 * time.Millisecond,
		cwnd: 8, ssthresh: 32, qtype: typeTXT, lastSuccess: now, inflight: 1}
	cs := &clientSession{session: newSession(true, streamConfig{StreamWindow: 1 << 16, SendBuffer: 1 << 16, MaxStreams: 4}, &packetCipher{}, &packetCipher{}), established: true}
	q := &pendingQuery{txn: 7, p: p, sess: cs, question: request.question, sent: now.Add(-30 * time.Millisecond), deadline: now.Add(time.Second), expired: expired}
	if expired {
		p.inflight = 0
	}
	c := &Client{cfg: Config{QNameLossGuard: true, SafeQName: 101, MaxQName: 253, MaxPathWindow: 32}, z: z, paths: []*path{p},
		pending: map[uint16]*pendingQuery{q.txn: q}, wakeCh: make(chan struct{}, 1)}
	plain := []byte{0, 0, frPing, frPadding, 0, 0}
	payload := (&packetCipher{}).sealDown(0, q.pn, plain)
	return c, p, q, request, payload
}

func TestCottenMaxQNameGuardFreshAuthenticatedLongKeepsSizeButStillRecoversLoss(t *testing.T) {
	for _, expired := range []bool{false, true} {
		name := "current"
		if expired {
			name = "late"
		}
		t.Run(name, func(t *testing.T) {
			c, p, q, request, payload := qnameGuardFixture(t, -1, expired)
			c.onAnswer(appendAnswer(nil, request, rcodeOK, payload))
			if p.lastLargeNameAuth.IsZero() {
				t.Fatal("authenticated large question did not record proof")
			}
			if _, pending := c.pending[q.txn]; pending {
				t.Fatal("valid answer was not consumed")
			}
			p.consec, p.inflight, p.cwnd, p.outN = 2, 1, 8, 0
			p.outIdx = 0
			p.outcomes = [outcomeWindow]bool{}
			lost := &pendingQuery{p: p, sess: q.sess, pn: 77}
			c.failLocked(lost, p.lastLargeNameAuth.Add(p.rto()/2), false)
			if p.nameLen != 253 || !p.nameRetryAt.IsZero() {
				t.Fatal("fresh authenticated long question caused size downgrade/backoff")
			}
			if p.consec != 3 || p.inflight != 0 || p.outN != 1 || !p.outcomes[0] || p.cwnd >= 8 {
				t.Fatalf("guard skipped congestion/loss handling: consecutive=%d inflight=%d outcomes=%d cwnd=%.1f", p.consec, p.inflight, p.outN, p.cwnd)
			}
			if got := q.sess.lostQ; len(got) != 1 || got[0] != 77 {
				t.Fatalf("guard skipped retransmission queue: %v", got)
			}
		})
	}
}

func TestCottenMaxQNameGuardSmallOrForgedAnswersDoNotProveLargeNames(t *testing.T) {
	for _, kind := range []string{"authenticated-small", "authenticated-mid-size", "forged-large", "unmatched-question"} {
		t.Run(kind, func(t *testing.T) {
			size := -1
			if kind == "authenticated-small" {
				size = 8
			}
			if kind == "authenticated-mid-size" {
				size = 77
			}
			c, p, _, request, payload := qnameGuardFixture(t, size, false)
			if kind == "authenticated-mid-size" {
				length := len(request.question) - 6
				if length <= c.cfg.SafeQName || length > 150 {
					t.Fatalf("partial-cutoff test did not use a medium name: %d", length)
				}
			}
			if kind == "forged-large" {
				payload[len(payload)-1] ^= 1
			}
			if kind == "unmatched-question" {
				request.question = append([]byte(nil), request.question...)
				request.question[1] ^= 1
			}
			c.onAnswer(appendAnswer(nil, request, rcodeOK, payload))
			if !p.lastLargeNameAuth.IsZero() {
				t.Fatal("small/forged/unmatched response refreshed large-name proof")
			}
			p.consec, p.inflight = 2, 1
			c.failLocked(&pendingQuery{p: p}, time.Now(), false)
			if p.nameLen != c.cfg.SafeQName || p.nameRetryAt.IsZero() {
				t.Fatal("missing proof blocked the original safe-size fallback")
			}
		})
	}
}

func TestCottenMaxQNameGuardOutageAndLongNameBlockRestoreFallback(t *testing.T) {
	for _, name := range []string{"outage", "large-names-blocked-short-answers", "partial-cutoff-medium-answers"} {
		t.Run(name, func(t *testing.T) {
			c, p, q, request, payload := qnameGuardFixture(t, -1, false)
			c.onAnswer(appendAnswer(nil, request, rcodeOK, payload))
			proof := p.lastLargeNameAuth
			if name != "outage" {
				z, _ := parseZone(testZone)
				answeringPayload := []byte("short")
				if name == "partial-cutoff-medium-answers" {
					answeringPayload = bytes.Repeat([]byte{42}, 77)
				}
				short, err := parseQuery(appendQuery(nil, 8, answeringPayload, z, typeTXT, 1232), z)
				if err != nil {
					t.Fatal(err)
				}
				p.inflight++
				sq := &pendingQuery{txn: 8, p: p, sess: q.sess, pn: 1, question: short.question, sent: time.Now().Add(-30 * time.Millisecond)}
				c.pending[sq.txn] = sq
				body := (&packetCipher{}).sealDown(1, sq.pn, []byte{0, 0, frPing, frPadding, 0, 0})
				c.onAnswer(appendAnswer(nil, short, rcodeOK, body))
				if p.lastLargeNameAuth != proof {
					t.Fatal("authenticated short poll extended stale large-name proof")
				}
			}
			p.consec, p.inflight = 2, 1
			now := proof.Add(p.rto() + time.Nanosecond)
			c.failLocked(&pendingQuery{p: p}, now, false)
			if p.nameLen != c.cfg.SafeQName || !p.nameRetryAt.After(now) {
				t.Fatal("stale large-name proof prevented outage recovery")
			}
			p.successes = 3
			if !p.beginNameProbe(p.nameRetryAt, c.cfg.MaxQName) {
				t.Fatal("safe fallback lost the existing backed-off capacity recheck")
			}
		})
	}
}

func TestCottenMaxQNameGuardProofExpiresAtOneRTO(t *testing.T) {
	now := time.Now()
	p := &path{lastLargeNameAuth: now, lastLargeNameLen: 253, nameLen: 253, hasRTT: true, srtt: 30 * time.Millisecond}
	if !p.freshLargeQNameProof(now.Add(p.rto()-time.Nanosecond), 2) {
		t.Fatal("fresh proof expired early")
	}
	if p.freshLargeQNameProof(now.Add(p.rto()), 2) {
		t.Fatal("proof outlived one RTO")
	}
	if p.freshLargeQNameProof(now.Add(-time.Nanosecond), 2) {
		t.Fatal("future-dated proof accepted")
	}
}

func TestCottenMaxQNameGuardJitterUsesBoundedRoundingSlack(t *testing.T) {
	c, p, _, request, payload := qnameGuardFixture(t, -1, false, true)
	c.onAnswer(appendAnswer(nil, request, rcodeOK, payload))
	if p.lastLargeNameLen < p.nameLen-5 {
		t.Fatalf("jitter proof not near cap: %d", p.lastLargeNameLen)
	}
	if !p.freshLargeQNameProof(p.lastLargeNameAuth, c.qnameProofSlack()) {
		t.Fatal("valid jittered near-cap proof not accepted")
	}
	p.lastLargeNameLen = p.nameLen - 6
	if p.freshLargeQNameProof(p.lastLargeNameAuth, c.qnameProofSlack()) {
		t.Fatal("jitter slack concealed a materially smaller limit")
	}
}

func TestCottenMaxQNameGuardDefaultKeepsExistingDowngrade(t *testing.T) {
	c, p, q, request, payload := qnameGuardFixture(t, -1, false)
	c.cfg.QNameLossGuard = false
	c.onAnswer(appendAnswer(nil, request, rcodeOK, payload))
	if !p.lastLargeNameAuth.IsZero() {
		t.Fatal("disabled guard recorded size proof")
	}
	p.lastLargeNameAuth = time.Now()
	p.lastLargeNameLen = 253
	p.consec, p.inflight = 2, 1
	c.failLocked(&pendingQuery{p: p, sess: q.sess}, time.Now(), false)
	if p.nameLen != c.cfg.SafeQName {
		t.Fatal("disabled guard changed existing fallback")
	}
}
