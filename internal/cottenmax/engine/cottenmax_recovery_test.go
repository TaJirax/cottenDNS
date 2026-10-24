package soar

import (
	"net"
	"net/netip"
	"reflect"
	"testing"
	"time"
)

type capturePacketConn struct {
	net.PacketConn
	writes int
}

func (c *capturePacketConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	c.writes++
	return len(b), nil
}

type wrappedReplyAddr struct{ net.Addr }

func (a wrappedReplyAddr) UDPAddr() *net.UDPAddr {
	addr, _ := a.Addr.(*net.UDPAddr)
	return addr
}

func TestCottenMaxWrappedUDPAmplificationBudget(t *testing.T) {
	for _, addr := range []*net.UDPAddr{
		{IP: net.ParseIP("192.0.2.10"), Port: 53},
		{IP: net.ParseIP("2001:db8::10"), Port: 53},
	} {
		t.Run(addr.String(), func(t *testing.T) {
			pc := &capturePacketConn{}
			s := &Server{pc: pc, cfg: ServerConfig{MaxBytesPerPrefix: 1}, rrl: make(map[netip.Prefix]*byteBucket)}
			wrapped := wrappedReplyAddr{addr}
			s.write(make([]byte, 32), wrapped, 1)
			if pc.writes != 0 || len(s.rrl) != 1 {
				t.Fatal("wrapped UDP source bypassed its amplification budget")
			}
			s.write(make([]byte, 32), wrapped, 32)
			s.write(make([]byte, 32), wrappedReplyAddr{&net.TCPAddr{IP: addr.IP, Port: 53}}, 1)
			if pc.writes != 2 {
				t.Fatal("non-amplifying or stream response was incorrectly throttled")
			}
		})
	}
}

func TestCottenMaxReorderedHeldPollKeepsDeadline(t *testing.T) {
	now := time.Now()
	p := &path{hasRTT: true, srtt: 30 * time.Millisecond, rttvar: time.Millisecond,
		maxAnswered: 100, inflight: 1, cwnd: 32, nameLen: 253, consec: 2}
	cs := &clientSession{session: newSession(true, streamConfig{}, nil, nil)}
	q := &pendingQuery{p: p, sess: cs, pn: 7, seq: 1, poll: true,
		sent: now.Add(-100 * time.Millisecond), deadline: now.Add(600 * time.Millisecond)}
	c := &Client{cfg: Config{SafeQName: 101}, paths: []*path{p}, pending: map[uint16]*pendingQuery{1: q}}
	c.expireLocked(now)
	if q.expired || p.inflight != 1 || p.nameLen != 253 || len(cs.lostQ) != 0 {
		t.Fatal("later answers caused false poll loss or MTU fallback")
	}
	c.expireLocked(q.deadline.Add(time.Millisecond))
	if !q.expired || p.inflight != 0 || !reflect.DeepEqual(cs.lostQ, []uint64{7}) {
		t.Fatal("genuine poll loss was not recovered at its deadline")
	}
	c.expireLocked(q.deadline.Add(2 * time.Millisecond))
	if len(cs.lostQ) != 1 {
		t.Fatal("loss reported twice")
	}
}

func TestCottenMaxDataLossAllowsReordering(t *testing.T) {
	now := time.Now()
	p := &path{hasRTT: true, srtt: time.Millisecond, maxAnswered: 100, inflight: 1, cwnd: 32}
	q := &pendingQuery{p: p, sent: now, deadline: now.Add(200 * time.Millisecond)}
	c := &Client{paths: []*path{p}, pending: map[uint16]*pendingQuery{1: q}}
	c.expireLocked(now.Add(20 * time.Millisecond))
	if q.expired {
		t.Fatal("ordinary response reordering declared data lost")
	}
	c.expireLocked(now.Add(60 * time.Millisecond))
	if !q.expired {
		t.Fatal("fast recovery of an unanswered data query did not run")
	}
}

func TestCottenMaxACKOwnershipAndLossRequeue(t *testing.T) {
	s := newSession(true, streamConfig{MaxStreams: 1, StreamWindow: 65536, SendBuffer: 65536}, nil, nil)
	st, err := s.openStream()
	if err != nil {
		t.Fatal(err)
	}
	s.ctrlQ = nil
	st.smax = 65536
	st.sbuf = make([]byte, 100)
	st.spending.add(0, 100)
	// Fragmented ACKs fill a tiny query, as happens under a short-name cap.
	for pn := uint64(1); pn < 12; pn += 2 {
		s.recvd.add(pn, pn+1)
		s.toAck.add(pn, pn+1)
	}
	want := append(rangeSet(nil), s.toAck...)
	now := time.Now()
	_, _, _, first := s.build(nil, 16, now, 0)
	if first == nil || !reflect.DeepEqual(first.ack, want) || len(s.toAck) != 0 {
		t.Fatal("query did not take ownership of its ACK ranges")
	}
	_, _, data, second := s.build(nil, 16, now, 0)
	if !data || second == nil || len(second.streams) == 0 || len(second.ack) != 0 {
		t.Fatal("repeated ACKs starved stream data in the next query")
	}
	s.declareLost(first.pn)
	if !reflect.DeepEqual(s.toAck, want) {
		t.Fatal("lost query did not return ACK ranges for retransmission")
	}
	_, _, _, retry := s.build(nil, 16, now, 0)
	if retry == nil || !reflect.DeepEqual(retry.ack, want) {
		t.Fatal("ACK ranges were not retransmitted")
	}
	s.acked(retry)
	if len(s.toAck) != 0 || s.sent[retry.pn] != nil {
		t.Fatal("confirmed ACK packet was not retired")
	}
}
