package soar

import (
	"crypto/ecdh"
	"crypto/rand"
	"math"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestPercentagePacerSharedRateTargetsAndCleanup(t *testing.T) {
	for _, reduction := range []int{10, 35, 90} {
		p := NewPercentagePacer(reduction)
		a, b := &Client{}, &Client{}
		now := time.Unix(1000, 0)
		p.update(a, 100, now)
		p.update(b, 300, now)
		want := 400 * float64(100-reduction) / 100
		if math.Abs(p.rate-want) > 1e-9 {
			t.Fatalf("target%d: sharedrate%v want%v", reduction, p.rate, want)
		}
		var admitted atomic.Int32
		var wg sync.WaitGroup
		for range 32 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if ok, _ := p.TryTake(now); ok {
					admitted.Add(1)
				}
			}()
		}
		wg.Wait()
		if admitted.Load() != 4 {
			t.Fatalf("independent owners multiplied burst: %d", admitted.Load())
		}
		ok, next := p.TryTake(now)
		if ok || math.Abs(float64(next.Sub(now))-float64(time.Second)/want) > 2 {
			t.Fatalf("incorrect aggregate delay: %v %v", ok, next.Sub(now))
		}
		// Updating with the same CC reference must not multiply the reduction.
		for range 100 {
			p.update(a, 100, now)
		}
		if math.Abs(p.rate-want) > 1e-9 {
			t.Fatal("paced rate fed back into reference")
		}
		p.remove(b, now)
		if math.Abs(p.rate-100*float64(100-reduction)/100) > 1e-9 || len(p.references) != 1 {
			t.Fatal("closed owner still contributes")
		}
		p.remove(a, now)
		if p.rate != 0 || len(p.references) != 0 {
			t.Fatal("reference leaked after closing all owners")
		}
	}
}

func TestPercentageReferenceUsesUnscaledCCAndHoldAdjustedRTT(t *testing.T) {
	c, good, _, _ := schedulerFixture(t, 0, 256)
	c.cfg.MaxPathWindow, c.cfg.MaxInflight = 100, 80
	c.cfg.LowReductionPercent = 35
	c.cfg.PercentagePacer = NewPercentagePacer(35)
	good.cwnd, good.srtt, good.hasRTT = 100, 100*time.Millisecond, true
	now := time.Now()
	c.updatePercentageReferenceLocked(now)
	if got := c.cfg.PercentagePacer.rate; math.Abs(got-520) > 1e-9 {
		t.Fatalf("Full 80/.1 reference must keep65%%, got%v", got)
	}
	if c.percentageFlightLimit() != 52 || c.percentagePathWindow(good) != 65 || good.cwnd != 100 || c.cfg.MaxPathWindow != 100 {
		t.Fatal("reference was scaled or flight gate is incorrect")
	}
	for _, reduction := range []int{10, 35, 90} {
		c.cfg.LowReductionPercent = reduction
		if c.percentageFlightLimit() != 80*(100-reduction)/100 || c.percentagePathWindow(good) != float64(100-reduction) {
			t.Fatal("incorrect reduction bounds")
		}
	}
	c.cfg.LowReductionPercent = 0
	if c.percentageFlightLimit() != 80 || c.percentagePathWindow(good) != 100 {
		t.Fatal("Full path changed")
	}
}

func TestPercentagePacingDoesNotMutateUnsentDataOrProbes(t *testing.T) {
	c, good, st, pc := schedulerFixture(t, 0, 32)
	c.cfg.LowReductionPercent = 35
	c.cfg.PercentagePacer = NewPercentagePacer(35)
	c.cfg.MaxQName = 253
	good.successes = 3
	now := time.Now()
	c.updatePercentageReferenceLocked(now)
	for range 4 {
		c.cfg.PercentagePacer.TryTake(now)
	}
	controls := append([]ctrl(nil), c.sess.ctrlQ...)
	pending := append(rangeSet(nil), st.spending...)
	if c.sendDataWithSlotsLocked(c.sess, good, now, true, 32) != 0 {
		t.Fatal("denied query sent")
	}
	if len(pc.writes) != 0 || len(c.pending) != 0 || len(c.sess.sent) != 0 || good.probing || good.alt != 0 || good.inflight != 0 || !reflect.DeepEqual(controls, c.sess.ctrlQ) || !reflect.DeepEqual(pending, st.spending) {
		t.Fatal("local pacing mutated unsent packet/probe/ARQ state")
	}
	if !c.rateNext.After(now) {
		t.Fatal("no pacing wake scheduled")
	}
	if c.sendDataWithSlotsLocked(c.sess, good, c.rateNext.Add(time.Nanosecond), false, 32) != 1 {
		t.Fatal("paced probe did not resume")
	}
}

func TestPercentagePacingBootstrapAndUnsentHelloClock(t *testing.T) {
	c, _, _, pc := schedulerFixture(t, 2, 32)
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c.sess.eph, c.sess.established = eph, false
	c.cfg.LowReductionPercent, c.cfg.PercentagePacer = 90, NewPercentagePacer(90)
	for _, path := range c.paths {
		path.verified, path.hasRTT, path.cwnd = false, false, 4
	}
	now := time.Now()
	c.updatePercentageReferenceLocked(now)
	if c.cfg.PercentagePacer.rate <= 0 {
		t.Fatal("bootstrap cannot progress without a verified RTT")
	}
	for range 4 {
		c.cfg.PercentagePacer.TryTake(now)
	}
	c.sendHellosLocked(c.sess, now)
	if len(pc.writes) != 0 || !c.sess.firstHello.IsZero() {
		t.Fatal("denied HELLO changed clock or socket")
	}
	for _, path := range c.paths {
		if !path.lastHello.IsZero() || path.inflight != 0 {
			t.Fatal("denied HELLO changed path")
		}
	}
	c.sendHellosLocked(c.sess, c.rateNext.Add(time.Nanosecond))
	if len(pc.writes) == 0 || c.sess.firstHello.IsZero() {
		t.Fatal("bootstrap HELLO did not resume")
	}
}

func TestPercentageFlightGateAndClosedReferenceCleanup(t *testing.T) {
	c, good, _, pc := schedulerFixture(t, 0, 32)
	c.done = make(chan struct{})
	c.cfg.LowReductionPercent, c.cfg.PercentagePacer = 35, NewPercentagePacer(35)
	now := time.Now()
	c.updatePercentageReferenceLocked(now)
	good.inflight = int(c.percentagePathWindow(good))
	if c.sendDataWithSlotsLocked(c.sess, good, now, false, 32) != 0 || len(pc.writes) != 0 || len(c.sess.sent) != 0 {
		t.Fatal("scaled flight gate mutated unsent packet")
	}
	if good.cwnd != 32 {
		t.Fatal("Low modified unscaled congestion reference")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	p := c.cfg.PercentagePacer
	if len(p.references) != 0 || p.rate != 0 {
		t.Fatal("Close leaked reference")
	}
	c.updatePercentageReferenceLocked(now.Add(time.Second))
	if len(p.references) != 0 {
		t.Fatal("scheduler re-registered closed engine")
	}
}
