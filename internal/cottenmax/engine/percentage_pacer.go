package soar

import (
	"math"
	"sync"
	"time"
)

// PercentagePacer shares one token bucket across all domain engines. Its rate
// comes from their unscaled congestion windows and RTT, never achieved paced
// throughput: measuring that would apply the reduction repeatedly toward zero.
// The target is approximate, especially when CPU or application work is limiting.
type PercentagePacer struct {
	mu           sync.Mutex
	reduction    int
	keep         float64
	references   map[*Client]float64
	rate, tokens float64
	last         time.Time
}

const percentageBurst = 4.0

// NewPercentagePacer constructs a 10..90 percent reduction target.
func NewPercentagePacer(reduction int) *PercentagePacer {
	if reduction < 10 || reduction > 90 {
		panic("soar: reduction percent must be 10..90")
	}
	return &PercentagePacer{reduction: reduction, keep: float64(100-reduction) / 100, references: make(map[*Client]float64), tokens: percentageBurst}
}

func (p *PercentagePacer) refillLocked(now time.Time) {
	if p.last.IsZero() {
		p.last = now
		return
	}
	if now.After(p.last) {
		p.tokens = min(percentageBurst, p.tokens+now.Sub(p.last).Seconds()*p.rate)
		p.last = now
	}
}

func (p *PercentagePacer) update(owner *Client, reference float64, now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.refillLocked(now)
	if reference > 0 {
		p.references[owner] = reference
	} else {
		delete(p.references, owner)
	}
	p.rate = 0
	for _, rate := range p.references {
		p.rate += rate * p.keep
	}
}

func (p *PercentagePacer) remove(owner *Client, now time.Time) { p.update(owner, 0, now) }

// TryTake is nonblocking and may be called under an engine's mutex. Only one
// shared burst can accumulate while idle. An initial burst permits bootstrap.
func (p *PercentagePacer) TryTake(now time.Time) (bool, time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.refillLocked(now)
	if p.tokens >= 1 {
		p.tokens--
		return true, time.Time{}
	}
	if p.rate <= 0 {
		return false, now.Add(time.Second)
	}
	wait := time.Duration(math.Ceil((1 - p.tokens) / p.rate * float64(time.Second)))
	return false, p.last.Add(max(wait, time.Nanosecond))
}

func (c *Client) percentageFlightLimit() int {
	if c.cfg.LowReductionPercent == 0 {
		return c.cfg.MaxInflight
	}
	return max(1, c.cfg.MaxInflight*(100-c.cfg.LowReductionPercent)/100)
}

func (c *Client) percentagePathWindow(p *path) float64 {
	if c.cfg.LowReductionPercent == 0 {
		return p.cwnd
	}
	return max(1, math.Floor(min(p.cwnd, float64(c.cfg.MaxPathWindow))*float64(100-c.cfg.LowReductionPercent)/100))
}

// updatePercentageReferenceLocked publishes only this engine's currently usable
// Full reference. p.srtt already excludes advertised server hold time. The RTT
// floor prevents near-zero loopback samples producing an unbounded token rate.
func (c *Client) updatePercentageReferenceLocked(now time.Time) {
	pacer := c.cfg.PercentagePacer
	if pacer == nil {
		return
	}
	select {
	case <-c.done:
		pacer.remove(c, now)
		return
	default:
	}
	cs := c.sess
	if cs == nil || (cs.established && cs.isClosed()) {
		pacer.remove(c, now)
		return
	}
	if cs.established && !cs.busy() && !now.Before(c.probeUntil) {
		pacer.remove(c, now)
		return
	}
	window, rate := 0.0, 0.0
	verified := c.anyUsableLocked(now)
	for _, path := range c.paths {
		if !path.usable(now) || (verified && !path.verified) {
			continue
		}
		w := min(path.cwnd, float64(c.cfg.MaxPathWindow))
		rtt := path.rto()
		if path.hasRTT {
			rtt = path.srtt
		}
		window += w
		rate += w / max(rtt, time.Millisecond).Seconds()
	}
	if window > float64(c.cfg.MaxInflight) {
		rate *= float64(c.cfg.MaxInflight) / window
	}
	pacer.update(c, rate, now)
}
