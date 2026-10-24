package soar

import (
	"bytes"
	"testing"
)

func TestOptionalQNameShapingCapacityAndRoundTrip(t *testing.T) {
	for _, label := range []int{16, 32, 63} {
		for _, jitter := range []bool{false, true} {
			z, err := parseZone(testZone)
			if err != nil {
				t.Fatal(err)
			}
			z.labelLength, z.labelJitter = label, jitter
			for limit := 80; limit <= 253; limit++ {
				size := z.maxPayload(limit)
				if size < 1 {
					continue
				}
				payload := bytes.Repeat([]byte{0x9d}, size)
				for id := uint16(0); id < 8; id++ {
					wire := appendQuery(nil, id, payload, z, typeTXT, 1232)
					end, err := skipName(wire, hdrLen)
					if err != nil {
						t.Fatal(err)
					}
					if end-hdrLen-2 > limit {
						t.Fatalf("label=%d jitter=%v limit=%d actual=%d", label, jitter, limit, end-hdrLen-2)
					}
					decoded, err := parseQuery(wire, z)
					if err != nil || !bytes.Equal(decoded.payload, payload) {
						t.Fatalf("shaped query lost payload: %v", err)
					}
				}
			}
		}
	}
}

func TestOptionalQNameCountVariesWithoutChangingPayload(t *testing.T) {
	z, _ := parseZone(testZone)
	z.labelLength = 32
	z.labelJitter = true
	payload := bytes.Repeat([]byte{3}, 40)
	counts := map[int]bool{}
	for id := uint16(0); id < 16; id++ {
		msg := appendQuery(nil, id, payload, z, typeTXT, 1232)
		count := 0
		for pos := hdrLen; msg[pos] != 0; {
			n := int(msg[pos])
			pos += n + 1
			count++
		}
		counts[count] = true
	}
	if len(counts) < 2 {
		t.Fatal("enabled label-count shaping did not vary labels")
	}
}

func TestDefaultQNameShapingRetainsWireBytes(t *testing.T) {
	z, _ := parseZone(testZone)
	implicit := appendQuery(nil, 42, bytes.Repeat([]byte{7}, 80), z, typeTXT, 1232)
	z.labelLength = 63
	explicit := appendQuery(nil, 42, bytes.Repeat([]byte{7}, 80), z, typeTXT, 1232)
	if !bytes.Equal(implicit, explicit) {
		t.Fatal("default shaping changed wire format")
	}
}
