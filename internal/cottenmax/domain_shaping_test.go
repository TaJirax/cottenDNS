package cottenmax

import (
	"context"
	"net"
	"strings"
	"testing"
)

// Validate every backup before opening any primary socket, including the
// separators and reserved count variation used by the wire encoder.
func TestStandbyShapingCapacityValidatedBeforeSocket(t *testing.T) {
	backup := strings.Repeat("x", 28) + ".io"
	for _, shape := range []struct {
		label  int
		jitter bool
	}{{16, false}, {63, true}} {
		opened := false
		_, err := NewClient(ClientConfig{Domain: "a.io", Domains: []string{backup}, Secret: "same-existing-key", Resolvers: []string{"127.0.0.1:53"}, SafeQName: 101, QNameLabelLength: shape.label, QNameLabelJitter: shape.jitter, ListenPacket: func(context.Context, string, string) (net.PacketConn, error) {
			opened = true
			return nil, net.ErrClosed
		}})
		if err == nil || opened {
			t.Fatalf("shape=%+v err=%v opened=%v", shape, err, opened)
		}
	}
	if _, err := normalizeFailoverDomainsShaped("a.io", []string{backup}, 101, 63, false); err != nil {
		t.Fatalf("unshaped domain should fit: %v", err)
	}
}
