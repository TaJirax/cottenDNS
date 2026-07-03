// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================

package vpnproto

import (
	"testing"

	Enums "cottendns-go/internal/enums"
)

// TestLegacySessionIDWireFormat locks the 1-byte MasterDNS/StormDNS header
// layout and the 2-byte CottenDns native layout so the compatibility switch
// cannot silently regress the on-wire format.
func TestLegacySessionIDWireFormat(t *testing.T) {
	defer ConfigureLegacySessionID(false) // restore package default

	// Legacy 1-byte format: [0]=sessionID, [1]=packetType.
	ConfigureLegacySessionID(true)
	if !LegacySessionID() {
		t.Fatal("expected legacy mode active")
	}
	legacyRaw, err := BuildRaw(BuildOptions{
		SessionID:     0x42,
		PacketType:    Enums.PACKET_PING,
		SessionCookie: 0x09,
	})
	if err != nil {
		t.Fatalf("legacy BuildRaw: %v", err)
	}
	if legacyRaw[0] != 0x42 || legacyRaw[1] != Enums.PACKET_PING {
		t.Fatalf("legacy header = [% x]; want sid=0x42 at [0], type at [1]", legacyRaw)
	}
	legacyParsed, err := Parse(legacyRaw)
	if err != nil {
		t.Fatalf("legacy Parse: %v", err)
	}
	if legacyParsed.SessionID != 0x42 || legacyParsed.PacketType != Enums.PACKET_PING {
		t.Fatalf("legacy round-trip mismatch: sid=%d type=%#x", legacyParsed.SessionID, legacyParsed.PacketType)
	}
	legacySize := HeaderRawSize(Enums.PACKET_PING)

	// Native 2-byte format: [0..1]=sessionID big-endian, [2]=packetType.
	ConfigureLegacySessionID(false)
	nativeRaw, err := BuildRaw(BuildOptions{
		SessionID:     0x0142,
		PacketType:    Enums.PACKET_PING,
		SessionCookie: 0x09,
	})
	if err != nil {
		t.Fatalf("native BuildRaw: %v", err)
	}
	if nativeRaw[0] != 0x01 || nativeRaw[1] != 0x42 || nativeRaw[2] != Enums.PACKET_PING {
		t.Fatalf("native header = [% x]; want sid=0x0142 at [0:2], type at [2]", nativeRaw)
	}
	nativeParsed, err := Parse(nativeRaw)
	if err != nil {
		t.Fatalf("native Parse: %v", err)
	}
	if nativeParsed.SessionID != 0x0142 {
		t.Fatalf("native round-trip sid = %d; want 0x0142", nativeParsed.SessionID)
	}
	nativeSize := HeaderRawSize(Enums.PACKET_PING)

	if nativeSize != legacySize+1 {
		t.Fatalf("native header should be 1 byte larger: native=%d legacy=%d", nativeSize, legacySize)
	}
}
