// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================
// compat.go — wire-format compatibility for the MasterDNS/StormDNS lineage.
//
// CottenDns widened the on-wire session-ID field from 1 byte to 2 bytes to grow
// the session space to 65535. That change is incompatible with servers speaking
// the original 1-byte format (MasterDNS, StormDNS, WhiteDNS). To let one client
// talk to either server generation, the session-ID width is configurable and
// applied uniformly to the packet header (here) and the session-accept payload
// (see internal/client/session.go).
//
// The width is process-global and set once at client startup via
// ConfigureLegacySessionID before any packet is built or parsed. This is safe
// because a client process serves exactly one server profile for its lifetime;
// the server binary never calls this and stays on the 2-byte native format.
// ==============================================================================
package vpnproto

// sessionIDLen is the on-wire width, in bytes, of the session-ID header field.
// 2 = CottenDns native; 1 = legacy MasterDNS/StormDNS/WhiteDNS.
var sessionIDLen = 2

// ConfigureLegacySessionID selects the on-wire session-ID width. Call once at
// startup, before building or parsing any packet. legacy=true selects the
// 1-byte MasterDNS/StormDNS format; legacy=false selects CottenDns's 2-byte
// native format (the default).
func ConfigureLegacySessionID(legacy bool) {
	if legacy {
		sessionIDLen = 1
		return
	}
	sessionIDLen = 2
}

// LegacySessionID reports whether the 1-byte legacy wire format is active.
func LegacySessionID() bool { return sessionIDLen == 1 }

// headerBaseLen is the fixed prefix length: session ID + packet type.
func headerBaseLen() int { return sessionIDLen + 1 }

// minHeaderLen is the shortest valid header: base prefix + integrity trailer.
func minHeaderLen() int { return headerBaseLen() + integrityLength }

func writeSessionID(raw []byte, id uint16) {
	if sessionIDLen == 1 {
		raw[0] = byte(id)
		return
	}
	raw[0] = byte(id >> 8)
	raw[1] = byte(id)
}

func readSessionID(data []byte) uint16 {
	if sessionIDLen == 1 {
		return uint16(data[0])
	}
	return (uint16(data[0]) << 8) | uint16(data[1])
}
