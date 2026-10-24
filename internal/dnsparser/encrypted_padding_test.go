package dnsparser

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestEncryptedDNSPaddingPreservesQueryAndOptions(t *testing.T) {
	for _, withOPT := range []bool{false, true} {
		packet := []byte{0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 'a', 0, 0, 16, 0, 1}
		if withOPT {
			packet[11] = 1
			packet = append(packet, 0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 12, 0, 10, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8)
		}
		original := append([]byte(nil), packet...)
		padded, err := PadEncryptedDNSQuery(packet, 128)
		if err != nil {
			t.Fatal(err)
		}
		if len(padded)%128 != 0 || !bytes.Equal(packet, original) || !bytes.Equal(padded[:10], packet[:10]) || !bytes.Equal(padded[12:19], packet[12:19]) {
			t.Fatal("padding changed query or input")
		}
		if withOPT && !bytes.Contains(padded, packet[len(packet)-12:]) {
			t.Fatal("COOKIE lost")
		}
		again, err := PadEncryptedDNSQuery(padded, 128)
		if err != nil || !bytes.Equal(padded, again) {
			t.Fatalf("padding is not idempotent: %v", err)
		}
		parsed, err := ParseDNSRequestLite(padded)
		if err != nil || parsed.Header.ID != 0x1234 || !parsed.HasQuestion {
			t.Fatalf("invalid padded query: %v", err)
		}
	}
}

func TestEncryptedDNSPaddingRejectsMalformedInput(t *testing.T) {
	query := []byte{0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 'a', 0, 0, 16, 0, 1}
	for _, block := range []int{-1, 1, 4097} {
		if _, err := PadEncryptedDNSQuery(query, block); err == nil {
			t.Fatal("invalid block accepted")
		}
	}
	reply := append([]byte(nil), query...)
	reply[2] |= 0x80
	badOPT := append([]byte(nil), query...)
	badOPT[11] = 1
	badOPT = append(badOPT, 0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 4, 0, 10, 0, 8)
	for _, packet := range [][]byte{nil, query[:15], reply, badOPT, append(query, 0)} {
		if _, err := PadEncryptedDNSQuery(packet, 128); err == nil {
			t.Fatal("invalid packet accepted")
		}
	}
	huge := append([]byte(nil), query...)
	huge[11] = 1
	size := 65535 - len(huge) - 11
	huge = append(huge, 0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0)
	binary.BigEndian.PutUint16(huge[len(huge)-2:], uint16(size))
	huge = append(huge, make([]byte, size)...)
	if _, err := PadEncryptedDNSQuery(huge, 4096); err == nil {
		t.Fatal("oversized padding accepted")
	}
	unchanged, err := PadEncryptedDNSQuery(query, 0)
	if err != nil || !bytes.Equal(query, unchanged) {
		t.Fatal("disabled padding changed wire")
	}
}
