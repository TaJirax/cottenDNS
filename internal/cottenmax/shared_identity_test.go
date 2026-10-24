package cottenmax

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

func TestSharedIdentityIsStableSeparatedAndRejectsEmpty(t *testing.T) {
	a, err := SharedIdentity("existing-cottendns-credential")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := SharedIdentity("existing-cottendns-credential")
	other, _ := SharedIdentity("different-credential")
	if !bytes.Equal(a, b) || bytes.Equal(a, other) {
		t.Fatal("identity does not follow the shared credential")
	}
	if bytes.Equal(a.Seed(), []byte("existing-cottendns-credential")) {
		t.Fatal("identity lacks key separation")
	}
	message := []byte("test transcript")
	if !ed25519.Verify(a.Public().(ed25519.PublicKey), message, ed25519.Sign(a, message)) {
		t.Fatal("derived identity invalid")
	}
	if _, err := SharedIdentity(" "); err == nil {
		t.Fatal("empty credential accepted")
	}
}

func TestDNSFrameRoundtripAndBounds(t *testing.T) {
	for _, size := range []int{12, 4096, 65535} {
		packet := bytes.Repeat([]byte{0x42}, size)
		var frame bytes.Buffer
		if err := WriteDNSFrame(&frame, packet); err != nil {
			t.Fatal(err)
		}
		got, err := ReadDNSFrame(&frame)
		if err != nil || !bytes.Equal(got, packet) {
			t.Fatalf("size %d: %v", size, err)
		}
	}
	for _, size := range []int{0, 11, 65536} {
		if err := WriteDNSFrame(&bytes.Buffer{}, make([]byte, size)); err == nil {
			t.Fatal("invalid frame accepted")
		}
	}
	if _, err := ReadDNSFrame(bytes.NewReader([]byte{0, 20, 0})); err == nil {
		t.Fatal("truncated frame accepted")
	}
}
