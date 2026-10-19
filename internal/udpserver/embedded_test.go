package udpserver

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	DnsParser "cottendns-go/internal/dnsparser"
	Enums "cottendns-go/internal/enums"
	"cottendns-go/internal/security"
	VpnProto "cottendns-go/internal/vpnproto"
)

func TestEmbeddedIsolationPolicyAndShutdown(t *testing.T) {
	var allowed atomic.Bool
	allowed.Store(true)
	key := "embedded-account-key-material-000001"
	var tcpCalls, udpCalls, dnsCalls atomic.Int32
	policyErr := errors.New("account quota denied")
	e, err := NewEmbedded(context.Background(), EmbeddedConfig{Domain: "v.example.com", Key: key, Allowed: allowed.Load,
		DialContext: func(_ context.Context, network, address string) (net.Conn, error) {
			if network == "tcp" {
				tcpCalls.Add(1)
			} else {
				udpCalls.Add(1)
			}
			return nil, policyErr
		},
		ExchangeDNS: func(context.Context, []byte) ([]byte, error) { dnsCalls.Add(1); return nil, policyErr },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	codec, _ := security.NewCodec(5, key)
	query := secureTestQuery(t, codec, Enums.DNS_RECORD_TYPE_TXT, VpnProto.BuildOptions{SessionID: 255, PacketType: Enums.PACKET_MTU_UP_REQ, Payload: []byte{security.DownstreamEncryptedFlag, 1, 2, 3, 4}})
	response := e.HandleDNS(query)
	if _, err := DnsParser.ExtractEncryptedVPNResponseMatching(response, false, []string{"v.example.com"}, codec); err != nil {
		t.Fatal("native encrypted probe failed", err)
	}
	other, _ := security.NewCodec(5, key+"other")
	if _, err := DnsParser.ExtractEncryptedVPNResponseMatching(response, false, []string{"v.example.com"}, other); err == nil {
		t.Fatal("another account decrypted reply")
	}
	if _, err := e.s.dialTCPTargetContext(context.Background(), "8.8.8.8:443"); !errors.Is(err, policyErr) {
		t.Fatal("TCP bypassed policy", err)
	}
	u := newUDPAssociationConn(e.s)
	if _, err := u.endpointFor("8.8.8.8", 443); !errors.Is(err, policyErr) {
		t.Fatal("UDP bypassed policy", err)
	}
	u.Close()
	if e.s.buildDNSQueryResponsePayload([]byte("dns"), 1, 1) != nil {
		t.Fatal("DNS bypassed policy")
	}
	if tcpCalls.Load() != 1 || udpCalls.Load() != 1 || dnsCalls.Load() != 1 {
		t.Fatal("missing egress hooks")
	}
	allowed.Store(false)
	if len(e.HandleDNS(query)) != 0 {
		t.Fatal("disabled account still answered")
	}
	allowed.Store(true)
	done := make(chan struct{})
	go func() { e.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("embedded server did not stop")
	}
	if len(e.HandleDNS(query)) != 0 {
		t.Fatal("closed account answered")
	}
}

func TestEmbeddedRequiresPolicyHooks(t *testing.T) {
	if _, err := NewEmbedded(context.Background(), EmbeddedConfig{Domain: "v.example.com", Key: "embedded-account-key-material-000001"}); err == nil {
		t.Fatal("embedding without account policy was accepted")
	}
}
