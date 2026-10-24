package udpserver

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"cottendns-go/internal/config"
	"cottendns-go/internal/cottenmax"
	"cottendns-go/internal/dnsparser"
	Enums "cottendns-go/internal/enums"
	"cottendns-go/internal/logger"
	"cottendns-go/internal/security"
	VpnProto "cottendns-go/internal/vpnproto"
)

func longLegacyDomain() string {
	return strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 61) + ".test"
}

// Exercise the actual UDP listener, not just a filter helper. A valid legacy
// MTU exchange must work on a long delegated domain even when Max cannot fit
// its handshake there; a compatible domain in the same config still runs Max.
func TestOptionalMaxDomainsDoNotPreventLegacyServerStartup(t *testing.T) {
	for _, mixed := range []bool{false, true} {
		t.Run(map[bool]string{false: "all_legacy_only", true: "mixed_domains"}[mixed], func(t *testing.T) {
			const secret = "unchanged shared server key"
			domains := []string{longLegacyDomain()}
			if mixed {
				domains = append(domains, "max.example")
			}
			dir := t.TempDir()
			path := filepath.Join(dir, "server.toml")
			quoted := make([]string, len(domains))
			for i, d := range domains {
				quoted[i] = strconv.Quote(d)
			}
			probe, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			port := probe.LocalAddr().(*net.UDPAddr).Port
			probe.Close()
			text := fmt.Sprintf("DOMAIN = [%s]\nUDP_HOST = \"127.0.0.1\"\nUDP_PORT = %d\nUDP_READERS = 1\nDNS_REQUEST_WORKERS = 1\nTCP_LISTENER_ENABLED = false\n", strings.Join(quoted, ","), port)
			if err := os.WriteFile(path, []byte(text), 0600); err != nil {
				t.Fatal(err)
			}
			cfg, err := config.LoadServerConfig(path)
			if err != nil {
				t.Fatal(err)
			}

			var origin net.Listener
			if mixed {
				origin, err = net.Listen("tcp4", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer origin.Close()
				cfg.ProtocolType = "TCP"
				cfg.ForwardIP = "127.0.0.1"
				cfg.ForwardPort = origin.Addr().(*net.TCPAddr).Port
			}
			keypath := filepath.Join(dir, "encrypt_key.txt")
			if err := os.WriteFile(keypath, []byte(secret), 0600); err != nil {
				t.Fatal(err)
			}
			// A skipped optional module must not create an explicitly configured old
			// experimental identity. Mixed domains retain the normal shared identity.
			if !mixed {
				cfg.CottenMaxKeyFile = "unused-identity.key"
			}
			codec, err := security.NewCodec(1, secret)
			if err != nil {
				t.Fatal(err)
			}
			log := logger.New("optional-max-test", "ERROR")
			defer log.Close()
			server := New(cfg, log, codec)
			server.SetCottenMaxSecret(secret)
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- server.Run(ctx) }()
			defer func() {
				cancel()
				select {
				case err := <-done:
					if err != nil && !errors.Is(err, context.Canceled) {
						t.Error(err)
					}
				case <-time.After(2 * time.Second):
					t.Error("server did not stop")
				}
			}()
			limit := time.Now().Add(time.Second)
			for !server.running.Load() && time.Now().Before(limit) {
				select {
				case err := <-done:
					done <- err
					t.Fatalf("legacy server stopped before listening: %v", err)
				default:
				}
				time.Sleep(time.Millisecond)
			}
			if !server.running.Load() {
				t.Fatal("legacy UDP listener did not start")
			}
			if (server.cottenMax != nil) != mixed {
				t.Fatalf("optional Max active=%v mixed=%v", server.cottenMax != nil, mixed)
			}
			if !reflect.DeepEqual(server.cfg.Domain, domains) {
				t.Fatalf("legacy domains changed: %v", server.cfg.Domain)
			}
			encoded, err := VpnProto.BuildEncoded(VpnProto.BuildOptions{SessionID: 255, PacketType: Enums.PACKET_MTU_UP_REQ, Payload: []byte{0, 1, 2, 3, 4}}, codec)
			if err != nil {
				t.Fatal(err)
			}
			query, err := dnsparser.BuildTunnelTXTQuestionPacket(domains[0], []byte(encoded), Enums.DNS_RECORD_TYPE_TXT, 1232)
			if err != nil {
				t.Fatal(err)
			}
			socket, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
			if err != nil {
				t.Fatal(err)
			}
			defer socket.Close()
			socket.SetDeadline(time.Now().Add(time.Second))
			if _, err := socket.Write(query); err != nil {
				t.Fatal(err)
			}
			response := make([]byte, 4096)
			n, err := socket.Read(response)
			if err != nil {
				t.Fatal(err)
			}
			packet, err := dnsparser.ExtractVPNResponseMatching(response[:n], false, []string{domains[0]})
			if err != nil || packet.PacketType != Enums.PACKET_MTU_UP_RES || (len(packet.Payload) < 4 || !bytes.Equal(packet.Payload[:4], []byte{1, 2, 3, 4})) {
				t.Fatalf("legacy MTU exchange: %+v %v", packet, err)
			}
			raw, err := os.ReadFile(keypath)
			if err != nil || string(raw) != secret {
				t.Fatalf("existing key changed: %q %v", raw, err)
			}
			if !mixed {
				if _, err := os.Stat(filepath.Join(dir, "unused-identity.key")); !os.IsNotExist(err) {
					t.Fatal("disabled Max created or accessed separate identity")
				}
			}
			if mixed {
				// The strict standalone API still rejects the long domain; the optional
				// adapter filters only its own copy and accepts Max on the valid domain.
				if err := cottenmax.ValidateServerDomain(domains[0]); err == nil {
					t.Fatal("fixture unexpectedly fits Max")
				}
				go func() {
					conn, err := origin.Accept()
					if err != nil {
						return
					}
					defer conn.Close()
					stop := context.AfterFunc(ctx, func() { conn.Close() })
					defer stop()
					io.Copy(conn, conn)
				}()
				max, err := cottenmax.NewClient(cottenmax.ClientConfig{Domain: "max.example", Secret: secret, Resolvers: []string{socket.RemoteAddr().String()}, TCP: "off"})
				if err != nil {
					t.Fatal(err)
				}
				defer max.Close()
				dialctx, stop := context.WithTimeout(ctx, time.Second)
				defer stop()
				conn, err := max.Dial(dialctx, "forward:0")
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(time.Second))
				message := []byte("Max and legacy share one server")
				if _, err := conn.Write(message); err != nil {
					t.Fatal(err)
				}
				reply := make([]byte, len(message))
				if _, err := io.ReadFull(conn, reply); err != nil || !bytes.Equal(reply, message) {
					t.Fatalf("Max echo: %q %v", reply, err)
				}
			}
		})
	}
}

func TestExplicitMaxWithNoCompatibleDomainsFailsClearly(t *testing.T) {
	server := &Server{cfg: config.ServerConfig{TunnelMode: config.TunnelCottenMax, Domain: []string{longLegacyDomain()}}}
	server.SetCottenMaxSecret("same key")
	err := server.startCottenMax(context.Background())
	if err == nil || !strings.Contains(err.Error(), "no compatible") {
		t.Fatalf("explicit Max startup error: %v", err)
	}
	if server.cottenMax != nil {
		server.cottenMax.Close()
		t.Fatal("invalid explicit Max started")
	}
}
