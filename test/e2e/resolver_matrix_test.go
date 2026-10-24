//go:build e2e

// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================
// resolver_matrix_test.go — runs the real client and server through a simulated
// recursive resolver that does to answers what public and ISP resolvers do in
// the wild (reorder, 0x20 case, caching, CNAME chasing, EDNS rewriting, private
// address filtering, refused types, forged NXDOMAIN, loss), across every
// carrier and the Android presets. Diagnostic, so it is opt-in:
//
//	COTTEN_RESOLVER_MATRIX=1 go test -tags e2e -run ResolverMatrix -parallel 8 -timeout 90m ./test/e2e/
// ==============================================================================

package e2e

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	typeA     = 1
	typeCNAME = 5
	typeTXT   = 16
	typeAAAA  = 28
	typeOPT   = 41
	typeNULL  = 10
	typeHTTPS = 65
)

type resolverSim struct {
	shuffle  bool           // reorder answer RRs (resolvers rotate RRsets)
	case0x20 bool           // randomize QNAME case upstream, drop replies that do not echo it
	cache    bool           // answer repeated questions from cache
	chase    bool           // follow a CNAME answer to an A/AAAA question
	edns     int            // 0 keep, >0 rewrite the UDP size upstream, -1 strip OPT
	filter   []netip.Prefix // strip A/AAAA answers inside these (rebinding protection)
	refuse   []uint16       // SERVFAIL these query types
	nx       string         // "race": forged NXDOMAIN, then the real answer; "drop": forged only
	loss     float64        // drop this share of queries
}

func prefixes(list ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(list))
	for i, p := range list {
		out[i] = netip.MustParsePrefix(p)
	}
	return out
}

// Unbound private-address / dnsmasq stop-dns-rebind style lists.
var rebindRanges = prefixes("0.0.0.0/8", "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16",
	"::1/128", "::ffff:0:0/96", "fc00::/7", "fe80::/10")

// Bogon filtering as some ISP middleboxes do it: also CGNAT, multicast,
// reserved, and the IPv6 ::/8 reserved block.
var bogonRanges = append(slices.Clone(rebindRanges), prefixes("100.64.0.0/10", "224.0.0.0/4", "240.0.0.0/4", "::/8")...)

func startResolverSim(t *testing.T, ip net.IP, upstream *net.UDPAddr, sim resolverSim) string {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: ip})
	if err != nil {
		t.Fatalf("sim listen: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	var mu sync.Mutex
	cache := map[string][]byte{}
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			q := slices.Clone(buf[:n])
			go func() {
				send := func(b []byte) { _, _ = pc.WriteToUDP(b, from) }
				qEnd, qtype, ok := questionEnd(q)
				if !ok || (sim.loss > 0 && rand.Float64() < sim.loss) {
					return
				}
				if slices.Contains(sim.refuse, qtype) {
					send(rcodeReply(q, qEnd, 2))
					return
				}
				if sim.nx != "" {
					send(rcodeReply(q, qEnd, 3))
					if sim.nx == "drop" {
						return
					}
					time.Sleep(20 * time.Millisecond)
				}
				key := strings.ToLower(string(q[12:qEnd]))
				if sim.cache {
					mu.Lock()
					hit, ok := cache[key]
					mu.Unlock()
					if ok {
						r := slices.Clone(hit)
						copy(r[0:2], q[0:2])
						copy(r[12:qEnd], q[12:qEnd])
						send(r)
						return
					}
				}
				resp, ok := sim.exchange(upstream, q, qEnd)
				if !ok {
					return
				}
				resp = sim.rewrite(upstream, resp, qEnd, qtype)
				if sim.cache {
					mu.Lock()
					cache[key] = resp
					mu.Unlock()
				}
				send(resp)
			}()
		}
	}()
	return pc.LocalAddr().String()
}

func (sim resolverSim) exchange(upstream *net.UDPAddr, q []byte, qEnd int) ([]byte, bool) {
	up := slices.Clone(q)
	if sim.case0x20 {
		for i := 13; i < qEnd-4; i++ {
			if c := up[i]; ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) && rand.IntN(2) == 0 {
				up[i] ^= 0x20
			}
		}
	}
	up = sim.rewriteEDNS(up, qEnd)
	resp, ok := udpExchange(upstream, up)
	if !ok || len(resp) < qEnd || !bytes.EqualFold(resp[12:qEnd], q[12:qEnd]) {
		return nil, false
	}
	if sim.case0x20 && !bytes.Equal(resp[12:qEnd], up[12:qEnd]) {
		return nil, false // a 0x20 resolver treats a case mismatch as spoofed
	}
	copy(resp[0:2], q[0:2])
	copy(resp[12:qEnd], q[12:qEnd])
	return resp, true
}

func udpExchange(upstream *net.UDPAddr, q []byte) ([]byte, bool) {
	conn, err := net.DialUDP("udp", nil, upstream)
	if err != nil {
		return nil, false
	}
	defer conn.Close()
	q = slices.Clone(q)
	binary.BigEndian.PutUint16(q[0:2], uint16(rand.IntN(65536)))
	if _, err := conn.Write(q); err != nil {
		return nil, false
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 65535)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return nil, false
		}
		if n >= 12 && bytes.Equal(buf[0:2], q[0:2]) {
			return slices.Clone(buf[:n]), true
		}
	}
}

// rewriteEDNS edits the OPT record of a query (questions only, no answers).
func (sim resolverSim) rewriteEDNS(q []byte, qEnd int) []byte {
	if sim.edns == 0 {
		return q
	}
	off := qEnd
	for i := 0; i < int(binary.BigEndian.Uint16(q[10:12])); i++ {
		end, typ, _, _, ok := skipRR(q, off)
		if !ok {
			return q
		}
		if typ == typeOPT {
			if sim.edns < 0 {
				out := append(slices.Clone(q[:off]), q[end:]...)
				binary.BigEndian.PutUint16(out[10:12], binary.BigEndian.Uint16(q[10:12])-1)
				return out
			}
			nameEnd, _ := skipName(q, off)
			binary.BigEndian.PutUint16(q[nameEnd+2:nameEnd+4], uint16(sim.edns))
			return q
		}
		off = end
	}
	return q
}

// rewrite applies answer-side behaviors and rebuilds the reply when anything
// changed (authority dropped, OPT kept), like a minimal-responses resolver.
func (sim resolverSim) rewrite(upstream *net.UDPAddr, resp []byte, qEnd int, qtype uint16) []byte {
	if resp[3]&0x0F != 0 {
		return resp
	}
	an := int(binary.BigEndian.Uint16(resp[6:8]))
	ns := int(binary.BigEndian.Uint16(resp[8:10]))
	ar := int(binary.BigEndian.Uint16(resp[10:12]))
	var answers, opts [][]byte
	off := qEnd
	for i := 0; i < an+ns+ar; i++ {
		end, typ, _, _, ok := skipRR(resp, off)
		if !ok {
			return resp
		}
		switch {
		case i < an:
			rr, ok := canonicalRR(resp, off, end)
			if !ok {
				return resp
			}
			answers = append(answers, rr)
		case i >= an+ns && typ == typeOPT:
			opts = append(opts, resp[off:end])
		}
		off = end
	}

	modified := false
	if len(sim.filter) > 0 {
		kept := answers[:0:0]
		for _, rr := range answers {
			if addr, ok := rrAddr(rr); ok && slices.ContainsFunc(sim.filter, func(p netip.Prefix) bool { return p.Contains(addr) }) {
				modified = true
				continue
			}
			kept = append(kept, rr)
		}
		answers = kept
	}
	if sim.chase && (qtype == typeA || qtype == typeAAAA) {
		answers, modified = sim.chaseCNAME(upstream, qEnd, qtype, answers, modified)
	}
	if sim.shuffle && len(answers) > 1 {
		rand.Shuffle(len(answers), func(i, j int) { answers[i], answers[j] = answers[j], answers[i] })
		modified = true
	}
	if !modified {
		return resp
	}
	out := slices.Clone(resp[:qEnd])
	binary.BigEndian.PutUint16(out[6:8], uint16(len(answers)))
	binary.BigEndian.PutUint16(out[8:10], 0)
	binary.BigEndian.PutUint16(out[10:12], uint16(len(opts)))
	for _, rr := range append(answers, opts...) {
		out = append(out, rr...)
	}
	return out
}

func (sim resolverSim) chaseCNAME(upstream *net.UDPAddr, qEnd int, qtype uint16, answers [][]byte, modified bool) ([][]byte, bool) {
	var target string
	for _, rr := range answers {
		_, typ, _, _, _ := skipRR(rr, 0)
		if typ == qtype {
			return answers, modified
		}
		if typ == typeCNAME && target == "" {
			_, _, rd, _, _ := skipRR(rr, 0) // canonicalRR left no pointers
			target, _ = readName(rr, rd)
		}
	}
	if target == "" {
		return answers, modified
	}
	q := make([]byte, 12, 64)
	binary.BigEndian.PutUint16(q[2:4], 0x0100)
	binary.BigEndian.PutUint16(q[4:6], 1)
	q = append(q, encodeName(target)...)
	q = binary.BigEndian.AppendUint16(q, qtype)
	q = binary.BigEndian.AppendUint16(q, 1)
	chased, ok := udpExchange(upstream, q)
	if !ok || chased[3]&0x0F != 0 {
		return answers, modified
	}
	off := len(q)
	for i := 0; i < int(binary.BigEndian.Uint16(chased[6:8])); i++ {
		end, typ, _, _, ok := skipRR(chased, off)
		if !ok {
			break
		}
		if typ == typeA || typ == typeAAAA || typ == typeTXT {
			nameEnd, _ := skipName(chased, off)
			answers = append(answers, append(encodeName(target), chased[nameEnd:end]...))
			modified = true
		}
		off = end
	}
	return answers, modified
}

// canonicalRR re-encodes an answer with uncompressed names, as a resolver does
// when it rebuilds a reply, so reordering or dropping answers cannot leave a
// compression pointer aimed at a record that moved.
func canonicalRR(b []byte, off, end int) ([]byte, bool) {
	owner, ok := readName(b, off)
	nameEnd, _ := skipName(b, off)
	if !ok {
		return nil, false
	}
	typ := binary.BigEndian.Uint16(b[nameEnd : nameEnd+2])
	rd := nameEnd + 10
	rdata := b[rd:end]
	var prefix int
	switch typ {
	case typeCNAME, 2 /* NS */, 12 /* PTR */ :
		prefix = 0
	case 15 /* MX */ :
		prefix = 2
	default:
		prefix = -1 // no compressible names in rdata
	}
	if prefix >= 0 {
		target, ok := readName(b, rd+prefix)
		if !ok {
			return nil, false
		}
		rdata = append(slices.Clone(b[rd:rd+prefix]), encodeName(target)...)
	}
	out := append(encodeName(owner), b[nameEnd:nameEnd+8]...)
	out = binary.BigEndian.AppendUint16(out, uint16(len(rdata)))
	return append(out, rdata...), true
}

func rrAddr(rr []byte) (netip.Addr, bool) {
	_, typ, rd, n, ok := skipRR(rr, 0)
	if !ok || !((typ == typeA && n == 4) || (typ == typeAAAA && n == 16)) {
		return netip.Addr{}, false
	}
	addr, _ := netip.AddrFromSlice(rr[rd : rd+n])
	return addr, true
}

func questionEnd(q []byte) (int, uint16, bool) {
	if len(q) < 12 || binary.BigEndian.Uint16(q[4:6]) != 1 {
		return 0, 0, false
	}
	end, ok := skipName(q, 12)
	if !ok || end+4 > len(q) {
		return 0, 0, false
	}
	return end + 4, binary.BigEndian.Uint16(q[end : end+2]), true
}

func skipName(b []byte, off int) (int, bool) {
	for off < len(b) {
		l := int(b[off])
		switch {
		case l == 0:
			return off + 1, true
		case l&0xC0 == 0xC0:
			return off + 2, off+2 <= len(b)
		default:
			off += 1 + l
		}
	}
	return 0, false
}

func skipRR(b []byte, off int) (end int, typ uint16, rdOff, rdLen int, ok bool) {
	nameEnd, ok := skipName(b, off)
	if !ok || nameEnd+10 > len(b) {
		return 0, 0, 0, 0, false
	}
	typ = binary.BigEndian.Uint16(b[nameEnd : nameEnd+2])
	rdLen = int(binary.BigEndian.Uint16(b[nameEnd+8 : nameEnd+10]))
	rdOff = nameEnd + 10
	if rdOff+rdLen > len(b) {
		return 0, 0, 0, 0, false
	}
	return rdOff + rdLen, typ, rdOff, rdLen, true
}

func readName(b []byte, off int) (string, bool) {
	var labels []string
	for hops := 0; off < len(b) && hops < 64; hops++ {
		l := int(b[off])
		switch {
		case l == 0:
			return strings.Join(labels, "."), true
		case l&0xC0 == 0xC0:
			if off+2 > len(b) {
				return "", false
			}
			off = int(binary.BigEndian.Uint16(b[off:off+2]) & 0x3FFF)
		default:
			if off+1+l > len(b) {
				return "", false
			}
			labels = append(labels, string(b[off+1:off+1+l]))
			off += 1 + l
		}
	}
	return "", false
}

func encodeName(name string) []byte {
	var out []byte
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if label != "" {
			out = append(out, byte(len(label)))
			out = append(out, label...)
		}
	}
	return append(out, 0)
}

func rcodeReply(q []byte, qEnd int, rcode byte) []byte {
	r := slices.Clone(q[:qEnd])
	binary.BigEndian.PutUint16(r[2:4], 0x8180|uint16(rcode))
	binary.BigEndian.PutUint16(r[6:8], 0)
	binary.BigEndian.PutUint16(r[8:10], 0)
	binary.BigEndian.PutUint16(r[10:12], 0)
	return r
}

func viaSims(sims ...resolverSim) func(t *testing.T, server *net.UDPAddr) []string {
	return func(t *testing.T, server *net.UDPAddr) []string {
		addrs := make([]string, len(sims))
		// One loopback IP each: the client treats resolvers as distinct by IP.
		for i, sim := range sims {
			addrs[i] = startResolverSim(t, net.IPv4(127, 0, 0, byte(10+i)), server, sim)
		}
		return addrs
	}
}

var (
	serverDeliveryOff = "A_RECORD_DATA_DELIVERY = false\nAAAA_RECORD_DATA_DELIVERY = false"
	realistic         = resolverSim{shuffle: true, case0x20: true, cache: true, chase: true, edns: 1232}
)

func matrixBehaviors() map[string]resolverSim {
	rebindReal := realistic
	rebindReal.filter = rebindRanges
	return map[string]resolverSim{
		"clean":          {},
		"shuffle":        {shuffle: true},
		"case0x20":       {case0x20: true},
		"cache":          {cache: true},
		"chase":          {chase: true},
		"edns1232":       {edns: 1232},
		"edns512":        {edns: 512},
		"noedns":         {edns: -1},
		"rebind":         {filter: rebindRanges},
		"bogon":          {filter: bogonRanges},
		"refuse-rare":    {refuse: []uint16{typeNULL, typeHTTPS}},
		"loss10":         {loss: 0.10},
		"nx-race":        {nx: "race"},
		"realistic":      realistic,
		"rebind+realism": rebindReal,
	}
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

func requireMatrix(t *testing.T) {
	if os.Getenv("COTTEN_RESOLVER_MATRIX") == "" {
		t.Skip("set COTTEN_RESOLVER_MATRIX=1 to run the resolver behavior matrix")
	}
	listenTimeout = 60 * time.Second
}

// Every carrier alone through every resolver behavior, so rotation cannot hide
// a carrier that breaks; A and AAAA also with server delivery off (old template).
func TestResolverMatrixCarriers(t *testing.T) {
	requireMatrix(t)
	carriers := []string{"TXT", "NULL", "HTTPS", "SVCB", "CNAME", "A", "AAAA", "MX", "NS", "PTR", "SRV", "CAA", "NAPTR", "SOA"}
	behaviors := matrixBehaviors()
	for _, name := range sortedKeys(behaviors) {
		sim := behaviors[name]
		for _, carrier := range carriers {
			servers := map[string]string{"srv-default": ""}
			if carrier == "A" || carrier == "AAAA" {
				servers["srv-delivery-off"] = serverDeliveryOff
			}
			for _, srv := range sortedKeys(servers) {
				extra := servers[srv]
				t.Run(name+"/"+carrier+"/"+srv, func(t *testing.T) {
					t.Parallel()
					runTunnelEchoVia(t, 3, 3, extra, fmt.Sprintf("[%q]", carrier), "", "127.0.0.1", tunnelBins{}, viaSims(sim))
				})
			}
		}
	}
}

// The QUERY_TYPES the Android app renders for each preset and delivery mode.
func TestResolverMatrixAndroidPresets(t *testing.T) {
	requireMatrix(t)
	presets := map[string]string{
		"default-txt":  `["TXT"]`,
		"speed":        `["TXT", "HTTPS"]`,
		"survival":     `["TXT", "CNAME", "HTTPS", "A"]`,
		"txt-cname":    `["TXT", "CNAME"]`,
		"txt-https":    `["TXT", "HTTPS"]`,
		"txt-aaaa":     `["TXT", "AAAA"]`,
		"all":          `["TXT", "CNAME", "NULL", "HTTPS", "AAAA"]`,
		"core-default": `["TXT", "CNAME", "A", "AAAA"]`,
	}
	behaviors := matrixBehaviors()
	for _, preset := range sortedKeys(presets) {
		for _, bname := range []string{"clean", "realistic", "rebind", "rebind+realism", "bogon", "refuse-rare"} {
			for _, srv := range []string{"srv-default", "srv-delivery-off"} {
				extra := ""
				if srv == "srv-delivery-off" {
					extra = serverDeliveryOff
				}
				qtypes, sim := presets[preset], behaviors[bname]
				t.Run(preset+"/"+bname+"/"+srv, func(t *testing.T) {
					t.Parallel()
					runTunnelEchoVia(t, 3, 3, extra, qtypes, "", "127.0.0.1", tunnelBins{}, viaSims(sim))
				})
			}
		}
	}
}

// Forged NXDOMAIN during probes: several resolvers whose real answer never
// comes plus one clean one, with RESOLVER_IGNORE_INJECTED_NXDOMAIN_IN_PROBES
// off and on; and a racing injector (real answer follows) alone.
func TestResolverMatrixNXDOMAIN(t *testing.T) {
	requireMatrix(t)
	probes := "MTU_TEST_RETRIES_RESOLVERS = 2\nMTU_TEST_TIMEOUT_RESOLVERS = 2.0\n"
	for _, inProbes := range []bool{false, true} {
		extra := probes + fmt.Sprintf("RESOLVER_IGNORE_INJECTED_NXDOMAIN_IN_PROBES = %v", inProbes)
		t.Run(fmt.Sprintf("drop4+clean1/in-probes=%v", inProbes), func(t *testing.T) {
			t.Parallel()
			drop := resolverSim{nx: "drop"}
			start := time.Now()
			runTunnelEchoVia(t, 3, 3, "", `["TXT"]`, extra, "127.0.0.1", tunnelBins{}, viaSims(drop, drop, drop, drop, resolverSim{}))
			t.Logf("connected and echoed in %s", time.Since(start).Round(time.Second))
		})
		t.Run(fmt.Sprintf("race-only/in-probes=%v", inProbes), func(t *testing.T) {
			t.Parallel()
			runTunnelEchoVia(t, 3, 3, "", `["TXT"]`, extra, "127.0.0.1", tunnelBins{}, viaSims(resolverSim{nx: "race"}))
		})
	}
}

// One realistic behavior at a time, old client against the new server and
// against its own release, to find which one an old client cannot cope with.
func TestResolverMatrixOldClientIsolation(t *testing.T) {
	requireMatrix(t)
	behaviors := matrixBehaviors()
	for _, release := range []string{"cdf084f", "fdf09a6"} {
		for _, bname := range []string{"clean", "shuffle", "case0x20", "cache", "chase", "edns1232", "realistic"} {
			for _, srv := range []string{"new-server", "own-server"} {
				sim := behaviors[bname]
				t.Run(release+"/"+bname+"/"+srv, func(t *testing.T) {
					t.Parallel()
					old := releaseBinaries(t, release)
					bins := tunnelBins{client: old.client}
					if srv == "own-server" {
						bins = old
					}
					runTunnelEchoVia(t, 3, 3, "", `["TXT"]`, "", "127.0.0.1", bins, viaSims(sim))
				})
			}
		}
	}
}
