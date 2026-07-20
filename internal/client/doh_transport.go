// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================
// doh_transport.go — DNS-over-HTTPS resolver transport (RFC 8484), used when
// RESOLVER_TRANSPORT=doh. Unlike UDP/TCP/DoT there is no persistent framed
// stream: each query is an HTTP POST whose body is the raw DNS wire-format
// message, and the response body is the wire-format answer. HTTP/2 multiplexes
// them over a small number of connections, and Go's Transport pools one
// connection set per resolver host automatically.
//
// Two users of this file:
//   - dohQueryTransport — the synchronous exchanger used by MTU probing,
//     session init and health rechecks (implements queryExchanger).
//   - dohDataManager    — the data-plane sender, which mirrors tcpDataManager:
//     it posts asynchronously and pushes answers into the SAME rxChannel the UDP
//     reader feeds, so handleInboundPacket treats every transport identically.
// ==============================================================================

package client

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

const (
	dohContentType     = "application/dns-message"
	dohDialTimeout     = 6 * time.Second
	dohIdleConnTimeout = 90 * time.Second
	dohMaxResponse     = 65535
	// dohMaxInflight bounds concurrent in-flight POSTs on the data plane so a
	// burst cannot spawn unbounded goroutines and sockets.
	dohMaxInflight = 256
)

var errDoHStatus = errors.New("doh: non-200 response")

// newDoHHTTPClient builds the shared HTTP/2 client used by both DoH users. The
// resolver is addressed by IP in the URL, while SNI/verification come from the
// TLS config, so one client serves every resolver with per-host pooling.
func (c *Client) newDoHHTTPClient() *http.Client {
	tlsCfg := c.resolverTLSConfig()
	transport := &http.Transport{
		TLSClientConfig:       tlsCfg,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          256,
		MaxIdleConnsPerHost:   8,
		IdleConnTimeout:       dohIdleConnTimeout,
		TLSHandshakeTimeout:   dohDialTimeout,
		ExpectContinueTimeout: time.Second,
		DialContext: (&net.Dialer{
			Timeout:   dohDialTimeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}
	return &http.Client{Transport: transport}
}

// dohEndpoint builds the request URL for a resolver. Resolver entries carry the
// DNS port (53); DoH lives on its own port and path.
func (c *Client) dohEndpoint(resolverLabel string) string {
	return "https://" + resolverHostWithPort(resolverLabel, c.cfg.ResolverDoHPort) + c.cfg.ResolverDoHPath
}

// dohExchange performs one DoH round trip and returns the wire-format answer.
func dohExchange(ctx context.Context, httpClient *http.Client, endpoint string, packet []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(packet))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", dohContentType)
	req.Header.Set("Accept", dohContentType)

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, errDoHStatus
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, dohMaxResponse))
	if err != nil {
		return nil, err
	}
	if len(body) < 12 {
		return nil, errDoHStatus
	}
	return body, nil
}

// ---------------------------------------------------------------------------
// Synchronous exchanger (queryExchanger)
// ---------------------------------------------------------------------------

type dohQueryTransport struct {
	httpClient *http.Client
	endpoint   string
}

func (c *Client) newDoHQueryTransport(resolverLabel string) (queryExchanger, error) {
	return &dohQueryTransport{
		httpClient: c.newDoHHTTPClient(),
		endpoint:   c.dohEndpoint(resolverLabel),
	}, nil
}

func (t *dohQueryTransport) exchange(packet []byte, timeout time.Duration) ([]byte, error) {
	if t == nil || t.httpClient == nil {
		return nil, net.ErrClosed
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return dohExchange(ctx, t.httpClient, t.endpoint, packet)
}

func (t *dohQueryTransport) Close() error {
	if t == nil || t.httpClient == nil {
		return nil
	}
	if tr, ok := t.httpClient.Transport.(*http.Transport); ok {
		tr.CloseIdleConnections()
	}
	return nil
}

// ---------------------------------------------------------------------------
// Data-plane manager (streamDataTransport)
// ---------------------------------------------------------------------------

type dohDataManager struct {
	client     *Client
	httpClient *http.Client

	mu       sync.Mutex
	ctx      context.Context
	dead     bool
	inFlight chan struct{}
	wg       sync.WaitGroup
}

func newDoHDataManager(c *Client) *dohDataManager {
	return &dohDataManager{
		client:     c,
		httpClient: c.newDoHHTTPClient(),
		inFlight:   make(chan struct{}, dohMaxInflight),
	}
}

func (m *dohDataManager) Start(ctx context.Context) {
	m.mu.Lock()
	m.ctx = ctx
	m.dead = false
	m.mu.Unlock()
}

func (m *dohDataManager) Stop() {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.dead = true
	m.mu.Unlock()
	m.wg.Wait()
	if tr, ok := m.httpClient.Transport.(*http.Transport); ok {
		tr.CloseIdleConnections()
	}
}

// Send posts one already-built DNS query and feeds the answer back into the
// client's rxChannel, mirroring the UDP writer's bookkeeping. The POST runs on
// its own goroutine because DoH is request/response: the answer arrives on the
// same exchange rather than on a separate read loop.
func (m *dohDataManager) Send(serverKey string, addr *net.UDPAddr, packet []byte, now time.Time) {
	if m == nil || addr == nil || len(packet) == 0 {
		return
	}
	m.mu.Lock()
	ctx, dead := m.ctx, m.dead
	m.mu.Unlock()
	if dead || ctx == nil || ctx.Err() != nil {
		return
	}

	select {
	case m.inFlight <- struct{}{}:
	default:
		// Saturated: drop rather than queue. ARQ retransmits, and shedding here
		// keeps a burst from opening unbounded sockets.
		m.client.onRXDrop(addr)
		return
	}

	// Copy the packet: the caller owns its buffer and may recycle it once Send
	// returns, while the POST body is read asynchronously.
	body := append([]byte(nil), packet...)
	endpoint := m.client.dohEndpoint(addr.String())

	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		defer func() { <-m.inFlight }()

		m.client.trackResolverSend(body, addr.String(), "", serverKey, now)
		m.client.txTotalBytes.Add(uint64(len(body)))

		reqCtx, cancel := context.WithTimeout(ctx, m.client.resolverRequestTimeout())
		defer cancel()

		response, err := dohExchange(reqCtx, m.httpClient, endpoint, body)
		if err != nil || len(response) < 12 {
			return
		}
		// Only DNS responses (QR=1) are of interest, mirroring the UDP reader.
		if (response[2] & 0x80) == 0 {
			return
		}

		buf := m.client.getRuntimeUDPBuffer()
		if len(response) > len(buf) {
			m.client.putRuntimeUDPBuffer(buf)
			return
		}
		n := copy(buf, response)
		m.client.rxTotalBytes.Add(uint64(n))
		select {
		case m.client.rxChannel <- asyncReadPacket{data: buf[:n], addr: addr, localAddr: ""}:
		default:
			m.client.putRuntimeUDPBuffer(buf)
			m.client.onRXDrop(addr)
		}
	}()
}
