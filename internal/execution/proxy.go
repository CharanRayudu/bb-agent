package execution

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/bb-agent/mirage/internal/policy"
)

// EgressProxy authorizes every browser request, including subresources,
// and forwards the original method, headers, and body.
type EgressProxy struct {
	server *http.Server
	Addr   string
	gw     *Gateway
	flowID string
}

// StartEgressProxy listens on localhost.
func StartEgressProxy(gw *Gateway) (*EgressProxy, error) {
	return StartFlowProxy(gw, "")
}

// StartFlowProxy listens on localhost and stamps flowID onto each request.
func StartFlowProxy(gw *Gateway, flowID string) (*EgressProxy, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	proxy := &EgressProxy{Addr: ln.Addr().String(), gw: gw, flowID: flowID}
	proxy.server = &http.Server{Handler: proxy}
	go func() { _ = proxy.server.Serve(ln) }()
	return proxy, nil
}

func (p *EgressProxy) Close() error {
	if p == nil || p.server == nil {
		return nil
	}
	return p.server.Close()
}

func (p *EgressProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if p.gw == nil {
		http.Error(w, ErrGatewayRequired.Error(), http.StatusForbidden)
		return
	}
	ctx := r.Context()
	if p.flowID != "" && FlowID(ctx) == "" {
		ctx = WithFlowID(ctx, p.flowID)
	}
	if r.Method == http.MethodConnect {
		p.serveConnect(w, r.WithContext(ctx))
		return
	}
	if r.URL == nil || !r.URL.IsAbs() {
		http.Error(w, "proxy request was not absolute", http.StatusBadRequest)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 10<<20+1))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if len(body) > 10<<20 {
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		return
	}
	target := r.URL.String()
	action, err := HTTPAction(FlowID(ctx), "browser.subresource", r.Method, target)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	action.ActionType = "browser.subresource"
	header := filterRequestHeaders(r.Header)
	action.Digest = RequestFingerprint(r.Method, target, header, body)
	action.IdempotencyKey += ":" + action.Digest
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		action = action.WithRisk(policy.RiskPassive)
	}
	resp, err := p.gw.Do(ctx, action, func(out *http.Request) {
		out.Header = header
		out.Body = io.NopCloser(bytes.NewReader(body))
		out.ContentLength = int64(len(body))
		if r.Host != "" {
			out.Host = r.Host
		}
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	defer resp.Body.Close()
	copyHeader(w.Header(), filterResponseHeaders(resp.Header))
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func (p *EgressProxy) serveConnect(w http.ResponseWriter, r *http.Request) {
	target := "https://" + r.Host
	action, err := HTTPAction(FlowID(r.Context()), "browser.connect", http.MethodConnect, target)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	action.Scheme = "tcp"
	action.ActionType = "net.dial"
	action.Digest = RequestFingerprint(http.MethodConnect, target, nil, nil)
	action.IdempotencyKey += ":" + action.Digest
	action = action.WithRisk(policy.RiskActive)
	ctx := WithEgress(r.Context(), p.gw.egress)
	_, ips, err := p.gw.decide(ctx, action, true)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	if FlowID(ctx) == "" && action.FlowID != "" {
		ctx = WithFlowID(ctx, action.FlowID)
	}
	dest, err := dialPinned(ctx, "tcp", r.Host, ips)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer dest.Close()
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "proxy cannot tunnel this response", http.StatusInternalServerError)
		return
	}
	client, _, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer client.Close()
	_, _ = client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	go func() { _, _ = io.Copy(dest, client) }()
	_, _ = io.Copy(client, dest)
}

func filterRequestHeaders(src http.Header) http.Header {
	dst := make(http.Header, len(src))
	for key, values := range src {
		if hopByHop(key) {
			continue
		}
		for _, value := range values {
			dst.Add(key, value)
		}
	}
	return dst
}

func filterResponseHeaders(src http.Header) http.Header {
	return filterRequestHeaders(src)
}

func hopByHop(key string) bool {
	switch strings.ToLower(key) {
	case "connection", "proxy-connection", "keep-alive", "transfer-encoding", "upgrade", "te", "trailer", "proxy-authorization":
		return true
	default:
		return false
	}
}

func copyHeader(dst, src http.Header) {
	for key, values := range src {
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}
