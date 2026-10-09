package execution

import (
	"io"
	"net"
	"net/http"

	"github.com/bb-agent/mirage/internal/policy"
)

// EgressProxy authorizes every browser request, including subresources.
type EgressProxy struct {
	server *http.Server
	Addr   string
	gw     *Gateway
}

// StartEgressProxy listens on localhost.
func StartEgressProxy(gw *Gateway) (*EgressProxy, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	proxy := &EgressProxy{Addr: ln.Addr().String(), gw: gw}
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
	target := r.URL.String()
	actionType := "browser.subresource"
	schemeNote := ""
	if r.Method == http.MethodConnect {
		target = "https://" + r.Host
		schemeNote = "tcp"
	} else if r.URL == nil || !r.URL.IsAbs() {
		http.Error(w, "proxy request was not absolute", http.StatusBadRequest)
		return
	}
	action, err := HTTPAction(FlowID(r.Context()), "browser.subresource", http.MethodGet, target)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	action.ActionType = actionType
	action = action.WithRisk(policy.RiskPassive)
	if schemeNote == "tcp" {
		action.Scheme = "tcp"
		action.ActionType = "net.dial"
		action = action.WithRisk(policy.RiskActive)
	}
	if _, err := p.gw.Authorize(r.Context(), action); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	if r.Method == http.MethodConnect {
		_, ips, err := p.gw.decide(r.Context(), action, false)
		if err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		dest, err := dialPinned(r.Context(), "tcp", r.Host, ips)
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
		return
	}
	resp, err := p.gw.Do(r.Context(), action, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	defer resp.Body.Close()
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func copyHeader(dst, src http.Header) {
	for key, values := range src {
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}
