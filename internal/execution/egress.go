package execution

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ErrEgressDenied means the flow allow-list does not include this socket.
var ErrEgressDenied = errors.New("egress denied")

// FlowEgress is the per-flow set of IP:port pairs a gateway has authorized.
// Dials that do not match are refused before a socket is opened.
type FlowEgress struct {
	mu      sync.Mutex
	allowed map[string]map[string]struct{}
}

func NewFlowEgress() *FlowEgress {
	return &FlowEgress{allowed: map[string]map[string]struct{}{}}
}

// Permit records addresses the gateway has already authorized for one flow.
func (e *FlowEgress) Permit(flowID string, ips []net.IP, port int) {
	if e == nil || port <= 0 {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.allowed == nil {
		e.allowed = map[string]map[string]struct{}{}
	}
	set := e.allowed[flowID]
	if set == nil {
		set = map[string]struct{}{}
		e.allowed[flowID] = set
	}
	for _, ip := range ips {
		if ip == nil {
			continue
		}
		set[ip.String()+"|"+strconv.Itoa(port)] = struct{}{}
	}
}

// Allows reports whether flowID may open this socket.
func (e *FlowEgress) Allows(flowID string, ip net.IP, port int) bool {
	if e == nil || ip == nil || port <= 0 {
		return false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	_, ok := e.allowed[flowID][ip.String()+"|"+strconv.Itoa(port)]
	return ok
}

// ClearFlow drops every permit for one flow. Used when its authorization ends.
func (e *FlowEgress) ClearFlow(flowID string) {
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.allowed, flowID)
}

// DialContext opens a socket only when the flow allow-list contains it.
func (e *FlowEgress) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if e == nil {
		return nil, ErrEgressDenied
	}
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, ErrEgressDenied
	}
	if !e.Allows(FlowID(ctx), ip, port) {
		return nil, ErrEgressDenied
	}
	return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, network, address)
}

func (g *Gateway) Egress() *FlowEgress {
	if g == nil {
		return nil
	}
	return g.egress
}

func (g *Gateway) permit(flowID string, ips []string, port int, scheme string) {
	if g == nil || g.egress == nil {
		return
	}
	g.egress.Permit(flowID, parseIPs(ips), effectiveDialPort(port, scheme))
}

func effectiveDialPort(port int, scheme string) int {
	if port > 0 {
		return port
	}
	if strings.EqualFold(scheme, "https") {
		return 443
	}
	return 80
}
