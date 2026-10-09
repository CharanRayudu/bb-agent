package execution

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/bb-agent/mirage/internal/policy"
)

// DialAuthorized opens a TCP connection only after the gateway allows that
// host and port. The socket is bound to the addresses authorized for this
// attempt, not to a later DNS answer.
func DialAuthorized(ctx context.Context, network, address string) (net.Conn, error) {
	if !HasGateway(ctx) && !Required(ctx) {
		return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, network, address)
	}
	gw := GatewayFrom(ctx)
	if gw == nil {
		return nil, ErrGatewayRequired
	}
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return nil, err
	}
	action := Action{
		FlowID:         FlowID(ctx),
		ActionType:     "net.dial",
		SkillID:        "net.dial",
		ToolID:         "tcp.connect",
		Phase:          "exploitation",
		Scheme:         "tcp",
		Host:           host,
		Port:           port,
		Risk:           policy.RiskActive,
		IdempotencyKey: FlowID(ctx) + ":dial:" + address,
	}
	decision, ips, err := gw.decide(ctx, action, true)
	if err != nil {
		return nil, err
	}
	if !decision.Allowed {
		return nil, ErrDenied
	}
	return dialPinned(ctx, network, address, ips)
}

func dialPinned(ctx context.Context, network, address string, ips []net.IP) (net.Conn, error) {
	if len(ips) == 0 {
		return nil, fmt.Errorf("no authorized address to dial")
	}
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	var last error
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	for _, ip := range ips {
		conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
		last = err
	}
	if last == nil {
		last = fmt.Errorf("authorized addresses were not dialable")
	}
	return nil, last
}
