package base

import (
	"net/http"
	"time"

	"github.com/bb-agent/mirage/internal/execution"
	"github.com/bb-agent/mirage/internal/policy"
)

// WrapClient returns a client that asks the context gateway before every
// target request. Without a gateway, the original transport is unchanged.
func WrapClient(c *http.Client) *http.Client {
	if c == nil {
		c = &http.Client{Timeout: 15 * time.Second}
	}
	baseRT := c.Transport
	if baseRT == nil {
		baseRT = http.DefaultTransport
	}
	clone := *c
	clone.Transport = gatedTransport{base: baseRT}
	return &clone
}

type gatedTransport struct {
	base http.RoundTripper
}

func (t gatedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx := req.Context()
	if ctx == nil || (!execution.HasGateway(ctx) && !execution.Required(ctx)) {
		return t.base.RoundTrip(req)
	}
	gw := execution.GatewayFrom(ctx)
	if gw == nil {
		return nil, execution.ErrGatewayRequired
	}
	action, err := execution.HTTPAction(execution.FlowID(ctx), "http.probe", req.Method, req.URL.String())
	if err != nil {
		return nil, err
	}
	action = action.WithRisk(policy.RiskActive)
	action.FollowRedirects = false
	return gw.Do(ctx, action, func(out *http.Request) {
		if req.Header != nil {
			out.Header = req.Header.Clone()
		}
		out.Body = req.Body
		out.ContentLength = req.ContentLength
		out.Host = req.Host
	})
}
