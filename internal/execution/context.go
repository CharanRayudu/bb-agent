package execution

import "context"

type gatewayKey struct{}
type requiredKey struct{}
type flowKey struct{}
type egressKey struct{}
type proxyKey struct{}

// WithGateway attaches the engagement gateway to a specialist context.
func WithGateway(ctx context.Context, gw *Gateway) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, gatewayKey{}, gw)
}

// GatewayFrom returns the gateway on ctx, or nil.
func GatewayFrom(ctx context.Context) *Gateway {
	if ctx == nil {
		return nil
	}
	gw, _ := ctx.Value(gatewayKey{}).(*Gateway)
	return gw
}

// HasGateway reports whether a gateway is attached.
func HasGateway(ctx context.Context) bool {
	return GatewayFrom(ctx) != nil
}

// WithRequired marks this context as fail-closed when no gateway is present.
func WithRequired(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, requiredKey{}, true)
}

// Required reports whether missing a gateway must deny the action.
func Required(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	v, _ := ctx.Value(requiredKey{}).(bool)
	return v
}

// WithFlowID stores the engagement id specialists should put on actions.
func WithFlowID(ctx context.Context, flowID string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, flowKey{}, flowID)
}

// FlowID returns the engagement id previously stored on ctx.
func FlowID(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	v, _ := ctx.Value(flowKey{}).(string)
	return v
}

// WithEgress attaches the flow allow-list used by pinned dials.
func WithEgress(ctx context.Context, egress *FlowEgress) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, egressKey{}, egress)
}

// EgressFrom returns the flow allow-list on ctx.
func EgressFrom(ctx context.Context) *FlowEgress {
	if ctx == nil {
		return nil
	}
	egress, _ := ctx.Value(egressKey{}).(*FlowEgress)
	return egress
}

// WithFlowProxy stores the browser egress proxy for this flow.
func WithFlowProxy(ctx context.Context, proxy *EgressProxy) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, proxyKey{}, proxy)
}

// ProxyFrom returns the flow browser proxy, if one was started.
func ProxyFrom(ctx context.Context) *EgressProxy {
	if ctx == nil {
		return nil
	}
	proxy, _ := ctx.Value(proxyKey{}).(*EgressProxy)
	return proxy
}

// WithToolProxy records an HTTP proxy URL that sandbox tools can honor.
func WithToolProxy(ctx context.Context, rawURL string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, toolProxyKey{}, rawURL)
}

type toolProxyKey struct{}

// ToolProxyURL returns the sandbox proxy URL, if the caller set one.
func ToolProxyURL(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	v, _ := ctx.Value(toolProxyKey{}).(string)
	return v
}
