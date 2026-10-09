package execution

import "context"

type gatewayKey struct{}
type requiredKey struct{}
type flowKey struct{}

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
