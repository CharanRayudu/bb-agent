package agent

import (
	"context"
	"testing"

	"github.com/bb-agent/mirage/internal/execution"
	"github.com/bb-agent/mirage/internal/policy"
	"github.com/google/uuid"
)

func TestBindExecutionContextCarriesGatewayIntoBrowserCalls(t *testing.T) {
	gw := execution.NewGateway(policy.NewBook(), execution.NewMemoryStore(), execution.NetResolver{})
	orchestrator := &Orchestrator{}
	orchestrator.SetExecutionGateway(gw, true)
	flowID := uuid.New()
	ctx := orchestrator.bindExecutionContext(context.Background(), flowID)
	if execution.GatewayFrom(ctx) != gw {
		t.Fatal("gateway was not attached")
	}
	if !execution.Required(ctx) {
		t.Fatal("execution v2 was not required")
	}
	if execution.FlowID(ctx) != flowID.String() {
		t.Fatalf("flow id=%s", execution.FlowID(ctx))
	}
	again := orchestrator.bindExecutionContext(ctx, uuid.Nil)
	if execution.FlowID(again) != flowID.String() {
		t.Fatal("rebinding cleared the flow id")
	}
}
