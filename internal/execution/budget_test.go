package execution

import (
	"testing"
	"time"

	"github.com/bb-agent/mirage/internal/policy"
)

func TestRequestBudgetTrackingAndHighVolumeFuzzing(t *testing.T) {
	book := policy.NewBook()
	auth := policy.Authorization{
		ID:          "auth-fuzz",
		FlowID:      "flow-fuzz",
		Autonomy:    policy.AutonomyL3,
		MaxRequests: 100, // Budget set to 100 requests
		Targets: []policy.Target{
			{Host: "93.184.216.34", Port: 80},
		},
	}
	book.Put(auth)

	// Simulate high volume requests up to budget
	for i := 0; i < 100; i++ {
		if !book.TryConsume("flow-fuzz") {
			t.Fatalf("Request %d should be permitted within budget of 100", i+1)
		}
	}

	// 101st request must be denied due to budget exhaustion
	if book.TryConsume("flow-fuzz") {
		t.Fatal("Request 101 should be denied when budget of 100 is exhausted")
	}

	// Verify policy engine decision when budget is exhausted
	engine := policy.Engine{}
	snap, _ := book.Snapshot("flow-fuzz")
	subj := policy.Subject{
		Scheme: "http",
		Host:   "93.184.216.34",
		Port:   80,
		IPs:    []string{"93.184.216.34"},
	}
	dec := engine.Decide(&snap, subj, nil, time.Now())
	if dec.Allowed {
		t.Fatal("Policy engine should deny execution when MaxRequests budget is reached")
	}
	if dec.Code != policy.CodeBudgetExhausted {
		t.Fatalf("Expected decision code CodeBudgetExhausted, got %s", dec.Code)
	}

	// Unlimited budget test (MaxRequests = 0)
	unlimitedAuth := policy.Authorization{
		ID:          "auth-unlimited",
		FlowID:      "flow-unlimited",
		Autonomy:    policy.AutonomyL3,
		MaxRequests: 0, // 0 = unlimited
		Targets: []policy.Target{
			{Host: "93.184.216.34", Port: 80},
		},
	}
	book.Put(unlimitedAuth)

	for i := 0; i < 500; i++ {
		if !book.TryConsume("flow-unlimited") {
			t.Fatalf("Request %d should be permitted under unlimited budget", i+1)
		}
	}
}

func TestBudgetConsumptionIsAtomicAcrossConcurrentRequests(t *testing.T) {
	book := policy.NewBook()
	auth := policy.Authorization{
		ID:          "auth-concurrent",
		FlowID:      "flow-concurrent",
		Autonomy:    policy.AutonomyL3,
		MaxRequests: 50,
		Targets: []policy.Target{
			{Host: "93.184.216.34", Port: 80},
		},
	}
	book.Put(auth)

	consumed := 0
	ch := make(chan bool, 100)

	for i := 0; i < 100; i++ {
		go func() {
			ch <- book.TryConsume("flow-concurrent")
		}()
	}

	for i := 0; i < 100; i++ {
		if <-ch {
			consumed++
		}
	}

	if consumed != 50 {
		t.Fatalf("Expected exactly 50 requests consumed concurrently, got %d", consumed)
	}
}
