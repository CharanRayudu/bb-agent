package decision

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestFoundryLive calls a real Foundry deployment when the operator opts in.
// It does not embed a credential. Set FOUNDRY_LIVE=1 plus FOUNDRY_ENDPOINT,
// FOUNDRY_DEPLOYMENT, and FOUNDRY_API_KEY.
func TestFoundryLive(t *testing.T) {
	if os.Getenv("FOUNDRY_LIVE") != "1" {
		t.Skip("set FOUNDRY_LIVE=1 to call Microsoft Foundry")
	}
	endpoint := os.Getenv("FOUNDRY_ENDPOINT")
	deployment := os.Getenv("FOUNDRY_DEPLOYMENT")
	key := os.Getenv("FOUNDRY_API_KEY")
	if endpoint == "" || deployment == "" || key == "" {
		t.Fatal("FOUNDRY_LIVE=1 requires FOUNDRY_ENDPOINT, FOUNDRY_DEPLOYMENT, and FOUNDRY_API_KEY")
	}
	client := NewFoundryClient(endpoint, deployment, key, 30*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resp, err := client.Decide(ctx, Request{
		State: map[string]string{"observation": "the search parameter reflects a script tag"},
		Questions: map[string]Question{
			"specialist": {
				Type:         TypeChoice,
				Instructions: "Which specialist should handle this observation?",
				Criteria: map[string]string{
					"XSS":  "Script or markup injection",
					"SQLi": "Database query injection",
					"none": "No specialist applies",
				},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	answer, ok := resp.Answers["specialist"]
	if !ok || answer.Choice == "" || answer.Confidence == nil {
		t.Fatalf("live answer=%+v", answer)
	}
	t.Logf("choice=%s confidence=%.3f latency=%s", answer.Choice, *answer.Confidence, resp.Latency)
}
