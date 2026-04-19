// Package racecondition implements the Race Condition specialist agent.
//
// Tests for concurrent request vulnerabilities including token/coupon consumption
// races, account limit bypass, TOCTOU, concurrent update races, and session
// fixation races.
package racecondition

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/bb-agent/mirage/internal/agent/base"
	"github.com/bb-agent/mirage/internal/queue"
)

// Agent implements the Specialist interface for race condition detection.
type Agent struct {
	systemPrompt string
}

// New creates a new Race Condition specialist agent.
func New() *Agent {
	return &Agent{systemPrompt: defaultSystemPrompt}
}

func (a *Agent) Name() string         { return "Race Condition Agent" }
func (a *Agent) ID() string           { return "racecondition" }
func (a *Agent) SystemPrompt() string { return a.systemPrompt }

// concurrentN is the number of goroutines used in race condition probes.
const concurrentN = 15

// raceResult holds one concurrent request outcome.
type raceResult struct {
	statusCode int
	body       string
	headers    http.Header
	duration   time.Duration
	err        error
	workerID   int
}

// raceClient wraps http.Client for concurrent requests.
type raceClient struct {
	hc *http.Client
}

func newRaceClient() *raceClient {
	return &raceClient{
		hc: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 100,
				IdleConnTimeout:     30 * time.Second,
			},
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// doRequest executes a single HTTP request and returns the result.
func (c *raceClient) doRequest(ctx context.Context, method, targetURL, body, contentType string, extraHeaders map[string]string, workerID int) raceResult {
	start := time.Now()

	var bodyReader io.Reader
	if body != "" {
		bodyReader = bytes.NewBufferString(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, targetURL, bodyReader)
	if err != nil {
		return raceResult{err: err, workerID: workerID}
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; SecurityScanner/1.0)")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}

	resp, err := c.hc.Do(req)
	dur := time.Since(start)
	if err != nil {
		return raceResult{err: err, duration: dur, workerID: workerID}
	}
	defer resp.Body.Close()

	lr := io.LimitReader(resp.Body, 64*1024)
	respBody, _ := io.ReadAll(lr)

	return raceResult{
		statusCode: resp.StatusCode,
		body:       string(respBody),
		headers:    resp.Header,
		duration:   dur,
		workerID:   workerID,
	}
}

// sendConcurrent fires n parallel requests and collects all results.
// A barrier (sync channel) ensures all goroutines start as simultaneously as possible.
func (c *raceClient) sendConcurrent(ctx context.Context, n int, method, targetURL, body, contentType string, extraHeaders map[string]string) []raceResult {
	results := make([]raceResult, n)
	var wg sync.WaitGroup
	barrier := make(chan struct{})

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-barrier // wait for all goroutines to be ready
			results[idx] = c.doRequest(ctx, method, targetURL, body, contentType, extraHeaders, idx)
		}(i)
	}

	// Release all goroutines simultaneously
	close(barrier)
	wg.Wait()
	return results
}

// ProcessItem runs race condition tests against the target URL.
func (a *Agent) ProcessItem(ctx context.Context, item *queue.Item) ([]*base.Finding, error) {
	targetURL, _ := item.Payload["target"].(string)
	if targetURL == "" {
		return nil, fmt.Errorf("missing target URL in work item")
	}

	client := newRaceClient()
	var findings []*base.Finding

	// Test 1: Token/coupon consumption race
	if f := testTokenRace(ctx, client, targetURL); f != nil {
		findings = append(findings, f)
	}

	// Test 2: Account limit bypass via parallel requests
	if f := testLimitBypass(ctx, client, targetURL); f != nil {
		findings = append(findings, f)
	}

	// Test 3: TOCTOU — balance check vs deduction gap
	if f := testTOCTOU(ctx, client, targetURL); f != nil {
		findings = append(findings, f)
	}

	// Test 4: Concurrent update race — parallel writes to same resource
	if f := testConcurrentUpdate(ctx, client, targetURL); f != nil {
		findings = append(findings, f)
	}

	// Test 5: Session fixation race — parallel logins
	if f := testSessionFixationRace(ctx, client, targetURL); f != nil {
		findings = append(findings, f)
	}

	return findings, nil
}

// testTokenRace sends N concurrent redemption requests for the same token.
// Anomaly: more than one 200/success response indicates double-spend.
func testTokenRace(ctx context.Context, client *raceClient, targetURL string) *base.Finding {
	// Probe common redemption endpoints
	redeemPaths := []string{
		"/redeem", "/api/redeem", "/coupon/redeem", "/voucher/redeem",
		"/api/coupon/use", "/api/voucher/apply", "/checkout/apply-coupon",
	}

	base_ := strings.TrimRight(targetURL, "/")
	token := "RACE-TEST-TOKEN-" + fmt.Sprintf("%d", time.Now().UnixNano()%10000)

	for _, path := range redeemPaths {
		endpoint := base_ + path
		formBody := url.Values{"token": {token}, "code": {token}, "coupon": {token}}.Encode()

		results := client.sendConcurrent(ctx, concurrentN, http.MethodPost, endpoint,
			formBody, "application/x-www-form-urlencoded", nil)

		successCount := 0
		var successBodies []string
		for _, r := range results {
			if r.err == nil && (r.statusCode == 200 || r.statusCode == 201) {
				lower := strings.ToLower(r.body)
				if !strings.Contains(lower, "not found") && !strings.Contains(lower, "invalid") &&
					!strings.Contains(lower, "expired") && !strings.Contains(lower, "error") {
					successCount++
					successBodies = append(successBodies, truncate(r.body, 200))
				}
			}
		}

		if successCount > 1 {
			return &base.Finding{
				Type:       "Race Condition - Token Double-Spend",
				URL:        endpoint,
				Parameter:  "token",
				Payload:    token,
				Severity:   base.SeverityHigh,
				Confidence: 0.85,
				Evidence: map[string]interface{}{
					"test":          "token_race",
					"concurrent_n":  concurrentN,
					"success_count": successCount,
					"sample_bodies": successBodies,
					"description":   fmt.Sprintf("%d concurrent requests all succeeded for single-use token", successCount),
				},
				Method: "POST",
			}
		}
	}
	return nil
}

// testLimitBypass sends N parallel signup/purchase requests to exceed per-account limits.
func testLimitBypass(ctx context.Context, client *raceClient, targetURL string) *base.Finding {
	limitPaths := []string{
		"/api/signup", "/register", "/api/register",
		"/api/purchase", "/buy", "/api/buy",
		"/api/subscribe", "/api/invite",
	}

	base_ := strings.TrimRight(targetURL, "/")
	ts := fmt.Sprintf("%d", time.Now().UnixNano())

	for _, path := range limitPaths {
		endpoint := base_ + path
		formBody := url.Values{
			"email":    {"race_" + ts + "@example.com"},
			"username": {"race_" + ts},
			"password": {"RaceTest123!"},
		}.Encode()

		results := client.sendConcurrent(ctx, concurrentN, http.MethodPost, endpoint,
			formBody, "application/x-www-form-urlencoded", nil)

		successCount := 0
		for _, r := range results {
			if r.err == nil && (r.statusCode == 200 || r.statusCode == 201) {
				lower := strings.ToLower(r.body)
				if !strings.Contains(lower, "already exists") && !strings.Contains(lower, "duplicate") &&
					!strings.Contains(lower, "conflict") {
					successCount++
				}
			}
		}

		// More than 1 success for same email = race condition on uniqueness constraint
		if successCount > 1 {
			return &base.Finding{
				Type:       "Race Condition - Account Limit Bypass",
				URL:        endpoint,
				Parameter:  "email",
				Payload:    formBody,
				Severity:   base.SeverityHigh,
				Confidence: 0.80,
				Evidence: map[string]interface{}{
					"test":          "limit_bypass",
					"concurrent_n":  concurrentN,
					"success_count": successCount,
					"description":   fmt.Sprintf("%d concurrent registrations succeeded for same email, bypassing uniqueness limit", successCount),
				},
				Method: "POST",
			}
		}
	}
	return nil
}

// testTOCTOU probes for Time-Of-Check-Time-Of-Use races in balance/funds operations.
func testTOCTOU(ctx context.Context, client *raceClient, targetURL string) *base.Finding {
	toctouPaths := []string{
		"/api/withdraw", "/api/transfer", "/payment/process",
		"/api/balance/deduct", "/api/spend", "/checkout",
	}

	base_ := strings.TrimRight(targetURL, "/")

	for _, path := range toctouPaths {
		endpoint := base_ + path

		// First, do a sequential baseline — what does a single request return?
		seqResult := client.doRequest(ctx, http.MethodPost, endpoint,
			`{"amount":1}`, "application/json", nil, -1)

		if seqResult.err != nil {
			continue
		}
		seqStatus := seqResult.statusCode

		// Now race N concurrent requests
		results := client.sendConcurrent(ctx, concurrentN, http.MethodPost, endpoint,
			`{"amount":1}`, "application/json", nil)

		// Count statuses that differ significantly from baseline (extra 200s after first)
		twoHundredCount := 0
		for _, r := range results {
			if r.err == nil && r.statusCode == 200 {
				twoHundredCount++
			}
		}

		// Anomaly: N/2 or more concurrent 200s when sequential also returned 200
		// suggests the check-then-use window is exploitable
		if seqStatus == 200 && twoHundredCount >= concurrentN/2 {
			return &base.Finding{
				Type:       "Race Condition - TOCTOU Balance/Fund Deduction",
				URL:        endpoint,
				Parameter:  "amount",
				Payload:    `{"amount":1}`,
				Severity:   base.SeverityCritical,
				Confidence: 0.75,
				Evidence: map[string]interface{}{
					"test":            "toctou",
					"concurrent_n":    concurrentN,
					"concurrent_200s": twoHundredCount,
					"seq_status":      seqStatus,
					"description":     fmt.Sprintf("%d/%d concurrent requests returned 200; potential TOCTOU on balance check", twoHundredCount, concurrentN),
				},
				Method: "POST",
			}
		}
	}
	return nil
}

// testConcurrentUpdate races parallel writes to the same resource to detect lost updates.
func testConcurrentUpdate(ctx context.Context, client *raceClient, targetURL string) *base.Finding {
	updatePaths := []string{
		"/api/user/update", "/api/profile", "/api/account/update",
		"/api/settings", "/user/profile",
	}

	base_ := strings.TrimRight(targetURL, "/")
	ts := fmt.Sprintf("%d", time.Now().UnixNano()%10000)

	for _, path := range updatePaths {
		endpoint := base_ + path

		// Send N concurrent updates with different values
		var wg sync.WaitGroup
		results := make([]raceResult, concurrentN)
		barrier := make(chan struct{})

		for i := 0; i < concurrentN; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				<-barrier
				body := fmt.Sprintf(`{"username":"race_%s_%d","email":"race_%d_%s@example.com"}`, ts, idx, idx, ts)
				results[idx] = client.doRequest(ctx, http.MethodPut, endpoint, body, "application/json", nil, idx)
			}(i)
		}
		close(barrier)
		wg.Wait()

		// Detect anomaly: multiple 200s with different content (lost update or double write)
		successCount := 0
		uniqueBodies := make(map[string]int)
		for _, r := range results {
			if r.err == nil && (r.statusCode == 200 || r.statusCode == 204) {
				successCount++
				snippet := truncate(r.body, 100)
				uniqueBodies[snippet]++
			}
		}

		if successCount >= concurrentN/2 && len(uniqueBodies) > 1 {
			return &base.Finding{
				Type:       "Race Condition - Concurrent Update / Lost Write",
				URL:        endpoint,
				Parameter:  "body",
				Payload:    fmt.Sprintf(`{"username":"race_%s_N","email":"race_N_%s@example.com"}`, ts, ts),
				Severity:   base.SeverityMedium,
				Confidence: 0.70,
				Evidence: map[string]interface{}{
					"test":          "concurrent_update",
					"concurrent_n":  concurrentN,
					"success_count": successCount,
					"unique_bodies": len(uniqueBodies),
					"description":   "Parallel writes to same resource succeeded with different values; possible lost update race",
				},
				Method: "PUT",
			}
		}
	}
	return nil
}

// testSessionFixationRace fires parallel login requests with the same credentials.
func testSessionFixationRace(ctx context.Context, client *raceClient, targetURL string) *base.Finding {
	loginPaths := []string{
		"/login", "/api/login", "/auth/login", "/api/auth/login",
		"/signin", "/api/signin", "/api/session",
	}

	base_ := strings.TrimRight(targetURL, "/")

	for _, path := range loginPaths {
		endpoint := base_ + path
		body := url.Values{"username": {"admin"}, "password": {"admin"}, "email": {"admin@example.com"}}.Encode()

		results := client.sendConcurrent(ctx, concurrentN, http.MethodPost, endpoint,
			body, "application/x-www-form-urlencoded", nil)

		// Collect unique session tokens
		sessionTokens := make(map[string]int)
		for _, r := range results {
			if r.err == nil && (r.statusCode == 200 || r.statusCode == 302) {
				for _, cookie := range r.headers["Set-Cookie"] {
					lower := strings.ToLower(cookie)
					if strings.Contains(lower, "session") || strings.Contains(lower, "token") || strings.Contains(lower, "auth") {
						// Extract the token value portion
						parts := strings.SplitN(cookie, "=", 2)
						if len(parts) == 2 {
							val := strings.SplitN(parts[1], ";", 2)[0]
							sessionTokens[val]++
						}
					}
				}
			}
		}

		// Anomaly: same session token issued to multiple concurrent requests
		for token, count := range sessionTokens {
			if count > 1 {
				return &base.Finding{
					Type:       "Race Condition - Session Fixation / Token Reuse",
					URL:        endpoint,
					Parameter:  "session",
					Payload:    body,
					Severity:   base.SeverityHigh,
					Confidence: 0.78,
					Evidence: map[string]interface{}{
						"test":          "session_fixation_race",
						"concurrent_n":  concurrentN,
						"reuse_count":   count,
						"token_snippet": truncate(token, 40),
						"description":   fmt.Sprintf("Same session token issued %d times to concurrent login requests", count),
					},
					Method: "POST",
				}
			}
		}
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

const defaultSystemPrompt = `You are a Race Condition specialist. You identify time-of-check-time-of-use (TOCTOU)
vulnerabilities, token double-spend, limit bypass via concurrency, and session fixation races.

Tests:
1. Token/coupon consumption races: concurrent redemption of single-use tokens
2. Account limit bypass: parallel signup to exceed uniqueness constraints
3. TOCTOU: concurrent balance/fund deduction requests
4. Concurrent update races: parallel writes causing lost updates
5. Session fixation races: identical session tokens issued to parallel logins

Severity: CRITICAL for financial TOCTOU, HIGH for token double-spend/session issues, MEDIUM for lost updates.`
