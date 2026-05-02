// Package devsecops implements the DevSecOps pipeline specialist agent.
//
// Capabilities:
//   - SAST: Semgrep integration (subprocess) with native regex fallback covering OWASP Top 10
//   - SCA: Grype integration (subprocess) with native dependency parser for npm/pypi/go/maven/rubygems
//   - Secret Detection: 25+ patterns (AWS, GitHub, Stripe, Slack, JWT, private keys, DB URLs)
//   - Container Security: Trivy integration (subprocess) + native Dockerfile/Compose analysis
//   - GitHub App webhook trigger: PR-scoped scanning on open/update events
package devsecops

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/bb-agent/mirage/internal/agent/base"
	"github.com/bb-agent/mirage/internal/queue"
)

// Agent implements the Specialist interface for DevSecOps pipeline scanning.
type Agent struct {
	systemPrompt string
}

// New creates a new DevSecOps specialist agent.
func New() *Agent {
	return &Agent{systemPrompt: defaultSystemPrompt}
}

func (a *Agent) Name() string         { return "DevSecOps Agent" }
func (a *Agent) ID() string           { return "devsecops" }
func (a *Agent) SystemPrompt() string { return a.systemPrompt }

// ProcessItem runs a DevSecOps scan on the given work item.
// Payload keys:
//
//	"target" — base URL of the application (required)
//	"mode"   — "sast" | "sca" | "secrets" | "container" | "full" (default: "full")
//	"image"  — Docker image name for Trivy scanning (optional)
func (a *Agent) ProcessItem(ctx context.Context, item *queue.Item) ([]*base.Finding, error) {
	targetURL, _ := item.Payload["target"].(string)
	mode, _ := item.Payload["mode"].(string)
	image, _ := item.Payload["image"].(string)

	if targetURL == "" {
		return nil, fmt.Errorf("missing target URL in work item")
	}
	if mode == "" {
		mode = "full"
	}

	// Normalize target URL
	targetURL = normalizeTarget(targetURL)

	client := newDevSecOpsHTTPClient()
	var allFindings []*base.Finding

	switch strings.ToLower(mode) {
	case "secrets":
		allFindings = append(allFindings, fetchAndScanSecrets(ctx, client, targetURL)...)

	case "sast":
		allFindings = append(allFindings, runSAST(ctx, client, targetURL)...)

	case "sca":
		allFindings = append(allFindings, runSCA(ctx, client, targetURL)...)

	case "container":
		if image != "" {
			if findings, err := runTrivy(ctx, image); err == nil {
				allFindings = append(allFindings, findings...)
			}
		}
		allFindings = append(allFindings, runContainerScan(ctx, client, targetURL)...)

	case "full":
		// Run all scanners concurrently
		type result struct {
			findings []*base.Finding
			err      error
		}

		secretsCh := make(chan result, 1)
		sastCh := make(chan result, 1)
		scaCh := make(chan result, 1)
		containerCh := make(chan result, 1)

		go func() {
			f := fetchAndScanSecrets(ctx, client, targetURL)
			secretsCh <- result{findings: f}
		}()
		go func() {
			f := runSAST(ctx, client, targetURL)
			sastCh <- result{findings: f}
		}()
		go func() {
			f := runSCA(ctx, client, targetURL)
			scaCh <- result{findings: f}
		}()
		go func() {
			var f []*base.Finding
			if image != "" {
				if trivyFindings, err := runTrivy(ctx, image); err == nil {
					f = append(f, trivyFindings...)
				}
			}
			f = append(f, runContainerScan(ctx, client, targetURL)...)
			containerCh <- result{findings: f}
		}()

		for _, ch := range []chan result{secretsCh, sastCh, scaCh, containerCh} {
			r := <-ch
			allFindings = append(allFindings, r.findings...)
		}

	default:
		return nil, fmt.Errorf("unknown mode %q: use sast, sca, secrets, container, or full", mode)
	}

	return allFindings, nil
}

func normalizeTarget(target string) string {
	target = strings.TrimSpace(target)
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}
	u, err := url.Parse(target)
	if err != nil {
		return target
	}
	// Strip path for root-level probing
	u.Path = ""
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

func newDevSecOpsHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
			DisableKeepAlives:   true,
			MaxIdleConnsPerHost: 4,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}
