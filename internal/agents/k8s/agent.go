// Package k8s implements the Kubernetes/Docker API Exposure specialist agent.
//
// Checks for unauthenticated access to Kubernetes API server, Docker daemon API,
// etcd, Prometheus metrics, and Spring Actuator endpoints.
package k8s

import (
	"context"
	"fmt"
	"strings"

	"github.com/bb-agent/mirage/internal/agent/base"
	"github.com/bb-agent/mirage/internal/queue"
)

// Agent implements the Specialist interface for K8s/Docker API exposure detection.
type Agent struct {
	systemPrompt string
}

// New creates a new K8s/Docker specialist agent.
func New() *Agent {
	return &Agent{systemPrompt: defaultSystemPrompt}
}

func (a *Agent) Name() string         { return "K8s/Docker Agent" }
func (a *Agent) ID() string           { return "k8s" }
func (a *Agent) SystemPrompt() string { return a.systemPrompt }

// endpointCheck describes one API endpoint probe.
type endpointCheck struct {
	path          string
	label         string
	category      string
	jsonIndicator string // substring in response body that confirms the API responded correctly
}

var checks = []endpointCheck{
	// Kubernetes API server
	{path: "/api/v1/namespaces", label: "k8s_namespaces", category: "kubernetes",
		jsonIndicator: `"kind":"NamespaceList"`},
	{path: "/api/v1/pods", label: "k8s_pods", category: "kubernetes",
		jsonIndicator: `"kind":"PodList"`},
	{path: "/api/v1/nodes", label: "k8s_nodes", category: "kubernetes",
		jsonIndicator: `"kind":"NodeList"`},
	{path: "/api/v1/secrets", label: "k8s_secrets", category: "kubernetes",
		jsonIndicator: `"kind":"SecretList"`},
	{path: "/apis", label: "k8s_apis", category: "kubernetes",
		jsonIndicator: `"kind":"APIGroupList"`},
	{path: "/version", label: "k8s_version", category: "kubernetes",
		jsonIndicator: `"gitVersion"`},

	// Docker daemon (typically port 2375/2376 but sometimes behind a reverse proxy)
	{path: "/_ping", label: "docker_ping", category: "docker",
		jsonIndicator: "OK"},
	{path: "/v1.40/containers/json", label: "docker_containers", category: "docker",
		jsonIndicator: `"Id"`},
	{path: "/v1.40/images/json", label: "docker_images", category: "docker",
		jsonIndicator: `"RepoTags"`},
	{path: "/v1.40/info", label: "docker_info", category: "docker",
		jsonIndicator: `"DockerRootDir"`},
	{path: "/v1.24/containers/json", label: "docker_containers_v124", category: "docker",
		jsonIndicator: `"Id"`},

	// etcd
	{path: "/v2/keys", label: "etcd_v2_keys", category: "etcd",
		jsonIndicator: `"action"`},
	{path: "/v2/members", label: "etcd_v2_members", category: "etcd",
		jsonIndicator: `"members"`},
	{path: "/health", label: "etcd_health", category: "etcd",
		jsonIndicator: `"health"`},

	// Prometheus metrics
	{path: "/metrics", label: "prometheus_metrics", category: "metrics",
		jsonIndicator: "# HELP"},

	// Spring Actuator
	{path: "/actuator", label: "actuator_root", category: "actuator",
		jsonIndicator: `"_links"`},
	{path: "/actuator/health", label: "actuator_health", category: "actuator",
		jsonIndicator: `"status"`},
	{path: "/actuator/env", label: "actuator_env", category: "actuator",
		jsonIndicator: `"activeProfiles"`},
	{path: "/actuator/beans", label: "actuator_beans", category: "actuator",
		jsonIndicator: `"beans"`},
	{path: "/actuator/mappings", label: "actuator_mappings", category: "actuator",
		jsonIndicator: `"dispatcherServlets"`},
	{path: "/actuator/heapdump", label: "actuator_heapdump", category: "actuator",
		jsonIndicator: ""},
}

// ProcessItem probes a target for exposed infrastructure APIs.
func (a *Agent) ProcessItem(ctx context.Context, item *queue.Item) ([]*base.Finding, error) {
	targetURL, _ := item.Payload["target"].(string)
	if targetURL == "" {
		return nil, fmt.Errorf("missing target URL in work item")
	}

	// Derive base URL (scheme://host) without path
	baseURL := extractBaseURL(targetURL)
	fc := base.NewFuzzClient()

	var findings []*base.Finding

	for _, check := range checks {
		probeURL := baseURL + check.path
		result := fc.ProbeGET(ctx, probeURL, "", "")
		if result.Error != nil {
			continue
		}

		if result.StatusCode != 200 {
			continue
		}

		// Confirm the response matches expected API content
		conf := 0.0
		evidence := map[string]interface{}{
			"label":       check.label,
			"category":    check.category,
			"status_code": result.StatusCode,
			"path":        check.path,
			"body_len":    len(result.Body),
		}

		if check.jsonIndicator == "" {
			// heapdump or similar binary: 200 is enough
			conf = 0.8
			evidence["note"] = "200 response on sensitive endpoint"
		} else if strings.Contains(result.Body, check.jsonIndicator) {
			conf = 0.95
			evidence["json_indicator"] = check.jsonIndicator
			evidence["confirmed"] = true
		} else if result.StatusCode == 200 && len(result.Body) > 20 {
			// 200 but no exact match — still suspicious
			conf = 0.6
			evidence["soft_match"] = true
		}

		if conf == 0 {
			continue
		}

		severity := categoryToSeverity(check.category)

		findings = append(findings, &base.Finding{
			Type:       "Exposed " + categoryLabel(check.category) + " API",
			URL:        probeURL,
			Parameter:  "",
			Payload:    check.path,
			Severity:   severity,
			Confidence: conf,
			Evidence:   evidence,
			Method:     "GET",
		})
	}

	return findings, nil
}

// extractBaseURL returns scheme://host from any URL.
func extractBaseURL(rawURL string) string {
	// Find end of scheme://host
	idx := strings.Index(rawURL, "://")
	if idx < 0 {
		return rawURL
	}
	rest := rawURL[idx+3:]
	slashIdx := strings.Index(rest, "/")
	if slashIdx < 0 {
		return rawURL
	}
	return rawURL[:idx+3+slashIdx]
}

func categoryToSeverity(cat string) string {
	switch cat {
	case "kubernetes", "docker", "etcd":
		return "critical"
	case "actuator":
		return "high"
	case "metrics":
		return "medium"
	default:
		return "high"
	}
}

func categoryLabel(cat string) string {
	switch cat {
	case "kubernetes":
		return "Kubernetes"
	case "docker":
		return "Docker"
	case "etcd":
		return "etcd"
	case "actuator":
		return "Spring Actuator"
	case "metrics":
		return "Prometheus Metrics"
	default:
		return cat
	}
}

const defaultSystemPrompt = `You are a Kubernetes/Docker infrastructure exposure specialist.
You detect unauthenticated access to:

- Kubernetes API Server: /api/v1/namespaces, /api/v1/pods, /api/v1/secrets
- Docker daemon API: /_ping, /v1.40/containers/json
- etcd: /v2/keys, /v2/members
- Prometheus metrics: /metrics (leaks internal stats)
- Spring Actuator: /actuator/env (leaks secrets), /actuator/heapdump

Confidence: 0.95 when JSON response contains expected type field.
Severity: CRITICAL for K8s/Docker/etcd (full cluster compromise), HIGH for Actuator, MEDIUM for metrics.`
