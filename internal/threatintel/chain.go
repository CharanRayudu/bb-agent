package threatintel

import "strings"

// ChainEdge defines a directed "enables" relationship between two finding types.
type ChainEdge struct {
	From       string  // source finding type
	To         string  // target finding type
	Relation   string  // "enables" | "amplifies" | "prerequisite"
	Impact     string  // what the combined exploitation achieves
	Confidence float64 // how likely this chain applies (0–1)
}

// AttackChain is a resolved kill path through the vulnerability graph.
type AttackChain struct {
	Steps      []ChainStep `json:"steps"`
	Impact     string      `json:"impact"`
	Score      float64     `json:"score"`  // 0–100
	Length     int         `json:"length"`
}

// ChainStep is one node in a resolved attack chain.
type ChainStep struct {
	FindingType string  `json:"finding_type"`
	Relation    string  `json:"relation"`
	Impact      string  `json:"impact"`
	Confidence  float64 `json:"confidence"`
}

// ChainAnalysis is the full result of attack chain analysis.
type ChainAnalysis struct {
	InputFindings []string      `json:"input_findings"`
	Chains        []AttackChain `json:"chains"`
	TopChain      *AttackChain  `json:"top_chain,omitempty"`
	EdgeCount     int           `json:"edge_count"`
}

// chainEdges defines the attack chain graph.
// Each edge means: if From is confirmed, To becomes significantly easier or unlocked.
var chainEdges = []ChainEdge{
	// SSRF kill paths
	{From: "SSRF", To: "Cloud-IMDS", Relation: "enables", Impact: "Access AWS/Azure/GCP instance metadata to steal cloud credentials", Confidence: 0.85},
	{From: "SSRF", To: "IMDS-Credentials", Relation: "enables", Impact: "Steal IAM role credentials via IMDS v1", Confidence: 0.87},
	{From: "SSRF", To: "K8s-APIServer", Relation: "enables", Impact: "Reach internal Kubernetes API server for cluster takeover", Confidence: 0.72},
	{From: "SAST-SSRF-001", To: "Cloud-IMDS", Relation: "enables", Impact: "SSRF code sink reachable — can be used to probe IMDS", Confidence: 0.75},
	{From: "Cloud-IMDS", To: "IMDS-Credentials", Relation: "enables", Impact: "Unauthenticated IMDS v1 returns IAM credentials directly", Confidence: 0.92},
	{From: "IMDS-Credentials", To: "S3-PublicRead", Relation: "amplifies", Impact: "Stolen IAM credentials grant access to all S3 buckets in account", Confidence: 0.88},
	{From: "IMDS-Credentials", To: "Cloud-StorageExposed", Relation: "amplifies", Impact: "Stolen cloud credentials enable lateral movement to all cloud services", Confidence: 0.85},

	// XSS → Session → privilege
	{From: "XSS", To: "IDOR", Relation: "enables", Impact: "XSS steals session token; attacker impersonates victim to abuse insecure direct object references", Confidence: 0.78},
	{From: "Stored XSS", To: "IDOR", Relation: "enables", Impact: "Persistent XSS exfiltrates admin session; enables IDOR as privileged user", Confidence: 0.83},
	{From: "XSS", To: "CSRF", Relation: "amplifies", Impact: "XSS bypasses SameSite cookie protection, amplifying CSRF impact", Confidence: 0.72},
	{From: "Reflected XSS", To: "OAuth", Relation: "enables", Impact: "XSS in OAuth redirect_uri or state parameter allows token theft", Confidence: 0.68},
	{From: "SAST-XSS-001", To: "IDOR", Relation: "enables", Impact: "XSS sink in source enables session theft → IDOR exploitation", Confidence: 0.70},

	// SQLi paths
	{From: "SQLi", To: "RCE", Relation: "enables", Impact: "MySQL FILE privilege or MSSQL xp_cmdshell enables code execution from SQL injection", Confidence: 0.62},
	{From: "SAST-SQLi-001", To: "RCE", Relation: "enables", Impact: "SQL injection via string concatenation can achieve RCE on some DB configs", Confidence: 0.55},
	{From: "SQLi", To: "Auth Bypass", Relation: "enables", Impact: "Classic SQLi bypass: ' OR 1=1-- circumvents authentication", Confidence: 0.88},
	{From: "SQL Injection", To: "Auth Bypass", Relation: "enables", Impact: "Authentication bypass via tautology injection", Confidence: 0.88},

	// LFI paths
	{From: "LFI", To: "RCE", Relation: "enables", Impact: "LFI to RCE via log poisoning (Apache access.log, /proc/self/environ) or include wrapper", Confidence: 0.65},
	{From: "LFI", To: "Secret-DatabaseConnectionString", Relation: "enables", Impact: "LFI reads /etc/passwd, config files, .env — exposes DB credentials", Confidence: 0.80},
	{From: "LFI", To: "Secret-GenericPasswordinConfig", Relation: "enables", Impact: "LFI reads application config files containing hardcoded credentials", Confidence: 0.78},

	// Open Redirect paths
	{From: "Open Redirect", To: "OAuth", Relation: "enables", Impact: "Open redirect in redirect_uri steals OAuth authorization codes", Confidence: 0.75},
	{From: "SAST-OpenRedirect-001", To: "OAuth", Relation: "enables", Impact: "Open redirect code path exploitable in OAuth flows", Confidence: 0.65},

	// Default Creds paths
	{From: "Default Credentials", To: "RCE", Relation: "enables", Impact: "Admin panel access via default creds enables config changes, file upload, or plugin install RCE", Confidence: 0.72},
	{From: "Default Creds", To: "Exposed Docker API", Relation: "amplifies", Impact: "Default creds on management interface exposes Docker daemon control", Confidence: 0.60},
	{From: "Unauthenticated Redis", To: "RCE", Relation: "enables", Impact: "Unauthenticated Redis allows config rewrite (authorized_keys, cron) for RCE", Confidence: 0.82},

	// Container escape paths
	{From: "Container-Privileged", To: "RCE", Relation: "enables", Impact: "Privileged container can mount host filesystem and escape to full host RCE", Confidence: 0.92},
	{From: "Container-RootUser", To: "Container-Privileged", Relation: "amplifies", Impact: "Root user in container amplifies impact of any other container misconfiguration", Confidence: 0.70},
	{From: "Container-SensitiveMount", To: "RCE", Relation: "enables", Impact: "docker.sock mount allows creating a privileged container → host escape", Confidence: 0.88},
	{From: "Exposed Docker API", To: "Container-Privileged", Relation: "enables", Impact: "Unauthenticated Docker API allows deploying privileged containers", Confidence: 0.90},

	// Subdomain takeover paths
	{From: "Subdomain Takeover", To: "XSS", Relation: "enables", Impact: "Attacker controls subdomain.target.com — same-origin XSS against parent domain cookies", Confidence: 0.75},
	{From: "Subdomain Takeover", To: "CORS", Relation: "enables", Impact: "Controlled subdomain satisfies permissive CORS wildcard (*.target.com)", Confidence: 0.68},

	// Secret disclosure chains
	{From: "Secret-AWSKey", To: "S3-PublicRead", Relation: "enables", Impact: "Exposed AWS key provides direct API access to all S3 buckets", Confidence: 0.95},
	{From: "Secret-AWSSecretAccessKey", To: "IMDS-Credentials", Relation: "amplifies", Impact: "Combined static key + instance credentials = full account takeover", Confidence: 0.90},
	{From: "Secret-GitHubPersonalAccessToken", To: "SCA-CVE", Relation: "amplifies", Impact: "GitHub token enables supply chain compromise — inject malicious dependency", Confidence: 0.65},
	{From: "Secret-FileExposure", To: "Secret-DatabaseConnectionString", Relation: "enables", Impact: "Exposed .env or config file contains database connection string with credentials", Confidence: 0.80},
	{From: "Secret-DatabaseConnectionString", To: "SQLi", Relation: "amplifies", Impact: "Direct DB credentials amplify SQL injection — attacker can connect directly", Confidence: 0.85},

	// LLM chains
	{From: "LLM01-PromptInjection", To: "LLM06-ExcessiveAgency", Relation: "enables", Impact: "Prompt injection triggers autonomous agent to execute attacker-controlled actions", Confidence: 0.80},
	{From: "LLM01-PromptInjection", To: "LLM02-InfoDisclosure", Relation: "enables", Impact: "Injected prompt leaks system prompt, user data, or tool outputs", Confidence: 0.75},
	{From: "LLM07-SystemPromptLeak", To: "LLM08-Jailbreak", Relation: "amplifies", Impact: "Knowing the system prompt enables more targeted jailbreak attempts", Confidence: 0.70},

	// Supply chain
	{From: "SCA-CVE", To: "RCE", Relation: "enables", Impact: "Known RCE CVE in direct dependency (e.g. Log4Shell) achieves code execution", Confidence: 0.75},

	// K8s chains
	{From: "K8s-ServiceAccount", To: "K8s-APIServer", Relation: "enables", Impact: "Overprivileged service account token enables full API server access", Confidence: 0.82},
	{From: "K8s-APIServer", To: "Container-Privileged", Relation: "enables", Impact: "Unauthenticated API server allows deploying privileged pods", Confidence: 0.88},
}

// BuildChainIndex creates a lookup map from finding type to outgoing edges.
func BuildChainIndex() map[string][]ChainEdge {
	idx := map[string][]ChainEdge{}
	for _, e := range chainEdges {
		idx[e.From] = append(idx[e.From], e)
	}
	return idx
}

// AnalyzeChains finds all attack chains reachable from the given finding types.
// It performs a bounded DFS (max depth 4) to prevent combinatorial explosion.
func AnalyzeChains(findingTypes []string) ChainAnalysis {
	present := map[string]bool{}
	for _, ft := range findingTypes {
		present[ft] = true
	}

	idx := BuildChainIndex()
	var chains []AttackChain

	// For each starting finding that has outgoing edges, DFS to find chains
	for _, start := range findingTypes {
		if _, hasEdges := idx[start]; !hasEdges {
			continue
		}
		discovered := dfsChains(start, idx, present, []ChainStep{}, 0, 4)
		chains = append(chains, discovered...)
	}

	// Deduplicate chains by their step sequence
	chains = deduplicateChains(chains)

	// Sort by score descending
	sortChainsByScore(chains)

	var topChain *AttackChain
	if len(chains) > 0 {
		topChain = &chains[0]
	}

	return ChainAnalysis{
		InputFindings: findingTypes,
		Chains:        chains,
		TopChain:      topChain,
		EdgeCount:     len(chainEdges),
	}
}

func dfsChains(current string, idx map[string][]ChainEdge, present map[string]bool, path []ChainStep, depth, maxDepth int) []AttackChain {
	if depth >= maxDepth {
		return nil
	}

	edges, ok := idx[current]
	if !ok {
		return nil
	}

	var chains []AttackChain
	for _, edge := range edges {
		// Only follow edges where the target is also in our finding set (validated chains)
		// OR the target is a high-value end goal
		targetInSet := present[edge.To]
		highValueTarget := isHighValueTarget(edge.To)

		if !targetInSet && !highValueTarget {
			continue
		}

		step := ChainStep{
			FindingType: edge.To,
			Relation:    edge.Relation,
			Impact:      edge.Impact,
			Confidence:  edge.Confidence,
		}
		newPath := append(append([]ChainStep{}, path...), step)

		if len(newPath) >= 2 {
			chain := buildChain(current, newPath)
			chains = append(chains, chain)
		}

		// Continue DFS
		deeper := dfsChains(edge.To, idx, present, newPath, depth+1, maxDepth)
		chains = append(chains, deeper...)
	}
	return chains
}

func buildChain(start string, steps []ChainStep) AttackChain {
	// Score = sum of step confidences × severity weight × length bonus
	var score float64
	for _, s := range steps {
		score += s.Confidence * 25.0
	}
	// Length bonus — longer chains are more impactful
	score += float64(len(steps)) * 5.0
	if score > 100 {
		score = 100
	}

	impact := ""
	if len(steps) > 0 {
		impact = steps[len(steps)-1].Impact
	}

	// Build full step list including start
	allSteps := []ChainStep{{FindingType: start, Relation: "start", Confidence: 1.0}}
	allSteps = append(allSteps, steps...)

	return AttackChain{
		Steps:  allSteps,
		Impact: impact,
		Score:  score,
		Length: len(allSteps),
	}
}

var highValueTargets = map[string]bool{
	"RCE":             true,
	"Container-Privileged": true,
	"IMDS-Credentials": true,
	"S3-PublicRead":   true,
	"K8s-APIServer":   true,
	"Auth Bypass":     true,
}

func isHighValueTarget(t string) bool {
	return highValueTargets[t]
}

func deduplicateChains(chains []AttackChain) []AttackChain {
	seen := map[string]bool{}
	var out []AttackChain
	for _, c := range chains {
		key := chainKey(c)
		if !seen[key] {
			seen[key] = true
			out = append(out, c)
		}
	}
	return out
}

func chainKey(c AttackChain) string {
	var sb strings.Builder
	for _, s := range c.Steps {
		sb.WriteString(s.FindingType)
		sb.WriteString("→")
	}
	return sb.String()
}

func sortChainsByScore(chains []AttackChain) {
	// Simple insertion sort (chain lists are small)
	for i := 1; i < len(chains); i++ {
		for j := i; j > 0 && chains[j].Score > chains[j-1].Score; j-- {
			chains[j], chains[j-1] = chains[j-1], chains[j]
		}
	}
}
