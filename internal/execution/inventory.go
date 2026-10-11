package execution

// Path is one way Mirage can cause an effect outside the API process.
type Path struct {
	ID         string
	Kind       string
	Entry      string
	ScopeToday string
	V2Status   string
}

// ExecutionPaths is the PR 0 inventory. V2Status records what this change
// actually enforces. Paths marked legacy still run when MIRAGE_EXECUTION_V2
// is off, and several still bypass the gateway when the flag is on.
func ExecutionPaths() []Path {
	return []Path{
		{ID: "llm.execute_command", Kind: "shell", Entry: "internal/agent/orchestrator.go runAgentLoop → tools.Registry execute_command → docker.Sandbox.Execute", ScopeToday: "ScopeEngine.ValidateToolArgs parses the shell string. Shared mirage-sandbox.", V2Status: "execute_command is unrestricted shell and stays denied without an explicit grant. nuclei, nmap, ffuf, curl, sqlmap, and the other scanners run through run_security_tool as argv. HTTP scanners can take a flow proxy; raw TCP from the shared sandbox bridge is still not packet-filtered"},
		{ID: "llm.visual_crawl", Kind: "browser", Entry: "tools visual_crawl → base.RunCrawl", ScopeToday: "ScopeEngine checks the URL argument only. No DNS or redirect re-check.", V2Status: "RunFlow, the SPA crawl, and visual_crawl attach the gateway. The egress proxy forwards the original method, headers, and body"},
		{ID: "llm.analyze_source_code", Kind: "shell", Entry: "tools/registry.go analyze_source_code → sandbox git", ScopeToday: "Repository URL scheme and host-character checks. Not the flow ScopeEngine.", V2Status: "classified as source.fetch, not unrestricted shell; every URL in the arguments is checked"},
		{ID: "llm.other_tools", Kind: "control", Entry: "think, update_brain, report_findings, causal graph, oob_generate, oob_poll, generate_payloads", ScopeToday: "ValidateToolArgs returns true without a destination check.", V2Status: "local control tools pass through the gateway and do not open sockets"},
		{ID: "fuzzclient", Kind: "http", Entry: "internal/agent/base/httpclient.go FuzzClient", ScopeToday: "scopeAllows is fail-open when no Scope is on the context. Redirects are followed inside the HTTP client.", V2Status: "payload GETs are active; dials only the authorized IPs"},
		{ID: "cors.raw_client", Kind: "http", Entry: "internal/agents/cors/agent.go sendCORSProbe", ScopeToday: "Own http.Client. Does not consult ScopeEngine.", V2Status: "gateway Do, and the legacy client is wrapped"},
		{ID: "specialist.raw_clients", Kind: "http", Entry: "hostheader, llmpentest, racecondition, log4shell, saml and other specialists that construct http.Client directly", ScopeToday: "Bypass ScopeEngine and FuzzClient.", V2Status: "target HTTP clients are wrapped; a missing gateway fails closed when execution v2 is required"},
		{ID: "browser.screenshot", Kind: "browser", Entry: "internal/agent/screenshot.go", ScopeToday: "Navigates with chromedp and no scope check of its own.", V2Status: "uses the same egress proxy as crawl"},
		{ID: "waf.fingerprint", Kind: "http", Entry: "internal/agent/waf_fingerprint.go FingerprintWAF", ScopeToday: "Creates its own FuzzClient without the flow context.", V2Status: "receives the flow gateway context"},
		{ID: "oob.callback", Kind: "listen", Entry: "internal/agent/base/oob_server.go and orchestrator OOB promotion", ScopeToday: "In-process callback server. A match can be appended as a critical finding.", V2Status: "listener is not an outbound dial; finding promotion is still outside this gateway"},
		{ID: "netpentest", Kind: "network", Entry: "internal/agents/netpentest", ScopeToday: "Specialist-owned network activity.", V2Status: "TCP connect scan uses DialAuthorized; HTTP clients are wrapped"},
		{ID: "schedule", Kind: "trigger", Entry: "server.schedulerTrigger and server.firePlan", ScopeToday: "Creates a flow and calls runAgent with no extra authorization record.", V2Status: "inherits the parent authorization, including autonomy and expiry"},
		{ID: "cicd", Kind: "trigger", Entry: "POST /api/cicd/trigger", ScopeToday: "Creates a flow for any target when the optional HMAC secret matches.", V2Status: "same inheritance check as scheduled scans"},
		{ID: "docker.shared_sandbox", Kind: "shell", Entry: "server.runAgent → docker.FlowSandbox when execution v2 is on", ScopeToday: "Executes in the long-lived mirage-sandbox container. FlowSandbox exists and is not used here.", V2Status: "v2 tool execution uses a per-flow container without NET_ADMIN. A host iptables chain drops forwarded packets from that container except authorized TCP or UDP sockets"},
		{ID: "plugins", Kind: "latent", Entry: "internal/plugins/loader.go", ScopeToday: "Loads prompts and script paths. This package does not execute those scripts.", V2Status: "no execution hook added"},
	}
}
