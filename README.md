# Mirage

**Autonomous LLM-Driven Penetration Testing Agent**

Mirage is a black-box web penetration testing platform powered by large language models. It autonomously plans, executes, and validates vulnerability scans against live web targets using a multi-phase pipeline, 48 specialist agents, a hallucination-gated findings system, hypothesis-driven attack reasoning, and a real-time React dashboard.

---

## Architecture

```text
React + Vite Frontend (port 3000)
  → real-time dashboard, WebSocket event stream, knowledge graph visualiser
  → Go backend (REST + WebSocket API, port 8443)
     → 8-phase pipeline state machine
     → Orchestrator: ReAct loop, brain, iterative feedback
     → 48 specialist agents, per-agent async queues
     → Mythos Hypothesis Engine: pre-dispatch attack hypothesis generation
     → WAF fingerprinting + vendor-specific bypass payload injection
     → Scope Engine: port-strict enforcement, shell-variable filtering
     → Hallucination Bin: gate-based finding quarantine and promotion
     → Known-Defence Recorder: avoids dead-end paths across loops
     → Out-of-Band (OOB) blind vulnerability detection via Interactsh
     → Headless browser validation (Chrome DevTools Protocol)
     → Causal evidence graph for non-monotonic reasoning
     → Cross-session knowledge graph (in-memory or Neo4j)
     → RAG Knowledge Base client for payload context enrichment
  → PostgreSQL for scan state, brain snapshots, findings
  → Docker sandbox for isolated tool execution
  → LLM API (OpenAI / Codex)
  → Neo4j (optional) for persistent cross-scan knowledge
```

---

## Key Features

### Core Pipeline
- **8-Phase State Machine** — Idle → Reconnaissance → Discovery → Strategy → Exploitation → Validation → Reporting → Complete, with iterative feedback loops and pivot-triggered recon restarts
- **Iterative Feedback Loops** — Up to 3 recon restarts when credential or pivot discoveries unlock new attack surface; adaptive convergence detection stops early when no new findings emerge
- **Schema-Validated Planner Output** — Structured JSON validation at phase boundaries prevents garbage-in-garbage-out across the swarm dispatch layer

### Hallucination Bin (Guilty Until Proven Innocent)
- Every new finding starts in `Brain.HallucinationBin` with the exact gate it failed (e.g. *"missing request/response proof"*)
- Findings are promoted only after passing concrete proof gates: request/response pair, browser validation, timing differential, or OOB callback
- The planner receives the full hallucination bin state and dispatches targeted specialists to acquire missing proof, rather than re-discovering the same endpoint
- Parallel `Known-Defence` recording: when WAF rules, auth walls, or rate limits persistently block a path, agents call `update_brain(category='defence')` and the planner avoids those paths in subsequent loops

### Mythos Hypothesis Engine
- Pre-dispatch LLM reasoning generates 8–12 prioritised attack hypotheses before swarm deployment, following a 5-step adversarial chain: Threat Modelling → Attack Surface Analysis → Exploitation Chain → Zero-Day Assessment → Impact Scoring
- Hypotheses include kill chains, confidence scores, and zero-day risk flags
- Post-exploitation refinement updates hypothesis confidence based on specialist outcomes; active hypotheses (confidence > 0.2) feed into the next planner iteration
- Rule-based fallback covers SQLi, SSRF, IDOR, Auth Bypass, JWT, Business Logic, GraphQL, and XSS when LLM is unavailable

### Scope Engine
- **Port-strict enforcement** — If the target URL specifies an explicit port (e.g. `http://86.48.30.37:3001`), all requests to other ports are blocked; nmap/naabu port-scanning the SSH or HTTP port of an app-only target is prevented
- **Shell variable filtering** — Loop variables like `http://host$p` are excluded from scope checks so bash for-loops don't trigger false-positive blocks
- **Accurate error messages** — Block messages show both `AllowedDomains` and `AllowedIPs` so agents understand their scope correctly

### Specialist Swarm (48 Agents)
- **Minimum 6 agents dispatched per scan** regardless of recon findings: Auth Bypass, Reflected XSS, Time-based SQLi, IDOR, Misconfigs, Business Logic
- **Hypothesis-driven dispatch** — planner maps every hypothesis with priority ≥ 6 to a specialist, mandatory minimum of 5 specialists per loop
- Specialist-specific tool guidance, WAF bypass payload injection, and RAG knowledge base enrichment per agent

### Detection & Validation
- **WAF Fingerprinting** — Detects Cloudflare, Akamai, AWS Shield, ModSecurity, WordFence, Sucuri, Incapsula; injects vendor-specific bypass payloads before swarm dispatch
- **OOB Blind Detection** — Interactsh-based DNS/HTTP/SMTP callbacks with in-process callback server for blind SSRF, XXE, and command injection
- **Visual Validation** — Headless Chrome confirms XSS execution via screenshot and DOM inspection
- **Reflector Agent** — Vetoes findings by re-analysing tool output before promotion
- **Causal Evidence Graph** — Non-monotonic DAG tracking attack nodes, confidence, and evidence chains

### Cross-Session Intelligence
- **Shared Knowledge Graph** — Single `knowledge.Graph` instance (in-memory or Neo4j) shared across concurrent scans; records hosts, services, vulnerabilities, techniques, and proven payloads
- **Cross-flow Memory** — Thompson Sampling-based memory stores insights about which techniques worked on which targets across all historical scans
- **RAG Knowledge Base** — External Python RAG service queried per specialist with target-specific payload and bypass context
- **Adaptive Payload Engine** — LLM-generated bypass variants for high-priority specialists; WAF-specific mutations prepended to payload lists

### Operational
- **RBAC** — Admin, Operator, and Viewer roles
- **Scheduling** — Recurring scans with cron expressions and schedule-plan management
- **Webhooks** — HMAC-SHA256 signed webhook notifications on findings
- **Audit Log** — Append-only event log for all user actions
- **Burp Suite Export** — Findings exportable as Burp XML
- **CI/CD Integration** — Webhook trigger endpoint for pipeline-initiated scans
- **GitHub App Integration** — Webhook handler and DevSecOps pipeline scan trigger
- **Ticketing** — Create tickets from findings via the integrations API
- **Configurable Prompts** — `prompts.yaml` controls all phase and agent instructions without code changes

---

## Specialist Agents (48)

| Category | Agents |
|---|---|
| Injection | SQLi, SQLmap, XSS, SSTI, CSTI, XXE, LFI/Path Traversal, RCE, Log4Shell |
| Auth & Access | Auth Discovery, Auth Bypass, JWT, OAuth, SAML, IDOR, Mass Assignment |
| API & Protocol | API Security, GraphQL, WebSocket, HTTP Smuggling, Second Order |
| Infrastructure | SSRF, Host Header, CORS, Cache Poisoning, Header Injection |
| Client-Side | Reflected XSS, Stored XSS, Prototype Pollution, Open Redirect, File Upload |
| Cloud & Assets | Cloud Hunter, S3 Enum, Resource Hunter, Blind Oracle |
| Recon & Discovery | Asset Discovery, GoSpider, Visual Crawler, URLMaster, Chain Discovery |
| Evasion | WAF Evasion, Deserialization |
| Post-Exploitation | Post Exploit, Race Condition, Business Logic |
| Analysis & Report | Nuclei, DAST+SAST, Consolidation, Validation, Reporting |
| Specialised | K8s, Auth Discovery |

---

## Project Structure

```text
bb-agent/
├── cmd/mirage/              # Application entry point
├── internal/
│   ├── agent/               # Core orchestrator and agent infrastructure
│   │   ├── base/            # Shared types (Finding, Specialist interface, browser primitives)
│   │   ├── schema/          # LLM output schema validation
│   │   ├── orchestrator.go  # Main ReAct loop, pipeline phases, iterative feedback, brain
│   │   ├── hypothesis_engine.go  # Mythos: pre-dispatch attack hypothesis generation
│   │   ├── scope.go         # Scope enforcement (port-strict, shell-variable filtering)
│   │   ├── proof.go         # Finding proof classification (request/response, OOB, timing, browser)
│   │   ├── waf_fingerprint.go    # WAF vendor detection and bypass payload selection
│   │   ├── zero_day_patterns.go  # Novel/0-day vulnerability patterns beyond OWASP
│   │   ├── oob.go / oob_server.go  # Out-of-band blind detection (Interactsh)
│   │   ├── payload_engine.go     # Adaptive LLM-driven payload generation
│   │   ├── memory.go        # Cross-flow target intelligence (Thompson Sampling)
│   │   ├── brain_snapshot.go     # Brain state serialization and restoration
│   │   ├── attack_graph.go  # Causal evidence graph management
│   │   ├── rag_client.go    # RAG knowledge base client
│   │   ├── conductor.go     # Agent lifecycle and timeout management
│   │   ├── resilience.go    # Self-healing tool error recovery
│   │   ├── dedup.go         # Advanced finding deduplication
│   │   ├── cvss.go          # CVSS 3.1 scoring and remediation guidance
│   │   ├── compliance.go    # CWE / OWASP / NIST / PCI-DSS mapping
│   │   └── ...              # + scheduler, webhooks, RBAC, reporting, exports
│   ├── agents/              # 48 vulnerability specialist agents
│   │   ├── xss/             # XSS (reflected, stored, DOM, WAF bypass)
│   │   ├── sqli/            # SQL Injection (error, blind, union, OOB, sqlmap)
│   │   ├── ssrf/            # SSRF (cloud metadata, internal, OOB)
│   │   ├── idor/            # Insecure Direct Object References
│   │   ├── businesslogic/   # Business logic (price manipulation, coupon abuse)
│   │   ├── llmpentest/      # LLM jailbreak and prompt injection testing
│   │   ├── wafevasion/      # WAF bypass with LLM-driven mutation
│   │   └── ...              # + 41 more specialists
│   ├── knowledge/           # Knowledge graph (in-memory + Neo4j backend)
│   ├── config/              # YAML prompt configuration loader
│   ├── database/            # PostgreSQL queries and schema migrations
│   ├── llm/                 # LLM provider integrations (OpenAI, Codex)
│   ├── models/              # Data models (Flow, Task, SubTask, Action, CausalGraph)
│   ├── notify/              # Notification dispatcher (Slack, webhook, email channels)
│   ├── pipeline/            # 8-phase state machine with lifecycle management
│   ├── queue/               # Per-specialist async queues with backpressure
│   ├── remediation/         # Remediation tracking and ticket integration
│   ├── schedplan/           # Schedule plan runner (cron-based automation)
│   ├── threatintel/         # ATT&CK mapping, CVE enrichment, risk prioritization
│   └── server/              # HTTP REST API, WebSocket, and all route handlers
│       ├── server.go        # Core mux registration, CORS, auth middleware
│       ├── api_extensions.go       # Auth, knowledge graph, config, assets, notifications
│       ├── apts_routes.go          # Autonomous Pentest System status and control
│       ├── copilot_handler.go      # AI copilot chat sessions
│       ├── github_app.go           # GitHub App webhook + DevSecOps scan trigger
│       ├── integrations_handler.go # Ticketing integrations
│       ├── monitoring_handler.go   # Continuous asset monitoring and alerting
│       ├── notify_handler.go       # Notification channels and event routing
│       ├── posture_handler.go      # Security posture scoring and history
│       ├── profiles_handler.go     # Scan profile templates
│       ├── remediation_tracking_handler.go  # Remediation items and metrics
│       ├── report_generation_handler.go     # AI report generation
│       ├── schedplan_handler.go    # Schedule plan CRUD
│       ├── threatintel_handler.go  # ATT&CK, attack chains, CVE enrichment
│       └── vuln_intel_handler.go   # Finding stats, search, and export
├── frontend/                # React + Vite dashboard (Mirage Design System v3)
│   └── src/
│       ├── pages/
│       │   ├── Dashboard.jsx        # Scan list + paginated findings grid
│       │   ├── FlowDetail.jsx       # Real-time terminal, findings, evidence ledger
│       │   ├── NewTask.jsx          # Scan launch form with profile selector
│       │   ├── Assets.jsx           # Asset inventory with search/filter + pagination
│       │   ├── Posture.jsx          # Security posture score and history chart
│       │   ├── Remediation.jsx      # Remediation tracking board
│       │   ├── ThreatIntel.jsx      # ATT&CK matrix and CVE enrichment
│       │   ├── DevSecOps.jsx        # CI/CD pipeline integration
│       │   ├── Monitoring.jsx       # Continuous asset monitoring
│       │   ├── Reports.jsx          # Report generation and export
│       │   ├── ScanProfiles.jsx     # Scan profile template management
│       │   ├── ScheduledScans.jsx   # Cron-based scheduled scan management
│       │   ├── Notifications.jsx    # Alert channel configuration
│       │   ├── VulnIntel.jsx        # Vulnerability analytics and search
│       │   ├── AuditLog.jsx         # Append-only user action log
│       │   ├── KnowledgeGraph.jsx   # Cross-scan knowledge graph visualiser
│       │   ├── Settings.jsx         # Platform configuration (providers, webhooks)
│       │   └── NotFound.jsx         # 404 page with ambient Liquid Glass design
│       └── components/
│           ├── Sidebar.jsx          # Navigation with mobile drawer + hamburger toggle
│           ├── CopilotPanel.jsx     # AI assistant side panel
│           ├── ErrorBoundary.jsx    # Global React error boundary
│           ├── Toast.jsx            # Stacked animated toast notifications (ToastProvider)
│           ├── Modal.jsx            # Reusable glass modal/dialog (size variants, Esc-close)
│           ├── EmptyState.jsx       # Unified empty state with icon, title, CTA
│           ├── CopyButton.jsx       # Copy-to-clipboard with animated feedback
│           ├── Pagination.jsx       # Sliding-window pagination controls
│           ├── FlowLedgerPanel.jsx  # Finding ledger and evidence panel
│           ├── HypothesisTracker.jsx # Live hypothesis confidence tracker
│           ├── ScreenshotGallery.jsx # Visual evidence screenshot viewer
│           ├── RiskOverview.jsx     # Risk gauge and severity chart
│           ├── StatsRow.jsx         # Summary stat chips strip
│           └── TrendChart.jsx       # Finding trend line chart
├── prompts.yaml             # All agent prompts — edit to tune behavior without rebuilding
├── docker-compose.yml       # PostgreSQL, backend, frontend, sandbox, Neo4j
├── .golangci.yml            # Go static analysis config (golangci-lint v2)
├── start.ps1 / start.sh     # Launch scripts
└── stop.ps1 / stop.sh       # Shutdown scripts
```

---

## Prerequisites

- **Docker** and **Docker Compose**
- **Go 1.25+** (for native backend development)
- **Node.js 18+** and **npm** (for native frontend development)
- An **OpenAI API Key** or Codex CLI authentication

---

## Getting Started

### 1. Clone & Configure

```bash
git clone https://github.com/your-org/bb-agent.git
cd bb-agent
cp .env.example .env
# Edit .env and set OPENAI_API_KEY (and optionally NEO4J_* for persistent knowledge graph)
```

### 2. Launch

**Windows:**
```powershell
./start.ps1    # Cleans ports, runs migrations, builds containers, starts all services
./stop.ps1     # Graceful shutdown
```

**Linux / macOS:**
```bash
./start.sh
# Or directly:
docker-compose up -d --build
```

### 3. Access the Dashboard

Open `http://localhost:3000` in your browser.

---

## Configuration

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `OPENAI_API_KEY` | — | OpenAI API key (required if not using Codex) |
| `OPENAI_MODEL` | `gpt-4o` | LLM model for all agents |
| `OPENAI_TEMPERATURE` | `0.1` | Sampling temperature |
| `CODEX_HOME` | `~/.codex` | Codex OAuth config directory |
| `DATABASE_URL` | — | PostgreSQL connection string |
| `SERVER_PORT` | `8443` | Backend listen port |
| `SERVER_HOST` | `0.0.0.0` | Backend listen host |
| `DOCKER_HOST` | platform default | Docker socket path |
| `SANDBOX_IMAGE` | `mirage-tools:latest` | Sandbox container image |
| `NEO4J_URL` | `bolt://localhost:7687` | Neo4j for persistent knowledge graph (optional) |
| `NEO4J_USER` | `neo4j` | Neo4j username |
| `NEO4J_PASSWORD` | `miragepass` | Neo4j password |
| `TAVILY_API_KEY` | — | Tavily search enrichment (optional) |
| `SHODAN_API_KEY` | — | Shodan integration (optional) |
| `AUTH_REQUIRED` | `false` | Require Mirage JWTs for API and WebSocket requests |
| `JWT_SECRET` | — | JWT signing secret used when auth is required |
| `VITE_API_URL` | `localhost:8443` | Backend target used by the Vite dev proxy |
| `VITE_WS_URL` | `ws://localhost:8443/ws` | WebSocket target used by the Vite dev proxy and frontend |

### Prompt Tuning (`prompts.yaml`)

All agent instructions are externalized to `prompts.yaml`. Edit and restart the backend to change behavior without recompiling:

- `phase_template` — Shared authorization context, rules, and cognitive loop injected into every phase
- `phases.recon` — Reconnaissance phase instructions
- `phases.planner` — Mythos Reasoning Protocol for the Thinking & Consolidation agent
- `phases.swarm` — Base swarm agent instructions (assertive, proof-gated)
- `phases.poc_generator` — PoC generation and evidence formatting
- `swarm_agents` — Per-agent-type override prompts
- `tooling` — Tool recommendations per vulnerability class

---

## How It Works

### 1. Create a Flow
Provide a target URL (e.g., `http://target.example.com:8080`). The scope engine automatically extracts the allowed host and port — requests to any other port are blocked.

### 2. Reconnaissance
The orchestrator maps the attack surface using LLM-guided tool execution (subfinder, httpx, waybackurls, gau, katana) and a headless SPA crawl. All discoveries are routed to the brain via `update_brain`:
- `lead` — interesting endpoint or parameter
- `tech` — detected technology stack
- `defence` — WAF rule, auth wall, or rate limit (avoids the path in future loops)
- `credentials` / `pivot` — triggers an iterative feedback loop to re-recon with auth context

### 3. Hypothesis Generation (Mythos)
Before dispatching the swarm, the Hypothesis Engine generates 8–12 prioritised attack hypotheses using 5-step adversarial reasoning. Hypotheses with priority ≥ 6 map directly to specialist agents.

### 4. Planning (Swarm Construction)
The Thinking & Consolidation agent receives the full brain state, the hypothesis list, the hallucination bin, and the known-defence map. It dispatches ≥ 5 specialists with:
- specific target URL and parameter
- hypothesis and required proof class
- auth context if needed
- WAF bypass payloads if a WAF was fingerprinted

### 5. Specialist Swarm
48 specialists run concurrently through per-agent async queues. Each receives:
- RAG-enriched context from prior scans
- Proven payloads from the cross-session knowledge graph
- Adaptive LLM-generated bypass variants for high-priority targets

### 6. Hallucination Bin & Promotion
When a specialist reports a finding via `update_brain(category='finding')` or `report_findings`:
- The orchestrator evaluates the proof gates (request/response, OOB, browser, timing)
- **Pass** → promoted to `Brain.Findings`, CVSS scored, evidence recorded
- **Fail** → quarantined in `Brain.HallucinationBin` with the failing gate; the planner re-dispatches to acquire missing proof

### 7. Post-Exploitation & Validation
Critical/high findings trigger the Post-Exploit agent. XSS findings are visually confirmed via headless Chrome. OOB callbacks are polled for blind injection confirmation.

### 8. Reporting
AI-generated pentest report with deduplication, CVSS scoring, CWE/OWASP compliance mapping, and optional Burp Suite XML export.

---

## API Endpoints

### Core

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/api/health` | — | Server health check |
| `GET` | `/api/models` | — | Available LLM models |
| `GET/PUT` | `/api/config` | — | Read or update runtime configuration |
| `GET` | `/api/audit` | — | Append-only audit log |
| `GET` | `/ws` | — | WebSocket for real-time event streaming |

### Flows & Findings

| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/api/flows/create` | Operator | Create and start a scan |
| `GET` | `/api/flows` | — | List all flows |
| `GET/POST` | `/api/flows/{id}` | — | Flow detail, pause, resume, cancel |
| `GET` | `/api/findings` | — | All findings across flows |
| `GET` | `/api/findings/remediation` | — | Remediation status list |
| `GET` | `/api/findings/stats` | — | Severity counts and trend data |
| `GET` | `/api/findings/search` | — | Full-text finding search |
| `GET` | `/api/findings/export` | — | Export findings (JSON / Burp XML) |

### Remediation

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET/POST` | `/api/remediation/items` | — | Remediation item list and creation |
| `GET/PUT/DELETE` | `/api/remediation/items/{id}` | — | Individual remediation item |
| `GET` | `/api/remediation/metrics` | — | Remediation completion metrics |
| `POST` | `/api/remediation/promote` | — | Promote findings to remediation |

### Intelligence & Posture

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/api/posture` | — | Current security posture score |
| `GET` | `/api/posture/history` | — | Posture score history |
| `GET` | `/api/threatintel/attck` | — | MITRE ATT&CK technique mapping |
| `GET` | `/api/threatintel/chains` | — | Attack chain analysis |
| `GET` | `/api/threatintel/risk` | — | Risk prioritization |
| `POST` | `/api/threatintel/enrich` | — | Enrich CVEs with threat context |
| `GET` | `/api/knowledge/graph` | — | Cross-scan knowledge graph nodes and edges |
| `GET` | `/api/assets` | — | Discovered asset inventory |

### Scheduling & Automation

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET/POST` | `/api/schedules` | Operator | Scheduled scan list and creation |
| `GET/PUT/DELETE` | `/api/schedules/{id}` | Operator | Individual scheduled scan |
| `GET/POST` | `/api/schedule-plans` | — | Schedule plan list and creation |
| `GET/PUT/DELETE` | `/api/schedule-plans/{id}` | — | Individual schedule plan |
| `POST` | `/api/cicd/trigger` | — | CI/CD webhook scan trigger |

### Profiles & Reporting

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET/POST` | `/api/profiles` | — | Scan profile template list and creation |
| `GET/PUT/DELETE` | `/api/profiles/{id}` | — | Individual scan profile |
| `POST` | `/api/reports/generate` | — | Generate AI pentest report |
| `GET` | `/api/reports/available` | — | List available generated reports |
| `POST` | `/api/mutate` | Operator | Stateless LLM payload mutation |

### Notifications & Monitoring

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET/POST` | `/api/notify/channels` | — | Notification channel list and creation |
| `GET/PUT/DELETE` | `/api/notify/channels/{id}` | — | Individual channel (Slack, webhook, email) |
| `GET` | `/api/notify/events` | — | Notification event routing rules |
| `POST` | `/api/notifications/test` | — | Send test notification |
| `GET/POST` | `/api/monitors` | — | Continuous monitor list and creation |
| `GET/PUT/DELETE` | `/api/monitors/{id}` | — | Individual monitor |
| `GET/POST` | `/api/alerting/channels` | — | Alerting channel configuration |
| `GET/PUT/DELETE` | `/api/alerting/channels/{id}` | — | Individual alerting channel |
| `POST` | `/api/alerting/test` | — | Test alerting channel |

### Integrations & Auth

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/api/auth/login` | — | Authentication |
| `GET/POST` | `/api/auth/keys` | — | API key management |
| `GET/POST` | `/api/users` | Admin | User management |
| `POST` | `/api/integrations/ticket` | — | Create ticket from finding |
| `POST` | `/api/webhooks/github` | — | GitHub App webhook receiver |
| `GET/PUT` | `/api/webhooks/github/config` | — | GitHub App configuration |
| `POST` | `/api/devsecops/scan` | — | DevSecOps pipeline scan |
| `GET` | `/api/system/migrations` | — | Database migration status |

### AI Copilot

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET/POST` | `/api/copilot/sessions` | — | Copilot chat session list and creation |
| `GET/DELETE` | `/api/copilot/sessions/{id}` | — | Individual copilot session |
| `POST` | `/api/copilot/chat` | — | Send message to AI copilot |
| `GET` | `/api/copilot/suggestions` | — | Contextual remediation suggestions |
| `GET` | `/api/copilot/available` | — | Copilot availability check |

### APTS (Autonomous Pentest System)

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/api/apts/status` | — | Autonomous system status |
| `GET` | `/api/apts/autonomy-levels` | — | Available autonomy level definitions |
| `GET` | `/api/apts/coverage` | — | Attack surface coverage metrics |
| `GET` | `/api/apts/provenance` | — | Finding provenance and chain-of-evidence |
| `POST` | `/api/apts/emergency-stop` | Operator | Emergency halt all active agents |

---

## Frontend — Mirage Design System v3

The dashboard is built with React 18, Vite 5, Tailwind CSS 3, and Framer Motion using a custom **Liquid Glass** aesthetic — deep dark backgrounds, frosted glass surfaces, aurora gradients, and cyan accent glows.

### Design Tokens

| Token | Value | Purpose |
|---|---|---|
| `accent-cyan` | `#22d3ee` | Primary interactive accent |
| `accent-purple` | `#a78bfa` | Secondary / hypothesis |
| `accent-green` | `#4ade80` | Success / safe |
| `severity-critical` | `#ff4757` | Critical findings |
| `severity-high` | `#ff7f50` | High findings |
| `severity-medium` | `#eccc68` | Medium findings |
| `severity-low` | `#2ed573` | Low findings |

### Utility Classes

| Class | Description |
|---|---|
| `.lg-surface` | Frosted glass card with border and shadow |
| `.lg-surface-hero` | Larger elevated hero card |
| `.lg-btn` | Glass button with shine-sweep hover animation |
| `.lg-btn-ghost` | Ghost/outline variant |
| `.lg-pill` | Compact pill chip |
| `.lg-gradient-text` | Aurora gradient text |
| `.badge-severity` | Severity badge (`.badge-critical`, `.badge-high`, etc.) |
| `.skeleton` | Shimmer loading placeholder |
| `.spinner` | Spinning loader |
| `.terminal-block` | Monospace terminal output block |

### Key UI Features

- **Command palette** (`⌘K` / `Ctrl+K`) — keyboard-driven page navigation
- **Global toast system** — `ToastProvider` context with stacked animated toasts (`useToast()` hook)
- **Mobile sidebar drawer** — hamburger toggle on small screens with slide-in animation and backdrop
- **Paginated findings grid** — Dashboard findings paginate at 12/page with per-severity filter
- **Asset search & pagination** — Assets page search/filter bar with 10/page pagination
- **Copy-to-clipboard** — Terminal log copy in FlowDetail, webhook URL copy in Settings
- **Unified empty states** — `EmptyState` component across all list/grid views
- **Reusable modal** — `Modal` component with Escape-close, scroll lock, size variants
- **404 page** — On-brand Not Found page with quick-nav grid
- **Global error boundary** — Wraps the entire app tree with a polished fallback UI

---

## Code Quality

### Go (`golangci-lint` v2)

Static analysis is configured in `.golangci.yml` using golangci-lint v2 with the `standard` default linter set plus:

- `copyloopvar` — detects redundant loop-variable capture patterns (Go 1.22+ semantics)
- `misspell` — spelling corrections in comments and strings
- `bodyclose` — ensures HTTP response bodies are closed
- `noctx` — enforces context propagation on HTTP requests

Run locally:
```bash
golangci-lint run ./...
```

### Frontend (ESLint v10)

ESLint is configured in `frontend/eslint.config.js` using the flat config format with `eslint-plugin-react` and `eslint-plugin-react-hooks`.

```bash
cd frontend && npm run lint
```

---

## License

MIT License
