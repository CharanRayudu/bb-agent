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
- **Scheduling** — Recurring scans with cron expressions
- **Webhooks** — HMAC-SHA256 signed webhook notifications on findings
- **Audit Log** — Append-only event log for all user actions
- **Burp Suite Export** — Findings exportable as Burp XML
- **CI/CD Integration** — Webhook trigger endpoint for pipeline-initiated scans
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
│   │   ├── wafevasion/      # WAF bypass with LLM-driven mutation
│   │   └── ...              # + 42 more specialists
│   ├── knowledge/           # Knowledge graph (in-memory + Neo4j backend)
│   ├── config/              # YAML prompt configuration loader
│   ├── database/            # PostgreSQL queries and schema migrations
│   ├── llm/                 # LLM provider integrations (OpenAI, Codex)
│   ├── models/              # Data models (Flow, Task, SubTask, Action, CausalGraph)
│   ├── pipeline/            # 8-phase state machine with lifecycle management
│   ├── queue/               # Per-specialist async queues with backpressure
│   ├── server/              # HTTP REST API, WebSocket, and extended routes
│   └── tools/               # Tool registry (execute_command, update_brain, OOB, browser, etc.)
├── frontend/                # React + Vite dashboard
│   └── src/
│       ├── pages/           # Dashboard, FlowDetail, NewTask, Settings, KnowledgeGraph
│       └── components/      # HypothesisTracker, FlowLedgerPanel, ScreenshotGallery, TrendChart
├── prompts.yaml             # All agent prompts — edit to tune behavior without rebuilding
├── docker-compose.yml       # PostgreSQL, backend, frontend, sandbox, Neo4j
├── start.ps1 / start.sh     # Launch scripts
└── stop.ps1 / stop.sh       # Shutdown scripts
```

---

## Prerequisites

- **Docker** and **Docker Compose**
- **Go 1.21+** (for native backend development)
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

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/health` | Server health check |
| `GET` | `/api/models` | Available LLM models |
| `POST` | `/api/flows/create` | Create and start a scan |
| `GET` | `/api/flows` | List all flows |
| `GET/POST` | `/api/flows/{id}` | Flow detail, pause, resume, cancel |
| `GET` | `/api/findings` | All findings across flows |
| `GET` | `/api/findings/remediation` | Remediation status tracking |
| `GET` | `/api/knowledge/graph` | Knowledge graph nodes and edges |
| `GET/PUT` | `/api/config` | Read or update runtime configuration |
| `GET` | `/api/schedules` | Scheduled scan management |
| `POST` | `/api/cicd/trigger` | CI/CD webhook scan trigger |
| `POST` | `/api/mutate` | Stateless LLM payload mutation |
| `GET` | `/api/auth/login` | Authentication |
| `GET` | `/api/audit` | Audit log |
| `GET` | `/ws` | WebSocket for real-time event streaming |

---

## License

MIT License
