# Mirage

**Autonomous LLM-Driven Penetration Testing Agent**

Mirage is a black-box penetration testing platform powered by large language models. It autonomously plans, executes, and validates vulnerability scans against live web targets — combining a multi-phase pipeline, 32 specialist agents, headless browser validation, and a real-time React dashboard.

---

## Architecture

```
┌────────────────────────────────────────────────────────────────────┐
│                      React + Vite Frontend                        │
│              (Real-time Dashboard, WebSocket Stream)               │
└──────────────────────────┬─────────────────────────────────────────┘
                           │ WebSocket + REST API
┌──────────────────────────▼─────────────────────────────────────────┐
│                        Go Backend                                  │
│                                                                    │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐ │
│  │ Orchestrator │──│   Pipeline   │──│   32 Specialist Agents   │ │
│  │  (ReAct Loop)│  │ (8 Phases)   │  │  (XSS, SQLi, SSRF, ...) │ │
│  └──────────────┘  └──────────────┘  └──────────────────────────┘ │
│                                                                    │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐ │
│  │ Schema Valid. │  │ Queue Manager│  │  Headless Browser (CDP)  │ │
│  │ (LLM Output) │  │ (Per-Agent)  │  │  (Visual Validation)     │ │
│  └──────────────┘  └──────────────┘  └──────────────────────────┘ │
└──────────────────────────┬─────────────────────────────────────────┘
                           │
        ┌──────────────────┼──────────────────┐
        ▼                  ▼                  ▼
  ┌───────────┐    ┌──────────────┐    ┌────────────┐
  │ PostgreSQL │    │ Docker       │    │ LLM API    │
  │ (State)    │    │ Sandbox      │    │ (OpenAI)   │
  └───────────┘    └──────────────┘    └────────────┘
```

## Key Features

- **Multi-Phase Pipeline** — 8-phase state machine (Recon → Discovery → Strategy → Exploitation → Validation → Reporting → Complete) with iterative feedback loops
- **32 Specialist Agents** — Dedicated agents for XSS, SQLi, SSRF, IDOR, LFI, RCE, XXE, CSTI, JWT, File Upload, API Security, Business Logic, WAF Evasion, and more
- **Schema-Validated LLM Outputs** — Structured JSON validation at phase boundaries prevents garbage-in-garbage-out across the pipeline
- **Headless Browser Validation** — Chrome DevTools Protocol integration for visual XSS confirmation, SPA crawling, and DOM analysis
- **Isolated Sandbox Execution** — Tools and scans run inside a dedicated Docker container
- **Self-Healing Resilience** — Automatic tool error recovery with timeout injection, rate limiting, and concurrency adjustment
- **Cross-Flow Memory** — PostgreSQL-backed intelligence that persists across scans of the same target
- **Real-Time UI** — React dashboard streaming agent thoughts, tool calls, findings, and pipeline state via WebSocket
- **Configurable Prompts** — YAML-based prompt configuration (`prompts.yaml`) for tuning agent behavior without code changes

## Project Structure

```
bb-agent/
├── cmd/mirage/              # Application entry point
├── internal/
│   ├── agent/               # Core orchestrator and agent infrastructure
│   │   ├── base/            # Shared types (Finding, Specialist interface, browser primitives)
│   │   ├── schema/          # LLM output schema validation (JSON extraction, typed parsing)
│   │   ├── orchestrator.go  # Main ReAct loop, pipeline phases, iterative feedback
│   │   ├── conductor.go     # Agent lifecycle management and timeout enforcement
│   │   ├── context.go       # Tech stack inference and context-aware prompting
│   │   ├── memory.go        # Cross-flow target intelligence (Thompson Sampling)
│   │   ├── resilience.go    # Self-healing tool error recovery
│   │   ├── dedup.go         # Advanced finding deduplication
│   │   └── ...
│   ├── agents/              # 32 vulnerability specialist agents
│   │   ├── xss/             # XSS (reflected, DOM, stored, WAF bypass)
│   │   ├── sqli/            # SQL Injection (error, blind, union, OOB)
│   │   ├── ssrf/            # SSRF (cloud metadata, internal services, OOB)
│   │   ├── idor/            # Insecure Direct Object References
│   │   ├── businesslogic/   # Business logic abuse
│   │   ├── wafevasion/      # WAF bypass strategies
│   │   ├── consolidation/   # Thinking & Consolidation (brain)
│   │   ├── validation/      # Agentic multi-strategy validation
│   │   ├── reporting/       # AI-powered report generation
│   │   └── ...              # + 23 more specialists
│   ├── config/              # YAML prompt configuration loader
│   ├── database/            # PostgreSQL queries and schema
│   ├── docker/              # Sandbox container management
│   ├── llm/                 # LLM provider integrations (OpenAI, Codex)
│   ├── models/              # Data models (Flow, Task, SubTask, Action)
│   ├── pipeline/            # 8-phase state machine with lifecycle management
│   ├── queue/               # Per-specialist async queues with backpressure
│   ├── server/              # HTTP API and WebSocket handlers
│   └── tools/               # Tool registry (execute_command, nuclei, browser, etc.)
├── frontend/                # React + Vite dashboard
├── prompts.yaml             # Configurable agent prompts
├── docker-compose.yml       # PostgreSQL, backend, frontend, sandbox
├── start.ps1 / start.sh     # Launch scripts
└── stop.ps1 / stop.sh       # Shutdown scripts
```

## Prerequisites

- **Docker** and **Docker Compose**
- **Go 1.21+** (if running the backend natively)
- **Node.js 18+** and **npm** (if running the frontend natively)
- **OpenAI API Key** or Codex CLI authentication

## Getting Started

### 1. Clone & Configure

```bash
git clone https://github.com/your-org/bb-agent.git
cd bb-agent
cp .env.example .env
# Add your OPENAI_API_KEY to the .env file
```

### 2. Launch (Windows)

```powershell
./start.ps1    # Cleans ports, runs migrations, builds containers, starts services
./stop.ps1     # Graceful shutdown
```

### 3. Launch (Linux/macOS)

```bash
./start.sh     # Same as above for Unix systems
# Or manually:
docker-compose up -d --build
```

### 4. Access the Dashboard

Open `http://localhost:3000` in your browser.

## How It Works

1. **Create a Flow** — Provide a target URL (e.g., `https://target.example.com`)
2. **Recon Phase** — The orchestrator maps the attack surface using LLM-guided reconnaissance + headless SPA crawling
3. **Planning Phase** — The Thinking & Consolidation agent analyzes recon leads and dispatches specialist agents via schema-validated output
4. **Specialist Swarm** — 32 specialist agents run concurrently through per-agent queues, each hunting for their specific vulnerability class
5. **Validation** — Findings are visually confirmed via headless browser, OOB callbacks, and multi-strategy validation
6. **Reporting** — AI-generated pentest report with deduplication, severity classification, and PoC evidence

## License

MIT License
