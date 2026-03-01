# 🛡️ PentAGI — Autonomous Penetration Testing Agent

A fully autonomous AI-powered penetration testing system inspired by [PentAGI](https://github.com/vxcontrol/pentagi). The AI agent autonomously plans, executes, and reports on security assessments using professional penetration testing tools.

## ✨ Features

- 🤖 **Fully Autonomous** — AI agent plans and executes pentest steps without manual intervention
- 🛡️ **Sandboxed Execution** — All security tools run inside isolated Docker containers
- 🔧 **20+ Security Tools** — nmap, sqlmap, nikto, nuclei, metasploit, gobuster, and more
- 📊 **Live Dashboard** — Real-time WebSocket streaming of agent actions and results
- 🧠 **Smart Agent Loop** — ReAct-style orchestrator with tool calling, reasoning, and reporting
- 📝 **Structured Reports** — Automated vulnerability reporting with severity ratings
- 💾 **Persistent Storage** — PostgreSQL with pgvector for memory and vector search

## 🏗️ Architecture

```
Frontend (React + Vite)  →  Backend API (Go)  →  Docker Sandbox (Kali Linux)
        ↕ WebSocket              ↕ SQL                  ↕ Docker SDK
                          PostgreSQL + pgvector
```

## 🚀 Quick Start

### Prerequisites
- Go 1.22+
- Node.js 20+
- Docker
- PostgreSQL (or use Docker Compose)

### Option 1: Docker Compose (Recommended)

```bash
# Clone and configure
cp .env.example .env
# Edit .env and set your OPENAI_API_KEY

# Build the security tools image
docker build -t pentagi-tools:latest -f build/tools/Dockerfile .

# Start everything
docker-compose up --build
```

Open http://localhost:3000

### Option 2: Local Development

```bash
# Backend
go mod download
cp .env.example .env
# Edit .env with your API key
# Source env vars, then:
go run cmd/pentagi/main.go

# Frontend (separate terminal)
cd frontend
npm install
npm run dev
```

## 📁 Project Structure

```
bb-agent/
├── cmd/pentagi/main.go          # Entry point
├── internal/
│   ├── agent/orchestrator.go    # AI agent ReAct loop
│   ├── config/config.go         # Environment config
│   ├── database/                # PostgreSQL + pgvector
│   ├── docker/sandbox.go        # Sandboxed tool execution
│   ├── llm/                     # LLM provider abstraction
│   │   ├── provider.go          # Interface
│   │   └── openai.go            # OpenAI implementation
│   ├── models/models.go         # Domain models
│   ├── server/server.go         # HTTP/WS server
│   └── tools/registry.go        # Agent tool definitions
├── frontend/                    # React + Vite dashboard
├── build/
│   ├── backend/Dockerfile       # Backend container
│   └── tools/Dockerfile         # Kali security tools
├── docker-compose.yml
└── .env.example
```

## 🔧 Security Tools Available

| Category | Tools |
|----------|-------|
| Reconnaissance | nmap, masscan, amass, subfinder, httpx |
| Web Testing | nikto, gobuster, sqlmap, wfuzz, nuclei |
| Exploitation | metasploit-framework, searchsploit |
| Network | netcat, socat, curl, wget, dig, whois |
| Scripting | python3, bash, jq, git |

## 📄 License

MIT
