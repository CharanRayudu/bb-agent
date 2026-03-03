# 🛡️ Mirage — Enterprise Autonomous Penetration Testing Agent

Mirage is a fully autonomous, AI-driven penetration testing system. Unlike simple LLM wrappers that naively run tools and hallucinate, Mirage is built on a **Cognitive Architecture** designed to mimic a human Senior Penetration Tester. It autonomously plans, dynamically exploits, memorizes past findings, and visually interacts with Single Page Applications using native browser orchestration.

## ✨ Core Capabilities

- 🤖 **Conscious Testing Philosophy**: Mirage doesn't just run scans; it consciously hypothesizes vulnerabilities based on reconnaissance output and dynamically chains exploit tools to prove them.
- �️ **Native Headless Browser Orchestration**: Integrated Node.js & Playwright allow the AI to bypass SPA rendering walls, interact with complex login portals, and natively extract DOM data.
- 🧠 **Neural Scratchpad Memory**: Mirage features a persistent Scratchpad (`update_memory` tool) and Historical Context extraction. It will never "forget" an open port mid-scan, solving the LLM Context Window Treadmill problem.
- 🛡️ **Air-Gapped Sandbox**: All tools (from Nmap to Metasploit) execute inside a strictly isolated Kali Linux Docker container.
- 🧬 **Autonomous Tooling**: If Mirage discovers it lacks a specific exploit script, it has root permissions to use `apt-get` or `git clone` to seamlessly install the missing weapon mid-flight.

---

## 🏗️ Architecture

```mermaid
graph LR
    A[Frontend (React + Vite)] -->|WebSocket & REST| B(Backend Orchestrator)
    B -->|SQL| C[(PostgreSQL + pgvector)]
    B -->|Docker API| D[Kali Linux Sandbox]
    D -.->|Native Playwright| E(SPA / Target)
    D -.->|CLI Scanners| E
```

---

## 🚀 Quick Start (Docker Compose)

The easiest way to launch Mirage is via the unified Docker Compose stack, which provisions the Database, the Backend Orchestrator, and builds the Kali Linux Sandbox with all required Node.js/Playwright binaries.

### Prerequisites
- Docker & Docker Compose
- An OpenAI API Key (or compatible LLM endpoint)

### Installation

1. **Clone the Repository**
   ```bash
   git clone https://github.com/your-org/bb-agent.git
   cd bb-agent
   ```

2. **Configure Environment**
   ```bash
   cp .env.example .env
   # Open .env and insert your OPENAI_API_KEY
   ```

3. **Build & Boot the Stack**
   Windows users can run the native startup script:
   ```powershell
   ./start.ps1
   ```
   Or manually via Docker Compose:
   ```bash
   docker-compose up -d --build
   ```

4. **Access the Dashboard**
   Navigate to `http://localhost:3000` to interact with the AI and launch pentests.

---

## 📁 Project Structure

```
bb-agent/
├── cmd/mirage/main.go           # Go backend entry point
├── internal/
│   ├── agent/orchestrator.go    # AI agent ReAct loop & System Constraints
│   ├── database/queries.go      # PostgreSQL + Neural Memory extraction
│   ├── docker/sandbox.go        # Isolated Docker exec controller
│   └── tools/registry.go        # Tool Registry (think, execute, execute_browser_script)
├── frontend/                    # Glassmorphic React + Vite dashboard
├── build/
│   ├── backend/Dockerfile       # Go container
│   └── tools/Dockerfile         # Kali pentest sandbox (Node, Playwright, Nmap, etc.)
└── docker-compose.yml
```

---

## 🔧 Default Sandbox Arsenal

The `mirage-tools` Kali sandbox comes pre-loaded with an enterprise toolkit. If a tool is missing, the AI is instructed to install it autonomously.

| Category | Available Weapons |
|----------|-------|
| **Reconnaissance** | Nmap, Masscan, Amass, Subfinder, Httpx |
| **Web Enumeration** | Nikto, Gobuster, SQLMap, Wfuzz, Nuclei |
| **GUI Bypassing** | Playwright (Node.js DOM Execution) |
| **Exploitation** | Metasploit-Framework, Searchsploit |
| **Network & Utilities** | Netcat, Socat, Curl, Wget, Python3, Git |

---

## 📄 License
MIT License
