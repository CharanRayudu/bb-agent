# Mirage (bb-agent)

Mirage is an autonomous, LLM-driven penetration testing agent. It consists of a Go backend orchestrator, an isolated Docker sandbox for tool execution, and a React frontend for managing and viewing scans in real-time.

## Architecture & Features

- **Autonomous Agent Loop**: Uses LLMs (OpenAI/Codex) in a ReAct loop to plan, execute tools, and analyze results.
- **Isolated Execution**: Operational tools and network scans are executed within a dedicated Docker sandbox container (`mirage-sandbox`).
- **Tool Integration**: The agent can autonomously run terminal commands, search Nuclei templates, execute browser scripts via Playwright, and report structured findings.
- **Historical Context**: Stores scan results and memory in a PostgreSQL database to maintain context across multiple scans of the same target.
- **Real-time UI**: A React/Vite frontend that streams agent thoughts, tool outputs, terminal logs, and findings via WebSockets.

## Project Structure

- `cmd/mirage/`: Go backend application entry point.
- `internal/`: Core backend logic including:
  - `agent/`: Orchestrator and ReAct loop implementation.
  - `database/`: Database queries and schema models.
  - `docker/`: Sandbox container management.
  - `llm/`: OpenAI and Codex provider integrations.
  - `server/`: HTTP API and WebSocket handlers.
- `frontend/`: React application (Vite, TailwindCSS).
- `docker-compose.yml`: Defines the Postgres DB, backend, frontend, and persistent sandbox container.

## Prerequisites

- Docker and Docker Compose
- Node.js & npm (if running the frontend natively)
- Go (if running the backend natively)
- Valid OpenAI API Key or Codex CLI authentication

## Getting Started

1. **Clone & Configure**
   ```bash
   git clone https://github.com/your-org/bb-agent.git
   cd bb-agent
   cp .env.example .env
   ```
   *Note: Add your `OPENAI_API_KEY` to the `.env` file if not using Codex CLI auth.*

2. **Launch Infrastructure (Windows)**
   We provide PowerShell scripts for easy environment management:
   - `./start.ps1` : Cleans up ports, runs database migrations, builds the containers, and starts the services.
   - `./stop.ps1` : Gracefully shuts down containers and kills orphaned processes.

3. **Launch Infrastructure (Manual/Linux/macOS)**
   ```bash
   docker-compose up -d --build
   ```
   Start the frontend natively if desired:
   ```bash
   cd frontend
   npm install
   npm run dev
   ```

4. **Access the Interface**
   Open your browser to `http://localhost:3000` to access the Mirage Dashboard.

## License

MIT License
