# Implementing Neo & LuaN1ao Features in Mirage

This guide details the technical steps required to transform **Mirage** from an 8-phase state machine into a state-of-the-art Cognitive Graph Hacker and Enterprise AI Security Engineer.

---

## 1. Migrating to a P-E-R (Planner-Executor-Reflector) Architecture
Currently, `internal/agent/orchestrator.go` acts as a monolithic ReAct loop that pushes data through `internal/pipeline/phases.go`.

**Implementation Steps:**
1.  **Refactor the Orchestrator:** Break down the orchestrator into three distinct Go routines or microservices running concurrently, communicating via `internal/agent/eventbus.go`.
2.  **The Planner (The Brain):** Modify `internal/agent/strategist.go` to become the Planner. It should listen to the event bus for new findings. Instead of outputting natural language tasks, define a strict schema in `internal/agent/schema/` that outputs **Graph Operations** (`ADD_NODE`, `UPDATE_NODE`, `DEPRECATE_NODE`).
3.  **The Executor (The Muscle):** The current 32 agents in `internal/agents/` should be simplified. They become "Executors." The Planner passes a specific graph node (e.g., "Run SQLmap on ID=5") to the Executor queue. The Executor runs the tool and returns raw stdout/stderr to the event bus.
4.  **The Reflector (The Critic):** Expand `internal/agent/reflector.go` to analyze Executor outputs. If a tool fails (e.g., WAF blocked), the Reflector classifies the failure (L1-L4) and sends a `FAILURE_EVENT` back to the Planner, forcing the Planner to mutate the task graph (e.g., `ADD_NODE: WAF Evasion`).

---

## 2. Implementing Plan-on-Graph (PoG) & Causal Graph Reasoning
Currently, findings are likely stored in a flat relational table in PostgreSQL.

**Implementation Steps:**
1.  **Database Schema Update:** Update `internal/database/` migrations to support Directed Acyclic Graphs (DAGs). You can use recursive CTEs in PostgreSQL or migrate to a Graph DB (like Neo4j) for complex relationships.
2.  **Causal Reasoning Engine:** Expand `internal/agent/attack_graph.go` and `internal/agent/causal_test.go`. Ensure every entry has four distinct node types: `Evidence -> Hypothesis -> Vulnerability -> Exploit`.
3.  **Confidence Scoring:** Add a `Confidence float32` field to the findings struct in `internal/agent/base/`. When the Reflector evaluates an Executor's output, it updates the confidence score. If `Confidence > 0.8`, the Planner promotes a Hypothesis to a Vulnerability.
4.  **Graph Visualization:** Update the React Frontend (`frontend/src/`) using a library like `react-flow` to visualize the Plan-on-Graph in real-time, matching LuaN1ao's visual feedback.

---

## 3. Integrating Model Context Protocol (MCP) for 100+ Tools
Currently, Mirage uses custom wrappers for tools in `internal/tools/`.

**Implementation Steps:**
1.  **Adopt the MCP Standard:** Create an MCP Client inside `internal/tools/registry.go`.
2.  **Tool Servers:** Instead of baking tools into the Mirage Go binary, run security tools (Nmap, Nuclei, SQLmap, Metasploit) as standalone **MCP Servers** inside the Docker Sandbox (`internal/docker/`).
3.  **Dynamic Discovery:** The MCP Client will dynamically ask the MCP Servers what tools are available and what their JSON schemas are. This allows you to add tools by simply dropping an MCP Server into the Docker container without recompiling Mirage.

---

## 4. Enterprise CI/CD & Ticketing Integration (Neo Features)
To make Mirage an "Engineer" rather than a scanner, it needs to hook into the development lifecycle.

**Implementation Steps:**
1.  **Webhook Receivers:** Add HTTP handlers in `internal/server/` to listen for GitHub/GitLab Webhooks (e.g., `pull_request.opened`).
2.  **SAST & DAST Correlation:** When a PR is opened, the orchestrator pulls the source code. Pass the diff to the Planner. The Planner creates a temporary task graph specifically to run SAST tools on the diff, and then dynamically tests the deployed staging environment (DAST) based on the SAST findings.
3.  **Ticketing APIs:** Create a new `internal/integrations/` package with Jira and Linear API clients. When the `Reflector` confirms a vulnerability with > 0.9 confidence, it automatically opens a Jira ticket.
4.  **Remediation Drafting:** Add a `internal/agents/remediation/` specialist. This agent takes the Causal Graph (Evidence + Exploit) and the source code diff, and prompts an LLM to generate a `git patch` fixing the vulnerability, which is posted as a comment on the Jira ticket or GitHub PR.

---

## 5. Enterprise Security & RBAC
**Implementation Steps:**
1.  **Authentication Middleware:** Add OIDC/SAML middleware to `internal/server/` using a library like `coreos/go-oidc`.
2.  **RBAC Models:** Update `internal/database/` to include `Users`, `Roles`, and `Permissions`. Ensure endpoints check if a user has permission to start a scan on a specific target or view a specific causal graph.
3.  **Audit Logging:** Implement a ledger (expanding `internal/agent/ledger.go`) that logs every user action and every LLM API call for enterprise compliance.
