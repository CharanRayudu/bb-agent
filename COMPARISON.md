# Comparison: Mirage vs ProjectDiscovery Neo vs LuaN1aoAgent

This document compares **Mirage** (our current project) with two prominent AI security systems: **ProjectDiscovery Neo** (an enterprise-grade AI security engineer) and **LuaN1aoAgent** (an open-source cognitive-driven AI hacker).

---

## 1. What Mirage Has (Current State)
Based on the `README.md` and codebase exploration, **Mirage** is an autonomous LLM-driven black-box penetration testing agent. Its core features include:
*   **Multi-Phase Pipeline:** 8-phase state machine (Recon → Discovery → Strategy → Exploitation → Validation → Reporting → Complete).
*   **32 Specialist Agents:** Dedicated agents for specific vulnerabilities like XSS, SQLi, SSRF, IDOR, LFI, RCE, etc.
*   **Schema-Validated LLM Outputs:** Ensures structured JSON validation at phase boundaries.
*   **Headless Browser Validation:** Uses Chrome DevTools Protocol for visual XSS confirmation, SPA crawling, etc.
*   **Isolated Sandbox Execution:** Tools and scans run inside a dedicated Docker container.
*   **Self-Healing Resilience:** Automatic tool error recovery (timeout injection, rate limiting, concurrency adjustment).
*   **Cross-Flow Memory:** PostgreSQL-backed memory that persists across scans of the same target (using Thompson Sampling).
*   **Real-Time UI:** React dashboard streaming agent thoughts, tool calls, findings, and pipeline state via WebSocket.

---

## 2. What Neo Has (That Mirage Lacks)
Based on public information and official documentation snippets, **Neo** is a cloud-based "AI Security Engineer" designed to fit directly into day-to-day security engineering workflows. It replaces the patchwork of scanners and manual pentests with a single system that handles security testing end-to-end.

**Key Features Neo has over Mirage:**
1.  **Continuous PR to Production Integration (CI/CD):**
    *   Integrates directly into GitHub/GitLab and triggers **secure design reviews on every new Pull Request (PR)**.
    *   Performs continuous pentesting from PR to production and automatic retesting when fixes ship.
2.  **Workflow Integration (Ticketing & Remediation):**
    *   Automatically creates and triages findings directly in ticketing systems like **Linear or Jira**.
    *   Actively **drafts remediation plans** with actionable fixes for developers.
3.  **White-Box / Grey-Box Capabilities (AI Code Reviews & Threat Modeling):**
    *   Acts as an AI code reviewer that pairs code review with runtime testing (DAST) to validate if a bug found in code is actually exploitable in the deployed app.
    *   Performs **Threat Modeling** by understanding system architecture and business logic.
4.  **Proof, Not Alerts (Extensive Evidence Generation):**
    *   Validates every finding with **concrete evidence, payloads, execution traces, and step-by-step reproduction scripts**.
5.  **Compounding Context (Continuous Learning Framework):**
    *   Continuously learns an organization's specific code, architecture, naming conventions, payments API, auth flows, and accepted risks over time. Every assessment is faster and more targeted.
6.  **Enterprise Role-Based Access Control (RBAC) & Single Sign-On (SSO):**
    *   Supports SAML/OIDC SSO, RBAC with custom permission policies, and comprehensive audit trails.

---

## 3. What LuaN1aoAgent Has (That Mirage Lacks)
**LuaN1aoAgent (鸾鸟)** is a next-generation open-source autonomous penetration testing agent that focuses heavily on cognitive reasoning and graph-based dynamic planning, rather than a rigid state machine.

**Key Features LuaN1aoAgent has over Mirage:**
1.  **P-E-R (Planner-Executor-Reflector) Collaboration Framework:**
    *   Instead of an 8-phase linear pipeline, LuaN1ao decouples thinking into three independent cognitive roles.
    *   **Planner:** Dynamic planning based on global graph awareness.
    *   **Executor:** Focuses on tool invocation and context compression.
    *   **Reflector:** Failure pattern analysis (L1-L4) to prevent repeated errors and judge termination.
2.  **Causal Graph Reasoning:**
    *   Constructs explicit causal graphs (`Evidence -> Hypothesis -> Vulnerability -> Exploit`) to drive decisions.
    *   Mandatory evidence validation prevents LLM hallucinations (rejecting blind guessing).
    *   Each causal edge has a confidence score.
3.  **Plan-on-Graph (PoG) Dynamic Task Planning:**
    *   Models penetration testing plans as dynamically evolving **Directed Acyclic Graphs (DAGs)** rather than static task lists or strict state machines.
    *   The Planner outputs structured graph editing instructions (`ADD_NODE`, `UPDATE_NODE`, `DEPRECATE_NODE`) instead of natural language.
    *   Automatically identifies and **parallelizes** independent tasks based on DAG topology.
4.  **Model Context Protocol (MCP) Integration:**
    *   Uses unified scheduling of security tools via MCP, standardizing tool invocation.

---

## 4. How to Make Mirage More Like Neo & LuaN1ao

To evolve Mirage into a hybrid of an Enterprise AI Security Engineer (Neo) and a Cognitive Graph Hacker (LuaN1ao), we should implement the following high-level epics:

### Epic A: Shift to Graph-Based Cognitive Reasoning (Inspired by LuaN1ao)
*   **Action:** Replace or augment the strict 8-phase state machine with a **Directed Acyclic Graph (DAG) Task Planner**. Allow the orchestrator to dynamically branch, parallelize, and prune tasks as new evidence is discovered.
*   **Action:** Implement **Causal Graph Reasoning**. Force specialist agents to map findings into an `Evidence -> Hypothesis -> Vulnerability -> Exploit` chain with confidence scores to eliminate hallucinations.
*   **Action:** Adopt the **P-E-R framework**. Introduce a dedicated "Reflector" agent that analyzes failures across all specialist agents to prevent repeating the same mistakes during a scan.

### Epic B: Deep Workflow & Source Code Integration (Inspired by Neo)
*   **Action:** Add GitHub/GitLab app integrations. Allow Mirage to trigger on **Pull Requests**, ingest source code (White-box/SAST), and correlate code findings with its dynamic testing (DAST) results.
*   **Action:** Build two-way sync integrations with **Jira and Linear**. Automatically create tickets for validated findings and update them based on automated regression retesting.
*   **Action:** Add an automated **Remediation Phase** where Mirage drafts specific code patches or configuration changes to fix the validated vulnerabilities.

### Epic C: Threat Modeling & Compounding Context (Inspired by Neo)
*   **Action:** Expand the `Cross-Flow Memory` to not just remember target endpoints, but explicitly map "Auth Flows", "Payment APIs", and "Business Logic".
*   **Action:** Allow users to upload architectural diagrams and API schemas (OpenAPI/Swagger). Create a **Threat Modeling Agent** that analyzes these documents to guide the Recon phase more intelligently.

### Epic D: Enterprise Features & Evidence Collection (Inspired by Neo)
*   **Action:** Enhance the `Reporting` phase to generate concrete execution traces and step-by-step reproduction scripts alongside standard payloads.
*   **Action:** Implement user authentication (OIDC/SAML), Role-Based Access Control (RBAC), and audit logging in the Go backend.
