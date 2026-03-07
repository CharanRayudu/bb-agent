# Comparison: Mirage vs ProjectDiscovery Neo

## What Mirage Has (Current State)
Based on the `README.md` and codebase exploration, **Mirage** is an autonomous LLM-driven black-box penetration testing agent. Its core features include:
1.  **Multi-Phase Pipeline:** 8-phase state machine (Recon → Discovery → Strategy → Exploitation → Validation → Reporting → Complete).
2.  **32 Specialist Agents:** Dedicated agents for specific vulnerabilities like XSS, SQLi, SSRF, IDOR, LFI, RCE, etc.
3.  **Schema-Validated LLM Outputs:** Ensures structured JSON validation at phase boundaries.
4.  **Headless Browser Validation:** Uses Chrome DevTools Protocol for visual XSS confirmation, SPA crawling, etc.
5.  **Isolated Sandbox Execution:** Tools and scans run inside a dedicated Docker container.
6.  **Self-Healing Resilience:** Automatic tool error recovery (timeout injection, rate limiting, concurrency adjustment).
7.  **Cross-Flow Memory:** PostgreSQL-backed memory that persists across scans of the same target (using Thompson Sampling).
8.  **Real-Time UI:** React dashboard streaming agent thoughts, tool calls, findings, and pipeline state via WebSocket.
9.  **Configurable Prompts:** YAML-based configuration for tuning agent behavior.

## What Neo Has (That Mirage Lacks)
Based on public information and recent releases from ProjectDiscovery, **Neo** is described as an "AI Security Engineer" designed to fit directly into day-to-day security engineering workflows, not just penetration testing. Here are the key features Neo has that Mirage is currently missing:

1.  **Workflow Integration (Ticketing & Remediation):**
    *   Neo automatically pulls findings from vulnerability backlogs, clusters them, and prioritizes them with context.
    *   It updates tickets (e.g., Jira, ServiceNow) until closure.
    *   It actively **drafts remediation plans** and provides actionable fixes for developers.
2.  **White-Box / Grey-Box Capabilities (Code Reviews & Threat Modeling):**
    *   Neo integrates directly with code repositories for **AI Code Reviews**. It pairs code review with runtime testing to validate if a bug found in code is actually exploitable in the deployed app.
    *   Neo performs **Threat Modeling**, understanding system architecture and naming conventions.
3.  **Enterprise Role-Based Access Control (RBAC) & Single Sign-On (SSO):**
    *   Neo supports SAML/OIDC SSO, RBAC with custom permission policies, and comprehensive audit trails.
    *   Network controls like private connectivity and IP allowlisting.
4.  **Continuous Learning Framework (Not just single-target memory):**
    *   While Mirage has cross-flow memory per target, Neo acts as a framework that continuously learns an organization's specific code, architecture, naming conventions, and accepted risks over time, applying this context to all future workflows.
5.  **Interactive Security Co-Engineer Workflows:**
    *   Instead of just "fire-and-forget" scans, Neo operates as a co-engineer capable of pausing, resuming, and handling large volumes of long-running tasks in parallel (like triaging findings or investigating incidents).

## How to Make Mirage More Like Neo

To evolve Mirage from a black-box pentesting agent to an AI Security Engineer like Neo, we would need to implement the following high-level epics:

1.  **Source Code Integration (White-box testing):**
    *   *Action:* Add GitHub/GitLab integration. Allow Mirage to ingest source code, perform Static Application Security Testing (SAST), and correlate code findings with its dynamic testing (DAST) results.
2.  **Ticketing & Issue Tracking Integration:**
    *   *Action:* Build two-way sync integrations with Jira, Linear, or GitHub Issues. Mirage should automatically create tickets for validated findings, group related vulnerabilities, and update ticket statuses.
3.  **Automated Remediation Drafting:**
    *   *Action:* Add a new pipeline phase (e.g., `Remediation Phase`) where an LLM agent drafts specific code patches or configuration changes to fix the validated vulnerabilities.
4.  **Threat Modeling & Architecture Context:**
    *   *Action:* Allow users to upload architectural diagrams, API schemas (OpenAPI/Swagger), and system documentation. Create a "Threat Modeling" agent that analyzes these documents to guide the Recon phase more intelligently.
5.  **Enterprise Features & Access Control:**
    *   *Action:* Implement user authentication (OIDC/SAML), RBAC, and audit logging in the Go backend.
