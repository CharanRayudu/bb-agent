# Mirage v2 execution inventory

This is the PR 0 map of places an engagement can cause an effect outside the API process. The same list is enforced by `TestExecutionPathInventory` in `internal/execution/inventory.go`.

`MIRAGE_EXECUTION_V2` defaults to off. When it is on, tool calls, browser traffic, FuzzClient probes, wrapped specialist HTTP clients, and TCP connect scans ask the gateway before they run. Known security tools such as nuclei, nmap, ffuf, curl, and sqlmap run when every destination is inside the engagement. Arbitrary shell commands stay denied unless the authorization explicitly grants them.

Scheduled scans and `POST /api/cicd/trigger` inherit the parent authorization, including autonomy level, exclusions, and expiry. They do not mint a broader record.

Production startup (`MIRAGE_ENV=production`) refuses to boot unless authentication is required, the JWT secret is not a default, the database URL is not `mirage:mirage`, and `MIRAGE_EXECUTION_V2` is true.

Still outside this gateway: the shared sandbox container's network egress, and OOB callback promotion into a finding. An audit write failure now refuses the action.
