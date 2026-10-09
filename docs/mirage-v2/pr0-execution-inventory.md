# Mirage v2 execution inventory

This is the PR 0 map of places an engagement can cause an effect outside the API process. The same list is enforced by `TestExecutionPathInventory` in `internal/execution/inventory.go`.

`MIRAGE_EXECUTION_V2` defaults to off. When it is on, `execute_command`, browser crawl, `FuzzClient`, and the CORS specialist ask the action gateway before they run. Scheduled scans and `POST /api/cicd/trigger` use `authorizeTriggeredScan`, which calls `policy.Book.AuthorizeStart`.

Paths that still do not pass through that gateway are listed in the Go inventory with `V2Status` of "not wired in this change". Those include raw HTTP clients in other specialists, screenshot capture, WAF fingerprinting, the OOB callback promotion, and the shared `mirage-sandbox` container.

Production startup (`MIRAGE_ENV=production`) refuses to boot unless authentication is required, the JWT secret is not a default, the database URL is not `mirage:mirage`, and `MIRAGE_EXECUTION_V2` is true.
