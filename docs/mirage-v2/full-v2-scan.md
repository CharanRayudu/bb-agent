# Run a full Mirage v2 scan

`MIRAGE_EXECUTION_V2` defaults to off for a native `go run`. Docker Compose sets it to `true` unless you override it. A v2 scan authorizes every tool call, runs the scanner in its own container, and keeps that container's files under `data/workspaces/<flow>`.

The scanner image and the firewall image are different:

| Variable | Image | Role |
| --- | --- | --- |
| `SANDBOX_IMAGE` | `mirage-tools:latest` | nmap, nuclei, sqlmap, ffuf, curl, and the other scanner binaries |
| `FIREWALL_HELPER_IMAGE` | `mirage-firewall:local` | `iptables` on the Docker host only |

The API container does not run iptables itself. It uses the Docker CLI to start the helper image with the host network. The backend image installs `docker-cli` for that call.

## Build and start

```powershell
docker compose build firewall-helper sandbox backend frontend
docker compose up -d
```

`sandbox` is the Kali tool image in `build/tools/Dockerfile`. That build is large. The firewall helper is the small Alpine image and finishes quickly.

The UI is `http://localhost:3000`. The API is proxied at `/api/` and the websocket at `/ws`. Compose passes `MIRAGE_EXECUTION_V2=true`.

## What a v2 scan does

1. Create a flow in the UI against a target you are allowed to test.
2. The API stores the flow in Postgres and starts the orchestrator.
3. The generative model still writes the plan and the report.
4. If `FOUNDRY_ENDPOINT`, `FOUNDRY_DEPLOYMENT`, and `FOUNDRY_API_KEY` are set, Decision-1 chooses the specialist. A low-confidence answer, an abstention, or an API error keeps the existing keyword rules and does not replace a plan that Decision-1 could not classify.
5. Each scanner runs in a container from `mirage-tools:latest`, with its output and any target-list or raw-request file under `/workspace`.
6. The UI reads status, events, and artifacts back through the API and websocket.

Set `MIRAGE_EXECUTION_V2=false` in the environment before `docker compose up` to keep the legacy shared sandbox. Leave the Foundry variables empty to keep specialist selection on the deterministic rules.

Do not put a Foundry key in the repository. Pass it only through the environment.
