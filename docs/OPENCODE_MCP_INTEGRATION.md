# OpenCode Local MCP Integration

## Current implementation

SNAKE includes a local MCP server at `app.mcp_server`. OpenCode is the MCP
client/host; SNAKE exposes the tools. The server uses MCP over standard
input/output (stdio) and does not open a TCP listener. Most tools are
read-only; one explicit tool performs bounded, unauthenticated HTTP GET
collection against a currently approved target.

The initial tools are deliberately limited:

- `snake_list_projects`: list projects owned by the configured local operator.
- `snake_list_authorized_targets`: list targets with an active scope snapshot
  that passes current authorization, target, and snapshot-integrity checks.
- `snake_list_scan_jobs`: list persisted job records. A queued job is not a
  running scan.
- `snake_get_job_observations`: read stored, unconfirmed worker observations.
- `snake_get_security_signals`: run the existing deterministic signal engine
  over stored observations.
- `snake_collect_http`: collect a bounded same-origin set of HTTP pages for a
  target ID and active scope-snapshot ID; the model cannot supply a URL.
- `snake_get_local_recon_evidence`: read persisted, redacted metadata and
  deterministic security signals from a local collection run.

All project, job, and evidence reads are constrained to the operator ID
configured for this local MCP process. The process fails closed if
`SNAKE_MCP_USER_ID` is absent, invalid, or points to an inactive user.
Do not configure this value from model-generated input.

## OpenCode configuration

Install the backend requirements in the local SNAKE Python environment, then
configure OpenCode to launch the module from the backend directory. Example
OpenCode configuration (adjust the absolute paths and operator ID):

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "servers": {
      "snake": {
        "type": "local",
        "command": [
          "/absolute/path/to/snake/backend/.venv/bin/python",
          "-m",
          "app.mcp_server"
        ],
        "cwd": "/absolute/path/to/snake/backend",
        "environment": {
          "SNAKE_MCP_USER_ID": "1"
        }
      }
    }
  }
}
```

OpenCode's local MCP configuration uses `mcp.servers`, `type: "local"`,
`command`, `cwd`, and `environment`. Keep the configured path absolute for
a stable local installation. Never put database passwords, API keys, or model
credentials in tool arguments.

## Security boundaries

- The MCP server is a local operator integration, not an authentication
  replacement for the SNAKE API.
- The configured user ID is trusted local configuration. Anyone able to edit
  the OpenCode configuration or launch environment as that OS user is inside
  this local trust boundary.
- There is no arbitrary URL, shell, filesystem, exploit, or arbitrary-request
  tool. The sole network-capable tool resolves the target from an owned,
  currently valid scope snapshot.
- Scope snapshots are revalidated against project ownership, snapshot digest,
  authorization state/window/rules, and the current target before a target is
  listed as authorized.
- Evidence is returned as unconfirmed observations. Security signals are
  leads requiring independent validation, not findings.
- The existing worker scan-job queue remains non-executable. Local recon runs
  are stored separately and never set worker execution flags.

## Local HTTP collection boundary

The first live-collection milestone is implemented as a deliberately small
HTTP metadata collector:

- GET only; no authentication, cookies, forms, POST, payloads, fuzzing, or
  brute force.
- Starts from a target ID plus its active snapshot ID; the model never passes
  an arbitrary URL.
- Only HTTP/HTTPS on ports 80 and 443. DNS results must all be globally
  routable; the socket connects to the validated, pinned IP while HTTPS keeps
  normal certificate and hostname verification.
- Redirects are manually handled, revalidated, restricted to the exact original
  origin, and limited to three hops.
- HTML discovery is same-origin only and bounded to at most 10 pages per run.
- One-second minimum interval between requests to the same host within the
  local MCP process and a persisted 30-second cooldown per target; five-second
  socket timeout; response bodies capped at 256 KiB and never persisted.
- Only selected response headers and metadata are stored. Set-Cookie values
  and URL query values are redacted; Location values are used for redirect
  decisions but not stored.
- Every run is persisted separately from worker scan jobs and has an audit
  event. All observations remain unconfirmed and signal severity stays
  unassessed.

The collector is a low-impact reconnaissance primitive, not a vulnerability
scanner. It does not prove that a discovered path is accessible or vulnerable.
Its network controls have unit coverage against a local test server; a full
end-to-end SNAKE/OpenCode lab run is still required before describing the
workflow as ready for operational bug bounty use.
