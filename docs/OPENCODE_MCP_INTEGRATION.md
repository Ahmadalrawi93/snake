# OpenCode Local MCP Integration

## Current implementation

SNAKE now includes a **read-only local MCP server** at `app.mcp_server`.
OpenCode is the MCP client/host; SNAKE exposes the tools. The server uses
MCP over standard input/output (stdio), does not open a TCP listener, and
does not make target-network requests.

The initial tools are deliberately limited:

- `snake_list_projects`: list projects owned by the configured local operator.
- `snake_list_authorized_targets`: list targets with an active scope snapshot
  that passes current authorization, target, and snapshot-integrity checks.
- `snake_list_scan_jobs`: list persisted job records. A queued job is not a
  running scan.
- `snake_get_job_observations`: read stored, unconfirmed worker observations.
- `snake_get_security_signals`: run the existing deterministic signal engine
  over stored observations.

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
    "snake": {
      "type": "local",
      "command": [
        "/absolute/path/to/snake/backend/.venv/bin/python",
        "-m",
        "app.mcp_server"
      ],
      "environment": {
        "SNAKE_MCP_USER_ID": "1"
      },
      "enabled": true
    }
  }
}
```

Set the MCP server working directory to `backend` using the working-directory
facility supported by the installed OpenCode version, or launch it through a
small local wrapper that changes directory before executing Python. Never put
database passwords, API keys, or model credentials in tool arguments.

## Security boundaries

- The MCP server is a local operator integration, not an authentication
  replacement for the SNAKE API.
- The configured user ID is trusted local configuration. Anyone able to edit
  the OpenCode configuration or launch environment as that OS user is inside
  this local trust boundary.
- The initial MCP surface is read-only. It has no arbitrary URL, shell,
  filesystem, exploit, or target-request tool.
- Scope snapshots are revalidated against project ownership, snapshot digest,
  authorization state/window/rules, and the current target before a target is
  listed as authorized.
- Evidence is returned as unconfirmed observations. Security signals are
  leads requiring independent validation, not findings.
- Existing scan jobs remain persisted records; this MCP release does not make
  queued jobs execute.

## Next engineering milestone

Add a bounded local HTTP collector behind a separate explicit tool only after
implementing and testing per-request scope checks, redirect revalidation,
DNS/IP destination controls, response-size/time limits, and audit records.
The model must never supply an unrestricted URL or shell command. The collector
must resolve its destination from a currently valid approved target/snapshot
and remain limited to low-impact collection. Until that work and local-lab
tests are complete, SNAKE does not perform live reconnaissance.
