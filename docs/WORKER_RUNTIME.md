# Worker runtime security boundary

SNAKE now has two validation-only worker entrypoints:

- `worker_entrypoint.py`: one-shot signed JSON validator over stdin/stdout.
- `worker_https_server.py`: minimal HTTPS listener for the fixed
  `POST /internal/v1/tasks` route, requiring a trusted client certificate.

The HTTPS listener:
- Requires TLS 1.2 or newer and mutual TLS. The worker presents its TLS
  certificate; it trusts only client certificates chaining to the configured
  backend-client CA.
- Accepts only bounded JSON requests (64 KiB), rejects ambiguous HTTP framing,
  validates the exact signed task schema, backend Ed25519 signature, and worker/key
  binding. A durable SQLite ledger stores each accepted task ID, digest, identity,
  and exact signed acknowledgement; identical retries return the stored bytes,
  while changed-content task-ID reuse is rejected. Expiry is checked on first acceptance.
- Returns a signed validation-only acknowledgement. It does not execute scans,
  invoke a shell, connect to targets, access a database, or consume a queue.
- Uses a fixed path and no caller-controlled destination or command fields.

Required HTTPS listener environment:
- `SNAKE_WORKER_TLS_CERT_FILE`
- `SNAKE_WORKER_TLS_KEY_FILE`
- `SNAKE_BACKEND_CLIENT_CA_FILE`
- `SNAKE_BACKEND_CLIENT_CERT_SHA256` (exact DER certificate SHA-256 pin)
- `SNAKE_BACKEND_ED25519_PUBLIC_KEY_B64`
- `SNAKE_WORKER_ED25519_PRIVATE_KEY_B64`
- `SNAKE_WORKER_ID`
- `SNAKE_WORKER_KEY_ID`
- `SNAKE_WORKER_REPLAY_DB_PATH` (required durable SQLite ledger path)\n- Optional `SNAKE_WORKER_PASSIVE_FEED_FILE` (trusted, pre-collected JSON feed; mount read-only)
- Optional bind host/port: `SNAKE_WORKER_BIND_HOST`, `SNAKE_WORKER_BIND_PORT`. The default bind is `127.0.0.1:8443`; host must be an explicit IP address and wildcard binds (`0.0.0.0` / `::`) are rejected. Remote deployment must explicitly bind a private interface address and enforce ingress with the host/network firewall.

Run the HTTPS listener in the worker image by overriding its one-shot entrypoint:
```sh
install -d -m 0700 -o 10001 -g 10001 ./worker-state
docker run --rm --entrypoint python \
  --read-only --user 10001:10001 --cap-drop ALL --security-opt no-new-privileges \
  -p 8443:8443 \
  --env-file worker-secrets.env \
  -v ./worker-tls:/run/snake-tls:ro \
  -v ./worker-state:/var/lib/snake-worker \
  -v ./passive-feed.json:/run/snake/passive-feed.json:ro \
  -e SNAKE_WORKER_REPLAY_DB_PATH=/var/lib/snake-worker/replay.sqlite3 \
  -e SNAKE_WORKER_PASSIVE_FEED_FILE=/run/snake/passive-feed.json \
  snake-worker-validator:latest /opt/snake/worker_https_server.py
```

The command above is an example deployment shape, not a production-ready
orchestrator. It must be amended with an explicit private-interface
`SNAKE_WORKER_BIND_HOST` when remote backend connectivity is required; without
that setting the listener is reachable only through loopback. The `install` command creates the host directory with restrictive
permissions and ownership for UID/GID 10001; otherwise the non-root listener
cannot write its replay ledger. The SQLite database file is restricted to mode
0600 by the worker at initialization. Do not share this directory with
untrusted containers or users. Keep
that volume persistent across container replacement, protect it from other
containers/users, and include it in backup/retention planning. The TLS
certificate/key and CA files must be provisioned securely.
The worker's public Ed25519 key must be registered by an administrator; the
backend private key must never be mounted into the worker.

The existing Compose `worker-validator` remains isolated with
`network_mode: none` and runs only the stdin/stdout validator. The HTTPS listener
is not launched by Compose and is not automatically exposed. Do not attach it
to a network until host firewalling, worker-only ingress, certificate lifecycle,
and deployment-specific egress policy are configured.

A valid signed acknowledgement proves only that the registered worker key holder
signed validation metadata. It does not prove a scan ran or that a target was
authorized. Scan execution remains disabled.


## Offline passive feed

The optional feed file is a JSON array, maximum 1 MiB / 500 records. Each record contains `hostname`, `kind` (`hostname`, `url`, `dns_record`, `technology`, or `http_header`), `value`, `evidence`, `source`, and an ISO-8601 timezone-aware `observed_at`. It must be a regular non-symlink file and not group/world writable. Provision it through a trusted external feed preparation process and mount it read-only. The worker does not fetch or refresh the feed.

The producer matches every record to the exact scope manifest carried inside the signed task. Out-of-scope records are dropped; URL records with credentials, query strings, fragments, or mismatched hosts are rejected. The worker signs the remaining records with its registered Ed25519 key. The replay ledger stores the exact complete response, not just the acknowledgement, so retries cannot silently substitute a newer feed. This component does not establish the truth or collection legality of the input feed.


## External passive CT collector

`backend/collect_passive_feed.py` is a separate, network-enabled operator tool.
It queries only the fixed HTTPS origin `crt.sh` (Certificate Transparency),
never resolves or connects to discovered target hosts, and filters every
returned DNS name through the operator-supplied scope rules before writing a
feed accepted by the offline worker.

Example scope file (mode 0600):
```json
{"approved_scope_rules":["example.org","*.example.org"]}
```

Run from the backend environment:
```sh
python collect_passive_feed.py \
  --scope-file ./approved-scope.json \
  --output ./passive-feed.json \
  --authorization-reference "program-approval-ticket-123"
```

The authorization reference is an audit label only. The collector does not
verify a program policy, signed scope snapshot, domain ownership, or legal
authorization. An operator must review the program's current rules and create
the scope file from an explicitly authorized asset list before running it.
The collector has no arbitrary provider URL option; redirects are disabled,
requests and response sizes are bounded, and output is atomically written with
mode 0600. CT names are untrusted leads, can be stale or unrelated, and do not
prove asset ownership, service reachability, or vulnerability. Human review
and the backend's signed-scope checks remain mandatory.

This collector is intentionally not installed in or copied into the isolated
worker image. Run it on a separate controlled host with outbound access only
to the provider. Transfer the resulting feed to the worker through a trusted
channel and mount it read-only. Provider availability, terms, rate limits, and
data retention practices must be reviewed before operational use.


## External passive DNS collector (DNSDB)

The same external collector can optionally query DomainTools Farsight DNSDB
API v2 as a passive DNS source. It uses the fixed HTTPS origin
`api.dnsdb.info`, the documented `X-API-Key` header, NDJSON/SAF framing,
and a bounded response. It requests only exact approved names or the wildcard
form for an explicitly wildcard-approved scope rule. It never resolves names
or connects to discovered hosts.

Set the API key in the collector process environment (do not put it in the
scope file, command line, output feed, or source control):
```sh
export DNSDB_API_KEY='your-provider-api-key'
python collect_passive_feed.py \
  --scope-file ./approved-scope.json \
  --output ./passive-feed.json \
  --provider ct --provider dnsdb \
  --authorization-reference "program-approval-ticket-123"
```

DNSDB API access requires a separately provisioned paid/provider account and
is not enabled by default. The collector rejects incomplete SAF streams and
accepts only RRsets with passive replication timestamps; records containing
only zone-file import timestamps are excluded. A DNSDB response marked
`limited` is retained as a bounded, potentially truncated result. RRset owner
names are rechecked against the approved scope before they enter the feed.
Only a bounded sample per provider is included when both providers are
selected. Provider rate limits, account entitlements, terms, and data handling
must be checked by the operator.

DNSDB records are historical observations, not proof of current DNS state,
asset ownership, authorization, reachability, or vulnerability. The API key
is used only in the outbound provider request and is never persisted by SNAKE.


## Periodic passive-feed scheduler

`backend/passive_feed_scheduler.py` runs as a separate operator-controlled
process. It refreshes the configured CT and/or DNSDB providers on a bounded
interval (15 minutes to 7 days; default 6 hours), reloads the scope manifest
before every cycle, and publishes a feed only after every selected provider
completes successfully. A failed refresh leaves the previous feed untouched.
A process lock prevents two scheduler instances from writing the same feed
concurrently. SIGTERM and SIGINT stop the loop cleanly.

Example:
```sh
python passive_feed_scheduler.py \\
  --scope-file /etc/snake/approved-scope.json \\
  --output /var/lib/snake/passive-feed.json \\
  --provider ct --provider dnsdb \\
  --interval-seconds 21600 \\
  --authorization-reference "program-approval-ticket-123"
```

The DNSDB key is read from `DNSDB_API_KEY` in the process environment. Keep
that environment file outside source control with mode 0600. The scheduler
must run on a dedicated controlled host, not in the worker container. Apply
host egress firewall rules that permit only the selected passive-provider
endpoints; the Python origin allowlist is an additional control, not a
replacement for network egress enforcement. The output feed should be
transferred to the worker through a trusted channel and mounted read-only.
The scheduler does not verify authorization, provider terms, domain ownership,
or the truth/currentness of passive records. Review scope and program rules
before each deployment and after every scope change.


## Passive asset history and change detection

The external scheduler records each successfully published feed snapshot in a
private SQLite history database (default: `OUTPUT.history.sqlite3`; override
with `--history-db`). It emits append-only change events for newly observed
records, records that reappear after being absent, and records missing from a
later complete snapshot. An unchanged record updates its last-seen timestamp
without generating an event. A changed DNS value is represented as the old
record becoming missing and the new value appearing.

The history database is maintained outside the isolated worker. Missing events
are meaningful only when all selected providers completed successfully; failed
refreshes do not publish a feed or update history. The history is a record-level
view, not proof that a hostname is offline or an asset has been decommissioned:
provider coverage, retention, rate limits, and query differences can make
records disappear. Treat these events as investigation leads, not facts about
target availability. The database contains passive metadata and should be
protected and retained under the same access policy as the feed.

Example:
```sh
python passive_feed_scheduler.py \\
  --scope-file /etc/snake/approved-scope.json \\
  --output /var/lib/snake/passive-feed.json \\
  --history-db /var/lib/snake/asset-history.sqlite3 \\
  --provider ct --provider dnsdb
```


## Passive asset prioritization

The scheduler now writes a separate ranked report (default
`OUTPUT.priority.json`; override with `--priority-report`). The worker feed
remains unchanged and does not receive prioritization metadata. Scores are
deterministic triage hints based on observation freshness, distinct passive
source count, record kind, and the current snapshot's change events. The report
includes a factor breakdown and a coarse low/medium/high label.

Freshness uses the observation timestamp, not the provider fetch timestamp.
Future or malformed timestamps receive no freshness bonus. Multiple records
from the same source do not increase source diversity. Scores do not establish
exploitability, asset ownership, reachability, severity, or authorization.
Missing events reduce priority but do not mean that an asset is offline; they
may reflect provider coverage or retention changes. Human review remains
required.

Example output paths:
```text
passive-feed.json
passive-feed.json.history.sqlite3
passive-feed.json.priority.json
```
