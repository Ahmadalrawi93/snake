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
- `SNAKE_WORKER_REPLAY_DB_PATH` (required durable SQLite ledger path)
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
  -e SNAKE_WORKER_REPLAY_DB_PATH=/var/lib/snake-worker/replay.sqlite3 \
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
