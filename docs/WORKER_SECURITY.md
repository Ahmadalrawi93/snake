# Worker protocol boundary

SNAKE currently has no worker process, dispatcher, queue consumer, or scan execution.
`backend/app/core/worker_protocol.py` defines a deliberately narrow future message
contract only:

- fixed `passive_recon` profile;
- positive database identifiers and a SHA-256 scope snapshot digest;
- HTTP(S) target URL and timezone-aware issue/expiry timestamps;
- `execution_enabled` is a literal false value;
- unknown fields are rejected, including command/script/argv injection.

This schema is not an authorization decision and does not execute anything. A future
dispatcher must independently load the job and snapshot from the database, verify
ownership and the snapshot digest, re-check authorization status and its complete
time window, compare the current approved scope rules to the immutable snapshot,
resolve and pin public destination IPs, and enforce egress restrictions.

A future worker must run non-root in a disposable isolated container with a read-only
root filesystem, bounded CPU/memory/PIDs/time, dropped Linux capabilities, no host
network, no Docker socket, no host mounts, and a default-deny egress policy. The LLM
may propose structured findings or adapter parameters only; it must never provide
shell commands or executable code to the worker.

No outbound traffic or execution is enabled by this change.
