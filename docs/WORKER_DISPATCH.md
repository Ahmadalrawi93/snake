# Dispatch gate

`backend/app/core/worker_dispatch.py` adds a database-backed dispatch gate that
re-reads the job, project, target, snapshot, and authorization immediately before a
future dispatch decision. It checks ownership/linkage, queued status, disabled
execution, the fixed passive profile, snapshot integrity/scope, and authorization
validity. It emits a short-lived envelope whose expiry cannot exceed the authorization
or snapshot expiry (maximum five minutes).

**Important:** this is not a queue consumer or worker dispatcher. It does not change
job state, make network requests, resolve DNS, or contact a worker. The returned
envelope always has `execution_enabled=false`. A real dispatcher still needs atomic
job claiming, replay protection, worker authentication, and egress enforcement.
