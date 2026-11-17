"""Authenticated stdin/stdout worker validator; it never executes scan tasks."""
import json
import os
import sys
from datetime import datetime, timezone

from pydantic import ValidationError

from app.core.worker_signing import worker_task_digest
from app.core.worker_protocol import WorkerValidationResult, ensure_not_expired
from app.core.worker_signing import (
    SignedWorkerTask,
    sign_worker_validation_result,
    verify_worker_task,
)

MAX_INPUT_BYTES = 64 * 1024


def main() -> int:
    raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    if not raw:
        print("No signed task supplied.", file=sys.stderr)
        return 2
    if len(raw) > MAX_INPUT_BYTES:
        print("Task message exceeds 64 KiB.", file=sys.stderr)
        return 2

    secret = os.environ.get("SNAKE_WORKER_SIGNING_SECRET", "")
    worker_id = os.environ.get("SNAKE_WORKER_ID", "local-validator")
    if len(secret) < 32:
        print("Dedicated worker signing secret is not configured.", file=sys.stderr)
        return 2

    try:
        signed = SignedWorkerTask.model_validate_json(raw)
        if not verify_worker_task(signed, secret):
            raise ValueError("task signature verification failed")
        task = signed.envelope
        ensure_not_expired(task)
        result = WorkerValidationResult(
            task_id=task.task_id,
            envelope_sha256=worker_task_digest(task),
            worker_id=worker_id,
            outcome="accepted",
            validated_at=datetime.now(timezone.utc),
            execution_enabled=False,
        )
        signed_result = sign_worker_validation_result(result, secret)
    except (ValidationError, ValueError) as exc:
        print(f"Task rejected: {exc}", file=sys.stderr)
        return 2

    # This validator verifies authenticated metadata only. It has no DB connection,
    # replay ledger, network access, or scan capability.
    print(signed_result.model_dump_json())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
