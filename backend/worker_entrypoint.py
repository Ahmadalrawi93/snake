"""Validation-only worker container entrypoint; it never executes scan tasks."""
import json
import sys

from pydantic import ValidationError

from app.core.worker_protocol import WorkerTaskEnvelope, ensure_not_expired


MAX_INPUT_BYTES = 64 * 1024


def main() -> int:
    raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    if not raw:
        print("No task envelope supplied.", file=sys.stderr)
        return 2
    if len(raw) > MAX_INPUT_BYTES:
        print("Task envelope exceeds 64 KiB.", file=sys.stderr)
        return 2

    try:
        payload = json.loads(raw)
        task = WorkerTaskEnvelope.model_validate(payload)
        ensure_not_expired(task)
    except (json.JSONDecodeError, UnicodeDecodeError, ValidationError, ValueError) as exc:
        print(f"Task rejected: {exc}", file=sys.stderr)
        return 2

    # This container intentionally cannot execute tasks, make network requests,
    # or claim jobs. A valid envelope is only acknowledged as parsed metadata.
    print(json.dumps({
        "task_id": str(task.task_id),
        "accepted": True,
        "execution_enabled": False,
        "mode": "validation_only",
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
