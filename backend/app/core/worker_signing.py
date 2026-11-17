"""HMAC authentication for worker task envelopes.

Signing is a transport-integrity primitive only. It does not authorize a target,
claim a job, prevent replay by itself, or enable execution.
"""
import hashlib
import hmac
import json
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field

from app.core.worker_protocol import WorkerTaskEnvelope, WorkerValidationResult


_SIGNATURE_RE = r"^v1=[a-f0-9]{64}$"


class SignedWorkerTask(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    envelope: WorkerTaskEnvelope
    signature: Annotated[str, Field(pattern=_SIGNATURE_RE)]


def _canonical_payload(envelope: WorkerTaskEnvelope) -> bytes:
    data = envelope.model_dump(mode="json")
    return json.dumps(
        data, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sign_worker_task(envelope: WorkerTaskEnvelope, secret: str) -> SignedWorkerTask:
    """Sign a task with a dedicated high-entropy secret (minimum 32 chars)."""
    if not isinstance(secret, str) or len(secret) < 32:
        raise ValueError("worker signing secret must contain at least 32 characters")
    digest = hmac.new(
        secret.encode("utf-8"), b"SNAKE-WORKER-TASK-v1\\x00" + _canonical_payload(envelope), hashlib.sha256
    ).hexdigest()
    return SignedWorkerTask(envelope=envelope, signature=f"v1={digest}")


def verify_worker_task(signed: SignedWorkerTask, secret: str) -> bool:
    """Verify authenticity/integrity; callers must still check scope and replay."""
    if not isinstance(secret, str) or len(secret) < 32:
        raise ValueError("worker signing secret must contain at least 32 characters")
    expected = sign_worker_task(signed.envelope, secret).signature
    return hmac.compare_digest(expected, signed.signature)


class SignedWorkerValidationResult(BaseModel):
    """Authenticated worker acknowledgement, not evidence of scan execution."""

    model_config = ConfigDict(extra="forbid", strict=True)

    result: WorkerValidationResult
    signature: Annotated[str, Field(pattern=_SIGNATURE_RE)]


def sign_worker_validation_result(result: WorkerValidationResult, secret: str) -> SignedWorkerValidationResult:
    """Sign a validation acknowledgement with result-specific domain separation."""
    if not isinstance(secret, str) or len(secret) < 32:
        raise ValueError("worker signing secret must contain at least 32 characters")
    payload = json.dumps(
        result.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    digest = hmac.new(
        secret.encode("utf-8"),
        b"SNAKE-WORKER-RESULT-v1\\x00" + payload,
        hashlib.sha256,
    ).hexdigest()
    return SignedWorkerValidationResult(result=result, signature=f"v1={digest}")


def verify_worker_validation_result(
    signed: SignedWorkerValidationResult, secret: str
) -> bool:
    """Verify a worker acknowledgement; caller must still bind it to a consumed task."""
    if not isinstance(secret, str) or len(secret) < 32:
        raise ValueError("worker signing secret must contain at least 32 characters")
    payload = json.dumps(
        signed.result.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    expected = "v1=" + hmac.new(
        secret.encode("utf-8"),
        b"SNAKE-WORKER-RESULT-v1\\x00" + payload,
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected, signed.signature)
