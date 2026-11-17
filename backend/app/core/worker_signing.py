"""HMAC authentication for worker task and validation-result messages.

Signatures authenticate canonical message contents only. They do not authorize targets,
consume replay receipts, or enable scan execution.
"""
import hashlib
import hmac
import json
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field

from app.core.worker_protocol import WorkerTaskEnvelope, WorkerValidationResult

_SIGNATURE_RE = r"^v1=[a-f0-9]{64}$"
_TASK_DOMAIN = b"SNAKE-WORKER-TASK-v1" + bytes.fromhex("00")
_RESULT_DOMAIN = b"SNAKE-WORKER-RESULT-v1" + bytes.fromhex("00")


class SignedWorkerTask(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    envelope: WorkerTaskEnvelope
    signature: Annotated[str, Field(pattern=_SIGNATURE_RE)]


class SignedWorkerValidationResult(BaseModel):
    """Authenticated worker acknowledgement, not evidence of scan execution."""

    model_config = ConfigDict(extra="forbid", strict=True)

    result: WorkerValidationResult
    signature: Annotated[str, Field(pattern=_SIGNATURE_RE)]


def _canonical_payload(model: BaseModel) -> bytes:
    return json.dumps(
        model.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def worker_task_digest(envelope: WorkerTaskEnvelope) -> str:
    return hashlib.sha256(_canonical_payload(envelope)).hexdigest()


def _sign(payload: bytes, domain: bytes, secret: str) -> str:
    if not isinstance(secret, str) or len(secret) < 32:
        raise ValueError("worker signing secret must contain at least 32 characters")
    digest = hmac.new(secret.encode("utf-8"), domain + payload, hashlib.sha256).hexdigest()
    return f"v1={digest}"


def sign_worker_task(envelope: WorkerTaskEnvelope, secret: str) -> SignedWorkerTask:
    """Sign a task with a dedicated high-entropy secret (minimum 32 chars)."""
    signature = _sign(_canonical_payload(envelope), _TASK_DOMAIN, secret)
    return SignedWorkerTask(envelope=envelope, signature=signature)


def verify_worker_task(signed: SignedWorkerTask, secret: str) -> bool:
    """Verify task authenticity/integrity; callers must still check scope and replay."""
    expected = _sign(_canonical_payload(signed.envelope), _TASK_DOMAIN, secret)
    return hmac.compare_digest(expected, signed.signature)


def sign_worker_validation_result(
    result: WorkerValidationResult, secret: str
) -> SignedWorkerValidationResult:
    """Sign a validation acknowledgement with result-specific domain separation."""
    signature = _sign(_canonical_payload(result), _RESULT_DOMAIN, secret)
    return SignedWorkerValidationResult(result=result, signature=signature)


def verify_worker_validation_result(
    signed: SignedWorkerValidationResult, secret: str
) -> bool:
    """Verify acknowledgement; caller must bind it to an authorized, consumed task."""
    expected = _sign(_canonical_payload(signed.result), _RESULT_DOMAIN, secret)
    return hmac.compare_digest(expected, signed.signature)
