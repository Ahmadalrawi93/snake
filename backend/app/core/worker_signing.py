"""Per-worker HMAC authentication for task and validation-result messages.

Each worker must receive a unique high-entropy secret out of band. key_id is a
non-secret identifier used for rotation and routing; it is included in signatures.
"""
import hashlib
import hmac
import json
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field

from app.core.worker_protocol import WorkerTaskEnvelope, WorkerValidationResult

_SIGNATURE_RE = r"^v1=[a-f0-9]{64}$"
_ID_RE = r"^[a-zA-Z0-9._-]{1,128}$"
_TASK_DOMAIN = b"SNAKE-WORKER-TASK-v2\x00"
_RESULT_DOMAIN = b"SNAKE-WORKER-RESULT-v2\x00"


class SignedWorkerTask(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    envelope: WorkerTaskEnvelope
    worker_id: Annotated[str, Field(pattern=_ID_RE)]
    key_id: Annotated[str, Field(pattern=_ID_RE)]
    signature: Annotated[str, Field(pattern=_SIGNATURE_RE)]


class SignedWorkerValidationResult(BaseModel):
    """Authenticated validation acknowledgement, not evidence of scan execution."""

    model_config = ConfigDict(extra="forbid", strict=True)

    result: WorkerValidationResult
    key_id: Annotated[str, Field(pattern=_ID_RE)]
    signature: Annotated[str, Field(pattern=_SIGNATURE_RE)]


def _canonical_payload(value: dict) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def worker_task_digest(envelope: WorkerTaskEnvelope) -> str:
    return hashlib.sha256(_canonical_payload(envelope.model_dump(mode="json"))).hexdigest()


def _sign(payload: bytes, domain: bytes, secret: str) -> str:
    if not isinstance(secret, str) or len(secret) < 32:
        raise ValueError("worker signing secret must contain at least 32 characters")
    digest = hmac.new(secret.encode("utf-8"), domain + payload, hashlib.sha256).hexdigest()
    return f"v1={digest}"


def sign_worker_task(
    envelope: WorkerTaskEnvelope, secret: str, *, worker_id: str, key_id: str
) -> SignedWorkerTask:
    """Sign a task for one named worker using that worker's unique secret."""
    payload = _canonical_payload({
        "envelope": envelope.model_dump(mode="json"),
        "worker_id": worker_id,
        "key_id": key_id,
    })
    signature = _sign(payload, _TASK_DOMAIN, secret)
    return SignedWorkerTask(
        envelope=envelope, worker_id=worker_id, key_id=key_id, signature=signature
    )


def verify_worker_task(
    signed: SignedWorkerTask, secret: str, *, expected_worker_id: str, expected_key_id: str
) -> bool:
    """Verify authenticity and intended worker; callers must still check scope/replay."""
    if signed.worker_id != expected_worker_id or signed.key_id != expected_key_id:
        return False
    payload = _canonical_payload({
        "envelope": signed.envelope.model_dump(mode="json"),
        "worker_id": signed.worker_id,
        "key_id": signed.key_id,
    })
    expected = _sign(payload, _TASK_DOMAIN, secret)
    return hmac.compare_digest(expected, signed.signature)


def sign_worker_validation_result(
    result: WorkerValidationResult, secret: str, *, key_id: str
) -> SignedWorkerValidationResult:
    payload = _canonical_payload({
        "result": result.model_dump(mode="json"), "key_id": key_id
    })
    signature = _sign(payload, _RESULT_DOMAIN, secret)
    return SignedWorkerValidationResult(result=result, key_id=key_id, signature=signature)


def verify_worker_validation_result(
    signed: SignedWorkerValidationResult, secret: str, *, expected_key_id: str
) -> bool:
    """Verify result with the unique secret selected for its expected worker/key."""
    if signed.key_id != expected_key_id:
        return False
    payload = _canonical_payload({
        "result": signed.result.model_dump(mode="json"), "key_id": signed.key_id
    })
    expected = _sign(payload, _RESULT_DOMAIN, secret)
    return hmac.compare_digest(expected, signed.signature)
