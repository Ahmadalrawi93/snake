"""Ed25519 authentication for worker tasks and validation acknowledgements.

The backend signs tasks with its private key; workers receive only the backend
public key. Each worker signs acknowledgements with its own private key; the
backend stores only that worker's public key. Private keys are injected out of band.
"""
import base64
import hashlib
import json
from typing import Annotated

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field

from app.core.worker_protocol import WorkerTaskEnvelope, WorkerValidationResult

_ID_RE = r"^[a-zA-Z0-9._-]{1,128}$"
_SIG_RE = r"^ed25519:v1:[A-Za-z0-9_-]{86}$"
_TASK_DOMAIN = b"SNAKE-WORKER-TASK-ED25519-v1\x00"
_RESULT_DOMAIN = b"SNAKE-WORKER-RESULT-ED25519-v1\x00"


class SignedWorkerTask(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    envelope: WorkerTaskEnvelope
    worker_id: Annotated[str, Field(pattern=_ID_RE)]
    key_id: Annotated[str, Field(pattern=_ID_RE)]
    signature: Annotated[str, Field(pattern=_SIG_RE)]


class SignedWorkerValidationResult(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    result: WorkerValidationResult
    key_id: Annotated[str, Field(pattern=_ID_RE)]
    signature: Annotated[str, Field(pattern=_SIG_RE)]


def _canonical(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _decode_key(value: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise ValueError("Ed25519 key material is required")
    try:
        return base64.b64decode(value, validate=True)
    except Exception as exc:
        raise ValueError("Ed25519 key must be base64-encoded DER") from exc


def _private_key(value: str) -> Ed25519PrivateKey:
    try:
        key = serialization.load_der_private_key(_decode_key(value), password=None)
    except Exception as exc:
        raise ValueError("invalid Ed25519 private key") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("private key must be Ed25519")
    return key


def _public_key(value: str) -> Ed25519PublicKey:
    try:
        key = serialization.load_der_public_key(_decode_key(value))
    except Exception as exc:
        raise ValueError("invalid Ed25519 public key") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("public key must be Ed25519")
    return key


def _signature(private_key_b64: str, domain: bytes, payload: bytes) -> str:
    raw = _private_key(private_key_b64).sign(domain + payload)
    return "ed25519:v1:" + base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _verify(public_key_b64: str, domain: bytes, payload: bytes, signature: str) -> bool:
    try:
        prefix, version, encoded = signature.split(":", 2)
        if prefix != "ed25519" or version != "v1":
            return False
        raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        if len(raw) != 64:
            return False
        _public_key(public_key_b64).verify(raw, domain + payload)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def worker_task_digest(envelope: WorkerTaskEnvelope) -> str:
    return hashlib.sha256(_canonical(envelope.model_dump(mode="json"))).hexdigest()


def sign_worker_task(
    envelope: WorkerTaskEnvelope, private_key_b64: str, *, worker_id: str, key_id: str
) -> SignedWorkerTask:
    payload = _canonical({
        "envelope": envelope.model_dump(mode="json"),
        "worker_id": worker_id,
        "key_id": key_id,
    })
    signature = _signature(private_key_b64, _TASK_DOMAIN, payload)
    return SignedWorkerTask(envelope=envelope, worker_id=worker_id, key_id=key_id, signature=signature)


def verify_worker_task(
    signed: SignedWorkerTask, public_key_b64: str, *,
    expected_worker_id: str, expected_key_id: str
) -> bool:
    if signed.worker_id != expected_worker_id or signed.key_id != expected_key_id:
        return False
    payload = _canonical({
        "envelope": signed.envelope.model_dump(mode="json"),
        "worker_id": signed.worker_id,
        "key_id": signed.key_id,
    })
    return _verify(public_key_b64, _TASK_DOMAIN, payload, signed.signature)


def sign_worker_validation_result(
    result: WorkerValidationResult, private_key_b64: str, *, key_id: str
) -> SignedWorkerValidationResult:
    payload = _canonical({"result": result.model_dump(mode="json"), "key_id": key_id})
    signature = _signature(private_key_b64, _RESULT_DOMAIN, payload)
    return SignedWorkerValidationResult(result=result, key_id=key_id, signature=signature)


def verify_worker_validation_result(
    signed: SignedWorkerValidationResult, public_key_b64: str, *,
    expected_worker_id: str, expected_key_id: str
) -> bool:
    if signed.key_id != expected_key_id or signed.result.worker_id != expected_worker_id:
        return False
    payload = _canonical({"result": signed.result.model_dump(mode="json"), "key_id": signed.key_id})
    return _verify(public_key_b64, _RESULT_DOMAIN, payload, signed.signature)
