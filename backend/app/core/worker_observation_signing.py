"""Domain-separated Ed25519 signatures for passive recon observation batches."""
import hashlib
import json

from app.core.worker_signing import _RESULT_DOMAIN, _canonical, _signature, _verify
from app.schemas.worker_results import SignedWorkerObservationBatch, WorkerObservationBatch


_OBSERVATION_DOMAIN = b"SNAKE-WORKER-OBSERVATIONS-ED25519-v1\\x00"


def observation_batch_digest(batch: WorkerObservationBatch) -> str:
    payload = _canonical(batch.model_dump(mode="json"))
    return hashlib.sha256(payload).hexdigest()


def sign_worker_observation_batch(
    batch: WorkerObservationBatch, private_key_b64: str
) -> SignedWorkerObservationBatch:
    payload = _canonical(batch.model_dump(mode="json"))
    return SignedWorkerObservationBatch(
        batch=batch,
        signature=_signature(private_key_b64, _OBSERVATION_DOMAIN, payload),
    )


def verify_worker_observation_batch(
    signed: SignedWorkerObservationBatch, public_key_b64: str
) -> bool:
    payload = _canonical(signed.batch.model_dump(mode="json"))
    return _verify(public_key_b64, _OBSERVATION_DOMAIN, payload, signed.signature)
