from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.schemas.worker_results import WorkerObservation, WorkerObservationBatch


NOW = datetime.now(timezone.utc)


def observation(**overrides):
    data = dict(
        observation_id=uuid4(),
        kind="url",
        value="https://example.test/status",
        evidence="Observed URL in passive source",
        source="passive_source",
        observed_at=NOW,
    )
    data.update(overrides)
    return WorkerObservation(**data)


def batch(**overrides):
    data = dict(
        task_id=uuid4(),
        envelope_sha256="a" * 64,
        worker_id="worker-01",
        key_id="worker-key-v1",
        collected_at=NOW,
        observations=[observation()],
        execution_enabled=False,
    )
    data.update(overrides)
    return WorkerObservationBatch(**data)


def test_rejects_extra_finding_claim_fields():
    with pytest.raises(ValidationError):
        observation(severity="critical", confirmed=True)


def test_rejects_arbitrary_kind():
    with pytest.raises(ValidationError):
        observation(kind="confirmed_vulnerability")


def test_rejects_control_characters_in_value():
    with pytest.raises(ValidationError):
        observation(value="host.test" + chr(10) + "INJECTED")


def test_rejects_execution_enabled_true():
    with pytest.raises(ValidationError):
        batch(execution_enabled=True)


def test_rejects_naive_collection_timestamp():
    with pytest.raises(ValidationError):
        batch(collected_at=datetime.now())


def test_rejects_more_than_500_observations():
    with pytest.raises(ValidationError):
        batch(observations=[observation() for _ in range(501)])


def test_rejects_duplicate_observation_ids():
    item = observation()
    with pytest.raises(ValidationError):
        batch(observations=[item, item])


def test_rejects_observation_after_collection():
    future = observation(observed_at=NOW + timedelta(seconds=1))
    with pytest.raises(ValidationError):
        batch(observations=[future])
