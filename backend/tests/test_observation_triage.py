from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.schemas.observation_triage import ObservationTriage
from app.core.observation_triage import validate_triage_references


def make_triage(**overrides):
    data = dict(
        category="authorization",
        hypothesis="An endpoint may expose another user's record.",
        supporting_observation_ids=[uuid4()],
        missing_evidence=["A second controlled account"],
        validation_questions=["Can account B access account A's record?"],
        confidence="low",
        disposition="requires_independent_validation",
    )
    data.update(overrides)
    return ObservationTriage(**data)


def test_accepts_hypothesis_with_known_evidence():
    triage = make_triage()
    assert validate_triage_references(triage, triage.supporting_observation_ids) is triage


def test_rejects_reference_outside_context():
    triage = make_triage()
    with pytest.raises(ValueError, match="outside"):
        validate_triage_references(triage, [uuid4()])


def test_rejects_confirmed_finding_claim():
    with pytest.raises(ValidationError):
        make_triage(disposition="confirmed_finding", severity="critical")


def test_rejects_duplicate_evidence_references():
    ref = uuid4()
    with pytest.raises(ValidationError):
        make_triage(supporting_observation_ids=[ref, ref])


def test_rejects_unknown_categories():
    with pytest.raises(ValidationError):
        make_triage(category="remote_code_execution")


def test_rejects_empty_validation_questions():
    with pytest.raises(ValidationError):
        make_triage(validation_questions=[])
