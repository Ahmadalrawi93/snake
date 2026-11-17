"""Trust-boundary checks for model-generated observation triage."""
from collections.abc import Iterable
from uuid import UUID

from app.schemas.observation_triage import ObservationTriage


def validate_triage_references(
    triage: ObservationTriage,
    available_observation_ids: Iterable[str | UUID],
) -> ObservationTriage:
    """Reject model output that cites evidence outside the supplied observation set.

    This validates provenance only. It does not validate the security hypothesis,
    establish exploitability, or promote any record to a vulnerability finding.
    """
    allowed = {UUID(str(value)) for value in available_observation_ids}
    referenced = set(triage.supporting_observation_ids)
    if not referenced.issubset(allowed):
        raise ValueError("triage references observations outside its evidence context")
    return triage
