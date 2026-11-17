from datetime import datetime, timezone
from uuid import uuid4

from app.core.analysis_redaction import redact_analysis_context, redact_text
from app.core.analysis_context import build_analysis_context
from app.schemas.worker_results import WorkerObservation


def observation(kind, value, evidence):
    return WorkerObservation(
        observation_id=uuid4(), kind=kind, value=value, evidence=evidence,
        source="passive", observed_at=datetime.now(timezone.utc),
    )


def test_redacts_bearer_jwt_aws_and_key_value_secrets():
    text = "Authorization: Bearer abcdefghijklmnop password=hunter2 AKIA1234567890ABCDEF"
    result = redact_text(text)
    assert "abcdefghijklmnop" not in result
    assert "hunter2" not in result
    assert "AKIA1234567890ABCDEF" not in result


def test_redacts_sensitive_url_query_values_but_keeps_non_sensitive_parameters():
    item = observation("url", "https://example.test/path?token=abc123&lang=en", "observed")
    result = redact_analysis_context(build_analysis_context([item]))
    assert "abc123" not in result.groups[0].observations[0].value
    assert "lang=en" in result.groups[0].observations[0].value


def test_preserves_original_context_and_observation_provenance():
    item = observation("http_header", "Authorization: Bearer abcdefghijklmnop", "Cookie: session=secretvalue")
    original = build_analysis_context([item])
    safe = redact_analysis_context(original)
    assert "abcdefghijklmnop" in original.ungrouped[0].value
    assert "abcdefghijklmnop" not in safe.ungrouped[0].value
    assert safe.ungrouped[0].observation_ids == original.ungrouped[0].observation_ids
    assert "secretvalue" not in safe.ungrouped[0].evidence
