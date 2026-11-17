"""Deterministic redaction for secrets before external model transmission."""
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from app.schemas.analysis_context import AnalysisContext, ContextObservation, ObservationGroup


_PATTERNS = [
    (re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}"), r"\1 [REDACTED]"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), "[REDACTED_JWT]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED_AWS_KEY]"),
    (re.compile(r"(?im)-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "[REDACTED_PRIVATE_KEY]"),
    (re.compile(r"(?i)\b(password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|authorization|cookie|set-cookie)\s*[:=]\s*([^\s&,;]+)"), r"\1=[REDACTED]"),
]
_SENSITIVE_QUERY = {"token", "access_token", "refresh_token", "api_key", "apikey", "key", "password", "secret", "code"}


def redact_text(value: str) -> str:
    result = value
    for pattern, replacement in _PATTERNS:
        result = pattern.sub(replacement, result)
    return result


def redact_url(value: str) -> str:
    try:
        parts = urlsplit(value)
        if not parts.scheme or not parts.netloc or not parts.query:
            return redact_text(value)
        query = [
            (key, "[REDACTED]" if key.lower() in _SENSITIVE_QUERY else val)
            for key, val in parse_qsl(parts.query, keep_blank_values=True)
        ]
        return redact_text(urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment)))
    except ValueError:
        return redact_text(value)


def redact_analysis_context(context: AnalysisContext) -> AnalysisContext:
    """Return a copy with common credential patterns removed, preserving provenance."""
    def clean(item: ContextObservation) -> ContextObservation:
        value = redact_url(item.value) if item.kind == "url" else redact_text(item.value)
        return item.model_copy(update={"value": value, "evidence": redact_text(item.evidence)})

    groups = [
        ObservationGroup(host_key=group.host_key, observations=[clean(item) for item in group.observations])
        for group in context.groups
    ]
    ungrouped = [clean(item) for item in context.ungrouped]
    return context.model_copy(update={"groups": groups, "ungrouped": ungrouped})
