"""Offline passive-feed adapter for the isolated SNAKE worker.

This module performs no DNS, HTTP, socket, subprocess, or shell operations.
It accepts a pre-collected local JSON feed and emits only observations whose
hostname is covered by the task's signed scope manifest.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit
from uuid import UUID, uuid5

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, model_validator

from app.core.scope_policy import ScopePolicy, normalize_host
from app.core.worker_observation_signing import sign_worker_observation_batch
from app.core.worker_protocol import WorkerTaskEnvelope, ensure_not_expired
from app.core.worker_signing import worker_task_digest
from app.schemas.worker_results import WorkerObservation, WorkerObservationBatch, SignedWorkerObservationBatch

MAX_FEED_BYTES = 1024 * 1024
MAX_FEED_RECORDS = 500
_OBSERVATION_NAMESPACE = UUID("3d21ac5e-47a1-4b45-8db0-6d50a14c30c1")


class PassiveFeedRecord(BaseModel):
    """One externally collected, non-executable evidence item."""
    model_config = ConfigDict(extra="forbid", strict=True)

    hostname: str = Field(min_length=1, max_length=253)
    kind: Literal["hostname", "url", "dns_record", "technology", "http_header"]
    value: str = Field(min_length=1, max_length=2048, pattern=r"^[^\x00-\x1f\x7f]+$")
    evidence: str = Field(default="", max_length=8000)
    source: str = Field(min_length=1, max_length=80, pattern=r"^[a-zA-Z0-9._-]+$")
    observed_at: datetime

    @model_validator(mode="after")
    def validate_record(self):
        if any(ord(char) < 32 or ord(char) == 127 for char in self.value + self.evidence):
            raise ValueError("feed value and evidence must not contain control characters")
        if self.observed_at.tzinfo is None:
            raise ValueError("feed timestamp must be timezone-aware")
        host = normalize_host(self.hostname)
        if host != self.hostname.lower().rstrip("."):
            raise ValueError("feed hostname must be canonical")
        if self.kind == "hostname":
            if normalize_host(self.value) != host:
                raise ValueError("hostname observation value must match its hostname")
        elif self.kind == "url":
            parsed = urlsplit(self.value)
            if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
                raise ValueError("URL observation must be an absolute HTTP(S) URL")
            if parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment:
                raise ValueError("URL observation must not contain credentials, query, or fragment")
            _ = parsed.port
            if normalize_host(parsed.hostname) != host:
                raise ValueError("URL hostname does not match feed hostname")
        return self


_FEED_ADAPTER = TypeAdapter(list[PassiveFeedRecord])


def read_passive_feed(path: str | os.PathLike[str]) -> list[PassiveFeedRecord]:
    """Read a bounded, regular, non-symlink, non-group/world-writable JSON feed."""
    feed_path = Path(path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(feed_path, flags)
    except OSError as exc:
        raise ValueError("passive feed cannot be opened safely") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("passive feed must be a regular non-symlink file")
        if metadata.st_mode & 0o022:
            raise ValueError("passive feed must not be group- or world-writable")
        if metadata.st_size < 2 or metadata.st_size > MAX_FEED_BYTES:
            raise ValueError("passive feed size is outside the allowed range")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read(MAX_FEED_BYTES + 1)
        if len(raw) > MAX_FEED_BYTES:
            raise ValueError("passive feed exceeds the 1 MiB limit")
    finally:
        os.close(descriptor)
    records = _FEED_ADAPTER.validate_json(raw)
    if len(records) > MAX_FEED_RECORDS:
        raise ValueError("passive feed exceeds the 500 record limit")
    return records


def build_signed_passive_batch(
    task: WorkerTaskEnvelope,
    records: list[PassiveFeedRecord],
    *,
    worker_id: str,
    key_id: str,
    worker_private_key_b64: str,
    now: datetime | None = None,
) -> SignedWorkerObservationBatch | None:
    """Filter offline evidence against the signed scope and sign a bounded batch."""
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise ValueError("current time must be timezone-aware")
    current = current.astimezone(timezone.utc)
    ensure_not_expired(task, now=current)
    if task.execution_enabled is not False or not task.approved_scope_rules:
        raise ValueError("task must carry an approved signed scope manifest")
    if len(records) > MAX_FEED_RECORDS:
        raise ValueError("too many passive feed records")

    policy = ScopePolicy(task.approved_scope_rules)
    observations: list[WorkerObservation] = []
    seen: set[tuple[str, str, str, str, str]] = set()
    for record in records:
        host = normalize_host(record.hostname)
        if not policy.check_url("https://" + host).allowed:
            continue
        observed_at = record.observed_at.astimezone(timezone.utc)
        if observed_at > current:
            raise ValueError("passive feed contains a future observation")
        semantic_key = (
            record.kind, record.value, record.evidence, record.source,
            observed_at.isoformat(),
        )
        if semantic_key in seen:
            continue
        seen.add(semantic_key)
        stable_id = uuid5(
            _OBSERVATION_NAMESPACE,
            str(task.task_id) + "|" + hashlib.sha256(
                json.dumps(semantic_key, separators=(",", ":"), ensure_ascii=False).encode()
            ).hexdigest(),
        )
        observations.append(WorkerObservation(
            observation_id=stable_id,
            kind=record.kind,
            value=record.value,
            evidence=(record.evidence if record.kind in {"hostname", "url"}
                      else f"hostname={host}; {record.evidence}"),
            source=record.source,
            observed_at=observed_at,
        ))

    if not observations:
        return None
    batch = WorkerObservationBatch(
        task_id=task.task_id,
        envelope_sha256=worker_task_digest(task),
        worker_id=worker_id,
        key_id=key_id,
        collected_at=current,
        observations=observations,
        execution_enabled=False,
    )
    return sign_worker_observation_batch(batch, worker_private_key_b64)
