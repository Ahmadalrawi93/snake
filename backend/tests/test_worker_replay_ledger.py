from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest

from worker_replay_ledger import ReplayConflict, WorkerReplayLedger


def test_replay_returns_exact_ack_after_ledger_reopen(tmp_path):
    path = tmp_path / "worker-ledger.sqlite3"
    first = WorkerReplayLedger(path)
    ack, duplicate = first.get_or_create(
        task_id="task-1", envelope_sha256="a" * 64,
        worker_id="worker-1", key_id="key-1",
        create_acknowledgement=lambda: b'{"signed":"ack"}',
        validate_first_acceptance=lambda: None,
    )
    assert ack == b'{"signed":"ack"}'
    assert duplicate is False

    reopened = WorkerReplayLedger(path)
    replay, duplicate = reopened.get_or_create(
        task_id="task-1", envelope_sha256="a" * 64,
        worker_id="worker-1", key_id="key-1",
        create_acknowledgement=lambda: pytest.fail("must return stored ack"),
        validate_first_acceptance=lambda: pytest.fail("must not revalidate expiry"),
    )
    assert replay == ack
    assert duplicate is True


def test_same_task_id_with_different_digest_or_identity_is_rejected(tmp_path):
    ledger = WorkerReplayLedger(tmp_path / "ledger.sqlite3")
    ledger.get_or_create(
        task_id="task-1", envelope_sha256="a" * 64,
        worker_id="worker-1", key_id="key-1",
        create_acknowledgement=lambda: b"ack",
        validate_first_acceptance=lambda: None,
    )
    with pytest.raises(ReplayConflict):
        ledger.get_or_create(
            task_id="task-1", envelope_sha256="b" * 64,
            worker_id="worker-1", key_id="key-1",
            create_acknowledgement=lambda: b"other",
            validate_first_acceptance=lambda: None,
        )
    with pytest.raises(ReplayConflict):
        ledger.get_or_create(
            task_id="task-1", envelope_sha256="a" * 64,
            worker_id="worker-2", key_id="key-1",
            create_acknowledgement=lambda: b"other",
            validate_first_acceptance=lambda: None,
        )


def test_concurrent_duplicate_delivery_creates_one_ack(tmp_path):
    ledger_path = tmp_path / "ledger.sqlite3"
    barrier = Barrier(8)
    ledgers = [WorkerReplayLedger(ledger_path) for _ in range(8)]

    def deliver(index):
        ledger = ledgers[index]
        barrier.wait()
        return ledger.get_or_create(
            task_id="task-concurrent", envelope_sha256="c" * 64,
            worker_id="worker-1", key_id="key-1",
            create_acknowledgement=lambda: b"one-canonical-ack",
            validate_first_acceptance=lambda: None,
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(deliver, range(8)))
    assert {ack for ack, _ in results} == {b"one-canonical-ack"}
    assert sum(not duplicate for _, duplicate in results) == 1
    assert sum(duplicate for _, duplicate in results) == 7
