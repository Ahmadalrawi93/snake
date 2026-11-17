"""Periodic passive-feed refresh loop, separate from the isolated worker.

The scheduler contacts only the fixed passive providers implemented by
collect_passive_feed. It never probes discovered hosts. A failed refresh keeps
the last known-good feed intact.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import time
from pathlib import Path
from typing import Callable

from asset_intelligence_history import update_history

from collect_passive_feed import (
    MAX_FEED_RECORDS,
    collect_ct_feed,
    collect_dnsdb_feed,
    load_scope,
    write_feed,
)

LOG = logging.getLogger("snake.passive_scheduler")
MIN_INTERVAL_SECONDS = 15 * 60
MAX_INTERVAL_SECONDS = 7 * 24 * 60 * 60


def run_cycle(
    scope_file: str,
    output_file: str,
    providers: list[str],
    authorization_reference: str,
    *,
    ct_collector: Callable = collect_ct_feed,
    dnsdb_collector: Callable = collect_dnsdb_feed,
    environ: dict[str, str] | None = None,
    history_db: str | None = None,
) -> int:
    """Build a fresh feed and atomically publish it only after all sources succeed."""
    if not providers or len(set(providers)) != len(providers) or any(p not in {"ct", "dnsdb"} for p in providers):
        raise ValueError("providers must be a non-empty unique list of supported sources")
    env = os.environ if environ is None else environ
    scope_rules = load_scope(scope_file)  # reload every cycle; scope changes take effect
    records: list[dict[str, str]] = []
    per_provider_limit = MAX_FEED_RECORDS // len(providers)
    for provider in providers:
        if provider == "ct":
            records.extend(ct_collector(scope_rules)[:per_provider_limit])
        elif provider == "dnsdb":
            api_key = env.get("DNSDB_API_KEY", "")
            if not api_key:
                raise ValueError("DNSDB_API_KEY is required for DNSDB refresh")
            records.extend(dnsdb_collector(scope_rules, api_key)[:per_provider_limit])
        else:
            raise ValueError("unsupported passive provider")
    records = records[:MAX_FEED_RECORDS]
    # Audit reference is deliberately metadata only and never changes trust.
    if not authorization_reference or len(authorization_reference) > 200:
        raise ValueError("invalid authorization audit reference")
    write_feed(output_file, records)
    if history_db:
        changes = update_history(history_db, records)
        LOG.info("asset history updated; changes=%d", len(changes))
    return len(records)


def _acquire_lock(path: str):
    """Acquire an exclusive process lock; reject symlink lock paths."""
    import fcntl

    lock_path = Path(path)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(lock_path, flags, 0o600)
    info = os.fstat(fd)
    if not __import__("stat").S_ISREG(info.st_mode):
        os.close(fd)
        raise ValueError("scheduler lock must be a regular file")
    os.fchmod(fd, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd)
        raise RuntimeError("another passive scheduler instance is already running")
    return fd


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Periodically refresh SNAKE passive intelligence feeds")
    parser.add_argument("--scope-file", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--provider", action="append", choices=["ct", "dnsdb"])
    parser.add_argument("--authorization-reference", required=True)
    parser.add_argument("--interval-seconds", type=int, default=6 * 60 * 60)
    parser.add_argument("--lock-file", help="defaults to OUTPUT.scheduler.lock")
    parser.add_argument("--history-db", help="SQLite asset history path; defaults to OUTPUT.history.sqlite3")
    args = parser.parse_args(argv)
    if not args.authorization_reference.strip() or len(args.authorization_reference) > 200:
        parser.error("authorization reference must be 1-200 characters")
    if not MIN_INTERVAL_SECONDS <= args.interval_seconds <= MAX_INTERVAL_SECONDS:
        parser.error("interval must be between 900 seconds and 7 days")
    providers = list(dict.fromkeys(args.provider or ["ct"]))
    lock_path = args.lock_file or args.output + ".scheduler.lock"
    try:
        lock_fd = _acquire_lock(lock_path)
    except (OSError, ValueError, RuntimeError) as exc:
        LOG.error("scheduler lock unavailable: %s", exc)
        return 2

    stopping = False

    def stop(_signum, _frame):
        nonlocal stopping
        stopping = True

    previous_handlers = {}
    for signum in (signal.SIGTERM, signal.SIGINT):
        previous_handlers[signum] = signal.signal(signum, stop)

    LOG.info("passive scheduler started; providers=%s interval_seconds=%d", ",".join(providers), args.interval_seconds)
    try:
        while not stopping:
            started = time.monotonic()
            try:
                count = run_cycle(
                    args.scope_file, args.output, providers,
                    args.authorization_reference,
                    history_db=args.history_db or args.output + ".history.sqlite3",
                )
                LOG.info("passive feed refreshed; records=%d", count)
            except Exception as exc:
                # Do not print provider response bodies, credentials, or tracebacks.
                LOG.error("passive feed refresh failed; previous feed retained (%s)", type(exc).__name__)
            remaining = max(0.0, args.interval_seconds - (time.monotonic() - started))
            deadline = time.monotonic() + remaining
            while not stopping and time.monotonic() < deadline:
                time.sleep(min(1.0, deadline - time.monotonic()))
    finally:
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)
        os.close(lock_fd)
        LOG.info("passive scheduler stopped")
    return 0


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    raise SystemExit(main())
