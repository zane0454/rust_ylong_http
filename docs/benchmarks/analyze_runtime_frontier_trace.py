#!/usr/bin/env python3
"""Analyze ylong_runtime S9F runtime-frontier JSONL traces."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            events.append(json.loads(line))
    return events


def analyze_lines(lines: list[str]) -> dict[str, Any]:
    events = [json.loads(line) for line in lines if line.strip()]
    return analyze_events(events)


def analyze_events(events: list[dict[str, Any]]) -> dict[str, Any]:
    last_poll_worker: dict[int, int | None] = {}
    pending: dict[int, dict[str, Any]] = {}
    chains: list[dict[str, Any]] = []
    io_wake_enqueue_chains = 0

    for event in sorted(events, key=lambda item: int(item.get("ts_ns", 0))):
        task_id = event.get("task_id")
        if task_id is None:
            continue
        task_id = int(task_id)
        name = event.get("event")

        if name == "task_poll_enter":
            chain = pending.pop(task_id, None)
            if chain is not None:
                next_poll_worker = event.get("worker_id")
                next_poll_worker = int(next_poll_worker) if next_poll_worker is not None else None
                chain["next_poll_worker_id"] = next_poll_worker
                chain["wake_to_next_poll_ns"] = int(event.get("ts_ns", 0)) - chain["wake_ts_ns"]
                chain["locality_mismatch"] = has_locality_mismatch(chain)
                chains.append(public_chain(chain))
            worker_id = event.get("worker_id")
            last_poll_worker[task_id] = int(worker_id) if worker_id is not None else None
            continue

        if name == "task_wake_enqueue" and event.get("wake_origin") == "io_readiness":
            io_wake_enqueue_chains += 1
            worker_id = event.get("worker_id")
            pending[task_id] = {
                "task_id": task_id,
                "wake_ts_ns": int(event.get("ts_ns", 0)),
                "last_poll_worker_id": last_poll_worker.get(task_id),
                "wake_worker_id": int(worker_id) if worker_id is not None else None,
                "enqueue_worker_id": None,
                "target_worker_id": None,
                "next_poll_worker_id": None,
                "wake_to_next_poll_ns": None,
            }
            continue

        if name in {
            "scheduler_enqueue_local",
            "scheduler_enqueue_global",
            "scheduler_enqueue_lifo",
            "scheduler_enqueue_io_affine",
            "scheduler_enqueue_io_home",
        }:
            chain = pending.get(task_id)
            if chain is None:
                continue
            worker_id = event.get("worker_id")
            target_worker_id = event.get("target_worker_id")
            chain["enqueue_worker_id"] = int(worker_id) if worker_id is not None else None
            chain["target_worker_id"] = (
                int(target_worker_id) if target_worker_id is not None else None
            )

    mismatch_count = sum(1 for chain in chains if chain["locality_mismatch"])
    complete_count = len(chains)
    return {
        "io_wake_enqueue_chains": io_wake_enqueue_chains,
        "complete_chains": complete_count,
        "incomplete_chains": len(pending),
        "locality_mismatches": mismatch_count,
        "mismatch_ratio": mismatch_count / complete_count if complete_count else 0.0,
        "chains": chains,
    }


def has_locality_mismatch(chain: dict[str, Any]) -> bool:
    last_poll_worker = chain.get("last_poll_worker_id")
    next_poll_worker = chain.get("next_poll_worker_id")
    target_worker = chain.get("target_worker_id")
    enqueue_worker = chain.get("enqueue_worker_id")

    if last_poll_worker is None:
        return False
    if next_poll_worker is not None and next_poll_worker != last_poll_worker:
        return True
    if target_worker is not None and target_worker != last_poll_worker:
        return True
    if target_worker is None and enqueue_worker is not None and enqueue_worker != last_poll_worker:
        return True
    return False


def public_chain(chain: dict[str, Any]) -> dict[str, Any]:
    return {
        "task_id": chain["task_id"],
        "last_poll_worker_id": chain["last_poll_worker_id"],
        "wake_worker_id": chain["wake_worker_id"],
        "enqueue_worker_id": chain["enqueue_worker_id"],
        "target_worker_id": chain["target_worker_id"],
        "next_poll_worker_id": chain["next_poll_worker_id"],
        "wake_to_next_poll_ns": chain["wake_to_next_poll_ns"],
        "locality_mismatch": chain["locality_mismatch"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("runtime_trace", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    summary = analyze_events(load_jsonl(args.runtime_trace))
    payload = json.dumps(summary, indent=2, sort_keys=True)
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload + "\n", encoding="utf-8")
    else:
        print(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
