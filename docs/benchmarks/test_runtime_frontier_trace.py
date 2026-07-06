#!/usr/bin/env python3
"""Tests for S9F runtime-frontier trace analysis."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("analyze_runtime_frontier_trace.py")
SPEC = importlib.util.spec_from_file_location("analyze_runtime_frontier_trace", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
analyzer = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = analyzer
SPEC.loader.exec_module(analyzer)


class RuntimeFrontierTraceTest(unittest.TestCase):
    def test_analyze_lines_links_io_wake_to_enqueue_and_next_poll(self) -> None:
        lines = [
            '{"ts_ns":1,"event":"task_poll_enter","thread":"ThreadId(1)",'
            '"worker_id":2,"task_id":4660}',
            '{"ts_ns":2,"event":"task_wake_enqueue","thread":"ThreadId(4)",'
            '"worker_id":5,"task_id":4660,"wake_origin":"io_readiness",'
            '"lifo":false}',
            '{"ts_ns":3,"event":"scheduler_enqueue_local","thread":"ThreadId(4)",'
            '"worker_id":5,"target_worker_id":5,"task_id":4660,'
            '"wake_origin":"io_readiness","lifo":false}',
            '{"ts_ns":4,"event":"task_poll_enter","thread":"ThreadId(4)",'
            '"worker_id":5,"task_id":4660}',
        ]

        summary = analyzer.analyze_lines(lines)

        self.assertEqual(summary["io_wake_enqueue_chains"], 1)
        self.assertEqual(summary["complete_chains"], 1)
        self.assertEqual(summary["locality_mismatches"], 1)
        self.assertEqual(summary["mismatch_ratio"], 1.0)
        self.assertEqual(
            summary["chains"][0],
            {
                "task_id": 4660,
                "last_poll_worker_id": 2,
                "wake_worker_id": 5,
                "enqueue_worker_id": 5,
                "target_worker_id": 5,
                "next_poll_worker_id": 5,
                "wake_to_next_poll_ns": 2,
                "locality_mismatch": True,
            },
        )

    def test_analyze_lines_accepts_io_affine_enqueue(self) -> None:
        lines = [
            '{"ts_ns":1,"event":"task_poll_enter","thread":"ThreadId(1)",'
            '"worker_id":2,"task_id":4660}',
            '{"ts_ns":2,"event":"task_wake_enqueue","thread":"ThreadId(4)",'
            '"worker_id":5,"task_id":4660,"wake_origin":"io_readiness",'
            '"lifo":false}',
            '{"ts_ns":3,"event":"scheduler_enqueue_io_affine","thread":"ThreadId(4)",'
            '"worker_id":5,"target_worker_id":2,"task_id":4660,'
            '"wake_origin":"io_readiness","lifo":false}',
            '{"ts_ns":4,"event":"task_poll_enter","thread":"ThreadId(1)",'
            '"worker_id":2,"task_id":4660}',
        ]

        summary = analyzer.analyze_lines(lines)

        self.assertEqual(summary["io_wake_enqueue_chains"], 1)
        self.assertEqual(summary["complete_chains"], 1)
        self.assertEqual(summary["locality_mismatches"], 0)
        self.assertEqual(summary["chains"][0]["enqueue_worker_id"], 5)
        self.assertEqual(summary["chains"][0]["target_worker_id"], 2)

    def test_analyze_lines_accepts_io_home_enqueue(self) -> None:
        lines = [
            '{"ts_ns":1,"event":"task_poll_enter","thread":"ThreadId(1)",'
            '"worker_id":2,"task_id":4660}',
            '{"ts_ns":2,"event":"task_wake_enqueue","thread":"ThreadId(4)",'
            '"worker_id":5,"task_id":4660,"wake_origin":"io_readiness",'
            '"lifo":false}',
            '{"ts_ns":3,"event":"scheduler_enqueue_io_home","thread":"ThreadId(4)",'
            '"worker_id":5,"target_worker_id":2,"task_id":4660,'
            '"wake_origin":"io_readiness","lifo":false}',
            '{"ts_ns":4,"event":"task_poll_enter","thread":"ThreadId(1)",'
            '"worker_id":2,"task_id":4660}',
        ]

        summary = analyzer.analyze_lines(lines)

        self.assertEqual(summary["io_wake_enqueue_chains"], 1)
        self.assertEqual(summary["complete_chains"], 1)
        self.assertEqual(summary["locality_mismatches"], 0)
        self.assertEqual(summary["chains"][0]["enqueue_worker_id"], 5)
        self.assertEqual(summary["chains"][0]["target_worker_id"], 2)


if __name__ == "__main__":
    unittest.main()
