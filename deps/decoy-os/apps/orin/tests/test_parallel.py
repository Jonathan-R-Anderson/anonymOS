# Copyright (C) 2026 Musa Jaradat
# Licensed under GNU AGPLv3
"""
Unit tests for orin.collectors.parallel
"""
import time
import unittest
from concurrent.futures import TimeoutError as FuturesTimeoutError
from unittest.mock import patch, MagicMock, call

from orin.collectors.parallel import (
    CollectorTask,
    CollectorResult,
    ParallelCollector,
    _execute_collector,
    gather_parallel_system_state,
)


class TestCollectorTask(unittest.TestCase):
    def test_defaults(self):
        def dummy():
            pass

        task = CollectorTask(name="test", func=dummy)
        self.assertEqual(task.name, "test")
        self.assertEqual(task.func, dummy)
        self.assertEqual(task.args, tuple())
        self.assertEqual(task.kwargs, dict())
        self.assertAlmostEqual(task.timeout, 300.0)
        self.assertEqual(task.priority, 10)

    def test_custom_values(self):
        f = lambda: None
        task = CollectorTask(
            name="custom",
            func=f,
            args=(1, 2),
            kwargs={"key": "val"},
            timeout=60.0,
            priority=1,
        )
        self.assertEqual(task.args, (1, 2))
        self.assertEqual(task.timeout, 60.0)
        self.assertEqual(task.priority, 1)


class TestCollectorResult(unittest.TestCase):
    def test_defaults(self):
        result = CollectorResult(name="test", success=True)
        self.assertIsNone(result.data)
        self.assertIsNone(result.error)
        self.assertAlmostEqual(result.duration, 0.0)
        self.assertFalse(result.timed_out)

    def test_failure_result(self):
        result = CollectorResult(
            name="failed",
            success=False,
            error="Some error occurred",
            duration=1.5,
            timed_out=False,
        )
        self.assertFalse(result.success)
        self.assertEqual(result.error, "Some error occurred")


class TestExecuteCollector(unittest.TestCase):
    def test_successful_execution(self):
        def good_func(x, y):
            return x + y

        task = CollectorTask(name="add", func=good_func, args=(3, 4))
        result = _execute_collector(task)

        self.assertTrue(result.success)
        self.assertEqual(result.data, 7)
        self.assertIsNone(result.error)
        self.assertGreaterEqual(result.duration, 0.0)

    def test_failed_execution(self):
        def bad_func():
            raise ValueError("Something went wrong")

        task = CollectorTask(name="bad", func=bad_func)
        result = _execute_collector(task)

        self.assertFalse(result.success)
        self.assertIsNone(result.data)
        self.assertIn("ValueError", result.error)
        self.assertIn("Something went wrong", result.error)

    def test_execution_with_kwargs(self):
        def func_with_kwargs(name="world"):
            return f"hello {name}"

        task = CollectorTask(name="greeting", func=func_with_kwargs, kwargs={"name": "orin"})
        result = _execute_collector(task)

        self.assertTrue(result.success)
        self.assertEqual(result.data, "hello orin")

    def test_execution_duration_measured(self):
        def slow_func():
            time.sleep(0.05)
            return "done"

        task = CollectorTask(name="slow", func=slow_func)
        result = _execute_collector(task)

        self.assertTrue(result.success)
        self.assertGreaterEqual(result.duration, 0.04)


class TestParallelCollector(unittest.TestCase):
    def setUp(self):
        self.collector = ParallelCollector(max_workers=2, default_timeout=30.0)

    def test_init_defaults(self):
        pc = ParallelCollector()
        self.assertGreater(pc.max_workers, 0)
        self.assertAlmostEqual(pc.default_timeout, 300.0)
        self.assertEqual(pc.tasks, [])
        self.assertEqual(pc.results, {})

    def test_init_custom_workers(self):
        pc = ParallelCollector(max_workers=8)
        self.assertEqual(pc.max_workers, 8)

    def test_add_task_basic(self):
        self.collector.add_task("task1", lambda: None)
        self.assertEqual(len(self.collector.tasks), 1)
        self.assertEqual(self.collector.tasks[0].name, "task1")

    def test_add_task_with_args_kwargs(self):
        def func(a, b, key=None):
            return (a, b, key)

        self.collector.add_task("task_args", func, 1, 2, key="val", timeout=10.0)
        task = self.collector.tasks[0]
        self.assertEqual(task.args, (1, 2))
        self.assertEqual(task.kwargs, {"key": "val"})
        self.assertEqual(task.timeout, 10.0)

    def test_add_task_sorted_by_priority(self):
        self.collector.add_task("low", lambda: None, priority=20)
        self.collector.add_task("high", lambda: None, priority=1)
        self.collector.add_task("mid", lambda: None, priority=10)

        priorities = [t.priority for t in self.collector.tasks]
        self.assertEqual(priorities, sorted(priorities))

    def test_add_task_uses_default_timeout(self):
        self.collector.add_task("t", lambda: None)
        self.assertAlmostEqual(self.collector.tasks[0].timeout, 30.0)

    def test_clear_tasks(self):
        self.collector.add_task("task1", lambda: None)
        self.collector.add_task("task2", lambda: None)
        self.collector.clear_tasks()
        self.assertEqual(self.collector.tasks, [])

    def test_run_no_tasks(self):
        results = self.collector.run()
        self.assertEqual(results, {})

    def test_run_successful_tasks(self):
        self.collector.add_task("add_one", lambda: [1, 2, 3])
        self.collector.add_task("add_two", lambda: {"a": 1})
        results = self.collector.run()

        self.assertIn("add_one", results)
        self.assertIn("add_two", results)
        self.assertTrue(results["add_one"].success)
        self.assertTrue(results["add_two"].success)
        self.assertEqual(results["add_one"].data, [1, 2, 3])

    def test_run_failing_task(self):
        def fail():
            raise RuntimeError("collector failed")

        self.collector.add_task("broken", fail)
        results = self.collector.run()

        self.assertIn("broken", results)
        self.assertFalse(results["broken"].success)
        self.assertIn("RuntimeError", results["broken"].error)

    def test_run_mixed_tasks(self):
        self.collector.add_task("good", lambda: [1, 2])
        self.collector.add_task("bad", lambda: 1 / 0)
        results = self.collector.run()

        self.assertTrue(results["good"].success)
        self.assertFalse(results["bad"].success)

    def test_run_with_progress_callback(self):
        callback = MagicMock()
        self.collector.add_task("t1", lambda: None)
        self.collector.add_task("t2", lambda: None)
        self.collector.run(progress_callback=callback)

        self.assertEqual(callback.call_count, 2)

    def test_get_successful_results(self):
        self.collector.add_task("good", lambda: [1, 2, 3])
        self.collector.add_task("bad", lambda: 1 / 0)
        self.collector.run()

        successful = self.collector.get_successful_results()
        self.assertIn("good", successful)
        self.assertNotIn("bad", successful)
        self.assertEqual(successful["good"], [1, 2, 3])

    def test_get_failed_results(self):
        self.collector.add_task("good", lambda: "ok")
        self.collector.add_task("bad", lambda: 1 / 0)
        self.collector.run()

        failed = self.collector.get_failed_results()
        self.assertNotIn("good", failed)
        self.assertIn("bad", failed)

    def test_get_summary_empty(self):
        summary = self.collector.get_summary()
        self.assertEqual(summary["total_tasks"], 0)
        self.assertEqual(summary["successful"], 0)

    def test_get_summary_after_run(self):
        self.collector.add_task("good", lambda: [1, 2])
        self.collector.add_task("bad", lambda: 1 / 0)
        self.collector.run()

        summary = self.collector.get_summary()
        self.assertEqual(summary["total_tasks"], 2)
        self.assertEqual(summary["successful"], 1)
        self.assertEqual(summary["failed"], 1)
        self.assertIn("good", summary["collectors"])
        self.assertIn("bad", summary["collectors"])
        self.assertTrue(summary["collectors"]["good"]["success"])
        self.assertFalse(summary["collectors"]["bad"]["success"])

    def test_get_summary_data_size(self):
        self.collector.add_task("list_task", lambda: [1, 2, 3, 4, 5])
        self.collector.run()

        summary = self.collector.get_summary()
        self.assertEqual(summary["collectors"]["list_task"]["data_size"], 5)

    def test_get_summary_scalar_data(self):
        """Scalar (non-len-able) data should have None data_size."""
        self.collector.add_task("scalar", lambda: 42)
        self.collector.run()

        summary = self.collector.get_summary()
        self.assertIsNone(summary["collectors"]["scalar"]["data_size"])


class TestGatherParallelSystemState(unittest.TestCase):
    def test_with_custom_collectors(self):
        collectors = {
            "proc_list": lambda: [1, 2, 3],
            "user_list": lambda: ["root", "admin"],
        }
        successful, failed = gather_parallel_system_state(
            collectors=collectors,
            max_workers=2,
            timeout=30.0,
        )
        self.assertIn("proc_list", successful)
        self.assertIn("user_list", successful)
        self.assertEqual(successful["proc_list"], [1, 2, 3])
        self.assertEqual(successful["user_list"], ["root", "admin"])
        self.assertEqual(failed, {})

    def test_with_failing_collector(self):
        collectors = {
            "good": lambda: [1],
            "fail": lambda: (_ for _ in ()).throw(Exception("boom")),
        }
        # The lambda above doesn't work cleanly; use a proper def
        def failing_collector():
            raise RuntimeError("test failure")

        collectors = {
            "good": lambda: [1],
            "fail": failing_collector,
        }
        successful, failed = gather_parallel_system_state(
            collectors=collectors,
            max_workers=2,
            timeout=30.0,
        )
        self.assertIn("good", successful)
        self.assertIn("fail", failed)

    def test_with_progress_callback(self):
        callback = MagicMock()
        collectors = {"c1": lambda: None, "c2": lambda: None}
        gather_parallel_system_state(
            collectors=collectors,
            max_workers=2,
            timeout=30.0,
            progress_callback=callback,
        )
        self.assertEqual(callback.call_count, 2)

    def test_returns_tuple(self):
        result = gather_parallel_system_state(
            collectors={"c": lambda: None},
            max_workers=1,
            timeout=5.0,
        )
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 2)


if __name__ == "__main__":
    unittest.main()
