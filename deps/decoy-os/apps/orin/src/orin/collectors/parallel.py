# Copyright (C) 2026 Musa Jaradat
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
# orin/collectors/parallel.py
"""
orin.collectors.parallel – Thread Pool Executor for Independent Collectors
==========================================================================
Provides parallel execution capabilities for system telemetry collectors
that can safely run concurrently without shared state dependencies.

This module implements:
- Thread pool executor for independent collectors
- Timeout configuration per collector
- Error resilience and partial result capture
- Progress tracking during parallel collection
"""
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeoutError
from typing import Callable, Dict, Any, Optional, Tuple, List
from dataclasses import dataclass, field

from orin.core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class CollectorTask:
    """Represents a collector function to be executed in parallel.

    Attributes
    ----------
    name : str
        Human-readable name for this collector task.
    func : Callable
        The collector function to execute (e.g., gather_active_processes).
    args : tuple
        Positional arguments to pass to the collector function.
    kwargs : dict
        Keyword arguments to pass to the collector function.
    timeout : float
        Maximum execution time in seconds before timing out.
    priority : int
        Execution priority (lower = higher priority). Used for ordering.
    """
    name: str
    func: Callable
    args: tuple = field(default_factory=tuple)
    kwargs: dict = field(default_factory=dict)
    timeout: float = 300.0  # Default 5 minutes
    priority: int = 10


@dataclass
class CollectorResult:
    """Result from executing a collector task.

    Attributes
    ----------
    name : str
        Name of the collector task.
    success : bool
        Whether the collector completed successfully.
    data : Any
        The collected data if successful, None otherwise.
    error : Optional[str]
        Error message if failed, None if successful.
    duration : float
        Execution time in seconds.
    timed_out : bool
        Whether the collector timed out.
    """
    name: str
    success: bool
    data: Any = None
    error: Optional[str] = None
    duration: float = 0.0
    timed_out: bool = False


def _execute_collector(task: CollectorTask) -> CollectorResult:
    """Execute a single collector task with timeout handling.

    This function runs in a worker thread and captures any exceptions
    or timeouts that occur during collection.

    Parameters
    ----------
    task : CollectorTask
        The collector task to execute.

    Returns
    -------
    CollectorResult
        Result containing collected data or error information.
    """
    start_time = time.perf_counter()

    try:
        logger.debug(f"Starting collector: {task.name}")
        data = task.func(*task.args, **task.kwargs)
        duration = time.perf_counter() - start_time

        logger.debug(f"Collector {task.name} completed in {duration:.2f}s")
        return CollectorResult(
            name=task.name,
            success=True,
            data=data,
            duration=duration
        )

    except Exception as e:
        duration = time.perf_counter() - start_time
        error_msg = f"{type(e).__name__}: {str(e)}"
        logger.error(f"Collector {task.name} failed: {error_msg}")

        return CollectorResult(
            name=task.name,
            success=False,
            error=error_msg,
            duration=duration
        )


class ParallelCollector:
    """Manages parallel execution of independent collectors.

    This class provides a thread pool executor for running multiple
    collectors concurrently, with support for timeouts, progress
    tracking, and error resilience.

    Examples
    --------
    >>> from orin.collectors.processes import gather_active_processes
    >>> from orin.collectors.connections import gather_listening_ports
    >>>
    >>> collector = ParallelCollector(max_workers=4)
    >>> collector.add_task("processes", gather_active_processes)
    >>> collector.add_task("ports", gather_listening_ports)
    >>> results = collector.run()
    >>>
    >>> for name, result in results.items():
    ...     if result.success:
    ...         print(f"{name}: collected {len(result.data)} items")
    ...     else:
    ...         print(f"{name}: failed - {result.error}")
    """

    def __init__(self, max_workers: Optional[int] = None,
                 default_timeout: float = 300.0):
        """Initialize the parallel collector.

        Parameters
        ----------
        max_workers : int, optional
            Maximum number of worker threads. Defaults to CPU count + 4.
        default_timeout : float
            Default timeout in seconds for collectors without explicit timeout.
        """
        if max_workers is None:
            # Default to CPU count + 4, similar to ThreadPoolExecutor default
            max_workers = min(32, (os.cpu_count() or 1) + 4)

        self.max_workers = max_workers
        self.default_timeout = default_timeout
        self.tasks: List[CollectorTask] = []
        self.results: Dict[str, CollectorResult] = {}

        logger.info(f"ParallelCollector initialized with {max_workers} workers")

    def add_task(self, name: str, func: Callable,
                 *args, timeout: Optional[float] = None,
                 priority: int = 10, **kwargs) -> None:
        """Add a collector task to the execution queue.

        Parameters
        ----------
        name : str
            Human-readable name for this task.
        func : Callable
            The collector function to execute.
        *args
            Positional arguments for the collector function.
        timeout : float, optional
            Maximum execution time in seconds. Uses default if not specified.
        priority : int
            Execution priority (lower = higher priority).
        **kwargs
            Keyword arguments for the collector function.
        """
        task = CollectorTask(
            name=name,
            func=func,
            args=args,
            kwargs=kwargs,
            timeout=timeout if timeout is not None else self.default_timeout,
            priority=priority
        )

        # Sort tasks by priority before adding
        self.tasks.append(task)
        self.tasks.sort(key=lambda t: t.priority)

        logger.debug(f"Added task: {name} (timeout={task.timeout}s, priority={priority})")

    def clear_tasks(self) -> None:
        """Clear all pending tasks from the queue."""
        self.tasks.clear()
        logger.debug("Cleared all pending tasks")

    def run(self, progress_callback: Optional[Callable[[str, int, int], None]] = None
            ) -> Dict[str, CollectorResult]:
        """Execute all collector tasks in parallel.

        Parameters
        ----------
        progress_callback : callable, optional
            Callback function called with (collector_name, completed, total)
            after each collector completes. Useful for progress reporting.

        Returns
        -------
        dict
            Dictionary mapping collector names to their CollectorResult objects.
        """
        if not self.tasks:
            logger.warning("No tasks to execute")
            return {}

        total_tasks = len(self.tasks)
        completed = 0
        self.results = {}

        logger.info(f"Starting parallel collection of {total_tasks} tasks with {self.max_workers} workers")
        start_time = time.perf_counter()

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all tasks
            future_to_task = {
                executor.submit(_execute_collector, task): task
                for task in self.tasks
            }

            # Collect results as they complete
            # Use a generous overall timeout to allow all tasks to complete or timeout individually
            overall_timeout = max(task.timeout for task in self.tasks) * 1.5 if self.tasks else self.default_timeout * 2
            try:
                for future in as_completed(future_to_task, timeout=overall_timeout):
                    task = future_to_task[future]

                    try:
                        result = future.result(timeout=task.timeout)
                        self.results[task.name] = result

                        if result.timed_out:
                            logger.warning(f"Collector {task.name} timed out after {task.timeout}s")
                        elif not result.success:
                            logger.warning(f"Collector {task.name} failed: {result.error}")
                        else:
                            data_size = len(result.data) if hasattr(result.data, '__len__') else 1
                            logger.info(f"Collector {task.name} succeeded: {data_size} items in {result.duration:.2f}s")

                    except FuturesTimeoutError:
                        logger.error(f"Collector {task.name} exceeded timeout of {task.timeout}s")
                        self.results[task.name] = CollectorResult(
                            name=task.name,
                            success=False,
                            error=f"Timeout after {task.timeout}s",
                            duration=task.timeout,
                            timed_out=True
                        )

                    except Exception as e:
                        logger.error(f"Unexpected error collecting {task.name}: {e}")
                        self.results[task.name] = CollectorResult(
                            name=task.name,
                            success=False,
                            error=f"Unexpected error: {type(e).__name__}: {str(e)}",
                            duration=time.perf_counter() - start_time
                        )

                    completed += 1
                    if progress_callback:
                        progress_callback(task.name, completed, total_tasks)
            except FuturesTimeoutError:
                # Overall timeout exceeded - mark remaining tasks as timed out
                logger.error(f"Overall collection timeout exceeded ({overall_timeout}s). Cancelling remaining tasks.")
                for future, task in future_to_task.items():
                    if task.name not in self.results:
                        logger.error(f"Collector {task.name} cancelled due to overall timeout")
                        self.results[task.name] = CollectorResult(
                            name=task.name,
                            success=False,
                            error=f"Cancelled: overall timeout after {overall_timeout}s",
                            duration=overall_timeout,
                            timed_out=True
                        )
                        completed += 1
                        if progress_callback:
                            progress_callback(task.name, completed, total_tasks)

        total_duration = time.perf_counter() - start_time
        success_count = sum(1 for r in self.results.values() if r.success)

        logger.info(f"Parallel collection completed: {success_count}/{total_tasks} successful in {total_duration:.2f}s")

        return self.results

    def get_successful_results(self) -> Dict[str, Any]:
        """Extract only successful results as raw data.

        Returns
        -------
        dict
            Dictionary mapping collector names to their collected data.
            Only includes successful collections.
        """
        return {
            name: result.data
            for name, result in self.results.items()
            if result.success and result.data is not None
        }

    def get_failed_results(self) -> Dict[str, str]:
        """Extract only failed results with error messages.

        Returns
        -------
        dict
            Dictionary mapping collector names to their error messages.
            Only includes failed collections.
        """
        return {
            name: result.error
            for name, result in self.results.items()
            if not result.success
        }

    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of the collection run.

        Returns
        -------
        dict
            Summary statistics including total tasks, success/failure counts,
            total duration, and per-collector timing information.
        """
        if not self.results:
            return {
                "total_tasks": 0,
                "successful": 0,
                "failed": 0,
                "timed_out": 0,
                "total_duration": 0.0,
                "collectors": {}
            }

        successful = sum(1 for r in self.results.values() if r.success)
        failed = sum(1 for r in self.results.values() if not r.success)
        timed_out = sum(1 for r in self.results.values() if r.timed_out)
        total_duration = sum(r.duration for r in self.results.values())

        collector_stats = {
            name: {
                "success": result.success,
                "duration": result.duration,
                "timed_out": result.timed_out,
                "error": result.error,
                "data_size": len(result.data) if result.success and hasattr(result.data, '__len__') else None
            }
            for name, result in self.results.items()
        }

        return {
            "total_tasks": len(self.results),
            "successful": successful,
            "failed": failed,
            "timed_out": timed_out,
            "total_duration": total_duration,
            "collectors": collector_stats
        }


def gather_parallel_system_state(collectors: Optional[Dict[str, Callable]] = None,
                                  max_workers: Optional[int] = None,
                                  timeout: float = 300.0,
                                  progress_callback: Optional[Callable] = None
                                  ) -> Tuple[Dict[str, Any], Dict[str, str]]:
    """Convenience function to run multiple system state collectors in parallel.

    This is a high-level API for common parallel collection scenarios.

    Parameters
    ----------
    collectors : dict, optional
        Dictionary mapping collector names to collector functions.
        If None, uses a default set of core collectors.
    max_workers : int, optional
        Number of worker threads. Defaults to CPU count + 4.
    timeout : float
        Default timeout per collector in seconds.
    progress_callback : callable, optional
        Callback for progress reporting: (name, completed, total).

    Returns
    -------
    tuple
        Two dictionaries: (successful_results, failed_results)
        - successful_results: {name: data} for successful collectors
        - failed_results: {name: error_message} for failed collectors
    """
    # Default collectors if none specified
    if collectors is None:
        from orin.collectors.processes import gather_active_processes
        from orin.collectors.connections import gather_listening_ports, gather_outbound_connections
        from orin.collectors.kernel import gather_loaded_kernel_modules
        from orin.collectors.users import gather_system_accounts
        from orin.collectors.suid import gather_suid_binaries
        from orin.collectors.promisc import gather_promisc_interfaces
        from orin.collectors.crontabs import gather_crontabs
        from orin.collectors.deleted_binaries import gather_deleted_binaries

        collectors = {
            "processes": gather_active_processes,
            "listening_ports": gather_listening_ports,
            "outbound_connections": gather_outbound_connections,
            "kernel_modules": gather_loaded_kernel_modules,
            "system_users": gather_system_accounts,
            "suid_binaries": gather_suid_binaries,
            "promisc_interfaces": gather_promisc_interfaces,
            "crontabs": gather_crontabs,
            "deleted_binaries": gather_deleted_binaries,
        }

    # Create parallel collector
    parallel = ParallelCollector(max_workers=max_workers, default_timeout=timeout)

    # Add all collectors as tasks
    for name, func in collectors.items():
        parallel.add_task(name, func, timeout=timeout)

    # Run collection
    parallel.run(progress_callback=progress_callback)

    # Return results
    return parallel.get_successful_results(), parallel.get_failed_results()


if __name__ == "__main__":
    # Example usage and testing

    def print_progress(name: str, completed: int, total: int):
        print(f"[{completed}/{total}] Completed: {name}")

    print("Testing parallel collector...")
    print("=" * 60)

    successful, failed = gather_parallel_system_state(
        max_workers=4,
        timeout=60.0,
        progress_callback=print_progress
    )

    print("\n" + "=" * 60)
    print("COLLECTION SUMMARY")
    print("=" * 60)

    print(f"\nSuccessful collectors: {len(successful)}")
    for name, data in successful.items():
        size = len(data) if hasattr(data, '__len__') else 1
        print(f"  ✓ {name}: {size} items")

    if failed:
        print(f"\nFailed collectors: {len(failed)}")
        for name, error in failed.items():
            print(f"  ✗ {name}: {error}")

    print("\n" + "=" * 60)