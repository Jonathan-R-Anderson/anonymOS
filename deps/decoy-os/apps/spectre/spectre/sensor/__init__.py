from __future__ import annotations

import time
from typing import Dict, Generator, List, Optional, Set, Tuple

import psutil


class ProcessSensor:
    """
    Sensor component that monitors host processes on Linux using psutil,
    detecting new spawns and resource access (Files and Sockets),
    yielding their updated ancestry tree.
    """

    def __init__(self, interval: float = 0.5, ignores_config: dict = None):
        self.interval = interval
        self.ignores_config = ignores_config or {}
        self.ignored_processes = self.ignores_config.get("processes", [])
        self.ignored_files = self.ignores_config.get("files", [])
        self.ignored_dirs = self.ignores_config.get("directories", [])
        self.known_processes: dict[int, float] = {}
        # Maps (pid, create_time) -> {"files": list of dicts, "connections": list of dicts}
        self.process_resources: dict[tuple[int, float], dict] = {}
        # Active processes we are monitoring files and sockets for
        self.monitored_processes: set[tuple[int, float]] = set()
        self._initialize_snapshot()

    def _is_ignored_process(self, proc: psutil.Process) -> bool:
        """
        Ignores processes defined in the ignores configuration to avoid noise.
        """
        try:
            name = proc.name().lower()
            cmdline_str = " ".join(proc.cmdline()).lower()
            for ignored_proc in self.ignored_processes:
                if ignored_proc.lower() in name or ignored_proc.lower() in cmdline_str:
                    return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        return False

    def _is_ignored_file(self, path: str) -> bool:
        """
        Filters out files and directories defined in the ignores configuration.
        """
        if not path:
            return True
        path_lower = path.lower()
        
        for ignored_file in self.ignored_files:
            if ignored_file.lower() in path_lower:
                return True

        return any(path.startswith(prefix) for prefix in self.ignored_dirs)

    def _get_process_files(self, proc: psutil.Process) -> list[dict]:
        """
        Retrieves files opened by the process, classifying them as READ or WRITE.
        """
        files = []
        try:
            for f in proc.open_files():
                if self._is_ignored_file(f.path):
                    continue
                # Determine read or write event based on file mode flags
                event = "READ"
                if "w" in f.mode or "a" in f.mode or "+" in f.mode:
                    event = "WRITE"

                files.append(
                    {
                        "path": f.path,
                        "event": event,
                    },
                )
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        return files

    def _get_process_connections(self, proc: psutil.Process) -> list[dict]:
        """
        Retrieves active connections or local listeners established by the process.
        """
        connections = []
        try:
            for conn in proc.net_connections():
                if conn.raddr:
                    # Ignore localhost connections for active outbound connections
                    if conn.raddr.ip in ("127.0.0.1", "::1", "localhost"):
                        continue
                    raddr_str = f"{conn.raddr.ip}:{conn.raddr.port}"
                    connections.append(
                        {
                            "raddr": raddr_str,
                            "status": conn.status,
                            "event": "CONNECT",
                        },
                    )
                elif conn.status == "LISTEN" and conn.laddr:
                    laddr_str = f"{conn.laddr.ip}:{conn.laddr.port}"
                    connections.append(
                        {
                            "raddr": laddr_str,
                            "status": conn.status,
                            "event": "LISTEN",
                        },
                    )
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        return connections

    def _safe_get_process_info(self, proc: psutil.Process) -> dict | None:
        """
        Safely retrieves key information from a Process instance.
        """
        try:
            with proc.oneshot():
                pid = proc.pid
                ctime = proc.create_time()
                key = (pid, ctime)

                res = self.process_resources.get(key, {"files": [], "connections": []})

                return {
                    "pid": pid,
                    "name": proc.name(),
                    "create_time": ctime,
                    "cmdline": proc.cmdline(),
                    "files": res["files"],
                    "connections": res["connections"],
                }
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return None

    def _initialize_snapshot(self):
        """
        Populates the initial known process dictionary to avoid flagging existing processes.
        """
        for proc in psutil.process_iter():
            info = self._safe_get_process_info(proc)
            if info:
                self.known_processes[info["pid"]] = info["create_time"]

    def _trace_ancestry(self, pid: int) -> list[dict]:
        """
        Traces the ancestry of a process starting from a PID up to the root.
        """
        chain = []
        current_pid = pid
        visited_pids = set()

        while current_pid and current_pid not in visited_pids:
            visited_pids.add(current_pid)
            try:
                proc = psutil.Process(current_pid)
                info = self._safe_get_process_info(proc)
                if not info:
                    break

                chain.append(info)
                parent = proc.parent()
                if parent:
                    current_pid = parent.pid
                else:
                    break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                break

        chain.reverse()
        return chain

    def start_monitoring(self) -> Generator[list[dict], None, None]:
        """
        Runs the monitoring loop using Netlink (if available) or falling back to polling.
        """
        from .netlink import NetlinkProcessMonitor
        import queue
        import logging
        
        event_queue = queue.Queue()
        def _on_netlink_event(event_type, pid, ppid):
            event_queue.put((event_type, pid))
            
        netlink_monitor = NetlinkProcessMonitor(callback=_on_netlink_event)
        use_netlink = netlink_monitor.start()
        
        try:
            while True:
                current_processes: dict[int, float] = {}
                new_processes_detected: list[tuple[int, float]] = []

                if use_netlink:
                    try:
                        ev_type, pid = event_queue.get(timeout=self.interval)
                        events = [(ev_type, pid)]
                        while not event_queue.empty():
                            events.append(event_queue.get())
                            
                        for ev_type, pid in events:
                            if ev_type in ("EXEC", "FORK"):
                                try:
                                    proc = psutil.Process(pid)
                                    ctime = proc.create_time()
                                    new_processes_detected.append((pid, ctime))
                                    self.known_processes[pid] = ctime
                                except (psutil.NoSuchProcess, psutil.AccessDenied):
                                    pass
                            elif ev_type == "EXIT":
                                if pid in self.known_processes:
                                    del self.known_processes[pid]
                    except queue.Empty:
                        pass
                        
                    # For resource polling, check active monitored processes
                    for pid, ctime in list(self.monitored_processes):
                        try:
                            proc = psutil.Process(pid)
                            if proc.create_time() == ctime:
                                current_processes[pid] = ctime
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass
                else:
                    # Fallback Polling Mode
                    time.sleep(self.interval)
                    for proc in psutil.process_iter():
                        try:
                            pid = proc.pid
                            ctime = proc.create_time()
                            current_processes[pid] = ctime

                            if pid not in self.known_processes or self.known_processes[pid] != ctime:
                                new_processes_detected.append((pid, ctime))
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            continue

                # 2. Process spawns
                for pid, ctime in new_processes_detected:
                    self.known_processes[pid] = ctime
                    try:
                        proc = psutil.Process(pid)
                        if self._is_ignored_process(proc):
                            continue
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue

                    chain = self._trace_ancestry(pid)
                    if chain:
                        self.monitored_processes.add((pid, ctime))
                        yield chain

                # 3. Update resources for all monitored processes
                updated_processes = []
                dead_monitored = []

                for key in list(self.monitored_processes):
                    pid, ctime = key
                    try:
                        if pid in current_processes and current_processes[pid] == ctime:
                            proc = psutil.Process(pid)

                            current_files = self._get_process_files(proc)
                            current_conns = self._get_process_connections(proc)

                            if key not in self.process_resources:
                                self.process_resources[key] = {"files": [], "connections": []}

                            entry = self.process_resources[key]
                            existing_files = {(f["path"], f["event"]) for f in entry["files"]}
                            existing_conns = {(c["raddr"], c["event"]) for c in entry["connections"]}

                            updated = False
                            for f in current_files:
                                if (f["path"], f["event"]) not in existing_files:
                                    entry["files"].append(f)
                                    updated = True

                            for c in current_conns:
                                if (c["raddr"], c["event"]) not in existing_conns:
                                    entry["connections"].append(c)
                                    updated = True

                            if updated:
                                updated_processes.append(key)
                        else:
                            dead_monitored.append(key)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        dead_monitored.append(key)

                for key in dead_monitored:
                    self.monitored_processes.discard(key)

                for pid, ctime in updated_processes:
                    chain = self._trace_ancestry(pid)
                    if chain:
                        yield chain

                # 4. Clean up exited known processes (only in polling mode since netlink handles EXIT)
                if not use_netlink:
                    exited_pids = [pid for pid in self.known_processes if pid not in current_processes]
                    for pid in exited_pids:
                        del self.known_processes[pid]
        finally:
            netlink_monitor.stop()
