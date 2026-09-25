from __future__ import annotations

import time
from collections import deque
from typing import Deque, Dict, List, Optional, Tuple

import networkx as nx


class ProcessResourceGraph:
    """
    In-memory process-resource graph using NetworkX, with event expiration
    and sliding window memory.
    """

    def __init__(self, window_size: float = 60.0):
        self.window_size = window_size
        self.graph = nx.DiGraph()
        # Deque of (timestamp, event_type, data)
        # u and v are nodes. u is always the process_key. v can be child process_key or resource_node.
        self.events: deque[tuple[float, str, tuple]] = deque()
        # Track active processes to avoid prematurely garbage collecting alive processes
        # Maps process_key -> last_seen_time
        self.active_processes: dict[tuple[int, float], float] = {}

    def update_active_processes(self, current_processes: dict[int, float]):
        """
        Updates the active processes registry with the latest system process snapshot.
        """
        now = time.time()
        for pid, ctime in current_processes.items():
            self.active_processes[(pid, ctime)] = now

    def add_chain(self, chain: list[dict]):
        """
        Adds a process ancestry chain and all its resources to the graph.
        """
        now = time.time()
        if not chain:
            return

        # 1. Add process nodes and SPAWN edges
        for i in range(len(chain)):
            proc = chain[i]
            proc_key = (proc["pid"], proc["create_time"])

            # Add/Update process node
            self.graph.add_node(
                proc_key,
                type="process",
                name=proc["name"],
                cmdline=proc["cmdline"],
                last_seen=now,
            )
            self.active_processes[proc_key] = now

            # If not root, add SPAWN edge from parent
            if i > 0:
                parent_proc = chain[i - 1]
                parent_key = (parent_proc["pid"], parent_proc["create_time"])
                edge = (parent_key, proc_key)

                if not self.graph.has_edge(*edge):
                    self.graph.add_edge(*edge, type="SPAWN", timestamp=now)
                    self.events.append((now, "spawn", edge))
                else:
                    self.graph[edge[0]][edge[1]]["timestamp"] = now

            # 2. Add resource nodes and edges (READ, WRITE, CONNECT, LISTEN)
            for f in proc.get("files", []):
                file_node = f["path"]
                self.graph.add_node(file_node, type="file", last_seen=now)
                edge = (proc_key, file_node)
                event_type = f["event"]  # READ or WRITE

                # If edge doesn't exist, or has different relationship type
                if (
                    not self.graph.has_edge(*edge)
                    or self.graph[edge[0]][edge[1]]["type"] != event_type
                ):
                    self.graph.add_edge(*edge, type=event_type, timestamp=now)
                    self.events.append((now, event_type.lower(), (proc_key, file_node, event_type)))
                else:
                    self.graph[edge[0]][edge[1]]["timestamp"] = now

            for c in proc.get("connections", []):
                socket_node = c["raddr"]
                self.graph.add_node(socket_node, type="socket", last_seen=now)
                edge = (proc_key, socket_node)
                event_type = c["event"]  # CONNECT or LISTEN

                if (
                    not self.graph.has_edge(*edge)
                    or self.graph[edge[0]][edge[1]]["type"] != event_type
                ):
                    self.graph.add_edge(*edge, type=event_type, timestamp=now)
                    self.events.append(
                        (now, event_type.lower(), (proc_key, socket_node, event_type)),
                    )
                else:
                    self.graph[edge[0]][edge[1]]["timestamp"] = now

    def expire_old_events(self):
        """
        Removes edges and nodes that have expired past the sliding window.
        """
        now = time.time()
        expiration_threshold = now - self.window_size

        # 1. Pop expired events from the deque
        while self.events and self.events[0][0] < expiration_threshold:
            timestamp, event_type, data = self.events.popleft()

            if event_type == "spawn":
                parent_key, child_key = data
                if self.graph.has_edge(parent_key, child_key):
                    edge_time = self.graph[parent_key][child_key].get("timestamp", 0)
                    if edge_time < expiration_threshold:
                        self.graph.remove_edge(parent_key, child_key)

            elif event_type in ("read", "write", "connect", "listen"):
                proc_key, resource_node, edge_type = data
                if self.graph.has_edge(proc_key, resource_node):
                    edge_attr = self.graph[proc_key][resource_node]
                    if (
                        edge_attr.get("type") == edge_type.upper()
                        and edge_attr.get("timestamp", 0) < expiration_threshold
                    ):
                        self.graph.remove_edge(proc_key, resource_node)

        # 2. Cleanup orphaned nodes (nodes with degree 0)
        nodes_to_remove = []
        for node in list(self.graph.nodes):
            node_type = self.graph.nodes[node].get("type")

            if node_type == "process":
                # Check if process has no active edges left in the graph
                if self.graph.degree(node) == 0:
                    is_alive = False
                    if node in self.active_processes:
                        # Consider process alive if seen in the last 2 seconds
                        if now - self.active_processes[node] < 2.0:
                            is_alive = True

                    if not is_alive:
                        nodes_to_remove.append(node)
                        self.active_processes.pop(node, None)
            # Remove file/socket nodes immediately when they have no relationships left
            elif self.graph.degree(node) == 0:
                nodes_to_remove.append(node)

        for node in nodes_to_remove:
            self.graph.remove_node(node)

    def get_stats(self) -> dict[str, int]:
        """
        Returns simple node and edge metrics for logging.
        """
        nodes = list(self.graph.nodes(data=True))
        processes = sum(1 for n in nodes if n[1].get("type") == "process")
        files = sum(1 for n in nodes if n[1].get("type") == "file")
        sockets = sum(1 for n in nodes if n[1].get("type") == "socket")
        edges = self.graph.number_of_edges()

        return {
            "total_nodes": len(nodes),
            "processes": processes,
            "files": files,
            "sockets": sockets,
            "edges": edges,
        }
