# Project Spectre V3: Sliding Window Graph

We have successfully completed **V3 (Sliding Window Graph)**. This version introduces an in-memory sliding window process-resource graph powered by NetworkX.

---

## 1. Graph Model & Topology

The EDR's local state is represented as a directed graph $G = (V, E)$ using `networkx.DiGraph`:

* **Nodes ($V$)**:
  * **Process Node**: Unique identifier key is `(pid, create_time)`. Attributes include process name, command line, and last-seen timestamp.
  * **File Node**: Unique key is the absolute path string.
  * **Socket Node**: Unique key is the remote address string `IP:Port`.
* **Edges ($E$)**:
  * **`SPAWN`**: Directed edge from parent process key to child process key.
  * **`READ` / `WRITE`**: Directed edge from process key to file node path.
  * **`CONNECT` / `LISTEN`**: Directed edge from process key to socket node.

Each edge maintains a `timestamp` property recording when the event was last detected.

---

## 2. Sliding Window Expiration & Garbage Collection

To ensure rolling memory limits and prevent leaks:
1. **Event Queue (`deque`)**: All graph events (spawns and resource access) are pushed to a `collections.deque` with their detection timestamp.
2. **Pruning Loop**: During each polling cycle, events older than the configured sliding window size (e.g., `--window-size 60.0`) are popped from the queue. Their corresponding edges are removed from the NetworkX graph if their timestamps have not been refreshed.
3. **Orphan Pruning**:
   - For **Resource Nodes** (Files, Sockets): If the node's degree drops to `0` (no active reads, writes, or connections), the node is removed from the graph.
   - For **Process Nodes**: If the process degree is `0` and the process is no longer active on the system (determined via `psutil` snapshot registration), the node is garbage-collected.

---

## 3. Verification Logs

We ran the EDR monitor with a 5-second sliding window size (`--window-size 5.0`):

### Phase 1: Event Graph Growth
During active reads of `/etc/hosts` and connection to `8.8.8.8:53`, the graph size increases:
```text
[GRAPH STATE] Nodes: 10 (Proc: 8, File: 1, Sock: 1), Edges: 8
```

### Phase 2: Expiration & Pruning
5 seconds after the test processes completed execution, the sliding window expired their active edges. The orphaned nodes (the file `/etc/hosts` and the socket `8.8.8.8:53`) and dead processes were garbage-collected, returning the graph back to baseline size:
```text
[GRAPH STATE] Nodes: 7 (Proc: 7, File: 0, Sock: 0), Edges: 6
```
This confirms the sliding window rolling memory is fully functional and bounds system resources.
