# Project Spectre V10: Active Containment

We have successfully completed **V10 (Containment)**. This version introduces active mitigation capabilities to Spectre, allowing it to take direct action against suspicious process trees when threat thresholds are breached.

---

## 1. Feature Overview

- **Containment Module (`mitigation/Container`)**: A new module that can apply signals to a session leader and its entire process tree.
- **Actions (`--contain`)**:
  - `stop`: Sends `SIGSTOP` to freeze the process tree.
  - `kill`: Sends `SIGKILL` to terminate the process tree.
  - `none`: Default monitoring-only mode.
- **Integration**: The mitigation action is triggered in `main.py` immediately after an alert is fired for a session breaching the configured threat threshold.

---

## 2. Usage

You can enable active containment using the `--contain` flag:

```bash
# To freeze suspicious process trees
python main.py --contain stop

# To terminate suspicious process trees
python main.py --contain kill
```

---

## 3. Verification

```bash
python3 tests/v10/run_test.py
```

The testing suite verifies that the containment actions are properly dispatched to the target process tree.
