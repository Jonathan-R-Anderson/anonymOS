# Project Spectre V6: Persistence (SQLite)

We have successfully completed **V6 (Persistence)**. This version adds a SQLite database layer that persists all behavioral events, high-severity alerts, and session threat scores across restarts.

---

## 1. Database Schema

Three tables:
- **`events`**: Individual rule-match events with timestamp, process info, detail, and MITRE metadata.
- **`alerts`**: High-severity threshold alerts with the full chain JSON and explanation text.
- **`sessions`**: Session leader processes with their cumulative threat scores.

---

## 2. Usage

```bash
# Default database path
python main.py --db spectre.db

# Custom database path
python main.py --db /var/log/spectre/events.db
```

---

## 3. Verification

```bash
python3 tests/v6/run_test.py
```

All assertions pass:
- Events persisted to SQLite (≥2 rows).
- Alert persisted on threshold breach (≥1 row).
- Session score tracked (≥1 row).
- MITRE metadata stored in event records.
