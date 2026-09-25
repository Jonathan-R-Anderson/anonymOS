# Project Spectre V7: REST API (FastAPI)

We have successfully completed **V7 (REST API)**. This version exposes an HTTP REST API using FastAPI and Uvicorn, allowing external tools and the upcoming dashboard to query the SQLite persistence layer.

---

## 1. Endpoints

The API serves the following endpoints under `http://localhost:8000`:
- **`GET /api/health`**: Liveness probe returning version and timestamp.
- **`GET /api/events`**: Paginated behavioral events (most recent first).
- **`GET /api/alerts`**: Paginated high-severity threshold alerts.
- **`GET /api/sessions`**: Session threat scores (highest threat first).
- **`GET /api/stats`**: Summary database counts.

---

## 2. Usage

To start the API, pass the `--api` flag:

```bash
python main.py --api --api-port 8000
```

*Note: Uvicorn runs in a background daemon thread, and its access logs are suppressed to prevent spamming the Spectre terminal console.*

---

## 3. Verification

```bash
python3 tests/v7/run_test.py
```

All assertions pass:
- API health check returned `ok` on port 8001.
- API returned multiple generated events from the simulation.
- API returned correct summary statistics.
