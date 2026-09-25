# Project Spectre V8: Dashboard

We have successfully completed **V8 (Dashboard)**. This version introduces a beautiful, single-page web interface to view the live threat telemetry provided by the FastAPI REST API (V7).

---

## 1. Architecture

- **Static Assets**: The dashboard is a single `index.html` file containing HTML, vanilla CSS (using glassmorphism design), and vanilla JavaScript.
- **Delivery**: The FastAPI server mounts the file and serves it directly at the root endpoint `/`. This avoids requiring Node.js or an external web server like Nginx.
- **Data Fetching**: The JS client polls the `/api/*` endpoints every 2 seconds to update statistics, threat sessions, and the latest alerts in near real-time.

---

## 2. Usage

Run Spectre with the API enabled:

```bash
python main.py --api --api-port 8000
```

Then open your browser to [http://localhost:8000/](http://localhost:8000/).

---

## 3. Verification

```bash
python3 tests/v8/run_test.py
```

All assertions pass:
- API correctly serves HTML Content-Type on `/`.
- Dashboard contains the correct Title and UI structure.
- Dashboard script contains logic to fetch from `/api`.
