# Testing Guidelines & Contributor Onboarding

This document covers how to set up a development environment, run the test suite, and write new tests for Orin.

---

## Environment Setup

Orin uses optional dependencies for testing. To set up a local development environment:

```bash
# Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Orin in editable mode with development dependencies
pip install -e .[dev]
```

This installs `pytest` and `pytest-cov` as defined in `pyproject.toml`.

---

## Running the Test Suite

Orin uses `pytest` as its primary test runner.

```bash
ORIN_TEST_FAST=1 pytest
```

Setting `ORIN_TEST_FAST=1` skips slow-running integrations (eBPF loads, heavy subprocess calls, large database writes) for rapid developer feedback.

### Fast vs. Full Test Modes

| Mode | Environment Variable | Use Case |
|---|---|---|
| **Fast** (recommended for development) | `ORIN_TEST_FAST=1` | Active development and rapid feedback |
| **Full** (pre-commit / CI) | `ORIN_TEST_FAST=0` or unset | Complete validation including eBPF, stress tests, and integration tests |

### Legacy Runner (Alternative)

The `unittest` runner is also supported, though it does not generate coverage reports:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

---

## Coverage Gate

> **Minimum required coverage: 85%**

The CI pipeline will fail if total test coverage falls below this threshold, as configured in `pyproject.toml` under `[tool.pytest.ini_options]`.

To check coverage locally with a line-by-line breakdown:

```bash
pytest --cov=orin --cov-report=term-missing
```

Certain files that cannot be safely tested in CI (remote daemon servers, CLI entry points) are excluded from coverage tracking under `[tool.coverage.run]`.

---

## Writing New Tests

### File Location and Naming

- All test files must reside in the `tests/` directory.
- File names must be prefixed with `test_` (e.g. `test_my_feature.py`).
- Test classes should inherit from `unittest.TestCase` or use standard `pytest` assertion patterns.

### Temporary Databases

Never read from or write to the active `orin_vault.db` during tests. Create a temporary database in `setUp()` and clean it up in `tearDown()`.

```python
import unittest
from pathlib import Path
from orin.core.database import OrinStorage

class TestMyFeature(unittest.TestCase):
    def setUp(self):
        self.db_path = Path("test_db_temp.db")
        self.storage = OrinStorage(self.db_path)
        self.storage.initialize_db()

    def tearDown(self):
        if self.db_path.exists():
            self.db_path.unlink()

    def test_database_write(self):
        # Test logic here
        pass
```

### Mocking System Calls and eBPF

Because Orin interacts deeply with the Linux kernel and system state, use `unittest.mock.patch` to mock system commands, process execution, and filesystem interactions. This avoids requiring root privileges during testing.

```python
from unittest.mock import patch
import unittest

class TestSystemCheck(unittest.TestCase):
    @patch("subprocess.run")
    def test_system_command(self, mock_run):
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = b"active"

        # Call the function under test and assert expected behaviour
        pass
```

---

## CI Environment Variable Reference

| Variable | Value | Effect |
|---|---|---|
| `ORIN_TEST_FAST` | `1` | Skips slow and integration tests |
| `ORIN_TEST_FAST` | `0` or unset | Runs the full test suite |
| `PYTHONPATH` | `src` | Required when using the legacy `unittest` runner |