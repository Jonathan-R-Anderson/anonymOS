# Project Spectre V9: YARA Integration

We have successfully completed **V9 (YARA Integration)**. This version integrates the `yara-python` engine into Spectre, allowing it to perform deep file content inspection on resources accessed by suspicious processes.

---

## 1. Feature Overview

- **YaraScanner Module**: A wrapper around `yara-python` that compiles all `.yar` / `.yara` rules from a specified directory on startup.
- **Dynamic File Scanning**: When a process triggers a behavioral rule (e.g., reading sensitive files, spawning shells), Spectre scans the actual files opened by the process against the compiled YARA rules.
- **Threat Enrichment**: If a file matches a YARA rule, the alert detail is enriched with the YARA rule name and the file's SHA256 hash. Additionally, the process's session threat score is bumped by +10.

---

## 2. Usage

You can supply custom YARA rules in a directory and pass the flag to Spectre:

```bash
python main.py --yara-rules yara_rules
```

If the `yara-python` dependency is not installed, Spectre will gracefully disable YARA scanning and continue with behavioral detection only.

---

## 3. Verification

```bash
python3 tests/v9/run_test.py
```

All assertions pass:
- A simulated dummy payload script matched the `SuspiciousShellScript` YARA rule.
- The resulting log warning included the matched YARA rule name and the calculated SHA256 hash.
