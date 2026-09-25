from __future__ import annotations

import hashlib
import os
from typing import Dict, List, Optional

try:
    import yara

    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False


class YaraScanner:
    """
    Scans files against compiled YARA rules and calculates hashes.
    """

    def __init__(self, rule_dir: str):
        self.rules = None
        self.rule_dir = rule_dir
        if YARA_AVAILABLE:
            self._load_rules()
        else:
            print("[!] yara-python not installed. YARA scanning is disabled.")

    def _load_rules(self):
        """Loads and compiles all .yar or .yara files in the directory."""
        if not os.path.exists(self.rule_dir):
            print(f"[!] YARA rule directory not found: {self.rule_dir}")
            return

        filepaths = {}
        for filename in os.listdir(self.rule_dir):
            if filename.endswith(".yar") or filename.endswith(".yara"):
                path = os.path.join(self.rule_dir, filename)
                # Ensure the path is valid and accessible before passing to yara
                if os.path.isfile(path) and os.access(path, os.R_OK):
                    filepaths[filename] = path

        if not filepaths:
            print(f"[*] No YARA rules found in {self.rule_dir}")
            return

        try:
            self.rules = yara.compile(filepaths=filepaths)
            print(f"[*] Compiled {len(filepaths)} YARA rule files from {self.rule_dir}.")
        except Exception as e:
            print(f"[!] Failed to compile YARA rules: {e}")

    def get_file_hash(self, filepath: str) -> str | None:
        """Calculates the SHA256 hash of a file."""
        if not os.path.isfile(filepath):
            return None
        sha256 = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception:
            return None

    def scan_file(self, filepath: str) -> list[str]:
        """
        Scans a single file against loaded YARA rules.
        Returns a list of matched rule names.
        """
        if not self.rules or not os.path.isfile(filepath):
            return []

        try:
            matches = self.rules.match(filepath)
            return [m.rule for m in matches]
        except Exception:
            # File might be inaccessible (e.g. permission denied)
            return []
