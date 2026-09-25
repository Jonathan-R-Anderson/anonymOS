# Copyright (C) 2026 Musa Jaradat
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
# src/orin/analysis/yara_engine.py
"""
orin.analysis.yara_engine – Embedded YARA Pattern Matching Engine
==================================================================
Integrates YARA rule scanning capabilities into Orin for pattern-based
malware detection across files, memory dumps, and process binaries.

Features
--------
- Load and compile .yar rules from configured directories
- Scan files against loaded rules with match caching
- Scan process memory dumps and in-memory payloads
- File Integrity Monitoring (FIM) integration for incremental scans
- MITRE ATT&CK technique tagging support
"""
import re
import hashlib
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, field

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False


@dataclass
class YaraMatch:
    """Represents a single YARA rule match."""
    rule_name: str
    namespace: str
    matched_strings: list = field(default_factory=list)
    tags: list = field(default_factory=list)
    meta: dict = field(default_factory=dict)
    file_path: Optional[str] = None
    process_pid: Optional[int] = None
    match_context: Optional[str] = None

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "rule_name": self.rule_name,
            "namespace": self.namespace,
            "matched_strings": self.matched_strings,
            "tags": self.tags,
            "meta": self.meta,
            "file_path": self.file_path,
            "process_pid": self.process_pid,
            "match_context": self.match_context
        }


@dataclass
class YaraScanResult:
    """Results from a YARA scan operation."""
    total_files_scanned: int = 0
    total_matches: int = 0
    matches: list = field(default_factory=list)
    scan_errors: list = field(default_factory=list)
    rules_loaded: int = 0

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "total_files_scanned": self.total_files_scanned,
            "total_matches": self.total_matches,
            "matches": [m.to_dict() for m in self.matches],
            "scan_errors": self.scan_errors,
            "rules_loaded": self.rules_loaded
        }


class YaraEngine:
    """
    Embedded YARA scanning engine for Orin forensic analysis.

    Supports loading rules from multiple directories, scanning files
    and memory regions, and integrating with FIM for optimized rescans.
    """

    DEFAULT_RULES_DIRS = [
        Path("/etc/orin/yara"),
        Path("/var/lib/orin/yara"),
        Path("./rules/yara"),
        Path(__file__).resolve().parents[3] / "rules" / "yara",
        Path(__file__).resolve().parents[2] / "yara",
    ]

    # Default severity mapping based on YARA rule tags
    SEVERITY_MAP = {
        "malware": "critical",
        "ransomware": "critical",
        "trojan": "high",
        "backdoor": "high",
        "rootkit": "critical",
        "cryptominer": "medium",
        "suspicious": "medium",
        "tool": "low",
        "pua": "low",  # Potentially Unwanted Application
    }

    def __init__(self, rules_dirs: Optional[list[Path]] = None):
        """
        Initialize the YARA engine.

        Parameters
        ----------
        rules_dirs : list[Path], optional
            Directories to search for .yar rules. Uses defaults if not provided.
        """
        if not YARA_AVAILABLE:
            raise RuntimeError(
                "YARA library not available. Install with: pip install yara-python"
            )

        self.rules_dirs = rules_dirs or self.DEFAULT_RULES_DIRS.copy()
        self.compiled_rules = None
        self.loaded_rules_count = 0
        self._rules_hash = None  # For detecting rule changes

    def _compute_rules_hash(self, rules_content: dict[str, str]) -> str:
        """Compute a hash of all loaded rules for change detection."""
        combined = ""
        for namespace, content in sorted(rules_content.items()):
            combined += f"{namespace}:{content}"
        return hashlib.sha256(combined.encode()).hexdigest()

    def load_rules(self, rules_dirs: Optional[list[Path]] = None) -> int:
        """
        Load and compile YARA rules from specified directories.

        Parameters
        ----------
        rules_dirs : list[Path], optional
            Override default directories to search for rules.

        Returns
        -------
        int
            Number of rules successfully loaded.

        Raises
        ------
        RuntimeError
            If no rules are found or compilation fails.
        """
        dirs_to_scan = rules_dirs or self.rules_dirs
        rules_files = {}
        rules_content = {}

        # Collect all .yar files
        for rules_dir in dirs_to_scan:
            if not rules_dir.exists():
                continue
            if not rules_dir.is_dir():
                continue

            for yar_file in rules_dir.glob("*.yar"):
                try:
                    content = yar_file.read_text(encoding='utf-8')
                    # Use filename (without extension) as namespace
                    namespace = yar_file.stem.replace("-", "_").replace(".", "_")
                    rules_files[namespace] = yar_file
                    rules_content[namespace] = content
                    print(f"[+] Loaded YARA rule file: {yar_file}")
                except Exception as e:
                    print(f"[!] Error reading YARA rule file {yar_file}: {e}")

        if not rules_content:
            print("[!] Warning: No YARA rule files found in configured directories")
            self.loaded_rules_count = 0
            self.compiled_rules = None
            return 0

        # Compute hash for change detection
        new_hash = self._compute_rules_hash(rules_content)
        if new_hash == self._rules_hash and self.compiled_rules is not None:
            # Rules haven't changed, skip recompilation
            return self.loaded_rules_count

        # Compile rules with namespaces
        try:
            compiled = yara.compile(sources=rules_content)
            self.compiled_rules = compiled
            self._rules_hash = new_hash
            # In yara-python 4.x, Rules object is iterable directly
            self.loaded_rules_count = len(list(compiled))
            print(f"[+] Compiled {self.loaded_rules_count} YARA rules from {len(rules_files)} files")
            return self.loaded_rules_count
        except yara.SyntaxError as e:
            print(f"[!] YARA syntax error during compilation: {e}")
            raise RuntimeError(f"YARA rule compilation failed: {e}")
        except Exception as e:
            print(f"[!] Error compiling YARA rules: {e}")
            raise RuntimeError(f"YARA compilation error: {e}")

    def scan_file(self, file_path: Path, timeout: int = 30) -> list[YaraMatch]:
        """
        Scan a single file against loaded YARA rules.

        Parameters
        ----------
        file_path : Path
            Path to the file to scan.
        timeout : int
            Maximum scan time in seconds (default: 30).

        Returns
        -------
        list[YaraMatch]
            List of matches found in the file.
        """
        if not self.compiled_rules:
            return []

        if not file_path.exists():
            return []

        try:
            matches = self.compiled_rules.match(
                str(file_path),
                timeout=timeout
            )

            results = []
            for match in matches:
                # In yara-python 4.x, match.strings is a list of StringMatch objects
                # Each StringMatch has an 'instances' list containing StringMatchInstance objects
                matched_strings = []
                for string_match in match.strings:
                    for instance in string_match.instances:
                        try:
                            matched_strings.append(instance.matched_data.decode('utf-8', errors='replace'))
                        except:
                            matched_strings.append(instance.matched_data.hex())

                yara_match = YaraMatch(
                    rule_name=match.rule,
                    namespace=match.namespace,
                    matched_strings=matched_strings,
                    tags=match.tags,
                    meta=match.meta,
                    file_path=str(file_path)
                )
                results.append(yara_match)

            return results

        except yara.TimeoutError:
            print(f"[!] YARA scan timeout for file: {file_path}")
            return []
        except Exception as e:
            print(f"[!] Error scanning file {file_path}: {e}")
            return []

    def scan_data(self, data: bytes, identifier: str = "memory") -> list[YaraMatch]:
        """
        Scan raw data (e.g., memory dump, process memory) against rules.

        Parameters
        ----------
        data : bytes
            Raw binary data to scan.
        identifier : str
            Identifier for the data source (e.g., "pid_1234", "dump.bin").

        Returns
        -------
        list[YaraMatch]
            List of matches found in the data.
        """
        if not self.compiled_rules:
            return []

        try:
            matches = self.compiled_rules.match(data=data, timeout=30)

            results = []
            for match in matches:
                # In yara-python 4.x, match.strings is a list of StringMatch objects
                matched_strings = []
                for string_match in match.strings:
                    for instance in string_match.instances:
                        try:
                            matched_strings.append(instance.matched_data.decode('utf-8', errors='replace'))
                        except:
                            matched_strings.append(instance.matched_data.hex())

                # Extract context around matched strings
                context = self._extract_match_context(data, match.strings)

                yara_match = YaraMatch(
                    rule_name=match.rule,
                    namespace=match.namespace,
                    matched_strings=matched_strings,
                    tags=match.tags,
                    meta=match.meta,
                    match_context=context
                )

                # Try to extract PID if identifier contains it
                pid_match = re.search(r'pid[_\s]*(\d+)', identifier, re.IGNORECASE)
                if pid_match:
                    yara_match.process_pid = int(pid_match.group(1))

                results.append(yara_match)

            return results

        except yara.TimeoutError:
            print(f"[!] YARA scan timeout for  {identifier}")
            return []
        except Exception as e:
            print(f"[!] Error scanning data {identifier}: {e}")
            return []

    def scan_process(self, pid: int, timeout: int = 30) -> list[YaraMatch]:
        """
        Scan a process's memory space using YARA rules.

        Attempts native YARA process matching via `compiled_rules.match(pid=pid)`.
        If that fails, falls back to manually parsing /proc/<pid>/maps and reading /proc/<pid>/mem.

        Parameters
        ----------
        pid : int
            Process ID to scan.
        timeout : int
            Scan timeout in seconds (default: 30).

        Returns
        -------
        list[YaraMatch]
            List of matches found.
        """
        if not self.compiled_rules:
            return []

        # 1. Attempt native YARA match(pid=pid)
        try:
            matches = self.compiled_rules.match(pid=pid, timeout=timeout)
            results = []
            for match in matches:
                matched_strings = []
                for string_match in match.strings:
                    for instance in string_match.instances:
                        try:
                            matched_strings.append(instance.matched_data.decode('utf-8', errors='replace'))
                        except:
                            matched_strings.append(instance.matched_data.hex())

                yara_match = YaraMatch(
                    rule_name=match.rule,
                    namespace=match.namespace,
                    matched_strings=matched_strings,
                    tags=match.tags,
                    meta=match.meta,
                    process_pid=pid
                )
                results.append(yara_match)
            return results
        except Exception:
            # Fallback to manual /proc/<pid>/mem scan
            pass

        # 2. Manual fallback scan
        results = []
        maps_path = Path(f"/proc/{pid}/maps")
        mem_path = Path(f"/proc/{pid}/mem")

        if not maps_path.exists() or not mem_path.exists():
            return []

        try:
            readable_regions = []
            # Parse /proc/<pid>/maps
            with open(maps_path, "r", errors="replace") as maps_file:
                for line in maps_file:
                    parts = line.strip().split()
                    if len(parts) < 2:
                        continue
                    addr_range = parts[0]
                    perms = parts[1]

                    # We only care about readable regions
                    if 'r' not in perms:
                        continue

                    # Skip special regions to prevent hangs or read faults
                    pathname = parts[-1] if len(parts) > 5 else ""
                    if pathname in ("[vvar]", "[vdso]", "[vsyscall]"):
                        continue

                    addr_start_str, addr_end_str = addr_range.split("-")
                    addr_start = int(addr_start_str, 16)
                    addr_end = int(addr_end_str, 16)
                    readable_regions.append((addr_start, addr_end))

            if not readable_regions:
                return []

            seen_rules = set()
            with open(mem_path, "rb") as mem_file:
                for start, end in readable_regions:
                    length = end - start
                    # Limit chunk size to avoid memory exhaustion
                    max_chunk = 16 * 1024 * 1024
                    if length > max_chunk:
                        offset = start
                        while offset < end:
                            chunk_len = min(max_chunk, end - offset)
                            try:
                                mem_file.seek(offset)
                                chunk_data = mem_file.read(chunk_len)
                                if chunk_data:
                                    matches = self.scan_data(chunk_data, identifier=f"pid_{pid}")
                                    for m in matches:
                                        m.process_pid = pid
                                        if m.rule_name not in seen_rules:
                                            seen_rules.add(m.rule_name)
                                            results.append(m)
                            except OSError:
                                pass
                            offset += chunk_len
                    else:
                        try:
                            mem_file.seek(start)
                            chunk_data = mem_file.read(length)
                            if chunk_data:
                                matches = self.scan_data(chunk_data, identifier=f"pid_{pid}")
                                for m in matches:
                                    m.process_pid = pid
                                    if m.rule_name not in seen_rules:
                                        seen_rules.add(m.rule_name)
                                        results.append(m)
                        except OSError:
                            pass
        except Exception:
            pass

        return results

    def _extract_match_context(self, data: bytes, strings: list, context_bytes: int = 64) -> Optional[str]:
        """Extract readable context around matched strings."""
        if not strings:
            return None

        try:
            # Get the first string's first instance offset
            first_string = strings[0]
            if first_string.instances:
                offset = first_string.instances[0].offset
                matched_data = first_string.instances[0].matched_data
            else:
                return None

            # Extract context window
            start = max(0, offset - context_bytes)
            end = min(len(data), offset + len(matched_data) + context_bytes)
            context_data = data[start:end]

            # Try to decode as text, fall back to hex
            try:
                return context_data.decode('utf-8', errors='replace')
            except:
                return context_data.hex()
        except:
            return None

    def scan_directory(
        self,
        directory: Path,
        recursive: bool = True,
        file_patterns: Optional[list[str]] = None,
        exclude_patterns: Optional[list[str]] = None,
        max_file_size: int = 100 * 1024 * 1024,  # 100MB default
        timeout_per_file: int = 30
    ) -> YaraScanResult:
        """
        Scan a directory tree for YARA matches.

        Parameters
        ----------
        directory : Path
            Root directory to scan.
        recursive : bool
            Whether to scan subdirectories (default: True).
        file_patterns : list[str], optional
            Glob patterns to include (e.g., ["*.exe", "*.dll"]).
        exclude_patterns : list[str], optional
            Glob patterns to exclude (e.g., ["*.log", "*.tmp"]).
        max_file_size : int
            Maximum file size to scan in bytes (default: 100MB).
        timeout_per_file : int
            Timeout per file in seconds (default: 30).

        Returns
        -------
        YaraScanResult
            Comprehensive scan results.
        """
        result = YaraScanResult()

        if not self.compiled_rules:
            result.scan_errors.append("No YARA rules loaded")
            return result

        if not directory.exists():
            result.scan_errors.append(f"Directory does not exist: {directory}")
            return result

        # Compile patterns
        include_re = [re.compile(p.replace("*", ".*").replace("?", "."))
                      for p in file_patterns] if file_patterns else None
        exclude_re = [re.compile(p.replace("*", ".*").replace("?", "."))
                      for p in exclude_patterns or []]

        # Walk directory
        files_to_scan = []
        if recursive:
            walker = directory.rglob("*")
        else:
            walker = directory.glob("*")

        for file_path in walker:
            if not file_path.is_file():
                continue

            # Check size
            try:
                if file_path.stat().st_size > max_file_size:
                    continue
            except:
                continue

            # Check include patterns
            if include_re:
                if not any(p.match(file_path.name) for p in include_re):
                    continue

            # Check exclude patterns
            if exclude_re:
                if any(p.match(file_path.name) for p in exclude_re):
                    continue

            files_to_scan.append(file_path)

        # Scan files
        result.total_files_scanned = len(files_to_scan)
        for file_path in files_to_scan:
            try:
                matches = self.scan_file(file_path, timeout=timeout_per_file)
                if matches:
                    result.matches.extend(matches)
                    result.total_matches += len(matches)
            except Exception as e:
                result.scan_errors.append(f"Error scanning {file_path}: {e}")

        result.rules_loaded = self.loaded_rules_count
        return result

    def get_severity_for_match(self, match: YaraMatch) -> str:
        """
        Determine severity level for a YARA match based on tags and metadata.

        Parameters
        ----------
        match : YaraMatch
            The YARA match to evaluate.

        Returns
        -------
        str
            Severity level: "critical", "high", "medium", or "low".
        """
        # Check explicit severity in metadata
        if "severity" in match.meta:
            sev = str(match.meta["severity"]).lower()
            if sev in {"critical", "high", "medium", "low"}:
                return sev

        # Check tags for severity indicators
        for tag in match.tags:
            tag_lower = tag.lower()
            if tag_lower in self.SEVERITY_MAP:
                return self.SEVERITY_MAP[tag_lower]

        # Check rule name for keywords
        rule_lower = match.rule_name.lower()
        if any(kw in rule_lower for kw in ["ransomware", "rootkit", "apt"]):
            return "critical"
        elif any(kw in rule_lower for kw in ["trojan", "backdoor", "infostealer"]):
            return "high"
        elif any(kw in rule_lower for kw in ["miner", "cryptominer", "suspicious"]):
            return "medium"

        # Default to medium for unknown matches
        return "medium"

    def get_attck_techniques(self, match: YaraMatch) -> list[str]:
        """
        Extract MITRE ATT&CK technique IDs from match metadata/tags.

        Parameters
        ----------
        match : YaraMatch
            The YARA match to analyze.

        Returns
        -------
        list[str]
            List of ATT&CK technique IDs (e.g., ["T1059", "T1055"]).
        """
        techniques = []

        # Check metadata for ATT&CK references
        if "attack" in match.meta:
            attack_meta = match.meta["attack"]
            if isinstance(attack_meta, str):
                techniques.append(attack_meta.upper())
            elif isinstance(attack_meta, list):
                techniques.extend([t.upper() for t in attack_meta])

        # Check tags for ATT&CK patterns
        for tag in match.tags:
            # Match patterns like T1059, T1059.001, etc.
            if re.match(r'^T\d{4}(\.\d{3})?$', tag, re.IGNORECASE):
                techniques.append(tag.upper())

        return list(set(techniques))


def create_sample_yara_rules(output_dir: Path) -> int:
    """
    Create sample YARA rules for testing and demonstration.

    Parameters
    ----------
    output_dir : Path
        Directory to write sample rules to.

    Returns
    -------
    int
        Number of rules created.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    sample_rules = {
        "suspicious_strings.yar": '''// Suspicious Command Execution Patterns
rule Suspicious_Python_Reverse_Shell : reverse_shell python suspicious {
    meta:
        description = "Detects Python reverse shell one-liners"
        author = "Orin Security"
        severity = "high"
        attack = "T1059.006"
    strings:
        $py1 = "socket.socket(socket.AF_INET,socket.SOCK_STREAM)" ascii
        $py2 = "subprocess.call(['/bin/sh','-i'])" ascii
        $py3 = "os.dup2(s.fileno(),0)" ascii
        $py4 = "os.dup2(s.fileno(),1)" ascii
        $py5 = "os.dup2(s.fileno(),2)" ascii
    condition:
        2 of them
}

rule Suspicious_Bash_Reverse_Shell : reverse_shell bash suspicious {
    meta:
        description = "Detects Bash reverse shell patterns"
        author = "Orin Security"
        severity = "high"
        attack = "T1059.004"
    strings:
        $bash1 = "/bin/bash -i >& /dev/tcp/" ascii
        $bash2 = "0<&196;exec 196<>/dev/tcp/" ascii
        $bash3 = "bash -c 'bash -i'" ascii
    condition:
        any of them
}

rule Suspicious_Curl_Download_Execute : download execute suspicious {
    meta:
        description = "Detects curl/wget download and execute patterns"
        author = "Orin Security"
        severity = "medium"
        attack = "T1105"
    strings:
        $curl1 = "curl" ascii
        $curl2 = "wget" ascii
        $exec1 = "| sh" ascii
        $exec2 = "| bash" ascii
        $pipe = "||" ascii
    condition:
        ($curl1 or $curl2) and ($exec1 or $exec2)
}
''',

        "crypto_miners.yar": '''// Cryptocurrency Miner Detection
rule CryptoMiner_XMRig_Generic : cryptominer xmrig malware {
    meta:
        description = "Generic XMRig cryptocurrency miner detection"
        author = "Orin Security"
        severity = "medium"
        attack = "T1496"
    strings:
        $s1 = "XMRig" ascii
        $s2 = "xmrig" ascii
        $s3 = "Donate level:" ascii
        $s4 = "stratum+tcp://" ascii
        $s5 = "pool." ascii nocase
    condition:
        2 of them
}

rule CryptoMiner_Stratum_Protocol : cryptominer stratum suspicious {
    meta:
        description = "Detects Stratum mining protocol strings"
        author = "Orin Security"
        severity = "medium"
        attack = "T1496"
    strings:
        $stratum1 = "{\"id\":1,\"method\":\"mining.subscribe\"" ascii
        $stratum2 = "{\"method\":\"mining.notify\"" ascii
        $stratum3 = "mining.submit" ascii
        $wallet = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/ ascii
    condition:
        $stratum1 or $stratum2 or $stratum3
}
''',

        "webshells.yar": '''// Web Shell Detection
rule WebShell_PHP_Generic : webshell php backdoor {
    meta:
        description = "Generic PHP webshell detection"
        author = "Orin Security"
        severity = "critical"
        attack = "T1505.003"
    strings:
        $php1 = "<?php" ascii
        $php2 = "eval(" ascii
        $php3 = "base64_decode(" ascii
        $php4 = "gzinflate(" ascii
        $shell1 = "system(" ascii
        $shell2 = "exec(" ascii
        $shell3 = "passthru(" ascii
        $shell4 = "shell_exec(" ascii
    condition:
        $php1 and ($php2 or $php3 or $php4) and ($shell1 or $shell2 or $shell3 or $shell4)
}

rule WebShell_PHP_C99_Variant : webshell php c99 backdoor {
    meta:
        description = "C99-style PHP webshell detection"
        author = "Orin Security"
        severity = "critical"
        attack = "T1505.003"
    strings:
        $c99_1 = "$safe_mode = false;" ascii
        $c99_2 = "function ex($c){" ascii
        $c99_3 = "ini_set(\"max_execution_time\",0);" ascii
        $c99_4 = "@set_time_limit(0);" ascii
        $c99_5 = "Security mode is" ascii
    condition:
        2 of them
}
''',

        "rootkits.yar": '''// Rootkit Detection Signatures
rule Rootkit_Diamorphine_Signature : rootkit linux kernel diamorphine {
    meta:
        description = "Diamorphine kernel rootkit detection"
        author = "Orin Security"
        severity = "critical"
        attack = "T1014"
    strings:
        $mod1 = "module_init(diamorphine_init)" ascii
        $mod2 = "hiding_module" ascii
        $mod3 = "orig_getdents64" ascii
        $mod4 = "orig_getdents" ascii
        $kill_signal = 63 ascii
        $clean_signal = 64 ascii
    condition:
        2 of them
}

rule Rootkit_Reptile_Signature : rootkit linux kernel reptile {
    meta:
        description = "Reptile kernel rootkit detection"
        author = "Orin Security"
        severity = "critical"
        attack = "T1014"
    strings:
        $rep1 = "reptile_net" ascii
        $rep2 = "reptile.h" ascii
        $rep3 = "reptile.c" ascii
        $magic = 0xCAFEBABE
    condition:
        2 of them
}
''',

        "malware_tools.yar": '''// Common Malware Tools Detection
rule Tool_Nmap_Port_Scanner : tool scanner nmap reconnaissance {
    meta:
        description = "Nmap network scanner binary detection"
        author = "Orin Security"
        severity = "low"
        attack = "T1046"
    strings:
        $nmap1 = "Nmap" ascii
        $nmap2 = "nmap.org" ascii
        $nmap3 = "NSE: Starting" ascii
    condition:
        2 of them
}

rule Tool_Netcat_Generic : tool netcat networking {
    meta:
        description = "Netcat networking utility detection"
        author = "Orin Security"
        severity = "low"
        attack = "T1071"
    strings:
        $nc1 = "GNU netcat" ascii
        $nc2 = "OpenBSD netcat" ascii
        $nc3 = "Ncat:" ascii
        $nc4 = "Connection to" ascii
    condition:
        any of them
}

rule Tool_Meterpreter_Payload : malware meterpreter metasploit payload {
    meta:
        description = "Metasploit Meterpreter payload detection"
        author = "Orin Security"
        severity = "critical"
        attack = "T1059"
    strings:
        $met1 = "METERPRETER_TRANSPORT_SSL" ascii
        $met2 = "TRANSPORT_STATE_NONE" ascii
        $met3 = "transport_create_tcp_session" ascii
        $met4 = "remote_dispatch" ascii
    condition:
        2 of them
}
'''
    }

    rules_created = 0
    for filename, content in sample_rules.items():
        output_path = output_dir / filename
        try:
            output_path.write_text(content, encoding='utf-8')
            print(f"[+] Created sample YARA rule: {output_path}")
            rules_created += 1
        except Exception as e:
            print(f"[!] Error creating {filename}: {e}")

    return rules_created


def run_yara_scan(
    target_path: Path,
    rules_dirs: Optional[list[Path]] = None,
    recursive: bool = True,
    scan_type: str = "auto"
) -> YaraScanResult:
    """
    Convenience function to run a complete YARA scan.

    Parameters
    ----------
    target_path : Path
        File or directory to scan.
    rules_dirs : list[Path], optional
        Directories containing YARA rules.
    recursive : bool
        Whether to scan recursively (for directories).
    scan_type : str
        Type of scan: "file", "directory", or "auto" (default).

    Returns
    -------
    YaraScanResult
        Scan results with all matches and metadata.
    """
    if not YARA_AVAILABLE:
        result = YaraScanResult()
        result.scan_errors.append("YARA library not available")
        return result

    engine = YaraEngine(rules_dirs=rules_dirs)

    # Load rules
    rules_loaded = engine.load_rules()
    if rules_loaded == 0:
        result = YaraScanResult()
        result.scan_errors.append("No YARA rules could be loaded")
        return result

    # Run appropriate scan
    if target_path.is_file() or scan_type == "file":
        result = YaraScanResult()
        result.total_files_scanned = 1
        result.rules_loaded = rules_loaded
        matches = engine.scan_file(target_path)
        result.matches = matches
        result.total_matches = len(matches)
        return result
    elif target_path.is_dir() or scan_type == "directory":
        return engine.scan_directory(target_path, recursive=recursive)
    else:
        result = YaraScanResult()
        result.scan_errors.append(f"Invalid target path: {target_path}")
        return result


if __name__ == "__main__":
    # Demo/test mode
    print("=" * 60)
    print("Orin YARA Engine - Demo Mode")
    print("=" * 60)

    # Create sample rules
    sample_dir = Path("./sample_yara_rules")
    created = create_sample_yara_rules(sample_dir)
    print(f"\nCreated {created} sample YARA rule files\n")

    # Initialize engine
    engine = YaraEngine(rules_dirs=[sample_dir])
    rules_loaded = engine.load_rules()
    print(f"Loaded {rules_loaded} YARA rules\n")

    # Scan current directory
    print("Scanning current directory...")
    result = engine.scan_directory(Path("."), recursive=False)

    print(f"\n{'=' * 60}")
    print("Scan Results:")
    print(f"  Files scanned: {result.total_files_scanned}")
    print(f"  Total matches: {result.total_matches}")
    print(f"  Errors: {len(result.scan_errors)}")

    if result.matches:
        print("\nMatches found:")
        for match in result.matches:
            severity = engine.get_severity_for_match(match)
            techniques = engine.get_attck_techniques(match)
            print(f"\n  Rule: {match.rule_name}")
            print(f"    Severity: {severity}")
            print(f"    File: {match.file_path}")
            print(f"    Tags: {', '.join(match.tags)}")
            if techniques:
                print(f"    ATT&CK: {', '.join(techniques)}")
            if match.matched_strings:
                print(f"    Strings: {match.matched_strings[:3]}")  # Show first 3

    print(f"\n{'=' * 60}")