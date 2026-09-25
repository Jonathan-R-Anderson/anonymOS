#!/usr/bin/env python3
"""
Orin eBPF Real-Time Streamer Consumer

This script loads the pre-compiled eBPF program using system libbpf,
attaches to tracepoints, and consumes events from the ring buffer in real-time.
It queues events to the local SQLite database and triggers threat analysis.
"""

import os
import sys
import time
import signal
import sqlite3
import argparse
from datetime import datetime, timezone
from pathlib import Path
import ctypes
from ctypes import CDLL, c_char_p, c_int, c_void_p, c_size_t, CFUNCTYPE

# Add system-wide python package paths to access system libraries if run in a virtualenv
for path in ["/usr/lib/python3/dist-packages", "/usr/local/lib/python3/dist-packages"]:
    if path not in sys.path:
        sys.path.append(path)

# Configuration
DB_PATH = Path(__file__).parent.parent / "data" / "orin.db"
EBPF_PROGRAM_PATH = Path(__file__).parent / "streamer.c"
EBPF_ELF_PATH = Path(__file__).parent / "streamer.bpf.o"

# Ensure DB directory exists
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# Ctypes-based Libbpf Wrapper
# ---------------------------------------------------------------------------

libbpf = None
try:
    for lib_name in ["libbpf.so.1", "libbpf.so.0", "libbpf.so"]:
        try:
            libbpf = CDLL(lib_name)
            break
        except OSError:
            continue
except Exception:
    pass

# Setup ctypes signatures if libbpf is available
if libbpf:
    try:
        # struct bpf_object *bpf_object__open_file(const char *path, const struct bpf_object_open_opts *opts);
        libbpf.bpf_object__open_file.restype = c_void_p
        libbpf.bpf_object__open_file.argtypes = [c_char_p, c_void_p]

        # int bpf_object__load(struct bpf_object *obj);
        libbpf.bpf_object__load.restype = c_int
        libbpf.bpf_object__load.argtypes = [c_void_p]

        # int bpf_object__attach(struct bpf_object *obj);
        libbpf.bpf_object__attach.restype = c_int
        libbpf.bpf_object__attach.argtypes = [c_void_p]

        # struct bpf_map *bpf_object__find_map_by_name(const struct bpf_object *obj, const char *name);
        libbpf.bpf_object__find_map_by_name.restype = c_void_p
        libbpf.bpf_object__find_map_by_name.argtypes = [c_void_p, c_char_p]

        # int bpf_map__fd(const struct bpf_map *map);
        libbpf.bpf_map__fd.restype = c_int
        libbpf.bpf_map__fd.argtypes = [c_void_p]

        # void bpf_object__close(struct bpf_object *obj);
        libbpf.bpf_object__close.restype = None
        libbpf.bpf_object__close.argtypes = [c_void_p]

        # Ring buffer callback: typedef int (*ring_buffer_sample_fn)(void *ctx, void *data, size_t size);
        RING_BUFFER_CB = CFUNCTYPE(c_int, c_void_p, c_void_p, c_size_t)

        # struct ring_buffer *ring_buffer__new(int map_fd, ring_buffer_sample_fn sample_cb, void *ctx, const struct ring_buffer_opts *opts);
        libbpf.ring_buffer__new.restype = c_void_p
        libbpf.ring_buffer__new.argtypes = [c_int, RING_BUFFER_CB, c_void_p, c_void_p]

        # int ring_buffer__poll(struct ring_buffer *rb, int timeout_ms);
        libbpf.ring_buffer__poll.restype = c_int
        libbpf.ring_buffer__poll.argtypes = [c_void_p, c_int]

        # void ring_buffer__free(struct ring_buffer *rb);
        libbpf.ring_buffer__free.restype = None
        libbpf.ring_buffer__free.argtypes = [c_void_p]
    except Exception as sig_err:
        # Fallback if symbols aren't fully resolved
        libbpf = None


class RingBuffer:
    def __init__(self, loader, map_name: str):
        self.loader = loader
        self.map_name = map_name
        self.rb = None
        self.cb_wrapper = None
        
        if not libbpf:
            raise ImportError("libbpf shared library is not loaded.")

        # Get map FD
        map_ptr = libbpf.bpf_object__find_map_by_name(self.loader.obj, map_name.encode('utf-8'))
        if not map_ptr:
            raise RuntimeError(f"Map '{map_name}' not found in eBPF program.")
        self.map_fd = libbpf.bpf_map__fd(map_ptr)
        if self.map_fd < 0:
            raise RuntimeError(f"Failed to get file descriptor for map '{map_name}'.")

    def open_ring_buffer(self, user_callback):
        # We need to preserve the ctypes callback reference to prevent garbage collection
        def ring_buffer_cb(ctx, data, size):
            user_callback(ctx, data, size)
            return 0
        
        self.cb_wrapper = RING_BUFFER_CB(ring_buffer_cb)
        self.rb = libbpf.ring_buffer__new(self.map_fd, self.cb_wrapper, None, None)
        if not self.rb:
            raise RuntimeError(f"Failed to create ring buffer for map '{self.map_name}'.")

    def poll(self, timeout_ms: int):
        if not self.rb:
            raise RuntimeError("Ring buffer is not opened.")
        return libbpf.ring_buffer__poll(self.rb, timeout_ms)

    def close(self):
        if self.rb:
            libbpf.ring_buffer__free(self.rb)
            self.rb = None
        self.cb_wrapper = None


class BPF:
    """Libbpf loader class designed to act as a drop-in replacement for BCC's BPF interface."""
    def __init__(self, src_file=None, elf_file=None):
        if not libbpf:
            raise ImportError("Could not find system libbpf library (libbpf.so). Please install libbpf.")

        if elf_file:
            self.elf_path = Path(elf_file)
        elif src_file:
            src_path = Path(src_file)
            self.elf_path = src_path.parent / "streamer.bpf.o"
        else:
            self.elf_path = EBPF_ELF_PATH

        self.obj = None
        self.maps = {}
        self._load()

    def _load(self):
        if not self.elf_path.exists():
            raise FileNotFoundError(f"eBPF ELF file not found at {self.elf_path}")

        # Open BPF object file
        self.obj = libbpf.bpf_object__open_file(str(self.elf_path).encode('utf-8'), None)
        if not self.obj or self.obj == c_void_p(-1).value or self.obj == 0:
            raise RuntimeError(f"Failed to open eBPF ELF file {self.elf_path}")

        # Load programs/maps
        err = libbpf.bpf_object__load(self.obj)
        if err < 0:
            self.close()
            raise RuntimeError(f"Failed to load eBPF object (code {err})")

        # Auto-attach programs to tracepoints
        err = libbpf.bpf_object__attach(self.obj)
        if err < 0:
            self.close()
            raise RuntimeError(f"Failed to attach eBPF programs (code {err})")

    def __getitem__(self, map_name: str) -> RingBuffer:
        if map_name not in self.maps:
            self.maps[map_name] = RingBuffer(self, map_name)
        return self.maps[map_name]

    def close(self):
        for map_obj in list(self.maps.values()):
            try:
                map_obj.close()
            except Exception:
                pass
        self.maps.clear()

        if self.obj:
            libbpf.bpf_object__close(self.obj)
            self.obj = None


# ---------------------------------------------------------------------------
# Database and Event Handlers
# ---------------------------------------------------------------------------

def init_db():
    """Initialize the database schema for streaming events if not exists."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS stream_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp_ns INTEGER,
        timestamp_human TEXT,
        pid INTEGER,
        uid INTEGER,
        event_type INTEGER,
        comm TEXT,
        filename TEXT,
        processed BOOLEAN DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_stream_ts ON stream_events(timestamp_ns)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_stream_pid ON stream_events(pid)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_stream_type ON stream_events(event_type)")

    conn.commit()
    conn.close()

def parse_event_type(t):
    types = {1: "EXEC", 2: "CONNECT", 3: "FILE_OPEN"}
    return types.get(t, "UNKNOWN")

def handle_event(ctx, data, size):
    """Callback function called when an event is available in the ring buffer."""
    class Event(ctypes.Structure):
        _fields_ = [
            ("pid", ctypes.c_uint),
            ("uid", ctypes.c_uint),
            ("etype", ctypes.c_uint),
            ("comm", ctypes.c_char * 16),
            ("filename", ctypes.c_char * 256),
            ("timestamp", ctypes.c_ulonglong)
        ]

    event = ctypes.cast(data, ctypes.POINTER(Event)).contents

    ts_ns = event.timestamp
    ts_human = datetime.fromtimestamp(ts_ns / 1e9, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]

    comm_str = event.comm.decode('utf-8', errors='ignore').rstrip('\x00')
    filename_str = event.filename.decode('utf-8', errors='ignore').rstrip('\x00')
    etype = parse_event_type(event.etype)

    print(f"[{ts_human}] {etype} | PID:{event.pid} UID:{event.uid} | Comm:{comm_str} | File:{filename_str}")

    # Store in database
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO stream_events (timestamp_ns, timestamp_human, pid, uid, event_type, comm, filename)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (ts_ns, ts_human, event.pid, event.uid, event.etype, comm_str, filename_str))
        conn.commit()
        conn.close()

    except Exception as e:
        print(f"Error storing event: {e}")


def _compile_ebpf_binary():
    vmlinux_path = EBPF_PROGRAM_PATH.parent / "vmlinux.h"
    if not vmlinux_path.exists():
        print(f"[*] 'vmlinux.h' not found. Checking system BTF support to auto-generate...")
        btf_source = Path("/sys/kernel/btf/vmlinux")
        if btf_source.exists():
            import shutil
            bpftool_bin = shutil.which("bpftool")
            if bpftool_bin:
                print(f"[*] Found bpftool at {bpftool_bin}. Generating vmlinux.h from {btf_source}...")
                try:
                    import subprocess
                    subprocess.run(
                        [bpftool_bin, "btf", "dump", "file", str(btf_source), "format", "c"],
                        stdout=open(vmlinux_path, "w"),
                        check=True
                    )
                    print(f"[+] Successfully generated 'vmlinux.h' dynamically.")
                except Exception as gen_err:
                    print(f"[!] Error: Failed to generate vmlinux.h dynamically: {gen_err}")
                    if vmlinux_path.exists():
                        try:
                            vmlinux_path.unlink()
                        except Exception:
                            pass
            else:
                print("[!] 'bpftool' is not available on this system.")
        else:
            print(f"[!] Kernel BTF structure not found at {btf_source}.")

        if not vmlinux_path.exists():
            print("\n❌ Error: Cannot compile eBPF streaming. 'vmlinux.h' is missing.")
            print("   Please execute the setup script to install dependencies and configure eBPF:")
            print("   $ sudo ./scripts/setup_ebpf.sh")
            print("   Or consult docs/EBPF_TROUBLESHOOTING.md for manual steps.\n")
            sys.exit(1)

    # Compile using clang
    import shutil
    import subprocess
    clang_bin = shutil.which("clang")
    if not clang_bin:
        print("\n❌ Error: 'clang' compiler not found. Cannot compile streamer.c.")
        print("   Please install clang on the build machine or distribute streamer.bpf.o.\n")
        sys.exit(1)

    print(f"[*] Compiling {EBPF_PROGRAM_PATH} -> {EBPF_ELF_PATH} using clang...")
    try:
        import platform
        arch = platform.machine()
        target_arch = "x86"
        if "arm" in arch or "aarch" in arch:
            target_arch = "arm64"
        elif "powerpc" in arch:
            target_arch = "powerpc"
        elif "mips" in arch:
            target_arch = "mips"
        elif "s390" in arch:
            target_arch = "s390"

        cmd = [
            clang_bin,
            "-g", "-O2",
            "-target", "bpf",
            f"-D__TARGET_ARCH_{target_arch}",
            "-c", str(EBPF_PROGRAM_PATH),
            "-o", str(EBPF_ELF_PATH)
        ]
        subprocess.run(cmd, check=True)
        print(f"[+] Successfully compiled eBPF ELF binary: {EBPF_ELF_PATH}")
    except Exception as e:
        print(f"❌ Error: Compilation failed: {e}")
        if EBPF_ELF_PATH.exists():
            try:
                EBPF_ELF_PATH.unlink()
            except Exception:
                pass
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Orin eBPF Real-Time Streamer")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose debug output")
    args = parser.parse_args()

    print(f"[*] Orin eBPF Streamer Starting...")

    # Initialize Database
    init_db()
    print(f"[*] Database ready at: {DB_PATH}")

    # Build ELF if missing
    if not EBPF_ELF_PATH.exists():
        print(f"[*] Pre-compiled eBPF ELF binary not found at {EBPF_ELF_PATH}.")
        if not EBPF_PROGRAM_PATH.exists():
            print(f"❌ Error: eBPF C source file not found at {EBPF_PROGRAM_PATH}")
            sys.exit(1)
        _compile_ebpf_binary()

    # Load BPF Program
    try:
        b = BPF(elf_file=EBPF_ELF_PATH)
    except Exception as e:
        print(f"[!] Failed to load eBPF program: {e}")
        print("Note: This requires root privileges, a kernel with BTF support, and libbpf installed.")
        print("For details, please refer to docs/EBPF_TROUBLESHOOTING.md.")
        sys.exit(1)

    print("[*] eBPF program loaded successfully.")

    # Attach to Ring Buffer
    rb = b["rb"]
    rb.open_ring_buffer(handle_event)

    print("[*] Attached to ring buffer. Waiting for events... (Ctrl+C to stop)")

    running = True
    def signal_handler(sig, frame):
        nonlocal running
        print("\n[*] Shutting down gracefully...")
        running = False

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        while running:
            rb.poll(100)
    except KeyboardInterrupt:
        pass
    finally:
        rb.close()
        b.close()
        print("[*] Orin eBPF Streamer stopped.")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[!] Warning: Not running as root. eBPF programs usually require root privileges.")

    main()