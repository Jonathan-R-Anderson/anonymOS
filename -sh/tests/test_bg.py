#!/usr/bin/env python3
import os
import re
import select
import signal
import subprocess
import time

MARKER = "__END_JOBS__"
SLEEP_MARKER = "__AFTER_SLEEP__"


def read_line(proc, timeout=2.0):
    fd = proc.stdout.fileno()
    ready, _, _ = select.select([fd], [], [], timeout)
    if not ready:
        raise RuntimeError("Timed out waiting for shell output")
    line = proc.stdout.readline()
    if not line:
        raise RuntimeError("Shell exited unexpectedly")
    return line.rstrip("\n")


def run_jobs_and_collect(proc):
    proc.stdin.write("jobs\n")
    proc.stdin.write(f"echo {MARKER}\n")
    proc.stdin.flush()
    lines = []
    while True:
        line = read_line(proc)
        if line.strip() == MARKER:
            break
        if line:
            lines.append(line)
    return lines


def wait_for_marker(proc, marker):
    while True:
        line = read_line(proc)
        if line.strip() == marker:
            break


def main():
    print("Running test: bg resumes stopped jobs")
    proc = subprocess.Popen(
        ["stdbuf", "-o0", "./lfe-sh"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    try:
        proc.stdin.write("sleep 1 &\n")
        proc.stdin.flush()
        job_line = read_line(proc)
        match = re.match(r"^\[(\d+)\]\s+(\d+)$", job_line.strip())
        if not match:
            raise RuntimeError(f"Unexpected job launch output: {job_line}")
        job_id = match.group(1)
        pgid = int(match.group(2))

        os.killpg(pgid, signal.SIGTSTP)
        time.sleep(0.1)

        lines = run_jobs_and_collect(proc)
        if not any("Stopped" in line for line in lines):
            raise RuntimeError("jobs output did not report the job as stopped")

        proc.stdin.write(f"bg %{job_id}\n")
        proc.stdin.flush()
        bg_output = read_line(proc)
        if "&" not in bg_output:
            raise RuntimeError(f"Unexpected bg output: {bg_output}")

        proc.stdin.write("sleep 1.2\n")
        proc.stdin.write(f"echo {SLEEP_MARKER}\n")
        proc.stdin.flush()
        wait_for_marker(proc, SLEEP_MARKER)

        lines = run_jobs_and_collect(proc)
        if not any("Completed" in line for line in lines):
            raise RuntimeError("jobs output did not report the resumed job as completed")

        proc.stdin.close()
        proc.wait(timeout=5)
        print("  [PASS]")
        print("\nBackground job test passed!")
    finally:
        if proc.poll() is None:
            try:
                proc.stdin.close()
                proc.wait(timeout=1)
            except Exception:
                proc.terminate()
                proc.wait(timeout=1)


if __name__ == "__main__":
    main()
