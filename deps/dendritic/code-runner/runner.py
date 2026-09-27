"""Sandboxed judge for arcade code submissions.

THREAT MODEL
------------
Everything arriving here is hostile by assumption: it is arbitrary code written
by anyone with a slip. The containment is layered, because any single layer will
eventually have a hole:

  1. Process    - each run is a fresh subprocess, never eval() in this one.
  2. Identity   - the container runs as an unprivileged uid with no new privs.
  3. Resources  - RLIMIT_CPU / AS / NPROC / FSIZE are set in the child before
                  exec, so a fork bomb or a 50GB allocation dies rather than
                  taking the node down with it.
  4. Time       - a wall-clock timeout kills the whole process group, which
                  RLIMIT_CPU alone would not (a sleeping process burns no CPU).
  5. Filesystem - the image runs read-only with a per-run temp dir as the only
                  writable path.
  6. Network    - a NetworkPolicy denies this pod all egress. Nothing here
                  should ever be the only thing standing between submitted code
                  and the internet.

Layers 5 and 6 live in the manifest, not in this file, and are deliberately
noted here so they are not dropped in a future edit.

This service is reachable only from the backend on the cluster network; it is
never exposed publicly.
"""
import json
import os
import resource
import shutil
import signal
import subprocess
import sys
import tempfile

from flask import Flask, jsonify, request

app = Flask(__name__)

# Deliberately small. These are practice exercises, not batch jobs.
CPU_SECONDS = int(os.environ.get("RUNNER_CPU_SECONDS", "5"))
WALL_SECONDS = int(os.environ.get("RUNNER_WALL_SECONDS", "10"))
MEMORY_BYTES = int(os.environ.get("RUNNER_MEMORY_MB", "256")) * 1024 * 1024
MAX_PROCESSES = int(os.environ.get("RUNNER_MAX_PROCESSES", "64"))
MAX_FILE_BYTES = int(os.environ.get("RUNNER_MAX_FILE_MB", "8")) * 1024 * 1024
MAX_SOURCE_BYTES = 64 * 1024
MAX_OUTPUT_BYTES = 32 * 1024

LANGUAGES = {
    "python": {"file": "main.py", "argv": [sys.executable, "-I", "-B", "main.py"]},
    "javascript": {"file": "main.js", "argv": ["node", "--no-warnings", "main.js"]},
}


def _limits():
    """Applied in the child between fork and exec."""
    # Own process group, so the timeout can kill descendants too.
    os.setsid()
    resource.setrlimit(resource.RLIMIT_CPU, (CPU_SECONDS, CPU_SECONDS))
    resource.setrlimit(resource.RLIMIT_AS, (MEMORY_BYTES, MEMORY_BYTES))
    resource.setrlimit(resource.RLIMIT_NPROC, (MAX_PROCESSES, MAX_PROCESSES))
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_FILE_BYTES, MAX_FILE_BYTES))
    # No core dumps: they are large, useless here, and land on disk.
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def run_once(language, source, stdin_text=""):
    """Execute one program. Returns a dict; never raises for user-code errors."""
    spec = LANGUAGES.get(language)
    if spec is None:
        return {"ok": False, "error": "unsupported language"}
    if len(source.encode("utf-8", "replace")) > MAX_SOURCE_BYTES:
        return {"ok": False, "error": "source too large"}

    workdir = tempfile.mkdtemp(prefix="run-")
    try:
        path = os.path.join(workdir, spec["file"])
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(source)

        # A scrubbed environment: no cluster service-discovery variables, no
        # tokens, no PATH surprises. Submitted code should learn nothing about
        # where it is running.
        env = {
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "HOME": workdir,
            "TMPDIR": workdir,
            "LANG": "C.UTF-8",
            "PYTHONDONTWRITEBYTECODE": "1",
            "NODE_OPTIONS": "--max-old-space-size=128",
        }
        process = subprocess.Popen(
            spec["argv"], cwd=workdir, env=env,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            preexec_fn=_limits, close_fds=True, start_new_session=False,
        )
        timed_out = False
        try:
            out, err = process.communicate(input=stdin_text.encode("utf-8", "replace"),
                                           timeout=WALL_SECONDS)
        except subprocess.TimeoutExpired:
            timed_out = True
            # The group, not just the leader: a child that outlived its parent
            # would otherwise keep running after we answered.
            try:
                os.killpg(os.getpgid(process.pid), signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                process.kill()
            out, err = process.communicate()

        def clip(raw):
            text = (raw or b"").decode("utf-8", "replace")
            if len(text) > MAX_OUTPUT_BYTES:
                return text[:MAX_OUTPUT_BYTES] + "\n... output truncated ..."
            return text

        return {
            "ok": True,
            "timed_out": timed_out,
            "exit_code": process.returncode,
            "stdout": clip(out),
            "stderr": clip(err),
        }
    except Exception as exc:                       # noqa: BLE001 - report, never leak a trace
        app.logger.exception("runner failed")
        return {"ok": False, "error": "runner failure: %s" % type(exc).__name__}
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def egress_reachable(host="1.1.1.1", port=443, timeout=2.0):
    """Can this container open an outbound connection?

    It must not be able to. Network isolation for untrusted code has to come
    from the kernel -- a NetworkPolicy, plus a seccomp profile -- because no
    amount of care inside a Python process can stop `import _socket`. But a
    manifest is exactly the kind of thing that gets edited, reordered or
    forgotten, and the failure is silent: everything keeps working and the only
    difference is that submitted code can now reach the internet.

    So the invariant is asserted from inside, at startup, and a container that
    finds it can reach the network refuses to serve.
    """
    import socket
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def enforce_isolation():
    """Fail closed on startup if egress is open. Returns True when contained."""
    if os.environ.get("RUNNER_ALLOW_EGRESS") == "i-understand-this-is-unsafe":
        # The escape hatch exists for local development, where there is no
        # NetworkPolicy. It is deliberately verbose so it cannot be set by
        # accident, and it is logged every time.
        app.logger.warning(
            "RUNNER: egress check bypassed by RUNNER_ALLOW_EGRESS. "
            "Untrusted code can reach the network. Never set this in production."
        )
        return True
    if egress_reachable():
        app.logger.critical(
            "RUNNER: outbound network is reachable from the sandbox. Refusing to "
            "serve. Apply the deny-egress NetworkPolicy for this pod "
            "(k8s/app/60-code-runner.yaml) before starting it."
        )
        return False
    return True


CONTAINED = enforce_isolation()


@app.route("/health")
def health():
    if not CONTAINED:
        return jsonify({"ok": False, "error": "sandbox is not network-isolated"}), 503
    return jsonify({"ok": True, "languages": sorted(LANGUAGES)})


@app.route("/run", methods=["POST"])
def run():
    if not CONTAINED:
        return jsonify({"ok": False, "error": "sandbox is not network-isolated"}), 503
    payload = request.get_json(silent=True) or {}
    result = run_once(
        payload.get("language", "python"),
        payload.get("source", ""),
        payload.get("stdin", "") or "",
    )
    return jsonify(result), (200 if result.get("ok") else 400)


@app.route("/judge", methods=["POST"])
def judge():
    """Run a program against test cases and report pass/fail per case.

    Comparison is whitespace-normalised per line, so trailing spaces and a
    missing final newline do not fail an otherwise correct answer.
    """
    if not CONTAINED:
        return jsonify({"ok": False, "error": "sandbox is not network-isolated"}), 503
    payload = request.get_json(silent=True) or {}
    language = payload.get("language", "python")
    source = payload.get("source", "")
    cases = payload.get("cases") or []
    if not isinstance(cases, list) or len(cases) > 25:
        return jsonify({"ok": False, "error": "bad test cases"}), 400

    def normalise(text):
        return "\n".join(line.rstrip() for line in (text or "").strip().splitlines())

    results, passed = [], 0
    for case in cases:
        outcome = run_once(language, source, str(case.get("input", "")))
        if not outcome.get("ok"):
            return jsonify(outcome), 400
        expected = normalise(str(case.get("output", "")))
        actual = normalise(outcome["stdout"])
        ok = (not outcome["timed_out"] and outcome["exit_code"] == 0
              and actual == expected)
        if ok:
            passed += 1
        results.append({
            "passed": ok,
            "timed_out": outcome["timed_out"],
            "expected": expected,
            "actual": actual,
            "stderr": outcome["stderr"][:2000],
        })

    return jsonify({
        "ok": True,
        "passed": passed,
        "total": len(cases),
        "all_passed": bool(cases) and passed == len(cases),
        "cases": results,
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8000")))
