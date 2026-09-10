"""Client for the sandboxed code judge (code-runner service).

The backend never executes submitted code itself. It hands it to an isolated
pod that has no network, no service-account token, a read-only root filesystem
and per-run resource limits, and only reads back a verdict. If that pod is
missing or unhealthy, judging is unavailable -- it never silently falls back to
running the code here.
"""
import json
import os
import urllib.error
import urllib.request

from shared import app

RUNNER_URL = os.environ.get("CODE_RUNNER_URL", "http://code-runner:8000")
# Comfortably above the runner's own 10s wall clock times a few test cases,
# but bounded so a wedged runner cannot hold a gevent worker indefinitely.
TIMEOUT = float(os.environ.get("CODE_RUNNER_TIMEOUT", "45"))

LANGUAGES = ("python", "javascript")


def available():
    """Is the judge up AND reporting itself contained?"""
    try:
        with urllib.request.urlopen(RUNNER_URL + "/health", timeout=3) as response:
            if response.status != 200:
                return False
            return bool(json.loads(response.read(4096) or b"{}").get("ok"))
    except Exception:
        return False


def _post(path, payload):
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        RUNNER_URL + path, data=body,
        headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            return json.loads(response.read(1 << 20) or b"{}")
    except urllib.error.HTTPError as error:
        try:
            return json.loads(error.read(1 << 20) or b"{}")
        except Exception:
            return {"ok": False, "error": "judge rejected the request"}
    except Exception:
        app.logger.exception("code runner unreachable at %s", RUNNER_URL)
        return {"ok": False, "error": "the code judge is unavailable"}


def run(language, source, stdin_text=""):
    if language not in LANGUAGES:
        return {"ok": False, "error": "unsupported language"}
    return _post("/run", {"language": language, "source": source, "stdin": stdin_text})


def judge(language, source, cases):
    """Run source against test cases. Returns the runner's verdict dict."""
    if language not in LANGUAGES:
        return {"ok": False, "error": "unsupported language"}
    return _post("/judge", {"language": language, "source": source,
                            "cases": list(cases)[:25]})


def cases_for_problem(problem):
    """Turn a problem's worked examples into judge test cases.

    The upstream content has examples for humans, not a hidden test suite, so
    those examples ARE the tests. That is weaker than a real judge -- someone
    can special-case the sample inputs -- which is why solving a problem is
    worth XP toward a personal chart and nothing else.
    """
    cases = []
    for example in (problem.get("examples") or []):
        if example.get("input") is None or example.get("output") is None:
            continue
        cases.append({"input": str(example["input"]),
                      "output": str(example["output"])})
    if cases:
        return cases

    # Imported problems carry a real hidden suite in `testCases` rather than
    # worked examples — a stronger judge than the above, since the cases cannot
    # all be special-cased.
    #
    # Gated on `judgeable`, which the importer sets only when the whole suite
    # converted AND the language is one this runner executes. The export is
    # mostly ruby, cpp, java, php and swift; offering those for judging produces
    # a Submit button that can never pass, which is worse than offering none.
    if not problem.get("judgeable"):
        return []
    for case in (problem.get("testCases") or []):
        if case.get("input") is None or case.get("expectedOutput") is None:
            continue
        cases.append({"input": str(case["input"]),
                      "output": str(case["expectedOutput"])})
    return cases


def run_program(language, files, entrypoint, stdin_text=""):
    """Run a MULTI-FILE program in the sandbox.

    The runner's API takes one source string, not a file tree, and changing that
    means changing the runner image. So the several files are materialised by a
    bootstrap that the single source slot carries: it writes each file into the
    sandbox's own scratch directory and then executes the entry point.

    That is a real technique rather than a workaround, but it has two honest
    costs and they are worth naming here rather than being discovered:

      * A syntax error in the entry point surfaces with the bootstrap in the
        traceback, so the reported line numbers belong to the user's file but
        the frames above it do not.
      * The whole program is one string, so the runner's existing size and
        time limits apply to the total rather than per file.

    Both are acceptable for a queue whose jobs are minutes long. If this grows
    into something bigger, the right fix is a `files` field on the runner API,
    not a cleverer bootstrap.
    """
    if language not in LANGUAGES:
        return {"ok": False, "error": "unsupported language: %s" % language}
    if entrypoint not in files:
        return {"ok": False, "error": "entry point %r is not one of the files" % entrypoint}

    payload = json.dumps(files)
    if language == "python":
        source = (
            "import json, os, sys\n"
            "_F = json.loads(%r)\n"
            "for _p, _c in _F.items():\n"
            "    _d = os.path.dirname(_p)\n"
            "    if _d: os.makedirs(_d, exist_ok=True)\n"
            "    open(_p, 'w', encoding='utf-8').write(_c)\n"
            "sys.path.insert(0, os.getcwd())\n"
            "sys.argv = [%r]\n"
            "exec(compile(_F[%r], %r, 'exec'), {'__name__': '__main__', '__file__': %r})\n"
            % (payload, entrypoint, entrypoint, entrypoint, entrypoint)
        )
    else:
        source = (
            "const _F = %s;\n"
            "const fs = require('fs'), path = require('path');\n"
            "for (const [p, c] of Object.entries(_F)) {\n"
            "  const d = path.dirname(p);\n"
            "  if (d && d !== '.') fs.mkdirSync(d, {recursive: true});\n"
            "  fs.writeFileSync(p, c);\n"
            "}\n"
            "require(path.resolve(%s));\n"
            % (payload, json.dumps(entrypoint))
        )
    return run(language, source, stdin_text)
