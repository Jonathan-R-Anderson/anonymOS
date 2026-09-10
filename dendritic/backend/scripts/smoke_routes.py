#!/usr/bin/env python3
"""Boot the app and GET every registered page route.

This exists because static analysis cannot answer "will it serve a page".
Template syntax, endpoint resolution and import graphs were all verified
statically after the network-only strip; none of that renders a template, and
the failure mode that survives static checking is a context processor or a
model query that only runs when a request is in flight.

Run it against a real database. It needs the same environment the app needs.

    cd backend && python3 scripts/smoke_routes.py

Exit status is 0 only when every route returned a non-5xx status. A 4xx is
reported but not treated as failure: /admin correctly returns a redirect or a
403 to an unauthenticated client, and that is the route working.
"""

import os
import sys
import traceback

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Routes that legitimately need arguments or a session; GET-ing them blind
# proves nothing useful.
SKIP_PREFIXES = (
    "/static", "/dev", "/webhook", "/api/v1/status/report",
)


def main() -> int:
    try:
        import app as app_module
    except Exception:
        print("FATAL: the app did not import at all.\n")
        traceback.print_exc()
        return 2

    flask_app = getattr(app_module, "app", None)
    if flask_app is None:
        print("FATAL: no `app` object found in app.py")
        return 2

    targets = []
    for rule in flask_app.url_map.iter_rules():
        if "GET" not in (rule.methods or set()):
            continue
        if any(str(rule).startswith(p) for p in SKIP_PREFIXES):
            continue
        if "<" in str(rule):          # needs a parameter
            continue
        targets.append(str(rule))
    targets.sort()

    client = flask_app.test_client()
    failures, warnings = [], []

    print(f"probing {len(targets)} parameterless GET routes\n")
    for path in targets:
        try:
            resp = client.get(path, follow_redirects=False)
            code = resp.status_code
        except Exception as exc:  # a raised exception is worse than a 500
            failures.append((path, f"raised {type(exc).__name__}: {exc}"))
            print(f"  EXC  {path}  {type(exc).__name__}: {exc}")
            continue

        if code >= 500:
            failures.append((path, code))
            print(f"  FAIL {code}  {path}")
        elif code >= 400:
            warnings.append((path, code))
            print(f"  warn {code}  {path}")
        else:
            print(f"  ok   {code}  {path}")

    print()
    print(f"{len(targets)} routes | {len(failures)} server errors | {len(warnings)} 4xx")
    if warnings:
        print("\n4xx (usually auth-gated, check they are the ones you expect):")
        for path, code in warnings:
            print(f"  {code}  {path}")
    if failures:
        print("\nSERVER ERRORS — do not deploy until these are zero:")
        for path, code in failures:
            print(f"  {code}  {path}")
        return 1

    print("\nno server errors.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
