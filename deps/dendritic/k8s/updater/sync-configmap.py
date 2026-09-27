#!/usr/bin/env python3
"""Keep 30-configmap-updater.yaml's embedded update.sh identical to update.sh.

WHY THIS EXISTS
---------------
The ConfigMap carries the whole updater script inline (see the manifest header
for why it is not baked into the image). That means there are TWO copies of
update.sh in the repo, and nothing stopped them drifting.

They had drifted, badly: the manifest held an 892-line copy while update.sh was
2171 lines, so the deployed updater silently ran a version with no
consume_requests() at all. The admin "Update now" button wrote its request file
and the updater — running old code that had never heard of request files —
ignored it forever. The button looked broken; the real bug was two files
disagreeing with no check between them.

USAGE
    python3 k8s/updater/sync-configmap.py            # rewrite the manifest
    python3 k8s/updater/sync-configmap.py --check    # verify only; exit 1 on drift

Run --check in CI, or before applying the manifest, so this cannot rot again.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "update.sh")
MANIFEST = os.path.join(HERE, "30-configmap-updater.yaml")
MARKER = "  update.sh: |\n"


def embedded_script(manifest_text):
    """The update.sh currently inlined in the manifest, de-indented."""
    if MARKER not in manifest_text:
        raise SystemExit("%s has no '%s' block" % (MANIFEST, MARKER.strip()))
    body = manifest_text[manifest_text.index(MARKER) + len(MARKER):]
    out = []
    for line in body.split("\n"):
        if line.startswith("    "):
            out.append(line[4:])
        elif not line.strip():
            out.append("")
        else:
            # Any non-blank line at lower indentation ends the block scalar.
            break
    return "\n".join(out)


def render(manifest_text, script_text):
    head = manifest_text[:manifest_text.index(MARKER)]
    indented = "".join(
        ("    " + line if line.strip() else "") + "\n"
        for line in script_text.split("\n")
    )
    return head + MARKER + indented


def main():
    check_only = "--check" in sys.argv
    script_text = open(SCRIPT, encoding="utf-8").read()
    manifest_text = open(MANIFEST, encoding="utf-8").read()

    current = embedded_script(manifest_text)
    if current.rstrip("\n") == script_text.rstrip("\n"):
        print("in sync: 30-configmap-updater.yaml matches update.sh")
        return 0

    if check_only:
        sys.stderr.write(
            "DRIFT: 30-configmap-updater.yaml's embedded update.sh does not match "
            "update.sh (%d vs %d lines).\n"
            "The deployed updater would run the manifest's copy, not the file you "
            "edited.\nRun: python3 k8s/updater/sync-configmap.py\n"
            % (len(current.split("\n")), len(script_text.split("\n")))
        )
        return 1

    open(MANIFEST, "w", encoding="utf-8").write(render(manifest_text, script_text))
    print("updated 30-configmap-updater.yaml from update.sh (%d lines)"
          % len(script_text.split("\n")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
