#!/usr/bin/env python3
"""Generate the master secret that encrypts public-interest submissions.

    python3 backend/scripts/generate_report_key.py

Prints one line to put in the environment. Nothing is written to disk and
nothing is sent anywhere -- this is deliberately a thing you copy, so the key
never exists in a file somebody forgets to delete.

WHY THIS IS NOT THE STORAGE KEY
-------------------------------
`STORAGE_CONTENT_MASTER_SECRET` already decrypts every stored media object on
the site. If reports were rooted in it, "authorised to read a civil-rights
complaint" and "holds the key to all site content" would be the same capability.
`services/report_crypto.py` therefore reads `REPORT_CONTENT_MASTER_SECRET` and
has NO fallback: with it unset, submissions are refused rather than sealed under
the wrong key.

WHAT LOSING THIS KEY MEANS
--------------------------
Every report ever filed becomes permanently unreadable. The ciphertext survives
in the DHT and nothing can open it -- not the operator, not a backup of the
database, not the storage nodes. The index rows remain, so you would know how
many reports existed and when they arrived, and never what they said.

Back it up somewhere that survives this machine, before the first submission
rather than after.

WHAT HAVING IT MEANS
--------------------
Whoever holds it can read every report. That is inherent to the design and worth
being plain about: the encryption protects submissions from the storage network
and from anyone who reaches it. It does not protect them from you.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services import report_crypto  # noqa: E402


def main():
    existing = (os.getenv(report_crypto.ENV_MASTER) or "").strip()
    if existing:
        sys.stderr.write(
            "%s is ALREADY SET in this environment.\n\n"
            "Generating a new one is not a rotation -- there is no re-encryption\n"
            "path, so every report filed under the old key becomes unreadable\n"
            "the moment you replace it. If you meant to rotate, that needs a\n"
            "migration that reads every report with the old key and re-seals it\n"
            "with the new one, and it does not exist yet.\n\n"
            % report_crypto.ENV_MASTER)
        return 1

    print("%s=%s" % (report_crypto.ENV_MASTER,
                     report_crypto.generate_master_secret()))
    sys.stderr.write(
        "\nPut that in the environment (.env / the maniwani-env secret), then\n"
        "restart. Back it up somewhere off this machine first: losing it makes\n"
        "every report permanently unreadable.\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
