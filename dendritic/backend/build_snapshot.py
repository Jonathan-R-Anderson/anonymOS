"""Ask the running site to build one emergency snapshot.

    python3 build_snapshot.py --genkey     # print a fresh publisher keypair
    python3 build_snapshot.py --help       # how to trigger a build

WHY THIS NO LONGER BUILDS ANYTHING ITSELF
-----------------------------------------
It used to. Importing `app` to get a context re-runs the startup DDL — the
`ALTER TABLE ... ADD COLUMN IF NOT EXISTS` block — against the database the
live process is already using. Those take AccessExclusiveLock. Running it once
deadlocked against the serving process and took the pod down with it:

    Process A waits for AccessExclusiveLock on relation 25297
    Process B waits for AccessShareLock on relation 25710
    ... blocked by process A

The snapshot was built and published correctly, and the site went down anyway.
So the build now happens inside the process that is already running, and this
file is a keygen plus instructions.

Trigger a build with an authenticated POST to /admin/snapshot/build, or wait for
the hourly timer once phase 2 lands.
"""

import sys


USAGE = """Build a snapshot by asking the running site:

    POST /admin/snapshot/build        (admin session required)

Never by running a second copy of the application: importing `app` re-runs the
startup DDL against a live database and can deadlock the serving process.
"""


def main():
    args = set(sys.argv[1:])

    if "--genkey" in args:
        # Safe to do here: generating a keypair touches nothing but entropy.
        from nacl.signing import SigningKey
        import base64

        key = SigningKey.generate()
        seed = base64.b64encode(bytes(key)).decode("ascii")
        public = base64.b64encode(bytes(key.verify_key)).decode("ascii")
        print("SNAPSHOT_SIGNING_KEY=%s" % seed)
        print("# public key (served at /.well-known/syndichan/snapshot-key.json)")
        print("# %s" % public)
        print("#")
        print("# Put the private line in .env. It must NOT be the origin signing")
        print("# key: this one is used by a process that crawls the whole site.")
        return 0

    print(USAGE)
    return 0


if __name__ == "__main__":
    sys.exit(main())
