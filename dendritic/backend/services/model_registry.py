"""Import every module under model/ so db.metadata is complete AT RUNTIME.

WHY THIS IS NOT JUST bootstrap.py's COPY
----------------------------------------
`bootstrap.import_all_models()` does the same walk, and it cannot be reused: the
first line of bootstrap.py is `from gevent import monkey`, so importing it from
a request path would monkey-patch the interpreter as a side effect of asking a
question about models.

WHY IT IS NEEDED AT ALL
-----------------------
`db.metadata` contains exactly the models that have been IMPORTED. bootstrap.py
imports them all, but the Dockerfile runs bootstrap at IMAGE BUILD time -- so a
running container has only the models something on the live import path happened
to pull in. Measured against production: 16 tables reference `slip.id` according
to the running app, and `post_vote` is not one of them, because nothing at
runtime imports `model.PostVote`.

That matters because `blueprints.admin._slip_references()` derives the deletion
list FROM THE METADATA. Its own docstring records why it stopped being a
hand-written list: "every one of them with a NOT NULL slip_id made account
deletion fail with a foreign-key violation... any account that had ever voted on
a post could not be deleted at all." Deriving it from metadata fixed the
stale-list problem and quietly introduced a completeness one -- the derivation is
only as good as what has been imported, and at runtime that is a subset.

`post_vote` exists in the production database with a foreign key to `slip`, and
is absent from the runtime metadata. It holds zero rows today, so the bug is
latent rather than active: the first vote cast on a post makes that account
undeletable, with the same silent "Could not delete slip" the docstring
describes.
"""

import importlib
import pkgutil

_IMPORTED = False


def import_all_models(force=False):
    """Import every `model.*` module. Idempotent and safe to call on a request.

    Returns the list of modules that could not be imported, so a caller can say
    so rather than silently working from an incomplete picture. A model that
    fails to import contributes no table, which is exactly the condition this
    function exists to prevent going unnoticed.
    """
    global _IMPORTED
    if _IMPORTED and not force:
        return []

    import model as model_pkg

    failed = []
    for info in pkgutil.iter_modules(model_pkg.__path__):
        if info.name.startswith("_"):
            continue
        try:
            importlib.import_module("model." + info.name)
        except Exception as error:  # noqa: BLE001 -- reported to the caller
            failed.append((info.name, str(error)))
    _IMPORTED = True
    return failed
