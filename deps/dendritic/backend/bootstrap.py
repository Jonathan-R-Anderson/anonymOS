from gevent import monkey
monkey.patch_all()

import json
import os

from alembic import command
from alembic.config import Config

from model.Ban import Ban
from model.BlockedMediaHash import BlockedMediaHash  # noqa: F401
from model.BlockedSourcePost import BlockedSourcePost  # noqa: F401
from model.FrontPageUpdate import FrontPageUpdate  # noqa: F401
from model.BanPageAsset import BanPageAsset  # noqa: F401
from model.WarrantCanary import WarrantCanaryEntry  # noqa: F401
from model.VideoStatsArchive import VideoStatsArchive  # noqa: F401
from model.CaptchaChallenge import CaptchaChallenge, CaptchaQuestion  # noqa: F401
from model.Report import Report  # noqa: F401
from model.Analytics import AnalyticsAnonProfile, AnalyticsConsent, AnalyticsDeletion, AnalyticsEvent, AnalyticsIngestIssue, AnalyticsJobState, AnalyticsSession, AnalyticsUserProfile, ContentFeature, ensure_analytics_schema, secure_analytics_schema  # noqa: F401
from model.Recommendation import CollaborativeSimilarity, RecommendationInteraction, RecommendationLog  # noqa: F401
from model.Experiment import BehaviorMetricDaily, ExperimentDefinition, ExperimentExposure, ExperimentGuardrailSnapshot, RecommendationSatisfaction  # noqa: F401
from model.AdvancedRecommendation import AlgorithmAudit, BehaviorSequence, ContextualBanditArm, CreatorExposureDaily, ModelHealthSnapshot, NotificationRecommendation, RecommendationPreference, UserValuePrediction  # noqa: F401
from model.Board import Board
from model.BoardBanner import BoardBanner  # noqa: F401
from model.BoardBookmark import BoardBookmark  # noqa: F401
from model.PostVote import PostVote  # noqa: F401
from model.OutboundReply import OutboundReply  # noqa: F401
from model.WordFilter import WordFilter, WordFilterBoard  # noqa: F401
from model.Slip import configured_admin_wallet_address, ensure_wallet_admin_slip, gen_slip
from model.SiteSetting import SiteSetting
from model.Tag import Tag
from model.Media import storage
from shared import app, db


MIGRATION_DIR = "./migrations"
BOOTSTRAP_SETTINGS = "./deploy-configs/bootstrap-config.json"
SECRET_FILE = "./deploy-configs/secret"


def import_all_models():
    """Import every module under model/ so db.metadata is complete.

    WHY THIS EXISTS (roadmap F1).

    `db.create_all()` creates tables for the models that have been IMPORTED at
    the moment it runs -- nothing else. This file imported 23 model modules by
    hand, which reached 56 tables transitively. The tree defines 145.

    `save_db()` then stamps alembic at `head`, which tells alembic every
    migration is already applied. On a FRESH database that is the whole failure:
    create_all makes 56 tables, the stamp skips all 74 migrations, and the other
    89 tables are never created by anything, ever. Each one fails at first use
    with "relation does not exist", a long way from its cause.

    An existing database never hit it -- ensure_runtime.py runs `update_db()`
    when the `board` table is present, and the migrations do their job. It is
    exactly and only a fresh install that ends up permanently short.

    Importing the package instead of a list makes the metadata complete BY
    CONSTRUCTION. A new model file is picked up because it exists, not because
    somebody remembered to add a line here -- and forgetting that line was the
    bug.
    """
    import importlib
    import pkgutil

    import model as model_pkg

    failed = []
    for info in pkgutil.iter_modules(model_pkg.__path__):
        if info.name.startswith("_"):
            continue
        try:
            importlib.import_module("model." + info.name)
        except Exception as error:  # noqa: BLE001 -- reported, then verified below
            # Not fatal here. A model that cannot be imported has no table in
            # the metadata, so verify_schema() below reports it as missing with
            # the name of the table rather than of the module -- which is what
            # an operator needs. Raising here would also make one broken
            # optional model stop a whole installation.
            failed.append((info.name, error))
    if failed:
        for name, error in failed:
            app.logger.error("bootstrap: could not import model.%s: %s: %s",
                             name, type(error).__name__, error)
    return failed


def verify_schema():
    """Every table the models declare must actually exist. Raise if not.

    This is the check that turns F1 from a silent permanent defect into a loud
    startup failure. It is deliberately AFTER create_all and BEFORE anything
    writes: an installation that is going to be missing tables should refuse to
    start rather than serve until somebody touches the one feature that needs
    the table nobody made.
    """
    from sqlalchemy import inspect as sa_inspect

    inspector = sa_inspect(db.engine)

    # Grouped BY SCHEMA. The analytics models live in their own Postgres schema
    # (see ensure_analytics_schema), and get_table_names() with no argument only
    # lists the default one -- so a flat comparison reported 25 perfectly healthy
    # tables as missing. Found by running this against a fresh database, which is
    # the only way a schema check gets tested.
    by_schema = {}
    for name, table in db.metadata.tables.items():
        by_schema.setdefault(table.schema, set()).add(table.name)

    # sqlite has no schemas, and the analytics models are schema-qualified on
    # purpose (ensure_analytics_schema is a no-op off Postgres). Checking them
    # on sqlite reports 25 healthy tables as missing -- a check that cries wolf
    # on the development backend is a check people learn to ignore.
    schema_capable = db.engine.url.get_backend_name() in ("postgresql", "postgres")

    missing = []
    declared = 0
    for schema, names in by_schema.items():
        if schema is not None and not schema_capable:
            continue
        declared += len(names)
        try:
            actual = set(inspector.get_table_names(schema=schema))
        except Exception:
            # A schema that does not exist at all: every table in it is missing,
            # which is the right answer and a louder one than a stack trace.
            actual = set()
        for missing_name in sorted(names - actual):
            missing.append(("%s.%s" % (schema, missing_name)) if schema else missing_name)
    missing.sort()
    if missing:
        raise RuntimeError(
            "bootstrap: %d of %d declared tables were not created: %s. "
            "This is roadmap F1: create_all() only builds tables for models that "
            "are imported, and save_db() stamps alembic at head so no migration "
            "will ever build the rest."
            % (len(missing), declared, ", ".join(missing[:20])
               + ("..." if len(missing) > 20 else ""))
        )
    return declared


def initialize_db():
    ensure_analytics_schema()
    import_all_models()
    db.create_all()
    secure_analytics_schema()
    app.logger.info("bootstrap: schema verified, %d tables", verify_schema())


def grab_settings():
    settings_file = open(BOOTSTRAP_SETTINGS)
    return json.load(settings_file)


def setup_boards(json_settings):
    for board_info in json_settings["boards"]:
        name = board_info["name"]
        threadlimit = board_info.get("threadlimit") or json_settings["default_threadlimit"]
        mimetypes = board_info.get("mimetypes")
        if mimetypes is None:
            mimetypes = json_settings["default_mimetypes"]
            extra_mimetypes = board_info.get("extra_mimetypes")
            if extra_mimetypes:
                mimetypes = mimetypes + "|" + extra_mimetypes
        rule_file = board_info.get("rules")
        rules = ""
        if rule_file:
            rules = open(os.path.join("deploy-configs", rule_file)).read()
        board = Board(name=name, max_threads=threadlimit, mimetypes=mimetypes, rules=rules)
        db.session.add(board)


def setup_slips(json_settings):
    for slip_info in json_settings["slips"]:
        username = slip_info["username"]
        password = slip_info["password"]
        is_admin = slip_info.get("is_admin") or False
        is_mod = slip_info.get("is_mod") or False
        slip = gen_slip(username, password)
        slip.is_admin = is_admin
        slip.is_mod = is_mod
        db.session.add(slip)
        db.session.commit()


def setup_tags(json_settings):
    for tag_info in json_settings["tags"]:
        tag_name = tag_info["tag"]
        bg_style = tag_info["bgstyle"]
        text_style = tag_info["textstyle"]
        tag = Tag(name=tag_name, bg_style=bg_style, text_style=text_style)
        db.session.add(tag)


def setup_admin_wallet():
    wallet_address = configured_admin_wallet_address()
    ensure_wallet_admin_slip()
    return wallet_address


def write_secret():
    if os.path.exists(SECRET_FILE):
        os.remove(SECRET_FILE)
    open(SECRET_FILE, "w+").write(str(os.urandom(16)))


def setup_storage():
    storage.bootstrap()


def save_db():
    db.session.commit()
    db.session.remove()
    backend_name = ""
    try:
        backend_name = db.engine.url.get_backend_name()
    except Exception:
        backend_name = ""
    if backend_name == "sqlite":
        db.engine.dispose()
    if os.path.exists(MIGRATION_DIR):
        alembic_config = Config(os.path.join(MIGRATION_DIR, "alembic.ini"))
        alembic_config.set_main_option("script_location", MIGRATION_DIR)
        with app.app_context():
            # mark the database as being up to date migration-wise since
            # it was just created
            command.stamp(config=alembic_config, revision="head")


def main():
    with app.app_context():
        initialize_db()
        settings = grab_settings()
        setup_boards(settings)
        setup_slips(settings)
        setup_tags(settings)
        setup_admin_wallet()
        setup_storage()
        write_secret()
        save_db()


if __name__ == "__main__":
    main()
