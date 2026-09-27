import gevent.monkey
gevent.monkey.patch_all()
import psycogreen.gevent
psycogreen.gevent.patch_psycopg()
import os

from alembic import command
from alembic.config import Config
from flask.cli import with_appcontext

from model.Media import storage
from shared import app, db


MIGRATION_DIR = "migrations"
EARLIEST_REVISION = "b38b893343b7"

# Newest-first schema markers for databases that were created by
# db.create_all() before ever being stamped by alembic. Such a database
# matches the complete model schema of its era, so the newest marker that is
# present identifies the revision the schema is equivalent to. Stamping that
# revision (instead of the earliest one) lets `alembic upgrade head` apply
# only the migrations that are genuinely missing.
SCHEMA_REVISION_MARKERS = (
    ("e2a7c93f1b48", "media", "dht_offload_attempts"),
    ("d1f4a86b3c27", "media", "dht_offloaded_at"),
    ("b5c1e83af927", "scraped_thread_stub", None),
    ("a3e9d15c72f4", "media_vote", None),
    ("f2c7a9e14b63", "post_vote", "target_key"),
    ("e8b2d41f7a90", "post_vote", None),
    ("d7a1c93e5b48", "board_bookmark", None),
    ("c4f6b8d0e213", "outbound_reply", "event_secret_hash"),
    ("b3e5a7c9d102", "outbound_reply", "handoff_secret_hash"),
    ("a2d4f6b8c901", "outbound_reply", None),
    ("ef15a92d5005", "behavior_sequence", None),
    ("de04f81c4004", "experiment_definition", None),
    ("cd93e70b3003", "recommendation_log", None),
    ("bc82d6fa2002", "content_feature", None),
    ("aa71c5e9d001", "analytics_event", None),
    ("f5d9c3b1a2e7", "video", None),
    ("e4c8b2a1f7d3", "word_sentiment", None),
    ("d3f7a1b9c2e5", "news_persona", None),
    ("c9a2f1e4b7d8", "board", "custom_css"),
    ("b8f4a1c72e93", "profile", "embed_stream"),
    ("a7e1c93f52d0", "stream", None),
    ("f3d82c47a911", "board_source", "source_thread_id"),
    ("8c1b7e2a4d55", "imported_media", None),
    ("5a2b1e9c4f33", "image_magnet", None),
    ("2f6c2b9a4d10", "media", "torrent_info_hash"),
    ("1d2e3f4a5b6c", "slip_board_moderator", None),
    ("8f2c1a6d4b77", "blocked_media_hash", None),
    ("7a1c2f8b4d9e", "board_banner", None),
    ("6d4f0a2219b2", "board_visit", None),
    ("0c5d2a7a6c11", "poster", "cookie_token"),
    ("e1b1e6a9d2c4", "board", "board_type"),
    ("4b8075b31201", "news_article", None),
    ("c4a9dd8d6b11", "site_setting", None),
    ("9f4f58a31c5c", "board_source", None),
)


def update_storage():
    storage.update()


def _detect_schema_revision(inspector) -> str:
    # PostgreSQL keeps behavior tables in a restricted schema; SQLite maps the
    # same model schema to the default namespace for local development.
    if inspector.bind.dialect.name == "postgresql":
        if inspector.has_table("behavior_sequence", schema="analytics"):
            return "ef15a92d5005"
        if inspector.has_table("experiment_definition", schema="analytics"):
            return "de04f81c4004"
        if inspector.has_table("recommendation_log", schema="analytics"):
            return "cd93e70b3003"
        if inspector.has_table("content_feature", schema="analytics"):
            return "bc82d6fa2002"
        if inspector.has_table("analytics_event", schema="analytics"):
            return "aa71c5e9d001"
    for revision, table_name, column_name in SCHEMA_REVISION_MARKERS:
        if not inspector.has_table(table_name):
            continue
        if column_name is not None:
            column_names = {column["name"] for column in inspector.get_columns(table_name)}
            if column_name not in column_names:
                continue
        return revision
    return EARLIEST_REVISION


def update_db():
    from sqlalchemy import inspect, text

    alembic_config = Config(os.path.join(MIGRATION_DIR, "alembic.ini"))
    alembic_config.set_main_option("script_location", MIGRATION_DIR)
    with app.app_context():
        inspector = inspect(db.engine)
        detected_revision = _detect_schema_revision(inspector)
        if not inspector.has_table("alembic_version"):
            app.logger.info(
                "Database has no alembic_version table; adopting it at detected revision %s",
                detected_revision,
            )
            command.stamp(config=alembic_config, revision=detected_revision)
            db.session.flush()
        else:
            # A previous buggy boot may have stamped a revision far older than
            # the schema actually is, which makes `upgrade head` replay
            # migrations into already-existing tables. If the stored revision
            # is older than what the schema fingerprint says, move the stamp
            # forward before upgrading. The stamp is only ever moved forward.
            revision_chain = [marker[0] for marker in SCHEMA_REVISION_MARKERS] + [EARLIEST_REVISION]
            with db.engine.connect() as connection:
                stored_revision = connection.execute(
                    text("SELECT version_num FROM alembic_version")
                ).scalar()
            if stored_revision is None or (
                stored_revision in revision_chain
                and detected_revision in revision_chain
                and revision_chain.index(detected_revision) < revision_chain.index(stored_revision)
            ):
                app.logger.warning(
                    "alembic_version %s is older than the revision the schema matches (%s); re-stamping before upgrade",
                    stored_revision,
                    detected_revision,
                )
                command.stamp(config=alembic_config, revision=detected_revision)
                db.session.flush()
        command.upgrade(config=alembic_config, revision="head")
        # flask-sqlalchemy 3.x scopes db.session to the app context, so the
        # commit must happen inside it or it raises "Working outside of
        # application context" - which kills startup on the very last step.
        db.session.commit()

if __name__ == "__main__":
    # SCHEMA FIRST, AND A SLOW OBJECT STORE MUST NOT BLOCK IT.
    #
    # These ran the other way round, and storage.update() re-uploads EVERY file
    # under static/ one PUT at a time. Against a DHT-backed store — each write
    # erasure-coded and distributed over I2P — that is slow enough to time out:
    #
    #   botocore.exceptions.ReadTimeoutError: Read timeout on endpoint URL:
    #   "https://syndichan-node:9000/static/logo.png"
    #
    # The migrate Job then exited non-zero, the updater treated the MIGRATION as
    # failed, and every deploy halted. Deploys were blocked for hours by an asset
    # upload, while the schema it was standing in front of would have applied in
    # seconds.
    #
    # So: the upgrade runs first, because it is what the new image actually
    # requires. The upload still runs, still logs loudly on failure, and is
    # retried by the next deploy — a stale asset is cosmetic and self-healing,
    # whereas a blocked migration stops everything.
    update_db()
    try:
        update_storage()
    except Exception:
        app.logger.exception(
            "static asset upload FAILED. The schema upgrade already succeeded, so "
            "this deploy is safe to continue; assets are re-uploaded on the next "
            "run. If this keeps happening, the object store is the thing to fix.")
