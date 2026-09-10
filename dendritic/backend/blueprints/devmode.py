from functools import wraps
import os
import shutil

from flask import Blueprint, flash, redirect, render_template, request, session, url_for
import requests

import cache
from model.Media import storage
from model.Board import Board
from model.Slip import Slip, configured_admin_wallet_address, gen_slip
from shared import app, db, get_secret, reload_runtime_environment

devmode_blueprint = Blueprint("devmode", __name__, template_folder="template")

_WIPE_CONFIRM_TOKEN = "WIPE"
_FULL_RESET_CONFIRM_TOKEN = "FULL RESET"


def _dev_required(endpoint):
    @wraps(endpoint)
    def wrapped(*args, **kwargs):
        if not app.config.get("DEV_MODE"):
            return "Dev mode is not enabled.", 403
        return endpoint(*args, **kwargs)
    return wrapped


def _wipe_folder_storage():
    if app.config.get("STORAGE_PROVIDER") == "FOLDER":
        storage.wipe_all()


def _wipe_aggregator_storage():
    from services.aggregator_sync.config import SUPPORTED_SCRAPER_TYPES
    from services.aggregator_sync.scraper_db import aggregator_db_path

    aggregator_paths = []
    for source_type in SUPPORTED_SCRAPER_TYPES:
        try:
            db_path = aggregator_db_path(source_type)
        except ValueError:
            continue
        if db_path and db_path not in aggregator_paths:
            aggregator_paths.append(db_path)
    for db_path in aggregator_paths:
        parent_dir = os.path.dirname(db_path) or "."
        if os.path.isdir(parent_dir):
            for item_name in os.listdir(parent_dir):
                item_path = os.path.join(parent_dir, item_name)
                if os.path.isdir(item_path):
                    shutil.rmtree(item_path)
                else:
                    os.remove(item_path)
        elif os.path.exists(db_path):
            os.remove(db_path)
        else:
            os.makedirs(parent_dir, exist_ok=True)


def _reset_seedbox():
    reset_url = "http://seedbox:8781/reset"
    try:
        response = requests.post(reset_url, timeout=5)
        response.raise_for_status()
        return None
    except Exception as exc:
        app.logger.warning("Seedbox reset during dev full reset failed: %s", exc)
        return "Seedbox cache reset was skipped: %s" % exc


def _clear_cache_store():
    cache.Cache().clear()


def _reset_scrapers_and_reregister_sources():
    import scraper_client
    from services.aggregator_sync.config import SUPPORTED_SCRAPER_TYPES

    warnings = []
    for source_type in SUPPORTED_SCRAPER_TYPES:
        if scraper_client.reset_storage(source_type) is False:
            warnings.append("%s scraper reset was skipped." % source_type)

    triples = []
    for board in db.session.query(Board).all():
        for source in board.sources:
            if source.source_type not in SUPPORTED_SCRAPER_TYPES or not source.source_thread_id:
                continue
            triples.append((source.source_type, source.source_name, source.source_thread_id))
    if triples:
        scraper_client.sync_all_threads(triples)
    return warnings


def _reload_runtime_state():
    runtime_config_path = reload_runtime_environment()
    storage.reload_config()
    return runtime_config_path


def _success_flash_message(prefix):
    return "%s Admin wallet restored from config: %s." % (
        prefix,
        configured_admin_wallet_address(),
    )




@devmode_blueprint.route("/slips/create", methods=["POST"])
@_dev_required
def create_slip():
    name = (request.form.get("name") or "").strip()
    password = request.form.get("password") or ""
    is_admin = bool(request.form.get("is_admin"))
    is_mod = bool(request.form.get("is_mod"))
    if not name or not password:
        flash("Name and password are required.")
        return redirect(url_for("devmode.dashboard"))
    if db.session.query(Slip).filter(Slip.name == name).one_or_none():
        flash("A slip named '%s' already exists." % name)
        return redirect(url_for("devmode.dashboard"))
    slip = gen_slip(name, password)
    slip.is_admin = is_admin
    slip.is_mod = is_mod
    db.session.commit()
    flash("Slip '%s' created." % name)
    return redirect(url_for("devmode.dashboard"))


@devmode_blueprint.route("/slips/<int:slip_id>/delete", methods=["POST"])
@_dev_required
def delete_slip(slip_id):
    slip = db.session.query(Slip).filter(Slip.id == slip_id).one_or_none()
    if slip is None:
        flash("Slip not found.")
        return redirect(url_for("devmode.dashboard"))
    name = slip.name
    db.session.delete(slip)
    db.session.commit()
    flash("Deleted slip '%s'." % name)
    return redirect(url_for("devmode.dashboard"))


@devmode_blueprint.route("/wipe", methods=["POST"])
@_dev_required
def wipe_database():
    if (request.form.get("confirm") or "").strip() != _WIPE_CONFIRM_TOKEN:
        flash("Type %s to confirm the wipe." % _WIPE_CONFIRM_TOKEN)
        return redirect(url_for("devmode.dashboard"))
    try:
        from bootstrap import main as bootstrap_main
        db.drop_all()
        _wipe_folder_storage()
        bootstrap_main()
        flash(_success_flash_message("Database wiped and re-bootstrapped."))
    except PermissionError as exc:
        app.logger.exception("Dev wipe failed due to upload directory permissions")
        flash(
            "Wipe failed because the upload storage path is not writable (%s). "
            "Recreate the uploads volume `maniwani_maniwani-uploads` and restart the app."
            % exc
        )
    except Exception as exc:
        app.logger.exception("Dev wipe failed")
        flash("Wipe failed: %s" % exc)
    return redirect(url_for("devmode.dashboard"))


@devmode_blueprint.route("/full-reset", methods=["POST"])
@_dev_required
def full_reset():
    if (request.form.get("confirm") or "").strip() != _FULL_RESET_CONFIRM_TOKEN:
        flash("Type %s to confirm the full reset." % _FULL_RESET_CONFIRM_TOKEN)
        return redirect(url_for("devmode.dashboard"))
    try:
        from bootstrap import main as bootstrap_main

        runtime_config_path = _reload_runtime_state()
        seedbox_warning = _reset_seedbox()
        db.session.remove()
        db.drop_all()
        _clear_cache_store()
        _wipe_aggregator_storage()
        storage.wipe_all()
        bootstrap_main()
        scraper_warnings = _reset_scrapers_and_reregister_sources()
        app.secret_key = get_secret()
        session.clear()
        flash(_success_flash_message("Full reset completed. Reloaded .env and re-bootstrapped."))
        if runtime_config_path:
            flash("Runtime config reloaded from %s." % runtime_config_path)
        if seedbox_warning:
            flash(seedbox_warning)
        for warning in scraper_warnings:
            flash(warning)
    except PermissionError as exc:
        app.logger.exception("Dev full reset failed due to storage permissions")
        flash(
            "Full reset failed because a mounted storage path is not writable (%s)." % exc
        )
    except Exception as exc:
        app.logger.exception("Dev full reset failed")
        flash("Full reset failed: %s" % exc)
    return redirect(url_for("devmode.dashboard"))
