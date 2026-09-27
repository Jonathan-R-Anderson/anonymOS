import sys
sys.stderr.write("DEBUG: [shared.py] LOADING\n")
sys.stderr.flush()

# Configure modular logging as early as possible so every module-level logger
# created during import inherits the shared file + stdout handlers.
try:
    from maniwani_logging import setup_logging
    setup_logging("backend")
except Exception as _logging_exc:  # pragma: no cover - never block startup
    sys.stderr.write("DEBUG: [shared.py] logging setup failed: %s\n" % _logging_exc)
    sys.stderr.flush()

# Make psycopg2 cooperate with gevent's event loop so concurrent greenlets
# don't leave connections in "async query underway" state.
try:
    from psycogreen.gevent import patch_psycopg
    patch_psycopg()
except ImportError:
    pass

import ast
import contextvars
import json
import mimetypes
import os
import random
import ipaddress
import functools
import threading
from customjsonencoder import CustomJSONEncoder, CustomJSONProvider
from flask import Flask, has_app_context
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_restful import Api
from sqlalchemy.exc import DBAPIError, NoSuchColumnError, OperationalError, ResourceClosedError
from werkzeug.datastructures import ImmutableDict

_ENV_BOOL_TRUE_VALUES = {"1", "true", "yes", "on"}
_ENV_BOOL_FALSE_VALUES = {"0", "false", "no", "off", ""}
_ENV_BOOL_KEYS = {
    "AGGREGATOR_REQUEST_SYNC",
    "ANALYTICS_MAINTENANCE_ENABLED",
    "ANALYTICS_PERSONALIZATION_ENABLED",
    "EXPERIMENTS_ENABLED",
    "EXPERIMENT_MONITOR_ENABLED",
    "PHASE5_ADVANCED_ENABLED",
    "RECOMMENDER_ENABLED",
    "RECOMMENDER_MAINTENANCE_ENABLED",
    "RECOMMENDER_SATISFACTION_PROMPTS_ENABLED",
    "DEV_MODE",
    "MANIWANI_DEV",
    "SERVE_REST",
    "SERVE_STATIC",
    "SESSION_COOKIE_SECURE",
    "SNAPSHOT_TIMER_ENABLED",
    "THREAT_WATCH_ENABLED",
    "SQLALCHEMY_TRACK_MODIFICATIONS",
    "TESTING",
    "TORRENT_FORCE_TURN_RELAY",
    "TORRENT_PUBLIC_SECURE",
    "VIDEO_OFFLOAD_ENABLED",
}
_ENV_INT_KEYS = {
    "AGGREGATOR_SYNC_ADVISORY_LOCK_ID",
    "ANALYTICS_MAINTENANCE_ADVISORY_LOCK_ID",
    "ANALYTICS_MAINTENANCE_INTERVAL_SECONDS",
    "EXPERIMENT_MONITOR_INTERVAL_SECONDS",
    "RECOMMENDER_SATISFACTION_PROMPT_PERCENT",
    "RECOMMENDER_ADVISORY_LOCK_ID",
    "RECOMMENDER_MAINTENANCE_INTERVAL_SECONDS",
    "AGGREGATOR_SYNC_INTERVAL",
    "BOARD_BANNER_HEIGHT",
    "BOARD_BANNER_WIDTH",
    "CAPTCHA_COOLDOWN",
    "FIREHOSE_LENGTH",
    "MAX_CONTENT_LENGTH",
    "NEWS_CLUSTER_WINDOW_HOURS",
    "NEWS_FRONT_PAGE_LIMIT",
    "NEWS_ARCHIVE_PAGE_SIZE",
    "NEWS_KEYWORDS_PER_SYNC",
    "NEWS_LOOKBACK_HOURS",
    "NEWS_MAX_PAGES",
    "NEWS_PAGE_SIZE",
    "NEWS_SYNC_INTERVAL_SECONDS",
    "NEWS_MIN_PUBLISH_INTERVAL_SECONDS",
    "NEWS_MAX_PUBLISH_INTERVAL_SECONDS",
    "NEWS_STORY_MIN_WORDS",
    "NEWS_STORY_MAX_CHARS",
    "REDIS_PORT",
    "TORRENT_DIRECT_FALLBACK_PEER_THRESHOLD",
    "TORRENT_STATS_POLL_INTERVAL_MS",
    "TORRENT_TURNS_PORT",
    "TORRENT_TURN_PORT",
    "VIDEO_OFFLOAD_ADVISORY_LOCK_ID",
    "VIDEO_OFFLOAD_GRACE_TICKS",
    "VIDEO_OFFLOAD_HIGH",
    "VIDEO_OFFLOAD_LOW",
    "VIDEO_OFFLOAD_MIN_PEERS",
    "VIDEO_OFFLOAD_TICK_SECONDS",
}
_ENV_FLOAT_KEYS = {
    "CACHE_VIEW_RATIO",
    "MIRROR_REQUEST_DELAY_SECONDS",
    "MIRROR_RETRY_BACKOFF_SECONDS",
    "NEWS_REQUEST_TIMEOUT_SECONDS",
    "RECOMMENDER_BANDIT_EPSILON",
    "RECOMMENDER_CREATOR_GINI_MAX",
    "RECOMMENDER_FEATURE_DRIFT_MAX",
    "OLLAMA_RETRY_BACKOFF_SECONDS",
    "OLLAMA_TIMEOUT_SECONDS",
    "WEB_SEARCH_TIMEOUT_SECONDS",
}
_ENV_STRUCTURED_KEYS = {
    "SQLALCHEMY_ENGINE_OPTIONS",
    "THEME_LIST",
}
_EXTRA_ENV_CONFIG_KEYS = {
    "ADMIN_WALLET_ADDRESS",
    # The deployed AxonChannels and the chain it is on. It is verified on chain
    # under its original name, ChannelManagerV2 -- the 2026-08-16 rename was a
    # source change and did not touch deployed bytecode. `channel_awards.
    # deployment()` reads both from app.config and returns None unless BOTH are
    # present — and None is what turns every tip, pooled or direct, into
    # "Channel payments are not configured on this site." before anything signs.
    #
    # Listed here for the same reason as the DHT and origin keys below: without
    # it these two are present on the pod and absent from app.config, so setting
    # them looks like configuring tipping and configures nothing. That failure
    # is invisible from the outside — the page renders, the button is there, and
    # the refusal only appears after a visitor has chosen an amount.
    #
    # They are inside the state digest, so they are not decoration: a state
    # signed for one deployment cannot be replayed against another, which is
    # exactly why deployment() refuses to let a caller name them.
    "CHANNEL_CHAIN_ID",
    "CHANNEL_MANAGER_ADDRESS",
    # Content generation. Without these here the env vars exist on the pod but
    # never reach app.config, so openai_api.configured() stays False and every
    # generate button reports "no key configured" while .env plainly has one —
    # the same trap the DHT keys below are commented for.
    "OPENAI_API_KEY",
    "OPENAI_MODEL",
    # Storage-DHT offload target. Without these here the env vars exist on the
    # pod but never reach app.config, so dht_enabled() stays False and the
    # offload silently reports "disabled" while looking correctly configured
    # from the outside.
    "DHT_S3_ENDPOINT",
    "DHT_S3_ACCESS_KEY",
    "DHT_S3_SECRET_KEY",
    "DHT_S3_CA_BUNDLE",
    "DHT_S3_INSECURE_TLS",
    "DHT_S3_UUID_PREFIX",
    # The origin content-signing key. Read from the environment like every other
    # secret here, because a key that only exists in a file the pod does not
    # mount is a key that silently is not there — and unsigned content looks
    # exactly like content nobody has got round to verifying.
    "ORIGIN_SIGNING_KEY",
    "ORIGIN_PUBLIC_KEY",
    # The emergency-snapshot publisher key. Deliberately a DIFFERENT key from
    # the origin signing key above — see services/snapshot_key.py — and listed
    # here for the same reason: without it the variable is present on the pod
    # and absent from app.config, so snapshots build unsigned while the
    # deployment looks correctly configured.
    "SNAPSHOT_SIGNING_KEY",
    "SNAPSHOT_PUBLIC_KEY",
    "SNAPSHOT_DIR",
    "SNAPSHOT_TIMER_ENABLED",
    # The PUBLIC half of the offline root key. Publishing it is the point;
    # the private half must never reach this repository or any server.
    "SNAPSHOT_ROOT_PUBLIC_KEY",
    "THREAT_WATCH_ENABLED",
    "ANALYTICS_MAINTENANCE_ADVISORY_LOCK_ID",
    "ANALYTICS_MAINTENANCE_ENABLED",
    "ANALYTICS_MAINTENANCE_INTERVAL_SECONDS",
    "ANALYTICS_PERSONALIZATION_ENABLED",
    "EXPERIMENTS_ENABLED",
    "EXPERIMENT_MONITOR_ENABLED",
    "EXPERIMENT_MONITOR_INTERVAL_SECONDS",
    "PHASE5_ADVANCED_ENABLED",
    "RECOMMENDER_ADVISORY_LOCK_ID",
    "RECOMMENDER_ENABLED",
    "RECOMMENDER_LIGHTGBM_MODEL_PATH",
    "RECOMMENDER_BANDIT_EPSILON",
    "RECOMMENDER_CREATOR_GINI_MAX",
    "RECOMMENDER_FEATURE_DRIFT_MAX",
    "RECOMMENDER_MAINTENANCE_ENABLED",
    "RECOMMENDER_MAINTENANCE_INTERVAL_SECONDS",
    "RECOMMENDER_SATISFACTION_PROMPTS_ENABLED",
    "RECOMMENDER_SATISFACTION_PROMPT_PERCENT",
    "AGGREGATOR_REQUEST_SYNC",
    "AGGREGATOR_SYNC_INTERVAL",
    "ANIME_CAPTCHA_SECRET",
    "BOARD_BANNER_HEIGHT",
    "BOARD_BANNER_WIDTH",
    "CACHE_VIEW_RATIO",
    "CAPTCHA_COOLDOWN",
    "CDN_REWRITE",
    "DEFAULT_THEME",
    "DEV_MODE",
    "EIGHTCHAN_AGGREGATOR_DB",
    "FFMPEG_PATH",
    "FIREHOSE_LENGTH",
    "FOURCHAN_AGGREGATOR_DB",
    "GEO_REVERSE_GEOCODE_URL",
    "GEO_USER_AGENT",
    "INSTANCE_NAME",
    "MAX_CONTENT_LENGTH",
    "PREFERRED_URL_SCHEME",
    "REDDIT_AGGREGATOR_DB",
    "REDIS_HOST",
    "REDIS_PORT",
    "RENDERER_HOST",
    "S3_ACCESS_KEY",
    "S3_CA_BUNDLE",
    "S3_ENDPOINT",
    "S3_SECRET_KEY",
    "S3_UUID_PREFIX",
    "SEEDBOX_STATUS_URL",
    "SERVER_NAME",
    "SERVE_REST",
    "SERVE_STATIC",
    "SEVENCHAN_AGGREGATOR_DB",
    "SQLALCHEMY_DATABASE_URI",
    "SQLALCHEMY_ENGINE_OPTIONS",
    "SQLALCHEMY_TRACK_MODIFICATIONS",
    "STATIC_URL_BASE",
    "STORAGE_PROVIDER",
    "STORE_PROVIDER",
    "TESTING",
    "THEME_LIST",
    "THUMB_FOLDER",
    "TORRENT_FORCE_TURN_RELAY",
    "TORRENT_DIRECT_FALLBACK_PEER_THRESHOLD",
    "TORRENT_PUBLIC_HOST",
    "TORRENT_PUBLIC_SECURE",
    "TORRENT_STATS_POLL_INTERVAL_MS",
    "TORRENT_TURNS_PORT",
    "TORRENT_TURN_HOST",
    "TORRENT_TURN_PASSWORD",
    "TORRENT_TURN_PORT",
    "TORRENT_TURN_USERNAME",
    "TRIPCODE_SECRET",
    "UPLOAD_FOLDER",
    "VIDEO_OFFLOAD_ADVISORY_LOCK_ID",
    "VIDEO_OFFLOAD_ENABLED",
    "VIDEO_OFFLOAD_GRACE_TICKS",
    "VIDEO_OFFLOAD_HIGH",
    "VIDEO_OFFLOAD_LOW",
    "VIDEO_OFFLOAD_MIN_PEERS",
    "VIDEO_OFFLOAD_TICK_SECONDS",
}
_RUNTIME_ENV_ONLY_KEYS = {
    "AGGREGATOR_SYNC_ADVISORY_LOCK_ID",
    "BRAVE_SEARCH_API_KEY",
    "MANIWANI_CFG",
    "MANIWANI_DEV",
    "MIRROR_MAX_RETRIES",
    "MIRROR_REQUEST_DELAY_SECONDS",
    "MIRROR_RETRY_BACKOFF_SECONDS",
    "MIRROR_USER_AGENT",
    "NEWS_API_BASE_URL",
    "NEWS_API_KEY",
    "NEWS_CLUSTER_WINDOW_HOURS",
    "NEWS_FRONT_PAGE_LIMIT",
    "NEWS_ARCHIVE_PAGE_SIZE",
    "NEWS_KEYWORDS_PER_SYNC",
    "NEWS_LOOKBACK_HOURS",
    "NEWS_MAX_PAGES",
    "NEWS_PAGE_SIZE",
    "NEWS_REQUEST_TIMEOUT_SECONDS",
    "NEWS_SEARCH_KEYWORDS",
    "NEWS_SYNC_INTERVAL_SECONDS",
    "NEWS_MIN_PUBLISH_INTERVAL_SECONDS",
    "NEWS_MAX_PUBLISH_INTERVAL_SECONDS",
    "NEWS_STORY_MIN_WORDS",
    "NEWS_STORY_MAX_CHARS",
    "OLLAMA_BASE_URL",
    "OLLAMA_MODEL",
    "OLLAMA_RETRY_BACKOFF_SECONDS",
    "OLLAMA_TIMEOUT_SECONDS",
    "WEB_SEARCH_TIMEOUT_SECONDS",
    "dev_mode",
}
_RUNTIME_CONFIG_BASELINE = None
_PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))


def iter_exception_chain(exc: Exception):
    queue = [exc]
    seen = set()
    while queue:
        current = queue.pop(0)
        if current is None or id(current) in seen:
            continue
        seen.add(id(current))
        yield current
        for attr in ("orig", "__cause__", "__context__"):
            nested = getattr(current, attr, None)
            if isinstance(nested, BaseException):
                queue.append(nested)


def is_retryable_session_error(exc: Exception) -> bool:
    exception_chain = list(iter_exception_chain(exc))
    for current in exception_chain:
        if isinstance(current, DBAPIError) and getattr(current, "connection_invalidated", False):
            return True
    
    # Check for specific strings in all exceptions in the chain
    message = " | ".join(
        str(current).lower()
        for current in exception_chain
        if str(current)
    )
    
    retry_markers = [
        "pgres_tuples_ok",
        "libpq",
        "server closed the connection unexpectedly",
        "connection not open",
        "terminating connection",
        "result object does not return rows",
        "closed automatically",
        "could not locate column in row",
        "connection reset by peer",
        "is not active"
    ]
    
    if any(m in message for m in retry_markers):
        return True
    return False


def db_retry(max_retries=3, delay=0.5):
    def decorator(func):
        if not callable(func):
            # This handles cases where circular imports might leave a name as a module
            return func
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            last_exc = None
            for i in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    import sys
                    exc_info = sys.exc_info()
                    if is_retryable_session_error(e):
                        app.logger.warning("Retryable DB error in %s (attempt %d/%d): %s", func.__name__, i+1, max_retries, e)
                        reset_sqlalchemy_session(dispose_engine=(i == max_retries - 1))
                        last_exc = e
                        if i < max_retries - 1:
                            import time
                            time.sleep(delay * (2 ** i)) # Exponential backoff
                            continue
                    raise exc_info[1].with_traceback(exc_info[2])
            if last_exc:
                raise last_exc
        return wrapper
    return decorator


def active_session_connections():
    if has_app_context() is False:
        return []
    try:
        session = db.session()
    except Exception:
        return []

    transaction = getattr(session, "transaction", None)
    seen_transactions = set()
    connections = []
    while transaction is not None and id(transaction) not in seen_transactions:
        seen_transactions.add(id(transaction))
        for value in getattr(transaction, "_connections", {}).values():
            connection = None
            if isinstance(value, (tuple, list)) and value:
                connection = value[0]
            else:
                connection = getattr(value, "connection", None)
            if connection is not None:
                connections.append(connection)
        transaction = getattr(transaction, "_parent", None)

    unique_connections = []
    seen_connections = set()
    for connection in connections:
        if connection is None or id(connection) in seen_connections:
            continue
        seen_connections.add(id(connection))
        unique_connections.append(connection)
    return unique_connections


def reset_sqlalchemy_session(dispose_engine: bool = False) -> None:
    if has_app_context() is False:
        if dispose_engine:
            try:
                db.engine.dispose()
            except Exception:
                pass
        return
    connections = active_session_connections()
    for connection in connections:
        try:
            connection.invalidate()
        except Exception:
            pass
    if not connections:
        try:
            db.session.rollback()
        except Exception:
            pass
    try:
        db.session.remove()
    except Exception:
        pass
    if dispose_engine:
        try:
            db.engine.dispose()
        except Exception:
            pass


def native_thread_class():
    try:
        import gevent.monkey

        original_thread = gevent.monkey.get_original("threading", "Thread")
        if original_thread is not None:
            return original_thread
    except Exception:
        pass
    return threading.Thread


def spawn_native_thread(*args, **kwargs):
    # gevent.patch_all(contextvars=True) makes ContextVars greenlet-local.
    # Native OS threads are not greenlets, so they all share the same default
    # gevent context — causing Flask's _cv_app to be clobbered across threads.
    # Wrapping the target in copy_context().run() gives each native thread an
    # independent snapshot so app-context push/pop never leaks between threads.
    original_target = kwargs.get('target')
    if original_target is not None:
        _ctx = contextvars.copy_context()
        def _isolated(*a, **kw):
            _ctx.run(original_target, *a, **kw)
        kwargs['target'] = _isolated
    thread = native_thread_class()(*args, **kwargs)
    thread.start()
    return thread


def _strip_env_value(raw_value):
    value = raw_value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        return value[1:-1]
    return value


def _read_env_file(path):
    values = {}
    if os.path.exists(path) is False:
        return values
    with open(path, encoding="utf-8") as env_file:
        for raw_line in env_file:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[7:].strip()
            if "=" not in line:
                continue
            key, raw_value = line.split("=", 1)
            key = key.strip()
            if not key:
                continue
            values[key] = _strip_env_value(raw_value)
    return values


def _load_env_file(path, override=False):
    values = _read_env_file(path)
    for key, value in values.items():
            existing_value = os.environ.get(key)
            if override is False and existing_value is not None and str(existing_value).strip():
                continue
            os.environ[key] = value
    return values


def _parse_bool_env_value(raw_value):
    normalized = str(raw_value).strip().lower()
    if normalized in _ENV_BOOL_TRUE_VALUES:
        return True
    if normalized in _ENV_BOOL_FALSE_VALUES:
        return False
    raise ValueError("Invalid boolean value: %s" % raw_value)


def _parse_structured_env_value(raw_value):
    for parser in (json.loads, ast.literal_eval):
        try:
            return parser(raw_value)
        except Exception:
            continue
    raise ValueError("Invalid structured value: %s" % raw_value)


def _managed_env_keys():
    app_keys = {
        key
        for key in app.config.keys()
        if isinstance(key, str) and key.isupper()
    }
    return app_keys | _EXTRA_ENV_CONFIG_KEYS


def _reloadable_env_keys():
    return _managed_env_keys() | _RUNTIME_ENV_ONLY_KEYS


def _coerce_env_config_value(key, raw_value):
    current_value = app.config.get(key)
    if key in _ENV_BOOL_KEYS or isinstance(current_value, bool):
        try:
            return _parse_bool_env_value(raw_value)
        except ValueError:
            return bool(raw_value)
    if key in _ENV_INT_KEYS or (isinstance(current_value, int) and not isinstance(current_value, bool)):
        return int(str(raw_value).strip(), 10)
    if key in _ENV_FLOAT_KEYS or isinstance(current_value, float):
        return float(str(raw_value).strip())
    if key in _ENV_STRUCTURED_KEYS or isinstance(current_value, (list, tuple, dict, ImmutableDict)):
        parsed_value = _parse_structured_env_value(raw_value)
        if isinstance(current_value, tuple):
            return tuple(parsed_value)
        if isinstance(current_value, list):
            return list(parsed_value)
        if isinstance(current_value, ImmutableDict):
            return ImmutableDict(parsed_value)
        return parsed_value
    return raw_value


def _apply_env_config_overrides():
    applied_keys = []
    managed_keys = _managed_env_keys()
    for key in sorted(managed_keys):
        if key not in os.environ:
            continue
        app.config[key] = _coerce_env_config_value(key, os.environ.get(key))
        applied_keys.append(key)
    if "UPLOAD_FOLDER" in os.environ and "THUMB_FOLDER" not in os.environ:
        app.config["THUMB_FOLDER"] = os.path.join(app.config["UPLOAD_FOLDER"], "thumbs")
    return applied_keys


    # Anything in .env that did NOT reach app.config. A key here is present on
    # the pod and invisible to the application, so the feature it controls is
    # silently off while the deployment looks correctly configured.
    #
    # This has happened three times: the origin signing key, the snapshot key
    # and directory, and the threat watcher -- each costing a deploy cycle to
    # notice, because the symptom is a feature quietly doing nothing. Checked
    # here rather than in a test because only the running process knows what the
    # runtime config file already supplied.
    try:
        unmanaged = sorted(
            key for key in os.environ
            if key.isupper() and key not in app.config
            and key not in _RUNTIME_ENV_ONLY_KEYS
            and not key.startswith(("KUBERNETES_", "PATH", "HOME", "HOSTNAME",
                                    "LANG", "LC_", "PWD", "SHLVL", "TERM",
                                    "PYTHON", "GPG_", "no_proxy", "NO_PROXY"))
        )
        if unmanaged:
            app.logger.warning(
                "config: %d environment key(s) never reach app.config, so any "
                "feature reading them is silently off: %s",
                len(unmanaged), ", ".join(unmanaged[:20]))
    except Exception:
        pass

def _reset_runtime_config():
    if _RUNTIME_CONFIG_BASELINE is None:
        return
    for key in _managed_env_keys():
        if key in _RUNTIME_CONFIG_BASELINE:
            app.config[key] = _RUNTIME_CONFIG_BASELINE[key]
        else:
            app.config.pop(key, None)


def _int_env_option(name, default):
    """Positive int from the environment, falling back to `default`.

    Used for pool sizing, so a typo in .env must not silently produce a 0-sized
    pool — anything unparseable or <1 keeps the default.
    """
    try:
        value = int(os.getenv(name, "") or default)
    except (TypeError, ValueError):
        return default
    return value if value >= 1 else default


def _apply_runtime_config():
    _reset_runtime_config()
    if os.getenv("MANIWANI_CFG"):
        app.config.from_envvar("MANIWANI_CFG")
    _apply_env_config_overrides()
    database_uri = app.config.get("SQLALCHEMY_DATABASE_URI")
    if isinstance(database_uri, str):
        app.config["SQLALCHEMY_DATABASE_URI"] = _normalize_sqlite_database_uri(database_uri)
        _ensure_sqlite_database_directory(app.config["SQLALCHEMY_DATABASE_URI"])
    engine_options = dict(app.config.get("SQLALCHEMY_ENGINE_OPTIONS") or {})
    engine_options.setdefault("pool_pre_ping", True)
    engine_options.setdefault("pool_recycle", 180)
    if not str(app.config.get("SQLALCHEMY_DATABASE_URI") or "").startswith("sqlite:"):
        # SIZE THE POOL EXPLICITLY. Leaving it at SQLAlchemy's default
        # (pool_size=5, max_overflow=10) gave 15 connections per process against
        # `gevent = 200` cores x `processes = 4`, and produced this in production:
        #   QueuePool limit of size 5 overflow 10 reached, connection timed out
        #   POST /session/keepalive => generated 0 bytes in 60010 msecs
        #
        # Budget, so these numbers can be re-derived rather than guessed:
        #   Postgres 17 ships max_connections = 100 and `maniwani` is its only
        #   client (docker-compose.yml has no other POSTGRES_HOST consumer).
        #   Subtract 3 superuser_reserved_connections, ~5 for the background-sync
        #   advisory locks — those are opened via pool._creator() and are
        #   deliberately NOT pool-managed (services/aggregator_sync/state.py) —
        #   and a few for psql/maintenance. That leaves ~84 for 4 workers, so 20
        #   each is the ceiling that cannot oversubscribe the server.
        engine_options.setdefault("pool_size", _int_env_option("SQLALCHEMY_POOL_SIZE", 8))
        engine_options.setdefault("max_overflow", _int_env_option("SQLALCHEMY_MAX_OVERFLOW", 12))
        # Fail fast instead of hanging. The default 30s wait is why a starved
        # request burned 60s wall-clock before dying: 30s queued on the pool, then
        # the rest unwinding. 10s surfaces overload as a prompt error, which keeps
        # the greenlet (and its core) from being held hostage.
        engine_options.setdefault("pool_timeout", _int_env_option("SQLALCHEMY_POOL_TIMEOUT", 10))
        # LIFO keeps the working set small so idle connections age out via
        # pool_recycle instead of every slot staying warm and reserved.
        engine_options.setdefault("pool_use_lifo", True)
    if str(app.config.get("SQLALCHEMY_DATABASE_URI") or "").startswith("sqlite:"):
        execution_options = dict(engine_options.get("execution_options") or {})
        schema_map = dict(execution_options.get("schema_translate_map") or {})
        schema_map.setdefault("analytics", None)
        execution_options["schema_translate_map"] = schema_map
        engine_options["execution_options"] = execution_options
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = engine_options


def reload_runtime_environment(env_path=".env"):
    runtime_config_path = os.getenv("MANIWANI_CFG")
    env_values = _read_env_file(env_path)
    for key in _reloadable_env_keys():
        if key == "MANIWANI_CFG" and runtime_config_path:
            continue
        if key not in env_values:
            os.environ.pop(key, None)
    for key, value in env_values.items():
        os.environ[key] = value
    if runtime_config_path:
        os.environ["MANIWANI_CFG"] = runtime_config_path
    _apply_runtime_config()
    return runtime_config_path


def _normalize_sqlite_database_uri(database_uri):
    sqlite_prefix = "sqlite:///"
    if not isinstance(database_uri, str) or not database_uri.startswith(sqlite_prefix):
        return database_uri

    database_path = database_uri[len(sqlite_prefix):]
    if not database_path or database_path == ":memory:" or database_path.startswith("file:"):
        return database_uri

    if os.path.isabs(database_path):
        return database_uri

    absolute_path = os.path.abspath(os.path.join(_PROJECT_ROOT, database_path))
    return "%s%s" % (sqlite_prefix, absolute_path)


def _ensure_sqlite_database_directory(database_uri):
    sqlite_prefix = "sqlite:///"
    if not isinstance(database_uri, str) or not database_uri.startswith(sqlite_prefix):
        return

    database_path = database_uri[len(sqlite_prefix):]
    if not database_path or database_path == ":memory:" or database_path.startswith("file:"):
        return

    directory = os.path.dirname(database_path)
    if directory:
        os.makedirs(directory, exist_ok=True)


_load_env_file(".env")

sys.stderr.write("DEBUG: [shared.py] INITIALIZING APP AND DB\n")
sys.stderr.flush()
# static_url_path='' mounts static/ at the domain root, which is what puts
# static/install.sh at https://syndichan.org/install.sh.
app = Flask(__name__, static_url_path='')
# text/plain, not the guessed text/x-sh, so a browser SHOWS install.sh instead
# of downloading it. Anybody sensible reads a `curl … | sh` script before they
# run it, and a script they cannot open in the tab they are already in is a
# script they will not read.
mimetypes.add_type("text/plain", ".sh")
if CustomJSONProvider is not None:
    app.json = CustomJSONProvider(app)
elif hasattr(app, "json_encoder"):
    app.json_encoder = CustomJSONEncoder

app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///test.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["UPLOAD_FOLDER"] = "./uploads"
app.config["THUMB_FOLDER"] = os.path.join(app.config["UPLOAD_FOLDER"], "thumbs")
app.config["SERVE_STATIC"] = True
app.config["SERVE_REST"] = True
app.config["FIREHOSE_LENGTH"] = 10
app.config["TRUSTED_PROXY_CIDRS"] = ()
app.config.setdefault("BOARD_BANNER_WIDTH", 300)
app.config.setdefault("BOARD_BANNER_HEIGHT", 100)
_RUNTIME_CONFIG_BASELINE = dict(app.config)
_apply_runtime_config()

db = SQLAlchemy(app)
migrate = Migrate(app, db)
rest_api = Api(app)



SECRET_FILE = "./deploy-configs/secret"
def get_secret():
    return open(SECRET_FILE).read()

if os.path.exists(SECRET_FILE):
    app.secret_key = get_secret()


def gen_poster_id():
    return '%04X' % random.randint(0, 0xffff)


def ip_to_int(ip_str):
    # The old version of ip_to_int had a logical bug where it would always shift the
    # final result to the left by 8. This is preserved with the `<< 8`.
    return int.from_bytes(
        ipaddress.ip_address(ip_str).packed,
        byteorder="little"
    ) << 8

sys.stderr.write("DEBUG: [shared.py] COMPLETED\n")
sys.stderr.flush()
