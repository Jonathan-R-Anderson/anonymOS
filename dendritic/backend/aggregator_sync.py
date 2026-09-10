import os
import sys

# Ensure the project root is in sys.path so 'services' can be found
_root = os.path.dirname(os.path.abspath(__file__))
if _root not in sys.path:
    sys.path.insert(0, _root)

from services.aggregator_sync.text import (
    _translated_imported_body,
    imported_replies,
    translate_imported_body,
)

_api = None


# Lazily import the real aggregator sync API module.
def _load_api():
    global _api
    if _api is not None:
        return _api
    try:
        from services.aggregator_sync import api as imported_api
    except Exception:
        return None
    _api = imported_api
    return _api


def _require_api():
    api_module = _load_api()
    if api_module is not None:
        return api_module
    from services.aggregator_sync import api as imported_api
    return imported_api


def get_sync_status(*args, **kwargs):
    return _require_api().get_sync_status(*args, **kwargs)


def get_aggregator_db_stats(*args, **kwargs):
    return _require_api().get_aggregator_db_stats(*args, **kwargs)


def sync_board_if_due(*args, **kwargs):
    return _require_api().sync_board_if_due(*args, **kwargs)


def sync_boards_if_due(*args, **kwargs):
    return _require_api().sync_boards_if_due(*args, **kwargs)


def start_background_sync(*args, **kwargs):
    return _require_api().start_background_sync(*args, **kwargs)


# Proxy missing attributes to the lazily loaded API module.
def __getattr__(name):
    api_module = _load_api()
    if api_module is not None and hasattr(api_module, name):
        return getattr(api_module, name)
    raise AttributeError(name)


# Expose attributes from both this shim and the loaded API module.
def __dir__():
    values = set(globals())
    api_module = _load_api()
    if api_module is not None:
        values.update(dir(api_module))
    return sorted(values)
