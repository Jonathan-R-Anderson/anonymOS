import base64
import hashlib
import hmac
import json
import random
import secrets
from pathlib import Path

from shared import app


DATA_DIRECTORY = Path(__file__).resolve().parent.parent / "anime-captcha" / "src" / "data"
QUESTIONS_PER_CHALLENGE = 16
SIGNATURE_PREFIX = "anime-captcha"


def _load_file_datasets():
    datasets = {}
    for data_path in DATA_DIRECTORY.glob("*.json"):
        with data_path.open(encoding="utf8") as data_file:
            datasets[data_path.stem] = json.load(data_file)
    return datasets


# The built-in JSON datasets are the fallback used before any admin-managed
# challenges exist (and if the admin removes all of them, so posting never
# gets locked out without a solvable captcha).
FILE_DATASETS = _load_file_datasets()


def _get_datasets():
    """Admin-managed challenges from the DB when available, otherwise the
    built-in JSON datasets. Queried per request so admin edits take effect
    immediately."""
    try:
        from model.CaptchaChallenge import datasets_from_db
        db_datasets = datasets_from_db(QUESTIONS_PER_CHALLENGE)
    except Exception:
        # DB unavailable (e.g. very early startup) — degrade to the files.
        db_datasets = None
    if db_datasets:
        return db_datasets
    return FILE_DATASETS


def _get_secret():
    secret = app.secret_key or app.config.get("ANIME_CAPTCHA_SECRET")
    if secret is None:
        secret = secrets.token_hex(32)
        app.config["ANIME_CAPTCHA_SECRET"] = secret
    if isinstance(secret, str):
        return secret.encode("utf8")
    return secret


def _serialize_payload(payload):
    payload_json = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    return base64.urlsafe_b64encode(payload_json.encode("utf8")).decode("ascii")


def _sign_payload(encoded_payload):
    payload_to_sign = ("%s:%s" % (SIGNATURE_PREFIX, encoded_payload)).encode("utf8")
    return hmac.new(_get_secret(), payload_to_sign, hashlib.sha256).hexdigest()


def _load_token(token):
    try:
        encoded_payload, provided_signature = token.rsplit(".", 1)
    except ValueError:
        return None

    expected_signature = _sign_payload(encoded_payload)
    if hmac.compare_digest(provided_signature, expected_signature) is False:
        return None

    try:
        payload_bytes = base64.urlsafe_b64decode(encoded_payload.encode("ascii"))
        return json.loads(payload_bytes.decode("utf8"))
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
        return None


def _question_pool(category, datasets=None):
    if datasets is None:
        datasets = _get_datasets()
    dataset = datasets.get(category)
    if dataset is None:
        return None
    return dataset.get("questions", [])


def build_challenge(category=None):
    datasets = _get_datasets()
    if not datasets:
        raise RuntimeError("Anime captcha datasets are unavailable")

    if category is None:
        category = random.choice(tuple(datasets.keys()))

    questions = _question_pool(category, datasets)
    if questions is None:
        raise ValueError("Invalid anime captcha category")
    if len(questions) < QUESTIONS_PER_CHALLENGE:
        raise ValueError("Not enough questions to build an anime captcha challenge")

    question_indexes = random.sample(range(len(questions)), QUESTIONS_PER_CHALLENGE)
    payload = {
        "category": category,
        "question_indexes": question_indexes,
    }
    encoded_payload = _serialize_payload(payload)
    token = "%s.%s" % (encoded_payload, _sign_payload(encoded_payload))

    return {
        "token": token,
        "title": datasets[category]["title"],
        "questions": [
            {
                "field_name": "anime-captcha-%d" % position,
                "image": questions[question_index]["image"],
            }
            for position, question_index in enumerate(question_indexes)
        ],
    }


def _field_selected(value):
    if value is True:
        return True
    if isinstance(value, str):
        return value.lower() in ("1", "on", "true", "yes")
    return False


def validate_solution(captcha_form):
    token = captcha_form.get("anime-captcha-token")
    if token is None:
        return False

    payload = _load_token(token)
    if payload is None:
        return False

    category = payload.get("category")
    question_indexes = payload.get("question_indexes")
    question_pool = _question_pool(category)
    if question_pool is None:
        return False
    if not isinstance(question_indexes, list):
        return False
    if len(question_indexes) != QUESTIONS_PER_CHALLENGE:
        return False
    if len(set(question_indexes)) != len(question_indexes):
        return False

    expected = set()
    try:
        for position, question_index in enumerate(question_indexes):
            if question_pool[question_index]["answer"] is True:
                expected.add(position)
    except (IndexError, KeyError, TypeError):
        return False

    actual = set()
    for position in range(len(question_indexes)):
        if _field_selected(captcha_form.get("anime-captcha-%d" % position)):
            actual.add(position)

    return actual == expected
