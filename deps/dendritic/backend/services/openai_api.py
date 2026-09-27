"""OpenAI, over plain HTTPS.

No `openai` package: the image installs from a hash-pinned Pipfile, so adding a
dependency means regenerating the lock, and this needs exactly one endpoint.
`requests` is already here — the same reasoning as services/stripe_api.py.

WHERE THIS IS ALLOWED TO RUN
----------------------------
Admin-triggered generation and background jobs only. NEVER on a request a reader
is waiting on. A page that blocks on a third-party model is a page that is down
whenever that model is slow, and this project has already taken an outage from
putting a network call inside a page render.

WHAT COMES BACK IS NOT TRUSTED
------------------------------
The model returns text that looks like JSON. It is parsed, then validated
against the exact shape each collection needs, and anything that does not fit is
discarded rather than stored. A quiz question whose `correctAnswer` indexes past
the end of its options list is worse than no question: it marks a right answer
wrong, and the player has no way to know the fault is ours.
"""

import json
import time

import requests

from shared import app

API_URL = "https://api.openai.com/v1/chat/completions"

# Generous, because generation happens in the background and a batch of twenty
# questions genuinely takes a while. Nothing waits on this interactively.
TIMEOUT = 120

# A batch that fails costs the whole batch, so retries are worth having; but a
# model that is down stays down, so the count is small and the backoff real.
MAX_ATTEMPTS = 3
BACKOFF_SECONDS = 4


class OpenAIError(RuntimeError):
    pass


def api_key():
    return (app.config.get("OPENAI_API_KEY") or "").strip()


def model():
    return (app.config.get("OPENAI_MODEL") or "gpt-4o-mini").strip()


def configured():
    return bool(api_key())


def complete_json(system, user, max_tokens=4000, temperature=0.8):
    """Ask for JSON and return the parsed object. Raises OpenAIError.

    response_format json_object is requested so the model cannot wrap its answer
    in prose or a markdown fence — the single commonest reason a generation
    pipeline "works" in testing and then stores nothing in production.
    """
    key = api_key()
    if not key:
        raise OpenAIError("No OpenAI API key is configured on this server.")

    body = {
        "model": model(),
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "max_tokens": int(max_tokens),
        # Warm, because a batch of quiz questions generated at temperature 0
        # comes back near-identical every run, and duplicates are exactly what
        # this is trying to avoid producing.
        "temperature": float(temperature),
        "response_format": {"type": "json_object"},
    }

    last = None
    for attempt in range(MAX_ATTEMPTS):
        try:
            response = requests.post(
                API_URL, json=body,
                headers={"Authorization": "Bearer %s" % key},
                timeout=TIMEOUT,
            )
        except Exception as exc:
            last = "unreachable: %s" % exc
        else:
            if response.status_code == 200:
                return _parse(response)
            # 429 and 5xx are worth another go; a 400 means the request itself
            # is wrong and repeating it just spends money on the same error.
            detail = _error_detail(response)
            # An exhausted quota arrives as 429, which is normally the most
            # retryable status there is -- but this one will still be exhausted
            # in twelve seconds. Retrying only delays telling the operator the
            # one thing they can act on.
            if _is_quota(detail):
                raise OpenAIError(detail)
            if response.status_code not in (408, 409, 429) and response.status_code < 500:
                raise OpenAIError(detail)
            last = detail
        if attempt < MAX_ATTEMPTS - 1:
            time.sleep(BACKOFF_SECONDS * (attempt + 1))
    raise OpenAIError(last or "OpenAI did not answer")


def _parse(response):
    try:
        payload = response.json()
        content = payload["choices"][0]["message"]["content"]
    except (ValueError, KeyError, IndexError, TypeError) as exc:
        raise OpenAIError("OpenAI returned an unreadable response: %s" % exc)
    try:
        parsed = json.loads(content)
    except ValueError as exc:
        raise OpenAIError("OpenAI did not return JSON: %s" % exc)
    if not isinstance(parsed, dict):
        raise OpenAIError("OpenAI returned JSON that is not an object")
    return parsed


_QUOTA_HINTS = ("no credits", "insufficient_quota", "exceeded your current quota",
                "billing")


def _is_quota(detail):
    """A quota error is permanent until somebody pays; retrying is pure delay."""
    text = (detail or "").lower()
    return any(hint in text for hint in _QUOTA_HINTS)


def _error_detail(response):
    try:
        return response.json().get("error", {}).get("message", "") or (
            "OpenAI returned HTTP %d" % response.status_code)
    except ValueError:
        # Never echo the raw body: it can quote the request, and the request
        # carries the prompt.
        return "OpenAI returned HTTP %d" % response.status_code
