from flask import Blueprint, session, redirect, request

from shared import app


theme_blueprint = Blueprint('theme', __name__, template_folder='template')

# The chosen theme is saved in a dedicated, long-lived cookie so the preference
# survives session expiry and browser restarts (session storage alone did not
# persist it). Session is still written for the current session / legacy reads.
THEME_COOKIE = "theme"
_THEME_COOKIE_MAX_AGE = 60 * 60 * 24 * 365  # one year


def available_themes():
    return tuple(app.config.get("THEME_LIST") or ("stock", "harajuku", "wildride", "711chan", "cyberpunk", "midnight"))


def resolve_current_theme():
    """The viewer's saved theme: persistent cookie first, then session (legacy),
    then the site default. Values are validated against the known theme list so a
    stale/forged cookie can never inject an arbitrary value into cache keys or
    the stylesheet path."""
    themes = available_themes()
    for value in (request.cookies.get(THEME_COOKIE), session.get("theme")):
        if value and value in themes:
            return value
    # Dark by default: near-black surfaces with off-white text are easier on the
    # eyes for long reading sessions, which is what this site is for. Viewers who
    # already picked a theme keep it — the `theme` cookie is checked first above.
    return app.config.get("DEFAULT_THEME") or "midnight"


@theme_blueprint.route("/set-theme", methods=["POST"])
def set_theme():
    theme_name = request.form.get("selected-theme", "")
    target = request.referrer or "/"
    if theme_name not in available_themes():
        return redirect(target)
    session["theme"] = theme_name
    response = redirect(target)
    response.set_cookie(
        THEME_COOKIE,
        theme_name,
        max_age=_THEME_COOKIE_MAX_AGE,
        samesite="Lax",
        path="/",
    )
    return response
