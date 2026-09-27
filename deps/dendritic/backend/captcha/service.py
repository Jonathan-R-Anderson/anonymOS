from flask_restful import inputs

from cooldown import on_captcha_cooldown, refresh_captcha_cooldown
from model.Slip import viewer_is_admin

from .anime import QUESTIONS_PER_CHALLENGE, build_challenge, validate_solution


class CaptchaError(Exception):
    "Error to be thrown when captcha is invalid."


def _captcha_bypass_active():
    return viewer_is_admin()


def add_request_arguments(parser):
    if _captcha_bypass_active():
        return
    if on_captcha_cooldown():
        return

    parser.add_argument("anime-captcha-token", type=str, required=True, location=["form", "args"])
    for i in range(QUESTIONS_PER_CHALLENGE):
        parser.add_argument(f"anime-captcha-{i}", type=inputs.boolean, default=False, location=["form", "args"])


def get_captcha():
    if _captcha_bypass_active():
        return None
    if on_captcha_cooldown():
        return None
    return build_challenge()


def get_render_payload():
    captcha = get_captcha()
    if captcha is None:
        return {}
    return {"captcha": captcha}


def get_template_context():
    return {"get_captcha": get_captcha}


def validate_submission(board_id, args):
    if _captcha_bypass_active():
        return
    if on_captcha_cooldown():
        return

    captcha_args = {
        key: value for key, value in args.items()
        if key.startswith("anime-captcha")
    }
    if validate_solution(captcha_args) is False:
        raise CaptchaError("Incorrect CAPTCHA solution", board_id)

    refresh_captcha_cooldown()
