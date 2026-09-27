from typing import Union

from flask_restful import reqparse, inputs

from board_access import get_thread_and_board_or_404
from captcha import add_request_arguments
from model.Thread import Thread
from model.Post import Post

from cooldown import on_captcha_cooldown
from post import create_post
from shared import db

def get_request_data() -> reqparse.Namespace:
    "Returns data about a new post request."

    parser = reqparse.RequestParser()
    parser.add_argument("name", type=str, location=["form", "args"])
    parser.add_argument("subject", type=str, location=["form", "args"])
    parser.add_argument("body", type=str, required=True, location=["form", "args"])
    parser.add_argument("useslip", type=inputs.boolean, location=["form", "args"])
    parser.add_argument("spoiler", type=inputs.boolean, location=["form", "args"])

    if not on_captcha_cooldown():
        add_request_arguments(parser)

    return parser.parse_args()


def get_thread(thread_id: int) -> Thread:
    "Returns a thread by its ID."
    thread, _ = get_thread_and_board_or_404(thread_id)
    return thread


class NewPost:
    def post(self, thread: Union[Thread, int]) -> Post:
        if isinstance(thread, int):
            thread = get_thread(thread)
        args = dict(get_request_data())
        return create_post(thread, args)
