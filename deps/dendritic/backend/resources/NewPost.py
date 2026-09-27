from flask import request
from flask_restful import Resource, inputs, reqparse

from model.NewPost import NewPost
from model.NewPost import get_request_data as _get_form_data
from post import create_post
from restauth import slip_required


def _get_post_data_with_json():
    parser = reqparse.RequestParser()
    parser.add_argument("name", type=str, location=["json", "form", "args"])
    parser.add_argument("subject", type=str, location=["json", "form", "args"])
    parser.add_argument("body", type=str, required=True, location=["json", "form", "args"])
    parser.add_argument("useslip", type=inputs.boolean, location=["json", "form", "args"])
    parser.add_argument("spoiler", type=inputs.boolean, location=["json", "form", "args"])
    return parser.parse_args()


class NewPostResource(NewPost, Resource):
    @slip_required
    def post(self, thread_id):
        if request.is_json:
            from model.NewPost import get_thread
            thread = get_thread(thread_id)
            args = dict(_get_post_data_with_json())
            return create_post(thread, args)
        return super().post(thread_id)
