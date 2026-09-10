from flask import request
from flask_restful import Resource

from model.NewThread import NewThread, get_request_data as _get_form_data
from model.NewThread import reqparse
from thread import create_thread


def _get_request_data_with_json():
    parser = reqparse.RequestParser()
    parser.add_argument("subject", type=str, location=["json", "form", "args"])
    parser.add_argument("body", type=str, required=True, location=["json", "form", "args"])
    parser.add_argument("board", type=int, required=True, location=["json", "form", "args"])
    parser.add_argument("tags", type=str, location=["json", "form", "args"])
    return parser.parse_args()


class NewThreadResource(NewThread, Resource):
    def post(self):
        if request.is_json:
            args = dict(_get_request_data_with_json())
            return create_thread(args)
        return super().post()
