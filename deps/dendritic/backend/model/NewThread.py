from flask_restful import reqparse

from thread import create_thread


def get_request_data() -> reqparse.Namespace:
    "Returns data about a new thread request."

    parser = reqparse.RequestParser()
    parser.add_argument("subject", type=str, location=["form", "args"])
    parser.add_argument("body", type=str, required=True, location=["form", "args"])
    parser.add_argument("board", type=int, required=True, location=["form", "args"])
    parser.add_argument("tags", type=str, location=["form", "args"])

    return parser.parse_args()


class NewThread:
    def post(self):
        args = dict(get_request_data())

        return create_thread(args)
