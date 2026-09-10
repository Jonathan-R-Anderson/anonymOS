# Taken from: http://blog.mmast.net/sqlalchemy-serialize-json

from sqlalchemy.ext.declarative import DeclarativeMeta

try:
    from flask.json import JSONEncoder as FlaskJSONEncoder
except ImportError:
    FlaskJSONEncoder = None

try:
    from flask.json.provider import DefaultJSONProvider
except ImportError:
    DefaultJSONProvider = None


def _serialize_sqlalchemy_model(obj):
    if isinstance(obj.__class__, DeclarativeMeta):
        return obj.to_dict()
    raise TypeError


if FlaskJSONEncoder is not None:
    class CustomJSONEncoder(FlaskJSONEncoder):

        def default(self, obj):
            try:
                return _serialize_sqlalchemy_model(obj)
            except TypeError:
                return super(CustomJSONEncoder, self).default(obj)
else:
    class CustomJSONEncoder(object):

        def default(self, obj):
            return _serialize_sqlalchemy_model(obj)


if DefaultJSONProvider is not None:
    class CustomJSONProvider(DefaultJSONProvider):

        def default(self, obj):
            try:
                return _serialize_sqlalchemy_model(obj)
            except TypeError:
                return super().default(obj)
else:
    CustomJSONProvider = None
