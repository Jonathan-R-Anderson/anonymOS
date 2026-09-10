from shared import db


class Poster(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    hex_string = db.Column(db.String(16), nullable=False)
    ip_address = db.Column(db.String(255), nullable=False)
    thread = db.Column(db.Integer, db.ForeignKey("thread.id", ondelete="CASCADE"), nullable=False)
    cookie_token = db.Column(db.String(64), nullable=True)
    slip = db.Column(db.Integer, db.ForeignKey("slip.id"), nullable=True)
    # ISO-3166 alpha-2 country resolved from the poster's IP at post time, for
    # boards with country flags enabled. Null when unknown / geoip unavailable.
    country_code = db.Column(db.String(2), nullable=True)
