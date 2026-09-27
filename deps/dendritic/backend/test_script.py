import time
from shared import db, app
from model.Media import Media
with app.app_context():
    print(db.session.query(Media).count())
