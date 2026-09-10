from sqlalchemy import text

from shared import db


class SiteSetting(db.Model):
    key = db.Column(db.String(64), primary_key=True)
    value = db.Column(db.Text, nullable=False, default="")


def get_setting(key, default=""):
    setting = db.session.query(SiteSetting).filter(SiteSetting.key == key).one_or_none()
    if setting is None:
        return default
    return setting.value


def set_setting(key, value):
    value = "" if value is None else str(value)
    with db.session.no_autoflush:
        db.session.execute(
            text(
                'INSERT INTO site_setting ("key", "value") '
                'VALUES (:key, :value) '
                'ON CONFLICT ("key") DO UPDATE SET "value" = EXCLUDED."value"'
            ),
            {"key": key, "value": value},
        )
        setting = db.session.query(SiteSetting).filter(SiteSetting.key == key).one_or_none()
        if setting is None:
            setting = SiteSetting(key=key, value=value)
            db.session.add(setting)
        else:
            setting.value = value
    return setting
