"""Admin-managed CAPTCHA challenges.

A "challenge" is a titled category (e.g. "Select images with Adult") backed by
a pool of images, each flagged as a correct answer (should be selected) or a
decoy. The anime-captcha service samples ``QUESTIONS_PER_CHALLENGE`` images
from the pool per request. These used to be hard-coded JSON files baked into
the image; storing them in the database lets the admin panel add/remove
challenges at runtime.
"""
import datetime as _datetime
import re

from shared import db


MAX_CATEGORY_LENGTH = 64
MAX_TITLE_LENGTH = 255
MAX_IMAGE_URL_LENGTH = 1024
_CATEGORY_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")


class CaptchaChallenge(db.Model):
    __tablename__ = "captcha_challenge"

    id = db.Column(db.Integer, primary_key=True)
    # Stable slug used inside the signed challenge token.
    category = db.Column(db.String(MAX_CATEGORY_LENGTH), nullable=False, unique=True)
    # Prompt shown above the grid; may contain simple inline markup like <b>.
    title = db.Column(db.String(MAX_TITLE_LENGTH), nullable=False)
    is_active = db.Column(db.Boolean, nullable=False, default=True, index=True)
    created_at = db.Column(db.DateTime, nullable=False, default=_datetime.datetime.utcnow)

    questions = db.relationship(
        "CaptchaQuestion",
        backref="challenge",
        cascade="all, delete-orphan",
        order_by="CaptchaQuestion.position",
        lazy="selectin",
    )

    @property
    def correct_count(self):
        return sum(1 for question in self.questions if question.answer)

    @property
    def decoy_count(self):
        return sum(1 for question in self.questions if not question.answer)


class CaptchaQuestion(db.Model):
    __tablename__ = "captcha_question"

    id = db.Column(db.Integer, primary_key=True)
    challenge_id = db.Column(
        db.Integer,
        db.ForeignKey("captcha_challenge.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    image_url = db.Column(db.String(MAX_IMAGE_URL_LENGTH), nullable=False)
    # True when the image matches the prompt and the user should select it.
    answer = db.Column(db.Boolean, nullable=False, default=False)
    position = db.Column(db.Integer, nullable=False, default=0)


def normalize_category(raw):
    return (raw or "").strip().lower()


def datasets_from_db(min_questions):
    """Return {category: {title, questions:[{image, answer}]}} for every active
    challenge that has at least ``min_questions`` images. Returns an empty dict
    when nothing usable is configured, so the caller can fall back to the
    built-in JSON datasets."""
    datasets = {}
    challenges = (
        db.session.query(CaptchaChallenge)
        .filter(CaptchaChallenge.is_active.is_(True))
        .all()
    )
    for challenge in challenges:
        questions = [
            {"image": question.image_url, "answer": bool(question.answer)}
            for question in challenge.questions
        ]
        if len(questions) < min_questions:
            continue
        datasets[challenge.category] = {
            "title": challenge.title,
            "questions": questions,
        }
    return datasets


def create_challenge(category, title, correct_urls, decoy_urls):
    """Create a challenge from a slug, prompt, and two URL lists. Raises
    ValueError with a user-facing message on any validation problem."""
    category = normalize_category(category)
    title = (title or "").strip()
    if not _CATEGORY_RE.match(category):
        raise ValueError("Category must be a slug: lowercase letters, numbers and hyphens only.")
    if len(category) > MAX_CATEGORY_LENGTH:
        raise ValueError("Category slug is too long.")
    if not title:
        raise ValueError("A challenge prompt/title is required.")
    if len(title) > MAX_TITLE_LENGTH:
        raise ValueError("Challenge prompt is too long.")

    exists = (
        db.session.query(CaptchaChallenge)
        .filter(CaptchaChallenge.category == category)
        .one_or_none()
    )
    if exists is not None:
        raise ValueError("A challenge with that category slug already exists.")

    correct = _clean_urls(correct_urls)
    decoys = _clean_urls(decoy_urls)
    if not correct:
        raise ValueError("Add at least one correct image (an image that should be selected).")
    if not decoys:
        raise ValueError("Add at least one decoy image (an image that should NOT be selected).")

    challenge = CaptchaChallenge(category=category, title=title, is_active=True)
    db.session.add(challenge)
    db.session.flush()

    position = 0
    for url in correct:
        db.session.add(CaptchaQuestion(challenge_id=challenge.id, image_url=url, answer=True, position=position))
        position += 1
    for url in decoys:
        db.session.add(CaptchaQuestion(challenge_id=challenge.id, image_url=url, answer=False, position=position))
        position += 1
    return challenge


def _clean_urls(urls):
    cleaned = []
    for url in urls:
        url = (url or "").strip()
        if not url:
            continue
        if len(url) > MAX_IMAGE_URL_LENGTH:
            raise ValueError("One of the image URLs is too long.")
        cleaned.append(url)
    return cleaned


def add_questions_to_challenge(challenge, correct_urls, decoy_urls):
    """Append images to an existing challenge. Raises ValueError if nothing
    usable was provided."""
    correct = _clean_urls(correct_urls)
    decoys = _clean_urls(decoy_urls)
    if not correct and not decoys:
        raise ValueError("Add at least one image URL.")
    next_position = 1 + max(
        [question.position for question in challenge.questions],
        default=-1,
    )
    added = 0
    for url in correct:
        db.session.add(CaptchaQuestion(challenge_id=challenge.id, image_url=url, answer=True, position=next_position))
        next_position += 1
        added += 1
    for url in decoys:
        db.session.add(CaptchaQuestion(challenge_id=challenge.id, image_url=url, answer=False, position=next_position))
        next_position += 1
        added += 1
    return added


def remove_question(question_id):
    """Delete a single image from a challenge. Returns the challenge id it
    belonged to, or None if it didn't exist."""
    question = (
        db.session.query(CaptchaQuestion)
        .filter(CaptchaQuestion.id == question_id)
        .one_or_none()
    )
    if question is None:
        return None
    challenge_id = question.challenge_id
    db.session.delete(question)
    return challenge_id


def seed_from_file_datasets(file_datasets):
    """One-time import of the built-in JSON datasets into the DB so the admin
    panel starts populated. No-op if the table already has any rows."""
    if db.session.query(CaptchaChallenge.id).first() is not None:
        return 0
    seeded = 0
    for category, dataset in (file_datasets or {}).items():
        category = normalize_category(category)
        if not _CATEGORY_RE.match(category):
            continue
        challenge = CaptchaChallenge(
            category=category,
            title=dataset.get("title") or category,
            is_active=True,
        )
        db.session.add(challenge)
        db.session.flush()
        for position, question in enumerate(dataset.get("questions", [])):
            image = question.get("image")
            if not image:
                continue
            db.session.add(CaptchaQuestion(
                challenge_id=challenge.id,
                image_url=image[:MAX_IMAGE_URL_LENGTH],
                answer=bool(question.get("answer")),
                position=position,
            ))
        seeded += 1
    return seeded
