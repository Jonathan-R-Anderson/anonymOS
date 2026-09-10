"""The object_id -> origin record, against a real database.

WHY A REAL DATABASE AND NOT A FAKE SESSION
------------------------------------------
The property being tested is first-write-wins, and in this system the write that
has to lose is a CONCURRENT one: a 40 MB object is hundreds of shards, every
shard leases separately, and the site serves them on 200 gevent workers. So the
read-then-insert race is the ordinary case, not an edge case, and the thing that
actually enforces the rule is the table's primary key -- which a fake session
does not have. This mounts the real model on a real SQLite file so the
IntegrityError path is exercised by an actual constraint.

Flask-SQLAlchemy's `db` is substituted with a plain SQLAlchemy one of the same
shape (`db.Model` is a declarative base, `db.Column`/`db.String`/... are
SQLAlchemy's own), which is enough because the model uses nothing else. That
also keeps the test runnable here, where importing `shared` pulls in the whole
application.
"""

import datetime
import os
import pathlib
import sys
import tempfile
import types
import unittest

import sqlalchemy
from sqlalchemy.orm import declarative_base, sessionmaker

BACKEND = pathlib.Path(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))


class _FakeDb(object):
    """The slice of the Flask-SQLAlchemy `db` object this model touches."""

    def __init__(self):
        self.Model = declarative_base()
        self.Column = sqlalchemy.Column
        self.String = sqlalchemy.String
        self.DateTime = sqlalchemy.DateTime
        self.Integer = sqlalchemy.Integer
        self.session = None


class ObjectOwnershipTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._saved_shared = sys.modules.get("shared")
        cls._saved_model = sys.modules.get("model.DhtObjectOwner")

        cls.db = _FakeDb()
        fake_shared = types.ModuleType("shared")
        fake_shared.db = cls.db
        sys.modules["shared"] = fake_shared
        sys.modules.pop("model.DhtObjectOwner", None)

        import model.DhtObjectOwner as ownership

        cls.ownership = ownership
        cls.directory = tempfile.TemporaryDirectory()
        cls.engine = sqlalchemy.create_engine(
            "sqlite:///" + os.path.join(cls.directory.name, "ownership.sqlite"))
        cls.db.Model.metadata.create_all(cls.engine)
        cls.Session = sessionmaker(bind=cls.engine)

    @classmethod
    def tearDownClass(cls):
        cls.engine.dispose()
        cls.directory.cleanup()
        if cls._saved_shared is None:
            sys.modules.pop("shared", None)
        else:
            sys.modules["shared"] = cls._saved_shared
        if cls._saved_model is None:
            sys.modules.pop("model.DhtObjectOwner", None)
        else:
            sys.modules["model.DhtObjectOwner"] = cls._saved_model

    def setUp(self):
        self.session = self.Session()
        self.db.session = self.session
        self.addCleanup(self.session.close)
        self.session.query(self.ownership.DhtObjectOwner).delete()
        self.session.commit()

    def _row(self, object_id):
        return (
            self.session.query(self.ownership.DhtObjectOwner)
            .filter(self.ownership.DhtObjectOwner.object_id == object_id)
            .one_or_none()
        )

    def test_the_first_lease_records_the_owner(self):
        owner, outcome = self.ownership.record_owner("a" * 64, "peer-one")
        self.assertEqual(("peer-one", "recorded"), (owner, outcome))
        self.assertEqual("peer-one", self.ownership.owner_of("a" * 64))
        self.assertEqual(0, self._row("a" * 64).contested_count)

    def test_a_later_lease_from_the_same_requester_is_a_no_op(self):
        self.ownership.record_owner("a" * 64, "peer-one")
        first_seen = self._row("a" * 64).first_leased_at
        for _ in range(5):
            owner, outcome = self.ownership.record_owner("a" * 64, "peer-one")
            self.assertEqual(("peer-one", "unchanged"), (owner, outcome))
        row = self._row("a" * 64)
        self.assertEqual(first_seen, row.first_leased_at)
        self.assertEqual(0, row.contested_count)
        self.assertIsNone(row.contested_by)

    def test_a_lease_from_another_origin_does_not_move_ownership(self):
        self.ownership.record_owner("a" * 64, "peer-one")
        owner, outcome = self.ownership.record_owner("a" * 64, "peer-two")
        self.assertEqual(("peer-one", "contested"), (owner, outcome),
                         "the second origin took ownership of the object")
        self.assertEqual("peer-one", self.ownership.owner_of("a" * 64))
        row = self._row("a" * 64)
        self.assertEqual(1, row.contested_count)
        self.assertEqual("peer-two", row.contested_by)
        self.assertIsInstance(row.contested_at, datetime.datetime)

    def test_contests_are_counted_rather_than_only_logged(self):
        # One stray request and a peer working through an object's every shard
        # are different events, and only the count tells them apart.
        self.ownership.record_owner("a" * 64, "peer-one")
        for _ in range(3):
            self.ownership.record_owner("a" * 64, "peer-two")
        self.assertEqual(3, self._row("a" * 64).contested_count)

    def test_an_object_nobody_has_leased_has_no_owner(self):
        self.assertIsNone(self.ownership.owner_of("f" * 64))

    def test_ownership_is_per_object(self):
        self.ownership.record_owner("a" * 64, "peer-one")
        self.ownership.record_owner("b" * 64, "peer-two")
        self.assertEqual("peer-one", self.ownership.owner_of("a" * 64))
        self.assertEqual("peer-two", self.ownership.owner_of("b" * 64))

    def test_the_loser_of_a_concurrent_insert_does_not_become_the_owner(self):
        """The race the primary key exists to settle.

        Both callers read "no row", both try to insert, and the second one gets
        an IntegrityError. If that were swallowed into "recorded" -- or worse, if
        first-write-wins were implemented as read-then-write with no constraint
        behind it -- the last writer would own the object, and ownership would be
        decided by scheduling.
        """
        other = self.Session()
        self.addCleanup(other.close)

        original_add = self.session.add
        raced = []

        def add_after_somebody_else_won(instance):
            if not raced:
                raced.append(True)
                other.add(self.ownership.DhtObjectOwner(
                    object_id="a" * 64, requester="peer-one"))
                other.commit()
            return original_add(instance)

        self.session.add = add_after_somebody_else_won
        try:
            owner, outcome = self.ownership.record_owner("a" * 64, "peer-two")
        finally:
            self.session.add = original_add

        self.assertTrue(raced, "the race never happened, so nothing was proved")
        self.assertEqual(("peer-one", "contested"), (owner, outcome))
        self.assertEqual("peer-one", self.ownership.owner_of("a" * 64))

    def test_the_object_id_is_the_primary_key(self):
        # First-write-wins is a database guarantee here, not a Python one: two
        # rows for one object would make "who owns this" ambiguous, and the
        # ambiguity would be resolved differently on every query.
        self.ownership.record_owner("a" * 64, "peer-one")
        self.session.add(self.ownership.DhtObjectOwner(
            object_id="a" * 64, requester="peer-two"))
        with self.assertRaises(self.ownership.IntegrityError):
            self.session.commit()
        self.session.rollback()

    def test_a_record_needs_both_halves(self):
        with self.assertRaises(ValueError):
            self.ownership.record_owner("", "peer-one")
        with self.assertRaises(ValueError):
            self.ownership.record_owner("a" * 64, "")
