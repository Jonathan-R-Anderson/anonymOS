"""An encrypted backup handed to people who must not be able to read it.

The tests are about the ways an artifact could betray the operator who made it
or the volunteers who store it:

  * opening for somebody who should not be able to open it;
  * restoring as complete when it is truncated, which loses data silently;
  * a holder being unable to prove they still have the right bytes, which is
    what a storage challenge asks;
  * a holder being ABLE to answer that without being able to read anything.
"""

import ast
import base64
import datetime
import hashlib
import json
import os
import pathlib
import struct
import sys
import unittest

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)


def _load_pure(relative_path, wanted, extra=None):
    source = (pathlib.Path(BACKEND) / relative_path).read_text()
    tree = ast.parse(source)
    keep = [node for node in tree.body
            if (isinstance(node, ast.Assign)
                and {t.id for t in node.targets if isinstance(t, ast.Name)} & wanted)
            or (isinstance(node, (ast.FunctionDef, ast.ClassDef))
                and node.name in wanted)]
    module = ast.Module(body=keep, type_ignores=[])
    ast.fix_missing_locations(module)
    namespace = dict(extra or {})
    exec(compile(module, relative_path, "exec"), namespace)
    return namespace


try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: F401
    HAVE_CRYPTO = True
except Exception:
    HAVE_CRYPTO = False

BK = _load_pure(
    "services/backup.py",
    {"MAGIC", "FORMAT_VERSION", "SEGMENT_BYTES", "KDF_N", "KDF_R", "KDF_P",
     "KEY_BYTES", "SALT_BYTES", "NONCE_BYTES", "MINIMUM_PASSPHRASE",
     "EXCLUDED_TABLES", "BackupError", "_encode", "decode", "uuidish",
     "_derive", "_header_bytes", "encrypt", "split", "verify", "decrypt",
     "parse_payload", "target_is_empty", "restore", "resequence", "_is_integer"},
    extra={"base64": base64, "hashlib": hashlib, "json": json, "os": os,
           "struct": struct, "_datetime": datetime},
)

GOOD = "correct horse battery staple"


@unittest.skipUnless(HAVE_CRYPTO, "cryptography is not installed here")
class RoundTripTest(unittest.TestCase):
    def test_it_comes_back_out(self):
        payload = b"line one\nline two\n" * 100
        blob = BK["encrypt"]([payload], GOOD)
        self.assertEqual(BK["decrypt"](blob, GOOD), payload)

    def test_an_empty_backup_round_trips(self):
        """A site with nothing in it must still produce a valid artifact, or
        the first backup anyone takes on a fresh instance fails."""
        blob = BK["encrypt"]([], GOOD)
        self.assertEqual(BK["decrypt"](blob, GOOD), b"")

    def test_it_spans_segments(self):
        # Bigger than one segment, so the reorder and truncation defences are
        # actually exercised rather than trivially satisfied.
        payload = os.urandom(BK["SEGMENT_BYTES"] * 2 + 1234)
        blob = BK["encrypt"]([payload], GOOD)
        self.assertEqual(BK["decrypt"](blob, GOOD), payload)

    def test_chunk_boundaries_do_not_change_the_plaintext(self):
        """The caller streams whatever sizes it likes; the artifact must not
        depend on how the producer happened to chunk it."""
        payload = os.urandom(BK["SEGMENT_BYTES"] + 500)
        one = BK["decrypt"](BK["encrypt"]([payload], GOOD), GOOD)
        many = BK["decrypt"](
            BK["encrypt"]([payload[i:i + 997]
                           for i in range(0, len(payload), 997)], GOOD), GOOD)
        self.assertEqual(one, many)


@unittest.skipUnless(HAVE_CRYPTO, "cryptography is not installed here")
class ConfidentialityTest(unittest.TestCase):
    """The holders must not be able to read it. That is the whole design."""

    def test_the_wrong_passphrase_opens_nothing(self):
        blob = BK["encrypt"]([b"secret rows"], GOOD)
        with self.assertRaises(BK["BackupError"]):
            BK["decrypt"](blob, "correct horse battery stapl3")

    def test_the_plaintext_is_not_in_the_artifact(self):
        marker = b"jranderson404-private-message-body"
        blob = BK["encrypt"]([marker * 40], GOOD)
        self.assertNotIn(marker, blob)

    def test_a_short_passphrase_is_refused(self):
        """Everything in the database is behind this one string, and it will be
        held by people who would like to read it."""
        for weak in ("", "hunter2", "x" * (BK["MINIMUM_PASSPHRASE"] - 1)):
            with self.subTest(passphrase=weak):
                with self.assertRaises(BK["BackupError"]):
                    BK["encrypt"]([b"x"], weak)

    def test_two_backups_of_the_same_data_differ(self):
        """A fresh salt and nonce each time. Identical artifacts would let a
        holder tell that nothing changed between two backups."""
        first = BK["encrypt"]([b"same"], GOOD)
        second = BK["encrypt"]([b"same"], GOOD)
        self.assertNotEqual(first, second)


@unittest.skipUnless(HAVE_CRYPTO, "cryptography is not installed here")
class IntegrityTest(unittest.TestCase):
    """Two different questions, two different mechanisms."""

    def test_a_holder_can_prove_it_is_intact_without_the_passphrase(self):
        """What a storage challenge asks. It has to be answerable by somebody
        who cannot decrypt a single byte."""
        blob = BK["encrypt"]([b"rows" * 1000], GOOD)
        self.assertTrue(BK["verify"](blob))

    def test_a_flipped_byte_is_caught_without_the_passphrase(self):
        blob = bytearray(BK["encrypt"]([b"rows" * 1000], GOOD))
        blob[-1] ^= 0x01
        self.assertFalse(BK["verify"](bytes(blob)))

    def test_a_flipped_byte_is_also_caught_with_it(self):
        blob = bytearray(BK["encrypt"]([b"rows" * 1000], GOOD))
        blob[-1] ^= 0x01
        with self.assertRaises(BK["BackupError"]):
            BK["decrypt"](bytes(blob), GOOD)

    def test_truncation_is_refused_rather_than_restored(self):
        """The dangerous failure: a cut-short backup that decrypts cleanly and
        restores as complete, quietly missing everything after the cut."""
        payload = os.urandom(BK["SEGMENT_BYTES"] * 2 + 10)
        blob = BK["encrypt"]([payload], GOOD)
        envelope, _, body = BK["split"](blob)
        # Drop the last segment, and repair the digest so only the AEAD's
        # final-segment marker can catch it.
        (length,) = struct.unpack(">I", body[:4])
        shortened = body[:4 + length]
        header = json.dumps({**envelope, "ciphertext_sha256":
                             hashlib.sha256(shortened).hexdigest(),
                             "ciphertext_bytes": len(shortened)},
                            sort_keys=True, separators=(",", ":")).encode()
        forged = (BK["MAGIC"] + struct.pack(">II", BK["FORMAT_VERSION"], len(header))
                  + header + shortened)
        self.assertTrue(BK["verify"](forged), "the digest was repaired")
        with self.assertRaises(BK["BackupError"]) as caught:
            BK["decrypt"](forged, GOOD)
        self.assertIn("incomplete", str(caught.exception).lower())

    def test_weakening_the_kdf_in_the_header_breaks_decryption(self):
        """The header is associated data. Otherwise an attacker who could edit
        it would drop the scrypt cost to something brute-forceable, and the
        file would still open."""
        blob = BK["encrypt"]([b"rows"], GOOD)
        envelope, _, body = BK["split"](blob)
        envelope["kdf"] = {**envelope["kdf"], "n": 2}
        header = json.dumps(envelope, sort_keys=True,
                            separators=(",", ":")).encode()
        forged = (BK["MAGIC"] + struct.pack(">II", BK["FORMAT_VERSION"], len(header))
                  + header + body)
        with self.assertRaises(BK["BackupError"]):
            BK["decrypt"](forged, GOOD)

    def test_junk_is_not_mistaken_for_a_backup(self):
        for blob in (b"", b"hello", b"ANONCHAN-BACKUP", os.urandom(500)):
            with self.subTest(length=len(blob)):
                with self.assertRaises(BK["BackupError"]):
                    BK["split"](blob)


class EncodingTest(unittest.TestCase):
    """Row values Postgres returns that JSON cannot hold."""

    def test_decimals_survive_as_decimals(self):
        """Credit balances live in these columns. A float round-trip is a
        silent change to somebody's money."""
        import decimal

        value = decimal.Decimal("12345678901234567890.123456789")
        self.assertEqual(BK["decode"](BK["_encode"](value)), value)

    def test_bytes_survive(self):
        blob = os.urandom(64)
        self.assertEqual(BK["decode"](BK["_encode"](blob)), blob)

    def test_datetimes_survive_as_text_the_column_reparses(self):
        moment = datetime.datetime(2026, 8, 1, 12, 30, 15)
        self.assertEqual(BK["decode"](BK["_encode"](moment)), moment.isoformat())

    def test_ordinary_values_pass_through_untouched(self):
        for value in (None, True, False, 0, -1, 3.5, "text", [1, 2], {"a": 1}):
            with self.subTest(value=value):
                self.assertEqual(BK["decode"](BK["_encode"](value)), value)

    def test_a_row_dict_that_looks_like_an_encoding_is_not_mangled(self):
        """A JSON column could legitimately hold {"__t": ...}. Left alone
        unless it is one of the encodings this file actually writes."""
        self.assertEqual(BK["decode"]({"__t": "not-a-kind", "v": 1}),
                         {"__t": "not-a-kind", "v": 1})


class ExclusionTest(unittest.TestCase):
    def test_the_migration_stamp_is_excluded(self):
        """A restore runs migrations. A stamped alembic_version would tell it
        the schema is already current when the database is empty."""
        self.assertIn("alembic_version", BK["EXCLUDED_TABLES"])

    def test_short_lived_observation_logs_are_excluded(self):
        self.assertIn("threat_event", BK["EXCLUDED_TABLES"])
        self.assertIn("falco_alert", BK["EXCLUDED_TABLES"])


if __name__ == "__main__":
    unittest.main()


# -- restore, against a real scratch database ------------------------------
#
# SQLite in memory. It is not Postgres, but it exercises the parts that decide
# whether a restore works at all: foreign-key ordering, the empty-target guard,
# schema drift, and the row round trip. The sequence repair is Postgres-only and
# is asserted separately, by construction.

def _scratch():
    import sqlalchemy as sa
    from sqlalchemy.orm import Session

    metadata = sa.MetaData()
    sa.Table("board", metadata,
             sa.Column("id", sa.Integer, primary_key=True),
             sa.Column("name", sa.String(40)))
    # Declared BEFORE its parent in source order on purpose: sorted_tables has
    # to put the parent first regardless, and a restore that inserted in
    # declaration order would fail the foreign key.
    sa.Table("post", metadata,
             sa.Column("id", sa.Integer, primary_key=True),
             sa.Column("board_id", sa.Integer, sa.ForeignKey("board.id")),
             sa.Column("body", sa.Text))
    engine = sa.create_engine("sqlite://")
    metadata.create_all(engine)
    session = Session(engine)
    session.execute(sa.text("PRAGMA foreign_keys=ON"))
    return metadata, session


def _payload(boards, posts, created="2026-08-01T00:00:00Z", settings=None):
    lines = [json.dumps({"format": BK["FORMAT_VERSION"], "created_at": created,
                         "tables": ["board", "post"],
                         "settings": settings or {}})]
    lines.append(json.dumps({"__table": "board"}))
    lines += [json.dumps(row) for row in boards]
    lines.append(json.dumps({"__table": "post"}))
    lines += [json.dumps(row) for row in posts]
    return ("\n".join(lines) + "\n").encode()


class RestoreTest(unittest.TestCase):
    def setUp(self):
        self.metadata, self.session = _scratch()

    def tearDown(self):
        self.session.close()

    def test_rows_come_back(self):
        import sqlalchemy as sa

        payload = _payload(
            [{"id": 1, "name": "g"}, {"id": 2, "name": "b"}],
            [{"id": 10, "board_id": 1, "body": "hello"}])
        report = BK["restore"](self.session, self.metadata, payload)

        self.assertEqual(report["rows"], 3)
        self.assertEqual(
            self.session.execute(sa.text("SELECT COUNT(*) FROM post")).scalar(), 1)
        self.assertEqual(
            self.session.execute(sa.text("SELECT name FROM board WHERE id=2")).scalar(),
            "b")

    def test_parents_are_inserted_before_children(self):
        """sorted_tables is topologically sorted by foreign key. Inserting in
        the order the dump happens to list would violate the constraint."""
        payload = _payload([{"id": 1, "name": "g"}],
                           [{"id": 10, "board_id": 1, "body": "x"}])
        BK["restore"](self.session, self.metadata, payload)  # must not raise

    def test_a_populated_target_is_refused(self):
        """The mistake is pointing a restore at production instead of the new
        server. Merging would collide primary keys against live rows and
        interleave two sites with no way to separate them afterwards."""
        import sqlalchemy as sa

        self.session.execute(sa.text("INSERT INTO board (id, name) VALUES (99, 'live')"))
        self.session.commit()
        payload = _payload([{"id": 1, "name": "g"}], [])
        with self.assertRaises(BK["BackupError"]) as caught:
            BK["restore"](self.session, self.metadata, payload)
        self.assertIn("board", str(caught.exception))
        # And nothing was written.
        self.assertEqual(
            self.session.execute(sa.text("SELECT COUNT(*) FROM board")).scalar(), 1)

    def test_a_populated_target_can_be_forced(self):
        import sqlalchemy as sa

        self.session.execute(sa.text("INSERT INTO board (id, name) VALUES (99, 'live')"))
        self.session.commit()
        payload = _payload([{"id": 1, "name": "g"}], [])
        BK["restore"](self.session, self.metadata, payload, allow_nonempty=True)
        self.assertEqual(
            self.session.execute(sa.text("SELECT COUNT(*) FROM board")).scalar(), 2)

    def test_a_column_this_schema_no_longer_has_is_dropped(self):
        """A backup from an older build is exactly the one somebody restores.
        Refusing it over a removed column makes the artifact useless at the
        moment it is needed."""
        payload = _payload([{"id": 1, "name": "g", "retired_column": "x"}], [])
        report = BK["restore"](self.session, self.metadata, payload)
        self.assertEqual(report["rows"], 1)

    def test_a_table_this_schema_does_not_have_is_reported_not_silent(self):
        lines = _payload([{"id": 1, "name": "g"}], []).decode().rstrip().split("\n")
        lines.append(json.dumps({"__table": "table_from_the_future"}))
        lines.append(json.dumps({"id": 1}))
        report = BK["restore"](self.session, self.metadata,
                               ("\n".join(lines) + "\n").encode())
        self.assertEqual(report["tables_in_backup_not_in_schema"],
                         ["table_from_the_future"])

    def test_an_empty_backup_restores_to_an_empty_database(self):
        report = BK["restore"](self.session, self.metadata, _payload([], []))
        self.assertEqual(report["rows"], 0)

    def test_a_corrupt_payload_writes_nothing(self):
        import sqlalchemy as sa

        for payload in (b"", b"not json\n", b'{"format": 999}\n'):
            with self.subTest(payload=payload[:12]):
                with self.assertRaises(BK["BackupError"]):
                    BK["restore"](self.session, self.metadata, payload)
        self.assertEqual(
            self.session.execute(sa.text("SELECT COUNT(*) FROM board")).scalar(), 0)

    def test_the_report_names_the_carried_settings_without_their_values(self):
        """An operator needs to know a signing key came back. Printing it into
        a report that ends up in a terminal, a ticket or a screenshot does not
        help them."""
        payload = _payload([], [], settings={"ORIGIN_SIGNING_KEY": "s3cr3t-key-material"})
        report = BK["restore"](self.session, self.metadata, payload)
        self.assertEqual(report["settings"], ["ORIGIN_SIGNING_KEY"])
        self.assertNotIn("s3cr3t", json.dumps(report))


class ResequenceTest(unittest.TestCase):
    def test_it_is_skipped_on_anything_that_is_not_postgres(self):
        """pg_get_serial_sequence does not exist elsewhere, and a statement that
        errors inside a Postgres transaction aborts the whole transaction — so
        this must not be attempted blind."""
        metadata, session = _scratch()
        try:
            self.assertEqual(BK["resequence"](session, list(metadata.sorted_tables)), [])
        finally:
            session.close()


@unittest.skipUnless(HAVE_CRYPTO, "cryptography is not installed here")
class EndToEndTest(unittest.TestCase):
    def test_encrypt_then_decrypt_then_restore(self):
        import sqlalchemy as sa

        payload = _payload([{"id": 1, "name": "g"}],
                           [{"id": 7, "board_id": 1, "body": "round trip"}])
        blob = BK["encrypt"]([payload], GOOD)

        # A holder can confirm the bytes without being able to read them.
        self.assertTrue(BK["verify"](blob))
        self.assertNotIn(b"round trip", blob)

        metadata, session = _scratch()
        try:
            report = BK["restore"](session, metadata, BK["decrypt"](blob, GOOD))
            self.assertEqual(report["rows"], 2)
            self.assertEqual(
                session.execute(sa.text("SELECT body FROM post WHERE id=7")).scalar(),
                "round trip")
        finally:
            session.close()
