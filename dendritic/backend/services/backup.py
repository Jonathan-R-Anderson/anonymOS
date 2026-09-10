"""An encrypted backup that the people holding it cannot read.

Phase 3 of roadmap/domain-and-origin-succession.md. The point is to be able to
rebuild this site on a machine that is not this one — including, if it comes to
it, on a volunteer's gateway. Which is exactly why the holders must not be able
to open it: a backup containing a usable database and a usable signing key,
sitting on other people's disks, hands every volunteer the ability to forge the
site and read every private message in it. That is worse than the outage it
prevents.

So the artifact is ciphertext plus a plaintext header, and the header carries
enough for a holder to prove they are still storing the right bytes without
being able to see any of them.

TWO DIFFERENT INTEGRITY QUESTIONS, TWO DIFFERENT MECHANISMS
-----------------------------------------------------------
They get confused constantly, and only having one of them leaves a real gap:

  * "Are these the bytes that were made?" — answerable by ANYONE, from the
    SHA-256 of the ciphertext in the header. This is what a storage challenge
    asks a gateway, and it needs no key, so a holder can answer it.
  * "Is this plaintext genuine and untampered?" — answerable only by someone
    with the passphrase, from the AEAD tags. A digest alone cannot do this job:
    an attacker who rewrites the ciphertext can rewrite the digest beside it.

The header is fed to every AEAD segment as associated data, so editing the KDF
parameters — say, dropping the scrypt cost to something brute-forceable — makes
decryption fail rather than quietly succeed with weakened protection.

WHY IT IS SEGMENTED
-------------------
One-shot AES-GCM needs the whole database in memory twice. Segmenting fixes
that, but naive segmenting introduces two new attacks: segments can be reordered
and the file can be truncated, and both produce a "valid" decryption of the
wrong thing. Each segment's index and its final-flag are therefore authenticated
along with the header, so a reordered or truncated file fails to open rather
than opening as something plausible.

WHAT IS NOT IN IT
-----------------
Media. It is content-addressed in the DHT and a new server fetches the same
objects by the same hashes, so copying it in would turn a small artifact into an
enormous one and prove nothing that the hashes do not already prove.
"""

import base64
import datetime as _datetime
import hashlib
import json
import os
import struct

from shared import app

MAGIC = b"ANONCHAN-BACKUP"
FORMAT_VERSION = 1

# 1 MiB. Large enough that per-segment overhead is noise, small enough that a
# restore never holds much at once.
SEGMENT_BYTES = 1024 * 1024

# scrypt. n=2**15 is roughly 100ms and 32 MiB here — chosen so an operator does
# not notice it once, and somebody guessing passphrases notices it every time.
KDF_N = 2 ** 15
KDF_R = 8
KDF_P = 1
KEY_BYTES = 32
SALT_BYTES = 16
NONCE_BYTES = 12

# The whole database is behind this one string. A short passphrase is not a
# smaller risk here than elsewhere, it is the entire risk.
MINIMUM_PASSPHRASE = 16

# Tables deliberately left out. Each one is either rebuildable from what IS
# included, or a cache whose staleness after a restore would be worse than its
# absence.
EXCLUDED_TABLES = frozenset({
    "alembic_version",   # the restore runs migrations; a stamped version would
                         # tell it the schema is already current when it is not
    "threat_event",      # 14-day observation log, rebuilt by observing
    "falco_alert",       # host IDS events, tied to hosts that will not exist
})


class BackupError(Exception):
    """Refused. The message is read by an operator mid-incident."""


# -- the payload -----------------------------------------------------------

def _encode(value):
    """JSON cannot hold what Postgres returns. Encode losslessly and say so."""
    if isinstance(value, (_datetime.datetime, _datetime.date, _datetime.time)):
        return {"__t": "dt", "v": value.isoformat()}
    if isinstance(value, _datetime.timedelta):
        return {"__t": "td", "v": value.total_seconds()}
    if isinstance(value, (bytes, bytearray, memoryview)):
        return {"__t": "b64", "v": base64.b64encode(bytes(value)).decode("ascii")}
    if isinstance(value, set):
        return {"__t": "set", "v": sorted(value)}
    try:
        import decimal

        if isinstance(value, decimal.Decimal):
            # As a string, not a float. Credit balances live in these columns
            # and a float round-trip is a silent change to somebody's money.
            return {"__t": "dec", "v": str(value)}
    except Exception:
        pass
    if isinstance(value, uuidish()):
        return {"__t": "uuid", "v": str(value)}
    return value


def uuidish():
    import uuid

    return uuid.UUID


def decode(value):
    if not isinstance(value, dict) or "__t" not in value:
        return value
    kind, raw = value.get("__t"), value.get("v")
    if kind == "dt":
        return raw          # left as ISO text; the column type re-parses it
    if kind == "td":
        return _datetime.timedelta(seconds=raw)
    if kind == "b64":
        return base64.b64decode(raw)
    if kind == "set":
        return set(raw)
    if kind == "dec":
        import decimal

        return decimal.Decimal(raw)
    if kind == "uuid":
        return raw
    return value


def table_names():
    """Every table to back up, in an order a restore can insert in.

    SQLAlchemy's sorted_tables is topologically sorted by foreign key, which is
    exactly the order rows have to be inserted in. Getting this from the
    metadata rather than a hand-kept list means a table added later is included
    without anybody remembering to add it — and a forgotten table is a restore
    that looks like it worked.
    """
    from shared import db

    return [table.name for table in db.metadata.sorted_tables
            if table.name not in EXCLUDED_TABLES]


def dump_stream(chunk_rows=500):
    """Yield the backup payload as bytes: a header line, then JSONL per table.

    A stream rather than one object, because the alternative is holding the
    whole database in memory as Python objects and then again as JSON.
    """
    from shared import db

    yield (json.dumps({
        "format": FORMAT_VERSION,
        "created_at": _datetime.datetime.utcnow().isoformat() + "Z",
        "tables": table_names(),
        # Inside the ciphertext, never in the plaintext header. These are the
        # keys that sign the site; a header naming which secrets are present
        # would tell a holder exactly what is worth attacking the file for.
        "settings": settings_payload(),
        "note": "Media is NOT here. It is content-addressed in the DHT and a "
                "restored server fetches the same objects by the same hashes.",
    }, sort_keys=True) + "\n").encode("utf-8")

    for table in db.metadata.sorted_tables:
        if table.name in EXCLUDED_TABLES:
            continue
        yield (json.dumps({"__table": table.name}) + "\n").encode("utf-8")
        columns = [column.name for column in table.columns]
        result = db.session.execute(table.select())
        while True:
            rows = result.fetchmany(chunk_rows)
            if not rows:
                break
            for row in rows:
                record = {name: _encode(value)
                          for name, value in zip(columns, row)}
                yield (json.dumps(record, sort_keys=True) + "\n").encode("utf-8")


# Configuration that is not in the repo and cannot be regenerated — losing any
# of these means the restored site is a DIFFERENT site to everyone who was
# relying on it, not merely an inconvenienced one.
#
# An allowlist, never the whole config, and deliberately short. app.config also
# holds the database URL, the S3 credentials and the Flask secret; "back up
# everything" would put the lot into an artifact designed to be handed to
# volunteers, and encrypting it is not what makes that acceptable.
CARRIED_SETTINGS = (
    # Every published page is signed with this. A restore with a new one makes
    # every snapshot and every signature in the wild fail to verify.
    "ORIGIN_SIGNING_KEY",
    "SNAPSHOT_SIGNING_KEY",
    "STORAGE_COORDINATOR_SIGNING_KEY",
    # Tripcodes are derived from this. A new one silently reassigns every
    # persistent identity on the site to a different string.
    "TRIPCODE_SECRET",
    # Who may issue a network directive. Without it the restored origin cannot
    # tell the network it has moved.
    "ADMIN_WALLET_ADDRESS",
)


def settings_payload(keys=None):
    """The carried settings that are actually set."""
    return {key: app.config.get(key)
            for key in (keys if keys is not None else CARRIED_SETTINGS)
            if app.config.get(key)}


# -- restore ---------------------------------------------------------------

def parse_payload(payload):
    """(manifest, {table: [row, ...]}) from a decrypted dump. Raises BackupError.

    Rows are grouped rather than streamed straight into the database because a
    restore that fails halfway is a half-populated database, and the person
    running it is already having a bad day. Parse fully, then write.
    """
    lines = payload.split(b"\n")
    if not lines or not lines[0].strip():
        raise BackupError("This backup has no manifest.")
    try:
        manifest = json.loads(lines[0])
    except ValueError:
        raise BackupError("The backup manifest is unreadable.")
    if manifest.get("format") != FORMAT_VERSION:
        raise BackupError("Backup payload format %r, this build reads %d."
                          % (manifest.get("format"), FORMAT_VERSION))

    tables = {}
    current = None
    for number, line in enumerate(lines[1:], start=2):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except ValueError:
            raise BackupError("Line %d of the backup is unreadable." % number)
        if isinstance(record, dict) and "__table" in record and len(record) == 1:
            current = record["__table"]
            tables.setdefault(current, [])
            continue
        if current is None:
            raise BackupError("Line %d has no table." % number)
        tables[current].append({key: decode(value)
                                for key, value in record.items()})
    return manifest, tables


def target_is_empty(session, names):
    """Whether every named table has no rows.

    A restore MUST NOT merge into a populated database. Doing so would collide
    primary keys against live rows and interleave two sites' content with no way
    to tell them apart afterwards — and it is the mistake somebody makes by
    pointing a restore at production instead of the new server.
    """
    from sqlalchemy import text

    for name in names:
        try:
            found = session.execute(
                text("SELECT 1 FROM %s LIMIT 1" % name)).first()
        except Exception:
            continue  # a table the target does not have yet
        if found is not None:
            return False, name
    return True, None


def restore(session, metadata, payload, allow_nonempty=False):
    """Load a decrypted dump into an EMPTY database. Returns a report.

    The schema must already exist — a restore runs migrations first, which is
    why `alembic_version` is excluded from the dump. Restoring a stamped version
    into an unmigrated database would tell Alembic the schema is current when
    there is nothing there.
    """
    manifest, tables = parse_payload(payload)

    ordered = [table for table in metadata.sorted_tables
               if table.name in tables]
    missing = sorted(set(tables) - {table.name for table in ordered})

    if not allow_nonempty:
        empty, offender = target_is_empty(session, [t.name for t in ordered])
        if not empty:
            raise BackupError(
                "%s already has rows, so this is not an empty database. A "
                "restore into a populated one collides primary keys against "
                "live rows and interleaves two sites with no way to separate "
                "them afterwards. Nothing was written." % offender)

    written = {}
    for table in ordered:
        rows = tables.get(table.name) or []
        if not rows:
            continue
        columns = {column.name for column in table.columns}
        # Columns the dump has and this schema does not are dropped rather than
        # failing the restore: a backup from an older build is exactly the one
        # somebody restores, and refusing it over a removed column would make
        # the artifact useless at the moment it is needed.
        cleaned = [{key: value for key, value in row.items() if key in columns}
                   for row in rows]
        session.execute(table.insert(), cleaned)
        written[table.name] = len(cleaned)

    resequenced = resequence(session, ordered)
    session.commit()
    return {
        "created_at": manifest.get("created_at"),
        "tables_written": written,
        "rows": sum(written.values()),
        "tables_in_backup_not_in_schema": missing,
        "sequences_advanced": resequenced,
        "settings": sorted((manifest.get("settings") or {}).keys()),
    }


def resequence(session, tables):
    """Advance each serial sequence past the highest id just inserted.

    WITHOUT THIS THE RESTORE LOOKS PERFECT AND THE SITE IS BROKEN
    Rows are inserted with explicit primary keys, which does not move the
    sequence behind them. It still returns 1, so the very first post, slip or
    board created after the restore collides with a row from the backup — and
    it keeps colliding, one id at a time, for as long as anyone has patience.
    Nothing about the restore looks wrong; the site just refuses to accept
    anything new.
    """
    from sqlalchemy import text

    # Postgres only. `pg_get_serial_sequence` does not exist elsewhere, and a
    # statement that errors inside a Postgres transaction aborts the whole
    # transaction — every subsequent statement then fails with "current
    # transaction is aborted", which would turn one unsupported column into a
    # failed restore. Checking the dialect up front avoids needing a savepoint
    # around each attempt.
    dialect = getattr(getattr(session, "bind", None), "dialect", None)
    if dialect is None:
        try:
            dialect = session.get_bind().dialect
        except Exception:
            return []
    if getattr(dialect, "name", "") != "postgresql":
        return []

    advanced = []
    for table in tables:
        for column in table.columns:
            if not column.primary_key or not _is_integer(column):
                continue
            # A savepoint per column: a natural integer key has no sequence, and
            # pg_get_serial_sequence returning NULL makes setval error. That is
            # expected for some columns and must not take the restore with it.
            savepoint = session.begin_nested()
            try:
                session.execute(text(
                    "SELECT setval("
                    "  pg_get_serial_sequence(:table, :column),"
                    "  COALESCE((SELECT MAX(%s) FROM %s), 0) + 1, false)"
                    % (column.name, table.name)),
                    {"table": table.name, "column": column.name})
                savepoint.commit()
                advanced.append("%s.%s" % (table.name, column.name))
            except Exception:
                savepoint.rollback()
    return advanced


def _is_integer(column):
    try:
        return column.type.python_type is int
    except Exception:
        return False


# -- encryption ------------------------------------------------------------

def _derive(passphrase, salt):
    return hashlib.scrypt(passphrase.encode("utf-8"), salt=salt,
                          n=KDF_N, r=KDF_R, p=KDF_P, dklen=KEY_BYTES,
                          maxmem=256 * 1024 * 1024)


def _header_bytes(header):
    return json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")


def encrypt(plaintext_chunks, passphrase, extra=None):
    """Encrypt a stream into one artifact. Returns bytes.

    Raises BackupError on a passphrase that is not worth having.
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    if len(passphrase or "") < MINIMUM_PASSPHRASE:
        raise BackupError(
            "The passphrase must be at least %d characters. Everything in the "
            "database is behind it, and it will be held by people who would "
            "like to read it." % MINIMUM_PASSPHRASE)

    salt = os.urandom(SALT_BYTES)
    nonce_base = os.urandom(NONCE_BYTES - 4)
    header = {
        "magic": MAGIC.decode("ascii"),
        "version": FORMAT_VERSION,
        "kdf": {"name": "scrypt", "n": KDF_N, "r": KDF_R, "p": KDF_P,
                "salt": base64.b64encode(salt).decode("ascii")},
        "cipher": "AES-256-GCM",
        "segment_bytes": SEGMENT_BYTES,
        "nonce_base": base64.b64encode(nonce_base).decode("ascii"),
        "created_at": _datetime.datetime.utcnow().isoformat() + "Z",
    }
    if extra:
        header["extra"] = extra
    header_blob = _header_bytes(header)

    key = _derive(passphrase, salt)
    cipher = AESGCM(key)

    body = bytearray()
    index = 0

    def seal(segment, final):
        nonlocal index
        # The index and the final flag are authenticated, so a reordered or
        # truncated file fails to open instead of opening as something else.
        aad = header_blob + struct.pack(">I?", index, final)
        nonce = nonce_base + struct.pack(">I", index)
        sealed = cipher.encrypt(nonce, bytes(segment), aad)
        body.extend(struct.pack(">I", len(sealed)))
        body.extend(sealed)
        index += 1

    pending = bytearray()
    for chunk in plaintext_chunks:
        pending.extend(chunk)
        while len(pending) >= SEGMENT_BYTES:
            seal(pending[:SEGMENT_BYTES], False)
            del pending[:SEGMENT_BYTES]
    # Always a final segment, even when empty: it is what marks the end, so a
    # file cut short has no final segment and cannot be mistaken for complete.
    seal(pending, True)

    body = bytes(body)
    # A digest over the ciphertext, in the clear. This is the question a
    # storage challenge asks -- "are you still holding the right bytes?" -- and
    # it has to be answerable by a holder who cannot decrypt anything.
    digest = hashlib.sha256(body).hexdigest()
    envelope = _header_bytes({**header, "ciphertext_sha256": digest,
                              "ciphertext_bytes": len(body)})

    return (MAGIC + struct.pack(">II", FORMAT_VERSION, len(envelope))
            + envelope + body)


def split(blob):
    """(envelope dict, header bytes, ciphertext). Raises BackupError."""
    if not blob or not blob.startswith(MAGIC):
        raise BackupError("That is not a syndichan backup.")
    offset = len(MAGIC)
    try:
        version, envelope_length = struct.unpack(">II", blob[offset:offset + 8])
    except struct.error:
        raise BackupError("Truncated backup header.")
    offset += 8
    if version != FORMAT_VERSION:
        raise BackupError("Backup format %d, this build reads %d."
                          % (version, FORMAT_VERSION))
    envelope_blob = blob[offset:offset + envelope_length]
    if len(envelope_blob) != envelope_length:
        raise BackupError("Truncated backup header.")
    try:
        envelope = json.loads(envelope_blob)
    except ValueError:
        raise BackupError("Unreadable backup header.")
    return envelope, envelope_blob, blob[offset + envelope_length:]


def verify(blob):
    """Whether an artifact is intact, WITHOUT the passphrase.

    What a gateway holding a backup can answer, and what a challenge should ask.
    It proves the bytes are the ones that were made; it does not and cannot
    prove the plaintext is genuine, because whoever rewrote the ciphertext could
    rewrite this digest beside it. That question is the AEAD's, and only the
    passphrase holder can ask it.
    """
    envelope, _, body = split(blob)
    expected = envelope.get("ciphertext_sha256")
    if not expected:
        return False
    return hashlib.sha256(body).hexdigest() == expected


def decrypt(blob, passphrase):
    """The plaintext, or BackupError. Verifies as it goes."""
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    envelope, _, body = split(blob)
    if not verify(blob):
        raise BackupError(
            "The ciphertext does not match the digest in its own header, so "
            "this file has been altered or is incomplete. Nothing was decrypted.")

    # Rebuilt without the fields added after sealing, because those were not
    # part of the associated data and including them would never authenticate.
    header = {key: value for key, value in envelope.items()
              if key not in ("ciphertext_sha256", "ciphertext_bytes")}
    header_blob = _header_bytes(header)

    kdf = envelope.get("kdf") or {}
    if kdf.get("name") != "scrypt":
        raise BackupError("Unsupported key derivation %r." % kdf.get("name"))
    try:
        salt = base64.b64decode(kdf["salt"])
        nonce_base = base64.b64decode(envelope["nonce_base"])
        key = hashlib.scrypt(passphrase.encode("utf-8"), salt=salt,
                             n=int(kdf["n"]), r=int(kdf["r"]), p=int(kdf["p"]),
                             dklen=KEY_BYTES, maxmem=256 * 1024 * 1024)
    except Exception as error:
        raise BackupError("Unusable backup header: %s" % error)
    cipher = AESGCM(key)

    out = bytearray()
    offset = 0
    index = 0
    saw_final = False
    while offset < len(body):
        try:
            (length,) = struct.unpack(">I", body[offset:offset + 4])
        except struct.error:
            raise BackupError("Truncated backup body.")
        offset += 4
        sealed = body[offset:offset + length]
        if len(sealed) != length:
            raise BackupError("Truncated backup body.")
        offset += length

        opened = None
        for final in (False, True):
            aad = header_blob + struct.pack(">I?", index, final)
            nonce = nonce_base + struct.pack(">I", index)
            try:
                opened = cipher.decrypt(nonce, sealed, aad)
                saw_final = final
                break
            except InvalidTag:
                continue
        if opened is None:
            raise BackupError(
                "Segment %d did not decrypt. Either the passphrase is wrong or "
                "the file has been altered." % index)
        out.extend(opened)
        index += 1

    if not saw_final:
        # No final segment means the file stops early. Without this a truncated
        # backup restores as a complete one that is quietly missing data.
        raise BackupError(
            "This backup has no final segment, so it is incomplete. A restore "
            "from it would look successful and be missing whatever came after "
            "the cut.")
    return bytes(out)
