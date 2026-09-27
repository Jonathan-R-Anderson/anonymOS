# Civil-rights reporting and the citizen newsroom — what is left

**This file holds only unfinished work.** Anything built and tested is deleted
from it, so its length is the remaining work and nothing else. The reasoning
behind what shipped lives in the module docstrings, which is where it stays true.

Everything marked *read* was confirmed against the code. Everything else is a
proposal and says so.

## Already shipped — do not re-plan these

A pointer list, not a plan. Read the docstrings before changing any of them.

| Where | What it does |
|---|---|
| `model/PublicInterestReport*.py` | index row (no PII), reference codes, retention, notes, audit |
| `services/report_crypto.py` | AEAD sealing under a separate master key, no fallback |
| `services/report_dht.py` | `civil-rights-reports/<id>/v<n>`, readback-gated writes |
| `services/report_schema.py` | one field definition for form, validation and payload |
| `services/public_interest_reports.py` | submit / read / status, and the `stored_at` invariant |
| `services/report_retention.py` + `_loop` | hourly leader-gated expiry that actually deletes |
| `services/report_rate_limit.py` | IP-token buckets, fails open |
| `services/report_evidence.py` | type gate, fail-closed scan, EXIF/OOXML/PDF scrubbing |
| `blueprints/civil_rights.py` | landing, form, tips line, confirmation, lookup |
| `blueprints/report_review.py` | reviewer queue, decrypt, status, notes, audit |
| `model/{Contributor,PenName,NewsStory,StoryRevision,StoryVote,EditorialAction}.py` | the newsroom's data |
| `services/bylines.py` | the only module that decides what a reader learns about authorship |
| `services/newsroom.py` | the editorial state machine, approvals bound to a content hash |
| `services/story_votes.py`, `services/news_rail.py` | voting, and the precomputed front-page rail |
| `blueprints/{news,newsroom,news_editor,story_votes}.py` | reading, writing, editing, voting |
| `services/admin_nav.py` + `templates/admin-shell.html` | admin navigation on every screen |

**Live today:** civil-rights reports and newsroom tips as text-only submissions;
the full newsroom — contributor desk, editor queue, author and pen-name pages,
feeds, front-page rail, voting.

---

# Outstanding decisions

**D6. What the web tier logs.** Outside the application but not outside scope: if
nginx or uWSGI records the client IP of a POST to `/civil-rights/report`, the
system retains an identifier for someone reporting police misconduct that the
encryption was built to avoid. Needs checking against the deployed config, and a
deliberate exclusion for that route if present. **Nothing in the application can
fix this.**

**D7. Is there a second reviewer, and a second editor?** *Read:* admin access is
one configured MetaMask wallet. `Slip.is_editor` now exists and
`slip_is_editor()` honours it, so the newsroom side is answerable — but there is
**no admin form to set the flag**, so granting it is a database update today.
The report reviewer side is unchanged: the audit trail's `actor` records the same
wallet on every row, answering "an admin" and never "who".

**D8. Archives in evidence uploads.** They are how a source sends forty
documents, and also a malware and decompression-bomb vector. If accepted: unpack
in a bounded sandbox with limits on entry count, total size and nesting depth,
scan every member, and refuse the whole archive on any failure rather than
importing what passed. **Recommendation: not at launch**, with a file-count
limit instead.

---

# Evidence and documents

The scanning and scrubbing core is built and tested (`services/report_evidence.py`
— type gate, fail-closed ClamAV, EXIF/OOXML/PDF scrubbing with a manifest of
what was removed). What remains is carrying files from a form into storage, and
showing them to a reviewer safely.

## Upload path

Nothing is attached to a submission today: no form accepts a file, and
`submit()`'s `evidence` slot is never populated. Needed: streamed upload to
temporary storage, `report_evidence.prepare()`, then the three artefacts sealed
and stored with a reference by digest in the payload.

**512 MB per file, 2 GB per submission.** Sized to what leaked material looks
like rather than to what has been verified, because a cap that forces sources to
split a dataset produces worse tips and more handling, not more safety. What
makes that safe ahead of the unproven large-object path is the readback gate that
already exists: an object the DHT cannot round-trip produces an error and no
confirmation.

Three constraints, none optional:

- **Stream, never buffer.** A 2 GB body read into memory kills a gevent worker.
- **nginx and uWSGI must agree with the application.** `client_max_body_size` and
  the uWSGI buffers default far below 2 GB, and the failure is a 413 from the
  proxy that the application never sees and therefore cannot explain.
- **Resumable above ~100 MB.** A source losing a 1.5 GB upload at 90% has no
  reason to try again, and the ones worth protecting are least likely to be on
  good connections.

## Warn before the upload, not after

Scrubbing protects a source from the site republishing their metadata. It does
nothing about them having sent it, and **printer tracking dots live in the pixels
of a scan and are never removed**. So a short plain warning goes *before the file
picker*, not in the acknowledgements — it is the only intervention early enough
to help somebody who should not be sending that file at all.

## Reviewer preview

A reviewer must never get the original bytes by default. The queue needs a
rendered preview — pages as images, extracted text — so reading a tip does not
mean opening an untrusted PDF on a newsroom machine. Downloading the original
stays possible as a separate, audited action. `prepare()` already produces the
scrubbed copy this renders from; the rendering and the download gate are missing.

## Remaining abuse controls

Duplicate detection on a hash of the normalised description — catches the same
text pasted repeatedly without blocking a genuine second report about the same
incident.

---

# The wall between a report and a story

*Read: the wall currently holds by absence* — nothing in `blueprints/newsroom.py`,
`blueprints/news_editor.py` or `services/newsroom.py` references a report. Keep
it that way. **There must be no automatic path from a report or tip to a draft**:
no "write a story from this" button, no pre-filled fields, no copy of a payload
into story tables. A reviewer opens a blank draft. The friction is deliberate —
a pre-fill is how a complainant's legal name reaches publication through a field
nobody remembered was populated.

## Consent is NOT built

The one piece of this that is missing rather than held. **Filing is not consent
to publish.** Anything derived from a submission needs a separate, explicit,
recorded consent artefact from the complainant, revocable up to publication —
consent to be helped is not consent to be named.

Needed: a consent record tied to a `report_id`, a way for a reviewer to request
it and a complainant to grant or withdraw it through their reference code, and a
gate on publishing any story that cites a report without one. Withdrawn consent
blocks a draft; after publication it is a retraction decision with a human making
it.

---

# Known defects

**The front-page rail has a concurrent-rebuild race.** *Found by review, not
fixed.* `rail_stories()` reads the cache, misses, builds, then writes with a
fresh timestamp and no compare-and-set. A request that begins `_build()` before a
publish can write its pre-publish result afterwards, re-pinning stale content for
the full 120 s TTL — including the case the invalidation exists to prevent, an
editor pressing Publish and immediately loading `/`. Needs a generation counter
or a compare-and-set, not a patch. Worst case is annoying rather than harmful.

**`/news/vote/<id>/clear` is unmetered and a weak existence oracle.** It is not
rate-limited and not gated on `_open_for_voting`, so a signed-in slip can walk
the id space and separate "unpublished story exists" from "no such story" on
latency — the fact `cast` deliberately refuses to disclose. Apply the rate limit
and skip the service call when there is no vote row.

**Three surfaces still resolve a contributor's display name independently**
(`blueprints/news.py`, `services/news_rail.py`, `blueprints/news_editor.py`). The
login-name leak is fixed in all three, but `bylines.public_byline()` receives an
already-decided dict, so the module that is supposed to be the single decider is
downstream of the decision. A `contributor_source(slip_id)` in `bylines.py` that
all three call would give `Slip.name` exactly one place it can be rejected.

---

# Still to build in the newsroom

- **An admin form for `Slip.is_editor`.** The flag and the predicate exist; the
  checkbox does not, so appointing an editor is a database update. It belongs in
  the same admin panel that already sets `is_mod`.
- **Section fronts.** `NewsStory.section` is stored and filterable but there is
  no `/news/section/<name>`.
- **A background pass for `story_votes.recompute_all()` and
  `news_rail.refresh()`.** Both exist and nothing calls them, so scores fold into
  ordering only when something else happens to rebuild.
- **Hero images.** `hero_media_id` is on the model and no form sets it.
- **Pull quotes, captions and footnotes** — markup or structured fields, still
  undecided (open question 2).

---

# Tests still to write

Only for work not yet built:

- EXIF GPS absent from every scrubbed copy **as served through the upload path**
  (the scrubber itself is tested; the path is not)
- a reviewer preview never serves original bytes
- ClamAV unavailable causes an upload to be refused
- a tip or report cannot pre-fill a story draft
- publishing report-derived material without a consent record is refused
- an upload larger than the cap is refused by the application, not only by nginx

---

# Open questions

1. **Do pen names need approval?** They currently do — `PenName.approved`
   defaults false and only an editor sets it. Confirm that is wanted, since it
   puts a human in the way of every pseudonym.
2. **Pull quotes, captions, footnotes: markup or form fields?**
3. **Several bylines on one story**, possibly in different modes? (The mixed case
   must not let the named author imply the other.)
4. **Do contributors get paid?** Payment records are an identity trail attached to
   otherwise unattributed work.
5. **Comments on stories?** A story with no discussion looks broken on a
   discussion board; comments under an investigation naming a private individual
   are a moderation load and possibly a liability.
6. **Is the tips line reachable without JavaScript?** It should be — the sources
   most in need of it run hardened browsers.
7. **Do tips and reports share one review desk or two?** They share a table;
   probably two desks, since the skills and urgency differ.

## What will not be proven when all of this is done

- **That the DHT durably holds submissions.** Readback proves retrievability from
  one gateway. Replication across distinct peers is not observable from the site.
- **That "only authorised personnel can decrypt" holds against the operator.**
  Whoever holds the report master secret reads everything. Inherent, and to be
  stated rather than claimed away.
- **That the acknowledgement wording is legally sound.** Placeholder text is in
  `services/report_schema.py` and wants a lawyer.
