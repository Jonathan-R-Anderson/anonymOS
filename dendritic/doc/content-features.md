# Content features and interest profiles

Phase 2 turns current threads and videos into versioned, non-personal content features and builds
interest profiles only for people who have separately opted into personalization.

## Content refresh

The analytics maintenance leader checks the `phase2_feature_profile_refresh` job every cycle and
runs it at most once every 24 hours. `refresh_content_features()` may also be invoked from an admin
shell for a backfill. Every current thread and video receives an `analytics.content_feature` row;
rows for deleted content are removed.

`content-v1` contains:

- distinctive TF-IDF-style keywords and tags, a normalized 64-dimensional local hashing embedding,
  learned `WordSentiment`, a conservative language label, and media type/count;
- quality, report rate, recent engagement velocity, video completion distribution, and estimated
  read/watch duration;
- a moderation eligibility decision and machine-readable exclusion reasons.

The local embedding is deterministic and dependency-free. Related-video retrieval uses cosine over
the bounded 500-item candidate pool, then quality and views as tie-breakers. This gives the current
data volume an exact result while keeping a fixed-width representation that can be copied to
`pgvector` and indexed with HNSW when the candidate pool outgrows bounded exact search. New content
uses the previous Jaccard scorer until its first refresh; known-ineligible content is always removed.
The same moderation-filtered similarity service is available for threads.

## Profiles and negative signals

PostgreSQL stores separate `user_profile` and shorter-lived `anon_profile` rows. Anonymous profiles
expire after 30 days; account profiles expire after 180 days and are refreshed nightly. Redis stores
only short-term counters under `analytics:profile:<subject-id>` with a 30-day TTL.

Profiles require all three conditions: analytics consent, personalization consent, and the global
`ANALYTICS_PERSONALIZATION_ENABLED` privacy/age gate. When the gate is disabled (the default), the
refresh job removes profiles while continuing to build non-personal content features.

Starting signal weights are bookmark +8, follow +7, reply +6, share +5, completion +4, deep dwell
+3, and weak opens/clicks +1. Explicit report −12, hide/not-interested −8, dismiss/mute −3, and fast
abandon −2 are stored in a separate negative-topic vector. Thus a single explicit negative action
outweighs weak positive behavior; the vectors are not collapsed into an opaque net score.

`POST /analytics/feedback` accepts only `hide` and `not_interested` for an opaque content id and
emits a taxonomy-v1 event after analytics consent. The related-video control hides the item locally
at once. It updates a profile only when personalization is also allowed.

## Operations and deletion

Job status, timestamps, counts, feature version, and errors live in `analytics_job_state`. Consent
withdrawal deletes raw events, reconstructed sessions, account/anonymous profiles, and matching
Redis profile keys. `GET /analytics/export` includes the current derived profile. Content features
contain public content attributes and aggregate metrics, never a subject identifier, so subject
deletion does not remove them; the next refresh recomputes aggregates from the retained dataset.
