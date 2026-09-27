# Baseline recommendation operations

Phase 4 experimentation and optimization controls are documented in
[experimentation.md](experimentation.md).
Phase 5 advanced ranking and maturity controls are documented in
[advanced-personalization.md](advanced-personalization.md).

Phase 3 serves and logs recommendations on the firehose, board catalog, video listing, and related
video surfaces. `GET /api/v1/recommendations/firehose`, `/catalog/<board_id>`, and `/videos` expose
the same pipeline to clients. Append `?ranking=chronological` to a page or endpoint to bypass all
personalized scoring and receive latest-first content.

## Privacy modes

Every request runs in exactly one mode:

- `chronological` — explicit user choice or `RECOMMENDER_ENABLED=false`;
- `baseline` — non-personal rules, popularity, recency, quality, and moderation;
- `personalized` — available only when analytics consent, separate personalization consent, and
  `ANALYTICS_PERSONALIZATION_ENABLED=true` all hold.

Without analytics consent, `recommendation_log` stores the content-serving decision but no subject
or account identifier. Frequency caps, profiles, creator/community affinity, and collaborative
signals are not consulted. Withdrawal deletes subject-linked recommendation logs and interaction
exports, clears the aggregate collaborative model conservatively, and schedules a rebuild.

## Candidate and ranking stages

Candidate generation is bounded at 500 items and applies visibility and Phase 2 moderation
eligibility first. Candidate sources include recent, popularity/freshness, topic and embedding
profile affinity, creator/community affinity, anchor-content similarity, and the nightly
collaborative item-item model.

The nightly job exports taxonomy-v1 behavior to `recommendation_interaction` using the documented
starting weights, including bookmark +8, completion +4, fast abandon −2, not-interested −8, and
report −12. It creates normalized co-occurrence rows in `collaborative_similarity`; this is the
item-item option in Stage 3 and avoids adding a continuously running ML service.

Stage 4 assembles a fixed tabular feature vector and uses a hot-reloaded LightGBM model when
`RECOMMENDER_LIGHTGBM_MODEL_PATH` points at a valid artifact. Until an evaluated artifact is
installed, the same vector uses the versioned `linear_baseline_v1` weights. This fallback is
intentional: serving and logging can launch without silently loading an unreviewed model.

After scoring, the re-ranker enforces moderation, a three-serves-per-item 24-hour frequency cap,
at most two items per creator, at most three previously seen items, topic streak limits, and a 40%
community cap on mixed-community surfaces. Fresh low-exposure content carries a logged 10%
exploration propensity. Scoped board and video feeds do not apply the impossible cross-community
cap, but retain creator/topic/seen limits.

## Logging and operations

Each `recommendation_log` row includes every eligible candidate, ranked items, position, score,
model id, per-item score components, candidate sources, exclusion reasons, experiment ids,
exploration propensity, mode, and ranking latency. Client viewport and click events carry the same
request/model identifiers. Logs expire after 30 days.

The admin analytics-quality page reports 24-hour request volume, source coverage, personalized
request count, and average ranking latency. The collaborative refresh has its own PostgreSQL
advisory lock (`741314`) and durable `analytics_job_state` entry.

Configuration:

| Key | Default | Purpose |
| --- | --- | --- |
| `RECOMMENDER_ENABLED` | `true` | Serve ranked results; false forces chronological mode |
| `RECOMMENDER_MAINTENANCE_ENABLED` | `true` | Run nightly interaction/model refresh checks |
| `RECOMMENDER_ADVISORY_LOCK_ID` | `741314` | Dedicated collaborative-training leader lock |
| `RECOMMENDER_MAINTENANCE_INTERVAL_SECONDS` | `3600` | Due-check cadence, minimum 300 seconds |
| `RECOMMENDER_LIGHTGBM_MODEL_PATH` | unset | Optional reviewed LightGBM artifact |
