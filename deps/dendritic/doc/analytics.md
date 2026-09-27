# Behavioral analytics operations

Behavioral analytics is opt-in and personalization is unavailable by default. Phase 1 measures
consented behavior. Phase 2 adds non-personal content features and consent-scoped interest profiles;
it still does not serve a personalized feed. See [Content features and interest profiles](content-features.md).
Phase 3 adds the consent-gated serving pipeline described in [Baseline recommendation operations](recommendations.md).

## User endpoints

- `GET /analytics/privacy` — privacy controls.
- `GET /analytics/consent` — current purpose-specific consent and the pseudonymous subject id only
  when analytics is enabled.
- `POST /analytics/consent` — JSON or form update. `analytics` and `personalization` are independent;
  personalization is rejected until `ANALYTICS_PERSONALIZATION_ENABLED` is explicitly enabled.
- `POST /events` — batches of 1–50 taxonomy-v1 events; requires analytics consent.
- `POST /analytics/feedback` — strict `hide` / `not_interested` negative-feedback capture.
- `GET /analytics/export` — export the current subject's retained analytics history.
- `POST` or `DELETE /analytics/history` — queue deletion through every analytics store.

The client bundle exposes `window.maniwaniAnalytics.track(name, envelopeFields)` and `.flush()`.
Unknown names, envelope fields, nested fields, and properties are rejected. Impression events require
`visible_ratio >= 0.5` and `visible_ms >= 500`.

## Storage and maintenance

`analytics_event` is append-only on the request path. PostgreSQL uses monthly range partitions;
SQLite uses a normal table for development. The elected maintenance worker uses advisory lock
`741313`, reconstructs sessions at a 30-minute inactivity boundary, processes deletion requests,
removes account linkage after 30 days, and purges detailed events after 180 days.

Configuration:

| Key | Default | Purpose |
| --- | --- | --- |
| `ANALYTICS_MAINTENANCE_ENABLED` | `true` | Run the maintenance worker |
| `ANALYTICS_MAINTENANCE_ADVISORY_LOCK_ID` | `741313` | Dedicated leader lock |
| `ANALYTICS_MAINTENANCE_INTERVAL_SECONDS` | `300` | Maintenance cadence, minimum 60 seconds |
| `ANALYTICS_PERSONALIZATION_ENABLED` | `false` | Privacy/age-reviewed personalization gate |

The admin-only `/admin/analytics-quality` page reports accepted volume, schema validity, duplicates,
clock skew, consent rejections, rate limiting, and delivery latency. A confirmed consent or privacy
failure is an incident, not a harmless data-quality warning.

## Deletion and incident checks

Withdrawal stops subsequent ingestion immediately and queues history deletion. The maintenance job
deletes matching event/session/profile rows and any Redis keys in the reserved subject namespace.
The export includes a current derived profile when one exists.

After restoring a backup, run one maintenance cycle before exposing analytics queries so queued
deletions and retention are reapplied.

Phase 3 recommendation operations are documented in [recommendations.md](recommendations.md).
Phase 4 experiments, guardrails, evaluation, and dashboards are documented in
[experimentation.md](experimentation.md).
Phase 5 sequence models, value predictions, user controls, maturity monitors, and audits are
documented in [advanced-personalization.md](advanced-personalization.md).
