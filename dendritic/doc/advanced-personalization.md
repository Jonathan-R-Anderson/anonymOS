# Advanced personalization and continuous maturity

Phase 5 extends the consent-gated Phase 3 ranker and Phase 4 experiment platform. The advanced path
is active only when analytics consent, separate personalization consent,
`ANALYTICS_PERSONALIZATION_ENABLED`, and `PHASE5_ADVANCED_ENABLED` all permit it. Chronological and
anonymous baseline modes remain available.

## Advanced serving

- `sasrec-style-hash-v1` maintains a recency-decayed sequence embedding over the last 50 meaningful
  items. Validated events update short-term intent immediately; a nightly replay corrects it.
- `multimodal-hash-64-v1` fuses text with media type/count signals or a supplied local visual vector.
  No third-party embedding API receives user behavior or content.
- The contextual UCB policy chooses among familiar, fresh-creator, new-topic, and cross-format arms.
  Exploration is capped by `RECOMMENDER_BANDIT_EPSILON`; moderation and eligibility run before the
  policy. Request-level arm, context, propensity, candidate sources, and item propensities are logged.
- Multi-objective ranking combines predicted engagement, explicit/implicit satisfaction, long-term
  constructive value, and safety. The creator-discovery pass reserves a bounded slot for an
  underexposed creator while retaining creator, topic, community, and seen-item constraints.
- Conversation continuation is sourced only from conversations the subject joined. Notification
  candidates expire after seven days and are available from
  `GET /api/v1/recommendations/notifications`.
- `survival-value-v1` produces interpretable churn and long-term-value components. These predictions
  adjust ranking objectives; they do not trigger external messaging or punitive treatment.

## User control and privacy

The privacy page and `GET/PATCH /api/v1/recommendations/preferences` expose inferred interests,
muted topics, creator exclusions, discovery choice, and personalization strength. Removing an
inferred interest also adds a durable topic mute so the nightly replay cannot silently restore it.
Advanced sequence, value, preference, and notification rows participate in export, retention,
consent withdrawal, and deletion.

The maturity cycle emits only k-anonymous topic aggregates with at least five distinct profiles.
Raw federated updates are not collected; the audit manifest records this invariant. This is the
privacy-enhancing option selected for the current scale, not a claim that federated learning is
always beneficial.

## Continuous measurement

The nightly recommendation maintenance cycle rebuilds:

- contextual-arm rewards from clicks, satisfaction, negative feedback, and reports;
- creator impression and exploration distributions;
- randomized-experiment causal click estimates with 95% confidence intervals;
- feature-drift and creator-concentration snapshots;
- k-anonymous topic aggregates.

Automated alerts use `RECOMMENDER_FEATURE_DRIFT_MAX` and `RECOMMENDER_CREATOR_GINI_MAX`. Phase 4
experiment rollback continues to protect treatments; the bandit cannot make ineligible content
eligible.

## Independent audits

An administrator can create a checksum-protected audit manifest with `POST /admin/algorithm-audits`
and retrieve it from `/admin/algorithm-audits/<id>`. The manifest includes model versions,
experiments, guardrails, fairness, model health, and privacy gates. It begins in
`pending_external_review`; only an authenticated reviewer submission changes it to
`externally_reviewed`. Implementation of the workflow does not count as independent sign-off.

## Configuration

- `PHASE5_ADVANCED_ENABLED` — advanced-serving master switch, default on behind personalization.
- `RECOMMENDER_BANDIT_EPSILON` — exploration budget, default 0.10 and hard-capped at 0.25.
- `RECOMMENDER_FEATURE_DRIFT_MAX` — absolute feature-mean drift alert, default 0.15.
- `RECOMMENDER_CREATOR_GINI_MAX` — creator exposure concentration alert, default 0.80.

Production promotion still requires Phase 4 experiment review and the Phase 5 exit evidence: new
content and creators receive sufficient viewport exposure, safety is not degraded, propensities are
complete, and offline correction remains stable.
