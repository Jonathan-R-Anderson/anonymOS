# Experimentation and optimization operations

Phase 4 adds a consent-gated experiment control plane around the Phase 3 recommender. Decisions must
consider meaningful dwell, satisfaction, return behavior, negative feedback, reports, diversity,
latency, and errors together; session duration alone cannot approve a change.

## Assignment and exposure

`ExperimentDefinition` stores namespace, traffic, variants, metrics, guardrails, schedule, salt, and
rollback state. Assignment hashes `namespace + subject_id` and `salt + experiment_id + subject_id`
into 10,000 buckets. Definitions in one namespace consume non-overlapping traffic ranges, so a
subject receives at most one experiment in that namespace. Assignment and exposure happen only with
basic analytics consent.

The installed `phase4_recommender_v1` definition has a durable 5% holdout, 85% Phase 3 control, and
10% bounded exploration variant. Exploration increases only the fresh/underexposed content budget;
moderation, policy eligibility, diversity, and frequency caps still apply. Exposure and satisfaction
rows expire after 180 days and participate in export, consent withdrawal, deletion, and retention.

## Guardrails and rollback

The background monitor evaluates running experiments every 15 minutes by default. It records
outcomes by variant, Pearson sample-ratio mismatch, recommendation click/negative/report rates, p95
serving latency, and explicit satisfaction. After the configured minimum sample, an SRM or guardrail
violation changes the experiment to `rolled_back`; subsequent requests receive no assignment from
it. Every evaluation and action is retained in `ExperimentGuardrailSnapshot`.

## Shadow and offline evaluation

Serving records current scores plus `multi_objective_shadow_v1` scores without changing the served
order. `services.recommendations.evaluation.offline_evaluation()` reports served-list NDCG, shadow
top-one agreement, CTR by position, and inverse-propensity reward for randomized items. It labels
only viewport-exposed items; an unseen candidate is never assumed to be negative.

Promote changes through shadow, internal, 1%, 5%, 25%, 50%, and full rollout stages. Investigate SRM
and severe segment regressions before increasing traffic.

## Satisfaction and explanations

A deterministic 5% sample of consented recommendation requests receives a one-to-five usefulness
prompt. Responses are idempotent per subject and request. Cards expose bounded explanations such as
“New or underexposed content” or “Related to what you are viewing” and never disclose sensitive
inferred attributes.

## Admin dashboards

Wallet-authenticated SSR pages are available at `/admin/analytics-executive`,
`/admin/analytics-product`, `/admin/analytics-recommendations`,
`/admin/analytics-content-health`, and `/admin/analytics-data-quality`. The recommendation view
includes experiment status, SRM, position bias, propensity-corrected evaluation, shadow agreement,
source coverage, and latency.
The analytics maintenance cycle rebuilds replay-safe `behavior_metric_daily` facts for the recent
31-day window; dashboard queries use those Postgres rollups and fall back to retained events only in
an empty development or test database. Daily facts are retained for two years.

## Configuration

- `EXPERIMENTS_ENABLED` — assignment master switch; defaults on.
- `EXPERIMENT_MONITOR_ENABLED` — guardrail worker switch; defaults on outside tests.
- `EXPERIMENT_MONITOR_INTERVAL_SECONDS` — evaluation interval; defaults to 900.
- `RECOMMENDER_SATISFACTION_PROMPTS_ENABLED` — prompt master switch; defaults on.
- `RECOMMENDER_SATISFACTION_PROMPT_PERCENT` — deterministic prompt percentage; defaults to 5.

Disabling experiments returns serving to the Phase 3 baseline and creates no new exposure records.
