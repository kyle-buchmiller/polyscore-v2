# 99 — Open questions

Known follow-ups — decisions **we** owe. Move an item into a spec once it is decided, and
record the decision in `decisions/`.

Asks on **other teams** live in [`07-requests.md`](./07-requests.md). If an item needs
somebody else to build something, it belongs there, not here. Work that only becomes
*possible* once the retrain succeeds lives in [`08-future-work.md`](./08-future-work.md) —
this file is what blocks us now.

## Blocking the pilot

- **Cohort volume.** Does the estimand §1 population (customer-submitted PE, feeds
  excluded, post-2026-09-08) actually yield 10,000 files in a sensible window? If not,
  which compromise — widen the window, or admit feed rows and record the skew?
- **Gold slice ownership.** Who adjudicates the 200 files, against what written rubric,
  and where do the labels live? Nothing in this repo produces grade-3 labels today.
- **Engine clustering.** The label rules require counting *independent clusters*, not
  engines. The similarity work exists in `polyscore-pipeline` but is orphaned; it needs
  porting or replacing.
- **The label-gap tolerance (`horizon_max_days`) — now known to be load-bearing.**
  Measured on stage 2026-09-29 over a 2024–2026 window: the nearest scan at or after T+30
  had a **median gap of 92 days for contested artifacts and 218 days for consensus-clean
  ones, with a maximum of 518 days.** So "nearest scan after the horizon" is routinely
  *hundreds* of days out, and an unbounded rule would have produced a column mixing T+31
  and T+518 labels. The bound is not theoretical.
  **And the gap correlates with the band** — contested artifacts are rescanned far sooner
  than clean ones, presumably because they are more interesting. That is the correlation
  §4 warns about, observed. Whether it holds at prod volume is the thing to check.
- **The label-gap tolerance (`horizon_max_days`).** T+30 is a target, not a floor, so the
  draw bounds how far past the horizon a label may be taken. The bound is provisionally 90
  days and is meant to be set from the gap distribution stage 02 reports. Two outcomes
  change the plan rather than the parameter: a p90 far beyond the horizon means most labels
  are not T+30 labels, and gaps that are systematically longer for contested artifacts than
  for consensus ones mean the heterogeneity tracks difficulty.
- **The §9 band thresholds, and the answering-engine floor.** `0.2` and `0.8` were chosen
  before anyone looked at how the bands actually populate, and the 45% contested share is
  an assertion about where the hard cases live, not a measurement. The minimum answering
  count below which `m` is treated as noise is **not set at all** — it needs the
  distribution of answer counts, which stage 02 produces. Stage 02 reports the realized shares against the
  targets; revisit **once**, and record the revision in `decisions/` rather than editing
  the numbers in silence.
- **Where the known-good arm is actually sourced.** [`0006`](../decisions/0006-stratified-sampling-with-recorded-inclusion-probabilities.md)
  fixes the containment rules and the value ordering — hard negatives over signed
  commodity binaries — but names no owner and no corpus. R9 is the ask; this is the plan
  that has to sit behind it.

## Blocking the composite

The platform capabilities the composite depends on have moved to
[`07-requests.md`](./07-requests.md) — they are asks on other teams rather than decisions
we owe. Specifically R1 (random detonation arm), R5 (bulk sandbox reports), R7
(certificate reputation) and R8 (engine independence clusters).

What remains ours to decide:

- **Who sets the provisional combiner coefficients**, who reviews them, and what marks a
  score `calibration: provisional` in the API. Decision 0005 fixes the posture but not
  the owner.
- **One combiner or one per coverage tier.** Deliberately left data-driven: fit one, report
  calibration per tier, split if the curves diverge. Somebody has to actually look.

## Verify against prod before stage 01 runs

Cheap `SELECT`s that each decide a filter. None needs a model, a label or a decision —
only access.

- **`SELECT name FROM scan_configs;`** — the four names are a seed, and the table is
  mutable. The feed filter rests on this list being exhaustive.
- **`extended_type` distribution** for `mimetype = 'application/x-dosexec'` — decides
  whether a `LIKE 'PE32%'` pre-filter has acceptable recall, and whether 64-bit `PE32+`
  and `.NET` variants are described as expected. Affects recall only; ES is the real gate.
- **The prod `AKM_API_KEY`** — needed to exclude internal re-submissions by `api_key`.
  Without it, some `ai instance rescan` traffic stays in the cohort.
- **ClickHouse `hash_searches` retention** — no `TTL` in the migration, so the window is
  unknown. Gates F11.
- **Which community polyfeeder submits into** — a per-sink DB config, not a static value.
  If feeds land in a private community the `_public` filter already excludes them and the
  `scan_config` filter is belt-and-braces; if not, both are load-bearing.
- ~~**`any_detections`**~~ — **settled 2026-09-29 on stage.** The column is `NOT NULL
  DEFAULT false`, so it is non-null on every row *by default* and never set true (519/519
  non-null, 0 true). Both code reads were partly right: it is defaulted, not assigned. It
  carries no information — use the `detections` JSONB.

## Surfaced by the Datadog counter, 2026-10-05

- **Who is `plan:other`?** It is ~90% of all rescans (in ~500/day batches) and ~97% of
  customer `default` submissions, including a **180,281-row spike on Oct 4**. `other` means
  "not in `metrics._KNOWN_PLANS`" — a legacy or custom plan, an internal account that does
  not use the AKM key, or an integration. Until it is identified, the §1 "customer"
  population and the natural-rescan training arm are both mostly *this one account*, and
  the reference population's meaning depends on what it is. AKM / billing can answer from
  the account number; the counter cannot.
  **Start with the two names the code already knows about.** The comment on
  `_KNOWN_PLANS` in `artifact-index/src/artifact_index/metrics.py` says real AKM responses
  carry plan names absent from `settings.AccountPlans` — it names **`'Polyswarm Internal'`**
  and **`'Free Trial'`** — and those are exactly what collapse to `other`. A ~500/day batch
  rescanner and a 180k single-day dump both read as *internal tooling on a non-AKM-key
  account* far more than as a trial user. If that is what it is, the §1 "customer"
  population is largely us, and `actor_tag` needs a second internal marker beyond the one
  API key.
- **The Oct 4 spike.** 180k `default` submissions in one day against a ~3k baseline. Bulk
  upload or a job. If it recurs, the §1 window's composition is dominated by such events
  and §9's draw should stratify on submission-day volume as well.
- **Why zero `actor:internal`.** No `ai instance rescan` or `process-backlog.py` traffic in
  six days is plausible, but worth confirming the AKM key comparison in `actor_tag` is
  actually matching in prod — if it is not, internal rescans are being counted as `user`
  and the "organic" numbers above are inflated.

## Blocking a real model

- **Inter-analyst agreement in the 0.3–0.7 band.** Never measured. It is the ceiling on
  calibration in the only region where a calibrated probability beats what exists today.
  A 200-file dual-adjudication pilot answers it cheaply and should precede any headcount
  request.
- **Randomised audit arm.** Calibration requires a probability sample of the deployment
  population with inclusion probabilities recorded *at draw time*. An unrecorded
  sampling probability cannot be reconstructed later. Estimand §9 now fixes this for the
  *training* draw; the audit arm is the same discipline applied to the **deployment**
  population, and it still has no owner.
- **The clock question — answered on stage, still open on prod.** Measured 2026-09-29
  against `us-stage-blue`: session `TimeZone = UTC`, median `completed - created` =
  **31.7s**, min **30.1s**, and **zero rows with `completed < created`**. So `created`
  (Postgres `now()`) and `completed` (Python UTC) are on the same clock there, and the lag
  matches `bounty_duration`. **Re-run on prod** — it is a server setting, not a code fact.
- **`delete_at` is written by nothing in `artifact-index`**, so whether another service or
  a retention job physically removes `artifactinstance` rows is unknown — confirm before
  relying on "history is never destroyed." Estimand B depends on the answer.
- **Reference-population remeasurement.** The 37%-indexed figure predates the
  September 2026 fixes; a fresh measurement changes the estimand's §1 caveat.

## Deferred by decision

- **Real-time scoring moment** (submission + 15 min) — a different and harder problem.
- **Per-file-type subscore models** — share the ranker, split the calibrator; needs a
  typing-stability measurement first.
- **"System One" classifiers** for classification-string features — belongs after a
  valid score exists, not before.
