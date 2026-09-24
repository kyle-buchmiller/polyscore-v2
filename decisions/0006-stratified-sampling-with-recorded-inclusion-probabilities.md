# 0006 — Stratified sampling with recorded inclusion probabilities

- **Status:** Accepted
- **Date:** 2026-09-24
- **Affects:** `specs/01-estimand.md` (§1 counting rule, new §9), `specs/04-pipeline.md` (stages 01, 02, 05, 06, 07), `specs/02-data.md`, `specs/03-labels.md`

## Context

The estimand named a population but never said how a cohort would be **drawn** from it,
which left the most consequential sampling choices to whoever wrote `01_extract.py`.

Both available defaults are bad. A flat draw at realistic prevalence yields too few
positives to fit anything and gives no control over how many hard cases are present. Any
non-flat draw changes the base rate the model sees — and an uncorrected base rate is
precisely what produced the two documented failures behind this rebuild: the whitepaper's
97% reconstructs to an exact 2:1 benign majority, and the 29:1 imbalance broke the 2023
model.

Two concrete proposals were on the table. Fix the ratios by **label confidence** — a share
of definitely-bad, a share of definitely-good known-good binaries, the rest unknown or
PUP. And use **third-party aggregator verdicts** to make bucket assignment cheap, since
determining a label is the expensive part.

## Decision

Draw **stratified on engine agreement at the scoring moment**, deliberately
over-weighting the contested band, and **record every artifact's inclusion probability
`π_i` at draw time** so the draw stays reversible. Inject a small externally-sourced
known-good arm under three containment rules, and exclude it from every prevalence
estimate.

Shares, rules and containment are in estimand §9.

## Alternatives considered

| Option | Why not |
|---|---|
| Flat random draw | Too few positives at realistic prevalence, and no control over the hard cases. Random sampling removes selection bias *within* a frame and does nothing about *which* frame — a perfectly random sample of the wrong population is precision about the wrong quantity. |
| Strata by label confidence (definitely-bad / definitely-good / unknown) | Label confidence here **is** engine agreement, which **is** the feature vector. Selecting the confident ends deletes the contested middle — the only region where a hash lookup has not already answered the question. `P(Y|X)` survives such a draw, but there is no data where the model is deployed and no way to verify calibration there. It is the 2023 frame's failure on a different axis. |
| `class_weight`, or synthetic oversampling (SMOTE) | Both reach balance **irreversibly**. Recorded `π_i` yields both views from one draw. SMOTE additionally interpolates between sparse binary engine responses, inventing combinations that have never occurred. Already forbidden in stage 07; now forbidden for a stated reason rather than by assertion. |
| Per-scoring-event weighting of the reference population | Makes the base rate track **usage mix**, not the file population: a threat hunter bulk-checking corporate software and a blue-team analyst working an incident pull it in opposite directions, and nothing distinguishes them. Also the wrong denominator for 0001, whose sentence is about *files*. |
| Third-party aggregator verdicts as labels (VirusTotal and equivalents) | **Roster overlap.** The same vendors supply our features and their consensus, so the label is partly a copy of the input; §8's `>0.97` stop rule would fire, correctly. It caps at **grade 1** by construction — aggregated engine opinion is what grades 0–1 *are* — so it cannot produce the grade-3 labels that are the actual bottleneck, while the grade-1 path (time-separated rescan, 0004) already exists and is free. Separately: such terms have historically prohibited use in building a competing product, and our engine partners are largely the same vendors, so the exposure is commercial as well as contractual. Not a pipeline detail; if ever revisited, it is a decision made with legal present. |

## Consequences

- **One draw serves both views.** Raw stratified folds are the balanced view; `1/π_i`
  weights recover natural prevalence. Training gets its balance, calibration gets its
  denominator, and nothing is manufactured twice.
- **`π_i` is unrecoverable if skipped.** Stage 01 refuses to write a snapshot without it.
  This is the only decision in this record that cannot be repaired later.
- **Balance is now paid back explicitly.** Logistic regression takes an exact intercept
  shift of `logit(π_p)`; trees have no closed form and must be recalibrated empirically.
  Both need `π_p`, which a composed training set cannot measure — so this **raises R3's
  priority** rather than substituting for it.
- **A new way for a run to fail.** The provenance probe can reject a draw outright. That
  is intended: a poisoned negative class is worth catching before it flatters us, and the
  cost is one extra model fit.
- **The injection arm needs an acquisition effort** that does not exist yet (R9), ordered
  hardest-negative-first — internal build artifacts and vendor retractions above signed
  commodity binaries.
- **The band thresholds (0.2 / 0.8) are arbitrary** and were chosen before anyone looked
  at how the bands populate. Stage 02 reports the realized shares; revisit them once, and
  record the revision rather than editing them in silence.
- **Estimand bumps to version 2.** No results existed under version 1, so nothing is
  invalidated — this is the cheapest moment the change could have been made.
- **It does not solve calibration.** Grade 3 still requires adjudication. Sampling design
  decides what the model learns from, never what the number is allowed to claim.
