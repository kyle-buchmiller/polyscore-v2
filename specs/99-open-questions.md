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
- **Reference-population remeasurement.** The 37%-indexed figure predates the
  September 2026 fixes; a fresh measurement changes the estimand's §1 caveat.

## Deferred by decision

- **Real-time scoring moment** (submission + 15 min) — a different and harder problem.
- **Per-file-type subscore models** — share the ranker, split the calibrator; needs a
  typing-stability measurement first.
- **"System One" classifiers** for classification-string features — belongs after a
  valid score exists, not before.
