# 99 — Open questions

Known follow-ups. Move an item into a spec once it is decided, and record the decision
in `decisions/`.

## Blocking the pilot

- **Cohort volume.** Does the estimand §1 population (customer-submitted PE, feeds
  excluded, post-2026-09-08) actually yield 10,000 files in a sensible window? If not,
  which compromise — widen the window, or admit feed rows and record the skew?
- **Gold slice ownership.** Who adjudicates the 200 files, against what written rubric,
  and where do the labels live? Nothing in this repo produces grade-3 labels today.
- **Engine clustering.** The label rules require counting *independent clusters*, not
  engines. The similarity work exists in `polyscore-pipeline` but is orphaned; it needs
  porting or replacing.

## Blocking a real model

- **Inter-analyst agreement in the 0.3–0.7 band.** Never measured. It is the ceiling on
  calibration in the only region where a calibrated probability beats what exists today.
  A 200-file dual-adjudication pilot answers it cheaply and should precede any headcount
  request.
- **Randomised audit arm.** Calibration requires a probability sample of the deployment
  population with inclusion probabilities recorded *at draw time*. An unrecorded
  sampling probability cannot be reconstructed later.
- **Reference-population remeasurement.** The 37%-indexed figure predates the
  September 2026 fixes; a fresh measurement changes the estimand's §1 caveat.

## Deferred by decision

- **Real-time scoring moment** (submission + 15 min) — a different and harder problem.
- **Per-file-type subscore models** — share the ranker, split the calibrator; needs a
  typing-stability measurement first.
- **"System One" classifiers** for classification-string features — belongs after a
  valid score exists, not before.
