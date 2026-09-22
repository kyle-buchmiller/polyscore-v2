# 01 — The estimand

## Scope

The eight decisions that define what the number means. **Frozen.** Changing any of
them invalidates every result produced under the old version; bump the version at the
bottom and record the change in `decisions/`.

## Invariants

- Written **before** any code, and not revised to suit a result.
- Every metric, gate and support answer elsewhere in this repo is defined relative to this file.
- A result quoted without naming the estimand version it was produced under is not a result.

---

## 1 · Reference population

**Which files is this number a probability about?**

Windows PE files submitted to the **public community by customers — not by bulk feeds
— in a fixed, closed date window.** Feed rows carry `scan_config = 'feed'` and are
excluded.

*Why.* A probability is always a probability for a group; change the group and the same
model is wrong, structurally rather than approximately. The score's job is to answer
"should I care about this file somebody handed us." Bulk malware feeds are a different
question and they dominate volume, so leaving them in makes the base rate mostly a
measure of how many feeds are switched on — the 29:1 imbalance that broke the 2023
model.

*If volume falls short*, widen it — and record here that you did, and that the base rate
is inflated as a result.

> **Date caveat.** Until early September 2026 an artifact only reached the metadata
> index if something *came back* about it. A cohort drawn from the historical index
> over-represents successfully-analysed files, which is the opposite of what the
> negative class needs. Prefer a window after **2026-09-08**, or state the skew here.

## 2 · Scoring moment

**At what instant is the evidence frozen?**

**Bounty reveal** — the instant the assertion window closes.

*Why.* It is the moment production already computes PolyScore, so results are directly
comparable to the incumbent, and engine evidence is naturally complete. A real-time
variant (submission + 15 min) is a genuinely different and harder prediction problem;
it is deferred, not dismissed.

## 3 · Label definition

**What does "malicious" mean?**

An artifact is **malicious** if, run as intended in a typical environment, it does
things a fully-informed owner of that machine would not agree to, for someone else's
benefit — assessed as of a stated date.

Four labels, not two: `malicious`, `benign`, `unwanted`, `undecidable`. Train on the
first two; report the other two as rates. Full taxonomy in
[`03-labels.md`](./03-labels.md).

## 4 · Horizon

**Malicious as of when?**

**T+30 days** from first sighting, with a **T+180** re-check on a subsample.

*Why.* Thirty days captures most detection accrual while still fitting inside a pilot.
The 180-day re-check yields the **churn rate** — the fraction of files called benign at
30 days that turn malicious later — which is a hard floor on the lowest score that can
honestly be emitted, and settles whether a true zero is reachable at all.

*Practical note.* A T+30 label only exists for files actually rescanned around then,
and rescans are user-driven and therefore non-random. Freeze the cohort, bulk-enqueue
its rescans (`ai instance rescan <start> <end>`), and harvest labels after the horizon.

## 5 · Split policy

**How is the data divided so the test is honest?**

Forward in time **and** grouped by family. Earliest ~60% train, next ~15% validate,
last ~25% test, with a gap of at least the label horizon between the end of training
and the start of testing. Grouping key: TLSH cluster, falling back to `imphash`.

The naive random split is **also computed and reported, clearly labelled optimistic**.
The gap between the two is a deliverable: it is the honest measure of how much apparent
performance was memorisation.

## 6 · Primary metric

**Which single number decides whether this worked?**

**ROC-AUC**, always quoted next to the baselines in §7.

Brier score and a reliability diagram are produced as well, but for the pilot they are
a **process demonstration, not a result** — with derived labels, a calibration number
measures agreement with our own label rule, not calibration.

**Accuracy is never the headline.** The 2023 model reported 0.9628; answering
"malicious" every time scored 0.9666 on the same data.

## 7 · Baselines

**What must the number beat to mean anything?**

Printed first, always, so the model's number never appears alone.

| # | Baseline | What it tells you |
|---|---|---|
| 1 | Constant (always the majority class) | the absolute floor |
| 2 | Prevalence-random | confirms the plumbing is not inverted |
| 3 | **Count of engines asserting malicious at T** | **the one that matters** — the dumbest thing that could work |
| 4 | The incumbent PolyScore (stored per scan) | what we are replacing |

## 8 · Decision rule

**What result makes us proceed, and what makes us stop?**

- **Proceed** if baseline 3 lands in **0.85–0.95 AUC** — high enough that the labels
  carry signal, low enough that they are not merely restating the features — **and**
  the trained model beats it by more than the seed-reshuffle noise band.
- **Stop and fix the labels** if baseline 3 exceeds **~0.97**. The answer column is a
  near-copy of the input column and nothing downstream can measure anything.
- **Stop and check the plumbing** if baseline 3 is near **0.5**. Something is
  disconnected.

A model that merely *ties* baseline 3 is a real and useful result: it says the rebuild's
value lives in calibration and abstention rather than in ranking.

---

**Estimand version:** `1` · frozen 2026-09-22 · unsigned

Record the signatory here when agreed. Any change to §1–§8 requires a version bump and
a record in `decisions/`.
