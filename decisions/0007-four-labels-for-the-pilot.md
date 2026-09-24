# 0007 — Four labels for the pilot

- **Status:** Accepted
- **Date:** 2026-09-24
- **Affects:** `specs/01-estimand.md` (§3), `specs/03-labels.md`, `specs/04-pipeline.md` (stages 01, 03), `src/polyscore_v2/labels.py`

## Context

Estimand §3 named **four** labels — `malicious`, `benign`, `unwanted`, `undecidable` —
and pointed at `03-labels.md` for the full taxonomy. That file had **seven**:
`known_good`, `benign`, `unwanted`, `dual_use`, `malicious`, `undecidable`, `excluded`,
and trained on `malicious` vs `benign ∪ known_good`.

So the frozen decision and the spec it delegated to disagreed about both the number of
classes and the composition of the negative class. `labels.py` implemented the seven.
Nobody had noticed, because nothing has run yet.

The finer taxonomy is not wrong about the world. A disclosed miner really is a different
thing from a covert one, and PsExec really is neither malicious nor a safe negative. The
question is whether a 10,000-file pilot can populate seven classes well enough for any of
them to mean anything — and at realistic prevalence it cannot: the finer classes come out
holding tens of files each. Too few to train on, too few to compute a stable rate from,
and numerous enough to make every reported count look more precise than it is.

## Decision

**Four labels for the pilot**, reconciling §3 and `03-labels.md` in favour of the fewer.
Each of the three removed labels moves somewhere that already expressed the distinction
better, so the fold loses no information and stays reversible.

| Was | Now | Where the distinction went |
|---|---|---|
| `known_good` | `benign` | **The grade.** Attested negatives are grade 2, adjudicated-benign grade 3, engine-derived grade 1. The grade already encoded evidence strength; a second label duplicated it. |
| `dual_use` | `unwanted` | **A reason field.** Both were excluded from training and reported as a rate, so behaviour is unchanged; the reason keeps the rate decomposable. |
| `excluded` | *(not a label)* | **The stage-01 cohort filter.** EICAR and non-scannable artifacts were never candidates. Dropped at extraction with the count reported. |

Re-expanding is a **new estimand version, not a code change**. `PILOT_COLLAPSE` in
`labels.py` keeps the map so that is deliberate rather than archaeological.

This also settles the rate denominators, which §9 had quietly broken — see Consequences.

## Alternatives considered

| Option | Why not |
|---|---|
| Keep the seven and fix §3 upward | Honest about the world and unusable on 10k files: the finer classes hold tens of rows each. A rate computed on 30 files has a confidence interval wide enough to contain any conclusion, and a class that small cannot be trained on either. Defer it to a cohort that can carry it. |
| Keep `known_good` as a separate label | Duplicates the grade, which already distinguishes attested from adjudicated from engine-derived — and duplicated state drifts. Folding it also forces the §9 injection arm's evidence quality to be expressed as a grade, which is where a consumer will look for it. |
| Keep `dual_use` separate | It is excluded from training either way, so it buys nothing operationally and costs a class the cohort cannot fill. The reason field retains everything the label carried. |
| Collapse further, to a strict binary | Would require folding `unwanted` and `undecidable` into one of the two classes — and the whole point of reporting them as rates is that **the size of that decision is unknown until measured**. At 1% of traffic the fold is a footnote; at 25% it is the dominant fact about what the score means. Deciding it before measuring is how the 2023 model acquired its 2:1 benign majority. |

## Consequences

- **The negative class narrows.** Training on `benign` alone rather than
  `benign ∪ known_good` means attested known-good rows now enter as `benign` with grade 2.
  Same rows, same training behaviour; the evidence strength is read from the grade
  instead of the label.
- **`assert_pilot_labels` is a new failure mode**, and an intended one. A pre-collapse
  label reaching a split would silently join a class it was never meant to be in — the
  quietest possible corruption of a training set.
- **Rate reporting is now specified, in three numbers.** §9's stratified draw means there
  was no single honest denominator. Raw (over the drawn cohort) sizes the *training data*
  lost; reweighted by `1/π_i` gives the *population* rate and is the only one that is a
  ceiling; per-stratum is a cheap check that labelling tracks difficulty. Raw and
  reweighted differ predictably — the contested band is over-weighted 45% by design and
  `undecidable` concentrates there — so **the raw rate overstates the population rate**
  and must never be quoted as a production ceiling.
- **`excluded` leaving the taxonomy creates a reporting obligation** at stage 01. An
  unreported filter is silent shrinkage, the same defect as an unreported `undecidable`
  rate two stages later.
- **The `undecidable` rate remains partly our own artifact.** The stability rule *forces*
  it when a detection count oscillates, so tightening that threshold moves the rate. It
  measures the label process as much as the corpus — worth knowing before anyone quotes
  it as an intrinsic property of the data.
- **Estimand bumps to version 3.** Still no results produced under any version.
