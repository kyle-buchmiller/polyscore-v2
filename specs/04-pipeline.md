# 04 — Pipeline

## Scope

The nine stages, what each reads and writes, and the contract between them.

## Invariants

- Each stage does one job, reads the previous stage's output, and writes its own.
- A stage can be re-run without redoing the ones before it.
- Only stage 09 reads the test split.
- Stage 08 **fits**; stage 09 **measures**. Nothing fits and measures.

## Rendered as a diagram

[**Build and Serve**](https://claude.ai/artifact/EHDK37N6ZgJ8EjpHaa5wKZ) draws these stages top to bottom — each row showing the
process, the library that performs it, and the file it writes — alongside a *slot table*
naming what technology currently fills each replaceable component. Use it to place a new
tool against the incumbent.

That page is a **rendering of this spec, not a second source of truth.** If they disagree,
this file wins and the diagram is stale. Link is internal and privately shared.

## Shape

Stages are **numbered scripts under `pipeline/`, not a package**, because they are run
in order by a human watching the output. Shared logic lives in `src/polyscore_v2/` so
the stages stay thin — a stage that grows real logic should push it down and keep only
the orchestration.

Outputs go to `data/` (gitignored). Parquet throughout, never CSV: it keeps column
types and will not silently turn a hash into a number.

| Stage | Reads | Writes | Libraries |
|---|---|---|---|
| `01_extract.py` | Postgres | `data/snapshots/<run>.parquet` + manifest | sqlalchemy, psycopg, pandas, pyarrow |
| `02_compose.py` | snapshot | `data/reports/composition.txt` | pandas |
| `03_label.py` | snapshot | `data/labels/<run>.parquet` | pandas |
| `04_features.py` | snapshot + labels | `data/features/<run>.parquet` | pandas, numpy |
| `05_split.py` | features | `data/splits/{train,validate,test}.parquet` (+ `*_random.parquet`) | pandas, scikit-learn |
| `06_baselines.py` | splits (not test) | `data/reports/baselines.txt` | scikit-learn |
| `07_train.py` | train + validate | `data/models/{a,b,c}.joblib` | scikit-learn, lightgbm |
| `08_calibrate.py` | models + validate | `data/models/{calibrator,combiner}.joblib` | scikit-learn |
| `09_evaluate.py` | models + calibrator + combiner + **test** | `data/reports/evaluation.txt`, `reliability.png` | scikit-learn, matplotlib |

## Stage contracts

**01 · extract.** Query Postgres for PE instances matching estimand §1, inside the date
window, with a deterministic `ORDER BY` before any limit. **Draw stratified per estimand
§9, and write `stratum`, `pi` (the inclusion probability) and `provenance` as columns on
every row.** `pi` is the one value that cannot be reconstructed after the fact — a draw
missing it is not correctable by any later step, so the stage refuses to write a snapshot
without it.

**Non-candidates are dropped here, not labelled.** EICAR, test files, and artifacts the
PE parser rejected were never in the running, so they are filtered at extraction with
**the count reported** — `excluded` is a cohort filter, not a label ([`03-labels.md`](./03-labels.md)).
An unreported filter is silent shrinkage, which is the same failure as an unreported
`undecidable` rate arriving two stages later. Write one parquet plus a
manifest recording the query, the window, the row count and a content hash. *The
snapshot, not the query, is the unit of reproducibility* — re-running a query against a
live database tomorrow returns different rows and silently invalidates everything
downstream.

**02 · compose.** Every count in the composition table, to stdout and to a file, plus
**realized stratum shares against their §9 targets** and the count below the coverage
floor. A band that under-fills is reported as a shortfall; it is never back-filled from a
neighbouring band, which would silently change the draw. No modelling. **Read it before continuing:** if distinct family clusters come back at 200,
the real sample size is 200 and treating 10,000 as meaningful is a mistake that will
propagate into every confidence interval.

**03 · label.** Apply the [`03-labels.md`](./03-labels.md) rules at T+30. Write one of
the **four** pilot labels per file with its grade, reason, source and horizon;
`assert_pilot_labels` refuses anything outside them, so a pre-collapse label cannot reach
a split and silently join a class. Keep `undecidable` and `unwanted` rows in the file but
flagged, so they are excluded from training and still counted in the report.

**Emit each rate-only label three ways** — raw over the drawn cohort, reweighted by
`1/π_i`, and split per §9 stratum. They answer different questions and the first two
genuinely differ: the contested band is over-weighted by design and `undecidable`
concentrates there, so the raw rate **overstates** the population rate. Quote the
reweighted one as a ceiling; quote the raw one when correcting the cohort's effective
size. The per-stratum split is the cheap check that labelling tracks difficulty at all —
`undecidable` spread evenly across bands means the rule is wrong.

**04 · features.** Build the ~120 numeric columns from [`02-data.md`](./02-data.md).
**The as-of rule is enforced here**, mechanically — every field carries a timestamp and
the builder refuses anything stamped later than the scoring moment.

**05 · split.** Sort by time, cut at the estimand's percentages, enforce the horizon
gap, and ensure no family cluster straddles a boundary. Also write the random-split
variant, clearly named as the optimistic one.

> **Split first, rebalance second — and only the training fold.** The validate and test
> folds keep natural prevalence, reconstructed by `1/π_i` weights from §9. Rebalancing
> before the split contaminates calibration and test invisibly: the reliability diagram
> comes out beautiful and means nothing, because it was measured against a prevalence we
> manufactured. The injection arm is training-fold-only for the same reason, and is
> excluded from every prevalence estimate.

**06 · baselines.** The four baselines from estimand §7, before any model exists. **The
most informative half hour in the project**: baseline 3 tells you immediately whether
the labels are a tautology, and it costs no model at all.

**Plus the provenance probe**, which is a gate rather than a report: a classifier trained
to predict `provenance` (injected known-good vs organic) from the *feature set*. Above
**~0.6 AUC** the negative class is poisoned — the model can identify the upload batch
rather than the file — and the draw is rejected and redrawn, not patched. The same probe
run against feed-vs-customer answers whether provenance is separable at all.

**07 · train.** Exactly three comparisons — (a) logistic regression on the *old*
one-column encoding, (b) the same model on the *new* two-column encoding, (c)
gradient-boosted trees on the new encoding. Tune on validate only, against log loss or
Brier — never a threshold metric like F1.

> Prediction worth recording before the run: (b) will land close to (c), and the gap
> between (a) and (b) — an *encoding* change, not a model change — will dwarf both. If
> so, the pilot has taught the most useful lesson available: representation beats
> algorithm.

Drop `class_weight` entirely rather than replacing it, and use **no synthetic
oversampling** (SMOTE and relatives): interpolating between sparse binary engine responses
invents combinations that have never occurred and destroys calibration.

Neither is a ban on class balance — it is a ban on reaching balance *irreversibly*. The
§9 draw already supplies it, and supplies it both ways: the raw stratified fold is the
balanced view, `1/π_i` weights recover the natural-prevalence view, and the two come from
one draw. What balance costs must then be paid back explicitly:

- **Logistic regression.** Sampling on the outcome biases only the intercept — the slopes
  stay consistent — so the correction is exact: add `logit(π_p)`, where `π_p` is the
  reference population's true prevalence. At 2% prevalence that shift is **−3.89**, which
  turns a balanced-model coin flip into 2.0%. Omit it and every number is inflated by
  roughly that much.
- **Gradient-boosted trees.** No such result holds. The sampling ratio changes which
  splits are chosen, so the structure itself differs and no closed form repairs it. Trees
  must be recalibrated empirically against a natural-prevalence held-out fold in stage 08.

Both corrections need `π_p`, and a deliberately composed training set cannot measure it —
that estimate comes from a separately drawn adjudicated sample (R3). Balancing does not
avoid the label problem; it raises R3's priority.

**08 · calibrate.** Fit two artefacts on **held-out** data: the *calibrator* (base score →
probability, Platt or beta — **not isotonic** at pilot volumes, where it fits the
calibration set exactly and looks wonderful for the wrong reason) and the *combiner*
(the small fitted model over base score plus signal indicators, per
[`06-signals.md`](./06-signals.md)). Both are versioned separately from the base model
because they refit on a different cadence.

> **Why this is not part of stage 09.** This stage *fits* — it changes the model. Stage 09
> *measures* under a look-once rule. A stage that does both cannot honour that rule: look
> at the reliability diagram, refit the calibrator, and the test set has been spent
> without anyone noticing. Separating them is what makes the rule enforceable.

Until grade-3 labels exist the combiner cannot be fitted; per decision 0005 its
coefficients are expert-set **in log-odds** and the score carries
`calibration: provisional`.

**09 · evaluate.** Load the frozen models *and* the frozen calibrator and combiner, score
the test split, print the primary metric beside all four baselines, and draw the
reliability diagram with bootstrap confidence bands. **Fits nothing.** The width of the
confidence bands is the finding.

## Running

`make all` runs 01–08 and deliberately stops. Stage 09 is invoked by hand, once, after
the model, calibrator and combiner are all frozen — see [`05-evaluation.md`](./05-evaluation.md).
