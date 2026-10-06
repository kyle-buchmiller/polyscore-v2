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
| `01_extract.py` (01a) | Postgres | `data/base/<window>.parquet`, `.assertions.parquet`, `.control.parquet` (pending) + manifest | sqlalchemy, psycopg, pandas, pyarrow |
| `01b_draw.py` | base | `data/runs/<run_id>/cohort.parquet` + manifest | pandas, pyarrow |
| `02_compose.py` | base (+ one run's cohort) | `data/reports/composition_<window>[_<run_id>].txt` | pandas |
| `03_label.py` | run cohort + the base's assertions | `data/runs/<run_id>/labels.parquet`, `labels.report.txt` | pandas |
| `04_features.py` | run cohort + assertions (+ optional static block) | `data/runs/<run_id>/features.parquet` (manifest carries the column groups) | pandas, numpy |
| `05_split.py` | features + labels | `data/runs/<run_id>/splits/{train,validate,test}.parquet` (+ `*_random.parquet`), `splits.manifest.json` | pandas |
| `06_baselines.py` | splits (not test) | `data/runs/<run_id>/reports/baselines.txt` (+ `.json`) | scikit-learn |
| `07_train.py` | train + validate (+ random) | `data/runs/<run_id>/models/{a,b,c,b_random}.joblib`, `models.manifest.json` | scikit-learn, lightgbm |
| `08_calibrate.py` | validate + models | `data/runs/<run_id>/models/calibrator_<key>.joblib`, `combiner.json`, `calibration.manifest.json` | scikit-learn |
| `09_evaluate.py` | models + calibrators + combiner + **test** | `data/runs/<run_id>/reports/evaluation.txt` (+ `.json`), `reliability.png`, `test_access.log` | scikit-learn, matplotlib |

Every stage from 03 on reads through `runs.load_run`, which verifies the run's cohort
against its base by content hash, and writes once (`--overwrite` is the deliberate
exception). Where a stage needs an input that does not exist yet, it uses the stand-in
named in [`decisions/0011`](../decisions/0011-provisional-pilot-rules.md) and says so in
its output.

## Stage contracts

**01 · extract — two tiers** ([`0010`](../decisions/0010-natural-rescans-for-training-forced-for-validation.md)).

*01a · base pull.* Every eligible PE artifact in the date window — estimand **§10**'s
population, feeds included — **that already has a natural later scan** inside
`[horizon_days, horizon_max_days]`, with both scans' assertions. **No sampling**:
`π_base = 1`. This is the reproducibility unit; it runs rarely. `engine_metadata` is
**projected** to `malware_family` plus a fixed short list, never pulled whole — at 1M
artifacts the full JSONB is tens of gigabytes.

**It is chunked, because the one-statement form does not scale** (measured on stage
2026-10-05: a 30-minute statement timeout, then a 78-minute port-forward, on 1.2M
artifacts). Three kinds of small statement, each resumable from `data/base/.cache/`:
the **frame** (`02a_frame_chunk.sql`, one statement per week of `created`, which is
indexed where `completed` is not; an anti-join finds the first-ever reveal), the
**labels** (`02b_label_chunk.sql`, one statement per 5,000 frame rows carried in as
`unnest()` arrays: the nearest later scan in bound and the verdict counts at T), and the
**assertions** (`03_assertions_pull.sql`, as before). The PE gate is applied to the frame
before the label chunks. The manifest's `query_sha256` covers the three files and the
variables, and `01b_draw` refuses a base that was pulled by different ones.

*The survey is a mode of the same script.* `--sample-pct 10 --survey` walks the frame and
label chunks over a deterministic 10% of artifacts (`hashtext(sha256)`), prints the band
histogram, gaps, coverage and the §1 share, writes the sampled frame, and stops before any
assertion is pulled. `01_survey.sql` is retired in its favour: shares and percentiles are
as good from a sample, and one extraction code path cannot disagree with itself.

*01a also sets aside the control sample.* A seeded `POLYSCORE_CONTROL_SIZE` (default 10k)
of frame artifacts that have **no** natural later scan in bound, with the T scan's
assertions only and no label, written beside the base as `<window>.control.parquet` with
its own manifest (`control_pi` = the fraction of unlabellable rows it took). It exists for
stage 06's rescan probe and the optional propensity weight (estimand §4) and never enters
a run draw.

*01b · run draw.* From the base Parquet, **locally**, draw `cohort_size` artifacts
stratified per §9 with `random_seed`, recording `π_draw` per row. Never touches the
database. Writes under `data/runs/<run_id>/`. This is what makes scaling a variable
change, retraining quick, and concurrent runs free — and it is the only form under which
"same base, same seed, same cohort" is a true sentence. Before drawing it **verifies the
base against the query on disk**: the manifest's `query_sha256` is the hash of
the three extraction SQL files plus the base's recorded variables, so a base pulled by
older ones is refused with the reason unless `POLYSCORE_ALLOW_STALE_BASE=1`. The stage
rehearsal base predated decision 0010 and drew without complaint, which is why.

*01c · validation tranche.* Separately and once: draw `validation_size` artifacts **blind
to rescan history**, enqueue daily forced tranches, harvest after the horizon. The gap is
≈30 by construction and the selection is ours. This set is never trained on.

Everything below about the query applies to 01a. **Not §1**: §1 is the reference frame the calibrator is
fitted on in stage 08, and drawing training data from it forfeits the contested band.
Every row carries its `provenance`, which is what lets stage 08 select the §1 subset back
out. **Draw stratified per estimand
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

**Report the change decomposition**, via `labels.decompose_change`: flips, retractions,
joined, left, and the turnover rate. The churn rate (§4) and the retraction signal are
both computed over **engines present at both moments only** — an engine that merely showed
up late is not a revised opinion, and counting it as one would overstate both. Report
turnover beside them, never folded in.

**Emit each rate-only label three ways** — raw over the drawn cohort, reweighted by
`1/π_i`, and split per §9 stratum. They answer different questions and the first two
genuinely differ: the contested band is over-weighted by design and `undecidable`
concentrates there, so the raw rate **overstates** the population rate. Quote the
reweighted one as a ceiling; quote the raw one when correcting the cohort's effective
size. The per-stratum split is the cheap check that labelling tracks difficulty at all —
`undecidable` spread evenly across bands means the rule is wrong.

**04 · features.** Build the ~120 numeric columns from [`02-data.md`](./02-data.md).
The engine-verdict columns pivot from the base's assertions Parquet. The PE static block
comes **from OpenSearch in bulk** for artifacts in the post-September index — it is
time-invariant and fully indexed there, which removes the per-artifact psstorage fetch
for A entirely — and from psstorage only for pre-September artifacts (Estimand B).
**The as-of rule is enforced here**, mechanically — every field carries a timestamp and
the builder refuses anything stamped later than the scoring moment.

**05 · split.** Sort by time, cut at the estimand's percentages, enforce the horizon
gap, and ensure no family cluster straddles a boundary. Also write the random-split
variant, clearly named as the optimistic one.

> **The forced validation tranche is not a split of the training draw.** It is drawn
> separately, blind to rescan history, and labelled by forced rescan — so it is the one
> set whose selection and gap are ours. The train/validate/test split here is *within*
> the natural-rescan draw; the forced set sits outside it and is what §8's decision and
> §11's stability measurement are judged on.

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
to predict `provenance` from the *feature set*. It runs **twice**, and both are blocking
above **~0.6 AUC**:

| Probe | What a failure means |
|---|---|
| injected known-good vs organic | the negative class is poisoned — the model can identify the upload batch rather than the file |
| **feed vs customer** | §10's breadth is unsafe — provenance is a near-perfect proxy for the label once feeds are in, so the model would learn the ingestion path |

A failure is fixed in the **feature set**, never by raising the threshold. If it cannot be
fixed, the fallback is narrowing the training frame back toward §1 and accepting a thinner
contested band — a real cost, and the reason the probe exists rather than a blanket ban.

**Plus the rescan probe**, which is a report rather than a gate: a classifier predicting
*was-rescanned* from the feature set, the cohort against the control sample stage 01a sets
aside (estimand §4). It answers how far the natural-rescan selection is visible in the
features — near 0.5, the labellable subset looks random; high, covariate shift, which
conditioning handles — and reports per-band coverage so a thin region is known before
training. Its propensity is written to `data/reports/rescan_propensity.parquet` as an
optional inverse-probability weight for stages 07–08; nothing consumes it by default. It
cannot detect selection on outcome given features; the validation set in stage 09 is the
only check for that.

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

**08 · calibrate.** Fit two artefacts on **held-out** data — and on the **§1 subset of
it**, reweighted by `1/π_i`, never the full training frame. Stage 01 drew broadly per §10;
this is the stage that narrows back, and it is the line that keeps feeds out of the base
rate. Filter on `provenance` before fitting anything here. The *calibrator* (base score →
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

Every stage is a `make` target (`make help` lists them with the run's settings). The
extraction targets — `pe-gate`, `survey`, `base` — need the Postgres tunnel and
`kubectl`; the run targets — `draw`, `compose`, `label`, `features`, `split`,
`baselines`, `train`, `calibrate` — read only local files, and `make all` runs them in
order from an existing base. `make rehearsal` is the stage run of 2026-10-05 start to
finish. Both deliberately stop before stage 09: `make evaluate` is invoked by hand, once,
after the model, calibrator and combiner are all frozen — see
[`05-evaluation.md`](./05-evaluation.md). The run is named by `POLYSCORE_RUN_ID`,
`POLYSCORE_COHORT_SIZE`, `POLYSCORE_RANDOM_SEED` and `POLYSCORE_BASE_SNAPSHOT`;
`BASELINES_FLAGS`, `CALIBRATE_FLAGS` and `OVERWRITE` carry the flags the stages explain.
Measured 2026-10-06: a second run id from the same base reproduces the first byte for
byte, which is the §11 determinism check through the other front door. The README's
*Running the pipeline* has the variable table.
