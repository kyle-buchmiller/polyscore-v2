# 04 — Pipeline

## Scope

The eight stages, what each reads and writes, and the contract between them.

## Invariants

- Each stage does one job, reads the previous stage's output, and writes its own.
- A stage can be re-run without redoing the ones before it.
- Only stage 08 reads the test split.

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
| `08_evaluate.py` | models + **test** | `data/reports/evaluation.txt`, `reliability.png` | scikit-learn, matplotlib |

## Stage contracts

**01 · extract.** Query Postgres for PE instances matching estimand §1, inside the date
window, with a deterministic `ORDER BY` before any limit. Write one parquet plus a
manifest recording the query, the window, the row count and a content hash. *The
snapshot, not the query, is the unit of reproducibility* — re-running a query against a
live database tomorrow returns different rows and silently invalidates everything
downstream.

**02 · compose.** Every count in the composition table, to stdout and to a file. No
modelling. **Read it before continuing:** if distinct family clusters come back at 200,
the real sample size is 200 and treating 10,000 as meaningful is a mistake that will
propagate into every confidence interval.

**03 · label.** Apply the [`03-labels.md`](./03-labels.md) rules at T+30. Write a label
per file with its grade, source and horizon. Keep `undecidable` rows in the file but
flagged, so they can be excluded from training and still counted in the report.

**04 · features.** Build the ~120 numeric columns from [`02-data.md`](./02-data.md).
**The as-of rule is enforced here**, mechanically — every field carries a timestamp and
the builder refuses anything stamped later than the scoring moment.

**05 · split.** Sort by time, cut at the estimand's percentages, enforce the horizon
gap, and ensure no family cluster straddles a boundary. Also write the random-split
variant, clearly named as the optimistic one.

**06 · baselines.** The four baselines from estimand §7, before any model exists. **The
most informative half hour in the project**: baseline 3 tells you immediately whether
the labels are a tautology, and it costs no model at all.

**07 · train.** Exactly three comparisons — (a) logistic regression on the *old*
one-column encoding, (b) the same model on the *new* two-column encoding, (c)
gradient-boosted trees on the new encoding. Tune on validate only, against log loss or
Brier — never a threshold metric like F1.

> Prediction worth recording before the run: (b) will land close to (c), and the gap
> between (a) and (b) — an *encoding* change, not a model change — will dwarf both. If
> so, the pilot has taught the most useful lesson available: representation beats
> algorithm.

Drop `class_weight` entirely rather than replacing it. **No synthetic oversampling**
(SMOTE and relatives): interpolating between sparse binary engine responses invents
combinations that have never occurred and destroys calibration.

**08 · evaluate.** Load frozen models, score the test split, print the primary metric
beside all four baselines, fit a calibrator on held-out data and draw the reliability
diagram with bootstrap confidence bands. Platt or beta calibration — **not isotonic** at
pilot volumes, where it will fit the calibration set exactly and look wonderful for the
wrong reason. The width of the confidence bands is the finding.

## Running

`make all` runs 01–07 and deliberately stops. Stage 08 is invoked by hand, once, after
the model is frozen — see [`05-evaluation.md`](./05-evaluation.md).
