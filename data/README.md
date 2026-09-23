# data/

Everything in here is **gitignored and reproducible**. Nothing in this directory
is a source of truth.

```
data/
  snapshots/     01_extract output — one parquet per run, plus a manifest
  labels/        03_label output
  features/      04_features output
  splits/        05_split output — train / validate / test, and the optimistic variant
  models/        07_train output — fitted models, one per comparison
  reports/       06 and 08 output — baseline tables, metrics, the reliability diagram
```

## The manifest is the unit of reproducibility, not the query

A snapshot is written once and never mutated. Alongside it, `01_extract.py`
writes a manifest recording the query, the date window, the row count and a
content hash.

Re-running the same query against a live database tomorrow returns different
rows and silently invalidates every downstream stage. So downstream stages read
the **snapshot**, and the manifest is what lets you say which snapshot a result
came from.

## The test split is handled differently on purpose

`05_split.py` writes the test split here like any other file, but nothing in
`pipeline/` loads it except `09_evaluate.py`. That separation is the mechanism
behind the look-once rule in `specs/05-evaluation.md`; treat any code that reads
it elsewhere as a bug.
