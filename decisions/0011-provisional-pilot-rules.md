# 0011 — Provisional rules that let the pilot run end to end

- **Status:** Proposed
- **Date:** 2026-10-05
- **Affects:** `src/polyscore_v2/labels.py`, `features.py`, `calibration.py`, `config.py`; `pipeline/03_label.py` … `09_evaluate.py`; `specs/04-pipeline.md`

## Context

Stages 03–09 were stubs. Writing them against the specs exposed five places where the
spec names an input that does not exist yet, and a pipeline that stops at each one never
reaches the number that tells us whether the labels are usable at all (baseline 3, §8).
Each stand-in below is the smallest thing that lets the next stage run, is named in the
output it affects, and is pinned by a test so that replacing it is an edit, not a drift.

**None of these is a claim about the right rule.** Accepting this record means "run the
pilot with these and read the composition and baseline reports"; the reports are what
the real rules get chosen against.

## Decision

1. **Label rule (03).** `label_at_horizon` applies `specs/03-labels.md` with:
   - **engines for clusters** — no vendor-cluster map exists, so the "three independent
     clusters" bar (`settings.min_independent_clusters = 3`) counts engines;
   - **`family_class` for specificity** — a family string with a word token that is not
     a category word is `specific` (weight 1.0); generic or absent is 0.5
     (`settings.heuristic_family_discount`); `pup` and `dual_use` token sets route to
     UNWANTED with that reason. Two specific names or six generic detections clear the
     bar; three generic ones do not;
   - **no stability check** — two scans cannot show oscillation; the row carries its
     change decomposition instead;
   - **a floor** of `LABEL_MIN_DEFINITE = 5` definite verdicts, below which the row is
     `undecidable / below_floor`; zero malicious above it is BENIGN, with `retracted`
     as the reason when an engine withdrew.
2. **Family group for the split (05).** The modal family string at T stands in for a
   TLSH cluster; rows with no family are their own group.
3. **Static PE block (04).** Merged only when a parquet is supplied (`--static-block`,
   with `pe_as_of`); nothing fetches it yet. The engine encodings, aggregates and family
   scalars are the feature set until it exists.
4. **Calibration on grade-1 labels (08).** `assert_calibration_eligible` refuses them;
   `--provisional` fits anyway and the manifest records `calibration: provisional`.
   When the validate fold has no §1 rows (stage today), the pooled fold is used and the
   report says so. The intercept shift `logit(π_p)` is recorded from the validate
   fold's reweighted prevalence, labelled provisional, and not applied — Platt refits
   the intercept regardless; R3 owns the real `π_p`.
5. **Stability stand-in (09).** `--compare-runs` scores other runs' model (b) on this
   run's test fold; the spec's shared forced validation set does not exist yet and the
   report names the substitution.
6. **Run layout.** Every stage writes under `data/runs/<run_id>/` (labels, features,
   splits/, models/, reports/), read through `runs.load_run`, which verifies the cohort
   against its base by content hash. Outputs are written once; `--overwrite` is the
   deliberate exception.

## Consequences

- The pipeline runs on the rehearsal draw and will run on the stage base; what it
  prints is what the real rules get chosen against.
- The `undecidable` rate partly measures these stand-ins (the generic discount and the
  floor move it), which `specs/03-labels.md` already warns about; quote it as a property
  of the rule, not of the corpus.
- Replacing a stand-in: edit the function, update its test, record the change here or in
  a new record, and bump the estimand version only if the label's meaning changed.
