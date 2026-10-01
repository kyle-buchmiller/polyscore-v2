# 0010 — Natural rescans for training, forced rescans for validation

- **Status:** Accepted
- **Date:** 2026-10-01
- **Affects:** `specs/01-estimand.md` (§4, §9, new §11), `specs/04-pipeline.md` (stage 01), `specs/05-evaluation.md`, `specs/09-extraction-runbook.md`, `src/polyscore_v2/config.py`

## Context

As frozen, the label was manufactured: freeze a cohort, bulk-rescan it ~30 days after
first sighting, harvest. That buys two things — every label is the same measurement, and
*which* artifacts get labelled is decided by us rather than by whoever found a file
interesting. It costs 30 days per cohort and an operational dependency on prod.

It does **not** buy calibration. Forced or natural, the label is engine consensus at a
later time — grade 1 — and grade 1 may train and may never calibrate. That wall is the
same height either way.

The requirements that broke the design are explicit now:

- scale from 10k to **1M+ training samples by changing an environment variable**
- pull those samples from **prod exactly as it exists today**, without waiting for
  predetermined rescans
- do it **repeatedly, quickly, and concurrently**, so that several models can be built
  from the same runbook and compared

A process that waits 30 days per cohort and requires prod to take a shape we dictate
cannot meet any of those. Meanwhile the stage survey showed prod-as-is has what we need:
~9% of candidates carried a natural later scan ≥30 days out, which against a pool of tens
of millions is far more than 1M.

## Decision

**Training labels come from natural rescans, prod as-is. Forced rescans shrink to a
small validation set.** Four parts:

1. **Training arm.** Draw from artifacts that already have a later scan. The gap is
   recorded per row and bounded above (`horizon_max_days`); within the bound, variance
   is accepted. Selection — the fact that *something* triggered each rescan — is accepted
   and **measured**, never assumed away.
2. **Validation arm.** 1–2k artifacts, forced tranche rescans at ≈T+30, drawn without
   regard to whether anyone rescanned them. Waits 30 days **once**. This is the honest
   check: does a model trained on selected, heterogeneous labels hold on unselected,
   homogeneous ones?
3. **Two-tier extraction.** One **base pull** of everything eligible in a date window —
   no sampling, so its inclusion probability is 1. Then any number of **run draws**,
   stratified per §9, each from the local base snapshot with its own seed and size.
   `π_run = π_base × π_draw = π_draw`. Runs never touch the database, so they are cheap,
   reproducible, and free to run concurrently.
4. **Process stability as a measurement.** The same runbook run with different seeds
   yields different models; their disagreement is the process's noise floor, and §8's
   "seed-reshuffle noise band" becomes an operational number rather than a phrase. The
   same seed twice must yield byte-identical artifacts — the determinism check.

## Alternatives considered

| Option | Why not |
|---|---|
| Keep forcing rescans for everything | Thirty days per cohort, an operational dependency on prod, and it does not scale past what we are willing to enqueue. It was paying a high price for homogeneity on a label that cannot calibrate regardless. |
| Drop forcing entirely | Loses the only unselected, homogeneous check we can afford. Without it, a model that learned the *selection* rather than the file would post a fine number on held-out natural rescans and nobody would know. The validation arm is small precisely because it only has to answer one question. |
| Reweight natural rescans by a modelled rescan propensity | Handles selection on *observables* — band, submitter, lookups — which conditioning on the features already handles. It cannot touch selection on outcome-given-features, which is the dangerous case, and it adds a model to trust. The validation set bounds that case empirically instead. |
| Adopt Estimand B outright | B is the right idea for *aged* artifacts and it needs the era machinery. For recent artifacts with natural rescans, A's horizon with a bounded gap is simpler and comparable to the forced validation set, which B's convergence label is not. |
| Draw each run from the database | Reproducible only if the database is, which it is not — tomorrow's query returns different rows. Also puts N concurrent 1M-row extractions on a shared replica. One base pull, many local draws, is both cheaper and the only form that makes "same runbook, same seed, same model" true. |

## Consequences

- **The training label and the validation label are slightly different measurements**,
  and the record says so. Training is "state at T+[30, bound]"; validation is "state at
  ≈T+30". If the model's performance holds across both, the difference was benign. If it
  does not, that gap is itself the finding — and it was found on 2k artifacts, not in
  production.
- **Selection becomes something we report.** Three measurements on prod decide how much
  it matters: the natural rescan rate, what triggered the rescans (`api_key` and the
  ClickHouse `hash_searches` table make the mechanism visible), and whether the rescanned
  population's band histogram matches the never-rescanned one. The provenance probe gains
  a fourth use: predicting "was naturally rescanned" from T-features. Above chance, the
  selection is observable and conditioning handles it; the validation set catches what
  the probe cannot.
- **`engine_metadata` must be projected, not pulled.** At 1M artifacts × 2 scans × ~15
  engines, 30M assertion rows carrying full JSONB is tens of gigabytes. The snapshot
  carries `malware_family` and a fixed short list of fields, never the whole document.
- **Pandas stops being enough.** 30M rows is arrow/polars territory for the pivot; stage
  04 processes in artifact-keyed chunks rather than loading the matrix whole.
- **The database is the bottleneck, and the two-tier shape keeps runs off it.** A base
  pull at 1M is a heavy query on a shared replica; it runs rarely and is itself the
  reproducibility unit. Everything "repeated, quick, concurrent" happens over Parquet.
- **Run isolation is mandatory.** Every artifact is written under `data/runs/<run_id>/`,
  and the manifest carries base-snapshot hash, seed, cohort size, estimand version and
  the resolved `horizon_max_days`. Two runs that share a base and a seed must produce
  identical files; the manifest is how that is checked.
- **100k grade-1 labels are not ten times better than 10k.** Volume tightens intervals,
  fills the contested band, and makes per-type and per-era splits possible. It does not
  move the calibration wall. Scale is worth having and must not be mistaken for progress
  on the thing that actually limits the model, which is still R3.
- **Estimand bumps to version 5.** §4 changes materially. Still no results produced under
  any version.
