# 11 — Extraction runbook: Estimand B

## Scope

How to run B's extraction. Written as a **delta against
[`09-extraction-runbook.md`](./09-extraction-runbook.md)** (A's runbook) — access paths,
permissions and the snapshot rule are identical and are not restated.

The estimand itself: [`10-estimand-b-settled-state.md`](./10-estimand-b-settled-state.md).

## Invariants

- Same as A's, plus: **B's cohort and A's never merge.** Separate draws, separate
  snapshots, separate models. They meet only in the comparison (§B8).
- **B is Proposed.** Nothing here should run before A's survey has, because A's churn rate
  is what sets B's convergence parameters.

---

## What this pulls, and why it differs from A

Same rows — `artifactinstance`, `assertions`, and later the PE block. Two differences in
*which* rows and *how many* scans:

| | A | B |
|---|---|---|
| Scans per artifact | **2** — T and T+30 | **T plus its whole later history** — convergence must be *demonstrated*, and one scan cannot demonstrate it |
| Era span | one window, weeks | the full history, stratified by era |
| Label comes from | a scan we **cause** | scans that **already happened** |

That last row is the practical headline: **B needs no rescan and no waiting.** A has to
freeze a cohort and bulk-rescan it ~30 days later; B's labels are already in the database.
So despite being the larger estimand, **B is faster to a first result** — which is exactly
why it is worth being careful about the prerequisites below rather than rushing it.

---

## Why B needs its own runbook

Three of A's steps change, and one is new:

1. **A new blocking prerequisite (step B0).** Over a decade, filter columns get *added*.
   A column that postdates a row is NULL on it — so `scan_config IS DISTINCT FROM 'feed'`
   passes every pre-column row regardless of what it was. **A filter that works perfectly on
   recent data can be a no-op on old data**, and nothing about the result looks wrong. A has
   no equivalent hazard because its whole window postdates every column.
2. **The PE gate moves to Postgres.** Before September 2026 an artifact only reached the
   metadata index if something came back about it, so OpenSearch coverage over B's window is
   both incomplete and biased toward successfully-analysed files — the opposite of what the
   negative class needs. B cannot use A's step 3.
3. **The survey asks a different question.** A's asks whether the bands populate. B's asks
   whether artifacts *converge at all*, and whether yield holds up across eras.
4. **The draw gains an era axis**, and the era probe becomes a blocking gate.

---

## Step B0 · Feasibility — `pipeline/sql/b00_feasibility.sql`

**New. Blocking. No equivalent in A.**

```bash
# Run one at a time -- these scan the full history, not a 30-day window.
psql "$PSQL_URI" -f pipeline/sql/b00_feasibility.sql | tee data/reports/b_feasibility.txt
```

Three questions, each able to end the exercise:

| Q | Question | A stop looks like |
|---|---|---|
| 1 | How far back does the data go? | four years, not ten — B buys much less breadth than assumed |
| 2 | When did each filter column start being written? | the cutoff lands near A's window, so B's usable span is short |
| 3 | How many engines are present in **every** year? | a near-empty era-stable vocabulary, making the feature restriction expensive |

**Q2 also sets `window_start` for every later step.** B's window must begin at or after the
latest year in which any filter column it depends on began being written. Read the migration
history alongside it — the query is a proxy that tells you where to look, not a substitute.

**Produces:** `data/reports/b_feasibility.txt`, and a decision: the `window_start` every
subsequent B query uses. If Q3 comes back with a tiny intersection, record that number — it
is what the A-restricted run in §B8 exists to price, and it is a finding whether or not B
proceeds.

**Done when** you can state B's usable span in years and the size of the era-stable engine
vocabulary.

---

## Step B1 · Convergence survey — `pipeline/sql/b01_survey.sql`

**B's decision point**, and it draws nothing — same discipline as A's step 2.

```bash
psql "$PSQL_URI" -f pipeline/sql/b01_survey.sql | tee data/reports/b_survey.txt
```

The output is a **funnel per era**, so you can see which condition does the killing:

```
candidates → f1_enough_scans → f2_old_enough → f3_converged → f4_labellable
```

| Transition | What losses there mean |
|---|---|
| candidates → f1 | rescan coverage — most files are scanned once and never again |
| f1 → f2 | age; should be ~100% for old eras |
| f2 → f3 | **genuine non-convergence** — still moving after years |
| f3 → f4 | engine coverage at the final scan |

**Read `pct_yield` down the eras.** 30% in 2024 and 2% in 2019 means the old artifacts
exist but are not usable — B is a slower A wearing a decade's clothes. **That is a stop, not
a reason to loosen the criterion.** Loosening it relabels unsettled artifacts as settled,
which is the single thing B must not do.

> **This survey's yield is an upper bound.** §B3's criterion is stability of the
> *independent cluster* count; clustering does not exist yet (R8), so the query uses raw
> `n_malicious` as a stand-in. Correlated engines moving together look like one change, so
> real clustering can only make artifacts look *less* settled, never more.

**Produces:** `data/reports/b_survey.txt` — one row per era, seven columns. Human-read; its
output is a go/no-go plus possibly revised convergence parameters, recorded in `decisions/`
before anything is drawn.

**Done when** you can say how many labellable artifacts exist **per era**, and whether that
is materially more than A's cohort *spread across time* — not merely larger in total.

---

## Step B2 · Confirm PE — **Postgres, not OpenSearch**

A's step 3 does not apply. Use the Postgres-side test:

```sql
-- a pefile analyzer row exists, AND it indicates success
JOIN metadata m         ON m.artifact_instance_id = ai.number AND m.tool = 'pefile'
JOIN artifactmetadata am ON am.number = m.artifact_metadata_id
WHERE am.storage_path IS NOT NULL        -- out-of-line => large => parsed
   OR am.tool_metadata ? 'imphash'       -- inline success
```

Out-of-line storage is the signal the parse **succeeded**: us-prod sends anything over 2000
bytes to psstorage, a parsed-PE document is far larger, and the 32-byte rejection document
`{"error": "unsupported file"}` is always inline.

**This is a heuristic, and it is checkable.** Run *both* tests — this one and A's
`exists: pefile.imphash` — on the **post-September-2026 overlap**, where ES is trustworthy,
and measure the disagreement rate. Do that before drawing, and record the number: it is the
error bar on B's entire PE selection.

**Produces:** `data/snapshots/b_pe_confirmed.txt` (newline sha256), plus a recorded
disagreement rate against ES on the overlap.

**Done when** the disagreement rate is known and small enough to state in a result.

---

## Step B3 · Draw — era × agreement

A's two-tier shape — a base pull, then `01b_draw.py` over it — with two changes:

- **Stratify on era as well as agreement**, targeting a roughly even artifact count per
  year rather than proportional representation. Recent years dominate the raw population,
  and that skew is the thing B exists to correct.
- **`π_i` is per (era × band) cell**, and is now doing strictly more work than in A: the
  era imbalance it corrects is larger than the band imbalance.

Everything else holds — the PE set is a **precondition, not a post-filter**, and the
permutation stays keyed by `md5(sha256 || seed)`.

**Produces:** `data/snapshots/b_cohort.csv`, as A's with an added `era` column and `π_i`
computed per cell.

**Done when** the three draw checks (target met or under-fill reported, `π ≤ 1`, row count equals Σ `n_draw`) pass *per cell*, and no era is
silently absent.

---

## Step B4 · The era probe — **a gate, not a report**

**New, and blocking.** Before any model is fitted:

> Train a classifier to predict **era** from the feature set. **Above ~0.6 AUC, reject the
> draw.**

If era is predictable from the features, the model will use it — missingness from engine
roster drift correlates almost perfectly with age, so a model would learn *"many absent
engines ⇒ old ⇒ the base rate of old files"*. That is a provenance detector wearing a
feature's clothes, and it would post excellent numbers while measuring nothing.

**Fix the feature set, never the threshold.** The fix is §B9's era-stable representation:
aggregate features that mean the same thing in any year, plus per-engine columns only for
engines in step B0's intersection.

**Produces:** `data/reports/b_era_probe.txt` — one AUC, and the feature ranking behind it.
The ranking is the useful part: it names which columns are leaking era.

**Done when** the probe is at or near chance. This is the same machinery as stage 06's
provenance probe, third use.

---

## Step B5 · Snapshot

As A's step 5, with `estimand: B` and its own version stamped into the manifest. **Never
written into A's snapshot directory** — two label definitions in one place is the failure
mode both estimands exist to avoid.

---

## Sequencing against A

| | |
|---|---|
| **A first, always** | A's churn rate is the evidence that sets B's `min_elapsed_days`. B cannot produce it — B defines churn away |
| **B needs no waiting** | no rescan, no horizon. Once B0 and B1 pass, B runs straight through |
| **They meet once** | at §B8's shared evaluation slice — artifacts ~1 year old, carrying both labels |

That shared slice is worth producing **even if B is never built**: the disagreement rate
between A-labels and B-labels on the same artifacts is the cost of the 30-day horizon, in
the only units that matter.

---

## What can go wrong that cannot in A

| Symptom | Cause |
|---|---|
| Cohort contains obvious feed artifacts | a filter column postdates the rows — the filter was a no-op. Re-read B0 Q2 |
| Convergence yield collapses in old eras | genuine — old artifacts are present but unlabellable. Stop; do not loosen the criterion |
| Era probe passes easily at first, fails after adding features | a per-engine column outside the B0 intersection crept in |
| PE set looks small and skewed | the Postgres heuristic was used without checking it against ES on the overlap |
| Old-era artifacts are systematically more malicious | survivorship — artifacts still being rescanned after years are not a random sample of their era. Unfixable within B; state it next to every result |
