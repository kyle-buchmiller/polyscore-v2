# 02 — Data

## Scope

What is collected, from which source, and the rule that keeps it honest.

## Invariants

- **Every feature must be true at or before the scoring moment.** Enforced in code, not by discipline.
- Features key on the engine's **immutable address**, never its display name.
- A snapshot is written once and never mutated.

## You do not need the binaries

PolyScore aggregates what engines said, not file content. The scoring path passes
`path=None` and never fetches artifact bytes.

Even the *structural* features need no binaries: `pefile` and `lief` already run on
every eligible file and their output is stored — `imphash`, code-signing certificate
chains, per-section entropy, imported functions, `is_probably_packed`. The platform has
already done the analysis; the old model simply never used it. Bytes are required only
for things nobody computes (own entropy measures, byte n-grams, disassembly), which is
a different product.

## Where to pull from

**Postgres for the feature matrix.** It keeps one row per *scan*, with that scan's own
assertions and analyzer output, so "what did we know at scan N" is a keyed read.

**OpenSearch is not usable for the matrix.** One document per file, overwritten, mixing
epochs — static output from the latest scan sitting beside assertions from the first.

**The firehose dump for survey work.** Local replay runs ~40,000 records/second against
~3,200/s from the cluster, and carries both scans, the static PE block, TLSH and the
incumbent's score. Cohort selection, the composition table and split keys all run
locally in one pass. It **cannot** supply engine identity: it keys assertions by display
name in a JSON map, so two engines registered under one name collapse to one before the
bytes reach disk.

## The feature groups

| Group | Columns | Why |
|---|---|---|
| Identity & split keys | `sha256`, instance number, `created`, `first_seen`, `tlsh`, `ssdeep`, `imphash` | joins, temporal ordering, family grouping |
| Per-engine verdicts | per engine: `responded` (0/1), `malicious` (0/1), keyed on **address** | the core signal — two columns so "said clean" and "said nothing" stay distinct |
| Aggregates | `n_malicious`, `n_benign`, `n_silent`, `n_eligible`, `coverage_ratio`, `n_independent_clusters` | the dumb baseline lives here; coverage is what later enables abstention |
| Temporal | `age_at_scoring`, `n_rescans`, `hours_to_first_detection`, `verdict_trend` | a file seen 3 hours ago with 2 detections is a different risk from one seen 2 years ago with 2 |
| Family strings | `n_distinct_families`, `has_specific_family`, `cross_cluster_family_agreement` | two independent vendors saying "Emotet" beats five saying "Trojan.Generic" |
| Static PE | `size`, `n_sections`, `max_section_entropy`, `mean_section_entropy`, `n_imports`, `is_probably_packed`, `signed`, `cert_valid`, `cert_subject_org` | **context, not detection** — tells the model whose opinion to trust on this kind of file |

Roughly 120 columns once the per-engine pairs expand, against the old model's 284 slots
of which 256 were hard zeros.

## Selecting the PE cohort

Do **not** select by mimetype: `WINDOWS_EXECUTABLE_MIMETYPES` also admits CAB, MSI, MS
Access and VBE. Select by whether the PE parser succeeded — the analyzer writes
`{'error': 'unsupported file'}` into its stored output on rejection, so the presence of
`imphash` or `sections` is the positive test.

## Columns the draw must record

Estimand §9 draws stratified, and three columns are written by stage 01 alongside the
features. They are **bookkeeping, never features** — `04_features.py` must not emit them,
and the provenance probe in stage 06 is the check that it didn't.

| Column | What it holds | Why it cannot be reconstructed later |
|---|---|---|
| `stratum` | which §9 band the artifact was drawn from | the band is defined at the scoring moment; engine verdicts accrue afterwards |
| `pi` | the artifact's inclusion probability | depends on the band's population *at draw time* and on how much of the target share was already filled |
| `provenance` | organic, or which injected known-good source | lost the moment the rows are mixed |

`pi` is the load-bearing one. Everything that makes a stratified draw safe — reweighting
to natural prevalence, the intercept correction, every rate metric — is `1/π_i` arithmetic,
and **a draw made without it cannot be corrected by any later step.** One column, written
once, or the cohort is only ever usable for ranking.

## The as-of rule

The label comes from the future by construction (horizon T+30). If a feature also comes
from the future, the model learns a clue that exists only because the answer already
happened. It will score brilliantly in testing and fail in production, and nothing in
the metrics will say so.

Enforcement: every field carries an "as of" timestamp and `features.py` refuses anything
stamped later than the scoring moment. `tests/test_asof.py` is the guard.

Known offenders that must never become features:
- `polyunite` output — regenerated and overwritten in place, folding in families that
  arrived weeks later from sandbox runs and tags;
- rolled-up `detections` counts, `tags`, `families` — same problem;
- the incumbent `polyscore` on any scan after the scoring moment.

These are fine for **stratification and survey**, where knowing the future is harmless.

## Sandbox data

Usable, with care. Detonation is **gated, not sampled**: the scheduler returns
immediately unless a malware family has already been resolved, and families come from
engine assertions. A file nobody detected never gets a family, so it never gets
detonated. **"Has sandbox data" is therefore downstream of the AV verdicts**, which are
both the features and the label source, and benign-side coverage is near zero.

Rules:
- encode presence as three states — `not_submitted` / `failed` / `succeeded` — never as a blank;
- prefer behavioural facts ("contacted a C2") over vendor aggregate scores, which are
  themselves signature-derived and reintroduce the circularity one layer down;
- always report the model with sandbox features ablated on the same rows. The gap is
  the true contribution; anything else measures the scheduler.
