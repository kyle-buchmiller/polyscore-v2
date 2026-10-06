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

> **Postgres, never Elasticsearch.** The ES document holds exactly two scans —
> `scan.first_scan` and `scan.latest_scan` — and is **overwritten on every rescan**, so it
> is current-state only and cannot answer an as-of question. It also renders engine
> identity as a *display name* resolved at write time from an external, mutable,
> unversioned lookup, which is the mechanism behind the 2023 model's alias splitting.
> Postgres stores the engine **address** and keeps every scan as its own row. The old
> pipeline's live training path read from ES; that is one of the reasons it could not be
> reconstructed.
>
> **The one exception, and it is narrow.** ES is the *clean* test for "did the PE parser
> succeed": a rejected `pefile` document is stripped to `{}` and removed entirely, so
> `exists: pefile.imphash` is exact, with none of the out-of-line trap below. That test is
> safe to take from ES precisely because it is **time-invariant** — a file's bytes do not
> change, so whether `pefile.PE()` parsed them cannot drift. Nothing time-varying may come
> from ES.
>
> But ES carries `meta_community` and carries **neither `community` nor `scan_config`**, so
> it cannot express the feed filter, while Postgres cannot cheaply express the PE filter.
> **Cohort selection needs both stores**: Postgres for the filters and all history, ES for
> PE confirmation.
>
> **The same argument admits one more thing from ES: the PE static block itself.** The
> index mapping carries 35 `pefile.*` fields (imphash, sections with entropy, the full
> certificate object, imports, libraries, exports, every ASLR/DEP/CFG/SEH flag, rich-header
> hash, pdb, compile date) and 14 `lief.*` fields (authentihash, signatures, signer,
> signing time, verification). Those are properties of the **bytes**, which do not change,
> so the overwritten-on-rescan document cannot drift on them. For artifacts in the
> post-September index, stage 04 reads them from ES in bulk — through the Cloudflare-Access
> door in [`09-extraction-runbook.md`](./09-extraction-runbook.md) — instead of one
> psstorage blob fetch per artifact. Two caveats: `pefile.is_valid` and `is_suspicious` are
> in the mapping but **written by nothing** (do not use them), and pre-September coverage
> is ~37% and biased, so Estimand B still takes features from psstorage.
>
> Also indexed and reachable the same way, relevant later: `known_good` (R9's catalogue),
> `cape_sandbox_v2` and `triage_sandbox_v0` (the sandbox signals in `06-signals.md`).

### Schema facts that are easy to get wrong

| Fact | Consequence |
|---|---|
| Every foreign key targets `artifactinstance.number`, **not** the primary key `id` | join on `number` |
| `number` is a **random 17-digit integer**, not a sequence | **never `ORDER BY number`**; `id` is the time-ordered column |
| `assertions` has **no timestamp column at all** | per-assertion arrival time is unrecoverable; the scan is the finest time resolution available. Relative order survives via the monotonic `assertions.id` |
| `assertions.mask` is hardcoded `TRUE` at write | vestigial; filtering on it is a no-op, and it cannot distinguish no-answer. The 2023 pipeline filtered on it anyway |
| `window_closed` is a boolean, and is set for known-good rows that never ran | use `completed IS NOT NULL` to mean "revealed" |
| A **completed** instance can have **no assertions at all** — on stage, feed ingestion records with `result = TRUE`, `quorum_mask = TRUE`, completed ~30 s after `created`, and zero assertion rows: ~23% of revealed artifacts (1.58M revealed, 1.22M with assertions, measured 2026-10-05) | "revealed" is not "scanned". A **scan** is `completed IS NOT NULL AND failed IS NOT TRUE AND EXISTS (assertions)`; the extraction SQL requires it for the T scan, the first-ever rule and the label scan. Before it did, 8 of the first stage base's 40 T scans were such records, and the frame fell from 913k to 680k artifacts once scans were required to have assertions |
| **A 17-digit `number` does not survive float64.** pandas chooses float64 for an integer column with a NULL, and float64's 53-bit mantissa rounds anything above ~9×10¹⁵ | every nullable instance-number column is `Int64` (nullable integer), and the extractor refuses to assemble a base from anything else. Measured 2026-10-05: every label instance in the first chunked base was rounded to a number that exists nowhere, and 26 of 32 artifacts labelled as "no assertions" for a scan the SQL had required assertions on |
| Rescan **inserts a new row**; assertions are INSERT-only with no UPDATE or DELETE path | history is genuinely append-only, which is what makes the as-of rule implementable |
| The read replica is a **hot standby** (`pg_is_in_recovery() = true`) and refuses `CREATE TEMP TABLE` | measured 2026-10-01. Any key set — the confirmed-PE hashes, the base's instance numbers — must ride in as a **query parameter** (`= ANY(array)`, chunked), never a temp table. `01_extract.py` does this; a hand-written `psql` session cannot |



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

Do **not** select by mimetype. `WINDOWS_EXECUTABLE_MIMETYPES` (nine values) is the
**analyzer dispatch list, not a PE selector** — four of the nine are not PE at all (CAB,
MSI in three spellings, MS Access, VBE), and `application/x-dosexec` covers plain MZ/DOS
binaries too.

Select by whether the PE parser succeeded. The rejection document is exactly
`{"error": "unsupported file"}` and nothing else.

> **Two corrections to the obvious test.** `sections` is **not** a valid positive: it is
> initialised to `[]` early and only filled inside a broad `try/except` commented
> *"malformed PE files are the norm"*, so a genuinely parsed PE can carry `sections: []`.
> And `pe.get_imphash()` returns **`""`** for a PE with no import table — so the test is
> **key presence**, never truthiness.

> ⚠️ **The out-of-line trap, which silently biases the cohort.** `tool_metadata` is a
> hybrid property with a size-based storage switch: documents at or above
> `AI_METADATA_OUT_OF_LINE_SIZE` go to psstorage and leave `tool_metadata NULL`. That
> threshold **defaults to 4000 but us-prod overrides it to 2000**, and a real parsed-PE
> document (sections, imports, resources, certificate) is far larger — while the 32-byte
> rejection document is *always* inline. So a query written as
> `tool_metadata ? 'imphash'` returns a small subset **skewed toward rejections**. Out-of-line
> storage is the signal that the parse *succeeded*, not a row to skip.

The JSON path is `artifactmetadata.tool_metadata -> 'imphash'` — **flat, not namespaced**.
The `pefile.` prefix is added at ES-serialization time and does not exist in Postgres.
Join `metadata.artifact_instance_id → artifactinstance.number` and
`metadata.artifact_metadata_id → artifactmetadata.number`, both on `number`, never `id`.

## Datadog: the scan-submission counter

`artifact-index` emits **`artifact_index.scan.submitted`** (DogStatsD, type `rate`) on every
submission, with tags that answer two questions the stores above cannot answer cheaply:

| Tag | Values seen (prod, 2026-09-28 → 10-04) | Why it matters |
|---|---|---|
| `endpoint` | `instance`, `url`, **`rescan`** | **rescans are counted directly** |
| `actor` | `user`, (`internal` for `ai instance rescan` / the AKM key) | separates our forced tranches from everyone else's rescans |
| `scan_config` | `default`, `feed`, `more-time`, `most-time`, `none` | **the feed split ES lacks** |
| `meta_community` | `public`, `private` | bucketed, not the raw name |
| `plan` | `enterprise`, `community`, `anonymous`, `small_business`, **`other`** | who; `other` is anything outside the allow-list in `metrics._KNOWN_PLANS` |
| `stage` | `created`, `started` | one of each per submission — **count `created`** or you double |

**It counts bounties, not artifacts.** That is the whole reconciliation with OpenSearch:
Discover showed **25.3M** public PE with a parsed `pefile` doc over 24 days (~1.05M/day);
the counter shows **~365k scans/day**. So roughly **two-thirds of indexed PE are stored and
never scanned** — they have analyzer output and no assertions, and cannot be a feature row.
Of the third that *are* scanned, **~99% are feed** (~360k/day) against **~3–8k/day of
customer `default`** submissions. The §1 population is that last number.

> **The counter went live on 2026-09-28.** It cannot see the §1 window (Sept 8 – Oct 1).
> For that window the rescan rate is a Postgres question, full stop; from Sept 28 onward
> it is a dashboard. Measured 2026-10-05 over its first six full days:
>
> - **Rescans: ~360/day**, all `actor:user` — no `ai instance rescan` traffic at all.
> - **~90% of them are `plan:other`**, arriving in **~500-per-day batches** (518, 500, 515
>   on the burst days). One actor's job, not organic interest.
> - **Enterprise rescans: ~23/day, steady.** That is the organic floor.
> - **Oct 4: 180,281 `default` submissions**, 20–200× a normal day — also `plan:other`.
>
> Which puts a name on the selection §4 worries about: *natural rescans are overwhelmingly
> whatever one unidentified-plan account chose to rescan.* Until that account is
> identified, the training arm's labels are selected by its criteria, not by anything we
> chose. Query shape, daily:
>
> ```
> sum:artifact_index.scan.submitted{env:prod,endpoint:rescan} by {actor,plan}.as_count().rollup(sum, 86400)
> ```
>
> Use the **timeseries** form with an explicit rollup. A scalar `sum` aggregator over this
> rate-type metric returned 300 where the daily series summed to ~2,800 for the same window
> — a normalization artifact, not data.

## The cohort filters, and how each one bites

| Filter | Column | The trap |
|---|---|---|
| exclude feeds | `scan_config` | Value domain is `{default, more-time, most-time, feed}` **plus NULL**, and NULL is common (URL artifacts, known-good rows). `scan_config <> 'feed'` silently drops every NULL — use **`IS DISTINCT FROM 'feed'`**. It is a plain `String` with no DB constraint; the four names come from a seed, so confirm against `SELECT name FROM scan_configs` before trusting the list. |
| exclude feeds, part two | `actions` (JSONB) | polyfeeder writes `{'_default': False, …}` for most items — but it scans a configurable fraction (`scan_percentages`), so **how many feed rows are storage-only is a per-environment setting, not a fact.** Measured on stage 2026-09-29: feed rows were **0% storage-only and 100% revealed**, the opposite of the code's default posture. Measure on prod before relying on it either way. Absent mapping, absent key and absent `_default` all mean *enabled*. |
| public only | `meta_community` | Values are **`'_public'` / `'_development'` / a private community's own name** — with leading underscores. The bare strings `'public'`/`'development'` are a *separate* metrics bucketing that is **never stored in this column**, so filtering on `'public'` returns nothing. |
| exclude internal | `api_key` (`CHAR(32)`) | `''` marks sandbox-derived dropped files; internal re-submissions carry the service key, so filtering them needs the prod `AKM_API_KEY` value. |
| tenant | `billing_id`, `user_account_number` | Team account and sub-account. There is no `tenant` column — `X-Request-Tenant` is request-scoped and never persisted. |

`weak_ref` looks like a bulk marker and is not — it is written nowhere. Do not use it.

> ⚠️ **The `actions` filter may be the largest single reducer of the cohort, and nobody
> has sized it.** Measured on stage 2026-09-29: of rows with `scan_config = 'default'` —
> ordinary customer submissions — **87% (433/497) carried `_default: false`**, i.e. they
> were stored and never scanned. A stored-but-unscanned artifact has no assertions, so it
> cannot be a feature row at all.
>
> If that ratio holds on prod, the §1 population is roughly an order of magnitude smaller
> than a raw row count suggests, and the 10,000-file target needs checking against it
> before anything is drawn. Stage traffic is small and partly synthetic, so this is a
> **warning to measure**, not a number to plan around.

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
- the incumbent `polyscore` on any scan after the scoring moment — and note `polyscore`
  and `detections` carry a second, sharper defect: both are write-once guarded, **but the
  admin backfills recompute them for NULL rows at backfill time and record nothing about
  when.** For an older row these fields can be far younger than the scan they hang off,
  so even the scan's own timestamp does not bound them.

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
