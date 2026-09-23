# 07 — Requests

## Scope

Capabilities **other teams own** that PolyScore needs, or would materially benefit from.
Outward-facing: this page exists to be read by the people who would build these things.

Distinct from [`99-open-questions.md`](./99-open-questions.md), which holds decisions
*we* owe. If an item is ours to decide, it belongs there. If it needs someone else to
build something, it belongs here.

## Invariants

- Every request names an **owner**, a **status**, and what it costs us **not** to have it.
- A request states the **workaround in use today** — an ask with no workaround is a
  blocker and should say so.
- Requests are ranked by what they unblock, not by how hard they are.

## Statuses

`not raised` · `raised` · `accepted` · `in progress` · `delivered` · `declined`

Keep the status current. A register nobody updates is a wish list.

---

# Tier 1 — unblocks something otherwise impossible

## R1 · A random detonation arm

- **Owner:** `polysando` · **Status:** not raised · **Size:** small

**What.** Detonate a fixed, small fraction of artifacts **regardless of whether a malware
family has been resolved** — sampled at random from the submission stream, with the
sampling fraction recorded.

**Why.** `evaluate()` returns immediately unless `metadata.polyunite.malware_family`
resolves, and families are derived from engine assertions. So a file nobody detected is
never detonated. Benign-side sandbox coverage is therefore near zero, and roughly 3.9% of
a day's artifacts are sandboxed at all.

**Cost of not having it.** Sandbox evidence can only ever inform artifacts that engines
already flagged — which is precisely the region where the score matters least. Worse,
`has_sandbox_data` becomes a function of the label's own generating process, so it cannot
be used as a feature without circularity. Detonation is the single most *independent*
evidence source available (behaviour, not opinion), and this gate is what stops it being
usable.

**Workaround.** Condition on presence rather than learn from it: use sandbox signals only
within the sandboxed population, and route by coverage tier. That is sound but it leaves
the whole undetected population without behavioural evidence forever.

## R2 · Engine identity on a bulk extraction path

- **Owner:** `artifact-index` (index mapping) and/or `ps-firehose-data-sampler` · **Status:** not raised · **Size:** medium

**What.** Expose the engine **address** (`assertion.author`) on whatever bulk path is
intended for analytics — either in the metadata index, or as an additional field the
firehose dump carries.

**Why.** The metadata document keys assertions by **display name**, as a JSON map, and
`assertion.author` is absent from the index entirely. A map holds one value per key, so
two engines registered under one name collapse to one *before the bytes reach disk* —
and a vendor's separate registrations (`SentinelOne` vs `SentinelOne Static ML`) stay two
unrelated columns. The registry holds **296 addresses under 258 names**.

**Cost of not having it.** Any feature matrix built from the dump inherits the exact
identity defect that ate the 2023 model, upstream of anything we can fix in training
code. So the as-of feature matrix must come from Postgres, at roughly a twelfth of the
throughput of local replay.

**Workaround.** Firehose for survey, cohort selection, composition table and split keys;
Postgres for the feature matrix. Documented in [`02-data.md`](./02-data.md). It works, it
just costs a lot of wall-clock on every iteration.

## R3 · An adjudication workflow, and sampling probability recorded at draw time

- **Owner:** unassigned — needs a product owner · **Status:** not raised · **Size:** large, and partly ongoing cost

**What.** Two things that have to exist together:

1. A queue where an analyst adjudicates an artifact against a written rubric, and the
   verdict is stored with the adjudicator, the timestamp, the rubric version and the
   horizon.
2. **The inclusion probability recorded at the moment an artifact is drawn** for
   adjudication.

**Why.** Calibration is a claim about frequencies in a population, and it can only be
measured against labels that are independent of the model's inputs. Nothing in the
platform produces such a label today — `ground_truth_value` in the hunt export is the
*arbitration result*, and arbitration is not independent: arbiter display names are
themselves columns in the model's vocabulary, and three of the four deployed arbiters
share a vendor with a scanning engine voting on the same artifact.

**Cost of not having it.** No grade-3 labels means no calibration, ever — see
[`03-labels.md`](./03-labels.md). The combiner in [`06-signals.md`](./06-signals.md)
cannot be fitted and its coefficients stay expert-set and provisional. The pilot can
measure ranking and nothing else.

**And the part that cannot be retrofitted:** an unrecorded sampling probability is gone
permanently. Adjudicating 10,000 artifacts without recording how they were drawn produces
10,000 labels that cannot support a calibration claim.

**Workaround.** None. This is the binding constraint on the whole contract.

---

# Tier 2 — removes a large, known distortion

## R4 · A status field beside `polyscore`

- **Owner:** `artifact-index` · **Status:** not raised · **Size:** medium (schema + consumers)

**What.** `polyscore_status` (and a reason code) alongside the existing nullable float, so
null means exactly one thing.

**Why.** NULL currently covers at least nine distinct situations — URL and IP artifacts,
store-only submissions, sandbox-created instances, known-good samples, the development
community, zero-assertion scans, bounties that never revealed, lost callbacks, and simply
the window between reveal and the callback landing. There is no column that separates
them.

**Cost of not having it.** We cannot enumerate the set of artifacts that actually received
a score, and without that set there is no sampling frame to audit. It also means the
coverage gate in [`06-signals.md`](./06-signals.md) has nowhere to express
`insufficient_coverage` — the one output that permanently retires the 0.3346 constant.

**Workaround.** Infer from `actions`, `window_closed`, assertion count and community.
Fragile, and it cannot distinguish "never asked" from "asked and lost".

## R5 · Bulk access to sandbox reports from object storage

- **Owner:** `polysando` / `artifact-index` · **Status:** not raised · **Size:** medium

**What.** A supported way to fetch full behavioural reports for a set of hashes, at
training-set scale.

**Why.** The index is a lossy view. Roughly 1.8% of detonations emit a Suricata TLS SNI
into OpenSearch and ~11% log DNS, against 15.6% in the report on object storage — an
~8.7× difference the index never ingested. Separately, CAPE's `behavior.enhanced` block is
**deleted before storage** (`del behavior['enhanced']`), so the process and registry event
stream is not retained anywhere queryable.

**Cost of not having it.** Every behavioural feature buildable from the index is floored
by roughly an order of magnitude. That is the same defect in a different costume as
PolyScore's own — the whitepaper advertised sandbox-derived inputs, the shipped model has
none, and it turns out the index could not have supplied good ones anyway.

**Workaround.** Use the handful of fields that do survive — `cape_config.address`/`.url`,
`extracted_c2_ips`, `suricata_alerts.*`, `dropped[]`. Enough for a first combiner, not
enough for the capability the whitepaper describes.

## R6 · A fresh measurement of metadata-index coverage

- **Owner:** `artifact-index` · **Status:** not raised · **Size:** small (a query)

**What.** Re-run the D-007 style survey: for one day of stream traffic, what fraction is
metadata-indexed, ever scored, ever sandboxed.

**Why.** The standing figure — 37.0% indexed, 29.7% scored — was measured **2026-09-02**,
and production was running an image promoted 2026-08-31 and not replaced until
2026-09-08. It measured the pre-`DN-8535` world, in which an ordinary scanned artifact's
ES write was never claimed at ingest. The number is stale and the repair has been
extensive.

**Cost of not having it.** Estimand §1 carries a caveat clause it cannot size, so the
reference population is described with a number we know to be wrong in an unknown
direction.

**Workaround.** Prefer a cohort window after 2026-09-08, stated in
[`01-estimand.md`](./01-estimand.md). Cheap and safe, but it forfeits the historical
corpus.

---

# Tier 3 — makes the score better

## R7 · A certificate reputation source

- **Owner:** this repo, or `shifty` / `polykg` · **Status:** not raised · **Size:** medium

**What.** A list to join certificate thumbprints against: revocation feeds, CT log
monitoring, vendor compromised-cert lists — or one derived from our own corpus.

**Why.** DN-8374 (shipped 2026-09-22) gives structured Authenticode verification and
per-certificate `sha1` / `sha256` **thumbprints**, which is the join key. What it does not
and cannot do is assert *stolen* — that requires an external reference.

**Cost of not having it.** The signal leadership specifically asked for does not exist.
What we can offer instead is `chain-broken`, `weak-digest-*` and `self_signed`, which are
useful but are not the same claim.

**Cheapest route.** Derive it internally: *a thumbprint that has signed N artifacts later
adjudicated malicious*. Computable from the corpus this repo already assembles — but it
needs the label store first, so it is gated on **R3**.

## R8 · Engine independence clusters

- **Owner:** this repo, or wherever the orphaned similarity work is adopted · **Status:** not raised · **Size:** medium

**What.** A maintained grouping of engines that share signature feeds or detection
lineage, so "three independent clusters" is computable.

**Why.** Five detections are not five opinions if four of those vendors license the same
feed. The label rules in [`03-labels.md`](./03-labels.md) require cluster-adjusted counts,
and it is a far stronger bar than counting engines at identical cost.

**Cost of not having it.** Label quality is capped by a vote count that systematically
over-weights whichever feed is most widely licensed.

**Note.** A working implementation exists in `polyscore-pipeline` — the engine-similarity
work described in the 2022 whitepaper — but it is orphaned: its only caller is a chart
function with no callers. It is more useful as a *labelling* tool than it ever was as a
scoring feature.

## R9 · Known-good corpus coverage for the negative class

- **Owner:** `artifact-index` (`known_good`) · **Status:** not raised · **Size:** medium

**What.** Broader known-good feed coverage, and a way to query the catalogue as a corpus
rather than as a per-hash lookup.

**Why.** The negative class is the expensive half of a calibration set, and it barely
exists today: the 2023 training frame filtered to malicious assertions before labelling,
so it contained **no artifacts that nobody detected at all**.

**Cost of not having it.** Negatives drawn from "nobody flagged it" teach the model that
signed Microsoft binaries are clean and little else. Positive attestation is strictly
better evidence than absence of detection.

**Workaround.** Vendor retractions — engines that detected a file and later stopped — are
the strongest negatives available and are already extractable. Good, and not a substitute
for attested known-good at volume.

---

# Already available — please don't request these

Verified to exist, so they are not asks:

| Capability | Where |
|---|---|
| **Bulk rescan over an id range** — how a T+30 label horizon is manufactured for a frozen cohort | `ai instance rescan <start> <end> -c <chunk>` |
| **Static PE analysis already stored per scan** — imphash, certificate chains, section entropy, imports, `is_probably_packed` | `pefile` / `lief` analyzer output |
| **Authenticode verification with chain flags and thumbprints** | DN-8374, shipped 2026-09-22 |
| **Per-scan history in Postgres** — one row per scan, making as-of reconstruction a keyed read | `artifactinstance` |
| **Three-state engine verdicts** — malicious / benign / no-answer, already recorded | `Assertion.verdict` (nullable boolean) |
| **A benchmarked bulk metadata extractor** — 62.9M records in 5h27m | `ps-firehose dump` |
