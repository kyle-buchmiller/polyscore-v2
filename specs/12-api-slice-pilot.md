# 12 · The API slice — the pilot's source while the replica is out of reach

## Scope

How the pilot gets prod data through the **public API** instead of the read replica:
what one slice is, why a sha256 prefix is a sample, what the metadata index can and
cannot say about a scan, the survey that sizes the slice, and the deviations from the
SQL path this source forces. The SQL path ([09](./09-extraction-runbook.md)) stays the
full-window source, and the exporter ticket DN-8712 is what retires this one. Decision:
[0013](../decisions/0013-pilot-data-from-the-public-api.md).

## Invariants

- **A slice is a uniform sample with an exact inclusion probability.** sha256 is
  uniform, so the files whose hash starts with a given `k` hex characters are a random
  `16^-k` of every file, chosen deterministically. `pi_base = 16^-k` is written into the
  manifest; nothing downstream estimates it.
- **The slice never enumerates the frame.** The server applies the prefix as a filter.
  The frame's size is `n / pi`, not a count of anything.
- **The index is the source of per-scan facts here, by exception to [02](./02-data.md).**
  That spec says Postgres, never the index, for verdict rows, because the index keeps one
  document per file and overwrites it. The exception is bounded to what the document
  holds immutably: the first scan is written once; the latest scan is whatever it was at
  pull time and is recorded as such.
- **Every deviation from the estimand is named in the manifest and the run report**, so a
  pilot result reads as "API-sourced, latest-scan labels, name-keyed engines" and not as
  the estimand's answer.
- **The key never leaves the environment.** It is read from `POLYSCORE_API_KEY` or
  `POLYSWARM_API_KEY`, sent as a header, and appears in no log line, manifest or error.

## What the index knows about a scan

One document per `(sha256, meta_community)`. The slice reads these fields and nothing
else (`SLICE_INCLUDE` in `src/polyscore_v2/api_source.py`; `artifact.*` always rides along):

| Field | What it is | Used for |
|---|---|---|
| `scan.first_scan.{created, artifact_instance_id}` | the file's first instance in this community | T, the scoring moment |
| `scan.first_scan.detections` | `{malicious, benign, total}` at T; `total` is the definite count | `m` at T, the band |
| `scan.first_scan.assertions` | `{engine name: {assertion, metadata.malware_family}}` | the verdict vector at T |
| `scan.latest_scan.*` | the same three for the last instance at pull time | the label scan |
| `scan.mimetype` | the detected type | reporting |

The query is `pefile.imphash:* AND scan.first_scan.created:[start TO end} AND
artifact.sha256:<prefix>*`: the PE gate, a half-open window on the first scan, the
sample. Pages are 300 documents, about 150 KB with this projection, about one second
each; the cursor is opaque and the walk resumes from the last cached page.

## What the index cannot say, and what the pilot does about it

1. **The first instance may not be a scan.** A file ingested unscanned and scanned later
   has a first instance with no verdicts. The survey counts these (`unscanned first
   instance`); for the pilot they are dropped from the frame, and the share is the first
   number to read, because the estimand's "first completed scan with assertions" would
   have picked a later instance instead.
2. **Only the first and the latest scan are visible.** The estimand's label is the nearest
   later scan inside `[horizon, horizon_max)`; the slice has the latest. For a file scanned
   exactly twice they coincide. `--history-sample N` measures how often they do not, with
   N cheap history calls.
3. **Engines are keyed by display name, not id.** Names drift. The pilot keys the verdict
   vector by name and records it; the full render (`/v3/instance?id=`) carries ids, bids
   and masks, at 6.5 MB a call, and is fetched only for a drawn cohort if a stage needs them.
4. **No `scan_config`.** Provenance is unknown for every row, so the reference population
   ([01 § 1](./01-estimand.md)) cannot be separated from feeds: **calibration (08) does not
   run on an API-sourced base**, the provenance guard in 06 reports n/a, and both resume
   once the field is exported (DN-8712) or rendered.
5. **Two counts of "definite".** The index's `detections.total`, which the draw bands on, is
   `ArtifactInstance.detections`: computed once by artifact-index's `post_reveal_tasks` from the
   assertions the read replica showed when the reveal task ran, stored, and never recomputed
   (`generate_detections` returns the stored value; `generate_polyscore` runs just before it on
   the same view, so the incumbent PolyScore has the same input set). An assertion that lands
   after that moment reaches the assertions table and nothing else: not the column, not the
   render's `detections`, not the index, not the PolyScore. The base's `n_definite` counts the
   render's non-null verdicts, the eventual set. Measured 2026-11-10 on the cohort's T scans:
   the two agree on 73%, the column is short by 1 on 24% and by 2–5 on 3%. The draw's stratum
   is recorded as drawn; `02_compose` re-bands from the base and reports the movement.
6. **A different sampling rule.** The SQL path samples by `hashtext(sha256) % 100`; the
   slice by hex prefix. Both are uniform; a base records which one it used.

## The survey (`pipeline/00_api_slice.py`)

One slice over one window, then the numbers that size the pilot:

- the unscanned-first share, and how many of those were scanned later;
- the rescan share, among all files and among scanned ones;
- the labellable share at `horizon_max` of 90, 180, 365 and 1000 days, each scaled to
  the full frame by `1/pi`;
- the gap to the latest scan (p10, p50, p90) and the definite-verdict count at T;
- the band histogram at T among the labellable, with the SS9 fill arithmetic from
  [01 § 9](./01-estimand.md), and the prefix length a 10k cohort would need from this
  window alone.

Outputs: `data/api_slice/<start>_<end>_<prefix>.parquet` with its manifest (stage
`00_api_slice`, the query, `pi`, pages, calls, seconds), raw pages under
`data/api_slice/.cache/<key>/`, and `data/reports/api_slice_<key>.txt`.

## Measured

**2026-11-09, May 2026** (first scan in `[2026-05-01, 2026-06-01)`), prefix `a1` (π = 1/256):
50,241 documents in 168 pages, 202 s, one call per page. The `a1b` slice of the same month
(3,074 documents, 15 s) agrees on every share.

| | |
|---|---|
| first instance unscanned (`STORED`, a scan later) | 30.5%; the scan follows p50 1.0 d later, p90 6.8 d, 5.4% after 30 d or more |
| scanned at the first instance | 69.5%; `first_scan.created` equals `artifact.created` for all of them |
| rescanned at least once, among the scanned | 1.3%; gap p50 0.1 d: 72 within an hour, 269 within a day, 25 in 1–7 d, 81 in 7–30 d, 7 beyond 30 d |
| labellable at `[30, 90)` / `[30, 1000)` | 2 / 7 of 50,241 (0.004% / 0.014%), about 500 / 1,800 in the month's frame of ~12.9M |
| definite verdicts at T, scanned files | p10 14, p50 16, p90 17, from 16–19 answering engines |
| bands at T over all scanned-first files | consensus malicious 84.2%, contested 8.0%, consensus clean 3.2%, leaning malicious 2.3%, leaning clean 2.0%, below floor 0.3% |

**The index's view is faithful.** For 150 sampled files the per-hash history
(`/v3/search/instances`) was compared with the document: both index instance ids appear in
every history; the 100 "single scan" files have exactly one instance each, `SETTLED`; the 30
unscanned-first files have exactly two, `STORED` then `SETTLED`; the 20 rescanned have two or
three. `first_scan` is the first *instance* of any state and `latest_scan` the last scanned one
(`_shape_search` in artifact-index `es/serializers.py`), which is what the survey assumes.

**2026-11-09, the first post-fix month** (`[2026-09-08, 2026-10-08)`, prefix `a1`): 133,502
documents in 446 pages, 483 s; 32–62 days of exposure at pull time.

| | |
|---|---|
| never scanned (`STORED` first and last) | 60.9% of documents: the post-fix index holds stored-only files, which the pre-fix index did not |
| first instance unscanned, scanned later | 3.8% |
| scanned at the first instance | 35.3%, about 13.4M scanned files in the month, the same scanned volume as May |
| rescanned at least once, among the scanned | 0.4%: 43 within an hour, 113 within a day, 6 in 1–7 d, 23 in 7–30 d, 3 beyond 30 d |
| rescanned 30+ days later, among the 25,610 scanned files with 45+ days of exposure | 1 |
| definite verdicts at T, scanned files | p10 13, p50 15, p90 16, from 15–17 answering engines |
| bands at T over all scanned-first files | consensus malicious 77.6%, contested 12.6%, leaning clean 4.9%, leaning malicious 2.3%, consensus clean 2.3%, below floor 0.3% |

**The two months agree once coverage is understood.** May's 12.9M-file frame is the scanned
files alone: the pre-fix index was written on scan completion, so "37% populated, biased
toward analysed files" ([09](./09-extraction-runbook.md)) is the scanned share of stored PE
files. September's 34.2M adds the 61% that are stored without a bounty. **About 13M scanned
public PE files a month** is the number to plan with, and `pefile.imphash:*` alone does not
mean scanned: the survey's test is `first_scan.detections.total > 0`.

**What it means.** A natural later scan 30 or more days after T happens to about 10⁻⁴ of
scanned public PE files: 7 of 34,896 after six months of exposure, 1 of 25,610 after 45–62
days, and the few seen were consensus-malicious at T. A month's whole scanned frame, at
π = 1, yields of order 10³ labellable files at any horizon; a 10k cohort at the SS9 shares is
out of reach of natural rescans in the public community by any data path. The slice remains
the frame-and-draw source; the label source is the open question in
[99](./99-open-questions.md).

## Arbitration as a label source: measured, not usable as deployed

The marketplace already takes a second look at every public scan: `ARBITER_VOTE_DELAY` is
two weeks in us-prod, then the arbiter engines vote, polyswarmd3 computes a ground truth
(`_prepare_quorum_truth`: malicious when at least half the arbiters say so, benign when more
than half do, otherwise whichever side has votes), and artifact-index stores it as
`ArtifactInstance.result` with `quorum_reached`. The votes render in the full instance JSON
(`votes`) and in the index (`scan.first_scan.votes`, `scan.latest_scan.votes`); `result`
renders on the full instance. Measured 2026-11-09 on 991 scanned-first PE files first seen
Sep 8 – Oct 8 2026 (every one had votes):

| arbiter | votes |
|---|---|
| ClamAV-Arbiter | malicious 878, benign 109, unknown 0; **equal to ClamAV's own assertion at T in 983 of 983** |
| Cyberstanc Arbiter | unknown 909, malicious 73, benign 9 |
| SentinelOne Static ML Arbiter | unknown 991 |
| k7-arbiter (deployed) | never votes |

Quorum by the rule above: 78 of 991 (71 malicious, 7 benign); for the other 913 the ground
truth is ClamAV's vote alone. So today's formal call is ClamAV's verdict at T, re-stated two
weeks later; it carries no information the T scan did not, and a model trained on it would
learn to predict ClamAV. **The mechanism is the right one**: a scheduled second scan of every
public file at T + 14 d, already paid for, with the votes already exposed. What is missing is
a roster of arbiters that answer and whose knowledge moves in two weeks. That is the
alternative to a separate rescanner recorded on DN-8721.

## Forced rescans (`pipeline/00b_force_rescan.py`)

The label the slice cannot provide is forced ([0014](../decisions/0014-forced-rescans-for-the-training-arm.md)).

- **The frame** is every scanned-first file of one or more disjoint-prefix slices of one
  window, aged `[horizon_days, horizon_max_days)` at draw time, no larger than the rescan
  route's size cap under the pilot's key (`--max-size-bytes`, 32 MiB; the index records
  `artifact.size`, so the rule is applied before the draw and the manifest counts what it
  removed) and not a memory image (§ Memory images are out of frame: `static` reads the
  layout fields, `draw` applies the rule and its manifest counts what it removed by reason
  and by band at T). `pi_base` is the sum of the slices' inclusion probabilities (disjoint prefixes, so
  the union is a sample too); the draw's `pi_draw` comes from `stratified_draw`, so a file the
  route would refuse is never drawn. The run cohort's `pi` is the **realized** share per
  band, labelled over available, so a file lost after the draw (a failed scan) lowers its
  band's π instead of vanishing; the manifest keeps the design's `pi_draw` and
  `excluded_after_draw` by band and reason. `pi_base` is a column, not a factor, as 01b's
  base π of 1 is not.
- **The rescan** is `POST /v3/consumer/submission/<community>/rescan/sha256/<hash>`: it
  copies the file's last scanned instance into a new bounty under the default scan config,
  bills `Feature.SCAN`, and is counted as `endpoint:rescan, actor:user` in
  `artifact_index.scan.submitted`. The response carries the new instance id, which is the
  label instance by construction. A POST that fails with a 5xx or a timeout is recorded and
  not retried blind: the instance may exist, and a second POST would scan the file twice.
- **The label scan is read back from the full instance render**, one `GET /v3/instance?id=`
  per forced instance and per T instance (about 30 KB each for a feed file: assertions, engine
  id and name, bid, mask, family; no sandbox report), cached as JSONL and accepted once the
  forced window has closed. Not from the index, whose `detections` is the frozen column of
  deviation 5, and under the pilot's submission rate the freeze came early. Re-read
  2026-11-10, a day after the rescans: the index's assertion map matched the render on 9,460
  of 9,460 documents (no engine missing, no verdict differing), while `detections.total`
  matched the render's definite count on 33%, short by a median of 2 and by up to 12. The
  first read, within the hour on 2026-11-09, had taken that shortfall (15 assertions, 3–6
  definite) for a pre-reveal document; it was not. The document is a faithful copy of
  Postgres; Postgres's own count is what is short, and the render carries the assertions
  themselves. A failed POST (`not_submitted`), a render the API cannot find
  (`missing_render`), a failed scan (`failed`), an open window (`pending`) and a scan with no
  assertions are counted per band and left out; `collect` is re-run until the pending ones
  close. The render also keys engines by id, which removes the name-keyed deviation for the
  cohort.
- **What downstream sees** is a base in 01a's shape (`label_instance_number` = the forced
  instance, `label_gap` = the file's age at the rescan, `scan_config` null, `provenance`
  `unknown`, plus `label_polyscore`) with its assertions long-form (`author` = engine id,
  `author_name` beside it, `verdict`, `bid` as int64 NCT-wei like 01a's, `mask`,
  `malware_family`, `scanner_version` when rendered; `label_moment` naive UTC and
  `scan_config` a null string column, again as 01a writes them, because 04 onwards take the
  column types as given) and a run cohort in 01b's shape carrying the base columns and the draw's, so
  `02_compose` onwards run unchanged; `08_calibrate` needs `--provisional` because no row is a
  customer row.
- **What a POST can fail with, measured.** A `400` for a file above the account's artifact size
  cap (`Artifact size too large`, limit 33,554,432 bytes), which is why the cap is a frame
  rule above: 116 of the 94,348 scanned-first files in the window are over it (0.12%), and the
  first draw, made before the rule, had 31 of them; and a transient network error (`No route to
  host`), recorded with no HTTP status and re-POSTed by `submit --retry-errors` once the run
  is through. A failed POST never retries blind during the run (a second rescan is the cost of
  guessing wrong).
- **Order and pace.** Submissions go out in a seeded permutation at about one a second,
  against a baseline of about five scans a second platform-wide; a run cut short is a
  random subsample of every band.
- **Topping up.** The draw is the head of a fixed per-band permutation keyed by
  `(sha256, seed)`, so re-running `draw` after a frame rule tightens reproduces every file
  still in frame, in its band, and appends the next in order to fill the quota; `submit`
  skips what the log already holds and `collect` re-reads only what is missing. A
  replacement's label gap is its own age at its rescan, so a top-up made days later carries
  a slightly longer gap, which the base records per row. A top-up that must leave the
  earlier run's outputs standing is drawn as a new run, `draw --continues <run>`: the draw
  exits unless every file the earlier run drew and that is still in frame is drawn again in
  its band, and it seeds the new run's `rescans.jsonl` and `renders.jsonl` with the earlier
  run's records of those files, so `submit` posts the new files only.

**Run `forced-a`, 2026-11-09, topped up 2026-11-10.** Drawn 9,500 from the two post-fix
slices (`a1` + `a0`, π_base = 1/128): contested 4,500, leaning malicious 1,500, leaning clean
1,500, consensus malicious 1,000, consensus clean 1,000; no band under-filled. Submitted at
one a second over 2 h 57 min: 9,444 accepted on the first pass, 25 transient network failures
accepted on the retry, 31 refused with `400` for files over the size cap. The cap then became
the frame rule above; the re-draw under it kept the 9,469 files in their bands and appended 31
replacements (15 contested, 8 consensus clean, 8 leaning clean), rescanned the next day. Every
forced window closed within a minute of its POST; the renders were read back in passes behind
the submission at three a second, about 19,000 calls in all.

Collected: 9,500 labelled, 288,274 assertion rows. Label gap p10 37.7, p50 53.7, p90 59.9,
max 63.0 days; 13 definite verdicts at the label scan (p50) against 14 at T, from the same 16
answering engines. Re-banded from the render's counts the base is contested 48.0%, leaning
malicious 15.9%, leaning clean 16.2%, consensus malicious 11.4%, consensus clean 8.5%: the
frozen `detections` of deviation 5 is short on 2,550 files, which moves 196 out of consensus
clean. Engine-level change from T to the label scan: 11,226 flips (276 retractions), 3,609
joined, 19,813 left, 121,200 stable; 6,888 files with at least one flip. Provisional labels
([0011](../decisions/0011-provisional-pilot-rules.md)): 5,718 trainable of 9,500 (4,798
malicious, 920 benign), 3,664 undecidable by weak consensus, 753 by no detection, 117
unwanted; the contested band resolved 2,394 malicious, 19 benign, 1,998 undecidable.
Prevalence among trainable 0.84 raw, 0.976 reweighted by 1/π; the three draw checks pass on
the design π. Outputs: `data/base/forced_forced-a.parquet` (+ assertions),
`data/runs/forced-a/{cohort,labels}.parquet`,
`data/reports/composition_forced_forced-a_forced-a.txt`; the pre-rule draw is kept beside the
run as `draw.v1.parquet`.

**Stages 04 to 08 on `forced-a`, 2026-11-10.** 18 engines, 53 new-encoding and 18
old-encoding columns, no static block. The temporal split (SS5: 60/15/25 by scoring moment,
a 30-day gap, family groups cut whole) has **no test fold**: the window is one month, so
`test_not_before` falls after its end, 1,671 trainable rows sit in the gap, and train is
3,430 with validate 617; only the random grouped split, the optimistic one, has a test fold
(1,012). **Baseline 3, the malicious-engine count at T, scores 0.999 AUC on validate**
(incumbent PolyScore 0.994), which is estimand §8's stop: the provisional label restates the
T band. Of the 920 benign labels 896 were below 0.1 at T and none above 0.4; of the 4,798
malicious labels 34 were below 0.1 at T. The contested band at T (4,573 files) is still
contested at the label scan for 3,890 of them, where [0011](../decisions/0011-provisional-pilot-rules.md)
labels 1,802 malicious on specific families and 2,015 undecidable; 133 went clean, of which
24 are benign and 109 undecidable. The 3,664 undecidable rows are where the question lives.
Every later number (models at 0.991 to 1.000 AUC, the provisional calibrators) is an
artefact of that label and measures nothing; stage 09 was not run. The label rule became
[0016](../decisions/0016-convergence-label-and-within-band-gate.md); the rerun under it
follows.

**Stages 03 to 08 on `forced-a` under 0016, 2026-11-12.** The movement rule labels 9,475 of
9,500: malicious 2,861 (`consensus` 1,656, `grew` 1,205), benign 6,614 (`stayed_contested`
5,279 — provisional —, `stayed_clean` 1,333, `fell` 2), unwanted 20, undecidable 5
(`thin_clean`); 1,326 files grew by 0.15 or more and 630 crossed 0.5. By the band at T:
clean 2,334 with 689 positives, contested 4,573 with 667, leaning malicious 1,508 with
472, consensus malicious 1,085 with 1,033. The temporal split now holds train 5,680 and
validate 1,118 (2,677 in the gap, test still empty), with the prevalence shifting from 0.42
in train to 0.20 in validate: the positives sit early in the window — 23% of the contested
files first scanned in the week of September 7 grew, 3% of those in the week of October 5
— and two scans cannot say whether that is the horizon (62 days against 33) or a
calendar effect; the T+90 and T+180 panel can. **Baseline 3 within band, read on
train + validate: clean 0.673, contested 0.577, leaning malicious 0.625, consensus
malicious 0.975** — every gated band in §8's proceed range, and the whole-cohort numbers
reproduce 0016's table (0.727 / 0.581 / 0.589). On validate alone the count reads 0.487,
0.362 and 0.586, the contested band *inverted*: its 751 rows are 106 family groups and three
of them hold more than half, which is why the gate reads the larger frame. The coverage
probe holds the clean band out (0.816; contested 0.669, leaning 0.693). The models on
validate, per band (clean / contested / leaning malicious): (a) 0.392 / 0.701 / 0.662, (b)
0.472 / 0.729 / 0.763, (c) 0.547 / 0.716 / 0.795, (b_verdicts) 0.397 / 0.731 / 0.757,
(b_random) 0.878 / 0.800 / 0.840. **In the contested band the models beat the count by
0.35 on the same frame** (0.73 against 0.36; 0.15 against the train + validate reading),
which is the proceed condition up to the noise band §11's stability runs have not yet
measured; the leaning band says the same on 61 rows; the clean band's number is not quoted
(held out, and validate holds 9 positives there). Pooled, every model still prints 0.98:
the consensus bands own it, as 0016 said. Two defects surfaced on the way and are fixed in
the stages: the logistic fits ran unscaled over the bid columns (10^15 NCT base units)
and had collapsed to a constant — under 0011's labels that still read 0.99 pooled — and
the gate's frame had been validate alone. Stage 09 is not run: the temporal test fold is
empty. Outputs: `data/runs/forced-a/{labels,features}.parquet`, `splits/`,
`reports/baselines.{txt,json}`, `models/`; the 0011 outputs were not kept.

**The noise band on `forced-a`, 2026-11-12** (`07b_noise_band.py`, 5 repeats × 5
family-grouped, label-stratified folds over the 9,475 trainable rows in 2,410 groups; (b)
at C = 0.1, (c) at 15 leaves × 100 trees, refit per fold). Per band, the per-repeat AUC on
the out-of-fold scores, mean (min..max): **contested** — count 0.581, (b) 0.701
(0.640..0.728), (c) 0.860 (0.840..0.869); gap over the count +0.120 for (b), worst repeat
+0.058, and +0.278 for (c), worst +0.259: **both clear**. Leaning malicious — count 0.589,
(b) 0.846 (0.843..0.852), (c) 0.926 (0.917..0.933): both clear. Clean — count 0.727, (b)
0.822, (c) 0.788: clear, and held out by the coverage probe all the same. Consensus
malicious — 0.970 / 0.971 / 0.988, reported. The per-artifact ranking barely moves between
repeats (Spearman 0.97 for both models). **The fold-level swing is the finding beside
it**: a single fold of about 1,900 rows reads the contested count anywhere from 0.151 to
0.706 and (c) from 0.712 to 0.901, which is the variance the 1,118-row validate fold
inherited when it read the count at 0.362. Two readings of the same rule therefore sit on
the record: the time-honest temporal split, where (b) and (c) tie near 0.72 in the
contested band, and the time-mixed cross-validation, where (c) reaches 0.86 and (b) 0.70
— the trees' extra lead is partly calendar structure the temporal split refuses, the same
optimism (b_random) prices. The gate reads the temporal number for the level and the
cross-validation for the band; §8's proceed condition holds on both.

**The gold slice drawn, 2026-11-12** (`03b_gold_draw.py`, seed 20260922, from the contested
band at T): 100 of the 667 files whose detections accrued (`grew` 76, `consensus` 24;
`π_gold` 0.1499) and 100 of the 3,749 that stayed contested (`π_gold` 0.0267), the overall
inclusion probability the product with the cohort's `π` (0.049–0.099 and 0.0088–0.0102).
Horizon at the label scan 33 to 62 days, median 57; the two groups sit at the same level at
T (median `m_t` 0.29 and 0.25) and differ in movement (median `Δm` +0.17 and +0.08). The
adjudicator reads `data/gold/forced-a/review.csv` — hash, portal link, empty verdict
columns, shuffled, no group — against estimand §3; `draw.parquet` beside it holds the
groups and probabilities for the import step. Kyle Buchmiller leads the adjudication; the
written rubric and the grade-3 import are the next change.

## Memory images are out of frame

Decision [0017](../decisions/0017-memory-images-are-not-training-material.md). A memory
image is a PE file written out of a running process: its sections sit at their mapped
sizes, its image base is the address the loader chose and its import slots hold addresses.
A sandbox submits one per process and per run, so one build arrives as hundreds of files
that differ in a load address and a few bytes of data. They are not training material. A
near-identical variant of a program that was submitted as a file is, and stays as a row of
its own.

**The rule** is a frame rule of stage 00b, applied before the draw like the size cap, so
`pi` is over the files that remain. `static` reads nine index fields for every frame file
(`artifact.{sha256, size}`, `pefile.sections.{raw_size, virtual_size, virtual_address}`,
`pefile.is_dll`, `lief.entrypoint`, `exiftool.{entrypoint, petype}`), 50 files a query
through `/v3/search/metadata/query`, one cached JSONL line per file, and
`memory_image.classify` gives each file the first reason that applies:

| Reason | The test | Pilot month, of 94,232 |
|---|---|---|
| `memory_layout` | every section that has bytes has `raw_size == virtual_size`, and either a raw size is off the 512-byte grid or the file ends exactly where the image does | 11,870 |
| `runtime_base_64` | image base at or above `0x7FF000000000`, where 64-bit Windows loads images and no linker points; the base is `lief.entrypoint − exiftool.entrypoint` | 100 |
| `relocated_exe_32` | a `PE32` EXE whose base is neither `0x400000` nor `0x10000000` | 864 |
| `confirmed_from_bytes` | named in `--confirmed-memory-images`, the findings of a byte-level check | 3 |
| `no_index_record` | the index returned no document for the hash | 0 |

A file the analyzers could not lay out stays: the rule acts on evidence and never on a
missing field (of the files that stay, 241 have no sections recorded, 2,826 a layout that
is neither kind, and 200 no image base). `draw` exits when the static table does not cover
the frame, and its manifest counts what the rule removed by reason and by band at T.

**Why every frame file is read, and not only the ones the draw reaches.** Skipping memory
images on the way down the permutation draws the same files and needs the fields of about
a fifth of the frame. It also leaves `n_available` unknown in any band that fills before
its end, and `pi_draw = n_draw / n_available` is the column no later stage can rebuild
(estimand §9). The full read is 1,885 index queries and 21 minutes for the pilot month and
bills no scan. A frame much larger than this one would want the walk, with `n_available`
estimated from the share that passes and the error of that estimate recorded.

**Checked against the bytes.** On the 200 gold-slice files of `forced-a`, read by DN-8811's
prototype (LIEF, cross-checked with pefile), the index rule removes 136, every one a memory
image by its bytes (130 by layout, 6 as relocated 32-bit EXEs), and none of the 45 files
confirmed as built. Of the 64 it passes, 45 are confirmed as built, 16 give no verdict
either way, and 3 are memory images saved back into file layout at a default base, which no
index field shows. Those three are out by name:
`data/forced/forced-b/confirmed_memory_images.txt` lists all 139. On `forced-a`'s cohort
the rule reproduces the measurement behind 0017 file for file (4,617 of 9,500 out).

**What the rule misses, and what it removes with them.** It is a floor: 3 of 64 passing
files is about one kept contested row in twenty still a memory image, all three 32-bit. A
byte-level pass over the 32-bit files of the draw would close it (4,770 files and 13.4 GB
in `forced-b`) and is open in [99](./99-open-questions.md). And `relocated_exe_32` takes
some files as built with the dumps: a 32-bit EXE linked at a custom base cannot be told
from a relocated one in the index (864 frame files, 0.9%). The analyzer tag of DN-8811,
which reads the import slots, replaces both compromises.

**Where they sit.** Memory images are 14% of the pilot month's frame and were 49% of
`forced-a`'s draw, because the draw over-samples the bands they arrive in: 7,656 of the
11,799 frame files contested at T (65%), 3,062 of 4,550 leaning clean (67%), 909 of 2,280
leaning malicious (40%), 1,077 of 73,245 consensus malicious (1.5%) and 86 of 2,139
consensus clean (4%).

**Run `forced-b`, 2026-11-18: `forced-a` topped up under the rule.** `static` read the
94,232 frame files and every hash had a document. `draw --continues forced-a` left 12,837
memory images out and drew 9,002 files from the 81,395 that stay: contested 4,143 of a
4,500 quota, leaning malicious 1,371 of 1,500 and leaning clean 1,488 of 1,500, each band
taken whole (`pi_draw` = 1) and under-filled; consensus malicious 1,000 of 72,168
(`pi_draw` 0.0139) and consensus clean 1,000 of 2,053 (0.487). Of `forced-a`'s 9,500 files
4,880 are drawn again, each in its band, with its rescan record and renders carried over;
4,620 are gone (4,313 by layout, 269 relocated 32-bit EXEs, 35 by a 64-bit run-time base,
3 by name). The 4,122 replacements (contested 2,564, leaning clean 1,034, leaning
malicious 470, consensus clean 38, consensus malicious 16) were 42 to 72 days old at the
draw, median 56.5. They were rescanned that evening at one a second (2026-11-19 02:50 to
04:04 UTC): 4,120 accepted on the first pass, 2 timed out and, their scan histories showing
no new scan, were accepted on a retry. **4,122 rescans, one per replacement.** The renders
were read back in two passes behind the submission, 8,247 calls. Collected: 9,002 labelled
of 9,002, 274,426 assertion rows; label gap p10 37.8, p50 51.5, p90 66.4, max 72.1 days,
the replacements' gap running nine days longer than that of the rows they join; 13 definite
verdicts at the label scan (p50) against 14 at T. Outputs: `data/forced/forced-b/`,
`data/base/forced_forced-b.parquet` (+ assertions), `data/runs/forced-b/`. Run `forced-a`
and its gold slice are untouched.

**Stages 02 to 08 on `forced-b`, 2026-11-18.** 8,952 of the 9,002 rows are trainable under
0016. The label counts by band are left out of this section while the gold slice of
`forced-a` is under blind adjudication; they are in `data/runs/forced-b/labels.report.txt`.
The temporal split holds train 5,371 and validate 1,343, with 2,238 rows in the gap and no
test fold, as before. Baseline 3 within band on train + validate: clean 0.584, contested
0.667, leaning malicious 0.524, consensus malicious 0.966, every gated band in §8's proceed
range. The coverage probe holds no band out (clean 0.637, contested 0.700, leaning
malicious 0.621); on `forced-a` it held the clean band out at 0.816. The models on validate,
per band (clean / contested / leaning malicious): (a) 0.507 / 0.759 / 0.861, (b) 0.554 /
0.787 / 0.882, (c) 0.567 / 0.887 / 0.874, (b_verdicts) 0.494 / 0.769 / 0.873, (b_random)
0.734 / 0.851 / 0.921, against the count's 0.537 / 0.640 / 0.520 on the same rows.

**The noise band on `forced-b`** (5 repeats × 5 family-grouped folds over the 8,952
trainable rows in 3,184 groups; (b) at C = 0.01, (c) at 7 leaves × 300 trees). Contested:
count 0.684, (b) 0.833 (0.824..0.836), (c) 0.862 (0.852..0.873); gap over the count +0.149
for (b), worst repeat +0.140, and +0.178 for (c), worst +0.168: **both clear**. Leaning
malicious: count 0.533, (b) 0.888, (c) 0.893: both clear. Clean: count 0.576, (b) 0.566,
which does not clear, and (c) 0.710, which does. Consensus malicious: 0.961 / 0.981 / 0.985,
reported. Against `forced-a`, where memory images were half the rows, the count rises from
0.581 to 0.684 and (b) from 0.701 to 0.833, and (c) is where it was (0.860, 0.862).

**The same comparison with the copies of a program held together** (outside the pipeline:
`~/dn-7927-pilot-scratch/forced_b_compare.py`, with stage 07b's fitting code; a program is
the files that share a largest section and size, joined by fuzzy hash within 30). The 8,952
trainable rows are 4,159 programs, 3,738 of them single files, and the ten largest hold
2,717 rows: variants of files as built cluster too. Folds grouped by program, contested:
(b) 0.840 and (c) 0.874, gaps +0.156 and +0.190. One row per program, 1,705 contested rows:
count 0.642, (b) 0.747, (c) 0.823, gaps +0.105 and +0.181. Bootstrap by program: (b)
+0.157, 95% interval +0.088 to +0.191; (c) +0.194, +0.161 to +0.230. **The lead does not
come from copies split across folds.** The temporal split still groups by 0011's stand-in
key and leaves 41% of the contested validate rows with a twin program in train.

## The injection arm (`pipeline/00c_inject_known_good.py`)

Decision [0015](../decisions/0015-injection-arm-from-the-index-authenticode-and-virustotal.md).
The index carries the lief analyzer's Authenticode result on every PE scan since DN-8374
(`lief.signature_tags`, `lief.signer.{common_name, organization, sha1, sha256}`,
`lief.signatures.certificates.{subject, is_ca, sha256, valid_to}`,
`lief.signatures.chain_of_trust.chain_flags`), all mapped and queryable through
`/v3/search/metadata/query`, though the search response does not render the `lief`
subtree — the full instance render does, under `metadata[].tool == 'lief'`. The arm is a
prefix slice of that: scanned-first PE files whose first scan has verdicts, `verified` among
the tags, signer organization `Microsoft Corporation`. The candidate order is hardest-first
(flagged by an engine at T), then a seeded permutation.

**What `verified` means, and what it does not.** The tag says the file's digest matches
the signed digest and the signer's signature checks against the embedded leaf certificate.
The analyzer pins no CA bundle, so a self-made chain passes too, and its `chain_of_trust`
checks validity dates *now*, so a timestamped Windows binary whose leaf has expired carries
neither `chain-verified` nor `chain-broken` (`expired-at-scan` and `counter-signed` instead).
Trust therefore comes from two independent checks, both required: VirusTotal's sigcheck
verdict on the hash (`signature_info.verified == "Signed"`, trust anchor named
`Microsoft Root …`, validated against the Windows trust store) and, on our side, `verified`
without `chain-broken`, the Microsoft signer, and a **pinned Microsoft CA** in the embedded
chain — a CA certificate seen in at least five chains that passed every other check, so
that one file cannot vouch for its own issuer. The pinned certificates are listed in the
arm's manifest (`pinned_cas`). VirusTotal's `known_distributors` and `trusted_verdict`
markers are recorded, not required: both were absent on a genuine Windows DLL.
**Nothing but the signature attestation is read from VirusTotal**: no detection count, no
verdict, no engine result is stored or used (`03-labels.md` puts aggregator verdicts at
grade 1; the arm's label is grade 2 by the modality of code signing).

**Measured 2026-11-10** on a 1/256 slice of scanned-first PE files with verdicts (all first
scanned in 2026, the analyzer being that new): 71 verified with a Microsoft signer
(~18,000 platform-wide; 8 flagged by an engine at T), 669 verified with any signer
(~171,000; 322 flagged). The first "Microsoft" candidate examined was signed by "Inspect
Element Ltd" on an untrusted root — our query matched it, VirusTotal rejected it. The
platform's own known-good catalogue is not a source: three catalogued PE documents on the
same slice, all `commercial`, one with a real scan; a catalogued hash is declined at
submission and blocked from rescans (artifact-index `specs/05-known-good.md`).

**What the arm's rows carry.** Base rows in 01a's shape with `provenance` and `stratum`
`injected_known_good`, the T scan's counts from the render, no label scan
(`label_instance_number`, `label_moment`, `label_gap`, `label_polyscore` null), `pi` NaN;
assertions in the `feature` role only. The run file is `data/runs/<run>/injected.parquet`,
beside the cohort and not merged into it: every stage from 02 on weights by `1/pi`, and
admitting the arm — an attested branch in 03, the injected-vs-organic probe in 06, NaN-safe
weights — is the change recorded in [`99`](./99-open-questions.md). The quota: 500
VirusTotal lookups a day and 240 an hour on the key in use, so `confirm` runs in daily
slices and resumes.

**Run `forced-a`, 2026-11-10.** Prefix `a` (1/16): 1,291 candidates in frame, 129 flagged
at T; 600 carried into `confirm`, 129 flagged first. `confirm` fetched 480 renders and made
480 VirusTotal lookups at 230 an hour (the day's quota; 120 candidates wait for the next
slice). `collect`: **384 trusted**, 50 `vt_not_signed`, 41 `vt_unknown`, 4
`chain_unpinned`, 1 `ours_failed`, 120 `not_confirmed`. The VirusTotal step did real
work: the 50 it rejected all pass our query, and sigcheck names the reason — 38 chains
"terminated in a root certificate which is not trusted by the trust provider", 5 "could
not be built to a trusted root authority", 7 carry no verdict; their anchors are the leaf
alone (20), "Microsoft Development Root Certificate Authority 2014" (11) and build-stamped
test signers — and 35 of the 50 were flagged by an engine at T, against 86 of the 384
trusted. The 41 unknown are files VirusTotal has never seen (8 flagged). The 4 unpinned
chain through the original "Microsoft Code Signing PCA" to the 1997 "Microsoft Root
Authority" or through the Windows Phone 2012 CA, each seen in one to three chains; the 1
`ours_failed` render carries no lief signature data at all. **Pinned CAs, 11:** Microsoft
Code Signing PCA 2024 (219 chains), Microsoft Code Signing PCA 2011 (83), Microsoft Windows
Code Signing PCA 2024 (52), Microsoft Windows Production PCA 2011 (16), Windows Production
PCA 2023 (12), Microsoft Windows Production PCA 2026 RSA2048-SHA256 (11), Microsoft Windows
Third Party Component CA 2014 (9), Microsoft Code Signing PCA 2010 (9), Microsoft Code
Signing PCA (5), Microsoft Windows Third Party Component CA 2013 (5), Microsoft Time-Stamp
PCA (5; a counter-signature CA that `_ms_ca_certs` does not tell from a signing CA — no
trusted row rests on it alone). **The trusted 384:** signer CN "Microsoft Corporation"
169, ".NET" 169, "Microsoft Windows" 27, the hardware and software compatibility
publishers 13, six others; first seen on VirusTotal 2013-01 to 2026-11, 304 of them in
2026; VirusTotal's known-distributor marker on 33, its trusted verdict on 4. At T: 12 to
15 definite verdicts (p10 to p90), 261 with no malicious verdict, 113 with one, 10 with
two. Note that 123 trusted rows carry a malicious assertion in the full render where the
search document's `first_scan.detections.malicious` is above zero for 86: the summary
undercounts the render by 37 files here — DN-8723, `detections` computed once at reveal
from an incomplete assertion set — and `flagged_at_t` reads the summary. Outputs:
`data/base/injected_forced-a.parquet` (384 rows, 6,236 assertion rows),
`data/runs/forced-a/injected.parquet`, `data/injected/forced-a/{confirm.parquet,
collect.report.txt}`. Short of the 500 planned: the 120 waiting candidates yield about 96
at this trust rate, so a 500-row arm needs a larger draw from the same frame.

## Relation to the other sources

| | SQL path (09) | API slice (this) | Exporter (DN-8712) |
|---|---|---|---|
| Needs | cluster access | an API key | the exporter shipped |
| Frame | complete, by `completed` | sampled, by first scan | complete, by `created` |
| Labels | nearest later scan | forced rescan at T + age (0014) | nearest later scan (local join) |
| Engine identity | id | name | id |
| Provenance | yes | no | yes |
| Fit for | the full window | the pilot, now | the full window, repeatably |
