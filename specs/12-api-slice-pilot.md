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
  removed) and not a memory image (§ Memory images are out of frame: `bytes` reads the
  files the draw needs, `draw` passes over the memory images and its manifest counts them
  by tell and by band at T). `pi_base` is the sum of the slices' inclusion probabilities
  (disjoint prefixes, so the union is a sample too); the draw's `pi_draw` comes from
  `screened_draw`, the share of each band it read, so a file the route would refuse or a
  memory image is never drawn. The run cohort's `pi` is the **realized** share per
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
  run's records of those files, so `submit` posts the new files only. When the slices
  cannot fill a band, `--top-up-slice` adds a slice of the same window that is read only
  after them (§ The walk, and a top-up slice).

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

Decisions [0017](../decisions/0017-memory-images-are-not-training-material.md) (they are not
training material) and [0018](../decisions/0018-memory-images-are-told-from-the-bytes.md) (how
they are told). A memory image is a PE file written out of a running process: its sections
sit at their mapped sizes, its image base is the address the loader chose and its import
slots hold addresses. A sandbox submits one per process and per run, so one build arrives
as hundreds of files that differ in a load address and a few bytes of data. They are not
training material. A near-identical variant of a program that was submitted as a file is,
and stays as a row of its own.

**The rule** is a frame rule of stage 00b, applied in the draw like the size cap, so `pi` is
over the files that remain. Whether a file is a memory image is read from the file's own
bytes. `bytes` gets every file the draw needs, from a sample directory or else through
`/v3/consumer/download/sha256/<hash>`, and `image_bytes.read` turns the bytes into facts: one
cached JSONL line per file, keyed by the sha256 of the reader's source, so a changed rule
reads every file again. `image_bytes.verdicts` gives each examined file one verdict:

| Verdict | When | Frame |
|---|---|---|
| `memory-image` | the file shows at least one tell of § Bytes decide, or is on the reviewed list | out |
| `as-built` | no tell, and positive evidence that the bytes are as the linker left them | stays |
| `no-evidence` | neither | stays |
| `not-pe` | the reader does not take the bytes for a PE image, though the index did | stays |

A file whose bytes cannot be had is out as well (`no_bytes`): it cannot be shown to stay. The
rule acts on evidence and never on its absence, so a file that shows nothing stays. The
reader is `struct` and nothing else: no parser library, and nothing is executed. The
downloads are live samples, kept read-only in a directory outside the repo (`--samples`),
and a file already there is not fetched again.

### Bytes decide

Loading a program leaves traces a linker never writes, and so does the tool that writes the
capture out. Any one tell makes a file a memory image. The counts are over the 27,293 frame
files examined for run `forced-c`, which was drawn under `image_bytes.RULES_VERSION` 9;
*alone* is the files that show no other tell. Version 13 gives every one of those files the
same verdict and the same tells. It reads one more fact, a signature's digest, and changes
only [what one file can say](#what-one-file-can-say).

| Tell | What the bytes show | Files | Alone |
|---|---|---|---|
| `imports-resolved` | more than half of the import slots hold the address of a loaded module, and in at least four in five of the descriptors that hold addresses these cluster as one module's exports do; or at least four addresses stand in tables that are resolved beyond doubt | 7,830 | 548 |
| `cookie-initialized` | the `/GS` security cookie is not the compiler's default and its complement sits beside it, as the C runtime leaves the pair at start-up | 392 | 3 |
| `module-addresses-in-data` | writable data holds addresses inside a module the file's own bound import table places, outside the address tables and far more than chance puts there | 1,907 | 1,906 |
| `relocations-other-base` | the values the relocation table points at miss the image at the header's base and fit it at one other base | 33 | 7 |
| `imagebase-runtime` | a 64-bit `ImageBase` at or above `0x7FF000000000`, where Windows 8.1 and later load images and no linker points | 13,093 | 8 |
| `imagebase-windows7-aslr` | a 64-bit EXE whose `ImageBase` is just below `0x100000000` or `0x140000000`, where Windows 7 puts a relocated EXE | 11 | 0 |
| `sections-memory-layout` | every section that has bytes is stored at its RVA and at no less than its virtual size, `FileAlignment` is below `SectionAlignment`, and no byte other than zero follows the sections | 13,375 | 35 |
| `content-memory-layout` | the content lies at the RVAs although the section table lists file offsets | 71 | 32 |
| `section-table-wiped` | the section table's rows are declared and every one is zero | 45 | 2 |
| `dump-tool-section` | a section named `.CAPE`, `.SCY` or `.mackt`, where CAPE, Scylla and ImpREC put the import table they rebuild | 188 | 0 |
| `imports-rebuilt` | an import table rebuilt in a section added at the end: every descriptor named and without a lookup table, every address table in another section, the slots ordinals or names in the added section | 310 | 2 |
| `section-size-is-address` | every section's virtual size holds the low 32 bits of `ImageBase + RVA`: one dump tool writes the address where the size belongs | 14 | 0 |
| `entry-below-image` | 32-bit, and `ImageBase + AddressOfEntryPoint` wraps past 4 GiB, so the entry address lies below the image: a tool that lost the entry point wrote it | 16 | 0 |
| `entry-not-stored` | the entry point lies in a section, past every byte the section table stores for it, in a file that holds every byte its table lists: a tool rebuilt the table around the bytes it had | 8 | 5 |
| `uninitialized-section-filled` | a section flagged as uninitialised data and nothing else, or the section named `UPX0` when the entry point lies in it, holds content with a byte entropy under 7.5: a packed program left unpacked | 561 | 20 |
| `exe-moved-unvouched` | a presumption, not a trace: below | 937 | 33 |
| `same-build-other-base` | compares files: below | 13,667 | 0 |
| `same-binding-other-addresses` | compares files: below | 4 | 4 |

By kind, memory images are 7,265 of the 11,518 64-bit EXEs examined, 6,149 of the 6,553
64-bit DLLs, 3,771 of the 8,325 32-bit EXEs and 124 of the 869 32-bit DLLs. The 17,300 files
the rules take are 1,067 builds, and five builds hold 13,670 of them.

**A base counts only when the loader could have written it**: not zero, a multiple of
64 KiB, and below where user space ends (`0x7FFF0000`, or `0x7FFFFFFF0000` for 64-bit). The
two base tells, the relocation tell and the presumption all need that.

**How the import tables are read.** The directory is walked as the loader walks it,
whatever its `Size` says: one descriptor after another up to the first that names no DLL or
has no address table. A slot is an address when it lies in user space, above the image's
own RVAs and outside the image. It is untouched when it equals its lookup-table entry or,
where one table does both jobs, when it is an ordinal or the RVA of a name.

- A descriptor that leads to no readable table voids the whole directory. Those bytes are
  packed data or another file's content, and nothing read from them counts.
- A descriptor with a time stamp whose slots hold addresses is *bound*. A binder writes
  addresses too, so such a table cannot say who wrote it and is left out. The exception is
  a 64-bit address at or above `0x7FF000000000`, which only the loader hands out.
- A descriptor whose DLL name was erased counts only when its table is at least four slots
  that are nothing but one module's distinct addresses.
- A table is *resolved beyond doubt* when its descriptor is named and has no time stamp,
  its lookup table holds nothing but ordinals and readable names, and its slots hold
  nothing but one module's addresses. Four such addresses make the tell whatever the other
  tables hold: a tool that adds imports to a file writes slots that would outvote the
  loader's. 30 files show the tell this way only.
- With no descriptor left and no bound-import directory, the address-table directory is
  read as zero-separated runs. It counts when it holds at least eight addresses and every
  run is one module's.
- When no directory leads to a descriptor at all, the descriptors are searched for: a
  module name (`.dll`, `.drv`, `.ocx`, `.exe`, `.sys`, `.cpl`) whose RVA stands in the
  fourth field of a descriptor in the name's own section. A capture can lose its directory
  and keep its tables; only tables resolved beyond doubt count there.
- The lookup table sets the slot count, so a blanked address table, a decoy the loader
  skips, shows its slots and is not resolved.
- A walk that reads more than 131,072 words is dropped: no program imports that many, and
  a crafted directory could otherwise cost seconds.

**A rebuilt import table** is the work of a dump tool that could not keep the original:
the directory sits in the last section (a trailing `.reloc` aside), every descriptor is
named and has no lookup table, every address table lies in another section, and of four or
more slots at least nine in ten are ordinals or RVAs into the directory's own section. A
linker puts the names beside the tables; 302 of the 310 files also show a dump tool's
section or an unpacked packer section, and none has a certificate or a valid checksum.

**Module addresses in data.** A named descriptor with a time stamp and a forwarder chain
of `0xFFFFFFFF` or a slot index is bound, and its addresses say where the module stood for
the binder. The module's span is the longest run of those addresses whose neighbours lie
under 1 MiB apart, when the run holds at least four addresses and three quarters of the
table and is at most 16 MiB wide. The tell is at least five distinct aligned words in the
writable sections that fall in a span, outside the address tables and not text, and at
least 16 times as many as chance gives. A program writes a library's addresses into its
data only while it runs. The tell rests on few programs here: the 1,907 files are 22
builds, and two builds of one Visual Basic 6 program hold 1,814.

**Relocation targets.** The first 4,096 entries of the relocation table are followed to
the values they point at (`HIGHLOW`, and `DIR64` in a 64-bit file). A linker writes each
for the header's base. The tell needs at least eight values read, fewer than a fifth of
them inside the image at the header's base, and at least four in five inside one span of
the image's size, rounded up to 64 KiB, that starts on another 64 KiB boundary. Values
below the image's size are RVAs or nothing and are left out. Values that merely miss the
image do not make it: one build keeps encoded values in its relocation slots.

**Content at the RVAs** is shown in one of two ways. A section begins where bytes follow 32
zero bytes: among the sections whose RVA and file offset differ, at least two and at least
three in five begin at their RVA and at most one in three at their file offset, an offset
that is one section's RVA and another's file offset counting for neither. Or the import
directory names every DLL and holds no unexplained slot only when RVAs are taken as file
offsets. When either holds, or the section table is wiped, every RVA is read as a file
offset for the imports and the cookie.

**The entry point where the file stores nothing.** The loader fills a section past its
stored bytes with zeros, so a program whose entry point lies there cannot start from the
file. A tool that writes out the sections it could read, and trims the ones it found
empty, leaves exactly that under a section table it rewrote to match. The tell needs the
table to fit the file (every row read, no stored byte past the file's end): a file cut
short lists bytes it no longer has and says nothing, and 92 examined files are cut short
of their entry point. It also needs `SectionAlignment` of a page or more, because below
that the loader maps the file in one piece, and neither a TLS directory nor a managed-code
header in stored bytes, because a TLS callback or the runtime starts such a program
without the entry point. Three of the eight files are memory images by another tell, two
of them by resolved imports; no file with the tell shows evidence of a file as built.

**The cookie** is reached through the load configuration. A 64-bit file without a readable
one is searched in its writable sections for an 8-byte value beside its complement, with
the top 16 bits clear, other than the compiler's default, and with at least 12 bit flips
in its low 47 bits: a random number, not a constant.

**The presumption.** `exe-moved-unvouched` is a 32-bit EXE whose header asks the loader to
choose its address (`DYNAMIC_BASE` and a relocation table) at a base that is neither
`0x400000` nor a multiple of 16 MiB, with no certificate in the file and no valid
checksum. A linker can be told to use another base, so this is not a trace. But 897 of the
937 files that show it also show a trace, and the tells that compare files confirm 7 of
the other 40, so the remaining 33 are presumed loaded: a screen that must keep memory
images out takes them, and loses a few files as built with them. A round base is one
somebody gave the linker: of the 19 examined files that ask for a load address at
`0x1000000`, `0x30000000`, `0x2E000000` or `0x1D000000`, 14 are files as built, system
programs among them, and the 5 that are not show a trace. A valid checksum keeps one more
examined file out of the presumption, at `0x4AD00000`.

**The tells that compare files.** A *build* is the files that share machine, link time
stamp, entry point, `SizeOfImage`, `SizeOfCode` and every section's name, RVA, virtual size
and flags. `same-build-other-base`: a build present at two or more image bases other than
the linkers' four defaults (`0x400000`, `0x10000000`, `0x140000000`, `0x180000000`) was
relocated at load, and every copy off a default base is a memory image.
`same-binding-other-addresses`: copies of a build whose bound import tables carry the same
DLL time stamps and different addresses had those addresses written at load, since a binder
gives one DLL one set. Both pass over a file that a certificate or a valid checksum vouches
for; no examined file is kept by that. They are applied to all examined files together, so
they find more as more files are read, and a verdict that rests on one of them alone (4
files) is not a property of the file by itself.

**Evidence of a file as built** is reported and never set against a tell:
`imports-unresolved` (every slot untouched), `cookie-default`, `overlay` (a byte other
than zero after the last section: zeros there are padding), `certificate-in-file` (the
security directory points at a certificate entry inside the file),
`signature-digest-matches` (a digest that entry names is the Authenticode hash of the
file's own bytes) and `checksum-valid`.
The first two say nothing for a 32-bit EXE at a base the presumption looks at. None outweighs
a tell: a capture can carry each of them but a matching digest, and no examined file shows
a matching digest beside a tell. Of the 17,309 memory images 7,224 still
show untouched imports and 6,874 a default cookie: the image was captured as it was
mapped, before the loader and the C runtime ran. 304 carry an overlay. 96 carry a valid
checksum, because dump tools recompute it: all 96 store their sections at their RVAs, and
every one of the 94 examined files in mapped layout with a valid checksum and nothing
after its sections is a dump, so a checksum does not clear the layout tell. No memory
image carries a certificate inside the file; 1,322 other files do.

**A certificate is not a signature over the file.** The Authenticode hash covers the file
without its checksum, its security directory entry and its certificate table. Verifiers
take it end to end or section by section, and the reader accepts either. Of the 1,322
files with a certificate table, 709 carry a digest that is the file's hash and 613 carry
one that is not: the table came from another program, or the bytes changed after signing.
LIEF's verifier gives the same answer on 1,318 of the 1,322 and reports a bad digest on all
613; on the other four the hash of the bytes end to end is a digest the table names. No
file with a matching digest shows a tell or is stored at its RVAs.

**The reviewed list** (`--reviewed`, a tab-separated `sha256` and `note`) holds files a
person examined and found to be memory images where no rule says so. A listed file is out
with the tell `reviewed`. The list lives with the run's data, because it names samples, and
the draw's manifest records its row count and content hash. Run `forced-c` lists nine:

- code relocated to an allocation address, with a table of system addresses the program
  resolved while running;
- a packer header over pages of other mapped modules;
- two files of one build with heap list pointers over the DOS header and heap addresses in
  the directory entries, and a third file with the same damage and heap data where its
  entry point is;
- a data section that holds one system-library address 71 times and about 75 heap
  pointers;
- two files of one build with heap memory where the last three sections should be;
- a managed program out of its packer: the packer's two sections hold no bytes, and the
  certificate entry points 70 KiB past the end of the file.

**Measured and not made rules**, because each takes files as built with the dumps, or has
no general form:

- zeros stored at the entry point: 84 examined files, 64 of them with no tell and 39 of
  those with evidence of a file as built;
- zero-filled gaps at the RVAs;
- runs of system-library addresses anywhere in a 32-bit file, or in its writable sections,
  with no bound table to say where the library is;
- three distinct 64-bit values in a row in the range the loader hands out: a protected
  file as built spells them in its instructions' displacements;
- heap pointers over the DOS header: seen on four files, too few for a rule, and those no
  tell takes are on the reviewed list;
- a 64-bit DLL base where Windows 7 loads DLLs (`0x7FE...`), which Microsoft's own DLLs are
  linked near and no examined file sits at;
- a checksum that does not match, and a debug-directory pointer that does not match;
- a certificate or a valid checksum set against the two base tells, which changes no
  examined file either way.
- whether the loader would start the file: sections it can map one after another, an entry
  point in stored, executable bytes that decode as plausible instructions up to the first
  call or jump, relocation targets at the header's base, and import tables that name every
  DLL and function. 14,167 of the 16,789 files the one-file label calls memory images pass
  all four, 634 of their 909 builds, against 8,675 of the 8,831 files as built. A capture
  is a program that was running, so its code, its relocations and its import names are
  real and agree with its header. The check tells a broken file from a loadable one, not a
  capture from a build. Decoding past the first call misreads a Visual Basic program, whose
  entry point is two instructions followed by data, so no rule decodes instructions.

**What the rule cannot see.**

- A capture taken before the loader ran and written back into file layout at its link-time
  base has every field a file as built has.
- A managed assembly rebuilt from memory into file layout: its code needs no relocation
  and it imports one function, so it carries no address. The one found is on the reviewed
  list, known by what its packer left behind.
- A 32-bit bound import table: below 2 GiB a binder's addresses and the loader's look
  alike. Addresses in data, or copies that disagree, give some away.
- A file made to be completed at load by another program would show `entry-not-stored`
  without being a capture. None is known among the eight.
- 575 examined files show no evidence either way, 524 of them drawn. Most are packed or
  hold no import table a reader can follow. They stay.
- Files read by hand and left in frame, because nothing in them was written at run time:
  five to which a tool added import sections, with no address in any slot and every
  relocation target at the header's base; a protected driver whose certificate entry
  points into a data section; and a driver whose discardable sections are zero under a
  valid checksum.
- An image stored at its RVAs with data after it is kept: 406 examined files with no tell,
  304 of them drawn. A packer's stub can be built in that layout with its payload after
  it, and a program can write its own image out that way to run again. Either is a file
  presented to run. See [What one file can say](#what-one-file-can-say).

### What one file can say

`image_bytes.single_file` gives one file a label by itself, with what decided it:
`memory-image`, `as-built` or `undecided`. It is what an analyzer that sees one file at a
time can apply (DN-8811).

**The label follows how the file is presented, not where its bytes came from.** A file
presented to be executed or re-executed is a file as built. That includes a capture a tool
rebuilt to load and a program that writes its own image out to run again, since either is
a way to make samples. A memory image is a capture left as captured. `undecided` is a
correct answer for any file, so evidence that is right most of the time is not let decide.

This is not the frame rule above. The frame rule asks where the bytes came from and takes
every capture out, rebuilt or not. The tells that compare files are left out here.

The tells are read as marks of three kinds:

- **Left by a running process**: `imports-resolved`, `cookie-initialized`,
  `module-addresses-in-data`, `relocations-other-base`, `content-memory-layout` and
  `section-table-wiped`. Neither a build nor a rebuild has them.
- **The form a capture is written in**: `imagebase-runtime` and `sections-memory-layout`.
- **Rebuilt to load**: `dump-tool-section` and `imports-rebuilt`. A tool made the imports
  loadable again, so the file is presented to run.

The label is:

- **`memory-image`**: a mark of the first or second kind, none of the third, and neither a
  valid checksum nor a signature over the file's bytes. Nothing was done to the capture.
- **`as-built`**: a sign, nothing a running process left, and no tell outside the three
  kinds; and either no capture mark at all, or a rebuilt import table on a file the loader
  could start. The signs are `imports-unresolved` and `cookie-default`, states that loading
  destroys, `signature-digest-matches`, and `checksum-valid`.
- **`undecided`**: every other file, and one not read as a PE.

What does not decide: an overlay, and a certificate whose digest is not the file's.
Unpacked content (`uninitialized-section-filled`) says the program ran its unpacker and
nothing about how the file is presented. A capture with a valid checksum or a matching
signature and no rebuilt import table is undecided: somebody finished the file, and nothing
shows it was made to load. The presumption and the tells of no kind (`section-size-is-address`,
`entry-below-image`, `entry-not-stored`, `imagebase-windows7-aslr`) keep a sign from
deciding.

**A rebuilt capture is as built only when nothing read keeps the loader from starting
it**: every import slot names what it imports (`imports-unresolved`), the file holds every
byte its section table lists, the entry point lies in bytes the file stores (the two entry
tells), and no other base holds a quarter as many relocation targets as the header's base
does. A rebuilt capture that fails one of these is undecided. All 292 rebuilt captures
labelled as built pass; the check is there for the files to come.

On the 27,293 examined files:

| Label | Files | Share | What they are |
|---|---|---|---|
| `memory-image` | 16,789 | 61.5% | captures left as captured |
| `as-built` | 8,831 | 32.4% | 8,142 with a sign and no mark, 397 stored at their RVAs with data after the image, 292 captures rebuilt to load |
| `undecided` | 1,673 | 6.1% | below |

The undecided are 831 files whose only evidence is an overlay, 585 with no evidence, 96
captures with a recomputed checksum, 51 with the presumption or a tell of no kind, 47
rebuilt captures that keep state a process left or show no sign, 28 not read as a PE, 21
with unpacked content and no other mark, 9 stored at their RVAs with data after the image
and no sign, and 5 with an overlay and a certificate whose digest is not the file's.
`forced-c`'s 9,500 files are 8,185 as built and 1,315 undecided: 757 with an overlay
alone, 524 with no evidence, 28 not read as a PE and 6 others.

**Checked against every other reading of these files**: the frame rule with its cross-file
tells, two independent reviews and the reviewed list. Those readings ask where the bytes
came from, so they differ from this label by design on the 292 rebuilt captures, 14 of
which the second review named. No file labelled a memory image is called anything else by
any of them. Two of the files labelled as built are on the reviewed list with nothing
rebuilt: process memory inside a file whose imports and cookie nothing touched. Those are
the 2 known wrong labels among 25,620, and no ground truth stands behind the readings.

**An image stored at its RVAs with data after it is a file as built when it shows a
sign**: 397 examined files, 303 of them drawn. No dump tool writes data after the image.
292 of the drawn files are copies of one worm: a UPX stub stored as mapped, its first
section all zeros, followed by 0.4 to 1.7 MB of data. A sample of the index shows the same
stub in file layout from 2023-11 and in mapped layout only from 2025-11, in growing
numbers. In other programs of the class the appended data is a list of executable paths
under several user names, a dated run log, or filler that grows from copy to copy. That
is a program writing its own image out to run again.

**A capture rebuilt to load is a file as built**: 292 examined files, none drawn, because
the frame rule takes them. 161 carry the CAPE sandbox's section, 120 an added section named
`.imports`, 8 one named `.pb`, and one each `.ap0x`, `.mackt` and a table rebuilt in
`.rsrc`; 282 hold unpacked content. The label says the file is in a form made to load and
that nothing read keeps the loader from starting it. It does not say the file runs: nothing
here is executed. The analyzer port (DN-8811) mirrors `single_file` at `RULES_VERSION` 13.
Whether a rebuilt capture that a sandbox wrote should count as one a person made is open in
[99](./99-open-questions.md).

### What the index fields say

`static` is a survey and the draw does not read it. It reads nine index fields for every
frame file (`artifact.{sha256, size}`, `pefile.sections.{raw_size, virtual_size,
virtual_address}`, `pefile.is_dll`, `lief.entrypoint`, `exiftool.{entrypoint, petype}`), 50
files a query through `/v3/search/metadata/query`, and `memory_image.classify` gives each
file the first reason that applies. Run `forced-b` was drawn under that rule. Read against
the bytes of the 23,994 files of the first two slices examined since, it is wrong in both
directions:

| Index reason | The test | Files | Memory images by bytes | As built | No evidence |
|---|---|---|---|---|---|
| `memory_layout` | every section that has bytes has `raw_size == virtual_size`, and either a raw size is off the 512-byte grid or the file ends exactly where the image does | 11,870 | 11,484 | 333 | 53 |
| `relocated_exe_32` | a `PE32` EXE whose base is neither `0x400000` nor `0x10000000` | 864 | 713 | 133 | 18 |
| `runtime_base_64` | image base at or above `0x7FF000000000`; the base is `lief.entrypoint − exiftool.entrypoint` | 100 | 100 | 0 | 0 |
| none: the file stays | | 11,160 | 2,856 | 7,837 | 445 |

(22 of the files that stay are not read as a PE.) The index rule removed 537 files that are
not memory images by their bytes, and passed 2,856 that are, a quarter of the files it
passed that were then read: a capture saved back into file layout, an import table resolved
under a link-time base, a program's data holding the addresses of a library, or an
unpacked program in a packer's empty section shows in no field the index stores. Of
`forced-b`'s 9,002 drawn files 1,385 are memory images by their bytes, 15.4%.

### The walk, and a top-up slice

**Only the files the draw needs are read.** Each band has a fixed order, keyed by
`(sha256, seed)`. `screened_draw` reads it from the top: a memory image is passed over and
a file that stays is drawn, until the band's target is met or the band ends. `bytes` asks
the draw which unexamined files it would need if every one of them stayed, reads those,
and asks again until nothing is needed. `pi_draw` is the share of the band the walk read,
`n_examined / n_band`: every file in that stretch was examined, so each drawn file stands
for the same number of files of its band. It is recorded as `n_draw / n_available`, with
`n_available = n_draw × n_band / n_examined`, which is the band's in-frame population when
the band is read to its end and an estimate of it otherwise; the manifest keeps
`n_examined` and `n_out` per band, from which the error of that estimate follows.

**A top-up slice is a later phase of the walk.** When the slices of a run cannot fill a
band, `--top-up-slice` adds a slice whose files come after every file of the first slices
in each band's order. Which slice a file is in follows from its sha256 prefix alone, so
reading the slices in turn is still a random order with respect to what a file is, and no
file already drawn moves. `pi_base` is the sum over all slices and `pi_draw` stays the share
of the whole band that was read. For a band whose walk reads the first two slices and a
share `f` of the third, a file of the band is in the first two with probability 2/256 and
is read, or in the third with probability 1/256 and is read with probability `f`:
`(2 + f)/256`, which is what `pi_draw × 3/256` records when the slices hold equal shares of
the band. `draw --continues` accepts an earlier run whose slices are read first and in its
order, with more allowed after them.

### Runs

Run `forced-b` was drawn under the index rule and run `forced-c` tops it up under the byte
rule. The figures of `forced-b` below stand as the record of that run: its cohort still
held the 1,385 memory images the bytes show.

**Run `forced-b`, 2026-11-18: `forced-a` topped up under the index rule.** `static` read the
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

**Run `forced-c`, 2026-11-19 and 2026-11-20: `forced-b` topped up under the byte rule.**
`bytes` examined 27,293 frame files: `forced-b`'s 9,002, the 12,834 the index rule had
left out, and 5,457 the walk fetched. 17,309 are memory images, 9,381 files as built, 575
show no evidence and 28 are not read as a PE. `draw --continues forced-b` filled every band
from three slices:

| Band | In band | Examined | Memory images | Target | Drawn | `pi_draw` |
|---|---|---|---|---|---|---|
| contested | 17,634 | 14,146 | 9,646 | 4,500 | 4,500 | 0.8021 |
| leaning malicious | 3,395 | 2,742 | 1,242 | 1,500 | 1,500 | 0.8078 |
| leaning clean | 6,903 | 5,040 | 3,540 | 1,500 | 1,500 | 0.7303 |
| consensus malicious | 109,521 | 3,162 | 2,162 | 1,000 | 1,000 | 0.0289 |
| consensus clean | 3,176 | 1,073 | 73 | 1,000 | 1,000 | 0.3378 |

Memory images are 68% of the contested files the walk read, 45% of leaning malicious, 70%
of leaning clean, 68% of consensus malicious and 7% of consensus clean: about two thirds
of the frame. Of `forced-b`'s 9,002 files 7,617 are drawn again, each in its band, with its
rescan record and renders carried over, and 1,385 are out as memory images. The cohort is
8,948 files as built, 524 with no evidence either way and 28 not read as a PE.

The rule was corrected while the run was open, and each correction was a new rules
version, a re-read of the files on disk and a re-draw that kept every file still in frame.
`forced-b`'s cohort held 763 memory images under rules version 5, 1,362 under version 7,
1,379 under version 8 and 1,385 under version 9. Versions 6 and 7 followed a first
independent review of the kept files. Version 6 added the addresses of a bound module in
a program's data: 1,905 of the 2,726 memory images examined in the consensus-malicious
band show it, most of them copies of one Visual Basic 6 program. A second
independent review judged the 27,049 files examined under version 6 from their bytes,
re-read its proposals with version 7's reader, and proposed 35 more files and
the release of 10. All 10 are released. Of the 35, 31 are out by a rule of
version 8 (relocation targets, rebuilt import tables, resolved tables that other tables
outvoted or a lost directory hid, the section UPX unpacks into) and 3 by name; the last is
not in the cohort. Version 9 added the entry point the file does not store, after a
reading of the files that review had left open. That review's table holds 9,428 of the
cohort's 9,500 files. The other 72 were read by hand afterwards, and that reading found
the 304 cohort files stored at their RVAs with data after the image
([What one file can say](#what-one-file-can-say)). The frame rule keeps them. Versions 11
to 13 changed the one-file label only, so the draw stands as version 9 made it.

**1,949 rescans**, at one a second, in five batches (UTC): 139 on 2026-11-19 from 23:58,
then on 2026-11-20 1,122 from 01:06 to 01:30, 342 from 18:07 to 18:13, 309 from 18:37 to
18:42 and 37 from 23:36 to 23:37. 13 requests failed on the network and were accepted on a
later pass; the third batch stopped on ten such failures in a row, and one rescan the API
had started before its answer was lost was adopted from the file's scan history. 1,883 of
the rescans are the cohort's new files, one each. The other 66 went to files that a later
rules version took out. Every one of the 9,500 files has one accepted rescan.

**Stages 02 to 08 on `forced-c`, 2026-11-23.** 9,447 of the 9,500 rows are trainable under
0016. The label counts by band are left out of this section while the gold slice is under
blind adjudication; they are in `data/runs/forced-c/labels.report.txt`. The temporal split
holds train 5,668 and validate 1,417, with 2,362 rows in the gap and no test fold, as
before. Baseline 3 within band on train + validate: clean 0.597, contested 0.656, leaning
malicious 0.523, consensus malicious 0.957, every gated band in §8's proceed range. The
coverage probe holds no band out (clean 0.642, contested 0.691, leaning malicious 0.615).
The models on validate, per band (clean / contested / leaning malicious): (a) 0.519 /
0.760 / 0.826, (b) 0.589 / 0.774 / 0.842, (c) 0.622 / 0.880 / 0.825, (b_verdicts) 0.551 /
0.767 / 0.840, (b_random) 0.568 / 0.833 / 0.882, against the count's 0.560 / 0.639 / 0.494
on the same rows.

**The noise band on `forced-c`** (5 repeats × 5 family-grouped folds over the 9,447
trainable rows in 3,353 groups; (b) at C = 0.01, (c) at 15 leaves × 300 trees). Contested:
count 0.680, (b) 0.839 (0.837..0.842), (c) 0.868 (0.864..0.872); gap over the count +0.159
for (b), worst repeat +0.157, and +0.189 for (c), worst +0.184: **both clear**. Leaning
malicious: count 0.533, (b) 0.887, (c) 0.879: both clear. Clean: count 0.583, (b) 0.635 and
(c) 0.771: both clear, (b) by +0.052 with a worst repeat of +0.032. Consensus malicious:
0.953 / 0.974 / 0.974, reported. Against `forced-b`, whose cohort held 1,385 memory images,
the contested band stands where it was (0.684 / 0.833 / 0.862 there).

**With the copies of a program held together** (outside the pipeline:
`~/dn-7927-pilot-scratch/forced_c_compare.py`, the method of `forced-b`'s comparison). The
9,447 trainable rows are 4,818 programs, 4,335 of them single files, and the ten largest
hold 2,731 rows. Folds grouped by program, contested: (b) 0.841 and (c) 0.875, gaps +0.161
and +0.195. One row per program, 1,786 contested rows: count 0.651, (b) 0.756, (c) 0.809,
gaps +0.105 and +0.158. Bootstrap by program: (b) +0.162, 95% interval +0.096 to +0.202;
(c) +0.200, +0.166 to +0.241. In the clean band (b) loses its lead once folds are grouped
by program (0.566 against 0.583) and (c) keeps it (0.731). The temporal split leaves 42% of
the contested validate rows with a twin program in train.

**Without the files the one-file label leaves undecided** (`forced_c_known_only.py`): 8,133
trainable rows, 3,811 of them contested. Count 0.705, (b) 0.852, (c) 0.893, gaps +0.148 and
+0.189; grouped by program (b) 0.858 and (c) 0.894. The lead does not rest on the undecided
files, and the pilot trains on the cohort as drawn (Kyle, 2026-11-23).

**Against the incumbent PolyScore at T** (`forced_c_incumbent.py`,
`forced_c_incumbent_boot.py`), contested band: 0.785 on the trainable rows, where the count
reads 0.680; 0.756 on the temporal validate rows, 0.724 with one row per program and 0.811
without the undecided files. Bootstrap by program of each model's gap over it, on
out-of-fold scores with folds grouped by program: (b) +0.057, 95% interval +0.015 to
+0.110; (c) +0.094, +0.067 to +0.159. Leaning malicious: incumbent 0.673, gaps +0.218 and
+0.222. Clean: incumbent 0.559; (b) +0.008 with an interval from −0.129 to +0.155, which is
no lead, and (c) +0.189, +0.115 to +0.249. On the temporal validate rows (b) is 0.018 ahead
of the incumbent in the contested band, and no noise band covers that gap: stage 07b
measures the gap over the count only.

**The gold slice of `forced-c`, 2026-11-23: `forced-a`'s slice topped up**
(`03b_gold_draw.py --continues forced-a`, seed 20260922;
[04 § Stage contracts](./04-pipeline.md#stage-contracts)). 140 of the 200 files of
`forced-a`'s slice are memory images and out of frame. The other 60 stay, each in the group
it was drawn in, and 140 files are drawn from the contested band of `forced-c`: 200 files,
100 per group, no rescan. No file of the band changed group between the two draws, and the
earlier sheet held no verdict to carry. By the one-file label 168 of the 200 are files as
built and 32 are undecided. The slice is 105 programs: 86 single files, 38 and 23 copies of
the band's two most-copied programs (627 and 472 of the 4,711 cohort files in the contested
band at T), and no other program more than five times. The adjudicator reads
`data/gold/forced-c/review.csv`, and `new_hashes.txt` beside it lists the 140. How many
files each group carried and drew is in the manifest and stays out of this section while
the slice is under adjudication.

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
