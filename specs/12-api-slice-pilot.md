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
  window, aged `[horizon_days, horizon_max_days)` at draw time and no larger than the rescan
  route's size cap under the pilot's key (`--max-size-bytes`, 32 MiB; the index records
  `artifact.size`, so the rule is applied before the draw and the manifest counts what it
  removed). `pi_base` is the sum of the slices' inclusion probabilities (disjoint prefixes, so
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
  a slightly longer gap, which the base records per row.

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
artefact of that label and measures nothing; stage 09 was not run. The label rule is the
next decision ([99](./99-open-questions.md)).

## Relation to the other sources

| | SQL path (09) | API slice (this) | Exporter (DN-8712) |
|---|---|---|---|
| Needs | cluster access | an API key | the exporter shipped |
| Frame | complete, by `completed` | sampled, by first scan | complete, by `created` |
| Labels | nearest later scan | forced rescan at T + age (0014) | nearest later scan (local join) |
| Engine identity | id | name | id |
| Provenance | yes | no | yes |
| Fit for | the full window | the pilot, now | the full window, repeatably |
