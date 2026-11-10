# 0013 — The pilot's data comes from the public API, as a sha256-prefix slice

- **Status:** Accepted
- **Date:** 2026-11-09
- **Affects:** `specs/12-api-slice-pilot.md` (new), `specs/04-pipeline.md` (stage 00), `specs/02-data.md` (the bounded exception), `src/polyscore_v2/api_source.py`, `pipeline/00_api_slice.py`, `src/polyscore_v2/config.py`

## Context

The extraction runbook ([09](../specs/09-extraction-runbook.md)) reads the prod read
replica through a `kubectl` tunnel. Measured 2026-11-06: the `ReadOnlyProd` role has no
EKS access entry on any prod cluster, and every identity that does is cluster-admin. The
Cloudflare door to OpenSearch issues a token and then refuses it. Both fixes belong to
other teams, and a scan-data exporter (DN-8712) is filed but not built.

The public API was measured on 2026-11-09. Its per-file renders are the wrong shape for
a census: the one render that carries verdicts also carries the sandbox reports (6.5 MB
a scan), and nothing renders `scan_config`. But its metadata search accepts a sha256
**prefix** as a filter, and sha256 is uniform, so a prefix is a server-applied random
sample with an exact inclusion probability. Each document carries the file's first and
latest scan: instance ids, times, verdict counts, name-keyed verdicts. That is enough to
find labellable files, band them at T, and draw, with no per-file call.

## Decision

Until the exporter ships, the pilot's base is an **API slice**: every public PE file
whose first scan falls in the window and whose sha256 starts with a chosen hex prefix,
read from the metadata index, with `pi = 16^-k` recorded. The first run is a survey over
one month that sizes the prefix for a 10k cohort. The deviations this forces are
recorded, not hidden: the index's first scan as T, the latest scan as the label, engines
by display name, no provenance and therefore **no calibration** from this source.

## Alternatives considered

| Option | Why not |
|---|---|
| Wait for cluster access | Owned by another team with no date; the pilot stalls on it. |
| Pull per file through the API | 10^5 to 10^6 full renders at 6.5 MB each, every one an object-storage read on the web pods; and the frame still has to be enumerated first. |
| Enumerate the frame through the metadata search, then sample | Pays for every document to keep one in 4,096. The prefix moves the sampling to the server for free. |
| Use the per-hash history render for labels | It has no verdicts (minified), so each label still needs a full render. Kept for the history sample only. |
| Change the estimand to "latest scan" | The label rule is right; the source is what is limited. Recording the deviation keeps the estimand intact for the exporter path. |

## Consequences

- **A pilot can run this week**, end to end through training and ranking evaluation, on
  real prod data, with every number marked as API-sourced.
- **Calibration waits** for `scan_config`: from the exporter, or from the one-field
  serializer change. Nothing in the slice has to be re-pulled for it; the instance ids
  are kept.
- **The index exception to [02](../specs/02-data.md) is bounded** to the first-scan
  sub-document (written once) and the latest-scan sub-document (recorded as of pull time).
  It must not grow into reading `latest_scan` as if it were a chosen label.
- **Two measurements decide how much the deviations cost**: the unscanned-first share
  and the share of labellable files with more than two scans. Both come out of the first
  survey. If either is large, the cohort's T and label scans are fetched from the
  history render plus the full render, for the drawn cohort only.
- **The sampling rule differs from the SQL path.** A base records which rule produced
  it; a run never mixes bases.
- **Measured on acceptance day** ([12 § Measured](../specs/12-api-slice-pilot.md)): the
  slice works as designed and the index's view is faithful to the history, but natural
  rescans 30+ days after T are about 10⁻⁴ of scanned files. The slice stays the
  frame-and-draw source; whether the labels come from forced rescans or elsewhere is
  [99](../specs/99-open-questions.md)'s open question and a 0010 matter, not this record's.
- When DN-8712 lands, stage 00 is retired and this record is marked Superseded.
