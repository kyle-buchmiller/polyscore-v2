# 0014 — Forced rescans label the training arm too

- **Status:** Accepted (amends [0010](./0010-natural-rescans-for-training-forced-for-validation.md))
- **Date:** 2026-11-09
- **Affects:** `specs/01-estimand.md` § 4 and § 10 (the label scan's origin), `specs/04-pipeline.md` (stage 00b), `specs/12-api-slice-pilot.md` § Forced rescans, `pipeline/00b_force_rescan.py`

## Context

Decision 0010 split the label source: natural rescans for training, forced rescans at
~30 days for a 2,000-file validation arm, so a model trained on files *someone chose to
rescan* could be judged on files nobody chose. It rested on natural rescans being plentiful.
Measured on prod on 2026-11-09 ([12 § Measured](../specs/12-api-slice-pilot.md)): a
natural later scan 30 or more days after the first happens to about 10⁻⁴ of scanned public
PE files, 7 of 34,896 after six months of exposure. A month's whole frame yields of order
10³ labellable files, and those are the selected ones. The training arm cannot be filled
from natural rescans at the pilot's scale, by any data path.

## Decision

The training arm's label is a **forced rescan** as well: a stratified cohort is drawn at T
from an API slice of a month already 30 or more days old, every drawn file is rescanned
through the public API, and the forced scan is its label scan. The label gap is the file's
age at submission, inside `[horizon_days, horizon_max_days)` by construction. The
validation arm of 0010 keeps its purpose as a held-out, time-separated set; its
"unselected versus selected" comparison dissolves, because now nothing in the cohort was
selected by a rescan.

## Alternatives considered

| Option | Why not |
|---|---|
| Natural rescans over the whole frame for many months | Of order 10³ labellable files a month, nearly all consensus-malicious at T, every one chosen by someone: the contested band cannot fill and the selection 0010 feared is the entire sample. |
| Wait 30 days after drawing fresh files | Adds a month to every iteration; the aged slice gives the same label with no wait. |
| Labels from another source (a vendor feed, a later community's scan) | A different estimand; nothing measured yet says it is available at scale. Open. |
| Shorten the horizon to catch the same-day rescans | Those are not time-separated; the estimand's label is the consensus after the engines had time to learn. |

## Consequences

- **The pilot is labelled in hours, not weeks.** A 10k draw from the first post-fix month
  (files 32–62 days old) is rescanned at about one a second and read back the same day.
- **Cost is explicit and bounded**: one bounty per drawn file, about 17 engine scans each,
  submitted under one account at a pace the platform does not notice (about 5 scans a second
  baseline). Scaling this to 10⁵–10⁶ labels a year is the rescanner's job (DN-8721), not
  this stage's.
- **The control sample of 01a is moot** under forced labels (there is no natural-rescan
  selection to probe), and stage 06's rescan probe reports n/a on a forced base.
- **Provenance stays unknown** on an API-sourced base (no `scan_config`), so calibration
  waits for the exporter or the serializer change, as in 0013.
- 0010 is amended, not reverted: its validation arm and the two-tier extraction stand.
