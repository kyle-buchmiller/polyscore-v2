# 0017 — Memory images are not training material

- **Status:** Accepted
- **Date:** 2026-11-18
- **Affects:** `specs/01-estimand.md` (§10; version 8), `specs/12-api-slice-pilot.md` (Forced
  rescans; Memory images are out of frame), `specs/04-pipeline.md` (stage 00b),
  `specs/99-open-questions.md`, `src/polyscore_v2/config.py` (`ESTIMAND_VERSION`),
  `src/polyscore_v2/memory_image.py`, `pipeline/00b_force_rescan.py`

## Context

The gold slice of run `forced-a` came back from adjudication looking like one program: 84 of
its 200 files were images of a single build, with the same `.text` section and import table,
differing in load address and two bytes of `.data`. Read from the bytes (DN-8811's prototype,
LIEF with a pefile cross-check), **139 of the 200 are memory images** — PE files written out
of a running process — and 123 of the 139 come from two builds; 45 are files as built and 16
give no verdict either way. Read from the index's layout fields over the whole cohort,
**4,617 of the 9,500 drawn files are memory images**, and the 9,500 files are 2,891 programs
by a build key (import hash, fuzzy hash, largest section and size).

The draw was sound. It represented what arrives: a sandbox upstream submits one image per
process and per run, so one build reaches the platform as hundreds of files in a burst.

That changes what the pilot's comparison had measured. In the contested band the noise band
of 2026-11-12 read the count at 0.581, model (b) at 0.701 and model (c) at 0.860, with the
folds grouped by engine family name. Rerun outside the pipeline with stage 07b's fitting code
(`~/dn-7927-pilot-scratch`):

| Rows | Folds grouped by | count | (b) | (c) |
|---|---|---|---|---|
| all 9,475 trainable | engine family name, as reported | 0.581 | 0.701 | 0.860 |
| all 9,475 trainable | program | 0.581 | 0.491 | 0.667 |
| memory images removed (4,859) | engine family name | 0.679 | 0.833 | 0.849 |
| memory images removed (4,859) | program | 0.679 | 0.835 | 0.836 |

With the copies of a program held together most of the reported lead goes: the models were
recognising a dump of a program they had already seen. With the memory images removed and
every on-disk variant kept, the lead no longer depends on the grouping (bootstrap by program:
(b) +0.157, 95% interval +0.098 to +0.194; (c) +0.164, +0.129 to +0.214). The leak was a
memory-image effect, not a near-duplicate effect.

## Decision

**Memory images are out of the training population (§10). Near-identical variants of a
program that were submitted as files stay, each as a row of its own** (Kyle Buchmiller,
2026-11-18). Until the Lief analyzer tags them at analysis time (DN-8811), stage 00b tells
them from the index's layout fields and leaves them out of the frame before the draw, and run
`forced-a` is topped up with replacements from the same window as run `forced-b`. Once this
pilot is through, the whole process is repeated on a wider window and the two are compared.

## Alternatives considered

| Option | Why not |
|---|---|
| Keep them and group the split by program | The comparison becomes honest, and the training set is still mostly copies of a few builds. A program key is also a clustering rule the pilot would then have to defend. |
| One row per program | It discards on-disk variants that were submitted as files in their own right, which are legitimate rows, and it needs the same program key. Measured on the kept rows it reads count 0.630, (b) 0.747, (c) 0.803: the same conclusion from 2,554 rows in place of 4,859. |
| Drop them after the draw and train on what is left | The cohort falls to 4,883 files and the contested band to 1,582 of its 4,500. |
| Refill from a wider or a later window | A replacement must be 30 to 90 days old at its rescan, like the rows it joins, or the label gap stops being comparable across the cohort (§4). A wider window is the next run of the whole process, not a patch to this one. |
| Wait for the Lief tag (DN-8811) | The tag is not built and would need a backfill over the window. The index fields already find 136 of the 139 byte-confirmed memory images of the gold slice, and the pilot month starts ageing out of the frame on 2026-12-07. |

## Consequences

- **The frame shrinks and the draw is topped up.** The rule removes 12,837 of the pilot
  month's 94,232 frame files: 7,656 of the 11,799 contested at T, 3,062 of 4,550 leaning
  clean, 909 of 2,280 leaning malicious, 1,077 of 73,245 consensus malicious and 86 of
  2,139 consensus clean. Memory images are 14% of the frame and were 49% of the draw,
  because the draw over-samples the bands they arrive in. Run `forced-b` keeps 4,880 of
  `forced-a`'s 9,500 files and adds 4,122 replacements, one forced rescan each. Two slices
  cannot fill three of the bands (contested 4,143 of 4,500, leaning malicious 1,371 of
  1,500, leaning clean 1,488 of 1,500), so the cohort is 9,002; a third slice of the same
  month would fill them and change `pi_base`.
- **The index rule is a floor.** A dump saved back into file layout at a default image base
  looks like a file as built to every field the index stores. Three of the 64 gold-slice
  files that pass the rule are such dumps; they are excluded by name from the byte-level
  list, and about one kept contested row in twenty may be another. A byte-level pass over
  the kept 32-bit files, where the residual lives, would close it; it needs the files
  downloaded and is not decided.
- **The rule also removes some files as built**: a 32-bit EXE linked at a base other than
  `0x400000` cannot be told from a relocated dump in the index, and goes with them (864
  of the frame's files, 0.9%). All six such files in the gold slice are memory images by
  their bytes.
- **The gold slice** loses 139 of its 200 files to the rule; 61 remain in the training
  population. Whether it is topped up from the on-disk contested rows, and whether the
  memory-image clusters are adjudicated to the end, is open.
- **§1 is not changed.** What PolyScore v2 says about a memory image a customer submits is
  open; this record only says the model does not learn from them.
- **Replacements carry a longer label gap**: they are rescanned nine days after the rows
  they join, inside the frame's `[30, 90)` days and recorded per row.
- **When DN-8811 ships**, the analyzer's tag replaces `memory_image.classify`, and the
  byte-level tells (import slots holding addresses) cover the dumps the index cannot see.
