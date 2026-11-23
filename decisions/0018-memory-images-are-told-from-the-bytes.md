# 0018 — Memory images are told from the file's bytes (amends 0017)

- **Status:** Proposed
- **Date:** 2026-11-19
- **Affects:** `specs/12-api-slice-pilot.md` (Forced rescans; Memory images are out of frame),
  `specs/04-pipeline.md` (stage 00b), `specs/99-open-questions.md`,
  `src/polyscore_v2/image_bytes.py`, `src/polyscore_v2/draw.py`,
  `pipeline/00b_force_rescan.py`, `Makefile`

## Context

[0017](./0017-memory-images-are-not-training-material.md) took memory images out of the
training population and, until an analyzer tags them, told them from nine layout fields of
the metadata index. Run `forced-b` was drawn under that rule: 9,002 files, three bands
taken whole and still short of their quotas.

Kyle Buchmiller then asked for the kept files to be downloaded and checked, and on
2026-11-19 for the rule to be narrowed until no memory image is left in the training set,
by whatever method, with the right number of files and one rescan for each.

Read from the bytes, the index rule is wrong in both directions. Of the 23,994 files of the
two slices examined, it calls 12,834 memory images, of which 537 are not by their bytes
(466 show evidence of a file as built), and it passes 11,160, of which 2,856 are. **1,385
of `forced-b`'s 9,002 drawn files are memory images**, 15.4%. The fields the index stores
cannot show a capture saved back into file layout, an import table resolved under a
link-time base, a library's addresses in a program's data, or an unpacked program sitting
in a packer's empty section.

## Decision

**A file is a memory image when its own bytes show a tell** (`image_bytes`, specs/12 §
Bytes decide): a trace of the loader, a trace of the tool that wrote the capture, or a
comparison between copies of one build. The draw reads each band's fixed order from the
top and passes over the memory images, so only the files it needs are downloaded. Three
things go with it:

1. **A presumption.** A 32-bit EXE that asks for a load-time address, sits at a base that
   is neither `0x400000` nor a multiple of 16 MiB, and has neither certificate nor valid
   checksum is taken for a memory image without a trace.
2. **A reviewed list.** A file a person examined and found to be a memory image where no
   rule says so is out by name.
3. **A third slice of the same month**, read only after the first two, fills the bands
   they could not.

Run `forced-b` is topped up under this rule as run `forced-c`. The estimand is unchanged
(version 8): §10 says which files are out, and this record changes only how they are told.

## Alternatives considered

| Option | Why not |
|---|---|
| Keep the index rule and add a list of confirmed files | That is what `forced-b` did, with three files on the list. The byte check found 1,385, and a list cannot remove what was never examined: every kept file has to be read anyway. |
| A parser library (LIEF, pefile) | The first prototype used LIEF. It skips an import directory whose `Size` is 0, which the loader walks; it logs a line per unreadable slot; and its checksum differs from ImageHlp's on some files. A capture is a malformed PE, which is where a general parser's choices are least visible. The reader is 900 lines of `struct` whose every choice is in view and under test. |
| Wait for the analyzer tag (DN-8811) | Not built, and it would need a backfill over the window. The pilot month starts ageing out of the frame on 2026-12-07. The reader is the reference that ticket ports. |
| Read every frame file, as the index rule did | 140,939 downloads for a draw that needs 27,293. The cost is that a band not read to its end has an estimated `n_available`; the manifest keeps what the estimate rests on. |
| No presumption: act on traces only | 40 of the 937 files that meet it show no trace of their own, and comparing files confirms 7 of those. Leaving the other 33 in keeps some memory images in the cohort; taking them out loses some files as built. The instruction was that none be left, so they go. An analyzer, which must not mislabel, reports the presumption and does not decide on it (`image_bytes.single_file`). |
| Let a valid checksum or a certificate outweigh a tell | Dump tools recompute the checksum: all 94 examined files in mapped layout with a valid checksum and nothing after their sections are dumps. A certificate has not been seen on a memory image, but a tool that keeps the original file's overlay would keep it. Both keep a file out of the presumption and of the cross-file tells, and out of nothing else. |
| Leave the three short bands short | `forced-b` held 9,002 of 9,500, and removing 1,385 more would leave 7,617. The request was for the right number. |
| Refill from a wider or later window | As in 0017: a replacement must be 30 to 90 days old at its rescan like the rows it joins. A third prefix of the same month keeps that, and a wider window is the next run of the whole process. |

## Consequences

- **The frame is three slices**, `pi_base` 3/256. The third is a later phase of every
  band's walk, so no file `forced-b` drew moves, and a band that fills within the first two
  slices keeps its inclusion probability up to the noise of band sizes between slices.
- **Memory images are about two thirds of the frame**, not a seventh: 68% of the contested
  files read, 70% of leaning clean, 45% of leaning malicious, 68% of consensus malicious
  and 7% of consensus clean.
- **The rule has a version** (`image_bytes.RULES_VERSION`, 9 for `forced-c`) and the draw's
  manifest records it with the hash of the reader's source, the tells' counts, the reviewed
  list's hash and the bands' `n_examined` and `n_out`. A cached reading made by another
  version of the reader is read again.
- **A verdict can depend on other files.** The two tells that compare copies of a build
  find more as more files are read. Four examined files are out on such a tell alone.
- **What the rule cannot see stays in**: a capture taken before the loader ran and written
  back into file layout at its link-time base; a managed assembly rebuilt into file
  layout; a 32-bit bound import table; and the 575 examined files that show no evidence
  either way. Two independent reviews of the kept files bound what is left, and each
  found files the rules of its day had missed (specs/12 § Runs).
- **The index survey stays** (`static`) as a measurement of what the index fields say. The
  draw no longer reads it, and `--confirmed-memory-images` is gone.
- **0017's own consequences that this replaces**: "the index rule is a floor" and "the rule
  also removes some files as built" described the index rule; the byte rule's limits are
  the ones above. 0017's decision stands.
- **If the rule is wrong** in a way a later review shows, the fix is a new rules version, a
  re-read of the files on disk and a re-draw with `--continues`: the walk keeps every file
  still in frame and replaces only what went out.
