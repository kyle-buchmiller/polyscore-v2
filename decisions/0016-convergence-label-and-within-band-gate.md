# 0016 — The answer column reads movement, and the gate is scored within band

- **Status:** Accepted
- **Date:** 2026-11-10
- **Affects:** `specs/01-estimand.md` (§3, §6, §8; version 7), `specs/03-labels.md` (Producing the
  pilot's labels), `src/polyscore_v2/config.py` (`ESTIMAND_VERSION`); to implement next:
  `src/polyscore_v2/labels.py`, `pipeline/03_label.py`, `pipeline/06_baselines.py`,
  `specs/04-pipeline.md`
- **Supersedes:** item 1 of [0011](./0011-provisional-pilot-rules.md), the label rule. Its
  other stand-ins (the split group, the static block, calibration on grade-1 labels, the
  stability stand-in, the run layout) stand.

## Context

Run `forced-a` (9,500 files, label scans at a median of 54 days) put baseline 3 — the count
of engines asserting malicious at T — at **0.999 AUC** against 0011's labels, estimand §8's
stop. The mechanism is measured, not guessed. Engines accrue detections and almost never
retract them: 5.6% of the verdicts present at both scans flipped, 276 of the 11,226 flips
went malicious → benign, and two files in 9,500 lost two or more engines. 0011's rule reads
the *level* at the label scan — benign is zero malicious verdicts, malicious is a
specific-family consensus — so the level at T decides the label almost everywhere: 896 of
the 920 benign labels were already below 0.1 at T, 34 of the 4,798 malicious ones were.
Inside the contested band at T (4,573 files) the rule produced **24 negatives in 2,348
decided files**, because nothing goes clean within the horizon; the other 2,015 contested
files were `undecidable`. The pooled AUC was owned by the two consensus bands, where a hash
lookup had already answered.

The same data says what the horizon *does* carry: 31% of files clean at T and 10% of
contested files moved up by 0.15 or more in `m` by day 54, and that movement sits where a
score is wanted.

## Decision

1. **The answer column reads movement.** Let `m_L` be the malicious share over the
   definite verdicts at the label scan and `Δm` the change in that share over the engines
   with a definite verdict at **both** scans, so turnover cannot pass for revision
   (`03-labels.md` § What actually changes).
   - **malicious** — consensus at the horizon (`m_L ≥ 0.5`), or growth: `Δm ≥ +0.15`
     (about two engines at the median coverage of 15), or `m` across 0.5 from below. 0011's
     family routing still applies to a positive: a PUP or dual-use family consensus is
     `unwanted`, with the reason.
   - **benign** — no growth, and one of: stayed clean (`m_L ≤ 0.1` with at least ten
     definite verdicts; reason `stayed_clean`), fell (`Δm ≤ −0.15`; reason `fell`), or
     stayed contested (`0.1 < m_L < 0.5`; reason `stayed_contested`). The last is a
     **provisional** negative: "did not converge within the horizon", the claim a 54-day
     rescan can support, and the one the T+90 and T+180 panel passes and the gold slice
     revise. A file that grows later was a false negative here, and the reason column is
     what lets it be re-labelled without re-running anything else.
   - **undecidable** — below the floor: fewer than `LABEL_MIN_DEFINITE` definite verdicts
     at the label scan, or fewer than five engines present at both scans (`below_floor`).
   - The grade stays **1**, time-separated. The positive class is unchanged for a file that
     reaches consensus; what changes is the negative class in the contested region, from
     "went clean", which does not happen within the horizon, to "did not converge", which
     the horizon can show.
2. **AUC is quoted per band at T** — clean (`m < 0.1`), contested (`0.1 ≤ m < 0.4`),
   leaning malicious (`0.4 ≤ m < 0.5`) — with the pooled number reported after them, never
   as the headline. The two consensus bands are reported, not gated: a score is not for
   them.
3. **The gate is per band, the contested band deciding** (estimand §8): proceed when
   baseline 3 lands in 0.5–0.8 there and the model beats it by more than the noise band;
   stop and fix the labels when baseline 3 exceeds ~0.9 in any band the model trains on;
   check the plumbing when the model is near 0.5 in every band.
4. **A coverage check beside the provenance probe.** A model fitted on the response
   pattern alone — which engines answered at T, verdicts ignored — above ~0.75 in a band
   means the features identify the file's source, not the file. That band's coverage
   features are held out and its number is not quoted until the probe passes.

## Measured on `forced-a`, 2026-11-10

5-fold CV logistic regression on per-engine verdict indicators at T, within band:

| Band at T | n | positives | count at T (baseline 3) | engine identities | response pattern only |
|---|---|---|---|---|---|
| clean, `m < 0.1` | 2,334 | 694 | 0.73 | 0.93 | 0.82 |
| contested, `0.1 ≤ m < 0.4` | 4,573 | 676 | 0.58 | 0.84 | 0.65 |
| leaning malicious | 1,508 | 477 | 0.59 | 0.95 | 0.76 |
| pooled | 9,500 | 1,848 | 0.45 | | |

Under 0011 the same bands read 0.87 / 0.91 / — for the count (the contested band with 24
negatives), 0.998 pooled. In the contested band the verdicts carry all of the signal
(verdict-only 0.84, verdicts plus response pattern 0.84) and the coefficients are readable:
early detections by SecureAge, Proton, Electron, K7 and CrowdStrike's ML engine predict
convergence; detections by Qihoo 360, Cyberstanc and Lionic predict that nothing follows.
The clean band's response-pattern number is the reason for rule 4.

## Consequences

- Estimand version 7. `03_label.py` implements the rule beside 0011's family routing, with
  the reason vocabulary above; `06_baselines.py` reports and gates per band and fits the
  response-pattern probe. 05's split is unchanged.
- What the number means shifts a little in words and not in use: "the probability the
  engines converge on malicious by the horizon, given the evidence at T". For a roster that
  accrues and does not retract, that is the operational content of "malicious at the
  horizon"; the gold slice is what checks that it is also the semantic content.
- The T+90 and T+180 panel is no longer optional: it is how `stayed_contested` negatives
  are confirmed or revised. The gold slice remains the only source of the stronger
  negative.
- The injection arm ([0015](./0015-injection-arm-from-the-index-authenticode-and-virustotal.md))
  is unaffected: attested negatives, mostly clean at T, scored within the clean band like
  everything else.

## Rejected

- **Held-out label engines.** Label from four engines chosen by their T → label flip rate,
  features from the rest. The choice selected the aggressive engines (Ikarus, Lionic,
  NanoAV, Qihoo 360), whose consensus called nearly every contested file malicious (148
  negatives in 4,459). The idea may return with engines chosen for independence, once the
  cluster map exists (R8).
- **Negatives defined by going clean.** They do not occur within the horizon: 133 of 4,573
  contested files, 24 of them benign under 0011.
- **Keeping the pooled AUC as the headline with a higher stop.** The pooled number is the
  band structure; no threshold on it measures the model.
