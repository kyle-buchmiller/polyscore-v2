# 0001 — The contract is a calibrated probability; rank derives from it

- **Status:** Accepted
- **Date:** 2026-09-22
- **Affects:** `specs/00-overview.md`, `specs/01-estimand.md`

## Context

A long-running internal argument treated the meaning of a mid-range PolyScore as
undecided, between two readings:

- **A — a likelihood.** 0.4 means "of files like this, about 40% are malicious."
- **B — a rank.** 0.4 means "more suspicious than 40% of the current queue."

The argument was, in fact, already settled in public. The 2022 whitepaper opens *and*
closes on the same sentence: PolyScore "provides the probability a given file contains
malware." Reading A is the published commitment. The shipped system does not honour it —
there is no calibration layer of any kind.

The team subsequently asked for **both** scores, noting that one deriving from the other
was acceptable.

## Decision

The **calibrated probability is the single source of truth**, and rank derives from it
by taking percentiles over a named cohort.

## Alternatives considered

| Option | Why not |
|---|---|
| Rank-primary, probability derived from it | Not recoverable. The top-ranked file is 6% likely at a 2% base rate and 96% likely at 30% — same rank, different answer. Recovering a probability needs exactly the labels that make A expensive. |
| Ship only the probability | Loses a genuinely useful operational tool; the queue percentile is a clean volume dial and costs nothing once A exists. |
| Ship only the rank, rename the field | Legitimate and honest, but contradicts a four-year-old published claim and the colour semantics customers already rely on. |

## Consequences

- Calibration is monotone, so it cannot reshuffle the ranking — both readings come from
  one model, one version, one story.
- A rank *always exists*, so a rank-primary system could never express "insufficient
  evidence." Probability-primary can, which is what makes the coverage gate possible.
- A file's probability is stable while its queue position moves, so the probability
  belongs in the coloured UI and rank ships as an explicitly-labelled triage tool.
- **Implementation trap:** rank on the raw model score, never the calibrated or rounded
  value — isotonic calibration maps large blocks to identical probabilities, and within
  a block the queue order collapses to whatever the sort is stable on.
- Rank needs a named cohort ("percentile among what?") exactly as the probability needs
  a named population.
