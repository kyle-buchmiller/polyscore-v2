# 0005 — Composite PolyScore via a fitted combiner

- **Status:** Accepted
- **Date:** 2026-09-23
- **Affects:** `specs/06-signals.md` (new), `specs/00-overview.md`, `specs/02-data.md`
- **Amends:** [`0001`](./0001-contract-is-a-calibrated-probability.md)

## Context

Leadership asked for PolyScore to be a **composite**: not only the ML probability, but
with the capacity for other factors to push it up — a stolen signing certificate as the
worked example, and sandbox behaviour as the other.

The instinct is sound and the current model is genuinely deficient in the way it implies:
it sees 28 engine display names and nothing else. The 2022 whitepaper already advertised
classification strings, sandbox input and engine similarity; none of it shipped. A
composite is not a new idea being bolted on, it is the original design finally being
built.

Two constraints frame the answer.

**A single number is non-negotiable.** Customers have integrations that read one field
and threshold on it. That is what they have.

**Decision 0001 committed to a calibrated probability.** The moment a probability is
multiplied by a hand-picked factor and clamped, it stops being one — and that exact
arithmetic is the live neonscan defect, where category multipliers make a container of
entirely clean files report 1.0.

Two facts arrived during the discussion and shaped the outcome:

- **DN-8374 shipped 2026-09-22**, giving structured Authenticode verification via LIEF —
  `signature_tags`, chain-of-trust flags, and per-certificate thumbprints. It does not
  assert "stolen"; nothing in the platform does.
- **Sandbox presence is downstream of engine verdicts.** Detonation is gated on a
  `polyunite` malware family, which comes from engine assertions, so a file nobody
  detected is never detonated and benign-side coverage is near zero.

## Decision

`polyscore` stays **one calibrated number** and becomes the output of a small **fitted
combiner** taking the base model's score plus signal indicators, rather than the base
model's score directly.

```
engine verdicts + features ──→ base model ──→ raw score ─┐
signature signals ───────────────────────────────────────┼──→ COMBINER ──→ polyscore
sandbox signals ─────────────────────────────────────────┘    (fitted)
```

Composition is **fitted, not asserted**: weights come from observed outcomes, so the
output remains a probability. A signal producer publishes an *observation* and never sets
its own weight.

Signals, the base probability and per-signal contributions are exposed under
`components` for drill-down. Full contract in [`specs/06-signals.md`](../specs/06-signals.md).

## Alternatives considered

| Option | Why not |
|---|---|
| **Signals as base-model features only** | Correct but insufficient. Sandbox evidence arrives *after* the scoring moment, and adding any signal would require retraining the base model — weeks, for a signal that should take minutes. |
| **Post-hoc multiply and clamp** | Breaks calibration outright, and is the neonscan bug by construction. Also double-counts: the base model already sees `signed` and `self_signed`. And it cannot express interaction — a broken signature on a file thirty engines flagged should add almost nothing; on a file nobody flagged, a great deal. |
| **Signals outside the score entirely, policy layer only** | Honest, and keeps `polyscore` clean — but fails the single-number constraint. Customers who read one field would never see the signal. |
| **Separate published scores (`ml_score` + `polyscore`)** | Two numbers to explain, two sets of thresholds to migrate, and customers would pick one arbitrarily. The combiner gives the same information under one number with drill-down. |
| **Log-odds adjustment with an expert-set likelihood ratio** | Mathematically sound *if* the LR is measured and the signal is conditionally independent of what the model already sees. Kept as the **interim** posture (see below), not the destination. |

## Consequences

**0001 is amended, not superseded.** The clarification: *the calibrated probability may
be composed from multiple evidence sources, provided the composition is fitted rather
than asserted.* `polyscore` remains the source of truth for rank, and rank still uses the
raw combiner score at full precision.

**Explanation becomes exact rather than estimated.** On a small linear combiner each
input's contribution *is* `coefficient × value`, so the drill-down is arithmetic. This
was called out as a wanted property and it falls out of choosing a small combiner over a
large one.

**Two model artefacts, versioned independently.** Base and combiner have separate
versions, separate refit cadences and separate gates. When the score moves, the versions
say which half moved. The idempotency key for a score observation must include
`combiner_version`, or a combiner refit silently no-ops on every already-scored artifact.

**Scores will change when sandbox lands.** A file is scored at reveal without sandbox and
re-scored when the report arrives — re-running only the combiner, not the base model.
This needs no new machinery: score observations are already append-only and versioned.
It does mean customers see a score move, so `components.contributions` must explain it
and exports must pin the observation they rendered.

**Calibration is reported per coverage tier.** Artifacts with and without sandbox come
from different evidence populations. One combiner for now with four-state presence
encoding; split per tier if the reliability curves diverge. Data-driven, not decided up
front.

**Interim posture, because there are no adjudicated labels yet.** The combiner cannot be
fitted until grade-3 labels exist (see [`0004`](./0004-labels-time-separated-for-the-pilot.md)).
Until then: set weights from expert judgement **in log-odds**, record them as assumptions,
and mark the score `calibration: provisional` in its status. Weights are `logit += w`,
never `score × k` — so the eventual refit is a parameter change rather than a rebuild,
and nothing saturates in the meantime.

**A new dependency on platform work.** Sandbox evidence is only usable across the whole
population if a **small random detonation arm** exists — a fixed fraction detonated
regardless of family resolution. Without it, sandbox can only ever inform artifacts
engines already flagged, which is the region where the score matters least. This is
recorded in `specs/99-open-questions.md` as the highest-leverage platform ask.

**Meaningful behavioural features mean pulling reports from object storage.** The index
carries roughly an eighth of the network evidence and CAPE's `behavior.enhanced` block is
deleted before storage. Anyone costing this work should not assume the index suffices.

**A standing risk to manage.** A combiner is easy to hand-tune, and the pressure to nudge
a coefficient after seeing a customer complaint will be constant. The guard is that
coefficients are fitted artefacts with a version, changed by refitting on data and
reviewed like any model promotion — never edited in place.
