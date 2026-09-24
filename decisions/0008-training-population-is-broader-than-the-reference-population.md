# 0008 — The training population is broader than the reference population

- **Status:** Accepted
- **Date:** 2026-09-24
- **Affects:** `specs/01-estimand.md` (§9 framing, new §10), `specs/05-evaluation.md`

## Context

Estimand §1 defines the **reference population** — customer-submitted PE, feeds excluded —
and §9 then asked "how is the cohort drawn from *that population*." So the specs said to
draw the **training** cohort from the **reference** frame.

That was never the agreed design, and two things in the repo already contradicted it. §9's
injection arm sources known-good binaries externally, which are by definition not
customer-submitted. And the whole reason §1 stayed narrow was that the *pilot cannot
calibrate at all* — its labels are grade 1 ([`0004`](./0004-labels-time-separated-for-the-pilot.md))
— which is an argument about the calibration denominator, not about what the model may
learn from.

The confusion is easy to have, because both are "the population." They answer different
questions:

- **Reference population** — what the number is *about*. The denominator that makes a
  probability mean something.
- **Training population** — what the model may *see*. A coverage question.

Forcing them to coincide costs real capability: the customer-submitted frame is thin in
exactly the contested region where a score earns its keep, while PolySwarm holds abundant
labelled data that would fill it.

## Decision

**Train on every PE artifact in the window, feeds included, plus the injection arm.
Calibrate on §1's population only.** Recorded as a new estimand §10, with §9 restated to
draw from §10 rather than §1.

## Alternatives considered

| Option | Why not |
|---|---|
| Draw the training cohort from §1 (the state this fixes) | Thin in the contested region, which is 45% of the design and the only place the product earns its keep. It also made §9's injection arm incoherent — externally-sourced known-good is not customer-submitted, so the spec already contradicted itself. |
| Make §1 store-wide, so both populations coincide | The original proposal, rejected in [`0006`](./0006-stratified-sampling-with-recorded-inclusion-probabilities.md) and still rejected: the base rate would track how many feeds are switched on. A file's probability would move because procurement signed a contract, with no evidence about the file having changed. |
| Train broad and report pooled metrics | Feed artifacts are easy — ingested largely *because* they are already known malware — so pooling inflates the headline with the rows we are not trying to be good at. A model excellent on feeds and mediocre on customer traffic would report a fine number. |
| Train broad without the provenance probe | Provenance is a near-perfect proxy for the label once feeds are in. Without the probe nothing detects that the model learned the ingestion path instead of the file, and every metric looks healthy while it happens. |

## Consequences

- **`P(Y|X)` is preserved, coverage is not.** Selection on features rather than on the
  outcome leaves the conditional intact, so a broader frame estimates the same thing.
  What broadening costs is data *where we deploy* and the ability to verify it there —
  hence the §1-sliced headline metric.
- **The headline number changes.** It is ROC-AUC on the §1 slice reweighted by `1/π_i`,
  not pooled AUC. Pooled is quoted nowhere. This will read as a *lower* number than a
  pooled one, and that is the point.
- **The provenance probe gains a second job.** It already gated injected-vs-organic; it
  now also gates feed-vs-customer. Above ~0.6 AUC, training broad is unsafe and the fix
  is the feature set, not the threshold.
- **§9 and §10 are complements, not independent choices.** Without stratification a
  broader frame would be swamped by feeds arriving at near-unanimous consensus; §9's 10%
  cap on `consensus malicious` and 45% floor on `contested` are what make breadth safe.
  Weakening §9's caps silently weakens this decision too.
- **Feeds still never touch the base rate.** Stage 08 calibrates on §1 only, which is what
  keeps the score off the procurement lever. Switching on a feed changes what the model
  has *seen*, never what the number *claims*.
- **Estimand bumps to version 4.** Still no results produced under any version.
