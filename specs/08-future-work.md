# 08 — Future work

## Scope

Work that becomes possible **once the retrain lands and the score is a calibrated
probability**. Nothing here is startable today; each item names what it waits on.

## Invariants

- Every item names its **gate** — the thing that must be true before it can begin.
- Nothing here is a commitment. This is a register of what success unlocks.
- If an item turns out to be startable now, it belongs in a spec, not here.

## The three registers, and which is which

| Register | Holds | Owner |
|---|---|---|
| [`99-open-questions.md`](./99-open-questions.md) | decisions **we** owe, blocking now | us |
| [`07-requests.md`](./07-requests.md) | capabilities **others** own, blocking now | other teams |
| **this file** | work unlocked **later**, by success | us, eventually |

## The gate almost everything shares

Most of this waits on the same thing: **a calibrated score, validated against
independently adjudicated labels.** That needs grade-3 labels, which needs
[R3](./07-requests.md) — the adjudication workflow with sampling probabilities recorded
at draw time. R3 is the single upstream dependency for most of this page.

---

## F1 · The ranking number

- **Gate:** a shipped calibrated `polyscore`. Nothing else.
- **Size:** small — a window function and two product decisions.

Decided in [`decisions/0001`](../decisions/0001-contract-is-a-calibrated-probability.md),
which is authoritative on the *direction*. This section is the **design**, restated to
stand alone — if the two ever disagree, 0001 wins and this is stale.

### The one-line answer, for when it comes up

> A ranking is a **percentile of the calibrated probability over a named cohort**. It
> comes almost free once the probability is real — but it cannot be built first, because
> you cannot recover a probability from a rank.

### Why the direction is one-way

This is the part worth being able to say precisely, because the instinct to build the
ranking first is reasonable and wrong.

**Probability → rank** is arithmetic. Sort the cohort by `polyscore`, take percentiles.
No labels, no second model, no second calibration.

**Rank → probability** is not recoverable. A rank carries no magnitude, so the same
top-ranked file is:

| Population base rate | What "top of the queue" actually means |
|---|---|
| 2% malicious | ≈ 6% likely |
| 30% malicious | ≈ 96% likely |

Same rank, different answer. Recovering the probability needs the base rate *and* the
score distribution — which needs labels, which is exactly what makes the probability
expensive. So the ordering is forced.

Three consequences worth carrying into the conversation:

- **Calibration is monotone**, so the calibration step cannot reshuffle the ordering —
  the rank you get from the calibrated score is the rank you would have got from the raw
  one. Both readings come from one model, one version, one story.
- **A rank always exists.** You can always sort. So a rank-primary system has no way to
  express *insufficient evidence* — it would manufacture a queue position for a file it
  knows nothing about. Probability-primary can abstain, which is what retires the 0.3346
  constant for good.
- **A probability is stable; a rank moves.** A file's `polyscore` changes only when its
  evidence changes. Its queue position changes whenever the queue does. That is the
  argument for putting the probability in the coloured UI and offering rank as an
  explicitly-labelled triage tool — and it answers the objection that a file should not
  change colour without changing.

### What it still needs decided

**Which cohort?** "Percentile among what?" needs an answer exactly as the probability
needs a named population. Candidates: the last 24 hours of submissions; a rolling 30-day
window; one customer's own stream. Each gives a different number for the same file, and
per-customer means two customers see two ranks for one artifact — a support conversation
worth choosing deliberately rather than discovering.

**Recomputed how often?** A rank is only as fresh as its cohort. Continuous recomputation
is expensive and makes the number jitter; a daily snapshot is cheap and stale by up to a
day.

### The traps

**Rank on the raw score, never the calibrated or displayed value.** Isotonic calibration
maps large blocks of files to an identical probability, and within a block the sort order
collapses to whatever it is stable on — insertion order, or sha256. The probabilities
would look right while the analyst queue was quietly ordered by hash. Display rounding
does the same thing at coarser granularity.

**Name it something that is not `polyscore`.** Two numbers in one field is how the
current mess started. `triage_rank` or `queue_percentile`, documented as drifting by
design.

---

## F2 · Publish a calibration report per model version

- **Gate:** measured calibration on an adjudicated sample.
- **Size:** small, once the measurement exists.

The reliability diagram, ECE, Brier decomposed, the reference population and its measured
prevalence, the abstain rate, and the trivial baselines — regenerated on every promotion.

This is what **replaces the 2022 whitepaper's "97% accuracy"** with something checkable,
and it is the honest end of the disclosure thread: a contract that can be regenerated
monthly cannot silently freeze for three years the way the last one did.

---

## F3 · Per-file-type calibrators

- **Gate:** enough adjudicated labels per type, plus a typing-stability measurement.
- **Size:** medium.

**Share the ranker, split the calibrator.** Calibration genuinely *is* per-population —
different file types have very different base rates — so splitting there captures most of
the benefit at a fraction of the label cost of separate models.

Two measurements first.

**Label count per type.** This is the binding constraint, and the arithmetic is
unforgiving. The pilot's gold slice is **200 files** ([`0004`](../decisions/0004-labels-time-separated-for-the-pilot.md));
split six ways that is ~33 each, and at realistic prevalence perhaps one or two positives
per type. You cannot fit a calibration curve on two positives. Even a tenfold larger
adjudication budget lands at a few hundred per type — thin, but workable. So this item is
gated on **label volume**, not on modelling effort, and the volume question is
[R3](./07-requests.md)'s.

**Typing stability.** Over files scanned twice or more, what fraction change resolved
type? Above ~0.5% is a product problem before it is a modelling one.

Prefer type as a **conditioning feature** over type as a **routing key** — a feature
degrades gracefully when typing is wrong, a router does not.

---

## F4 · Per-tenant calibration

- **Gate:** adjudicated labels drawn from individual tenant streams.
- **Size:** medium, and it carries an ongoing support cost.

A probability is population-relative, so a customer whose traffic mix differs from the
reference population gets a number that is wrong *for them* — structurally, not
approximately. The cheap correction is a one-parameter prior shift in log-odds.

**The caveat that decides whether it works.** A prior shift is valid only under *label
shift* — the same evidence meaning the same thing, just at a different base rate. If
tenants differ in file-type mix, size distribution, or which engines are even
type-capable, that is *covariate* shift, and a prior correction moves the intercept while
leaving the slope wrong. Aggregate calibration then looks repaired while per-band
calibration degrades. Test the assumption before applying the correction.

---

## F5 · Certificate reputation from our own corpus

- **Gate:** the label store ([R3](./07-requests.md)).
- **Size:** medium.

**Recorded in full as [R7](./07-requests.md#r7--a-certificate-reputation-source)**, whose
"cheapest route" *is* this item: a thumbprint that has signed N artifacts later
adjudicated malicious, computable from the corpus this repo already assembles.

Listed here only so the register is complete — it is the one request that becomes
buildable *by us* on success rather than needing another team. The detail lives in R7;
do not restate it here.

---

## F6 · Sandbox as genuine evidence

- **Gate:** [R1](./07-requests.md) (a random detonation arm), then [R5](./07-requests.md) (bulk report access).
- **Size:** large.

The signal design already exists in [`06-signals.md`](./06-signals.md). What does not
exist is a population it can speak about: detonation is gated on a family resolved from
engine assertions, so behavioural evidence can only inform artifacts engines already
flagged — the region where the score matters least.

Once R1 lands, sandbox becomes the most genuinely *independent* evidence available,
because it is a different modality: what the file did, not what somebody thought of it.

---

## F7 · URL, domain and IP scope

- **Gate:** the file model working, plus a labelled non-file population.
- **Size:** large — it is a second model, not an extension.

Non-file artifacts get a **NULL `polyscore`** today — which is the right answer, arrived
at by accident: the 2022 whitepaper scopes PolyScore to files, and no non-file population
was ever trained or validated. But NULL covers nine unrelated situations
([R4](./07-requests.md)), so "out of scope" is currently indistinguishable from "lost
callback." Making that distinction expressible is R4's job and comes long before this.

A URL score needs its own training population, its own reference population and its own
calibration. It is a second model, not a wider one.

Two calibrated probabilities **are** comparable across types when the label definition and
horizon match. Two per-type *ranks* never are — so a mixed-type queue must always be built
from probabilities.

---

## F8 · Unify arbitration and the score

- **Gate:** a calibrated score.
- **Size:** medium, and mostly a product decision.

Today the platform emits **two unrelated verdicts on the same artifact**: `polyscore`, and
arbitration's boolean OR over arbiter votes. Neither consults the other. A file can be
arbitrated malicious and render green.

Once the score is calibrated, the relationship is expressible — arbitration's cutoff
becomes a stated threshold on a meaningful scale rather than a parallel opinion.

**The trap:** arbitration must not become an input to the score while the score is an
input to arbitration. Arbiter names are already columns in the old model's vocabulary, and
three of four deployed arbiters share a vendor with a scanning engine voting on the same
artifact. Relate them; do not feed them to each other.

---

## F9 · A real-time scoring moment

- **Gate:** the reveal-time model working, and a coverage story for partial evidence.
- **Size:** large.

Scoring at submission + ~15 minutes rather than at bounty reveal. Genuinely useful — it is
what a customer waiting on a verdict actually wants — and genuinely *a different and
harder prediction problem*, because most engines have not answered yet.

The combiner architecture makes it tractable rather than easy: score early at a low
coverage tier, re-run the combiner as evidence arrives. Two coverage regimes, two
calibrators, and an explicit product decision about what an early score is allowed to
claim.

---

## F10 · Scheduled retraining, registry, shadow evaluation

- **Gate:** one successful hand-run retrain.
- **Size:** medium.

The operational maturity that should follow a first success rather than precede it: a
parameterised pipeline on a schedule, models loaded by version from a registry rather than
baked into an image, shadow evaluation on live traffic before promotion, one-deploy
rollback, and the roster-drift and point-mass alarms from the rebuild plan.

Deliberately last. Monitoring a system that has not shipped is premature — but this is
what stops the next model freezing for three years without anyone noticing.
