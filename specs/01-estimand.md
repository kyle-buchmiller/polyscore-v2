# 01 — The estimand

## Scope

The nine decisions that define what the number means. **Frozen.** Changing any of
them invalidates every result produced under the old version; bump the version at the
bottom and record the change in `decisions/`.

## Invariants

- Written **before** any code, and not revised to suit a result.
- Every metric, gate and support answer elsewhere in this repo is defined relative to this file.
- A result quoted without naming the estimand version it was produced under is not a result.

---

## 1 · Reference population

**Which files is this number a probability about?**

Windows PE files submitted to the **public community by customers — not by bulk feeds
— in a fixed, closed date window.** Feed rows carry `scan_config = 'feed'` and are
excluded.

*Why.* A probability is always a probability for a group; change the group and the same
model is wrong, structurally rather than approximately. The score's job is to answer
"should I care about this file somebody handed us." Bulk malware feeds are a different
question and they dominate volume, so leaving them in makes the base rate mostly a
measure of how many feeds are switched on — the 29:1 imbalance that broke the 2023
model.

*If volume falls short*, widen it — and record here that you did, and that the base rate
is inflated as a result.

*Counting rule.* **Per artifact, deduplicated on sha256 — never per scoring event.** A
file a thousand customers look up counts once. Per-event weighting would make the base
rate a function of who happened to be querying that month: a threat hunter bulk-checking
corporate software and a blue-team analyst working an incident pull it in opposite
directions, and nothing distinguishes them. It is also the weighting that makes 0001's
sentence literally true — the promise is "X% of *files* like this," not "X% of lookups
like this."

> **Known gap — files customers hold but never submitted.** A customer who finds a file
> on their network hash-searches first, and uploads only if the search misses, *and*
> policy permits, *and* they still choose to. Submissions are therefore approximately
> `novel ∩ suspicious-enough-to-justify-the-paperwork`, and any file already in PolySwarm
> is invisible to this frame even while sitting on a customer's disk — yet we serve a
> score for it on every hash lookup. The frame describes what we *store*, not what we
> *answer for*.
>
> This does not bind on the pilot. Per [`0004`](../decisions/0004-labels-time-separated-for-the-pilot.md)
> the pilot's labels are grade 1 and may never calibrate, and the reference population is
> the denominator for *calibration*. Settle it before calibration is real, not before
> training is. The candidate fix — membership by lookup-or-submission, counted once, the
> log answering "did anyone ask about this file" and never "how often" — is recorded in
> [`08-future-work.md`](./08-future-work.md).

> **Date caveat.** Until early September 2026 an artifact only reached the metadata
> index if something *came back* about it. A cohort drawn from the historical index
> over-represents successfully-analysed files, which is the opposite of what the
> negative class needs. Prefer a window after **2026-09-08**, or state the skew here.

## 2 · Scoring moment

**At what instant is the evidence frozen?**

**Bounty reveal** — the instant the assertion window closes.

*Why.* It is the moment production already computes PolyScore, so results are directly
comparable to the incumbent, and engine evidence is naturally complete. A real-time
variant (submission + 15 min) is a genuinely different and harder prediction problem;
it is deferred, not dismissed.

## 3 · Label definition

**What does "malicious" mean?**

An artifact is **malicious** if, run as intended in a typical environment, it does
things a fully-informed owner of that machine would not agree to, for someone else's
benefit — assessed as of a stated date.

Four labels, not two: `malicious`, `benign`, `unwanted`, `undecidable`. Train on the
first two; report the other two as rates. Full taxonomy in
[`03-labels.md`](./03-labels.md).

## 4 · Horizon

**Malicious as of when?**

**T+30 days** from first sighting, with a **T+180** re-check on a subsample.

*Why.* Thirty days captures most detection accrual while still fitting inside a pilot.
The 180-day re-check yields the **churn rate** — the fraction of files called benign at
30 days that turn malicious later — which is a hard floor on the lowest score that can
honestly be emitted, and settles whether a true zero is reachable at all.

*Practical note.* A T+30 label only exists for files actually rescanned around then,
and rescans are user-driven and therefore non-random. Freeze the cohort, bulk-enqueue
its rescans (`ai instance rescan <start> <end>`), and harvest labels after the horizon.

## 5 · Split policy

**How is the data divided so the test is honest?**

Forward in time **and** grouped by family. Earliest ~60% train, next ~15% validate,
last ~25% test, with a gap of at least the label horizon between the end of training
and the start of testing. Grouping key: TLSH cluster, falling back to `imphash`.

The naive random split is **also computed and reported, clearly labelled optimistic**.
The gap between the two is a deliverable: it is the honest measure of how much apparent
performance was memorisation.

## 6 · Primary metric

**Which single number decides whether this worked?**

**ROC-AUC**, always quoted next to the baselines in §7.

Brier score and a reliability diagram are produced as well, but for the pilot they are
a **process demonstration, not a result** — with derived labels, a calibration number
measures agreement with our own label rule, not calibration.

**Accuracy is never the headline.** The 2023 model reported 0.9628; answering
"malicious" every time scored 0.9666 on the same data.

## 7 · Baselines

**What must the number beat to mean anything?**

Printed first, always, so the model's number never appears alone.

| # | Baseline | What it tells you |
|---|---|---|
| 1 | Constant (always the majority class) | the absolute floor |
| 2 | Prevalence-random | confirms the plumbing is not inverted |
| 3 | **Count of engines asserting malicious at T** | **the one that matters** — the dumbest thing that could work |
| 4 | The incumbent PolyScore (stored per scan) | what we are replacing |

## 8 · Decision rule

**What result makes us proceed, and what makes us stop?**

- **Proceed** if baseline 3 lands in **0.85–0.95 AUC** — high enough that the labels
  carry signal, low enough that they are not merely restating the features — **and**
  the trained model beats it by more than the seed-reshuffle noise band.
- **Stop and fix the labels** if baseline 3 exceeds **~0.97**. The answer column is a
  near-copy of the input column and nothing downstream can measure anything.
- **Stop and check the plumbing** if baseline 3 is near **0.5**. Something is
  disconnected.

A model that merely *ties* baseline 3 is a real and useful result: it says the rebuild's
value lives in calibration and abstention rather than in ranking.

## 9 · Sampling design

**How is the cohort drawn from that population?**

**Stratified on engine agreement at the scoring moment, with every artifact's inclusion
probability `π_i` recorded at draw time.**

Let `m` = malicious assertions ÷ engines that answered, evaluated at the scoring moment.

| Stratum | Rule | Target share |
|---|---|---|
| **Contested** | `0.2 < m < 0.8` | **45%** |
| Leaning malicious | `0.8 ≤ m < 1.0` | 15% |
| Leaning clean | `0 < m ≤ 0.2` | 15% |
| Consensus malicious | `m = 1.0` | 10% |
| Consensus clean | `m = 0` | 10% |
| Injected known-good | not drawn — see below | 5% |

Shares are **targets for the draw, not claims about the world.** They are provisional
until stage 02 reports how many artifacts each band actually holds. A band that cannot
fill its share is *reported*, never quietly back-filled from another.

*Why stratify at all.* A flat draw at realistic prevalence yields too few positives to
fit anything, and gives no control over how many hard cases are present.

*Why on agreement rather than on the label.* There are no labels at draw time — that is
the entire difficulty. Agreement is visible at reveal, costs nothing, and correlates with
the label without being it.

*Why the contested band is over-represented.* It is the only region where a hash lookup
has not already answered the question, so it is where the score earns its keep. Drawing
the confident ends instead — "most-definitely-bad" and "most-definitely-good" — deletes
the middle, and a model that has never seen a hard case must extrapolate into exactly the
region where it is deployed. `P(Y|X)` survives such a draw; usable data in the deployment
region does not, and calibration there becomes unverifiable. This is the 2023 frame's
failure on a different axis: it filtered to malicious assertions before labelling and so
contained no artifact that nobody had detected.

*Why `π_i` is recorded.* **Reversibility.** One draw then serves both views — weight by
`1/π_i` for the natural-prevalence view that calibration and every rate metric require,
or take the raw stratified draw for the balanced view that training wants. This is
strictly better than `class_weight` or synthetic oversampling, which reach the same
balance irreversibly. **A draw made without `π_i` cannot be corrected afterwards by any
means**, which makes this the one decision here that is unrecoverable if skipped.

*Minimum answering engines.* `m` is meaningless when two engines answered — one verdict
moves it by 0.5. Artifacts below a floor of answering engines form their own stratum,
reported separately and never folded into a band by a noisy ratio. **The floor itself is
not yet set**; it needs the distribution of answer counts, which stage 02 produces.

> This is a *different* axis from the **coverage tier** in [`06-signals.md`](./06-signals.md),
> which counts available *signal families* (signature, sandbox, static) rather than engine
> responses. Both are routing keys and neither is a feature, but they partition the data
> differently and must not be conflated.

### The injection arm

The 5% known-good slice is **not drawn from PolySwarm.** It is externally sourced — NSRL
joins against artifacts already held, vendor retractions, commodity package corpora,
internal build artifacts — to cover a negative class the platform genuinely lacks (R9).
Three rules contain it:

1. **It never participates in prevalence estimation or `1/π_i` reweighting.** Its
   inclusion probability is undefined by construction. It anchors the feature space; it
   does not describe the population.
2. **It carries a provenance column, excluded from features.** If injected known-good
   arrives as a batch while malicious arrives organically, then tenant, timestamp,
   `scan_config` and coverage patterns separate the classes perfectly and the model
   learns the upload instead of the file.
3. **A provenance probe gates the run.** Train a classifier to predict injected-vs-organic
   from the *feature set*; above ~0.6 AUC the negatives are poisoned and the draw is
   rejected. The same probe answers the feed-vs-customer question.

*Value ordering inside the arm.* A negative's worth is inversely proportional to how
obviously benign it is. Unsigned internal build artifacts and vendor retractions are worth
more than signed Microsoft binaries, which anchor the bottom of the scale and teach little
else.

### Augmentation

Strata may be topped up as the draw proceeds. **Augment on counts, never on performance.**
"This stratum is below its target N" is a sampling decision. "The model does badly here"
is a result, and feeding it back into the draw spends the test set without anyone
noticing. The look-once rule in [`05-evaluation.md`](./05-evaluation.md) extends to
sampling decisions.

---

**Estimand version:** `2` · frozen 2026-09-24 · unsigned

Version 1 (frozen 2026-09-22) added §1–§8; version 2 adds §9 and the per-artifact counting
rule in §1, per [`0006`](../decisions/0006-stratified-sampling-with-recorded-inclusion-probabilities.md).
No results were produced under version 1.

Record the signatory here when agreed. Any change to §1–§9 requires a version bump and
a record in `decisions/`.
