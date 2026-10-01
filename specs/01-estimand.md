# 01 — The estimand

## Scope

The ten decisions that define what the number means. **Frozen.** Changing any of
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

### How this is enforced

**Not by the training frame.** §10 trains deliberately broader, so nothing about §1 is
enforced there. It is enforced in exactly one place: **stage 08 fits the calibrator on
the §1 subset of held-out data**, reweighted by `1/π_i`. The calibrator is two fitted
floats, and those two floats *are* this population's base rate — so §1 lives in the
serving path as a parameter, nowhere else.

Today that is prose plus a config flag (`reference_excludes_feeds`), not a guard. Unlike
the as-of rule, the label grades and the sampling bookkeeping, **nothing raises if the
calibrator is fitted on the wrong rows** — it would run clean, produce a healthy-looking
reliability diagram, and be wrong by a constant. Worth closing.

### One population is a choice, not a limit

Because the calibrator is a separate 1-in-1-out artifact, **several can exist over one
model with no retraining** — each is two more floats. That makes per-file-type, per
coverage tier, per-population and even **per-customer** calibration reachable
([`08-future-work.md`](./08-future-work.md) F3, F4), tailoring what the number means to
the population a given consumer actually sees.

Three things bound it:

- **Labels, not compute.** Each calibrator needs its own held-out *adjudicated* set. The
  200-file gold slice split six ways is ~33 files and one or two positives per cell —
  unfittable. The real ceiling is R3's budget.
- **Routing must be stable and knowable at scoring time.** A file that moves between
  calibrators gets a different number with no evidence having changed.
- **Per-customer calibration trades away a property we have otherwise held.** Two
  customers would see two numbers for the same artifact. That is a defensible product
  decision — their populations genuinely differ — but it is in direct tension with
  "the score should not depend on who is looking," and it should be taken deliberately
  rather than arrived at. It is also only valid under *label* shift; if tenants differ
  in file-type mix rather than just base rate, a prior shift repairs the aggregate while
  making per-band calibration worse (F4).

The cheap first move is not to split at all: fit one calibrator, **report reliability per
group anyway**, and split only where the curves visibly diverge. That keeps it a
measurement rather than an architectural guess.

*This section describes how §1 is enforced and does not change what §1 decides, so it
carries no version bump.*

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
first two; report the other two as rates.

*Why four and not seven.* A finer taxonomy was specified first — separating attested
`known_good` from adjudicated `benign`, `dual_use` from `unwanted`, and carving out
`excluded` — and was **collapsed for the pilot** ([`0007`](../decisions/0007-four-labels-for-the-pilot.md)).
Four is a claim about how many categories a 10,000-file cohort can populate, not about
how many the world has: at realistic prevalence the finer classes hold tens of files
each, which is too few to train on, too few to measure a rate from, and enough to make
every count look more precise than it is. Nothing was discarded — the attestation moved
to the **grade**, `dual_use` to a **reason field**, and `excluded` to the **cohort
filter**, where it belonged.

*Why the two rate-only labels are not folded into the binary.* Because the size of that
decision is unknown until it is measured. If `unwanted` is 1% of traffic, folding it
either way is a footnote; at 25% it is the single biggest determinant of what the score
means. Excluding them from training does **not** exclude them from production — the model
scores them anyway, having never seen one — so the rate is how that blind spot is sized.
Re-expanding the taxonomy is a new estimand version, not a code change.

Full taxonomy, the fold map and the rate denominators in
[`03-labels.md`](./03-labels.md).

## 4 · Horizon

**Malicious as of when?**

**T+30 days** from first sighting, with a **T+180** re-check on a subsample.

*Why.* Thirty days captures most detection accrual while still fitting inside a pilot.
The 180-day re-check yields the **churn rate** — the fraction of files called benign at
30 days that turn malicious later — which is a hard floor on the lowest score that can
honestly be emitted, and settles whether a true zero is reachable at all.

*T+30 is a target with a tolerance, not a floor.* No scan lands exactly on the horizon,
so the label comes from the **nearest scan at or after it** — but "at or after" cannot mean
*any* later scan. Detection accrual is roughly monotone, so a label taken at T+400 reflects
an order of magnitude more accrual than one at T+31; mixing them puts two different
measurements in one column. Worse, the spread is not random: rescan timing is user-driven,
so a long gap correlates with how interesting somebody found the file.

*Exactly 30 is neither achievable nor required.* A rescan is enqueued, queued, then runs
a bounty with its own window before it reveals, so even a forced rescan lands at T+30 plus
hours. What matters is **homogeneity** — that every row's label is the same measurement —
not the integer 30.

Two ways to schedule the forced rescan, and they differ by more than convenience:

| Schedule | Resulting gaps |
|---|---|
| **One batch**, at `max(T) + 30` | `[30, 30 + window_width]` — a one-week freeze window yields 30–37 day gaps. Narrowing the window tightens the label and shrinks the cohort |
| **Daily tranches** — each day's submissions rescanned 30 days later | **≈30 days for every row, at any cohort size.** Costs a scheduled job instead of one command, and dissolves the size-versus-homogeneity trade |

Prefer tranches. The batch form is the fallback when a scheduled job is not available.

*The deeper reason forcing beats waiting.* A forced rescan does not remove variance — it
removes **correlated** variance. Natural gaps are set by when somebody chose to look at the
file again, which correlates with how interesting it is, and therefore with the outcome.
Scheduled gaps are set by us and correlate with nothing about the artifact. A ±7-day spread
we created is harmless; a ±7-day spread that selected on interest is not.

So the pipeline **records the realized gap per row** and bounds it above. The bound is a
parameter (`horizon_max_days`), set from the gap distribution stage 02 reports rather than
guessed — and if gaps turn out to be systematically longer for contested artifacts than for
consensus ones, the heterogeneity is correlated with difficulty, which is the worst
available shape for it and a reason to stop.

This is also why the T+180 re-check is a **separate** measurement rather than a wider
window: churn is the thing being measured, so it cannot also be absorbed into the label.

> **This horizon is what constrains A to recent artifacts**, and it is not repairable by
> choosing a different T. An artifact first seen five years ago, rescanned today, yields a
> T+1825 label; and two scans thirty days apart in its third year give a clean gap and a
> near-worthless label, because accrual is front-loaded and by then the verdicts have
> stopped moving. The alternative — a **stability-based** label criterion that can use aged
> artifacts — is drafted as [Estimand B](./10-estimand-b-settled-state.md) and run as an
> explicit comparison ([`0009`](../decisions/0009-a-second-estimand-for-aged-artifacts.md)),
> not as a replacement. A's churn rate is what should set B's convergence parameters, so
> **A runs first.**

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

**How is the cohort drawn from the training population (§10)?**

> Not from §1. §1 is the *reference* population — the denominator that makes the
> probability mean something — and it is deliberately narrow. What the model may **learn
> from** is a different and broader question, answered in §10. Conflating them was a
> defect in version 3 of this file.

**Stratified on engine agreement at the scoring moment, with every artifact's inclusion
probability `π_i` recorded at draw time.**

Let `m` = malicious assertions ÷ engines that **gave a definite verdict** (malicious or
benign), evaluated at the scoring moment. Engines that answered `unknown` (`verdict IS
NULL`) and engines that never responded (no row) are **excluded from the denominator**,
not counted as benign — collapsing either into `0` is the 2023 model's error.

> This matches the stored `detections` JSONB (`{benign, malicious, total}`, where
> `total = benign + malicious`), so `m = malicious / total` — but **compute it from the
> assertion rows, not from that column**: `detections` is recomputed by admin backfills
> with nothing recording when, so it can be far younger than its own scan.

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
reported separately and never folded into a band by a noisy ratio.

> **Make the floor relative, not absolute.** Measured on six stage artifacts 2026-09-30:
> typical coverage was **15–16 answering engines**, and the one artifact whose T scan
> caught only **7** produced the sample's largest apparent change — `m` moved 2/7 → 7/14
> with **zero engines changing their verdict**. The entire move was the engine sample
> filling in, and the newcomers skewed malicious (5/7) against the originals (2/7).
>
> A flat floor of 5 would have admitted that artifact. A floor expressed as a *fraction of
> typical coverage* would not. The floor is still unset pending prod volume, but it should
> be specified relative to the observed distribution rather than as a bare count.

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

## 10 · Training population

**Which files may the model learn from?**

**Every PE artifact PolySwarm holds inside the window — feeds included — plus §9's
injection arm.** Deliberately broader than §1.

*Why it is a separate decision.* §1 answers *what the number is about*; this answers
*what the model may see*. They are different objects and forcing them to coincide buys
nothing: the reference population must stay narrow so the base rate describes files a
customer would recognise, while the model needs coverage of the feature space — above all
the contested region, which the customer-submitted frame is far too thin to supply. Feeds
are abundant and carry labels.

*Why this is statistically safe.* Selection that depends on the **features** rather than
on the outcome preserves `P(Y|X)`, so a model trained on a broader frame estimates the
same conditional. What broadening costs is coverage in the deployment region and the
ability to verify it — which is exactly what the guards below are for. Selection on the
**outcome** is a different matter and is handled by §9's recorded `π_i`.

*Why §9 is what makes this safe.* Without stratification, feeds would swamp the cohort:
they are ingested largely because they are known malware, so they arrive at near-unanimous
consensus and would pile into one band. §9 caps `consensus malicious` at 10% and holds
`contested` at 45%, so a broader frame fills the bands it can and the hard region keeps
its share. The two decisions are complements, not independent choices.

### Three guards, and the line they protect

1. **Feature hygiene.** No provenance-bearing column may become a feature — not
   `scan_config`, tenant, submission timing, ingestion path, `stratum` or `provenance`.
   Enforced by `FORBIDDEN_AS_FEATURES` and `BOOKKEEPING_NOT_FEATURES` in
   [`features.py`](../src/polyscore_v2/features.py). Without this the model learns
   *where a row came from*, and feed-provenance is a near-perfect proxy for the label.
2. **The provenance probe** (stage 06) extends to **feed-vs-customer**, not only
   injected-vs-organic. Above ~0.6 AUC the frames are separable from the features alone
   and training broad is not safe — fix the features or narrow the frame.
3. **The headline metric is computed on the §1 slice**, never pooled. A model that is
   excellent on feeds and mediocre on customer submissions must not be able to report a
   good number, and pooled metrics let it.

**The line: training may be broad, calibration may not.** Stage 08 fits the calibrator on
§1's population, reweighted by `1/π_i`. The model learns from everything; the probability
speaks about something specific. That separation is what keeps feeds out of the base rate
— so switching on a new feed contract changes what the model has *seen* and never what
the number *claims*, which was the whole objection to a store-wide reference population.

---

**Estimand version:** `4` · frozen 2026-09-24 · unsigned

| Version | Change |
|---|---|
| 1 (2026-09-22) | §1–§8 established |
| 2 (2026-09-24) | §9 sampling design; per-artifact counting rule in §1 — [`0006`](../decisions/0006-stratified-sampling-with-recorded-inclusion-probabilities.md) |
| 3 (2026-09-24) | §3 collapsed to four labels for the pilot — [`0007`](../decisions/0007-four-labels-for-the-pilot.md) |
| 4 (2026-09-24) | §10 training population, separated from §1's reference population — [`0008`](../decisions/0008-training-population-is-broader-than-the-reference-population.md) |

**No results have been produced under any version**, so no version bump here has
invalidated anything. That stops being true the moment stage 09 runs once.

Record the signatory here when agreed. Any change to §1–§10 requires a version bump and
a record in `decisions/`.
