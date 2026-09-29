# 10 — Estimand B: settled-state labels over a decade

## Scope

An **alternative** estimand that trades A's clean horizon for breadth of age, so the two
can be compared. Written as a **delta against [`01-estimand.md`](./01-estimand.md)**
(Estimand A) — anything not restated here is identical to A.

## Status

**PROPOSED. Not frozen. No version number yet.** A is the pilot; this is the comparison
arm. It becomes frozen — and acquires `ESTIMAND_B_VERSION = 1` — only if the go/no-go in
§B8 says to build it. Rationale in
[`0009`](../decisions/0009-a-second-estimand-for-aged-artifacts.md); how to run it in
[`11-extraction-runbook-b.md`](./11-extraction-runbook-b.md).

## Invariants

- **B never mixes with A in one cohort.** Two label definitions in one column is the
  failure this whole repo exists to avoid. They are separate draws, separate models,
  separate snapshots, compared explicitly.
- Every field below is stated as *same as A* or *differs, because …*. No silent divergence.

---

## Why a second estimand at all

A is constrained to artifacts whose first sighting is recent enough that we can manufacture
a T+30 rescan — in practice, **submissions from the last month or two.** That is a
deliberate trade, and it buys a label whose meaning is tightly controlled. It also costs
three things:

1. **No temporal generalization measurement.** A cannot answer *"does a model trained on
   last year's malware work on this year's?"* — it has three weeks of data. That is the
   question a deployed model is actually judged on.
2. **No exposure to how threats evolve.** Packers, loaders, families and signing practices
   all change. A model that has seen three weeks has seen one draw from that process.
3. **A small, recency-skewed population**, which makes every confidence interval wide.

B exists to measure what that trade cost.

---

## The one structural difference

Everything else follows from this:

| | A | B |
|---|---|---|
| Label is | the state at **T+30** | the state once it has **converged** |
| Criterion | **time-based** | **stability-based** |
| Gap | fixed, and heterogeneity is a defect | variable by design, and irrelevant once converged |

A's label asks *"what had accrued by day 30?"* — so the gap must be controlled, because
accrual is still in progress. B's label asks *"what did this settle to?"* — and once an
artifact has demonstrably stopped moving, a longer gap adds nothing and costs nothing.

That is why B can use a 5-year-old artifact and A cannot. It is also why **B must verify
convergence rather than assume it**: an unsettled old artifact is not a settled one.

---

## §B1 · Reference population — *differs*

Windows PE, customer-submitted, public community — **same filters as A**, but spanning the
**full history of the index** rather than a recent window.

*First, find out what that history is.* `SELECT min(created), max(created) FROM
artifactinstance` — "ten years" is an assumption. The population may be considerably
younger, which changes how much breadth B actually buys.

> ⚠️ **Schema evolution is a trap peculiar to B.** A's filters (`scan_config`, `actions`,
> `meta_community`) are columns that were *added at some point*. On a row that predates a
> column, the value is NULL — and `scan_config IS DISTINCT FROM 'feed'` passes every one of
> them, regardless of what the row actually was. **Before trusting any filter over a long
> window, read the migration history and establish when each column began being written.**
> A filter that silently becomes a no-op on old data is how a feed-contaminated cohort
> would enter without anyone noticing.

---

## §B2 · Scoring moment — *same as A*

Bounty reveal, at the artifact's **first** sighting. Features are as-of that instant, per
the same as-of rule. What changes is only where the label comes from.

---

## §B3 · Label definition — *same taxonomy, different derivation*

The four labels of A §3, unchanged. The derivation differs:

**An artifact is labellable when its verdicts have demonstrably converged.** Concretely,
all three must hold:

| Condition | Provisional value | Why |
|---|---|---|
| Minimum elapsed time since T | **≥ 365 days** | accrual is front-loaded; a year is well past the knee |
| Minimum scans after T | **≥ 3** | one later scan cannot demonstrate stability, only assert it |
| Independent-cluster count unchanged across the last *K* scans | **K = 3**, spanning ≥ 90 days | this is the actual convergence test |

An artifact that fails the third condition is **`undecidable`**, not forced. That is A's
`03-labels.md` rule 4 promoted from a tiebreak into the definition.

**Why this is arguably a *stronger* label than A's.** A T+30 label is a snapshot of an
ongoing process — genuinely useful, and still moving. A settled label has survived years of
re-examination by an evolving engine roster. For the **negative class** especially, *"in
the corpus for five years, rescanned repeatedly, never detected by anyone"* is far better
evidence of benign than *"nobody flagged it in its first month."* It is the cheapest strong
negative available and needs no adjudication budget — which is the R9 problem approached
from the other side.

**Its grade is still 1.** Settled or not, it is engine-derived, so it may train and may
never calibrate. Both estimands hit the same wall, and only R3 gets past it.

---

## §B4 · Horizon — *replaced*

A's T+30 (with a T+180 churn re-check) is replaced by the convergence criterion in §B3.
There is no horizon parameter in B.

One consequence worth stating: **B cannot measure churn**, because it defines churn away.
A's T+180 re-check exists precisely to quantify how many 30-day-benign artifacts turn
malicious later; B assumes that process has completed. So the two estimands answer
complementary questions, and **A's churn rate is what tells us whether B's convergence
criterion is set correctly.** Run A first.

---

## §B5 · Split policy — *differs, and this is B's main prize*

Forward in time and family-grouped, as in A — but over years rather than weeks, which makes
a genuinely informative split possible:

- **Train on an era, test on a later era.** This measures temporal generalization directly,
  which is the deployment question and which A structurally cannot ask.
- Report **AUC as a function of the train/test era gap.** A curve that decays tells you the
  model's useful shelf life in months — an operationally actionable number that nothing
  else in this repo produces, and the input to how often retraining must happen (F10).

---

## §B6 · Primary metric — *same as A*

ROC-AUC on the §1 slice, reweighted by `1/π_i`. Never pooled, never accuracy.

---

## §B7 · Baselines — *A's four, plus two that only exist here*

| # | Baseline | Tells you |
|---|---|---|
| 1–4 | as in A §7 | floor, plumbing, malicious-engine-count, incumbent |
| **5** | **A's model, evaluated on B's test set** | does a recency-trained model generalize backwards? |
| **6** | **B's model, evaluated on A's test set** | does a breadth-trained model work on current traffic? — **the one that matters for deployment** |

Baseline 6 is the question the product actually asks. If B beats A on *current* traffic,
breadth was worth more than horizon cleanliness, and the pilot's design should change.

---

## §B8 · Decision rule — the comparison

The comparison is only interpretable if the confounds are controlled, which takes **three
runs, not two**:

| Run | Data | Features |
|---|---|---|
| **A-full** | A's cohort | full per-engine vocabulary (the pilot as planned) |
| **A-restricted** | A's cohort | the era-stable feature set (§B9) |
| **B** | B's cohort | the era-stable feature set |

- **A-restricted vs B** is the clean comparison: same feature space, so the only variable is
  the data.
- **A-full vs A-restricted** prices the restriction — how much the era-stable feature set
  costs on its own.

Comparing A-full directly against B would confound the data with the feature space and is
not a result.

**The shared evaluation slice.** A model cannot be "better" on a different target, so the
comparison needs artifacts carrying **both** labels: old enough to have settled, *and* with
a T+30 label reconstructable retrospectively. Artifacts around a year old satisfy both.

That slice yields a finding independent of either model: **how often do A-labels and
B-labels disagree?** That number *is* the cost of the 30-day horizon, in the only units that
matter, and it is worth producing even if B is never built.

**Proceed with B** if the shared slice exists at usable volume, the era probe (§B9) passes,
and A's churn rate suggests 30 days is leaving material accrual on the table. **Stop** if
the era probe fails — a model that can identify the era is not measuring maliciousness.

---

## §B9 · Sampling design — *A's §9, plus an era axis*

Stratify on engine agreement **and era**, targeting a roughly even artifact count per year
rather than proportional representation — recent years dominate the raw population, which is
exactly the skew B exists to correct. `π_i` is recorded per cell as in A, and is now doing
strictly more work, since the era imbalance it corrects is larger than the band imbalance.

### The era problem, and the feature set it forces

**The engine roster is not stable across years.** Engines join, leave and are replaced, so a
feature vector keyed by engine address is mostly *never-responded* for any artifact outside
the current roster's lifetime — and that missingness **correlates almost perfectly with
age**. A model would learn *"many absent engines ⇒ old ⇒ the base rate of old files,"* which
is a provenance detector wearing a feature's clothes.

Two mitigations, both required:

1. **An era-stable feature set.** Aggregate features that mean the same thing in any year —
   independent-cluster counts, malicious fraction over *engines that could have answered*,
   family specificity, retraction counts, the static PE block — plus per-engine columns only
   for engines present across the whole span. This costs real signal, which is exactly why
   §B8 prices it with the A-restricted run rather than waving it away.
2. **The era probe, as a gate.** Stage 06's provenance probe, third use: train a classifier
   to predict *era* from the feature set. **Above ~0.6 AUC the draw is rejected.** Fix the
   features, never the threshold.

---

## §B10 · Training population — *same posture as A*

Broad, feeds included, calibrate narrow. The `1/π_i` rule and the Postgres-only sourcing are
unchanged.

**One mechanical difference:** the PE-confirmation gate cannot come from OpenSearch for
historical artifacts. Before September 2026 an artifact only reached the metadata index if
something came back about it, so ES coverage over B's window is both incomplete and biased
toward successfully-analysed files. B must use the **Postgres-side PE test** — a `metadata`
row with `tool='pefile'` where `storage_path IS NOT NULL` (out-of-line ⇒ large ⇒ parsed) or
`tool_metadata ? 'imphash'` (inline success).

That test is a heuristic, and it is **checkable**: run both tests on the post-September
overlap where ES is trustworthy, and measure the disagreement. Do that before drawing.

---

## What B cannot do

Stated plainly, so B is not oversold:

- **It cannot calibrate either.** Settled consensus is still engine-derived, still grade 1.
  R3 remains the only route to a calibrated probability.
- **It cannot measure churn** — it defines it away (§B4).
- **It carries survivorship selection.** Artifacts still present and still being rescanned
  after years are not a random sample of their era. This is real, unfixable within B, and
  must be stated next to every B result.
- **It inherits whatever retention does.** Nothing in `artifact-index` writes `delete_at`,
  but whether some other service prunes rows is unknown — and B is the estimand that
  depends on the answer.

---

## Open questions specific to B

- **How far back does the data actually go?** One `SELECT`. Everything else is contingent.
- **When did each filter column start being written?** From the migration history. Until
  answered, no filter can be trusted over a long window.
- **The convergence parameters** — 365 days, 3 scans, K=3 over 90 days — are placeholders
  chosen before anyone looked. A's churn rate is the evidence that should set them.
- **Does the shared evaluation slice exist at volume?** Without it there is no comparison,
  only two unrelated numbers.
