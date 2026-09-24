# 03 — Labels

## Scope

The label taxonomy, the independence grades, and how the pilot's labels are produced.

## Invariants

- **The answer must come from somewhere the inputs did not.**
- Grade 0 is banned. Grade 1 may train and may never calibrate.
- The calibration and test sets take grade 3 only.

## The failure being avoided

The 2023 model's answer column was built by counting how many engines called a file
malicious and thresholding at three — using the very verdicts that are the model's
inputs. A model that perfectly reproduced the vote count would have scored flawlessly
and known nothing. Every metric that pipeline ever produced is uninterpretable for that
one reason.

Notably, the 2022 whitepaper **explicitly rejects** this method by name, listing
"combine malice labels from multiple anti-malware vendors" among approaches it
considered and discarded.

## Independence grades

| Grade | Where the answer comes from | May train | May calibrate / test |
|---|---|---|---|
| **0 — fatal** | a threshold on the same scan's verdicts | no | no |
| **1 — usable** | the *same* engines, read *30 days later* | **yes** | no |
| **2 — better** | a different modality: detonation behaviour, code-signing, curated known-good | yes | partially |
| **3 — gold** | a human adjudicating against §3 of the estimand | yes | **yes — only this** |

Grade 1 is the pilot's training label. It breaks the fatal circularity because the label
carries information the features do not — but it is still engine-derived, so it can
never validate a calibration curve.

> **Third-party aggregators sit at grade 1, not above it.** VirusTotal and its equivalents
> look like a cheap way to make labels ascertainable, and they are not: their engine
> rosters overlap ours heavily, so the same vendors supply our *features* and their
> *consensus*, and the label becomes partly a copy of the input. A model trained that way
> learns to predict what the overlapping engines said — something it already has — and
> estimand §8's `>0.97` stop rule fires, correctly.
>
> The ceiling is structural, not incidental: **grade measures independence from engine
> opinion**, so anything built out of aggregated engine opinion is capped at 1 however
> mature the system producing it. It therefore cannot touch the actual bottleneck, which
> is grade 3 — while the grade-1 path below already exists and costs nothing. Commercial
> and contractual exposure is discussed in [`0006`](../decisions/0006-stratified-sampling-with-recorded-inclusion-probabilities.md);
> the methodological objection stands on its own without it.
>
> Only two things raise the grade, and both are internal: **detonation** (grade 2, gated
> on R1) and **adjudication** (grade 3, gated on R3).

## Taxonomy

**Four labels for the pilot.** A seven-label taxonomy was specified first and collapsed;
what was folded, and why nothing was lost, is recorded below and in
[`0007`](../decisions/0007-four-labels-for-the-pilot.md).

| Label | Definition | Used for |
|---|---|---|
| `malicious` | meets the consent test in estimand §3 | **positive class** |
| `benign` | not harmful — whether positively attested or adjudicated | **negative class** |
| `unwanted` | PUP, adware, bundleware, disclosed miners, and legitimate tools frequently abused | rate only |
| `undecidable` | evidence genuinely conflicts, or dual review disagreed | rate only |

Train on `malicious` vs `benign`. Exclude `unwanted` and `undecidable` from both classes
and **report their rates** — the `undecidable` rate in particular is a finding, not a
nuisance: it measures how much of the problem is intrinsically ambiguous and therefore
caps how good any model can get.

### What was folded, and where the information went

Four labels is a claim about **how many categories a 10,000-file cohort can populate**,
not a claim that the world has four. Each fold either moved the distinction somewhere
better or removed something that was never a label:

| Was | Now | What happened to the distinction |
|---|---|---|
| `known_good` | `benign` | **Moved to the grade.** Positively-attested negatives (NSRL, valid signature from a known publisher, distro package) are grade 2; adjudicated-benign is grade 3; engine-derived benign is grade 1. The grade already carried "how good is this evidence," so a second label was duplicating it — and duplicated state drifts. |
| `dual_use` | `unwanted` | **Moved to a reason field.** Both were excluded from training and reported as a rate, so the fold changes no behaviour. It does blur the rate, so stage 03 records a reason per row and the rate is reported decomposed. |
| `excluded` | *not a label* | **Moved to the cohort filter.** EICAR, test files and non-scannable artifacts were never candidates; stage 01 drops them and reports the count. Labelling them pretended they were in the running. |

`Label` in [`labels.py`](../src/polyscore_v2/labels.py) has exactly these four, and
`assert_pilot_labels` refuses anything else — so a pre-collapse label cannot reach a
training split by accident and silently join a class it was never meant to be in. The
fold map is kept in `PILOT_COLLAPSE` so re-expanding later is deliberate rather than
archaeological. **Re-expanding is a new estimand version, not a code change.**

### Reporting the rates

"Report their rates" needs a denominator, and the §9 stratified draw means there is more
than one honest answer. Report **three** numbers per rate-only label:

| Number | Denominator | Answers |
|---|---|---|
| **Raw** | the drawn cohort | how much *training data* we lost. This is the one that corrects "the 10k pilot" to its real size. |
| **Reweighted** | `1/π_i` over the draw | what fraction of *the population* is like this. **This is the one that is a ceiling** on production quality. |
| **Per stratum** | within each §9 band | a free sanity check — see below. |

Raw and reweighted differ, and the direction is predictable: §9 deliberately
over-weights the contested band at 45%, and `undecidable` concentrates in exactly that
band, since "engines disagree" is close to the definition of both. **So the raw rate
overstates the population rate**, and quoting it as a production ceiling would be wrong.

The per-stratum split is worth the line it costs: `undecidable` *should* be concentrated
in contested and near-absent at the consensus ends. If it comes back roughly uniform
across bands, the labelling is not tracking difficulty and the rule is wrong before any
model is fitted.

One caution on reading the `undecidable` rate at all: it is partly **our** artifact. Rule
4 below *forces* `undecidable` when a detection count oscillates, so tightening that
stability threshold moves the rate. It measures the label process as much as it measures
the files — useful, as long as nobody quotes it as a pure property of the corpus.

### Worked edges

A covert miner is `malicious`; a disclosed one is `unwanted`. PsExec is `unwanted` with
reason `dual_use` — an informed owner would consent to a sysadmin tool, so it is not
malicious, but it is not something to train a negative on either. A Cobalt Strike beacon
with an attacker's address baked in is `malicious` even though the framework installer is
`unwanted`/`dual_use`; configuration changes the answer. A legitimate signed DLL abused by
sideloading is `benign` — the file is fine, the campaign is not, and we score files.

## Producing the pilot's labels

1. **Wait out the horizon**, then pull each artifact's verdicts again at T+30.
2. **Count independent clusters, not engines.** Five detections are not five opinions if
   four of those vendors license the same signature feed. Three independent *clusters*
   is a far stronger bar at identical cost.
3. **Weight family specificity.** Two independent clusters naming a specific family is
   near-dispositive; five engines saying `Trojan.Generic` is weak. Generic and heuristic
   names are discounted.
4. **Require stability.** A count steady for weeks is settled; one oscillating between 1
   and 4 is `undecidable` rather than forced.
5. **Mine the retractions.** A vendor that detected a file and later *stopped* is
   actively asserting "we were wrong." These are the strongest negatives available and
   they land exactly on the hard cases. The old extraction already pulls them and throws
   the signal away.
6. **Carve out a gold slice** — even 200 files, hand-adjudicated against estimand §3,
   drawn **at random** rather than from the interesting end.

## Why the gold slice matters more than its size suggests

Two hundred files cannot train anything. What they do is **measure how wrong the cheap
labels are** — an error rate that is otherwise completely unknown and that caps model
quality. They also tell you whether the cluster threshold should be three or four, and
they are the only thing that can ever validate a calibration curve.

Draw at random. Adjudicating the files the model found interesting teaches you only
about the region the model already believed in — that is verification bias, and it is
how a system becomes confident about what it already thought.
