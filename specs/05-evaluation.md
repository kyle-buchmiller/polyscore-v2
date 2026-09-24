# 05 — Evaluation

## Scope

What testing means here, which numbers to produce, and the rules that make them worth
anything.

## Invariants

- **The test split is opened once.**
- No metric is ever quoted without its baselines.
- Accuracy is never the headline.

## What "testing" means

Not unit tests. It means: run the frozen model over files it has never seen and compare
its answers to the truth. The test split exists for exactly this and has been untouched
by every prior stage — which is the only reason its verdict means anything.

## The look-once rule

Check the test result, change something, check again, and that split has quietly become
a tuning set. After twenty such looks the number carries the optimism of a
best-of-twenty draw — easily 0.02–0.05 AUC, which is the entire margin this project
cares about.

Enforcement is physical, not procedural:

- `05_split.py` writes the test split to `data/splits/test.parquet`;
- **nothing in `pipeline/` loads it except `09_evaluate.py`**;
- every access is appended to `data/reports/test_access.log` with a timestamp;
- if the count exceeds two, `09_evaluate.py` prints that count next to the metric.

Treat any code outside stage 09 that reads the test split as a bug.

Note that stage 08 (calibrate) deliberately fits on **validate**, not test — a stage that
both fits and measures cannot honour the rule above.

## What to produce

| Output | Answers | How to read it |
|---|---|---|
| Baseline table | what does trivial look like? | printed first, always |
| ROC-AUC | does it rank bad above good? | compare to baseline 3, **not** to 0.5 |
| Grouped vs random split | how much was memorisation? | the gap is the finding |
| Reliability diagram | do the numbers mean what they say? | dots on the diagonal; a rehearsal at pilot scale |
| Brier score | ranking and honesty together | report against the base-rate Brier |
| **ROC-AUC on the §1 slice** | does it work *where it is deployed*? | **this is the headline number, not the pooled one** |
| Per-slice metrics | does it work everywhere? | packed/unpacked, signed/unsigned, has-sandbox/no-sandbox, **feed/customer**, §9 stratum |

Aggregate metrics routinely hide two large errors pointing in opposite directions, which
is why the per-slice row is not optional.

> **The §1 slice is the headline, because training is broader than the reference
> population.** Estimand §10 lets the model learn from the whole store, feeds included;
> §1 is the narrow frame the probability actually speaks about. A pooled metric mixes
> them, and feed artifacts are easy — ingested largely because they are already known
> malware — so pooling inflates the number with exactly the rows we are not trying to be
> good at. A model that is excellent on feeds and mediocre on customer submissions must
> not be able to report a good score, and only the sliced metric stops it.
>
> Quote pooled AUC nowhere. If a single number is needed, it is the one computed on §1's
> population, reweighted by `1/π_i`.

## Three standing controls

Cheap, and each catches a whole class of bug that is otherwise invisible.

**Shuffled-label control.** Randomly shuffle the answer column and re-run. Must score
≈0.5 AUC. Anything above ~0.55 means information is leaking through the plumbing.

**Seed reshuffle.** Re-run with several seeds and look at the spread. That spread is the
noise band, and it is how you learn that a 0.02 difference between two models is nothing.

**Row-count assertions** at every stage boundary. Catches silent drops and the
label-fabrication bug where unlabelled rows quietly become "benign".

## What success looks like

Not a high number — a **defensible** one: baseline 3 in a plausible range, a model that
beats it by more than the noise band, an honest gap between the grouped and random
splits, and a reliability diagram whose error bars tell you how many adjudicated labels
the real thing will need.

Finding baseline 3 at 0.98 instead is also a success. It means the labels are circular,
discovered in two weeks for the price of a query rather than in two years and a
whitepaper.
