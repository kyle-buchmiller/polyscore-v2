# 00 — Overview

## Scope

What this repo is, what it is not, and how the pieces fit. Read first.

## Invariants

- The deliverable is a **calibrated probability**, not a ranking wearing a percentage sign.
- The pilot's job is to walk the process and measure the constraints, **not** to ship a model.
- Nothing in this repo is interpretable without [`01-estimand.md`](./01-estimand.md).

## What this is

PolyScore is a **second-order model**: it does not look at a file, it aggregates what
~40 antivirus engines *said* about that file. This repo rebuilds it so that its output
is a probability that can be checked:

> Of all FILE artifacts we score near **0.40**, drawn from a named reference
> population, about **40%** are independently adjudicated malicious **within 30 days**
> of first sighting.

Every clause is load-bearing. *Independently* rules out labels derived from the model's
own inputs. *Named reference population* rules out a bare number. *Within 30 days* gives
"malicious" a date. And the claim is falsifiable, which is the point.

## Why a rebuild rather than a retrain

The shipped model is a single logistic regression over one slot per engine display
name, frozen since 2023-09-26. Three defects make a retrain insufficient:

1. **The labels are derived from the features.** Ground truth was "≥3 engines called it
   malicious," and those same verdicts are the inputs. A model that perfectly reproduced
   the vote count would have scored flawlessly and known nothing about malware. Every
   metric that pipeline ever produced is uninterpretable for that reason alone.
2. **Clean, silent and unknown are the same number.** A benign verdict, an engine that
   did not answer, and an engine the model has never heard of all arrive as `0.0`. This
   is the structural cause of the constant `0.33460048640798623065` that every
   undetected file receives — it is `sigmoid(intercept)`, the model's fallback when no
   input fires.
3. **There is no calibration layer at all.** The output is raw `predict_proba`. Nothing
   ever mapped the model's numbers onto observed frequencies, so the word "probability"
   has never been earned.

A retrain reproduces all three with fresher coefficients.

## The two-stage shape

```
engine evidence ->  base model  ->  raw score --+
                    (ranks)                     |
signature signals --------------------------> COMBINER -> coverage gate -> score record
sandbox signals ----------------------------->  (small,    (may refuse     (polyscore,
                                                 fitted)    to answer)      status,
                                                                            components)
```

The discriminator and the calibrator are **separately versioned** and fitted on
different data. The calibrator is the mechanism that makes the number a probability,
and it may only be fitted on independently adjudicated labels — see
[`03-labels.md`](./03-labels.md).

`polyscore` is the **combiner's** output — one calibrated number, composed from several
evidence sources, with the base probability and per-signal contributions exposed for
drill-down. See [`06-signals.md`](./06-signals.md).

The coverage gate is what permanently kills the 0.33 problem: when there is not enough
evidence, the system returns *no score and a reason* rather than a number.

## Repo layout

| Path | Contents |
|---|---|
| `specs/` | Design contracts. Authoritative on intent. |
| `decisions/` | Dated decision records. Authoritative on why. |
| `pipeline/` | The nine numbered stages, run in order by a human watching the output. |
| `src/polyscore_v2/` | Shared code the stages import — config, io, db, features, labels, splits, metrics. |
| `tests/` | Guards against the specific failure modes named in the specs. |
| `data/` | Snapshots and outputs. Gitignored and reproducible; the manifest is the unit of reproducibility. |

## What the pilot is

Ten thousand Windows PE files, end to end, to answer one question: **are our labels
good enough to build on?** The measurement that answers it is in stage 06 and costs no
model at all — see [`05-evaluation.md`](./05-evaluation.md).

A pilot that ends with "the labels are the bottleneck, here is the number that proves
it" has succeeded.
