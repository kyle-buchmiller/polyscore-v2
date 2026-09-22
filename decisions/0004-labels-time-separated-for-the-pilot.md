# 0004 — Pilot labels are time-separated consensus, not adjudication

- **Status:** Accepted
- **Date:** 2026-09-22
- **Affects:** `specs/03-labels.md`, `specs/01-estimand.md`

## Context

A calibrated probability requires labels independent of the model's inputs. The only
fully independent source is human adjudication, which is a standing operating cost
(roughly 1–3 analyst FTE) that is not yet funded.

The 2023 model's labels were a threshold on the same verdicts that were its features —
grade 0, and the reason none of its metrics can be interpreted.

## Decision

The pilot trains on **grade-1 labels**: the same engines' verdicts read at **T+30 days**,
with cluster-adjusted counts, family-specificity weighting and a stability requirement.
A **200-file gold slice**, drawn at random and hand-adjudicated, measures how wrong those
labels are.

## Alternatives considered

| Option | Why not |
|---|---|
| Keep grade-0 labels for the pilot | Reproduces the exact defect the rebuild exists to remove; nothing measured would mean anything. |
| Wait for a funded adjudication programme | Blocks all learning for a quarter or more, and the programme should be sized by the pilot's findings rather than guessed at. |
| Use sandbox verdicts as the label | Detonation is gated on a malware family already having been resolved from engine assertions — so it is downstream of the features, and benign-side coverage is near zero. |
| Use arbitration outcomes | Not independent: arbiter names are themselves columns in the model's vocabulary, and three of four deployed arbiters share a vendor with a scanning engine voting on the same artifact. |

## Consequences

- The pilot can honestly measure **ranking**. It cannot honestly measure **calibration** —
  a calibration number against grade-1 labels measures agreement with our own label rule.
  Calibration machinery is still built and exercised, labelled a rehearsal.
- The gold slice's disagreement rate is a **hard ceiling on model quality** that is
  otherwise completely unknown, and it is what sizes the real adjudication budget.
- The gold slice must be drawn **at random**, not from the interesting end. Adjudicating
  what the model found interesting teaches you only about what the model already believed.
- If the engine-count baseline exceeds ~0.97 AUC, these labels are still effectively
  circular and the pilot stops there — see estimand §8.
