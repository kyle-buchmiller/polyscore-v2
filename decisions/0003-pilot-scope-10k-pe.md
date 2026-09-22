# 0003 — Pilot scope is 10,000 Windows PE files

- **Status:** Accepted
- **Date:** 2026-09-22
- **Affects:** `specs/00-overview.md`, `specs/01-estimand.md`

## Context

The rebuild is large. A first milestone was wanted that would cement the training
process for an engineer new to machine learning, while producing a real signal about
whether the approach is viable.

## Decision

A **10,000-file Windows PE pilot**, run end to end, whose stated purpose is to walk the
process and measure the constraints — **not** to produce a deployable model.

## Alternatives considered

| Option | Why not |
|---|---|
| Go straight to the full rebuild | The binding constraint (labels) would be discovered late and expensively. |
| A smaller toy set (~1,000) | Too few independent family clusters to say anything, even directionally. |
| All artifact types at once | PE has the richest static analysis and the best engine coverage; mixing types confounds the first result and delays the lesson. |

## Consequences

- **PE findings will not transfer cleanly.** PE has the most distinctive benign
  population (signed Microsoft binaries) and the best analyzer coverage; conclusions
  about feature value, prevalence and achievable calibration must be labelled
  PE-specific.
- 10,000 files is likely a few hundred *independent family clusters*. That, not 10,000,
  is the real sample size, and every confidence interval should be read accordingly.
- A ~10,000-row result is **not** evidence that the rebuild works. It is evidence about
  whether the labels can support one.

> **Trap worth recording.** The old pipeline's `QUERY_LIMIT` already defaults to
> `10000`, so "a pilot on ~10,000 files" is almost exactly what the existing extraction
> returns unchanged — manufactured labels, malicious-only filter, unseeded random split
> and all. That path yields ~0.97 AUC in a week and reads as success. The extraction is
> built fresh for this reason.
