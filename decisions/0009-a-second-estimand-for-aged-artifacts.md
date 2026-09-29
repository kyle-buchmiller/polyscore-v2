# 0009 — A second estimand for aged artifacts, run as a comparison

- **Status:** Accepted (the *comparison* is accepted; Estimand B itself is Proposed)
- **Date:** 2026-09-29
- **Affects:** new `specs/10-estimand-b-settled-state.md`; `specs/01-estimand.md` §4 (context only)

## Context

Estimand A manufactures its label by bulk-rescanning a frozen cohort ~30 days after first
sighting. That works, and it constrains the cohort to artifacts submitted in roughly the
**last month or two** — because an artifact first seen five years ago, rescanned today,
yields a T+1825 label, not a T+30 one.

Nor can that be repaired by choosing a different T. Two scans thirty days apart in year
three of an artifact's life give a clean gap and a near-worthless label, because
**detection accrual is front-loaded**: by then the verdicts have stopped moving, so the
label becomes a restatement of the features — the grade-0 failure arriving by a side door.
That is why A anchors T to first sighting.

So A's population is extremely recent by construction. Three costs follow, and the first is
the one that matters:

1. A cannot measure **temporal generalization** — whether a model trained on last year's
   malware works on this year's. That is the question a deployed model is judged on, and A
   has three weeks of data.
2. It has seen one draw from an evolving threat process.
3. Small population, wide intervals.

## Decision

Draft a second estimand — **B, settled-state labels over the full history** — and run it as
an explicit comparison against A rather than as a replacement.

B replaces A's **time-based** label criterion with a **stability-based** one: an artifact is
labellable once its verdicts have demonstrably converged (elapsed time, a minimum number of
later scans, and an unchanged independent-cluster count across the last few). Once converged,
a longer gap adds nothing and costs nothing — which is exactly why B can use an artifact A
cannot.

**B is Proposed, not frozen.** It acquires a version only if §B8's go/no-go says to build it.

## Alternatives considered

| Option | Why not |
|---|---|
| Widen A's window and accept mixed horizons | Puts two different measurements in one column. A label at T+400 reflects an order of magnitude more accrual than one at T+31, and rescan timing is user-driven, so the spread correlates with how interesting someone found the file. This is the defect `a7ab1a2` fixed; re-introducing it deliberately is worse. |
| Pick a mid-history T so old artifacts get a clean 30-day gap | Clean gap, worthless label. Accrual is front-loaded, so by year three thirty days adds nothing and the label restates the features. |
| Hunt for artifacts naturally rescanned near T+30 | Selects on rescan timing, which is user-driven — a small cohort of files someone happened to revisit around day 30. Selection on interest, which correlates with the outcome. |
| Just run A and accept the recency skew | Defensible for a pilot whose purpose is to cement the process — and it leaves the deployment question unasked indefinitely. The comparison is cheap relative to what it answers. |
| Replace A with B | B cannot calibrate either, cannot measure churn, and carries survivorship selection. It is a complement, not a successor. |

## Consequences

- **The comparison needs three runs, not two.** A-full, A-restricted (A's data on B's
  era-stable feature set) and B. A-restricted vs B is the clean comparison; A-full vs
  A-restricted prices the restriction. Comparing A-full against B directly would confound
  the data with the feature space and is not a result.
- **A shared evaluation slice is required**, since a model cannot be better on a different
  target. Artifacts around a year old carry both labels — settled, and with a T+30 label
  reconstructable retrospectively.
- **That slice produces a finding on its own**, independent of either model: how often
  A-labels and B-labels disagree. That number is the cost of the 30-day horizon in the only
  units that matter, and it is worth producing even if B is never built.
- **A must run first.** A's churn rate — the fraction called benign at 30 days that turn
  malicious later — is the evidence that should set B's convergence parameters. B cannot
  produce it, because B defines churn away.
- **The era probe becomes a hard gate.** Engine-roster drift makes missingness correlate
  with age, so a model would learn era rather than maliciousness. Stage 06's probe gets its
  third use, and a failure is fixed in the feature set, never the threshold.
- **Two long-window hazards that do not exist in A.** ES coverage before September 2026 is
  incomplete and biased, so B's PE gate must be the Postgres-side test; and filter columns
  that postdate old rows read NULL, so `scan_config IS DISTINCT FROM 'feed'` silently passes
  every pre-column row. The migration history has to be read before any filter is trusted.
- **Neither estimand reaches a calibrated probability.** Both are grade 1. This decision
  buys breadth and a generalization measurement, not calibration.
