# Decision records

Short, dated, immutable notes on **why** something is the way it is. Specs say what the
design *is*; these say what else was considered and what tipped it.

## Conventions

- One file per decision: `NNNN-short-kebab-title.md`, numbered in order, never renumbered.
- **Immutable.** A decision that turns out wrong is *superseded* by a new record, not
  edited. Mark the old one `Superseded by 00NN` and leave the reasoning intact — the
  wrong turn is often the most useful thing in the file.
- Statuses: `Proposed`, `Accepted`, `Superseded by 00NN`, `Reversed`.
- Keep them short. If it needs more than a page, it is a spec.

## Why bother

The system being replaced failed partly because its reasoning was never written down.
Three years on, nobody could say why ground truth was "≥3 engines", whether the negative
class had been considered, or what the 0.33 constant was supposed to mean. The code was
readable; the intent was gone.

Worth noting the precedent: the firehose repo's decision log contains **eighteen recorded
reversals**, each naming its error class — and three of them are precisely the errors
that produced the 2023 PolyScore model. A log that records being wrong is worth more
than one that records being right.

## Index

| # | Decision | Status |
|---|---|---|
| [0001](./0001-contract-is-a-calibrated-probability.md) | The contract is a calibrated probability; rank derives from it | Accepted |
| [0002](./0002-metadata-not-binaries.md) | Train on metadata, not file bytes | Accepted |
| [0003](./0003-pilot-scope-10k-pe.md) | Pilot scope is 10,000 Windows PE files | Accepted |
| [0004](./0004-labels-time-separated-for-the-pilot.md) | Pilot labels are time-separated consensus, not adjudication | Accepted |
| [0005](./0005-composite-polyscore-via-a-fitted-combiner.md) | Composite PolyScore via a fitted combiner (amends 0001) | Accepted |
