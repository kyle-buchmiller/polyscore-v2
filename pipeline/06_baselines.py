#!/usr/bin/env python3
"""Stage 06 — the four baselines, before any model

The most informative half hour in the project, and it costs no model at all.

Baseline 3 -- a plain count of engines asserting malicious at T -- is the diagnostic:
  ~0.85-0.95 AUC  healthy, proceed
  >0.97           the label is a restatement of the features; STOP and fix the labels
  ~0.50           something is disconnected

Then three probes on the feature set (estimand §4, §9, §10):
  provenance: injected vs organic   GATE -- blocking above ~0.6 AUC
  provenance: feed vs customer      GATE -- blocking above ~0.6 AUC
  rescan: cohort vs control         REPORT -- per-band coverage + optional propensity weight

Does NOT read the test split.

Reads : data/splits/{train,validate}.parquet, data/base/<window>.control.parquet
Writes: data/reports/baselines.txt, data/reports/rescan_propensity.parquet

Contract: specs/04-pipeline.md
"""

from __future__ import annotations

from polyscore_v2.config import settings
from polyscore_v2.logging_setup import configure

log = configure()


def main() -> None:
    raise NotImplementedError("stage 06 — see specs/04-pipeline.md")


if __name__ == "__main__":
    main()
