#!/usr/bin/env python3
"""Stage 08 — open the test set, once

Load the frozen models, score the test split, print the primary metric beside all four
baselines, fit a calibrator on held-out data and draw the reliability diagram with
bootstrap confidence bands.

THE LOOK-ONCE RULE. This is the only stage permitted to read data/splits/test.parquet.
Every access is appended to data/reports/test_access.log; if the count exceeds two, that
count is printed next to the metric. Treat any other code reading the test split as a bug.

Platt or beta calibration -- NOT isotonic at pilot volumes.

Reads : data/models/*.joblib + data/splits/test.parquet
Writes: data/reports/evaluation.txt, data/reports/reliability.png

Contract: specs/04-pipeline.md
"""

from __future__ import annotations

from polyscore_v2.config import settings
from polyscore_v2.logging_setup import configure

log = configure()


def main() -> None:
    raise NotImplementedError("stage 08 — see specs/04-pipeline.md")


if __name__ == "__main__":
    main()
