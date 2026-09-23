#!/usr/bin/env python3
"""Stage 09 — open the test set, once

Load the frozen models AND the fitted calibrator/combiner from stage 08, score the test
split, print the primary metric beside all four baselines, and draw the reliability
diagram with bootstrap confidence bands.

This stage FITS NOTHING. Everything it uses was frozen by stage 08. That separation is
what makes the look-once rule below enforceable -- a stage that both fits and measures
cannot honour it.

THE LOOK-ONCE RULE. This is the only stage permitted to read data/splits/test.parquet.
Every access is appended to data/reports/test_access.log; if the count exceeds two, that
count is printed next to the metric. Treat any other code reading the test split as a bug.

The WIDTH of the confidence bands is the finding -- it is what sizes the real
adjudication budget.

Reads : data/models/{a,b,c}.joblib + calibrator.joblib + combiner.joblib
        + data/splits/test.parquet
Writes: data/reports/evaluation.txt, data/reports/reliability.png

Contract: specs/04-pipeline.md
"""

from __future__ import annotations

from polyscore_v2.config import settings
from polyscore_v2.logging_setup import configure

log = configure()


def main() -> None:
    raise NotImplementedError("stage 09 — see specs/04-pipeline.md")


if __name__ == "__main__":
    main()
