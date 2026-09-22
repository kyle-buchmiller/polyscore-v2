#!/usr/bin/env python3
"""Stage 07 — the three comparisons

Exactly three, tuned on validate only, against log loss or Brier -- never a threshold
metric like F1:

  (a) logistic regression, OLD one-column encoding
  (b) logistic regression, NEW two-column encoding
  (c) gradient-boosted trees, new encoding

Prediction on record: (b) lands close to (c), and the gap between (a) and (b) -- an
ENCODING change, not a model change -- dwarfs both.

No class_weight. No synthetic oversampling.

Reads : data/splits/{train,validate}.parquet
Writes: data/models/{a,b,c}.joblib

Contract: specs/04-pipeline.md
"""

from __future__ import annotations

from polyscore_v2.config import settings
from polyscore_v2.logging_setup import configure

log = configure()


def main() -> None:
    raise NotImplementedError("stage 07 — see specs/04-pipeline.md")


if __name__ == "__main__":
    main()
