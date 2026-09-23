#!/usr/bin/env python3
"""Stage 08 — fit the calibrator and the combiner

Turns a ranking into a probability, and folds signals into it.

Two artefacts, versioned SEPARATELY from the base model because they refit on a different
cadence (see specs/06-signals.md):

  calibrator.joblib   monotone map from base score -> probability. Platt or beta;
                      NOT isotonic at pilot volumes, where it fits the calibration set
                      exactly and looks wonderful for the wrong reason.
  combiner.joblib     small fitted model over [base score, signal indicators] -> polyscore.
                      Small on purpose: small is what makes attribution exact.

SEPARATE FROM STAGE 09 ON PURPOSE. This stage FITS -- it changes the model. Stage 09
MEASURES under a look-once rule. Fitting inside the look-once stage means that looking at
the reliability diagram and refitting silently spends the test set. Keeping them apart is
what makes that rule enforceable rather than aspirational.

Fits on HELD-OUT data, never on train and never on test.

GRADE GATE: the calibrator may only be fitted on grade-3 (adjudicated) labels --
labels.assert_calibration_eligible enforces it. Until those exist, the combiner's
coefficients are expert-set in LOG-ODDS and the score is marked
`calibration: provisional` (decision 0005). Never `score x k`; always `logit += w`.

Reads : data/models/{a,b,c}.joblib + data/splits/validate.parquet
Writes: data/models/calibrator.joblib, data/models/combiner.joblib

Contract: specs/04-pipeline.md, specs/06-signals.md
"""

from __future__ import annotations

from polyscore_v2.config import settings
from polyscore_v2.logging_setup import configure

log = configure()


def main() -> None:
    raise NotImplementedError("stage 08 — see specs/06-signals.md")


if __name__ == "__main__":
    main()
