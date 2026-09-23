"""Calibrator and combiner — the stage that makes the number a probability.

See specs/06-signals.md. Two artefacts, two versions, two refit cadences:

    base model   ranks. Retrained rarely (weeks).
    calibrator   base score -> probability. Refit on drift (monthly).
    combiner     [base score, signals] -> polyscore. Refit when a signal is added (minutes).

THE INVARIANT (decision 0001, as amended by 0005): composition is FITTED, never asserted.
`logit += w` where w was fitted keeps the output a probability. `score * k, clamp` does
not -- that is the neonscan failure, where category multipliers make a container of
entirely clean files report 1.0.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd


@dataclass(frozen=True)
class Contribution:
    """One input's exact effect on the score, in log-odds.

    On a small linear combiner this IS `coefficient * value` -- the drill-down is
    arithmetic, not an approximation the way SHAP over a large ensemble would be. That
    exactness is the reason to keep the combiner small.
    """

    source: str
    logit: float


def fit_calibrator(base_scores: np.ndarray, y_true: np.ndarray, *, method: str = "sigmoid"):
    """Fit the monotone map from base score to probability, on HELD-OUT data.

    `sigmoid` is Platt scaling: two parameters, well-behaved at pilot volumes.
    `isotonic` is more flexible and will overfit a small calibration set -- it also
    produces plateaus that map large blocks to an identical probability, which silently
    randomises queue order within a block. Rank on the RAW score, never this output.
    """
    raise NotImplementedError("stage 08 — see specs/06-signals.md")


def fit_combiner(base_scores: np.ndarray, signals: pd.DataFrame, y_true: np.ndarray):
    """Fit the small model over [base score, signal indicators].

    Callers must have passed labels through labels.assert_calibration_eligible first:
    fitting this on delayed engine consensus produces a system that passes its own
    reliability gates while remaining definitionally uncalibrated.
    """
    raise NotImplementedError("stage 08")


def provisional_combiner(weights: dict[str, float]):
    """The interim posture from decision 0005, for use before grade-3 labels exist.

    Expert-set weights in LOG-ODDS, so the eventual refit is a parameter change rather
    than a rebuild. A score produced this way must carry `calibration: provisional`.

    Weights are `logit += w`. Never `score * k` -- multipliers saturate and clamp, and
    clamping is how a probability stops being one.
    """
    raise NotImplementedError("stage 08 — see decision 0005")


def explain(contributions: list[Contribution]) -> pd.DataFrame:
    """Render the per-source drill-down, largest absolute effect first."""
    raise NotImplementedError("stage 08")
