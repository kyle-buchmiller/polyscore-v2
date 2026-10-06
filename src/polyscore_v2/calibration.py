"""Calibrator and combiner — the stage that makes the number a probability.

See specs/06-signals.md. Two artefacts, two versions, two refit cadences:

    base model   DISCRIMINATES -- emits a raw score whose ordering is the trustworthy
                 part. It does not emit a rank. Retrained rarely (weeks).
    calibrator   base score -> probability. Refit on drift (monthly).
    combiner     [base score, signals] -> polyscore. Refit when a signal is added (minutes).

The product's ranking number is a percentile of the finished polyscore over a named
cohort -- downstream of all three of these, and not built (08-future-work.md F1).
Calibration is monotone, so it cannot change the ordering, which is the same fact as
ROC-AUC being invariant under it.

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


@dataclass(frozen=True)
class Calibrator:
    """Platt scaling: p = sigmoid(a * score + b). Two floats, and they ARE the base rate."""

    a: float
    b: float
    n_fit: int
    provisional: bool  # fitted on grade < 3 labels: a rehearsal of the mechanism, not a probability

    def predict_proba(self, base_scores: np.ndarray) -> np.ndarray:
        z = self.a * np.asarray(base_scores, dtype="float64") + self.b
        return 1.0 / (1.0 + np.exp(-z))


def fit_calibrator(
    base_scores: np.ndarray, y_true: np.ndarray, *, method: str = "sigmoid",
    sample_weight: np.ndarray | None = None, provisional: bool = True,
) -> Calibrator:
    """Fit the monotone map from base score to probability, on HELD-OUT data.

    `sigmoid` is Platt scaling: two parameters, well-behaved at pilot volumes.
    `isotonic` is more flexible and will overfit a small calibration set -- it also
    produces plateaus that map large blocks to an identical probability, which silently
    randomises queue order within a block. Rank on the RAW score, never this output.
    It is refused here for exactly that reason; revisit when the calibration set is large.
    """
    if method != "sigmoid":
        raise NotImplementedError(f"{method}: only Platt scaling at pilot volumes (see docstring)")
    from sklearn.linear_model import LogisticRegression

    s = np.asarray(base_scores, dtype="float64").reshape(-1, 1)
    y = np.asarray(y_true).astype(int)
    if len(np.unique(y)) < 2:
        raise ValueError("calibration needs both classes present")
    lr = LogisticRegression(C=1e6, max_iter=2000).fit(s, y, sample_weight=sample_weight)
    return Calibrator(a=float(lr.coef_[0, 0]), b=float(lr.intercept_[0]), n_fit=int(len(y)),
                      provisional=provisional)


def _logit(p: np.ndarray) -> np.ndarray:
    p = np.clip(np.asarray(p, dtype="float64"), 1e-6, 1 - 1e-6)
    return np.log(p / (1 - p))


@dataclass(frozen=True)
class Combiner:
    """logit(polyscore) = logit(base probability) + sum_s w_s * signal_s.

    Signals are columns of the frame passed to `apply`, 0/1 or small floats; a signal
    with no column contributes nothing. Addition in log-odds is what keeps the output a
    probability (decision 0005): `score * k` saturates and clamps, and clamping is how a
    probability stops being one.
    """

    weights: dict[str, float]
    provisional: bool

    def apply(self, base_prob: np.ndarray, signals: pd.DataFrame | None = None
              ) -> tuple[np.ndarray, list[list[Contribution]]]:
        base = _logit(base_prob)
        total = base.copy()
        rows: list[list[Contribution]] = [[Contribution("engine_evidence", float(b))] for b in base]
        if signals is not None:
            for name, w in self.weights.items():
                if name not in signals.columns:
                    continue
                v = signals[name].fillna(0).to_numpy(dtype="float64") * w
                total = total + v
                for i, x in enumerate(v):
                    if x:
                        rows[i].append(Contribution(name, float(x)))
        return 1.0 / (1.0 + np.exp(-total)), rows


def fit_combiner(base_scores: np.ndarray, signals: pd.DataFrame, y_true: np.ndarray):
    """Fit the small model over [base score, signal indicators].

    Callers must have passed labels through labels.assert_calibration_eligible first:
    fitting this on delayed engine consensus produces a system that passes its own
    reliability gates while remaining definitionally uncalibrated.
    """
    raise NotImplementedError("stage 08: needs grade-3 labels; use provisional_combiner until then")


def provisional_combiner(weights: dict[str, float]) -> Combiner:
    """The interim posture from decision 0005, for use before grade-3 labels exist.

    Expert-set weights in LOG-ODDS, so the eventual refit is a parameter change rather
    than a rebuild. A score produced this way must carry `calibration: provisional`.

    Weights are `logit += w`. Never `score * k` -- multipliers saturate and clamp, and
    clamping is how a probability stops being one.
    """
    return Combiner(weights=dict(weights), provisional=True)


def explain(contributions: list[Contribution]) -> pd.DataFrame:
    """Render the per-source drill-down, largest absolute effect first."""
    df = pd.DataFrame([{"source": c.source, "logit": c.logit} for c in contributions])
    if df.empty:
        return df
    return df.reindex(df["logit"].abs().sort_values(ascending=False).index).reset_index(drop=True)
