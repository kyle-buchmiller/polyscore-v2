"""Baselines, metrics and the standing controls. See specs/05-evaluation.md.

No metric is ever quoted without its baselines. Accuracy is never the headline -- the
2023 model reported 0.9628 while answering "malicious" every time scored 0.9666.
"""

from __future__ import annotations

import numpy as np
import pandas as pd


def baseline_table(y_true: np.ndarray, features: pd.DataFrame, incumbent: np.ndarray | None = None) -> pd.DataFrame:
    """The four baselines from estimand SS7, printed before any model exists.

    1. constant (majority class)          -- the absolute floor
    2. prevalence-random                  -- confirms the plumbing is not inverted
    3. malicious-engine count             -- THE ONE THAT MATTERS
    4. the incumbent polyscore            -- what we are replacing

    Baseline 3 is the whole diagnostic: ~0.85-0.95 is healthy, >0.97 means the label is
    a restatement of the features and the pilot stops, ~0.5 means something is
    disconnected. See estimand SS8.
    """
    raise NotImplementedError("stage 06 — see specs/05-evaluation.md")


def shuffled_label_control(fit_and_score, y_true: np.ndarray, *, seed: int) -> float:
    """Shuffle the answer column and refit. Must score ~0.5 AUC.

    Anything above ~0.55 means information is leaking through the plumbing -- a whole
    class of bug that is otherwise invisible.
    """
    raise NotImplementedError("standing control — see specs/05-evaluation.md")


def seed_noise_band(fit_and_score, *, seeds: list[int]) -> tuple[float, float]:
    """Re-run across seeds and return the spread.

    That spread is the noise band, and it is how you learn that a 0.02 difference
    between two models is nothing.
    """
    raise NotImplementedError("standing control")


def reliability(y_true: np.ndarray, y_prob: np.ndarray, *, n_bins: int = 10):
    """Reliability curve with bootstrap confidence bands.

    At pilot scale the WIDTH of those bands is the finding -- it is what sizes the real
    adjudication budget. Use Platt or beta calibration upstream, never isotonic at these
    volumes: it will fit the calibration set exactly and look wonderful for the wrong
    reason.
    """
    raise NotImplementedError("stage 09 — see specs/05-evaluation.md")
