"""The model side of stages 06-09: the design matrix and the raw score.

Metrics live in metrics.py; this module is what turns a frame into model input and a
model into a score, and nothing else.
"""

from __future__ import annotations

import numpy as np
import pandas as pd

from .features import BOOKKEEPING_NOT_FEATURES, FORBIDDEN_AS_FEATURES


def design(df: pd.DataFrame, columns: list[str], *, impute: bool) -> pd.DataFrame:
    """The feature matrix for a model. Refuses bookkeeping and forbidden columns by name.
    `impute` fills NaN with 0 for models that cannot take NaN (logistic regression);
    gradient-boosted trees take NaN as a branch and get it as-is."""
    bad = sorted((set(columns) & (BOOKKEEPING_NOT_FEATURES | FORBIDDEN_AS_FEATURES)))
    if bad:
        raise ValueError(f"not features: {bad}")
    X = df[columns].astype("float64")
    return X.fillna(0.0) if impute else X


def raw_score(model, X: pd.DataFrame) -> np.ndarray:
    """The base model's raw output -- log-odds for logistic regression, raw leaf sums for
    LightGBM. Ranking happens on this; calibration maps it to a probability."""
    if hasattr(model, "decision_function"):
        return np.asarray(model.decision_function(X), dtype="float64")
    return np.asarray(model.predict(X, raw_score=True), dtype="float64")
