"""What stages 06-09 share: the design matrix, raw scores, and the sliced metric table.

The one invariant worth a module: a metric is reported RAW and REWEIGHTED by 1/pi, pooled
and on the SS1 slice, and the headline is the sliced reweighted one (specs/05-evaluation.md).
"""

from __future__ import annotations

import math

import numpy as np
import pandas as pd
from sklearn.metrics import brier_score_loss, log_loss, roc_auc_score

from .features import BOOKKEEPING_NOT_FEATURES, FORBIDDEN_AS_FEATURES

CUSTOMER = "customer"


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


def auc(y: np.ndarray, s: np.ndarray, w: np.ndarray | None = None) -> float:
    y = np.asarray(y)
    if len(y) < 2 or len(np.unique(y)) < 2:
        return math.nan
    return float(roc_auc_score(y, s, sample_weight=w))


def weighted_mean(x: np.ndarray, w: np.ndarray) -> float:
    return float(np.sum(w * x) / np.sum(w))


def metrics_table(df: pd.DataFrame, score: np.ndarray, y_col: str = "y") -> dict:
    """AUC pooled and on the SS1 slice, each raw and x 1/pi, plus per stratum and per provenance."""
    y = df[y_col].to_numpy(); w = (1.0 / df["pi"]).to_numpy()
    out = {"pooled_raw": auc(y, score), "pooled_reweighted": auc(y, score, w)}
    cust = (df["provenance"] == CUSTOMER).to_numpy()
    out["s1_raw"] = auc(y[cust], score[cust]) if cust.any() else math.nan
    out["s1_reweighted"] = auc(y[cust], score[cust], w[cust]) if cust.any() else math.nan
    out["s1_n"] = int(cust.sum())
    out["per_stratum"] = {s: auc(y[m], score[m]) for s, m in
                          ((s, (df["stratum"] == s).to_numpy()) for s in sorted(df["stratum"].unique()))}
    out["per_provenance"] = {p: auc(y[m], score[m]) for p, m in
                             ((p, (df["provenance"] == p).to_numpy()) for p in sorted(df["provenance"].unique()))}
    return out


def prob_metrics(df: pd.DataFrame, prob: np.ndarray, y_col: str = "y") -> dict:
    """Brier and log loss, reweighted, beside the base-rate Brier they must beat."""
    y = df[y_col].to_numpy(); w = (1.0 / df["pi"]).to_numpy()
    base_rate = weighted_mean(y.astype(float), w)
    out = {"brier": float(brier_score_loss(y, prob, sample_weight=w)),
           "brier_base_rate": float(brier_score_loss(y, np.full(len(y), base_rate), sample_weight=w)),
           "prevalence_reweighted": base_rate}
    if len(np.unique(y)) > 1:
        out["log_loss"] = float(log_loss(y, prob, sample_weight=w))
    return out


def fmt(x) -> str:
    return "  n/a " if x is None or (isinstance(x, float) and math.isnan(x)) else f"{x:6.3f}"
