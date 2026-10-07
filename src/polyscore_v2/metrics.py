"""Metrics, the sliced metric table, and the reliability diagram. See specs/05-evaluation.md.

No metric is ever quoted without its baselines. Accuracy is never the headline -- the
2023 model reported 0.9628 while answering "malicious" every time scored 0.9666.

THE INVARIANT: a metric is reported RAW and REWEIGHTED by 1/pi, pooled and on the SS1
slice, and the headline is the sliced reweighted one.
"""

from __future__ import annotations

import math
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import brier_score_loss, log_loss, roc_auc_score

CUSTOMER = "customer"


def auc(y: np.ndarray, s: np.ndarray, w: np.ndarray | None = None) -> float:
    """ROC-AUC, or NaN when it is undefined (fewer than two rows, or one class)."""
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


def reliability(y, p, w, path: Path, n_bins: int = 10, n_boot: int = 200, seed: int = 0) -> dict:
    """The reliability diagram with a bootstrap band, written to `path`. The band's width is
    the finding: it is what sizes the adjudication budget (specs/05-evaluation.md)."""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    rng = np.random.default_rng(seed)
    y, p, w = np.asarray(y, dtype="float64"), np.asarray(p, dtype="float64"), np.asarray(w, dtype="float64")
    n_bins = max(2, min(n_bins, len(y) // 5)) if len(y) >= 10 else 2
    edges = np.quantile(p, np.linspace(0, 1, n_bins + 1)); edges[0], edges[-1] = 0, 1
    idx = np.clip(np.searchsorted(edges, p, side="right") - 1, 0, n_bins - 1)

    def curve(sel):
        xs, ys = [], []
        for b in range(n_bins):
            m = (idx[sel] == b)
            if m.any():
                ww = w[sel][m]
                xs.append(np.sum(ww * p[sel][m]) / ww.sum()); ys.append(np.sum(ww * y[sel][m]) / ww.sum())
        return np.array(xs), np.array(ys)

    x0, y0 = curve(np.arange(len(y)))
    boots = [curve(rng.integers(0, len(y), len(y)))[1] for _ in range(n_boot)]
    k = min((len(b) for b in boots), default=0)
    band = np.array([b[:k] for b in boots]) if k else np.empty((0, 0))
    lo = np.quantile(band, 0.05, axis=0) if k else []; hi = np.quantile(band, 0.95, axis=0) if k else []
    fig, ax = plt.subplots(figsize=(5, 5))
    ax.plot([0, 1], [0, 1], "--", color="grey", lw=1)
    if k:
        ax.fill_between(x0[:k], lo, hi, alpha=0.2, label="90% bootstrap band")
    ax.plot(x0, y0, "o-", label="observed")
    ax.set_xlabel("predicted probability"); ax.set_ylabel("observed frequency (x 1/pi)")
    ax.set_title("reliability -- provisional (grade-1 labels)"); ax.legend(loc="upper left")
    fig.tight_layout(); fig.savefig(path, dpi=120); plt.close(fig)
    return {"bins": int(n_bins), "band_width_mean": float(np.mean(hi - lo)) if k else math.nan}
