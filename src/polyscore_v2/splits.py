"""Temporal and family-grouped splitting. See specs/01-estimand.md SS5, specs/04-pipeline.md (05).

Two traps this exists to avoid:
  TIME    -- production always scores tomorrow's files with yesterday's model, so the test
             fold must be later than training, with a horizon-sized gap between them.
  FAMILY  -- ten thousand samples of one family are nearly one sample; a group is never
             split across folds.
The random split is computed deliberately, beside the honest one, so the gap between the
two -- the memorisation the honest split refuses -- can be reported.
"""

from __future__ import annotations

import datetime as dt

import numpy as np
import pandas as pd

FOLDS = ("train", "validate", "test")


def grouping_key(df: pd.DataFrame) -> pd.Series:
    """The family group: a TLSH cluster when one exists, else imphash, else the modal
    family string at T (the stand-in of decisions/0011), else the artifact itself."""
    for col in ("tlsh_cluster", "imphash"):
        if col in df.columns and df[col].notna().any():
            key = df[col].astype(str).where(df[col].notna(), "")
            return key.where(key != "", df["sha256"])
    fam = df["modal_family"].fillna("").astype(str) if "modal_family" in df.columns else pd.Series("", index=df.index)
    return fam.where(fam != "", df["sha256"])


def temporal_grouped(df: pd.DataFrame, *, train_frac: float, validate_frac: float) -> pd.Series:
    """Fold per row: groups ordered by their earliest scoring moment, cut whole at the fractions."""
    first = df.groupby("group")["scoring_moment"].min().sort_values()
    sizes = df.groupby("group").size().reindex(first.index)
    cum = sizes.cumsum() / len(df)
    fold_of_group = pd.Series("train", index=first.index)
    fold_of_group[cum > train_frac] = "validate"
    fold_of_group[cum > train_frac + validate_frac] = "test"
    return df["group"].map(fold_of_group)


def horizon_gap(df: pd.DataFrame, fold: pd.Series, *, horizon_days: int) -> tuple[pd.Series, pd.Timestamp, pd.Timestamp]:
    """Test rows inside the horizon after the last training row: they are dropped, not kept,
    because their label was still forming when training ended."""
    train_end = df.loc[fold == "train", "scoring_moment"].max()
    gap_start = train_end + dt.timedelta(days=horizon_days)
    in_gap = (fold == "test") & (df["scoring_moment"] < gap_start)
    return in_gap, train_end, gap_start


def straddling_groups(df: pd.DataFrame, fold: pd.Series) -> int:
    """How many groups appear in more than one fold. Must be zero."""
    return int((df.assign(_fold=fold).groupby("group")["_fold"].nunique() > 1).sum())


def random_split(df: pd.DataFrame, *, seed: int, train_frac: float, validate_frac: float) -> pd.Series:
    """The naive split: a seeded shuffle, no groups, no gap. Named optimistic wherever it is reported."""
    order = np.random.default_rng(seed).permutation(len(df))
    fold = np.empty(len(df), dtype=object)
    n_train = int(round(train_frac * len(df)))
    n_val = int(round(validate_frac * len(df)))
    fold[order[:n_train]] = "train"
    fold[order[n_train:n_train + n_val]] = "validate"
    fold[order[n_train + n_val:]] = "test"
    return pd.Series(fold, index=df.index)


def prevalence(df: pd.DataFrame, y_col: str = "y") -> dict:
    """Positive share of a fold, raw and reweighted by 1/pi (estimand SS9)."""
    y = df[y_col].astype(float)
    w = 1.0 / df["pi"]
    return {"n": int(len(df)), "raw": round(float(y.mean()), 4) if len(df) else None,
            "reweighted": round(float((w * y).sum() / w.sum()), 4) if len(df) else None}
