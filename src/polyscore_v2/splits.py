"""Temporal and family-grouped splitting. See specs/01-estimand.md SS5.

Two traps this exists to avoid:

  TIME    -- production always scores tomorrow's files with yesterday's model, so the
             test set must be LATER than the training set. A random shuffle lets the
             model train on March and be tested on February, an easier question it will
             never face.
  FAMILY  -- ten thousand samples of one ransomware family are nearly one sample
             repeated. Shuffle randomly and half land on each side, so at test time the
             model recognises near-copies of what it studied. That measures memory.
"""

from __future__ import annotations

import pandas as pd


def grouping_key(df: pd.DataFrame) -> pd.Series:
    """TLSH cluster, falling back to imphash, falling back to sha256."""
    raise NotImplementedError("stage 05 — see specs/01-estimand.md SS5")


def temporal_grouped_split(
    df: pd.DataFrame, *, horizon_days: int, train_frac: float, validate_frac: float
) -> dict[str, pd.DataFrame]:
    """Split forward in time, with a horizon-sized gap, and no family straddling a boundary."""
    raise NotImplementedError("stage 05")


def random_split(df: pd.DataFrame, *, seed: int) -> dict[str, pd.DataFrame]:
    """The naive split, computed deliberately so the gap can be reported.

    ALWAYS label this output optimistic. The difference between this and the grouped
    temporal split is the pilot's single most valuable number: it is the honest measure
    of how much apparent performance was memorisation.
    """
    raise NotImplementedError("stage 05")
