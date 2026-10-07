"""Groups are cut whole, in time order, with a gap before the exam; the random split is beside it."""
import datetime as dt

import numpy as np
import pandas as pd
import pytest

from polyscore_v2.splits import (grouping_key, horizon_gap, prevalence, random_split,
                                 straddling_groups, temporal_grouped)


def frame():
    t0 = dt.datetime(2026, 1, 1)
    rows = []
    for g, day, n in (("fam-a", 0, 4), ("fam-b", 10, 2), ("fam-c", 20, 2), ("fam-d", 60, 2)):
        for i in range(n):
            rows.append({"sha256": f"{g}-{i}", "group": g, "scoring_moment": t0 + dt.timedelta(days=day + i),
                         "y": i % 2, "pi": 0.5})
    return pd.DataFrame(rows)


def test_groups_are_cut_whole_in_time_order():
    df = frame()
    fold = temporal_grouped(df, train_frac=0.6, validate_frac=0.15)
    assert straddling_groups(df, fold) == 0
    assert set(fold[df["group"] == "fam-a"]) == {"train"}      # earliest, 4 of 10 rows
    assert set(fold[df["group"] == "fam-d"]) == {"test"}       # latest


def test_horizon_gap_drops_test_rows_too_close_to_training():
    df = frame()
    fold = temporal_grouped(df, train_frac=0.6, validate_frac=0.15)
    in_gap, train_end, gap_start = horizon_gap(df, fold, horizon_days=30)
    assert gap_start == train_end + dt.timedelta(days=30)
    assert in_gap[df["group"] == "fam-c"].all()                 # day 20-21, inside 30 days of train end
    assert not in_gap[df["group"] == "fam-d"].any()             # day 60+, clear


def test_random_split_accounts_for_every_row_and_is_seeded():
    df = frame()
    a = random_split(df, seed=1, train_frac=0.6, validate_frac=0.15)
    b = random_split(df, seed=1, train_frac=0.6, validate_frac=0.15)
    assert a.equals(b) and a.value_counts().to_dict() == {"train": 6, "validate": 2, "test": 2}
    assert not a.equals(random_split(df, seed=2, train_frac=0.6, validate_frac=0.15))


def test_grouping_key_falls_back_down_the_chain():
    df = pd.DataFrame({"sha256": ["x", "y", "z"], "modal_family": ["emotet", "", None]})
    assert grouping_key(df).tolist() == ["emotet", "y", "z"]
    df["tlsh_cluster"] = ["c1", None, "c2"]
    assert grouping_key(df).tolist() == ["c1", "y", "c2"]


def test_prevalence_raw_and_reweighted():
    df = pd.DataFrame({"y": [1, 0, 0, 0], "pi": [1.0, 0.25, 0.25, 0.25]})
    p = prevalence(df)
    assert p["raw"] == 0.25 and p["reweighted"] == pytest.approx(1 / 13, abs=1e-4)   # 1 / (1 + 3*4)
