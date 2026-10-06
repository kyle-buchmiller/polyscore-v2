"""A 17-digit instance number beside a NULL must come out exact, not rounded."""
import datetime as dt

import pandas as pd
import pytest

from polyscore_v2.extract import assert_exact_instance_numbers, label_frame

BIG = 25035718062263813  # odd and above 2**53: float64 rounds it to a multiple of 4


def test_label_frame_keeps_instance_numbers_exact_beside_nulls():
    rows = [("a" * 64, BIG, dt.datetime(2026, 1, 1), dt.timedelta(days=40), 14, 7, 16),
            ("b" * 64, None, None, None, None, None, None)]
    f = label_frame(rows)
    assert str(f["label_instance_number"].dtype) == "Int64"
    assert int(f.loc[0, "label_instance_number"]) == BIG
    assert pd.isna(f.loc[1, "label_instance_number"]) and pd.isna(f.loc[1, "n_definite"])
    assert str(f.loc[0, "label_gap"]).startswith("40 days") and pd.isna(f.loc[1, "label_gap"])


def test_float64_would_have_rounded_it():
    assert int(float(BIG)) != BIG   # the whole reason the guard exists


def test_guard_refuses_a_float_column():
    df = pd.DataFrame({"label_instance_number": [float(BIG), None]})
    with pytest.raises(ValueError, match="float64"):
        assert_exact_instance_numbers(df, "label_instance_number")
    assert_exact_instance_numbers(label_frame([("a" * 64, BIG, None, None, 1, 1, 1)]), "label_instance_number") is None
