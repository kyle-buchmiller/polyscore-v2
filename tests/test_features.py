"""The four engine states survive encoding; the old encoding loses them; the matrix refuses
what it must. See specs/02-data.md."""
import datetime as dt

import pandas as pd
import pytest

from polyscore_v2.features import (AsOfViolation, Field, aggregates, assert_as_of, build_matrix,
                                   encode_engine_verdicts, encode_engine_verdicts_old)


def assertions_one_artifact():
    # A said malicious, B said clean, C answered "unknown", D never responded.
    df = pd.DataFrame({
        "sha256": ["x"] * 3, "scan_role": ["feature"] * 3,
        "author": ["A", "B", "C"], "verdict": [True, False, None], "bid": [10, 5, 1],
        "malware_family": ["Trojan.Emotet", None, None],
    })
    df["verdict"] = df["verdict"].astype("boolean")
    return df


def test_two_column_encoding_keeps_clean_silent_and_malicious_apart():
    enc = encode_engine_verdicts(assertions_one_artifact(), pd.Index(["x"]))
    row = enc.loc["x"]
    assert (row["engine_A_responded"], row["engine_A_malicious"]) == (1, 1)
    assert (row["engine_B_responded"], row["engine_B_malicious"]) == (1, 0)
    assert (row["engine_C_responded"], row["engine_C_malicious"]) == (1, 0)
    assert "engine_D_responded" not in enc.columns   # never responded anywhere: no column


def test_old_encoding_collapses_everything_but_malicious_to_zero():
    old = encode_engine_verdicts_old(assertions_one_artifact(), pd.Index(["x"]))
    assert old.loc["x"].to_dict() == {"engine_A": 1, "engine_B": 0, "engine_C": 0}


def test_aggregates_count_unknown_separately():
    agg = aggregates(assertions_one_artifact(), pd.Index(["x"]))
    r = agg.loc["x"]
    assert (r["n_responded"], r["n_definite"], r["n_malicious"], r["n_benign"], r["n_unknown"]) == (3, 2, 1, 1, 1)
    assert r["m"] == pytest.approx(0.5)


def test_artifact_with_no_assertions_is_all_zero_not_missing():
    enc = encode_engine_verdicts(assertions_one_artifact(), pd.Index(["x", "y"]))
    assert enc.loc["y"].sum() == 0
    agg = aggregates(assertions_one_artifact(), pd.Index(["x", "y"]))
    assert agg.loc["y", "n_responded"] == 0 and agg.loc["y", "m_defined"] == 0


def test_the_incumbent_is_refused_as_a_feature():
    now = dt.datetime(2026, 9, 1)
    with pytest.raises(AsOfViolation, match="regenerated"):
        assert_as_of([Field("incumbent_polyscore", now)], now)


def test_build_matrix_groups_and_checks_the_base_counts():
    cohort = pd.DataFrame({
        "sha256": ["x"], "instance_number": [1], "scoring_moment": [pd.Timestamp("2026-09-01")],
        "label_gap": ["40 days"], "n_definite": [2], "n_malicious": [1], "n_responded": [3],
        "stratum": ["contested"], "pi": [0.5], "provenance": ["customer"],
    })
    matrix, groups = build_matrix(cohort, assertions_one_artifact())
    assert set(groups) == {"meta", "bookkeeping", "features_new", "features_old"}
    assert "pi" in groups["bookkeeping"] and "pi" not in groups["features_new"]
    assert "modal_family" in groups["meta"] and matrix.loc[0, "modal_family"] == "trojan.emotet"
    assert "engine_A_malicious" in groups["features_new"] and "engine_A" in groups["features_old"]
    bad = cohort.assign(n_malicious=[2])
    with pytest.raises(ValueError, match="out of step"):
        build_matrix(bad, assertions_one_artifact())
