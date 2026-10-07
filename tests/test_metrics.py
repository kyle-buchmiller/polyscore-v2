"""A metric that cannot be computed says NaN; the sliced table carries the SS1 slice."""
import math

import numpy as np
import pandas as pd
import pytest

from polyscore_v2.metrics import auc, metrics_table, prob_metrics


def test_auc_is_nan_with_one_class_and_exact_when_separable():
    assert math.isnan(auc(np.array([1, 1, 1]), np.array([0.2, 0.5, 0.9])))
    assert auc(np.array([0, 0, 1, 1]), np.array([0.1, 0.2, 0.8, 0.9])) == 1.0
    assert auc(np.array([0, 1]), np.array([0.9, 0.1])) == 0.0


def test_metrics_table_slices_by_provenance_and_stratum():
    df = pd.DataFrame({"y": [0, 1, 0, 1], "pi": [1, 1, 0.5, 0.5],
                       "provenance": ["customer", "customer", "feed", "feed"],
                       "stratum": ["contested", "contested", "consensus_clean", "consensus_clean"]})
    m = metrics_table(df, np.array([0.1, 0.9, 0.2, 0.8]))
    assert m["pooled_raw"] == 1.0 and m["s1_raw"] == 1.0 and m["s1_n"] == 2
    assert set(m["per_stratum"]) == {"contested", "consensus_clean"} and set(m["per_provenance"]) == {"customer", "feed"}
    none = metrics_table(df.assign(provenance="feed"), np.array([0.1, 0.9, 0.2, 0.8]))
    assert math.isnan(none["s1_raw"]) and none["s1_n"] == 0


def test_prob_metrics_reports_the_base_rate_it_must_beat():
    df = pd.DataFrame({"y": [1, 0, 0, 0], "pi": [1.0, 1.0, 1.0, 1.0]})
    m = prob_metrics(df, np.array([0.25, 0.25, 0.25, 0.25]))
    assert m["prevalence_reweighted"] == 0.25
    assert m["brier"] == pytest.approx(m["brier_base_rate"])      # predicting the base rate IS the base-rate Brier
    assert m["brier_base_rate"] == pytest.approx(0.25 * 0.75)
