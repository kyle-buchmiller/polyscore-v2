"""Two floats are the base rate; addition in log-odds keeps a probability a probability."""
import numpy as np
import pandas as pd
import pytest

from polyscore_v2.calibration import Contribution, explain, fit_calibrator, provisional_combiner


def test_platt_is_monotone_and_learns_the_base_rate():
    rng = np.random.default_rng(0)
    y = rng.random(2000) < 0.1                       # 10% prevalence
    s = np.where(y, rng.normal(1.5, 1, 2000), rng.normal(-1.5, 1, 2000))
    cal = fit_calibrator(s, y)
    p = cal.predict_proba(np.linspace(-4, 4, 50))
    assert np.all(np.diff(p) > 0)
    assert cal.predict_proba(s).mean() == pytest.approx(y.mean(), abs=0.02)
    assert cal.provisional is True


def test_isotonic_is_refused_at_pilot_volumes():
    with pytest.raises(NotImplementedError, match="Platt"):
        fit_calibrator(np.zeros(4), np.array([0, 1, 0, 1]), method="isotonic")


def test_combiner_adds_in_log_odds_and_explains_itself():
    comb = provisional_combiner({"chain-broken": 1.84, "c2-contacted": 2.05})
    base = np.array([0.5, 0.5])
    signals = pd.DataFrame({"chain-broken": [1, 0], "c2-contacted": [0, 0]})
    p, rows = comb.apply(base, signals)
    assert p[1] == pytest.approx(0.5)                          # no signal, unchanged
    assert p[0] == pytest.approx(1 / (1 + np.exp(-1.84)))      # logit(0.5) + 1.84
    table = explain(rows[0])
    assert list(table["source"]) == ["chain-broken", "engine_evidence"]


def test_a_signal_with_no_column_contributes_nothing():
    comb = provisional_combiner({"never-present": 5.0})
    p, rows = comb.apply(np.array([0.3]), pd.DataFrame({"other": [1]}))
    assert p[0] == pytest.approx(0.3) and rows[0] == [Contribution("engine_evidence", pytest.approx(np.log(0.3 / 0.7)))]
