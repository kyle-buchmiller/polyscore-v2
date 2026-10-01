"""Guards on the run draw -- the stage that makes scale a variable and runs reproducible."""

from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from polyscore_v2.draw import DRAWN_STRATA, assign_stratum, check_draw, stratified_draw


def _base(n: int, seed: int = 0) -> pd.DataFrame:
    """A synthetic edge-agnostic base with a known band mix."""
    rng = np.random.default_rng(seed)
    n_def = rng.integers(5, 20, size=n)
    # mix of bands: mostly clean, a healthy contested middle, some consensus-malicious
    frac = rng.choice([0.0, 0.1, 0.5, 0.9, 1.0], size=n, p=[0.4, 0.15, 0.25, 0.1, 0.1])
    n_mal = np.round(frac * n_def).astype(int)
    return pd.DataFrame({
        "sha256": [f"{i:064x}" for i in range(n)],
        "n_malicious": n_mal,
        "n_definite": n_def,
        "n_responded": n_def + rng.integers(0, 3, size=n),
    })


def test_same_seed_same_base_is_identical():
    """The determinism check from SS11: identical inputs must give identical cohorts."""
    base = _base(5_000)
    a, _ = stratified_draw(base, cohort_size=500, seed=42, min_definite=5)
    b, _ = stratified_draw(base, cohort_size=500, seed=42, min_definite=5)
    pd.testing.assert_frame_equal(a, b)


def test_different_seeds_differ():
    base = _base(5_000)
    a, _ = stratified_draw(base, cohort_size=500, seed=1, min_definite=5)
    b, _ = stratified_draw(base, cohort_size=500, seed=2, min_definite=5)
    assert set(a["sha256"]) != set(b["sha256"])


def test_scaling_is_one_number():
    """Change cohort_size and nothing else; the draw takes more of the same base."""
    base = _base(20_000)
    small, _ = stratified_draw(base, cohort_size=1_000, seed=7, min_definite=5)
    large, _ = stratified_draw(base, cohort_size=5_000, seed=7, min_definite=5)
    assert len(large) > len(small)
    # per-stratum shares hold at both sizes where the band can supply them
    for df in (small, large):
        shares = df["stratum"].value_counts(normalize=True)
        assert shares.get("contested", 0) > shares.get("consensus_clean", 0)


def test_pi_is_n_draw_over_n_available():
    base = _base(5_000)
    cohort, reports = stratified_draw(base, cohort_size=500, seed=3, min_definite=5)
    for r in reports:
        if r.n_draw == 0:
            continue
        block = cohort[cohort["stratum"] == r.stratum]
        assert len(block) == r.n_draw
        assert block["pi"].nunique() == 1
        assert block["pi"].iloc[0] == pytest.approx(r.n_draw / r.n_available)
    assert check_draw(cohort, reports) == []


def test_underfill_is_reported_not_backfilled():
    """A band that cannot supply its share stays short. Never borrow from a neighbour."""
    base = _base(5_000)
    # make consensus_malicious tiny
    cm = (base["n_malicious"] == base["n_definite"]) & (base["n_definite"] >= 5)
    base = pd.concat([base[~cm], base[cm].head(3)])
    cohort, reports = stratified_draw(base, cohort_size=2_000, seed=9, min_definite=5)
    r = next(r for r in reports if r.stratum == "consensus_malicious")
    assert r.underfilled and r.n_draw == 3 and r.pi == pytest.approx(1.0)
    # and the shortfall was NOT made up elsewhere
    others = [x for x in reports if x.stratum in DRAWN_STRATA and x.stratum != "consensus_malicious"]
    assert all(x.n_draw <= x.n_target for x in others)


def test_below_floor_is_never_drawn():
    base = _base(2_000)
    cohort, reports = stratified_draw(base, cohort_size=500, seed=5, min_definite=10)
    assert "below_floor" not in set(cohort["stratum"])
    floor = next(r for r in reports if r.stratum == "below_floor")
    assert floor.n_available > 0 and floor.n_draw == 0


def test_the_base_must_be_edge_agnostic():
    """A stored stratum would freeze the band edges into the base. Refuse it."""
    base = _base(100).assign(stratum="contested")
    with pytest.raises(ValueError, match="edge-agnostic"):
        stratified_draw(base, cohort_size=10, seed=1)


def test_stratum_edges_are_applied_at_draw_time():
    s = assign_stratum(pd.Series([0, 1, 5, 9, 10, 2]), pd.Series([10, 10, 10, 10, 10, 3]), min_definite=5)
    assert list(s) == ["consensus_clean", "leaning_clean", "contested",
                       "leaning_malicious", "consensus_malicious", "below_floor"]
