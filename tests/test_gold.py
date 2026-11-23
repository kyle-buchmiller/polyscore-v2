"""Guards on the gold slice's draw: what it takes, what a top-up keeps, and the probability it records."""

from __future__ import annotations

import itertools
from fractions import Fraction

import numpy as np
import pandas as pd
import pytest

from polyscore_v2.gold import GROUPS, Earlier, draw, pools
from polyscore_v2.labels import Label

MAL, BEN = str(Label.MALICIOUS), str(Label.BENIGN)


def _labelled(n_accrued: int, n_stayed: int, other: int = 0, start: int = 0) -> pd.DataFrame:
    """A labelled band: files that accrued, files that stayed contested, and files of neither group."""
    rows = [(MAL, "grew" if i % 2 else "consensus") for i in range(n_accrued)]
    rows += [(BEN, "stayed_contested")] * n_stayed + [(BEN, "retracted")] * other
    return pd.DataFrame({
        "sha256": [f"{start + i:064x}" for i in range(len(rows))],
        "label": [label for label, _ in rows],
        "reason": [reason for _, reason in rows],
        "band_t": "contested",
    })


def test_pools_hold_each_groups_files_of_the_band_only():
    labelled = pd.concat([_labelled(5, 4, other=3), _labelled(2, 2, start=100).assign(band_t="clean")])
    got = pools(labelled, "contested")
    assert list(got) == list(GROUPS)
    assert (len(got["accrued"]), len(got["stayed"])) == (5, 4)
    assert set(got["accrued"]["label"]) == {MAL} and set(got["stayed"]["reason"]) == {"stayed_contested"}
    assert got["accrued"]["sha256"].is_monotonic_increasing


def test_a_plain_draw_takes_per_group_at_random_and_records_its_share():
    by_group = pools(_labelled(40, 25), "contested")
    gold, report = draw(by_group, 10, np.random.default_rng(7))
    assert gold.groupby("group").size().to_dict() == {"accrued": 10, "stayed": 10}
    assert not gold["sha256"].duplicated().any() and (gold["carried_from"] == "").all()
    assert gold.loc[gold["group"] == "accrued", "pi_gold"].unique().tolist() == [10 / 40]
    assert gold.loc[gold["group"] == "stayed", "pi_gold"].unique().tolist() == [10 / 25]
    assert report["stayed"] == {"eligible": 25, "drawn": 10, "carried": 0, "new": 10, "pi_new": 10 / 25,
                                "earlier_pools": {}}
    again, _ = draw(by_group, 10, np.random.default_rng(7))
    assert gold["sha256"].tolist() == again["sha256"].tolist()
    other, _ = draw(by_group, 10, np.random.default_rng(8))
    assert gold["sha256"].tolist() != other["sha256"].tolist()


def test_a_pool_that_cannot_fill_its_group_is_refused():
    with pytest.raises(ValueError, match="4 eligible files in group 'stayed'"):
        draw(pools(_labelled(40, 4), "contested"), 10, np.random.default_rng(0))


def _continued(per_group: int = 10, seed: int = 3):
    """An earlier slice of 10 per group, then a band that lost some of its files and gained others."""
    before = pools(_labelled(40, 30), "contested")
    first, _ = draw(before, 10, np.random.default_rng(1))
    earlier = Earlier("run-a", frozenset(first["sha256"]),
                      {s: g for g, pool in before.items() for s in pool["sha256"]})
    # Every third file of the earlier band is gone; forty files are new to it.
    stays = pd.concat(before.values()).iloc[lambda d: np.arange(len(d)) % 3 != 0]
    now = pools(pd.concat([stays, _labelled(25, 15, start=1000)]), "contested")
    gold, report = draw(now, per_group, np.random.default_rng(seed), earlier)
    return first, earlier, now, gold, report


def test_a_top_up_keeps_the_earlier_files_still_eligible_and_fills_each_group():
    first, earlier, now, gold, report = _continued()
    assert gold.groupby("group").size().to_dict() == {"accrued": 10, "stayed": 10}
    assert not gold["sha256"].duplicated().any()
    eligible = {s for pool in now.values() for s in pool["sha256"]}
    still = set(first["sha256"]) & eligible
    carried = set(gold.loc[gold["carried_from"] == "run-a", "sha256"])
    assert carried == still and 0 < len(still) < len(first)
    fresh = gold[gold["carried_from"] == ""]
    assert not set(fresh["sha256"]) & earlier.drawn and set(fresh["sha256"]) <= eligible
    for group, rows in gold.groupby("group"):
        assert report[group]["carried"] == int((rows["carried_from"] == "run-a").sum())
        assert report[group]["carried"] + report[group]["new"] == 10
        assert (rows["n_eligible"] == len(now[group])).all()


def test_a_top_up_records_the_chance_of_either_way_into_the_slice():
    _, earlier, now, gold, report = _continued()
    kinds = gold["sha256"].isin(earlier.pool.keys())
    assert kinds.any() and not kinds.all()
    for group, rows in gold.groupby("group"):
        pool, r = now[group], report[group]
        p_new = r["new"] / (len(pool) - r["carried"])
        assert r["pi_new"] == pytest.approx(p_new)
        was_there = pool["sha256"].isin(earlier.pool.keys())
        cell = r["earlier_pools"][group]
        assert cell == {"in_pool": int(was_there.sum()), "carried": r["carried"]}
        p_kept = cell["carried"] / cell["in_pool"]
        old = rows["sha256"].isin(earlier.pool.keys())
        assert rows.loc[old, "pi_gold"].to_numpy() == pytest.approx(p_kept + (1 - p_kept) * p_new)
        assert rows.loc[~old, "pi_gold"].to_numpy() == pytest.approx(p_new)
        assert (rows.loc[old, "pi_gold"] > p_new).all()


def test_the_recorded_chance_is_the_exact_one_given_how_many_were_carried():
    """Every earlier draw and every top-up of a small band, counted: the share of slices a file is in."""
    old_pool = [f"{i:064x}" for i in range(6)]
    now_pool = old_pool[:4] + [f"{i:064x}" for i in range(10, 13)]
    frame = pd.DataFrame({"sha256": sorted(now_pool), "label": MAL, "reason": "grew", "band_t": "contested"})
    by_group = {"accrued": pools(frame, "contested")["accrued"]}
    inside, total = {}, {}
    for first in itertools.combinations(old_pool, 2):
        kept = set(first) & set(now_pool)
        rest = [s for s in now_pool if s not in kept]
        fills = list(itertools.combinations(rest, 3 - len(kept)))
        for fill in fills:
            weight = Fraction(1, len(fills))
            total[len(kept)] = total.get(len(kept), 0) + weight
            for s in kept | set(fill):
                inside[len(kept), s] = inside.get((len(kept), s), 0) + weight
    seen = set()
    for first in itertools.combinations(old_pool, 2):
        earlier = Earlier("run-a", frozenset(first), dict.fromkeys(old_pool, "accrued"))
        gold, report = draw(by_group, 3, np.random.default_rng(0), earlier)
        k = report["accrued"]["carried"]
        seen.add(k)
        for sha, pi in zip(gold["sha256"], gold["pi_gold"], strict=True):
            assert pi == pytest.approx(float(inside[k, sha] / total[k]))
    assert seen == {0, 1, 2}


def test_a_top_up_refuses_more_earlier_files_than_the_group_takes():
    with pytest.raises(ValueError, match="holds 10 earlier files, 4 asked"):
        before = pools(_labelled(40, 30), "contested")
        first, _ = draw(before, 10, np.random.default_rng(1))
        earlier = Earlier("run-a", frozenset(first["sha256"]),
                          {s: g for g, pool in before.items() for s in pool["sha256"]})
        draw(before, 4, np.random.default_rng(2), earlier)


def test_an_earlier_file_missing_from_the_earlier_pools_is_refused():
    before = pools(_labelled(40, 30), "contested")
    first, _ = draw(before, 10, np.random.default_rng(1))
    with pytest.raises(ValueError, match="not in the earlier pools"):
        draw(before, 10, np.random.default_rng(2), Earlier("run-a", frozenset(first["sha256"]), {}))


def test_a_file_whose_group_changed_is_counted_with_the_pool_it_came_from():
    before = pools(_labelled(40, 30), "contested")
    first, _ = draw(before, 10, np.random.default_rng(1))
    earlier = Earlier("run-a", frozenset(first["sha256"]),
                      {s: g for g, pool in before.items() for s in pool["sha256"]})
    # Five files that stayed contested are relabelled: they sit in the other group's pool now.
    moved = before["stayed"]["sha256"].iloc[:5]
    frame = pd.concat(before.values())
    frame.loc[frame["sha256"].isin(moved), ["label", "reason"]] = [MAL, "grew"]
    now = pools(frame, "contested")
    gold, report = draw(now, 12, np.random.default_rng(4), earlier)
    cells = report["accrued"]["earlier_pools"]
    assert cells["stayed"]["in_pool"] == 5 and cells["accrued"]["in_pool"] == 40
    rows = gold[(gold["group"] == "accrued") & gold["sha256"].isin(moved)]
    p_new = report["accrued"]["pi_new"]
    p_kept = cells["stayed"]["carried"] / 5
    assert rows["pi_gold"].to_numpy() == pytest.approx(p_kept + (1 - p_kept) * p_new)
