"""Guard for the as-of rule — the invariant that keeps the pilot honest.

The label comes from the future by construction. If a feature does too, the model
learns a clue that exists only because the answer already happened; it scores
brilliantly in testing and fails in production, and no metric says so.

These tests exist so that failure mode is caught by CI rather than by a customer.
See specs/02-data.md.
"""

from __future__ import annotations

import datetime as dt

import pytest

from polyscore_v2.features import AsOfViolation, Field, assert_as_of

T = dt.datetime(2026, 9, 22, 12, 0, tzinfo=dt.UTC)


def test_fields_at_or_before_the_scoring_moment_are_accepted():
    assert_as_of(
        [
            Field("engine_0xabc_responded", T - dt.timedelta(hours=1)),
            Field("n_independent_clusters", T),
        ],
        T,
    )


def test_a_field_from_after_the_scoring_moment_is_refused():
    with pytest.raises(AsOfViolation, match="stamped after"):
        assert_as_of([Field("verdict_trend", T + dt.timedelta(seconds=1))], T)


@pytest.mark.parametrize("name", ["polyunite", "detections", "tags", "families", "polyscore"])
def test_regenerated_fields_are_refused_even_when_timestamped_early(name):
    """These are overwritten in place, so an early timestamp does not make them safe.

    polyunite in particular absorbs families that arrived weeks later from sandbox runs
    and tags. They are fine for stratification and survey; never as features.
    """
    with pytest.raises(AsOfViolation, match="regenerated in place"):
        assert_as_of([Field(name, T - dt.timedelta(days=1))], T)


@pytest.mark.parametrize("name", ["stratum", "pi", "provenance"])
def test_sampling_bookkeeping_is_refused_as_a_feature(name):
    """Estimand §9 columns describe how a row was *drawn*, not what the file is.

    As features they are perfect provenance detectors: `provenance` separates the
    injected known-good arm from organic traffic outright, and `stratum` is a
    coarsening of engine agreement the matrix already holds. Reweighting reads them;
    the model must not. Unlike the regenerated deny-list above, these are not late —
    they are simply not properties of the artifact.
    """
    with pytest.raises(AsOfViolation, match="bookkeeping"):
        assert_as_of([Field(name, T - dt.timedelta(days=1))], T)
