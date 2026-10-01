"""Guard for label independence. See specs/03-labels.md.

The 2023 model's answer column was a threshold on the verdicts that were its own
features. A model reproducing the vote count would have scored flawlessly and known
nothing. This test is what stops that happening again by accident.
"""

from __future__ import annotations

import pandas as pd
import pytest

from polyscore_v2.labels import (
    NEGATIVE,
    POSITIVE,
    PILOT_COLLAPSE,
    RATE_REPORTED,
    Grade,
    Label,
    assert_calibration_eligible,
    assert_pilot_labels,
    decompose_change,
)


def test_adjudicated_labels_may_calibrate():
    assert_calibration_eligible(pd.Series([Grade.ADJUDICATED] * 5))


@pytest.mark.parametrize(
    "grade",
    [Grade.DERIVED_SAME_SCAN, Grade.TIME_SEPARATED, Grade.DIFFERENT_MODALITY],
)
def test_lower_grades_may_not_calibrate(grade):
    """Grade 1 is the pilot's TRAINING label and must never reach the calibrator.

    Fitting on delayed engine consensus yields a system that passes its own reliability
    gates while remaining definitionally uncalibrated.
    """
    with pytest.raises(ValueError, match="grade 3"):
        assert_calibration_eligible(pd.Series([Grade.ADJUDICATED, grade]))


def test_the_pilot_has_exactly_four_labels():
    """Four is a claim about what a 10k cohort can populate, not about the world.

    See decisions/0007: a seven-label taxonomy was collapsed, and re-expanding is a new
    estimand version rather than a code change.
    """
    assert {str(v) for v in Label} == {"malicious", "benign", "unwanted", "undecidable"}
    assert POSITIVE == {Label.MALICIOUS}
    assert NEGATIVE == {Label.BENIGN}
    assert RATE_REPORTED == {Label.UNWANTED, Label.UNDECIDABLE}


def test_the_four_pilot_labels_are_accepted():
    assert_pilot_labels(pd.Series([str(v) for v in Label]))


@pytest.mark.parametrize("stray", sorted(PILOT_COLLAPSE))
def test_pre_collapse_labels_are_refused(stray):
    """A pre-collapse label reaching a split would silently join a class.

    known_good would land in the negative class carrying grade-2 evidence unmarked;
    dual_use would train as a negative it was explicitly excluded from being. This is
    the quietest available corruption of a training set, so it fails loudly instead.
    """
    with pytest.raises(ValueError, match="outside the pilot taxonomy"):
        assert_pilot_labels(pd.Series(["benign", stray]))


def test_turnover_is_not_counted_as_a_changed_opinion():
    """The failure this guards: an engine that merely showed up late reads as a flip.

    Reproduces the stage artifact that moved 2/7 -> 7/14 malicious with zero engines
    revising anything. Read naively that is dramatic late detection; it is attendance.
    """
    at_t = {"0xaa": False, "0xbb": True}
    at_label = {"0xaa": False, "0xbb": True, "0xcc": True, "0xdd": True}
    d = decompose_change(at_t, at_label)
    assert d.flips == 0, "nobody revised anything"
    assert d.joined == 2
    assert d.both == 2
    assert d.stable == 2


def test_a_retraction_is_a_flip_and_is_counted_separately():
    """An engine that detected and later stopped is the strongest negative available."""
    d = decompose_change({"0xaa": True, "0xbb": True}, {"0xaa": False, "0xbb": True})
    assert d.flips == 1
    assert d.retractions == 1
    assert d.joined == d.left == 0


def test_absent_and_unknown_are_different_states():
    """verdict IS NULL ("answered unknown") is presence; no row at all is absence."""
    present_unknown = decompose_change({"0xaa": None}, {"0xaa": True})
    assert present_unknown.flips == 1 and present_unknown.joined == 0
    absent = decompose_change({}, {"0xaa": True})
    assert absent.flips == 0 and absent.joined == 1


def test_turnover_rate_is_share_of_the_union():
    d = decompose_change({"0xaa": True}, {"0xaa": True, "0xbb": False, "0xcc": False})
    assert d.both == 1 and d.joined == 2
    assert d.turnover_rate == pytest.approx(2 / 3)
