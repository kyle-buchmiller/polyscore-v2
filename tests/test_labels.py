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
