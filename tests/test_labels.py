"""Guard for label independence. See specs/03-labels.md.

The 2023 model's answer column was a threshold on the verdicts that were its own
features. A model reproducing the vote count would have scored flawlessly and known
nothing. This test is what stops that happening again by accident.
"""

from __future__ import annotations

import pandas as pd
import pytest

from polyscore_v2.labels import Grade, assert_calibration_eligible


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
