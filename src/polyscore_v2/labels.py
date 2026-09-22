"""Label construction at the horizon. See specs/03-labels.md.

THE INVARIANT: the answer must come from somewhere the inputs did not. Grade 0 -- a
threshold on the same scan's verdicts -- is what destroyed the 2023 model and is banned.
"""

from __future__ import annotations

from enum import IntEnum, StrEnum

import pandas as pd


class Grade(IntEnum):
    """Label independence. Determines what a label may be used for."""

    DERIVED_SAME_SCAN = 0   # banned outright
    TIME_SEPARATED = 1      # may train, may never calibrate  <- the pilot's label
    DIFFERENT_MODALITY = 2  # may train, partial calibration
    ADJUDICATED = 3         # the only grade that may calibrate or test


class Label(StrEnum):
    KNOWN_GOOD = "known_good"
    BENIGN = "benign"
    UNWANTED = "unwanted"
    DUAL_USE = "dual_use"
    MALICIOUS = "malicious"
    UNDECIDABLE = "undecidable"
    EXCLUDED = "excluded"


#: Trained on. Everything else is excluded from both classes and reported as a rate.
POSITIVE = {Label.MALICIOUS}
NEGATIVE = {Label.BENIGN, Label.KNOWN_GOOD}


def label_at_horizon(history: pd.DataFrame) -> tuple[Label, Grade]:
    """Apply the settling rules to one artifact's verdict history at T+horizon.

    Counts INDEPENDENT CLUSTERS, not engines -- five detections are not five opinions if
    four vendors license the same signature feed. Weights family specificity, requires
    stability, and returns UNDECIDABLE rather than forcing a contested case.
    """
    raise NotImplementedError("stage 03 — see specs/03-labels.md")


def assert_calibration_eligible(grades: pd.Series) -> None:
    """Refuse to fit a calibrator on anything below grade 3.

    Fitting on delayed engine consensus produces a system that passes its own
    reliability gates while remaining definitionally uncalibrated. This check is what
    stops that happening by accident.
    """
    bad = sorted(set(grades[grades < Grade.ADJUDICATED].unique()))
    if bad:
        raise ValueError(
            f"calibration requires grade {int(Grade.ADJUDICATED)} labels; found grades {bad}. "
            f"See specs/03-labels.md."
        )
