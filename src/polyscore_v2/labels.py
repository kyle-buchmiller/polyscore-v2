"""Label construction at the horizon. See specs/03-labels.md.

THE INVARIANT: the answer must come from somewhere the inputs did not. Grade 0 -- a
threshold on the same scan's verdicts -- is what destroyed the 2023 model and is banned.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum, StrEnum

import pandas as pd


class Grade(IntEnum):
    """Label independence. Determines what a label may be used for."""

    DERIVED_SAME_SCAN = 0   # banned outright
    TIME_SEPARATED = 1      # may train, may never calibrate  <- the pilot's label
    DIFFERENT_MODALITY = 2  # may train, partial calibration
    ADJUDICATED = 3         # the only grade that may calibrate or test


class Label(StrEnum):
    """The pilot's four labels (estimand SS3). Deliberately fewer than the problem has.

    A seven-label taxonomy was specified first and collapsed for the pilot -- see
    PILOT_COLLAPSE below and decisions/0007. Nothing here is a claim that the world has
    four categories; it is a claim about how many a 10k cohort can populate.
    """

    MALICIOUS = "malicious"
    BENIGN = "benign"
    UNWANTED = "unwanted"
    UNDECIDABLE = "undecidable"


#: Trained on. Everything else is excluded from both classes and reported as a rate.
POSITIVE = {Label.MALICIOUS}
NEGATIVE = {Label.BENIGN}

#: Excluded from training, reported as rates. Never silently folded into either class:
#: how large these are decides whether the exclusion is a footnote or the dominant fact
#: about what the score means.
RATE_REPORTED = {Label.UNWANTED, Label.UNDECIDABLE}

#: The finer taxonomy this collapsed from, kept so the fold is reversible rather than
#: forgotten. Re-expanding is a new estimand version, not a code change.
#:
#: What each fold costs, and where the information went instead:
#:
#: - ``known_good`` -> BENIGN. The attestation is not lost: positively-attested
#:   negatives (NSRL, valid signature from a known publisher, distro package) are
#:   Grade.DIFFERENT_MODALITY, while adjudicated-benign is ADJUDICATED and
#:   engine-derived benign is TIME_SEPARATED. The grade already carried the
#:   distinction, so a separate label was duplicating it.
#: - ``dual_use`` -> UNWANTED. Both are excluded from training and reported as a rate,
#:   so the fold changes no behaviour -- but it does blur the rate, which is why stage
#:   03 records a reason per row and the rate is reported decomposed.
#: - ``excluded`` -> not a label at all. EICAR, test files and non-scannable artifacts
#:   are not in the cohort; dropping them at stage 01 with a reported count is honest,
#:   whereas labelling them pretends they were candidates.
PILOT_COLLAPSE: dict[str, Label | None] = {
    "known_good": Label.BENIGN,
    "dual_use": Label.UNWANTED,
    "excluded": None,  # filtered at extraction, never labelled
}


def assert_pilot_labels(labels: pd.Series) -> None:
    """Refuse any label outside the pilot's four.

    Guards the fold: if a finer label is ever produced again, it must be collapsed
    deliberately via PILOT_COLLAPSE rather than reaching a training split by accident,
    where it would silently join a class it was never meant to be in.
    """
    valid = {str(v) for v in Label}
    stray = sorted(set(labels.astype(str).unique()) - valid)
    if stray:
        folds = {k: (v.value if v else "dropped at stage 01") for k, v in PILOT_COLLAPSE.items()}
        raise ValueError(
            f"labels outside the pilot taxonomy: {stray}. Valid: {sorted(valid)}. "
            f"If these are the pre-collapse taxonomy, fold them explicitly: {folds}. "
            f"See specs/03-labels.md and decisions/0007."
        )


@dataclass(frozen=True)
class LabelResult:
    """One artifact's label, how independent it is, and why it landed there.

    ``reason`` is what keeps a collapsed rate decomposable: an UNWANTED row folded from
    the old ``dual_use`` reads "dual_use", so the reported rate can be split back into
    its parts without re-running the labelling.
    """

    label: Label
    grade: Grade
    reason: str | None = None


def label_at_horizon(history: pd.DataFrame) -> LabelResult:
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
