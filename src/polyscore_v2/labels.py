"""Label construction at the horizon. See specs/03-labels.md.

THE INVARIANT: the answer must come from somewhere the inputs did not. Grade 0 -- a
threshold on the same scan's verdicts -- is what destroyed the 2023 model and is banned.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import IntEnum, StrEnum

import pandas as pd

from .config import LABEL_MIN_DEFINITE


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
    evidence: dict = field(default_factory=dict)


#: PROVISIONAL family-string classes (decisions/0011, Proposed). A family string is
#: `specific` when it carries a token that is not a category word; `generic` when every
#: token is one -- "Trojan.Generic", "Gen:Variant", "Artemis!..", "a variant of Win32/Agent".
#: `pup` and `dual_use` route to UNWANTED with that reason. These are heuristics standing
#: in for the engine-cluster map and the specificity model the spec asks for; they are
#: here so the pipeline runs end to end, and they are the first thing to replace.
_GENERIC_TOKENS = frozenset("""
generic gen heur heuristic heuristics suspicious suspect unsafe malware malicious malicious_confidence
agent variant artemis unknown w32 win32 win64 w64 pe trojan trj virus worm packed packer pack
crypt cryptor obfuscated obfus score ml ai behavior behaveslike behaves like exe dll file high
medium low confidence detection downloader dropper backdoor ransom ransomware stealer spy
spyware injector rootkit exploit adload bundle multi msil win html script js vbs macro
""".split())
_PUP_TOKENS = frozenset("pup pua adware riskware unwanted grayware greyware potentially bundler toolbar optional".split())
_DUAL_USE_TOKENS = frozenset("hacktool hktl remoteadmin remote admintool pentest mimikatz psexec netcat nmap metasploit cobaltstrike cobalt".split())
_TOKEN_RE = re.compile(r"[a-z0-9]+")


def family_class(family: str | None) -> str:
    """One of `none`, `pup`, `dual_use`, `specific`, `generic` for an engine's family string."""
    if family is None or (isinstance(family, float) and pd.isna(family)) or not str(family).strip():
        return "none"
    tokens = _TOKEN_RE.findall(str(family).lower())
    if any(t in _PUP_TOKENS for t in tokens):
        return "pup"
    if any(t in _DUAL_USE_TOKENS for t in tokens):
        return "dual_use"
    # A specific family is a word: variant ids ("A1B2C3", "12345") and category words are not.
    if any(len(t) >= 4 and t.isalpha() and t not in _GENERIC_TOKENS for t in tokens):
        return "specific"
    return "generic"


def label_at_horizon(
    history: pd.DataFrame,
    *,
    min_definite: int = LABEL_MIN_DEFINITE,
    min_clusters: int = 3,
    generic_discount: float = 0.5,
) -> LabelResult:
    """Apply the settling rules to one artifact's verdict history at T+horizon.

    `history` holds the artifact's assertions at both moments: columns `scan_role`
    ('feature' = T, 'label' = the horizon scan), `author`, `verdict`, `malware_family`.

    PROVISIONAL RULE (decisions/0011, Proposed) -- what the spec asks for, with stand-ins
    for the three inputs that do not exist yet, each named in the result's `reason`:

      * clusters      -> engines. Until a vendor-cluster map exists, each engine is its own
                         cluster, so `min_clusters` is a count of engines.
      * specificity   -> `family_class`: a specific family weighs 1.0, a generic or absent
                         one `generic_discount`. "Two specific names" and "six generic
                         detections" both clear a bar of 3.0; three generic ones do not.
      * stability     -> not assessed. Two scans cannot show oscillation; the row carries
                         its change decomposition instead, and the churn re-check (SS4)
                         is where stability becomes measurable.

    Retractions -- engines malicious at T and benign at the horizon -- are the strongest
    negatives available (spec rule 5) and are what a BENIGN row's reason records.
    """
    lab = history[history["scan_role"] == "label"]
    at_t = {a: (None if pd.isna(v) else bool(v)) for a, v in
            zip(history.loc[history["scan_role"] == "feature", "author"],
                history.loc[history["scan_role"] == "feature", "verdict"])}
    at_l = {a: (None if pd.isna(v) else bool(v)) for a, v in zip(lab["author"], lab["verdict"])}
    change = decompose_change(at_t, at_l)

    n_definite = int(lab["verdict"].notna().sum())
    n_malicious = int((lab["verdict"] == True).sum())  # noqa: E712 -- nullable boolean
    classes = [family_class(f) for f in lab.loc[lab["verdict"] == True, "malware_family"]]  # noqa: E712
    weighted = sum(1.0 if c in ("specific", "pup", "dual_use") else generic_discount for c in classes)
    evidence = {
        "n_definite": n_definite, "n_malicious": n_malicious,
        "m": (n_malicious / n_definite) if n_definite else float("nan"),
        "weighted_malicious": weighted,
        "n_specific": classes.count("specific"), "n_generic": classes.count("generic") + classes.count("none"),
        "n_pup": classes.count("pup"), "n_dual_use": classes.count("dual_use"),
        "flips": change.flips, "retractions": change.retractions,
        "joined": change.joined, "left": change.left, "stable": change.stable,
    }
    grade = Grade.TIME_SEPARATED
    if n_definite < min_definite:
        return LabelResult(Label.UNDECIDABLE, grade, "below_floor", evidence)
    if n_malicious == 0:
        return LabelResult(Label.BENIGN, grade, "retracted" if change.retractions else "no_detection", evidence)
    if weighted >= min_clusters:
        if evidence["n_pup"] >= 2 and evidence["n_pup"] >= evidence["n_specific"]:
            return LabelResult(Label.UNWANTED, grade, "pup_family", evidence)
        if evidence["n_dual_use"] >= 2 and evidence["n_dual_use"] >= evidence["n_specific"]:
            return LabelResult(Label.UNWANTED, grade, "dual_use", evidence)
        return LabelResult(Label.MALICIOUS, grade,
                           "specific_families" if evidence["n_specific"] >= 2 else "generic_volume", evidence)
    return LabelResult(Label.UNDECIDABLE, grade, "weak_consensus", evidence)


@dataclass(frozen=True)
class ChangeDecomposition:
    """How much of a T -> label move was opinion, and how much was attendance.

    Two mechanisms shift `m` between the scoring moment and the horizon, and they do
    not mean the same thing:

      flips    an engine present at BOTH moments answered differently. Genuine
               revision -- this is what the horizon is supposed to capture, and
               retractions (flips True -> False) are the strongest negatives we have.
      joined   an engine that was absent at T answered by the horizon. Nobody
               revised anything; the sample filled in.
      left     an engine present at T was absent at the horizon.

    Measured on six stage artifacts 2026-09-30: 5 flips, 10 joined, 4 left -- so both
    are real and unevenly spread. One artifact moved from 2/7 to 7/14 malicious with
    ZERO flips: its T scan had caught only 7 of a typical 16 engines, and the arrivals
    skewed malicious. Read naively that looks like a dramatic late detection; it is
    attendance.

    Consequence: the label may use everyone (more engines is a better assessment), but
    any statement ABOUT change -- churn, retraction rate, "how much did verdicts move"
    -- must be computed over `both` only, with turnover reported beside it rather than
    folded in.
    """

    flips: int           # present at both, verdict differs
    retractions: int     # of those, True -> False specifically
    joined: int          # absent at T, present at the horizon
    left: int            # present at T, absent at the horizon
    stable: int          # present at both, verdict identical

    @property
    def both(self) -> int:
        """Engines present at both moments -- the only comparable population."""
        return self.flips + self.stable

    @property
    def turnover_rate(self) -> float:
        """Share of the engine union that is attendance rather than opinion."""
        union = self.both + self.joined + self.left
        return (self.joined + self.left) / union if union else 0.0


def decompose_change(
    at_t: dict[str, bool | None], at_label: dict[str, bool | None]
) -> ChangeDecomposition:
    """Split a T -> label move into revision and turnover.

    Both arguments map engine ADDRESS (never a display name -- see specs/02-data.md) to
    that engine's verdict: True, False, or None for an explicit "unknown". An engine
    that never responded is simply absent from the mapping, which is the fourth state.

    A flip requires presence at both moments. Appearing or disappearing is turnover and
    is never counted as a changed opinion.
    """
    both = set(at_t) & set(at_label)
    flips = [a for a in both if at_t[a] != at_label[a]]
    return ChangeDecomposition(
        flips=len(flips),
        retractions=sum(1 for a in flips if at_t[a] is True and at_label[a] is False),
        joined=len(set(at_label) - set(at_t)),
        left=len(set(at_t) - set(at_label)),
        stable=len(both) - len(flips),
    )


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
