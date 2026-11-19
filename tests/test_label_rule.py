"""The pilot's label rule (decisions/0016): the answer column reads movement. These tests
pin the behaviour so a change to the rule is a deliberate edit here, not a drift."""
import math

import pandas as pd
import pytest

from polyscore_v2.labels import Grade, Label, band_at_t, family_class, label_by_movement


def history(at_t: dict, at_label: dict, families: dict | None = None) -> pd.DataFrame:
    """at_t / at_label: author -> True/False/None. families: author -> family at the label scan."""
    rows = [{"scan_role": "feature", "author": a, "verdict": v, "malware_family": None} for a, v in at_t.items()]
    rows += [{"scan_role": "label", "author": a, "verdict": v, "malware_family": (families or {}).get(a)}
             for a, v in at_label.items()]
    df = pd.DataFrame(rows)
    df["verdict"] = df["verdict"].astype("boolean")
    return df


def verdicts(n_malicious: int, n_total: int, prefix: str = "e") -> dict:
    """n_total engines answering, the first n_malicious of them malicious."""
    return {f"{prefix}{i}": i < n_malicious for i in range(n_total)}


@pytest.mark.parametrize("family, expected", [
    ("Trojan.PWS.Rhadamanthys.1", "specific"),
    ("Trojan.Win32.Emotet.gen", "specific"),
    ("Trojan.Generic", "generic"),
    ("Gen:Variant.Ursu.12345", "specific"),   # a named cluster, however generic its owner's taxonomy
    ("a variant of Win32/Agent.ABC", "generic"),
    ("Artemis!A1B2C3", "generic"),
    ("PUA.Adware.Something", "pup"),
    ("HackTool.Win32.Mimikatz", "dual_use"),
    ("", "none"), (None, "none"),
])
def test_family_class(family, expected):
    assert family_class(family) == expected


def test_band_at_t_edges():
    assert band_at_t(0.0) == "clean" and band_at_t(0.099) == "clean"
    assert band_at_t(0.1) == "contested" and band_at_t(0.399) == "contested"
    assert band_at_t(0.4) == "leaning_malicious" and band_at_t(0.499) == "leaning_malicious"
    assert band_at_t(0.5) == "consensus_malicious" and band_at_t(1.0) == "consensus_malicious"
    assert band_at_t(math.nan) is None and band_at_t(None) is None


def test_below_the_floor_at_the_label_scan_is_undecidable_whatever_the_verdicts():
    r = label_by_movement(history(verdicts(0, 12), verdicts(3, 4)))
    assert (r.label, r.reason) == (Label.UNDECIDABLE, "below_floor")
    assert r.grade == Grade.TIME_SEPARATED


def test_too_few_engines_present_at_both_scans_is_undecidable():
    """m_L is 0.5 on twelve verdicts, but only four of those engines were there at T."""
    at_t = verdicts(0, 12, "a")
    at_l = {**verdicts(0, 4, "a"), **verdicts(6, 8, "b")}
    r = label_by_movement(history(at_t, at_l))
    assert (r.label, r.reason) == (Label.UNDECIDABLE, "below_floor")
    assert r.evidence["n_both"] == 4


def test_consensus_at_the_horizon_is_malicious():
    r = label_by_movement(history(verdicts(2, 12), verdicts(7, 12)))
    assert (r.label, r.reason) == (Label.MALICIOUS, "consensus")
    assert r.evidence["band_t"] == "contested"


def test_crossing_half_is_consensus_even_without_growth():
    r = label_by_movement(history(verdicts(5, 12), verdicts(6, 12)))   # 0.417 -> 0.5, dm = 0.083
    assert (r.label, r.reason) == (Label.MALICIOUS, "consensus")


def test_two_engines_of_twelve_joining_in_is_growth():
    r = label_by_movement(history(verdicts(1, 12), verdicts(3, 12)))   # dm = 2/12
    assert (r.label, r.reason) == (Label.MALICIOUS, "grew")
    assert r.evidence["delta_m"] == pytest.approx(2 / 12)


def test_one_engine_of_twelve_is_not_growth_and_the_negative_is_provisional():
    r = label_by_movement(history(verdicts(1, 12), verdicts(2, 12)))   # dm = 0.083, m_L = 0.167
    assert (r.label, r.reason) == (Label.BENIGN, "stayed_contested")


def test_engines_that_merely_joined_do_not_move_m():
    """0 of 10 at T, 4 of 14 at the label scan with zero revisions: attendance, not growth."""
    at_t = verdicts(0, 10, "a")
    at_l = {**verdicts(0, 10, "a"), **verdicts(4, 4, "late")}
    r = label_by_movement(history(at_t, at_l))
    assert (r.label, r.reason) == (Label.BENIGN, "stayed_contested")
    assert r.evidence["joined"] == 4 and r.evidence["delta_m"] == 0.0


def test_stayed_clean_needs_ten_definite_verdicts():
    r = label_by_movement(history(verdicts(0, 12), verdicts(0, 12)))
    assert (r.label, r.reason) == (Label.BENIGN, "stayed_clean")
    r = label_by_movement(history(verdicts(0, 8), verdicts(0, 8)))
    assert (r.label, r.reason) == (Label.UNDECIDABLE, "thin_clean")


def test_a_fall_is_benign_with_the_stronger_reason():
    r = label_by_movement(history(verdicts(4, 12), verdicts(1, 12)))   # dm = -0.25
    assert (r.label, r.reason) == (Label.BENIGN, "fell")
    assert r.evidence["retractions"] == 3


def test_a_pup_consensus_routes_a_positive_to_unwanted():
    at_l = verdicts(6, 12)
    fams = {"e0": "PUA.Adware.Foo", "e1": "Adware.Bar", "e2": "Riskware.Bundler"}
    r = label_by_movement(history(verdicts(1, 12), at_l, fams))
    assert (r.label, r.reason) == (Label.UNWANTED, "pup_family")


def test_an_unknown_answer_is_not_a_definite_verdict():
    at_t = {**verdicts(0, 10), "u": None}
    at_l = {**verdicts(0, 10), "u": True}
    r = label_by_movement(history(at_t, at_l))
    assert (r.label, r.reason) == (Label.BENIGN, "stayed_clean")
    assert r.evidence["n_both"] == 10 and r.evidence["delta_m"] == 0.0
