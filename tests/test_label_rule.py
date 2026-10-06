"""The provisional pilot label rule (decisions/0011, Proposed). These tests pin the
behaviour so a change to the rule is a deliberate edit here, not a drift."""
import pandas as pd
import pytest

from polyscore_v2.labels import Grade, Label, family_class, label_at_horizon


def history(at_t: dict, at_label: dict, families: dict | None = None) -> pd.DataFrame:
    """at_t / at_label: author -> True/False/None. families: author -> family at the label scan."""
    rows = [{"scan_role": "feature", "author": a, "verdict": v, "malware_family": None} for a, v in at_t.items()]
    rows += [{"scan_role": "label", "author": a, "verdict": v, "malware_family": (families or {}).get(a)}
             for a, v in at_label.items()]
    df = pd.DataFrame(rows)
    df["verdict"] = df["verdict"].astype("boolean")
    return df


def clean(n: int, prefix: str = "e") -> dict:
    return {f"{prefix}{i}": False for i in range(n)}


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


def test_below_the_floor_is_undecidable_whatever_the_verdicts():
    r = label_at_horizon(history(clean(3), {"a": True, "b": True, "c": True}))
    assert (r.label, r.reason) == (Label.UNDECIDABLE, "below_floor")
    assert r.grade == Grade.TIME_SEPARATED


def test_no_detection_at_the_horizon_is_benign():
    r = label_at_horizon(history(clean(6), clean(6)))
    assert (r.label, r.reason) == (Label.BENIGN, "no_detection")


def test_a_retraction_is_benign_with_the_stronger_reason():
    at_t = {**clean(6), "x": True}
    at_l = {**clean(6), "x": False}
    r = label_at_horizon(history(at_t, at_l))
    assert (r.label, r.reason) == (Label.BENIGN, "retracted")
    assert r.evidence["retractions"] == 1


def test_three_specific_families_are_malicious():
    at_l = {**clean(5), "a": True, "b": True, "c": True}
    fams = {"a": "Trojan.Emotet", "b": "Win32.Emotet.A", "c": "Trojan.PWS.Rhadamanthys"}
    r = label_at_horizon(history(at_l, at_l, fams))
    assert (r.label, r.reason) == (Label.MALICIOUS, "specific_families")


def test_three_generic_detections_do_not_clear_the_bar():
    at_l = {**clean(5), "a": True, "b": True, "c": True}
    fams = {"a": "Trojan.Generic", "b": "Malware.Heuristic", "c": None}
    r = label_at_horizon(history(at_l, at_l, fams))
    assert (r.label, r.reason) == (Label.UNDECIDABLE, "weak_consensus")
    assert r.evidence["weighted_malicious"] == pytest.approx(1.5)


def test_six_generic_detections_do():
    at_l = {**clean(5), **{f"m{i}": True for i in range(6)}}
    r = label_at_horizon(history(at_l, at_l, {f"m{i}": "Trojan.Generic" for i in range(6)}))
    assert (r.label, r.reason) == (Label.MALICIOUS, "generic_volume")


def test_pup_families_route_to_unwanted():
    at_l = {**clean(5), "a": True, "b": True, "c": True}
    fams = {"a": "PUA.Adware.Foo", "b": "Adware.Bar", "c": "Riskware.Bundler"}
    r = label_at_horizon(history(at_l, at_l, fams))
    assert (r.label, r.reason) == (Label.UNWANTED, "pup_family")


def test_two_pup_names_and_a_generic_do_not_clear_the_bar():
    at_l = {**clean(5), "a": True, "b": True, "c": True}
    fams = {"a": "PUA.Adware.Foo", "b": "Adware.Bar", "c": "Trojan.Generic"}
    r = label_at_horizon(history(at_l, at_l, fams))
    assert (r.label, r.reason) == (Label.UNDECIDABLE, "weak_consensus")   # 1 + 1 + 0.5 < 3


def test_engines_absent_at_t_do_not_count_as_flips():
    at_t = clean(5)
    at_l = {**clean(5), "late1": True, "late2": True, "late3": True}
    fams = {"late1": "Emotet", "late2": "Emotet", "late3": "Rhadamanthys"}
    r = label_at_horizon(history(at_t, at_l, fams))
    assert r.label == Label.MALICIOUS
    assert r.evidence["flips"] == 0 and r.evidence["joined"] == 3
