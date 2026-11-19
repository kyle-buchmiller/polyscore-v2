"""Guards on the frame rule that keeps memory images out of the draw."""

from __future__ import annotations

import pandas as pd
import pytest

from polyscore_v2.memory_image import (
    REASON_CONFIRMED,
    REASON_LAYOUT,
    REASON_NO_RECORD,
    REASON_RELOCATED_EXE,
    REASON_RUNTIME_BASE,
    absent,
    classify,
    frame_reasons,
    read_confirmed,
    to_frame,
    trim,
)


def _doc(sections, *, size, base=0x400000, rva=0x1000, petype="PE32", is_dll=False, sha="a" * 64) -> dict:
    """An index document as the metadata query returns it: numbers as strings, exiftool's RVA in hex."""
    return {
        "artifact": {"sha256": sha, "size": size, "md5": "ignored"},
        "pefile": {
            "is_dll": is_dll,
            "sections": [
                {"raw_size": str(raw), "virtual_size": str(vs), "virtual_address": str(va)}
                for raw, vs, va in sections
            ],
        },
        "lief": {"entrypoint": base + rva},
        "exiftool": {"entrypoint": hex(rva), "petype": petype},
    }


#: As linked: raw sizes rounded to the file alignment, smaller than the image they map to.
ON_DISK = [(0x1E00, 0x1C34, 0x1000), (0x600, 0x5A0, 0x3000), (0, 0x2000, 0x4000)]
#: As dumped: every section at its mapped size.
DUMPED = [(0x1C34, 0x1C34, 0x1000), (0x5A0, 0x5A0, 0x3000)]


def test_a_linked_file_at_its_default_base_stays():
    row = classify(_doc(ON_DISK, size=0x2800))
    assert row["layout"] == "file" and row["reason"] is None
    assert row["image_base"] == 0x400000 and not row["pe64"]


def test_sections_at_their_mapped_size_are_a_memory_image():
    row = classify(_doc(DUMPED, size=0x4000))
    assert row["layout"] == "memory" and row["reason"] == REASON_LAYOUT


def test_a_dump_cut_short_is_still_a_memory_image():
    row = classify(_doc(DUMPED, size=0x2000))
    assert row["layout"] == "memory_truncated" and row["reason"] == REASON_LAYOUT


def test_page_sized_sections_need_the_file_to_end_with_the_image():
    """Raw equal to virtual on a 512 boundary is ambiguous; the file's length settles it."""
    paged = [(0x2000, 0x2000, 0x1000), (0x1000, 0x1000, 0x3000)]
    assert classify(_doc(paged, size=0x4000))["reason"] == REASON_LAYOUT
    assert classify(_doc(paged, size=0x3400))["reason"] is None


def test_a_64_bit_run_time_base_is_a_memory_image_whatever_the_layout():
    row = classify(_doc(ON_DISK, size=0x2800, base=0x7FF6_1234_0000, petype="PE32+"))
    assert row["layout"] == "file" and row["reason"] == REASON_RUNTIME_BASE
    linked = classify(_doc(ON_DISK, size=0x2800, base=0x1_4000_0000, petype="PE32+"))
    assert linked["reason"] is None and linked["pe64"]


def test_a_32_bit_exe_off_its_default_base_goes_and_a_dll_stays():
    assert classify(_doc(ON_DISK, size=0x2800, base=0x00B4_0000))["reason"] == REASON_RELOCATED_EXE
    assert classify(_doc(ON_DISK, size=0x2800, base=0x6F00_0000, is_dll=True))["reason"] is None
    assert classify(_doc(ON_DISK, size=0x2800, base=0x1000_0000))["reason"] is None
    assert classify(_doc(ON_DISK, size=0x2800, base=0x00B4_0000, petype=None))["reason"] is None


def test_no_evidence_is_not_evidence():
    """A document the analyzers left empty stays: the rule never excludes on a missing field."""
    row = classify({"artifact": {"sha256": "b" * 64, "size": 10}})
    assert row["layout"] == "no_sections" and row["image_base"] is None and row["reason"] is None
    no_entry = _doc(ON_DISK, size=0x2800, rva=0)
    assert classify(no_entry)["image_base"] is None and classify(no_entry)["reason"] is None


def test_trim_keeps_what_classify_reads():
    doc = _doc(DUMPED, size=0x4000)
    assert classify(trim(doc)) == classify(doc)
    assert "md5" not in trim(doc)["artifact"]


def test_frame_reasons_adds_the_confirmed_list_under_the_index():
    hashes = [f"{i:064x}" for i in range(4)]
    static = to_frame(
        [
            classify(_doc(ON_DISK, size=0x2800, sha=hashes[0])),
            classify(_doc(DUMPED, size=0x4000, sha=hashes[1])),
            classify(_doc(ON_DISK, size=0x2800, sha=hashes[2])),
            absent(hashes[3]),
        ]
    )
    assert str(static["image_base"].dtype) == "Int64"
    reason = frame_reasons(pd.Series(hashes), static, confirmed=[hashes[1], hashes[2]])
    assert list(reason) == [None, REASON_LAYOUT, REASON_CONFIRMED, REASON_NO_RECORD]


def test_frame_reasons_refuses_a_frame_the_table_does_not_cover():
    static = to_frame([classify(_doc(ON_DISK, size=0x2800, sha="c" * 64))])
    with pytest.raises(ValueError, match="no static record"):
        frame_reasons(pd.Series(["c" * 64, "d" * 64]), static)


def test_read_confirmed_ignores_comments_and_hashes_the_list(tmp_path):
    p = tmp_path / "confirmed.txt"
    p.write_text("# from a byte-level check\n" + "E" * 64 + "  # sample 18\n\n" + "f" * 64 + "\n")
    hashes, digest = read_confirmed(p)
    assert hashes == ["e" * 64, "f" * 64] and len(digest) == 64
