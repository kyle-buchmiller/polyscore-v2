"""What the metadata index's own fields say about which frame files are memory images.

A survey, not the frame rule: the index stores no import table, so it passes memory images
saved in file layout and flags files that are merely built in an unusual way. The frame rule
reads each file's bytes (`image_bytes`).
see specs/12-api-slice-pilot.md § What the index fields say
"""

from __future__ import annotations

from collections.abc import Mapping

import pandas as pd

#: The index fields the rule reads, as `include` paths of the metadata query.
STATIC_INCLUDE: tuple[str, ...] = (
    "artifact.sha256",
    "artifact.size",
    "pefile.sections.raw_size",
    "pefile.sections.virtual_size",
    "pefile.sections.virtual_address",
    "pefile.is_dll",
    "lief.entrypoint",
    "exiftool.entrypoint",
    "exiftool.petype",
)
#: 64-bit Windows loads images at or above this address; no linker's default is near it.
RUNTIME_BASE_64 = 0x7FF0_0000_0000
#: The linkers' default image bases for a 32-bit EXE and a 32-bit DLL.
DEFAULT_BASES_32 = frozenset({0x400000, 0x10000000})

REASON_LAYOUT = "memory_layout"
REASON_RUNTIME_BASE = "runtime_base_64"
REASON_RELOCATED_EXE = "relocated_exe_32"
REASON_NO_RECORD = "no_index_record"
#: Report order; a file carries the first that applies.
REASONS: tuple[str, ...] = (
    REASON_LAYOUT,
    REASON_RUNTIME_BASE,
    REASON_RELOCATED_EXE,
    REASON_NO_RECORD,
)


def _int(value) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def trim(doc: Mapping) -> dict:
    """The part of an index document `classify` reads, which is what a cache needs to keep."""
    art = doc.get("artifact") or {}
    return {
        "artifact": {"sha256": art.get("sha256"), "size": art.get("size")},
        "pefile": doc.get("pefile") or {},
        "lief": doc.get("lief") or {},
        "exiftool": doc.get("exiftool") or {},
    }


def classify(doc: Mapping) -> dict:
    """One index document -> its layout, its image base and why it looks like a memory image.

    `reason` is None for a file that does not. A file the analyzers could not lay out
    (`no_sections`, `other`, no image base) gets none: the rule acts on evidence, not on its absence.
    """
    pe = doc.get("pefile") or {}
    lief = doc.get("lief") or {}
    exif = doc.get("exiftool") or {}
    art = doc.get("artifact") or {}
    sections = [
        (_int(s.get("raw_size")), _int(s.get("virtual_size")), _int(s.get("virtual_address")))
        for s in (pe.get("sections") or [])
    ]
    sized = [s for s in sections if s[0] > 0]
    size = _int(art.get("size"))
    image_end = max((va + max(vs, raw) for raw, vs, va in sections), default=0)
    raw_is_virtual = bool(sized) and all(raw == vs for raw, vs, _ in sized)
    raw_on_512 = bool(sized) and all(raw % 512 == 0 for raw, _, _ in sized)
    # A dump keeps each section at its mapped size; a linker rounds it to the file alignment.
    if not sized:
        layout = "no_sections"
    elif raw_is_virtual and (not raw_on_512 or size == image_end):
        layout = "memory" if size >= image_end else "memory_truncated"
    elif raw_on_512:
        layout = "file"
    else:
        layout = "other"

    # lief stores the absolute entry point and exiftool its RVA; the difference is ImageBase.
    image_base = None
    try:
        rva = int(str(exif.get("entrypoint")), 16)
        entry = int(lief.get("entrypoint"))
        if rva > 0 and entry >= rva:
            image_base = entry - rva
    except (TypeError, ValueError):
        pass
    petype = str(exif.get("petype") or "").strip()
    is_dll = bool(pe.get("is_dll"))

    reason = None
    if layout in ("memory", "memory_truncated"):
        reason = REASON_LAYOUT
    elif image_base is not None and image_base >= RUNTIME_BASE_64:
        reason = REASON_RUNTIME_BASE
    elif image_base is not None and petype == "PE32" and not is_dll and image_base not in DEFAULT_BASES_32:
        reason = REASON_RELOCATED_EXE
    return {
        "sha256": art.get("sha256"),
        "size": size,
        "n_sections": len(sections),
        "layout": layout,
        "image_base": image_base,
        "pe64": petype == "PE32+",
        "is_dll": is_dll,
        "reason": reason,
    }


def absent(sha256: str) -> dict:
    """The row of a file the index returned no document for."""
    return {
        "sha256": sha256,
        "size": 0,
        "n_sections": 0,
        "layout": "no_record",
        "image_base": None,
        "pe64": False,
        "is_dll": False,
        "reason": REASON_NO_RECORD,
    }


def to_frame(rows: list[dict]) -> pd.DataFrame:
    """`classify` rows as a table; the image base as a nullable integer, never a float."""
    df = pd.DataFrame(rows)
    # From the rows, not the frame: a column holding a None has already become float64 there.
    df["image_base"] = pd.array([r["image_base"] for r in rows], dtype="Int64")
    df["reason"] = pd.Series([r["reason"] for r in rows], dtype="object", index=df.index)
    return df
