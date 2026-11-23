"""Is this PE a memory image? Decided from the file's own bytes.

A memory image is a program written out of a running process, not the file as built. Loading
leaves traces a linker never writes: addresses where import names were, an initialised stack
cookie, a load-time image base, content stored where it was mapped. So does the tool that
wrote the file: a section of its own, a packed program left unpacked. This module reads those
traces from the bytes and nothing else: no parser library, nothing executed.
see specs/12-api-slice-pilot.md § Bytes decide

The label for one file alone follows how the file is presented: a capture that a tool rebuilt
to load again is a file as built. see specs/12-api-slice-pilot.md § What one file can say
"""

from __future__ import annotations

import array
import bisect
import hashlib
import itertools
import json
import math
import re
import struct
import sys
from collections import Counter, defaultdict
from collections.abc import Callable, Iterable, Mapping

#: Bumped whenever a rule here changes, so a verdict can be traced to the rules that gave it.
RULES_VERSION = 13

#: 64-bit Windows 8.1 and later load images at or above this address; no linker's default is near it.
RUNTIME_BASE_64 = 0x7FF0_0000_0000
#: Where user space ends: no module is loaded at or above these, by word size.
USER_CEILING = {False: 0x7FFF_0000, True: 0x7FFF_FFFF_0000}
#: Where Windows 7 puts a relocated 64-bit EXE: just below the two link-time defaults.
WINDOWS7_EXE_RANGES_64 = ((0xFF00_0000, 0x1_0000_0000), (0x1_3F00_0000, 0x1_4000_0000))
#: The linkers' default image bases: 32-bit EXE and DLL, 64-bit EXE and DLL.
DEFAULT_BASES = frozenset({0x40_0000, 0x1000_0000, 0x1_4000_0000, 0x1_8000_0000})
#: The compilers' /GS cookie defaults by word size; old 32-bit builds use the 16-bit one.
COOKIE_DEFAULTS = {False: (0xBB40_E64E, 0x0000_BB40), True: (0x0000_2B99_2DDF_A232,)}
#: Sections only a dump tool adds: where CAPE, Scylla and ImpREC put the import table they rebuild.
DUMP_TOOL_SECTIONS = frozenset({b".CAPE", b".SCY", b".mackt"})
#: The section UPX leaves empty in the file and unpacks the program into.
UNPACKED_INTO = frozenset({b"UPX0"})
#: A base someone gave the linker, as Windows' and Office's own programs have: the loader, which
#: moves an EXE in 64 KiB steps, lands on a multiple of this once in 256.
ROUND_BASE = 1 << 24
#: Byte entropy at or above which a section's content is packed data, not an unpacked program.
PACKED_ENTROPY = 7.5

TELL_IMPORTS = "imports-resolved"
TELL_COOKIE = "cookie-initialized"
TELL_MODULE_DATA = "module-addresses-in-data"
TELL_RELOCATED = "relocations-other-base"
TELL_RUNTIME_BASE = "imagebase-runtime"
TELL_WINDOWS7_BASE = "imagebase-windows7-aslr"
TELL_LAYOUT = "sections-memory-layout"
TELL_CONTENT_LAYOUT = "content-memory-layout"
TELL_WIPED = "section-table-wiped"
TELL_DUMP_TOOL = "dump-tool-section"
TELL_REBUILT = "imports-rebuilt"
TELL_SIZE_IS_ADDRESS = "section-size-is-address"
TELL_ENTRY = "entry-below-image"
TELL_UNSTORED_ENTRY = "entry-not-stored"
TELL_FILLED = "uninitialized-section-filled"
TELL_MOVED_EXE = "exe-moved-unvouched"
TELL_OTHER_BASE = "same-build-other-base"
TELL_OTHER_ADDRESSES = "same-binding-other-addresses"
#: Any one of these makes a file a memory image. The last two need other files of the same build,
#: and `TELL_MOVED_EXE` is a presumption, not a trace: it is there for a screen that must keep
#: memory images out, and an analyzer should report it without deciding on it.
TELLS: tuple[str, ...] = (
    TELL_IMPORTS,
    TELL_COOKIE,
    TELL_MODULE_DATA,
    TELL_RELOCATED,
    TELL_RUNTIME_BASE,
    TELL_WINDOWS7_BASE,
    TELL_LAYOUT,
    TELL_CONTENT_LAYOUT,
    TELL_WIPED,
    TELL_DUMP_TOOL,
    TELL_REBUILT,
    TELL_SIZE_IS_ADDRESS,
    TELL_ENTRY,
    TELL_UNSTORED_ENTRY,
    TELL_FILLED,
    TELL_MOVED_EXE,
    TELL_OTHER_BASE,
    TELL_OTHER_ADDRESSES,
)

BUILT_IMPORTS = "imports-unresolved"
BUILT_COOKIE = "cookie-default"
BUILT_OVERLAY = "overlay"
BUILT_CERTIFICATE = "certificate-in-file"
BUILT_SIGNED = "signature-digest-matches"
BUILT_CHECKSUM = "checksum-valid"
#: The evidence that keeps a file out of the tells that are not traces. It outweighs no trace:
#: a dump tool can recompute a checksum, keep an overlay, and capture untouched imports.
VOUCHES: tuple[str, ...] = (BUILT_CERTIFICATE, BUILT_CHECKSUM)

#: What decides for one file: a capture left as captured is a memory image, a file built or
#: rebuilt to load is a file as built. see specs/12-api-slice-pilot.md § What one file can say
#: LEFT is state a running process leaves and neither a build nor a rebuild has.
LEFT: tuple[str, ...] = (
    TELL_IMPORTS,
    TELL_COOKIE,
    TELL_MODULE_DATA,
    TELL_RELOCATED,
    TELL_CONTENT_LAYOUT,
    TELL_WIPED,
)
#: The form a capture is written in when nothing more is done to it.
FORM: tuple[str, ...] = (TELL_RUNTIME_BASE, TELL_LAYOUT)
#: A tool made the imports loadable again, so the file is presented to run: no memory image.
REBUILT: tuple[str, ...] = (TELL_DUMP_TOOL, TELL_REBUILT)
#: A state loading destroys, a signature over these bytes, or a checksum computed over them.
SIGNS: tuple[str, ...] = (BUILT_IMPORTS, BUILT_COOKIE, BUILT_SIGNED, BUILT_CHECKSUM)

MEMORY_IMAGE = "memory-image"
AS_BUILT = "as-built"
NO_EVIDENCE = "no-evidence"
NOT_PE = "not-pe"
#: What one file alone cannot settle: no evidence either way, or the presumption and nothing else.
UNDECIDED = "undecided"

_MAX_SECTIONS = 96
_MAX_DESCRIPTORS = 1024
_MAX_SLOTS = 5000
_MAX_READS = 131_072
_MAX_NAMES = 64
_MAX_RELOCATIONS = 4096
_MIN_RELOCATIONS = 8
_MAX_COOKIE_PAIRS = 65_536
_MAX_MODULE_ADDRESSES = 65_536
_MIN_FILLED = 64
_MIN_NAMELESS = 4
_MIN_MODULE_ADDRESSES = 5
_MODULE_SPAN = 16 << 20
_MODULE_GAP = 1 << 20
_COOKIE_SCAN = 4 << 20
_ENTROPY_SAMPLE = 1 << 20
_UNINITIALIZED, _HOLDS_CONTENT, _WRITABLE = 0x80, 0x60, 0x8000_0000
_NO_COOKIE = ("none", "config-unreadable", "bad-pointer", "unreadable")
#: The digest algorithms an Authenticode signature names: hashlib name, DER object identifier, length.
_DIGESTS = (
    ("md5", bytes.fromhex("06082a864886f70d0205"), 16),
    ("sha1", bytes.fromhex("06052b0e03021a"), 20),
    ("sha256", bytes.fromhex("0609608648016503040201"), 32),
    ("sha384", bytes.fromhex("0609608648016503040202"), 48),
    ("sha512", bytes.fromhex("0609608648016503040203"), 64),
)
_MAX_DIGESTS = 32
_COUNTED = ("slots", "addr", "same", "zero", "other")
_COUNTED += ("desc", "named", "bad_desc", "addr_desc", "modlike", "bound", "resolved", "rebuilt")
_NAME_BYTES = frozenset(b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-+ ")
_MODULE_SUFFIX = re.compile(
    rb"\.(?:[dD][lL][lL]|[dD][rR][vV]|[oO][cC][xX]|[eE][xX][eE]|[sS][yY][sS]|[cC][pP][lL])\0"
)


def read(data: bytes) -> dict | None:
    """The facts the tells are read from, or None when `data` is not a PE image."""
    size = len(data)
    if size < 0x40 or data[:2] != b"MZ":
        return None
    (nt,) = struct.unpack_from("<I", data, 0x3C)
    if nt + 24 > size or data[nt : nt + 4] != b"PE\0\0":
        return None
    coff = struct.unpack_from("<HHIIIHH", data, nt + 4)
    machine, n_sections, timestamp, opt_size, characteristics = coff[0], coff[1], coff[2], coff[5], coff[6]
    opt = nt + 24
    if opt + 2 > size:
        return None
    (magic,) = struct.unpack_from("<H", data, opt)
    if magic not in (0x10B, 0x20B):
        return None
    is64 = magic == 0x20B
    dirs_at = opt + (112 if is64 else 96)
    if dirs_at > size:
        return None
    size_of_code, entry = struct.unpack_from("<I8xI", data, opt + 4)
    (base,) = struct.unpack_from("<Q", data, opt + 24) if is64 else struct.unpack_from("<I", data, opt + 28)
    section_alignment, file_alignment = struct.unpack_from("<II", data, opt + 32)
    size_of_image, size_of_headers, checksum = struct.unpack_from("<III", data, opt + 56)
    (dll_characteristics,) = struct.unpack_from("<H", data, opt + 70)
    (n_dirs,) = struct.unpack_from("<I", data, dirs_at - 4)
    dirs = [
        struct.unpack_from("<II", data, dirs_at + 8 * i)
        for i in range(min(n_dirs & 0x7FFF_FFFF, 16))
        if dirs_at + 8 * i + 8 <= size
    ]

    def directory(i: int) -> tuple[int, int]:
        return dirs[i] if i < len(dirs) else (0, 0)

    sections, rows_read = [], 0
    raw_end = image_end = 0
    section_table = opt + opt_size
    for i in range(n_sections):
        at = section_table + 40 * i
        if at + 40 > size:
            break
        rows_read += 1
        # An erased row is skipped, not taken for the table's end: the rows after it still count.
        if not any(data[at : at + 40]):
            continue
        name = data[at : at + 8].rstrip(b"\0")
        vsize, va, raw_size, raw_ptr = struct.unpack_from("<IIII", data, at + 8)
        (flags,) = struct.unpack_from("<I", data, at + 36)
        raw_end = max(raw_end, raw_ptr + raw_size if raw_size else 0)
        image_end = max(image_end, va + max(vsize, raw_size))
        # Rows past the cap still say how far the file and the image reach.
        if i < _MAX_SECTIONS:
            sections.append((name, va, vsize, raw_ptr, raw_size, flags))
    sized = [s for s in sections if s[4] > 0]
    # A capture holds each section at its RVA and at its mapped size; a packer's stub that sits
    # at its RVA holds less than it unpacks to.
    at_rva = bool(sized) and all(s[3] == s[1] and s[4] >= s[2] for s in sized)
    mapped = at_rva and file_alignment < section_alignment and n_sections <= _MAX_SECTIONS
    # A capture may store each section at its exact size; the zeros that fill the last page are
    # then part of the image, not data appended to it.
    image_end += -image_end % max(section_alignment, 1)
    padded = mapped and raw_end < size <= image_end and not any(data[raw_end:size])
    # Zeros after the last section are padding. An overlay is data: a payload, a certificate.
    overlay = 0 < raw_end < size and data.count(0, raw_end) < size - raw_end
    wiped = rows_read > 0 and not sections

    ordered = sorted(sections, key=lambda s: s[1])
    starts = [s[1] for s in ordered]
    # The loader reads a section from the 512-byte boundary at or before its pointer.
    sector = 0x200 if file_alignment >= 0x200 else 1

    def by_table(rva: int) -> int | None:
        # The section that starts last at or before the RVA, so a wrong size claims no other's bytes.
        i = bisect.bisect_right(starts, rva) - 1
        if i < 0:
            return rva if rva < size_of_headers else None
        _, va, _, raw_ptr, raw_size, _ = ordered[i]
        return raw_ptr - raw_ptr % sector + rva - va if rva - va < raw_size else None

    def by_rva(rva: int) -> int | None:
        return rva if rva < size else None

    def rva_by_table(at: int) -> int | None:
        for _, va, _, raw_ptr, raw_size, _ in sections:
            if 0 <= at - (raw_ptr - raw_ptr % sector) < raw_size:
                return va + at - (raw_ptr - raw_ptr % sector)
        return at if at < size_of_headers else None

    def section_of(rva: int) -> tuple | None:
        i = bisect.bisect_right(starts, rva) - 1
        return ordered[i] if i >= 0 and rva - ordered[i][1] < max(ordered[i][2], ordered[i][4]) else None

    word = 8 if is64 else 4
    fmt = "<Q" if is64 else "<I"
    mask = (1 << (8 * word)) - 1
    ordinal = 1 << (8 * word - 1)
    ceiling = USER_CEILING[is64]

    def value(at: int | None) -> int | None:
        if at is None or at < 0 or at + word > size:
            return None
        return struct.unpack_from(fmt, data, at)[0]

    def is_address(v: int) -> bool:
        # A loaded module's address: in user space, above this image's own RVAs, outside the image.
        if v & ordinal or not max(size_of_image, 0x10000) <= v < ceiling:
            return False
        return not base <= v < base + size_of_image

    def is_name_or_ordinal(v: int) -> bool:
        # What a slot holds on disk when no lookup table says so: an ordinal, or the RVA of a name.
        return bool(v & ordinal and v & ~ordinal <= 0xFFFF) or v < size_of_image

    def module_like(addresses: list[int]) -> bool:
        # One module's exports and the few modules its forwarders lead to: a handful of 16 MiB regions.
        regions = Counter(v >> 24 for v in addresses)
        return sum(n for _, n in regions.most_common(3)) >= 0.9 * len(addresses)

    def one_module(slots: list[int]) -> bool:
        # Nothing but one module's addresses, each import its own: what the loader leaves in a table.
        return all(map(is_address, slots)) and module_like(slots) and 10 * len(set(slots)) >= 9 * len(slots)

    import_rva = directory(1)[0]

    def imports_under(offset: Callable[[int], int | None], rva_of: Callable[[int], int | None]) -> dict:
        """The import tables, counted slot by slot, when an RVA leads where `offset` says."""
        reads = 0

        def thunks(rva: int) -> list[int] | None:
            nonlocal reads
            if offset(rva) is None:
                return None
            # A table that the end of the file cuts short is read as far as it goes.
            out: list[int] = []
            while len(out) < _MAX_SLOTS and reads <= _MAX_READS:
                reads += 1
                v = value(offset(rva + len(out) * word))
                if not v:
                    return out
                out.append(v)
            return None

        def tables_of(lookup_rva: int, table_rva: int) -> tuple[list[int] | None, list[int] | None]:
            nonlocal reads
            # One table doing both jobs keeps no names to compare with once the loader has written to it.
            lookup = thunks(lookup_rva) if lookup_rva and lookup_rva != table_rva else None
            if not lookup:
                return None, thunks(table_rva)
            # The lookup table sets the slot count, so a blanked address table still shows its slots.
            reads += len(lookup)
            slots = [value(offset(table_rva + k * word)) for k in range(len(lookup))]
            return lookup, None if None in slots else slots

        def import_name(v: int) -> bool:
            # What a lookup table holds: an ordinal, or the RVA of a hint and the name after it.
            if v & ordinal:
                return v & ~ordinal <= 0xFFFF
            at = offset(v)
            if at is None:
                return False
            end = data.find(b"\0", at + 2, at + 258)
            return end > at + 2 and all(0x21 <= c < 0x7F for c in data[at + 2 : end])

        def resolved(stamp: int, lookup: list[int] | None, slots: list[int]) -> int:
            # A table with no stamp whose lookup table still spells the names, and whose slots hold
            # nothing but one module's addresses: the loader wrote it. Counted in addresses.
            addresses = [v for v in slots if v]
            if stamp or not lookup or not addresses or not all(map(is_address, addresses)):
                return 0
            return len(addresses) if module_like(addresses) and all(map(import_name, lookup)) else 0

        def searched() -> int:
            """The addresses in resolved tables that no directory leads to, found by the module
            names they keep: a descriptor holds its module name's RVA in its fourth field."""
            total, seen = 0, set()
            for match in itertools.islice(_MODULE_SUFFIX.finditer(data), _MAX_NAMES):
                start = match.start()
                while start and match.start() - start < 60 and data[start - 1] in _NAME_BYTES:
                    start -= 1
                name_rva = rva_of(start)
                if name_rva is None or start == match.start():
                    continue
                # A linker keeps a table's names and its descriptors in one section.
                home = section_of(name_rva) if rva_of is rva_by_table else None
                lo, hi = (home[3] - home[3] % sector, home[3] + home[4]) if home else (0, size)
                needle = struct.pack("<I", name_rva)
                at = data.find(needle, lo, hi)
                while at != -1 and reads <= _MAX_READS:
                    if at >= 12 and at + 8 <= size and at - 12 not in seen:
                        seen.add(at - 12)
                        lookup_rva, stamp, _, _, table_rva = struct.unpack_from("<5I", data, at - 12)
                        lookup, slots = tables_of(lookup_rva, table_rva) if table_rva else (None, None)
                        total += resolved(stamp, lookup, slots or [])
                    at = data.find(needle, at + 1, hi)
            return total

        def dll_name(rva: int) -> bool:
            at = offset(rva)
            if at is None:
                return False
            end = data.find(b"\0", at, at + 260)
            name = data[at:end] if end > at else b""
            # The loader adds ".dll" to a name without an extension, so a dot is not required.
            return 3 <= len(name) <= 259 and all(c in _NAME_BYTES for c in name)

        found = dict.fromkeys(_COUNTED, 0)
        found["bound_stamps"] = found["bound_slots"] = ""
        found["bound_spans"], found["tables"] = [], []
        tables: list[tuple[list[int], list[int] | None, bool, int, int, int, int]] = []
        walked = 0
        # The directory is walked as the loader walks it, whatever its Size says: up to the first
        # descriptor that names no DLL or has no address table.
        for i in range(_MAX_DESCRIPTORS if import_rva else 0):
            at = offset(import_rva + 20 * i)
            if at is None or at + 20 > size:
                break
            lookup_rva, stamp, chain, name_rva, table_rva = struct.unpack_from("<5I", data, at)
            if not name_rva or not table_rva:
                break
            walked += 1
            lookup, slots = tables_of(lookup_rva, table_rva)
            # A walk that reads more words than any program imports is not reading an import table.
            if slots is None or reads > _MAX_READS:
                found["bad_desc"] += 1
                break
            tables.append((slots, lookup, dll_name(name_rva), stamp, table_rva, chain, lookup_rva))
        # A descriptor that leads to no table is not a descriptor: these bytes are something else,
        # packed data or another file's content, and nothing read from them is counted.
        if found["bad_desc"]:
            return found
        if not walked:
            # No directory leads to a descriptor: a capture can still hold the tables it lost.
            found["resolved"] = searched()
        if not walked and not any(directory(11)):
            # No descriptor is left to read: the address-table directory still says where the slots are.
            table_rva, table_size = directory(12)
            count = min(table_size // word, _MAX_SLOTS) if table_rva else 0
            words = [value(offset(table_rva + k * word)) or 0 for k in range(count)]
            runs = [list(run) for empty, run in itertools.groupby(words, key=lambda v: not v) if not empty]
            if sum(map(len, runs)) >= 2 * _MIN_NAMELESS and all(map(one_module, runs)):
                tables = [(run, None, False, 0, 0, 0, 0) for run in runs]
        # A tool that rebuilds an import table adds a section for it at the end: descriptors and
        # names there, no lookup tables, the address tables left where the program had them.
        home = section_of(import_rva)
        last = next((s for s in reversed(ordered) if s[0] != b".reloc"), None)
        if walked and home is not None and home is last:
            apart = all(t[2] and not t[6] and section_of(t[4]) not in (None, home) for t in tables)
            held = [v for t in tables for v in t[0]]
            names = sum(bool(v & ordinal) or home[1] <= v < home[1] + max(home[2], home[4]) for v in held)
            found["rebuilt"] = int(apart and len(held) >= _MIN_NAMELESS and 10 * names >= 9 * len(held))

        stamps, bound_slots = hashlib.md5(usedforsecurity=False), hashlib.md5(usedforsecurity=False)
        for slots, lookup, named, stamp, table_rva, chain, _ in tables:
            kinds = []
            for k, v in enumerate(slots):
                if v == 0:
                    kinds.append("zero")
                elif v == lookup[k] if lookup is not None else is_name_or_ordinal(v):
                    kinds.append("same")
                else:
                    kinds.append("addr" if is_address(v) else "other")
            addresses = [v for v, kind in zip(slots, kinds, strict=True) if kind == "addr"]
            at = offset(table_rva) if table_rva else None
            if at is not None:
                found["tables"].append((at, at + (len(slots) + 1) * word))
            if named:
                found["resolved"] += resolved(stamp, lookup, slots)
            # A binder writes addresses too, and stamps the descriptor: such a table cannot say who
            # wrote it. Only a 64-bit address from the range the loader alone hands out can.
            if stamp and addresses and not (is64 and max(addresses) >= RUNTIME_BASE_64):
                found["bound"] += 1
                # The older binder's stamp is the DLL's own, so it fixes the addresses that go with it.
                if named and stamp != 0xFFFF_FFFF:
                    stamps.update(struct.pack("<I", stamp))
                    bound_slots.update(struct.pack(f"<{len(addresses)}Q", *addresses))
                    found["bound_stamps"] = stamps.hexdigest()[:16]
                    found["bound_slots"] = bound_slots.hexdigest()[:16]
                # A bound table says where its module is. A binder leaves the forwarder chain empty
                # or at a slot's index: anything else there was never a descriptor.
                if named and (chain == 0xFFFF_FFFF or chain < len(slots)):
                    found["bound_spans"] += _module_span(addresses)
                continue
            # A name erased after loading leaves a table that is nothing but one module's addresses.
            if not named and not (len(slots) >= _MIN_NAMELESS and one_module(slots)):
                continue
            found["desc"] += 1
            found["named"] += named
            found["slots"] += len(slots)
            for kind in kinds:
                found[kind] += 1
            if addresses:
                found["addr_desc"] += 1
                found["modlike"] += module_like(addresses)
        return found

    # A capture can keep its content at RVAs under a section table that still lists file offsets,
    # or under none at all. Then the table misleads, and every RVA is read as a file offset.
    offset, imports, at_rvas = by_table, imports_under(by_table, rva_by_table), ""
    if sections and not mapped:
        if _starts_at_rvas(data, sections):
            at_rvas = "section-starts"
        elif import_rva and not imports["named"] and not imports["bound"]:
            there = imports_under(by_rva, by_rva)
            if there["named"] and there["named"] == there["desc"] and not there["other"]:
                at_rvas = "imports"
    if wiped or at_rvas:
        offset, imports = by_rva, imports_under(by_rva, by_rva)

    cookie = _cookie(data, directory(10), offset, value, is64, base, size_of_image, word, mask)
    if is64 and cookie in _NO_COOKIE:
        writable = [s for s in sections if s[5] & _WRITABLE]
        held = [(s[1], s[1] + max(s[2], s[4])) if at_rvas else (s[3], s[3] + s[4]) for s in writable]
        if _cookie_pair(data, held):
            cookie = "initialized"

    def stored(section: tuple) -> tuple[int, int]:
        # A capture keeps a section at its RVA. So does a file whose table puts the raw data
        # outside the file, when no other section's stored bytes are there.
        _, va, vsize, raw_ptr, raw_size, _ = section
        end = va + max(vsize, raw_size)
        if at_rvas:
            return va, end
        if raw_ptr + raw_size <= size:
            return raw_ptr, raw_ptr + raw_size
        taken = any(o is not section and o[4] and o[3] < end and va < o[3] + o[4] for o in sections)
        return (0, 0) if taken else (va, end)

    def unstored(rva: int) -> bool:
        # In a section's memory, and past every byte the table stores for it.
        homes = [s for s in sections if s[1] <= rva < s[1] + max(s[2], s[4])]
        return bool(homes) and all(rva - s[1] >= s[4] for s in homes)

    # A TLS callback or managed code starts a program too, and below page alignment the loader
    # maps the file in one piece. Only a table that fits the file says what the file holds.
    whole = rows_read == n_sections <= _MAX_SECTIONS and raw_end <= size
    starts_elsewhere = any(rva and by_table(rva) is not None for rva in (directory(9)[0], directory(14)[0]))
    judged = whole and section_alignment >= 0x1000 and not at_rvas and not starts_elsewhere

    tables = imports.pop("tables")
    writable_data = [stored(s) for s in sections if s[5] & _WRITABLE and s[4]]
    module_addresses = _module_addresses(data, writable_data, imports["bound_spans"], tables, word)
    extent = max(size_of_image, image_end, 1)

    cert_at, cert_size = directory(4)
    certificate = _certificate(data, cert_at, cert_size)
    stored_at = sorted((s[3], s[4]) for s in sections if s[4])
    signed = (cert_at, cert_size, opt + 64, dirs_at + 32, size_of_headers, stored_at)
    sizes_are_addresses = all(s[2] == (base + s[1]) & 0xFFFF_FFFF for s in sections)
    key = [machine, timestamp, entry, size_of_image, size_of_code]
    key += [(s[0].hex(), s[1], s[2], s[5]) for s in sections]
    return {
        "is64": is64,
        "is_dll": bool(characteristics & 0x2000),
        "base": base,
        "size": size,
        "size_of_image": size_of_image,
        "file_alignment": file_alignment,
        "section_alignment": section_alignment,
        "n_sections": len(sections),
        "raw_end": size if padded else raw_end,
        "mapped_layout": mapped,
        "content_at_rvas": at_rvas,
        "sections_wiped": wiped,
        "dump_tool_section": next((s[0].decode() for s in sections if s[0] in DUMP_TOOL_SECTIONS), ""),
        # One dump tool writes each section's address where its size belongs; such a file cannot load.
        "sizes_are_addresses": bool(sections and base) and sizes_are_addresses,
        # A tool that lost where the program starts writes an address below the base: the RVA wraps.
        "entry_below_image": not is64 and bool(base) and base + entry > 0xFFFF_FFFF,
        # A tool that rebuilt the table around the bytes it had: the program cannot start from them.
        "entry_unstored": bool(entry) and judged and unstored(entry),
        "dynamic_base": bool(dll_characteristics & 0x40),
        "relocatable": not characteristics & 1 and bool(directory(5)[0]),
        "filled_section": _filled(data, sections, entry),
        "imports": imports,
        "cookie": cookie,
        "module_addresses": module_addresses,
        "relocations": _relocations(data, directory(5), offset, is64, base, extent),
        "overlay": overlay,
        "certificate_in_file": certificate,
        # The digest a signature carries covers the file as it was signed: a capture cannot keep it.
        "signature": _signature(data, *signed) if certificate else "",
        "checksum_valid": bool(checksum) and _checksum(data, opt + 64) == checksum,
        "build": hashlib.md5(json.dumps(key).encode(), usedforsecurity=False).hexdigest()[:16],
    }


def _starts_at_rvas(data: bytes, sections: list[tuple]) -> bool:
    """Whether the sections' content begins at their RVAs and not where the section table says.

    A section begins where bytes follow a run of zeros. A capture written page for page has
    those places at the RVAs, whatever offsets the header it copied from the file still lists.
    """
    sized = [s for s in sections if s[4] > 0]
    rvas, raws = {s[1] for s in sections}, {s[3] for s in sized}
    judged = at_rva = at_raw = 0
    for _, va, _, raw_ptr, _, _ in sized:
        if va == raw_ptr or min(va, raw_ptr) < 64 or va + 16 > len(data):
            continue
        judged += 1
        # An offset that is one section's RVA and another's file offset says nothing either way.
        if va not in raws:
            at_rva += not any(data[va - 32 : va]) and any(data[va : va + 16])
        if raw_ptr not in rvas:
            at_raw += not any(data[raw_ptr - 32 : raw_ptr]) and any(data[raw_ptr : raw_ptr + 16])
    return at_rva >= 2 and 5 * at_rva >= 3 * judged and 3 * at_raw <= judged


def _filled(data: bytes, sections: list[tuple], entry: int) -> str:
    """The first section that is empty in a file as built and holds an unpacked program, or "".

    That is a section declared uninitialised data, or the one UPX unpacks into when the program
    starts there: a tool that writes the unpacked program out may change the section's flags.
    """
    for i, (name, va, vsize, raw_ptr, raw_size, flags) in enumerate(sections):
        declared = flags & _UNINITIALIZED and not flags & _HOLDS_CONTENT
        started_in = name in UNPACKED_INTO and va <= entry < va + max(vsize, raw_size)
        if not (declared or started_in) or not raw_size:
            continue
        end = min(raw_ptr + raw_size, len(data))
        # Bytes that another section also claims are that section's content, not this one's.
        if any(j != i and s[4] and s[3] < end and raw_ptr < s[3] + s[4] for j, s in enumerate(sections)):
            continue
        content = data[raw_ptr:end]
        if len(content) - content.count(0) < _MIN_FILLED:
            continue
        # A packer may flag its packed data this way; that is how the file was built.
        counts = Counter(content.lstrip(b"\0")[:_ENTROPY_SAMPLE])
        total = sum(counts.values())
        if -sum(n / total * math.log2(n / total) for n in counts.values()) < PACKED_ENTROPY:
            return name.decode("latin-1")
    return ""


def _cookie(data, load_config, offset, value, is64, base, size_of_image, word, mask) -> str:
    """The state of the /GS security cookie, reached through the load configuration."""
    rva, dir_size = load_config
    if not rva:
        return "none"
    at = offset(rva)
    if at is None or at + 4 > len(data):
        return "config-unreadable"
    (own,) = struct.unpack_from("<I", data, at)
    field = 88 if is64 else 60
    if max(own if own <= 0x1000 else 0, dir_size if dir_size <= 0x1000 else 0) < field + word:
        return "none"
    pointer = value(at + field)
    if pointer is None:
        return "config-unreadable"
    if pointer == 0:
        return "none"
    if not 0 <= pointer - base < size_of_image:
        return "bad-pointer"
    here = offset(pointer - base)
    cookie = value(here)
    if cookie is None:
        return "unreadable"
    if cookie in COOKIE_DEFAULTS[is64]:
        return "default"
    if cookie in (0, mask):
        return "blank"
    near = {value(here + k * word) for k in range(-8, 9) if k}
    # The C runtime stores the cookie's complement beside it: proof the value is a cookie, not packed data.
    if ~cookie & mask in near:
        return "initialized"
    if any(~default & mask in near for default in COOKIE_DEFAULTS[is64]):
        return "loader-initialized"
    return "other"


def _cookie_pair(data: bytes, held: list[tuple[int, int]]) -> bool:
    """Whether writable data holds a 64-bit /GS cookie that the C runtime has initialised.

    The runtime keeps the cookie beside its complement, and a 64-bit cookie has its top 16 bits
    clear. A pair like that whose value is not the compiler's default, and whose bits alternate
    as a random number's do, is a cookie set at start-up, found here without a load configuration.
    """
    ones = bytes([0xFF]) * 8
    for start, end in held:
        end = min(end, start + _COOKIE_SCAN, len(data))
        count = (end - start) // 8
        if count < 2:
            continue
        words = int.from_bytes(data[start : start + 8 * count], "little")
        # Word k of this is word k xor word k+1 of the data: all ones where a value meets its complement.
        folded = (words ^ (words >> 64)).to_bytes(8 * count, "little")
        at, tried = folded.find(ones), 0
        while at != -1 and tried < _MAX_COOKIE_PAIRS:
            # Only a whole word counts: a match across two words is looked for again at the next one.
            if at % 8:
                at = folded.find(ones, at + 8 - at % 8)
                continue
            tried += 1
            if at + 16 <= 8 * count:
                v = min(struct.unpack_from("<QQ", data, start + at))
                flips = bin((v ^ (v >> 1)) & ((1 << 47) - 1)).count("1")
                if v >> 48 == 0 and v not in COOKIE_DEFAULTS[True] and flips >= 12:
                    return True
            at = folded.find(ones, at + 8)
    return False


def _module_span(addresses: list[int]) -> list[tuple[int, int]]:
    """Where the module a bound table points at is: its longest run of addresses that sit together.

    A slot far from the rest points into another module, a forwarder's or a hook's. The run has
    to hold most of the table: addresses scattered all over are not one module's.
    """
    ordered = sorted(set(addresses))
    cuts = [i for i in range(1, len(ordered)) if ordered[i] - ordered[i - 1] >= _MODULE_GAP]
    a, b = max(itertools.pairwise([0, *cuts, len(ordered)]), key=lambda run: run[1] - run[0])
    if b - a < _MIN_NAMELESS or 4 * (b - a) < 3 * len(ordered):
        return []
    lo, hi = ordered[a], ordered[b - 1] + 1
    return [(lo, hi)] if hi - lo <= _MODULE_SPAN else []


def _spells_text(data: bytes, at: int, word: int) -> bool:
    """Whether the word at `at` is text and no address: an address range can spell letters.

    Text is a word of printable characters, or one that holds a line break or a string's end
    and has such a word beside it.
    """

    def printable(chunk: bytes) -> bool:
        return len(chunk) == word and all(0x20 <= c < 0x7F for c in chunk)

    here = data[at : at + word]
    if printable(here):
        return True
    if not all(0x20 <= c < 0x7F or c in b"\0\t\n\r" for c in here):
        return False
    return printable(data[max(at - word, 0) : at]) or printable(data[at + word : at + 2 * word])


def _module_addresses(data: bytes, ranges: list, spans: list, tables: list, word: int) -> dict:
    """Addresses inside the modules a bound import table points at, found in writable data.

    A binder writes a module's addresses into the import address table and nowhere else, so
    one found elsewhere, in data the program can write, was put there by the program running.
    Words that read as text are passed over. `chance` is how many a section of random words
    would hold.
    """
    found: set[int] = set()
    # Two tables that point into one module give it one span, so its width counts once.
    spans, tables = _merged(spans), _merged(tables)
    span_starts, table_starts = [lo for lo, _ in spans], [a for a, _ in tables]
    low, high = (spans[0][0], spans[-1][1]) if spans else (0, 0)
    held = []
    for start, end in ranges if spans else ():
        held.append((start, max(0, min(end, start + _COOKIE_SCAN, len(data)) - start) // word))
    for start, count in held:
        for k, v in enumerate(_words("Q" if word == 8 else "I", data[start : start + count * word])):
            if not low <= v < high or v in found or v >= spans[bisect.bisect_right(span_starts, v) - 1][1]:
                continue
            at = start + k * word
            table = bisect.bisect_right(table_starts, at) - 1
            if table >= 0 and at < tables[table][1]:
                continue
            if _spells_text(data, at, word):
                continue
            found.add(v)
            # More than this is not counted. A file with so much writable data that chance alone
            # gives a sixteenth of it is not judged by this tell.
            if len(found) == _MAX_MODULE_ADDRESSES:
                break
        if len(found) == _MAX_MODULE_ADDRESSES:
            break
    width = sum(hi - lo for lo, hi in spans)
    words = sum(count for _, count in held)
    return {"found": len(found), "chance": round(words * width / (1 << (8 * word)), 4)}


def _merged(intervals: Iterable) -> list[tuple[int, int]]:
    """The intervals in order, with those that touch or overlap made one."""
    merged: list[tuple[int, int]] = []
    for lo, hi in sorted(map(tuple, intervals)):
        if merged and lo <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], hi))
        else:
            merged.append((lo, hi))
    return merged


def _words(code: str, data: bytes) -> array.array:
    """The file's little-endian words, whatever the byte order of the machine that reads them."""
    words = array.array(code, data)
    if sys.byteorder == "big":
        words.byteswap()
    return words


def _relocations(data: bytes, directory: tuple[int, int], offset, is64: bool, base: int, extent: int) -> dict:
    """Where the relocation table's targets point: into the image at the header's base, or elsewhere.

    A linker writes each target for the base it puts in the header. `elsewhere` is the most
    targets that fit the image at one other base. An image is loaded on a 64 KiB boundary and
    nothing else can lie before the next one after its end, so that is what a base and a fit
    are here. A value below the image's size is an RVA or nothing, not an address.
    """
    rva, length = directory
    at = offset(rva) if rva else None
    end = min(at + length, len(data)) if at is not None else 0
    targets: list[int] = []
    seen = 0
    while at is not None and at + 8 <= end and seen < _MAX_RELOCATIONS:
        page, block = struct.unpack_from("<II", data, at)
        if block < 8 or at + block > end:
            break
        entries = struct.iter_unpack("<H", data[at + 8 : at + block - block % 2])
        for (entry,) in itertools.islice(entries, _MAX_RELOCATIONS - seen):
            seen += 1
            width = 4 if entry >> 12 == 3 else 8 if entry >> 12 == 10 and is64 else 0
            site = offset(page + (entry & 0xFFF)) if width else None
            if site is not None and site + width <= len(data):
                targets.append(int.from_bytes(data[site : site + width], "little"))
        at += block
    extent += -extent % 0x1_0000
    inside = sum(base <= t < base + extent for t in targets)
    apart = sorted(t for t in targets if t >= extent and not base <= t < base + extent)
    elsewhere = 0
    for first, t in enumerate(apart):
        # Each target's own 64 KiB boundary is tried as the base, once.
        if first and apart[first - 1] >> 16 == t >> 16:
            continue
        elsewhere = max(elsewhere, bisect.bisect_left(apart, (t >> 16 << 16) + extent) - first)
    return {"read": len(targets), "in_image": inside, "elsewhere": elsewhere}


def _certificate(data: bytes, at: int, length: int) -> bool:
    """Whether the security directory points at a WIN_CERTIFICATE that lies inside the file."""
    if not at or length < 8 or at + length > len(data):
        return False
    own, revision, kind = struct.unpack_from("<IHH", data, at)
    # A dump can be long enough to cover the old offset; only a real entry header counts.
    return 8 <= own <= length and revision in (0x0100, 0x0200) and 1 <= kind <= 4


def _signature(
    data: bytes, at: int, length: int, checksum_at: int, entry_at: int, headers: int, stored: list
) -> str:
    """Whether a digest the certificate table carries is the Authenticode hash of this file:
    "matches", "differs", or "unreadable" when the table names no digest."""
    blob = data[at : at + length]
    named = []
    for name, oid, size in _DIGESTS:
        found = blob.find(oid)
        while found >= 0 and len(named) < _MAX_DIGESTS:
            # An algorithm identifier, with or without its NULL, and the octet string after it.
            end = found + len(oid)
            end += 2 * (blob[end : end + 2] == b"\x05\x00")
            if blob[end : end + 2] == bytes((4, size)) and end + 2 + size <= len(blob):
                named.append((name, blob[end + 2 : end + 2 + size]))
            found = blob.find(oid, found + 1)
    if not named or entry_at + 8 > min(at, len(data)):
        return "unreadable"
    view = memoryview(data)
    # Left out of the hash: the checksum, the security directory entry and the certificate table.
    # Verifiers walk the file end to end or section by section; either reading may be the signer's.
    head = [(0, checksum_at), (checksum_at + 4, entry_at)]
    whole = [*head, (entry_at + 8, at), (at + length, len(data))]
    by_section = [*head, (entry_at + 8, headers), *((raw, raw + size) for raw, size in stored)]
    by_section.append((headers + sum(size for _, size in stored), len(data) - length))
    hashes: dict[str, set[bytes]] = {}
    for name in {name for name, _ in named}:
        hashes[name] = set()
        for pieces in (whole, by_section):
            digest = hashlib.new(name, usedforsecurity=False)
            for start, stop in pieces:
                digest.update(view[start : max(start, min(stop, len(data)))])
            hashes[name].add(digest.digest())
    return "matches" if any(value in hashes[name] for name, value in named) else "differs"


def _checksum(data: bytes, field_at: int) -> int:
    """The PE checksum of the file as ImageHlp computes it, with the stored value left out."""
    total = sum(_words("H", data if len(data) % 2 == 0 else data + b"\0"))
    # ImageHlp adds with end-around carry, so a sum that is a multiple of 0xFFFF stays 0xFFFF.
    partial = total % 0xFFFF or (0xFFFF if total else 0)
    for stored in struct.unpack_from("<HH", data, field_at):
        partial = (partial - (partial < stored) - stored) & 0xFFFF
    return partial + len(data)


def tells(facts: Mapping) -> list[str]:
    """The decisive tells one file shows by itself; the two that compare files need `verdicts`."""
    imports = facts["imports"]
    found = []
    mostly_addresses = imports["slots"] and 2 * imports["addr"] > imports["slots"]
    mostly_addresses = mostly_addresses and imports["modlike"] >= 0.8 * imports["addr_desc"]
    # Most slots hold addresses, or some tables are resolved beyond doubt whatever the rest hold.
    if mostly_addresses or imports["resolved"] >= _MIN_NAMELESS:
        found.append(TELL_IMPORTS)
    if facts["cookie"] in ("initialized", "loader-initialized"):
        found.append(TELL_COOKIE)
    # Addresses of an imported module in writable data, far more than chance puts there.
    module = facts["module_addresses"]
    if module["found"] >= _MIN_MODULE_ADDRESSES and module["found"] >= 16 * module["chance"]:
        found.append(TELL_MODULE_DATA)
    # A linker writes every relocation target for the header's base. Targets that sit together
    # somewhere else were rewritten for a load there, under a header that kept its base.
    targets = facts["relocations"]
    apart = 5 * targets["in_image"] < targets["read"] and 5 * targets["elsewhere"] >= 4 * targets["read"]
    if apart and targets["read"] >= _MIN_RELOCATIONS and facts["base"] and facts["base"] % 0x1_0000 == 0:
        found.append(TELL_RELOCATED)
    # The loader only writes an address it can map at: a multiple of 64 KiB inside user space.
    loader_wrote = 0 < facts["base"] < USER_CEILING[facts["is64"]] and facts["base"] % 0x1_0000 == 0
    if facts["is64"] and loader_wrote and facts["base"] >= RUNTIME_BASE_64:
        found.append(TELL_RUNTIME_BASE)
    in_windows7_range = any(lo < facts["base"] < hi for lo, hi in WINDOWS7_EXE_RANGES_64)
    if facts["is64"] and not facts["is_dll"] and loader_wrote and in_windows7_range:
        found.append(TELL_WINDOWS7_BASE)
    # A mapped layout is how a capture is written, and how some packers and stubs are built. It
    # counts only when the file holds no data outside its sections. A valid checksum does not
    # clear it: dump tools recompute the checksum.
    if facts["mapped_layout"] and not facts["overlay"]:
        found.append(TELL_LAYOUT)
    # Content at its RVAs under a table of file offsets, or no table at all: the loader could not
    # map this file as the program, so nothing built it this way.
    if facts["content_at_rvas"]:
        found.append(TELL_CONTENT_LAYOUT)
    if facts["sections_wiped"]:
        found.append(TELL_WIPED)
    # The tool that wrote the file shows too: it added a section for the import table it rebuilt,
    # or it left a packed program unpacked in a section that holds nothing in a file as built.
    if facts["dump_tool_section"]:
        found.append(TELL_DUMP_TOOL)
    if imports["rebuilt"]:
        found.append(TELL_REBUILT)
    if facts["sizes_are_addresses"]:
        found.append(TELL_SIZE_IS_ADDRESS)
    if facts["entry_below_image"]:
        found.append(TELL_ENTRY)
    if facts["entry_unstored"]:
        found.append(TELL_UNSTORED_ENTRY)
    if facts["filled_section"]:
        found.append(TELL_FILLED)
    # A 32-bit EXE whose header asks the loader to choose its address, at an address the loader
    # may have chosen: nine in ten show another tell, so one that nothing vouches for is presumed loaded.
    vouched = facts["certificate_in_file"] or facts["checksum_valid"]
    asked = loader_wrote and facts["dynamic_base"] and facts["relocatable"]
    if _maybe_moved(facts) and asked and not vouched:
        found.append(TELL_MOVED_EXE)
    return found


def _maybe_moved(facts: Mapping) -> bool:
    """Whether a 32-bit EXE sits where the loader may have put it: not at the linker's default, and
    not at a round base someone gave the linker."""
    off_default = not facts["is64"] and not facts["is_dll"] and facts["base"] != 0x40_0000
    return off_default and facts["base"] % ROUND_BASE != 0


def as_built(facts: Mapping) -> list[str]:
    """Positive evidence that the bytes are as the linker left them. It never outweighs a tell."""
    imports = facts["imports"]
    found = []
    # An image captured before the loader ran still has untouched imports and cookie, and a
    # 32-bit EXE away from its link-time base may be one, so there these two say nothing.
    moved = _maybe_moved(facts)
    if imports["slots"] and imports["same"] == imports["slots"] and not moved:
        found.append(BUILT_IMPORTS)
    if facts["cookie"] == "default" and not moved:
        found.append(BUILT_COOKIE)
    if facts["overlay"] and not facts["content_at_rvas"]:
        found.append(BUILT_OVERLAY)
    if facts["certificate_in_file"]:
        found.append(BUILT_CERTIFICATE)
    if facts.get("signature") == "matches":
        found.append(BUILT_SIGNED)
    if facts["checksum_valid"]:
        found.append(BUILT_CHECKSUM)
    return found


def _startable(facts: Mapping, built: list[str]) -> bool:
    """Whether nothing read here keeps the loader from starting the file: every import slot names
    what it imports, the file holds every byte its section table lists, and no other base holds
    a quarter as many relocation targets as the header's does."""
    targets = facts["relocations"]
    fits = targets["in_image"] + targets["elsewhere"] < 8 or 4 * targets["elsewhere"] <= targets["in_image"]
    return BUILT_IMPORTS in built and facts["raw_end"] <= facts["size"] and fits


def single_file(facts: Mapping | None) -> dict:
    """What one file says by itself: memory image, as built, or undecided, and what decided it.

    A file presented to be executed is a file as built, a rebuilt capture included. A capture
    left as captured is a memory image: it shows state a running process left, or the form a
    capture is written in, and no rebuilt import table, valid checksum or signature over its
    bytes. A sign makes
    a file as built when no other tell stands against it and the file is no capture, or is one
    a tool rebuilt, that shows nothing a process left and that the loader could start. Every
    other file is undecided, as is one not read as a PE: an overlay or a certificate whose digest
    is not the file's does not decide, and unpacked content alone does not either. The tells
    that compare files are not here.
    """
    if facts is None:
        return {"verdict": UNDECIDED, "decided_by": [], "tells": [], "as_built": []}
    found, built = tells(facts), as_built(facts)
    left = [tell for tell in found if tell in LEFT]
    as_captured = [tell for tell in found if tell in LEFT or tell in FORM]
    rebuilt = [tell for tell in found if tell in REBUILT]
    signs = [sign for sign in built if sign in SIGNS]
    # The presumption and the tells that are no mark of either kind keep a sign from deciding.
    clear = not left and all(tell in (*FORM, *REBUILT, TELL_FILLED) for tell in found)
    capture = bool(as_captured) or TELL_FILLED in found
    # A checksum or a signature over these bytes was made after the capture: somebody finished the file.
    finished = BUILT_CHECKSUM in built or BUILT_SIGNED in built
    if as_captured and not rebuilt and not finished:
        verdict, decided_by = MEMORY_IMAGE, as_captured
    elif signs and clear and (_startable(facts, built) if rebuilt else not capture):
        verdict, decided_by = AS_BUILT, rebuilt + signs
    else:
        verdict, decided_by = UNDECIDED, []
    return {"verdict": verdict, "decided_by": decided_by, "tells": found, "as_built": built}


def verdicts(files: Iterable[tuple[str, Mapping | None]]) -> list[dict]:
    """One row per (sha256, facts): verdict, tells and as-built evidence.

    The tells no file shows alone are applied here. A build present at two or more image bases
    that no linker defaults to was relocated at load. A build whose bound import tables carry
    the same DLL stamps and different addresses had them written at load: a binder gives one
    DLL one set of addresses. Both pass over a file a certificate or a valid checksum vouches
    for, so the copy that really was built that way keeps its place.
    """
    files = list(files)
    bases: dict[str, set[int]] = defaultdict(set)
    bindings: dict[tuple[str, str], set[str]] = defaultdict(set)
    for _, facts in files:
        if facts is None:
            continue
        if facts["base"] not in DEFAULT_BASES:
            bases[facts["build"]].add(facts["base"])
        if facts["imports"]["bound_stamps"]:
            bindings[facts["build"], facts["imports"]["bound_stamps"]].add(facts["imports"]["bound_slots"])
    rows = []
    for sha256, facts in files:
        if facts is None:
            rows.append({"sha256": sha256, "verdict": NOT_PE, "tells": "", "as_built": ""})
            continue
        found, built = tells(facts), as_built(facts)
        vouched = any(b in VOUCHES for b in built)
        if not vouched and facts["base"] not in DEFAULT_BASES and len(bases[facts["build"]]) >= 2:
            found.append(TELL_OTHER_BASE)
        binding = facts["build"], facts["imports"]["bound_stamps"]
        if not vouched and binding[1] and len(bindings[binding]) >= 2:
            found.append(TELL_OTHER_ADDRESSES)
        verdict = MEMORY_IMAGE if found else (AS_BUILT if built else NO_EVIDENCE)
        row = {"sha256": sha256, "verdict": verdict, "tells": ",".join(found), "as_built": ",".join(built)}
        rows.append(row)
    return rows
