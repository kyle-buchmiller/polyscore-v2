"""The byte-level memory-image rule, on PE files built here: no sample file is needed or kept.

see specs/12-api-slice-pilot.md § Bytes decide
"""

from __future__ import annotations

import hashlib
import struct

from polyscore_v2 import image_bytes as ib

KERNEL32 = 0x7634_0000  # where a 32-bit process maps a system DLL
KERNEL64 = 0x7FFB_1234_0000
BOUND64 = 0x7_0000_0000  # an address a binder could have written into a 64-bit table
PAGE = 0x1000
SECTIONS = 0x80 + 24 + 224  # the section table of a 32-bit file from `build`
RESOLVED = [KERNEL32 + 0x1234, KERNEL32 + 0x5678]


def build(
    *,
    is64: bool = False,
    dll: bool = False,
    base: int | None = None,
    mapped: bool = False,
    slots: list[int] | None = None,
    lookup: bool = True,
    imported: int = 2,
    stamp: int = 0,
    chain: int = 0,
    import_size: int = 0x28,
    cookie: tuple[int, int] | None = None,
    tail: bytes = b"",
    checksum: bool = False,
    timestamp: int = 0x5F00_0000,
    text_name: bytes = b".text",
    text_flags: int = 0x6000_0020,
    text: bytes | None = None,
    data_name: bytes = b".data",
    data_flags: int = 0x6000_0020,
    size_is_address: bool = False,
    aslr: bool = False,
    entry: int | None = None,
) -> bytes:
    """A two-section PE: `.text`, and `.data` holding an import table and a load configuration.

    `slots` are the import address table's values; None leaves them equal to the lookup table.
    Without a lookup table there may be up to seven of them. `imported` is how many imports the
    lookup table lists, up to seven in a 32-bit image; the two names repeat. `stamp` and `chain`
    are the descriptor's TimeDateStamp and ForwarderChain.
    `cookie` is (value, the word stored after it). `mapped` stores sections at their RVAs.
    `text` is the first section's content, one raw section long; by default it is filled with int3.
    `aslr` sets DYNAMIC_BASE and a relocation directory: the header asks for a load-time address.
    """
    word = 8 if is64 else 4
    fmt = "<Q" if is64 else "<I"
    if base is None:
        base = (0x1_8000_0000 if dll else 0x1_4000_0000) if is64 else (0x1000_0000 if dll else 0x40_0000)
    text_rva, data_rva = PAGE, 2 * PAGE
    text_at, data_at = (text_rva, data_rva) if mapped else (0x400, 0x600)
    raw = PAGE if mapped else 0x200
    image_size = 3 * PAGE

    data = bytearray(raw)
    names = [0x100, 0x110]  # hint/name RVAs, relative to the section
    for at, name in zip(names, (b"\0\0CreateFileA\0", b"\0\0ExitProcess\0"), strict=True):
        data[at : at + len(name)] = name
    data[0x130:0x13D] = b"KERNEL32.dll\0"
    lookup_at, table_at, config_at, cookie_at = 0x40, 0x60, 0x80, 0x1C0
    entries = [data_rva + names[k % 2] for k in range(imported)]
    for k, v in enumerate(entries):
        if lookup:
            struct.pack_into(fmt, data, lookup_at + k * word, v)
    for k, v in enumerate(entries if slots is None else slots):
        struct.pack_into(fmt, data, table_at + k * word, v)
    lookup_rva = data_rva + lookup_at if lookup else 0
    struct.pack_into("<5I", data, 0, lookup_rva, stamp, chain, data_rva + 0x130, data_rva + table_at)
    config_size = 0x70 if is64 else 0x48
    if cookie is not None:
        struct.pack_into("<I", data, config_at, config_size)
        struct.pack_into(fmt, data, config_at + (88 if is64 else 60), base + data_rva + cookie_at)
        struct.pack_into(fmt, data, cookie_at, cookie[0])
        struct.pack_into(fmt, data, cookie_at + word, cookie[1])

    optional = bytearray(240 if is64 else 224)
    struct.pack_into("<H", optional, 0, 0x20B if is64 else 0x10B)
    struct.pack_into("<I", optional, 4, raw)  # SizeOfCode
    struct.pack_into("<I", optional, 16, text_rva if entry is None else entry)  # AddressOfEntryPoint
    if is64:
        struct.pack_into("<Q", optional, 24, base)
    else:
        struct.pack_into("<I", optional, 28, base)
    struct.pack_into("<II", optional, 32, PAGE, 0x200)  # SectionAlignment, FileAlignment
    struct.pack_into("<II", optional, 56, image_size, text_at)  # SizeOfImage, SizeOfHeaders
    dirs = 112 if is64 else 96
    struct.pack_into("<I", optional, dirs - 4, 16)
    struct.pack_into("<II", optional, dirs + 8, data_rva, import_size)
    if aslr:
        struct.pack_into("<H", optional, 70, 0x40)
        struct.pack_into("<II", optional, dirs + 40, data_rva + 0x1E0, 8)
    if cookie is not None:
        struct.pack_into("<II", optional, dirs + 80, data_rva + config_at, config_size)

    header = bytearray(0x80)
    header[:2] = b"MZ"
    struct.pack_into("<I", header, 0x3C, 0x80)
    flags = 0x2102 if dll else 0x0102
    coff = struct.pack("<HHIIIHH", 0x8664 if is64 else 0x14C, 2, timestamp, 0, 0, len(optional), flags)

    def vsize(rva: int) -> int:
        return base + rva if size_is_address else PAGE

    sections = b"".join(
        struct.pack("<8sIIIIIIHHI", name, vsize(rva), rva, raw, at, 0, 0, 0, 0, section_flags)
        for name, rva, at, section_flags in (
            (text_name, text_rva, text_at, text_flags),
            (data_name, data_rva, data_at, data_flags),
        )
    )
    out = bytearray(header + b"PE\0\0" + coff + optional + sections)
    out += bytes(text_at - len(out))
    out += b"\xcc" * raw if text is None else text.ljust(raw, b"\0")
    out += bytes(data_at - len(out))
    out += data + tail
    if checksum:
        at = 0x80 + 24 + 64
        struct.pack_into("<I", out, at, ib._checksum(bytes(out), at))
    return bytes(out)


def judge(data: bytes) -> tuple[str, list[str], list[str]]:
    (row,) = ib.verdicts([("f", ib.read(data))])
    tells, built = ([t for t in row[k].split(",") if t] for k in ("tells", "as_built"))
    return row["verdict"], tells, built


def test_a_file_as_built_shows_unresolved_imports():
    assert judge(build()) == (ib.AS_BUILT, [], [ib.BUILT_IMPORTS])


def test_addresses_in_the_import_table_mean_a_memory_image():
    verdict, tells, _ = judge(build(slots=[KERNEL32 + 0x1234, KERNEL32 + 0x5678]))
    assert (verdict, tells) == (ib.MEMORY_IMAGE, [ib.TELL_IMPORTS])
    verdict, tells, _ = judge(build(is64=True, slots=[KERNEL64 + 0x1234, KERNEL64 + 0x5678]))
    assert (verdict, tells) == (ib.MEMORY_IMAGE, [ib.TELL_IMPORTS])


def test_a_blanked_address_table_is_not_resolved():
    # The loader skips a descriptor whose first slot is zero, so such a table is a decoy, not a trace.
    assert judge(build(slots=[0, 0])) == (ib.NO_EVIDENCE, [], [])


def test_a_table_rebuilt_with_other_name_rvas_is_not_resolved():
    assert judge(build(slots=[0x2150, 0x2158])) == (ib.NO_EVIDENCE, [], [])


def test_without_a_lookup_table_the_slot_itself_is_read():
    assert judge(build(lookup=False)) == (ib.AS_BUILT, [], [ib.BUILT_IMPORTS])
    assert judge(build(lookup=False, slots=[KERNEL32 + 0x10, KERNEL32 + 0x20]))[1] == [ib.TELL_IMPORTS]


def test_bound_imports_say_nothing():
    bound = build(stamp=0x4CE7_9D93, slots=[KERNEL32 + 0x10, KERNEL32 + 0x20])
    assert judge(bound) == (ib.NO_EVIDENCE, [], [])
    assert judge(build(is64=True, stamp=0xFFFF_FFFF, slots=[BOUND64 + 0x10, BOUND64 + 0x20]))[1] == []


def test_a_stamp_does_not_hide_addresses_only_the_loader_hands_out():
    stamped = build(is64=True, stamp=0x48C8_5F51, slots=[KERNEL64 + 0x10, KERNEL64 + 0x20])
    assert judge(stamped)[:2] == (ib.MEMORY_IMAGE, [ib.TELL_IMPORTS])
    # A stamped descriptor whose slots still hold names is not bound: the table is as built.
    assert judge(build(stamp=0x92EA_E861)) == (ib.AS_BUILT, [], [ib.BUILT_IMPORTS])


def test_one_table_doing_both_jobs_is_read_by_what_it_holds():
    def shared(slots: list[int] | None) -> bytes:
        data = bytearray(build(slots=slots, lookup=False))
        struct.pack_into("<I", data, 0x600, 0x2000 + 0x60)  # OriginalFirstThunk = FirstThunk
        return bytes(data)

    assert judge(shared(RESOLVED))[1] == [ib.TELL_IMPORTS]
    assert judge(shared(None)) == (ib.AS_BUILT, [], [ib.BUILT_IMPORTS])


def test_a_dll_name_needs_no_extension():
    data = bytearray(build(slots=RESOLVED))
    data[0x600 + 0x130 : 0x600 + 0x13D] = b"KERNEL32\0\0\0\0\0"
    assert judge(bytes(data))[1] == [ib.TELL_IMPORTS]


def four_addresses(data: bytearray, at: int = 0x600 + 0x60) -> bytearray:
    struct.pack_into("<4I", data, at, *(KERNEL32 + 0x100 * k for k in range(1, 5)))
    return data


def test_an_erased_dll_name_leaves_a_table_of_one_modules_addresses():
    data = four_addresses(bytearray(build(lookup=False)))
    data[0x600 + 0x130 : 0x600 + 0x13D] = bytes(13)
    assert judge(bytes(data))[1] == [ib.TELL_IMPORTS]
    # Two slots are too few to tell a module's table from stray words.
    data = bytearray(build(lookup=False, slots=RESOLVED))
    data[0x600 + 0x130 : 0x600 + 0x13D] = bytes(13)
    assert judge(bytes(data)) == (ib.NO_EVIDENCE, [], [])


def test_a_descriptor_that_leads_to_no_table_voids_the_directory():
    # Bytes that only look like descriptors: the second one points outside the file.
    data = bytearray(build(slots=RESOLVED))
    struct.pack_into("<5I", data, 0x600 + 20, 0, 0, 0, 0x2130, 0x7000_0000)
    assert judge(bytes(data)) == (ib.NO_EVIDENCE, [], [])
    data = bytearray(build())
    struct.pack_into("<5I", data, 0x600 + 20, 0, 0, 0, 0x2130, 0x7000_0000)
    assert judge(bytes(data)) == (ib.NO_EVIDENCE, [], [])


def test_the_walk_ends_where_the_loader_ends_it():
    # A descriptor without a name ends the walk, whatever else it holds.
    data = bytearray(build(slots=RESOLVED))
    struct.pack_into("<5I", data, 0x600 + 20, 0x1234, 0x5678, 0, 0, 0x2C00_0000)
    assert judge(bytes(data))[1] == [ib.TELL_IMPORTS]


def test_a_walk_longer_than_any_import_table_is_dropped(monkeypatch):
    monkeypatch.setattr(ib, "_MAX_READS", 1)
    assert judge(build(slots=RESOLVED)) == (ib.NO_EVIDENCE, [], [])


def test_with_no_descriptor_left_the_address_table_directory_is_read():
    def erased(*, bound_directory: bool = False, words: int = 4) -> bytes:
        data = four_addresses(bytearray(build(lookup=False)))
        second = (KERNEL32 + 0x9000 + 0x40 * k for k in range(words))
        struct.pack_into(f"<{words}I", data, 0x600 + 0x74, *second)
        data[0x600 : 0x600 + 20] = bytes(20)
        directories = 0x80 + 24 + 96
        struct.pack_into("<II", data, directories + 8 * 12, 0x2060, 0x30)
        if bound_directory:
            struct.pack_into("<II", data, directories + 8 * 11, 0x2180, 8)
        return bytes(data)

    assert judge(erased())[1] == [ib.TELL_IMPORTS]
    # A bound file's table holds addresses as built, and a short table is too little to go on.
    assert judge(erased(bound_directory=True))[1] == []
    assert judge(erased(words=1))[1] == []


def test_the_import_directory_is_walked_whatever_its_size_says():
    assert judge(build(import_size=0, slots=[KERNEL32 + 0x10, KERNEL32 + 0x20]))[1] == [ib.TELL_IMPORTS]


BOUND_SLOTS = [KERNEL32 + 0x1000 * k for k in (1, 2, 3, 9)]
BOUND_SPAN = (KERNEL32 + 0x1000, KERNEL32 + 0x9001)


def bound(**kwargs) -> bytes:
    """A bound table: four of one module's addresses under a stamp."""
    return build(stamp=0xFFFF_FFFF, chain=0xFFFF_FFFF, lookup=False, slots=BOUND_SLOTS, **kwargs)


def test_a_modules_addresses_in_writable_data_mean_the_program_ran():
    pointers = struct.pack("<8I", *(KERNEL32 + 0x1100 + 0x18 * k for k in range(8)))
    verdict, tells, _ = judge(bound(text_flags=0xE000_0020, text=pointers))
    assert (verdict, tells) == (ib.MEMORY_IMAGE, [ib.TELL_MODULE_DATA])
    # Not in a section the program cannot write, and not when there are only a few.
    assert judge(bound(text=pointers))[1] == []
    assert judge(bound(text_flags=0xE000_0020, text=pointers[:16]))[1] == []
    # Without a bound table nothing says where the module is.
    assert judge(build(text_flags=0xE000_0020, text=pointers))[1] == []


def test_addresses_that_sit_together_are_one_module():
    assert ib._module_span(BOUND_SLOTS) == [BOUND_SPAN]
    assert ib.read(bound())["imports"]["bound_spans"] == [BOUND_SPAN]
    # A slot far from the rest points into another module, and one address gives no span.
    assert ib._module_span([*BOUND_SLOTS, KERNEL32 - 0x80_0000]) == [BOUND_SPAN]
    # Fewer than four addresses say too little about where a module is.
    assert ib._module_span(BOUND_SLOTS[:3]) == []
    # Addresses scattered all over are not one module's, even where four of them sit together.
    assert ib._module_span([*BOUND_SLOTS, KERNEL32 - 0x80_0000, KERNEL32 + 0x80_0000]) == []
    assert ib._module_span([KERNEL32 + (k << 21) for k in range(8)]) == []


def test_bytes_that_were_never_a_descriptor_say_nothing_of_a_module():
    # A binder leaves the forwarder chain empty or at a slot's index.
    text_there = build(stamp=0xFFFF_FFFF, chain=0x3E47E, lookup=False, slots=BOUND_SLOTS)
    assert ib.read(text_there)["imports"]["bound_spans"] == []
    first_forwarder = build(stamp=0x4A5B_DA6C, chain=2, lookup=False, slots=BOUND_SLOTS)
    assert ib.read(first_forwarder)["imports"]["bound_spans"] == [BOUND_SPAN]


def test_a_slot_nothing_was_written_to_does_not_hide_the_module():
    # The lookup table sets the count, so the table is read past an empty slot.
    slots = [*BOUND_SLOTS[:2], 0, *BOUND_SLOTS[2:], KERNEL32 + 0x9800]
    facts = ib.read(build(stamp=0xFFFF_FFFF, imported=6, slots=slots))
    assert facts["imports"]["bound_spans"] == [(KERNEL32 + 0x1000, KERNEL32 + 0x9801)]


def test_two_tables_into_one_module_count_its_width_once():
    span, everything = BOUND_SPAN, [(0, PAGE)]
    once = ib._module_addresses(bytes(PAGE), everything, [span], [], 4)
    assert ib._module_addresses(bytes(PAGE), everything, [span, span], [], 4) == once


def test_the_bound_table_itself_is_not_the_programs_writing():
    # The table often lies in writable data; its own slots are what the binder wrote.
    slots = [KERNEL32 + 0x1000 * k for k in range(1, 8)]
    table_in_data = build(stamp=0xFFFF_FFFF, lookup=False, slots=slots, data_flags=0xC000_0040)
    assert judge(table_in_data)[1] == []


def test_text_that_falls_in_a_modules_range_is_not_an_address():
    module = 0x7273_0000  # "sr" as the two high bytes: lower-case text lands in this range
    slots = [module + 0x100, module + 0x4000, module + 0x8000, module + 0xF000]
    for text in (
        b"".join(bytes([0x61 + k, 0x62 + k]) + b"sr" for k in range(8)),
        b"".join(b"line" + bytes([0x61 + k]) + b"\nsr" for k in range(8)),  # lines that start with "sr"
    ):
        spelled = build(stamp=0xFFFF_FFFF, lookup=False, slots=slots, text_flags=0xE000_0020, text=text)
        assert judge(spelled)[1] == []
    # The same range holds addresses that spell nothing, and a tab among zeros is no text.
    pointers = struct.pack("<8I", module + 0x0920, *(module + 0x1100 + 0x18 * k for k in range(7)))
    ran = build(stamp=0xFFFF_FFFF, lookup=False, slots=slots, text_flags=0xE000_0020, text=pointers)
    assert ib.read(ran)["module_addresses"]["found"] == 8
    assert judge(ran)[1] == [ib.TELL_MODULE_DATA]


def test_raw_data_the_table_puts_outside_the_file_is_read_at_its_rva():
    # A capture stored page for page, whose table sends one section's raw data past the file's end.
    pointers = struct.pack("<8I", *(KERNEL32 + 0x1100 + 0x18 * k for k in range(8)))
    data = bytearray(bound(mapped=True, text_flags=0xE000_0020, text=pointers))
    struct.pack_into("<I", data, SECTIONS + 20, 0xF000_1000)
    assert ib.TELL_MODULE_DATA in judge(bytes(data))[1]


def test_both_compiler_defaults_of_the_cookie_are_as_built():
    assert ib.BUILT_COOKIE in judge(build(cookie=(0xBB40_E64E, 0x44BF_19B1)))[2]
    assert ib.BUILT_COOKIE in judge(build(cookie=(0x0000_BB40, 0xFFFF_44BF)))[2]
    assert ib.BUILT_COOKIE in judge(build(is64=True, cookie=(0x2B99_2DDF_A232, 0xFFFF_D466_D220_5DCD)))[2]


def test_a_cookie_with_its_complement_beside_it_has_been_initialised():
    assert judge(build(cookie=(0x2D4F_56D3, 0xD2B0_A92C)))[1] == [ib.TELL_COOKIE]
    value = 0x0000_6B2A_9C41_77E5
    assert judge(build(is64=True, cookie=(value, ~value & (2**64 - 1))))[1] == [ib.TELL_COOKIE]


def test_a_cookie_the_loader_set_keeps_the_default_complement():
    assert judge(build(cookie=(0x325A_4BAB, 0x44BF_19B1)))[1] == [ib.TELL_COOKIE]


def test_a_64_bit_cookie_is_found_beside_its_complement_without_a_load_configuration():
    def with_pair(value: int, *, flags: int = 0xC000_0040) -> bytes:
        data = bytearray(build(is64=True, data_flags=flags))
        struct.pack_into("<QQ", data, 0x600 + 0x1C0, value, ~value & (2**64 - 1))
        return bytes(data)

    assert judge(with_pair(0x0000_40B3_D1CF_3A3E))[1] == [ib.TELL_COOKIE]
    # Not the compiler's default, not a mask and its inverse, and only in a section that can be written.
    assert judge(with_pair(0x0000_2B99_2DDF_A232))[1] == []
    assert judge(with_pair(0x0000_7FFF_FFFF_FFFF))[1] == []
    assert judge(with_pair(0x0000_40B3_D1CF_3A3E, flags=0x4000_0040))[1] == []


def test_a_changed_cookie_without_a_complement_is_not_a_tell():
    # Packed data sections read as arbitrary words; only the complement shows the word is a cookie.
    verdict, tells, built = judge(build(cookie=(0xDEAD_BEEF, 0x0C00_FFE0)))
    assert tells == [] and ib.BUILT_COOKIE not in built


def test_a_load_time_base_is_a_tell_for_64_bit_images():
    assert ib.TELL_RUNTIME_BASE in judge(build(is64=True, dll=True, base=0x7FFA_1C2B_0000))[1]
    assert ib.TELL_WINDOWS7_BASE in judge(build(is64=True, base=0x1_3F1B_0000))[1]
    assert ib.TELL_WINDOWS7_BASE in judge(build(is64=True, base=0xFF11_0000))[1]


def test_a_base_the_loader_could_not_have_written_is_not_a_tell():
    # Above user space, or not on a 64 KiB boundary: no loader maps an image there.
    assert judge(build(is64=True, base=0x1000_0000_0000_0000))[1] == []
    assert judge(build(is64=True, base=0xFFFF_F97F_FF00_0000))[1] == []
    assert judge(build(is64=True, dll=True, base=0x7FFA_1C2B_1000))[1] == []
    assert judge(build(base=0, aslr=True))[1] == []


def test_bases_a_linker_could_have_chosen_are_not_tells():
    for kwargs in (
        {"is64": True, "base": 0x1_4000_0000},
        {"is64": True, "base": 0x1_0000_0000},
        {"is64": True, "base": 0xFF00_0000},
        {"is64": True, "dll": True, "base": 0xFF11_0000},
        {"base": 0x3E_0000},
    ):
        assert judge(build(**kwargs))[1] == []


def test_a_mapped_layout_with_nothing_outside_its_sections_is_a_tell():
    verdict, tells, built = judge(build(mapped=True))
    assert verdict == ib.MEMORY_IMAGE and tells == [ib.TELL_LAYOUT]


def test_a_stub_stored_at_its_rvas_but_smaller_than_it_unpacks_to_is_an_ordinary_file():
    stub = bytearray(build(mapped=True))
    struct.pack_into("<I", stub, SECTIONS + 8, 0x21_7000)  # the first section's VirtualSize
    assert judge(bytes(stub)) == (ib.AS_BUILT, [], [ib.BUILT_IMPORTS])


def table_of_file_offsets(image: bytes) -> bytes:
    """`image`, built mapped, under the section table of the same program built in file layout."""
    out = bytearray(image)
    out[SECTIONS : SECTIONS + 80] = build()[SECTIONS : SECTIONS + 80]
    return bytes(out)


def test_content_at_its_rvas_under_a_table_of_file_offsets_is_a_memory_image():
    # Where the sections start shows it: bytes after a run of zeros at each RVA, none at the offsets listed.
    capture = table_of_file_offsets(build(mapped=True, text=b"\xcc" * 0x100))
    facts = ib.read(capture)
    assert facts["content_at_rvas"] == "section-starts"
    assert judge(capture)[:2] == (ib.MEMORY_IMAGE, [ib.TELL_CONTENT_LAYOUT])
    # So does an import directory that reads cleanly only when RVAs are taken as file offsets.
    capture = table_of_file_offsets(build(mapped=True, slots=RESOLVED))
    assert ib.read(capture)["content_at_rvas"] == "imports"
    assert judge(capture)[:2] == (ib.MEMORY_IMAGE, [ib.TELL_IMPORTS, ib.TELL_CONTENT_LAYOUT])
    # A file in file layout is neither.
    assert ib.read(build())["content_at_rvas"] == ""


def test_an_offset_that_is_one_sections_rva_and_anothers_file_offset_says_nothing():
    def section(va: int, raw: int) -> tuple:
        return (b"", va, 0x100, raw, 0x100, 0)

    data = bytearray(0x5000)
    for at in (0x1000, 0x2000, 0x3000):
        data[at : at + 4] = b"\x01\x02\x03\x04"
    at_rvas = [section(0x1000, 0x400), section(0x2000, 0x600), section(0x3000, 0x800)]
    assert ib._starts_at_rvas(bytes(data), at_rvas)
    # The third section's file offset is the first one's RVA: content there counts for neither.
    assert ib._starts_at_rvas(bytes(data), [*at_rvas[:2], section(0x3000, 0x1000)])
    data[0x400:0x404] = data[0x600:0x604] = b"\x01\x02\x03\x04"
    assert not ib._starts_at_rvas(bytes(data), at_rvas)


def test_a_section_table_with_every_row_erased_is_a_memory_image():
    capture = bytearray(build(mapped=True, slots=RESOLVED))
    capture[SECTIONS : SECTIONS + 80] = bytes(80)
    assert judge(bytes(capture))[:2] == (ib.MEMORY_IMAGE, [ib.TELL_IMPORTS, ib.TELL_WIPED])
    # One erased row is skipped, and the rows after it are still read.
    one = bytearray(build())
    one[SECTIONS : SECTIONS + 40] = bytes(40)
    facts = ib.read(bytes(one))
    assert facts["n_sections"] == 1 and not facts["sections_wiped"]


def test_zeros_that_fill_the_last_page_are_part_of_a_mapped_image():
    # A capture may store a section at its exact size; the rest of its page is not appended data.
    exact = bytearray(build(mapped=True))
    struct.pack_into("<I", exact, SECTIONS + 40 + 8, 0x180)  # the last section's VirtualSize
    struct.pack_into("<I", exact, SECTIONS + 40 + 16, 0x180)  # and its SizeOfRawData
    assert judge(bytes(exact))[:2] == (ib.MEMORY_IMAGE, [ib.TELL_LAYOUT])
    exact[0x2F00] = 1
    assert ib.BUILT_OVERLAY in judge(bytes(exact))[2] and judge(bytes(exact))[1] == []


def test_a_mapped_layout_with_a_payload_appended_is_an_ordinary_file():
    stub = build(mapped=True, tail=b"payload" * 100)
    assert judge(stub) == (ib.AS_BUILT, [], [ib.BUILT_IMPORTS, ib.BUILT_OVERLAY])


def test_a_valid_checksum_does_not_clear_a_mapped_layout():
    # Dump tools recompute the checksum, so it says nothing about how the sections are stored.
    verdict, tells, built = judge(build(mapped=True, checksum=True))
    assert verdict == ib.MEMORY_IMAGE and tells == [ib.TELL_LAYOUT] and ib.BUILT_CHECKSUM in built


def test_a_valid_checksum_does_not_outweigh_resolved_imports():
    verdict, tells, built = judge(build(slots=[KERNEL32 + 0x10, KERNEL32 + 0x20], checksum=True))
    assert verdict == ib.MEMORY_IMAGE and ib.BUILT_CHECKSUM in built


def test_the_checksum_follows_every_byte():
    data = bytearray(build(checksum=True))
    assert ib.read(bytes(data))["checksum_valid"]
    data[0x450] ^= 1
    assert not ib.read(bytes(data))["checksum_valid"]
    assert not ib.read(build())["checksum_valid"]


def test_only_a_real_certificate_entry_counts():
    data = bytearray(build(tail=bytes(0x40)))
    cert_at = len(data) - 0x40
    struct.pack_into("<II", data, 0x80 + 24 + 96 + 8 * 4, cert_at, 0x40)
    assert not ib.read(bytes(data))["certificate_in_file"]
    struct.pack_into("<IHH", data, cert_at, 0x40, 0x0200, 0x0002)
    assert ib.read(bytes(data))["certificate_in_file"]
    assert not ib.read(bytes(data[:-8]))["certificate_in_file"]


def test_what_is_not_a_pe_is_not_read():
    assert ib.read(b"") is None
    assert ib.read(b"MZ" + bytes(200)) is None
    data = bytearray(build())
    struct.pack_into("<H", data, 0x80 + 24, 0x0601)
    assert ib.read(bytes(data)) is None
    assert ib.verdicts([("f", None)])[0]["verdict"] == ib.NOT_PE


def test_a_truncated_file_is_read_as_far_as_it_goes():
    data = build()
    for cut in (0x150, 0x1B0, 0x400, 0x601, 0x700):
        ib.read(data[:cut])


def test_one_build_at_two_unusual_bases_was_relocated():
    # Imports bound and no cookie: nothing either file shows alone.
    bound = {"is64": True, "stamp": 0xFFFF_FFFF, "slots": [BOUND64 + 0x10, BOUND64 + 0x20]}
    a = ib.read(build(base=0x3F_0000, **bound))
    b = ib.read(build(base=0x80_0000, **bound))
    other = ib.read(build(base=0x9E_0000, timestamp=0x6000_0000, **bound))
    rows = {r["sha256"]: r for r in ib.verdicts([("a", a), ("b", b), ("other", other)])}
    assert rows["a"]["tells"] == rows["b"]["tells"] == ib.TELL_OTHER_BASE
    assert rows["other"]["verdict"] == ib.NO_EVIDENCE


def test_the_copy_linked_at_an_unusual_base_keeps_its_place_when_something_vouches_for_it():
    built = ib.read(build(is64=True, base=0x3F_0000, checksum=True))
    bound = [BOUND64 + 0x10, BOUND64 + 0x20]
    dump = ib.read(build(is64=True, base=0x80_0000, stamp=0xFFFF_FFFF, slots=bound))
    rows = {r["sha256"]: r for r in ib.verdicts([("built", built), ("dump", dump)])}
    assert rows["built"]["verdict"] == ib.AS_BUILT
    assert rows["dump"]["tells"] == ib.TELL_OTHER_BASE
    # Untouched imports and an overlay do not vouch: an early capture by a tool that keeps the
    # original file's overlay shows both.
    early = ib.read(build(is64=True, base=0x3F_0000, tail=b"kept overlay"))
    rows = {r["sha256"]: r for r in ib.verdicts([("early", early), ("dump", dump)])}
    assert rows["early"]["tells"] == ib.TELL_OTHER_BASE


def test_a_32_bit_exe_that_asks_for_a_load_address_and_sits_off_the_linkers_is_presumed_loaded():
    assert judge(build(base=0xB3_0000, aslr=True, tail=b"kept overlay"))[:2] == (
        ib.MEMORY_IMAGE,
        [ib.TELL_MOVED_EXE],
    )
    # Not at the linker's own base, not when the header fixes the address, not a DLL, not 64-bit.
    assert judge(build(aslr=True))[1] == []
    assert judge(build(base=0x50_0000))[1] == []
    assert judge(build(dll=True, base=0x6F00_0000, aslr=True))[1] == []
    assert judge(build(is64=True, base=0x1_0040_0000, aslr=True))[1] == []
    # A valid checksum vouches for the file: it was linked there.
    assert judge(build(base=0x4AD0_0000, aslr=True, checksum=True)) == (ib.AS_BUILT, [], [ib.BUILT_CHECKSUM])


def test_a_round_base_is_one_somebody_gave_the_linker():
    # The loader moves an EXE in 64 KiB steps and lands on a multiple of 16 MiB once in 256, so
    # there the file is not presumed loaded and its untouched imports count again.
    assert judge(build(base=0x100_0000, aslr=True)) == (ib.AS_BUILT, [], [ib.BUILT_IMPORTS])
    assert judge(build(base=0x3000_0000, aslr=True, tail=b"kept overlay"))[1] == []
    assert judge(build(base=0x101_0000, aslr=True))[:2] == (ib.MEMORY_IMAGE, [ib.TELL_MOVED_EXE])


def test_a_default_base_is_never_the_other_base():
    bound = {"is64": True, "stamp": 0xFFFF_FFFF, "slots": [BOUND64 + 0x10, BOUND64 + 0x20]}
    a = ib.read(build(base=0x1_4000_0000, **bound))
    b = ib.read(build(base=0x80_0000, **bound))
    rows = {r["sha256"]: r for r in ib.verdicts([("a", a), ("b", b)])}
    assert rows["a"]["verdict"] == rows["b"]["verdict"] == ib.NO_EVIDENCE


def test_a_dump_tool_section_means_a_memory_image():
    # CAPE and Scylla rebuild the import table in a section of their own, so the imports look
    # untouched, and they keep the original file's overlay.
    verdict, tells, built = judge(build(data_name=b".CAPE", tail=b"appended data"))
    assert (verdict, tells) == (ib.MEMORY_IMAGE, [ib.TELL_DUMP_TOOL])
    assert built == [ib.BUILT_IMPORTS, ib.BUILT_OVERLAY]
    assert judge(build(data_name=b".SCY"))[1] == [ib.TELL_DUMP_TOOL]
    assert judge(build(data_name=b".mackt"))[1] == [ib.TELL_DUMP_TOOL]
    assert judge(build(data_name=b".idata"))[1] == []


def test_an_entry_point_below_the_image_means_a_memory_image():
    # Address zero written as an RVA: 0 - ImageBase, wrapped to 32 bits.
    verdict, tells, _ = judge(build(entry=0x1_0000_0000 - 0x40_0000))
    assert (verdict, tells) == (ib.MEMORY_IMAGE, [ib.TELL_ENTRY])
    assert judge(build(entry=0xFFC0_0FA0))[1] == [ib.TELL_ENTRY]
    # No entry point at all, an entry past the image's end, and a 64-bit image, where no RVA wraps.
    assert judge(build(entry=0))[1] == []
    assert judge(build(entry=0xFFBF_FFFF))[1] == []
    assert judge(build(is64=True, entry=0xFFC0_0000))[1] == []


def test_an_entry_point_the_table_stores_no_byte_for_means_a_memory_image():
    def emptied(image: bytes, *, directory: int | None = None) -> bytes:
        # The first section keeps its place in memory and loses its bytes in the file.
        out = bytearray(image)
        struct.pack_into("<I", out, SECTIONS + 16, 0)
        if directory is not None:
            struct.pack_into("<II", out, 0x80 + 24 + 96 + 8 * directory, 2 * PAGE + 0x1E0, 0x18)
        return bytes(out)

    verdict, tells, _ = judge(emptied(build()))
    assert (verdict, tells) == (ib.MEMORY_IMAGE, [ib.TELL_UNSTORED_ENTRY])
    # Past the bytes a section does store, the loader fills with zeros just the same.
    assert judge(build(entry=PAGE + 0x800))[1] == [ib.TELL_UNSTORED_ENTRY]
    # A program that starts in stored bytes, has no entry point, or starts from a TLS callback
    # or as managed code can be the file as built.
    assert judge(emptied(build(entry=2 * PAGE)))[1] == []
    assert judge(emptied(build(entry=0)))[1] == []
    assert judge(emptied(build(), directory=9))[1] == []
    assert judge(emptied(build(), directory=14))[1] == []
    # A cut file says nothing: its table lists bytes the file no longer has.
    assert judge(emptied(build())[:-0x100])[1] == []
    # Below page alignment the loader maps the file in one piece, whatever the table says.
    flat = bytearray(emptied(build()))
    struct.pack_into("<I", flat, 0x80 + 24 + 32, 0x200)
    assert judge(bytes(flat))[1] == []


def test_an_unpacked_program_in_an_uninitialised_section_means_a_memory_image():
    unpacked = build(text_name=b"UPX0", text_flags=0xE000_0080)
    assert judge(unpacked)[:2] == (ib.MEMORY_IMAGE, [ib.TELL_FILLED])
    assert judge(build(mapped=True, tail=b"payload", text_flags=0xE000_0080))[1] == [ib.TELL_FILLED]


def test_an_uninitialised_section_that_is_empty_or_packed_says_nothing():
    assert judge(build(text_name=b"UPX0", text_flags=0xE000_0080, text=b""))[1] == []
    packed = bytes(range(256)) * 2
    assert judge(build(text_name=b"UPX0", text_flags=0xE000_0080, text=packed))[1] == []
    # A section that is also flagged as initialised data is an ordinary section.
    assert judge(build(text_flags=0xE000_00C0))[1] == []


def test_bytes_another_section_also_claims_are_not_the_uninitialised_sections_own():
    data = bytes(0x400) + b"\x01" * 0x200
    bss = (b".bss", 0x1000, 0x200, 0x400, 0x200, 0xC000_0080)
    reloc = (b".reloc", 0x2000, 0x200, 0x400, 0x200, 0x4200_0040)
    assert ib._filled(data, [bss], 0) == ".bss"
    assert ib._filled(data, [bss, reloc], 0) == ""


def test_the_section_upx_unpacks_into_means_a_memory_image_when_the_program_starts_there():
    # A tool that writes the unpacked program out may reset the flags that said the section is empty.
    assert judge(build(text_name=b"UPX0", text_flags=0xE000_00A0))[1] == [ib.TELL_FILLED]
    assert judge(build(text_name=b"UPX0", text_flags=0xE000_0020))[1] == [ib.TELL_FILLED]
    # Not when the program starts elsewhere, as a file UPX built does, and not under another
    # name: other packers build their stub in a section flagged this way.
    assert judge(build(text_name=b"UPX0", text_flags=0xE000_00A0, entry=2 * PAGE))[1] == []
    assert judge(build(text_name=b".MPRESS1", text_flags=0xE000_00E0))[1] == []
    packed = bytes(range(256)) * 2
    assert judge(build(text_name=b"UPX0", text_flags=0xE000_00A0, text=packed))[1] == []


def test_packed_data_after_a_run_of_zeros_is_still_packed_data():
    data = bytes(0x400) + bytes(0x100) + bytes(range(256))
    assert ib._filled(data, [(b".bss", 0x1000, 0x200, 0x400, 0x200, 0xC000_0080)], 0) == ""


def test_section_sizes_that_hold_addresses_mean_a_memory_image():
    # One dump tool writes each section's address where its size belongs; the loader refuses such a file.
    verdict, tells, _ = judge(build(base=0x204_0000, size_is_address=True))
    assert (verdict, tells) == (ib.MEMORY_IMAGE, [ib.TELL_SIZE_IS_ADDRESS])
    assert judge(build(dll=True, size_is_address=True))[1] == [ib.TELL_SIZE_IS_ADDRESS]
    # The size field is 32 bits wide, so above 4 GiB it holds the low half of the address.
    high = bytearray(build(is64=True, dll=True))
    for row, rva in enumerate((0x1000, 0x2000)):
        struct.pack_into("<I", high, SECTIONS + 16 + 40 * row + 8, (0x1_8000_0000 + rva) & 0xFFFF_FFFF)
    assert judge(bytes(high))[1] == [ib.TELL_SIZE_IS_ADDRESS]


def test_one_binding_with_two_sets_of_addresses_was_written_at_load():
    def stub(first: int, *, stamp: int = 0x371F_C2B3, checksum: bool = False) -> dict:
        return ib.read(build(stamp=stamp, slots=[first, first + 0x40], checksum=checksum))

    def tells(*files: dict) -> list[str]:
        return [r["tells"] for r in ib.verdicts([(str(k), facts) for k, facts in enumerate(files)])]

    # A binder gives one DLL one set of addresses: one stamp over two sets is the loader's work.
    assert tells(stub(0x7559_2140), stub(0x7749_7A28)) == [ib.TELL_OTHER_ADDRESSES] * 2
    assert tells(stub(0x7559_2140), stub(0x7559_2140)) == ["", ""]
    # The newer binder's stamp names no DLL, and a file that something vouches for keeps its place.
    assert tells(stub(0x7559_2140, stamp=0xFFFF_FFFF), stub(0x7749_7A28, stamp=0xFFFF_FFFF)) == ["", ""]
    assert tells(stub(0x7559_2140, checksum=True), stub(0x7749_7A28)) == ["", ib.TELL_OTHER_ADDRESSES]


def one_file(data: bytes) -> tuple[str, list[str], list[str], list[str]]:
    row = ib.single_file(ib.read(data))
    return row["verdict"], row["decided_by"], row["tells"], row["as_built"]


def test_one_file_alone_is_judged_by_its_traces_and_never_by_the_presumption():
    assert one_file(build(slots=RESOLVED))[:2] == (ib.MEMORY_IMAGE, [ib.TELL_IMPORTS])
    assert one_file(build()) == (ib.AS_BUILT, [ib.BUILT_IMPORTS], [], [ib.BUILT_IMPORTS])
    assert one_file(build(slots=[0, 0])) == (ib.UNDECIDED, [], [], [])
    # The presumption is reported and leaves the file undecided, overlay or not.
    presumed = one_file(build(base=0xB3_0000, aslr=True, tail=b"kept overlay"))
    assert presumed == (ib.UNDECIDED, [], [ib.TELL_MOVED_EXE], [ib.BUILT_OVERLAY])
    # Beside a trace the presumption changes nothing.
    both = ib.single_file(ib.read(build(base=0xB3_0000, aslr=True, slots=RESOLVED)))
    assert both["verdict"] == ib.MEMORY_IMAGE and ib.TELL_MOVED_EXE in both["tells"]
    assert ib.single_file(None)["verdict"] == ib.UNDECIDED


def test_a_tell_that_compares_files_is_not_in_one_files_view():
    bound = {"is64": True, "stamp": 0xFFFF_FFFF, "slots": [BOUND64 + 0x10, BOUND64 + 0x20]}
    a, b = ib.read(build(base=0x80_0000, **bound)), ib.read(build(base=0x90_0000, **bound))
    assert [r["tells"] for r in ib.verdicts([("a", a), ("b", b)])] == [ib.TELL_OTHER_BASE] * 2
    assert ib.single_file(a) == {"verdict": ib.UNDECIDED, "decided_by": [], "tells": [], "as_built": []}


def test_a_capture_left_as_captured_is_a_memory_image_for_one_file():
    marks = {*ib.LEFT, *ib.FORM, *ib.REBUILT}
    assert marks < set(ib.TELLS) and len(marks) == len(ib.LEFT) + len(ib.FORM) + len(ib.REBUILT)
    assert not {ib.TELL_MOVED_EXE, ib.TELL_OTHER_BASE, ib.TELL_OTHER_ADDRESSES, ib.TELL_FILLED} & marks
    assert one_file(build(mapped=True))[:2] == (ib.MEMORY_IMAGE, [ib.TELL_LAYOUT])
    # A tell that is no mark decides nothing, and keeps a sign from deciding.
    unstored = one_file(build(entry=PAGE + 0x800))
    assert unstored == (ib.UNDECIDED, [], [ib.TELL_UNSTORED_ENTRY], [ib.BUILT_IMPORTS])
    # Beside a mark it is reported and does not decide.
    both = one_file(build(entry=PAGE + 0x800, slots=RESOLVED))
    assert both[:3] == (ib.MEMORY_IMAGE, [ib.TELL_IMPORTS], [ib.TELL_IMPORTS, ib.TELL_UNSTORED_ENTRY])
    # Unpacked content says the program ran its unpacker, not how the file is presented.
    unpacked = one_file(build(text_name=b"UPX0", text_flags=0xE000_0080))
    assert unpacked == (ib.UNDECIDED, [], [ib.TELL_FILLED], [ib.BUILT_IMPORTS])
    # A capture whose checksum a tool recomputed is not left as captured, and not shown rebuilt.
    assert one_file(build(mapped=True, checksum=True))[:3] == (ib.UNDECIDED, [], [ib.TELL_LAYOUT])
    # Nor is one that somebody signed as it stands.
    signed_capture = signed(build(slots=RESOLVED))
    assert ib.read(signed_capture)["signature"] == "matches"
    assert one_file(signed_capture)[:3] == (ib.UNDECIDED, [], [ib.TELL_IMPORTS])


def test_a_capture_a_tool_rebuilt_to_load_is_a_file_as_built_for_one_file():
    # The imports are loadable again, so the file is presented to run, whoever wrote it.
    verdict, decided_by, found, built = one_file(build(data_name=b".CAPE"))
    assert (verdict, decided_by) == (ib.AS_BUILT, [ib.TELL_DUMP_TOOL, ib.BUILT_IMPORTS])
    assert (found, built) == ([ib.TELL_DUMP_TOOL], [ib.BUILT_IMPORTS])
    # It may keep the form it was captured in and the content it unpacked.
    kept = one_file(build(data_name=b".SCY", mapped=True, text_name=b"UPX0", text_flags=0xE000_0080))
    assert kept[0] == ib.AS_BUILT and set(kept[2]) == {ib.TELL_LAYOUT, ib.TELL_DUMP_TOOL, ib.TELL_FILLED}
    # Not with state a process left beside it, and not without a sign.
    assert one_file(build(data_name=b".CAPE", slots=RESOLVED))[:2] == (ib.UNDECIDED, [])
    assert one_file(build(data_name=b".CAPE", slots=[0, 0]))[:3] == (ib.UNDECIDED, [], [ib.TELL_DUMP_TOOL])


def test_a_rebuilt_capture_the_loader_could_not_start_is_undecided():
    inside = [0x40_0000 + PAGE + 0x10 * k for k in range(8)]
    other = [0x120_0000 + PAGE + 0x10 * k for k in range(4)]
    assert one_file(relocated(inside + inside[:4], data_name=b".CAPE"))[0] == ib.AS_BUILT
    # Relocation targets that another base holds a quarter as well as the header's does.
    torn = one_file(relocated(inside + other, data_name=b".CAPE"))
    assert torn[:3] == (ib.UNDECIDED, [], [ib.TELL_DUMP_TOOL])
    assert one_file(relocated(inside + other))[0] == ib.AS_BUILT
    # A file cut short of the bytes its section table lists.
    assert one_file(build(data_name=b".CAPE")[:-0x40])[:3] == (ib.UNDECIDED, [], [ib.TELL_DUMP_TOOL])
    # Import slots that name nothing: another sign does not make up for them.
    bare = build(data_name=b".CAPE", slots=[0, 0], cookie=(0xBB40_E64E, 0x44BF_19B1))
    assert one_file(bare) == (ib.UNDECIDED, [], [ib.TELL_DUMP_TOOL], [ib.BUILT_COOKIE])
    # An entry point the file stores no byte for keeps any sign from deciding.
    assert one_file(build(data_name=b".CAPE", entry=PAGE + 0x800))[0] == ib.UNDECIDED


def test_a_sign_with_nothing_against_it_makes_one_file_a_file_as_built():
    default_cookie = build(cookie=(0xBB40_E64E, 0x44BF_19B1), slots=[0, 0])
    assert one_file(default_cookie)[:2] == (ib.AS_BUILT, [ib.BUILT_COOKIE])
    checked = one_file(build(slots=[0, 0], checksum=True))
    assert checked == (ib.AS_BUILT, [ib.BUILT_CHECKSUM], [], [ib.BUILT_CHECKSUM])
    # An overlay is reported and does not decide.
    assert one_file(build(slots=[0, 0], tail=b"payload")) == (ib.UNDECIDED, [], [], [ib.BUILT_OVERLAY])
    assert one_file(build(tail=b"payload"))[:2] == (ib.AS_BUILT, [ib.BUILT_IMPORTS])
    # An image stored at its RVAs with data after it was written out to run again: a sign decides.
    copy = one_file(build(mapped=True, tail=b"payload" * 100))
    assert copy == (ib.AS_BUILT, [ib.BUILT_IMPORTS], [], [ib.BUILT_IMPORTS, ib.BUILT_OVERLAY])
    assert one_file(build(mapped=True, tail=b"payload" * 100, slots=[0, 0]))[0] == ib.UNDECIDED


def signed(image: bytes, *, algorithm: str = "sha256", null: bool = True) -> bytes:
    """`image`, 32-bit, with a certificate table that carries its Authenticode hash."""
    oid = {"sha1": "06052b0e03021a", "sha256": "0609608648016503040201"}[algorithm]
    out = bytearray(image + bytes(-len(image) % 8))
    checksum, entry = 0x80 + 24 + 64, 0x80 + 24 + 96 + 8 * 4
    covered = bytes(out[:checksum]) + bytes(out[checksum + 4 : entry]) + bytes(out[entry + 8 :])
    digest = hashlib.new(algorithm, covered).digest()
    identifier = bytes.fromhex(oid) + (b"\x05\x00" if null else b"")
    blob = b"\x30\x82" + identifier + bytes((4, len(digest))) + digest
    table = struct.pack("<IHH", 8 + len(blob), 0x0200, 0x0002) + blob
    table += bytes(-len(table) % 8)
    struct.pack_into("<II", out, entry, len(out), len(table))
    return bytes(out + table)


def test_a_signature_over_these_very_bytes_is_a_sign():
    facts = ib.read(signed(build(slots=[0, 0])))
    assert facts["signature"] == "matches"
    assert one_file(signed(build(slots=[0, 0])))[:2] == (ib.AS_BUILT, [ib.BUILT_SIGNED])
    assert ib.read(signed(build(), algorithm="sha1", null=False))["signature"] == "matches"
    # A byte changed after signing: the certificate is still there, and it decides nothing.
    patched = bytearray(signed(build(slots=[0, 0])))
    patched[0x410] ^= 1
    facts = ib.read(bytes(patched))
    assert (facts["signature"], facts["certificate_in_file"]) == ("differs", True)
    assert one_file(bytes(patched)) == (ib.UNDECIDED, [], [], [ib.BUILT_OVERLAY, ib.BUILT_CERTIFICATE])
    # A table that names no digest, and a file without a table.
    bare = bytearray(build(tail=bytes(0x40)))
    struct.pack_into("<II", bare, 0x80 + 24 + 96 + 8 * 4, len(bare) - 0x40, 0x40)
    struct.pack_into("<IHH", bare, len(bare) - 0x40, 0x40, 0x0200, 0x0002)
    assert ib.read(bytes(bare))["signature"] == "unreadable"
    assert ib.read(build())["signature"] == ""


def test_a_signed_image_stored_at_its_rvas_is_presented_to_run():
    # Whoever signed these bytes offered them as a program, however they came to be.
    capture = signed(build(mapped=True))
    assert ib.read(capture)["signature"] == "matches"
    assert one_file(capture)[:2] == (ib.AS_BUILT, [ib.BUILT_IMPORTS, ib.BUILT_SIGNED])


def relocated(targets: list[int], *, is64: bool = False, **kwargs) -> bytes:
    """A file whose relocation table lists up to twelve sites at the start of `.text`, holding `targets`."""
    data = bytearray(build(is64=is64, aslr=True, **kwargs))
    word, kind = (8, 10) if is64 else (4, 3)
    block = 8 + 2 * len(targets)
    struct.pack_into("<II", data, 0x600 + 0x1E0, PAGE, block)
    for k, target in enumerate(targets):
        struct.pack_into("<H", data, 0x600 + 0x1E8 + 2 * k, kind << 12 | 8 * k)
        data[0x400 + 8 * k : 0x400 + 8 * k + word] = target.to_bytes(word, "little")
    struct.pack_into("<I", data, 0x80 + 24 + (112 if is64 else 96) + 44, block)
    return bytes(data)


def test_relocation_targets_that_fit_another_base_mean_a_memory_image():
    assert judge(relocated([0x40_0000 + PAGE + 0x10 * k for k in range(8)]))[1] == []
    verdict, tells, built = judge(relocated([0x120_0000 + PAGE + 0x10 * k for k in range(8)]))
    assert (verdict, tells) == (ib.MEMORY_IMAGE, [ib.TELL_RELOCATED])
    # The imports are untouched and the header keeps the linker's base: nothing else shows the load.
    assert built == [ib.BUILT_IMPORTS]
    # A pointer just past the image's end still belongs to it: nothing else can be mapped there.
    assert judge(relocated([0x120_0000 + 0xF004 - 0x100 * k for k in range(8)]))[1] == [ib.TELL_RELOCATED]
    # A delta applied the wrong way leaves addresses no process has. The sites were rewritten all the same.
    wrapped = [0xFFFF_FF43_C6B3_0000 + PAGE + 0x10 * k for k in range(8)]
    assert judge(relocated(wrapped, is64=True, dll=True))[1] == [ib.TELL_RELOCATED]


def test_relocation_targets_say_nothing_without_one_other_base():
    there = [0x120_0000 + PAGE + 0x10 * k for k in range(12)]
    # Too few of them, sites that hold nothing, and RVAs where addresses belong.
    assert judge(relocated(there[:7]))[1] == []
    assert judge(relocated([0] * 8))[1] == []
    assert judge(relocated([PAGE + 0x10 * k for k in range(8)]))[1] == []
    # Addresses all over memory, and addresses no image on a 64 KiB boundary holds together.
    assert judge(relocated([0x100_0000 * (k + 2) for k in range(8)]))[1] == []
    assert judge(relocated([0x120_F000 + 0x400 * k for k in range(8)]))[1] == []
    # A third at the header's base and the rest never written.
    assert judge(relocated([0x40_0000 + PAGE + 0x10 * k for k in range(4)] + [0] * 8))[1] == []
    # A header base no loader uses says nothing about where the file has been.
    assert judge(relocated(there, base=0))[1] == []
    assert judge(relocated(there, base=0x3CC_0CC4))[1] == []


def second_descriptor(image: bytes, slots: list[int]) -> bytes:
    """`image` from `build` with a second import table of up to seven slots, each with a name."""
    data = bytearray(image)
    struct.pack_into("<5I", data, 0x614, 2 * PAGE + 0x140, 0, 0, 2 * PAGE + 0x130, 2 * PAGE + 0x160)
    for k, v in enumerate(slots):
        struct.pack_into("<I", data, 0x600 + 0x140 + 4 * k, 2 * PAGE + (0x100, 0x110)[k % 2])
        struct.pack_into("<I", data, 0x600 + 0x160 + 4 * k, v)
    return bytes(data)


def test_tables_the_loader_resolved_are_not_outvoted_by_the_others():
    four = [KERNEL32 + 0x1000 + 0x10 * k for k in range(4)]
    # A tool that adds imports leaves counters in its own table: more slots than the loader wrote.
    patched = second_descriptor(build(imported=4, slots=four), [1, 2, 3, 4, 5, 6, 7])
    counted = ib.read(patched)["imports"]
    assert (counted["slots"], counted["addr"], counted["resolved"]) == (11, 4, 4)
    assert judge(patched)[1] == [ib.TELL_IMPORTS]
    # Three addresses are too few to rest on.
    few = second_descriptor(build(imported=3, slots=four[:3]), [1, 2, 3, 4, 5, 6, 7])
    assert judge(few)[1] == []
    # Without the names in the lookup table nothing proves these are import tables.
    nameless = bytearray(patched)
    nameless[0x600 + 0x102 : 0x600 + 0x10D] = bytes(11)
    assert judge(bytes(nameless))[1] == []


def test_resolved_tables_are_found_when_no_directory_leads_to_them():
    four = [KERNEL32 + 0x1000 + 0x10 * k for k in range(4)]
    directory = 0x80 + 24 + 96 + 8

    def lost(image: bytes, rva: int = 0) -> bytes:
        data = bytearray(image)
        struct.pack_into("<II", data, directory, rva, 0x28 if rva else 0)
        return bytes(data)

    # The entry erased, and the entry pointing into no section.
    assert judge(lost(build(imported=4, slots=four)))[:2] == (ib.MEMORY_IMAGE, [ib.TELL_IMPORTS])
    assert judge(lost(build(imported=4, slots=four), 0x1A000))[1] == [ib.TELL_IMPORTS]
    # Only the loader's work is looked for: untouched tables and bound ones say nothing this way.
    assert judge(lost(build(imported=4))) == (ib.NO_EVIDENCE, [], [])
    assert judge(lost(build(imported=4, slots=four, stamp=0x5E00_0000)))[1] == []


def test_an_import_table_rebuilt_in_a_section_added_at_the_end_means_a_memory_image():
    def rebuilt(**kwargs) -> bytes:
        # The address table stays in the program's own section; only the descriptor and names are new.
        data = bytearray(build(imported=4, **kwargs))
        struct.pack_into("<I", data, 0x600 + 16, PAGE + 0x100)
        struct.pack_into("<5I", data, 0x400 + 0x100, *(2 * PAGE + n for n in (0x100, 0x110, 0x100, 0x110)), 0)
        return bytes(data)

    verdict, tells, built = judge(rebuilt(lookup=False))
    assert (verdict, tells) == (ib.MEMORY_IMAGE, [ib.TELL_REBUILT])
    assert built == [ib.BUILT_IMPORTS]
    # A linker that keeps lookup tables, or keeps the address table beside its descriptors, built the file.
    assert judge(rebuilt())[1] == []
    assert judge(build(imported=4, lookup=False))[1] == []


def test_zeros_after_the_last_section_are_not_an_overlay():
    assert judge(build(tail=bytes(64)))[2] == [ib.BUILT_IMPORTS]
    assert judge(build(tail=bytes(63) + b"x"))[2] == [ib.BUILT_IMPORTS, ib.BUILT_OVERLAY]
    # So padding does not make a mapped image an ordinary file, however long it is.
    assert judge(build(mapped=True, tail=bytes(5 * PAGE)))[1] == [ib.TELL_LAYOUT]


def test_rows_past_the_section_cap_still_say_where_the_file_ends(monkeypatch):
    monkeypatch.setattr(ib, "_MAX_SECTIONS", 1)
    facts = ib.read(build())
    assert facts["n_sections"] == 1 and not facts["overlay"]
    # A layout is judged only when every row was read.
    assert not ib.read(build(mapped=True))["mapped_layout"]


def test_words_of_zeros_and_ones_do_not_hide_the_cookie():
    cookie = 0x2B99_1234_5678
    noise = (bytes(8) + b"\xff" * 8) * 1000
    pair = struct.pack("<QQ", cookie, ~cookie & (2**64 - 1))
    assert ib._cookie_pair(noise + pair, [(0, len(noise) + 16)])
    assert not ib._cookie_pair(noise, [(0, len(noise))])


def test_the_checksum_is_imagehlps_also_where_the_sum_wraps():
    def imagehlp(data: bytes, at: int) -> int:
        total = 0
        for (word,) in struct.iter_unpack("<H", data + bytes(len(data) % 2)):
            total += word
            total = (total >> 16) + (total & 0xFFFF)
        for (stored,) in struct.iter_unpack("<H", data[at : at + 4]):
            total = (total - (total < stored) - stored) & 0xFFFF
        return total + len(data)

    samples = [bytes([0xFF]) * 64, bytes(64), bytes(range(256)) * 3 + b"\x7f", build()]
    samples.append(build(is64=True, tail=b"odd"))
    for data in samples:
        for at in (8, 16):
            assert ib._checksum(data, at) == imagehlp(data, at)
