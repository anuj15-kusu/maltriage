"""Construct a minimal, valid PE32 image in memory.

Tests must never ship real malware, so the PE fixtures are generated here.
"""

from __future__ import annotations

import struct

E_LFANEW = 0x40
OPTIONAL_HEADER_SIZE = 0xE0
HEADERS_SIZE = 0x200
SECTION_RAW_SIZE = 0x200
SECTION_RVA = 0x1000


def _dos_header() -> bytearray:
    dos = bytearray(E_LFANEW)
    dos[0:2] = b"MZ"
    struct.pack_into("<H", dos, 0x02, 0x0090)  # e_cblp
    struct.pack_into("<H", dos, 0x04, 0x0003)  # e_cp
    struct.pack_into("<I", dos, 0x3C, E_LFANEW)  # e_lfanew
    return dos


def _coff_header(machine: int) -> bytes:
    # Machine, Sections, TimeDateStamp, SymTab, NumSymbols, OptHdrSize, Characteristics
    return struct.pack("<HHIIIHH", machine, 1, 0x5F000000, 0, 0, OPTIONAL_HEADER_SIZE, 0x0102)


def _optional_header(entry_point: int) -> bytearray:
    opt = bytearray(OPTIONAL_HEADER_SIZE)
    struct.pack_into("<H", opt, 0, 0x10B)  # PE32 magic
    opt[2] = 8  # MajorLinkerVersion
    struct.pack_into("<I", opt, 4, SECTION_RAW_SIZE)  # SizeOfCode
    struct.pack_into("<I", opt, 8, 0)  # SizeOfInitializedData
    struct.pack_into("<I", opt, 12, 0)  # SizeOfUninitializedData
    struct.pack_into("<I", opt, 16, entry_point)  # AddressOfEntryPoint
    struct.pack_into("<I", opt, 20, SECTION_RVA)  # BaseOfCode
    struct.pack_into("<I", opt, 24, SECTION_RVA + SECTION_RAW_SIZE)  # BaseOfData
    struct.pack_into("<I", opt, 28, 0x400000)  # ImageBase
    struct.pack_into("<I", opt, 32, 0x1000)  # SectionAlignment
    struct.pack_into("<I", opt, 36, 0x200)  # FileAlignment
    struct.pack_into("<HHHHHH", opt, 40, 6, 0, 0, 0, 6, 0)  # OS/Image/Subsystem versions
    struct.pack_into("<I", opt, 52, 0)  # Win32VersionValue
    struct.pack_into("<I", opt, 56, 0x2000)  # SizeOfImage
    struct.pack_into("<I", opt, 60, HEADERS_SIZE)  # SizeOfHeaders
    struct.pack_into("<I", opt, 64, 0)  # CheckSum
    struct.pack_into("<H", opt, 68, 3)  # Subsystem = console
    struct.pack_into("<H", opt, 70, 0)  # DllCharacteristics
    struct.pack_into("<I", opt, 72, 0x100000)  # SizeOfStackReserve
    struct.pack_into("<I", opt, 76, 0x1000)  # SizeOfStackCommit
    struct.pack_into("<I", opt, 80, 0x100000)  # SizeOfHeapReserve
    struct.pack_into("<I", opt, 84, 0x1000)  # SizeOfHeapCommit
    struct.pack_into("<I", opt, 88, 0)  # LoaderFlags
    struct.pack_into("<I", opt, 92, 16)  # NumberOfRvaAndSizes
    # Data directories stay zeroed: no imports, no certificate table.
    return opt


def _section_header(name: bytes) -> bytes:
    return struct.pack(
        "<8sIIIIIIHHI",
        name.ljust(8, b"\x00"),
        SECTION_RAW_SIZE,  # VirtualSize
        SECTION_RVA,  # VirtualAddress
        SECTION_RAW_SIZE,  # SizeOfRawData
        HEADERS_SIZE,  # PointerToRawData
        0,
        0,
        0,
        0,
        0x60000020,  # CODE | EXECUTE | READ
    )


def build_pe(
    payload: bytes = b"\x90" * 16,
    section_name: bytes = b".text",
    machine: int = 0x14C,
    entry_point: int = SECTION_RVA,
) -> bytes:
    """Return a minimal but well-formed PE32 file as bytes."""
    body = bytearray(HEADERS_SIZE + SECTION_RAW_SIZE)
    body[0:E_LFANEW] = _dos_header()
    offset = E_LFANEW
    body[offset : offset + 4] = b"PE\x00\x00"
    offset += 4
    body[offset : offset + 20] = _coff_header(machine)
    offset += 20
    body[offset : offset + OPTIONAL_HEADER_SIZE] = _optional_header(entry_point)
    offset += OPTIONAL_HEADER_SIZE
    body[offset : offset + 40] = _section_header(section_name)
    body[HEADERS_SIZE : HEADERS_SIZE + len(payload)] = payload
    return bytes(body)


LONG_UNIQUE_PAYLOAD = (
    b"This synthetic sample was built by the maltriage test suite. "
    b"http://malware.example.com/gate.php "
)
