from __future__ import annotations

import io
import zipfile

from maltriage.filetype import detect
from maltriage.models import FileKind

from .pe_builder import build_pe


def _zip(entries: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return buffer.getvalue()


def test_pe_from_mz_header():
    assert detect(build_pe(), "sample.exe") is FileKind.PE


def test_pdf_from_header():
    assert detect(b"%PDF-1.7\n1 0 obj\n<<>>\nendobj\n", "invoice.pdf") is FileKind.PDF


def test_elf_from_magic():
    assert detect(b"\x7fELF\x02\x01\x01" + b"\x00" * 64, "binary") is FileKind.ELF


def test_ooxml_detected_inside_zip():
    data = _zip({"[Content_Types].xml": b"<Types/>", "word/document.xml": b"<w/>"})
    assert detect(data, "report.docx") is FileKind.OOXML


def test_apk_detected():
    data = _zip({"AndroidManifest.xml": b"<manifest/>", "classes.dex": b"dex\n035"})
    assert detect(data, "app.apk") is FileKind.APK


def test_plain_zip_is_archive():
    assert detect(_zip({"notes.txt": b"hello"}), "bundle.zip") is FileKind.ARCHIVE


def test_shebang_is_script():
    assert detect(b"#!/bin/bash\necho hi\n", "run.sh") is FileKind.SCRIPT


def test_powershell_hint_is_script():
    body = b"param($x)\nWrite-Host $x\nInvoke-Expression $x\n"
    assert detect(body, "loader.ps1") is FileKind.SCRIPT


def test_random_binary_is_unknown():
    assert detect(bytes(range(256)) * 4, "blob.bin") is FileKind.UNKNOWN


def test_plain_text():
    assert detect(b"just a note about the meeting\n", "note.txt") is FileKind.TEXT
