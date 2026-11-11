"""Portable Executable parser built on pefile."""

from __future__ import annotations

from datetime import UTC, datetime

from maltriage.models import FileKind, SampleContext
from maltriage.parsers.base import register_parser
from maltriage.strings import shannon_entropy

SECTION_EXECUTE = 0x20000000
SECTION_READ = 0x40000000
SECTION_WRITE = 0x80000000

MACHINES = {
    0x14C: "i386",
    0x8664: "amd64",
    0x1C0: "arm",
    0xAA64: "arm64",
}

SUBSYSTEMS = {
    1: "native",
    2: "gui",
    3: "console",
    7: "efi",
    9: "windows-ce",
    10: "efi-rom",
}


@register_parser
class PEParser:
    name = "pe"
    kinds = {FileKind.PE}

    def parse(self, ctx: SampleContext) -> None:
        import pefile

        try:
            pe = pefile.PE(data=ctx.read(), fast_load=False)
        except Exception as exc:  # malformed samples are expected
            ctx.add_error(f"pe parse failed: {exc}")
            return

        try:
            ctx.parsed["pe"] = self._extract(ctx, pe)
        finally:
            pe.close()

    def _extract(self, ctx: SampleContext, pe) -> dict:
        data = ctx.read()
        sections = []
        for section in pe.sections:
            raw = section.get_data() or b""
            name = section.Name.rstrip(b"\x00").decode("utf-8", "replace")
            flags = section.Characteristics
            sections.append(
                {
                    "name": name,
                    "virtual_size": int(section.Misc_VirtualSize),
                    "raw_size": int(section.SizeOfRawData),
                    "raw_offset": int(section.PointerToRawData),
                    "entropy": round(shannon_entropy(raw), 2),
                    "executable": bool(flags & SECTION_EXECUTE),
                    "writable": bool(flags & SECTION_WRITE),
                    "readable": bool(flags & SECTION_READ),
                }
            )

        imports: dict[str, list[str]] = {}
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
            dll = (
                entry.dll.decode("utf-8", "replace")
                if isinstance(entry.dll, bytes)
                else str(entry.dll)
            )
            funcs = []
            for imp in entry.imports:
                if imp.name:
                    funcs.append(
                        imp.name.decode("utf-8", "replace")
                        if isinstance(imp.name, bytes)
                        else str(imp.name)
                    )
                elif imp.ordinal:
                    funcs.append(f"ord_{imp.ordinal}")
            imports[dll] = funcs

        exports: list[str] = []
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if sym.name:
                    exports.append(
                        sym.name.decode("utf-8", "replace")
                        if isinstance(sym.name, bytes)
                        else str(sym.name)
                    )

        signed = False
        cert_size = 0
        try:
            security = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
            cert_size = int(security.Size)
            signed = cert_size > 0 and security.VirtualAddress > 0
        except Exception:
            pass

        overlay = 0
        if sections:
            end = max(s["raw_offset"] + s["raw_size"] for s in sections)
            overlay = max(0, len(data) - end)

        pdb_path = None
        for entry in getattr(pe, "DIRECTORY_ENTRY_DEBUG", []) or []:
            try:
                if entry.entry.PdbFileName:
                    pdb_path = entry.entry.PdbFileName.rstrip(b"\x00").decode("utf-8", "replace")
            except Exception:
                continue

        version_strings: list[str] = []
        if hasattr(pe, "FileInfo"):
            for fileinfo_list in pe.FileInfo:
                for info in fileinfo_list:
                    if getattr(info, "Key", b"") != b"StringFileInfo":
                        continue
                    for table in info.StringTable:
                        for key, value in table.entries.items():
                            key_text = key.decode("utf-8", "replace")
                            value_text = value.decode("utf-8", "replace")
                            version_strings.append(f"{key_text}={value_text}")

        timestamp = int(pe.FILE_HEADER.TimeDateStamp)
        compiled = None
        if timestamp:
            try:
                compiled = datetime.fromtimestamp(timestamp, tz=UTC).isoformat()
            except (OSError, ValueError, OverflowError):
                compiled = None

        resources = []
        if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                name = str(entry.name) if entry.name else str(entry.id)
                if entry.directory:
                    resources.append({"type": name, "count": len(entry.directory.entries)})

        return {
            "machine": MACHINES.get(int(pe.FILE_HEADER.Machine), hex(int(pe.FILE_HEADER.Machine))),
            "subsystem": SUBSYSTEMS.get(
                int(pe.OPTIONAL_HEADER.Subsystem), str(int(pe.OPTIONAL_HEADER.Subsystem))
            ),
            "timestamp": compiled,
            "entrypoint": hex(int(pe.OPTIONAL_HEADER.AddressOfEntryPoint)),
            "imagebase": hex(int(pe.OPTIONAL_HEADER.ImageBase)),
            "sections": sections,
            "imports": imports,
            "import_count": sum(len(v) for v in imports.values()),
            "exports": exports[:50],
            "signed": signed,
            "cert_size": cert_size,
            "overlay_size": overlay,
            "pdb_path": pdb_path,
            "version_strings": version_strings[:20],
            "resources": resources[:20],
            "is_dll": bool(pe.FILE_HEADER.Characteristics & 0x2000),
            "is_dotnet": any(r["type"] == "14" for r in resources),
        }
