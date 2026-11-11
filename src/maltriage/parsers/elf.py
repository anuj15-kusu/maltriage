"""ELF parser built on pyelftools."""

from __future__ import annotations

import io

from maltriage.models import FileKind, SampleContext
from maltriage.parsers.base import register_parser
from maltriage.strings import shannon_entropy


@register_parser
class ELFParser:
    name = "elf"
    kinds = {FileKind.ELF}

    def parse(self, ctx: SampleContext) -> None:
        from elftools.elf.elffile import ELFFile

        try:
            elf = ELFFile(io.BytesIO(ctx.read()))
        except Exception as exc:
            ctx.add_error(f"elf parse failed: {exc}")
            return

        sections = []
        for section in elf.iter_sections():
            try:
                raw = section.data() if section["sh_type"] != "SHT_NOBITS" else b""
            except Exception:
                raw = b""
            sections.append(
                {
                    "name": section.name,
                    "size": int(section["sh_size"]),
                    "entropy": round(shannon_entropy(raw), 2) if raw else 0.0,
                    "executable": bool(section["sh_flags"] & 0x4),
                    "writable": bool(section["sh_flags"] & 0x1),
                }
            )

        needed: list[str] = []
        rpath: list[str] = []
        try:
            dynamic = elf.get_section_by_name(".dynamic")
            if dynamic is not None:
                for tag in dynamic.iter_tags():
                    if tag.entry.d_tag == "DT_NEEDED":
                        needed.append(tag.needed)
                    elif tag.entry.d_tag in ("DT_RPATH", "DT_RUNPATH"):
                        rpath.append(getattr(tag, "rpath", ""))
        except Exception:
            pass

        header = elf.header
        ctx.parsed["elf"] = {
            "class": header["e_ident"]["EI_CLASS"],
            "type": header["e_type"],
            "machine": header["e_machine"],
            "entrypoint": hex(int(header["e_entry"])),
            "sections": sections,
            "needed": needed,
            "rpath": [r for r in rpath if r],
        }
