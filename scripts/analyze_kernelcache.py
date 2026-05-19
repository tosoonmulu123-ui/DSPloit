#!/usr/bin/env python3
"""
Analyze decompressed iOS kernelcache for DSPloit (physmap / pmap / trust cache).

Usage:
  python scripts/analyze_kernelcache.py
  python scripts/analyze_kernelcache.py path/to/kernelcache.decompressed
  python scripts/analyze_kernelcache.py --trust-cache
  python scripts/analyze_kernelcache.py --emit-swift

Expects Mach-O arm64 kernel (magic 0xFEEDFACF). IM4P must be decompressed first
(DSPloit Settings → Fetch kernelcache, or img4tool).
"""

from __future__ import annotations

import re
import struct
import sys
from collections import Counter
from pathlib import Path

LC_SEGMENT_64 = 0x19
MH_MAGIC_64 = 0xFEEDFACF

SEARCH_STRINGS = [
    "kernel_pmap",
    "kernel_map",
    "zone_map",
    "physmap",
    "trustcache",
    "TrustCache",
    "trust_cache",
    "pmap_cs",
    "AMFI",
    "amfi",
    "ppl",
    "__DATA.__ppl",
    "kernproc",
]

TRUST_CACHE_SYMBOLS = [
    "_query_trust_cache",
    "_query_trust_cache_for_rem",
    "_check_trust_cache_runtime_for_uuid",
    "_check_cdhash_in_trustcache",
    "_load_trust_cache",
    "_load_trust_cache_with_type",
    "_load_legacy_trust_cache",
    "_pmap_lookup_in_loaded_trust_caches",
    "_pmap_lookup_in_static_trust_cache",
    "_static_trust_cache_capabilities",
    "trust_cache_init",
]

DEFAULT_PATHS = [
    "kernelcache.release.iphone11b.decompressed",
    "kernelcache.decompressed",
    "kernelcache",
    "Documents/kernelcache",
]


def find_kernelcache(arg: str | None) -> Path:
    root = Path(__file__).resolve().parents[1]
    if arg and not arg.startswith("-"):
        p = Path(arg)
        if not p.is_file():
            raise SystemExit(f"File not found: {p}")
        return p
    for name in DEFAULT_PATHS:
        p = root / name
        if p.is_file():
            return p
    raise SystemExit(
        "No kernelcache found. Place decompressed Mach-O in repo root or pass path.\n"
        "On device: Settings → Fetch kernelcache (needs jailbreak)."
    )


def parse_macho_segments(data: bytes) -> tuple[int, list[dict]]:
    if len(data) < 32:
        raise ValueError("File too small")
    magic, = struct.unpack_from("<I", data, 0)
    if magic != MH_MAGIC_64:
        raise ValueError(f"Not Mach-O 64 (magic {magic:#x}); decompress kernelcache first")

    _, _, filetype, ncmds, _, _, _ = struct.unpack_from("<IIIIIII", data, 4)
    off = 32
    segments: list[dict] = []
    for _ in range(ncmds):
        if off + 8 > len(data):
            break
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmd == LC_SEGMENT_64 and off + cmdsize <= len(data):
            segname = data[off + 8 : off + 24].split(b"\0")[0].decode(errors="replace")
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", data, off + 24)
            segments.append(
                {
                    "name": segname,
                    "vmaddr": vmaddr,
                    "vmsize": vmsize,
                    "fileoff": fileoff,
                    "filesize": filesize,
                }
            )
        off += cmdsize
    return filetype, segments


def fileoff_to_vmaddr(segments: list[dict], fileoff: int) -> int | None:
    for seg in segments:
        if seg["fileoff"] <= fileoff < seg["fileoff"] + seg["filesize"]:
            return seg["vmaddr"] + (fileoff - seg["fileoff"])
    return None


def search_strings(data: bytes, segments: list[dict]) -> list[dict]:
    hits: list[dict] = []
    for needle in SEARCH_STRINGS:
        b = needle.encode("ascii")
        start = 0
        count = 0
        while count < 8:
            i = data.find(b, start)
            if i < 0:
                break
            va = fileoff_to_vmaddr(segments, i)
            hits.append({"string": needle, "fileoff": i, "unslid_va": va})
            start = i + 1
            count += 1
    return hits


def decode_adrp(insn: int, pc: int) -> int | None:
    if (insn & 0x9F000000) != 0x90000000:
        return None
    immlo = (insn >> 29) & 3
    immhi = (insn >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    if imm & (1 << 20):
        imm -= 1 << 21
    return (pc & ~0xFFF) + (imm << 12)


def decode_add_imm(insn: int) -> tuple[int, int, int] | None:
    if (insn & 0xFF800000) != 0x91000000:
        return None
    imm = (insn >> 10) & 0xFFF
    if (insn >> 22) & 1:
        imm <<= 12
    rn = (insn >> 5) & 0x1F
    rd = insn & 0x1F
    return rn, rd, imm


def scan_adrp_data_refs(
    data: bytes, segments: list[dict], *, pre_ppl_only: bool = False, max_rel: int | None = None
) -> Counter[int]:
    te = next((s for s in segments if s["name"] == "__TEXT_EXEC"), None)
    ds = next((s for s in segments if s["name"] == "__DATA"), None)
    if not te or not ds:
        return Counter()

    tb, db = te["vmaddr"], ds["vmaddr"]
    tstart = te["fileoff"]
    limit = max_rel if max_rel is not None else ds["vmsize"]
    hits: Counter[int] = Counter()

    for i in range(0, te["filesize"] - 8, 4):
        pc = tb + i
        i0, i1 = struct.unpack_from("<II", data, tstart + i)
        page = decode_adrp(i0, pc)
        if page is None:
            continue
        add = decode_add_imm(i1)
        if add is None:
            continue
        rn, rd, imm = add
        if rn != rd:
            continue
        va = page + imm
        if not (db <= va < db + limit):
            continue
        rel = va - db
        if pre_ppl_only and rel >= 0x8000:
            continue
        hits[rel] += 1
    return hits


def trust_cache_symbol_names(data: bytes) -> list[str]:
    found: set[str] = set()
    for pat in TRUST_CACHE_SYMBOLS:
        if data.find(pat.encode()) >= 0:
            found.add(pat)
    for m in re.finditer(rb"_[a-zA-Z0-9_]*trust[a-zA-Z0-9_]*", data):
        s = m.group().decode()
        if 4 < len(s) < 72:
            found.add(s)
    return sorted(found)


def pick_trust_cache_global_offsets(hits: Counter[int]) -> list[int]:
    """Heuristic: few-ref __DATA slots in pre-PPL + pmap_cs band (iphone11b)."""
    out: list[int] = []
    seen: set[int] = set()

    def add(rel: int) -> None:
        if rel not in seen and rel < 0x8000:
            seen.add(rel)
            out.append(rel)

    add(0x45B8)  # pmap_cs_allow_invalid (confirmed ADRP)
    for rel, count in hits.most_common(80):
        if rel >= 0x8000:
            continue
        if count > 80:
            continue
        if rel in (0xE8, 0xF8, 0x248):
            continue
        add(rel)
    for rel in range(0x4000, 0x5000, 8):
        if hits.get(rel, 0) > 0:
            add(rel)
    return out[:48]


def emit_swift_constants(
    text_base: int,
    data_base: int,
    data_off: int,
    pmap_off: int,
    tc_offsets: list[int],
    symbols: list[str],
) -> str:
    off_lines = ", ".join(f"0x{o:x}" for o in tc_offsets)
    sym_lines = "\n".join(f'        "{s}",' for s in symbols[:16])
    return f"""// AUTO-GENERATED by scripts/analyze_kernelcache.py --emit-swift
// Paste into PhysmapConstants or merge trust-cache block.
    static let unslidTextBase: UInt64 = 0x{text_base:x}
    static let unslidDataBase: UInt64 = 0x{data_base:x}
    static let dataOffsetFromText: UInt64 = 0x{data_off:x}
    static let pmapCsAllowInvalidOffsetInData: UInt64 = 0x{pmap_off:x}
    static let trustCacheGlobalOffsetsInData: [UInt64] = [{off_lines}]
    // XPF names to try at runtime (ds_xpf_resolve_runtime):
{sym_lines}
"""


def run_trust_cache_report(data: bytes, segments: list[dict]) -> None:
    ds = next(s for s in segments if s["name"] == "__DATA")
    te = next(s for s in segments if s["name"] == "__TEXT_EXEC")
    text_base = next((s["vmaddr"] for s in segments if s["name"] == "__TEXT"), 0)
    data_base = ds["vmaddr"]
    data_off = data_base - text_base

    print("=== Trust cache / AMFI (kernelcache) ===\n")
    symbols = trust_cache_symbol_names(data)
    print(f"Symbol names found ({len(symbols)}):")
    for s in symbols[:20]:
        print(f"  {s}")
    if len(symbols) > 20:
        print(f"  ... +{len(symbols) - 20} more")

    hits = scan_adrp_data_refs(data, segments, pre_ppl_only=True)
    print("\n--- __DATA pre-PPL: ADRP+ADD targets (top 20) ---")
    for rel, c in hits.most_common(20):
        print(f"  __DATA+0x{rel:x}  ({c} code refs)")

    tc_offs = pick_trust_cache_global_offsets(hits)
    print("\n--- Suggested trustCacheGlobalOffsetsInData ---")
    for o in tc_offs:
        print(f"  0x{o:x}")

    print("\n--- Swift snippet ---")
    print(
        emit_swift_constants(
            text_base, data_base, data_off, 0x45B8, tc_offs, symbols
        )
    )

    print("\n--- Runtime (on device) ---")
    print("1. Fetch kernelcache in DSPloit Settings (same IPSW as boot).")
    print("2. Exp 77 uses offsets above + ds_xpf_resolve_runtime(symbol).")
    print("3. Do NOT KRW-read __DATA.__ppl_data (+0x8000) — PPL panic.")


def main() -> None:
    argv = sys.argv[1:]
    emit_swift = "--emit-swift" in argv
    trust_only = "--trust-cache" in argv
    path_arg = next((a for a in argv if not a.startswith("-")), None)

    path = find_kernelcache(path_arg)
    data = path.read_bytes()

    if trust_only or emit_swift:
        _, segments = parse_macho_segments(data)
        run_trust_cache_report(data, segments)
        return

    print("=== DSPloit kernelcache analysis ===")
    print(f"File: {path} ({len(data) / 1024 / 1024:.1f} MiB)\n")

    filetype, segments = parse_macho_segments(data)
    print(f"Mach-O filetype: {filetype} (12 = MH_FILESET for modern kernels)")
    print("\n--- Segments (unslid VA) ---")
    text_base = None
    data_base = None
    for s in segments:
        print(
            f"  {s['name']:16} vm=0x{s['vmaddr']:016x} "
            f"size=0x{s['vmsize']:x} fileoff=0x{s['fileoff']:x}"
        )
        if s["name"] == "__TEXT":
            text_base = s["vmaddr"]
        if s["name"] == "__DATA":
            data_base = s["vmaddr"]

    if text_base:
        print(f"\nUnslid kernel __TEXT base (KASLR slide 0): 0x{text_base:x}")
        print("On device: kernel_base = __TEXT_base + slide (see panic log KernelCache slide)")

    if text_base and data_base:
        off = data_base - text_base
        print(f"__DATA base (unslid): 0x{data_base:x}")
        print(f"__DATA.__ppl_data (unslid +0x8000): 0x{data_base + 0x8000:x}")
        print(f"Offset __DATA - __TEXT = 0x{off:x}  (PhysmapConstants.dataOffsetFromText)")

    print("\n--- String hits (file offset -> unslid VA if mappable) ---")
    for h in search_strings(data, segments):
        va = h["unslid_va"]
        vas = f"0x{va:x}" if va is not None else "(not in segment)"
        print(f"  {h['string']!r:20} fileoff=0x{h['fileoff']:x}  unslid={vas}")

    print("\n--- Trust cache globals (ADRP scan, pre-PPL) ---")
    hits = scan_adrp_data_refs(data, segments, pre_ppl_only=True)
    for rel, c in hits.most_common(12):
        print(f"  __DATA+0x{rel:x}  ({c} refs)")

    print("\nRun: python scripts/analyze_kernelcache.py --trust-cache")
    print("     python scripts/analyze_kernelcache.py --emit-swift")


if __name__ == "__main__":
    main()
