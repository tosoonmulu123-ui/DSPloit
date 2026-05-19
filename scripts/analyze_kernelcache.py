#!/usr/bin/env python3
"""
Analyze decompressed iOS kernelcache for DSPloit (physmap / pmap / trust cache).

Usage:
  python scripts/analyze_kernelcache.py
  python scripts/analyze_kernelcache.py path/to/kernelcache.decompressed

Expects Mach-O arm64 kernel (magic 0xFEEDFACF). IM4P must be decompressed first
(DSPloit Settings → Fetch kernelcache, or img4tool).

Output: unslid segment map, string hits, optional pointer scan for kernel_pmap.
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

LC_SEGMENT_64 = 0x19
MH_MAGIC_64 = 0xFEEDFACF

# Strings useful for AMFI Lab / Exp 74–77
SEARCH_STRINGS = [
    "kernel_pmap",
    "kernel_map",
    "zone_map",
    "physmap",
    "trustcache",
    "TrustCache",
    "pmap_cs",
    "AMFI",
    "amfi",
    "ppl",
    "__DATA.__ppl",
    "kernproc",
]

DEFAULT_PATHS = [
    "kernelcache.release.iphone11b.decompressed",
    "kernelcache.decompressed",
    "kernelcache",
    "Documents/kernelcache",
]


def find_kernelcache(arg: str | None) -> Path:
    root = Path(__file__).resolve().parents[1]
    if arg:
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


def scan_kernel_pmap_ptr(data: bytes, segments: list[dict], unslid_text: int) -> list[dict]:
    """Find 8-byte pointers in __DATA that look like kernel_pmap (heuristic)."""
    results: list[dict] = []
    data_segs = [s for s in segments if s["name"] in ("__DATA", "__DATA_CONST", "__DATA.__ppl")]
    if not data_segs:
        data_segs = [s for s in segments if "DATA" in s["name"]]

    for seg in data_segs:
        start = seg["fileoff"]
        end = min(len(data), start + min(seg["filesize"], 0x400000))
        for off in range(start, end - 8, 8):
            ptr, = struct.unpack_from("<Q", data, off)
            # Kernel heap / zone-ish pointers (not __TEXT)
            if 0xFFFFFFDC00000000 <= ptr < 0xFFFFFFE600000000:
                va = seg["vmaddr"] + (off - seg["fileoff"])
                results.append({"field_va": va, "ptr": ptr})
                if len(results) >= 40:
                    return results
    return results


def main() -> None:
    arg = sys.argv[1] if len(sys.argv) > 1 else None
    path = find_kernelcache(arg)
    data = path.read_bytes()
    print(f"=== DSPloit kernelcache analysis ===")
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

    print("\n--- Heuristic: zone-range pointers in __DATA (first 15) ---")
    ptrs = scan_kernel_pmap_ptr(data, segments, text_base or 0)
    for p in ptrs[:15]:
        print(f"  *0x{p['field_va']:x} -> 0x{p['ptr']:x}")

    print("\n--- How this helps DSPloit ---")
    print("1. App already uses XPF/ChOma at runtime (init_offsets) - same kernelcache in Documents.")
    print("2. Use unslid VA + slide from panic to locate __DATA.__ppl_data on your boot.")
    print("3. kernel_pmap / zone_map strings - cross-check with KRW pointer chains in AMFI Lab.")
    print("4. Do NOT brute-force 385 gVirt values on device — zone_map band ~0xffffffdc..0xe2.")
    print("\nRun on Mac/Linux/Windows with Python 3.9+.")


if __name__ == "__main__":
    main()
