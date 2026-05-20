#!/usr/bin/env python3
"""
Analyze decompressed iOS kernelcache for DSPloit (physmap / pmap / trust cache).

Usage:
  python scripts/analyze_kernelcache.py
  python scripts/analyze_kernelcache.py path/to/kernelcache.decompressed
  python scripts/analyze_kernelcache.py --trust-cache
  python scripts/analyze_kernelcache.py --deep-probe        ← NEW: baca isi slot + cari TC struct
  python scripts/analyze_kernelcache.py --emit-swift
  python scripts/analyze_kernelcache.py --emit-json

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


# ---------------------------------------------------------------------------
# Deep probe: baca isi __DATA slots dari file kernelcache, ikuti pointer,
# cari trust cache struct berdasarkan layout iOS 18.
# ---------------------------------------------------------------------------

def va_to_fileoff(segments: list[dict], va: int) -> int | None:
    """Convert unslid VA → file offset."""
    for seg in segments:
        if seg["vmaddr"] <= va < seg["vmaddr"] + seg["vmsize"]:
            rel = va - seg["vmaddr"]
            if rel < seg["filesize"]:
                return seg["fileoff"] + rel
    return None


def read_u32(data: bytes, foff: int) -> int:
    if foff + 4 > len(data):
        return 0
    return struct.unpack_from("<I", data, foff)[0]


def read_u64(data: bytes, foff: int) -> int:
    if foff + 8 > len(data):
        return 0
    return struct.unpack_from("<Q", data, foff)[0]


def strip_pac(v: int) -> int:
    """Strip ARM64 PAC bits — kernel pointers biasanya 0xfffffff0… atau 0xffffff80…"""
    if v == 0:
        return 0
    # Jika bit 55 set (PAC), sign-extend dari bit 47
    if (v >> 55) & 1:
        return v | 0xFFFF000000000000
    return v


def is_kernel_va(v: int) -> bool:
    v = strip_pac(v)
    return v >= 0xFFFFFF8000000000 or (0xFFFFFFF000000000 <= v <= 0xFFFFFFFFFFFFFFFF)


def has_cdhash_entropy(data: bytes, foff: int) -> bool:
    """
    CDHash (20 bytes) harus punya entropy tinggi — bukan angka kecil.
    Minimal 12 dari 20 bytes harus non-zero, dan setidaknya 1 byte > 0x0F.
    """
    if foff + 20 > len(data):
        return False
    raw = data[foff:foff + 20]
    nonzero = sum(1 for b in raw if b != 0)
    high = sum(1 for b in raw if b > 0x0F)
    return nonzero >= 12 and high >= 4


def check_trust_cache_struct(data: bytes, foff: int, label: str, segments: list[dict]) -> dict | None:
    """
    Cek apakah data di foff adalah trust cache struct iOS 18.

    Layout yang dicoba:
      Format A (inline, version di +0):
        +0x00: uint32 version (1–16)
        +0x04: uint32 count (5–200000)
        +0x08: entries[0] mulai di sini

      Format B (dengan header 8 byte sebelum version):
        +0x00: uint64 header/pointer
        +0x08: uint32 version
        +0x0C: uint32 count
        +0x10: entries[0]

    Entry layout (24 bytes, iOS 18):
        [0..19]  CDHash (20 bytes)
        [20]     hashType (0–4)
        [21]     flags
        [22..23] pad
    """
    if foff + 64 > len(data):
        return None

    results = []

    for hdr_off in [0, 8, 0x10]:
        ver = read_u32(data, foff + hdr_off)
        cnt = read_u32(data, foff + hdr_off + 4)

        if not (1 <= ver <= 16):
            continue
        if not (5 <= cnt <= 200_000):
            continue

        entries_foff = foff + hdr_off + 8

        # Coba stride 24 dan 32
        for stride in [24, 32]:
            if entries_foff + stride * min(cnt, 3) > len(data):
                continue

            # Cek 3 entry pertama
            valid_entries = 0
            entry_samples = []
            for i in range(min(cnt, 5)):
                ef = entries_foff + i * stride
                if ef + 24 > len(data):
                    break
                if has_cdhash_entropy(data, ef):
                    valid_entries += 1
                    if len(entry_samples) < 3:
                        cdhash = data[ef:ef + 20].hex()
                        hash_type = data[ef + 20] if ef + 20 < len(data) else 0
                        entry_samples.append({
                            "index": i,
                            "cdhash": cdhash,
                            "hashType": hash_type,
                        })

            if valid_entries >= min(cnt, 2):
                results.append({
                    "label": label,
                    "fileoff": foff,
                    "hdr_offset": hdr_off,
                    "version": ver,
                    "count": cnt,
                    "stride": stride,
                    "entries_fileoff": entries_foff,
                    "valid_entries_checked": valid_entries,
                    "entry_samples": entry_samples,
                })

    return results[0] if results else None


def deep_probe_trust_cache(data: bytes, segments: list[dict]) -> None:
    """
    Deep probe: untuk setiap slot __DATA dari ADRP scan,
    baca nilai di file kernelcache dan cek apakah itu trust cache struct.
    """
    ds = next((s for s in segments if s["name"] == "__DATA"), None)
    text_seg = next((s for s in segments if s["name"] == "__TEXT"), None)
    if not ds or not text_seg:
        print("ERROR: __DATA atau __TEXT segment tidak ditemukan")
        return

    data_base = ds["vmaddr"]
    data_foff = ds["fileoff"]
    text_base = text_seg["vmaddr"]
    ppl_data_va = data_base + 0x8000  # jangan baca ini

    hits = scan_adrp_data_refs(data, segments, pre_ppl_only=True)
    tc_offsets = pick_trust_cache_global_offsets(hits)

    print("=== Deep Probe: Trust Cache Struct Analysis ===\n")
    print(f"__DATA base (unslid): 0x{data_base:x}")
    print(f"__DATA fileoff:       0x{data_foff:x}")
    print(f"__DATA.__ppl_data:    0x{ppl_data_va:x} (SKIP — PPL panic on device)")
    print(f"Probing {len(tc_offsets)} ADRP slots...\n")

    found_structs = []

    for rel_off in tc_offsets:
        slot_va = data_base + rel_off
        if slot_va >= ppl_data_va:
            continue  # skip PPL region

        slot_foff = data_foff + rel_off
        if slot_foff + 8 > len(data):
            continue

        label = f"kc+0x{rel_off:x}"

        # --- Cek 1: inline struct di slot itu sendiri ---
        result = check_trust_cache_struct(data, slot_foff, f"{label}@inline", segments)
        if result:
            found_structs.append(result)
            print(f"  ✅ INLINE: {label}")
            print(f"     version={result['version']}, count={result['count']}, stride={result['stride']}")
            for e in result['entry_samples']:
                print(f"     entry[{e['index']}]: {e['cdhash'][:40]}... hashType={e['hashType']}")
            print()
            continue

        # --- Cek 2: slot berisi pointer ke struct lain ---
        raw_val = read_u64(data, slot_foff)
        ptr = strip_pac(raw_val)

        if not is_kernel_va(ptr) or ptr == 0:
            continue

        # Coba resolve pointer ke file offset
        ptr_foff = va_to_fileoff(segments, ptr)
        if ptr_foff is None:
            # Pointer ke luar segment yang dikenal (heap saat runtime — tidak bisa dicek offline)
            # Tapi catat untuk info
            if ptr >= 0xFFFFFF8000000000:
                print(f"  ℹ️  {label}: ptr=0x{ptr:x} → luar kernelcache (heap runtime, tidak bisa dicek offline)")
            continue

        # Cek apakah pointer mengarah ke trust cache struct
        result = check_trust_cache_struct(data, ptr_foff, f"{label}→ptr", segments)
        if result:
            found_structs.append(result)
            print(f"  ✅ VIA POINTER: {label} → 0x{ptr:x} (foff=0x{ptr_foff:x})")
            print(f"     version={result['version']}, count={result['count']}, stride={result['stride']}")
            for e in result['entry_samples']:
                print(f"     entry[{e['index']}]: {e['cdhash'][:40]}... hashType={e['hashType']}")
            print()
        else:
            # Ikuti satu level lagi (pointer ke pointer)
            inner_raw = read_u64(data, ptr_foff)
            inner_ptr = strip_pac(inner_raw)
            if is_kernel_va(inner_ptr) and inner_ptr != ptr:
                inner_foff = va_to_fileoff(segments, inner_ptr)
                if inner_foff is not None:
                    result2 = check_trust_cache_struct(data, inner_foff, f"{label}→ptr→ptr", segments)
                    if result2:
                        found_structs.append(result2)
                        print(f"  ✅ VIA 2x POINTER: {label} → 0x{ptr:x} → 0x{inner_ptr:x}")
                        print(f"     version={result2['version']}, count={result2['count']}, stride={result2['stride']}")
                        for e in result2['entry_samples']:
                            print(f"     entry[{e['index']}]: {e['cdhash'][:40]}... hashType={e['hashType']}")
                        print()

    # --- Summary ---
    print("\n" + "=" * 60)
    if found_structs:
        print(f"✅ DITEMUKAN {len(found_structs)} trust cache struct kandidat:\n")
        for s in found_structs:
            print(f"  {s['label']}")
            print(f"    fileoff=0x{s['fileoff']:x}, hdr_off=+0x{s['hdr_offset']:x}")
            print(f"    version={s['version']}, count={s['count']}, stride={s['stride']}")
            # Hitung unslid VA
            va = fileoff_to_vmaddr(segments, s['fileoff'])
            if va:
                print(f"    unslid VA: 0x{va:x}")
                print(f"    slid VA (contoh slide=0x7598000): 0x{va + 0x7598000:x}")
            print()

        print("\n--- Swift: trustCacheHeaderAt hdr_offset yang benar ---")
        hdr_offsets = sorted(set(s['hdr_offset'] for s in found_structs))
        print(f"  Coba headerOff: {[hex(o) for o in hdr_offsets]}")

        print("\n--- Swift: entry stride yang benar ---")
        strides = sorted(set(s['stride'] for s in found_structs))
        print(f"  Stride: {strides} bytes per entry")

        print("\n--- Rekomendasi update Swift ---")
        best = found_structs[0]
        print(f"  1. trustCacheHeaderAt: coba hdr_off=[{', '.join(hex(o) for o in hdr_offsets)}]")
        print(f"  2. Entry stride: {best['stride']} bytes")
        print(f"  3. CDHash entropy check: bytes 0..19 harus non-trivial")
        print(f"  4. hashType di offset +20 dari entry start")

    else:
        print("❌ Tidak ada trust cache struct ditemukan di kernelcache (offline).")
        print()
        print("Kemungkinan:")
        print("  1. Trust cache diisi saat boot (runtime heap) — tidak ada di file kernelcache")
        print("  2. Struct ada di fileset component lain (AMFI kext, dll)")
        print("  3. Format iOS 18 berbeda dari yang kita cek")
        print()
        print("Coba: python scripts/analyze_kernelcache.py --fileset-probe")
        print("      untuk scan semua fileset components")

    # --- Scan fileset components juga ---
    print("\n" + "=" * 60)
    print("=== Fileset component scan ===\n")
    _scan_fileset_components(data, segments)

    # --- Analisis slot content ---
    run_slot_content_analysis(data, segments)

    # --- Analisis load_trust_cache ---
    analyze_load_trust_cache(data, segments)
    analyze_trust_cache_init(data, segments)


LC_FILESET_ENTRY = 0x80000035


def _scan_fileset_components(data: bytes, segments: list[dict]) -> None:
    """Scan semua LC_FILESET_ENTRY untuk cari trust cache struct di AMFI/trustcache kext."""
    if len(data) < 32:
        return
    magic, = struct.unpack_from("<I", data, 0)
    if magic != MH_MAGIC_64:
        return

    _, _, filetype, ncmds, _, _, _ = struct.unpack_from("<IIIIIII", data, 4)
    if filetype != 12:  # MH_FILESET
        print("  Bukan MH_FILESET — skip fileset scan")
        return

    off = 32
    components = []
    for _ in range(ncmds):
        if off + 8 > len(data):
            break
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmd == LC_FILESET_ENTRY and off + cmdsize <= len(data):
            vmaddr, fileoff = struct.unpack_from("<QQ", data, off + 8)
            name_off = struct.unpack_from("<I", data, off + 24)[0]
            name_abs = off + name_off
            name = b""
            while name_abs < len(data) and data[name_abs] != 0:
                name += bytes([data[name_abs]])
                name_abs += 1
            components.append({
                "name": name.decode(errors="replace"),
                "vmaddr": vmaddr,
                "fileoff": fileoff,
            })
        off += cmdsize

    trust_related = [c for c in components if any(
        kw in c["name"].lower() for kw in ["amfi", "trust", "coretrust", "security"]
    )]

    print(f"  Total fileset components: {len(components)}")
    print(f"  Trust-related: {len(trust_related)}")
    for comp in trust_related:
        print(f"\n  Component: {comp['name']}")
        print(f"    vmaddr=0x{comp['vmaddr']:x}, fileoff=0x{comp['fileoff']:x}")

        # Parse segments dari component ini
        comp_segs = []
        comp_off = comp["fileoff"]
        if comp_off + 32 > len(data):
            continue
        comp_magic, = struct.unpack_from("<I", data, comp_off)
        if comp_magic != MH_MAGIC_64:
            print(f"    (bukan Mach-O di fileoff 0x{comp_off:x})")
            continue

        _, _, _, comp_ncmds, _, _, _ = struct.unpack_from("<IIIIIII", data, comp_off + 4)
        lc_off = comp_off + 32
        for _ in range(comp_ncmds):
            if lc_off + 8 > len(data):
                break
            lc_cmd, lc_size = struct.unpack_from("<II", data, lc_off)
            if lc_cmd == LC_SEGMENT_64 and lc_off + lc_size <= len(data):
                segname = data[lc_off + 8:lc_off + 24].split(b"\0")[0].decode(errors="replace")
                vmaddr, vmsize, seg_fileoff, seg_filesize = struct.unpack_from("<QQQQ", data, lc_off + 24)
                comp_segs.append({
                    "name": segname,
                    "vmaddr": vmaddr,
                    "vmsize": vmsize,
                    "fileoff": seg_fileoff,
                    "filesize": seg_filesize,
                })
                print(f"    seg {segname:16} vm=0x{vmaddr:x} size=0x{vmsize:x} foff=0x{seg_fileoff:x}")
            lc_off += lc_size

        # Scan __DATA segment dari component ini untuk trust cache struct
        comp_data_seg = next((s for s in comp_segs if s["name"] == "__DATA"), None)
        if comp_data_seg:
            print(f"    Scanning __DATA (0x{comp_data_seg['fileoff']:x}, size=0x{comp_data_seg['filesize']:x})...")
            found_in_comp = 0
            for scan_off in range(0, min(comp_data_seg["filesize"], 0x10000), 8):
                foff = comp_data_seg["fileoff"] + scan_off
                result = check_trust_cache_struct(data, foff, f"{comp['name']}+0x{scan_off:x}", [])
                if result:
                    va = comp_data_seg["vmaddr"] + scan_off
                    print(f"    ✅ TC struct at __DATA+0x{scan_off:x} (VA=0x{va:x})")
                    print(f"       version={result['version']}, count={result['count']}, stride={result['stride']}")
                    for e in result['entry_samples'][:2]:
                        print(f"       entry[{e['index']}]: {e['cdhash'][:40]}... hashType={e['hashType']}")
                    found_in_comp += 1
                    if found_in_comp >= 3:
                        break
            if found_in_comp == 0:
                print(f"    (tidak ada TC struct inline di __DATA component ini)")


def analyze_trust_cache_init(data: bytes, segments: list[dict]) -> None:
    """
    Trace fungsi trust_cache_init: cari ADRP+STR pattern untuk tahu
    slot __DATA mana yang diisi pertama kali saat boot.
    Ini adalah slot yang PALING PENTING untuk probe on-device.
    """
    te = next((s for s in segments if s["name"] == "__TEXT_EXEC"), None)
    ds = next((s for s in segments if s["name"] == "__DATA"), None)
    text_seg = next((s for s in segments if s["name"] == "__TEXT"), None)
    if not te or not ds or not text_seg:
        return

    data_base = ds["vmaddr"]
    text_base = text_seg["vmaddr"]

    print("\n=== Trace trust_cache_init: slot __DATA yang diisi saat boot ===\n")

    # Cari string "trust_cache_init" untuk locate fungsi
    init_str_foff = data.find(b"trust_cache_init\x00")
    if init_str_foff < 0:
        print("  String 'trust_cache_init' tidak ditemukan")
        return

    init_str_va = fileoff_to_vmaddr(segments, init_str_foff)
    print(f"  'trust_cache_init' string VA: 0x{init_str_va:x}")

    # Scan __TEXT_EXEC untuk ADRP+STR pattern yang menulis ke __DATA
    # Pola: ADRP Xn, page; ADD Xn, Xn, #off; STR Xm, [Xn] atau STR Xm, [Xn, #0]
    # Ini adalah pola "store pointer ke global __DATA"
    tstart = te["fileoff"]
    tb = te["vmaddr"]
    db = ds["vmaddr"]
    ppl_data_va = db + 0x8000

    store_to_data: list[tuple[int, int, int]] = []  # (pc, data_rel, insn_foff)

    for i in range(0, te["filesize"] - 12, 4):
        pc = tb + i
        foff = tstart + i
        if foff + 12 > len(data):
            break

        i0 = read_u32(data, foff)
        i1 = read_u32(data, foff + 4)
        i2 = read_u32(data, foff + 8)

        # ADRP
        page = decode_adrp(i0, pc)
        if page is None:
            continue

        # ADD (same reg)
        add = decode_add_imm(i1)
        if add is None:
            continue
        rn, rd, imm = add
        if rn != rd:
            continue

        va = page + imm
        if not (db <= va < ppl_data_va):
            continue

        rel = va - db

        # Cek instruksi ke-3: STR Xm, [Xn] atau STR Xm, [Xn, #0]
        # STR 64-bit: 0xF9000000 | (imm12 << 10) | (Rn << 5) | Rt
        # Untuk STR [Xn, #0]: imm12=0, Rn=rd
        if (i2 & 0xFFC003E0) == (0xF9000000 | (rd << 5)):
            store_to_data.append((pc, rel, foff))

    print(f"  Ditemukan {len(store_to_data)} STR ke __DATA pre-PPL\n")

    # Group by data_rel dan tampilkan yang paling sering
    rel_counter: Counter[int] = Counter(rel for _, rel, _ in store_to_data)
    print("  Top slots yang di-STR (kemungkinan trust cache globals):")
    for rel, cnt in rel_counter.most_common(20):
        # Cek apakah slot ini ada di ADRP hits kita
        hits = scan_adrp_data_refs(data, segments, pre_ppl_only=True)
        adrp_cnt = hits.get(rel, 0)
        print(f"    __DATA+0x{rel:04x}: {cnt} STR, {adrp_cnt} ADRP refs")

    # Cari STR yang dekat dengan trust_cache_init string (dalam 4KB)
    if init_str_va:
        print(f"\n  STR ke __DATA dalam 4KB dari trust_cache_init string (VA 0x{init_str_va:x}):")
        for pc, rel, foff in store_to_data:
            if abs(pc - init_str_va) < 0x4000:
                print(f"    PC=0x{pc:x} → __DATA+0x{rel:x}")


def analyze_load_trust_cache(data: bytes, segments: list[dict]) -> None:
    """
    Cari fungsi _load_trust_cache / trust_cache_init di __TEXT_EXEC dan
    analisis instruksi untuk menemukan struct layout yang dipakai.
    Fokus: cari STR/LDR ke offset dari struct pointer (x0/x1).
    """
    te = next((s for s in segments if s["name"] == "__TEXT_EXEC"), None)
    if not te:
        return

    # Cari string "_load_trust_cache" di __TEXT untuk dapat alamat
    text_seg = next((s for s in segments if s["name"] == "__TEXT"), None)
    if not text_seg:
        return

    print("\n=== Analisis _load_trust_cache / trust_cache_init ===\n")

    # Cari symtab untuk resolve alamat fungsi
    # Scan __TEXT_EXEC untuk pola: BL ke fungsi yang namanya mengandung "trust_cache"
    # Pendekatan: cari string "trust_cache" di __TEXT, lalu cari ADRP yang mereferensikannya

    # Cari semua string trust_cache di kernelcache
    tc_strings = []
    for needle in [b"_load_trust_cache\x00", b"trust_cache_init\x00", b"_static_trust_cache\x00"]:
        pos = 0
        while True:
            idx = data.find(needle, pos)
            if idx < 0:
                break
            va = fileoff_to_vmaddr(segments, idx)
            tc_strings.append((needle.decode().strip('\x00'), idx, va))
            pos = idx + 1

    for name, foff, va in tc_strings[:5]:
        va_str = f"0x{va:x}" if va else "N/A"
        print(f"  String '{name}': fileoff=0x{foff:x}, VA={va_str}")

    # Scan __TEXT_EXEC untuk instruksi yang mengakses struct dengan offset kecil
    # Pola: LDR/STR Xn, [Xm, #offset] — offset kecil (< 0x100) = struct field access
    print("\n  Scanning __TEXT_EXEC untuk struct field access patterns...")
    print("  (LDR/STR dengan offset 0–0x80 dari register — kemungkinan trust cache struct fields)\n")

    field_accesses: Counter[int] = Counter()
    tstart = te["fileoff"]

    for i in range(0, min(te["filesize"] - 4, 0x200000), 4):
        insn = read_u32(data, tstart + i)
        # LDR/STR 64-bit: 0xF9400000 (LDR) / 0xF9000000 (STR)
        # Format: size(2) V(1) 00 opc(2) 1 imm12(12) Rn(5) Rt(5)
        if (insn & 0xFFC00000) in (0xF9400000, 0xF9000000, 0xB9400000, 0xB9000000):
            imm12 = (insn >> 10) & 0xFFF
            size = (insn >> 30) & 3
            offset = imm12 << size
            if 0 < offset <= 0x80:
                field_accesses[offset] += 1

    print("  Top struct field offsets (kemungkinan trust cache struct):")
    for off, cnt in field_accesses.most_common(20):
        print(f"    +0x{off:02x}: {cnt} akses")

    # Analisis khusus: cari pola yang cocok dengan trust cache struct
    # iOS 18 trust_cache_t kemungkinan:
    # +0x00: version (uint32)
    # +0x04: count (uint32)
    # +0x08: entries pointer atau inline
    # +0x10: next pointer (linked list)
    # +0x18: UUID (16 bytes)
    print("\n  Kemungkinan layout trust_cache_t iOS 18:")
    print("    +0x00: uint32 version")
    print("    +0x04: uint32 count")
    print("    +0x08: entries[] (inline atau pointer)")
    print("    +0x10: *next (linked list ke trust cache berikutnya)")
    print("    +0x18: uuid[16]")
    print("    +0x28: entries[0] mulai (jika ada UUID)")
    print()
    print("  Atau format 'TCType2' (iOS 16+):")
    print("    +0x00: uint64 header (type | flags)")
    print("    +0x08: uint32 version")
    print("    +0x0C: uint32 count")
    print("    +0x10: uuid[16]")
    print("    +0x20: entries[0]")


def run_slot_content_analysis(data: bytes, segments: list[dict]) -> None:
    """
    Tampilkan isi (nilai statis) dari setiap __DATA slot yang diidentifikasi ADRP.
    Ini membantu debug: slot mana yang 0 (runtime heap pointer) vs non-zero (static data).
    """
    ds = next((s for s in segments if s["name"] == "__DATA"), None)
    if not ds:
        return

    data_base = ds["vmaddr"]
    data_foff = ds["fileoff"]
    ppl_data_va = data_base + 0x8000

    hits = scan_adrp_data_refs(data, segments, pre_ppl_only=True)
    tc_offsets = pick_trust_cache_global_offsets(hits)

    print("\n=== Isi slot __DATA (nilai statis di kernelcache) ===\n")
    print(f"{'Slot':20} {'Raw value (unslid)':20} {'Keterangan'}")
    print("-" * 70)

    for rel_off in tc_offsets[:32]:
        slot_va = data_base + rel_off
        if slot_va >= ppl_data_va:
            continue
        slot_foff = data_foff + rel_off
        if slot_foff + 8 > len(data):
            continue

        raw = read_u64(data, slot_foff)
        ptr = strip_pac(raw)

        if raw == 0:
            note = "0 (runtime heap pointer — diisi saat boot)"
        elif is_kernel_va(ptr):
            ptr_foff = va_to_fileoff(segments, ptr)
            if ptr_foff is not None:
                note = f"→ 0x{ptr:x} (dalam kernelcache, foff=0x{ptr_foff:x})"
            else:
                note = f"→ 0x{ptr:x} (luar kernelcache — runtime heap)"
        elif raw < 0x10000:
            note = f"integer kecil ({raw}) — bukan pointer"
        else:
            note = f"0x{raw:x} — unknown"

        print(f"  kc+0x{rel_off:<6x}  0x{raw:016x}  {note}")


def emit_json(path: Path, segments: list[dict], tc_offs: list[int]) -> None:
    import json

    text_base = next((s["vmaddr"] for s in segments if s["name"] == "__TEXT"), 0)
    data_base = next((s["vmaddr"] for s in segments if s["name"] == "__DATA"), 0)
    out = {
        "source": str(path.name),
        "dataOffsetFromText": data_base - text_base if text_base and data_base else 0,
        "trustCacheGlobalOffsetsInData": [f"0x{o:x}" for o in tc_offs],
    }
    out_path = path.parent / "trust_cache_slots.json"
    out_path.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(f"\nWrote {out_path}")
    print("Copy to iPhone with kernelcache or rely on on-device ADRP scan after Import.")


def main() -> None:
    argv = sys.argv[1:]
    emit_swift = "--emit-swift" in argv
    emit_json_flag = "--emit-json" in argv
    trust_only = "--trust-cache" in argv
    deep_probe = "--deep-probe" in argv
    path_arg = next((a for a in argv if not a.startswith("-")), None)

    path = find_kernelcache(path_arg)
    data = path.read_bytes()

    _, segments = parse_macho_segments(data)

    if deep_probe:
        deep_probe_trust_cache(data, segments)
        return

    if trust_only or emit_swift or emit_json_flag:
        if emit_json_flag:
            hits = scan_adrp_data_refs(data, segments, pre_ppl_only=True)
            tc_offs = pick_trust_cache_global_offsets(hits)
            emit_json(path, segments, tc_offs)
        if trust_only or emit_swift:
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
