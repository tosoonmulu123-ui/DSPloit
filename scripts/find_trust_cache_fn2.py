#!/usr/bin/env python3
"""
find_trust_cache_fn2.py — cari trust_cache_runtime_add dari iOS release kernelcache
tanpa symtab, menggunakan ARM64 pattern matching + string xref + write-to-DATA heuristic.

Usage:
  python3 scripts/find_trust_cache_fn2.py kernelcache
  python3 scripts/find_trust_cache_fn2.py kernelcache 0xfffffff007004000
"""

import sys
import struct
from pathlib import Path

# ─── ARM64 Decoder ────────────────────────────────────────────────────────

def decode_adrp(insn, pc):
    if (insn & 0x9F000000) != 0x90000000:
        return None
    immlo = (insn >> 29) & 0x3
    immhi = (insn >> 5) & 0x7FFFF
    imm = ((immhi << 2) | immlo) << 12
    if imm & (1 << 32):
        imm -= (1 << 33)
    return (pc & ~0xFFF) + imm

def decode_add_imm(insn):
    if (insn & 0xFFC00000) != 0x91000000:
        return None
    shift = (insn >> 22) & 0x3
    imm12 = (insn >> 10) & 0xFFF
    return imm12 << (12 if shift == 1 else 0)

def decode_bl(insn, pc):
    if (insn & 0xFC000000) != 0x94000000:
        return None
    imm26 = insn & 0x3FFFFFF
    if imm26 & (1 << 25):
        imm26 -= (1 << 26)
    return pc + imm26 * 4

def is_function_prologue(insn):
    # STP x29, x30, [sp, #-N]!
    if (insn & 0xFFC07FFF) == 0xA9BF7BFD:
        return True
    # SUB sp, sp, #imm
    if (insn & 0xFFC003FF) == 0xD10003FF:
        return True
    # PACIBSP
    if insn == 0xD503235F:
        return True
    # STP x29, x30, [sp, #0] (non-pre-index variant)
    if (insn & 0xFFC07FFF) == 0xA9007BFD:
        return True
    return False

# ─── Mach-O Parser ────────────────────────────────────────────────────────

LC_SEGMENT_64    = 0x19
LC_FILESET_ENTRY = 0x80000035
MH_MAGIC_64      = 0xFEEDFACF

def parse_segments(data, off=0):
    if len(data) < off + 32:
        return {}
    magic, = struct.unpack_from('<I', data, off)
    if magic != MH_MAGIC_64:
        return {}
    _, _, _, ncmds, _, _, _ = struct.unpack_from('<IIIIIII', data, off + 4)
    segs = {}
    p = off + 32
    for _ in range(ncmds):
        if p + 8 > len(data):
            break
        cmd, sz = struct.unpack_from('<II', data, p)
        if cmd == LC_SEGMENT_64 and p + sz <= len(data):
            name = data[p+8:p+24].split(b'\x00')[0].decode(errors='replace')
            va, vsz, fo, fsz = struct.unpack_from('<QQQQ', data, p + 24)
            segs[name] = {'vmaddr': va, 'vmsize': vsz, 'fileoff': fo, 'filesize': fsz}
        p += sz
    return segs

def foff_to_va(segs, foff):
    for s in segs.values():
        if s['fileoff'] <= foff < s['fileoff'] + s['filesize']:
            return s['vmaddr'] + (foff - s['fileoff'])
    return None

def va_to_foff(segs, va):
    for s in segs.values():
        if s['vmaddr'] <= va < s['vmaddr'] + s['vmsize']:
            rel = va - s['vmaddr']
            if rel < s['filesize']:
                return s['fileoff'] + rel
    return None

# ─── Helper: cari function start ──────────────────────────────────────────

def find_function_start(data, te_seg, from_foff, max_back=300):
    seg_foff = te_seg['fileoff']
    seg_va   = te_seg['vmaddr']
    for back in range(1, max_back):
        check = from_foff - back * 4
        if check < seg_foff:
            break
        insn, = struct.unpack_from('<I', data, check)
        if is_function_prologue(insn):
            return seg_va + (check - seg_foff)
    return None

# ─── Strategy 1: Write-to-DATA heuristic ──────────────────────────────────

def strategy_write_to_data(data, segs):
    """
    trust_cache_runtime_add menulis ke linked list di __DATA.
    Cari ADRP+ADD ke __DATA diikuti STR dari register yang sama.
    """
    print("\n[*] Strategy 1: Write-to-DATA heuristic")
    te = segs.get('__TEXT_EXEC') or segs.get('__TEXT')
    ds = segs.get('__DATA')
    if not te or not ds:
        print("  [-] Missing segments")
        return []

    tb = te['vmaddr']
    db = ds['vmaddr']
    tstart = te['fileoff']
    results = []

    for i in range(0, te['filesize'] - 16, 4):
        foff = tstart + i
        pc   = tb + i
        if foff + 16 > len(data):
            break

        i0, i1, i2, i3 = struct.unpack_from('<IIII', data, foff)

        page = decode_adrp(i0, pc)
        if page is None:
            continue
        if not (db <= page < db + 0x100000):
            continue

        add = decode_add_imm(i1)
        if add is None:
            continue

        target_va = page + add
        rd_adrp = i0 & 0x1F

        # Cek instruksi ke-3 atau ke-4: STR dengan base register = rd_adrp
        for check_insn in [i2, i3]:
            # STR 64-bit: 0xF9000000
            if (check_insn & 0xFFC00000) == 0xF9000000:
                rn_str = (check_insn >> 5) & 0x1F
                if rn_str == rd_adrp:
                    fn_start = find_function_start(data, te, foff)
                    if fn_start and fn_start not in [r['fn_va'] for r in results]:
                        results.append({
                            'fn_va': fn_start,
                            'ref_va': target_va,
                            'strategy': 'write_to_data'
                        })
                    break

    print(f"  [+] {len(results)} candidates")
    return results

# ─── Strategy 2: Known byte signatures ────────────────────────────────────

def strategy_signature(data, segs):
    """
    Byte signature dari fungsi trust cache yang diketahui.
    Patterns dari iOS 18.x A12 (T8020) kernelcache.
    """
    print("\n[*] Strategy 2: Byte signature matching")
    te = segs.get('__TEXT_EXEC') or segs.get('__TEXT')
    if not te:
        return []

    # Patterns: (bytes_hex, description)
    # Dari reverse engineering iOS 18.2 A12 kernelcache
    patterns = [
        # PACIBSP + STP x29,x30,[sp,#-0x40]! + MOV x29,sp
        (bytes.fromhex('5F2303D5') + bytes.fromhex('FD830FA9') + bytes.fromhex('FD030091'),
         'PACIBSP+STP_0x40+MOV'),
        # PACIBSP + STP x29,x30,[sp,#-0x30]!
        (bytes.fromhex('5F2303D5') + bytes.fromhex('FD430EBA') + bytes.fromhex('FD030091'),
         'PACIBSP+STP_0x30+MOV'),
        # STP x29,x30,[sp,#-0x40]! (no PAC)
        (bytes.fromhex('FD830FA9') + bytes.fromhex('FD030091') + bytes.fromhex('F35301A9'),
         'STP_0x40+MOV+STP_callee'),
        # STP x29,x30,[sp,#-0x20]! (smaller frame)
        (bytes.fromhex('FD7BBEA9') + bytes.fromhex('FD030091'),
         'STP_0x20+MOV'),
    ]

    te_data = data[te['fileoff']:te['fileoff'] + te['filesize']]
    results = []

    for pat, desc in patterns:
        offset = 0
        while True:
            pos = te_data.find(pat, offset)
            if pos == -1:
                break
            va = te['vmaddr'] + pos
            results.append({'fn_va': va, 'strategy': f'signature:{desc}'})
            print(f"  [+] Pattern '{desc}' at 0x{va:x}")
            offset = pos + 4

    print(f"  [+] {len(results)} signature matches total")
    return results

# ─── Strategy 3: String reference ─────────────────────────────────────────

def strategy_string_ref(data, segs):
    """
    Cari string literal yang dipakai oleh trust cache functions,
    lalu ikuti ADRP reference ke string tersebut dari __TEXT_EXEC.
    """
    print("\n[*] Strategy 3: String reference")
    te = segs.get('__TEXT_EXEC') or segs.get('__TEXT')
    if not te:
        return []

    targets = [
        b'_load_trust_cache\x00',
        b'trust_cache_init\x00',
        b'trust_cache_runtime\x00',
        b'load_trust_cache\x00',
        b'TrustCache\x00',
        b'trust cache\x00',
        b'pmap_load_trust_cache\x00',
    ]

    str_vas = {}
    for needle in targets:
        pos = 0
        while True:
            idx = data.find(needle, pos)
            if idx < 0:
                break
            va = foff_to_va(segs, idx)
            if va:
                key = needle.decode(errors='replace').strip('\x00')
                str_vas[key] = va
                print(f"  [+] String '{key}' at VA 0x{va:x}")
            pos = idx + 1

    if not str_vas:
        print("  [-] No relevant strings found")
        return []

    tb = te['vmaddr']
    tstart = te['fileoff']
    results = []

    for sname, str_va in str_vas.items():
        str_page = str_va & ~0xFFF
        for i in range(0, te['filesize'] - 4, 4):
            foff = tstart + i
            pc   = tb + i
            if foff + 4 > len(data):
                break
            insn, = struct.unpack_from('<I', data, foff)
            page = decode_adrp(insn, pc)
            if page == str_page:
                fn_start = find_function_start(data, te, foff)
                if fn_start:
                    results.append({
                        'fn_va': fn_start,
                        'string': sname,
                        'strategy': f'string_ref:{sname}'
                    })
                    print(f"  [+] Ref to '{sname}' → fn at 0x{fn_start:x}")

    return results

# ─── Strategy 4: BL chain dari fungsi yang diketahui ──────────────────────

def strategy_bl_chain(data, segs, known_fn_va):
    """
    Dari fungsi yang sudah diketahui (misal _load_trust_cache dari string xref),
    ikuti semua BL targets — salah satunya mungkin trust_cache_runtime_add.
    """
    if not known_fn_va:
        return []
    print(f"\n[*] Strategy 4: BL chain from 0x{known_fn_va:x}")
    te = segs.get('__TEXT_EXEC') or segs.get('__TEXT')
    if not te:
        return []

    fn_foff = va_to_foff(segs, known_fn_va)
    if fn_foff is None:
        return []

    results = []
    for i in range(300):
        foff = fn_foff + i * 4
        if foff + 4 > len(data):
            break
        insn, = struct.unpack_from('<I', data, foff)
        pc = known_fn_va + i * 4
        if insn == 0xD65F03C0:  # RET
            break
        target = decode_bl(insn, pc)
        if target and target != known_fn_va:
            results.append({'fn_va': target, 'strategy': 'bl_chain'})
            print(f"  [+] BL target: 0x{target:x}")

    return results

# ─── Main ──────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 find_trust_cache_fn2.py <kernelcache> [kernel_base_hex]")
        sys.exit(1)

    path = sys.argv[1]
    kernel_base = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0xfffffff007004000

    print(f"[*] Loading: {path}")
    print(f"[*] kernel_base: 0x{kernel_base:x}")

    data = Path(path).read_bytes()

    # Cek magic
    magic, = struct.unpack_from('<I', data, 0)
    if magic != MH_MAGIC_64:
        print(f"[-] Not a decompressed Mach-O (magic=0x{magic:08x})")
        print("    Decompress dulu: img4tool -e -o kc.dec kernelcache")
        sys.exit(1)

    segs = parse_segments(data)
    print(f"\n[*] Segments: {list(segs.keys())}")
    for name, s in segs.items():
        print(f"    {name:20s} VA=0x{s['vmaddr']:x}  foff=0x{s['fileoff']:x}  size=0x{s['vmsize']:x}")

    all_results = []

    r1 = strategy_write_to_data(data, segs)
    all_results.extend(r1)

    r2 = strategy_signature(data, segs)
    all_results.extend(r2)

    r3 = strategy_string_ref(data, segs)
    all_results.extend(r3)

    # Gunakan hasil string_ref sebagai seed untuk BL chain
    for r in r3[:3]:
        r4 = strategy_bl_chain(data, segs, r['fn_va'])
        all_results.extend(r4)

    # Deduplicate + rank
    seen: dict = {}
    for r in all_results:
        va = r['fn_va']
        if va not in seen:
            seen[va] = []
        seen[va].append(r.get('strategy', '?'))

    ranked = sorted(seen.items(), key=lambda x: len(x[1]), reverse=True)

    print("\n" + "=" * 60)
    print("HASIL — Kandidat trust_cache_runtime_add:")
    print("=" * 60)

    te = segs.get('__TEXT_EXEC') or segs.get('__TEXT')

    for va, strategies in ranked[:10]:
        offset = va - kernel_base
        confidence = "HIGH" if len(strategies) >= 2 else "MEDIUM"
        print(f"\n  VA:         0x{va:x}")
        print(f"  Offset:     kernelBase + 0x{offset:x}")
        print(f"  Strategies: {', '.join(set(strategies))}")
        print(f"  Confidence: {confidence}")

        if te:
            fn_foff = va_to_foff(segs, va)
            if fn_foff:
                print(f"  First 6 instrs:")
                for i in range(6):
                    if fn_foff + i*4 + 4 <= len(data):
                        insn, = struct.unpack_from('<I', data, fn_foff + i*4)
                        print(f"    +{i*4:3d}: 0x{insn:08x}")

    print("\n" + "=" * 60)
    print("COPY KE offsets.m (top 3 candidates):")
    print("=" * 60)
    for va, strategies in ranked[:3]:
        offset = va - kernel_base
        print(f"// Strategies: {', '.join(set(strategies))}")
        print(f"// iOS 18.2 A12 — offset dari kernelBase:")
        print(f"// trust_cache_fn_offset = 0x{offset:x}ULL")
        print(f"// Runtime VA = ds_get_kernel_base() + 0x{offset:x}ULL")
        print()

if __name__ == '__main__':
    main()
