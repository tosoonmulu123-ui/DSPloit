#!/usr/bin/env python3
"""
analyze_amfid.py — Analisis binary /usr/libexec/amfid untuk cari patch target.

Cara pakai:
  1. Copy /usr/libexec/amfid dari device ke workspace (via AirDrop/File Manager/scp)
  2. Taruh di: workspace root sebagai 'amfid' atau path lain
  3. Jalankan: python3 scripts/analyze_amfid.py [path_to_amfid]

Output:
  - Offset instruksi yang perlu di-patch (CBNZ W0 setelah BL ke MISValidate*)
  - Hex patch bytes (NOP = D503201F, MOV W0,#0 = 52800000)
  - Info untuk hardcode di AMFIExperimentView.swift

Catatan:
  - amfid adalah Mach-O arm64e binary
  - Fungsi target: yang dipanggil via XPC dari kernel AMFI kext
  - Return 0 = signature valid, non-zero = invalid
  - Patch: NOP instruksi branch yang skip ke error path
"""

import struct
import sys
import os

def read_u32(data, offset):
    return struct.unpack_from('<I', data, offset)[0]

def read_u64(data, offset):
    return struct.unpack_from('<Q', data, offset)[0]

def decode_bl_target(instr, pc):
    """Decode BL instruction target address."""
    imm26 = instr & 0x3FFFFFF
    # Sign extend 26-bit immediate
    if imm26 & 0x2000000:
        imm26 |= 0xFC000000
    offset = (imm26 << 2) & 0xFFFFFFFF
    if offset & 0x80000000:
        offset = offset - 0x100000000
    return pc + offset

def is_bl(instr):
    return (instr >> 26) == 0x25

def is_cbnz_w0(instr):
    """CBNZ W0, label — opcode 0x35, Rt=0"""
    return (instr >> 24) == 0x35 and (instr & 0x1F) == 0

def is_cbz_w0(instr):
    """CBZ W0, label — opcode 0x34, Rt=0"""
    return (instr >> 24) == 0x34 and (instr & 0x1F) == 0

def is_b_ne(instr):
    """B.NE label — conditional branch not equal"""
    return (instr & 0xFF00001F) == 0x54000001

def is_b_eq(instr):
    """B.EQ label — conditional branch equal"""
    return (instr & 0xFF00001F) == 0x54000000

def is_ret(instr):
    return instr == 0xD65F03C0

def is_mov_w0_0(instr):
    """MOV W0, #0"""
    return instr == 0x52800000

def is_mov_w0_imm(instr):
    """MOV W0, #imm16"""
    return (instr & 0xFFE00000) == 0x52800000

def parse_macho(data):
    """Parse Mach-O header, return text segment info."""
    magic = read_u32(data, 0)
    if magic == 0xFEEDFACF:
        is_64 = True
    elif magic == 0xCEFAEDFE:
        # Need to swap
        print("Big-endian Mach-O not supported")
        return None
    else:
        print(f"Not a Mach-O file (magic=0x{magic:08x})")
        return None

    cputype = read_u32(data, 4)
    cpusubtype = read_u32(data, 8)
    filetype = read_u32(data, 12)
    ncmds = read_u32(data, 16)
    sizeofcmds = read_u32(data, 20)
    flags = read_u32(data, 24)

    print(f"Mach-O 64-bit, cputype=0x{cputype:x}, ncmds={ncmds}")
    print(f"  filetype={filetype}, flags=0x{flags:08x}")

    # Parse load commands
    offset = 32  # sizeof(mach_header_64)
    segments = []
    symtab_off = 0
    symtab_nsyms = 0
    strtab_off = 0
    strtab_size = 0

    for _ in range(ncmds):
        cmd = read_u32(data, offset)
        cmdsize = read_u32(data, offset + 4)

        if cmd == 0x19:  # LC_SEGMENT_64
            segname = data[offset+8:offset+24].split(b'\x00')[0].decode('ascii', errors='replace')
            vmaddr = read_u64(data, offset + 24)
            vmsize = read_u64(data, offset + 32)
            fileoff = read_u64(data, offset + 40)
            filesize = read_u64(data, offset + 48)
            maxprot = read_u32(data, offset + 56)
            initprot = read_u32(data, offset + 60)
            nsects = read_u32(data, offset + 64)

            segments.append({
                'name': segname,
                'vmaddr': vmaddr,
                'vmsize': vmsize,
                'fileoff': fileoff,
                'filesize': filesize,
                'maxprot': maxprot,
                'initprot': initprot,
                'nsects': nsects,
            })
            print(f"  Segment {segname}: vm=0x{vmaddr:x}-0x{vmaddr+vmsize:x}, file=0x{fileoff:x}+0x{filesize:x}, prot={initprot}")

        elif cmd == 0x02:  # LC_SYMTAB
            symtab_off = read_u32(data, offset + 8)
            symtab_nsyms = read_u32(data, offset + 12)
            strtab_off = read_u32(data, offset + 16)
            strtab_size = read_u32(data, offset + 20)

        offset += cmdsize

    return {
        'segments': segments,
        'symtab_off': symtab_off,
        'symtab_nsyms': symtab_nsyms,
        'strtab_off': strtab_off,
        'strtab_size': strtab_size,
    }

def find_text_segment(info):
    for seg in info['segments']:
        if seg['name'] == '__TEXT':
            return seg
    return None

def get_symbol_name(data, strtab_off, str_index):
    """Read null-terminated string from string table."""
    start = strtab_off + str_index
    end = data.index(b'\x00', start)
    return data[start:end].decode('ascii', errors='replace')

def find_symbols(data, info, target_names):
    """Find symbols by name, return {name: vmaddr}."""
    results = {}
    if info['symtab_nsyms'] == 0:
        return results

    symtab_off = info['symtab_off']
    strtab_off = info['strtab_off']
    nsyms = info['symtab_nsyms']

    # nlist_64: n_strx(4) + n_type(1) + n_sect(1) + n_desc(2) + n_value(8) = 16 bytes
    for i in range(nsyms):
        sym_off = symtab_off + i * 16
        if sym_off + 16 > len(data):
            break
        n_strx = read_u32(data, sym_off)
        n_type = data[sym_off + 4]
        n_value = read_u64(data, sym_off + 8)

        if n_strx == 0 or n_value == 0:
            continue

        name = get_symbol_name(data, strtab_off, n_strx)
        for target in target_names:
            if target in name:
                results[name] = n_value
                break

    return results

def scan_patch_targets(data, text_seg):
    """Scan __TEXT for BL + CBNZ/CBZ patterns (signature check + branch)."""
    fileoff = text_seg['fileoff']
    filesize = text_seg['filesize']
    vmaddr = text_seg['vmaddr']

    targets = []

    for i in range(0, filesize - 4, 4):
        offset = fileoff + i
        if offset + 8 > len(data):
            break

        instr = read_u32(data, offset)
        pc = vmaddr + i

        # Pattern 1: BL followed by CBNZ W0 (call + check return != 0 → error)
        if is_bl(instr):
            next_instr = read_u32(data, offset + 4)
            bl_target = decode_bl_target(instr, pc)

            if is_cbnz_w0(next_instr):
                targets.append({
                    'type': 'BL+CBNZ_W0',
                    'offset': i,
                    'fileoff': offset,
                    'vmaddr': pc,
                    'instr': instr,
                    'next_instr': next_instr,
                    'bl_target': bl_target,
                    'patch_offset': offset + 4,  # patch the CBNZ
                    'patch_vmaddr': pc + 4,
                })
            elif is_cbz_w0(next_instr):
                targets.append({
                    'type': 'BL+CBZ_W0',
                    'offset': i,
                    'fileoff': offset,
                    'vmaddr': pc,
                    'instr': instr,
                    'next_instr': next_instr,
                    'bl_target': bl_target,
                    'patch_offset': offset,  # patch the BL to MOV W0,#0
                    'patch_vmaddr': pc,
                })
            elif is_b_ne(next_instr):
                targets.append({
                    'type': 'BL+B.NE',
                    'offset': i,
                    'fileoff': offset,
                    'vmaddr': pc,
                    'instr': instr,
                    'next_instr': next_instr,
                    'bl_target': bl_target,
                    'patch_offset': offset + 4,  # patch the B.NE
                    'patch_vmaddr': pc + 4,
                })

    return targets

def main():
    if len(sys.argv) < 2:
        # Try default paths
        candidates = ['amfid', 'scripts/amfid', '../amfid']
        path = None
        for c in candidates:
            if os.path.exists(c):
                path = c
                break
        if not path:
            print("Usage: python3 analyze_amfid.py <path_to_amfid_binary>")
            print("\nCara mendapatkan amfid binary:")
            print("  1. Dari device: Root File Manager → /usr/libexec/amfid → Share → AirDrop ke PC")
            print("  2. Dari IPSW: extract rootfs DMG → /usr/libexec/amfid")
            print("  3. Via scp: scp root@device:/usr/libexec/amfid ./amfid")
            print("\nTaruh file di workspace root sebagai 'amfid'")
            sys.exit(1)
    else:
        path = sys.argv[1]

    print(f"=== Analyzing: {path} ===\n")

    with open(path, 'rb') as f:
        data = f.read()

    print(f"File size: {len(data)} bytes\n")

    # Parse Mach-O
    info = parse_macho(data)
    if not info:
        sys.exit(1)

    # Find __TEXT segment
    text_seg = find_text_segment(info)
    if not text_seg:
        print("ERROR: __TEXT segment not found")
        sys.exit(1)

    print(f"\n__TEXT: vm=0x{text_seg['vmaddr']:x}, size=0x{text_seg['vmsize']:x}")

    # Find relevant symbols
    print("\n=== Symbol Search ===")
    target_syms = [
        'MISValidateSignature',
        'MISCopyEntitlements',
        'verify_code_signature',
        'check_signature',
        'amfi',
        'trust_cache',
        'cdhash',
        'SecCode',
        'SecTrust',
    ]
    symbols = find_symbols(data, info, target_syms)
    if symbols:
        print(f"Found {len(symbols)} relevant symbols:")
        for name, addr in sorted(symbols.items(), key=lambda x: x[1]):
            print(f"  {name}: 0x{addr:x}")
    else:
        print("No relevant symbols found (stripped binary)")

    # Scan for patch targets
    print("\n=== Patch Target Scan ===")
    targets = scan_patch_targets(data, text_seg)
    print(f"Found {len(targets)} BL+branch patterns\n")

    # Filter: prioritize targets that call known signature functions
    priority_targets = []
    other_targets = []

    for t in targets:
        # Check if BL target is a known symbol
        bl_target = t['bl_target']
        is_sig_check = False
        for name, addr in symbols.items():
            if abs(bl_target - addr) < 16:  # within 16 bytes = likely same function
                t['called_func'] = name
                is_sig_check = True
                break

        if is_sig_check:
            priority_targets.append(t)
        else:
            other_targets.append(t)

    # Print priority targets
    if priority_targets:
        print("=== HIGH PRIORITY (calls known signature functions) ===")
        for t in priority_targets[:20]:
            func = t.get('called_func', '?')
            print(f"  [{t['type']}] file+0x{t['fileoff']:x} vm=0x{t['vmaddr']:x}")
            print(f"    BL → {func} (0x{t['bl_target']:x})")
            print(f"    Patch: file+0x{t['patch_offset']:x} vm=0x{t['patch_vmaddr']:x}")
            print(f"    Original: 0x{t['next_instr']:08x} → NOP (0xD503201F)")
            print()

    # Print top other targets (sorted by proximity to text start = likely main logic)
    print(f"=== OTHER CANDIDATES ({len(other_targets)} total, showing top 30) ===")
    for t in other_targets[:30]:
        print(f"  [{t['type']}] file+0x{t['fileoff']:x} vm=0x{t['vmaddr']:x} BL→0x{t['bl_target']:x}")

    # Generate Swift code snippet
    print("\n\n=== SWIFT CODE SNIPPET (for AMFIExperimentView.swift) ===")
    print("// Paste these offsets into expAmfidPatch():")
    print("// amfid __TEXT base on device = 0x16cd60000 (from Exp 84 Step 2)")
    print("// Offset from __TEXT start:")

    all_targets = priority_targets + other_targets[:10]
    if all_targets:
        print(f"let amfidPatchOffsets: [(offset: UInt64, original: UInt32, desc: String)] = [")
        for t in all_targets[:15]:
            off_from_text = t['patch_vmaddr'] - text_seg['vmaddr']
            desc = t.get('called_func', t['type'])
            print(f"    (0x{off_from_text:x}, 0x{t['next_instr']:08x}, \"{desc}\"),")
        print("]")
        print("// NOP = 0xD503201F")
        print("// MOV W0, #0 = 0x52800000")
    else:
        print("// No targets found — binary might be heavily stripped")

    print("\n=== DONE ===")
    print(f"Total patch candidates: {len(priority_targets)} high priority + {len(other_targets)} other")
    print("\nNext steps:")
    print("1. Pilih offset yang paling relevan (high priority)")
    print("2. Hardcode di AMFIExperimentView.swift")
    print("3. Patch via launchd RC + task_for_pid (Exp 84 v2)")

if __name__ == '__main__':
    main()
