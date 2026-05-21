#!/usr/bin/env python3
"""
analyze_amfi_enforcement.py — Deep analysis of AMFI CDHash enforcement path
iOS 18.2 (22C152) iPhone XR (A12 T8020)

Goal: Find WHERE exactly CDHash validation happens and what we can patch.
Key question: Is there a writable pointer/flag that controls the kill decision?

Known facts:
- AMFI __DATA (fileset) is WRITABLE (0xfffffff00a330098, size 0x541)
- 10 boolean flags at known offsets are NOT enforcement flags
- posix_spawn from /var/containers/Bundle/ works (ret=0) but SIGKILL
- CDHash validation causes SIGKILL regardless of AMFI flags
- Trust cache is in KTRR-protected __DATA (not heap)
"""

import struct
import sys
import os

IPSW_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "iPhone11,8_18.2_22C152_Restore")
KC_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "kernelcache")  # Decompressed Mach-O in repo root

# Known addresses (unslid)
KERNEL_TEXT_BASE = 0xfffffff007004000
KERNEL_DATA_BASE = 0xfffffff00a0e0000
AMFI_DATA_BASE = 0xfffffff00a330098
AMFI_DATA_SIZE = 0x541
AMFI_TEXT_EXEC = None  # Will find from fileset

# Fileset component info from deep_probe_out.txt
AMFI_COMPONENT = "com.apple.driver.AppleMobileFileIntegrity"
AMFI_TEXT_VA = 0xfffffff007497c30  # __TEXT of AMFI fileset component


def read_u32(data, off):
    if off + 4 > len(data):
        return 0
    return struct.unpack_from('<I', data, off)[0]


def read_u64(data, off):
    if off + 8 > len(data):
        return 0
    return struct.unpack_from('<Q', data, off)[0]


def find_string(data, s):
    """Find all occurrences of a string in binary data."""
    encoded = s.encode('utf-8')
    results = []
    start = 0
    while True:
        idx = data.find(encoded, start)
        if idx == -1:
            break
        results.append(idx)
        start = idx + 1
    return results


def fileoff_to_va(fileoff, segments):
    """Convert file offset to virtual address using segment info."""
    for seg in segments:
        if seg['fileoff'] <= fileoff < seg['fileoff'] + seg['filesize']:
            return seg['vmaddr'] + (fileoff - seg['fileoff'])
    return None


def va_to_fileoff(va, segments):
    """Convert virtual address to file offset."""
    for seg in segments:
        if seg['vmaddr'] <= va < seg['vmaddr'] + seg['vmsize']:
            off = seg['fileoff'] + (va - seg['vmaddr'])
            if off < seg['fileoff'] + seg['filesize']:
                return off
    return None


def parse_macho_segments(data, offset=0):
    """Parse Mach-O load commands to get segment info."""
    magic = read_u32(data, offset)
    if magic == 0xFEEDFACF:
        ncmds = read_u32(data, offset + 0x10)
        sizeofcmds = read_u32(data, offset + 0x14)
    else:
        return []

    segments = []
    cmd_off = offset + 0x20  # after mach_header_64

    for _ in range(ncmds):
        cmd = read_u32(data, cmd_off)
        cmdsize = read_u32(data, cmd_off + 4)
        if cmdsize == 0:
            break

        if cmd == 0x19:  # LC_SEGMENT_64
            segname = data[cmd_off + 8:cmd_off + 24].split(b'\x00')[0].decode('ascii', errors='ignore')
            vmaddr = read_u64(data, cmd_off + 24)
            vmsize = read_u64(data, cmd_off + 32)
            fileoff = read_u64(data, cmd_off + 40)
            filesize = read_u64(data, cmd_off + 48)
            segments.append({
                'name': segname,
                'vmaddr': vmaddr,
                'vmsize': vmsize,
                'fileoff': fileoff,
                'filesize': filesize,
            })

        cmd_off += cmdsize
        if cmd_off >= offset + 0x20 + sizeofcmds:
            break

    return segments


def parse_fileset(data):
    """Parse fileset kernel to find component entries."""
    magic = read_u32(data, 0)
    if magic != 0xFEEDFACF:
        print("Not a Mach-O file")
        return None, []

    ncmds = read_u32(data, 0x10)
    filetype = read_u32(data, 0x0C)

    segments = []
    fileset_entries = []
    cmd_off = 0x20

    for _ in range(ncmds):
        cmd = read_u32(data, cmd_off)
        cmdsize = read_u32(data, cmd_off + 4)
        if cmdsize == 0:
            break

        if cmd == 0x19:  # LC_SEGMENT_64
            segname = data[cmd_off + 8:cmd_off + 24].split(b'\x00')[0].decode('ascii', errors='ignore')
            vmaddr = read_u64(data, cmd_off + 24)
            vmsize = read_u64(data, cmd_off + 32)
            fileoff = read_u64(data, cmd_off + 40)
            filesize = read_u64(data, cmd_off + 48)
            segments.append({
                'name': segname,
                'vmaddr': vmaddr,
                'vmsize': vmsize,
                'fileoff': fileoff,
                'filesize': filesize,
            })

        elif cmd == 0x80000035:  # LC_FILESET_ENTRY
            # struct fileset_entry_command {
            #   uint32_t cmd, cmdsize;
            #   uint64_t vmaddr;
            #   uint64_t fileoff;
            #   uint32_t entry_id_offset;  // string offset from cmd start
            # }
            vmaddr = read_u64(data, cmd_off + 8)
            fileoff = read_u64(data, cmd_off + 16)
            entry_id_off = read_u32(data, cmd_off + 24)
            name_start = cmd_off + entry_id_off
            name_end = data.find(b'\x00', name_start)
            name = data[name_start:name_end].decode('ascii', errors='ignore')
            fileset_entries.append({
                'name': name,
                'vmaddr': vmaddr,
                'fileoff': fileoff,
            })

        cmd_off += cmdsize

    return segments, fileset_entries


def analyze_amfi_component(data, entry, all_segments):
    """Deep analysis of AMFI fileset component."""
    print(f"\n{'='*70}")
    print(f"AMFI COMPONENT ANALYSIS: {entry['name']}")
    print(f"{'='*70}")
    print(f"  VM addr: 0x{entry['vmaddr']:x}")
    print(f"  File offset: 0x{entry['fileoff']:x}")

    # Parse AMFI's own Mach-O header
    amfi_segments = parse_macho_segments(data, entry['fileoff'])
    print(f"\n  AMFI segments:")
    for seg in amfi_segments:
        print(f"    {seg['name']:16s} vm=0x{seg['vmaddr']:x} size=0x{seg['vmsize']:x} "
              f"fileoff=0x{seg['fileoff']:x} filesize=0x{seg['filesize']:x}")

    # Find __TEXT_EXEC (where enforcement code lives)
    text_exec = None
    data_seg = None
    for seg in amfi_segments:
        if seg['name'] == '__TEXT_EXEC':
            text_exec = seg
        elif seg['name'] == '__DATA':
            data_seg = seg

    if text_exec:
        print(f"\n  AMFI __TEXT_EXEC: vm=0x{text_exec['vmaddr']:x}, size=0x{text_exec['vmsize']:x}")
        print(f"  This is where CDHash validation code lives (KTRR protected)")

    if data_seg:
        print(f"  AMFI __DATA: vm=0x{data_seg['vmaddr']:x}, size=0x{data_seg['vmsize']:x}")
        print(f"  This is WRITABLE (confirmed by Exp 93)")

    return amfi_segments, text_exec, data_seg


def scan_amfi_strings(data, all_segments):
    """Find AMFI-related strings that reveal enforcement logic."""
    print(f"\n{'='*70}")
    print("AMFI ENFORCEMENT STRINGS")
    print(f"{'='*70}")

    enforcement_strings = [
        b"AMFI: code signature invalid",
        b"AMFI: denying",
        b"AMFI: kill",
        b"AMFI: exec",
        b"AMFI: spawn",
        b"AMFI: trust",
        b"AMFI: CDHash",
        b"AMFI: cdhash",
        b"not in trust cache",
        b"trust cache",
        b"cs_invalid",
        b"proc_check_run_cs_invalid",
        b"mac_vnode_check_exec",
        b"mac_proc_check_run_cs_invalid",
        b"amfi_check_dyld_policy_self",
        b"AMFI: allowing",
        b"AMFI: hook",
        b"cserr",
        b"csflags",
        b"get_trust_level_for_proc",
        b"check_signature_validity",
        b"vnode_check_signature",
        b"proc_check_launch_constraints",
    ]

    found_strings = []
    for s in enforcement_strings:
        offsets = find_string(data, s.decode('ascii', errors='ignore'))
        for off in offsets:
            va = fileoff_to_va(off, all_segments)
            if va:
                found_strings.append((va, off, s.decode('ascii', errors='ignore')))
                print(f"  0x{va:x} (fileoff 0x{off:x}): \"{s.decode('ascii', errors='ignore')}\"")

    return found_strings


def find_xrefs_to_string(data, string_va, all_segments, search_range=None):
    """Find ADRP+ADD pairs that reference a string VA."""
    xrefs = []
    page = string_va & ~0xFFF
    page_off = string_va & 0xFFF

    # Search in __TEXT_EXEC segments
    for seg in all_segments:
        if 'EXEC' not in seg['name'] and 'TEXT' not in seg['name']:
            continue
        if seg['filesize'] == 0:
            continue

        start = seg['fileoff']
        end = start + seg['filesize']

        for off in range(start, min(end, len(data) - 4), 4):
            instr = read_u32(data, off)

            # Check for ADRP (1x_x10000_xxxxxxx_xxxxx_xxxxx)
            if (instr & 0x9F000000) == 0x90000000:
                # Decode ADRP
                immhi = (instr >> 5) & 0x7FFFF
                immlo = (instr >> 29) & 0x3
                imm = (immhi << 2) | immlo
                if imm & 0x100000:  # sign extend 21-bit
                    imm |= ~0x1FFFFF
                    imm = imm & 0xFFFFFFFF
                    imm = struct.unpack('<i', struct.pack('<I', imm))[0]

                pc_page = (fileoff_to_va(off, all_segments) or 0) & ~0xFFF
                target_page = pc_page + (imm << 12)

                if target_page == page:
                    # Check next instruction for ADD with matching page offset
                    if off + 4 < end:
                        next_instr = read_u32(data, off + 4)
                        if (next_instr & 0xFFC00000) == 0x91000000:  # ADD immediate
                            add_imm = (next_instr >> 10) & 0xFFF
                            shift = (next_instr >> 22) & 0x3
                            if shift == 1:
                                add_imm <<= 12
                            if add_imm == page_off:
                                ref_va = fileoff_to_va(off, all_segments)
                                if ref_va:
                                    xrefs.append(ref_va)

    return xrefs


def analyze_trust_cache_validation(data, all_segments, fileset_entries):
    """Analyze the trust cache lookup path to find patchable points."""
    print(f"\n{'='*70}")
    print("TRUST CACHE VALIDATION FLOW ANALYSIS")
    print(f"{'='*70}")

    # Key strings that indicate trust cache lookup
    tc_strings = [
        "pmap_lookup_in_loaded_trust_caches",
        "pmap_lookup_in_static_trust_cache",
        "trust_cache",
        "query_trust_cache",
    ]

    print("\n--- Trust cache related strings ---")
    for s in tc_strings:
        offsets = find_string(data, s)
        for off in offsets[:3]:  # limit
            va = fileoff_to_va(off, all_segments)
            if va:
                print(f"  \"{s}\" at VA 0x{va:x}")


def analyze_amfi_data_content(data, all_segments):
    """Analyze what's actually in AMFI __DATA beyond the 10 boolean flags."""
    print(f"\n{'='*70}")
    print("AMFI __DATA DEEP CONTENT ANALYSIS")
    print(f"{'='*70}")

    # Find AMFI __DATA in file
    amfi_data_off = va_to_fileoff(AMFI_DATA_BASE, all_segments)
    if amfi_data_off is None:
        print("  Cannot find AMFI __DATA in file!")
        return

    print(f"  AMFI __DATA file offset: 0x{amfi_data_off:x}")
    print(f"  Size: 0x{AMFI_DATA_SIZE:x} ({AMFI_DATA_SIZE} bytes)")
    print()

    # Dump ALL non-zero values
    print("  Non-zero slots in AMFI __DATA:")
    print(f"  {'Offset':<8} {'Value':<20} {'Type':<15} {'Notes'}")
    print(f"  {'-'*8} {'-'*20} {'-'*15} {'-'*30}")

    pointers = []
    flags = []
    unknowns = []

    for off in range(0, AMFI_DATA_SIZE, 8):
        if amfi_data_off + off + 8 > len(data):
            break
        val = read_u64(data, amfi_data_off + off)
        if val == 0:
            continue

        va = AMFI_DATA_BASE + off
        note = ""

        if val == 1:
            flags.append((off, val))
            note = "boolean flag"
        elif val > 0xfffffff000000000 and val < 0xfffffffc00000000:
            pointers.append((off, val))
            note = f"kernel pointer → 0x{val:x}"
        elif val < 0x10000:
            note = f"small int ({val})"
        else:
            note = f"0x{val:x}"
            unknowns.append((off, val))

        print(f"  +0x{off:<5x} 0x{val:<18x} {'ptr' if 'pointer' in note else 'flag' if 'boolean' in note else 'int':<15} {note}")

    print(f"\n  Summary: {len(pointers)} pointers, {len(flags)} flags, {len(unknowns)} unknowns")

    # Analyze pointers — these might be function pointers or vtable entries
    if pointers:
        print(f"\n  --- Kernel pointers in AMFI __DATA ---")
        print(f"  These are potential hook/callback pointers we could redirect!")
        for off, val in pointers:
            # Check if pointer is in __TEXT_EXEC (function pointer)
            target_off = va_to_fileoff(val, all_segments)
            location = "unknown"
            if target_off:
                for seg in all_segments:
                    if seg['vmaddr'] <= val < seg['vmaddr'] + seg['vmsize']:
                        location = seg['name']
                        break
            print(f"    +0x{off:x}: 0x{val:x} → {location}")


def analyze_mac_policy_ops(data, all_segments):
    """Find mac_policy_ops struct — function pointer table for AMFI hooks."""
    print(f"\n{'='*70}")
    print("MAC POLICY OPS ANALYSIS")
    print(f"{'='*70}")
    print("  mac_policy_ops is a struct of function pointers.")
    print("  If it's in writable memory, we can redirect hooks!")
    print()

    # Search for "AppleMobileFileIntegrity" string (used in mac_policy_conf)
    amfi_name_offsets = find_string(data, "AppleMobileFileIntegrity")

    for off in amfi_name_offsets[:5]:
        va = fileoff_to_va(off, all_segments)
        if va:
            print(f"  \"AppleMobileFileIntegrity\" at VA 0x{va:x} (fileoff 0x{off:x})")

            # mac_policy_conf struct layout:
            # +0x00: mpc_name (pointer to string)
            # +0x08: mpc_fullname (pointer)
            # +0x10: mpc_labelnames (pointer)
            # +0x18: mpc_labelname_count
            # +0x20: mpc_ops (pointer to mac_policy_ops!)
            # +0x28: mpc_loadtime_flags
            # +0x30: mpc_field_off
            # +0x38: mpc_runtime_flags
            # +0x40: mpc_list (linked list)
            # +0x48: mpc_data

            # Find xrefs to this string to locate mac_policy_conf
            # The string pointer will be at mpc_name in the struct


def analyze_sigkill_path(data, all_segments):
    """Find the code path that sends SIGKILL for code signing violations."""
    print(f"\n{'='*70}")
    print("SIGKILL CODE PATH ANALYSIS")
    print(f"{'='*70}")

    # On iOS, SIGKILL for CS violations comes from:
    # 1. cs_invalid_page() → kills process when page fault on invalid CS page
    # 2. mac_proc_check_run_cs_invalid() → AMFI hook that decides kill/allow
    # 3. proc_check_launch_constraints() → launch constraint check
    #
    # The key function is the MAC hook: if it returns non-zero, process is killed.
    # If we can make it return 0, process lives!

    kill_strings = [
        "cs_invalid_page",
        "proc_check_run_cs_invalid",
        "csops",
        "CS_KILL",
        "SIGKILL",
        "cs_process_enforcement",
    ]

    print("\n  Kill-path related strings:")
    for s in kill_strings:
        offsets = find_string(data, s)
        for off in offsets[:2]:
            va = fileoff_to_va(off, all_segments)
            if va:
                print(f"    \"{s}\" at VA 0x{va:x}")

    # The critical insight: on iOS 18, the kill decision happens in
    # mac_vnode_check_exec (at exec time) and mac_proc_check_run_cs_invalid
    # (at page fault time). Both call into AMFI's MAC policy hooks.
    #
    # AMFI's hook function pointers are in mac_policy_ops struct.
    # If mac_policy_ops is in __DATA_CONST (read-only after boot) → can't patch
    # If it's in __DATA (writable) → we can redirect!


def analyze_data_const_vs_data(data, all_segments, fileset_entries):
    """Determine if AMFI's function pointers are in __DATA or __DATA_CONST."""
    print(f"\n{'='*70}")
    print("AMFI FUNCTION POINTER LOCATION ANALYSIS")
    print(f"{'='*70}")

    # Find AMFI fileset entry
    amfi_entry = None
    for entry in fileset_entries:
        if 'AppleMobileFileIntegrity' in entry['name']:
            amfi_entry = entry
            break

    if not amfi_entry:
        print("  AMFI fileset entry not found!")
        return

    # Parse AMFI's segments
    amfi_segs = parse_macho_segments(data, amfi_entry['fileoff'])

    print(f"\n  AMFI component segments:")
    for seg in amfi_segs:
        writable = "WRITABLE" if seg['name'] == '__DATA' else "READ-ONLY"
        if seg['name'] == '__DATA_CONST':
            writable = "READ-ONLY (const)"
        print(f"    {seg['name']:16s} vm=0x{seg['vmaddr']:x} size=0x{seg['vmsize']:x} [{writable}]")

    # Check __DATA_CONST — this is where mac_policy_ops likely lives
    data_const = None
    for seg in amfi_segs:
        if seg['name'] == '__DATA_CONST':
            data_const = seg
            break

    if data_const:
        print(f"\n  __DATA_CONST analysis:")
        print(f"    VA: 0x{data_const['vmaddr']:x}")
        print(f"    Size: 0x{data_const['vmsize']:x}")
        print(f"    File offset: 0x{data_const['fileoff']:x}")
        print(f"    STATUS: READ-ONLY (KTRR protected on A12)")
        print()
        print(f"    This is where mac_policy_ops function pointers live.")
        print(f"    We CANNOT patch these directly.")
        print()

        # Scan for kernel pointers in __DATA_CONST (function pointer table)
        dc_off = data_const['fileoff']
        dc_size = data_const['filesize']
        ptr_count = 0
        print(f"    Function pointers in __DATA_CONST (first 50):")
        for off in range(0, min(dc_size, 0x2000), 8):
            if dc_off + off + 8 > len(data):
                break
            val = read_u64(data, dc_off + off)
            if val > 0xfffffff007000000 and val < 0xfffffffc00000000:
                ptr_count += 1
                if ptr_count <= 50:
                    # Check if it points to __TEXT_EXEC
                    target_seg = ""
                    for seg in all_segments:
                        if seg['vmaddr'] <= val < seg['vmaddr'] + seg['vmsize']:
                            target_seg = seg['name']
                            break
                    print(f"      +0x{off:x}: 0x{val:x} → {target_seg}")
        print(f"    Total function pointers: {ptr_count}")

    # KEY QUESTION: Is __DATA_CONST actually KTRR-protected for fileset components?
    # We know AMFI __DATA is writable. What about __DATA_CONST?
    print(f"\n  ╔══════════════════════════════════════════════════════════════╗")
    print(f"  ║  KEY QUESTION: Is AMFI __DATA_CONST also writable?          ║")
    print(f"  ║                                                              ║")
    print(f"  ║  AMFI __DATA is writable (Exp 93 confirmed).                ║")
    print(f"  ║  If __DATA_CONST is ALSO writable for fileset components,   ║")
    print(f"  ║  we can redirect mac_policy_ops function pointers!          ║")
    print(f"  ║                                                              ║")
    print(f"  ║  TEST: Read+Write to AMFI __DATA_CONST on device.           ║")
    print(f"  ║  If writable → redirect mpo_vnode_check_exec to RET 0       ║")
    print(f"  ║  → ALL code signing checks bypassed → FULL JAILBREAK        ║")
    print(f"  ╚══════════════════════════════════════════════════════════════╝")

    if data_const:
        print(f"\n  AMFI __DATA_CONST (unslid): 0x{data_const['vmaddr']:x}")
        print(f"  AMFI __DATA_CONST size: 0x{data_const['vmsize']:x}")
        print(f"  → Add KASLR slide on device to get runtime address")
        print(f"  → Try ds_kwrite64(addr, value) — if no panic, it's writable!")


def main():
    print("=" * 70)
    print("  AMFI ENFORCEMENT DEEP ANALYSIS")
    print("  iOS 18.2 (22C152) — iPhone XR (A12)")
    print("=" * 70)

    if not os.path.exists(KC_PATH):
        print(f"ERROR: Kernelcache not found at {KC_PATH}")
        sys.exit(1)

    print(f"\nLoading kernelcache: {KC_PATH}")
    with open(KC_PATH, 'rb') as f:
        data = f.read()
    print(f"Size: {len(data)} bytes ({len(data)/1024/1024:.1f} MiB)")

    # Parse fileset kernel
    all_segments, fileset_entries = parse_fileset(data)
    print(f"\nSegments: {len(all_segments)}")
    print(f"Fileset entries: {len(fileset_entries)}")

    # Find AMFI entry
    amfi_entry = None
    for entry in fileset_entries:
        if 'AppleMobileFileIntegrity' in entry['name']:
            amfi_entry = entry
            break

    if amfi_entry:
        amfi_segs, text_exec, data_seg = analyze_amfi_component(data, amfi_entry, all_segments)
    else:
        print("WARNING: AMFI fileset entry not found")
        amfi_segs = []

    # Analyze AMFI __DATA content
    analyze_amfi_data_content(data, all_segments)

    # Analyze function pointer locations
    analyze_data_const_vs_data(data, all_segments, fileset_entries)

    # Find enforcement strings
    scan_amfi_strings(data, all_segments)

    # Analyze trust cache validation
    analyze_trust_cache_validation(data, all_segments, fileset_entries)

    # Analyze SIGKILL path
    analyze_sigkill_path(data, all_segments)

    # Final recommendations
    print(f"\n{'='*70}")
    print("RECOMMENDED NEXT EXPERIMENTS")
    print(f"{'='*70}")
    print("""
1. TEST AMFI __DATA_CONST WRITABILITY
   Address (unslid): [from analysis above]
   If writable → redirect mac_policy_ops hooks → JAILBREAK

2. FIND "RETURN 0" GADGET IN KERNEL
   Need a function that just does: MOV W0, #0; RET
   Address this gadget, then overwrite mac_policy_ops entry

3. ALTERNATIVE: PATCH amfid PROCESS
   amfid is the userspace daemon that validates signatures.
   If we can patch its TEXT pages via physmap → bypass validation.
   Need: correct page table walk for amfid's address space.

4. ALTERNATIVE: TRUST CACHE RUNTIME ADD
   Call trust_cache_runtime_add() kernel function via RemoteCall.
   This is how DDI trust caches are added legitimately.
   Need: find function address + craft valid TC struct.
""")


if __name__ == '__main__':
    main()
