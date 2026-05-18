#!/usr/bin/env python3
"""
DSPloit AMFI Deep Analyzer v4
=================================
Target: Find AMFI bypass paths in kernelcache

Focus areas:
1. AMFI check functions — exact signature verification flow
2. Trust cache lookup — how CDHash is verified
3. posix_spawn internals — why file_actions fail via RemoteCall
4. Function pointers in __DATA — patchable via KRW!
5. mac_policy hooks — AMFI's MAC framework integration
6. cs_blob / cs_flags — code signing enforcement points

Usage: python3 amfi_deep_analyze.py [kernelcache_path]
"""

import struct
import sys
import os
from collections import defaultdict

# Default path
KCACHE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "kernelcache.release.iphone11b.decompressed")
if len(sys.argv) > 1:
    KCACHE = sys.argv[1]

CODE_OFFSET = 0xe00000  # __TEXT segment start in file
KERNEL_BASE = 0xfffffff007004000  # typical iOS 18 kernel base (unslid)

def read32(data, off):
    if off + 4 > len(data): return 0
    return struct.unpack_from('<I', data, off)[0]

def read64(data, off):
    if off + 8 > len(data): return 0
    return struct.unpack_from('<Q', data, off)[0]

def decode_arm64(opcode, addr=0):
    """Decode ARM64 instruction to string"""
    if opcode == 0xD65F03C0: return "RET"
    if opcode == 0xD503201F: return "NOP"
    if (opcode & 0xFC000000) == 0x14000000:
        imm = opcode & 0x3FFFFFF
        if imm & 0x2000000: imm = imm - 0x4000000
        return f"B 0x{(addr + imm*4) & 0xFFFFFFFFFFFFFFFF:x}"
    if (opcode & 0xFC000000) == 0x94000000:
        imm = opcode & 0x3FFFFFF
        if imm & 0x2000000: imm = imm - 0x4000000
        return f"BL 0x{(addr + imm*4) & 0xFFFFFFFFFFFFFFFF:x}"
    if (opcode & 0xFFE0001F) == 0xD4000001:
        imm = (opcode >> 5) & 0xFFFF
        return f"SVC #0x{imm:x}"
    if (opcode & 0xFFFFFC1F) == 0xD61F0000:
        return f"BR X{(opcode>>5)&0x1F}"
    if (opcode & 0xFFFFFC1F) == 0xD63F0000:
        return f"BLR X{(opcode>>5)&0x1F}"
    if (opcode & 0xFFC00000) == 0xF9400000:
        rt = opcode & 0x1F; rn = (opcode>>5)&0x1F; imm = ((opcode>>10)&0xFFF)*8
        return f"LDR X{rt}, [X{rn}, #{imm}]"
    if (opcode & 0xFFC00000) == 0xF9000000:
        rt = opcode & 0x1F; rn = (opcode>>5)&0x1F; imm = ((opcode>>10)&0xFFF)*8
        return f"STR X{rt}, [X{rn}, #{imm}]"
    if (opcode & 0xFF800000) == 0x91000000:
        rd = opcode&0x1F; rn = (opcode>>5)&0x1F; imm = (opcode>>10)&0xFFF
        sh = (opcode>>22)&1
        if sh: imm <<= 12
        return f"ADD X{rd}, X{rn}, #0x{imm:x}"
    if (opcode & 0xFF800000) == 0xD2800000:
        rd = opcode&0x1F; imm = (opcode>>5)&0xFFFF; hw = (opcode>>21)&3
        return f"MOVZ X{rd}, #0x{imm<<(hw*16):x}"
    if (opcode & 0xFF800000) == 0xF2800000:
        rd = opcode&0x1F; imm = (opcode>>5)&0xFFFF; hw = (opcode>>21)&3
        return f"MOVK X{rd}, #0x{imm:x}, LSL #{hw*16}"
    if (opcode & 0x9F000000) == 0x90000000:
        rd = opcode&0x1F
        immhi=(opcode>>5)&0x7FFFF; immlo=(opcode>>29)&3
        imm = (immhi<<2)|immlo
        if imm & 0x100000: imm = imm - 0x200000
        pc_page = addr & ~0xFFF
        result = (pc_page + (imm<<12)) & 0xFFFFFFFFFFFFFFFF
        return f"ADRP X{rd}, 0x{result:x}"
    if (opcode & 0xFFE0FFE0) == 0xAA0003E0:
        return f"MOV X{opcode&0x1F}, X{(opcode>>16)&0x1F}"
    if (opcode & 0xFF000000) == 0x54000000:
        imm = (opcode>>5)&0x7FFFF
        if imm & 0x40000: imm = imm - 0x80000
        cond = opcode & 0xF
        conds = ["EQ","NE","CS","CC","MI","PL","VS","VC","HI","LS","GE","LT","GT","LE","AL","NV"]
        return f"B.{conds[cond]} 0x{(addr+imm*4)&0xFFFFFFFFFFFFFFFF:x}"
    if (opcode & 0x7F800000) == 0x37000000:
        rt = opcode&0x1F; bit = ((opcode>>19)&0x1F)|((opcode>>26)&0x20)
        imm = (opcode>>5)&0x3FFF
        if imm & 0x2000: imm = imm - 0x4000
        return f"TBNZ X{rt}, #{bit}, 0x{(addr+imm*4)&0xFFFFFFFFFFFFFFFF:x}"
    if (opcode & 0x7F800000) == 0x36000000:
        rt = opcode&0x1F; bit = ((opcode>>19)&0x1F)|((opcode>>26)&0x20)
        imm = (opcode>>5)&0x3FFF
        if imm & 0x2000: imm = imm - 0x4000
        return f"TBZ X{rt}, #{bit}, 0x{(addr+imm*4)&0xFFFFFFFFFFFFFFFF:x}"
    if (opcode & 0xFFC00000) == 0xEB000000 or (opcode & 0xFF20FC00) == 0xEB000000:
        return f"CMP/SUBS (0x{opcode:08x})"
    return f"??? (0x{opcode:08x})"


def find_strings(data, pattern, max_results=20):
    """Find all occurrences of a byte pattern"""
    results = []
    pos = 0
    while len(results) < max_results:
        pos = data.find(pattern, pos)
        if pos == -1: break
        # Extract full null-terminated string
        end = data.find(b'\x00', pos)
        if end == -1: end = pos + 100
        s = data[pos:min(end, pos+200)].decode('ascii', errors='replace')
        results.append((pos, s))
        pos += 1
    return results

def find_xrefs_to_string(data, string_offset, code_start, code_size):
    """Find code that references a string via ADRP+ADD pattern"""
    # Calculate page of string
    target_page = string_offset & ~0xFFF
    xrefs = []
    
    for i in range(0, min(code_size, 16*1024*1024), 4):
        op = read32(data, code_start + i)
        # Check for ADRP
        if (op & 0x9F000000) == 0x90000000:
            rd = op & 0x1F
            immhi = (op>>5) & 0x7FFFF
            immlo = (op>>29) & 3
            imm = (immhi<<2) | immlo
            if imm & 0x100000: imm = imm - 0x200000
            
            addr = code_start + i
            pc_page = addr & ~0xFFF
            adrp_target = (pc_page + (imm << 12)) & 0xFFFFFFFFFFFFFFFF
            
            if adrp_target == target_page:
                # Check next instruction for ADD with matching offset
                if i + 4 < code_size:
                    next_op = read32(data, code_start + i + 4)
                    if (next_op & 0xFF800000) == 0x91000000:  # ADD
                        add_imm = (next_op >> 10) & 0xFFF
                        if (adrp_target + add_imm) == string_offset:
                            xrefs.append(code_start + i)
    return xrefs

def scan_function_pointers_in_data(data, data_start, data_size, code_start, code_end):
    """Find function pointers in __DATA segment (patchable via KRW!)"""
    pointers = []
    for i in range(0, data_size, 8):
        val = read64(data, data_start + i)
        # Strip PAC bits
        stripped = val & 0x0000007FFFFFFFFF
        # Check if it points to code segment
        if code_start <= stripped <= code_end:
            pointers.append((data_start + i, val, stripped))
    return pointers

def main():
    print("=" * 80)
    print("  DSPloit AMFI Deep Analyzer v4")
    print("  Target: AMFI bypass paths in iOS 18.2 kernelcache")
    print("=" * 80)
    
    if not os.path.exists(KCACHE):
        print(f"\n❌ Kernelcache not found: {KCACHE}")
        print("Usage: python3 amfi_deep_analyze.py <kernelcache_path>")
        sys.exit(1)
    
    print(f"\nLoading: {KCACHE}")
    with open(KCACHE, 'rb') as f:
        data = f.read()
    
    file_size = len(data)
    print(f"Size: {file_size / 1024 / 1024:.1f} MB")
    
    # ================================================================
    print("\n" + "=" * 80)
    print("  SECTION 1: AMFI STRING REFERENCES")
    print("  Find all AMFI-related strings to locate check functions")
    print("=" * 80)
    
    amfi_strings = [
        b'AMFI:', b'amfi_', b'AMFI_', 
        b'amfi_check_dyld_policy_self',
        b'amfi_check_trust_cache',
        b'amfi_vnode_check_signature',
        b'amfi_vnode_check_exec',
        b'amfi_proc_check_get_task',
        b'amfi_file_check_mmap',
        b'amfi_check_dyld_policy_self',
        b'AppleMobileFileIntegrity',
        b'com.apple.private.amfi',
        b'cs_invalid',
        b'cs_blob',
        b'csblob_get_cdhash',
        b'trust_cache',
        b'trustcache',
        b'static_trust_cache',
        b'loadable_trust_cache',
        b'engineering_trust_cache',
        b'lookup_in_trust_cache',
        b'pmap_cs_',
        b'code_signing',
    ]
    
    all_amfi_refs = {}
    for pattern in amfi_strings:
        results = find_strings(data, pattern, max_results=5)
        if results:
            all_amfi_refs[pattern.decode()] = results
    
    print(f"\nFound {sum(len(v) for v in all_amfi_refs.values())} AMFI-related strings:\n")
    for pattern, refs in sorted(all_amfi_refs.items()):
        for offset, s in refs:
            print(f"  0x{offset:08x}: {s[:80]}")
    
    # ================================================================
    print("\n" + "=" * 80)
    print("  SECTION 2: MAC POLICY FUNCTION POINTERS (__DATA)")
    print("  These are in writable memory — PATCHABLE via KRW!")
    print("=" * 80)
    
    # MAC policy ops are stored as function pointer arrays in __DATA
    # If we find and patch these → bypass AMFI checks!
    mac_strings = [
        b'mac_policy_list',
        b'mac_policy_conf',
        b'mpo_vnode_check_exec',
        b'mpo_vnode_check_signature',
        b'mpo_proc_check_get_task',
        b'mpo_file_check_mmap',
        b'mpo_cred_check_label_update',
    ]
    
    mac_refs = {}
    for pattern in mac_strings:
        results = find_strings(data, pattern, max_results=3)
        if results:
            mac_refs[pattern.decode()] = results
    
    print(f"\nMAC policy strings: {sum(len(v) for v in mac_refs.values())}")
    for pattern, refs in sorted(mac_refs.items()):
        for offset, s in refs:
            print(f"  0x{offset:08x}: {s[:80]}")
    
    # ================================================================
    print("\n" + "=" * 80)
    print("  SECTION 3: TRUST CACHE STRUCTURE")
    print("  How CDHash lookup works — can we inject entries?")
    print("=" * 80)
    
    tc_strings = [
        b'trust_cache_lookup',
        b'trust_cache_contains',
        b'pmap_lookup_in_loaded_trust_caches',
        b'pmap_cs_lookup_trust_cache',
        b'TC_LOOKUP',
        b'amfi_tc_',
        b'trust_cache_runtime',
        b'loadable_trust_caches',
        b'trust_cache_image4',
    ]
    
    tc_refs = {}
    for pattern in tc_strings:
        results = find_strings(data, pattern, max_results=5)
        if results:
            tc_refs[pattern.decode()] = results
    
    print(f"\nTrust cache strings: {sum(len(v) for v in tc_refs.values())}")
    for pattern, refs in sorted(tc_refs.items()):
        for offset, s in refs:
            print(f"  0x{offset:08x}: {s[:80]}")
    
    # ================================================================
    print("\n" + "=" * 80)
    print("  SECTION 4: POSIX_SPAWN INTERNALS")
    print("  Why file_actions fail — find the implementation")
    print("=" * 80)
    
    spawn_strings = [
        b'posix_spawn',
        b'posix_spawnattr',
        b'_posix_spawn_file_actions',
        b'spawn_file_actions',
        b'exec_activate_image',
        b'exec_mach_imgact',
        b'load_machfile',
        b'exec_handle_sugid',
        b'imgact_',
    ]
    
    spawn_refs = {}
    for pattern in spawn_strings:
        results = find_strings(data, pattern, max_results=5)
        if results:
            spawn_refs[pattern.decode()] = results
    
    print(f"\nposix_spawn strings: {sum(len(v) for v in spawn_refs.values())}")
    for pattern, refs in sorted(spawn_refs.items()):
        for offset, s in refs:
            print(f"  0x{offset:08x}: {s[:80]}")
    
    # ================================================================
    print("\n" + "=" * 80)
    print("  SECTION 5: __DATA FUNCTION POINTERS (PATCHABLE!)")
    print("  Scan __DATA for pointers to __TEXT — these can be overwritten!")
    print("=" * 80)
    
    # Estimate __DATA location (after __TEXT which is ~12MB)
    # __TEXT: CODE_OFFSET to ~CODE_OFFSET + 12MB
    # __DATA_CONST: after __TEXT
    # __DATA: after __DATA_CONST
    
    # Heuristic: scan for dense function pointer regions
    # Function pointers look like: 0xFFFFFFF0XXXXXXXX (kernel VA)
    
    print("\nScanning for function pointer tables in file...")
    
    # Look for regions with many consecutive kernel pointers
    # Kernel pointers: 0xFFFFFFF0XXXXXXXX pattern
    dense_regions = []
    window = 256  # 32 pointers
    
    # Scan from 12MB to 20MB (likely __DATA region)
    scan_start = 12 * 1024 * 1024
    scan_end = min(20 * 1024 * 1024, file_size)
    
    for offset in range(scan_start, scan_end, window):
        count = 0
        for i in range(0, window, 8):
            val = read64(data, offset + i)
            # Check if looks like kernel pointer (with or without PAC)
            stripped = val & 0x0000FFFFFFFFFFFF
            if 0xFFF007000000 <= stripped <= 0xFFF00FFFFFFF:
                count += 1
        if count >= 16:  # At least 16/32 are kernel pointers
            dense_regions.append((offset, count))
    
    print(f"\nDense function pointer regions: {len(dense_regions)}")
    for offset, count in dense_regions[:20]:
        print(f"  0x{offset:08x}: {count}/32 kernel pointers")
        # Show first few
        for i in range(0, min(5*8, window), 8):
            val = read64(data, offset + i)
            if val != 0:
                stripped = val & 0x0000FFFFFFFFFFFF
                print(f"    +{i:3d}: 0x{val:016x} (stripped: 0x{stripped:012x})")
    
    # ================================================================
    print("\n" + "=" * 80)
    print("  SECTION 6: AMFI MAC POLICY OPS TABLE")
    print("  The holy grail — AMFI's function pointer table")
    print("  If in __DATA → patchable → bypass ALL AMFI checks!")
    print("=" * 80)
    
    # AMFI registers as a MAC policy module
    # Its ops table (mac_policy_ops) contains function pointers for each check
    # Key entries:
    #   mpo_vnode_check_exec → called on every exec
    #   mpo_vnode_check_signature → signature verification
    #   mpo_file_check_mmap → mmap permission check
    
    # Find "AppleMobileFileIntegrity" string and trace references
    amfi_name = data.find(b'AppleMobileFileIntegrity\x00')
    if amfi_name != -1:
        print(f"\n'AppleMobileFileIntegrity' string at: 0x{amfi_name:08x}")
        
        # Look for references to this string in nearby data
        # mac_policy_conf structure contains: name pointer, ops pointer, etc
        # Search for the string's file offset as a pointer value
        print("  Searching for references to this string...")
        
        # The string address in kernel VA would be approximately:
        # KERNEL_BASE + (amfi_name - some_offset)
        # But we don't know exact mapping. Instead, search for the file offset
        # pattern in nearby data
        
        # Search in __DATA region for pointer to this string
        for scan_off in range(scan_start, scan_end, 8):
            val = read64(data, scan_off)
            # Check if this could be a pointer to our string
            # (accounting for kernel VA translation)
            stripped = val & 0x0000FFFFFFFFFFFF
            # Heuristic: string is in __TEXT_CONST, pointer should be close
            if stripped != 0 and abs(int(stripped) - int(amfi_name)) < 0x1000000:
                # Possible reference! Check surrounding values
                nearby_ptrs = sum(1 for i in range(0, 64, 8) 
                                 if read64(data, scan_off + i) != 0)
                if nearby_ptrs >= 4:
                    print(f"  Possible mac_policy_conf at 0x{scan_off:08x}")
                    print(f"    (value 0x{val:016x} may reference string)")
                    for i in range(0, 80, 8):
                        v = read64(data, scan_off + i)
                        if v != 0:
                            print(f"    +{i:3d}: 0x{v:016x}")
                    break
    
    # ================================================================
    print("\n" + "=" * 80)
    print("  SECTION 7: KERNEL FUNCTION HOOKING CANDIDATES")
    print("  Functions called via pointer (indirect call) that we can redirect")
    print("=" * 80)
    
    # Find BLR instructions (indirect calls via register)
    # These call through function pointers — if pointer is in __DATA, patchable!
    blr_count = 0
    blr_locations = []
    
    for i in range(0, min(8*1024*1024, file_size - CODE_OFFSET), 4):
        op = read32(data, CODE_OFFSET + i)
        if (op & 0xFFFFFC1F) == 0xD63F0000:  # BLR Xn
            blr_count += 1
            if blr_count <= 50:
                reg = (op >> 5) & 0x1F
                blr_locations.append((CODE_OFFSET + i, reg))
    
    print(f"\nTotal BLR (indirect calls) in first 8MB: {blr_count}")
    print("First 20 BLR locations:")
    for addr, reg in blr_locations[:20]:
        # Disassemble context (2 instructions before)
        ctx = ""
        for j in range(-8, 4, 4):
            op = read32(data, addr + j)
            ctx += f" {decode_arm64(op, addr+j)}"
        print(f"  0x{addr:08x}: BLR X{reg} | context:{ctx}")
    
    # ================================================================
    print("\n" + "=" * 80)
    print("  SECTION 8: SUMMARY & EXPLOITATION PATHS")
    print("=" * 80)
    
    print("""
╔══════════════════════════════════════════════════════════════════════╗
║                    AMFI BYPASS RESEARCH SUMMARY                      ║
╠══════════════════════════════════════════════════════════════════════╣
║                                                                      ║
║  CONFIRMED FROM DEVICE TESTING:                                      ║
║  ✅ posix_spawn works (PIDs confirmed, process executes)             ║
║  ✅ System binaries run (/bin/df, /sbin/mount)                       ║
║  ✅ Copied binaries BLOCKED (ret=1, AMFI re-validates)               ║
║  ✅ mmap RWX allocates but APRR blocks execution                     ║
║  ✅ mprotect RWX returns success but APRR blocks                     ║
║  ✅ dlopen signed libs works, unsigned blocked                        ║
║  ✅ fork() works from launchd                                        ║
║  ❌ Shellcode execution impossible (APRR hardware)                   ║
║  ❌ cs_flags patch impossible (PPL)                                  ║
║  ❌ Kernel fd table in inaccessible zone                             ║
║                                                                      ║
║  POTENTIAL BYPASS PATHS (from kernelcache analysis):                 ║
║                                                                      ║
║  1. MAC POLICY OPS TABLE PATCH                                       ║
║     - AMFI registers mac_policy_ops with function pointers           ║
║     - If ops table is in __DATA (writable) → patch via KRW!          ║
║     - Replace mpo_vnode_check_exec with RET gadget                   ║
║     - All exec checks return 0 (allow) → run anything!               ║
║                                                                      ║
║  2. TRUST CACHE INJECTION                                            ║
║     - Find loadable_trust_caches linked list in kernel               ║
║     - If accessible via socket KRW → add our CDHash                  ║
║     - Requires: trust cache struct in accessible zone                ║
║                                                                      ║
║  3. AMFI SYSCTL/BOOT-ARG                                            ║
║     - amfi_get_out_of_my_way boot-arg disables AMFI                  ║
║     - If we can modify boot-args in kernel memory...                 ║
║     - Or: find amfi_allow_any_signature global variable              ║
║                                                                      ║
║  4. FUNCTION POINTER REDIRECT                                        ║
║     - Find BLR instructions that call through __DATA pointers        ║
║     - Redirect to our controlled address (RET gadget)                ║
║     - Specific target: AMFI's signature check function               ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
""")

if __name__ == "__main__":
    main()
