#!/usr/bin/env python3
"""
DSPloit: PPL/SPTM Bypass Research
===================================
Page Protection Layer (PPL) protects:
- Page tables (pmap)
- Trust caches
- Code signing structures (cs_blob)
- AMFI enforcement variables in protected zones

SPTM (Secure Page Table Monitor) is the newer version on A15+.

This script searches the kernelcache for:
1. PPL entry/exit functions (ppl_enter, ppl_leave, ppl_dispatch)
2. SPTM handler table
3. PPL-protected memory regions
4. Potential weaknesses (PPL functions that take user-controlled input)
5. pmap functions that modify page tables
6. Any "backdoor" or debug paths in PPL code

Target: kernelcache.release.iphone11b.decompressed (iOS 18.2, A12)
Note: A12 uses PPL (not SPTM). SPTM is A15+.
"""

import struct
import sys
import os

KCACHE = "kernelcache.release.iphone11b.decompressed"

def read_u32(data, off):
    return struct.unpack_from('<I', data, off)[0]

def read_u64(data, off):
    return struct.unpack_from('<Q', data, off)[0]

def find_all_segments(data):
    segs = {}
    ncmds = read_u32(data, 16)
    offset = 32
    for _ in range(ncmds):
        cmd = read_u32(data, offset)
        cmdsize = read_u32(data, offset + 4)
        if cmd == 0x19:
            segname = data[offset+8:offset+24].split(b'\x00')[0].decode()
            segs[segname] = {
                'vmaddr': read_u64(data, offset + 24),
                'vmsize': read_u64(data, offset + 32),
                'fileoff': read_u64(data, offset + 40),
                'filesize': read_u64(data, offset + 48),
            }
        offset += cmdsize
    return segs

def find_cstrings(data, target):
    target_bytes = target.encode() + b'\x00'
    results = []
    start = 0
    while True:
        idx = data.find(target_bytes, start)
        if idx == -1:
            break
        results.append(idx)
        start = idx + 1
    return results

def file_to_vm(segs, file_off):
    for seg in segs.values():
        if seg['fileoff'] <= file_off < seg['fileoff'] + seg['filesize']:
            return seg['vmaddr'] + (file_off - seg['fileoff'])
    return None

def main():
    if not os.path.exists(KCACHE):
        print(f"ERROR: {KCACHE} not found!")
        sys.exit(1)

    with open(KCACHE, 'rb') as f:
        data = f.read()

    print("=" * 80)
    print("DSPloit: PPL/SPTM Bypass Research")
    print(f"Kernelcache: {len(data) / 1024 / 1024:.1f} MB")
    print("=" * 80)

    segs = find_all_segments(data)
    for name, seg in sorted(segs.items(), key=lambda x: x[1]['vmaddr']):
        print(f"  {name:20s} vm=0x{seg['vmaddr']:016x} size=0x{seg['vmsize']:08x}")

    # =================================================================
    # SEARCH 1: PPL-related strings
    # =================================================================
    print("\n" + "=" * 80)
    print("SEARCH 1: PPL/SPTM Related Strings")
    print("=" * 80)

    ppl_strings = [
        "ppl_enter",
        "ppl_leave", 
        "ppl_dispatch",
        "ppl_handler",
        "pmap_enter",
        "pmap_remove",
        "pmap_protect",
        "pmap_page_protect",
        "pmap_cs",
        "pmap_lookup_in_loaded_trust_caches",
        "pmap_cs_associate",
        "pmap_cs_lookup_trust_cache",
        "ppl_trust_cache",
        "sptm",
        "SPTM",
        "ppl_bootstrap",
        "ppl_allocate",
        "ppl_deallocate",
        "PPL",
        "page_protection",
        "pmap_set_ppl",
        "pmap_mark_page",
        "kern_return_t pmap",
        "pmap_cs_allow",
        "pmap_cs_invalid",
        "cs_enforcement",
        "trust_cache_runtime_add",
        "pmap_image4_trust",
        "lockdown_handler",
        "monitor_call",
        "guarded_mode",
    ]

    found_strings = {}
    for s in ppl_strings:
        offsets = find_cstrings(data, s)
        if offsets:
            vm = file_to_vm(segs, offsets[0])
            found_strings[s] = (offsets[0], vm, len(offsets))
            print(f"  '{s}' -> vm=0x{vm:x} ({len(offsets)}x)")

    # =================================================================
    # SEARCH 2: PPL segment / section
    # =================================================================
    print("\n" + "=" * 80)
    print("SEARCH 2: PPL-specific Segments/Sections")
    print("=" * 80)

    # Look for __PPLTEXT, __PPLDATA, __PPLTRAMP segments
    ppl_segs = {k: v for k, v in segs.items() if 'PPL' in k or 'ppl' in k}
    if ppl_segs:
        print("  PPL segments found!")
        for name, seg in ppl_segs.items():
            print(f"    {name}: vm=0x{seg['vmaddr']:x} size=0x{seg['vmsize']:x}")
    else:
        print("  No dedicated PPL segments (might be inline in __TEXT_EXEC)")

    # Check for __TEXT_EXEC sections that might be PPL
    # On A12, PPL code lives in a special region of __TEXT_EXEC
    # marked by specific page table attributes

    # =================================================================
    # SEARCH 3: pmap function signatures
    # =================================================================
    print("\n" + "=" * 80)
    print("SEARCH 3: pmap Functions (Page Table Manipulation)")
    print("=" * 80)

    pmap_funcs = [
        "pmap_enter_options",
        "pmap_remove_range",
        "pmap_protect_options",
        "pmap_query_page_info",
        "pmap_find_pa",
        "pmap_create",
        "pmap_destroy",
        "pmap_switch",
        "pmap_map_bd",
        "pmap_cs_register",
        "pmap_cs_unregister",
        "pmap_cs_cd_register",
        "pmap_cs_cd_unregister",
        "pmap_trim",
        "pmap_unnest",
    ]

    print("  Functions found in strings:")
    for func in pmap_funcs:
        offsets = find_cstrings(data, func)
        if offsets:
            vm = file_to_vm(segs, offsets[0])
            print(f"    {func} -> vm=0x{vm:x}")

    # =================================================================
    # SEARCH 4: Trust cache registration functions
    # =================================================================
    print("\n" + "=" * 80)
    print("SEARCH 4: Trust Cache Registration (PPL-protected)")
    print("=" * 80)

    tc_funcs = [
        "pmap_lookup_in_loaded_trust_caches",
        "trust_cache_runtime_add",
        "pmap_cs_lookup_trust_cache",
        "ppl_trust_cache_rt",
        "static_trust_cache",
        "loadable_trust_cache",
        "image4_trust_cache",
        "pmap_image4_trust_caches",
        "trust_cache_init",
        "lookup_in_static_trust_cache",
    ]

    for func in tc_funcs:
        offsets = find_cstrings(data, func)
        if offsets:
            vm = file_to_vm(segs, offsets[0])
            print(f"  {func} -> vm=0x{vm:x}")

    # =================================================================
    # SEARCH 5: PPL dispatch table / handler array
    # =================================================================
    print("\n" + "=" * 80)
    print("SEARCH 5: PPL Dispatch / Handler Patterns")
    print("=" * 80)

    # PPL dispatch uses a table of function pointers
    # On A12, PPL is entered via a specific trap instruction
    # Look for HVC (Hypervisor Call) or SMC (Secure Monitor Call) instructions
    # HVC #0 = 0xD4000002, SMC #0 = 0xD4000003

    text_exec = segs.get('__TEXT_EXEC')
    if text_exec:
        te_start = text_exec['fileoff']
        te_end = te_start + text_exec['filesize']

        hvc_count = 0
        smc_count = 0
        hvc_locations = []
        smc_locations = []

        for off in range(te_start, te_end - 4, 4):
            insn = read_u32(data, off)
            # HVC: 0xD4000002 or HVC #imm (0xD4000002 | imm<<5)
            if (insn & 0xFFE0001F) == 0xD4000002:
                hvc_count += 1
                if len(hvc_locations) < 10:
                    vm = text_exec['vmaddr'] + (off - te_start)
                    imm = (insn >> 5) & 0xFFFF
                    hvc_locations.append((vm, imm))
            # SMC: 0xD4000003
            if (insn & 0xFFE0001F) == 0xD4000003:
                smc_count += 1
                if len(smc_locations) < 10:
                    vm = text_exec['vmaddr'] + (off - te_start)
                    imm = (insn >> 5) & 0xFFFF
                    smc_locations.append((vm, imm))

        print(f"  HVC instructions found: {hvc_count}")
        for vm, imm in hvc_locations[:5]:
            print(f"    HVC #{imm} at vm=0x{vm:x}")

        print(f"  SMC instructions found: {smc_count}")
        for vm, imm in smc_locations[:5]:
            print(f"    SMC #{imm} at vm=0x{vm:x}")

    # =================================================================
    # SEARCH 6: PPL-related panic strings (reveal internal logic)
    # =================================================================
    print("\n" + "=" * 80)
    print("SEARCH 6: PPL Panic/Assert Strings (Reveal Internal Logic)")
    print("=" * 80)

    panic_patterns = [
        "PPL",
        "ppl",
        "page table",
        "pmap_enter",
        "trust cache",
        "cs_invalid",
        "code signing",
        "not permitted",
        "permission denied",
        "lockdown",
        "monitor",
        "guarded",
    ]

    for pattern in panic_patterns:
        # Search for panic strings containing this pattern
        idx = 0
        count = 0
        while idx < len(data) - 100:
            idx = data.find(pattern.encode(), idx)
            if idx == -1:
                break
            # Check if this is in a readable string context
            # Read surrounding bytes to get full message
            start = max(0, idx - 20)
            end = min(len(data), idx + 80)
            chunk = data[start:end]
            # Find null terminators
            null_before = chunk[:20].rfind(b'\x00')
            null_after = chunk[20:].find(b'\x00')
            if null_before >= 0 and null_after >= 0:
                msg_start = start + null_before + 1
                msg_end = start + 20 + null_after
                msg = data[msg_start:msg_end]
                try:
                    decoded = msg.decode('ascii')
                    if len(decoded) > 10 and decoded.isprintable():
                        if count < 3:
                            vm = file_to_vm(segs, msg_start)
                            print(f"  [{pattern}] '{decoded[:70]}' (vm=0x{vm:x})")
                        count += 1
                except:
                    pass
            idx += 1
        if count > 3:
            print(f"    ... +{count-3} more")

    # =================================================================
    # SEARCH 7: __DATA variables related to PPL state
    # =================================================================
    print("\n" + "=" * 80)
    print("SEARCH 7: PPL State Variables in __DATA")
    print("=" * 80)

    # Known: pmap_cs_allow_invalid_internal at 0xfffffff00a0e45b8
    # Look for other pmap/ppl variables nearby
    data_seg = segs.get('__DATA')
    if data_seg:
        # Search for "pmap" strings that reference __DATA addresses
        pmap_vars = [
            "pmap_cs_allow_invalid",
            "pmap_cs_enforcement",
            "ppl_locked",
            "ppl_state",
            "trust_cache_loaded",
        ]
        for var in pmap_vars:
            offsets = find_cstrings(data, var)
            if offsets:
                vm = file_to_vm(segs, offsets[0])
                print(f"  '{var}' string at vm=0x{vm:x}")

    # =================================================================
    # SUMMARY
    # =================================================================
    print("\n" + "=" * 80)
    print("SUMMARY: PPL Bypass Feasibility")
    print("=" * 80)
    print("""
FINDINGS:
""")

    if hvc_count > 0:
        print(f"  - {hvc_count} HVC instructions = PPL entry points exist in kernel")
        print(f"  - PPL is ACTIVE on this device (A12)")
    if smc_count > 0:
        print(f"  - {smc_count} SMC instructions = Secure Monitor calls present")

    if ppl_segs:
        print(f"  - Dedicated PPL segments found = PPL code is isolated")
    else:
        print(f"  - No dedicated PPL segments = PPL code inline in __TEXT_EXEC")

    print(f"  - {len(found_strings)} PPL-related strings found")

    print("""
PPL BYPASS APPROACHES (theoretical):

1. PPL Handler Bug:
   - If any PPL handler has a logic bug (wrong bounds check, type confusion)
   - We could call it with crafted input to corrupt PPL-protected memory
   - Requires: finding vulnerable handler + crafting input

2. Race Condition:
   - PPL transitions (enter/leave) might have TOCTOU windows
   - If we can modify data between PPL check and PPL use...
   - Requires: precise timing + multi-core exploitation

3. Hardware Debug Interface:
   - JTAG/SWD can bypass PPL (hardware level)
   - Not applicable for software-only exploit

4. PPL Code Reuse:
   - Call legitimate PPL functions with unexpected arguments
   - E.g.: pmap_enter with our controlled physical page
   - Requires: understanding PPL function interfaces

5. Physical Memory Manipulation:
   - IOSurface maps physical memory to userspace
   - If PPL-protected page's physical address is known...
   - We already have IOSurface access from SpringBoard!
   - Requires: finding physical address of trust cache page

CONCLUSION:
  Approach 5 (physical memory via IOSurface) is most promising
  because we already have IOSurface access from SpringBoard.
  If we can determine the PHYSICAL address of a trust cache page,
  we might be able to map it via IOSurface and modify it directly,
  bypassing PPL's virtual memory protections.
""")

if __name__ == "__main__":
    main()
