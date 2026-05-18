#!/usr/bin/env python3
"""
DSPloit: Find AMFI KEXT's Own Data Section
============================================
AMFI is a kernel extension (kext). Kexts have their OWN __DATA sections
that are SEPARATE from the main kernel's __DATA_CONST.

Key insight: kext __DATA might be in a DIFFERENT memory zone than
kernel __DATA_CONST — possibly accessible via socket KRW!

This script:
1. Find AMFI kext boundaries in kernelcache (via __PRELINK_INFO)
2. Locate AMFI's __DATA section
3. Find global variables that control AMFI behavior
4. Calculate addresses for device testing
"""

import struct
import sys
import os
import plistlib

KCACHE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "kernelcache.release.iphone11b.decompressed")
if len(sys.argv) > 1:
    KCACHE = sys.argv[1]

SEGMENTS = {
    "__TEXT":        {"vm": 0xfffffff007004000, "file": 0x00000000, "size": 0x00008000},
    "__PRELINK_TEXT":{"vm": 0xfffffff00700c000, "file": 0x00008000, "size": 0x008f4000},
    "__DATA_CONST":  {"vm": 0xfffffff007900000, "file": 0x008fc000, "size": 0x00490000},
    "__TEXT_EXEC":   {"vm": 0xfffffff007d90000, "file": 0x00d8c000, "size": 0x02198000},
    "__PRELINK_INFO":{"vm": 0xfffffff009f28000, "file": 0x02f24000, "size": 0x001b8000},
    "__DATA":        {"vm": 0xfffffff00a0e0000, "file": 0x030dc000, "size": 0x00328000},
}

def read32(data, off):
    if off + 4 > len(data): return 0
    return struct.unpack_from('<I', data, off)[0]

def read64(data, off):
    if off + 8 > len(data): return 0
    return struct.unpack_from('<Q', data, off)[0]

def main():
    print("=" * 80)
    print("  DSPloit: Find AMFI Kext Data Section")
    print("  Looking for AMFI's own writable globals")
    print("=" * 80)
    
    with open(KCACHE, 'rb') as f:
        data = f.read()
    print(f"\nLoaded: {len(data)/1024/1024:.1f} MB")
    
    # ================================================================
    # STEP 1: Parse __PRELINK_INFO to find AMFI kext info
    # ================================================================
    print(f"\n{'='*80}")
    print("  STEP 1: Parse __PRELINK_INFO for AMFI kext")
    print(f"{'='*80}")
    
    prelink_info = SEGMENTS["__PRELINK_INFO"]
    prelink_data = data[prelink_info["file"]:prelink_info["file"]+prelink_info["size"]]
    
    # Find XML plist in prelink info
    plist_start = prelink_data.find(b'<?xml')
    if plist_start == -1:
        plist_start = prelink_data.find(b'bplist')
    
    amfi_info = None
    if plist_start != -1:
        try:
            # Try to parse as plist
            plist_end = prelink_data.find(b'</plist>', plist_start)
            if plist_end != -1:
                plist_bytes = prelink_data[plist_start:plist_end+8]
                plist = plistlib.loads(plist_bytes)
                
                # Search for AMFI in kext list
                if isinstance(plist, dict):
                    kexts = plist.get('_PrelinkInfoDictionary', [])
                    for kext in kexts:
                        bundle_id = kext.get('CFBundleIdentifier', '')
                        if 'AMFI' in bundle_id or 'AppleMobileFileIntegrity' in bundle_id:
                            amfi_info = kext
                            print(f"\n  Found AMFI kext!")
                            print(f"  Bundle: {bundle_id}")
                            for key in ['_PrelinkExecutableLoadAddr', '_PrelinkExecutableSize',
                                       '_PrelinkModuleIndex', 'CFBundleName']:
                                if key in kext:
                                    val = kext[key]
                                    if isinstance(val, int):
                                        print(f"  {key}: 0x{val:x}")
                                    else:
                                        print(f"  {key}: {val}")
                            break
        except Exception as e:
            print(f"  Plist parse error: {e}")
    
    if amfi_info is None:
        print("  Could not parse __PRELINK_INFO plist")
        print("  Trying alternative: search for AMFI strings in code")
    
    # ================================================================
    # STEP 2: Find AMFI code region by string references
    # ================================================================
    print(f"\n{'='*80}")
    print("  STEP 2: Find AMFI code boundaries")
    print(f"{'='*80}")
    
    # AMFI-specific strings that only appear in AMFI kext code
    amfi_markers = [
        b'AMFI: ',
        b'AppleMobileFileIntegrity',
        b'amfi_check_dyld_policy_self',
        b'com.apple.private.amfi',
    ]
    
    amfi_string_offsets = []
    for marker in amfi_markers:
        pos = 0
        while True:
            pos = data.find(marker, pos)
            if pos == -1: break
            amfi_string_offsets.append(pos)
            pos += 1
    
    if amfi_string_offsets:
        min_off = min(amfi_string_offsets)
        max_off = max(amfi_string_offsets)
        print(f"\n  AMFI strings span: 0x{min_off:x} — 0x{max_off:x}")
        print(f"  Range: {(max_off-min_off)/1024:.1f} KB")
    
    # ================================================================
    # STEP 3: Find AMFI's global variables
    # ================================================================
    print(f"\n{'='*80}")
    print("  STEP 3: Search for AMFI global variables in __DATA")
    print(f"{'='*80}")
    
    # AMFI kext stores its state in globals. On older iOS these were:
    # - amfi_allow_any_signature (bool)
    # - amfi_get_out_of_my_way (bool)
    # - amfi_unrestrict_task_for_pid (bool)
    # On iOS 18, these might be renamed or moved.
    
    # Search for patterns near "AMFI" strings that reference __DATA
    # The AMFI kext code at 0x494xxx references strings
    # Its code is in __PRELINK_TEXT (0x8000 - 0x8fc000)
    # Its data would be in __DATA (0x30dc000 - 0x3404000)
    
    # Find ADRP instructions in AMFI code region that target __DATA
    amfi_code_start = 0x00490000  # approximate from string locations
    amfi_code_end = 0x004A0000
    
    print(f"\n  Scanning AMFI code region (0x{amfi_code_start:x} - 0x{amfi_code_end:x})")
    print(f"  Looking for ADRP to __DATA segment...")
    
    data_seg = SEGMENTS["__DATA"]
    data_vm_start = data_seg["vm"]
    data_vm_end = data_seg["vm"] + data_seg["size"]
    
    # But wait — AMFI code is in __PRELINK_TEXT
    # Its VM address = __PRELINK_TEXT vm + (file_offset - __PRELINK_TEXT file)
    prelink_text = SEGMENTS["__PRELINK_TEXT"]
    
    amfi_data_refs = []
    
    for i in range(amfi_code_start, min(amfi_code_end, len(data)-4), 4):
        op = read32(data, i)
        # Check for ADRP
        if (op & 0x9F000000) != 0x90000000:
            continue
        
        rd = op & 0x1F
        immhi = (op >> 5) & 0x7FFFF
        immlo = (op >> 29) & 3
        imm = (immhi << 2) | immlo
        if imm & 0x100000: imm = imm - 0x200000
        
        # Calculate PC for this instruction
        pc_vm = prelink_text["vm"] + (i - prelink_text["file"])
        pc_page = pc_vm & ~0xFFF
        target_page = pc_page + (imm << 12)
        
        # Check if target is in __DATA
        if data_vm_start <= target_page < data_vm_end:
            # Check next instruction for ADD
            if i + 4 < len(data):
                op2 = read32(data, i + 4)
                if (op2 & 0xFF800000) == 0x91000000:  # ADD
                    add_imm = (op2 >> 10) & 0xFFF
                    exact_addr = target_page + add_imm
                    
                    # Calculate file offset of target
                    target_file = data_seg["file"] + (exact_addr - data_seg["vm"])
                    if 0 <= target_file < len(data):
                        current_val = read32(data, target_file)
                        amfi_data_refs.append((exact_addr, target_file, current_val, pc_vm))
    
    print(f"\n  Found {len(amfi_data_refs)} ADRP→__DATA references from AMFI code:")
    
    seen = set()
    for vm, foff, val, ref_pc in amfi_data_refs:
        if vm in seen: continue
        seen.add(vm)
        print(f"    0x{vm:016x} [file 0x{foff:08x}] val=0x{val:08x} (ref from 0x{ref_pc:x})")
    
    # ================================================================
    # STEP 4: Also scan for AMFI-specific patterns in __DATA
    # ================================================================
    print(f"\n{'='*80}")
    print("  STEP 4: Scan __DATA for AMFI-related patterns")
    print(f"{'='*80}")
    
    # Look for small clusters of 0/1 values in __DATA that could be AMFI flags
    # AMFI typically has 5-10 boolean flags grouped together
    
    data_start = data_seg["file"]
    data_size = data_seg["size"]
    
    # Find clusters of 4+ consecutive 32-bit 0/1 values
    clusters = []
    i = 0
    while i < data_size - 16:
        # Check if 4 consecutive values are all 0 or 1
        vals = [read32(data, data_start + i + j*4) for j in range(4)]
        if all(v <= 1 for v in vals) and any(v == 1 for v in vals):
            # Found a cluster! Extend it
            cluster_start = i
            cluster_vals = []
            while i < data_size and read32(data, data_start + i) <= 1:
                cluster_vals.append(read32(data, data_start + i))
                i += 4
                if len(cluster_vals) > 20: break
            
            if 4 <= len(cluster_vals) <= 20 and any(v == 1 for v in cluster_vals):
                vm_addr = data_seg["vm"] + cluster_start
                clusters.append((vm_addr, cluster_start, cluster_vals))
        else:
            i += 4
    
    print(f"\n  Found {len(clusters)} flag clusters in __DATA:")
    for vm, off, vals in clusters[:20]:
        vals_str = ''.join(str(v) for v in vals)
        print(f"    0x{vm:016x} [+0x{off:x}]: [{vals_str}] ({len(vals)} flags)")
    
    # ================================================================
    # RESULTS
    # ================================================================
    print(f"\n{'='*80}")
    print("  RESULTS: ADDRESSES TO TEST ON DEVICE")
    print(f"{'='*80}")
    
    print("\n  AMFI __DATA references (add kernel_slide):")
    seen = set()
    for vm, foff, val, ref_pc in amfi_data_refs:
        if vm in seen: continue
        seen.add(vm)
        if val <= 1:  # likely flags
            print(f"    ⭐ 0x{vm:016x} = {val} (likely flag!)")
    
    print("\n  Flag clusters (add kernel_slide):")
    for vm, off, vals in clusters[:10]:
        print(f"    0x{vm:016x}: {vals}")
    
    print("""
  
  NEXT STEP ON DEVICE:
  1. For each flag address above, try:
     - Read current value (verify accessible)
     - If 0 → write 1 (or vice versa)
     - Test spawn after each write
  2. Focus on addresses referenced from AMFI code
  3. These are in __DATA (writable!) not __DATA_CONST
""")

if __name__ == "__main__":
    main()
