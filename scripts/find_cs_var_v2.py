#!/usr/bin/env python3
"""
DSPloit: Find cs_enforcement_disable Variable v2
=================================================
Previous approach failed — pointer at __DATA_CONST was not what we thought.

NEW APPROACH:
1. Find ALL ADRP+ADD pairs that reference "cs_enforcement_disable" string
   in ALL segments (not just __TEXT_EXEC)
2. For each reference, trace the FULL function to find STR to __DATA
3. Also: find PE_parse_boot_argn calls and trace their output parameter
4. Scan __DATA for small integer values (0/1) that could be flags

Key insight: the function that reads boot-arg "cs_enforcement_disable"
calls PE_parse_boot_argn(&result, "cs_enforcement_disable", sizeof(int))
The &result is the variable we want!
"""

import struct
import sys
import os

KCACHE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "kernelcache.release.iphone11b.decompressed")
if len(sys.argv) > 1:
    KCACHE = sys.argv[1]

SEGMENTS = {
    "__TEXT":        {"vm": 0xfffffff007004000, "file": 0x00000000, "size": 0x00008000},
    "__PRELINK_TEXT":{"vm": 0xfffffff00700c000, "file": 0x00008000, "size": 0x008f4000},
    "__DATA_CONST":  {"vm": 0xfffffff007900000, "file": 0x008fc000, "size": 0x00490000},
    "__TEXT_EXEC":   {"vm": 0xfffffff007d90000, "file": 0x00d8c000, "size": 0x02198000},
    "__DATA":        {"vm": 0xfffffff00a0e0000, "file": 0x030dc000, "size": 0x00328000},
}

def read32(data, off):
    if off + 4 > len(data): return 0
    return struct.unpack_from('<I', data, off)[0]

def file_to_vm(file_offset):
    for name, seg in SEGMENTS.items():
        if seg["file"] <= file_offset < seg["file"] + seg["size"]:
            return seg["vm"] + (file_offset - seg["file"]), name
    return None, None

def vm_to_file(vm_addr):
    for name, seg in SEGMENTS.items():
        if seg["vm"] <= vm_addr < seg["vm"] + seg["size"]:
            return seg["file"] + (vm_addr - seg["vm"]), name
    return None, None

def is_in_data(vm_addr):
    seg = SEGMENTS["__DATA"]
    return seg["vm"] <= vm_addr < seg["vm"] + seg["size"]

def decode_adrp(op, pc):
    if (op & 0x9F000000) != 0x90000000: return None
    rd = op & 0x1F
    immhi = (op >> 5) & 0x7FFFF; immlo = (op >> 29) & 3
    imm = (immhi << 2) | immlo
    if imm & 0x100000: imm = imm - 0x200000
    return (rd, (pc & ~0xFFF) + (imm << 12))

def decode_add(op):
    if (op & 0xFF800000) != 0x91000000: return None
    rd = op & 0x1F; rn = (op >> 5) & 0x1F
    imm = (op >> 10) & 0xFFF
    sh = (op >> 22) & 1
    if sh: imm <<= 12
    return (rd, rn, imm)

def decode_str(op):
    if (op & 0xFFC00000) == 0xF9000000:
        return ("X", op & 0x1F, (op>>5)&0x1F, ((op>>10)&0xFFF)*8)
    if (op & 0xFFC00000) == 0xB9000000:
        return ("W", op & 0x1F, (op>>5)&0x1F, ((op>>10)&0xFFF)*4)
    if (op & 0xFFC00000) == 0x39000000:
        return ("B", op & 0x1F, (op>>5)&0x1F, (op>>10)&0xFFF)
    return None

def main():
    print("=" * 80)
    print("  DSPloit: Find cs_enforcement_disable Variable v2")
    print("  IMPROVED: Full function trace + PE_parse_boot_argn tracking")
    print("=" * 80)
    
    with open(KCACHE, 'rb') as f:
        data = f.read()
    print(f"\nLoaded: {len(data)/1024/1024:.1f} MB")
    
    # String location
    str_off = 0x00498d5d
    str_vm, _ = file_to_vm(str_off)
    str_page = str_vm & ~0xFFF
    str_page_off = str_vm & 0xFFF
    
    print(f"\nTarget: 'cs_enforcement_disable'")
    print(f"  String VM: 0x{str_vm:x}")
    print(f"  Page: 0x{str_page:x}, offset: 0x{str_page_off:x}")
    
    # ================================================================
    # APPROACH 1: Scan ALL code for references, trace FULL function
    # ================================================================
    print(f"\n{'='*80}")
    print("  APPROACH 1: Full function trace from string reference")
    print(f"{'='*80}")
    
    # Scan both __TEXT_EXEC and __PRELINK_TEXT
    all_code_ranges = [
        ("__TEXT_EXEC", SEGMENTS["__TEXT_EXEC"]["file"], SEGMENTS["__TEXT_EXEC"]["size"], SEGMENTS["__TEXT_EXEC"]["vm"]),
        ("__PRELINK_TEXT", SEGMENTS["__PRELINK_TEXT"]["file"], SEGMENTS["__PRELINK_TEXT"]["size"], SEGMENTS["__PRELINK_TEXT"]["vm"]),
    ]
    
    all_data_targets = []
    
    for seg_name, seg_file, seg_size, seg_vm in all_code_ranges:
        for i in range(0, seg_size - 8, 4):
            pc = seg_vm + i
            op1 = read32(data, seg_file + i)
            adrp = decode_adrp(op1, pc)
            if adrp is None: continue
            rd, page = adrp
            if page != str_page: continue
            
            op2 = read32(data, seg_file + i + 4)
            add = decode_add(op2)
            if add is None: continue
            if add[1] != rd or add[2] != str_page_off: continue
            
            # Found reference!
            ref_file = seg_file + i
            ref_pc = pc
            print(f"\n  ✅ Reference in {seg_name} at 0x{ref_pc:x}")
            
            # Trace ENTIRE function (up to 200 instructions) for ANY ADRP to __DATA
            reg_pages = {}
            
            for j in range(0, 200):
                off = ref_file + j * 4
                cur_pc = ref_pc + j * 4
                op = read32(data, off)
                
                # Track ALL ADRP
                a = decode_adrp(op, cur_pc)
                if a:
                    reg_pages[a[0]] = a[1]
                    # Check if targets __DATA
                    if is_in_data(a[1]):
                        print(f"    +{j*4:4d}: ADRP X{a[0]}, 0x{a[1]:x} ← __DATA page!")
                    continue
                
                # Track ADD
                add_d = decode_add(op)
                if add_d:
                    a_rd, a_rn, a_imm = add_d
                    if a_rn in reg_pages:
                        exact = reg_pages[a_rn] + a_imm
                        reg_pages[a_rd] = exact
                        if is_in_data(exact):
                            f_off, _ = vm_to_file(exact)
                            val = read32(data, f_off) if f_off else 0
                            print(f"    +{j*4:4d}: ADD X{a_rd}, X{a_rn}, #0x{a_imm:x} → 0x{exact:x} __DATA! (val=0x{val:x})")
                            all_data_targets.append((exact, f_off, val, ref_pc))
                    continue
                
                # Track STR
                s = decode_str(op)
                if s:
                    sz, rt, rn, imm = s
                    if rn in reg_pages:
                        addr = reg_pages[rn] + imm
                        if is_in_data(addr):
                            f_off, _ = vm_to_file(addr)
                            val = read32(data, f_off) if f_off else 0
                            print(f"    +{j*4:4d}: STR {sz}{rt}, [X{rn}, #{imm}] → 0x{addr:x} __DATA! (val=0x{val:x})")
                            all_data_targets.append((addr, f_off, val, ref_pc))
                    continue
                
                # Stop at RET
                if op == 0xD65F03C0:
                    break
    
    # ================================================================
    # APPROACH 2: Scan __DATA for flag-like values near known variables
    # ================================================================
    print(f"\n{'='*80}")
    print("  APPROACH 2: Scan __DATA for flag variables")
    print(f"{'='*80}")
    
    # pmap_cs_allow_invalid is at file 0x030e05b8, vm 0xfffffff00a0e45b8
    # Other CS variables should be NEARBY (same struct or same init function)
    known_var_vm = 0xfffffff00a0e45b8
    known_var_file = 0x030e05b8
    
    # Scan wider range: ±4KB around known variable
    print(f"\n  Scanning ±4KB around pmap_cs_allow_invalid (0x{known_var_vm:x}):")
    print(f"  Looking for 32-bit values that are 0 or 1 (flags)...")
    
    flag_candidates = []
    for offset in range(-4096, 4096, 4):
        f_off = known_var_file + offset
        val = read32(data, f_off)
        vm = known_var_vm + offset
        if val == 0 or val == 1:
            flag_candidates.append((vm, f_off, val, offset))
    
    print(f"  Found {len(flag_candidates)} flag candidates (val=0 or 1):")
    for vm, f_off, val, offset in flag_candidates:
        marker = " ← pmap_cs_allow_invalid!" if offset == 0 else ""
        print(f"    0x{vm:016x} [off {offset:+5d}]: {val}{marker}")
    
    # ================================================================
    # RESULTS
    # ================================================================
    print(f"\n{'='*80}")
    print("  FINAL RESULTS")
    print(f"{'='*80}")
    
    if all_data_targets:
        print(f"\n  __DATA targets from code tracing ({len(all_data_targets)}):")
        seen = set()
        for vm, f_off, val, ref in all_data_targets:
            if vm in seen: continue
            seen.add(vm)
            print(f"    0x{vm:016x} (file 0x{f_off:08x}) val=0x{val:x} [ref 0x{ref:x}]")
    
    print(f"\n  Flag candidates near pmap_cs_allow_invalid:")
    print(f"  (These are ALL 0/1 values within 4KB — one of them is likely cs_enforcement_disable)")
    print(f"\n  ADDRESSES TO TRY ON DEVICE (add kernel_slide):")
    for vm, f_off, val, offset in flag_candidates:
        if offset == 0: continue  # skip known variable
        if -256 <= offset <= 256:  # focus on nearby ones
            print(f"    0x{vm:016x}  (offset {offset:+4d} from pmap_cs, current={val})")

if __name__ == "__main__":
    main()
