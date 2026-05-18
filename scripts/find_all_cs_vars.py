#!/usr/bin/env python3
"""
DSPloit: Find ALL Code Signing Disable Variables
=================================================
pmap_cs_allow_invalid is already 1 but copies still blocked.
Need to find OTHER variables that control AMFI/CS enforcement.

Scan ALL code segments (including kext/PRELINK) for references to:
- cs_enforcement_disable
- cs_enforcement
- amfi_get_out_of_my_way  
- cs_debug
- proc_enforce

Also: scan __DATA segment directly for flag-like values near
known variable addresses.
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

def read64(data, off):
    if off + 8 > len(data): return 0
    return struct.unpack_from('<Q', data, off)[0]

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

def is_in_data(file_offset):
    seg = SEGMENTS["__DATA"]
    return seg["file"] <= file_offset < seg["file"] + seg["size"]

def is_in_data_const(file_offset):
    seg = SEGMENTS["__DATA_CONST"]
    return seg["file"] <= file_offset < seg["file"] + seg["size"]

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
    if (op & 0xFFC00000) == 0xF9000000:  # STR X
        return ("X", op & 0x1F, (op>>5)&0x1F, ((op>>10)&0xFFF)*8)
    if (op & 0xFFC00000) == 0xB9000000:  # STR W
        return ("W", op & 0x1F, (op>>5)&0x1F, ((op>>10)&0xFFF)*4)
    if (op & 0xFFC00000) == 0x39000000:  # STRB
        return ("B", op & 0x1F, (op>>5)&0x1F, (op>>10)&0xFFF)
    return None

def decode_ldr(op):
    if (op & 0xFFC00000) == 0xF9400000:  # LDR X
        return ("X", op & 0x1F, (op>>5)&0x1F, ((op>>10)&0xFFF)*8)
    if (op & 0xFFC00000) == 0xB9400000:  # LDR W
        return ("W", op & 0x1F, (op>>5)&0x1F, ((op>>10)&0xFFF)*4)
    return None

def scan_code_segment(data, seg_name, seg_file, seg_size, seg_vm, target_str_vm):
    """Scan a code segment for ADRP+ADD referencing target string"""
    target_page = target_str_vm & ~0xFFF
    target_off = target_str_vm & 0xFFF
    results = []
    
    for i in range(0, seg_size - 8, 4):
        pc = seg_vm + i
        op1 = read32(data, seg_file + i)
        adrp = decode_adrp(op1, pc)
        if adrp is None: continue
        rd, page = adrp
        if page != target_page: continue
        
        # Check ADD
        op2 = read32(data, seg_file + i + 4)
        add = decode_add(op2)
        if add is None: continue
        add_rd, add_rn, add_imm = add
        if add_rn != rd or add_imm != target_off: continue
        
        results.append((seg_file + i, pc))
    
    return results

def trace_forward_for_data_refs(data, file_off, pc, max_instrs=60):
    """From a code reference, trace forward to find STR/LDR to __DATA"""
    found = []
    reg_pages = {}
    
    for j in range(2, max_instrs):
        off = file_off + j * 4
        cur_pc = pc + j * 4
        op = read32(data, off)
        
        # ADRP
        adrp = decode_adrp(op, cur_pc)
        if adrp:
            reg_pages[adrp[0]] = adrp[1]
            continue
        
        # ADD
        add = decode_add(op)
        if add:
            a_rd, a_rn, a_imm = add
            if a_rn in reg_pages:
                reg_pages[a_rd] = reg_pages[a_rn] + a_imm
            continue
        
        # STR
        s = decode_str(op)
        if s:
            sz, rt, rn, imm = s
            if rn in reg_pages:
                addr = reg_pages[rn] + imm
                f_off, seg = vm_to_file(addr)
                if f_off:
                    found.append(("STR", sz, addr, f_off, seg, j*4))
            continue
        
        # LDR
        l = decode_ldr(op)
        if l:
            sz, rt, rn, imm = l
            if rn in reg_pages:
                addr = reg_pages[rn] + imm
                f_off, seg = vm_to_file(addr)
                if f_off:
                    found.append(("LDR", sz, addr, f_off, seg, j*4))
                    reg_pages[rt] = addr  # might be loading a pointer
            continue
    
    return found

def main():
    print("=" * 80)
    print("  DSPloit: Find ALL Code Signing Variables")
    print("  Scanning ALL code segments (kernel + kexts)")
    print("=" * 80)
    
    with open(KCACHE, 'rb') as f:
        data = f.read()
    print(f"\nLoaded: {len(data)/1024/1024:.1f} MB")
    
    # Target strings to trace
    targets = {
        "cs_enforcement_disable": 0x00498d5d,
        "cs_debug": 0x00080f7b,
        "cs_debug_fail_on_unsigned_code": 0x00080f84,
        "pmap_cs_allow_invalid_internal": 0x00050540,
    }
    
    # Also search for additional strings
    extra_patterns = [
        b'amfi_get_out_of_my_way\x00',
        b'cs_enforcement_panic\x00',
        b'cs_library_val_enable\x00',
        b'cs_process_enforcement\x00',
    ]
    
    for pat in extra_patterns:
        pos = data.find(pat)
        if pos != -1:
            name = pat.rstrip(b'\x00').decode()
            targets[name] = pos
            print(f"  Extra found: '{name}' at 0x{pos:08x}")
    
    all_variables = []
    
    # Scan BOTH __TEXT_EXEC and __PRELINK_TEXT
    code_segments = [
        ("__TEXT_EXEC", SEGMENTS["__TEXT_EXEC"]),
        ("__PRELINK_TEXT", SEGMENTS["__PRELINK_TEXT"]),
    ]
    
    for str_name, str_file_off in targets.items():
        str_vm, str_seg = file_to_vm(str_file_off)
        if str_vm is None:
            print(f"\n  ⚠️ '{str_name}' at 0x{str_file_off:x} — cannot map to VM")
            continue
        
        print(f"\n{'━'*80}")
        print(f"  Tracing: '{str_name}' (vm=0x{str_vm:x}, in {str_seg})")
        print(f"{'━'*80}")
        
        total_refs = 0
        for seg_name, seg_info in code_segments:
            refs = scan_code_segment(data, seg_name, seg_info["file"], 
                                    seg_info["size"], seg_info["vm"], str_vm)
            
            for ref_file, ref_pc in refs:
                total_refs += 1
                print(f"\n  ✅ Ref #{total_refs} in {seg_name} at vm=0x{ref_pc:x}")
                
                # Trace forward
                data_refs = trace_forward_for_data_refs(data, ref_file, ref_pc)
                
                for op_type, sz, addr, f_off, seg, offset in data_refs:
                    writable = is_in_data(f_off)
                    data_const = is_in_data_const(f_off)
                    
                    current_val = read32(data, f_off) if f_off else 0
                    
                    marker = ""
                    if writable: marker = "✅ __DATA (WRITABLE!)"
                    elif data_const: marker = "⚠️ __DATA_CONST (PPL)"
                    else: marker = f"({seg})"
                    
                    print(f"     +{offset:3d}: {op_type} {sz} → 0x{addr:016x} "
                          f"[file 0x{f_off:08x}] val=0x{current_val:x} {marker}")
                    
                    if writable:
                        all_variables.append({
                            "name": str_name,
                            "var_vm": addr,
                            "var_file": f_off,
                            "current": current_val,
                            "op": op_type,
                            "ref_pc": ref_pc,
                        })
                
                if total_refs >= 10:
                    break
            if total_refs >= 10:
                break
    
    # ================================================================
    # Also: scan __DATA directly near pmap_cs_allow_invalid (0x030e05b8)
    # Look for other flag variables nearby
    # ================================================================
    print(f"\n{'━'*80}")
    print(f"  SCANNING __DATA NEAR pmap_cs_allow_invalid (file 0x030e05b8)")
    print(f"{'━'*80}")
    
    known_var_file = 0x030e05b8
    known_var_vm = 0xfffffff00a0e45b8
    
    print(f"\n  Dumping 256 bytes around known variable:")
    for i in range(-128, 128, 4):
        off = known_var_file + i
        val = read32(data, off)
        vm = known_var_vm + i
        marker = " ← pmap_cs_allow_invalid_internal" if i == 0 else ""
        if val != 0 or i == 0:
            print(f"    0x{vm:016x} [+{i:4d}]: 0x{val:08x}{marker}")
    
    # ================================================================
    # RESULTS
    # ================================================================
    print(f"\n{'━'*80}")
    print(f"  RESULTS: ALL WRITABLE VARIABLES FOUND")
    print(f"{'━'*80}")
    
    if all_variables:
        seen = set()
        print(f"\n  Found {len(all_variables)} references to __DATA variables:\n")
        for var in all_variables:
            key = var["var_vm"]
            if key in seen: continue
            seen.add(key)
            print(f"  ✅ {var['name']}")
            print(f"     VM addr:  0x{var['var_vm']:016x}")
            print(f"     File off: 0x{var['var_file']:08x}")
            print(f"     Current:  0x{var['current']:08x}")
            print(f"     Access:   {var['op']}")
            print(f"     Ref from: 0x{var['ref_pc']:x}")
            print()
    else:
        print("\n  No additional __DATA variables found via code tracing.")
        print("  Variables might be accessed differently (indirect pointer, etc)")
    
    print(f"\n{'━'*80}")
    print(f"  DEVICE TESTING PLAN")
    print(f"{'━'*80}")
    print("""
  Variables to try patching on device:
  
  1. pmap_cs_allow_invalid_internal: 0xfffffff00a0e45b8 + slide
     Current: ALREADY 1 (already disabled!)
     
  2. Try nearby variables (±128 bytes from pmap_cs_allow_invalid):
     These might be other CS enforcement flags!
     
  3. For each variable found above:
     - Read current value
     - Write 1 (or 0 depending on semantics)
     - Try spawn copied binary
     - If works → THAT'S the flag!
""")
    
    # Print all addresses for device testing
    if all_variables:
        print("  ADDRESSES TO TEST ON DEVICE:")
        seen = set()
        for var in all_variables:
            if var["var_vm"] in seen: continue
            seen.add(var["var_vm"])
            print(f"    0x{var['var_vm']:016x}  ({var['name']}, current=0x{var['current']:x})")

if __name__ == "__main__":
    main()
