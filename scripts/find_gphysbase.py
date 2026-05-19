#!/usr/bin/env python3
"""
Find gPhysBase/gVirtBase offset in kernelcache.
Strategy: find phystokv function, then look for ADRP+LDR instructions
that reference the globals.

phystokv(pa) { return pa - gPhysBase + gVirtBase; }
The function loads two globals and does arithmetic.
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

def file_to_vm(segs, file_off):
    for seg in segs.values():
        if seg['fileoff'] <= file_off < seg['fileoff'] + seg['filesize']:
            return seg['vmaddr'] + (file_off - seg['fileoff'])
    return None

def vm_to_file(segs, vm_addr):
    for seg in segs.values():
        if seg['vmaddr'] <= vm_addr < seg['vmaddr'] + seg['vmsize']:
            return seg['fileoff'] + (vm_addr - seg['vmaddr'])
    return None

def decode_adrp(insn, pc):
    """Decode ADRP instruction: target = PC[31:12]:imm << 12"""
    if (insn & 0x9F000000) != 0x90000000:
        return None
    immlo = (insn >> 29) & 0x3
    immhi = (insn >> 5) & 0x7FFFF
    imm = ((immhi << 2) | immlo) << 12
    # Sign extend 33-bit value
    if imm & (1 << 32):
        imm |= 0xFFFFFFFF00000000
        imm = imm & 0xFFFFFFFFFFFFFFFF
    page = pc & ~0xFFF
    return (page + imm) & 0xFFFFFFFFFFFFFFFF

def decode_ldr_imm(insn):
    """Decode LDR Xt, [Xn, #imm] (64-bit)"""
    # LDR (immediate, unsigned offset): 1x111000010 imm12 Rn Rt
    if (insn & 0xFFC00000) == 0xF9400000:
        imm12 = (insn >> 10) & 0xFFF
        return imm12 * 8  # Scale by 8 for 64-bit
    return None

def main():
    if not os.path.exists(KCACHE):
        print(f"ERROR: {KCACHE} not found!")
        sys.exit(1)

    with open(KCACHE, 'rb') as f:
        data = f.read()

    segs = find_all_segments(data)
    
    print("=" * 70)
    print("Finding gPhysBase / gVirtBase in kernelcache")
    print("=" * 70)
    
    # Find phystokv string
    phystokv_str = data.find(b'phystokv\x00')
    if phystokv_str >= 0:
        phystokv_vm = file_to_vm(segs, phystokv_str)
        print(f"\n'phystokv' string at file=0x{phystokv_str:x}, vm=0x{phystokv_vm:x}")
    
    # Strategy: scan __DATA and __DATA_CONST for values that look like
    # gPhysBase (0x800000000) and gVirtBase (0xfffffff0XXXXXXXX)
    
    data_seg = segs.get('__DATA')
    data_const = segs.get('__DATA_CONST')
    
    print(f"\n__DATA: vm=0x{data_seg['vmaddr']:x}, size=0x{data_seg['vmsize']:x}")
    if data_const:
        print(f"__DATA_CONST: vm=0x{data_const['vmaddr']:x}, size=0x{data_const['vmsize']:x}")
    
    # Scan __DATA for gPhysBase pattern
    print("\n--- Scanning __DATA for gPhysBase (0x800000000) pattern ---")
    
    data_start = data_seg['fileoff']
    data_end = data_start + data_seg['filesize']
    
    candidates = []
    
    for off in range(data_start, data_end - 16, 8):
        val = read_u64(data, off)
        # gPhysBase is typically 0x800000000 on A12
        if val == 0x800000000:
            next_val = read_u64(data, off + 8)
            vm = file_to_vm(segs, off)
            # Check if next value could be gVirtBase
            if next_val > 0xfffffff000000000 and next_val < 0xffffffffffffffff:
                print(f"  CANDIDATE at file=0x{off:x}, vm=0x{vm:x}")
                print(f"    [0] = 0x{val:016x} (gPhysBase?)")
                print(f"    [1] = 0x{next_val:016x} (gVirtBase?)")
                candidates.append((vm, val, next_val))
            # Also check previous value
            if off >= data_start + 8:
                prev_val = read_u64(data, off - 8)
                if prev_val > 0xfffffff000000000 and prev_val < 0xffffffffffffffff:
                    vm_prev = file_to_vm(segs, off - 8)
                    print(f"  CANDIDATE (reversed) at file=0x{off-8:x}, vm=0x{vm_prev:x}")
                    print(f"    [0] = 0x{prev_val:016x} (gVirtBase?)")
                    print(f"    [1] = 0x{val:016x} (gPhysBase?)")
                    candidates.append((vm_prev, val, prev_val))
    
    if not candidates:
        print("  No exact 0x800000000 found. Trying range 0x800000000-0x8FFFFFFFF...")
        for off in range(data_start, data_end - 16, 8):
            val = read_u64(data, off)
            if 0x800000000 <= val <= 0x8FFFFFFFF and (val & 0xFFF) == 0:
                next_val = read_u64(data, off + 8)
                if next_val > 0xfffffff000000000 and (next_val & 0xFFF) == 0:
                    vm = file_to_vm(segs, off)
                    print(f"  RANGE CANDIDATE at vm=0x{vm:x}: phys=0x{val:x}, virt=0x{next_val:x}")
                    candidates.append((vm, val, next_val))
                    if len(candidates) >= 5:
                        break
    
    # Also try: scan for the phystokv function code and trace ADRP references
    print("\n--- Scanning near phystokv for ADRP+LDR patterns ---")
    
    text_exec = segs.get('__TEXT_EXEC')
    if text_exec and phystokv_str >= 0:
        # phystokv function is likely near its string reference
        # Search __TEXT_EXEC for references to the string
        te_start = text_exec['fileoff']
        te_end = te_start + text_exec['filesize']
        te_vmbase = text_exec['vmaddr']
        
        # Look for ADRP instructions that could reference __DATA globals
        # near where phystokv might be implemented
        # The function is small: sub x0, x0, gPhysBase; add x0, x0, gVirtBase; ret
        
        # Search for the pattern: ADRP + LDR + SUB + ADRP + LDR + ADD + RET
        # within first 1MB of __TEXT_EXEC
        
        found_globals = []
        for off in range(te_start, min(te_end, te_start + 0x200000) - 28, 4):
            insn0 = read_u32(data, off)
            insn1 = read_u32(data, off + 4)
            
            # Check for ADRP + LDR pattern
            pc = te_vmbase + (off - te_start)
            adrp_target = decode_adrp(insn0, pc)
            if adrp_target is None:
                continue
            
            ldr_offset = decode_ldr_imm(insn1)
            if ldr_offset is None:
                continue
            
            global_addr = adrp_target + ldr_offset
            
            # Check if this global is in __DATA and contains our target value
            global_file = vm_to_file(segs, global_addr)
            if global_file is not None and data_start <= global_file < data_end:
                global_val = read_u64(data, global_file)
                if global_val == 0x800000000:
                    print(f"  ADRP+LDR at vm=0x{pc:x} references global at vm=0x{global_addr:x}")
                    print(f"    Global value: 0x{global_val:016x} = gPhysBase!")
                    # Check next instruction pair for gVirtBase
                    insn2 = read_u32(data, off + 8)
                    insn3 = read_u32(data, off + 12)
                    adrp2 = decode_adrp(insn2, pc + 8)
                    if adrp2:
                        ldr2 = decode_ldr_imm(insn3)
                        if ldr2 is not None:
                            global2 = adrp2 + ldr2
                            global2_file = vm_to_file(segs, global2)
                            if global2_file:
                                global2_val = read_u64(data, global2_file)
                                print(f"    Next global at vm=0x{global2:x} = 0x{global2_val:016x}")
                                if global2_val > 0xfffffff000000000:
                                    print(f"    *** gVirtBase FOUND! ***")
                                    found_globals.append((global_addr, global2))
    
    # Summary
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    
    if candidates:
        print(f"\nFound {len(candidates)} candidate(s) for gPhysBase/gVirtBase:")
        for vm, phys, virt in candidates:
            print(f"  vm=0x{vm:x}: gPhysBase=0x{phys:x}, gVirtBase=0x{virt:x}")
            # Calculate offset from __DATA start for use in device scan
            offset_from_data = vm - data_seg['vmaddr']
            print(f"    Offset from __DATA start: 0x{offset_from_data:x}")
            print(f"    On device: __DATA_start + slide + 0x{offset_from_data:x}")
    else:
        print("\nNo candidates found in static analysis.")
        print("gPhysBase/gVirtBase might be initialized at boot time (not in kernelcache).")
        print("They ARE in __DATA but contain 0 in the static kernelcache.")
        print("Need to scan at runtime on device.")

if __name__ == "__main__":
    main()
