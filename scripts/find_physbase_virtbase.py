#!/usr/bin/env python3
"""
DSPloit: Find gPhysBase / gVirtBase in kernelcache
====================================================
These kernel globals store the physical-to-virtual translation:
  virtual_addr = physical_addr - gPhysBase + gVirtBase
  physical_addr = virtual_addr - gVirtBase + gPhysBase

If we can READ these from device (via socket KRW), we can convert
any kernel virtual address to its physical address.

Then: map that physical address via IOSurface → bypass PPL!

Target: kernelcache.release.iphone11b.decompressed (iOS 18.2, A12)
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

def find_cstring(data, target):
    target_bytes = target.encode() + b'\x00'
    idx = data.find(target_bytes)
    return idx if idx != -1 else None

def file_to_vm(segs, file_off):
    for seg in segs.values():
        if seg['fileoff'] <= file_off < seg['fileoff'] + seg['filesize']:
            return seg['vmaddr'] + (file_off - seg['fileoff'])
    return None

def decode_adrp(insn, pc):
    if (insn & 0x9F000000) != 0x90000000:
        return None
    immhi = (insn >> 5) & 0x7FFFF
    immlo = (insn >> 29) & 0x3
    imm = (immhi << 2) | immlo
    if imm & 0x100000:
        imm = imm - 0x200000
    page = (pc & ~0xFFF) + (imm << 12)
    return page & 0xFFFFFFFFFFFFFFFF

def main():
    if not os.path.exists(KCACHE):
        print(f"ERROR: {KCACHE} not found!")
        sys.exit(1)

    with open(KCACHE, 'rb') as f:
        data = f.read()

    print("=" * 80)
    print("DSPloit: Find gPhysBase / gVirtBase")
    print(f"Kernelcache: {len(data) / 1024 / 1024:.1f} MB")
    print("=" * 80)

    segs = find_all_segments(data)
    text_exec = segs['__TEXT_EXEC']
    data_seg = segs['__DATA']

    # Method 1: Find "phystokv" string and trace code references
    # phystokv uses gPhysBase and gVirtBase
    print("\n--- Method 1: Find via 'phystokv' string reference ---")
    
    phystokv_off = find_cstring(data, "phystokv")
    if phystokv_off:
        phystokv_vm = file_to_vm(segs, phystokv_off)
        print(f"'phystokv' string at vm=0x{phystokv_vm:x}")
        
        # Search __TEXT_EXEC for ADRP instructions that reference __DATA
        # near where phystokv is referenced
        te_start = text_exec['fileoff']
        te_end = te_start + text_exec['filesize']
        te_vm = text_exec['vmaddr']
        
        # Find code that references the phystokv string
        target_page = phystokv_vm & ~0xFFF
        refs = []
        for off in range(te_start, te_end - 4, 4):
            insn = read_u32(data, off)
            pc = te_vm + (off - te_start)
            page = decode_adrp(insn, pc)
            if page == target_page:
                refs.append((off, pc))
        
        print(f"Code references to phystokv string page: {len(refs)}")
        
        # For each reference, look nearby for ADRP to __DATA
        # (gPhysBase/gVirtBase are in __DATA)
        data_vm_start = data_seg['vmaddr']
        data_vm_end = data_seg['vmaddr'] + data_seg['vmsize']
        
        data_refs = set()
        for ref_off, ref_pc in refs[:5]:
            # Scan +-100 instructions around this reference
            scan_start = max(te_start, ref_off - 400)
            scan_end = min(te_end, ref_off + 400)
            
            for off in range(scan_start, scan_end, 4):
                insn = read_u32(data, off)
                pc = te_vm + (off - te_start)
                page = decode_adrp(insn, pc)
                if page and data_vm_start <= page < data_vm_end:
                    # Check next instruction for ADD/LDR
                    if off + 4 < te_end:
                        next_insn = read_u32(data, off + 4)
                        # LDR X (64-bit load)
                        if (next_insn & 0xFFC00000) == 0xF9400000:
                            ldr_imm = ((next_insn >> 10) & 0xFFF) * 8
                            target = page + ldr_imm
                            if data_vm_start <= target < data_vm_end:
                                data_refs.add(target)
        
        if data_refs:
            print(f"\n__DATA variables referenced near phystokv:")
            for addr in sorted(data_refs):
                # Read value at this address in kernelcache
                file_off_var = data_seg['fileoff'] + (addr - data_seg['vmaddr'])
                if 0 <= file_off_var < len(data) - 8:
                    val = read_u64(data, file_off_var)
                    print(f"  vm=0x{addr:x} (file=0x{file_off_var:x}): value=0x{val:x}")

    # Method 2: Search for known pattern
    # gPhysBase and gVirtBase are typically adjacent in __DATA
    # gVirtBase should be close to 0xfffffff007004000 (kernel base)
    # gPhysBase is typically 0x800000000 range on A12
    print("\n--- Method 2: Scan __DATA for phys/virt base pair ---")
    
    data_start = data_seg['fileoff']
    data_end = data_start + data_seg['filesize']
    
    candidates = []
    for off in range(data_start, data_end - 16, 8):
        val = read_u64(data, off)
        # Look for values that could be gVirtBase (kernel VA range)
        if 0xfffffff000000000 < val < 0xffffffffffff0000:
            # Check adjacent value for gPhysBase (physical range 0x8xxxxxxxx)
            next_val = read_u64(data, off + 8)
            prev_val = read_u64(data, off - 8) if off > data_start else 0
            
            # gPhysBase is typically in 0x800000000 - 0x900000000 range
            if 0x800000000 <= next_val <= 0x900000000:
                vm = file_to_vm(segs, off)
                candidates.append((vm, val, next_val, "virt then phys"))
            if 0x800000000 <= prev_val <= 0x900000000:
                vm = file_to_vm(segs, off)
                candidates.append((vm, prev_val, val, "phys then virt"))
    
    if candidates:
        print(f"Found {len(candidates)} potential gPhysBase/gVirtBase pairs:")
        for vm, phys_or_virt1, phys_or_virt2, order in candidates[:10]:
            print(f"  vm=0x{vm:x}: {order} = (0x{phys_or_virt1:x}, 0x{phys_or_virt2:x})")
    else:
        print("No obvious pairs found (values might be 0 in static kernelcache)")
        print("gPhysBase/gVirtBase are likely initialized at BOOT TIME only")

    # Method 3: Find via XPF offset names
    # XPF patchfinder resolves these as "physBase" and "virtBase"
    print("\n--- Method 3: Known XPF symbol names ---")
    for name in ["physBase", "virtBase", "gPhysBase", "gVirtBase", 
                 "phys_base", "virt_base", "arm_vm_init"]:
        off = find_cstring(data, name)
        if off:
            vm = file_to_vm(segs, off)
            print(f"  '{name}' string at vm=0x{vm:x}")

    # Method 4: Find pmap_bootstrap which initializes these
    print("\n--- Method 4: pmap_bootstrap references ---")
    pmap_boot = find_cstring(data, "pmap_bootstrap")
    if pmap_boot:
        pmap_vm = file_to_vm(segs, pmap_boot)
        print(f"  'pmap_bootstrap' at vm=0x{pmap_vm:x}")
        print(f"  This function initializes gPhysBase/gVirtBase at boot")

    # Summary
    print("\n" + "=" * 80)
    print("DEVICE EXPERIMENT PLAN")
    print("=" * 80)
    print("""
ON DEVICE (via socket KRW from launchd):

1. Read gPhysBase and gVirtBase:
   - These are in __DATA segment
   - Try reading addresses found above
   - Values will be NON-ZERO at runtime (set during boot)

2. Once we have gPhysBase and gVirtBase:
   physical_addr = virtual_addr - gVirtBase + gPhysBase

3. Calculate trust cache physical address:
   - We know pmap_cs_allow_invalid at vm=0xfffffff00a0e45b8 + slide
   - Trust cache is nearby in __DATA
   - phys_trust_cache = trust_cache_vm - gVirtBase + gPhysBase

4. Map physical address via PurpleGfxMem IOSurface:
   - Create large PurpleGfxMem surface
   - Check if it overlaps trust cache physical page
   - OR: try IOSurfaceAddress with calculated physical addr

5. Write CDHash to mapped trust cache → FULL JAILBREAK!

ADDRESSES TO TRY ON DEVICE (add kernel_slide):
""")
    
    if data_refs:
        for addr in sorted(data_refs)[:5]:
            print(f"  0x{addr:x} + slide  (near phystokv)")
    
    if candidates:
        for vm, _, _, _ in candidates[:3]:
            print(f"  0x{vm:x} + slide  (potential pair)")

if __name__ == "__main__":
    main()
