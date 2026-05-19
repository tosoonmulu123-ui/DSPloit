#!/usr/bin/env python3
"""
DSPloit: PPL Physical Memory Bypass Research
==============================================
Key insight from previous analysis:
- A12 PPL uses SOFTWARE isolation (0 HVC/SMC instructions!)
- PPL protects VIRTUAL memory mappings (page tables)
- But IOSurface can map PHYSICAL memory to userspace
- If we know the physical address of trust cache → map it → write directly

This script searches for:
1. Physical memory mapping functions (how kernel maps phys→virt)
2. IOSurface physical address handling code
3. pmap physical page tracking structures
4. kvtophys / phystokv conversion functions
5. Physical memory layout hints

The attack: IOSurface with IOSurfaceAddress property maps a physical page.
PPL only protects virtual mappings. If we map the SAME physical page
that backs a trust cache entry → we bypass PPL entirely!
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

def find_bytes_pattern(data, pattern, start=0, end=None):
    if end is None:
        end = len(data)
    results = []
    idx = start
    while idx < end:
        idx = data.find(pattern, idx)
        if idx == -1 or idx >= end:
            break
        results.append(idx)
        idx += 1
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
    print("DSPloit: PPL Physical Memory Bypass Research")
    print(f"Kernelcache: {len(data) / 1024 / 1024:.1f} MB")
    print("=" * 80)

    segs = find_all_segments(data)

    # =================================================================
    # SEARCH 1: Physical memory functions
    # =================================================================
    print("\n" + "=" * 80)
    print("SEARCH 1: Physical Memory Functions")
    print("=" * 80)

    phys_funcs = [
        "kvtophys",
        "phystokv",
        "ml_phys_read",
        "ml_phys_write",
        "pmap_find_phys",
        "pmap_vtophys",
        "IOMemoryDescriptor",
        "IOSurfaceAddress",
        "IOSurfaceGetBaseAddress",
        "IOSurfaceLock",
        "IOSurfaceCreate",
        "createMappingInTask",
        "mapPhysical",
        "physmap",
        "gPhysBase",
        "gVirtBase",
        "physBase",
        "virtBase",
        "arm_vm_init",
        "pmap_bootstrap",
        "pmap_virtual_region",
    ]

    for func in phys_funcs:
        offsets = find_cstrings(data, func)
        if offsets:
            vm = file_to_vm(segs, offsets[0])
            print(f"  '{func}' -> vm=0x{vm:x} ({len(offsets)}x)")

    # =================================================================
    # SEARCH 2: IOSurface physical mapping code
    # =================================================================
    print("\n" + "=" * 80)
    print("SEARCH 2: IOSurface Physical Mapping")
    print("=" * 80)

    iosurface_strings = [
        "IOSurfaceAddress",
        "IOSurfaceAllocSize",
        "IOSurfaceMemoryRegion",
        "PurpleGfxMem",
        "IOSurfacePrefetchPages",
        "IOSurfaceGetBaseAddress",
        "IOSurfaceRoot",
        "IOSurfaceRootUserClient",
        "IOSurface::create",
        "IOSurface::map",
        "IOSurface::wire",
        "IOSurface::getAddress",
        "IOSurface::getPhysicalAddress",
        "s_get_iokit_user_client_target",
    ]

    for s in iosurface_strings:
        offsets = find_cstrings(data, s)
        if offsets:
            vm = file_to_vm(segs, offsets[0])
            print(f"  '{s}' -> vm=0x{vm:x} ({len(offsets)}x)")

    # =================================================================
    # SEARCH 3: Physical-to-virtual mapping constants
    # =================================================================
    print("\n" + "=" * 80)
    print("SEARCH 3: Phys/Virt Base Addresses")
    print("=" * 80)

    # On iOS, physical memory typically starts at 0x800000000 (DRAM base)
    # Virtual kernel base is 0xfffffff007004000
    # The relationship: virt = phys - physBase + virtBase
    # gPhysBase and gVirtBase are kernel globals

    phys_base_strings = [
        "gPhysBase",
        "gVirtBase",
        "gPhysSize",
        "physmap_base",
        "physmap_end",
        "first_avail",
        "avail_start",
        "avail_end",
        "real_avail_end",
    ]

    for s in phys_base_strings:
        offsets = find_cstrings(data, s)
        if offsets:
            vm = file_to_vm(segs, offsets[0])
            print(f"  '{s}' -> vm=0x{vm:x}")

    # =================================================================
    # SEARCH 4: PPL page protection check strings
    # =================================================================
    print("\n" + "=" * 80)
    print("SEARCH 4: PPL Page Protection Checks")
    print("=" * 80)

    # These strings reveal WHERE PPL checks happen
    ppl_checks = [
        "attempt to map PPL-protected",
        "PPL-protected I/O",
        "ppl_page",
        "pmap_mark_page_as_ppl",
        "pmap_cs_check",
        "pmap_page_protect",
        "lockdown_page",
        "ppl_lockdown",
        "PMAP_CS",
        "cs_blob",
        "cs_validate_page",
        "cs_invalid_page",
    ]

    for s in ppl_checks:
        offsets = find_cstrings(data, s)
        if offsets:
            vm = file_to_vm(segs, offsets[0])
            # Read more context
            ctx_start = max(0, offsets[0] - 5)
            ctx_end = min(len(data), offsets[0] + len(s) + 50)
            ctx = data[ctx_start:ctx_end]
            try:
                null_idx = ctx.find(b'\x00', len(s) + 5)
                if null_idx > 0:
                    full_msg = ctx[5:null_idx].decode('ascii', errors='replace')
                else:
                    full_msg = s
            except:
                full_msg = s
            print(f"  '{full_msg[:70]}' (vm=0x{vm:x})")

    # =================================================================
    # SEARCH 5: IOSurface external method table
    # =================================================================
    print("\n" + "=" * 80)
    print("SEARCH 5: IOSurface User Client Methods")
    print("=" * 80)

    # IOSurfaceRootUserClient has external methods that handle
    # IOSurfaceAddress property. If we can find which method
    # processes this property, we can understand the validation.

    iosurface_methods = [
        "s_create_surface",
        "s_release_surface",
        "s_lock_surface",
        "s_unlock_surface",
        "s_get_value",
        "s_set_value",
        "s_get_iokit_user_client_target",
        "s_increment_use_count",
        "s_decrement_use_count",
        "s_set_notify",
        "s_set_surface_address",
        "s_get_surface_address",
    ]

    for method in iosurface_methods:
        offsets = find_cstrings(data, method)
        if offsets:
            vm = file_to_vm(segs, offsets[0])
            print(f"  {method} -> vm=0x{vm:x}")

    # =================================================================
    # SEARCH 6: Physical page allocation tracking
    # =================================================================
    print("\n" + "=" * 80)
    print("SEARCH 6: Page Allocation & Tracking")
    print("=" * 80)

    page_funcs = [
        "vm_page_grab",
        "vm_page_free",
        "vm_page_wire",
        "pmap_page_protect",
        "pmap_disconnect",
        "pmap_enter_pv",
        "pp_attr",
        "pv_head_table",
        "pai_to_pvh",
        "pvh_list",
        "pa_index",
        "managed_page",
    ]

    for func in page_funcs:
        offsets = find_cstrings(data, func)
        if offsets:
            vm = file_to_vm(segs, offsets[0])
            print(f"  '{func}' -> vm=0x{vm:x}")

    # =================================================================
    # SUMMARY & ATTACK PLAN
    # =================================================================
    print("\n" + "=" * 80)
    print("ATTACK PLAN: Physical Memory PPL Bypass")
    print("=" * 80)
    print("""
THEORY:
  PPL protects VIRTUAL memory mappings via page table attributes.
  But physical memory is just RAM — if we can map the same physical
  page through a DIFFERENT virtual mapping (one not PPL-protected),
  we can read/write the physical page directly.

ATTACK STEPS:
  1. Find physical address of trust cache page
     - Use pmap_find_phys(kernel_pmap, trust_cache_vaddr)
     - OR: scan IOSurface kernel object for physical page list
     - OR: use vm_page structures to trace virt→phys

  2. Map physical page via IOSurface
     - IOSurface with IOSurfaceAddress = physical_addr
     - IOSurfacePrefetchPages to wire it
     - IOSurfaceGetBaseAddress to get userspace pointer

  3. Write to trust cache via physical mapping
     - PPL doesn't protect this mapping (it's IOSurface, not pmap)
     - Write our CDHash directly to the trust cache entries
     - Kernel sees modified trust cache on next lookup

  4. Spawn unsigned binary
     - Binary's CDHash now in trust cache
     - AMFI approves → binary executes!

CHALLENGES:
  - Step 1 is hardest: finding physical address requires either:
    a) Calling pmap_find_phys from kernel context (we can't — PPL function)
    b) Reading page table entries (PPL-protected)
    c) Using IOKit to query physical addresses (might work from SpringBoard!)
    d) Scanning physical memory for known patterns (IOSurface can do this!)

  - IOSurfaceAddress might be REJECTED by kernel for arbitrary addresses
    (our exp 52 showed it doesn't work from app context)
    BUT: from SpringBoard with IOSurfaceRoot user client, it might work differently

DEVICE EXPERIMENT NEEDED:
  From SpringBoard RC:
  1. Create IOSurface with IOSurfaceAddress = known kernel physical addr
  2. Check if IOSurfaceGetBaseAddress returns non-NULL
  3. If yes → we have physical memory R/W → PPL bypass!
""")

if __name__ == "__main__":
    main()
