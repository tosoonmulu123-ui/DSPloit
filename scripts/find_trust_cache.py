#!/usr/bin/env python3
"""
DSPloit: Find Trust Cache structures in kernelcache
====================================================
Trust caches are linked lists of CDHash arrays in kernel memory.
If we can find the HEAD pointer and it's in a zone accessible via socket KRW,
we can ADD our binary's CDHash → full AMFI bypass!

Also searches for:
- AMFI MAC policy ops table (function pointers we might patch)
- pmap_cs trust cache registration functions
- Static trust cache entries (built into kernel)

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

def find_segment(data, name):
    """Find Mach-O segment by name"""
    magic = read_u32(data, 0)
    if magic != 0xFEEDFACF:
        print(f"Not a Mach-O 64 file (magic=0x{magic:x})")
        return None
    
    ncmds = read_u32(data, 16)
    offset = 32  # mach_header_64 size
    
    for _ in range(ncmds):
        cmd = read_u32(data, offset)
        cmdsize = read_u32(data, offset + 4)
        
        if cmd == 0x19:  # LC_SEGMENT_64
            segname = data[offset+8:offset+24].split(b'\x00')[0].decode()
            vmaddr = read_u64(data, offset + 24)
            vmsize = read_u64(data, offset + 32)
            fileoff = read_u64(data, offset + 40)
            filesize = read_u64(data, offset + 48)
            
            if segname == name:
                return {
                    'name': segname,
                    'vmaddr': vmaddr,
                    'vmsize': vmsize,
                    'fileoff': fileoff,
                    'filesize': filesize,
                }
        
        offset += cmdsize
    return None

def find_cstring(data, target, segment_info=None):
    """Find a C string in the binary, return file offset"""
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

def find_xrefs_to_offset(data, text_seg, target_file_offset, data_seg):
    """Find ADRP+ADD/LDR sequences that reference a target address"""
    # Convert file offset to VM address
    target_vm = data_seg['vmaddr'] + (target_file_offset - data_seg['fileoff'])
    
    results = []
    text_start = text_seg['fileoff']
    text_end = text_start + text_seg['filesize']
    
    # Scan for ADRP instructions that could reach our target
    for off in range(text_start, text_end - 4, 4):
        insn = read_u32(data, off)
        
        # ADRP: 1xx10000 xxxxxxxx xxxxxxxx xxxddddd
        if (insn & 0x9F000000) == 0x90000000:
            # Decode ADRP
            rd = insn & 0x1F
            immhi = (insn >> 5) & 0x7FFFF
            immlo = (insn >> 29) & 0x3
            imm = (immhi << 2) | immlo
            if imm & 0x100000:  # sign extend 21-bit
                imm |= ~0x1FFFFF
                imm = imm & 0xFFFFFFFFFFFFFFFF
            
            pc = text_seg['vmaddr'] + (off - text_start)
            page = (pc & ~0xFFF) + (imm << 12)
            
            # Check if page matches target page
            if (page & ~0xFFF) == (target_vm & ~0xFFF):
                # Check next instruction for ADD/LDR with matching page offset
                if off + 4 < text_end:
                    next_insn = read_u32(data, off + 4)
                    # ADD immediate: x0010001 0xxxxxxx xxxxxxxx xxxddddd
                    if (next_insn & 0x7F800000) == 0x11000000:
                        add_imm = (next_insn >> 10) & 0xFFF
                        shift = (next_insn >> 22) & 0x3
                        if shift == 1:
                            add_imm <<= 12
                        final_addr = page + add_imm
                        if final_addr == target_vm:
                            results.append((off, pc, 'ADRP+ADD'))
                    # LDR immediate: 1x111001 0xxxxxxx xxxxxxxx xxxddddd  
                    elif (next_insn & 0xBF400000) == 0xB9400000:
                        ldr_imm = ((next_insn >> 10) & 0xFFF) << 2
                        final_addr = page + ldr_imm
                        if abs(final_addr - target_vm) < 16:
                            results.append((off, pc, 'ADRP+LDR'))
    
    return results

def main():
    if not os.path.exists(KCACHE):
        print(f"ERROR: {KCACHE} not found!")
        print("Run from project root directory")
        sys.exit(1)
    
    print("=" * 80)
    print("DSPloit: Trust Cache & AMFI Hook Analysis")
    print("=" * 80)
    
    with open(KCACHE, 'rb') as f:
        data = f.read()
    
    print(f"Loaded: {len(data) / 1024 / 1024:.1f} MB")
    
    # Find segments
    text_exec = find_segment(data, '__TEXT_EXEC')
    data_seg = find_segment(data, '__DATA')
    data_const = find_segment(data, '__DATA_CONST')
    prelink_text = find_segment(data, '__PRELINK_TEXT')
    
    print(f"\n__TEXT_EXEC: vm=0x{text_exec['vmaddr']:x}, file=0x{text_exec['fileoff']:x}, size=0x{text_exec['filesize']:x}")
    print(f"__DATA:      vm=0x{data_seg['vmaddr']:x}, file=0x{data_seg['fileoff']:x}, size=0x{data_seg['filesize']:x}")
    print(f"__DATA_CONST: vm=0x{data_const['vmaddr']:x}, file=0x{data_const['fileoff']:x}, size=0x{data_const['filesize']:x}")
    
    # ═══════════════════════════════════════════════════════════════
    # SEARCH 1: Trust Cache strings
    # ═══════════════════════════════════════════════════════════════
    print("\n" + "=" * 80)
    print("SEARCH 1: Trust Cache Related Strings")
    print("=" * 80)
    
    tc_strings = [
        "trust_cache",
        "pmap_lookup_in_loaded_trust_caches",
        "pmap_cs_lookup_trust_cache",
        "static_trust_cache",
        "loadable_trust_cache",
        "engineering_trust_cache",
        "trust_cache_runtime_add",
        "pmap_image4_trust_caches",
        "amfi_trust_cache",
        "AMFI: trust cache",
        "com.apple.MobileFileIntegrity",
    ]
    
    for s in tc_strings:
        offsets = find_cstring(data, s)
        if offsets:
            for off in offsets[:3]:
                # Determine which segment
                seg = "?"
                vm = 0
                if data_seg and data_seg['fileoff'] <= off < data_seg['fileoff'] + data_seg['filesize']:
                    seg = "__DATA"
                    vm = data_seg['vmaddr'] + (off - data_seg['fileoff'])
                elif prelink_text and prelink_text['fileoff'] <= off < prelink_text['fileoff'] + prelink_text['filesize']:
                    seg = "__PRELINK_TEXT"
                    vm = prelink_text['vmaddr'] + (off - prelink_text['fileoff'])
                elif text_exec and text_exec['fileoff'] <= off < text_exec['fileoff'] + text_exec['filesize']:
                    seg = "__TEXT_EXEC"
                    vm = text_exec['vmaddr'] + (off - text_exec['fileoff'])
                elif data_const and data_const['fileoff'] <= off < data_const['fileoff'] + data_const['filesize']:
                    seg = "__DATA_CONST"
                    vm = data_const['vmaddr'] + (off - data_const['fileoff'])
                
                print(f"  '{s}' → file=0x{off:x}, vm=0x{vm:x} ({seg})")
    
    # ═══════════════════════════════════════════════════════════════
    # SEARCH 2: AMFI MAC Policy Ops
    # ═══════════════════════════════════════════════════════════════
    print("\n" + "=" * 80)
    print("SEARCH 2: AMFI MAC Policy Operations Table")
    print("=" * 80)
    print("Looking for mac_policy_ops struct (array of function pointers)...")
    
    # mac_policy_ops is a struct of ~300+ function pointers
    # It's in __DATA_CONST (read-only after boot) or __DATA
    # The struct is registered via mac_policy_register()
    
    # Find "AppleMobileFileIntegrity" string (AMFI kext name)
    amfi_name_offsets = find_cstring(data, "AppleMobileFileIntegrity")
    if amfi_name_offsets:
        print(f"  AMFI kext name at file offsets: {[hex(x) for x in amfi_name_offsets[:3]]}")
    
    # Find "AMFI" short name (used in mac_policy_conf)
    amfi_short = find_cstring(data, "AMFI")
    
    # ═══════════════════════════════════════════════════════════════
    # SEARCH 3: Trust Cache struct layout
    # ═══════════════════════════════════════════════════════════════
    print("\n" + "=" * 80)
    print("SEARCH 3: Trust Cache Data Structures in __DATA")
    print("=" * 80)
    
    # Trust cache entries have a specific magic: 0x2 (version 2)
    # struct trust_cache_entry {
    #     uint8_t cdhash[20];
    #     uint8_t hash_type;
    #     uint8_t flags;
    # }
    # struct trust_cache {
    #     uint32_t version;  // 2
    #     uuid_t uuid;       // 16 bytes
    #     uint32_t num_entries;
    #     trust_cache_entry entries[];
    # }
    
    # Scan __DATA for trust cache version magic (0x00000002) followed by UUID-like data
    data_start = data_seg['fileoff']
    data_end = data_start + data_seg['filesize']
    
    tc_candidates = []
    for off in range(data_start, data_end - 24, 4):
        val = read_u32(data, off)
        if val == 2:  # version = 2
            # Check if followed by non-zero UUID (16 bytes)
            uuid_bytes = data[off+4:off+20]
            if uuid_bytes != b'\x00' * 16 and any(b != 0 for b in uuid_bytes):
                # Check num_entries (should be reasonable: 1-10000)
                num_entries = read_u32(data, off + 20)
                if 1 <= num_entries <= 10000:
                    vm = data_seg['vmaddr'] + (off - data_start)
                    tc_candidates.append((off, vm, num_entries, uuid_bytes.hex()))
    
    if tc_candidates:
        print(f"Found {len(tc_candidates)} trust cache candidates in __DATA!")
        for off, vm, count, uuid in tc_candidates[:10]:
            print(f"  file=0x{off:x}, vm=0x{vm:x}: version=2, entries={count}, uuid={uuid[:16]}...")
            # Read first few CDHashes
            entry_start = off + 24
            for i in range(min(count, 3)):
                entry_off = entry_start + i * 22  # 20 bytes cdhash + 1 hash_type + 1 flags
                if entry_off + 22 <= len(data):
                    cdhash = data[entry_off:entry_off+20].hex()
                    hash_type = data[entry_off+20]
                    flags = data[entry_off+21]
                    print(f"    [{i}] cdhash={cdhash}, type={hash_type}, flags={flags}")
    else:
        print("No trust cache structs found in __DATA")
        print("Trust caches might be dynamically allocated (not in static kernel image)")
    
    # ═══════════════════════════════════════════════════════════════
    # SEARCH 4: Pointers near pmap_cs_allow_invalid
    # ═══════════════════════════════════════════════════════════════
    print("\n" + "=" * 80)
    print("SEARCH 4: Variables near pmap_cs_allow_invalid_internal")
    print("=" * 80)
    
    # Known: pmap_cs_allow_invalid_internal at file offset 0x030e05b8 (from previous analysis)
    pmap_cs_file_off = 0x030dc000 + 0x45b8  # __DATA fileoff + offset within
    # Actually let's recalculate: __DATA vm=0xfffffff00a0e0000, file=0x030dc000
    # pmap_cs at vm=0xfffffff00a0e45b8, so file = 0x030dc000 + 0x45b8 = 0x030e05b8
    
    print(f"pmap_cs_allow_invalid at file=0x{pmap_cs_file_off:x}")
    print(f"Dumping ±512 bytes for interesting values:\n")
    
    # Look for pointers and non-zero values
    interesting = []
    for off in range(pmap_cs_file_off - 512, pmap_cs_file_off + 512, 8):
        if 0 <= off < len(data) - 8:
            val = read_u64(data, off)
            if val != 0:
                rel_off = off - pmap_cs_file_off
                vm = data_seg['vmaddr'] + (off - data_seg['fileoff'])
                
                # Categorize
                if 0xfffffff000000000 < val < 0xffffffffffff0000:
                    interesting.append((rel_off, vm, val, "KERNEL_PTR"))
                elif 0 < val < 0x100:
                    interesting.append((rel_off, vm, val, "SMALL_INT"))
                elif val == 1:
                    interesting.append((rel_off, vm, val, "FLAG=1"))
    
    for rel, vm, val, kind in interesting[:30]:
        marker = " ← pmap_cs_allow_invalid" if rel == 0 else ""
        print(f"  {rel:+5d} (vm=0x{vm:x}): 0x{val:016x} [{kind}]{marker}")
    
    # ═══════════════════════════════════════════════════════════════
    # SEARCH 5: AMFI function pointers in __DATA_CONST
    # ═══════════════════════════════════════════════════════════════
    print("\n" + "=" * 80)
    print("SEARCH 5: Function pointer tables in __DATA_CONST")
    print("=" * 80)
    print("Looking for dense arrays of __TEXT_EXEC pointers (MAC policy ops)...")
    
    dc_start = data_const['fileoff']
    dc_end = dc_start + data_const['filesize']
    text_vm_start = text_exec['vmaddr']
    text_vm_end = text_exec['vmaddr'] + text_exec['vmsize']
    
    # Find runs of consecutive kernel text pointers (function pointer tables)
    best_runs = []
    i = dc_start
    while i < dc_end - 8:
        val = read_u64(data, i)
        if text_vm_start <= val < text_vm_end:
            # Start of potential function pointer run
            run_start = i
            count = 0
            while i < dc_end - 8:
                v = read_u64(data, i)
                if text_vm_start <= v < text_vm_end or v == 0:
                    count += 1
                    i += 8
                else:
                    break
            if count >= 20:  # MAC policy ops has 300+ entries
                vm = data_const['vmaddr'] + (run_start - dc_start)
                best_runs.append((run_start, vm, count))
        else:
            i += 8
    
    best_runs.sort(key=lambda x: -x[2])
    print(f"Found {len(best_runs)} function pointer tables (≥20 entries)")
    for off, vm, count in best_runs[:5]:
        print(f"  file=0x{off:x}, vm=0x{vm:x}: {count} pointers")
        # Print first few
        for j in range(min(count, 5)):
            ptr = read_u64(data, off + j * 8)
            if ptr != 0:
                print(f"    [{j}] 0x{ptr:x}")
    
    # ═══════════════════════════════════════════════════════════════
    # SUMMARY
    # ═══════════════════════════════════════════════════════════════
    print("\n" + "=" * 80)
    print("SUMMARY & NEXT STEPS")
    print("=" * 80)
    print("""
Key findings to test on device:
1. Trust cache candidates in __DATA → try reading from device via socket KRW
2. Function pointer tables → if in writable memory, can patch AMFI hooks
3. Variables near pmap_cs → might be other CS enforcement flags

DEVICE TESTING PLAN:
For each trust cache candidate address:
  1. Add kernel_slide to get runtime address
  2. Try ds_kread64() — if no panic, it's accessible!
  3. If accessible: read the struct, verify it's a trust cache
  4. If trust cache: ADD our binary's CDHash to the entries array
  5. Try spawn → if works → FULL JAILBREAK!

For function pointer tables:
  1. These are in __DATA_CONST (PPL protected after boot)
  2. Cannot write directly — but might find writable copy/shadow
  3. Or: find the registration function and hook at runtime
""")

if __name__ == "__main__":
    main()
