#!/usr/bin/env python3
"""
DSPloit: Deep Trust Cache & AMFI Vulnerability Analysis
========================================================
Previous script found 195 "candidates" but most are false positives.
This script does PRECISE analysis:

1. Find the REAL static trust cache (has valid CDHashes)
2. Find trust cache LINKED LIST HEAD pointer (for runtime injection)
3. Find AMFI's mac_policy_ops registration
4. Find pmap_cs functions that ADD to trust cache
5. Analyze which __DATA addresses are in SAME zone as proc (socket KRW accessible)
"""

import struct
import sys
import os
import hashlib

KCACHE = "kernelcache.release.iphone11b.decompressed"

def read_u8(data, off):
    return data[off]

def read_u16(data, off):
    return struct.unpack_from('<H', data, off)[0]

def read_u32(data, off):
    return struct.unpack_from('<I', data, off)[0]

def read_u64(data, off):
    return struct.unpack_from('<Q', data, off)[0]

def find_segment(data, name):
    ncmds = read_u32(data, 16)
    offset = 32
    for _ in range(ncmds):
        cmd = read_u32(data, offset)
        cmdsize = read_u32(data, offset + 4)
        if cmd == 0x19:  # LC_SEGMENT_64
            segname = data[offset+8:offset+24].split(b'\x00')[0].decode()
            if segname == name:
                return {
                    'name': segname,
                    'vmaddr': read_u64(data, offset + 24),
                    'vmsize': read_u64(data, offset + 32),
                    'fileoff': read_u64(data, offset + 40),
                    'filesize': read_u64(data, offset + 48),
                }
        offset += cmdsize
    return None

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
                'name': segname,
                'vmaddr': read_u64(data, offset + 24),
                'vmsize': read_u64(data, offset + 32),
                'fileoff': read_u64(data, offset + 40),
                'filesize': read_u64(data, offset + 48),
            }
        offset += cmdsize
    return segs

def vm_to_file(segs, vm_addr):
    """Convert VM address to file offset"""
    for seg in segs.values():
        if seg['vmaddr'] <= vm_addr < seg['vmaddr'] + seg['vmsize']:
            return seg['fileoff'] + (vm_addr - seg['vmaddr']), seg['name']
    return None, None

def file_to_vm(segs, file_off):
    """Convert file offset to VM address"""
    for seg in segs.values():
        if seg['fileoff'] <= file_off < seg['fileoff'] + seg['filesize']:
            return seg['vmaddr'] + (file_off - seg['fileoff']), seg['name']
    return None, None

def is_valid_cdhash(cdhash_bytes):
    """Check if bytes look like a real CDHash (not all zeros, not structured data)"""
    if cdhash_bytes == b'\x00' * 20:
        return False
    # Real CDHashes have high entropy (they're SHA1/SHA256 hashes)
    unique_bytes = len(set(cdhash_bytes))
    return unique_bytes >= 8  # At least 8 unique byte values

def find_cstring_vm(data, segs, target):
    """Find string and return VM address"""
    target_bytes = target.encode() + b'\x00'
    idx = data.find(target_bytes)
    if idx != -1:
        vm, seg = file_to_vm(segs, idx)
        return vm, idx, seg
    return None, None, None

def decode_adrp(insn, pc):
    """Decode ADRP instruction, return target page address"""
    if (insn & 0x9F000000) != 0x90000000:
        return None
    immhi = (insn >> 5) & 0x7FFFF
    immlo = (insn >> 29) & 0x3
    imm = (immhi << 2) | immlo
    # Sign extend 21 bits
    if imm & 0x100000:
        imm = imm - 0x200000
    page = (pc & ~0xFFF) + (imm << 12)
    return page & 0xFFFFFFFFFFFFFFFF

def decode_add_imm(insn):
    """Decode ADD immediate, return immediate value"""
    if (insn & 0x7F800000) != 0x11000000:
        return None
    imm = (insn >> 10) & 0xFFF
    shift = (insn >> 22) & 0x3
    if shift == 1:
        imm <<= 12
    return imm

def decode_ldr_imm(insn):
    """Decode LDR unsigned offset"""
    # LDR Xt, [Xn, #imm] = 1x111001 01xxxxxx xxxxxxxx xxxnnnnn
    if (insn & 0xBFC00000) == 0xB9400000:
        imm = ((insn >> 10) & 0xFFF) * 4  # scale by 4 for 32-bit
        return imm
    if (insn & 0xFFC00000) == 0xF9400000:
        imm = ((insn >> 10) & 0xFFF) * 8  # scale by 8 for 64-bit
        return imm
    return None

def find_references_to_vm(data, segs, target_vm, text_seg):
    """Find all code references (ADRP+ADD or ADRP+LDR) to a VM address"""
    results = []
    text_start = text_seg['fileoff']
    text_end = text_start + text_seg['filesize']
    text_vm_base = text_seg['vmaddr']
    
    target_page = target_vm & ~0xFFF
    target_offset = target_vm & 0xFFF
    
    for off in range(text_start, text_end - 8, 4):
        insn = read_u32(data, off)
        pc = text_vm_base + (off - text_start)
        
        page = decode_adrp(insn, pc)
        if page is None or page != target_page:
            continue
        
        # Check next instruction
        next_insn = read_u32(data, off + 4)
        
        # ADD
        add_val = decode_add_imm(next_insn)
        if add_val is not None and add_val == target_offset:
            results.append((off, pc, 'ADRP+ADD'))
            continue
        
        # LDR (various scales)
        ldr_val = decode_ldr_imm(next_insn)
        if ldr_val is not None and ldr_val == target_offset:
            results.append((off, pc, 'ADRP+LDR'))
    
    return results

def main():
    if not os.path.exists(KCACHE):
        print(f"ERROR: {KCACHE} not found!")
        sys.exit(1)
    
    print("=" * 80)
    print("DSPloit: DEEP Trust Cache & Vulnerability Analysis")
    print("=" * 80)
    
    with open(KCACHE, 'rb') as f:
        data = f.read()
    
    print(f"Loaded: {len(data) / 1024 / 1024:.1f} MB\n")
    
    segs = find_all_segments(data)
    text_exec = segs.get('__TEXT_EXEC')
    data_seg = segs.get('__DATA')
    data_const = segs.get('__DATA_CONST')
    
    for name, seg in sorted(segs.items(), key=lambda x: x[1]['vmaddr']):
        print(f"  {name:20s} vm=0x{seg['vmaddr']:016x} size=0x{seg['vmsize']:08x} file=0x{seg['fileoff']:08x}")
    
    # ═══════════════════════════════════════════════════════════════
    # ANALYSIS 1: Find pmap_lookup_in_loaded_trust_caches
    # This function is called to CHECK if a CDHash is trusted.
    # It iterates the trust cache linked list.
    # By finding this function, we can find the LIST HEAD variable.
    # ═══════════════════════════════════════════════════════════════
    print("\n" + "═" * 80)
    print("ANALYSIS 1: Find trust cache lookup function → list head")
    print("═" * 80)
    
    # Find the string reference
    tc_lookup_str = "pmap_lookup_in_loaded_trust_caches"
    tc_vm, tc_file, tc_seg = find_cstring_vm(data, segs, tc_lookup_str)
    
    if tc_vm:
        print(f"String '{tc_lookup_str}' at vm=0x{tc_vm:x} ({tc_seg})")
        
        # Find code that references this string (panic/log message)
        refs = find_references_to_vm(data, segs, tc_vm, text_exec)
        print(f"Code references: {len(refs)}")
        
        for ref_file, ref_vm, ref_type in refs[:5]:
            print(f"  0x{ref_vm:x} ({ref_type})")
            
            # Scan backwards from this reference to find ADRP to __DATA
            # The function that uses this string likely also loads the TC list head
            scan_start = max(ref_file - 200, text_exec['fileoff'])
            scan_end = min(ref_file + 200, text_exec['fileoff'] + text_exec['filesize'])
            
            data_refs_nearby = []
            for scan_off in range(scan_start, scan_end, 4):
                insn = read_u32(data, scan_off)
                pc = text_exec['vmaddr'] + (scan_off - text_exec['fileoff'])
                page = decode_adrp(insn, pc)
                
                if page and data_seg['vmaddr'] <= page < data_seg['vmaddr'] + data_seg['vmsize']:
                    # This ADRP points to __DATA!
                    next_insn = read_u32(data, scan_off + 4)
                    add_val = decode_add_imm(next_insn)
                    ldr_val = decode_ldr_imm(next_insn)
                    
                    target = None
                    if add_val is not None:
                        target = page + add_val
                    elif ldr_val is not None:
                        target = page + ldr_val
                    
                    if target and data_seg['vmaddr'] <= target < data_seg['vmaddr'] + data_seg['vmsize']:
                        data_refs_nearby.append((scan_off, pc, target))
            
            if data_refs_nearby:
                print(f"    __DATA references near this function:")
                for _, dpc, dtarget in data_refs_nearby[:8]:
                    # Read the value at this __DATA address
                    dfile, _ = vm_to_file(segs, dtarget)
                    if dfile and dfile + 8 <= len(data):
                        val = read_u64(data, dfile)
                        print(f"      0x{dtarget:x}: value=0x{val:x} (from code at 0x{dpc:x})")
    else:
        print(f"String '{tc_lookup_str}' NOT FOUND")
    
    # Also try shorter variants
    for alt_str in ["trust_cache_runtime", "loaded_trust_caches", "pmap_cs_lookup"]:
        alt_vm, alt_file, alt_seg = find_cstring_vm(data, segs, alt_str)
        if alt_vm:
            print(f"\n  Also found: '{alt_str}' at vm=0x{alt_vm:x} ({alt_seg})")
    
    # ═══════════════════════════════════════════════════════════════
    # ANALYSIS 2: Find REAL static trust cache
    # Real trust caches have VALID CDHashes (high entropy, 20 bytes)
    # ═══════════════════════════════════════════════════════════════
    print("\n" + "═" * 80)
    print("ANALYSIS 2: Find REAL static trust cache with valid CDHashes")
    print("═" * 80)
    
    # Search ALL segments for trust cache magic
    real_trust_caches = []
    
    for seg_name, seg in segs.items():
        seg_start = seg['fileoff']
        seg_end = seg_start + seg['filesize']
        
        for off in range(seg_start, seg_end - 24, 4):
            version = read_u32(data, off)
            if version != 1 and version != 2:
                continue
            
            # For version 2: uuid (16 bytes) + num_entries (4 bytes)
            # For version 1: uuid (16 bytes) + num_entries (4 bytes)
            num_entries = read_u32(data, off + 20)
            
            if num_entries < 1 or num_entries > 50000:
                continue
            
            # Validate: check first 3 CDHashes for high entropy
            entry_size = 22 if version == 2 else 24  # v2: 20+1+1, v1: 20+2+2
            entries_start = off + 24
            
            valid_count = 0
            for i in range(min(num_entries, 5)):
                entry_off = entries_start + i * entry_size
                if entry_off + 20 > len(data):
                    break
                cdhash = data[entry_off:entry_off+20]
                if is_valid_cdhash(cdhash):
                    valid_count += 1
            
            if valid_count >= 3:
                vm, _ = file_to_vm(segs, off)
                real_trust_caches.append({
                    'file_off': off,
                    'vm': vm,
                    'segment': seg_name,
                    'version': version,
                    'num_entries': num_entries,
                    'valid_hashes': valid_count,
                })
    
    print(f"Found {len(real_trust_caches)} REAL trust caches with valid CDHashes:")
    for tc in real_trust_caches[:10]:
        print(f"\n  ✅ Trust Cache at vm=0x{tc['vm']:x} ({tc['segment']})")
        print(f"     Version: {tc['version']}, Entries: {tc['num_entries']}")
        print(f"     File offset: 0x{tc['file_off']:x}")
        
        # Print first 3 CDHashes
        entry_size = 22 if tc['version'] == 2 else 24
        for i in range(min(tc['num_entries'], 3)):
            entry_off = tc['file_off'] + 24 + i * entry_size
            cdhash = data[entry_off:entry_off+20].hex()
            hash_type = data[entry_off+20] if entry_off+20 < len(data) else 0
            flags = data[entry_off+21] if entry_off+21 < len(data) else 0
            print(f"     [{i}] {cdhash} (type={hash_type}, flags={flags})")
        
        # KEY: Is this in __DATA (writable) or __DATA_CONST (read-only)?
        if tc['segment'] == '__DATA':
            print(f"     🔥 IN __DATA (potentially WRITABLE via KRW!)")
        elif tc['segment'] == '__DATA_CONST':
            print(f"     ⚠️ In __DATA_CONST (PPL protected)")
    
    # ═══════════════════════════════════════════════════════════════
    # ANALYSIS 3: Zone analysis — what's accessible via socket KRW?
    # ═══════════════════════════════════════════════════════════════
    print("\n" + "═" * 80)
    print("ANALYSIS 3: Socket KRW Zone Accessibility")
    print("═" * 80)
    
    # Known accessible: pmap_cs_allow_invalid_internal at 0xfffffff00a0e45b8
    # This is in __DATA at file offset 0x030e05b8
    # Socket KRW accesses proc zone objects which are in __DATA
    
    pmap_cs_vm = 0xfffffff00a0e45b8
    pmap_cs_file = 0x030e05b8
    
    print(f"Known accessible (pmap_cs): vm=0x{pmap_cs_vm:x}, file=0x{pmap_cs_file:x}")
    print(f"__DATA range: vm=0x{data_seg['vmaddr']:x} - 0x{data_seg['vmaddr']+data_seg['vmsize']:x}")
    print(f"__DATA file:  0x{data_seg['fileoff']:x} - 0x{data_seg['fileoff']+data_seg['filesize']:x}")
    
    # Check if any real trust caches are in __DATA
    data_trust_caches = [tc for tc in real_trust_caches if tc['segment'] == '__DATA']
    
    if data_trust_caches:
        print(f"\n🔥🔥🔥 {len(data_trust_caches)} trust caches in __DATA!")
        print("These MIGHT be accessible via socket KRW!")
        print("\nAddresses to test on device (add kernel_slide):")
        for tc in data_trust_caches:
            print(f"  0x{tc['vm']:x} ({tc['num_entries']} entries)")
            # Calculate distance from pmap_cs (known accessible)
            dist = abs(tc['vm'] - pmap_cs_vm)
            print(f"    Distance from pmap_cs: {dist} bytes ({dist//4096} pages)")
            if dist < 0x100000:  # Within 1MB
                print(f"    ⚡ CLOSE to known-accessible address!")
    else:
        print("\nNo real trust caches in __DATA")
        print("Trust caches are likely dynamically allocated at runtime")
        print("→ Need to find the HEAD POINTER that points to runtime trust caches")
    
    # ═══════════════════════════════════════════════════════════════
    # ANALYSIS 4: Find trust cache HEAD pointer
    # ═══════════════════════════════════════════════════════════════
    print("\n" + "═" * 80)
    print("ANALYSIS 4: Trust Cache Linked List HEAD Pointer")
    print("═" * 80)
    
    # The trust cache list head is a global variable in __DATA
    # It's accessed by pmap_lookup_in_loaded_trust_caches
    # Pattern: pointer to first trust_cache_module struct
    # struct trust_cache_module {
    #     struct trust_cache_module *next;  // linked list
    #     struct trust_cache *cache;        // pointer to actual cache
    #     ...
    # }
    
    # Look for "loaded_trust_caches" or similar global name
    for candidate_str in ["loaded_trust_caches", "pmap_image4_trust_caches", 
                          "trust_cache_rt", "static_trust_cache_module"]:
        vm, foff, seg = find_cstring_vm(data, segs, candidate_str)
        if vm:
            print(f"  '{candidate_str}' at vm=0x{vm:x} ({seg})")
            # Find code refs to this string
            refs = find_references_to_vm(data, segs, vm, text_exec)
            if refs:
                print(f"    Referenced from {len(refs)} code locations")
                # The function using this string likely also accesses the HEAD
    
    # Alternative: scan __DATA for pointer-sized values that point to other __DATA addresses
    # Trust cache HEAD is a pointer in __DATA that points to a trust_cache_module in __DATA
    print("\n  Scanning __DATA for self-referencing pointers (linked list heads)...")
    
    data_vm_start = data_seg['vmaddr']
    data_vm_end = data_seg['vmaddr'] + data_seg['vmsize']
    data_file_start = data_seg['fileoff']
    
    self_refs = []
    for off in range(data_file_start, data_file_start + data_seg['filesize'] - 8, 8):
        val = read_u64(data, off)
        # Check if this pointer points WITHIN __DATA
        if data_vm_start <= val < data_vm_end:
            # This is a __DATA pointer pointing to __DATA — could be linked list!
            vm, _ = file_to_vm(segs, off)
            target_file, _ = vm_to_file(segs, val)
            if target_file:
                # Check if target also contains a __DATA pointer (linked list next)
                target_val = read_u64(data, target_file)
                if data_vm_start <= target_val < data_vm_end or target_val == 0:
                    # Looks like a linked list! head → node → next_node/NULL
                    self_refs.append((off, vm, val, target_val))
    
    print(f"  Found {len(self_refs)} potential linked list heads in __DATA")
    
    # Filter: near pmap_cs_allow_invalid (same page/region = likely same zone)
    nearby_lists = [(off, vm, val, tval) for off, vm, val, tval in self_refs 
                    if abs(vm - pmap_cs_vm) < 0x10000]  # within 64KB
    
    if nearby_lists:
        print(f"\n  🔥 {len(nearby_lists)} linked lists NEAR pmap_cs (within 64KB):")
        for off, vm, val, tval in nearby_lists[:15]:
            dist = vm - pmap_cs_vm
            print(f"    vm=0x{vm:x} (pmap_cs{dist:+d}) → 0x{val:x} → 0x{tval:x}")
    
    # ═══════════════════════════════════════════════════════════════
    # FINAL SUMMARY
    # ═══════════════════════════════════════════════════════════════
    print("\n" + "═" * 80)
    print("FINAL SUMMARY — DEVICE TESTING PLAN")
    print("═" * 80)
    
    print("""
APPROACH A: Static Trust Cache in __DATA
""")
    if data_trust_caches:
        print(f"  Found {len(data_trust_caches)} candidates!")
        print("  Test plan:")
        print("  1. ds_kread64(addr + slide) for each candidate")
        print("  2. If readable → verify version field = 2")
        print("  3. If valid → APPEND our CDHash to entries")
        print("  4. Try spawn → FULL JAILBREAK!")
    else:
        print("  No static trust caches in __DATA (runtime-allocated)")
    
    print("""
APPROACH B: Linked List HEAD near pmap_cs
""")
    if nearby_lists:
        print(f"  Found {len(nearby_lists)} linked list heads near known-accessible address!")
        print("  Test plan:")
        print("  1. Read each HEAD pointer via socket KRW")
        print("  2. Follow linked list (read next pointers)")
        print("  3. Find trust_cache_module → trust_cache pointer")
        print("  4. Modify trust cache entries or insert new module")
    else:
        print("  No linked lists found near pmap_cs")
    
    print("""
APPROACH C: Direct __DATA variable patching
  Variables near pmap_cs_allow_invalid that we haven't tried:
""")
    # Print non-zero values near pmap_cs that aren't the variable itself
    for off in range(pmap_cs_file - 128, pmap_cs_file + 128, 8):
        if 0 <= off < len(data) - 8:
            val = read_u64(data, off)
            if val != 0 and off != pmap_cs_file:
                vm, _ = file_to_vm(segs, off)
                dist = off - pmap_cs_file
                print(f"    vm=0x{vm:x} (pmap_cs{dist:+d}): 0x{val:x}")

if __name__ == "__main__":
    main()
