#!/usr/bin/env python3
"""
find_amfi_kernel_patch.py — Cari offset fungsi AMFI di kernelcache untuk patch.

Target: fungsi kernel yang memvalidasi code signature saat posix_spawn/exec.
Patch: NOP instruksi branch yang reject binary, atau MOV W0,#0 + RET di prologue.

Kernelcache format: Mach-O fileset (iOS 15+) atau monolithic Mach-O.
"""

import struct
import sys
import os

def read_u32(data, offset):
    if offset + 4 > len(data):
        return 0
    return struct.unpack_from('<I', data, offset)[0]

def read_u64(data, offset):
    if offset + 8 > len(data):
        return 0
    return struct.unpack_from('<Q', data, offset)[0]

def read_cstring(data, offset, maxlen=256):
    end = data.find(b'\x00', offset, offset + maxlen)
    if end == -1:
        end = offset + maxlen
    return data[offset:end].decode('ascii', errors='replace')

def find_string_refs(data, text_off, text_size, string_offset):
    """Find ADRP+ADD pairs that reference a string at given file offset."""
    refs = []
    # Convert string file offset to virtual address would need segment info
    # Instead, scan for the string bytes pattern near instructions
    return refs

def scan_for_string(data, target_string):
    """Find all occurrences of a string in the binary."""
    target_bytes = target_string.encode('ascii') + b'\x00'
    results = []
    start = 0
    while True:
        idx = data.find(target_bytes, start)
        if idx == -1:
            break
        results.append(idx)
        start = idx + 1
    return results

def parse_fileset_kernelcache(data):
    """Parse iOS 15+ fileset kernelcache."""
    magic = read_u32(data, 0)
    if magic != 0xFEEDFACF:
        return None
    
    filetype = read_u32(data, 12)
    ncmds = read_u32(data, 16)
    
    print(f"Mach-O 64-bit, filetype={filetype}, ncmds={ncmds}")
    
    if filetype != 12:  # MH_FILESET
        print(f"  Not a fileset (type={filetype}), trying as monolithic")
    
    segments = []
    fileset_entries = []
    offset = 32  # sizeof(mach_header_64)
    
    for _ in range(ncmds):
        if offset + 8 > len(data):
            break
        cmd = read_u32(data, offset)
        cmdsize = read_u32(data, offset + 4)
        if cmdsize == 0:
            break
        
        if cmd == 0x19:  # LC_SEGMENT_64
            segname = data[offset+8:offset+24].split(b'\x00')[0].decode('ascii', errors='replace')
            vmaddr = read_u64(data, offset + 24)
            vmsize = read_u64(data, offset + 32)
            fileoff = read_u64(data, offset + 40)
            filesize = read_u64(data, offset + 48)
            segments.append({
                'name': segname, 'vmaddr': vmaddr, 'vmsize': vmsize,
                'fileoff': fileoff, 'filesize': filesize
            })
        
        elif cmd == 0x35:  # LC_FILESET_ENTRY
            # LC_FILESET_ENTRY: vmaddr(8) + fileoff(8) + entry_id offset(4) + reserved(4)
            entry_vmaddr = read_u64(data, offset + 8)
            entry_fileoff = read_u64(data, offset + 16)
            entry_id_off = read_u32(data, offset + 24)
            entry_id = read_cstring(data, offset + entry_id_off)
            fileset_entries.append({
                'name': entry_id, 'vmaddr': entry_vmaddr, 'fileoff': entry_fileoff
            })
        
        offset += cmdsize
    
    return {
        'segments': segments,
        'fileset_entries': fileset_entries,
        'ncmds': ncmds,
        'filetype': filetype,
    }

def find_amfi_entry(info):
    """Find AMFI kext in fileset entries."""
    for entry in info.get('fileset_entries', []):
        name = entry['name'].lower()
        if 'amfi' in name or 'mobilefileintegrity' in name:
            return entry
    return None

def find_text_exec_in_entry(data, entry_fileoff):
    """Parse Mach-O at fileset entry offset to find __TEXT_EXEC segment."""
    magic = read_u32(data, entry_fileoff)
    if magic != 0xFEEDFACF:
        return None
    
    ncmds = read_u32(data, entry_fileoff + 16)
    offset = entry_fileoff + 32
    
    segments = []
    for _ in range(ncmds):
        if offset + 8 > len(data):
            break
        cmd = read_u32(data, offset)
        cmdsize = read_u32(data, offset + 4)
        if cmdsize == 0:
            break
        
        if cmd == 0x19:  # LC_SEGMENT_64
            segname = data[offset+8:offset+24].split(b'\x00')[0].decode('ascii', errors='replace')
            vmaddr = read_u64(data, offset + 24)
            vmsize = read_u64(data, offset + 32)
            fileoff = read_u64(data, offset + 40)
            filesize = read_u64(data, offset + 48)
            segments.append({
                'name': segname, 'vmaddr': vmaddr, 'vmsize': vmsize,
                'fileoff': fileoff, 'filesize': filesize
            })
        
        offset += cmdsize
    
    return segments

def scan_amfi_functions(data, text_fileoff, text_size, text_vmaddr):
    """Scan AMFI __TEXT_EXEC for patch targets."""
    targets = []
    
    for i in range(0, min(text_size, 512*1024), 4):
        offset = text_fileoff + i
        if offset + 8 > len(data):
            break
        
        instr = read_u32(data, offset)
        next_instr = read_u32(data, offset + 4)
        pc = text_vmaddr + i
        
        # BL instruction
        is_bl = (instr >> 26) == 0x25
        
        if is_bl:
            # CBNZ W0 after BL
            is_cbnz_w0 = (next_instr >> 24) == 0x35 and (next_instr & 0x1F) == 0
            # CBZ W0 after BL
            is_cbz_w0 = (next_instr >> 24) == 0x34 and (next_instr & 0x1F) == 0
            # B.NE after BL
            is_bne = (next_instr & 0xFF00001F) == 0x54000001
            
            if is_cbnz_w0:
                # Decode BL target
                imm26 = instr & 0x3FFFFFF
                if imm26 & 0x2000000:
                    imm26 |= 0xFC000000
                bl_offset = (imm26 << 2) & 0xFFFFFFFF
                if bl_offset & 0x80000000:
                    bl_offset -= 0x100000000
                bl_target = pc + bl_offset
                
                targets.append({
                    'type': 'BL+CBNZ_W0',
                    'file_offset': offset + 4,  # patch the CBNZ
                    'vmaddr': pc + 4,
                    'bl_vmaddr': pc,
                    'bl_target': bl_target,
                    'instr': next_instr,
                    'text_offset': i + 4,  # offset from __TEXT_EXEC start
                })
            elif is_cbz_w0:
                targets.append({
                    'type': 'BL+CBZ_W0',
                    'file_offset': offset,
                    'vmaddr': pc,
                    'bl_target': 0,
                    'instr': instr,
                    'text_offset': i,
                })
            elif is_bne:
                targets.append({
                    'type': 'BL+B.NE',
                    'file_offset': offset + 4,
                    'vmaddr': pc + 4,
                    'bl_target': 0,
                    'instr': next_instr,
                    'text_offset': i + 4,
                })
    
    return targets

def find_amfi_strings(data):
    """Find AMFI-related strings to identify key functions."""
    strings_to_find = [
        "AMFI: code signature",
        "AMFI: denying",
        "AMFI: allowing",
        "not valid",
        "signature not valid",
        "CDHash",
        "trust cache",
        "mac_vnode_check",
        "proc_check_run_cs_invalid",
        "csproc_check_invalid",
    ]
    
    results = {}
    for s in strings_to_find:
        offsets = scan_for_string(data, s)
        if offsets:
            results[s] = offsets
    
    return results

def main():
    # Find kernelcache
    candidates = [
        'kernelcache',
        os.path.join('..', 'kernelcache'),
        os.path.join(os.path.dirname(__file__), '..', 'kernelcache'),
    ]
    
    path = None
    for c in candidates:
        if os.path.exists(c):
            path = c
            break
    
    if len(sys.argv) > 1:
        path = sys.argv[1]
    
    if not path or not os.path.exists(path):
        print("Usage: python find_amfi_kernel_patch.py [kernelcache]")
        print("Default: looks for 'kernelcache' in workspace root")
        sys.exit(1)
    
    print(f"=== Analyzing: {path} ===")
    print(f"File size: {os.path.getsize(path)} bytes\n")
    
    with open(path, 'rb') as f:
        data = f.read()
    
    # Parse kernelcache
    info = parse_fileset_kernelcache(data)
    if not info:
        print("ERROR: Cannot parse kernelcache")
        sys.exit(1)
    
    print(f"Fileset entries: {len(info['fileset_entries'])}")
    
    # Find AMFI kext
    amfi_entry = find_amfi_entry(info)
    if amfi_entry:
        print(f"\n✅ AMFI kext found: {amfi_entry['name']}")
        print(f"   vmaddr: 0x{amfi_entry['vmaddr']:x}")
        print(f"   fileoff: 0x{amfi_entry['fileoff']:x}")
    else:
        print("\n⚠️ AMFI kext not found in fileset entries")
        print("Fileset entries:")
        for e in info['fileset_entries'][:20]:
            print(f"  {e['name']}: vm=0x{e['vmaddr']:x} file=0x{e['fileoff']:x}")
        # Try scanning entire __TEXT_EXEC
        print("\nFalling back to full kernelcache scan...")
    
    # Find AMFI-related strings
    print("\n=== String Search ===")
    amfi_strings = find_amfi_strings(data)
    for s, offsets in amfi_strings.items():
        print(f"  '{s}': {len(offsets)} occurrence(s) at {['0x%x' % o for o in offsets[:3]]}")
    
    # Find __TEXT_EXEC in AMFI kext (or main kernel)
    text_exec = None
    scan_entry_off = 0
    
    if amfi_entry:
        segments = find_text_exec_in_entry(data, amfi_entry['fileoff'])
        if segments:
            for seg in segments:
                print(f"  AMFI segment: {seg['name']} vm=0x{seg['vmaddr']:x} size=0x{seg['vmsize']:x} file=0x{seg['fileoff']:x}")
                if seg['name'] == '__TEXT_EXEC' or (seg['name'] == '__TEXT' and seg['vmsize'] > 0x1000):
                    text_exec = seg
    
    if not text_exec:
        # Fallback: scan main kernel __TEXT_EXEC
        for seg in info['segments']:
            if seg['name'] == '__TEXT_EXEC':
                text_exec = seg
                break
        if not text_exec:
            for seg in info['segments']:
                if seg['name'] == '__TEXT' and seg['filesize'] > 0x100000:
                    text_exec = seg
                    break
    
    if not text_exec:
        print("\nERROR: No executable segment found")
        sys.exit(1)
    
    print(f"\n=== Scanning executable segment ===")
    print(f"Segment: {text_exec['name']}")
    print(f"  vmaddr: 0x{text_exec['vmaddr']:x}")
    print(f"  size: 0x{text_exec['vmsize']:x} ({text_exec['vmsize']//1024} KB)")
    print(f"  fileoff: 0x{text_exec['fileoff']:x}")
    
    # Scan for patch targets
    targets = scan_amfi_functions(
        data, 
        text_exec['fileoff'], 
        min(text_exec['filesize'], 2*1024*1024),  # max 2MB scan
        text_exec['vmaddr']
    )
    
    print(f"\nFound {len(targets)} BL+branch patterns in scanned region")
    
    # Group by BL target (same function called multiple times = likely important)
    bl_target_counts = {}
    for t in targets:
        if t.get('bl_target', 0) != 0:
            bt = t['bl_target']
            bl_target_counts[bt] = bl_target_counts.get(bt, 0) + 1
    
    # Sort by frequency (most called = most likely signature check)
    hot_targets = sorted(bl_target_counts.items(), key=lambda x: -x[1])
    
    print(f"\n=== Hot BL targets (called multiple times) ===")
    for target_addr, count in hot_targets[:15]:
        if count >= 2:
            print(f"  0x{target_addr:x}: called {count} times")
    
    # Find targets that call hot functions
    print(f"\n=== HIGH PRIORITY patch targets ===")
    print("(BL+CBNZ_W0 that call frequently-used functions)")
    
    priority_targets = []
    for t in targets:
        if t['type'] == 'BL+CBNZ_W0' and t.get('bl_target', 0) in dict(hot_targets[:10]):
            priority_targets.append(t)
    
    for i, t in enumerate(priority_targets[:20]):
        kern_offset = t['vmaddr'] - text_exec['vmaddr']
        print(f"  [{i}] vm=0x{t['vmaddr']:x} file=0x{t['file_offset']:x} "
              f"kern_off=+0x{kern_offset:x} BL→0x{t.get('bl_target', 0):x} "
              f"instr=0x{t['instr']:08x}")
    
    # Also find the hot function itself (patch prologue = disable entirely)
    print(f"\n=== HOT FUNCTIONS (patch prologue → always return 0) ===")
    for target_addr, count in hot_targets[:5]:
        if count >= 3:
            # Find file offset of this function
            func_kern_off = target_addr - text_exec['vmaddr']
            func_file_off = text_exec['fileoff'] + func_kern_off
            if func_file_off < len(data):
                prologue = read_u32(data, func_file_off)
                print(f"  0x{target_addr:x} (called {count}x): "
                      f"kern_off=+0x{func_kern_off:x} file=0x{func_file_off:x} "
                      f"prologue=0x{prologue:08x}")
                print(f"    Patch: write 0x52800000 (MOV W0,#0) + 0xD65F03C0 (RET) at kern_off +0x{func_kern_off:x}")
    
    # Generate Swift code
    print(f"\n\n=== SWIFT CODE for AMFIExperimentView.swift ===")
    print(f"// Kernel __TEXT_EXEC base (unslid): 0x{text_exec['vmaddr']:x}")
    print(f"// Runtime: kernBase + (offset - unslidTextExecBase)")
    print(f"// Physmap: (kernBase + offset) - gVirtBase + gPhysBase → physmap VA")
    print(f"//")
    print(f"// Patch via physmap: ds_kwrite32(physmapVA, NOP)")
    print(f"// NOP = 0xD503201F, MOV W0,#0 = 0x52800000, RET = 0xD65F03C0")
    print()
    
    # Output offsets relative to kernel text exec base
    print(f"let amfiKernTextExecBase: UInt64 = 0x{text_exec['vmaddr']:x}  // unslid")
    print(f"let amfiKernPatchOffsets: [(offset: UInt64, instr: UInt32, desc: String)] = [")
    
    all_targets = priority_targets[:10] if priority_targets else targets[:10]
    for t in all_targets:
        kern_off = t['vmaddr'] - text_exec['vmaddr']
        print(f"    (0x{kern_off:x}, 0x{t['instr']:08x}, \"{t['type']}\"),")
    print("]")
    
    # Hot function patches
    print()
    print("// HOT FUNCTION PATCHES (patch prologue → always return 0)")
    print("let amfiKernFuncPatches: [(offset: UInt64, desc: String)] = [")
    for target_addr, count in hot_targets[:5]:
        if count >= 3:
            kern_off = target_addr - text_exec['vmaddr']
            print(f"    (0x{kern_off:x}, \"called {count}x — likely signature check\"),")
    print("]")
    
    print(f"\n=== DONE ===")
    print(f"Total BL+CBNZ_W0: {len([t for t in targets if t['type'] == 'BL+CBNZ_W0'])}")
    print(f"Priority targets: {len(priority_targets)}")
    print(f"Hot functions (called 3+): {len([x for x in hot_targets if x[1] >= 3])}")

if __name__ == '__main__':
    main()
