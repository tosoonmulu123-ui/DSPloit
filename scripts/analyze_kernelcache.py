#!/usr/bin/env python3
"""
DSPloit Kernelcache Analyzer
Extracts useful information for PPL bypass research from decompressed kernelcache.
Run: python analyze_kernelcache.py <path_to_kernelcache>
"""

import sys
import struct
import os

def find_macho_offset(data):
    """Find Mach-O magic (0xFEEDFACF) in file"""
    magic = struct.pack('<I', 0xFEEDFACF)
    offset = data.find(magic)
    return offset if offset >= 0 else 0

def find_strings(data, min_len=10, keywords=None):
    """Extract strings containing keywords"""
    results = []
    current = b""
    start = 0
    
    for i, byte in enumerate(data):
        if 32 <= byte <= 126:
            if not current:
                start = i
            current += bytes([byte])
        else:
            if len(current) >= min_len:
                s = current.decode('ascii', errors='ignore')
                if keywords is None or any(k in s for k in keywords):
                    results.append((start, s))
            current = b""
    
    return results

def find_ret_gadgets(data, macho_offset, max_gadgets=100):
    """Find RET instruction gadgets"""
    RET = struct.pack('<I', 0xD65F03C0)
    gadgets = []
    offset = macho_offset
    
    while len(gadgets) < max_gadgets:
        pos = data.find(RET, offset)
        if pos < 0 or pos < macho_offset + 8:
            break
        
        # Read 2 instructions before RET
        prev1 = struct.unpack_from('<I', data, pos - 4)[0]
        prev2 = struct.unpack_from('<I', data, pos - 8)[0]
        
        # Decode basic ARM64 instructions
        instr1 = decode_arm64(prev2)
        instr2 = decode_arm64(prev1)
        
        if instr1 != "???" or instr2 != "???":
            file_offset = pos - 8 - macho_offset
            gadgets.append({
                'offset': file_offset,
                'instructions': f"{instr1} ; {instr2} ; RET",
                'type': classify_gadget(instr1, instr2)
            })
        
        offset = pos + 4
    
    return gadgets

def find_br_gadgets(data, macho_offset, max_gadgets=50):
    """Find BR Xn (indirect branch) gadgets"""
    gadgets = []
    
    for i in range(macho_offset, min(len(data) - 4, macho_offset + 2*1024*1024), 4):
        instr = struct.unpack_from('<I', data, i)[0]
        
        # BR Xn: 1101 0110 0001 1111 0000 00nn nnn0 0000
        if (instr & 0xFFFFFC1F) == 0xD61F0000:
            rn = (instr >> 5) & 0x1F
            
            if i >= macho_offset + 4:
                prev = struct.unpack_from('<I', data, i - 4)[0]
                prev_instr = decode_arm64(prev)
                
                file_offset = i - 4 - macho_offset
                gadgets.append({
                    'offset': file_offset,
                    'instructions': f"{prev_instr} ; BR X{rn}",
                    'type': 'control_flow'
                })
        
        if len(gadgets) >= max_gadgets:
            break
    
    return gadgets

def decode_arm64(opcode):
    """Basic ARM64 instruction decoder"""
    # RET
    if opcode == 0xD65F03C0:
        return "RET"
    # NOP
    if opcode == 0xD503201F:
        return "NOP"
    # B (branch)
    if (opcode & 0xFC000000) == 0x14000000:
        return "B"
    # BL (branch with link)
    if (opcode & 0xFC000000) == 0x94000000:
        return "BL"
    # BR Xn
    if (opcode & 0xFFFFFC1F) == 0xD61F0000:
        rn = (opcode >> 5) & 0x1F
        return f"BR X{rn}"
    # BLR Xn
    if (opcode & 0xFFFFFC1F) == 0xD63F0000:
        rn = (opcode >> 5) & 0x1F
        return f"BLR X{rn}"
    # LDR (immediate, 64-bit)
    if (opcode & 0xFFC00000) == 0xF9400000:
        rt = opcode & 0x1F
        rn = (opcode >> 5) & 0x1F
        imm = ((opcode >> 10) & 0xFFF) * 8
        return f"LDR X{rt}, [X{rn}, #{imm}]"
    # LDP (load pair, 64-bit)
    if (opcode & 0xFFC00000) == 0xA9400000:
        rt = opcode & 0x1F
        rt2 = (opcode >> 10) & 0x1F
        rn = (opcode >> 5) & 0x1F
        return f"LDP X{rt}, X{rt2}, [X{rn}]"
    # STR (immediate, 64-bit)
    if (opcode & 0xFFC00000) == 0xF9000000:
        rt = opcode & 0x1F
        rn = (opcode >> 5) & 0x1F
        imm = ((opcode >> 10) & 0xFFF) * 8
        return f"STR X{rt}, [X{rn}, #{imm}]"
    # STP (store pair, 64-bit)
    if (opcode & 0xFFC00000) == 0xA9000000:
        rt = opcode & 0x1F
        rt2 = (opcode >> 10) & 0x1F
        rn = (opcode >> 5) & 0x1F
        return f"STP X{rt}, X{rt2}, [X{rn}]"
    # ADD (immediate, 64-bit)
    if (opcode & 0xFF800000) == 0x91000000:
        rd = opcode & 0x1F
        rn = (opcode >> 5) & 0x1F
        imm = (opcode >> 10) & 0xFFF
        return f"ADD X{rd}, X{rn}, #{imm}"
    # SUB (immediate, 64-bit)
    if (opcode & 0xFF800000) == 0xD1000000:
        rd = opcode & 0x1F
        rn = (opcode >> 5) & 0x1F
        imm = (opcode >> 10) & 0xFFF
        return f"SUB X{rd}, X{rn}, #{imm}"
    # MOV (register, 64-bit) - ORR alias
    if (opcode & 0xFFE0FFE0) == 0xAA0003E0:
        rd = opcode & 0x1F
        rm = (opcode >> 16) & 0x1F
        return f"MOV X{rd}, X{rm}"
    # MOVZ (64-bit)
    if (opcode & 0xFF800000) == 0xD2800000:
        rd = opcode & 0x1F
        imm = (opcode >> 5) & 0xFFFF
        return f"MOVZ X{rd}, #0x{imm:x}"
    # SVC
    if (opcode & 0xFFE0001F) == 0xD4000001:
        imm = (opcode >> 5) & 0xFFFF
        return f"SVC #{imm}"
    # MSR
    if (opcode & 0xFFF00000) == 0xD5100000:
        rt = opcode & 0x1F
        return f"MSR sys, X{rt}"
    # MRS
    if (opcode & 0xFFF00000) == 0xD5300000:
        rt = opcode & 0x1F
        return f"MRS X{rt}, sys"
    
    return "???"

def classify_gadget(instr1, instr2):
    """Classify gadget type"""
    combined = instr1 + " " + instr2
    if "LDR" in combined or "LDP" in combined:
        return "load"
    if "STR" in combined or "STP" in combined:
        return "store"
    if "ADD" in combined or "SUB" in combined:
        return "arithmetic"
    if "MOV" in combined:
        return "move"
    if "SP" in combined:
        return "stack_pivot"
    return "other"

def find_ppl_related(data, macho_offset):
    """Find PPL-related data structures"""
    results = {}
    
    # Search for known PPL strings
    ppl_strings = find_strings(data, min_len=5, keywords=[
        'pmap_enter', 'ppl', 'PPL', 'page belongs to PPL',
        'page locked down', 'KTRR', 'ktrr',
        'mac_proc_enforce', 'sandbox',
        'proc_ucred', 'ucred',
        'trust_cache', 'amfi',
    ])
    results['ppl_strings'] = ppl_strings[:50]  # Limit output
    
    return results

def main():
    if len(sys.argv) < 2:
        print("Usage: python analyze_kernelcache.py <kernelcache_file>")
        print("Example: python analyze_kernelcache.py kernelcache.release.iphone11b.decompressed")
        sys.exit(1)
    
    filepath = sys.argv[1]
    
    if not os.path.exists(filepath):
        print(f"Error: File not found: {filepath}")
        sys.exit(1)
    
    filesize = os.path.getsize(filepath)
    print(f"=== DSPloit Kernelcache Analyzer ===")
    print(f"File: {filepath}")
    print(f"Size: {filesize / 1024 / 1024:.1f} MB")
    print()
    
    # Scan entire file in chunks to find where code lives
    print("Scanning entire file for ARM64 code...")
    code_offset = 0
    chunk_size = 1024 * 1024  # 1MB chunks
    
    with open(filepath, 'rb') as f:
        offset = 0
        while offset < filesize:
            f.seek(offset)
            chunk = f.read(4096)  # Read 4KB sample from each MB
            if len(chunk) < 4:
                break
            
            # Count RET instructions in this sample
            ret_count = 0
            for i in range(0, len(chunk) - 4, 4):
                val = struct.unpack_from('<I', chunk, i)[0]
                if val == 0xD65F03C0:  # RET
                    ret_count += 1
            
            if ret_count >= 3:  # Found code section (3+ RETs in 4KB = definitely code)
                code_offset = offset
                print(f"  Found code at offset 0x{offset:x} ({ret_count} RET instructions in 4KB sample)")
                break
            
            offset += chunk_size
    
    if code_offset == 0:
        print("  ERROR: Could not find ARM64 code in file!")
        print("  File may not be a valid decompressed kernelcache.")
        sys.exit(1)
    
    # Now read 2MB from code section
    print(f"Reading 2MB from code offset 0x{code_offset:x}...")
    with open(filepath, 'rb') as f:
        f.seek(code_offset)
        data = f.read(2 * 1024 * 1024)
    
    # Read first 2MB for strings
    with open(filepath, 'rb') as f:
        header_data = f.read(2 * 1024 * 1024)
    
    macho_offset = 0
    print()
    
    # Find ROP gadgets
    print("=== ROP GADGETS (first 30) ===")
    gadgets = find_ret_gadgets(data, macho_offset, max_gadgets=30)
    for g in gadgets:
        print(f"  +0x{g['offset']:08x} [{g['type']:12s}] {g['instructions']}")
    print(f"Total: {len(gadgets)} gadgets found in first 4MB")
    print()
    
    # Find BR gadgets
    print("=== BR/BLR GADGETS (first 20) ===")
    br_gadgets = find_br_gadgets(data, macho_offset, max_gadgets=20)
    for g in br_gadgets:
        print(f"  +0x{g['offset']:08x} [{g['type']:12s}] {g['instructions']}")
    print(f"Total: {len(br_gadgets)} BR gadgets found")
    print()
    
    # Find PPL-related strings (from both header and code sections)
    print("=== PPL-RELATED STRINGS ===")
    ppl_data = find_ppl_related(data, 0)
    ppl_header = find_ppl_related(header_data, 0)
    all_ppl = ppl_header['ppl_strings'] + ppl_data['ppl_strings']
    for offset, s in all_ppl[:30]:
        print(f"  0x{offset:08x}: {s[:100]}")
    print(f"Total: {len(all_ppl)} PPL strings found")
    print()
    
    # Summary
    print("=== SUMMARY ===")
    print(f"File size: {filesize / 1024 / 1024:.1f} MB")
    print(f"Code found at offset: 0x{code_offset:x}")
    print(f"ROP gadgets: {len(gadgets)}")
    print(f"BR gadgets: {len(br_gadgets)}")
    print(f"PPL strings: {len(all_ppl)}")
    print()
    print("Copy this output and send to Kiro for analysis.")

if __name__ == "__main__":
    main()
