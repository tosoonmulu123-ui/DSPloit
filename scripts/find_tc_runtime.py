#!/usr/bin/env python3
"""
Find trust_cache_runtime_add and related functions in kernelcache.
Goal: locate the function address so we can call it via RemoteCall.
"""
import struct, os

KC = r'd:\Backup\Personal\Hp\iPhone\DSPloit\kernelcache'

def read_u32(data, off):
    return struct.unpack_from('<I', data, off)[0]

def read_u64(data, off):
    return struct.unpack_from('<Q', data, off)[0]

with open(KC, 'rb') as f:
    data = f.read()

print(f"Kernelcache: {len(data)} bytes")

# Parse segments for VA mapping
segments = []
ncmds = read_u32(data, 0x10)
cmd_off = 0x20
for _ in range(ncmds):
    cmd = read_u32(data, cmd_off)
    cmdsize = read_u32(data, cmd_off + 4)
    if cmdsize == 0: break
    if cmd == 0x19:  # LC_SEGMENT_64
        segname = data[cmd_off+8:cmd_off+24].split(b'\x00')[0].decode('ascii', errors='ignore')
        vmaddr = read_u64(data, cmd_off + 24)
        vmsize = read_u64(data, cmd_off + 32)
        fileoff = read_u64(data, cmd_off + 40)
        filesize = read_u64(data, cmd_off + 48)
        segments.append({'name': segname, 'vmaddr': vmaddr, 'vmsize': vmsize, 'fileoff': fileoff, 'filesize': filesize})
    cmd_off += cmdsize

def fileoff_to_va(off):
    for seg in segments:
        if seg['fileoff'] <= off < seg['fileoff'] + seg['filesize']:
            return seg['vmaddr'] + (off - seg['fileoff'])
    return None

def va_to_fileoff(va):
    for seg in segments:
        if seg['vmaddr'] <= va < seg['vmaddr'] + seg['vmsize']:
            return seg['fileoff'] + (va - seg['vmaddr'])
    return None

# Search for key strings
print("\n=== Trust Cache Function Strings ===")
targets = [
    b'trust_cache_runtime_add',
    b'pmap_load_trust_cache', 
    b'trust_cache_add',
    b'pmap_lookup_in_loaded_trust_caches',
    b'query_trust_cache',
    b'load_trust_cache',
    b'TrustCache',
    b'amfi_allow_any_signature',
    b'PE_i_can_has_debugger',
    b'cs_enforcement_disable',
    b'proc_check_run_cs_invalid',
    b'vnode_check_exec',
]

for t in targets:
    idx = data.find(t)
    if idx >= 0:
        va = fileoff_to_va(idx)
        va_str = f"VA=0x{va:x}" if va else "VA=?"
        print(f"  {t.decode():40s} fileoff=0x{idx:x} {va_str}")

# Find AMFI __TEXT_EXEC for function scanning
print("\n=== AMFI __TEXT_EXEC Function Scan ===")
# AMFI __TEXT_EXEC: vm=0xfffffff008f76d10 size=0x263e4
amfi_text_exec_va = 0xfffffff008f76d10
amfi_text_exec_size = 0x263e4
amfi_text_exec_off = va_to_fileoff(amfi_text_exec_va)

if amfi_text_exec_off:
    print(f"AMFI __TEXT_EXEC at fileoff 0x{amfi_text_exec_off:x}, size 0x{amfi_text_exec_size:x}")
    
    # Find "MOV W0, #0; RET" gadget in AMFI text
    print("\n--- Searching for RET-0 gadget in AMFI __TEXT_EXEC ---")
    for off in range(amfi_text_exec_off, amfi_text_exec_off + amfi_text_exec_size - 4, 4):
        instr = read_u32(data, off)
        if instr == 0x52800000:  # MOV W0, #0
            next_instr = read_u32(data, off + 4)
            if next_instr == 0xD65F03C0:  # RET
                va = fileoff_to_va(off)
                print(f"  GADGET: MOV W0,#0; RET at VA 0x{va:x} (fileoff 0x{off:x})")
                break
    
    # Also search in main kernel __TEXT_EXEC
    print("\n--- Searching for RET-0 gadget in kernel __TEXT_EXEC ---")
    # kernel __TEXT_EXEC: 0xfffffff007d90000
    kern_te_va = 0xfffffff007d90000
    kern_te_off = va_to_fileoff(kern_te_va)
    if kern_te_off:
        count = 0
        for off in range(kern_te_off, min(kern_te_off + 0x2000000, len(data) - 4), 4):
            instr = read_u32(data, off)
            if instr == 0x52800000:  # MOV W0, #0
                next_instr = read_u32(data, off + 4)
                if next_instr == 0xD65F03C0:  # RET
                    va = fileoff_to_va(off)
                    print(f"  GADGET: MOV W0,#0; RET at VA 0x{va:x}")
                    count += 1
                    if count >= 5:
                        print(f"  ... (found {count}+ gadgets)")
                        break

# Find IOUserClient::externalMethod or similar that might call trust cache add
print("\n=== Searching for trust_cache_runtime_add xrefs ===")
# The string "trust_cache_runtime_add" is referenced by the function itself (for logging)
# Find the string, then find ADRP+ADD that reference it
tc_str = b'trust_cache_runtime_add'
tc_idx = data.find(tc_str)
if tc_idx >= 0:
    tc_va = fileoff_to_va(tc_idx)
    print(f"String at VA 0x{tc_va:x}")
    tc_page = tc_va & ~0xFFF
    tc_pageoff = tc_va & 0xFFF
    
    # Search for ADRP targeting this page
    print(f"Searching for ADRP refs to page 0x{tc_page:x}...")
    
    # Scan __TEXT_EXEC segments
    for seg in segments:
        if seg['filesize'] == 0: continue
        if seg['vmaddr'] < 0xfffffff007d00000: continue  # skip non-exec
        if seg['vmaddr'] > 0xfffffff00a000000: continue
        
        start = seg['fileoff']
        end = min(start + seg['filesize'], len(data) - 4)
        
        for off in range(start, end, 4):
            instr = read_u32(data, off)
            if (instr & 0x9F000000) != 0x90000000: continue  # not ADRP
            
            # Decode ADRP
            immhi = (instr >> 5) & 0x7FFFF
            immlo = (instr >> 29) & 0x3
            imm = (immhi << 2) | immlo
            if imm & 0x100000:
                imm = imm - 0x200000  # sign extend
            
            pc_va = fileoff_to_va(off)
            if not pc_va: continue
            pc_page = pc_va & ~0xFFF
            target_page = pc_page + (imm << 12)
            
            if target_page == tc_page:
                # Check ADD with matching offset
                if off + 4 < end:
                    next_instr = read_u32(data, off + 4)
                    if (next_instr & 0xFFC00000) == 0x91000000:
                        add_imm = (next_instr >> 10) & 0xFFF
                        if add_imm == tc_pageoff:
                            func_va = pc_va
                            # Walk back to find function start (look for STP X29, X30)
                            func_start = func_va
                            for back in range(0, 0x100, 4):
                                check_off = off - back
                                if check_off < start: break
                                i = read_u32(data, check_off)
                                # STP X29, X30, [SP, #-XX]! (frame setup)
                                if (i & 0xFFE00000) == 0xA9800000:
                                    func_start = fileoff_to_va(check_off)
                                    break
                                # PACIBSP
                                if i == 0xD503237F:
                                    func_start = fileoff_to_va(check_off)
                                    break
                            print(f"  XREF at VA 0x{func_va:x}, func likely starts at 0x{func_start:x}")

print("\n=== Summary ===")
print("To call trust_cache_runtime_add:")
print("  1. Find its address (from xref above)")
print("  2. Craft trust_cache struct in userspace memory")
print("  3. Call via kernel function pointer call (not RC - need kernel context)")
print("  4. OR: find IOKit/sysctl interface that calls it")
