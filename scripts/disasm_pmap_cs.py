#!/usr/bin/env python3
"""
disasm_pmap_cs.py — Full ARM64 disassembly of pmap_cs kill path
Uses capstone to decode every instruction and show the actual logic.

Targets:
1. AMFI __TEXT_EXEC functions that reference AMFI __DATA+0x428
2. pmap_cs functions near "pmap_cs_check_" string
3. The mac_proc_check_run_cs_invalid hook
"""
import struct, os
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

KC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "kernelcache")

def read_u32(data, off):
    if off + 4 > len(data): return 0
    return struct.unpack_from('<I', data, off)[0]

def read_u64(data, off):
    if off + 8 > len(data): return 0
    return struct.unpack_from('<Q', data, off)[0]

print("Loading kernelcache...")
with open(KC, 'rb') as f:
    data = f.read()

# Parse segments
segments = []
ncmds = read_u32(data, 0x10)
cmd_off = 0x20
for _ in range(ncmds):
    cmd = read_u32(data, cmd_off)
    cmdsize = read_u32(data, cmd_off + 4)
    if cmdsize == 0: break
    if cmd == 0x19:
        segname = data[cmd_off+8:cmd_off+24].split(b'\x00')[0].decode('ascii', errors='ignore')
        vmaddr = read_u64(data, cmd_off + 24)
        vmsize = read_u64(data, cmd_off + 32)
        fileoff = read_u64(data, cmd_off + 40)
        filesize = read_u64(data, cmd_off + 48)
        segments.append({'name': segname, 'vmaddr': vmaddr, 'vmsize': vmsize,
                        'fileoff': fileoff, 'filesize': filesize})
    cmd_off += cmdsize

def va_to_fileoff(va):
    for seg in segments:
        if seg['vmaddr'] <= va < seg['vmaddr'] + seg['vmsize']:
            off = seg['fileoff'] + (va - seg['vmaddr'])
            if off < seg['fileoff'] + seg['filesize']:
                return off
    return None

def fileoff_to_va(off):
    for seg in segments:
        if seg['fileoff'] <= off < seg['fileoff'] + seg['filesize']:
            return seg['vmaddr'] + (off - seg['fileoff'])
    return None

# Initialize capstone
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True

def disasm_function(va, max_instrs=100, label=""):
    """Disassemble a function starting at VA, stop at RET or max instructions."""
    off = va_to_fileoff(va)
    if off is None:
        print(f"  Cannot resolve VA 0x{va:x}")
        return
    
    code = data[off:off + max_instrs * 4]
    
    print(f"\n{'='*60}")
    print(f"  FUNCTION at 0x{va:x} {label}")
    print(f"{'='*60}")
    
    for i, insn in enumerate(md.disasm(code, va)):
        # Annotate interesting instructions
        annotation = ""
        mnemonic = insn.mnemonic
        op_str = insn.op_str
        
        if mnemonic == 'adrp':
            # Decode ADRP target
            raw = read_u32(data, off + i * 4)
            immhi = (raw >> 5) & 0x7FFFF
            immlo = (raw >> 29) & 0x3
            imm = (immhi << 2) | immlo
            if imm & 0x100000:
                imm = imm - 0x200000
            target_page = (insn.address & ~0xFFF) + (imm << 12)
            annotation = f"  ; → page 0x{target_page:x}"
            
            # Check if it targets writable fileset __DATA
            if 0xfffffff00a200000 <= target_page < 0xfffffff00a500000:
                annotation += " [WRITABLE FILESET __DATA!]"
            elif 0xfffffff00a0e0000 <= target_page < 0xfffffff00a200000:
                annotation += " [kernel __DATA (KTRR)]"
        
        elif mnemonic in ('bl', 'b'):
            # Branch target
            annotation = f"  ; call/jump"
        
        elif mnemonic in ('cbz', 'cbnz', 'tbz', 'tbnz'):
            annotation = f"  ; conditional branch"
        
        elif mnemonic == 'ret' or mnemonic == 'retab':
            print(f"  0x{insn.address:x}: {mnemonic:8s} {op_str}{annotation}")
            print(f"  --- END (return) ---")
            return
        
        elif 'mrs' in mnemonic:
            annotation = f"  ; system register read"
        
        print(f"  0x{insn.address:x}: {mnemonic:8s} {op_str}{annotation}")
        
        if i >= max_instrs - 1:
            print(f"  --- TRUNCATED at {max_instrs} instructions ---")
            return

# ============================================================
# TARGET 1: AMFI functions that read AMFI __DATA+0x428
# From trace_pmap_cs_kill.py: PC=0xfffffff008f76d68 refs AMFI+0x428
# This is in AMFI __TEXT_EXEC (0xfffffff008f76d10, size 0x263e4)
# ============================================================
print("\n" + "="*70)
print("TARGET 1: AMFI function at 0xfffffff008f76d10 (start of __TEXT_EXEC)")
print("This is the FIRST function in AMFI — likely the main entry point")
print("="*70)

# The first ref is at 0xfffffff008f76d68, which is very close to __TEXT_EXEC start
# Function likely starts at 0xfffffff008f76d10 (the segment start)
disasm_function(0xfffffff008f76d10, max_instrs=60, label="(AMFI main entry?)")

# ============================================================
# TARGET 2: Function around 0xfffffff008f778a0 (refs AMFI+0x3b0)
# This reads a DIFFERENT offset — might be a different check
# ============================================================
print("\n" + "="*70)
print("TARGET 2: Function near 0xfffffff008f778a0 (refs AMFI+0x3b0)")
print("="*70)

# Walk back to find function start (look for PACIBSP or STP X29,X30)
func_start = 0xfffffff008f778a0
off = va_to_fileoff(func_start)
if off:
    for back in range(0, 0x200, 4):
        check = off - back
        instr = read_u32(data, check)
        if instr == 0xD503237F:  # PACIBSP
            func_start = fileoff_to_va(check)
            break
        if (instr & 0xFFE00000) == 0xA9800000:  # STP with pre-index
            func_start = fileoff_to_va(check)
            break

disasm_function(func_start, max_instrs=80, label="(refs AMFI+0x3b0)")

# ============================================================
# TARGET 3: pmap_cs_check function
# String "pmap_cs_check_" at VA 0xfffffff0070554a8
# Find xref to this string → that's the function
# ============================================================
print("\n" + "="*70)
print("TARGET 3: Function that references 'pmap_cs_check_' string")
print("="*70)

# The string is at 0xfffffff0070554a8
# Search for ADRP+ADD that targets this page
target_str_va = 0xfffffff0070554a8
target_page = target_str_va & ~0xFFF
target_pageoff = target_str_va & 0xFFF

# Search in __TEXT_EXEC
TEXT_EXEC_OFF = va_to_fileoff(0xfffffff007d90000)
found_pmap_cs_func = None

if TEXT_EXEC_OFF:
    for scan_off in range(TEXT_EXEC_OFF, min(TEXT_EXEC_OFF + 0x2198000, len(data) - 8), 4):
        instr = read_u32(data, scan_off)
        if (instr & 0x9F000000) != 0x90000000:
            continue
        
        immhi = (instr >> 5) & 0x7FFFF
        immlo = (instr >> 29) & 0x3
        imm = (immhi << 2) | immlo
        if imm & 0x100000:
            imm = imm - 0x200000
        
        pc_va = fileoff_to_va(scan_off)
        if not pc_va: continue
        pc_page = pc_va & ~0xFFF
        adrp_target = pc_page + (imm << 12)
        
        if adrp_target == target_page:
            next_instr = read_u32(data, scan_off + 4)
            if (next_instr & 0xFFC00000) == 0x91000000:
                add_imm = (next_instr >> 10) & 0xFFF
                if add_imm == target_pageoff:
                    found_pmap_cs_func = pc_va
                    break

if found_pmap_cs_func:
    # Walk back to function start
    func_start = found_pmap_cs_func
    off = va_to_fileoff(func_start)
    if off:
        for back in range(0, 0x100, 4):
            check = off - back
            instr = read_u32(data, check)
            if instr == 0xD503237F or (instr & 0xFFE00000) == 0xA9800000:
                func_start = fileoff_to_va(check)
                break
    
    disasm_function(func_start, max_instrs=80, label="(pmap_cs_check)")
else:
    print("  pmap_cs_check function not found via string xref")

# ============================================================
# TARGET 4: cs_invalid_page — the function that actually kills
# String "cs_invalid_page" at 0xfffffff007086429 (from earlier analysis)
# ============================================================
print("\n" + "="*70)
print("TARGET 4: cs_invalid_page (the kill function)")
print("="*70)

target_str_va = 0xfffffff007086429
target_page = target_str_va & ~0xFFF
target_pageoff = target_str_va & 0xFFF

found_cs_invalid = None
if TEXT_EXEC_OFF:
    for scan_off in range(TEXT_EXEC_OFF, min(TEXT_EXEC_OFF + 0x800000, len(data) - 8), 4):
        instr = read_u32(data, scan_off)
        if (instr & 0x9F000000) != 0x90000000:
            continue
        
        immhi = (instr >> 5) & 0x7FFFF
        immlo = (instr >> 29) & 0x3
        imm = (immhi << 2) | immlo
        if imm & 0x100000:
            imm = imm - 0x200000
        
        pc_va = fileoff_to_va(scan_off)
        if not pc_va: continue
        pc_page = pc_va & ~0xFFF
        adrp_target = pc_page + (imm << 12)
        
        if adrp_target == target_page:
            next_instr = read_u32(data, scan_off + 4)
            if (next_instr & 0xFFC00000) == 0x91000000:
                add_imm = (next_instr >> 10) & 0xFFF
                if add_imm == target_pageoff:
                    found_cs_invalid = pc_va
                    break

if found_cs_invalid:
    func_start = found_cs_invalid
    off = va_to_fileoff(func_start)
    if off:
        for back in range(0, 0x200, 4):
            check = off - back
            instr = read_u32(data, check)
            if instr == 0xD503237F or (instr & 0xFFE00000) == 0xA9800000:
                func_start = fileoff_to_va(check)
                break
    
    disasm_function(func_start, max_instrs=120, label="(cs_invalid_page — KILL)")
else:
    print("  cs_invalid_page function not found")

# ============================================================
# TARGET 5: AMFI __DATA+0x428 — what IS this value?
# 62 refs from enforcement code → this is heavily used
# ============================================================
print("\n" + "="*70)
print("TARGET 5: AMFI __DATA+0x428 analysis")
print("="*70)

amfi_data_off = va_to_fileoff(0xfffffff00a330098)
if amfi_data_off:
    val_at_428 = read_u64(data, amfi_data_off + 0x428)
    val_at_3b0 = read_u64(data, amfi_data_off + 0x3b0)
    print(f"  AMFI __DATA+0x428 (in kernelcache): 0x{val_at_428:016x}")
    print(f"  AMFI __DATA+0x3b0 (in kernelcache): 0x{val_at_3b0:016x}")
    print()
    
    # Dump context around +0x428
    print("  Context around +0x428:")
    for off in range(0x410, 0x450, 8):
        val = read_u64(data, amfi_data_off + off)
        marker = " ← +0x428" if off == 0x428 else ""
        print(f"    +0x{off:x}: 0x{val:016x}{marker}")
    
    print(f"\n  Context around +0x3b0:")
    for off in range(0x3a0, 0x3d0, 8):
        val = read_u64(data, amfi_data_off + off)
        marker = " ← +0x3b0" if off == 0x3b0 else ""
        print(f"    +0x{off:x}: 0x{val:016x}{marker}")

print("\n" + "="*70)
print("ANALYSIS COMPLETE")
print("="*70)
print("""
Look at the disassembled functions above for:
1. CBZ/CBNZ/TBZ/TBNZ after loading from AMFI __DATA → conditional bypass
2. Any LDR from writable address followed by comparison → patchable flag
3. BL to other functions → trace the call chain
4. The exact instruction sequence that leads to SIGKILL

If any conditional branch depends on a value loaded from writable memory,
we can patch that value to take the "allow" path instead of "kill" path.
""")
