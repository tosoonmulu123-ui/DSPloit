#!/usr/bin/env python3
"""
DSPloit Deep Kernelcache Analyzer v3
- Disassemble PPL check functions
- Find IOSurface externalMethod handler
- Map pmap_enter_options_internal
- Find sandbox bypass vectors
"""

import struct
import os
import sys
from collections import defaultdict

KCACHE = r"d:\Backup\Personal\Hp\iPhone\DSPloit\kernelcache.release.iphone11b.decompressed"
CODE_OFFSET = 0xe00000

def decode_arm64(opcode, addr=0):
    if opcode == 0xD65F03C0: return "RET"
    if opcode == 0xD503201F: return "NOP"
    if (opcode & 0xFC000000) == 0x14000000:
        imm = opcode & 0x3FFFFFF
        if imm & 0x2000000: imm |= ~0x3FFFFFF
        return f"B 0x{(addr + imm*4) & 0xFFFFFFFFFFFFFFFF:x}"
    if (opcode & 0xFC000000) == 0x94000000:
        imm = opcode & 0x3FFFFFF
        if imm & 0x2000000: imm |= ~0x3FFFFFF
        return f"BL 0x{(addr + imm*4) & 0xFFFFFFFFFFFFFFFF:x}"
    if (opcode & 0xFFFFFC1F) == 0xD61F0000:
        return f"BR X{(opcode>>5)&0x1F}"
    if (opcode & 0xFFFFFC1F) == 0xD63F0000:
        return f"BLR X{(opcode>>5)&0x1F}"
    if (opcode & 0xFFC00000) == 0xF9400000:
        rt = opcode & 0x1F; rn = (opcode>>5)&0x1F; imm = ((opcode>>10)&0xFFF)*8
        return f"LDR X{rt}, [X{rn}, #{imm}]"
    if (opcode & 0xFFC00000) == 0xF9000000:
        rt = opcode & 0x1F; rn = (opcode>>5)&0x1F; imm = ((opcode>>10)&0xFFF)*8
        return f"STR X{rt}, [X{rn}, #{imm}]"
    if (opcode & 0xFF800000) == 0x91000000:
        rd = opcode&0x1F; rn = (opcode>>5)&0x1F; imm = (opcode>>10)&0xFFF
        sh = (opcode>>22)&1
        if sh: imm <<= 12
        return f"ADD X{rd}, X{rn}, #0x{imm:x}"
    if (opcode & 0xFF800000) == 0xD1000000:
        rd = opcode&0x1F; rn = (opcode>>5)&0x1F; imm = (opcode>>10)&0xFFF
        return f"SUB X{rd}, X{rn}, #0x{imm:x}"
    if (opcode & 0xFFE0FFE0) == 0xAA0003E0:
        return f"MOV X{opcode&0x1F}, X{(opcode>>16)&0x1F}"
    if (opcode & 0xFF800000) == 0xD2800000:
        rd = opcode&0x1F; imm = (opcode>>5)&0xFFFF; hw = (opcode>>21)&3
        return f"MOVZ X{rd}, #0x{imm<<(hw*16):x}"
    if (opcode & 0xFF800000) == 0xF2800000:
        rd = opcode&0x1F; imm = (opcode>>5)&0xFFFF; hw = (opcode>>21)&3
        return f"MOVK X{rd}, #0x{imm:x}, LSL #{hw*16}"
    if (opcode & 0x7F800000) == 0x37000000:
        rt = opcode&0x1F; bit = ((opcode>>19)&0x1F)|((opcode>>26)&0x20)
        imm = (opcode>>5)&0x3FFF
        if imm & 0x2000: imm |= ~0x3FFF
        return f"TBNZ X{rt}, #{bit}, 0x{(addr+imm*4)&0xFFFFFFFFFFFFFFFF:x}"
    if (opcode & 0x7F800000) == 0x36000000:
        rt = opcode&0x1F; bit = ((opcode>>19)&0x1F)|((opcode>>26)&0x20)
        imm = (opcode>>5)&0x3FFF
        if imm & 0x2000: imm |= ~0x3FFF
        return f"TBZ X{rt}, #{bit}, 0x{(addr+imm*4)&0xFFFFFFFFFFFFFFFF:x}"
    if (opcode & 0xFF000000) == 0x54000000:
        imm = (opcode>>5)&0x7FFFF
        if imm & 0x40000: imm |= ~0x7FFFF
        cond = opcode & 0xF
        conds = ["EQ","NE","CS","CC","MI","PL","VS","VC","HI","LS","GE","LT","GT","LE","AL","NV"]
        return f"B.{conds[cond]} 0x{(addr+imm*4)&0xFFFFFFFFFFFFFFFF:x}"
    if (opcode & 0xFFC00000) == 0xA9400000:
        rt = opcode&0x1F; rt2 = (opcode>>10)&0x1F; rn = (opcode>>5)&0x1F
        imm = (opcode>>15)&0x7F
        if imm & 0x40: imm -= 128
        return f"LDP X{rt}, X{rt2}, [X{rn}, #{imm*8}]"
    if (opcode & 0xFFC00000) == 0xA9000000:
        rt = opcode&0x1F; rt2 = (opcode>>10)&0x1F; rn = (opcode>>5)&0x1F
        imm = (opcode>>15)&0x7F
        if imm & 0x40: imm -= 128
        return f"STP X{rt}, X{rt2}, [X{rn}, #{imm*8}]"
    if (opcode & 0xFFF00000) == 0xD5300000:
        rt = opcode&0x1F; op1=(opcode>>16)&7; crn=(opcode>>12)&0xF
        crm=(opcode>>8)&0xF; op2=(opcode>>5)&7
        return f"MRS X{rt}, S3_{op1}_C{crn}_C{crm}_{op2}"
    if (opcode & 0x9F000000) == 0x90000000:
        rd = opcode&0x1F; immhi=(opcode>>5)&0x7FFFF; immlo=(opcode>>29)&3
        imm = (immhi<<2)|immlo
        if imm & 0x100000: imm |= ~0xFFFFF
        pc_page = addr & ~0xFFF
        result = (pc_page + (imm<<12)) & 0xFFFFFFFFFFFFFFFF
        return f"ADRP X{rd}, 0x{result:x}"
    if (opcode & 0xFF800000) == 0x72800000:
        rd = opcode&0x1F; imm = (opcode>>5)&0xFFFF; hw = (opcode>>21)&3
        return f"MOVK W{rd}, #0x{imm:x}, LSL #{hw*16}"
    if (opcode & 0xFF800000) == 0x52800000:
        rd = opcode&0x1F; imm = (opcode>>5)&0xFFFF; hw = (opcode>>21)&3
        return f"MOVZ W{rd}, #0x{imm<<(hw*16):x}"
    if (opcode & 0xBFC00000) == 0xB9400000:
        rt = opcode&0x1F; rn = (opcode>>5)&0x1F; imm = ((opcode>>10)&0xFFF)*4
        sf = "X" if (opcode>>30)&1 else "W"
        return f"LDR {sf}{rt}, [X{rn}, #{imm}]"
    if (opcode & 0xBFC00000) == 0xB9000000:
        rt = opcode&0x1F; rn = (opcode>>5)&0x1F; imm = ((opcode>>10)&0xFFF)*4
        sf = "X" if (opcode>>30)&1 else "W"
        return f"STR {sf}{rt}, [X{rn}, #{imm}]"
    if (opcode & 0xFFE00C00) == 0xB8600800:
        rt = opcode&0x1F; rn = (opcode>>5)&0x1F; rm = (opcode>>16)&0x1F
        return f"LDR W{rt}, [X{rn}, X{rm}]"
    if (opcode & 0x7F200000) == 0x1B000000:
        rd = opcode&0x1F; rn = (opcode>>5)&0x1F; rm = (opcode>>16)&0x1F
        ra = (opcode>>10)&0x1F
        return f"MADD W{rd}, W{rn}, W{rm}, W{ra}"
    return f"??? (0x{opcode:08x})"

def disassemble_range(data, file_offset, vaddr, count):
    """Disassemble count instructions starting at file_offset"""
    lines = []
    for i in range(0, count*4, 4):
        if file_offset + i + 4 > len(data): break
        op = struct.unpack_from('<I', data, file_offset + i)[0]
        addr = vaddr + i
        lines.append((addr, decode_arm64(op, addr)))
    return lines

def find_function_containing(data, code_start, target_addr):
    """Find function prologue before target_addr"""
    # Search backwards from target for STP X29, X30 or SUB SP
    offset = target_addr - code_start
    for i in range(offset, max(offset - 0x10000, 0), -4):
        op = struct.unpack_from('<I', data, i)[0]
        # STP with pre-index to SP (function prologue)
        if (op & 0xFFC003E0) == 0xA98003E0:  # STP Xn, Xm, [SP, #imm]!
            return code_start + i
        # SUB SP, SP, #imm (also prologue)
        if (op & 0xFFC003FF) == 0xD10003FF:
            # Check if next is STP
            if i + 4 < len(data):
                next_op = struct.unpack_from('<I', data, i+4)[0]
                if (next_op & 0xFFC00000) == 0xA9000000:  # STP
                    return code_start + i
    return target_addr

def find_function_end(data, code_start, func_start):
    """Find RET after func_start (simplified)"""
    offset = func_start - code_start
    for i in range(offset, min(offset + 0x20000, len(data)), 4):
        op = struct.unpack_from('<I', data, i)[0]
        if op == 0xD65F03C0:  # RET
            return code_start + i + 4
    return func_start + 0x1000

def main():
    print("=" * 70)
    print("  DSPloit Deep Analyzer v3 - PPL/IOSurface/Sandbox Deep Dive")
    print("=" * 70)
    
    with open(KCACHE, 'rb') as f:
        data = f.read()
    
    code_data = data[CODE_OFFSET:]
    print(f"Loaded {len(data)/1024/1024:.1f} MB, code at 0x{CODE_OFFSET:x}\n")

    # ================================================================
    # PART 1: Disassemble around PPL check locations
    # ================================================================
    print("=" * 70)
    print("  PART 1: PPL CHECK FUNCTIONS (TBNZ/TBZ bit #14)")
    print("=" * 70)
    
    ppl_check_addrs = [
        0xe33e14, 0xe4f7c4, 0xe4f860, 0xe50124,
        0xe91114, 0xe91cb4, 0xe98368, 0xe9848c,
        0xe9b448, 0xe9bce4
    ]
    
    # Group by function (find which function each PPL check belongs to)
    ppl_functions = {}
    for addr in ppl_check_addrs:
        func_start = find_function_containing(code_data, CODE_OFFSET, addr)
        if func_start not in ppl_functions:
            ppl_functions[func_start] = []
        ppl_functions[func_start].append(addr)
    
    print(f"\nPPL checks found in {len(ppl_functions)} distinct functions:\n")
    
    for func_addr, checks in sorted(ppl_functions.items()):
        func_offset = func_addr - CODE_OFFSET
        func_end = find_function_end(code_data, CODE_OFFSET, func_addr)
        func_size = func_end - func_addr
        print(f"\n--- Function at 0x{func_addr:x} (size ~{func_size} bytes, "
              f"{len(checks)} PPL checks) ---")
        
        # Disassemble first 30 instructions
        lines = disassemble_range(code_data, func_offset, func_addr, 30)
        for addr, instr in lines:
            marker = " <-- PPL CHECK" if addr in checks else ""
            print(f"  0x{addr:x}: {instr}{marker}")
        
        # Also show context around each PPL check
        for check_addr in checks:
            if check_addr - func_addr > 120:  # Only if not already shown
                print(f"\n  ... (PPL check context at 0x{check_addr:x}):")
                check_offset = check_addr - CODE_OFFSET
                ctx_lines = disassemble_range(code_data, check_offset - 16, 
                                             check_addr - 16, 12)
                for addr, instr in ctx_lines:
                    marker = " <-- PPL CHECK" if addr == check_addr else ""
                    print(f"  0x{addr:x}: {instr}{marker}")

    # ================================================================
    # PART 2: Find IOSurface externalMethod
    # ================================================================
    print("\n" + "=" * 70)
    print("  PART 2: IOSurface externalMethod HANDLER")
    print("=" * 70)
    
    # Search for "IOSurfaceRootUserClient" and "externalMethod" strings
    # near each other - this identifies the IOSurface user client
    iosurface_ext_offsets = []
    search_terms = [b'IOSurfaceRootUserClient', b'IOSurfaceRoot::']
    
    for term in search_terms:
        pos = 0
        while True:
            pos = data.find(term, pos)
            if pos == -1: break
            iosurface_ext_offsets.append((pos, data[pos:pos+80].split(b'\x00')[0].decode('ascii', errors='ignore')))
            pos += 1
    
    print(f"\nIOSurfaceRoot references: {len(iosurface_ext_offsets)}")
    for offset, s in iosurface_ext_offsets[:15]:
        print(f"  0x{offset:08x}: {s}")
    
    # Find "s_methods" or dispatch table patterns for IOSurface
    # IOSurface external methods are numbered 0-35+
    ext_method_str = data.find(b'IOSurfaceRootUserClient::externalMethod')
    if ext_method_str != -1:
        print(f"\n  IOSurfaceRootUserClient::externalMethod string at: 0x{ext_method_str:x}")
    
    # Search for IOSurface selector count (usually around 35-40 methods)
    # Look for MOVZ with values 33-40 near externalMethod code
    
    # ================================================================
    # PART 3: Function #3 deep analysis (667 branches = likely pmap)
    # ================================================================
    print("\n" + "=" * 70)
    print("  PART 3: FUNCTION #3 (0x11126c0) - 667 BRANCHES - DEEP DISASM")
    print("=" * 70)
    
    func3_offset = 0x11126c0 - CODE_OFFSET
    # Disassemble first 100 instructions
    print("\nFirst 100 instructions:")
    lines = disassemble_range(code_data, func3_offset, 0x11126c0, 100)
    for addr, instr in lines:
        print(f"  0x{addr:x}: {instr}")
    
    # Find PPL-related patterns within this function
    print("\n\nPPL patterns within function #3 (scanning 30KB):")
    ppl_in_func3 = []
    for i in range(func3_offset, func3_offset + 30784, 4):
        if i + 4 > len(code_data): break
        op = struct.unpack_from('<I', code_data, i)[0]
        if (op & 0xFFF80000) == 0x37700000 or (op & 0xFFF80000) == 0x36700000:
            addr = CODE_OFFSET + i
            ppl_in_func3.append((addr, decode_arm64(op, addr)))
    
    print(f"  Found {len(ppl_in_func3)} TBNZ/TBZ bit#14 in function #3")
    for addr, instr in ppl_in_func3[:10]:
        print(f"    0x{addr:x}: {instr}")

    # ================================================================
    # PART 4: Scan for IOSurface property get/set (KRW primitive)
    # ================================================================
    print("\n" + "=" * 70)
    print("  PART 4: IOSurface PROPERTY GET/SET (potential KRW)")
    print("=" * 70)
    
    # IOSurface properties are accessed via s_property_get/s_property_set
    # These are the functions that can give us arbitrary read/write
    prop_terms = [
        b's_property_get', b's_property_set', b'set_value',
        b'get_value', b'IOSurfacePropertyKey', b'IOSurfaceSetValue',
        b'IOSurfaceGetValue', b'IOSurfaceCopyValue',
    ]
    
    print("\nIOSurface property-related strings:")
    for term in prop_terms:
        pos = data.find(term)
        if pos != -1:
            s = data[pos:pos+60].split(b'\x00')[0].decode('ascii', errors='ignore')
            print(f"  0x{pos:08x}: {s}")
    
    # ================================================================
    # PART 5: Find sandbox evaluation function
    # ================================================================
    print("\n" + "=" * 70)
    print("  PART 5: SANDBOX EVALUATION (sb_evaluate)")
    print("=" * 70)
    
    sb_terms = [b'sb_evaluate', b'sandbox_check', b'mac_proc_check',
                b'sandbox_apply', b'sb_ustate']
    
    print("\nSandbox-related function strings:")
    for term in sb_terms:
        pos = 0
        count = 0
        while count < 3:
            pos = data.find(term, pos)
            if pos == -1: break
            s = data[pos:pos+80].split(b'\x00')[0].decode('ascii', errors='ignore')
            print(f"  0x{pos:08x}: {s}")
            pos += 1
            count += 1
    
    # ================================================================
    # PART 6: XPRR/APRR register analysis
    # ================================================================
    print("\n" + "=" * 70)
    print("  PART 6: XPRR/APRR SYSTEM REGISTERS")
    print("=" * 70)
    
    # Key system registers for PPL:
    # S3_6_C15_C1_0 = APRR_EL1 (Apple Page Region Register)
    # S3_6_C15_C1_5 = APRR_EL0
    # S3_4_C15_C2_7 = GXF_ENTER (Guarded Execution Facility)
    
    aprr_reads = []
    gxf_instrs = []
    
    scan_size = min(8*1024*1024, len(code_data))
    for i in range(0, scan_size, 4):
        op = struct.unpack_from('<I', code_data, i)[0]
        if (op & 0xFFF00000) == 0xD5300000:  # MRS
            # Decode system register
            op1 = (op>>16)&7; crn = (op>>12)&0xF; crm = (op>>8)&0xF; op2 = (op>>5)&7
            # APRR: op1=6, crn=15, crm=1
            if op1 == 6 and crn == 15 and crm == 1:
                aprr_reads.append((CODE_OFFSET + i, op, op2))
            # GXF: op1=4, crn=15, crm=2
            if op1 == 4 and crn == 15:
                gxf_instrs.append((CODE_OFFSET + i, op))
        elif (op & 0xFFF00000) == 0xD5100000:  # MSR
            op1 = (op>>16)&7; crn = (op>>12)&0xF; crm = (op>>8)&0xF; op2 = (op>>5)&7
            if op1 == 6 and crn == 15 and crm == 1:
                aprr_reads.append((CODE_OFFSET + i, op, op2))
            if op1 == 4 and crn == 15:
                gxf_instrs.append((CODE_OFFSET + i, op))
    
    print(f"\nAPRR register accesses: {len(aprr_reads)}")
    for addr, op, op2 in aprr_reads[:20]:
        is_read = (op & 0xFFF00000) == 0xD5300000
        rt = op & 0x1F
        rw = "MRS" if is_read else "MSR"
        print(f"  0x{addr:x}: {rw} X{rt}, S3_6_C15_C1_{op2} (APRR)")
    
    print(f"\nGXF register accesses: {len(gxf_instrs)}")
    for addr, op in gxf_instrs[:20]:
        is_read = (op & 0xFFF00000) == 0xD5300000
        rt = op & 0x1F
        crm = (op>>8)&0xF; op2 = (op>>5)&7
        rw = "MRS" if is_read else "MSR"
        print(f"  0x{addr:x}: {rw} X{rt}, S3_4_C15_C{crm}_{op2} (GXF)")

    # ================================================================
    # PART 7: Find ucred structure and cr_label offset
    # ================================================================
    print("\n" + "=" * 70)
    print("  PART 7: UCRED / CR_LABEL / SANDBOX LABEL OFFSETS")
    print("=" * 70)
    
    # Search for ucred-related strings that reveal structure layout
    ucred_terms = [b'ucred_rw', b'cr_label', b'posix_cred', b'cr_uid',
                   b'proc_ucred', b'kauth_cred_get', b'l_perpolicy']
    
    print("\nUcred/label structure strings:")
    for term in ucred_terms:
        pos = 0
        count = 0
        while count < 5:
            pos = data.find(term, pos)
            if pos == -1: break
            s = data[pos:pos+100].split(b'\x00')[0].decode('ascii', errors='ignore')
            print(f"  0x{pos:08x}: {s}")
            pos += 1
            count += 1
    
    # ================================================================
    # PART 8: Find proc_find / procbypid implementation
    # ================================================================
    print("\n" + "=" * 70)
    print("  PART 8: PROC_FIND / ALLPROC")
    print("=" * 70)
    
    proc_terms = [b'_proc_find', b'proc_find_ident', b'allproc',
                  b'proc_list_lock', b'proc_iterate']
    
    print("\nProcess lookup strings:")
    for term in proc_terms:
        pos = 0
        count = 0
        while count < 3:
            pos = data.find(term, pos)
            if pos == -1: break
            s = data[pos:pos+60].split(b'\x00')[0].decode('ascii', errors='ignore')
            print(f"  0x{pos:08x}: {s}")
            pos += 1
            count += 1
    
    # ================================================================
    # PART 9: Key offsets summary for exploitation
    # ================================================================
    print("\n" + "=" * 70)
    print("  PART 9: EXPLOITATION SUMMARY")
    print("=" * 70)
    
    print("""
KEY FINDINGS:
=============

1. PPL PROTECTION:
   - 223 PPL check instructions (TBNZ/TBZ bit #14) in first 8MB of code
   - PPL checks are in pmap functions (page table management)
   - APRR registers control page permissions at hardware level
   - GXF (Guarded Execution Facility) enforces PPL entry/exit

2. POTENTIAL BYPASS VECTORS:
   a) IOSurface property manipulation (if we can find the dispatch table)
   b) DMA via IOSurface (GPU can write to PPL-protected pages)
   c) Race condition in pmap_enter (667 branches = complex logic = race window)
   d) APRR register manipulation (requires EL1 or PPL context)

3. CONFIRMED WRITABLE (from device testing):
   - Sandbox label pointer (cr_label -> l_perpolicy[sandbox])
   - vm_map entries
   - Kernel heap objects (via socket KRW)

4. CONFIRMED PPL-BLOCKED:
   - ucred uid/gid fields (proc_ro -> ucred -> cr_uid)
   - Page table entries
   - Kernel __TEXT, __DATA_CONST

5. NEXT STEPS FOR RESEARCH:
   - Disassemble IOSurface externalMethod dispatch table
   - Find IOSurface property get/set kernel implementation
   - Map APRR register usage to find potential manipulation points
   - Analyze function #3 (0x11126c0) for race conditions
""")
    
    print("\nDone! Analysis complete.")

if __name__ == "__main__":
    main()
