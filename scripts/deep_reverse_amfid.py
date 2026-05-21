#!/usr/bin/env python3
"""
deep_reverse_amfid.py — Deep disassembly amfid
Fokus: XPC handlers, override paths, auxiliary signatures, local signing
Trace setiap function yang berhubungan dengan bypass
"""
import struct, os
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

AMFID = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                     "extracted", "usr", "libexec", "amfid")

def read_u32(data, off):
    if off + 4 > len(data): return 0
    return struct.unpack_from('<I', data, off)[0]

def read_u64(data, off):
    if off + 8 > len(data): return 0
    return struct.unpack_from('<Q', data, off)[0]

with open(AMFID, 'rb') as f:
    data = f.read()

# Parse segments
segments = []
ncmds = read_u32(data, 16)
cmd_off = 32
for _ in range(ncmds):
    cmd = read_u32(data, cmd_off)
    cmdsize = read_u32(data, cmd_off + 4)
    if cmdsize == 0: break
    if cmd == 0x19:
        segname = data[cmd_off+8:cmd_off+24].split(b'\x00')[0].decode()
        vmaddr = read_u64(data, cmd_off + 24)
        vmsize = read_u64(data, cmd_off + 32)
        fileoff = read_u64(data, cmd_off + 40)
        filesize = read_u64(data, cmd_off + 48)
        segments.append({'name': segname, 'vmaddr': vmaddr, 'vmsize': vmsize,
                        'fileoff': fileoff, 'filesize': filesize})
    cmd_off += cmdsize

def va_to_off(va):
    for seg in segments:
        if seg['vmaddr'] <= va < seg['vmaddr'] + seg['vmsize']:
            return seg['fileoff'] + (va - seg['vmaddr'])
    return None

def off_to_va(off):
    for seg in segments:
        if seg['fileoff'] <= off < seg['fileoff'] + seg['filesize']:
            return seg['vmaddr'] + (off - seg['fileoff'])
    return None

def find_string_va(s):
    """Cari string dan return VA-nya."""
    encoded = s.encode() if isinstance(s, str) else s
    idx = data.find(encoded)
    if idx >= 0:
        return off_to_va(idx)
    return None

def find_xrefs_to_va(target_va, search_range=None):
    """Cari semua ADRP+ADD yang reference target VA."""
    target_page = target_va & ~0xFFF
    target_pageoff = target_va & 0xFFF
    xrefs = []
    
    # Search di __TEXT segment
    for seg in segments:
        if seg['name'] != '__TEXT' or seg['filesize'] == 0:
            continue
        start = seg['fileoff']
        end = start + seg['filesize']
        
        for off in range(start, min(end, len(data) - 8), 4):
            instr = read_u32(data, off)
            if (instr & 0x9F000000) != 0x90000000:
                continue
            
            immhi = (instr >> 5) & 0x7FFFF
            immlo = (instr >> 29) & 0x3
            imm = (immhi << 2) | immlo
            if imm & 0x100000:
                imm = imm - 0x200000
            
            pc_va = off_to_va(off)
            if not pc_va: continue
            pc_page = pc_va & ~0xFFF
            adrp_target = pc_page + (imm << 12)
            
            if adrp_target == target_page:
                if off + 4 < end:
                    next_instr = read_u32(data, off + 4)
                    if (next_instr & 0xFFC00000) == 0x91000000:
                        add_imm = (next_instr >> 10) & 0xFFF
                        if add_imm == target_pageoff:
                            xrefs.append(pc_va)
    return xrefs

def find_func_start(va):
    """Walk back dari VA untuk cari function start (PACIBSP)."""
    off = va_to_off(va)
    if not off: return va
    for back in range(0, 0x400, 4):
        check = off - back
        if check < 0: break
        instr = read_u32(data, check)
        if instr == 0xD503237F:  # PACIBSP
            return off_to_va(check)
    return va

def disasm_at(va, count=60):
    """Disassemble dari VA, return list of (addr, mnemonic, op_str)."""
    off = va_to_off(va)
    if not off: return []
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    code = data[off:off + count * 4]
    result = []
    for insn in md.disasm(code, va):
        result.append((insn.address, insn.mnemonic, insn.op_str))
        if insn.mnemonic in ('ret', 'retab'):
            break
    return result

print("="*70)
print("  DEEP REVERSE ENGINEERING: amfid")
print("  Fokus: Override paths, XPC handlers, Auxiliary signatures")
print("="*70)

# ============================================================
# 1. _AMFIShowOverridePath — APA INI?
# ============================================================
print(f"\n{'='*70}")
print("1. _AMFIShowOverridePath")
print(f"{'='*70}")

override_va = find_string_va("_AMFIShowOverridePath")
if override_va:
    print(f"   String VA: 0x{override_va:x}")
    xrefs = find_xrefs_to_va(override_va)
    print(f"   Xrefs: {len(xrefs)}")
    for xref in xrefs[:5]:
        func_start = find_func_start(xref)
        print(f"\n   Function at 0x{func_start:x} (xref at 0x{xref:x}):")
        instrs = disasm_at(func_start, 40)
        for addr, mn, op in instrs[:30]:
            print(f"     0x{addr:x}: {mn:8s} {op}")

# ============================================================
# 2. __xpcActionDisable — handler untuk "disable"
# ============================================================
print(f"\n{'='*70}")
print("2. __xpcActionDisable")
print(f"{'='*70}")

disable_va = find_string_va("__xpcActionDisable")
if disable_va:
    print(f"   String VA: 0x{disable_va:x}")
    xrefs = find_xrefs_to_va(disable_va)
    print(f"   Xrefs: {len(xrefs)}")
    for xref in xrefs[:3]:
        func_start = find_func_start(xref)
        print(f"\n   Function at 0x{func_start:x}:")
        instrs = disasm_at(func_start, 50)
        for addr, mn, op in instrs[:40]:
            print(f"     0x{addr:x}: {mn:8s} {op}")

# ============================================================
# 3. __handleXPCDictionary — main XPC message dispatcher
# ============================================================
print(f"\n{'='*70}")
print("3. __handleXPCDictionary (main XPC dispatcher)")
print(f"{'='*70}")

handler_va = find_string_va("__handleXPCDictionary")
if handler_va:
    print(f"   String VA: 0x{handler_va:x}")
    xrefs = find_xrefs_to_va(handler_va)
    print(f"   Xrefs: {len(xrefs)}")
    for xref in xrefs[:2]:
        func_start = find_func_start(xref)
        print(f"\n   Function at 0x{func_start:x}:")
        instrs = disasm_at(func_start, 80)
        for addr, mn, op in instrs[:60]:
            annotation = ""
            if mn == 'bl': annotation = "  ; CALL"
            elif mn in ('cbz', 'cbnz', 'tbz', 'tbnz'): annotation = "  ; BRANCH"
            elif mn == 'adrp' and '0x100028' in op: annotation = "  ; __DATA ref"
            print(f"     0x{addr:x}: {mn:8s} {op}{annotation}")

# ============================================================
# 4. com.apple.private.amfi.set-trust — wie wordt dit gecheckt?
# ============================================================
print(f"\n{'='*70}")
print("4. com.apple.private.amfi.set-trust (entitlement check)")
print(f"{'='*70}")

settrust_va = find_string_va("com.apple.private.amfi.set-trust")
if settrust_va:
    print(f"   String VA: 0x{settrust_va:x}")
    xrefs = find_xrefs_to_va(settrust_va)
    print(f"   Xrefs: {len(xrefs)}")
    for xref in xrefs[:3]:
        func_start = find_func_start(xref)
        print(f"\n   Function at 0x{func_start:x}:")
        instrs = disasm_at(func_start, 60)
        for addr, mn, op in instrs[:50]:
            print(f"     0x{addr:x}: {mn:8s} {op}")

# ============================================================
# 5. com.apple.private.mis.trust.set — MIS trust set
# ============================================================
print(f"\n{'='*70}")
print("5. com.apple.private.mis.trust.set")
print(f"{'='*70}")

mis_va = find_string_va("com.apple.private.mis.trust.set")
if mis_va:
    print(f"   String VA: 0x{mis_va:x}")
    xrefs = find_xrefs_to_va(mis_va)
    print(f"   Xrefs: {len(xrefs)}")
    for xref in xrefs[:3]:
        func_start = find_func_start(xref)
        print(f"\n   Function at 0x{func_start:x}:")
        instrs = disasm_at(func_start, 50)
        for addr, mn, op in instrs[:40]:
            print(f"     0x{addr:x}: {mn:8s} {op}")

# ============================================================
# 6. Auxiliary signature creation
# ============================================================
print(f"\n{'='*70}")
print("6. Auxiliary signature creation")
print(f"{'='*70}")

aux_va = find_string_va("creating auxiliary signature")
if aux_va:
    print(f"   String VA: 0x{aux_va:x}")
    xrefs = find_xrefs_to_va(aux_va)
    print(f"   Xrefs: {len(xrefs)}")
    for xref in xrefs[:3]:
        func_start = find_func_start(xref)
        print(f"\n   Function at 0x{func_start:x}:")
        instrs = disasm_at(func_start, 60)
        for addr, mn, op in instrs[:50]:
            print(f"     0x{addr:x}: {mn:8s} {op}")

# ============================================================
# 7. Local signing key
# ============================================================
print(f"\n{'='*70}")
print("7. Local signing public key")
print(f"{'='*70}")

localsign_va = find_string_va("local signing public key")
if localsign_va:
    print(f"   String VA: 0x{localsign_va:x}")
    xrefs = find_xrefs_to_va(localsign_va)
    print(f"   Xrefs: {len(xrefs)}")
    for xref in xrefs[:3]:
        func_start = find_func_start(xref)
        print(f"\n   Function at 0x{func_start:x}:")
        instrs = disasm_at(func_start, 50)
        for addr, mn, op in instrs[:40]:
            print(f"     0x{addr:x}: {mn:8s} {op}")

# ============================================================
# 8. trustedCodeSigningIdentities (managed config)
# ============================================================
print(f"\n{'='*70}")
print("8. trustedCodeSigningIdentities")
print(f"{'='*70}")

trusted_id_va = find_string_va("trustedCodeSigningIdentities")
if trusted_id_va:
    print(f"   String VA: 0x{trusted_id_va:x}")
    xrefs = find_xrefs_to_va(trusted_id_va)
    print(f"   Xrefs: {len(xrefs)}")
    for xref in xrefs[:3]:
        func_start = find_func_start(xref)
        print(f"\n   Function at 0x{func_start:x}:")
        instrs = disasm_at(func_start, 50)
        for addr, mn, op in instrs[:40]:
            print(f"     0x{addr:x}: {mn:8s} {op}")

# ============================================================
# 9. "invalid XPC action" — dispatch table analysis
# ============================================================
print(f"\n{'='*70}")
print("9. XPC Action dispatch (invalid XPC action handler)")
print(f"{'='*70}")

invalid_action_va = find_string_va("invalid XPC action: %lu")
if invalid_action_va:
    print(f"   String VA: 0x{invalid_action_va:x}")
    xrefs = find_xrefs_to_va(invalid_action_va)
    print(f"   Xrefs: {len(xrefs)}")
    for xref in xrefs[:2]:
        # This function contains the switch/dispatch for XPC actions
        func_start = find_func_start(xref)
        print(f"\n   DISPATCH FUNCTION at 0x{func_start:x}:")
        print(f"   (Ini berisi switch case untuk semua XPC actions)")
        instrs = disasm_at(func_start, 120)
        for addr, mn, op in instrs[:100]:
            annotation = ""
            if mn == 'bl': annotation = "  ; → handler"
            elif 'cmp' in mn: annotation = "  ; compare action ID"
            elif mn in ('b.eq', 'b.ne', 'b.hi', 'b.lo'): annotation = "  ; dispatch"
            print(f"     0x{addr:x}: {mn:8s} {op}{annotation}")

# ============================================================
# 10. darwinOS check — skip path
# ============================================================
print(f"\n{'='*70}")
print("10. darwinOS check (skip AMFI)")
print(f"{'='*70}")

darwin_va = find_string_va("amfid is booted as darwinOS")
if darwin_va:
    print(f"   String VA: 0x{darwin_va:x}")
    xrefs = find_xrefs_to_va(darwin_va)
    print(f"   Xrefs: {len(xrefs)}")
    for xref in xrefs[:2]:
        func_start = find_func_start(xref)
        print(f"\n   Function at 0x{func_start:x}:")
        instrs = disasm_at(func_start, 50)
        for addr, mn, op in instrs[:40]:
            print(f"     0x{addr:x}: {mn:8s} {op}")

# ============================================================
# 11. __DATA segment analysis — writable globals
# ============================================================
print(f"\n{'='*70}")
print("11. amfid __DATA segment (writable globals)")
print(f"{'='*70}")

for seg in segments:
    if seg['name'] == '__DATA':
        print(f"   VA: 0x{seg['vmaddr']:x}, size: 0x{seg['vmsize']:x}")
        print(f"   Non-zero values:")
        for off in range(0, min(seg['filesize'], 0x1000), 8):
            val = read_u64(data, seg['fileoff'] + off)
            if val != 0:
                # Check if it's a pointer to __TEXT
                is_ptr = 0x100000000 <= val < 0x100030000
                tag = " ← CODE PTR!" if is_ptr else ""
                print(f"     +0x{off:x}: 0x{val:016x}{tag}")

# ============================================================
# SUMMARY
# ============================================================
print(f"\n{'='*70}")
print("DEEP ANALYSIS SUMMARY")
print(f"{'='*70}")
print("""
CELAH YANG DITEMUKAN:

1. _AMFIShowOverridePath — fungsi yang menunjukkan ada "override" path
   Perlu trace: apa yang di-override dan bagaimana trigger-nya

2. __xpcActionDisable — XPC handler untuk disable sesuatu
   Perlu: kirim XPC message dengan action ini dari launchd RC

3. darwinOS check — amfid skip beberapa check kalau "booted as darwinOS"
   Perlu: cari bagaimana amfid detect darwinOS (mungkin sysctl/nvram)

4. Auxiliary signatures — mekanisme add signature tanpa Apple cert
   Perlu: understand format dan trigger condition

5. Local signing key — amfid bisa generate signing key sendiri
   Perlu: trigger key generation + sign binary dengan key itu

6. trustedCodeSigningIdentities — managed config bisa add trusted identities
   Perlu: write managed config plist via KRW/file write

7. com.apple.private.amfi.set-trust — entitlement untuk set trust
   Perlu: forge entitlement atau find process yang sudah punya

8. __DATA code pointers — kalau ada function pointer di __DATA yang writable
   dan dipanggil saat validation → bisa redirect ke "allow" function
""")
