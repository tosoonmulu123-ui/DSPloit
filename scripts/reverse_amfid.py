#!/usr/bin/env python3
"""
reverse_amfid.py — Full reverse engineering amfid binary
Cari celah: XPC handler bugs, validation bypass, logic errors
"""
import struct, os, sys
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

AMFID = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                     "extracted", "usr", "libexec", "amfid")

def read_u32(data, off):
    if off + 4 > len(data): return 0
    return struct.unpack_from('<I', data, off)[0]

def read_u64(data, off):
    if off + 8 > len(data): return 0
    return struct.unpack_from('<Q', data, off)[0]

print("="*70)
print("  AMFID FULL REVERSE ENGINEERING")
print("  iOS 18.2 (22C152) — iPhone XR (A12)")
print("="*70)

with open(AMFID, 'rb') as f:
    data = f.read()
print(f"\namfid size: {len(data)} bytes ({len(data)/1024:.0f} KB)")

# Parse Mach-O header
magic = read_u32(data, 0)
assert magic == 0xFEEDFACF, f"Bukan Mach-O 64-bit: 0x{magic:x}"

cputype = read_u32(data, 4)
ncmds = read_u32(data, 16)
print(f"CPU: {'arm64e' if cputype == 0x0100000C else 'arm64'}")
print(f"Load commands: {ncmds}")

# Parse segments
segments = []
cmd_off = 32
text_exec_off = 0
text_exec_size = 0
text_exec_va = 0

for _ in range(ncmds):
    cmd = read_u32(data, cmd_off)
    cmdsize = read_u32(data, cmd_off + 4)
    if cmdsize == 0: break
    
    if cmd == 0x19:  # LC_SEGMENT_64
        segname = data[cmd_off+8:cmd_off+24].split(b'\x00')[0].decode()
        vmaddr = read_u64(data, cmd_off + 24)
        vmsize = read_u64(data, cmd_off + 32)
        fileoff = read_u64(data, cmd_off + 40)
        filesize = read_u64(data, cmd_off + 48)
        segments.append({'name': segname, 'vmaddr': vmaddr, 'vmsize': vmsize,
                        'fileoff': fileoff, 'filesize': filesize})
        print(f"  {segname:16s} vm=0x{vmaddr:x} size=0x{vmsize:x} fileoff=0x{fileoff:x}")
        
        if segname == '__TEXT':
            text_exec_off = fileoff
            text_exec_size = filesize
            text_exec_va = vmaddr
    
    cmd_off += cmdsize

# Cari strings yang relevan untuk security
print(f"\n{'='*70}")
print("FASE 1: STRINGS ANALYSIS")
print(f"{'='*70}")

security_strings = [
    b'verify', b'valid', b'sign', b'trust', b'hash', b'cdhash',
    b'CDHash', b'entitlement', b'amfi', b'AMFI', b'policy',
    b'allow', b'deny', b'reject', b'accept', b'bypass',
    b'debug', b'developer', b'platform', b'profile',
    b'provisioning', b'certificate', b'anchor', b'root',
    b'XPC', b'xpc', b'connection', b'message',
    b'MIS', b'libmis', b'CoreTrust',
    b'error', b'fail', b'success', b'invalid',
    b'cs_', b'proc_', b'task_',
]

found_strings = {}
for s in security_strings:
    idx = 0
    while True:
        idx = data.find(s, idx)
        if idx == -1: break
        # Cek apakah ini bagian dari string yang lebih panjang (null-terminated)
        start = idx
        while start > 0 and data[start-1] != 0:
            start -= 1
        end = idx
        while end < len(data) and data[end] != 0:
            end += 1
        full_str = data[start:end].decode('ascii', errors='ignore')
        if len(full_str) > 3 and len(full_str) < 200:
            if full_str not in found_strings:
                found_strings[full_str] = start
        idx += 1

# Sort dan tampilkan
print(f"\nDitemukan {len(found_strings)} string security-relevant:\n")
sorted_strings = sorted(found_strings.items(), key=lambda x: x[1])
for s, off in sorted_strings[:80]:
    # Hitung VA
    va = None
    for seg in segments:
        if seg['fileoff'] <= off < seg['fileoff'] + seg['filesize']:
            va = seg['vmaddr'] + (off - seg['fileoff'])
            break
    va_str = f"0x{va:x}" if va else "?"
    print(f"  {va_str:14s} \"{s}\"")

# Cari XPC handler patterns
print(f"\n{'='*70}")
print("FASE 2: XPC MESSAGE HANDLERS")
print(f"{'='*70}")
print("amfid menerima XPC messages dari kernel AMFI kext.")
print("Setiap message type punya handler berbeda.\n")

xpc_strings = [s for s, _ in sorted_strings if 'xpc' in s.lower() or 'XPC' in s 
               or 'message' in s.lower() or 'connection' in s.lower()
               or 'handler' in s.lower() or 'request' in s.lower()]
for s in xpc_strings[:20]:
    print(f"  \"{s}\"")

# Cari function signatures (PACIBSP prologue)
print(f"\n{'='*70}")
print("FASE 3: FUNCTION ANALYSIS")
print(f"{'='*70}")

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

# Cari semua function starts (PACIBSP = 0xD503237F atau STP X29,X30)
functions = []
for off in range(0, len(data) - 4, 4):
    instr = read_u32(data, off)
    if instr == 0xD503237F:  # PACIBSP
        va = None
        for seg in segments:
            if seg['fileoff'] <= off < seg['fileoff'] + seg['filesize']:
                va = seg['vmaddr'] + (off - seg['fileoff'])
                break
        if va:
            functions.append((va, off))

print(f"\nTotal functions (PACIBSP): {len(functions)}")

# Analisis setiap fungsi — cari yang berhubungan dengan validation
print(f"\n{'='*70}")
print("FASE 4: VALIDATION FUNCTIONS (BL + CBZ/CBNZ pattern)")
print(f"{'='*70}")
print("Cari fungsi yang: call validation → check result → branch\n")

validation_funcs = []

for func_va, func_off in functions:
    # Scan max 200 instruksi per fungsi
    has_validation_pattern = False
    bl_targets = set()
    cbnz_count = 0
    
    for i in range(0, min(800, len(data) - func_off), 4):
        instr = read_u32(data, func_off + i)
        
        # BL (call)
        if (instr >> 26) == 0x25:
            imm26 = instr & 0x3FFFFFF
            if imm26 & 0x2000000:
                imm26 = imm26 - 0x4000000
            target = func_va + i + (imm26 << 2)
            bl_targets.add(target)
        
        # CBNZ W0 (check return value)
        if (instr >> 24) == 0x35 and (instr & 0x1F) == 0:
            cbnz_count += 1
            # Cek apakah instruksi sebelumnya adalah BL
            if i >= 4:
                prev = read_u32(data, func_off + i - 4)
                if (prev >> 26) == 0x25:
                    has_validation_pattern = True
    
    if has_validation_pattern and cbnz_count >= 2:
        validation_funcs.append((func_va, func_off, cbnz_count, len(bl_targets)))

print(f"Fungsi dengan validation pattern (BL+CBNZ): {len(validation_funcs)}")
print(f"\nTop candidates (paling banyak CBNZ W0 = paling banyak check):")
validation_funcs.sort(key=lambda x: x[2], reverse=True)

for va, off, cbnz, bl_count in validation_funcs[:15]:
    print(f"  0x{va:x}: {cbnz} CBNZ W0, {bl_count} BL calls")

# Disassemble top validation function
if validation_funcs:
    print(f"\n{'='*70}")
    print(f"FASE 5: DISASSEMBLY FUNGSI VALIDASI UTAMA")
    print(f"{'='*70}")
    
    top_func = validation_funcs[0]
    func_va, func_off = top_func[0], top_func[1]
    print(f"\nFungsi di 0x{func_va:x} ({top_func[2]} CBNZ, {top_func[3]} BL):")
    print(f"Ini kemungkinan besar main signature validation handler.\n")
    
    code = data[func_off:func_off + 400]
    for insn in md.disasm(code, func_va):
        annotation = ""
        if insn.mnemonic in ('cbnz', 'cbz'):
            annotation = "  ; ← CHECK RESULT"
        elif insn.mnemonic == 'bl':
            annotation = "  ; ← CALL"
        elif insn.mnemonic in ('ret', 'retab'):
            print(f"  0x{insn.address:x}: {insn.mnemonic:8s} {insn.op_str}{annotation}")
            break
        print(f"  0x{insn.address:x}: {insn.mnemonic:8s} {insn.op_str}{annotation}")

# Cari "bypass" indicators
print(f"\n{'='*70}")
print("FASE 6: BYPASS INDICATORS")
print(f"{'='*70}")

bypass_indicators = [
    (b'get_task_allow', "CS_GET_TASK_ALLOW — debug entitlement"),
    (b'developer', "Developer mode check"),
    (b'platform-application', "Platform app entitlement"),
    (b'skip', "Skip validation?"),
    (b'allow', "Allow path"),
    (b'disable', "Disable check?"),
    (b'debug', "Debug mode"),
    (b'provisioning', "Provisioning profile"),
    (b'com.apple.private', "Private entitlement"),
    (b'com.apple.security', "Security entitlement"),
    (b'amfi.can', "AMFI capability entitlement"),
    (b'run-unsigned', "Run unsigned?"),
    (b'cs_enforcement', "CS enforcement flag"),
]

print("\nStrings yang menunjukkan possible bypass path:\n")
for pattern, desc in bypass_indicators:
    idx = data.find(pattern)
    if idx >= 0:
        # Get full string
        start = idx
        while start > 0 and data[start-1] != 0: start -= 1
        end = idx
        while end < len(data) and data[end] != 0: end += 1
        full = data[start:end].decode('ascii', errors='ignore')
        print(f"  ✓ [{desc}]")
        print(f"    \"{full}\"")

# Summary
print(f"\n{'='*70}")
print("RINGKASAN & CELAH POTENSIAL")
print(f"{'='*70}")
print(f"""
Binary: amfid ({len(data)} bytes, {'arm64e' if cputype == 0x0100000C else 'arm64'})
Functions: {len(functions)}
Validation functions: {len(validation_funcs)}
Security strings: {len(found_strings)}

CELAH YANG PERLU DI-INVESTIGATE:
1. XPC handler — apakah ada message type yang bypass validation?
2. Entitlement check — apakah ada entitlement yang skip AMFI?
3. Developer mode — apakah ada code path khusus dev mode?
4. Error handling — apakah error di validation = default allow?
5. Race condition — apakah ada TOCTOU di XPC handling?
""")
