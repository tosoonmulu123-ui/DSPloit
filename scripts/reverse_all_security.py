#!/usr/bin/env python3
"""
reverse_all_security.py — Reverse engineer SEMUA binary security-critical
Target: amfid, trustd, securityd
Cari: XPC handlers, entitlements, validation bypass, logic bugs
"""
import struct, os, sys
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

EXTRACT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                           "extracted", "usr", "libexec")

def read_u32(data, off):
    if off + 4 > len(data): return 0
    return struct.unpack_from('<I', data, off)[0]

def read_u64(data, off):
    if off + 8 > len(data): return 0
    return struct.unpack_from('<Q', data, off)[0]

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

def analyze_binary(path, name):
    """Full analysis satu binary."""
    with open(path, 'rb') as f:
        data = f.read()
    
    print(f"\n{'#'*70}")
    print(f"# {name.upper()} ({len(data)} bytes, {len(data)/1024:.0f} KB)")
    print(f"{'#'*70}")
    
    # Parse Mach-O
    magic = read_u32(data, 0)
    if magic != 0xFEEDFACF:
        print(f"  BUKAN Mach-O 64-bit!")
        return {}
    
    cputype = read_u32(data, 4)
    ncmds = read_u32(data, 16)
    
    # Parse segments
    segments = []
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
    
    # Extract ALL strings
    strings = {}
    i = 0
    while i < len(data):
        if data[i] >= 0x20 and data[i] < 0x7F:
            start = i
            while i < len(data) and data[i] >= 0x20 and data[i] < 0x7F:
                i += 1
            if i - start >= 4:  # min 4 chars
                s = data[start:i].decode('ascii', errors='ignore')
                strings[start] = s
        i += 1
    
    # Security-relevant string categories
    categories = {
        'entitlements': [],
        'xpc_services': [],
        'validation': [],
        'trust': [],
        'bypass_hints': [],
        'crypto': [],
        'error_handling': [],
        'file_paths': [],
    }
    
    for off, s in strings.items():
        sl = s.lower()
        if 'com.apple.' in s and ('amfi' in sl or 'trust' in sl or 'security' in sl or 'private' in sl):
            categories['entitlements'].append(s)
        elif 'xpc' in sl or 'mach_service' in sl or 'connection' in sl:
            categories['xpc_services'].append(s)
        elif 'valid' in sl or 'verify' in sl or 'check' in sl or 'sign' in sl:
            categories['validation'].append(s)
        elif 'trust' in sl or 'anchor' in sl or 'certificate' in sl or 'cert' in sl:
            categories['trust'].append(s)
        elif 'skip' in sl or 'bypass' in sl or 'disable' in sl or 'allow' in sl or 'override' in sl:
            categories['bypass_hints'].append(s)
        elif 'hash' in sl or 'sha' in sl or 'cdhash' in sl or 'digest' in sl:
            categories['crypto'].append(s)
        elif 'error' in sl or 'fail' in sl or 'invalid' in sl:
            categories['error_handling'].append(s)
        elif s.startswith('/') and len(s) > 5:
            categories['file_paths'].append(s)
    
    # Print categories
    for cat, items in categories.items():
        unique = sorted(set(items))
        if unique:
            print(f"\n  === {cat.upper()} ({len(unique)}) ===")
            for item in unique[:25]:
                print(f"    {item}")
            if len(unique) > 25:
                print(f"    ... ({len(unique)-25} more)")
    
    # Count functions
    func_count = 0
    for off in range(0, len(data) - 4, 4):
        if read_u32(data, off) == 0xD503237F:  # PACIBSP
            func_count += 1
    
    # Find validation patterns
    validation_funcs = []
    for off in range(0, len(data) - 4, 4):
        if read_u32(data, off) != 0xD503237F:
            continue
        
        cbnz_count = 0
        bl_count = 0
        for i in range(4, min(800, len(data) - off), 4):
            instr = read_u32(data, off + i)
            if (instr >> 26) == 0x25: bl_count += 1
            if (instr >> 24) == 0x35 and (instr & 0x1F) == 0: cbnz_count += 1
            if instr == 0xD65F0FFF or instr == 0xD65F03C0: break  # RETAB/RET
        
        if cbnz_count >= 3 and bl_count >= 5:
            va = None
            for seg in segments:
                if seg['fileoff'] <= off < seg['fileoff'] + seg['filesize']:
                    va = seg['vmaddr'] + (off - seg['fileoff'])
                    break
            if va:
                validation_funcs.append((va, off, cbnz_count, bl_count))
    
    print(f"\n  === STATISTICS ===")
    print(f"    Functions: {func_count}")
    print(f"    Validation functions (3+ CBNZ): {len(validation_funcs)}")
    print(f"    Total strings: {len(strings)}")
    
    # Top validation functions
    if validation_funcs:
        validation_funcs.sort(key=lambda x: x[2], reverse=True)
        print(f"\n  === TOP VALIDATION FUNCTIONS ===")
        for va, off, cbnz, bl in validation_funcs[:10]:
            print(f"    0x{va:x}: {cbnz} checks, {bl} calls")
    
    return {
        'name': name,
        'size': len(data),
        'functions': func_count,
        'validation_funcs': len(validation_funcs),
        'entitlements': categories['entitlements'],
        'bypass_hints': categories['bypass_hints'],
        'xpc_services': categories['xpc_services'],
        'trust': categories['trust'],
        'data': data,
        'segments': segments,
    }

# ============================================================
# ANALYZE ALL BINARIES
# ============================================================
print("="*70)
print("  FULL SECURITY BINARY REVERSE ENGINEERING")
print("  iOS 18.2 (22C152) — iPhone XR (A12)")
print("="*70)

results = {}
for binary in ['amfid', 'trustd', 'securityd']:
    path = os.path.join(EXTRACT_DIR, binary)
    if os.path.exists(path):
        results[binary] = analyze_binary(path, binary)
    else:
        print(f"\n  [SKIP] {binary} tidak ditemukan")

# ============================================================
# CROSS-REFERENCE ANALYSIS
# ============================================================
print(f"\n\n{'='*70}")
print("CROSS-REFERENCE: CELAH POTENSIAL")
print(f"{'='*70}")

# Collect all entitlements
all_entitlements = set()
for name, r in results.items():
    for e in r.get('entitlements', []):
        all_entitlements.add((e, name))

print(f"\n=== SEMUA ENTITLEMENTS SECURITY ({len(all_entitlements)}) ===")
for ent, binary in sorted(all_entitlements):
    marker = " ⚠️ CRITICAL" if any(x in ent for x in ['set-trust', 'execute', 'unsigned', 'disable', 'override']) else ""
    print(f"  [{binary}] {ent}{marker}")

# Bypass hints
print(f"\n=== BYPASS HINTS ===")
for name, r in results.items():
    for hint in r.get('bypass_hints', []):
        print(f"  [{name}] {hint}")

# XPC services
print(f"\n=== XPC SERVICES ===")
for name, r in results.items():
    for svc in r.get('xpc_services', [])[:10]:
        print(f"  [{name}] {svc}")

# Trust-related
print(f"\n=== TRUST OPERATIONS ===")
for name, r in results.items():
    for t in r.get('trust', [])[:15]:
        print(f"  [{name}] {t}")

# ============================================================
# FINAL ASSESSMENT
# ============================================================
print(f"\n\n{'='*70}")
print("FINAL ASSESSMENT — EXPLOITABLE VECTORS")
print(f"{'='*70}")
print("""
Berdasarkan reverse engineering amfid + trustd + securityd:

1. ENTITLEMENT "com.apple.private.amfi.set-trust"
   - Ditemukan di amfid strings
   - Proses dengan entitlement ini bisa SET trust
   - TAPI: hanya Apple-signed processes yang punya entitlement ini
   - KECUALI: kalau kita bisa forge entitlement via KRW...

2. XPC ACTION "__xpcActionDisable"
   - amfid punya handler untuk "disable" action
   - Kalau kita bisa kirim XPC message ini dari launchd...
   - TAPI: kernel SIGKILL terjadi SEBELUM amfid dipanggil

3. DEVELOPER MODE
   - amfid punya code path khusus developer mode
   - "enabling developer mode daemons"
   - "skipping AMFI migration"
   - Device kita sudah developer mode enabled!
   - TAPI: developer mode di iOS 18 tidak bypass code signing

4. LOCAL SIGNING
   - "successfully stored local signing public key"
   - "creating auxiliary signature"
   - amfid bisa CREATE signatures!
   - Kalau kita bisa trigger local signing path...

5. AUXILIARY SIGNATURES
   - "misMigrate | created auxiliary signature"
   - "upgrading auxiliary signature"
   - Ada mekanisme untuk ADD signatures tanpa Apple cert!
   - Ini mungkin untuk enterprise/MDM profiles

REKOMENDASI EXPERIMENT BARU:
- Exp 100: Kirim XPC "__xpcActionDisable" ke amfid dari launchd
- Exp 101: Trigger "local signing" path via XPC
- Exp 102: Exploit "auxiliary signature" mechanism
- Exp 103: Forge entitlement via proc_ro KRW (kalau bisa write)
""")
