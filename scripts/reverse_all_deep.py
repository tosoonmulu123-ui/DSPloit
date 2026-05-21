#!/usr/bin/env python3
"""
reverse_all_deep.py — Reverse engineer SEMUA extracted binaries
Fokus: cari celah di launchd, dyld, xpcproxy yang bisa bypass code signing
Karena kernel enforce CS SEBELUM amfid, kita perlu cari celah di:
1. dyld — dynamic linker yang load binary
2. launchd — yang spawn processes
3. xpcproxy — yang setup process environment
"""
import struct, os, sys
from collections import defaultdict

EXTRACT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "extracted")

def read_u32(data, off):
    if off + 4 > len(data): return 0
    return struct.unpack_from('<I', data, off)[0]

def read_u64(data, off):
    if off + 8 > len(data): return 0
    return struct.unpack_from('<Q', data, off)[0]

def extract_strings(data, min_len=5, max_len=200):
    """Extract semua printable strings dari binary."""
    strings = {}
    i = 0
    while i < len(data):
        if 0x20 <= data[i] < 0x7F:
            start = i
            while i < len(data) and 0x20 <= data[i] < 0x7F:
                i += 1
            if min_len <= (i - start) <= max_len:
                s = data[start:i].decode('ascii', errors='ignore')
                strings[start] = s
        i += 1
    return strings

def find_security_strings(strings):
    """Kategorikan strings berdasarkan relevansi security."""
    categories = defaultdict(list)
    
    keywords = {
        'code_signing': ['codesign', 'cdhash', 'CDHash', 'cs_', 'signature', 'signed', 'unsigned'],
        'trust': ['trust', 'Trust', 'anchor', 'certificate', 'cert_'],
        'entitlement': ['entitlement', 'com.apple.private', 'com.apple.security'],
        'bypass': ['skip', 'bypass', 'override', 'disable', 'allow', 'exempt', 'whitelist'],
        'amfi': ['amfi', 'AMFI', 'AppleMobileFileIntegrity'],
        'spawn': ['spawn', 'exec', 'fork', 'posix_spawn', 'launch'],
        'dyld': ['dyld', 'DYLD', 'dylib', 'image', 'loader'],
        'sandbox': ['sandbox', 'Sandbox', 'container', 'profile'],
        'xpc': ['xpc', 'XPC', 'mach_service', 'bootstrap'],
        'developer': ['developer', 'debug', 'internal', 'development'],
        'error': ['error', 'fail', 'invalid', 'denied', 'reject'],
    }
    
    for off, s in strings.items():
        for cat, kws in keywords.items():
            if any(kw in s for kw in kws):
                categories[cat].append(s)
                break
    
    return categories

def analyze_binary_deep(filepath, name):
    """Deep analysis van een binary."""
    if not os.path.exists(filepath):
        return None
    
    with open(filepath, 'rb') as f:
        data = f.read()
    
    if read_u32(data, 0) != 0xFEEDFACF:
        return None
    
    strings = extract_strings(data)
    categories = find_security_strings(strings)
    
    # Count functions
    func_count = sum(1 for off in range(0, len(data)-4, 4) if read_u32(data, off) == 0xD503237F)
    
    return {
        'name': name,
        'size': len(data),
        'functions': func_count,
        'strings': len(strings),
        'categories': categories,
    }

# ============================================================
# MAIN
# ============================================================
print("="*70)
print("  COMPREHENSIVE REVERSE ENGINEERING — ALL BINARIES")
print("  iOS 18.2 (22C152) iPhone XR")
print("="*70)

# Find all binaries
binaries = []
for root, dirs, files in os.walk(EXTRACT_DIR):
    for f in files:
        path = os.path.join(root, f)
        rel = os.path.relpath(path, EXTRACT_DIR)
        binaries.append((path, rel))

print(f"\nBinaries: {len(binaries)}")

results = {}
for path, name in sorted(binaries):
    r = analyze_binary_deep(path, name)
    if r:
        results[name] = r
        print(f"  {name}: {r['size']//1024}KB, {r['functions']} funcs, {r['strings']} strings")

# ============================================================
# CROSS-BINARY ANALYSIS
# ============================================================
print(f"\n\n{'='*70}")
print("CROSS-BINARY SECURITY ANALYSIS")
print(f"{'='*70}")

# 1. Code signing related strings per binary
print(f"\n--- CODE SIGNING strings ---")
for name, r in sorted(results.items()):
    cs = r['categories'].get('code_signing', [])
    if cs:
        unique = sorted(set(cs))[:10]
        print(f"\n  [{name}] ({len(cs)} strings)")
        for s in unique:
            print(f"    {s}")

# 2. Bypass/override hints
print(f"\n\n--- BYPASS/OVERRIDE hints ---")
for name, r in sorted(results.items()):
    bp = r['categories'].get('bypass', [])
    if bp:
        unique = sorted(set(bp))[:15]
        print(f"\n  [{name}] ({len(bp)} strings)")
        for s in unique:
            print(f"    {s}")

# 3. Spawn/exec related (how processes are launched)
print(f"\n\n--- SPAWN/EXEC strings ---")
for name, r in sorted(results.items()):
    sp = r['categories'].get('spawn', [])
    if sp:
        unique = sorted(set(sp))[:10]
        print(f"\n  [{name}] ({len(sp)} strings)")
        for s in unique:
            print(f"    {s}")

# 4. DYLD related (dynamic linker — loads code)
print(f"\n\n--- DYLD strings ---")
for name, r in sorted(results.items()):
    dy = r['categories'].get('dyld', [])
    if dy:
        unique = sorted(set(dy))[:15]
        print(f"\n  [{name}] ({len(dy)} strings)")
        for s in unique:
            print(f"    {s}")

# 5. Developer/debug mode
print(f"\n\n--- DEVELOPER/DEBUG strings ---")
for name, r in sorted(results.items()):
    dev = r['categories'].get('developer', [])
    if dev:
        unique = sorted(set(dev))[:10]
        print(f"\n  [{name}] ({len(dev)} strings)")
        for s in unique:
            print(f"    {s}")

# 6. AMFI related
print(f"\n\n--- AMFI strings ---")
for name, r in sorted(results.items()):
    amfi = r['categories'].get('amfi', [])
    if amfi:
        unique = sorted(set(amfi))[:10]
        print(f"\n  [{name}] ({len(amfi)} strings)")
        for s in unique:
            print(f"    {s}")

# ============================================================
# KEY FINDINGS
# ============================================================
print(f"\n\n{'='*70}")
print("KEY FINDINGS & EXPLOITATION VECTORS")
print(f"{'='*70}")
print("""
ANALISIS BERDASARKAN BINARY:

1. LAUNCHD (sbin/launchd):
   - Ini yang spawn semua processes
   - Kalau ada bypass di launchd spawn path → bisa skip CS check
   - Cari: "spawn" flags, "exempt" conditions, "allow" paths

2. DYLD (usr/lib/dyld):
   - Dynamic linker — load binary ke memory
   - Kalau ada bypass di dyld loading → bisa load unsigned code
   - Cari: "DYLD_" env vars yang tidak di-strip, "amfi" checks

3. XPCPROXY (usr/libexec/xpcproxy):
   - Setup process environment sebelum exec
   - Kalau ada bypass di xpcproxy → bisa modify exec context
   - Cari: entitlement injection, sandbox bypass

4. KEYBAGD (usr/libexec/keybagd):
   - Manage encryption keys
   - Mungkin punya akses ke signing keys

5. MOBILEASSETD:
   - Download dan install assets (termasuk trust cache updates!)
   - Kalau bisa trigger trust cache update → add our CDHash

CRITICAL QUESTION:
- Apakah ada binary yang punya entitlement "com.apple.private.amfi.set-trust"?
- Apakah ada binary yang bisa trigger trust cache reload?
- Apakah ada bypass condition di dyld/launchd untuk CS check?
""")
