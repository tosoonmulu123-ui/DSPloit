#!/usr/bin/env python3
"""
mass_vuln_scan.py — Scan SEMUA extracted binary untuk celah critical
Fokus: trust cache manipulation, code signing bypass, spawn override
"""
import struct, os, sys
from collections import defaultdict

EXTRACT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "extracted")

# Keyword yang menunjukkan celah potensial
CRITICAL_PATTERNS = [
    # Trust cache manipulation
    (b'trust_cache', 'TRUST_CACHE'),
    (b'trustcache', 'TRUST_CACHE'),
    (b'TrustCache', 'TRUST_CACHE'),
    (b'load_trust', 'TRUST_CACHE_LOAD'),
    (b'add_trust', 'TRUST_CACHE_ADD'),
    (b'runtime_add', 'TRUST_CACHE_ADD'),
    
    # Code signing bypass
    (b'cs_enforcement', 'CS_ENFORCEMENT'),
    (b'amfi_get_out_of_my_way', 'AMFI_BYPASS'),
    (b'PE_i_can_has_debugger', 'DEBUGGER_CHECK'),
    (b'cs_debug', 'CS_DEBUG'),
    (b'CS_DEBUGGED', 'CS_DEBUGGED'),
    (b'CS_GET_TASK_ALLOW', 'CS_TASK_ALLOW'),
    (b'get-task-allow', 'CS_TASK_ALLOW'),
    
    # Provisioning/signing
    (b'provisioning', 'PROVISIONING'),
    (b'Provisioning', 'PROVISIONING'),
    (b'enterprise', 'ENTERPRISE'),
    (b'Enterprise', 'ENTERPRISE'),
    (b'MDM', 'MDM'),
    (b'managed', 'MDM'),
    
    # Cryptex (runtime trust cache loading)
    (b'cryptex', 'CRYPTEX'),
    (b'Cryptex', 'CRYPTEX'),
    (b'personalize', 'PERSONALIZE'),
    (b'Personalize', 'PERSONALIZE'),
    
    # Developer disk image (adds trust cache at runtime!)
    (b'DeveloperDiskImage', 'DDI'),
    (b'developer_disk', 'DDI'),
    (b'DiskImage', 'DDI'),
    (b'disk_image', 'DDI'),
    (b'PersonalizedBundle', 'DDI'),
    
    # MobileStorageMounter (mounts DDI!)
    (b'MobileStorage', 'STORAGE_MOUNT'),
    (b'mount_image', 'STORAGE_MOUNT'),
    (b'image_mount', 'STORAGE_MOUNT'),
    
    # Override/bypass mechanisms
    (b'override', 'OVERRIDE'),
    (b'Override', 'OVERRIDE'),
    (b'whitelist', 'WHITELIST'),
    (b'allowlist', 'WHITELIST'),
    (b'exempt', 'EXEMPT'),
    
    # Entitlements that grant special access
    (b'com.apple.private.amfi', 'AMFI_ENTITLEMENT'),
    (b'com.apple.private.security', 'SECURITY_ENTITLEMENT'),
    (b'com.apple.private.kernel', 'KERNEL_ENTITLEMENT'),
    (b'com.apple.rootless', 'ROOTLESS'),
    (b'platform-application', 'PLATFORM_APP'),
    
    # Image4/personalization (firmware validation)
    (b'image4', 'IMAGE4'),
    (b'Image4', 'IMAGE4'),
    (b'IMG4', 'IMAGE4'),
    (b'ApTicket', 'APTICKET'),
    (b'SHSH', 'SHSH'),
    
    # Kernel function calls
    (b'IOKit', 'IOKIT'),
    (b'IOConnect', 'IOKIT'),
    (b'externalMethod', 'IOKIT'),
    
    # File paths that might be writable
    (b'/var/MobileDevice', 'WRITABLE_PATH'),
    (b'/var/db/', 'WRITABLE_PATH'),
    (b'/var/containers', 'WRITABLE_PATH'),
    (b'/private/var', 'WRITABLE_PATH'),
]

def scan_binary(filepath):
    """Scan binary voor critical patterns."""
    with open(filepath, 'rb') as f:
        data = f.read()
    
    findings = defaultdict(list)
    
    for pattern, category in CRITICAL_PATTERNS:
        idx = 0
        while True:
            idx = data.find(pattern, idx)
            if idx == -1:
                break
            # Get context (full string around match)
            start = idx
            while start > 0 and data[start-1] >= 0x20 and data[start-1] < 0x7F:
                start -= 1
            end = idx + len(pattern)
            while end < len(data) and data[end] >= 0x20 and data[end] < 0x7F:
                end += 1
            context = data[start:end].decode('ascii', errors='ignore')
            if len(context) > 3:
                findings[category].append(context)
            idx += 1
    
    return findings

# ============================================================
# SCAN ALL BINARIES
# ============================================================
print("="*70)
print("  MASS VULNERABILITY SCAN — ALL EXTRACTED BINARIES")
print("  iOS 18.2 (22C152) iPhone XR (A12)")
print("="*70)

all_findings = {}
binary_count = 0

for root, dirs, files in os.walk(EXTRACT_DIR):
    for f in files:
        path = os.path.join(root, f)
        rel = os.path.relpath(path, EXTRACT_DIR)
        
        # Skip non-binary
        try:
            with open(path, 'rb') as fh:
                magic = fh.read(4)
            if magic != b'\xcf\xfa\xed\xfe':  # MH_MAGIC_64 LE
                continue
        except:
            continue
        
        binary_count += 1
        findings = scan_binary(path)
        if findings:
            all_findings[rel] = findings

print(f"\nBinaries scanned: {binary_count}")
print(f"Binaries with findings: {len(all_findings)}")

# ============================================================
# RESULTS BY CATEGORY (most critical first)
# ============================================================
priority_order = [
    'TRUST_CACHE', 'TRUST_CACHE_LOAD', 'TRUST_CACHE_ADD',
    'CRYPTEX', 'DDI', 'STORAGE_MOUNT',
    'AMFI_BYPASS', 'CS_ENFORCEMENT', 'CS_DEBUGGED', 'CS_TASK_ALLOW',
    'AMFI_ENTITLEMENT', 'SECURITY_ENTITLEMENT', 'KERNEL_ENTITLEMENT',
    'OVERRIDE', 'WHITELIST', 'EXEMPT',
    'PROVISIONING', 'ENTERPRISE', 'MDM',
    'PERSONALIZE', 'IMAGE4', 'APTICKET',
    'PLATFORM_APP', 'ROOTLESS',
    'IOKIT', 'WRITABLE_PATH',
    'DEBUGGER_CHECK', 'CS_DEBUG',
]

for category in priority_order:
    binaries_with_cat = [(name, findings[category]) 
                         for name, findings in all_findings.items() 
                         if category in findings]
    
    if not binaries_with_cat:
        continue
    
    print(f"\n{'='*60}")
    print(f"  [{category}] — {len(binaries_with_cat)} binary(s)")
    print(f"{'='*60}")
    
    for binary_name, strings in sorted(binaries_with_cat):
        unique = sorted(set(strings))
        print(f"\n  {binary_name}:")
        for s in unique[:8]:
            if len(s) > 100:
                s = s[:100] + "..."
            print(f"    {s}")
        if len(unique) > 8:
            print(f"    ... ({len(unique)-8} more)")

# ============================================================
# CRITICAL SUMMARY
# ============================================================
print(f"\n\n{'='*70}")
print("CRITICAL SUMMARY — EXPLOITABLE VECTORS")
print(f"{'='*70}")

# Count per category
cat_counts = defaultdict(int)
for name, findings in all_findings.items():
    for cat in findings:
        cat_counts[cat] += 1

print(f"\nCategory hits:")
for cat in priority_order:
    if cat_counts[cat] > 0:
        marker = " <<<" if cat in ('TRUST_CACHE_ADD', 'TRUST_CACHE_LOAD', 'DDI', 'CRYPTEX', 'AMFI_BYPASS') else ""
        print(f"  {cat:25s}: {cat_counts[cat]} binaries{marker}")

print(f"""

TOP EXPLOITATION TARGETS:

1. CRYPTEX/DDI binaries — these ADD trust caches at runtime!
   Kalau kita bisa trigger path ini → inject CDHash → jailbreak

2. MobileStorageMounter — mounts Developer Disk Images
   DDI mount = trust cache added. Fake DDI = fake trust cache?

3. TRUST_CACHE_LOAD/ADD — binaries yang load trust cache
   Trace exact function → find callable path

4. PROVISIONING/ENTERPRISE — managed profiles add trust
   Enterprise provisioning bisa add trusted identities

5. OVERRIDE/WHITELIST — bypass mechanisms
   Ada override path di beberapa binary
""")
