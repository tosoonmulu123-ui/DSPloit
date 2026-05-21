#!/usr/bin/env python3
"""
deep_cryptexd_mobileassetd.py — Deep reverse engineering cryptexd & mobileassetd
Fokus: trace path ke amfi_load_trust_cache
Cari: XPC interface, parameter format, trigger conditions
"""
import struct, os
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

EXTRACT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "extracted")

def read_u32(data, off):
    if off + 4 > len(data): return 0
    return struct.unpack_from('<I', data, off)[0]

def read_u64(data, off):
    if off + 8 > len(data): return 0
    return struct.unpack_from('<Q', data, off)[0]

def extract_all_strings(data, min_len=4):
    strings = {}
    i = 0
    while i < len(data):
        if 0x20 <= data[i] < 0x7F:
            start = i
            while i < len(data) and 0x20 <= data[i] < 0x7F:
                i += 1
            if i - start >= min_len:
                strings[start] = data[start:i].decode('ascii', errors='ignore')
        i += 1
    return strings

def find_string_offset(data, s):
    encoded = s.encode() if isinstance(s, str) else s
    return data.find(encoded)

def parse_segments(data):
    segments = []
    if read_u32(data, 0) != 0xFEEDFACF:
        return segments
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
    return segments

def off_to_va(segments, off):
    for seg in segments:
        if seg['fileoff'] <= off < seg['fileoff'] + seg['filesize']:
            return seg['vmaddr'] + (off - seg['fileoff'])
    return None

def va_to_off(segments, va):
    for seg in segments:
        if seg['vmaddr'] <= va < seg['vmaddr'] + seg['vmsize']:
            return seg['fileoff'] + (va - seg['vmaddr'])
    return None

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

def disasm_from(data, segments, va, max_instrs=80):
    off = va_to_off(segments, va)
    if not off: return []
    code = data[off:off + max_instrs * 4]
    result = []
    for insn in md.disasm(code, va):
        result.append((insn.address, insn.mnemonic, insn.op_str))
        if insn.mnemonic in ('ret', 'retab'):
            break
        if len(result) >= max_instrs:
            break
    return result

def find_func_start(data, segments, va):
    off = va_to_off(segments, va)
    if not off: return va
    for back in range(0, 0x400, 4):
        check = off - back
        if check < 0: break
        instr = read_u32(data, check)
        if instr == 0xD503237F:
            return off_to_va(segments, check)
    return va

def analyze_binary(path, name, focus_strings):
    """Analisis binary dengan fokus ke strings tertentu."""
    with open(path, 'rb') as f:
        data = f.read()
    
    segments = parse_segments(data)
    if not segments:
        return
    
    print(f"\n{'#'*70}")
    print(f"# {name} ({len(data)//1024} KB)")
    print(f"{'#'*70}")
    
    # Cari semua focus strings dan trace xrefs
    for focus in focus_strings:
        idx = find_string_offset(data, focus)
        if idx < 0:
            continue
        
        str_va = off_to_va(segments, idx)
        if not str_va:
            continue
        
        print(f"\n  === \"{focus}\" (VA 0x{str_va:x}) ===")
        
        # Cari ADRP+ADD xrefs ke string ini
        str_page = str_va & ~0xFFF
        str_pageoff = str_va & 0xFFF
        xrefs = []
        
        for seg in segments:
            if seg['filesize'] == 0: continue
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
                
                pc_va = off_to_va(segments, off)
                if not pc_va: continue
                pc_page = pc_va & ~0xFFF
                target_page = pc_page + (imm << 12)
                
                if target_page == str_page and off + 4 < end:
                    next_instr = read_u32(data, off + 4)
                    if (next_instr & 0xFFC00000) == 0x91000000:
                        add_imm = (next_instr >> 10) & 0xFFF
                        if add_imm == str_pageoff:
                            xrefs.append(pc_va)
        
        print(f"    Xrefs: {len(xrefs)}")
        
        for xref in xrefs[:3]:
            func_start = find_func_start(data, segments, xref)
            print(f"\n    Function 0x{func_start:x} (xref at 0x{xref:x}):")
            instrs = disasm_from(data, segments, func_start, 60)
            for addr, mn, op in instrs[:50]:
                annotation = ""
                if mn == 'bl': annotation = " ; CALL"
                elif mn in ('cbz', 'cbnz', 'tbz', 'tbnz'): annotation = " ; CHECK"
                elif 'adrp' in mn and '0x100' in op: annotation = " ; DATA/STRING ref"
                print(f"      0x{addr:x}: {mn:8s} {op}{annotation}")
    
    # Juga cari XPC service names
    print(f"\n  === XPC/MACH SERVICES ===")
    all_strings = extract_all_strings(data)
    for off, s in sorted(all_strings.items()):
        if 'com.apple.' in s and ('cryptex' in s.lower() or 'amfi' in s.lower() 
            or 'trust' in s.lower() or 'mobile' in s.lower() or 'asset' in s.lower()
            or 'storage' in s.lower() or 'install' in s.lower()):
            print(f"    {s}")
    
    # Cari entitlements
    print(f"\n  === ENTITLEMENTS (security-relevant) ===")
    for off, s in sorted(all_strings.items()):
        if 'com.apple.private' in s and len(s) < 80:
            if any(x in s.lower() for x in ['amfi', 'trust', 'cryptex', 'security', 'kernel', 'rootless', 'install']):
                print(f"    {s}")

# ============================================================
# ANALYZE CRYPTEXD
# ============================================================
cryptexd_path = os.path.join(EXTRACT_DIR, "usr", "libexec", "cryptexd")
if os.path.exists(cryptexd_path):
    analyze_binary(cryptexd_path, "CRYPTEXD", [
        "amfi_load_trust_cache",
        "trustcache file transfer",
        "bootstrap_load_trust_cache",
        "Cryptex already mounted",
        "Cryptex1 format is required",
        "com.apple.cryptexd",
        "personalize",
    ])

# ============================================================
# ANALYZE MOBILEASSETD
# ============================================================
mobileassetd_path = os.path.join(EXTRACT_DIR, "usr", "libexec", "mobileassetd")
if os.path.exists(mobileassetd_path):
    analyze_binary(mobileassetd_path, "MOBILEASSETD", [
        "amfi_load_trust_cache",
        "loadTrustCache",
        "MobileAssetTrustCache",
        "MobileAssetBrain",
        "cryptex1ticket",
    ])

# ============================================================
# ANALYZE MobileStorageMounter
# ============================================================
msm_path = os.path.join(EXTRACT_DIR, "usr", "libexec", "MobileStorageMounter")
if os.path.exists(msm_path):
    analyze_binary(msm_path, "MobileStorageMounter", [
        "TrustCache",
        "DeveloperDiskImage",
        "mount",
        "ImageTrustCache",
        "PersonalizedBundle",
        "com.apple.mobile.storage_mounter",
    ])

# ============================================================
# SUMMARY
# ============================================================
print(f"\n\n{'='*70}")
print("EXPLOITATION PATH SUMMARY")
print(f"{'='*70}")
print("""
TRUST CACHE LOADING CHAIN:

1. cryptexd:
   - Daemon yang manage cryptex (system extensions)
   - Panggil amfi_load_trust_cache() untuk load TC dari cryptex
   - XPC service: com.apple.security.cryptexd
   - Entitlement: com.apple.private.security.cryptex.install

2. mobileassetd:
   - Daemon yang download/install MobileAssets
   - Panggil amfi_load_trust_cache() untuk load TC dari asset
   - Bisa trigger via MobileAsset framework
   - Entitlement: com.apple.private.img4.nonce.cryptex1.asset

3. MobileStorageMounter:
   - Mount Developer Disk Images
   - DDI mount = trust cache loaded
   - XPC via lockdownd (USB connection)
   - Entitlement: com.apple.private.security.cryptex.install

ATTACK VECTORS:

A. Trigger cryptexd trust cache load:
   - Kirim XPC ke com.apple.security.cryptexd dari launchd
   - Provide fake trust cache data
   - Butuh: correct XPC message format + entitlement check bypass

B. Trigger mobileassetd trust cache load:
   - Kirim XPC ke mobileassetd dari launchd
   - Trigger loadTrustCache:bundle:bundleName:needsUnlock:
   - Provide path ke fake trust cache file di /var/tmp

C. Fake DDI mount via MobileStorageMounter:
   - Craft fake DDI image dengan trust cache kita
   - Trigger mount via lockdownd XPC
   - Trust cache dari DDI akan di-load ke kernel

D. Direct amfi_load_trust_cache call:
   - Ini kernel function (bukan userspace)
   - Dipanggil oleh cryptexd/mobileassetd setelah validation
   - Validation: Image4 personalization check
   - TAPI: kalau kita bisa bypass personalization check...

CRITICAL BLOCKER:
- amfi_load_trust_cache() butuh Image4 personalized trust cache
- Personalization = signed by Apple's TSS server
- Tanpa valid personalization ticket, kernel reject trust cache
- Ini sama seperti SHSH blobs untuk firmware restore

TAPI:
- Apakah ada "unpersonalized" path? (untuk development/testing)
- Apakah ada bypass di Image4 validation?
- Apakah mobileassetd punya path yang skip personalization?
""")
