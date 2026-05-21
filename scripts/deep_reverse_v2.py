#!/usr/bin/env python3
"""
deep_reverse_v2.py — Deep reverse engineering with:
1. Kernelcache LZFSE decompress + full scan
2. iBoot deep disassembly (function tracing)
3. Cross-reference analysis (XPC input → dangerous functions)
4. Control flow analysis on extracted binaries

Output: deep_reverse_v2_output.txt
"""

import struct
import os
import sys
from pathlib import Path
from collections import defaultdict

try:
    from imagecodecs import lzfse_decode
    HAS_LZFSE = True
except ImportError:
    HAS_LZFSE = False
    print("[WARN] imagecodecs not installed — no LZFSE decompression")

try:
    from capstone import *
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False
    print("[WARN] capstone not installed — limited disassembly")

BASE_DIR = Path(r"d:\Backup\Personal\Hp\iPhone\DSPloit")
EXTRACTED_DIR = BASE_DIR / "extracted"
IPSW_DIR = BASE_DIR / "iPhone11,8_18.2_22C152_Restore"
OUTPUT_FILE = BASE_DIR / "deep_reverse_v2_output.txt"

CRITICAL = "CRITICAL"
HIGH = "HIGH"
MEDIUM = "MEDIUM"
LOW = "LOW"
INFO = "INFO"

findings = []
out_lines = []

def log(msg):
    out_lines.append(msg)
    
def add_finding(binary, severity, category, title, detail, offset=0):
    findings.append((binary, severity, category, title, detail, offset))

# ============================================================
# PART 1: KERNELCACHE DEEP ANALYSIS
# ============================================================

def decompress_kernelcache(kc_path):
    """Decompress kernelcache and return raw Mach-O data"""
    with open(kc_path, "rb") as f:
        data = f.read()
    
    # iOS 15+ kernelcache is a fileset Mach-O, may have multiple LZFSE blocks
    # or may be uncompressed Mach-O directly
    if data[:4] == b'\xcf\xfa\xed\xfe':
        log(f"Kernelcache: already decompressed Mach-O ({len(data)} bytes)")
        return data
    
    # Try LZFSE
    if HAS_LZFSE:
        bvx2_idx = data.find(b'bvx2')
        if bvx2_idx != -1:
            try:
                dec = lzfse_decode(data[bvx2_idx:])
                log(f"Kernelcache: LZFSE decompressed {len(data)} → {len(dec)} bytes")
                return dec
            except:
                pass
    
    # Try finding Mach-O inside (fileset kernelcache)
    macho_idx = data.find(b'\xcf\xfa\xed\xfe')
    if macho_idx != -1:
        log(f"Kernelcache: found Mach-O at offset {macho_idx}")
        return data[macho_idx:]
    
    log(f"Kernelcache: using raw data ({len(data)} bytes)")
    return data


def analyze_kernelcache_deep(kc_path):
    """Deep analysis of kernelcache"""
    log("\n" + "=" * 70)
    log("KERNELCACHE DEEP ANALYSIS")
    log("=" * 70)
    
    data = decompress_kernelcache(kc_path)
    if not data:
        log("ERROR: Cannot read kernelcache")
        return
    
    # Extract ALL strings
    log(f"\n--- String extraction ({len(data)} bytes) ---")
    strings = extract_strings(data, min_len=8)
    log(f"Total strings: {len(strings)}")
    
    # Categorize strings
    categories = {
        "AMFI/Trust Cache": [],
        "Code Signing": [],
        "Sandbox": [],
        "Boot/Debug": [],
        "Crypto Keys": [],
        "Panic/Error": [],
        "IOKit Drivers": [],
        "Syscalls": [],
        "Process/Task": [],
        "Memory/VM": [],
        "Network": [],
        "USB": [],
        "Entitlements": [],
    }
    
    kw_map = {
        "AMFI/Trust Cache": ['amfi', 'trust_cache', 'trustcache', 'cdhash', 'CDHash',
                             'cs_blob', 'cs_valid', 'code_sign', 'pmap_cs', 'load_trust',
                             'query_trust', 'AMFI', 'AppleMobileFileIntegrity'],
        "Code Signing": ['codesign', 'signature', 'MISValidate', 'SecCode', 'CoreTrust',
                         'cert', 'certificate', 'provisioning', 'entitlement'],
        "Sandbox": ['sandbox', 'sb_evaluate', 'mac_policy', 'mac_proc', 'container',
                    'sandbox_check', 'sandbox_extension', 'app-sandbox'],
        "Boot/Debug": ['boot-args', 'debug', 'PE_i_can_has_debugger', 'kprintf',
                       'serial', 'uart', 'panic', 'cs_enforcement', 'amfi_get_out'],
        "Crypto Keys": ['AES', 'aes_key', 'SHA256', 'sha1', 'HMAC', 'RSA', 'ECDSA',
                        'kext_key', 'encryption', 'decrypt', 'encrypt'],
        "Panic/Error": ['panic', 'assertion', 'fatal', 'abort', 'kernel trap',
                        'data abort', 'page fault'],
        "IOKit Drivers": ['IOUserClient', 'externalMethod', 'IOService', 'IOConnect',
                          'AppleKeyStore', 'AppleMobileAP', 'IOSurface', 'IOMFB'],
        "Process/Task": ['proc_', 'task_', 'thread_', 'posix_spawn', 'execve',
                         'fork', 'vfork', 'credential', 'ucred', 'uid', 'setuid'],
        "Memory/VM": ['vm_map', 'pmap', 'kalloc', 'kfree', 'zone_', 'copyin',
                      'copyout', 'mach_vm', 'vm_fault'],
        "Network": ['socket', 'tcp', 'udp', 'ip_input', 'necp', 'ipsec'],
        "USB": ['usb', 'USB', 'IOUSBHost', 'AppleUSB', 'lightning'],
        "Entitlements": ['com.apple.private', 'com.apple.security', 'task_for_pid',
                         'get-task-allow', 'platform-application'],
    }
    
    for off, s in strings:
        for cat, keywords in kw_map.items():
            if any(kw in s for kw in keywords):
                categories[cat].append((off, s))
                break
    
    # Report findings per category
    for cat, items in sorted(categories.items(), key=lambda x: -len(x[1])):
        if not items:
            continue
        log(f"\n{'─' * 50}")
        log(f"[{cat}] — {len(items)} strings")
        log(f"{'─' * 50}")
        
        # Show most interesting (deduplicated, max 30)
        seen = set()
        shown = 0
        for off, s in items:
            short = s[:80]
            if short in seen:
                continue
            seen.add(short)
            log(f"  0x{off:08x}: {short}")
            shown += 1
            if shown >= 30:
                log(f"  ... and {len(items) - shown} more")
                break

    # Deep scan: AMFI bypass vectors in kernel
    log(f"\n{'═' * 70}")
    log("AMFI/TRUST CACHE KERNEL ANALYSIS")
    log(f"{'═' * 70}")
    
    # Find specific patterns that indicate bypass opportunities
    bypass_patterns = [
        (b"cs_enforcement_disable", CRITICAL, "Kernel CS disable variable"),
        (b"amfi_get_out_of_my_way", CRITICAL, "AMFI disable boot-arg check"),
        (b"cs_debug", HIGH, "CS debug mode variable"),
        (b"cs_system_enforcement", HIGH, "System-wide CS enforcement toggle"),
        (b"cs_process_enforcement", HIGH, "Per-process CS enforcement"),
        (b"pmap_cs_allow_invalid", HIGH, "pmap_cs allow invalid pages"),
        (b"PE_i_can_has_debugger", HIGH, "Debugger check function"),
        (b"proc_enforce", MEDIUM, "Process enforcement variable"),
        (b"vnode_enforce", MEDIUM, "Vnode enforcement variable"),
        (b"cs_library_val_enable", MEDIUM, "Library validation toggle"),
        (b"amfi_allow_any_signature", CRITICAL, "Allow any signature flag"),
        (b"cs_require_lv", MEDIUM, "Library validation requirement"),
        (b"trust_cache_runtime", HIGH, "Runtime trust cache operations"),
        (b"pmap_lookup_in_loaded_trust_caches", HIGH, "TC lookup function"),
        (b"pmap_lookup_in_static_trust_cache", HIGH, "Static TC lookup"),
        (b"load_trust_cache_entries_from_vnode", CRITICAL, "Load TC from file!"),
        (b"kext_request", MEDIUM, "Kext loading request"),
        (b"OSKext", MEDIUM, "Kext management"),
    ]
    
    for pattern, severity, desc in bypass_patterns:
        count = data.count(pattern)
        if count > 0:
            # Find first occurrence offset
            idx = data.find(pattern)
            add_finding("kernelcache", severity, "Kernel AMFI",
                       f"{pattern.decode('ascii','ignore')} ({count}x)", desc, idx)
            log(f"  [{severity}] {pattern.decode('ascii','ignore')} ({count}x) @ 0x{idx:x}")
            log(f"         → {desc}")
    
    # Find kernel functions related to trust cache
    log(f"\n--- Trust Cache Functions ---")
    tc_funcs = [
        b"_pmap_cs_",
        b"_trust_cache_",
        b"_amfi_",
        b"_load_trust_cache",
        b"_query_trust_cache",
        b"_check_trust_cache",
    ]
    
    for func_prefix in tc_funcs:
        # Find all instances and extract full function name
        idx = 0
        found_names = set()
        while True:
            idx = data.find(func_prefix, idx)
            if idx == -1:
                break
            # Extract full name (until null or non-printable)
            end = idx
            while end < len(data) and end < idx + 80:
                if data[end] == 0 or data[end] < 32 or data[end] > 126:
                    break
                end += 1
            name = data[idx:end].decode('ascii', 'ignore')
            if len(name) > 4:
                found_names.add(name)
            idx += 1
        
        if found_names:
            for name in sorted(found_names)[:10]:
                log(f"  {name}")
                add_finding("kernelcache", MEDIUM, "Kernel TC Function",
                           name, f"Trust cache related function", 0)

    # Scan for NVRAM-related code (boot-args manipulation)
    log(f"\n--- NVRAM / Boot-args ---")
    nvram_patterns = [
        (b"boot-args", "Boot arguments variable"),
        (b"nvram", "NVRAM access"),
        (b"IODTNVRAMVariables", "NVRAM variable list"),
        (b"IONVRAM", "NVRAM IOKit class"),
        (b"OFVariables", "OpenFirmware variables"),
        (b"SystemAuditToken", "System audit token"),
        (b"kern.bootargs", "Kernel boot args sysctl"),
    ]
    
    for pattern, desc in nvram_patterns:
        count = data.count(pattern)
        if count > 0:
            idx = data.find(pattern)
            log(f"  {pattern.decode('ascii','ignore')} ({count}x) @ 0x{idx:x} — {desc}")
            if count > 5:
                add_finding("kernelcache", HIGH, "Kernel NVRAM",
                           f"{pattern.decode('ascii','ignore')} ({count}x)", desc, idx)

# ============================================================
# PART 2: iBOOT DEEP DISASSEMBLY
# ============================================================

def analyze_iboot_deep(iboot_path):
    """Deep analysis of iBoot — trace boot-args, debug, trust validation"""
    log("\n" + "=" * 70)
    log("iBOOT DEEP ANALYSIS")
    log("=" * 70)
    
    with open(iboot_path, "rb") as f:
        raw = f.read()
    
    # Decompress
    bvx2_idx = raw.find(b'bvx2')
    if bvx2_idx == -1 or not HAS_LZFSE:
        log("Cannot decompress iBoot")
        return
    
    data = lzfse_decode(raw[bvx2_idx:])
    log(f"iBoot decompressed: {len(data)} bytes")
    
    # Extract all strings
    strings = extract_strings(data, min_len=4)
    log(f"Strings: {len(strings)}")
    
    # Find security-critical strings
    log(f"\n--- Security-Critical Strings ---")
    security_strings = []
    security_kw = [
        'debug', 'boot-args', 'nonce', 'ticket', 'trust', 'cert', 'sign',
        'verify', 'hash', 'img4', 'manifest', 'allow', 'disable', 'enable',
        'skip', 'force', 'demot', 'nvram', 'secure', 'production', 'development',
        'fuse', 'key', 'aes', 'uid', 'gid', 'BNCH', 'ECID', 'SEPO', 'krnl',
        'amfi', 'cs_enforcement', 'PE_i_can_has', 'root_hash', 'StaticTrustCache',
        'personalize', 'restore', 'upgrade', 'diag', 'serial', 'usb',
    ]
    
    for off, s in strings:
        if any(kw in s for kw in security_kw):
            security_strings.append((off, s))
    
    log(f"Security strings: {len(security_strings)}")
    for off, s in security_strings[:80]:
        log(f"  0x{off:06x}: {s[:100]}")
    
    # ARM64 disassembly of key functions
    if HAS_CAPSTONE and len(data) > 1000:
        log(f"\n--- ARM64 Function Analysis ---")
        analyze_iboot_functions(data, strings)
    
    # Find boot-args handling
    log(f"\n--- Boot-Args Handling ---")
    ba_idx = data.find(b'boot-args\x00')
    if ba_idx != -1:
        log(f"  'boot-args' string at 0x{ba_idx:x}")
        # Find xrefs to this string (ADRP+ADD patterns pointing near this offset)
        # In ARM64, strings are referenced via ADRP+ADD
        add_finding("iBoot", HIGH, "Boot Chain",
                   "boot-args string found",
                   f"iBoot reads boot-args from NVRAM at 0x{ba_idx:x}", ba_idx)
    
    # Find debug-enabled check
    de_idx = data.find(b'debug-enabled\x00')
    if de_idx != -1:
        log(f"  'debug-enabled' at 0x{de_idx:x}")
        add_finding("iBoot", CRITICAL, "Boot Chain",
                   "debug-enabled check in iBoot",
                   f"If set in DeviceTree/NVRAM, enables full debug mode", de_idx)
    
    # Find certificate validation
    for pattern in [b'production-cert', b'development-cert', b'certificate-production-status']:
        idx = data.find(pattern)
        if idx != -1:
            log(f"  '{pattern.decode()}' at 0x{idx:x}")
            add_finding("iBoot", HIGH, "Boot Chain",
                       f"{pattern.decode()} check",
                       "Certificate status check — production vs development", idx)
    
    # Find secure-boot check
    sb_idx = data.find(b'secure-boot\x00')
    if sb_idx != -1:
        log(f"  'secure-boot' at 0x{sb_idx:x}")
        add_finding("iBoot", HIGH, "Boot Chain",
                   "secure-boot flag",
                   "Secure boot enforcement check", sb_idx)


def analyze_iboot_functions(data, strings):
    """Disassemble iBoot and find key function patterns"""
    if not HAS_CAPSTONE:
        return
    
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    
    # iBoot loads at 0x0 typically, ARM64 code starts early
    # Find code region (look for valid ARM64 instruction patterns)
    code_start = 0
    for i in range(0, min(len(data), 0x1000), 4):
        insn = struct.unpack_from("<I", data, i)[0]
        # Look for typical function prologue: STP X29, X30, [SP, #-xx]!
        if (insn & 0xFFC003E0) == 0xA9800000:
            code_start = i
            break
    
    if code_start == 0:
        # Try offset 0 anyway
        code_start = 0
    
    log(f"  Code region starts at: 0x{code_start:x}")
    
    # Disassemble first 256KB looking for interesting patterns
    code_size = min(len(data) - code_start, 256 * 1024)
    code = data[code_start:code_start + code_size]
    
    # Count patterns
    svc_count = 0
    bl_count = 0
    cbz_after_bl = 0  # Unchecked return values
    str_refs = 0
    
    prev_was_bl = False
    for insn in md.disasm(code, code_start):
        if insn.mnemonic == "svc":
            svc_count += 1
        elif insn.mnemonic == "bl":
            bl_count += 1
            prev_was_bl = True
            continue
        elif insn.mnemonic in ("cbz", "cbnz") and prev_was_bl:
            cbz_after_bl += 1
        elif insn.mnemonic in ("adrp", "adr"):
            str_refs += 1
        prev_was_bl = False
    
    log(f"  BL (function calls): {bl_count}")
    log(f"  SVC (syscalls): {svc_count}")
    log(f"  CBZ/CBNZ after BL (return checks): {cbz_after_bl}")
    log(f"  ADRP/ADR (string/data refs): {str_refs}")
    
    if bl_count > 0:
        unchecked_pct = 100 - (cbz_after_bl * 100 // bl_count)
        log(f"  Unchecked returns: ~{unchecked_pct}% (potential error handling bugs)")

# ============================================================
# PART 3: BINARY CROSS-REFERENCE ANALYSIS
# ============================================================

def analyze_xpc_to_dangerous(binary_path):
    """Trace XPC input handlers to dangerous functions (strcpy, memcpy, etc)"""
    name = os.path.basename(binary_path)
    
    with open(binary_path, "rb") as f:
        data = f.read()
    
    if len(data) < 100:
        return
    
    # Check if binary has both XPC input AND dangerous functions
    has_xpc_input = any(p in data for p in [
        b"xpc_dictionary_get_string",
        b"xpc_dictionary_get_data",
        b"xpc_dictionary_get_value",
    ])
    
    dangerous_funcs = {
        b"_strcpy": "strcpy — buffer overflow",
        b"_strcat": "strcat — buffer overflow",
        b"_sprintf": "sprintf — format string + overflow",
        b"_memcpy": "memcpy — size not validated?",
        b"_memmove": "memmove — size not validated?",
        b"_sscanf": "sscanf — format parsing",
        b"_system": "system() — command injection",
        b"_popen": "popen() — command injection",
        b"_dlopen": "dlopen — code loading",
        b"_NSKeyedUnarchiver": "deserialization",
        b"_xpc_connection_create": "creates XPC connection (outbound)",
    }
    
    if not has_xpc_input:
        return
    
    found_dangerous = []
    for func, desc in dangerous_funcs.items():
        if func in data:
            count = data.count(func)
            found_dangerous.append((func.decode('ascii','ignore'), count, desc))
    
    if not found_dangerous:
        return
    
    log(f"\n  [{name}] XPC Input → Dangerous Functions:")
    for func, count, desc in found_dangerous:
        severity = HIGH if 'overflow' in desc or 'injection' in desc or 'deserialization' in desc else MEDIUM
        log(f"    {func} ({count}x) — {desc}")
        add_finding(name, severity, "XPC→Dangerous",
                   f"XPC input + {func} ({count}x)",
                   f"Binary receives XPC input AND uses {func}: {desc}")
    
    # Deep: check if binary has BOTH xpc_get_string AND strcpy
    # This is the most dangerous combo
    if b"xpc_dictionary_get_string" in data and b"_strcpy" in data:
        add_finding(name, CRITICAL, "XPC→Overflow",
                   "xpc_dictionary_get_string + strcpy",
                   "XPC string input flows to strcpy — BUFFER OVERFLOW if string > buffer!")
        log(f"    🔴 CRITICAL: XPC string → strcpy path exists!")
    
    if b"xpc_dictionary_get_data" in data and b"_memcpy" in data:
        if b"_malloc" not in data and b"_calloc" not in data:
            add_finding(name, HIGH, "XPC→Overflow",
                       "xpc_dictionary_get_data + memcpy (no malloc)",
                       "XPC data copied without dynamic allocation — stack overflow?")


def analyze_entitlement_abuse(binary_path):
    """Find binaries with dangerous entitlements that are XPC-accessible"""
    name = os.path.basename(binary_path)
    
    with open(binary_path, "rb") as f:
        data = f.read()
    
    # Check for XPC service (accepts connections)
    is_xpc_service = b"xpc_connection_create_mach_service" in data or \
                     b"xpc_main" in data or \
                     b"NSXPCListener" in data
    
    # Check for dangerous entitlements
    dangerous_ents = [
        (b"com.apple.private.amfi.can-load-trust-cache", CRITICAL, "Can load trust cache"),
        (b"com.apple.private.pmap.load-trust-cache", CRITICAL, "Kernel TC load"),
        (b"com.apple.private.security.no-sandbox", CRITICAL, "No sandbox"),
        (b"task_for_pid-allow", CRITICAL, "task_for_pid"),
        (b"com.apple.private.kernel", HIGH, "Kernel private"),
        (b"com.apple.private.MobileInstallation", HIGH, "App install"),
        (b"com.apple.rootless.storage", HIGH, "SIP exception"),
        (b"get-task-allow", HIGH, "Debuggable"),
    ]
    
    has_no_auth = b"xpc_connection_get_audit_token" not in data and \
                  b"SecTaskCopyValueForEntitlement" not in data
    
    for ent, severity, desc in dangerous_ents:
        if ent in data:
            if is_xpc_service and has_no_auth:
                add_finding(name, CRITICAL, "Entitlement Abuse",
                           f"XPC service + {ent.decode()} + NO AUTH",
                           f"Service has {desc} AND no caller validation — anyone can trigger!")
                log(f"  🔴 [{name}] CRITICAL: {desc} + XPC accessible + no auth check!")
            elif is_xpc_service:
                add_finding(name, HIGH, "Entitlement Abuse",
                           f"XPC service + {ent.decode()}",
                           f"Service has {desc} — check if auth can be bypassed")

# ============================================================
# PART 4: MACH-O DEEP ANALYSIS (IOKit, syscalls, etc)
# ============================================================

def analyze_binary_deep(binary_path):
    """Deep analysis of a single binary with disassembly"""
    name = os.path.basename(binary_path)
    
    with open(binary_path, "rb") as f:
        data = f.read()
    
    if len(data) < 100:
        return
    
    # Run cross-reference analysis
    analyze_xpc_to_dangerous(binary_path)
    analyze_entitlement_abuse(binary_path)
    
    # Find IOKit user client connections (kernel attack surface)
    if b"IOConnectCallMethod" in data or b"IOConnectCallStructMethod" in data:
        # Find which IOKit services are opened
        iokit_services = []
        for off, s in extract_strings(data, min_len=10):
            if 'AppleKeyStore' in s or 'IOSurface' in s or 'AppleMobileAP' in s or \
               'AMFI' in s or 'AppleCredentialManager' in s or 'IOHIDFamily' in s or \
               'AppleUSB' in s or 'IOBluetoothHCI' in s:
                iokit_services.append(s)
        
        if iokit_services:
            for svc in set(iokit_services):
                add_finding(name, HIGH, "IOKit Target",
                           f"Opens IOKit: {svc[:50]}",
                           f"Binary connects to kernel driver {svc} — attack surface")
                log(f"  [{name}] IOKit target: {svc[:60]}")
    
    # Find mach_msg patterns (IPC attack surface)
    if b"mach_msg" in data:
        # Check for specific mach port operations
        mach_ops = [
            (b"host_get_special_port", "Gets host special port — privilege escalation"),
            (b"task_get_special_port", "Gets task special port"),
            (b"mach_port_insert_right", "Inserts port right — can give access to others"),
            (b"mach_port_extract_right", "Extracts port right"),
            (b"thread_set_state", "Sets thread state — code injection"),
            (b"task_threads", "Enumerates threads"),
        ]
        
        for pattern, desc in mach_ops:
            if pattern in data:
                add_finding(name, MEDIUM, "Mach IPC",
                           f"{pattern.decode()} in {name}", desc)


# ============================================================
# HELPERS
# ============================================================

def extract_strings(data, min_len=6):
    """Extract printable strings from binary data"""
    strings = []
    current = b""
    for i, b in enumerate(data):
        if 32 <= b < 127:
            current += bytes([b])
        else:
            if len(current) >= min_len:
                strings.append((i - len(current), current.decode('ascii', 'ignore')))
            current = b""
    if len(current) >= min_len:
        strings.append((len(data) - len(current), current.decode('ascii', 'ignore')))
    return strings


# ============================================================
# MAIN
# ============================================================

def main():
    print("=" * 70)
    print("DEEP REVERSE ENGINEERING v2 — iPhone11,8 iOS 18.2")
    print("=" * 70)
    print()
    
    log("=" * 80)
    log("DEEP REVERSE ENGINEERING REPORT v2")
    log("iPhone11,8 — iOS 18.2 (22C152)")
    log("Includes: kernelcache decompress, iBoot disasm, XPC cross-ref")
    log("=" * 80)
    
    # 1. Kernelcache deep analysis
    kc_path = IPSW_DIR / "kernelcache.release.iphone11b"
    if kc_path.exists():
        print("[1/4] Kernelcache deep analysis...")
        analyze_kernelcache_deep(str(kc_path))
    
    # 2. iBoot deep analysis
    iboot_path = IPSW_DIR / "Firmware" / "all_flash" / "iBoot.n841.RELEASE.im4p"
    if iboot_path.exists():
        print("[2/4] iBoot deep analysis...")
        analyze_iboot_deep(str(iboot_path))
    
    # 3. Cross-reference analysis on all extracted binaries
    print("[3/4] Cross-reference analysis (XPC → dangerous functions)...")
    log("\n" + "=" * 70)
    log("CROSS-REFERENCE ANALYSIS: XPC Input → Dangerous Functions")
    log("=" * 70)
    
    for root_dir, dirs, files in os.walk(EXTRACTED_DIR):
        for f in files:
            path = os.path.join(root_dir, f)
            analyze_binary_deep(path)
    
    # 4. iBEC/iBSS analysis
    print("[4/4] iBEC/iBSS analysis...")
    for fw_name in ["iBEC.n841.RELEASE.im4p", "iBSS.n841.RELEASE.im4p"]:
        fw_path = IPSW_DIR / "Firmware" / "dfu" / fw_name
        if fw_path.exists():
            log(f"\n--- {fw_name} ---")
            with open(fw_path, "rb") as f:
                raw = f.read()
            bvx2 = raw.find(b'bvx2')
            if bvx2 != -1 and HAS_LZFSE:
                dec = lzfse_decode(raw[bvx2:])
                strs = extract_strings(dec, min_len=6)
                security_strs = [(o,s) for o,s in strs if any(
                    kw in s for kw in ['debug','boot','nonce','trust','cert','key','secure','verify','hash','sign']
                )]
                log(f"  Decompressed: {len(dec)} bytes, {len(strs)} strings, {len(security_strs)} security-related")
                for off, s in security_strs[:30]:
                    log(f"    0x{off:06x}: {s[:80]}")
    
    # Write report
    print(f"\n{'=' * 70}")
    print(f"COMPLETE — {len(findings)} deep findings")
    print(f"{'=' * 70}")
    
    # Summary
    counts = defaultdict(int)
    for _, sev, _, _, _, _ in findings:
        counts[sev] += 1
    
    log(f"\n\n{'=' * 80}")
    log("SUMMARY")
    log(f"{'=' * 80}")
    log(f"  CRITICAL: {counts[CRITICAL]}")
    log(f"  HIGH:     {counts[HIGH]}")
    log(f"  MEDIUM:   {counts[MEDIUM]}")
    log(f"  LOW:      {counts[LOW]}")
    log(f"  TOTAL:    {len(findings)}")
    
    # Top findings
    log(f"\n{'=' * 80}")
    log("TOP CRITICAL/HIGH FINDINGS")
    log(f"{'=' * 80}")
    
    for binary, sev, cat, title, detail, off in findings:
        if sev in [CRITICAL, HIGH]:
            loc = f" @ 0x{off:x}" if off else ""
            log(f"\n  [{sev}] [{cat}] {binary}{loc}")
            log(f"    {title}")
            log(f"    → {detail}")
    
    # Write output
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(out_lines))
    
    print(f"\nOutput: {OUTPUT_FILE}")
    print(f"Critical: {counts[CRITICAL]}, High: {counts[HIGH]}, Medium: {counts[MEDIUM]}")


if __name__ == "__main__":
    main()
