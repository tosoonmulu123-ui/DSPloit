#!/usr/bin/env python3
"""
mass_reverse_all.py — Full reverse engineering of ALL iPhone11,8 iOS 18.2 binaries.
Scans for vulnerabilities: buffer overflows, format strings, race conditions,
XPC issues, entitlement abuse, sandbox escapes, memory corruption, etc.
Output: mass_reverse_output.txt

Target: ALL extracted binaries + kernelcache + iBoot + trust caches
"""

import struct
import os
import sys
import hashlib
from pathlib import Path
from collections import defaultdict

# Capstone for ARM64 disassembly
try:
    from capstone import *
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False
    print("[WARN] capstone not installed — using pattern-based analysis only")

BASE_DIR = Path(r"d:\Backup\Personal\Hp\iPhone\DSPloit")
EXTRACTED_DIR = BASE_DIR / "extracted"
IPSW_DIR = BASE_DIR / "iPhone11,8_18.2_22C152_Restore"
OUTPUT_FILE = BASE_DIR / "mass_reverse_output.txt"

# Vulnerability severity levels
CRITICAL = "CRITICAL"
HIGH = "HIGH"
MEDIUM = "MEDIUM"
LOW = "LOW"
INFO = "INFO"

findings = []

class Finding:
    def __init__(self, binary, severity, category, title, detail, offset=0):
        self.binary = binary
        self.severity = severity
        self.category = category
        self.title = title
        self.detail = detail
        self.offset = offset

    def __str__(self):
        loc = f" @ 0x{self.offset:x}" if self.offset else ""
        return f"[{self.severity}] [{self.category}] {self.binary}{loc}: {self.title}\n  {self.detail}"


def add_finding(binary, severity, category, title, detail, offset=0):
    findings.append(Finding(binary, severity, category, title, detail, offset))


# ============================================================
# MACH-O PARSER
# ============================================================

class MachOBinary:
    def __init__(self, path):
        self.path = path
        self.name = os.path.basename(path)
        self.data = b""
        self.is_valid = False
        self.is_64 = False
        self.segments = []
        self.sections = []
        self.imports = []
        self.exports = []
        self.strings = []
        self.entitlements = ""
        self.load_commands = []
        self.text_section = None
        self.cstring_section = None

    def parse(self):
        try:
            with open(self.path, "rb") as f:
                self.data = f.read()
        except Exception as e:
            return False

        if len(self.data) < 32:
            return False

        magic = struct.unpack_from("<I", self.data, 0)[0]

        # Handle FAT binary
        offset = 0
        if magic == 0xBEBAFECA or magic == 0xBFBAFECA:
            # FAT binary — find ARM64 slice
            nfat = struct.unpack_from(">I", self.data, 4)[0]
            for i in range(min(nfat, 10)):
                fat_off = 8 + i * 20
                cpu = struct.unpack_from(">I", self.data, fat_off)[0]
                if cpu == 0x0100000C:  # ARM64
                    offset = struct.unpack_from(">I", self.data, fat_off + 8)[0]
                    break
            if offset == 0:
                return False
            magic = struct.unpack_from("<I", self.data, offset)[0]

        if magic == 0xFEEDFACF:
            self.is_64 = True
            self.is_valid = True
        elif magic == 0xFEEDFACE:
            self.is_64 = False
            self.is_valid = True
        else:
            return False

        self._parse_load_commands(offset)
        self._extract_strings()
        return True

    def _parse_load_commands(self, base):
        hdr_size = 32 if self.is_64 else 28
        ncmds = struct.unpack_from("<I", self.data, base + 16)[0]
        off = base + hdr_size

        for _ in range(min(ncmds, 256)):
            if off + 8 > len(self.data):
                break
            cmd, cmdsize = struct.unpack_from("<II", self.data, off)
            if cmdsize < 8:
                break

            self.load_commands.append((cmd, off, cmdsize))

            # LC_SEGMENT_64 = 0x19
            if cmd == 0x19 and off + 72 <= len(self.data):
                segname = self.data[off+8:off+24].split(b'\x00')[0].decode('ascii', errors='ignore')
                vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", self.data, off+24)
                nsects = struct.unpack_from("<I", self.data, off+64)[0]
                self.segments.append({
                    'name': segname, 'vmaddr': vmaddr, 'vmsize': vmsize,
                    'fileoff': fileoff, 'filesize': filesize, 'nsects': nsects
                })

                # Parse sections
                sect_off = off + 72
                for s in range(min(nsects, 64)):
                    if sect_off + 80 > len(self.data):
                        break
                    sectname = self.data[sect_off:sect_off+16].split(b'\x00')[0].decode('ascii', errors='ignore')
                    seg = self.data[sect_off+16:sect_off+32].split(b'\x00')[0].decode('ascii', errors='ignore')
                    saddr, ssize, soff = struct.unpack_from("<QQI", self.data, sect_off+32)
                    self.sections.append({
                        'sectname': sectname, 'segname': seg,
                        'addr': saddr, 'size': ssize, 'offset': soff
                    })
                    if sectname == "__text" and seg == "__TEXT":
                        self.text_section = {'addr': saddr, 'size': ssize, 'offset': soff}
                    if sectname == "__cstring":
                        self.cstring_section = {'addr': saddr, 'size': ssize, 'offset': soff}
                    sect_off += 80

            # LC_CODE_SIGNATURE = 0x1D
            elif cmd == 0x1D and off + 16 <= len(self.data):
                cs_off, cs_size = struct.unpack_from("<II", self.data, off+8)
                self._parse_code_signature(cs_off, cs_size)

            # LC_LOAD_DYLIB = 0xC
            elif cmd == 0xC and off + 24 <= len(self.data):
                str_off = struct.unpack_from("<I", self.data, off+8)[0]
                dylib_name = self.data[off+str_off:off+cmdsize].split(b'\x00')[0]
                self.imports.append(dylib_name.decode('ascii', errors='ignore'))

            off += cmdsize

    def _parse_code_signature(self, cs_off, cs_size):
        """Extract entitlements from code signature"""
        if cs_off + cs_size > len(self.data):
            return
        cs_data = self.data[cs_off:cs_off+cs_size]
        # Look for entitlements plist
        ent_marker = b"<!DOCTYPE plist"
        idx = cs_data.find(ent_marker)
        if idx == -1:
            ent_marker = b"<?xml"
            idx = cs_data.find(ent_marker)
        if idx != -1:
            end = cs_data.find(b"</plist>", idx)
            if end != -1:
                self.entitlements = cs_data[idx:end+8].decode('utf-8', errors='ignore')

    def _extract_strings(self):
        """Extract printable strings (min 6 chars)"""
        current = b""
        for i, b in enumerate(self.data):
            if 32 <= b < 127:
                current += bytes([b])
            else:
                if len(current) >= 6:
                    self.strings.append((i - len(current), current.decode('ascii', errors='ignore')))
                current = b""

    def get_text_bytes(self):
        if self.text_section:
            off = self.text_section['offset']
            size = self.text_section['size']
            return self.data[off:off+size], self.text_section['addr']
        return None, 0

    def has_entitlement(self, ent):
        return ent in self.entitlements


# ============================================================
# VULNERABILITY SCANNERS
# ============================================================

def scan_dangerous_functions(binary):
    """Scan for dangerous C function usage (buffer overflow, format string)"""
    dangerous = {
        # Buffer overflow
        b"strcpy": (HIGH, "Buffer Overflow", "strcpy() tanpa bounds check — bisa overflow"),
        b"strcat": (HIGH, "Buffer Overflow", "strcat() tanpa bounds check"),
        b"sprintf": (HIGH, "Format String/Overflow", "sprintf() tanpa size limit"),
        b"gets": (CRITICAL, "Buffer Overflow", "gets() — SELALU vulnerable"),
        b"scanf": (MEDIUM, "Buffer Overflow", "scanf() tanpa width specifier"),
        # Format string
        b"printf": (LOW, "Format String", "printf() — cek apakah user-controlled format"),
        b"syslog": (MEDIUM, "Format String", "syslog() — format string jika user input"),
        b"NSLog": (LOW, "Info Leak", "NSLog() — info leak via console"),
        # Memory
        b"memcpy": (LOW, "Memory", "memcpy() — cek bounds validation"),
        b"memmove": (LOW, "Memory", "memmove() — cek bounds"),
        b"alloca": (MEDIUM, "Stack Overflow", "alloca() — stack overflow jika size user-controlled"),
        # Race condition
        b"access": (MEDIUM, "TOCTOU", "access() + open() = TOCTOU race condition"),
        b"mktemp": (MEDIUM, "Race Condition", "mktemp() — predictable temp file"),
        # Crypto
        b"rand": (MEDIUM, "Weak Crypto", "rand()/srand() — not cryptographically secure"),
        b"MD5": (LOW, "Weak Crypto", "MD5 — deprecated, collision attacks"),
        b"SHA1": (LOW, "Weak Crypto", "SHA1 — deprecated for signatures"),
        b"DES": (HIGH, "Weak Crypto", "DES — broken encryption"),
        b"RC4": (HIGH, "Weak Crypto", "RC4 — broken stream cipher"),
    }

    for func_name, (severity, category, detail) in dangerous.items():
        # Search in string table and imports
        count = binary.data.count(func_name + b"\x00")
        if count > 0:
            # Check if it's actually imported (not just a substring)
            if func_name.decode() in str(binary.imports) or \
               binary.data.count(b"_" + func_name + b"\x00") > 0:
                add_finding(binary.name, severity, category,
                           f"Uses {func_name.decode()}() ({count} refs)",
                           detail)

def scan_xpc_vulnerabilities(binary):
    """Scan for XPC-related vulnerabilities"""
    xpc_patterns = [
        (b"xpc_connection_create", INFO, "XPC", "Creates XPC connection"),
        (b"xpc_dictionary_get_string", MEDIUM, "XPC Input", "Gets string from XPC — validate length"),
        (b"xpc_dictionary_get_data", MEDIUM, "XPC Input", "Gets raw data from XPC — validate size"),
        (b"xpc_dictionary_get_value", MEDIUM, "XPC Input", "Gets value from XPC — type confusion possible"),
        (b"xpc_connection_set_event_handler", INFO, "XPC", "XPC event handler registered"),
    ]

    has_xpc = False
    for pattern, severity, category, detail in xpc_patterns:
        if pattern in binary.data:
            has_xpc = True
            if severity != INFO:
                add_finding(binary.name, severity, category,
                           f"XPC: {pattern.decode()}", detail)

    # Check for missing entitlement validation in XPC handlers
    if has_xpc:
        if b"xpc_connection_get_audit_token" not in binary.data and \
           b"SecTaskCopyValueForEntitlement" not in binary.data:
            add_finding(binary.name, HIGH, "XPC Auth",
                       "XPC service tanpa entitlement check",
                       "Tidak ada xpc_connection_get_audit_token atau SecTaskCopyValueForEntitlement — "
                       "siapapun bisa connect ke service ini")

        # Check for xpc_connection_set_target_uid(0) — root-only
        if b"xpc_connection_set_target_uid" not in binary.data:
            add_finding(binary.name, MEDIUM, "XPC Auth",
                       "XPC tanpa UID restriction",
                       "Tidak ada target_uid check — non-root mungkin bisa connect")


def scan_sandbox_issues(binary):
    """Scan for sandbox escape vectors"""
    sandbox_patterns = [
        (b"sandbox_check", INFO, "Sandbox", "Performs sandbox check"),
        (b"sandbox_extension_consume", MEDIUM, "Sandbox", "Consumes sandbox extension token"),
        (b"sandbox_extension_issue", HIGH, "Sandbox Escape", "Issues sandbox extension — bisa di-abuse"),
        (b"sandbox_apply", INFO, "Sandbox", "Applies sandbox profile"),
        (b"/private/var/tmp", MEDIUM, "Sandbox", "Accesses /var/tmp — shared writable location"),
        (b"/private/var/mobile", LOW, "Sandbox", "Accesses mobile user directory"),
    ]

    for pattern, severity, category, detail in sandbox_patterns:
        if pattern in binary.data:
            count = binary.data.count(pattern)
            add_finding(binary.name, severity, category,
                       f"Sandbox: {pattern.decode()[:50]} ({count}x)", detail)

    # Check for file operations without sandbox
    file_ops = [b"open(", b"fopen(", b"creat(", b"mkdir("]
    if not any("sandbox" in s for _, s in binary.strings[:1000]):
        for op in file_ops:
            if op in binary.data:
                pass  # Too noisy, skip

def scan_entitlements(binary):
    """Analyze entitlements for privilege escalation vectors"""
    dangerous_ents = {
        "com.apple.private.security.no-sandbox": (CRITICAL, "No sandbox — full filesystem access"),
        "com.apple.private.skip-library-validation": (HIGH, "Skip library validation — load any dylib"),
        "com.apple.private.amfi.can-load-trust-cache": (CRITICAL, "Can load trust cache — code signing bypass"),
        "com.apple.private.pmap.load-trust-cache": (CRITICAL, "pmap trust cache load — kernel trust cache"),
        "platform-application": (HIGH, "Platform binary — elevated privileges"),
        "com.apple.private.security.no-container": (HIGH, "No container — unrestricted file access"),
        "com.apple.rootless.storage.": (HIGH, "SIP storage exception"),
        "task_for_pid-allow": (CRITICAL, "task_for_pid — can control any process"),
        "com.apple.private.kernel.": (CRITICAL, "Kernel private entitlement"),
        "com.apple.security.exception.mach-lookup": (MEDIUM, "Mach service lookup exception"),
        "com.apple.private.MobileInstallation": (HIGH, "Can install apps without validation"),
        "com.apple.private.persona-mgmt": (MEDIUM, "Persona management — identity spoofing"),
        "com.apple.private.xpc.launchd": (HIGH, "Direct launchd XPC access"),
        "com.apple.private.iokit-user-client-class": (MEDIUM, "IOKit user client access"),
        "get-task-allow": (HIGH, "get-task-allow — debuggable, injectable"),
        "com.apple.private.security.storage.": (MEDIUM, "Storage class exception"),
        "com.apple.developer.kernel.increased-memory-limit": (LOW, "Increased memory limit"),
        "com.apple.private.amfi": (HIGH, "AMFI private entitlement"),
        "com.apple.private.CoreAuthentication": (MEDIUM, "Core authentication access"),
        "keychain-access-groups": (LOW, "Keychain access"),
        "com.apple.private.tcc.": (HIGH, "TCC bypass — privacy access without prompt"),
        "com.apple.private.apfs.": (MEDIUM, "APFS private operations"),
        "com.apple.private.memorystatus": (MEDIUM, "Memory status manipulation"),
        "com.apple.private.spawn-constraint": (MEDIUM, "Spawn constraint modification"),
    }

    if not binary.entitlements:
        add_finding(binary.name, INFO, "Entitlements", "No entitlements found", "Binary tanpa entitlements")
        return

    for ent, (severity, detail) in dangerous_ents.items():
        if ent in binary.entitlements:
            add_finding(binary.name, severity, "Entitlement",
                       f"Has: {ent}", detail)


def scan_crypto_issues(binary):
    """Scan for cryptographic weaknesses"""
    # Hardcoded keys/secrets
    key_patterns = [
        (b"-----BEGIN RSA PRIVATE", CRITICAL, "Hardcoded RSA private key"),
        (b"-----BEGIN EC PRIVATE", CRITICAL, "Hardcoded EC private key"),
        (b"-----BEGIN PRIVATE", CRITICAL, "Hardcoded private key"),
        (b"password", LOW, "Password string reference"),
        (b"secret", LOW, "Secret string reference"),
        (b"api_key", MEDIUM, "API key reference"),
        (b"token", LOW, "Token reference"),
    ]

    for pattern, severity, detail in key_patterns:
        if pattern in binary.data:
            # Find context
            idx = binary.data.find(pattern)
            context = binary.data[max(0,idx-20):idx+len(pattern)+40]
            context_str = context.decode('ascii', errors='replace')[:60]
            add_finding(binary.name, severity, "Crypto/Secrets",
                       f"Found: {pattern.decode()[:30]}", f"{detail} — context: {context_str}")

def scan_ipc_mach(binary):
    """Scan for Mach IPC vulnerabilities"""
    mach_patterns = [
        (b"mach_msg", INFO, "Mach IPC", "Uses Mach messaging"),
        (b"mach_port_allocate", LOW, "Mach IPC", "Allocates Mach ports"),
        (b"mach_port_insert_right", MEDIUM, "Mach IPC", "Inserts port rights — check authorization"),
        (b"task_for_pid", CRITICAL, "Mach IPC", "task_for_pid — full process control"),
        (b"processor_set_tasks", HIGH, "Mach IPC", "Enumerates all tasks"),
        (b"host_get_special_port", MEDIUM, "Mach IPC", "Gets host special port"),
        (b"mach_vm_read", HIGH, "Mach IPC", "Reads other process memory"),
        (b"mach_vm_write", CRITICAL, "Mach IPC", "Writes other process memory"),
        (b"mach_vm_remap", HIGH, "Mach IPC", "Remaps VM — memory manipulation"),
        (b"thread_create_running", HIGH, "Mach IPC", "Creates thread in target — code injection"),
    ]

    for pattern, severity, category, detail in mach_patterns:
        if pattern in binary.data:
            count = binary.data.count(pattern)
            if severity in [CRITICAL, HIGH] or count > 2:
                add_finding(binary.name, severity, category,
                           f"Mach: {pattern.decode()} ({count}x)", detail)


def scan_iokit_surface(binary):
    """Scan for IOKit attack surface"""
    iokit_patterns = [
        (b"IOServiceGetMatchingService", MEDIUM, "IOKit", "Opens IOKit service"),
        (b"IOServiceOpen", MEDIUM, "IOKit", "Opens IOKit user client"),
        (b"IOConnectCallMethod", HIGH, "IOKit", "Calls IOKit external method — kernel attack surface"),
        (b"IOConnectCallStructMethod", HIGH, "IOKit", "Struct method call — complex input parsing"),
        (b"IOConnectCallScalarMethod", MEDIUM, "IOKit", "Scalar method call"),
        (b"IOSurfaceCreate", MEDIUM, "IOKit", "Creates IOSurface — shared memory"),
        (b"IOSurfaceLock", LOW, "IOKit", "Locks IOSurface"),
        (b"IOConnectMapMemory", HIGH, "IOKit", "Maps kernel memory to userspace"),
        (b"IOConnectTrap", HIGH, "IOKit", "IOKit trap — fast path to kernel"),
    ]

    for pattern, severity, category, detail in iokit_patterns:
        if pattern in binary.data:
            count = binary.data.count(pattern)
            add_finding(binary.name, severity, category,
                       f"IOKit: {pattern.decode()} ({count}x)", detail)


def scan_network_surface(binary):
    """Scan for network attack surface"""
    net_patterns = [
        (b"socket(", LOW, "Network", "Creates socket"),
        (b"connect(", LOW, "Network", "Connects to remote"),
        (b"bind(", MEDIUM, "Network", "Binds to port — listening service"),
        (b"listen(", MEDIUM, "Network", "Listens for connections"),
        (b"accept(", MEDIUM, "Network", "Accepts connections"),
        (b"recv(", LOW, "Network", "Receives data"),
        (b"recvfrom(", LOW, "Network", "Receives data with source"),
        (b"SSL_read", LOW, "Network", "SSL/TLS read"),
        (b"http://", MEDIUM, "Network", "HTTP (not HTTPS) URL — cleartext"),
        (b"NSURLSession", LOW, "Network", "URL session — network access"),
        (b"CFHTTPMessage", LOW, "Network", "HTTP message handling"),
    ]

    for pattern, severity, category, detail in net_patterns:
        if pattern in binary.data:
            count = binary.data.count(pattern)
            if severity != LOW or count > 3:
                add_finding(binary.name, severity, category,
                           f"Net: {pattern.decode()[:40]} ({count}x)", detail)

def scan_file_operations(binary):
    """Scan for dangerous file operations"""
    file_patterns = [
        (b"/tmp/", MEDIUM, "File", "Uses /tmp/ — world-writable, race conditions"),
        (b"/var/tmp/", MEDIUM, "File", "Uses /var/tmp/ — shared writable"),
        (b"mkstemp", LOW, "File", "Creates temp file (safer than mktemp)"),
        (b"symlink", MEDIUM, "File", "Creates symlink — symlink attacks possible"),
        (b"link(", MEDIUM, "File", "Creates hard link"),
        (b"chmod", LOW, "File", "Changes permissions"),
        (b"chown", MEDIUM, "File", "Changes ownership — privilege issues"),
        (b"setuid", HIGH, "Privilege", "setuid — privilege escalation vector"),
        (b"setgid", MEDIUM, "Privilege", "setgid — group privilege change"),
        (b"execve", MEDIUM, "Exec", "execve — command execution"),
        (b"posix_spawn", MEDIUM, "Exec", "posix_spawn — process creation"),
        (b"system(", HIGH, "Command Injection", "system() — shell command execution"),
        (b"popen(", HIGH, "Command Injection", "popen() — shell command with pipe"),
        (b"dlopen", MEDIUM, "Code Loading", "dlopen — dynamic library loading"),
        (b"NSTask", MEDIUM, "Exec", "NSTask — process execution"),
    ]

    for pattern, severity, category, detail in file_patterns:
        if pattern in binary.data:
            count = binary.data.count(pattern)
            if severity in [HIGH, CRITICAL] or count > 2:
                add_finding(binary.name, severity, category,
                           f"File/Exec: {pattern.decode()[:30]} ({count}x)", detail)


def scan_memory_issues(binary):
    """Scan for memory safety issues"""
    # Look for stack buffer patterns (large local arrays)
    mem_patterns = [
        (b"_stack_chk_fail", LOW, "Memory", "Has stack canary protection"),
        (b"__stack_chk_guard", LOW, "Memory", "Stack guard present"),
        (b"malloc(", LOW, "Memory", "Dynamic allocation"),
        (b"realloc(", MEDIUM, "Memory", "realloc — use-after-realloc possible"),
        (b"free(", LOW, "Memory", "free — double-free / UAF possible"),
        (b"mmap(", MEDIUM, "Memory", "mmap — memory mapping"),
        (b"munmap(", LOW, "Memory", "munmap — unmap"),
        (b"vm_allocate", LOW, "Memory", "VM allocation"),
    ]

    has_stack_protection = b"_stack_chk_fail" in binary.data or b"__stack_chk_guard" in binary.data

    if not has_stack_protection and binary.text_section and binary.text_section['size'] > 1000:
        add_finding(binary.name, HIGH, "Memory",
                   "NO stack canary protection",
                   "Binary tidak punya stack_chk_fail — stack buffer overflow tidak terdeteksi")

    for pattern, severity, category, detail in mem_patterns:
        if pattern in binary.data:
            if severity in [MEDIUM, HIGH]:
                count = binary.data.count(pattern)
                add_finding(binary.name, severity, category,
                           f"Memory: {pattern.decode()[:30]} ({count}x)", detail)


def scan_objc_methods(binary):
    """Scan for interesting Objective-C methods"""
    objc_patterns = [
        (b"performSelector:", MEDIUM, "ObjC", "performSelector — arbitrary method call"),
        (b"setValue:forKey:", MEDIUM, "ObjC", "KVC — can set private properties"),
        (b"valueForKey:", LOW, "ObjC", "KVC read — info disclosure"),
        (b"NSKeyedUnarchiver", HIGH, "Deserialization", "NSKeyedUnarchiver — deserialization attack"),
        (b"initWithCoder:", MEDIUM, "Deserialization", "NSCoding — object deserialization"),
        (b"NSSecureCoding", LOW, "Deserialization", "Secure coding (good)"),
        (b"evaluateJavaScript", HIGH, "WebView", "JavaScript evaluation — XSS/injection"),
        (b"stringByEvaluatingJavaScript", HIGH, "WebView", "JS eval in WebView"),
        (b"WKWebView", MEDIUM, "WebView", "WebView — web content rendering"),
        (b"UIWebView", HIGH, "WebView", "UIWebView (deprecated) — less secure than WKWebView"),
        (b"loadHTMLString", MEDIUM, "WebView", "Loads HTML — injection if user-controlled"),
        (b"NSURLConnection", MEDIUM, "Network", "NSURLConnection (deprecated)"),
        (b"allowsArbitraryLoads", HIGH, "ATS", "App Transport Security disabled"),
    ]

    for pattern, severity, category, detail in objc_patterns:
        if pattern in binary.data:
            count = binary.data.count(pattern)
            if count > 0:
                add_finding(binary.name, severity, category,
                           f"ObjC: {pattern.decode()[:40]} ({count}x)", detail)

def scan_auth_bypass(binary):
    """Scan for authentication/authorization bypass vectors"""
    auth_patterns = [
        (b"SecAccessControlCreateWithFlags", LOW, "Auth", "Biometric/passcode access control"),
        (b"LAContext", MEDIUM, "Auth", "LocalAuthentication — biometric bypass possible"),
        (b"evaluatePolicy", MEDIUM, "Auth", "Biometric evaluation — check error handling"),
        (b"kSecAttrAccessibleAlways", HIGH, "Keychain", "Keychain item accessible always — even locked"),
        (b"kSecAttrAccessibleAfterFirstUnlock", MEDIUM, "Keychain", "Accessible after first unlock"),
        (b"SecItemCopyMatching", LOW, "Keychain", "Keychain query"),
        (b"SecItemAdd", LOW, "Keychain", "Keychain add"),
        (b"kSecAttrAccessGroup", LOW, "Keychain", "Keychain access group"),
    ]

    for pattern, severity, category, detail in auth_patterns:
        if pattern in binary.data:
            add_finding(binary.name, severity, category,
                       f"Auth: {pattern.decode()[:40]}", detail)


def scan_url_schemes(binary):
    """Scan for URL scheme handlers (attack surface)"""
    # Look for URL scheme registrations
    url_patterns = [
        (b"CFBundleURLSchemes", MEDIUM, "URL Scheme", "Registers URL scheme — input from other apps"),
        (b"openURL:", MEDIUM, "URL Scheme", "Opens URL — can be triggered externally"),
        (b"handleOpenURL:", MEDIUM, "URL Scheme", "URL handler — validate input"),
        (b"application:openURL:", MEDIUM, "URL Scheme", "App delegate URL handler"),
        (b"universalLinks", LOW, "URL Scheme", "Universal links"),
    ]

    for pattern, severity, category, detail in url_patterns:
        if pattern in binary.data:
            add_finding(binary.name, severity, category,
                       f"URL: {pattern.decode()[:40]}", detail)


def scan_process_injection(binary):
    """Scan for process injection / code execution vectors"""
    inject_patterns = [
        (b"task_for_pid", CRITICAL, "Injection", "task_for_pid — full process control"),
        (b"thread_create", HIGH, "Injection", "Creates thread in target process"),
        (b"mach_vm_write", CRITICAL, "Injection", "Writes to other process memory"),
        (b"mach_vm_allocate", HIGH, "Injection", "Allocates in other process"),
        (b"DYLD_INSERT_LIBRARIES", HIGH, "Injection", "DYLD injection reference"),
        (b"ptrace", HIGH, "Debug", "ptrace — process debugging/tracing"),
        (b"PT_DENY_ATTACH", MEDIUM, "Anti-Debug", "Anti-debugging (PT_DENY_ATTACH)"),
        (b"sysctl", LOW, "Info", "sysctl — system info query"),
        (b"proc_info", MEDIUM, "Info", "Process info — enumerate processes"),
    ]

    for pattern, severity, category, detail in inject_patterns:
        if pattern in binary.data:
            count = binary.data.count(pattern)
            add_finding(binary.name, severity, category,
                       f"Inject: {pattern.decode()[:30]} ({count}x)", detail)


def scan_trust_cache_ops(binary):
    """Scan for trust cache related operations"""
    tc_patterns = [
        (b"trust_cache", HIGH, "Trust Cache", "Trust cache reference"),
        (b"amfi_load_trust_cache", CRITICAL, "Trust Cache", "amfi_load_trust_cache — can load TC"),
        (b"pmap_lookup_in_loaded_trust_caches", HIGH, "Trust Cache", "TC lookup function"),
        (b"load_trust_cache", CRITICAL, "Trust Cache", "Trust cache load function"),
        (b"personalize_trust_cache", HIGH, "Trust Cache", "TC personalization"),
        (b"query_trust_cache", MEDIUM, "Trust Cache", "TC query"),
        (b"CDHash", MEDIUM, "Code Signing", "CDHash reference"),
        (b"cdhash", MEDIUM, "Code Signing", "cdhash reference"),
        (b"cs_blob", MEDIUM, "Code Signing", "Code signature blob"),
        (b"MISValidateSignature", HIGH, "Code Signing", "MIS signature validation"),
        (b"SecStaticCode", MEDIUM, "Code Signing", "Static code validation"),
        (b"SecCodeCheckValidity", MEDIUM, "Code Signing", "Code validity check"),
    ]

    for pattern, severity, category, detail in tc_patterns:
        if pattern in binary.data:
            count = binary.data.count(pattern)
            add_finding(binary.name, severity, category,
                       f"TC/CS: {pattern.decode()[:40]} ({count}x)", detail)

def scan_arm64_patterns(binary):
    """ARM64 instruction pattern analysis for vulnerabilities"""
    if not HAS_CAPSTONE:
        return

    text_bytes, text_addr = binary.get_text_bytes()
    if not text_bytes or len(text_bytes) < 100:
        return

    # Limit disassembly to first 512KB to avoid timeout
    max_size = min(len(text_bytes), 512 * 1024)
    text_bytes = text_bytes[:max_size]

    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True

    # Track patterns
    unchecked_mallocs = 0
    stack_pivots = 0
    ret_gadgets = 0
    br_x_gadgets = []
    svc_calls = 0

    prev_insn = None
    for insn in md.disasm(text_bytes, text_addr):
        # SVC #0x80 — syscall (interesting for syscall fuzzing)
        if insn.mnemonic == "svc":
            svc_calls += 1

        # BR Xn — indirect branch (ROP/JOP gadget)
        if insn.mnemonic == "br" and insn.op_str.startswith("x"):
            br_x_gadgets.append((insn.address, insn.op_str))

        # RET — return gadget
        if insn.mnemonic == "ret":
            ret_gadgets += 1

        # Stack pivot: MOV SP, Xn
        if insn.mnemonic == "mov" and "sp" in insn.op_str and insn.op_str.startswith("sp"):
            stack_pivots += 1

        prev_insn = insn

    if svc_calls > 0:
        add_finding(binary.name, INFO, "Syscall",
                   f"ARM64: {svc_calls} SVC instructions (syscalls)",
                   "Direct syscalls — bypass libc wrappers")

    if len(br_x_gadgets) > 10:
        add_finding(binary.name, LOW, "Gadgets",
                   f"ARM64: {len(br_x_gadgets)} BR Xn gadgets",
                   f"Indirect branches — JOP gadgets. First: 0x{br_x_gadgets[0][0]:x} BR {br_x_gadgets[0][1]}")

    if stack_pivots > 0:
        add_finding(binary.name, MEDIUM, "Gadgets",
                   f"ARM64: {stack_pivots} stack pivot gadgets (MOV SP, Xn)",
                   "Stack pivot — useful for ROP chains")


def scan_kernelcache(kc_path):
    """Special analysis for kernelcache"""
    try:
        with open(kc_path, "rb") as f:
            data = f.read()
    except:
        return

    name = os.path.basename(kc_path)

    # Check if it's an IM4P container — scan payload inside
    if data[:4] == b"IM4P":
        # IM4P: magic(4) + type(4) + desc_len(4) + desc + data_len(4) + data
        # Skip header, find Mach-O or raw payload
        mach_idx = data.find(b"\xCF\xFA\xED\xFE")  # MH_MAGIC_64
        if mach_idx != -1:
            data = data[mach_idx:]
        else:
            # Scan raw payload for patterns
            pass

    # Check for known vulnerable patterns
    vuln_patterns = [
        (b"copyin", MEDIUM, "Kernel", "copyin — user→kernel copy, validate size"),
        (b"copyout", MEDIUM, "Kernel", "copyout — kernel→user copy, info leak"),
        (b"copyinstr", MEDIUM, "Kernel", "copyinstr — string from user, length check"),
        (b"IOUserClient", HIGH, "Kernel IOKit", "IOUserClient — kernel attack surface"),
        (b"externalMethod", HIGH, "Kernel IOKit", "externalMethod — IOKit method dispatch"),
        (b"getTargetAndMethodForIndex", HIGH, "Kernel IOKit", "Legacy IOKit dispatch"),
        (b"is_io_connect_method", HIGH, "Kernel IOKit", "IOKit connect method handler"),
        (b"kalloc", LOW, "Kernel", "kalloc — kernel heap allocation"),
        (b"kfree", LOW, "Kernel", "kfree — kernel heap free"),
        (b"zone_require", MEDIUM, "Kernel", "zone_require — zone isolation check"),
        (b"pmap_cs", HIGH, "Kernel", "pmap_cs — code signing enforcement"),
        (b"AMFI", HIGH, "Kernel", "AMFI references in kernel"),
        (b"trust_cache", HIGH, "Kernel", "Trust cache kernel code"),
        (b"proc_ucred", MEDIUM, "Kernel", "Process credentials"),
        (b"kauth_cred", MEDIUM, "Kernel", "Kernel auth credentials"),
        (b"mac_proc_check", MEDIUM, "Kernel MAC", "MAC policy check"),
        (b"sandbox_check", MEDIUM, "Kernel Sandbox", "Kernel sandbox check"),
    ]

    for pattern, severity, category, detail in vuln_patterns:
        count = data.count(pattern)
        if count > 0:
            add_finding(name, severity, category,
                       f"Kernel: {pattern.decode()[:30]} ({count}x)", detail)

    # Look for panic strings (indicates error paths we can trigger)
    panic_count = data.count(b"panic")
    if panic_count > 0:
        add_finding(name, INFO, "Kernel",
                   f"Kernel: {panic_count} panic references",
                   "Panic paths — some may be triggerable from userspace")

def scan_bootloader_firmware(binary):
    """Scan iBoot/iBEC/iBSS/LLB for bootloader-specific vulnerabilities"""
    boot_patterns = [
        (b"debug-uarts", HIGH, "Bootloader", "Debug UART — serial console access"),
        (b"debug-enabled", CRITICAL, "Bootloader", "Debug enabled flag — full debug access"),
        (b"production-fused", MEDIUM, "Bootloader", "Production fuse check"),
        (b"development-fused", HIGH, "Bootloader", "Development fuse reference"),
        (b"boot-command", MEDIUM, "Bootloader", "Boot command string"),
        (b"upgrade", MEDIUM, "Bootloader", "Upgrade path"),
        (b"fsboot", MEDIUM, "Bootloader", "Filesystem boot"),
        (b"diags", HIGH, "Bootloader", "Diagnostics mode — special boot"),
        (b"restore", MEDIUM, "Bootloader", "Restore mode"),
        (b"usb-", MEDIUM, "Bootloader", "USB interface reference"),
        (b"serial-number", LOW, "Bootloader", "Serial number"),
        (b"nonce", HIGH, "Bootloader", "Nonce — anti-replay, downgrade protection"),
        (b"ticket", HIGH, "Bootloader", "APTicket — SHSH blob validation"),
        (b"img4", HIGH, "Bootloader", "IMG4 validation — boot chain trust"),
        (b"manifest", MEDIUM, "Bootloader", "Manifest validation"),
        (b"BNCH", HIGH, "Bootloader", "Boot nonce hash — downgrade vector"),
        (b"ECID", MEDIUM, "Bootloader", "ECID — device unique ID"),
        (b"CHIP", LOW, "Bootloader", "Chip ID reference"),
        (b"BORD", LOW, "Bootloader", "Board ID reference"),
        (b"SEPO", HIGH, "Bootloader", "SEP OS version — SEP downgrade?"),
        (b"krnl", HIGH, "Bootloader", "Kernel reference in bootloader"),
        (b"trst", HIGH, "Bootloader", "Trust reference — trust chain"),
        (b"AMNM", MEDIUM, "Bootloader", "AMFI/AMNM reference"),
        (b"cert", MEDIUM, "Bootloader", "Certificate reference"),
        (b"sha2", LOW, "Bootloader", "SHA256 reference"),
        (b"aes", MEDIUM, "Bootloader", "AES encryption reference"),
        (b"gid", HIGH, "Bootloader", "GID key reference — device group key"),
        (b"uid", HIGH, "Bootloader", "UID key reference — device unique key"),
        (b"demotion", CRITICAL, "Bootloader", "Demotion — security downgrade!"),
        (b"demote", CRITICAL, "Bootloader", "Demote reference — security level change"),
        (b"allow-mix-and-match", CRITICAL, "Bootloader", "Mix-and-match — component version bypass"),
        (b"skip-fcs-check", CRITICAL, "Bootloader", "Skip FCS check — bypass validation"),
        (b"force-dfu", HIGH, "Bootloader", "Force DFU — recovery mode trigger"),
        (b"nvram", MEDIUM, "Bootloader", "NVRAM access — persistent storage"),
        (b"boot-args", HIGH, "Bootloader", "Boot arguments — kernel boot params"),
        (b"cs_enforcement_disable", CRITICAL, "Bootloader", "Code signing disable flag!"),
        (b"amfi_get_out_of_my_way", CRITICAL, "Bootloader", "AMFI disable boot-arg!"),
        (b"PE_i_can_has_debugger", HIGH, "Bootloader", "Debugger enable check"),
    ]

    for pattern, severity, category, detail in boot_patterns:
        if pattern in binary.data:
            count = binary.data.count(pattern)
            add_finding(binary.name, severity, category,
                       f"Boot: {pattern.decode('ascii', errors='replace')[:30]} ({count}x)", detail)


def scan_interesting_strings(binary):
    """Find interesting strings that reveal attack surface"""

    # Special handling for firmware files (iBoot, iBEC, etc)
    name_lower = binary.name.lower()
    if any(x in name_lower for x in ['iboot', 'ibec', 'ibss', 'llb', 'sep']):
        scan_bootloader_firmware(binary)

    interesting = [
        (b"AAAA", MEDIUM, "Fuzzing", "Potential test/debug pattern left in"),
        (b"TODO", LOW, "Code Quality", "TODO comment — incomplete implementation"),
        (b"FIXME", MEDIUM, "Code Quality", "FIXME — known bug"),
        (b"HACK", MEDIUM, "Code Quality", "HACK comment — workaround"),
        (b"DEBUG", LOW, "Debug", "Debug reference"),
        (b"test", LOW, "Debug", "Test reference"),
        (b"/usr/lib/log", LOW, "Logging", "Logging library"),
        (b"com.apple.private", MEDIUM, "Private API", "Private API usage"),
        (b"_OBJC_CLASS_$_", LOW, "ObjC", "ObjC class"),
        (b"root", LOW, "Privilege", "Root reference"),
        (b"sudo", MEDIUM, "Privilege", "Sudo reference"),
        (b"jailbreak", HIGH, "Jailbreak", "Jailbreak detection/reference"),
        (b"Cydia", HIGH, "Jailbreak", "Cydia reference — jailbreak detection"),
        (b"substrate", HIGH, "Jailbreak", "Substrate reference"),
        (b"/bin/sh", HIGH, "Shell", "Shell path — command execution"),
        (b"/bin/bash", HIGH, "Shell", "Bash path — command execution"),
        (b"/usr/bin/ssh", MEDIUM, "Shell", "SSH reference"),
        (b"SIGKILL", LOW, "Signal", "SIGKILL reference"),
        (b"SIGSTOP", LOW, "Signal", "SIGSTOP reference"),
    ]

    for pattern, severity, category, detail in interesting:
        if pattern in binary.data:
            if severity in [HIGH, CRITICAL, MEDIUM]:
                count = binary.data.count(pattern)
                add_finding(binary.name, severity, category,
                           f"String: {pattern.decode()[:30]} ({count}x)", detail)


def scan_safari_webkit(binary):
    """Scan for WebKit/Safari specific vulnerabilities"""
    webkit_patterns = [
        (b"WebKit", MEDIUM, "WebKit", "WebKit framework usage"),
        (b"JavaScriptCore", HIGH, "WebKit", "JavaScriptCore — JIT engine"),
        (b"WKWebView", MEDIUM, "WebKit", "WKWebView — web content"),
        (b"JSContext", HIGH, "WebKit", "JSContext — JavaScript execution"),
        (b"JSValue", MEDIUM, "WebKit", "JSValue — JS↔Native bridge"),
        (b"evaluateScript", HIGH, "WebKit", "Script evaluation"),
        (b"userContentController", MEDIUM, "WebKit", "User content controller — message handler"),
        (b"WKScriptMessage", MEDIUM, "WebKit", "Script message — JS→Native bridge"),
        (b"decidePolicyForNavigationAction", MEDIUM, "WebKit", "Navigation policy — URL filtering"),
        (b"file://", HIGH, "WebKit", "file:// URL — local file access"),
        (b"javascript:", HIGH, "WebKit", "javascript: URL — XSS vector"),
        (b"data:", MEDIUM, "WebKit", "data: URL — content injection"),
        (b"blob:", MEDIUM, "WebKit", "blob: URL"),
        (b"SFSafariViewController", LOW, "Safari", "Safari view controller"),
        (b"SafariServices", LOW, "Safari", "Safari services framework"),
    ]

    for pattern, severity, category, detail in webkit_patterns:
        if pattern in binary.data:
            count = binary.data.count(pattern)
            if count > 0:
                add_finding(binary.name, severity, category,
                           f"WebKit: {pattern.decode()[:40]} ({count}x)", detail)


def scan_dyld_issues(binary):
    """Scan for dyld-related vulnerabilities"""
    dyld_patterns = [
        (b"DYLD_", HIGH, "DYLD", "DYLD environment variable reference"),
        (b"dyld_shared_cache", MEDIUM, "DYLD", "Shared cache reference"),
        (b"_dyld_register_func_for_add_image", MEDIUM, "DYLD", "Image load callback"),
        (b"dlopen", MEDIUM, "DYLD", "Dynamic library loading"),
        (b"dlsym", LOW, "DYLD", "Dynamic symbol lookup"),
        (b"NSBundle", LOW, "DYLD", "Bundle loading"),
        (b"@rpath", LOW, "DYLD", "Relative path — dylib hijacking possible"),
        (b"@loader_path", MEDIUM, "DYLD", "Loader path — hijacking if writable"),
        (b"LC_RPATH", MEDIUM, "DYLD", "RPATH in binary — check if writable dirs"),
    ]

    for pattern, severity, category, detail in dyld_patterns:
        if pattern in binary.data:
            count = binary.data.count(pattern)
            if severity in [HIGH, MEDIUM]:
                add_finding(binary.name, severity, category,
                           f"DYLD: {pattern.decode()[:30]} ({count}x)", detail)

def scan_privilege_escalation(binary):
    """Scan for privilege escalation vectors"""
    priv_patterns = [
        (b"setuid(0)", CRITICAL, "Privilege", "setuid(0) — becomes root"),
        (b"seteuid", HIGH, "Privilege", "seteuid — effective UID change"),
        (b"setreuid", HIGH, "Privilege", "setreuid — real/effective UID change"),
        (b"initgroups", MEDIUM, "Privilege", "initgroups — group membership change"),
        (b"AuthorizationCreate", MEDIUM, "Privilege", "macOS authorization"),
        (b"SecTaskCopyValueForEntitlement", LOW, "Privilege", "Entitlement check"),
        (b"audit_token", LOW, "Privilege", "Audit token — caller identification"),
        (b"posix_spawnattr_setflags", MEDIUM, "Privilege", "Spawn attribute flags"),
        (b"POSIX_SPAWN_SETEXEC", MEDIUM, "Privilege", "SETEXEC flag — replace process"),
        (b"persona", MEDIUM, "Privilege", "Persona — identity manipulation"),
    ]

    for pattern, severity, category, detail in priv_patterns:
        if pattern in binary.data:
            count = binary.data.count(pattern)
            add_finding(binary.name, severity, category,
                       f"Priv: {pattern.decode()[:30]} ({count}x)", detail)


def scan_data_validation(binary):
    """Scan for input validation issues"""
    # Look for integer overflow patterns
    val_patterns = [
        (b"atoi", MEDIUM, "Input", "atoi() — no overflow check, no error handling"),
        (b"atol", MEDIUM, "Input", "atol() — no overflow check"),
        (b"strtol", LOW, "Input", "strtol — better but check errno"),
        (b"sscanf", MEDIUM, "Input", "sscanf — format string parsing"),
        (b"NSJSONSerialization", LOW, "Input", "JSON parsing"),
        (b"NSPropertyListSerialization", MEDIUM, "Input", "Plist parsing — complex format"),
        (b"XMLParser", MEDIUM, "Input", "XML parsing — XXE possible"),
        (b"NSXMLParser", MEDIUM, "Input", "XML parsing — XXE, billion laughs"),
        (b"CFPropertyListCreateWithData", MEDIUM, "Input", "CF plist parsing"),
    ]

    for pattern, severity, category, detail in val_patterns:
        if pattern in binary.data:
            count = binary.data.count(pattern)
            if count > 0:
                add_finding(binary.name, severity, category,
                           f"Input: {pattern.decode()[:30]} ({count}x)", detail)


# ============================================================
# TRUST CACHE ANALYSIS
# ============================================================

def analyze_trust_caches():
    """Analyze trust cache files for structure and potential manipulation"""
    tc_dir = IPSW_DIR / "Firmware"
    tc_files = list(tc_dir.glob("*.trustcache"))

    for tc_file in tc_files:
        try:
            with open(tc_file, "rb") as f:
                data = f.read()
        except:
            continue

        name = tc_file.name

        if len(data) < 24:
            add_finding(name, INFO, "Trust Cache", "Too small", f"Size: {len(data)} bytes")
            continue

        # Parse trust cache header
        # Could be IMG4 wrapped or raw
        if data[:4] == b"IM4P":
            add_finding(name, INFO, "Trust Cache",
                       f"IMG4 wrapped trust cache ({len(data)} bytes)",
                       "Wrapped in IMG4 container — needs unwrap for analysis")
            # Try to find raw TC inside
            tc_marker = data.find(b"\x02\x00\x00\x00")  # version=2
            if tc_marker != -1 and tc_marker + 24 < len(data):
                version = struct.unpack_from("<I", data, tc_marker)[0]
                if version == 2:
                    uuid_bytes = data[tc_marker+4:tc_marker+20]
                    count = struct.unpack_from("<I", data, tc_marker+20)[0]
                    add_finding(name, MEDIUM, "Trust Cache",
                               f"TC v2: {count} entries, UUID={uuid_bytes.hex()[:16]}...",
                               f"Trust cache with {count} CDHash entries — "
                               f"if we can add entries here, unsigned code runs")
        else:
            # Raw trust cache
            version = struct.unpack_from("<I", data, 0)[0]
            if version == 1 or version == 2:
                count = struct.unpack_from("<I", data, 20)[0]
                add_finding(name, MEDIUM, "Trust Cache",
                           f"Raw TC v{version}: {count} entries ({len(data)} bytes)",
                           "Raw trust cache — structure known, injection target")

# ============================================================
# MAIN EXECUTION
# ============================================================

def try_decompress_im4p(data):
    """Try to decompress LZFSE payload from IM4P container"""
    try:
        from imagecodecs import lzfse_decode
    except ImportError:
        return None

    # Find LZFSE magic (bvx2)
    bvx2_idx = data.find(b'bvx2')
    if bvx2_idx == -1:
        return None

    compressed = data[bvx2_idx:]
    try:
        decompressed = lzfse_decode(compressed)
        if len(decompressed) > 100:
            return decompressed
    except Exception:
        pass
    return None


def analyze_binary(path):
    """Full analysis of a single binary"""
    binary = MachOBinary(path)
    if not binary.parse():
        # Not Mach-O — but might be firmware (IM4P, raw ARM, etc)
        name_lower = binary.name.lower()
        is_firmware = any(x in name_lower for x in [
            'iboot', 'ibec', 'ibss', 'llb', 'sep', 'savage', 'yonkers',
            'stockholm', 'aop', 'ane', 'ave', 'agx', 'callan', 'multitouch',
            'smartio', 'wirelesspower', 'vinyl', 'bbfw', 'adc-petra'
        ]) or name_lower.endswith(('.im4p', '.fw', '.sefw', '.bbfw', '.vnlfw'))

        if is_firmware and len(binary.data) > 100:
            print(f"  Firmware scan: {binary.name} ({len(binary.data)} bytes)")
            # Try LZFSE decompression for IM4P files
            decompressed = try_decompress_im4p(binary.data)
            if decompressed and len(decompressed) > len(binary.data):
                print(f"    Decompressed: {len(decompressed)} bytes")
                # Replace data with decompressed for scanning
                binary.data = decompressed
            scan_bootloader_firmware(binary)
            scan_crypto_issues(binary)
            return

        add_finding(os.path.basename(path), INFO, "Parse",
                   "Not a valid Mach-O binary", f"Path: {path}")
        return

    print(f"  Analyzing: {binary.name} ({len(binary.data)} bytes, "
          f"{len(binary.segments)} segments, {len(binary.imports)} imports)")

    # Run all scanners
    scan_dangerous_functions(binary)
    scan_xpc_vulnerabilities(binary)
    scan_sandbox_issues(binary)
    scan_entitlements(binary)
    scan_crypto_issues(binary)
    scan_ipc_mach(binary)
    scan_iokit_surface(binary)
    scan_network_surface(binary)
    scan_file_operations(binary)
    scan_memory_issues(binary)
    scan_objc_methods(binary)
    scan_auth_bypass(binary)
    scan_url_schemes(binary)
    scan_process_injection(binary)
    scan_trust_cache_ops(binary)
    scan_interesting_strings(binary)
    scan_safari_webkit(binary)
    scan_dyld_issues(binary)
    scan_privilege_escalation(binary)
    scan_data_validation(binary)

    # ARM64 disassembly (only if capstone available and binary not too large)
    if HAS_CAPSTONE and binary.text_section and binary.text_section['size'] < 2 * 1024 * 1024:
        scan_arm64_patterns(binary)


def main():
    global findings
    print("=" * 70)
    print("MASS REVERSE ENGINEERING — iPhone11,8 iOS 18.2 (22C152)")
    print("=" * 70)
    print()

    # Collect all binaries to analyze
    binaries = []

    # 1. Extracted binaries
    print("[1/4] Collecting extracted binaries...")
    for root, dirs, files in os.walk(EXTRACTED_DIR):
        for f in files:
            path = os.path.join(root, f)
            binaries.append(path)

    # 2. Kernelcache
    kc_path = IPSW_DIR / "kernelcache.release.iphone11b"
    if kc_path.exists():
        print("[2/4] Adding kernelcache...")
        binaries.append(str(kc_path))

    # 3. ALL firmware files (iBoot, iBEC, iBSS, LLB, SEP, AGX, ANE, AVE, AOP, etc)
    print("[3/4] Adding ALL firmware files...")
    fw_dir = IPSW_DIR / "Firmware"
    if fw_dir.exists():
        for root_dir, dirs, files in os.walk(fw_dir):
            for f in files:
                if f.endswith(('.im4p', '.fw', '.sefw', '.bbfw', '.vnlfw')):
                    binaries.append(os.path.join(root_dir, f))

    # 4. Trust caches
    print("[4/4] Analyzing trust caches...")
    analyze_trust_caches()

    print(f"\nTotal binaries to analyze: {len(binaries)}")
    print()

    # Analyze each binary
    for i, path in enumerate(binaries):
        name = os.path.basename(path)
        print(f"[{i+1}/{len(binaries)}] {name}...")

        if "kernelcache" in name.lower():
            scan_kernelcache(path)
        else:
            analyze_binary(path)

    # Generate report
    print(f"\n{'=' * 70}")
    print(f"ANALYSIS COMPLETE — {len(findings)} findings")
    print(f"{'=' * 70}")

    # Sort by severity
    severity_order = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4}
    findings.sort(key=lambda f: (severity_order.get(f.severity, 5), f.binary))

    # Write output
    with open(OUTPUT_FILE, "w", encoding="utf-8") as out:
        out.write("=" * 80 + "\n")
        out.write("MASS REVERSE ENGINEERING REPORT\n")
        out.write(f"iPhone11,8 — iOS 18.2 (22C152) — {len(binaries)} binaries analyzed\n")
        out.write(f"Date: 2026-05-21\n")
        out.write("=" * 80 + "\n\n")

        # Summary
        counts = defaultdict(int)
        for f in findings:
            counts[f.severity] += 1

        out.write("SUMMARY\n")
        out.write("-" * 40 + "\n")
        out.write(f"  CRITICAL: {counts[CRITICAL]}\n")
        out.write(f"  HIGH:     {counts[HIGH]}\n")
        out.write(f"  MEDIUM:   {counts[MEDIUM]}\n")
        out.write(f"  LOW:      {counts[LOW]}\n")
        out.write(f"  INFO:     {counts[INFO]}\n")
        out.write(f"  TOTAL:    {len(findings)}\n\n")

        # Findings by severity
        for severity in [CRITICAL, HIGH, MEDIUM, LOW, INFO]:
            sev_findings = [f for f in findings if f.severity == severity]
            if not sev_findings:
                continue

            out.write(f"\n{'=' * 80}\n")
            out.write(f"[{severity}] — {len(sev_findings)} findings\n")
            out.write(f"{'=' * 80}\n\n")

            # Group by binary
            by_binary = defaultdict(list)
            for f in sev_findings:
                by_binary[f.binary].append(f)

            for binary_name in sorted(by_binary.keys()):
                out.write(f"--- {binary_name} ---\n")
                for f in by_binary[binary_name]:
                    out.write(f"  [{f.category}] {f.title}\n")
                    out.write(f"    → {f.detail}\n")
                out.write("\n")

        # Exploitation recommendations
        out.write("\n" + "=" * 80 + "\n")
        out.write("EXPLOITATION RECOMMENDATIONS\n")
        out.write("=" * 80 + "\n\n")

        # Find most promising targets
        critical_binaries = set(f.binary for f in findings if f.severity == CRITICAL)
        high_binaries = set(f.binary for f in findings if f.severity == HIGH)

        out.write("Most promising targets (CRITICAL findings):\n")
        for b in sorted(critical_binaries):
            crits = [f for f in findings if f.binary == b and f.severity == CRITICAL]
            out.write(f"  • {b}: {len(crits)} critical issues\n")
            for c in crits[:5]:
                out.write(f"    - {c.title}\n")
        out.write("\n")

        out.write("High-value targets (HIGH findings):\n")
        for b in sorted(high_binaries):
            highs = [f for f in findings if f.binary == b and f.severity == HIGH]
            out.write(f"  • {b}: {len(highs)} high issues\n")
            for h in highs[:3]:
                out.write(f"    - {h.title}\n")
        out.write("\n")

        # Specific attack vectors
        out.write("\nATTACK VECTORS FOR JAILBREAK:\n")
        out.write("-" * 40 + "\n")

        xpc_findings = [f for f in findings if "XPC" in f.category and f.severity in [CRITICAL, HIGH]]
        if xpc_findings:
            out.write("\n1. XPC Service Attacks:\n")
            for f in xpc_findings[:10]:
                out.write(f"   [{f.binary}] {f.title}\n")

        tc_findings = [f for f in findings if "Trust Cache" in f.category]
        if tc_findings:
            out.write("\n2. Trust Cache Manipulation:\n")
            for f in tc_findings[:10]:
                out.write(f"   [{f.binary}] {f.title}\n")

        iokit_findings = [f for f in findings if "IOKit" in f.category and f.severity in [CRITICAL, HIGH]]
        if iokit_findings:
            out.write("\n3. IOKit Kernel Attack Surface:\n")
            for f in iokit_findings[:10]:
                out.write(f"   [{f.binary}] {f.title}\n")

        inject_findings = [f for f in findings if "Injection" in f.category]
        if inject_findings:
            out.write("\n4. Process Injection:\n")
            for f in inject_findings[:10]:
                out.write(f"   [{f.binary}] {f.title}\n")

        ent_findings = [f for f in findings if "Entitlement" in f.category and f.severity == CRITICAL]
        if ent_findings:
            out.write("\n5. Critical Entitlements (abuse targets):\n")
            for f in ent_findings[:15]:
                out.write(f"   [{f.binary}] {f.title}\n")

        out.write("\n\n" + "=" * 80 + "\n")
        out.write("END OF REPORT\n")
        out.write("=" * 80 + "\n")

    print(f"\nOutput written to: {OUTPUT_FILE}")
    print(f"Critical: {counts[CRITICAL]}, High: {counts[HIGH]}, "
          f"Medium: {counts[MEDIUM]}, Low: {counts[LOW]}")


if __name__ == "__main__":
    main()
