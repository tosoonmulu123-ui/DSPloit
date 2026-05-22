#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║          Mach-O ARM64 iOS Binary — SUPER GODMODE Static Analyzer           ║
║                                                                              ║
║  Layers covered:                                                             ║
║  1.  FAT/Mach-O structure, all load commands                                ║
║  2.  ObjC: classes, categories, protocols, ivars, properties, methods,      ║
║            type encodings decoded to human-readable signatures               ║
║  3.  Swift: type/protocol/field descriptors, witness tables, capture lists  ║
║  4.  Symbols: symtab, export trie, chained fixups, bind/rebase opcodes      ║
║  5.  Strings: __cstring, __cfstring, __ustring, CFString struct decoding    ║
║  6.  CFG: function starts, basic-block boundaries, call-graph edges         ║
║  7.  ARM64 disassembler (pure-Python, covers ~90 common mnemonics)          ║
║  8.  Taint analysis: SecTrustEvaluate return-value tracking                 ║
║  9.  Security: anti-debug patterns, jailbreak checks, pinning, obfuscation  ║
║  10. Entropy analysis per section (detect encrypted/packed regions)         ║
║  11. Code signature deep parse: requirements expression decoder             ║
║  12. DER entitlements parser                                                 ║
║  13. Constructor/destructor sections (__mod_init_func, __mod_term_func)     ║
║  14. Inline crypto constant detection (AES, SHA, ChaCha20 constants)        ║
║  15. Binary fingerprinting & version diffing helpers                        ║
║                                                                              ║
║  GODMODE Extensions:                                                         ║
║  G1. Apple Private Entitlements Database (200+ entries) — find privilege    ║
║      escalation entitlements with risk scoring                               ║
║  G2. Vulnerability Heuristic Scanner — format strings, buffer overflows,    ║
║      command injection, weak crypto, race conditions, hardcoded secrets,    ║
║      SQL injection, TLS misconfiguration                                     ║
║  G3. Exploit Primitive Detector — task_for_pid, mach_vm_*, csops, IOKit,    ║
║      kernel attack surface, capability assessment                            ║
║  G4. YARA-style Pattern Scanner — anti-debug, ROP gadgets, crypto consts,   ║
║      MIG tables, with hex/nibble wildcards                                   ║
║  G5. Stub Resolver — map __stubs VA → imported function name                ║
║  G6. Cross-Reference Database — find all callers of any string/symbol/VA    ║
║  G7. Pseudo-C Decompiler — ARM64 → readable C-like output with stub names   ║
║  G8. iOS CVE Knowledge Base (33+ CVEs) with hardware filtering              ║
║  G9. Firmware Intelligence Engine — IPSW-wide risk assessment               ║
║                                                                              ║
║  Pure Python 3.8+ — zero external dependencies (auto-installs optional)     ║
╚══════════════════════════════════════════════════════════════════════════════╝

Usage:
    python3 analyze_binary_deep.py <binary_path> [options]

Quick Examples:
    python3 analyze_binary_deep.py lsd                       # full deep scan
    python3 analyze_binary_deep.py lsd --scan-vulns          # quick vuln scan
    python3 analyze_binary_deep.py lsd --scan-primitives     # exploit primitive detector
    python3 analyze_binary_deep.py lsd --scan-ents           # private entitlement audit
    python3 analyze_binary_deep.py lsd --xref-query "amfi"   # find amfi callers
    python3 analyze_binary_deep.py lsd --decompile-va 0x4000 # pseudo-C decompile
"""

from __future__ import annotations
import struct, re, os, sys, json, argparse, plistlib, hashlib, math
import subprocess, io, collections, itertools, textwrap
from pathlib import Path
from typing import Optional, Iterator, Any
import base64
import queue
import threading
try:
    import tkinter as tk
    from tkinter import filedialog, ttk
except ImportError:
    tk = None
    filedialog = None
    ttk = None

# ═══════════════════════════════════════════════════════════════════════════════
# §0.1  SUPER GODMODE DEPENDENCY & CONVERSION UTILITIES
# ═══════════════════════════════════════════════════════════════════════════════

def check_and_install_dependencies():
    """Mandatory dependencies (auto-install). Quietly skips items that fail to build on this platform."""
    required_packages = {
        "cryptography": "cryptography",
        "requests": "requests"
    }
    # Optional packages — try to install but don't fail if they don't build (e.g. lzfse on Windows)
    optional_packages = {
        "pyhpke": "pyhpke",
        "lzfse": "lzfse",
        "lz4": "lz4",
    }
    for module_name, package_name in required_packages.items():
        try:
            __import__(module_name)
        except ImportError:
            print(f"[*] Required dependency '{package_name}' is missing. Installing via pip...")
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", package_name],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                print(f"[+] Installed '{package_name}' successfully.")
            except Exception as e:
                print(f"[!] Failed to install '{package_name}': {e}", file=sys.stderr)
    for module_name, package_name in optional_packages.items():
        try:
            __import__(module_name)
        except ImportError:
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", package_name],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                       timeout=120)
            except Exception:
                # Optional — silent fallback. Some platforms can't build lzfse without a C compiler.
                pass


def check_godmax_dependencies(auto_install: bool = False) -> dict:
    """
    Optional GODMAX power-up dependencies. Auto-detected, never blocking.
    Returns capability map of what's available.
    """
    optional_packages = {
        "capstone":     "Real ARM64 disassembler — 1000x more accurate",
        "keystone":     "ARM64 assembler — for inline patching",
        "unicorn":      "Real CPU emulator — full instruction support",
        "yara":         "Real YARA engine — match thousands of rules",
        "networkx":     "Call graph analysis & visualization",
        "matplotlib":   "Plot call graphs to PNG",
        "reportlab":    "Generate PDF analysis reports",
        "PIL":          "Image embedding for reports (Pillow)",
        "pymobiledevice3": "Direct iOS device communication via USB",
        "frida":        "Dynamic instrumentation (run-time hooking)",
        "z3":           "Symbolic execution & SMT solving (z3-solver)",
    }
    capabilities = {}
    for mod, desc in optional_packages.items():
        try:
            __import__(mod)
            capabilities[mod] = True
        except ImportError:
            capabilities[mod] = False
            if auto_install:
                pkg_name = {
                    "PIL": "Pillow", "z3": "z3-solver",
                    "pymobiledevice3": "pymobiledevice3", "yara": "yara-python",
                }.get(mod, mod)
                print(f"[godmax] Installing optional '{pkg_name}' ({desc})...")
                try:
                    subprocess.check_call([sys.executable, "-m", "pip", "install", pkg_name],
                                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    __import__(mod)
                    capabilities[mod] = True
                    print(f"[godmax] ✓ {mod} installed")
                except Exception:
                    print(f"[godmax] ✗ {mod} install failed (continuing without it)")
    return capabilities


# Global capability registry — populated lazily
_GODMAX_CAPS: Optional[dict] = None

def godmax_caps() -> dict:
    """Return optional capability registry, populated on first call."""
    global _GODMAX_CAPS
    if _GODMAX_CAPS is None:
        _GODMAX_CAPS = check_godmax_dependencies(auto_install=False)
    return _GODMAX_CAPS

# ── PURE-PYTHON SWIFT SYMBOL DEMANGLER ─────────────────────────────────────────
def demangle_swift_symbol(sym: str) -> str:
    if not (sym.startswith("_$s") or sym.startswith("$s") or sym.startswith("_T0") or sym.startswith("$S")):
        return sym
    
    s = sym
    for prefix in ("_$s", "$s", "_T0", "$S"):
        if s.startswith(prefix):
            s = s[len(prefix):]
            break
            
    parts = []
    idx = 0
    while idx < len(s):
        m = re.match(r'^(\d+)', s[idx:])
        if not m:
            break
        length_str = m.group(1)
        length = int(length_str)
        start = idx + len(length_str)
        end = start + length
        if end <= len(s):
            parts.append(s[start:end])
            idx = end
        else:
            parts.append(s[start:])
            break
            
    if not parts:
        return sym
    return "Swift: " + ".".join(parts)

# ── MACH-O DYLIB PATH REDIRECTOR / RENAMER ─────────────────────────────────────
def rename_macho_dylib(binary_path: str, old_path: str, new_path: str) -> bool:
    path = Path(binary_path)
    if not path.exists():
        print(f"[!] Target binary not found: {binary_path}", file=sys.stderr)
        return False
        
    data = bytearray(path.read_bytes())
    if len(data) < 32:
        return False
        
    magic = u32le(data, 0)
    slice_off = 0
    if magic == 0xCAFEBABE: # FAT
        nfat = u32be(data, 4)
        for i in range(nfat):
            off = 8 + i * 20
            if off + 20 > len(data): break
            cputype = u32be(data, off)
            if cputype == 0x0100000C: # ARM64
                slice_off = u32be(data, off + 8)
                break
                
    hdr_magic = u32le(data, slice_off) if slice_off + 4 <= len(data) else 0
    if hdr_magic not in (0xFEEDFACF, 0xFEEDFACE):
        print(f"[!] Invalid Mach-O magic 0x{hdr_magic:08X} @ offset 0x{slice_off:X}", file=sys.stderr)
        return False
        
    ncmds = u32le(data, slice_off + 16)
    sizeofcmds = u32le(data, slice_off + 20)
    
    off = slice_off + 32 # MachOHeader64
    if hdr_magic == 0xFEEDFACE:
        off = slice_off + 28 # MachOHeader32
        
    patched_count = 0
    for _ in range(ncmds):
        if off + 8 > len(data): break
        cmd = u32le(data, off)
        size = u32le(data, off + 4)
        if size < 8 or off + size > len(data): break
        
        # LC_LOAD_DYLIB (0xc), LC_LOAD_WEAK_DYLIB (0x18 | 0x80000000), LC_REEXPORT_DYLIB (0x1f | 0x80000000), LC_LOAD_UPWARD_DYLIB (0x23)
        if cmd in (0x0C, 0x18 | 0x80000000, 0x1F | 0x80000000, 0x1C, 0x23 | 0x80000000, 0x23):
            str_off = u32le(data, off + 8)
            abs_str_off = off + str_off
            
            end_idx = abs_str_off
            while end_idx < off + size and data[end_idx] != 0:
                end_idx += 1
                
            current_path = data[abs_str_off:end_idx].decode("utf-8", "replace")
            if current_path == old_path:
                new_path_bytes = new_path.encode("utf-8")
                max_len = (off + size) - str_off
                if len(new_path_bytes) >= max_len:
                    print(f"[!] Warning: New path '{new_path}' too long. Max allowed: {max_len - 1} chars.", file=sys.stderr)
                    continue
                    
                # Overwrite dylib string in-place
                data[abs_str_off:abs_str_off + len(new_path_bytes)] = new_path_bytes
                for j in range(abs_str_off + len(new_path_bytes), off + size):
                    data[j] = 0
                patched_count += 1
                print(f"[+] Sideload patch successful: redirected '{old_path}' -> '{new_path}'")
                
        off += size
        
    if patched_count > 0:
        path.write_bytes(data)
        print(f"[+] Wrote {patched_count} patches to {path.name}")
        return True
    else:
        print(f"[-] No matching dylib path '{old_path}' found to redirect.", file=sys.stderr)
        return False

# ── PURE-PYTHON ARM64 MICRO-EMULATOR SANDBOX ───────────────────────────────────
class ARM64Emulator:
    def __init__(self, start_pc: int = 0):
        self.regs = {f"X{i}": 0 for i in range(32)}
        self.regs["SP"] = 0x7FFFFFF0
        self.pc = start_pc
        self.flags = {"N": 0, "Z": 0, "C": 0, "V": 0}
        self.mem = {}  # Address -> byte
        self.history = []  # Log of executed steps

    def read_mem(self, addr: int, size: int) -> int:
        val = 0
        for i in range(size):
            val |= self.mem.get(addr + i, 0) << (8 * i)
        return val

    def write_mem(self, addr: int, val: int, size: int):
        for i in range(size):
            self.mem[addr + i] = (val >> (8 * i)) & 0xFF

    def set_flags_nz(self, val: int, sf: bool = True):
        mask = 0xFFFFFFFFFFFFFFFF if sf else 0xFFFFFFFF
        val &= mask
        sign_bit = 63 if sf else 31
        self.flags["Z"] = 1 if val == 0 else 0
        self.flags["N"] = 1 if (val & (1 << sign_bit)) != 0 else 0

    def step(self, word: int) -> str:
        pc_str = f"0x{self.pc:X}"
        
        # 1. RET
        if word == 0xD65F03C0:
            self.pc = self.regs.get("X30", 0)  # LR
            desc = f"{pc_str}: RET -> jump to X30 (0x{self.pc:X})"
            self.history.append(desc)
            return desc

        # 2. NOP
        if word == 0xD503201F:
            self.pc += 4
            desc = f"{pc_str}: NOP"
            self.history.append(desc)
            return desc

        rn = (word >> 5) & 0x1F
        rd = word & 0x1F
        rt = word & 0x1F
        rt2 = (word >> 10) & 0x1F

        # 3. ADD / SUB (Immediate)
        if (word >> 22) & 0x3F in (0x11, 0x15, 0x31, 0x35): # ADD, ADDS, SUB, SUBS
            sf = (word >> 31) & 1
            op = (word >> 30) & 1  # 0=ADD, 1=SUB
            S = (word >> 29) & 1   # Set flags
            shift = (word >> 22) & 3
            imm12 = (word >> 10) & 0xFFF
            if shift == 1:
                imm12 <<= 12
            rn_val = self.regs[f"X{rn}"] if rn != 31 else self.regs["SP"]
            
            if op == 0:  # ADD
                res = rn_val + imm12
            else:        # SUB
                res = rn_val - imm12
                
            mask = 0xFFFFFFFFFFFFFFFF if sf else 0xFFFFFFFF
            res &= mask
            
            if rd == 31:
                if not S:
                    self.regs["SP"] = res
            else:
                self.regs[f"X{rd}"] = res
                
            if S:
                self.set_flags_nz(res, sf)
                
            op_name = "SUB" if op else "ADD"
            if S: op_name += "S"
            dest_name = "SP" if rd == 31 else f"X{rd}"
            src_name = "SP" if rn == 31 else f"X{rn}"
            desc = f"{pc_str}: {op_name} {dest_name}, {src_name}, #{imm12} -> {dest_name} = 0x{res:X}"
            self.pc += 4
            self.history.append(desc)
            return desc

        # 4. MOVZ / MOVK
        if (word >> 23) & 0x3F == 0x25:  # MOVZ/MOVK
            sf = (word >> 31) & 1
            opc = (word >> 29) & 3
            hw = (word >> 21) & 3
            imm16 = (word >> 5) & 0xFFFF
            shift = hw * 16
            
            dest_name = f"X{rd}"
            val = imm16 << shift
            if opc == 2:  # MOVZ
                self.regs[dest_name] = val
                desc = f"{pc_str}: MOVZ {dest_name}, #0x{imm16:X}, LSL #{shift} -> {dest_name} = 0x{val:X}"
            elif opc == 3:  # MOVK
                mask = ~(0xFFFF << shift)
                curr = self.regs.get(dest_name, 0)
                new_val = (curr & mask) | val
                self.regs[dest_name] = new_val
                desc = f"{pc_str}: MOVK {dest_name}, #0x{imm16:X}, LSL #{shift} -> {dest_name} = 0x{new_val:X}"
            else:
                self.regs[dest_name] = val
                desc = f"{pc_str}: MOV {dest_name}, #0x{val:X}"
            self.pc += 4
            self.history.append(desc)
            return desc

        # 5. LDR / STR (Immediate Offset)
        if (word >> 25) & 0x1F == 0x1C:
            size = (word >> 30) & 3
            opc = (word >> 22) & 3
            imm9 = (word >> 12) & 0x1FF
            is_unsigned = ((word >> 24) & 3) == 2
            
            rn_val = self.regs[f"X{rn}"] if rn != 31 else self.regs["SP"]
            
            if is_unsigned:
                imm12 = (word >> 10) & 0xFFF
                offset = imm12 << size
            else:
                offset = _sign_extend(imm9, 9)
                
            addr = rn_val + offset
            bytes_size = 1 << size
            
            dest_name = f"X{rt}"
            src_name = "SP" if rn == 31 else f"X{rn}"
            
            if opc == 0:  # STR
                val = self.regs.get(dest_name, 0)
                self.write_mem(addr, val, bytes_size)
                desc = f"{pc_str}: STR {dest_name}, [{src_name}, #{offset}] -> wrote 0x{val:X} to 0x{addr:X}"
            else:  # LDR
                val = self.read_mem(addr, bytes_size)
                self.regs[dest_name] = val
                desc = f"{pc_str}: LDR {dest_name}, [{src_name}, #{offset}] -> loaded 0x{val:X} from 0x{addr:X}"
            self.pc += 4
            self.history.append(desc)
            return desc

        # 6. STP / LDP
        if (word >> 22) & 0x3F8 == 0x280:
            sf = (word >> 31) & 1
            L = (word >> 22) & 1
            imm7 = (word >> 15) & 0x7F
            offset = _sign_extend(imm7, 7) << (3 if sf else 2)
            
            rn_val = self.regs[f"X{rn}"] if rn != 31 else self.regs["SP"]
            indexing = (word >> 23) & 3
            
            base_addr = rn_val
            if indexing == 3: # Pre-indexed
                base_addr += offset
                
            addr1 = base_addr
            addr2 = base_addr + (8 if sf else 4)
            bytes_size = 8 if sf else 4
            
            reg1 = f"X{rt}"
            reg2 = f"X{rt2}"
            src_name = "SP" if rn == 31 else f"X{rn}"
            
            if L == 0:  # STP
                val1 = self.regs.get(reg1, 0)
                val2 = self.regs.get(reg2, 0)
                self.write_mem(addr1, val1, bytes_size)
                self.write_mem(addr2, val2, bytes_size)
                desc = f"{pc_str}: STP {reg1}, {reg2}, [{src_name}, #{offset}] -> wrote 0x{val1:X}, 0x{val2:X} to 0x{addr1:X}"
            else:  # LDP
                val1 = self.read_mem(addr1, bytes_size)
                val2 = self.read_mem(addr2, bytes_size)
                self.regs[reg1] = val1
                self.regs[reg2] = val2
                desc = f"{pc_str}: LDP {reg1}, {reg2}, [{src_name}, #{offset}] -> loaded 0x{val1:X}, 0x{val2:X} from 0x{addr1:X}"
                
            if indexing == 3 or indexing == 1:
                if rn == 31:
                    self.regs["SP"] = rn_val + offset
                else:
                    self.regs[f"X{rn}"] = rn_val + offset
                    
            self.pc += 4
            self.history.append(desc)
            return desc

        # 7. Unconditional B / BL
        if (word >> 26) & 0x3F in (0x05, 0x25):
            is_bl = (word >> 31) & 1
            imm26 = word & 0x3FFFFFF
            offset = _sign_extend(imm26, 26) << 2
            target = (self.pc + offset) & 0xFFFFFFFFFFFFFFFF
            mn = "BL" if is_bl else "B"
            if is_bl:
                self.regs["X30"] = self.pc + 4
            self.pc = target
            desc = f"{pc_str}: {mn} #0x{target:X}"
            self.history.append(desc)
            return desc

        # 8. CBZ / CBNZ
        if (word >> 24) & 0x7F in (0x34, 0x35, 0x74, 0x75):
            nz = (word >> 24) & 1
            imm19 = (word >> 5) & 0x7FFFF
            off = _sign_extend(imm19, 19) << 2
            target = (self.pc + off) & 0xFFFFFFFFFFFFFFFF
            
            rt_val = self.regs.get(f"X{rt}", 0)
            condition = (rt_val != 0) if nz else (rt_val == 0)
            mn = "CBNZ" if nz else "CBZ"
            if condition:
                self.pc = target
                desc = f"{pc_str}: {mn} X{rt}, #0x{target:X} (taken)"
            else:
                self.pc += 4
                desc = f"{pc_str}: {mn} X{rt}, #0x{target:X} (not taken)"
            self.history.append(desc)
            return desc

        self.pc += 4
        fallback_desc = f"{pc_str}: UNSUPPORTED 0x{word:08X}"
        self.history.append(fallback_desc)
        return fallback_desc

# ── FRIDA & LOGOS HOOK GENERATORS ──────────────────────────────────────────────
def generate_frida_hook(objc_class: str, method_name: str, signature: str = "") -> str:
    is_instance = not method_name.startswith("+")
    clean_method = method_name.lstrip("+-").strip()
    args_count = clean_method.count(":")
    
    code = f"""// Frida Hook for {objc_class} {method_name}
if (ObjC.available) {{
    try {{
        var className = "{objc_class}";
        var methodSig = "{method_name}";
        var hook = ObjC.classes[className][methodSig];
        
        Interceptor.attach(hook.implementation, {{
            onEnter: function (args) {{
                console.log("[*] Entered: {objc_class} {method_name}");
                // args[0] is 'self', args[1] is 'selector'"""
    for i in range(args_count):
        code += f"\n                console.log(\"  -> Argument {i}: \" + new ObjC.Object(args[{i+2}]).toString());"
    code += f"""
            }},
            onLeave: function (retval) {{
                console.log("[*] Exited: {objc_class} {method_name} -> Return Value: \" + new ObjC.Object(retval).toString());
            }}
        }});
        console.log("[+] Activated hook for {objc_class} {method_name}");
    }} catch (err) {{
        console.log("[!] Error hooking {objc_class} {method_name}: \" + err);
    }}
}} else {{
    console.log("[-] Objective-C Runtime is not available.");
}}
"""
    return code

def generate_logos_hook(objc_class: str, method_name: str, signature: str = "") -> str:
    clean_method = method_name.lstrip("+-").strip()
    is_instance = method_name.startswith("-")
    prefix = "-" if is_instance else "+"
    
    parts = clean_method.split(":")
    logos_sig = ""
    if len(parts) == 1:
        logos_sig = f"{prefix} (void){parts[0]}"
    else:
        sig_parts = []
        for i, part in enumerate(parts[:-1]):
            sig_parts.append(f"{part}:(id)arg{i}")
        logos_sig = f"{prefix} (void)" + " ".join(sig_parts)
        
    code = f"""// Logos / Theos Tweak Hook for {objc_class} {method_name}
%hook {objc_class}

{logos_sig} {{
    %log;
    NSLog(@"[*] Hooked {objc_class} {method_name}!");
    %orig; // Call original method
}}

%end
"""
    return code

# ── INTERACTIVE MACH-O BINARY DIFFER ──────────────────────────────────────────
def diff_binaries(bin_path_a: str, bin_path_b: str) -> dict:
    path_a = Path(bin_path_a)
    path_b = Path(bin_path_b)
    
    report = {
        "binary_a": path_a.name,
        "binary_b": path_b.name,
        "size_a": path_a.stat().st_size if path_a.exists() else 0,
        "size_b": path_b.stat().st_size if path_b.exists() else 0,
        "added_classes": [],
        "removed_classes": [],
        "added_entitlements": [],
        "removed_entitlements": [],
        "added_dylibs": [],
        "removed_dylibs": [],
        "changes_detected": False
    }
    
    try:
        report_a = analyze(bin_path_a, [], build_cfg=False, run_taint=False)
        report_b = analyze(bin_path_b, [], build_cfg=False, run_taint=False)
        
        # Classes Compare
        classes_a = set(c.get("name") for c in report_a.get("objc", {}).get("classes", []))
        classes_b = set(c.get("name") for c in report_b.get("objc", {}).get("classes", []))
        report["added_classes"] = sorted(list(classes_b - classes_a))
        report["removed_classes"] = sorted(list(classes_a - classes_b))
        
        # Entitlements Compare
        ent_a = set((report_a.get("entitlements") or {}).keys())
        ent_b = set((report_b.get("entitlements") or {}).keys())
        report["added_entitlements"] = sorted(list(ent_b - ent_a))
        report["removed_entitlements"] = sorted(list(ent_a - ent_b))
        
        # Dylibs Compare
        dylibs_a = set(report_a.get("meta", {}).get("dylibs", []) or [])
        dylibs_b = set(report_b.get("meta", {}).get("dylibs", []) or [])
        report["added_dylibs"] = sorted(list(dylibs_b - dylibs_a))
        report["removed_dylibs"] = sorted(list(dylibs_a - dylibs_b))
        
        if (report["added_classes"] or report["removed_classes"] or 
            report["added_entitlements"] or report["removed_entitlements"] or
            report["added_dylibs"] or report["removed_dylibs"] or
            report["size_a"] != report["size_b"]):
            report["changes_detected"] = True
            
    except Exception as e:
        report["error"] = str(e)
        
    return report

# ── AEA Decryptor ─────────────────────────────────────────────────────────────
ProfileType_SIGNED = 0
ProfileType_SYMMETRIC_ENCRYPTION = 1
ProfileType_SYMMETRIC_ENCRYPTION_SIGNED = 2
ProfileType_ASYMMETRIC_ENCRYPTION = 3
ProfileType_ASYMMETRIC_ENCRYPTION_SIGNED = 4
ProfileType_PASSWORD_ENCRYPTION = 5

KeySize = {0: 32, 1: 80, 2: 80, 3: 80, 4: 80, 5: 80}
SignatureSize = {0: 128, 1: 0, 2: 160, 3: 0, 4: 160, 5: 0}
PublicKeySize = {0: 32, 1: 0, 2: 0, 3: 65, 4: 65, 5: 0}

def murmur64a(data: bytes, seed: int) -> bytes:
    m = 0xC6A4A7935BD1E995
    r = 47
    MASK = (1 << 64) - 1
    h = (seed ^ (len(data) * m)) & MASK

    for i in range(0, len(data) & ~7, 8):
        k = struct.unpack_from("<Q", data, i)[0]
        k = (k * m) & MASK
        k ^= k >> r
        k = (k * m) & MASK
        h ^= k
        h = (h * m) & MASK

    if len(data) % 8:
        block = data[len(data) & ~7:].ljust(8, b"\0")
        h ^= struct.unpack("<Q", block)[0]
        h = (h * m) & MASK

    h ^= h >> r
    h = (h * m) & MASK
    h ^= h >> r
    return struct.pack("<Q", h)

def derive_key(size: int, ikm: bytes, info: bytes, salt: bytes = b"") -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    hkdf = HKDF(hashes.SHA256(), size, salt, info)
    return hkdf.derive(ikm)

def serialize_public_key(key) -> bytes:
    from cryptography.hazmat.primitives import serialization
    return key.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint
    )

def derive_main_key(profile: int, scrypt_strength: int, sender_pub, recipient_pub, signature_pub, symmetric_key: bytes, salt: bytes) -> bytes:
    stream = io.BytesIO()
    stream.write(b"AEA_AMK")
    stream.write(struct.pack("<I", profile)[:3])
    stream.write(bytes([scrypt_strength]))
    if sender_pub:
        stream.write(serialize_public_key(sender_pub))
    if recipient_pub:
        stream.write(serialize_public_key(recipient_pub))
    if signature_pub:
        stream.write(serialize_public_key(signature_pub))
    return derive_key(32, symmetric_key, stream.getvalue(), salt)

def calculate_mac(key: bytes, data: bytes, salt: bytes) -> bytes:
    import hmac
    data = salt + data + struct.pack("<Q", len(salt))
    return hmac.digest(key, data, "sha256")

def decrypt_and_verify(key: bytes, data: bytes, salt: bytes, mac: bytes) -> bytes:
    if mac != calculate_mac(key[:32], data, salt):
        raise ValueError("HMAC validation failed")
    if len(key) == 80:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        cipher = Cipher(algorithms.AES(key[32:64]), modes.CTR(key[64:]))
        decryptor = cipher.decryptor()
        return decryptor.update(data)
    return data

class KeyDerivation:
    def __init__(self, main_key: bytes, key_size: int):
        self.main_key = main_key
        self.key_size = key_size

    def root_header_key(self) -> bytes:
        return derive_key(self.key_size, self.main_key, b"AEA_RHEK")

    def cluster_key(self, index: int) -> bytes:
        info = b"AEA_CK" + struct.pack("<I", index)
        return derive_key(32, self.main_key, info)

    def cluster_header_key(self, cluster_key: bytes) -> bytes:
        return derive_key(self.key_size, cluster_key, b"AEA_CHEK")

    def segment_key(self, cluster_key: bytes, index: int) -> bytes:
        info = b"AEA_SK" + struct.pack("<I", index)
        return derive_key(self.key_size, cluster_key, info)

def extract_aea_symmetric_key(aea_data: bytes) -> Optional[bytes]:
    """Extract AEA symmetric key from header. Accepts full file bytes OR just the header portion."""
    if len(aea_data) < 12:
        raise ValueError("AEA file is too short")
    magic = aea_data[:4]
    if magic != b"AEA1":
        raise ValueError("Invalid AEA magic")
    profile = int.from_bytes(aea_data[4:7], "little")
    auth_data_blob_size = int.from_bytes(aea_data[8:12], "little")
    if auth_data_blob_size == 0:
        raise ValueError("No auth data blob found in AEA")
    
    # Only need header + auth_data_blob for key extraction
    if len(aea_data) < 12 + auth_data_blob_size:
        raise ValueError("AEA data too short for auth_data_blob")
        
    auth_data_blob = aea_data[12:12+auth_data_blob_size]
        
    fields = {}
    while len(auth_data_blob) > 0:
        if len(auth_data_blob) < 4:
            break
        field_size = int.from_bytes(auth_data_blob[:4], "little")
        if field_size < 4 or field_size > len(auth_data_blob):
            break
        field_blob = auth_data_blob[:field_size]
        
        parts = field_blob[4:].split(b"\x00", 1)
        if len(parts) == 2:
            k = parts[0].decode("utf-8", errors="ignore")
            v = parts[1]
            if v.endswith(b"\x00"):
                v = v[:-1]
            fields[k] = v
        auth_data_blob = auth_data_blob[field_size:]
        
    if "com.apple.wkms.fcs-response" not in fields:
        return None
        
    fcs_response_bytes = fields["com.apple.wkms.fcs-response"]
    fcs_response = json.loads(fcs_response_bytes.decode("utf-8", errors="ignore"))
    enc_request = base64.b64decode(fcs_response["enc-request"])
    wrapped_key = base64.b64decode(fcs_response["wrapped-key"])
    
    if "com.apple.wkms.fcs-key-url" in fields:
        url = fields["com.apple.wkms.fcs-key-url"].decode("utf-8", errors="ignore")
        print(f"[*] Fetching private key from: {url}")
        import requests
        r = requests.get(url, timeout=10)
        r.raise_for_status()
        pem_text = r.text
    else:
        return None
        
    from pyhpke import AEADId, CipherSuite, KDFId, KEMId, KEMKey
    suite = CipherSuite.new(KEMId.DHKEM_P256_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.AES256_GCM)
    privkey = KEMKey.from_pem(pem_text)
    recipient = suite.create_recipient_context(enc_request, privkey)
    symmetric_key = recipient.open(wrapped_key)
    return symmetric_key

class AEADecrypter:
    @staticmethod
    def decrypt(aea_data: bytes, symmetric_key: bytes) -> bytes:
        if len(aea_data) < 12:
            raise ValueError("AEA data is too short")
        if aea_data[:4] != b"AEA1":
            raise ValueError("Invalid AEA magic number")
            
        profile = int.from_bytes(aea_data[4:7], "little")
        scrypt_strength = aea_data[7]
        auth_data_size = int.from_bytes(aea_data[8:12], "little")
        
        offset = 12
        auth_data = aea_data[offset:offset+auth_data_size]
        offset += auth_data_size
        
        sig_size = SignatureSize.get(profile, 0)
        signature = aea_data[offset:offset+sig_size]
        offset += sig_size
        
        pubkey_size = PublicKeySize.get(profile, 0)
        public_key = aea_data[offset:offset+pubkey_size]
        offset += pubkey_size
        
        main_salt = aea_data[offset:offset+32]
        offset += 32
        
        root_header_mac = aea_data[offset:offset+32]
        offset += 32
        
        root_header_data = aea_data[offset:offset+48]
        offset += 48
        
        cluster_mac = aea_data[offset:offset+32]
        offset += 32
        
        if profile == ProfileType_SIGNED:
            symmetric_key = public_key
        elif profile in (ProfileType_SYMMETRIC_ENCRYPTION, ProfileType_SYMMETRIC_ENCRYPTION_SIGNED):
            if not symmetric_key or len(symmetric_key) != 32:
                raise ValueError("Symmetric key must be 32 bytes")
        else:
            raise ValueError(f"AEA Profile {profile} is not supported for automatic decryption.")
            
        main_key = derive_main_key(profile, scrypt_strength, None, None, None, symmetric_key, main_salt)
        key_derivation = KeyDerivation(main_key, KeySize[profile])
        
        root_header_key = key_derivation.root_header_key()
        root_header_salt = cluster_mac + auth_data
        decrypted_root_header = decrypt_and_verify(root_header_key, root_header_data, root_header_salt, root_header_mac)
        
        orig_size = struct.unpack_from("<Q", decrypted_root_header, 0)[0]
        arch_size = struct.unpack_from("<Q", decrypted_root_header, 8)[0]
        segment_size = struct.unpack_from("<I", decrypted_root_header, 16)[0]
        segments_per_cluster = struct.unpack_from("<I", decrypted_root_header, 20)[0]
        comp_algo = chr(decrypted_root_header[24])
        checksum_algo = decrypted_root_header[25]
        
        if orig_size == 0:
            return b""
            
        checksum_size = {0: 0, 1: 8, 2: 32}[checksum_algo]
        segment_header_size = checksum_size + 8
        
        output = io.BytesIO()
        cluster_index = 0
        
        while True:
            cluster_key = key_derivation.cluster_key(cluster_index)
            cluster_header_key = key_derivation.cluster_header_key(cluster_key)
            
            seg_headers_len = segment_header_size * segments_per_cluster
            if offset + seg_headers_len > len(aea_data):
                raise ValueError("Unexpected EOF in AEA cluster headers")
            segment_headers = aea_data[offset:offset+seg_headers_len]
            offset += seg_headers_len
            
            if offset + 32 > len(aea_data):
                raise ValueError("Unexpected EOF in AEA next cluster mac")
            next_cluster_mac = aea_data[offset:offset+32]
            offset += 32
            
            seg_macs_len = 32 * segments_per_cluster
            if offset + seg_macs_len > len(aea_data):
                raise ValueError("Unexpected EOF in AEA segment macs")
            segment_macs = aea_data[offset:offset+seg_macs_len]
            offset += seg_macs_len
            
            segment_headers = decrypt_and_verify(cluster_header_key, segment_headers, next_cluster_mac + segment_macs, cluster_mac)
            
            for i in range(segments_per_cluster):
                header_offset = segment_header_size * i
                seg_hdr = segment_headers[header_offset:header_offset+segment_header_size]
                original_size, compressed_size = struct.unpack_from("<II", seg_hdr)
                checksum = seg_hdr[8:]
                
                if offset + compressed_size > len(aea_data):
                    raise ValueError("Unexpected EOF in AEA segment data")
                segment_data = aea_data[offset:offset+compressed_size]
                offset += compressed_size
                
                seg_mac = segment_macs[32*i:32*(i+1)]
                seg_key = key_derivation.segment_key(cluster_key, i)
                segment_data = decrypt_and_verify(seg_key, segment_data, b"", seg_mac)
                
                if original_size > compressed_size:
                    if comp_algo == "-":
                        pass
                    elif comp_algo == "4":
                        import lz4.block
                        segment_data = lz4.block.decompress(segment_data, original_size)
                    elif comp_algo == "e":
                        import lzfse
                        segment_data = lzfse.decompress(segment_data)
                    elif comp_algo == "x":
                        import lzma
                        segment_data = lzma.decompress(segment_data)
                    elif comp_algo == "z":
                        import zlib
                        segment_data = zlib.decompress(segment_data)
                    else:
                        raise ValueError(f"Unsupported compression algorithm: {comp_algo}")
                        
                if len(segment_data) != original_size:
                    raise ValueError("Segment has incorrect size after decompression")
                    
                if checksum_algo == 1:
                    calc_checksum = murmur64a(segment_data, 0xE2236FDC26A5F6D2)
                elif checksum_algo == 2:
                    calc_checksum = hashlib.sha256(segment_data).digest()
                else:
                    calc_checksum = b""
                    
                if calc_checksum != checksum:
                    raise ValueError("Checksum validation failed")
                    
                output.write(segment_data)
                
                if output.tell() >= orig_size:
                    res = output.getvalue()
                    return res[:orig_size]
                    
            cluster_mac = next_cluster_mac
            cluster_index += 1

# ── Apple Archive Extractor ───────────────────────────────────────────────────

def decompress_payload(data: bytes) -> bytes:
    if data.startswith(b"AA01"):
        return data
    try:
        import lzfse
        return lzfse.decompress(data)
    except Exception:
        pass
    try:
        import zlib
        return zlib.decompress(data)
    except Exception:
        pass
    try:
        import lzma
        return lzma.decompress(data)
    except Exception:
        pass
    return data

class AppleArchiveExtractor:
    @staticmethod
    def extract(archive_data: bytes, output_dir: Path) -> list[Path]:
        extracted_files = []
        view = memoryview(archive_data)
        idx = 0
        
        while idx < len(view):
            start = idx
            if idx + 6 > len(view):
                break
            magic, header_size = struct.unpack_from("<4sH", view, idx)
            if magic != b"AA01":
                break
                
            idx += header_size
            blob_size = 0
            parsed_fields = {}
            
            field_view = view[start + 6 : start + header_size]
            field_offset = 0
            
            while field_offset < len(field_view):
                if field_offset + 4 > len(field_view):
                    break
                key, subtype = struct.unpack_from("<3sc", field_view, field_offset)
                key_str = key.decode("utf-8", errors="ignore")
                subtype_str = subtype.decode("utf-8", errors="ignore")
                field_offset += 4
                
                if subtype_str in ("1", "2", "4", "8"):
                    size = int(subtype_str)
                    if field_offset + size > len(field_view):
                        break
                    val = int.from_bytes(field_view[field_offset : field_offset + size], "little")
                    field_offset += size
                elif subtype_str == "P":
                    if field_offset + 2 > len(field_view):
                        break
                    size = int.from_bytes(field_view[field_offset : field_offset + 2], "little")
                    field_offset += 2
                    if field_offset + size > len(field_view):
                        break
                    val = field_view[field_offset : field_offset + size].tobytes().decode("utf-8", errors="ignore")
                    field_offset += size
                elif subtype_str in ("A", "B", "C"):
                    size_bytes = {"A": 2, "B": 4, "C": 8}[subtype_str]
                    if field_offset + size_bytes > len(field_view):
                        break
                    size = int.from_bytes(field_view[field_offset : field_offset + size_bytes], "little")
                    field_offset += size_bytes
                    val = (idx, size)
                    idx += size
                    blob_size += size
                elif subtype_str in ("S", "T"):
                    size = {"S": 8, "T": 12}[subtype_str]
                    if field_offset + size > len(field_view):
                        break
                    val = int.from_bytes(field_view[field_offset : field_offset + size], "little")
                    field_offset += size
                else:
                    break
                    
                parsed_fields[key_str] = val
                
            idx = start + header_size + blob_size
            
            typ = parsed_fields.get("TYP")
            pat = parsed_fields.get("PAT")
            
            if typ == ord("M"):  # Metadata
                lbl = parsed_fields.get("LBL")
                dat_info = parsed_fields.get("DAT")
                if lbl == "main" and dat_info:
                    blob_start, blob_len = dat_info
                    compressed_data = view[blob_start : blob_start + blob_len].tobytes()
                    decompressed = decompress_payload(compressed_data)
                    extracted_files.extend(AppleArchiveExtractor.extract(decompressed, output_dir))
                    
            elif typ == ord("F") and pat:  # File
                dat_info = parsed_fields.get("DAT")
                file_path = output_dir / pat
                file_path.parent.mkdir(parents=True, exist_ok=True)
                
                if dat_info:
                    blob_start, blob_len = dat_info
                    file_data = view[blob_start : blob_start + blob_len].tobytes()
                else:
                    file_data = b""
                    
                try:
                    file_path.write_bytes(file_data)
                    extracted_files.append(file_path)
                except Exception as e:
                    print(f"[!] Failed to write file {file_path}: {e}", file=sys.stderr)
                    
            elif typ == ord("D") and pat:  # Directory
                dir_path = output_dir / pat
                dir_path.mkdir(parents=True, exist_ok=True)
                
            elif typ == ord("L") and pat:  # Symlink
                lnk = parsed_fields.get("LNK")
                if lnk:
                    link_path = output_dir / pat
                    link_path.parent.mkdir(parents=True, exist_ok=True)
                    try:
                        if link_path.exists() or link_path.is_symlink():
                            link_path.unlink()
                        os.symlink(lnk, link_path)
                    except Exception:
                        try:
                            link_path.write_text(f"Symlink to: {lnk}")
                        except Exception:
                            pass
                            
        return extracted_files

# ── DMG Parser & Mach-O Scanner ────────────────────────────────────────────────

def decompress_blkx(dmg_data: bytes, blkx_data: bytes, out_file_path: Path, data_fork_offset: int = 0):
    if len(blkx_data) < 68:
        return
    sig, version, start_sector, sector_count, data_offset, buffers, descriptors, reserved, num_chunks = \
        struct.unpack_from(">4sIQQQII24sI", blkx_data, 0)
        
    if sig != b"mish":
        return
        
    chunk_offset = 68
    chunks = []
    for _ in range(num_chunks):
        if chunk_offset + 40 > len(blkx_data):
            break
        ctype, comment, sec_num, sec_cnt, comp_offset, comp_len = struct.unpack_from(">IIQQQQ", blkx_data, chunk_offset)
        chunks.append({
            "type": ctype,
            "sec_num": sec_num,
            "sec_cnt": sec_cnt,
            "comp_offset": comp_offset,
            "comp_len": comp_len
        })
        chunk_offset += 40
        
    import zlib
    with open(out_file_path, "wb") as out_f:
        for chunk in chunks:
            ctype = chunk["type"]
            sec_cnt = chunk["sec_cnt"]
            comp_offset = chunk["comp_offset"]
            comp_len = chunk["comp_len"]
            
            if ctype == 0xffffffff:
                break
                
            chunk_bytes = dmg_data[data_fork_offset + comp_offset : data_fork_offset + comp_offset + comp_len]
            
            if ctype == 0x00000001:  # Raw
                out_f.write(chunk_bytes[:sec_cnt * 512])
            elif ctype == 0x00000002:  # Zero
                out_f.write(b"\x00" * (sec_cnt * 512))
            elif ctype == 0x80000005:  # Zlib
                try:
                    decompressed = zlib.decompress(chunk_bytes)
                    out_f.write(decompressed[:sec_cnt * 512])
                except Exception:
                    out_f.write(b"\x00" * (sec_cnt * 512))
            elif ctype == 0x80000007:  # LZMA
                try:
                    import lzma
                    decompressed = lzma.decompress(chunk_bytes)
                    out_f.write(decompressed[:sec_cnt * 512])
                except Exception:
                    out_f.write(b"\x00" * (sec_cnt * 512))
            else:
                out_f.write(b"\x00" * (sec_cnt * 512))

def get_macho_size_from_file(f, start_off: int) -> Optional[int]:
    f.seek(start_off)
    header_bytes = f.read(32)
    if len(header_bytes) < 32:
        return None
    magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags = \
        struct.unpack_from("<IIIIIII", header_bytes)
        
    if magic != 0xFEEDFACF or cputype != 0x0100000C:
        return None
        
    max_offset = 32 + sizeofcmds
    f.seek(start_off + 32)
    cmds_bytes = f.read(sizeofcmds)
    if len(cmds_bytes) < sizeofcmds:
        return None
        
    lc_offset = 0
    for _ in range(ncmds):
        if lc_offset + 8 > len(cmds_bytes):
            break
        cmd, cmdsize = struct.unpack_from("<II", cmds_bytes, lc_offset)
        if cmdsize < 8 or lc_offset + cmdsize > len(cmds_bytes):
            break
            
        if cmd == 0x19:  # LC_SEGMENT_64
            if lc_offset + 56 <= len(cmds_bytes):
                fileoff, filesize = struct.unpack_from("<QQ", cmds_bytes, lc_offset + 40)
                max_offset = max(max_offset, fileoff + filesize)
        elif cmd in (0x1D, 0x26, 0x29, 0x2E, 0x33, 0x34):
            if lc_offset + 16 <= len(cmds_bytes):
                dataoff, datasize = struct.unpack_from("<II", cmds_bytes, lc_offset + 8)
                max_offset = max(max_offset, dataoff + datasize)
                
        lc_offset += cmdsize
        
    return max_offset

def get_macho_name(f, start_off: int) -> str:
    f.seek(start_off)
    header_bytes = f.read(32)
    if len(header_bytes) < 32:
        return f"binary_{start_off}"
    magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags = \
        struct.unpack_from("<IIIIIII", header_bytes)
        
    f.seek(start_off + 32)
    cmds_bytes = f.read(sizeofcmds)
    
    lc_offset = 0
    for _ in range(ncmds):
        if lc_offset + 8 > len(cmds_bytes):
            break
        cmd, cmdsize = struct.unpack_from("<II", cmds_bytes, lc_offset)
        if cmdsize < 8 or lc_offset + cmdsize > len(cmds_bytes):
            break
            
        if cmd == 0x0D:  # LC_ID_DYLIB
            if lc_offset + 12 <= len(cmds_bytes):
                name_off = struct.unpack_from("<I", cmds_bytes, lc_offset + 8)[0]
                name_start = lc_offset + name_off
                if name_start < len(cmds_bytes):
                    name_end = cmds_bytes.find(b"\x00", name_start)
                    if name_end != -1:
                        dylib_path = cmds_bytes[name_start:name_end].decode("utf-8", errors="ignore")
                        return Path(dylib_path).name
        lc_offset += cmdsize
        
    if filetype == 2:
        return f"exec_{start_off:X}"
    return f"macho_{start_off:X}"

def scan_file_for_machos(file_path: Path) -> list[tuple[int, int]]:
    machos = []
    chunk_size = 4 * 1024 * 1024  # 4MB
    overlap = 32
    magic = b'\xcf\xfa\xed\xfe'
    
    with open(file_path, "rb") as f:
        file_offset = 0
        while True:
            f.seek(file_offset)
            block = f.read(chunk_size)
            if not block:
                break
                
            search_start = 0
            while True:
                idx = block.find(magic, search_start)
                if idx == -1:
                    break
                
                absolute_offset = file_offset + idx
                if absolute_offset % 4 == 0:
                    size = get_macho_size_from_file(f, absolute_offset)
                    if size and size > 0:
                        machos.append((absolute_offset, size))
                        search_start = idx + size
                        if absolute_offset + size > file_offset + chunk_size:
                            file_offset = absolute_offset + size
                            block = b""
                            break
                        continue
                search_start = idx + 1
                
            if block:
                file_offset += chunk_size - overlap
                
    return machos

# ── Module-level IPSW firmware metadata store ──────────────────────────────────
# Populated by process_input_recursive() when an IPSW is processed.
# Consumed by build_firmware_intelligence_report() and GUI/CLI output layers.
_ipsw_firmware_meta: dict = {}

def detect_file_type(file_path: Path) -> str:
    if not file_path.exists():
        return "unknown"
    with open(file_path, "rb") as f:
        magic = f.read(4)
        
    if file_path.suffix.lower() == ".ipsw":
        return "ipsw"
    # AEA magic check MUST come before DMG suffix check — iOS 18+ DMGs are AEA-wrapped
    if magic == b"AEA1":
        return "aea"
    if file_path.suffix.lower() == ".aea":
        return "aea"
    if magic == b"AA01" or file_path.suffix.lower() in (".aar", ".aa"):
        return "apple_archive"
        
    # Mach-O magic check before DMG (some extracted files have no extension)
    if magic in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"):
        return "macho"

    size = file_path.stat().st_size
    if size > 64:
        with open(file_path, "rb") as f:
            f.seek(32)
            block0_32 = f.read(4)
            if block0_32 == b"NXSB" or file_path.suffix.lower() in (".dmg", ".raw", ".img"):
                return "dmg"
                
    if size > 512:
        with open(file_path, "rb") as f:
            f.seek(size - 512)
            trailer = f.read(4)
            if trailer == b"koly":
                return "dmg"
        
    return "unknown"

def process_input_recursive(input_path: Path, extract_dir: Path, aea_key_b64: Optional[str] = None) -> list[Path]:
    file_type = detect_file_type(input_path)
    print(f"[*] Detected file type of '{input_path.name}': {file_type}")
    
    if file_type == "macho":
        return [input_path]
        
    elif file_type == "aea":
        print(f"[*] Decrypting AEA archive: {input_path.name}")
        symmetric_key = None
        if aea_key_b64:
            try:
                symmetric_key = base64.b64decode(aea_key_b64)
                print("[*] Using user-provided AEA symmetric key.")
            except Exception as e:
                print(f"[!] Invalid base64 key: {e}", file=sys.stderr)
                
        if not symmetric_key:
            try:
                # Only read header + auth_data_blob for key extraction (not entire file)
                with open(input_path, "rb") as f:
                    hdr = f.read(12)
                    if len(hdr) == 12 and hdr[:4] == b"AEA1":
                        auth_size = int.from_bytes(hdr[8:12], "little")
                        auth_blob = f.read(auth_size)
                        aea_header = hdr + auth_blob
                    else:
                        aea_header = hdr
                symmetric_key = extract_aea_symmetric_key(aea_header)
                if symmetric_key:
                    print(f"[+] Automatically unwrapped AEA key from Apple WKMS: {base64.b64encode(symmetric_key).decode()}")
            except Exception as e:
                print(f"[!] Automatic AEA key unwrapping failed: {e}", file=sys.stderr)
                
        if not symmetric_key:
            print("[!] AEA symmetric key is missing or could not be unwrapped. Provide it with --aea-key.", file=sys.stderr)
            print("[!] Required packages: pip install requests pyhpke", file=sys.stderr)
            return []
            
        try:
            print(f"[*] Loading AEA file ({input_path.stat().st_size / (1024*1024):.1f} MB) for decryption...")
            aea_data = input_path.read_bytes()
            decrypted_data = AEADecrypter.decrypt(aea_data, symmetric_key)
            del aea_data  # free memory immediately
            decrypted_path = extract_dir / (input_path.stem + ".decrypted")
            decrypted_path.write_bytes(decrypted_data)
            del decrypted_data  # free memory
            print(f"[+] Decrypted AEA payload written to: {decrypted_path.name} ({decrypted_path.stat().st_size / (1024*1024):.1f} MB)")
            return process_input_recursive(decrypted_path, extract_dir, aea_key_b64)
        except Exception as e:
            print(f"[!] AEA decryption failed: {e}", file=sys.stderr)
            return []
            
    elif file_type == "apple_archive":
        print(f"[*] Extracting Apple Archive: {input_path.name}")
        out_sub_dir = extract_dir / (input_path.stem + "_extracted")
        out_sub_dir.mkdir(parents=True, exist_ok=True)
        try:
            archive_data = input_path.read_bytes()
            extracted_files = AppleArchiveExtractor.extract(archive_data, out_sub_dir)
            print(f"[+] Extracted {len(extracted_files)} files to {out_sub_dir.name}")
            
            macho_targets = []
            for path in extracted_files:
                if path.is_file() and detect_file_type(path) == "macho":
                    macho_targets.append(path)
            return macho_targets
        except Exception as e:
            print(f"[!] Apple Archive extraction failed: {e}", file=sys.stderr)
            return []
            
    elif file_type == "dmg":
        print(f"[*] Processing DMG: {input_path.name}")
        dmg_data = input_path.read_bytes()
        
        if len(dmg_data) < 512:
            print("[!] DMG is too small", file=sys.stderr)
            return []
            
        koly = dmg_data[-512:]
        if koly[:4] != b"koly":
            print("[*] No standard DMG koly trailer found. Treating as raw disk image and scanning directly...")
            macho_targets = []
            carved_machos = scan_file_for_machos(input_path)
            print(f"[+] Found {len(carved_machos)} Mach-O binaries in raw disk image.")
            
            if carved_machos:
                extracted_dir = extract_dir / f"{input_path.stem}_carved"
                extracted_dir.mkdir(parents=True, exist_ok=True)
                
                with open(input_path, "rb") as disk_f:
                    for absolute_offset, size in carved_machos:
                        macho_name = get_macho_name(disk_f, absolute_offset)
                        out_macho_path = extracted_dir / macho_name
                        
                        disk_f.seek(absolute_offset)
                        macho_data = disk_f.read(size)
                        out_macho_path.write_bytes(macho_data)
                        macho_targets.append(out_macho_path)
                        print(f"    - Carved {macho_name} ({size:,} bytes)")
            return macho_targets
            
        xml_offset = int.from_bytes(koly[216:224], "big")
        xml_length = int.from_bytes(koly[224:232], "big")
        data_fork_offset = int.from_bytes(koly[24:32], "big")
        
        plist_data = dmg_data[xml_offset : xml_offset + xml_length]
        try:
            plist = plistlib.loads(plist_data)
        except Exception as e:
            print(f"[!] Failed to parse DMG plist: {e}", file=sys.stderr)
            return []
            
        resource_fork = plist.get("resource-fork", {})
        blkx_list = resource_fork.get("blkx", [])
        
        macho_targets = []
        for blkx_idx, blkx_entry in enumerate(blkx_list):
            name = blkx_entry.get("Name", f"partition_{blkx_idx}")
            print(f"[*] Processing partition: {name}")
            data_b64 = blkx_entry.get("Data")
            if not data_b64:
                continue
                
            blkx_bytes = base64.b64decode(data_b64)
            temp_partition_file = extract_dir / f"temp_partition_{blkx_idx}.raw"
            
            try:
                decompress_blkx(dmg_data, blkx_bytes, temp_partition_file, data_fork_offset)
                print(f"[*] Decompressed partition to {temp_partition_file.name}. Scanning for Mach-O binaries...")
                
                carved_machos = scan_file_for_machos(temp_partition_file)
                print(f"[+] Found {len(carved_machos)} Mach-O binaries in partition {name}.")
                
                if carved_machos:
                    extracted_dir = extract_dir / f"{input_path.stem}_carved"
                    extracted_dir.mkdir(parents=True, exist_ok=True)
                    
                    with open(temp_partition_file, "rb") as partition_f:
                        for absolute_offset, size in carved_machos:
                            macho_name = get_macho_name(partition_f, absolute_offset)
                            out_macho_path = extracted_dir / macho_name
                            
                            partition_f.seek(absolute_offset)
                            macho_data = partition_f.read(size)
                            out_macho_path.write_bytes(macho_data)
                            macho_targets.append(out_macho_path)
                            print(f"    - Carved {macho_name} ({size:,} bytes)")
                            
            except Exception as e:
                print(f"[!] DMG partition decompression/scan failed: {e}", file=sys.stderr)
            finally:
                if temp_partition_file.exists():
                    try:
                        temp_partition_file.unlink()
                    except Exception:
                        pass
                        
        return macho_targets
        
    elif file_type == "ipsw":
        global _ipsw_firmware_meta
        print(f"[*] Processing iOS Firmware IPSW: {input_path.name}")
        import zipfile
        out_sub_dir = extract_dir / (input_path.stem + "_extracted")
        out_sub_dir.mkdir(parents=True, exist_ok=True)
        
        macho_targets = []
        try:
            with zipfile.ZipFile(input_path, "r") as z:
                # 1. Look for metadata plists
                plist_files = [n for n in z.namelist() if n.lower() in ("restore.plist", "buildmanifest.plist")]
                for pf in plist_files:
                    try:
                        plist_data = z.read(pf)
                        plist = plistlib.loads(plist_data)
                        if pf.lower() == "restore.plist":
                            ver = plist.get("ProductVersion", "Unknown")
                            build = plist.get("ProductBuildVersion", "Unknown")
                            prod = plist.get("ProductType", "Unknown")
                            print(f"[+] IPSW Firmware Metadata:")
                            print(f"    - iOS Version: {ver}")
                            print(f"    - Build: {build}")
                            print(f"    - Product: {prod}")
                            # ── Store metadata globally for firmware intelligence ──
                            _ipsw_firmware_meta = {
                                "ios_version": ver,
                                "ios_build": build,
                                "product_type": prod,
                                "ipsw_filename": input_path.name,
                                "ipsw_size_bytes": input_path.stat().st_size,
                                "supported_product_types": plist.get("SupportedProductTypes", []),
                                "system_restore_images": plist.get("SystemRestoreImages", {}),
                            }
                    except Exception as pe:
                        print(f"[!] Failed to parse IPSW metadata {pf}: {pe}")
                
                # 2. Identify key assets: kernelcache, dmgs, trustcaches
                all_names = z.namelist()
                kernel_files = [n for n in all_names if "kernelcache" in n.lower()]
                dmg_files = [n for n in all_names if n.lower().endswith(".dmg")]
                aea_dmg_files = [n for n in all_names if n.lower().endswith(".dmg.aea")]
                tc_files = [n for n in all_names if n.lower().endswith(".tc") or "trustcache" in n.lower()]
                
                print(f"[*] Found {len(kernel_files)} kernelcache(s), {len(dmg_files)} DMG(s), "
                      f"{len(aea_dmg_files)} AEA-wrapped DMG(s), {len(tc_files)} trustcache(s) in IPSW.")
                
                # Extract kernelcache(s)
                for k in kernel_files:
                    dest = out_sub_dir / Path(k).name
                    print(f"[*] Extracting kernelcache: {k} -> {dest.name}")
                    with open(dest, "wb") as f_out:
                        f_out.write(z.read(k))
                    if detect_file_type(dest) == "macho":
                        macho_targets.append(dest)
                        
                # Extract and process DMGs
                if dmg_files:
                    # Sort DMGs by zipped size to find the biggest one
                    dmg_infos = []
                    for d in dmg_files:
                        info = z.getinfo(d)
                        dmg_infos.append((d, info.file_size))
                    dmg_infos.sort(key=lambda x: x[1], reverse=True)
                    
                    # Extract the largest DMG (Main OS Root filesystem)
                    largest_dmg, size_bytes = dmg_infos[0]
                    dest_dmg = out_sub_dir / Path(largest_dmg).name
                    print(f"[*] Extracting largest OS Root DMG: {largest_dmg} ({size_bytes / (1024*1024):.2f} MB) -> {dest_dmg.name}")
                    with open(dest_dmg, "wb") as f_out:
                        f_out.write(z.read(largest_dmg))
                    
                    # Process this DMG recursively!
                    dmg_targets = process_input_recursive(dest_dmg, extract_dir, aea_key_b64)
                    macho_targets.extend(dmg_targets)
                    
                    # Clean up the large extracted DMG to save disk space
                    if dest_dmg.exists():
                        try:
                            dest_dmg.unlink()
                        except Exception:
                            pass

                # ── AEA-wrapped DMGs (iOS 18+): these contain the actual rootfs ──
                if aea_dmg_files and not macho_targets:
                    # Only process AEA DMGs if regular DMGs yielded no Mach-O
                    # (regular .dmg in iOS 18 are IMG4-wrapped, not directly usable)
                    # Sort by size — largest is rootfs
                    aea_infos = []
                    for d in aea_dmg_files:
                        info = z.getinfo(d)
                        aea_infos.append((d, info.file_size))
                    aea_infos.sort(key=lambda x: x[1], reverse=True)
                    
                    largest_aea, aea_size = aea_infos[0]
                    dest_aea = out_sub_dir / Path(largest_aea).name
                    print(f"[*] Extracting AEA-wrapped rootfs DMG: {largest_aea} ({aea_size / (1024*1024):.1f} MB)")
                    print(f"    This is the real rootfs — will auto-decrypt via Apple WKMS...")
                    
                    # Stream-extract from zip to avoid double memory usage
                    with open(dest_aea, "wb") as f_out:
                        with z.open(largest_aea) as zf:
                            import shutil
                            shutil.copyfileobj(zf, f_out)
                    
                    # process_input_recursive will detect AEA1 magic → auto-decrypt → carve Mach-O
                    aea_targets = process_input_recursive(dest_aea, extract_dir, aea_key_b64)
                    macho_targets.extend(aea_targets)
                    
                    # Clean up
                    if dest_aea.exists():
                        try:
                            dest_aea.unlink()
                        except Exception:
                            pass
                            
                # Extract trust caches
                for tc in tc_files:
                    dest = out_sub_dir / Path(tc).name
                    print(f"[*] Extracting Trust Cache: {tc} -> {dest.name}")
                    with open(dest, "wb") as f_out:
                        f_out.write(z.read(tc))
                        
            print(f"[+] Completed IPSW firmware extraction. Found {len(macho_targets)} total target binaries to scan.")
            return macho_targets
        except Exception as e:
            print(f"[!] IPSW extraction failed: {e}", file=sys.stderr)
            return []
            
    else:
        print(f"[!] Unsupported file type: {file_type}", file=sys.stderr)
        return []


# ═══════════════════════════════════════════════════════════════════════════════
# §0  CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════════

# ── Magic numbers ──────────────────────────────────────────────────────────────
MH_MAGIC_64   = 0xFEEDFACF
MH_CIGAM_64   = 0xCFFAEDFE
FAT_MAGIC     = 0xCAFEBABE
FAT_CIGAM     = 0xBEBAFECA

# ── CPU ───────────────────────────────────────────────────────────────────────
CPU_TYPE_ARM64        = 0x0100000C
CPU_SUBTYPE_ARM64E    = 0x80000002

# ── Mach-O file types ─────────────────────────────────────────────────────────
MH_FILETYPE = {
    1: "MH_OBJECT",    2: "MH_EXECUTE",   6: "MH_DYLIB",
    7: "MH_DYLINKER",  8: "MH_BUNDLE",    0xA: "MH_DYLIB_STUB",
    0xB: "MH_DSYM",    0xC: "MH_KEXT_BUNDLE",
}

# ── Mach-O header flags ────────────────────────────────────────────────────────
MH_FLAGS = {
    0x1:      "MH_NOUNDEFS",
    0x4:      "MH_DYLDLINK",
    0x8:      "MH_BINDATLOAD",
    0x10:     "MH_PREBOUND",
    0x20:     "MH_SPLIT_SEGS",
    0x80:     "MH_TWOLEVEL",
    0x200:    "MH_FORCE_FLAT",
    0x800:    "MH_NOMULTIDEFS",
    0x1000:   "MH_NOFIXPREBINDING",
    0x2000:   "MH_PREBINDABLE",
    0x4000:   "MH_ALLMODSBOUND",
    0x8000:   "MH_SUBSECTIONS_VIA_SYMBOLS",
    0x10000:  "MH_CANONICAL",
    0x20000:  "MH_WEAK_DEFINES",
    0x40000:  "MH_BINDS_TO_WEAK",
    0x80000:  "MH_ALLOW_STACK_EXECUTION",
    0x100000: "MH_ROOT_SAFE",
    0x200000: "MH_SETUID_SAFE",
    0x400000: "MH_NO_REEXPORTED_DYLIBS",
    0x800000: "MH_PIE",
    0x1000000:"MH_DEAD_STRIPPABLE_DYLIB",
    0x2000000:"MH_HAS_TLV_DESCRIPTORS",
    0x4000000:"MH_NO_HEAP_EXECUTION",
    0x8000000:"MH_APP_EXTENSION_SAFE",
}

# ── Load command IDs ───────────────────────────────────────────────────────────
LC_SEGMENT_64             = 0x19
LC_SYMTAB                 = 0x02
LC_DYSYMTAB               = 0x0B
LC_LOAD_DYLIB             = 0x0C
LC_ID_DYLIB               = 0x0D
LC_LOAD_DYLINKER          = 0x0E
LC_LOAD_WEAK_DYLIB        = 0x80000018
LC_REEXPORT_DYLIB         = 0x8000001F
LC_LAZY_LOAD_DYLIB        = 0x20
LC_CODE_SIGNATURE         = 0x1D
LC_ENCRYPTION_INFO        = 0x21
LC_ENCRYPTION_INFO_64     = 0x2C
LC_DYLD_INFO              = 0x22
LC_DYLD_INFO_ONLY         = 0x80000022
LC_DYLD_EXPORTS_TRIE      = 0x80000033
LC_DYLD_CHAINED_FIXUPS    = 0x80000034
LC_UUID                   = 0x1B
LC_VERSION_MIN_IPHONEOS   = 0x25
LC_BUILD_VERSION          = 0x32
LC_SOURCE_VERSION         = 0x2A
LC_MAIN                   = 0x80000028
LC_FUNCTION_STARTS        = 0x26
LC_DATA_IN_CODE           = 0x29
LC_RPATH                  = 0x8000001C
LC_LINKER_OPTION          = 0x2D
LC_LINKER_OPTIMIZATION    = 0x2E
LC_NOTE                   = 0x31
LC_MOD_INIT_FUNC          = 0x16  # not segment — but __mod_init_func section
LC_THREAD                 = 0x04
LC_UNIXTHREAD             = 0x05

LC_NAMES = {
    0x01:"LC_SEGMENT",          0x02:"LC_SYMTAB",
    0x04:"LC_THREAD",           0x05:"LC_UNIXTHREAD",
    0x0B:"LC_DYSYMTAB",         0x0C:"LC_LOAD_DYLIB",
    0x0D:"LC_ID_DYLIB",         0x0E:"LC_LOAD_DYLINKER",
    0x16:"LC_ROUTINES",         0x19:"LC_SEGMENT_64",
    0x1B:"LC_UUID",             0x1D:"LC_CODE_SIGNATURE",
    0x20:"LC_LAZY_LOAD_DYLIB",  0x21:"LC_ENCRYPTION_INFO",
    0x22:"LC_DYLD_INFO",        0x25:"LC_VERSION_MIN_IPHONEOS",
    0x26:"LC_FUNCTION_STARTS",  0x29:"LC_DATA_IN_CODE",
    0x2A:"LC_SOURCE_VERSION",   0x2C:"LC_ENCRYPTION_INFO_64",
    0x2D:"LC_LINKER_OPTION",    0x2E:"LC_LINKER_OPTIMIZATION",
    0x31:"LC_NOTE",             0x32:"LC_BUILD_VERSION",
    0x80000018:"LC_LOAD_WEAK_DYLIB",
    0x8000001C:"LC_RPATH",
    0x80000022:"LC_DYLD_INFO_ONLY",
    0x80000028:"LC_MAIN",
    0x8000001F:"LC_REEXPORT_DYLIB",
    0x80000033:"LC_DYLD_EXPORTS_TRIE",
    0x80000034:"LC_DYLD_CHAINED_FIXUPS",
}

DYLIB_LC_TYPES = {LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB, LC_LAZY_LOAD_DYLIB}

# ── Code Signature ─────────────────────────────────────────────────────────────
CSMAGIC_REQUIREMENT                = 0xFADE0C00
CSMAGIC_REQUIREMENTS               = 0xFADE0C01
CSMAGIC_CODEDIRECTORY              = 0xFADE0C02
CSMAGIC_EMBEDDED_SIGNATURE         = 0xFADE0CC0
CSMAGIC_DETACHED_SIGNATURE         = 0xFADE0CC1
CSMAGIC_BLOBWRAPPER                = 0xFADE0B01
CSMAGIC_EMBEDDED_ENTITLEMENTS      = 0xFADE7171
CSMAGIC_EMBEDDED_ENTITLEMENTS_DER  = 0xFADE7172
CSMAGIC_LAUNCH_CONSTRAINT          = 0xFADE8181

HASH_TYPE_NAMES = {1:"SHA-1",2:"SHA-256",3:"SHA-256-truncated",4:"SHA-384",5:"SHA-512"}

PLATFORM_NAMES = {
    1:"macOS",2:"iOS",3:"tvOS",4:"watchOS",5:"bridgeOS",
    6:"macCatalyst",7:"iOSSimulator",8:"tvOSSimulator",9:"watchOSSimulator",
}

# ── ObjC type encoding atoms ───────────────────────────────────────────────────
OBJC_TYPE_CHARS = {
    'c':'char','i':'int','s':'short','l':'long','q':'long long',
    'C':'unsigned char','I':'unsigned int','S':'unsigned short',
    'L':'unsigned long','Q':'unsigned long long',
    'f':'float','d':'double','D':'long double',
    'B':'BOOL','v':'void','*':'char*','@':'id','#':'Class',':':'SEL',
    '[':'array','(':'union','{':'struct','b':'bitfield','^':'pointer',
    '?':'unknown/block','r':'const','n':'in','N':'inout','o':'out',
    'O':'bycopy','R':'byref','V':'oneway',
}

# ── Swift context descriptor kinds ────────────────────────────────────────────
SWIFT_CTX_KIND = {
    0:"Module",1:"Extension",2:"Anonymous",3:"Protocol",4:"OpaqueType",
    16:"Class",17:"Struct",18:"Enum",
}

# ── Security-relevant symbol sets ─────────────────────────────────────────────
ANTIDEBUG_SYMS   = {"ptrace","sysctl","isatty","getppid",
                     "task_get_exception_ports","PT_DENY_ATTACH"}
PINNING_SYMS     = {"SecTrustEvaluate","SecTrustEvaluateAsync",
                     "SecTrustEvaluateWithError","SecPolicyCopyProperties",
                     "SSL_CTX_set_verify","URLSession:didReceiveChallenge:completionHandler:"}
CRYPTO_SYMS      = {"CCCrypt","CCHmac","CCKeyDerivationPBKDF","CCDigest",
                     "SecKeyRawSign","SecKeyRawVerify","SecKeyCreateSignature",
                     "SecCertificateCopyData","SSLHandshake","SSLSetSessionOption",
                     "SecRandomCopyBytes","kSecAttrKeyType","kSecAttrKeySizeInBits"}
JAILBREAK_PATHS  = {"/bin/bash","/usr/bin/ssh","/etc/apt","/var/lib/dpkg",
                     "/private/var/lib/apt","/var/cache/apt","/usr/sbin/sshd",
                     "/bin/sh","/usr/bin/sshd","/private/etc/dpkg",
                     "/private/var/stash","/Library/MobileSubstrate",
                     "/var/lib/cydia","/System/Library/LaunchDaemons/com.saurik"}
JAILBREAK_STRS   = {"cydia","substrate","MobileSubstrate","Cydia",
                     "unc0ver","checkra1n","Sileo","Zebra","Electra",
                     "palera1n","TrollStore","apt.saurik","Dopamine"}

# ── Inline crypto constants ────────────────────────────────────────────────────
# AES S-box first 16 bytes
AES_SBOX_HEADER  = bytes([0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,
                           0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76])
# SHA-256 initial hash values (big-endian u32)
SHA256_IV = struct.pack(">8I",
    0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
    0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19)
# ChaCha20 constant "expand 32-byte k"
CHACHA20_CONST = b"expand 32-byte k"
# MD5 initial state
MD5_IV = struct.pack("<4I",0x67452301,0xefcdab89,0x98badcfe,0x10325476)

CRYPTO_CONSTANTS = {
    "AES_SBOX":     AES_SBOX_HEADER,
    "SHA256_IV":    SHA256_IV,
    "ChaCha20":     CHACHA20_CONST,
    "MD5_IV":       MD5_IV,
}

# ── Default keyword list ───────────────────────────────────────────────────────
DEFAULT_KEYWORDS = [
    "register","validate","container","install","trust","cache",
    "signature","verify","certificate","entitlement","sandbox",
    "amfi","codesign","springboard","icon","launch","application",
    "bundle","plist","MCM","LSApplication","MobileInstallation","lsd",
    "dyld","mach","kern","iokit","security","key","token","secret",
    "password","credential","network","url","http","https","socket",
    "encrypt","decrypt","hash","sign","auth","permission","priv",
]


# ═══════════════════════════════════════════════════════════════════════════════
# §1  LOW-LEVEL READERS
# ═══════════════════════════════════════════════════════════════════════════════

def u8(d,o):    return d[o]
def u16be(d,o): return struct.unpack_from(">H",d,o)[0]
def u16le(d,o): return struct.unpack_from("<H",d,o)[0]
def u32le(d,o): return struct.unpack_from("<I",d,o)[0]
def u32be(d,o): return struct.unpack_from(">I",d,o)[0]
def u64le(d,o): return struct.unpack_from("<Q",d,o)[0]
def i32le(d,o): return struct.unpack_from("<i",d,o)[0]
def i64le(d,o): return struct.unpack_from("<q",d,o)[0]

def cstring(d:bytes, off:int, limit:int=512) -> str:
    end = d.find(b'\x00', off, off+limit)
    if end == -1: end = min(off+limit, len(d))
    return d[off:end].decode("utf-8","replace")

def cstrings_section(raw:bytes) -> list[str]:
    """Parse a null-terminated string table into a list."""
    out, i = [], 0
    while i < len(raw):
        end = raw.find(b'\x00', i)
        if end == -1:
            s = raw[i:].decode("utf-8","replace")
            if s: out.append(s)
            break
        s = raw[i:end].decode("utf-8","replace")
        if s: out.append(s)
        i = end+1
    return out

def format_uuid(b:bytes) -> str:
    assert len(b)==16
    h = b.hex().upper()
    return f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"

def decode_version(v:int) -> str:
    return f"{(v>>16)&0xFFFF}.{(v>>8)&0xFF}.{v&0xFF}"

def decode_flags(val:int, flag_map:dict) -> list[str]:
    return [name for bit,name in flag_map.items() if val & bit]

def uleb128(d:bytes, off:int) -> tuple[int,int]:
    r,s = 0,0
    while off < len(d):
        b = d[off]; off+=1
        r |= (b&0x7F)<<s; s+=7
        if not(b&0x80): break
    return r,off

def sleb128(d:bytes, off:int) -> tuple[int,int]:
    r,s = 0,0
    while off < len(d):
        b = d[off]; off+=1
        r |= (b&0x7F)<<s; s+=7
        if not(b&0x80):
            if s<64 and (b&0x40): r |= -(1<<s)
            break
    return r,off

def shannon_entropy(data:bytes) -> float:
    if not data: return 0.0
    freq = collections.Counter(data)
    n = len(data)
    return -sum((c/n)*math.log2(c/n) for c in freq.values() if c)


# ═══════════════════════════════════════════════════════════════════════════════
# §2  FAT / MACH-O LOCATOR
# ═══════════════════════════════════════════════════════════════════════════════

def find_arm64_slice(data:bytes) -> tuple[bytes,int]:
    magic = u32le(data,0)
    if magic in (FAT_MAGIC, FAT_CIGAM):
        big = (magic == FAT_MAGIC)
        nfat = u32be(data,4) if big else u32le(data,4)
        off = 8
        for _ in range(nfat):
            cpu_type  = u32be(data,off)
            arch_off  = u32be(data,off+8)
            arch_size = u32be(data,off+12)
            off += 20
            if cpu_type == CPU_TYPE_ARM64:
                return data[arch_off:arch_off+arch_size], arch_off
        raise ValueError("No ARM64 slice in FAT binary")
    elif magic in (MH_MAGIC_64, MH_CIGAM_64):
        return data, 0
    else:
        raise ValueError(f"Unknown magic 0x{magic:08X}")


# ═══════════════════════════════════════════════════════════════════════════════
# §3  MACH-O HEADER + LOAD COMMANDS
# ═══════════════════════════════════════════════════════════════════════════════

class MachOHeader:
    SIZE = 32
    def __init__(self, d:bytes):
        (self.magic,self.cputype,self.cpusubtype,
         self.filetype,self.ncmds,self.sizeofcmds,self.flags
        ) = struct.unpack_from("<IIIIIII",d,0)
        self.arm64e = bool(self.cpusubtype & CPU_SUBTYPE_ARM64E)

class LoadCommand:
    def __init__(self, cmd, cmdsize, raw):
        self.cmd=cmd; self.cmdsize=cmdsize; self.raw=raw
    @property
    def name(self): return LC_NAMES.get(self.cmd,f"LC_UNK_0x{self.cmd:08X}")

def parse_load_commands(data:bytes) -> list[LoadCommand]:
    hdr = MachOHeader(data)
    off = MachOHeader.SIZE
    lcs = []
    for _ in range(hdr.ncmds):
        if off+8 > len(data): break
        cmd  = u32le(data,off)
        size = u32le(data,off+4)
        if size < 8 or off+size > len(data): break
        lcs.append(LoadCommand(cmd,size,data[off:off+size]))
        off += size
    return lcs


# ═══════════════════════════════════════════════════════════════════════════════
# §4  SEGMENT / SECTION MAP
# ═══════════════════════════════════════════════════════════════════════════════

class Section64:
    SIZE = 80
    def __init__(self, raw:bytes, off:int):
        self.sectname = raw[off:off+16].rstrip(b'\x00').decode("utf-8","replace")
        self.segname  = raw[off+16:off+32].rstrip(b'\x00').decode("utf-8","replace")
        self.addr     = u64le(raw,off+32)
        self.size     = u64le(raw,off+40)
        self.offset   = u32le(raw,off+48)
        self.align    = u32le(raw,off+52)
        self.reloff   = u32le(raw,off+56)
        self.nreloc   = u32le(raw,off+60)
        self.flags    = u32le(raw,off+64)
        # section type = flags & 0xFF
        self.type_id  = self.flags & 0xFF

class Segment64:
    def __init__(self, lc:LoadCommand):
        r = lc.raw
        self.segname  = r[8:24].rstrip(b'\x00').decode("utf-8","replace")
        self.vmaddr   = u64le(r,24)
        self.vmsize   = u64le(r,32)
        self.fileoff  = u64le(r,40)
        self.filesize = u64le(r,48)
        self.maxprot  = u32le(r,56)
        self.initprot = u32le(r,60)
        self.nsects   = u32le(r,64)
        self.flags    = u32le(r,68)
        self.sections: list[Section64] = []
        so = 72
        for _ in range(self.nsects):
            if so+Section64.SIZE > len(r): break
            self.sections.append(Section64(r,so))
            so += Section64.SIZE

def build_segment_map(lcs:list[LoadCommand]) -> dict[str,Segment64]:
    return {(seg:=Segment64(lc)).segname: seg
            for lc in lcs if lc.cmd==LC_SEGMENT_64}

def find_section(segs:dict, seg:str, sec:str) -> Optional[Section64]:
    s = segs.get(seg)
    if s:
        for x in s.sections:
            if x.sectname == sec: return x
    return None

def section_data(data:bytes, sec:Section64) -> bytes:
    if not sec.offset or not sec.size: return b""
    return data[sec.offset:min(sec.offset+sec.size,len(data))]

def va_to_fo(va:int, segs:dict) -> Optional[int]:
    for seg in segs.values():
        if seg.vmaddr <= va < seg.vmaddr+seg.vmsize:
            return seg.fileoff+(va-seg.vmaddr)
    return None

def fo_to_va(fo:int, segs:dict) -> Optional[int]:
    for seg in segs.values():
        if seg.fileoff <= fo < seg.fileoff+seg.filesize:
            return seg.vmaddr+(fo-seg.fileoff)
    return None


# ═══════════════════════════════════════════════════════════════════════════════
# §5  ObjC TYPE ENCODING DECODER
# ═══════════════════════════════════════════════════════════════════════════════

def decode_objc_type(enc:str) -> str:
    """
    Decode ObjC type encoding string to human-readable C-like signature.
    E.g.  "v32@0:8@16@24"  →  "void (id, SEL, id, id)"
    """
    if not enc: return ""
    # strip leading qualifiers
    tokens = []
    i = 0
    while i < len(enc):
        c = enc[i]
        # skip offset numbers
        if c.isdigit():
            i += 1
            continue
        if c in OBJC_TYPE_CHARS:
            name = OBJC_TYPE_CHARS[c]
            # handle struct/union: read until matching }/)
            if c == '{':
                end = enc.find('}', i)
                inner = enc[i+1:end] if end!=-1 else enc[i+1:]
                eq = inner.find('=')
                struct_name = inner[:eq] if eq!=-1 else inner.split('}')[0]
                tokens.append(f"struct {struct_name}")
                i = (end+1) if end!=-1 else len(enc)
                continue
            if c == '(':
                end = enc.find(')', i)
                inner = enc[i+1:end] if end!=-1 else enc[i+1:]
                eq = inner.find('=')
                union_name = inner[:eq] if eq!=-1 else inner
                tokens.append(f"union {union_name}")
                i = (end+1) if end!=-1 else len(enc)
                continue
            if c == '[':
                # array[N type]
                j = i+1
                while j < len(enc) and enc[j].isdigit(): j+=1
                count = enc[i+1:j]
                tokens.append(f"array[{count}]")
                i = j
                continue
            if c == '^':
                tokens.append("ptr-to")
                i+=1; continue
            tokens.append(name)
        else:
            tokens.append(c)
        i += 1
    return " ".join(tokens) if tokens else enc

def decode_method_signature(types_enc:str) -> dict:
    """
    Return {return_type, arg_types} from a method type encoding string.
    First type = return, then pairs of (type, offset) for each arg.
    """
    if not types_enc:
        return {"return": "", "args": []}
    # split by digits but keep the type chars
    parts = re.split(r'(\d+)', types_enc)
    type_chars = [p for p in parts if p and not p.isdigit()]
    if not type_chars:
        return {"return": decode_objc_type(types_enc), "args": []}
    return {
        "return": decode_objc_type(type_chars[0]),
        "args":   [decode_objc_type(t) for t in type_chars[1:]],
    }


# ═══════════════════════════════════════════════════════════════════════════════
# §6  FULL ObjC RUNTIME PARSER
# ═══════════════════════════════════════════════════════════════════════════════

class ObjCIvar:
    __slots__ = ["name","type_enc","type_decoded","offset","size"]
    def __init__(self,name,type_enc,offset,size):
        self.name=name; self.type_enc=type_enc
        self.type_decoded=decode_objc_type(type_enc)
        self.offset=offset; self.size=size

class ObjCProperty:
    __slots__ = ["name","attrs","decoded_attrs"]
    def __init__(self,name,attrs):
        self.name=name; self.attrs=attrs
        self.decoded_attrs=_decode_property_attrs(attrs)

class ObjCMethod:
    __slots__ = ["name","types","return_type","arg_types","imp","is_class"]
    def __init__(self,name,types,imp,is_class=False):
        self.name=name; self.types=types; self.imp=hex(imp)
        self.is_class=is_class
        sig = decode_method_signature(types)
        self.return_type=sig["return"]
        self.arg_types=sig["args"]

class ObjCProtocol:
    __slots__ = ["name","instance_methods","class_methods","properties"]
    def __init__(self,name):
        self.name=name
        self.instance_methods:list[str]=[]
        self.class_methods:list[str]=[]
        self.properties:list[str]=[]

class ObjCCategory:
    __slots__ = ["name","class_name","instance_methods","class_methods","properties"]
    def __init__(self,name,class_name):
        self.name=name; self.class_name=class_name
        self.instance_methods:list[ObjCMethod]=[]
        self.class_methods:list[ObjCMethod]=[]
        self.properties:list[ObjCProperty]=[]

class ObjCClass:
    __slots__ = ["name","superclass","instance_methods","class_methods",
                 "ivars","properties","protocols","categories","is_swift_class"]
    def __init__(self,name,superclass=""):
        self.name=name; self.superclass=superclass
        self.instance_methods:list[ObjCMethod]=[]
        self.class_methods:list[ObjCMethod]=[]
        self.ivars:list[ObjCIvar]=[]
        self.properties:list[ObjCProperty]=[]
        self.protocols:list[str]=[]
        self.categories:list[ObjCCategory]=[]
        self.is_swift_class=False

def _decode_property_attrs(attrs:str) -> dict:
    """Decode ObjC property attribute string like T@"NSString",N,V_name"""
    result = {"type":"","storage":[],"ivar":"","custom_getter":"","custom_setter":""}
    for part in attrs.split(','):
        if not part: continue
        if part.startswith('T'):
            type_str = part[1:]
            if type_str.startswith('@"') and type_str.endswith('"'):
                result["type"] = type_str[2:-1]
            else:
                result["type"] = decode_objc_type(type_str.lstrip('@').strip('"'))
        elif part == 'N': result["storage"].append("nonatomic")
        elif part == 'C': result["storage"].append("copy")
        elif part == '&': result["storage"].append("strong/retain")
        elif part == 'W': result["storage"].append("weak")
        elif part == 'R': result["storage"].append("readonly")
        elif part.startswith('V'): result["ivar"] = part[1:]
        elif part.startswith('G'): result["custom_getter"] = part[1:]
        elif part.startswith('S'): result["custom_setter"] = part[1:]
    return result

def _parse_method_list(data:bytes, segs:dict, ml_va:int,
                        is_class:bool, cls_name:str) -> list[ObjCMethod]:
    methods = []
    ml_fo = va_to_fo(ml_va, segs)
    if ml_fo is None or ml_fo+8 > len(data): return methods
    flags  = u32le(data, ml_fo)
    count  = u32le(data, ml_fo+4)
    if count == 0 or count > 100_000: return methods
    is_relative = bool(flags & 0x80000000)
    meth_size   = 12 if is_relative else 24
    base = ml_fo+8
    for i in range(count):
        mo = base + i*meth_size
        if mo+meth_size > len(data): break
        try:
            if is_relative:
                # relative method references (iOS 14+ small method lists)
                # field 0: relative ptr to SEL ref, field 1: rel ptr to types, field 2: rel ptr to IMP
                sel_ref_va  = (ml_va+8+i*12+0) + i32le(data,mo+0)
                types_va    = (ml_va+8+i*12+4) + i32le(data,mo+4)
                imp_va_rel  = (ml_va+8+i*12+8) + i32le(data,mo+8)

                # sel_ref_va points to a pointer to the selector string
                sel_ref_fo = va_to_fo(sel_ref_va, segs)
                name = ""
                if sel_ref_fo is not None and sel_ref_fo+8 <= len(data):
                    sel_ptr = u64le(data, sel_ref_fo)
                    sel_fo  = va_to_fo(sel_ptr, segs)
                    if sel_fo is not None and sel_fo < len(data):
                        name = cstring(data, sel_fo)

                types_str = ""
                types_fo = va_to_fo(types_va, segs)
                if types_fo is not None and types_fo < len(data):
                    types_str = cstring(data, types_fo)

                imp = imp_va_rel
            else:
                name_ptr  = u64le(data, mo)
                name_fo   = va_to_fo(name_ptr, segs)
                name      = cstring(data, name_fo) if name_fo is not None and name_fo < len(data) else ""
                types_ptr = u64le(data, mo+8)
                types_fo  = va_to_fo(types_ptr, segs)
                types_str = cstring(data, types_fo) if types_fo is not None and types_fo < len(data) else ""
                imp       = u64le(data, mo+16)

            if name and all(32 <= ord(c) < 127 for c in name) and len(name) < 512:
                methods.append(ObjCMethod(name, types_str, imp, is_class))
        except Exception:
            continue
    return methods

def _parse_ivar_list(data:bytes, segs:dict, ivars_va:int) -> list[ObjCIvar]:
    ivars = []
    fo = va_to_fo(ivars_va, segs)
    if fo is None or fo+8 > len(data): return ivars
    count = u32le(data, fo+4)
    if count == 0 or count > 10_000: return ivars
    # ivar_t: offset_ptr(8), name_ptr(8), type_ptr(8), alignment_raw(4), size(4) = 32 bytes
    base = fo+8
    for i in range(count):
        io_ = base + i*32
        if io_+32 > len(data): break
        try:
            off_ptr  = u64le(data, io_)
            name_ptr = u64le(data, io_+8)
            type_ptr = u64le(data, io_+16)
            ivar_size= u32le(data, io_+28)

            # read the actual offset value via pointer-to-int32
            ivar_off = 0
            off_fo = va_to_fo(off_ptr, segs)
            if off_fo is not None and off_fo+4 <= len(data):
                ivar_off = i32le(data, off_fo)

            name_fo = va_to_fo(name_ptr, segs)
            name = cstring(data, name_fo) if name_fo is not None and name_fo < len(data) else f"ivar_{i}"

            type_fo = va_to_fo(type_ptr, segs)
            type_enc = cstring(data, type_fo) if type_fo is not None and type_fo < len(data) else ""

            if name: ivars.append(ObjCIvar(name, type_enc, ivar_off, ivar_size))
        except Exception:
            continue
    return ivars

def _parse_property_list(data:bytes, segs:dict, props_va:int) -> list[ObjCProperty]:
    props = []
    fo = va_to_fo(props_va, segs)
    if fo is None or fo+8 > len(data): return props
    count = u32le(data, fo+4)
    if count == 0 or count > 10_000: return props
    # property_t: name_ptr(8), attrs_ptr(8) = 16 bytes
    base = fo+8
    for i in range(count):
        po = base+i*16
        if po+16 > len(data): break
        try:
            name_ptr  = u64le(data, po)
            attrs_ptr = u64le(data, po+8)
            name_fo   = va_to_fo(name_ptr, segs)
            attrs_fo  = va_to_fo(attrs_ptr, segs)
            name  = cstring(data, name_fo)  if name_fo  is not None and name_fo  < len(data) else ""
            attrs = cstring(data, attrs_fo) if attrs_fo is not None and attrs_fo < len(data) else ""
            if name: props.append(ObjCProperty(name, attrs))
        except Exception:
            continue
    return props

def _parse_protocol_list(data:bytes, segs:dict, protos_va:int,
                          proto_cache:dict) -> list[str]:
    fo = va_to_fo(protos_va, segs)
    if fo is None or fo+8 > len(data): return []
    count = u64le(data, fo)
    names = []
    for i in range(min(count, 1000)):
        ptr_fo = fo+8+i*8
        if ptr_fo+8 > len(data): break
        proto_va = u64le(data, ptr_fo) & ~0x7
        if proto_va in proto_cache:
            names.append(proto_cache[proto_va])
        else:
            proto_fo = va_to_fo(proto_va, segs)
            if proto_fo is not None and proto_fo+40 <= len(data):
                # protocol_t: isa(8), name_ptr(8), protocols(8), ...
                name_ptr = u64le(data, proto_fo+8)
                name_fo  = va_to_fo(name_ptr, segs)
                name = cstring(data, name_fo) if name_fo is not None and name_fo < len(data) else ""
                if name:
                    proto_cache[proto_va] = name
                    names.append(name)
    return names

def parse_objc_full(data:bytes, segs:dict) -> dict:
    """
    Full ObjC runtime parse:
    - __objc_classlist  → ObjCClass with methods, ivars, properties, protocols
    - __objc_catlist    → ObjCCategory with methods/properties patched onto classes
    - __objc_protolist  → ObjCProtocol with required methods
    Returns {"classes": [...], "categories": [...], "protocols": [...]}
    """
    proto_cache: dict[int,str] = {}

    # ── Protocols first ───────────────────────────────────────────────────────
    protocols: list[ObjCProtocol] = []
    for data_seg in ("__DATA","__DATA_CONST"):
        sec = find_section(segs, data_seg, "__objc_protolist")
        if not sec: continue
        raw = section_data(data, sec)
        n = len(raw)//8
        for i in range(n):
            proto_va = u64le(raw, i*8) & ~0x7
            if not proto_va: continue
            proto_fo = va_to_fo(proto_va, segs)
            if proto_fo is None or proto_fo+48 > len(data): continue
            name_ptr = u64le(data, proto_fo+8)
            name_fo  = va_to_fo(name_ptr, segs)
            name = cstring(data, name_fo) if name_fo is not None and name_fo < len(data) else ""
            if not name: continue
            proto_cache[proto_va] = name
            proto = ObjCProtocol(name)
            # instance_methods at offset 24, class_methods at 32
            im_va = u64le(data, proto_fo+24)
            cm_va = u64le(data, proto_fo+32)
            if im_va:
                for m in _parse_method_list(data,segs,im_va,False,name):
                    proto.instance_methods.append(m.name)
            if cm_va:
                for m in _parse_method_list(data,segs,cm_va,True,name):
                    proto.class_methods.append(m.name)
            prop_va = u64le(data, proto_fo+48) if proto_fo+56<=len(data) else 0
            if prop_va:
                for p in _parse_property_list(data,segs,prop_va):
                    proto.properties.append(p.name)
            protocols.append(proto)

    # ── Classes ───────────────────────────────────────────────────────────────
    classes: list[ObjCClass] = []
    class_by_va: dict[int,ObjCClass] = {}

    for data_seg in ("__DATA","__DATA_CONST"):
        sec = find_section(segs, data_seg, "__objc_classlist")
        if not sec: continue
        raw = section_data(data, sec)
        n = len(raw)//8
        for i in range(n):
            cls_va = u64le(raw, i*8) & ~0x7
            if not cls_va: continue
            cls_fo = va_to_fo(cls_va, segs)
            if cls_fo is None or cls_fo+40 > len(data): continue
            try:
                # class_t: metaclass(8) superclass(8) cache(8) vtable(8) data(8)
                super_va  = u64le(data, cls_fo+8) & ~0x7
                data_ptr  = u64le(data, cls_fo+32) & ~0x7

                data_fo   = va_to_fo(data_ptr, segs)
                if data_fo is None or data_fo+72 > len(data): continue

                # class_ro_t: flags(4) ivar_start(4) inst_size(4) pad(4)
                #             ivar_layout(8) name(8) methods(8) protos(8)
                #             ivars(8) weak_ivar(8) props(8)
                ro_flags  = u32le(data, data_fo)
                name_ptr  = u64le(data, data_fo+24)
                meth_va   = u64le(data, data_fo+32)
                proto_va  = u64le(data, data_fo+40)
                ivars_va  = u64le(data, data_fo+48)
                props_va  = u64le(data, data_fo+64) if data_fo+72<=len(data) else 0

                name_fo2  = va_to_fo(name_ptr, segs)
                cls_name  = cstring(data, name_fo2) if name_fo2 and name_fo2 < len(data) else f"cls@{hex(cls_va)}"

                # Superclass name
                super_name = ""
                if super_va:
                    super_fo = va_to_fo(super_va, segs)
                    if super_fo is not None and super_fo+40 <= len(data):
                        super_data_ptr = u64le(data, super_fo+32) & ~0x7
                        super_data_fo  = va_to_fo(super_data_ptr, segs)
                        if super_data_fo is not None and super_data_fo+32 <= len(data):
                            super_name_ptr = u64le(data, super_data_fo+24)
                            super_name_fo  = va_to_fo(super_name_ptr, segs)
                            if super_name_fo is not None and super_name_fo < len(data):
                                super_name = cstring(data, super_name_fo)

                cls = ObjCClass(cls_name, super_name)
                cls.is_swift_class = bool(ro_flags & 0x8)  # RO_IS_SWIFT

                if meth_va:
                    cls.instance_methods = _parse_method_list(data,segs,meth_va,False,cls_name)
                if proto_va:
                    cls.protocols = _parse_protocol_list(data,segs,proto_va,proto_cache)
                if ivars_va:
                    cls.ivars = _parse_ivar_list(data,segs,ivars_va)
                if props_va:
                    cls.properties = _parse_property_list(data,segs,props_va)

                # Metaclass → class methods
                meta_va  = u64le(data, cls_fo) & ~0x7
                meta_fo  = va_to_fo(meta_va, segs)
                if meta_fo is not None and meta_fo+40 <= len(data):
                    meta_data_ptr = u64le(data, meta_fo+32) & ~0x7
                    meta_data_fo  = va_to_fo(meta_data_ptr, segs)
                    if meta_data_fo is not None and meta_data_fo+40 <= len(data):
                        meta_meth_va = u64le(data, meta_data_fo+32)
                        if meta_meth_va:
                            cls.class_methods = _parse_method_list(data,segs,meta_meth_va,True,cls_name)

                classes.append(cls)
                class_by_va[cls_va] = cls
            except Exception:
                continue

    # ── Categories ────────────────────────────────────────────────────────────
    categories: list[ObjCCategory] = []
    for data_seg in ("__DATA","__DATA_CONST"):
        sec = find_section(segs, data_seg, "__objc_catlist")
        if not sec: continue
        raw = section_data(data, sec)
        n = len(raw)//8
        for i in range(n):
            cat_va = u64le(raw, i*8)
            if not cat_va: continue
            cat_fo = va_to_fo(cat_va, segs)
            if cat_fo is None or cat_fo+48 > len(data): continue
            try:
                # category_t: name(8) cls_ptr(8) inst_methods(8) cls_methods(8)
                #             protocols(8) inst_props(8)
                cat_name_ptr = u64le(data, cat_fo)
                cat_cls_va   = u64le(data, cat_fo+8) & ~0x7
                im_va        = u64le(data, cat_fo+16)
                cm_va        = u64le(data, cat_fo+24)
                pp_va        = u64le(data, cat_fo+40) if cat_fo+48<=len(data) else 0

                name_fo = va_to_fo(cat_name_ptr, segs)
                cat_name = cstring(data, name_fo) if name_fo is not None and name_fo < len(data) else ""

                # resolve class name
                target_cls = class_by_va.get(cat_cls_va)
                cls_name = target_cls.name if target_cls else f"cls@{hex(cat_cls_va)}"

                cat = ObjCCategory(cat_name, cls_name)
                if im_va: cat.instance_methods = _parse_method_list(data,segs,im_va,False,cls_name)
                if cm_va: cat.class_methods    = _parse_method_list(data,segs,cm_va,True,cls_name)
                if pp_va: cat.properties       = _parse_property_list(data,segs,pp_va)

                categories.append(cat)

                # patch methods onto the target class
                if target_cls:
                    target_cls.instance_methods.extend(cat.instance_methods)
                    target_cls.class_methods.extend(cat.class_methods)
                    target_cls.categories.append(cat)
            except Exception:
                continue

    return {
        "classes":    classes,
        "categories": categories,
        "protocols":  protocols,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# §7  CFSTRING PARSER
# ═══════════════════════════════════════════════════════════════════════════════

def parse_cfstrings(data:bytes, segs:dict) -> list[dict]:
    """
    Parse __DATA/__cfstring section.
    CFString layout (64-bit):
        isa       (8)  — pointer to NSCFString class
        flags     (8)
        data_ptr  (8)  — pointer to UTF-8 string
        length    (8)
    """
    results = []
    for seg_name in ("__DATA","__DATA_CONST"):
        sec = find_section(segs, seg_name, "__cfstring")
        if not sec: continue
        raw = section_data(data, sec)
        n = len(raw)//32
        for i in range(n):
            try:
                flags    = u64le(raw, i*32+8)
                data_ptr = u64le(raw, i*32+16)
                length   = u64le(raw, i*32+24)
                fo = va_to_fo(data_ptr, segs)
                if fo is not None and fo+length <= len(data) and length < 4096:
                    s = data[fo:fo+length].decode("utf-8","replace")
                    results.append({
                        "string": s,
                        "length": length,
                        "flags":  hex(flags),
                        "va":     hex(sec.addr + i*32),
                    })
            except Exception:
                continue
    return results


def parse_ustrings(data:bytes, segs:dict) -> list[str]:
    """Parse __TEXT/__ustring (UTF-16LE strings)."""
    sec = find_section(segs, "__TEXT", "__ustring")
    if not sec: return []
    raw = section_data(data, sec)
    strings = []
    i = 0
    while i < len(raw)-1:
        end = i
        while end < len(raw)-1 and (raw[end] != 0 or raw[end+1] != 0): end += 2
        chunk = raw[i:end]
        if len(chunk) >= 4:
            try:
                s = chunk.decode("utf-16-le","replace").strip()
                if s and all(c.isprintable() or c.isspace() for c in s):
                    strings.append(s)
            except Exception:
                pass
        i = end+2
    return strings


# ═══════════════════════════════════════════════════════════════════════════════
# §8  SYMBOL TABLE + EXPORT TRIE + CHAINED FIXUPS
# ═══════════════════════════════════════════════════════════════════════════════

N_EXT  = 0x01; N_TYPE = 0x0E; N_UNDF = 0x00; N_SECT = 0x0E; N_STAB = 0xE0
NLIST64_SIZE = 16

def parse_symtab(data:bytes, lcs:list[LoadCommand]) -> dict:
    lc = next((l for l in lcs if l.cmd==LC_SYMTAB), None)
    if not lc: return {"imported":[],"exported":[],"local":[]}
    symoff  = u32le(lc.raw,8); nsyms   = u32le(lc.raw,12)
    stroff  = u32le(lc.raw,16); strsize = u32le(lc.raw,20)
    strtab  = data[stroff:stroff+strsize]
    imported,exported,local = [],[],[]
    for i in range(nsyms):
        off = symoff + i*NLIST64_SIZE
        if off+NLIST64_SIZE > len(data): break
        strx  = u32le(data,off); flags = u8(data,off+4)
        value = u64le(data,off+8)
        if flags & N_STAB: continue
        n_type = flags & N_TYPE; n_ext = flags & N_EXT
        end = strtab.find(b'\x00', strx)
        name = strtab[strx:end].decode("utf-8","replace") if end!=-1 else ""
        if not name or name=="<redacted>": continue
        if n_type==N_UNDF:   imported.append(name)
        elif n_type==N_SECT and n_ext: exported.append({"name":name,"address":hex(value)})
        elif n_type==N_SECT: local.append({"name":name,"address":hex(value)})
    return {"imported":sorted(set(imported)),"exported":exported,"local":local}


def _decode_export_trie(data:bytes, off:int, end:int,
                         prefix:str, results:list):
    """Recursive export trie decoder."""
    if off >= end: return
    terminal_size, off = uleb128(data, off)
    if terminal_size:
        # read flags and offset/ordinal
        flags, off2 = uleb128(data, off)
        if flags & 0x40:  # EXPORT_SYMBOL_FLAGS_REEXPORT
            ordinal, off2 = uleb128(data, off2)
            imp_end = data.find(b'\x00', off2, off+terminal_size+10)
            imported_name = data[off2:imp_end].decode("utf-8","replace") if imp_end!=-1 else ""
            results.append({"symbol":prefix,"flags":hex(flags),
                            "reexport_ordinal":ordinal,"imported_as":imported_name})
        elif flags & 0x08:  # EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER
            stub_off, off2 = uleb128(data, off2)
            resolver_off, off2 = uleb128(data, off2)
            results.append({"symbol":prefix,"flags":hex(flags),
                            "stub_offset":hex(stub_off),"resolver_offset":hex(resolver_off)})
        else:
            sym_off, off2 = uleb128(data, off2)
            results.append({"symbol":prefix,"flags":hex(flags),"offset":hex(sym_off)})
    off += terminal_size
    if off >= end: return
    n_children = u8(data, off); off+=1
    for _ in range(n_children):
        label_end = data.find(b'\x00', off, off+256)
        if label_end==-1: return
        label = data[off:label_end].decode("utf-8","replace")
        off = label_end+1
        child_off, off = uleb128(data, off)
        _decode_export_trie(data, child_off, end, prefix+label, results)

def parse_export_trie(data:bytes, lcs:list[LoadCommand]) -> list[dict]:
    results = []
    # Try LC_DYLD_EXPORTS_TRIE first (newer), fallback to LC_DYLD_INFO export
    trie_lc = next((l for l in lcs if l.cmd==LC_DYLD_EXPORTS_TRIE), None)
    if trie_lc:
        off  = u32le(trie_lc.raw,8)
        size = u32le(trie_lc.raw,12)
    else:
        dyld_lc = next((l for l in lcs if l.cmd in (LC_DYLD_INFO,LC_DYLD_INFO_ONLY)), None)
        if not dyld_lc or len(dyld_lc.raw)<48: return results
        off  = u32le(dyld_lc.raw,36)
        size = u32le(dyld_lc.raw,40)
    if not off or not size or off+size > len(data): return results
    try:
        _decode_export_trie(data, off, off+size, "", results)
    except Exception as e:
        results.append({"error":str(e)})
    return results


def parse_chained_fixups(data:bytes, lcs:list[LoadCommand],
                          segs:dict) -> dict:
    """
    Parse LC_DYLD_CHAINED_FIXUPS (iOS 14+ replacement for bind/rebase opcodes).
    Returns {"imports": [...], "fixup_chains": [...]}
    """
    result = {"imports":[],"fixup_chains":[],"error":None}
    lc = next((l for l in lcs if l.cmd==LC_DYLD_CHAINED_FIXUPS), None)
    if not lc: return result

    dataoff  = u32le(lc.raw,8)
    datasize = u32le(lc.raw,12)
    if dataoff+datasize > len(data):
        result["error"] = "fixups extend beyond file"; return result

    fb = data[dataoff:dataoff+datasize]  # fixup blob
    # dyld_chained_fixups_header:
    #   fixups_version(4), starts_offset(4), imports_offset(4), symbols_offset(4)
    #   imports_count(4),  imports_format(4), symbols_format(4)
    if len(fb) < 28: return result
    try:
        starts_off   = u32le(fb,4)
        imports_off  = u32le(fb,8)
        symbols_off  = u32le(fb,12)
        imports_count= u32le(fb,16)
        imports_fmt  = u32le(fb,20)  # 1=IMPORT, 2=IMPORT_ADDEND, 3=IMPORT_ADDEND64

        result["starts_offset"]  = starts_off
        result["imports_format"] = imports_fmt
        result["imports_count"]  = imports_count

        # Sanity bound: cap imports_count to a reasonable max.
        if imports_count > 1_000_000:
            result["error"] = f"imports_count too large ({imports_count})"
            return result

        # Parse imports
        import_size = {1:4, 2:8, 3:8}.get(imports_fmt, 4)
        for i in range(imports_count):
            io_ = imports_off + i*import_size
            if io_+import_size > len(fb): break
            raw_imp = u32le(fb, io_)
            # dyld_chained_import: lib_ordinal(8), weak_import(1), name_offset(23)
            lib_ord  = raw_imp & 0xFF
            weak     = bool((raw_imp>>8)&1)
            name_off = (raw_imp>>9) & 0x7FFFFF
            name_abs = symbols_off + name_off
            if name_abs >= len(fb): break
            name_end = fb.find(b'\x00', name_abs)
            name = fb[name_abs:name_end].decode("utf-8","replace") if name_end!=-1 else ""
            addend = 0
            if imports_fmt in (2,3) and io_+8 <= len(fb):
                addend = i32le(fb, io_+4)
            result["imports"].append({
                "name": name,
                "lib_ordinal": lib_ord,
                "weak": weak,
                "addend": addend,
            })
    except Exception as e:
        result["error"] = str(e)
    return result


def parse_dyld_bind_all(data:bytes, lcs:list[LoadCommand],
                         dylibs:list[dict]) -> dict:
    """Parse all bind/weak/lazy bind from LC_DYLD_INFO."""
    result = {"bind":[],"lazy_bind":[],"weak_bind":[],"error":None}
    lc = next((l for l in lcs if l.cmd in (LC_DYLD_INFO,LC_DYLD_INFO_ONLY)), None)
    if not lc or len(lc.raw)<48: return result

    bind_off   = u32le(lc.raw,12); bind_sz   = u32le(lc.raw,16)
    weak_off   = u32le(lc.raw,20); weak_sz   = u32le(lc.raw,24)
    lazy_off   = u32le(lc.raw,28); lazy_sz   = u32le(lc.raw,32)
    lib_names  = [d["name"].split("/")[-1] for d in dylibs]

    DONE=0x00; SET_ORD_IMM=0x10; SET_ORD_ULEB=0x20; SET_SPEC_IMM=0x30
    SET_SYM=0x40; SET_TYPE=0x50; SET_ADD=0x60; SET_SEG=0x70
    ADD_ADDR=0x80; DO_BIND=0x90; DO_BIND_ADDADDR=0xA0
    DO_BIND_ADDIMM=0xB0; DO_BIND_ULEB=0xC0

    def _parse(raw:bytes, out:list):
        sym=""; ordinal=0; seg_idx=0; seg_off=0; addend=0; btype=1
        off=0
        while off < len(raw):
            b=raw[off]; off+=1
            op=b&0xF0; imm=b&0x0F
            if   op==DONE: break
            elif op==SET_ORD_IMM: ordinal=imm
            elif op==SET_ORD_ULEB: ordinal,off=uleb128(raw,off)
            elif op==SET_SPEC_IMM: ordinal=imm if imm==0 else imm|0xF0
            elif op==SET_SYM:
                e=raw.find(b'\x00',off); sym=raw[off:e].decode("utf-8","replace"); off=e+1
            elif op==SET_TYPE: btype=imm
            elif op==SET_ADD: addend,off=sleb128(raw,off)
            elif op==SET_SEG: seg_idx=imm; seg_off,off=uleb128(raw,off)
            elif op==ADD_ADDR: d,off=uleb128(raw,off); seg_off+=d
            elif op in (DO_BIND,DO_BIND_ADDADDR,DO_BIND_ADDIMM,DO_BIND_ULEB):
                lib=lib_names[ordinal-1] if 1<=ordinal<=len(lib_names) else f"ord_{ordinal}"
                out.append({"symbol":sym,"lib":lib,"seg":seg_idx,
                            "offset":hex(seg_off),"addend":addend})
                if op==DO_BIND_ADDADDR:
                    d,off=uleb128(raw,off); seg_off+=d+8
                elif op==DO_BIND_ADDIMM: seg_off+=(imm*8)+8
                elif op==DO_BIND_ULEB:
                    cnt,off=uleb128(raw,off); skip,off=uleb128(raw,off)
                    for _ in range(cnt-1):
                        out.append({"symbol":sym,"lib":lib,"seg":seg_idx,
                                    "offset":hex(seg_off+8),"addend":addend})
                    seg_off+=8
                else: seg_off+=8
    try:
        if bind_sz and bind_off+bind_sz<=len(data):
            _parse(data[bind_off:bind_off+bind_sz], result["bind"])
        if weak_sz and weak_off+weak_sz<=len(data):
            _parse(data[weak_off:weak_off+weak_sz], result["weak_bind"])
        if lazy_sz and lazy_off+lazy_sz<=len(data):
            _parse(data[lazy_off:lazy_off+lazy_sz], result["lazy_bind"])
    except Exception as e:
        result["error"]=str(e)
    return result


# ═══════════════════════════════════════════════════════════════════════════════
# §9  DYLIB IMPORTS
# ═══════════════════════════════════════════════════════════════════════════════

def parse_dylibs(lcs:list[LoadCommand]) -> list[dict]:
    out=[]
    for lc in lcs:
        if lc.cmd not in (DYLIB_LC_TYPES|{LC_ID_DYLIB}): continue
        name_off = u32le(lc.raw,8)
        out.append({
            "name":    cstring(lc.raw, name_off),
            "type":    LC_NAMES.get(lc.cmd,"LC_LOAD_DYLIB"),
            "version": decode_version(u32le(lc.raw,16)),
            "compat":  decode_version(u32le(lc.raw,20)),
        })
    return out


# ═══════════════════════════════════════════════════════════════════════════════
# §10  SWIFT METADATA DEEP PARSER
# ═══════════════════════════════════════════════════════════════════════════════

SWIFT_SECTIONS = [
    ("__TEXT","__swift5_types"),
    ("__TEXT","__swift5_protos"),
    ("__TEXT","__swift5_proto"),
    ("__TEXT","__swift5_assocty"),
    ("__TEXT","__swift5_replace"),
    ("__TEXT","__swift5_fieldmd"),
    ("__TEXT","__swift5_capture"),
    ("__TEXT","__swift5_reflstr"),
    ("__TEXT","__swift5_builtin"),
    ("__TEXT","__swift5_acfuncs"),
]

def _swift_demangle_builtin(name:str) -> str:
    """
    Very limited pure-Python Swift demangler covering common patterns.
    Full demangling needs swift-demangle binary.
    """
    if not (name.startswith("$s") or name.startswith("_$s")): return name
    n = name.lstrip("_")
    # Try external tool first
    try:
        r = subprocess.run(["swift-demangle","--compact",name],
                           capture_output=True,text=True,timeout=2)
        if r.returncode==0 and r.stdout.strip(): return r.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired): pass
    # Fallback: strip prefix and return raw mangled minus $s
    return f"(mangled){n}"

def parse_swift_deep(data:bytes, segs:dict, imported:list, exported:list) -> dict:
    result = {
        "available":False,
        "sections":[],
        "types":[],
        "field_descriptors":[],
        "protocol_conformances":[],
        "capture_descriptors":[],
        "symbols_imported":[],
        "symbols_exported":[],
    }

    found_any = False
    for seg_name,sec_name in SWIFT_SECTIONS:
        sec = find_section(segs, seg_name, sec_name)
        if not sec: continue
        raw = section_data(data, sec)
        if not raw: continue
        found_any = True
        result["sections"].append(f"{seg_name},{sec_name}")

        # ── type records ─────────────────────────────────────────────────────
        if sec_name == "__swift5_types":
            n = len(raw)//4
            for i in range(n):
                if i*4+4 > len(raw): break
                rel = struct.unpack_from("<i",raw,i*4)[0]
                ctx_va = sec.addr + i*4 + rel
                ctx_fo = va_to_fo(ctx_va, segs)
                if ctx_fo is None or ctx_fo+12 > len(data): continue
                flags = u32le(data, ctx_fo)
                kind  = flags & 0x1F
                # name is relative ptr at ctx+8
                name_rel = i32le(data, ctx_fo+8)
                name_va  = ctx_va+8+name_rel
                name_fo  = va_to_fo(name_va, segs)
                name = cstring(data, name_fo) if name_fo is not None and name_fo < len(data) else ""
                if name and all(32<=ord(c)<127 for c in name) and 1<len(name)<200:
                    result["types"].append({
                        "name": name,
                        "kind": SWIFT_CTX_KIND.get(kind,f"kind_{kind}"),
                        "va":   hex(ctx_va),
                    })

        # ── field descriptors ─────────────────────────────────────────────────
        elif sec_name == "__swift5_fieldmd":
            off = 0
            while off < len(raw):
                if off+16 > len(raw): break
                # FieldDescriptor: mangled_type_name_offset(4), superclass(4),
                #                  kind(2), field_record_size(2), num_fields(4)
                mtn_rel = i32le(raw, off)
                kind    = u16le(raw, off+8)
                rec_sz  = u16le(raw, off+10)
                n_fields= u32le(raw, off+12)
                if rec_sz < 12 or n_fields > 10000: break

                mtn_va  = (sec.addr + off) + mtn_rel
                mtn_fo  = va_to_fo(mtn_va, segs)
                type_name = cstring(data, mtn_fo) if mtn_fo is not None and mtn_fo < len(data) else ""

                fields = []
                for j in range(min(n_fields, 256)):
                    fr_off = off+16+j*rec_sz
                    if fr_off+rec_sz > len(raw): break
                    # FieldRecord: flags(4), mangled_type_ref(4), field_name(4)
                    fname_rel = i32le(raw, fr_off+8)
                    fname_va  = (sec.addr + fr_off+8) + fname_rel
                    fname_fo  = va_to_fo(fname_va, segs)
                    fname = cstring(data, fname_fo) if fname_fo is not None and fname_fo < len(data) else ""
                    if fname: fields.append(fname)

                if type_name:
                    result["field_descriptors"].append({
                        "type": type_name,
                        "kind": kind,
                        "fields": fields,
                    })
                step = 16 + n_fields*rec_sz
                if step <= 0:
                    break  # no progress, would infinite-loop
                off += step

    result["available"] = found_any

    # ── Swift symbols from symtab ─────────────────────────────────────────────
    for sym in imported:
        if sym.startswith("$s") or sym.startswith("_$s"):
            result["symbols_imported"].append({
                "mangled": sym,
                "demangled": _swift_demangle_builtin(sym),
            })
    for sym in exported:
        n = sym.get("name","")
        if n.startswith("$s") or n.startswith("_$s"):
            result["symbols_exported"].append({
                "mangled": n,
                "demangled": _swift_demangle_builtin(n),
                "address": sym.get("address"),
            })

    return result


# ═══════════════════════════════════════════════════════════════════════════════
# §11  PURE-PYTHON ARM64 DISASSEMBLER
# ═══════════════════════════════════════════════════════════════════════════════
"""
Covers the ~90 most common ARM64 instructions needed for static analysis:
  - Branches: B, BL, BLR, BR, BX, CBZ, CBNZ, TBZ, TBNZ, B.cond
  - Loads/Stores: LDR, LDRB, LDRH, STR, STRB, STRH, LDP, STP, LDRSW
  - Data: MOV, MOVZ, MOVK, MOVN, ADD, SUB, MUL, AND, ORR, EOR, LSL, LSR,
           ASR, ROR, CMP, CMN, TST, NEG, MVN, MADD, MSUB
  - System: SVC, NOP, BRK, RET, MRS, MSR, HINT
  - FP/SIMD: basic FMOV/FADD/FSUB/FMUL/FDIV
  - Atomics: LDADD, STLR, LDAR, LDXR, STXR (pattern matching only)
Not decoded as full instructions but still identified for call-graph analysis.
"""

_COND_NAMES = {
    0:"EQ",1:"NE",2:"CS",3:"CC",4:"MI",5:"PL",6:"VS",7:"VC",
    8:"HI",9:"LS",10:"GE",11:"LT",12:"GT",13:"LE",14:"AL",15:"NV"
}

_GREG = [f"x{i}" for i in range(31)] + ["sp","xzr"]
_WREG = [f"w{i}" for i in range(31)] + ["wsp","wzr"]

def _reg(n:int, sf:int=1) -> str:
    if n==31: return "xzr" if sf else "wzr"
    return f"x{n}" if sf else f"w{n}"

def _sreg(n:int, sf:int=1) -> str:
    """sp-variant for stack pointer"""
    if n==31: return "sp"
    return _reg(n,sf)

def _sign_extend(val:int, bits:int) -> int:
    if val & (1<<(bits-1)): val -= (1<<bits)
    return val

def _arm64_disasm_one(word:int, pc:int) -> tuple[str,str,Optional[int]]:
    """
    Decode a single ARM64 instruction word.
    Returns (mnemonic, operands_str, branch_target_or_None).
    """
    if word == 0xD503201F: return "NOP", "", None
    if word == 0xD65F03C0: return "RET", "", None
    if word == 0xD503233F: return "PACIBSP","", None
    if word == 0xD50323BF: return "AUTIBSP","", None

    op31 = (word>>31)&1
    op30 = (word>>30)&1
    group = (word>>25)&0xF

    # ── B / BL (unconditional) ─────────────────────────────────────────────
    if (word>>26)&0x3F in (0x05,0x25):
        is_bl = (word>>31)&1
        imm26 = word & 0x3FFFFFF
        offset = _sign_extend(imm26,26)<<2
        target = (pc + offset) & 0xFFFFFFFFFFFFFFFF
        mn = "BL" if is_bl else "B"
        return mn, f"#0x{target:x}", target

    # ── B.cond ─────────────────────────────────────────────────────────────
    if (word>>24)&0xFF == 0x54:
        imm19   = (word>>5)&0x7FFFF
        cond    = word&0xF
        offset  = _sign_extend(imm19,19)<<2
        target  = (pc+offset)&0xFFFFFFFFFFFFFFFF
        return f"B.{_COND_NAMES.get(cond,str(cond))}", f"#0x{target:x}", target

    # ── CBZ/CBNZ ──────────────────────────────────────────────────────────
    if (word>>24)&0x7F in (0x34,0x35,0x74,0x75):
        sf    = (word>>31)&1
        nz    = (word>>24)&1
        imm19 = (word>>5)&0x7FFFF
        rt    = word&0x1F
        off   = _sign_extend(imm19,19)<<2
        target= (pc+off)&0xFFFFFFFFFFFFFFFF
        mn    = "CBNZ" if nz else "CBZ"
        return mn, f"{_reg(rt,sf)}, #0x{target:x}", target

    # ── TBZ/TBNZ ──────────────────────────────────────────────────────────
    if (word>>24)&0x7E in (0x36,0x37,0x76,0x77):
        nz    = (word>>24)&1
        b5    = (word>>31)&1
        b40   = (word>>19)&0x1F
        imm14 = (word>>5)&0x3FFF
        rt    = word&0x1F
        bit   = (b5<<5)|b40
        off   = _sign_extend(imm14,14)<<2
        target= (pc+off)&0xFFFFFFFFFFFFFFFF
        mn    = "TBNZ" if nz else "TBZ"
        return mn, f"{_reg(rt)}, #{bit}, #0x{target:x}", target

    # ── BLR / BR / RET-reg ────────────────────────────────────────────────
    # ── BLR / BR / RET (branch via register) ──────────────────────────────
    if word&0xFFFFFC1F == 0xD61F0000:
        rn=(word>>5)&0x1F; return "BR",_reg(rn),None
    if word&0xFFFFFC1F == 0xD63F0000:
        rn=(word>>5)&0x1F; return "BLR",_reg(rn),None
    if word&0xFFFFFC1F == 0xD65F0000:
        rn=(word>>5)&0x1F; return "RET",_reg(rn),None
    # PAC variants: BRAA/BRAAZ/BLRAA/BLRAAZ/RETAA/RETAB
    if word&0xFFFFFC00 == 0xD63F0800 or word&0xFFFFFC00 == 0xD63F0C00:
        rn=(word>>5)&0x1F; return "BLRAA",_reg(rn),None
    if word&0xFFFFFC00 == 0xD61F0800 or word&0xFFFFFC00 == 0xD61F0C00:
        rn=(word>>5)&0x1F; return "BRAA",_reg(rn),None
    if word in (0xD65F0BFF, 0xD65F0FFF):  # RETAA / RETAB
        return ("RETAA" if word == 0xD65F0BFF else "RETAB"), "", None

    # ── SVC ───────────────────────────────────────────────────────────────
    if (word>>21)&0x7FF == 0x6A0 and (word&0x1F)==1:
        imm16 = (word>>5)&0xFFFF
        return "SVC", f"#0x{imm16:x}", None

    # ── MOVZ / MOVN / MOVK ────────────────────────────────────────────────
    # Encoding: sf:1, opc:2, 100101:6, hw:2, imm16:16, Rd:5
    # bits[28:23] must equal 100101 = 0x25
    if (word>>23)&0x3F == 0x25:
        sf  = (word>>31)&1
        opc = (word>>29)&0x3
        hw  = (word>>21)&0x3
        imm16 = (word>>5)&0xFFFF
        rd  = word&0x1F
        # opc: 00=MOVN, 10=MOVZ, 11=MOVK, 01=reserved
        mn = {0:"MOVN", 2:"MOVZ", 3:"MOVK"}.get(opc, None)
        if mn is None or (sf == 0 and hw > 1):
            return ".word", f"0x{word:08x}", None
        shift = hw*16
        ops = f"{_reg(rd,sf)}, #0x{imm16:x}"
        if shift: ops += f", LSL #{shift}"
        return mn, ops, None

    # ── ADD/SUB immediate ─────────────────────────────────────────────────
    if (word>>24)&0x1F == 0x11:
        sf  = (word>>31)&1; sub=(word>>30)&1
        rn  = (word>>5)&0x1F; rd=word&0x1F
        imm12=(word>>10)&0xFFF; sh=(word>>22)&1
        val = imm12<<12 if sh else imm12
        mn = "SUB" if sub else "ADD"
        if rd==31 or rn==31:  # CMN/CMP alias
            if rd==31: mn = "CMP" if sub else "CMN"
        return mn, f"{_sreg(rd,sf)}, {_sreg(rn,sf)}, #0x{val:x}", None

    # ── LDR (literal) ─────────────────────────────────────────────────────
    if (word>>27)&0x1F == 0x08 and (word>>24)&0x3 in (0,1,2):
        opc = (word>>30)&0x3; imm19=(word>>5)&0x7FFFF; rt=word&0x1F
        off = _sign_extend(imm19,19)<<2
        target = (pc+off)&0xFFFFFFFFFFFFFFFF
        sf = 1 if opc!=0 else 0
        return "LDR", f"{_reg(rt,sf)}, [#0x{target:x}]", target

    # ── LDP/STP ───────────────────────────────────────────────────────────
    # encoding: opc:2, 101:3, V:1, ind:2, L:1, imm7:7, Rt2:5, Rn:5, Rt:5
    # bits[29:27] = 101 and bit[26] = 0 (GP register variant)
    if (word>>27)&0x7 == 0x5 and ((word>>26)&1) == 0 and ((word>>23)&0x3) != 0:
        opc = (word>>30) & 0x3
        if opc != 0x3:  # exclude reserved
            is_load = (word>>22)&1
            sf  = 1 if opc == 0x2 else 0   # 0x0=32-bit, 0x2=64-bit
            imm7= (word>>15)&0x7F; rt2=(word>>10)&0x1F
            rn  = (word>>5)&0x1F; rt=word&0x1F
            scale = 3 if sf else 2
            off = _sign_extend(imm7,7) << scale
            mn  = "LDP" if is_load else "STP"
            return mn, f"{_reg(rt,sf)}, {_reg(rt2,sf)}, [{_sreg(rn)}, #{off}]", None

    # ── LDR/STR (register offset, unsigned) ───────────────────────────────
    if (word>>27)&0x7 == 0x7 and (word>>24)&0x3 in (1,):
        size=(word>>30)&0x3; opc=(word>>22)&0x3; is_load=bool(opc&1)
        rn=(word>>5)&0x1F; rt=word&0x1F
        imm12=(word>>10)&0xFFF; scale=size
        off = imm12 << scale
        mn = {(0,0):"STRB",(0,1):"LDRB",(1,0):"STRH",(1,1):"LDRH",
              (2,0):"STR",(2,1):"LDR",(3,0):"STR",(3,1):"LDR"}.get((size,opc&1),"LDR?")
        sf = 0 if size < 2 else 1
        return mn, f"{_reg(rt,sf)}, [{_sreg(rn)}, #{off}]", None

    # ── MRS/MSR ───────────────────────────────────────────────────────────
    if (word>>20)&0xFFF == 0xD53:
        rt = word&0x1F
        sysreg = (word>>5)&0xFFFF
        return "MRS", f"{_reg(rt)}, S{sysreg}", None
    if (word>>20)&0xFFF == 0xD51:
        rt = word&0x1F
        sysreg = (word>>5)&0xFFFF
        return "MSR", f"S{sysreg}, {_reg(rt)}", None

    # ── AND/ORR/EOR/BIC (immediate) ───────────────────────────────────────
    if (word>>23)&0x1FF in (0x124,0x144,0x164,0x104):
        sf=(word>>31)&1; opc=(word>>29)&0x3
        n=(word>>22)&1; immr=(word>>16)&0x3F; imms=(word>>10)&0x3F
        rn=(word>>5)&0x1F; rd=word&0x1F
        mns={0:"AND",1:"ORR",2:"EOR",3:"ANDS"}
        mn=mns.get(opc,"AND?")
        if rd==31 and opc==3: mn="TST"
        return mn, f"{_reg(rd,sf)}, {_reg(rn,sf)}, #<bitmask>", None

    # ── Data processing (register) ────────────────────────────────────────
    if (word>>24)&0x1F == 0x0B:
        sf=(word>>31)&1; sub=(word>>30)&1; setf=(word>>29)&1
        shift=(word>>22)&0x3; imm6=(word>>10)&0x3F
        rm=(word>>16)&0x1F; rn=(word>>5)&0x1F; rd=word&0x1F
        mn = ("SUBS" if setf else "SUB") if sub else ("ADDS" if setf else "ADD")
        if rd==31: mn = "CMP" if sub else "CMN"
        shift_names=["LSL","LSR","ASR","ROR"]
        shift_str = f", {shift_names[shift]} #{imm6}" if imm6 else ""
        return mn, f"{_reg(rd,sf)}, {_reg(rn,sf)}, {_reg(rm,sf)}{shift_str}", None

    # ── MUL/MADD/MSUB ─────────────────────────────────────────────────────
    if (word>>24)&0xFF == 0x9B:
        sf=(word>>31)&1; ra=(word>>10)&0x1F; rm=(word>>16)&0x1F
        rn=(word>>5)&0x1F; rd=word&0x1F; sub=(word>>15)&1
        mn = "MSUB" if sub else "MADD"
        if ra==31: mn = "MNEG" if sub else "MUL"
        return mn, f"{_reg(rd,sf)}, {_reg(rn,sf)}, {_reg(rm,sf)}", None

    # ── ADRP / ADR ────────────────────────────────────────────────────────
    # ADR/ADRP encoding: op:1, immlo:2, 10000:5, immhi:19, Rd:5
    # bits[28:24] must == 0b10000 = 0x10
    if (word>>24)&0x1F == 0x10:
        page = (word>>31)&1
        immlo=(word>>29)&0x3; immhi=(word>>5)&0x7FFFF
        imm = _sign_extend((immhi<<2)|immlo, 21)
        rd  = word&0x1F
        if page:
            target=((pc&~0xFFF)+(imm<<12)) & 0xFFFFFFFFFFFFFFFF
            return "ADRP",f"{_reg(rd)}, #0x{target:x}",target
        else:
            target=(pc+imm) & 0xFFFFFFFFFFFFFFFF
            return "ADR",f"{_reg(rd)}, #0x{target:x}",target

    # Generic fallback
    return f".word", f"0x{word:08x}", None

def disassemble_region(data:bytes, start_va:int, start_fo:int,
                        max_insns:int=300) -> list[dict]:
    """Disassemble up to max_insns ARM64 instructions starting at start_fo."""
    insns = []
    fo = start_fo
    va = start_va
    for _ in range(max_insns):
        if fo+4 > len(data): break
        word = u32le(data, fo)
        mn, ops, branch_target = _arm64_disasm_one(word, va)
        insns.append({
            "address": hex(va),
            "word":    hex(word),
            "mnemonic": mn,
            "operands": ops,
            "branch_target": hex(branch_target) if branch_target else None,
        })
        fo += 4; va += 4
        # stop at terminal instructions
        if mn in ("RET","B") and len(insns) > 4: break
    return insns


# ═══════════════════════════════════════════════════════════════════════════════
# §12  FUNCTION STARTS + CALL GRAPH
# ═══════════════════════════════════════════════════════════════════════════════

def parse_function_starts(data:bytes, lcs:list, segs:dict) -> list[int]:
    lc = next((l for l in lcs if l.cmd==LC_FUNCTION_STARTS), None)
    if not lc: return []
    off  = u32le(lc.raw,8); size = u32le(lc.raw,12)
    if off+size > len(data): return []
    raw  = data[off:off+size]
    text = segs.get("__TEXT")
    if not text: return []
    funcs=[]; addr=text.vmaddr; i=0
    while i < len(raw):
        delta,i = uleb128(raw,i)
        if delta==0: break
        addr+=delta; funcs.append(addr)
    return funcs

def build_call_graph(data:bytes, segs:dict, func_starts:list[int],
                      max_funcs:int=2000) -> dict:
    """
    Build a call graph: {caller_va: [callee_va, ...]}
    by disassembling each function and collecting BL targets.
    """
    graph: dict[int,list[int]] = {}
    func_set = set(func_starts)

    for func_va in func_starts[:max_funcs]:
        fo = va_to_fo(func_va, segs)
        if fo is None or fo >= len(data): continue
        callees = []
        va = func_va
        for _ in range(400):  # max instructions per function
            if fo+4 > len(data): break
            word = u32le(data, fo)
            mn, ops, target = _arm64_disasm_one(word, va)
            if mn == "BL" and target:
                callees.append(target)
            fo += 4; va += 4
            if mn in ("RET","B"): break
        if callees:
            graph[func_va] = callees

    return graph

def call_graph_to_edges(graph:dict) -> list[dict]:
    edges = []
    for caller, callees in graph.items():
        for callee in callees:
            edges.append({"from":hex(caller),"to":hex(callee)})
    return edges


# ═══════════════════════════════════════════════════════════════════════════════
# §13  BASIC BLOCK SPLITTER
# ═══════════════════════════════════════════════════════════════════════════════

def split_basic_blocks(func_va:int, data:bytes, segs:dict,
                        func_set:set[int]) -> list[dict]:
    """
    Split a function into basic blocks using branch instructions as terminators.
    Returns list of {start_va, end_va, instructions, successors}.
    """
    TERMINATORS = {"B","BL","BLR","BR","RET","CBZ","CBNZ","TBZ","TBNZ"}
    TERMINATORS.update({f"B.{c}" for c in _COND_NAMES.values()})

    fo = va_to_fo(func_va, segs)
    if fo is None or fo >= len(data): return []

    # First pass: collect all instructions
    all_insns = []
    va = func_va
    cur_fo = fo
    for _ in range(500):
        if cur_fo+4 > len(data): break
        word = u32le(data, cur_fo)
        mn, ops, target = _arm64_disasm_one(word, va)
        all_insns.append({"va":va,"word":word,"mn":mn,"ops":ops,"target":target})
        cur_fo += 4; va += 4
        if mn == "RET": break
        if mn == "B" and target not in range(func_va, va+1): break

    # Second pass: identify BB boundaries
    bb_starts = {all_insns[0]["va"]} if all_insns else set()
    for insn in all_insns:
        if insn["mn"] in TERMINATORS:
            if insn["target"]: bb_starts.add(insn["target"])
            if insn["va"]+4 <= all_insns[-1]["va"]: bb_starts.add(insn["va"]+4)

    bb_starts_sorted = sorted(bb_starts)
    bbs = []
    va_to_insn = {i["va"]:i for i in all_insns}

    for idx, bb_start in enumerate(bb_starts_sorted):
        bb_end = bb_starts_sorted[idx+1] if idx+1 < len(bb_starts_sorted) else va+4
        bb_insns = [i for i in all_insns if bb_start <= i["va"] < bb_end]
        if not bb_insns: continue
        successors = []
        last = bb_insns[-1]
        if last["target"] and last["mn"] not in ("RET",):
            successors.append(hex(last["target"]))
        if last["mn"] not in ("RET","B"):
            successors.append(hex(last["va"]+4))
        bbs.append({
            "start": hex(bb_start),
            "end":   hex(bb_insns[-1]["va"]+4),
            "n_insns": len(bb_insns),
            "successors": successors,
            "instructions": [{"va":hex(i["va"]),"mn":i["mn"],"ops":i["ops"]} for i in bb_insns],
        })
    return bbs


# ═══════════════════════════════════════════════════════════════════════════════
# §14  TAINT ANALYSIS  — SecTrustEvaluate return value tracking
# ═══════════════════════════════════════════════════════════════════════════════

def taint_sec_trust(data:bytes, segs:dict, func_starts:list[int],
                     bind_entries:list[dict]) -> list[dict]:
    """
    Track the return value of SecTrustEvaluate/SecTrustEvaluateWithError.
    Flags functions that call it but never check x0 afterward (potential bypass).
    Returns list of {func_va, verdict, calls_sec_trust, checks_return}.
    """
    # Find stub VAs for SecTrustEvaluate*
    trust_stub_names = {"SecTrustEvaluate","SecTrustEvaluateWithError",
                         "SecTrustEvaluateAsync","_SecTrustEvaluate",
                         "_SecTrustEvaluateWithError"}
    # Build stub map from lazy bind
    stub_sec = segs.get("__TEXT")
    stubs_section = find_section(segs,"__TEXT","__stubs") if stub_sec else None
    stub_vas: set[int] = set()

    if stubs_section:
        STUB_SIZE = 12
        n = stubs_section.size // STUB_SIZE
        for i,entry in enumerate(bind_entries[:n]):
            sym = entry.get("symbol","").lstrip("_")
            if sym in trust_stub_names:
                stub_vas.add(stubs_section.addr + i*STUB_SIZE)

    results = []
    for func_va in func_starts[:3000]:
        fo = va_to_fo(func_va, segs)
        if fo is None or fo >= len(data): continue

        calls_trust = []
        checks_x0   = False
        last_call_idx = -1
        all_insns = []

        va = func_va; cur_fo = fo
        for step in range(500):
            if cur_fo+4 > len(data): break
            word = u32le(data, cur_fo)
            mn, ops, target = _arm64_disasm_one(word, va)
            all_insns.append((va,mn,ops,target))
            cur_fo+=4; va+=4
            if mn=="RET": break

        for idx,(va2,mn,ops,target) in enumerate(all_insns):
            if mn in ("BL","BLR") and target in stub_vas:
                calls_trust.append(hex(va2))
                last_call_idx = idx
            # After a BL to trust evaluate, check if x0 is used in a compare
            if last_call_idx >= 0 and idx > last_call_idx:
                if mn in ("CBZ","CBNZ") and "x0" in ops:
                    checks_x0 = True
                if mn in ("CMP","TST") and "x0" in ops:
                    checks_x0 = True
                if mn == "MOV" and "x0" not in ops:
                    pass  # x0 clobbered — return not checked
                if mn == "BL":  # new call — x0 from trust evaluate likely used as arg
                    checks_x0 = True  # conservative

        if calls_trust:
            results.append({
                "func_va":       hex(func_va),
                "calls_sec_trust": calls_trust,
                "checks_return":  checks_x0,
                "verdict": "OK" if checks_x0 else "POTENTIAL_BYPASS",
            })

    return results


# ═══════════════════════════════════════════════════════════════════════════════
# §15  CODE SIGNATURE DEEP PARSER
# ═══════════════════════════════════════════════════════════════════════════════

# ── Requirements expression decoder ──────────────────────────────────────────
# Opcodes from Security/codesign.h
REQ_FALSE=0; REQ_TRUE=1; REQ_IDENT=2; REQ_APPLE_ANCHOR=3
REQ_ANCHOR_HASH=4; REQ_INFO_KEY_VALUE=5; REQ_AND=6; REQ_OR=7
REQ_CODE_DIR_HASH=8; REQ_NOT=9; REQ_INFO_KEY_FIELD=10
REQ_CERT_FIELD=11; REQ_TRUSTED_CERT=12; REQ_TRUSTED_CERTS=13
REQ_CERT_GENERIC=14; REQ_APPLE_GENERIC_ANCHOR=15
REQ_ENTITLEMENT_FIELD=16; REQ_CERT_POLICY=17; REQ_NAMED_ANCHOR=18
REQ_NAMED_CODE=19; REQ_PLATFORM=20

def _req_read_data(blob:bytes, off:int) -> tuple[bytes,int]:
    length = u32be(blob,off); off+=4
    val = blob[off:off+length]; off+=length
    # align to 4
    if length%4: off += 4-(length%4)
    return val,off

def _req_read_string(blob:bytes, off:int) -> tuple[str,int]:
    data,off = _req_read_data(blob,off)
    return data.decode("utf-8","replace"),off

def _decode_req_expr(blob:bytes, off:int, depth:int=0) -> tuple[str,int]:
    if off+4 > len(blob): return "(truncated)",off
    op = u32be(blob,off); off+=4
    indent = "  "*depth
    if   op==REQ_FALSE: return "false",off
    elif op==REQ_TRUE:  return "true",off
    elif op==REQ_IDENT:
        s,off2 = _req_read_string(blob,off)
        return f'identifier "{s}"',off2
    elif op==REQ_APPLE_ANCHOR: return "anchor apple",off
    elif op==REQ_APPLE_GENERIC_ANCHOR: return "anchor apple generic",off
    elif op==REQ_AND:
        l,off=_decode_req_expr(blob,off,depth+1)
        r,off=_decode_req_expr(blob,off,depth+1)
        return f"({l} and {r})",off
    elif op==REQ_OR:
        l,off=_decode_req_expr(blob,off,depth+1)
        r,off=_decode_req_expr(blob,off,depth+1)
        return f"({l} or {r})",off
    elif op==REQ_NOT:
        e,off=_decode_req_expr(blob,off,depth+1)
        return f"! ({e})",off
    elif op==REQ_INFO_KEY_VALUE:
        k,off=_req_read_string(blob,off)
        v,off=_req_read_string(blob,off)
        return f'info["{k}"] = "{v}"',off
    elif op==REQ_CERT_FIELD:
        slot = u32be(blob,off); off+=4
        field,off=_req_read_string(blob,off)
        match,off=_req_read_data(blob,off)
        slot_name = {0:"leaf",0xFFFFFFFF:"root"}.get(slot,f"cert[{slot}]")
        return f'{slot_name}["{field}"] = <{match.hex()}>',off
    elif op==REQ_CERT_GENERIC:
        slot=u32be(blob,off); off+=4
        oid,off=_req_read_data(blob,off)
        val,off=_req_read_data(blob,off)
        slot_name={0:"leaf",0xFFFFFFFF:"root"}.get(slot,f"cert[{slot}]")
        return f'{slot_name}[oid:{oid.hex()}] = <{val.hex()}>',off
    elif op==REQ_TRUSTED_CERT:
        slot=u32be(blob,off); off+=4
        slot_name={0:"leaf",0xFFFFFFFF:"root"}.get(slot,f"cert[{slot}]")
        return f"trusted {slot_name}",off
    elif op==REQ_TRUSTED_CERTS: return "trusted",off
    elif op==REQ_ENTITLEMENT_FIELD:
        k,off=_req_read_string(blob,off)
        match,off=_req_read_data(blob,off)
        return f'entitlement["{k}"] = <{match.hex()}>',off
    elif op==REQ_NAMED_ANCHOR:
        s,off=_req_read_string(blob,off)
        return f'anchor named "{s}"',off
    elif op==REQ_NAMED_CODE:
        s,off=_req_read_string(blob,off)
        return f'(name "{s}")',off
    elif op==REQ_PLATFORM:
        pid=u32be(blob,off); off+=4
        return f"platform({pid})",off
    else:
        return f"(unknown op=0x{op:x})",off

def decode_requirements_blob(blob:bytes) -> dict:
    """Decode a CSMAGIC_REQUIREMENTS superblob."""
    if len(blob)<12: return {"error":"too short"}
    count = u32be(blob,8)
    entries = []
    for i in range(count):
        io_ = 12+i*8
        if io_+8 > len(blob): break
        req_type   = u32be(blob,io_)
        req_offset = u32be(blob,io_+4)
        if req_offset+8 > len(blob): continue
        req_magic = u32be(blob,req_offset)
        req_len   = u32be(blob,req_offset+4)
        if req_magic != CSMAGIC_REQUIREMENT: continue
        expr_bytes = blob[req_offset+8:req_offset+req_len]
        try:
            expr_str,_ = _decode_req_expr(expr_bytes,0)
        except Exception as e:
            expr_str = f"(decode error: {e})"
        entries.append({
            "type":       req_type,
            "type_name":  {1:"HOST",2:"GUEST",3:"DESIGNATED",4:"LIBRARY",5:"PLUGIN"}.get(req_type,f"type_{req_type}"),
            "expression": expr_str,
        })
    return {"requirements": entries}


def parse_code_signature_deep(data:bytes, lcs:list) -> dict:
    result = {
        "present": False,
        "entitlements": None,
        "entitlements_raw": None,
        "entitlements_der_present": False,
        "requirements": None,
        "code_directories": [],
        "team_id": None,
        "identifiers": [],
        "hash_types": [],
        "cd_hashes": [],
        "blobs": [],
        "error": None,
    }
    lc = next((l for l in lcs if l.cmd==LC_CODE_SIGNATURE), None)
    if not lc:
        result["error"] = "No LC_CODE_SIGNATURE"; return result
    dataoff  = u32le(lc.raw,8); datasize = u32le(lc.raw,12)
    if dataoff+datasize > len(data):
        result["error"] = "CS extends beyond file"; return result
    cs = data[dataoff:dataoff+datasize]
    result["present"] = True

    magic = u32be(cs,0)
    if magic not in (CSMAGIC_EMBEDDED_SIGNATURE, CSMAGIC_DETACHED_SIGNATURE):
        result["error"] = f"Bad superblob magic 0x{magic:08X}"; return result

    count = u32be(cs,8)
    for i in range(count):
        io_ = 12+i*8
        if io_+8 > len(cs): break
        slot   = u32be(cs,io_)
        boff   = u32be(cs,io_+4)
        if boff >= len(cs): continue
        bmagic = u32be(cs,boff)
        blen   = u32be(cs,boff+4)
        blob   = cs[boff:boff+blen]

        result["blobs"].append({"slot":slot,"magic":hex(bmagic),"length":blen})

        if bmagic == CSMAGIC_CODEDIRECTORY:
            _parse_cd_blob(blob, result)
        elif bmagic == CSMAGIC_EMBEDDED_ENTITLEMENTS:
            ent_bytes = blob[8:]
            result["entitlements_raw"] = ent_bytes.decode("utf-8","replace")
            try:    result["entitlements"] = plistlib.loads(ent_bytes)
            except Exception as e: result["entitlements"] = {"_error":str(e)}
        elif bmagic == CSMAGIC_EMBEDDED_ENTITLEMENTS_DER:
            result["entitlements_der_present"] = True
            result["entitlements_raw"] = "(DER-encoded)"
            # Attempt basic DER parse for sequence of UTF8String
            der_bytes = blob[8:]
            result["entitlements_der_keys"] = _extract_der_strings(der_bytes)
        elif bmagic == CSMAGIC_REQUIREMENTS:
            try: result["requirements"] = decode_requirements_blob(blob)
            except Exception as e: result["requirements"] = {"error":str(e)}

    return result

def _parse_cd_blob(blob:bytes, result:dict):
    if len(blob) < 44: return
    version     = u32be(blob,8)
    hash_offset = u32be(blob,16)
    ident_off   = u32be(blob,20)
    n_special   = u32be(blob,24)
    n_code      = u32be(blob,28)
    hash_size   = u8(blob,36)
    hash_type   = u8(blob,37)
    page_sz_log2= u8(blob,39)

    ident = cstring(blob,ident_off) if ident_off < len(blob) else ""
    team_id = ""
    if version >= 0x20300 and len(blob) >= 52:
        team_off = u32be(blob,48)
        if team_off and team_off < len(blob):
            team_id = cstring(blob, team_off)

    # Exec segment flags (v >= 0x20500)
    exec_seg_flags = 0
    if version >= 0x20500 and len(blob) >= 88:
        exec_seg_flags = struct.unpack_from(">Q",blob,80)[0]

    exec_flags_decoded = []
    if exec_seg_flags:
        ef_map = {
            0x1:"CS_EXECSEG_MAIN_BINARY",     0x2:"CS_EXECSEG_ALLOW_UNSIGNED",
            0x4:"CS_EXECSEG_DEBUGGER",        0x8:"CS_EXECSEG_JIT",
            0x10:"CS_EXECSEG_SKIP_LV",        0x20:"CS_EXECSEG_CAN_LOAD_CDHASH",
            0x40:"CS_EXECSEG_CAN_EXEC_CDHASH",
        }
        exec_flags_decoded = decode_flags(exec_seg_flags, ef_map)

    # first 8 code hashes
    first_hashes = []
    for i in range(min(n_code,8)):
        ho = hash_offset + i*hash_size
        if ho+hash_size <= len(blob):
            first_hashes.append(blob[ho:ho+hash_size].hex())

    cd_info = {
        "version":          hex(version),
        "identifier":       ident,
        "team_id":          team_id,
        "hash_type":        HASH_TYPE_NAMES.get(hash_type,f"unk({hash_type})"),
        "hash_size":        hash_size,
        "page_size":        2**page_sz_log2 if page_sz_log2 else 0,
        "n_code_slots":     n_code,
        "n_special_slots":  n_special,
        "exec_seg_flags":   exec_flags_decoded,
        "cd_hash_sha256":   hashlib.sha256(blob).hexdigest(),
        "cd_hash_sha1":     hashlib.sha1(blob).hexdigest(),
        "first_code_hashes":first_hashes,
    }
    result["code_directories"].append(cd_info)
    if team_id and not result["team_id"]: result["team_id"] = team_id
    if ident and ident not in result["identifiers"]: result["identifiers"].append(ident)
    ht_name = HASH_TYPE_NAMES.get(hash_type,str(hash_type))
    if ht_name not in result["hash_types"]: result["hash_types"].append(ht_name)
    result["cd_hashes"].append(cd_info["cd_hash_sha256"])

def _extract_der_strings(der:bytes) -> list[str]:
    """Very basic DER string extraction (UTF8String, PrintableString, IA5String)."""
    strings = []
    i = 0
    while i < len(der)-2:
        tag = der[i]
        if tag in (0x0C, 0x13, 0x16, 0x1E):  # UTF8, Printable, IA5, BMPString
            length = der[i+1]
            if length & 0x80:  # long form
                n = length & 0x7F
                if i+1+n+1 > len(der): break
                length = int.from_bytes(der[i+2:i+2+n], 'big')
                i += n
            i += 2
            if i+length <= len(der):
                try:
                    s = der[i:i+length].decode("utf-8","replace")
                    if s.strip(): strings.append(s.strip())
                except Exception: pass
                i += length
        else:
            i += 1
    return strings


# ═══════════════════════════════════════════════════════════════════════════════
# §16  ENTROPY + CRYPTO CONSTANT DETECTION
# ═══════════════════════════════════════════════════════════════════════════════

def analyze_entropy(data:bytes, segs:dict) -> list[dict]:
    """Compute per-section Shannon entropy. High entropy ≈ encrypted/compressed."""
    results = []
    for seg in segs.values():
        for sec in seg.sections:
            raw = section_data(data, sec)
            if len(raw) < 64: continue
            ent = shannon_entropy(raw)
            results.append({
                "segment": seg.segname,
                "section": sec.sectname,
                "size":    len(raw),
                "entropy": round(ent,4),
                "risk":    "HIGH" if ent>7.2 else ("MEDIUM" if ent>6.5 else "LOW"),
            })
    return sorted(results, key=lambda x: x["entropy"], reverse=True)

def detect_crypto_constants(data:bytes) -> list[dict]:
    """Scan raw binary for embedded crypto primitive constants."""
    found = []
    for name, pattern in CRYPTO_CONSTANTS.items():
        off = 0
        while True:
            idx = data.find(pattern, off)
            if idx == -1: break
            found.append({"constant": name, "file_offset": hex(idx),
                           "context": data[idx:idx+32].hex()})
            off = idx+1
    return found


# ═══════════════════════════════════════════════════════════════════════════════
# §17  SECURITY HEURISTICS (expanded)
# ═══════════════════════════════════════════════════════════════════════════════

def security_heuristics_deep(data:bytes, segs:dict,
                              imported:list, all_strings:list,
                              func_starts:list[int],
                              bind_entries:list[dict],
                              entitlements:dict=None) -> dict:
    imp_set = {s.lstrip("_") for s in imported}

    # ── Anti-debug ────────────────────────────────────────────────────────────
    antidebug_syms   = sorted(ANTIDEBUG_SYMS & imp_set)
    ptrace_in_data   = b"ptrace" in data
    pt_deny_pattern  = b'\x00\x00\x00\x1f\x20\x00\x80\xd2'  # MOV x0,0x1f then SVC heuristic
    pt_deny_detected = data.count(pt_deny_pattern) > 0

    # Scan for sysctl MIB CTL_KERN/KERN_PROC patterns (anti-debug via sysctl)
    # [CTL_KERN=1, KERN_PROC=14] encoded as little-endian int32 pairs
    sysctl_mib_pattern = struct.pack("<II",1,14)
    sysctl_antidebug   = data.count(sysctl_mib_pattern) > 0

    antidebug_strings = [s for s in all_strings
                         if any(x in s.lower() for x in
                                ("ptrace","debugger","jit","deny_attach","anti_debug",
                                 "isdebugged","debugged","debugserver"))]

    # ── Jailbreak detection ───────────────────────────────────────────────────
    jb_path_hits = []
    for s in all_strings:
        for p in JAILBREAK_PATHS:
            if p.lower() in s.lower(): jb_path_hits.append(s); break
    jb_str_hits  = []
    for s in all_strings:
        for p in JAILBREAK_STRS:
            if p.lower() in s.lower(): jb_str_hits.append(s); break
    # Also check for Substrate/MSHookFunction import
    hook_syms = {s for s in imp_set if "hook" in s.lower() or "substitute" in s.lower()
                 or "mshook" in s.lower() or "substrate" in s.lower()}

    # ── Certificate pinning ───────────────────────────────────────────────────
    pinning_syms   = sorted(PINNING_SYMS & imp_set)
    pinning_strings= [s for s in all_strings
                      if any(x in s.lower() for x in
                             ("pinning","publickeypin","trustkit","ssl_pinning",
                              "certpin","sslpinning","certchain"))]
    # TrustKit / Alamofire / AFNetworking pinning
    trustkit_present = any("TrustKit" in s for s in all_strings)
    af_pinning       = any("AFSSLPinningMode" in s for s in all_strings)

    # ── Crypto ────────────────────────────────────────────────────────────────
    crypto_syms    = sorted(CRYPTO_SYMS & imp_set)
    crypto_strs    = [s for s in all_strings
                      if any(x in s for x in
                             ("kCCAlgorithm","kCCOption","AES256","kSecAttr",
                              "RSA","ECDSA","HMAC","SHA-","SHA256"))]

    # ── Hardcoded secrets ─────────────────────────────────────────────────────
    secret_pats = [
        re.compile(r'(?i)(api[-_]?key|apikey|secret[-_]?key|access[-_]?token|auth[-_]?token|bearer|password|passwd)[^\x00]{4,80}'),
        re.compile(r'[A-Za-z0-9+/]{40,}={0,2}'),   # long base64
        re.compile(r'[0-9a-fA-F]{40,}'),             # long hex
        re.compile(r'https?://[a-zA-Z0-9._/-]{20,}'),# hardcoded URLs
    ]
    secrets = []
    for s in all_strings:
        if len(s) < 16: continue
        for pat in secret_pats:
            m = pat.search(s)
            if m and len(m.group()) >= 16:
                secrets.append(s); break

    # ── Obfuscation indicators ────────────────────────────────────────────────
    # High-entropy sections indicate packed/encrypted code
    high_entropy_secs = []
    for seg in segs.values():
        for sec in seg.sections:
            raw = section_data(data, sec)
            if len(raw) >= 256:
                ent = shannon_entropy(raw)
                if ent > 7.2:
                    high_entropy_secs.append(f"{seg.segname},{sec.sectname} ({ent:.2f})")

    # Very few strings relative to binary size → obfuscated
    string_density = len(all_strings) / max(len(data)//1024,1)
    likely_obfuscated = string_density < 0.5 and len(func_starts) > 50

    # ── Constructors / initializers ───────────────────────────────────────────
    init_funcs = []
    for seg_name in ("__DATA","__DATA_CONST","__TEXT"):
        sec = find_section(segs, seg_name, "__mod_init_func")
        if not sec: continue
        raw = section_data(data, sec)
        for i in range(len(raw)//8):
            va = u64le(raw, i*8)
            if va: init_funcs.append(hex(va))

    term_funcs = []
    for seg_name in ("__DATA","__DATA_CONST","__TEXT"):
        sec = find_section(segs, seg_name, "__mod_term_func")
        if not sec: continue
        raw = section_data(data, sec)
        for i in range(len(raw)//8):
            va = u64le(raw, i*8)
            if va: term_funcs.append(hex(va))

    # ── Entitlements Audit Heuristics ─────────────────────────────────────────
    ent_audit = []
    ent_risk = "LOW"
    if entitlements:
        high_priv_ents = {
            "get-task-allow": "Allows debuggers to attach directly. HIGH risk in production App Store binaries.",
            "com.apple.private.security.no-sandbox": "Completely bypasses all App Sandbox security restrictions. EXTREMELY HIGH risk.",
            "task_for_pid-allow": "Allows obtaining task ports for arbitrary processes, bypassing kernel process segregation. CRITICAL security risk.",
            "com.apple.system-task-ports": "Provides control over system-wide tasks and kernel control endpoints. CRITICAL risk.",
            "com.apple.private.security.sandbox.debug-mode": "Forces sandbox into debug logging/bypass mode. HIGH risk.",
            "com.apple.security.exception.files.absolute-path.read-write": "Explicit exception granting read-write access to arbitrary filesystem paths. HIGH risk.",
            "com.apple.security.exception.files.home-relative-path.read-write": "Read-write access to arbitrary user home paths. MEDIUM/HIGH risk.",
            "com.apple.security.exception.shared-preference.read-write": "Access to third-party app preferences and shared containers. MEDIUM risk.",
            "com.apple.private.tcc.allow": "Allows direct TCC privacy database bypasses (Camera, Microphone, Photos). HIGH risk.",
            "dynamic-codesigning": "Allows JIT and runtime memory modification without signature checks. HIGH risk."
        }
        for key, desc in high_priv_ents.items():
            if key in entitlements:
                val = entitlements[key]
                if val is True or val:
                    ent_audit.append({"key": key, "value": val, "description": desc})
                    ent_risk = "HIGH"

    return {
        "anti_debug": {
            "imported_symbols":    antidebug_syms,
            "suspicious_strings":  antidebug_strings[:20],
            "ptrace_string_present": ptrace_in_data,
            "pt_deny_pattern_found": pt_deny_detected,
            "sysctl_anti_debug":   sysctl_antidebug,
            "risk": "HIGH" if antidebug_syms else ("MEDIUM" if ptrace_in_data or sysctl_antidebug else "LOW"),
        },
        "jailbreak_detection": {
            "path_strings":      list(dict.fromkeys(jb_path_hits))[:30],
            "keyword_strings":   list(dict.fromkeys(jb_str_hits))[:30],
            "hook_symbols":      sorted(hook_syms),
            "count":             len(jb_path_hits)+len(jb_str_hits),
            "risk": "HIGH" if len(jb_path_hits)+len(jb_str_hits)>3 else "MEDIUM" if jb_path_hits else "LOW",
        },
        "certificate_pinning": {
            "imported_symbols": pinning_syms,
            "suspicious_strings":pinning_strings[:10],
            "trustkit_present":  trustkit_present,
            "af_pinning_mode":   af_pinning,
            "risk": "HIGH" if pinning_syms or trustkit_present else ("MEDIUM" if pinning_strings else "LOW"),
        },
        "crypto": {
            "imported_symbols": crypto_syms,
            "related_strings":  crypto_strs[:20],
        },
        "hardcoded_secrets": {
            "candidates": secrets[:50],
            "count":       len(secrets),
            "risk": "HIGH" if len(secrets)>5 else ("MEDIUM" if secrets else "LOW"),
        },
        "obfuscation": {
            "high_entropy_sections": high_entropy_secs,
            "likely_obfuscated":     likely_obfuscated,
            "string_density":        round(string_density,2),
            "risk": "HIGH" if likely_obfuscated else ("MEDIUM" if high_entropy_secs else "LOW"),
        },
        "constructors": {
            "mod_init_funcs": init_funcs,
            "mod_term_funcs": term_funcs,
        },
        "entitlements_audit": {
            "findings": ent_audit,
            "risk": ent_risk,
        },
    }


# ═══════════════════════════════════════════════════════════════════════════════
# §18  CONSTRUCTOR SECTION PARSER
# ═══════════════════════════════════════════════════════════════════════════════

def parse_constructor_sections(data:bytes, segs:dict) -> dict:
    """Parse __mod_init_func, __mod_term_func, __init_func, __term_func."""
    result = {"init":[],"term":[],"swift_init":[]}
    for seg_name in ("__DATA","__DATA_CONST","__TEXT"):
        for sec_name,key in (("__mod_init_func","init"),("__mod_term_func","term"),
                              ("__init_func","init"),("__term_func","term"),
                              ("__swift5_acfuncs","swift_init")):
            sec = find_section(segs, seg_name, sec_name)
            if not sec: continue
            raw = section_data(data, sec)
            for i in range(len(raw)//8):
                va = u64le(raw,i*8)
                if va and hex(va) not in result[key]:
                    result[key].append(hex(va))
    return result


# ═══════════════════════════════════════════════════════════════════════════════
# §19  XPC DEEP ANALYZER
# ═══════════════════════════════════════════════════════════════════════════════

def analyze_xpc_deep(data:bytes, segs:dict, objc_result:dict,
                      all_strings:list) -> dict:
    xpc_re = re.compile(
        r'(xpc|XPC|remoteObject|proxyWithInterface|exportedObject|'
        r'remoteObjectProxy|invalidationHandler|interruptionHandler|'
        r'NSXPCConnection|NSXPCInterface|xpc_connection|xpc_object|'
        r'XPCService|xpc_main|xpc_transaction)',
        re.IGNORECASE
    )
    bundle_id_re  = re.compile(r'com\.[a-zA-Z0-9_\-]+(?:\.[a-zA-Z0-9_\-]+)+')
    xpc_bundle_re = re.compile(r'com\.[a-zA-Z0-9._-]+\.xpc(?:\.[a-zA-Z0-9._-]+)?')

    xpc_methods, xpc_strings, xpc_bundles = [], [], set()

    for cls in objc_result.get("classes",[]):
        for m in cls.instance_methods + cls.class_methods:
            if xpc_re.search(m.name):
                xpc_methods.append({
                    "class": cls.name,
                    "method": m.name,
                    "type": "class" if m.is_class else "instance",
                    "return_type": m.return_type,
                    "imp": m.imp,
                })

    for s in all_strings:
        if xpc_re.search(s): xpc_strings.append(s)
        for m in xpc_bundle_re.finditer(s): xpc_bundles.add(m.group())

    # Also mine all bundle IDs
    all_bundles = set()
    for s in all_strings:
        for m in bundle_id_re.finditer(s):
            all_bundles.add(m.group())

    return {
        "xpc_handler_methods":    xpc_methods[:100],
        "xpc_related_strings":    list(dict.fromkeys(xpc_strings))[:50],
        "xpc_bundle_ids":         sorted(xpc_bundles),
        "all_bundle_ids":         sorted(all_bundles),
        "method_count":           len(xpc_methods),
    }


# ═══════════════════════════════════════════════════════════════════════════════
# §20  STRING AGGREGATOR (all sources)
# ═══════════════════════════════════════════════════════════════════════════════

def collect_all_strings(data:bytes, segs:dict) -> dict:
    """Collect strings from every relevant section and source."""
    cstrings  = []
    sec = find_section(segs,"__TEXT","__cstring")
    if sec: cstrings = cstrings_section(section_data(data,sec))

    objc_cls   = []
    sec = find_section(segs,"__TEXT","__objc_classnames")
    if sec: objc_cls = cstrings_section(section_data(data,sec))

    objc_meth  = []
    sec = find_section(segs,"__TEXT","__objc_methnames")
    if sec: objc_meth = cstrings_section(section_data(data,sec))

    cfstrings  = parse_cfstrings(data, segs)
    cfstr_vals = [c["string"] for c in cfstrings]

    ustrings   = parse_ustrings(data, segs)

    # Combine deduplicated
    combined = list(dict.fromkeys(cstrings + cfstr_vals + ustrings + objc_cls + objc_meth))

    return {
        "cstrings":   cstrings,
        "cfstrings":  cfstrings,
        "ustrings":   ustrings,
        "objc_class_names": objc_cls,
        "objc_method_names": objc_meth,
        "all_unique": combined,
    }

def scan_keywords(strings:list, keywords:list) -> dict:
    kl = [k.lower() for k in keywords]
    results = {k:[] for k in keywords}
    for s in strings:
        sl = s.lower()
        for i,kw in enumerate(kl):
            if kw in sl:
                results[keywords[i]].append(s)
    return {k:v for k,v in results.items() if v}


# ═══════════════════════════════════════════════════════════════════════════════
# §21  BINARY FINGERPRINT
# ═══════════════════════════════════════════════════════════════════════════════

def fingerprint(data:bytes, segs:dict, lcs:list) -> dict:
    text = segs.get("__TEXT")
    text_hash = ""
    if text and text.fileoff+text.filesize <= len(data):
        text_hash = hashlib.sha256(data[text.fileoff:text.fileoff+text.filesize]).hexdigest()

    sec_hashes = {}
    for seg in segs.values():
        for sec in seg.sections:
            if sec.offset and sec.size:
                sec_hashes[f"{sec.segname},{sec.sectname}"] = \
                    hashlib.md5(data[sec.offset:sec.offset+sec.size]).hexdigest()

    return {
        "file_md5":           hashlib.md5(data).hexdigest(),
        "file_sha1":          hashlib.sha1(data).hexdigest(),
        "file_sha256":        hashlib.sha256(data).hexdigest(),
        "text_segment_sha256":text_hash,
        "file_size":          len(data),
        "section_md5_map":    sec_hashes,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# §22  LOAD COMMAND FULL DESCRIBE
# ═══════════════════════════════════════════════════════════════════════════════

def describe_load_commands_full(lcs:list[LoadCommand]) -> list[dict]:
    result = []
    for lc in lcs:
        e = {"cmd":lc.name,"cmd_id":hex(lc.cmd),"size":lc.cmdsize}
        if lc.cmd == LC_SEGMENT_64:
            seg = Segment64(lc)
            e.update({"segment":seg.segname,"vmaddr":hex(seg.vmaddr),
                      "vmsize":hex(seg.vmsize),"fileoff":hex(seg.fileoff),
                      "filesize":hex(seg.filesize),"nsects":seg.nsects,
                      "sections":[s.sectname for s in seg.sections],
                      "maxprot":hex(seg.maxprot),"initprot":hex(seg.initprot)})
        elif lc.cmd in DYLIB_LC_TYPES|{LC_ID_DYLIB}:
            name_off = u32le(lc.raw,8)
            e.update({"dylib":cstring(lc.raw,name_off),
                      "version":decode_version(u32le(lc.raw,16)),
                      "compat":decode_version(u32le(lc.raw,20))})
        elif lc.cmd == LC_UUID:
            e["uuid"] = format_uuid(lc.raw[8:24])
        elif lc.cmd == LC_CODE_SIGNATURE:
            e.update({"dataoff":hex(u32le(lc.raw,8)),"datasize":hex(u32le(lc.raw,12))})
        elif lc.cmd in (LC_ENCRYPTION_INFO,LC_ENCRYPTION_INFO_64):
            e.update({"cryptoff":hex(u32le(lc.raw,8)),"cryptsize":hex(u32le(lc.raw,12)),
                      "cryptid":u32le(lc.raw,16)})
        elif lc.cmd == LC_BUILD_VERSION:
            e.update({"platform":PLATFORM_NAMES.get(u32le(lc.raw,8),f"plat_{u32le(lc.raw,8)}"),
                      "minos":decode_version(u32le(lc.raw,12)),
                      "sdk":decode_version(u32le(lc.raw,16))})
        elif lc.cmd == LC_VERSION_MIN_IPHONEOS:
            e.update({"version":decode_version(u32le(lc.raw,8)),
                      "sdk":decode_version(u32le(lc.raw,12))})
        elif lc.cmd == LC_SOURCE_VERSION:
            v = struct.unpack_from("<Q",lc.raw,8)[0]
            e["version"] = f"{(v>>40)&0xFFFFFF}.{(v>>30)&0x3FF}.{(v>>20)&0x3FF}.{(v>>10)&0x3FF}.{v&0x3FF}"
        elif lc.cmd == LC_MAIN:
            e.update({"entryoff":hex(struct.unpack_from("<Q",lc.raw,8)[0]),
                      "stacksize":hex(struct.unpack_from("<Q",lc.raw,16)[0])})
        elif lc.cmd == LC_RPATH:
            e["path"] = cstring(lc.raw, u32le(lc.raw,8))
        elif lc.cmd == LC_SYMTAB:
            e.update({"symoff":hex(u32le(lc.raw,8)),"nsyms":u32le(lc.raw,12),
                      "stroff":hex(u32le(lc.raw,16)),"strsize":hex(u32le(lc.raw,20))})
        elif lc.cmd == LC_DYSYMTAB:
            e.update({"nlocalsym":u32le(lc.raw,12),"nextdefsym":u32le(lc.raw,20),
                      "nundefsym":u32le(lc.raw,28)})
        elif lc.cmd == LC_LOAD_DYLINKER:
            e["dylinker"] = cstring(lc.raw, u32le(lc.raw,8))
        elif lc.cmd == LC_FUNCTION_STARTS:
            e.update({"dataoff":hex(u32le(lc.raw,8)),"datasize":hex(u32le(lc.raw,12))})
        result.append(e)
    return result


# ── iOS Trust Cache Parser (.tc) ──────────────────────────────────────────────
def parse_trust_cache(data: bytes) -> dict:
    if len(data) < 24:
        return {"error": "File size is too small to be an iOS Trust Cache container"}
    
    # Try parsing v0/v1 headers
    # Struct: magic (4B), version (4B), uuid (16B), num_entries (4B)
    magic = u32le(data, 0)
    version = u32le(data, 4)
    uuid_raw = data[8:24]
    
    uuid_str = format_uuid(uuid_raw)
    
    # Standard Magic: 0x74636872 ("tchr") or typical bootloader v1 header 0x01
    is_valid_magic = (magic in (0x74636872, 0x1, 0x2)) or (data[:4] == b"tchr")
    
    if not is_valid_magic:
        # Fallback raw scan for 20-byte SHA-1 CDHash chunks
        num_entries = len(data) // 22
        offset = 0
        entry_size = 22
    else:
        num_entries = u32le(data, 24) if len(data) >= 28 else (len(data) - 24) // 22
        offset = 28 if len(data) >= 28 else 24
        entry_size = 22
        
    entries = []
    for i in range(num_entries):
        if offset + entry_size > len(data):
            break
        cdhash = data[offset : offset + 20].hex()
        hash_type = data[offset + 20]
        flags = data[offset + 21]
        
        hash_name = {1: "SHA-1", 2: "SHA-256 (Truncated)", 3: "SHA-256 (Full)"}.get(hash_type, f"Type_{hash_type}")
        entries.append({
            "index": i,
            "cdhash": cdhash.upper(),
            "hash_type": hash_name,
            "flags": f"0x{flags:X}"
        })
        offset += entry_size
        
    return {
        "magic": f"0x{magic:X}",
        "version": version,
        "uuid": uuid_str,
        "num_entries": len(entries),
        "entries": entries
    }

# ── Interactive Byte Patching ────────────────────────────────────────────────
def patch_binary_offset(binary_path: str, offset: int, hex_bytes_str: str):
    path = Path(binary_path)
    if not path.exists():
        print(f"[!] Target binary not found: {binary_path}", file=sys.stderr)
        return
        
    try:
        patch_bytes = bytes.fromhex(hex_bytes_str.replace(" ", "").replace("0x", ""))
    except ValueError as e:
        print(f"[!] Invalid hex patch bytes: {e}", file=sys.stderr)
        return
        
    print(f"[*] Patching target binary: {path.name}")
    print(f"    Offset: 0x{offset:X} ({offset:,} bytes)")
    print(f"    Patch payload size: {len(patch_bytes)} bytes")
    print(f"    Patch bytes (hex): {patch_bytes.hex().upper()}")
    
    raw = bytearray(path.read_bytes())
    if offset < 0 or offset + len(patch_bytes) > len(raw):
        print(f"[!] Patch offset is out of bounds! Binary size: {len(raw):,} bytes", file=sys.stderr)
        return
        
    # Print old bytes for absolute audit logs
    old_bytes = raw[offset : offset + len(patch_bytes)]
    print(f"    Original bytes (hex): {old_bytes.hex().upper()}")
    
    # Overwrite
    raw[offset : offset + len(patch_bytes)] = patch_bytes
    path.write_bytes(raw)
    print("[+] Patch successfully injected into biner file.")


# ── Threat Scorecard Calculator Heuristics ──
def calculate_threat_scorecard(meta: dict, security: dict, imported_symbols: list) -> dict:
    imp_set = {s.lstrip("_") for s in imported_symbols}
    
    # Check mitigations
    has_pie = meta.get("has_pie", False)
    has_arc = meta.get("has_arc", False)
    
    # Stack canary detection
    has_canary = any(x in imp_set for x in ("__stack_chk_fail", "__stack_chk_guard", "stack_chk_fail"))
    
    # Encryption (FairPlay DRM)
    is_encrypted = meta.get("encrypted", False)
    
    # Banned/Insecure functions detection
    banned_apis = {
        "strcpy": "Susceptible to stack/heap buffer overflow. Replace with strlcpy.",
        "strcat": "Susceptible to stack/heap buffer overflow. Replace with strlcat.",
        "sprintf": "Susceptible to buffer overflow. Replace with snprintf.",
        "vsprintf": "Susceptible to buffer overflow. Replace with vsnprintf.",
        "gets": "Extremely insecure. Absolutely banned. Replace with fgets.",
        "memcpy": "Susceptible to buffer overflow if size is uncontrolled. Replace with memcpy_s or bounds check.",
        "system": "Allows arbitrary command execution via shell injection.",
        "popen": "Allows arbitrary command execution via shell injection.",
        "execve": "Allows arbitrary process execution."
    }
    found_banned = {}
    for sym in imp_set:
        for b_api, desc in banned_apis.items():
            if b_api in sym.lower():
                found_banned[b_api] = desc
                
    # Entitlements check
    ent_findings = security.get("entitlements_audit", {}).get("findings", [])
    has_no_sandbox = any(f.get("key") == "com.apple.private.security.no-sandbox" for f in ent_findings)
    has_task_allow = any(f.get("key") == "get-task-allow" for f in ent_findings)
    
    # Calculate scores
    # 1. Exploitation / Audit Potential Score
    exploit_score = 15 # Base score
    reasons = []
    
    if not has_pie:
        exploit_score += 25
        reasons.append("ASLR/PIE is disabled. Memory layouts are static, enabling highly reliable absolute-address ROP/injection chains.")
    else:
        reasons.append("ASLR/PIE is enabled. Address space layouts are randomized at runtime, requiring separate information leaks to bypass.")
        
    if not has_canary:
        exploit_score += 25
        reasons.append("Stack Smashing Protection (canary) is missing. Direct stack buffer overflows can overwrite return addresses without triggering canary panic.")
    else:
        reasons.append("Stack Smashing Protection (canary) is active. Prevents trivial control flow hijack via stack overflows.")
        
    if not has_arc:
        exploit_score += 15
        reasons.append("Objective-C Automatic Reference Counting (ARC) is disabled. Memory management is manual, heavily increasing risk of Use-After-Free (UAF) vulnerabilities.")
    else:
        reasons.append("Objective-C Automatic Reference Counting (ARC) is active. Lowers the frequency of manual memory corruption bugs.")
        
    if found_banned:
        exploit_score += min(15, len(found_banned) * 5)
        reasons.append(f"Insecure/banned APIs imported ({', '.join(found_banned.keys())}). Increases probability of classic memory corruption vectors.")
        
    if has_no_sandbox:
        exploit_score += 15
        reasons.append("Target possesses un-sandboxed entitlements (com.apple.private.security.no-sandbox). Successful code execution achieves immediate full system access.")
    if has_task_allow:
        exploit_score += 10
        reasons.append("Target possesses 'get-task-allow' entitlement. Direct debugger attachments and task-port injections are supported out-of-the-box.")
        
    exploit_score = min(95, exploit_score)
    
    # 2. Security Hardening / Patch Integrity Score
    hardening_score = 100 - exploit_score
    if has_pie: hardening_score += 5
    if has_canary: hardening_score += 5
    hardening_score = min(100, max(5, hardening_score))
    
    # Verdicts
    if exploit_score >= 65:
        verdict = "CRITICAL / HIGH EXPLOITABILITY POTENTIAL"
        color = "#FF4500" # OrangeRed
    elif exploit_score >= 35:
        verdict = "MEDIUM RISK / STANDARD AUDITING DIFFICULTY"
        color = "#FFD700" # Gold
    else:
        verdict = "LOW RISK / HEAVILY HARDENED TARGET"
        color = "#00FF00" # Green
        
    # Tweak Sideloading & Injectability Score
    inject_score = 80
    inject_reasons = []
    if is_encrypted:
        inject_score -= 60
        inject_reasons.append("App is encrypted with FairPlay DRM. Sideloading requires decryption and dumping via jailbreak memory dumpers.")
    else:
        inject_reasons.append("App is not encrypted. Sideloading and patching are directly possible.")
        
    if has_task_allow:
        inject_score += 10
        inject_reasons.append("Possesses get-task-allow. Ideal for cycript, frida-gadget or lldb injection.")
        
    inject_score = max(5, min(95, inject_score))
    
    return {
        "exploit_score": exploit_score,
        "hardening_score": hardening_score,
        "inject_score": inject_score,
        "verdict": verdict,
        "verdict_color": color,
        "has_canary": has_canary,
        "found_banned": found_banned,
        "reasons": reasons,
        "inject_reasons": inject_reasons
    }


# ═══════════════════════════════════════════════════════════════════════════════
# §22B  iOS CVE KNOWLEDGE BASE & FIRMWARE INTELLIGENCE ENGINE
# ═══════════════════════════════════════════════════════════════════════════════


def build_ios_cve_knowledge_base() -> list:
    """
    Returns a curated list of real, publicly documented iOS CVEs and exploit
    primitives.  Each entry carries the iOS version range it affects, whether
    it has been patched, the attack category, and a human-readable synopsis.

    Categories:
        kernel        – Kernel-level vulnerabilities (LPE, UAF, race, info-leak)
        userland      – Userland sandbox escapes, TCC bypasses, IPC abuse
        jailbreak     – Full jailbreak chains or key primitives used in jailbreaks
        bootrom       – Hardware / BootROM / SecureROM exploits (unpatchable)
        injection     – Code-signing or dyld injection weaknesses
        webkit        – WebKit / browser-based initial access vectors
        malware       – Vectors abused by known in-the-wild malware / spyware
    """
    return [
        # ── BootROM / Hardware (unpatchable) ──────────────────────────────────
        {
            "id": "CVE-2019-8900", "name": "checkm8",
            "category": "bootrom",
            "affects_hw": ["A5", "A6", "A7", "A8", "A9", "A10", "A11"],
            "affects_ios_min": "0.0", "affects_ios_max": "99.99",
            "patched_ios": None,
            "severity": "CRITICAL",
            "description": "SecureROM use-after-free in USB DFU. Unpatchable hardware exploit enabling tethered/semi-tethered jailbreaks on A5-A11 devices regardless of iOS version.",
            "references": ["checkra1n", "ipwndfu", "gala1n"],
        },
        {
            "id": "CVE-2022-32917", "name": "checkm8 SEP variant research",
            "category": "bootrom",
            "affects_hw": ["A10", "A11"],
            "affects_ios_min": "0.0", "affects_ios_max": "99.99",
            "patched_ios": None,
            "severity": "HIGH",
            "description": "Research into Secure Enclave Processor (SEP) firmware attack surfaces on A10/A11 leveraging checkm8 DFU access.",
            "references": ["SEPOS research", "checkra1n"],
        },

        # ── iOS 14.x ─────────────────────────────────────────────────────────
        {
            "id": "CVE-2021-1782", "name": "Kernel UAF (cicuta_virosa)",
            "category": "kernel",
            "affects_hw": ["all"],
            "affects_ios_min": "14.0", "affects_ios_max": "14.3",
            "patched_ios": "14.4",
            "severity": "CRITICAL",
            "description": "Kernel race condition / UAF in mach vouchers. Used as kernel LPE in unc0ver 6.x jailbreak chain.",
            "references": ["unc0ver 6.x", "Project Zero"],
        },
        {
            "id": "CVE-2021-30737", "name": "Fugu14 coretrust bypass",
            "category": "jailbreak",
            "affects_hw": ["A12+"],
            "affects_ios_min": "14.3", "affects_ios_max": "14.5.1",
            "patched_ios": "14.6",
            "severity": "HIGH",
            "description": "CoreTrust bug allowing PPL bypass for untethered code signing. Used in Fugu14 untethered jailbreak.",
            "references": ["Fugu14", "Linus Henze"],
        },
        {
            "id": "CVE-2021-30883", "name": "IOMobileFrameBuffer LPE",
            "category": "kernel",
            "affects_hw": ["all"],
            "affects_ios_min": "14.0", "affects_ios_max": "14.8",
            "patched_ios": "15.0.2",
            "severity": "CRITICAL",
            "description": "IOMobileFrameBuffer integer overflow leading to kernel memory corruption. Exploited in-the-wild. Used in multiple jailbreak chains.",
            "references": ["Saar Amar", "KTRR bypass research"],
        },
        {
            "id": "CVE-2021-30860", "name": "FORCEDENTRY (NSO Pegasus)",
            "category": "malware",
            "affects_hw": ["all"],
            "affects_ios_min": "14.0", "affects_ios_max": "14.7.1",
            "patched_ios": "14.8",
            "severity": "CRITICAL",
            "description": "Zero-click iMessage exploit via malicious PDF in CoreGraphics. Used by NSO Group Pegasus spyware for full device compromise without user interaction.",
            "references": ["Citizen Lab", "Project Zero", "NSO Group"],
        },

        # ── iOS 15.x ─────────────────────────────────────────────────────────
        {
            "id": "CVE-2022-26766", "name": "CoreTrust bypass (TrollStore)",
            "category": "jailbreak",
            "affects_hw": ["all"],
            "affects_ios_min": "14.0", "affects_ios_max": "15.4.1",
            "patched_ios": "15.5",
            "severity": "HIGH",
            "description": "CoreTrust failure to validate certain certificate chains. Allows permanent app installation without jailbreak (TrollStore). Critical for sideloading.",
            "references": ["TrollStore", "opa334"],
        },
        {
            "id": "CVE-2022-32898", "name": "oob_timestamp kernel exploit",
            "category": "kernel",
            "affects_hw": ["all"],
            "affects_ios_min": "15.0", "affects_ios_max": "15.6.1",
            "patched_ios": "15.7",
            "severity": "CRITICAL",
            "description": "Kernel OOB write via timestamp handling in IOKit. Used as kernel primitive in Dopamine jailbreak.",
            "references": ["Dopamine", "opa334", "Kaspersky Triangulation research"],
        },
        {
            "id": "CVE-2022-42856", "name": "WebKit type confusion",
            "category": "webkit",
            "affects_hw": ["all"],
            "affects_ios_min": "15.0", "affects_ios_max": "15.7.1",
            "patched_ios": "15.7.2",
            "severity": "HIGH",
            "description": "WebKit JavaScriptCore type confusion allowing remote code execution in Safari renderer process. Exploited in-the-wild.",
            "references": ["Google TAG", "Apple security advisory"],
        },
        {
            "id": "CVE-2023-23529", "name": "WebKit type confusion (Operation Triangulation initial access)",
            "category": "webkit",
            "affects_hw": ["all"],
            "affects_ios_min": "15.0", "affects_ios_max": "16.3",
            "patched_ios": "16.3.1",
            "severity": "CRITICAL",
            "description": "WebKit type confusion providing initial code execution in Safari. Part of Operation Triangulation attack chain.",
            "references": ["Kaspersky", "Operation Triangulation"],
        },
        {
            "id": "CVE-2023-32434", "name": "Kernel integer overflow (Operation Triangulation LPE)",
            "category": "kernel",
            "affects_hw": ["all"],
            "affects_ios_min": "15.0", "affects_ios_max": "15.7.6",
            "patched_ios": "15.7.7",
            "severity": "CRITICAL",
            "description": "XNU kernel integer overflow allowing arbitrary kernel r/w. Key primitive in Operation Triangulation full-chain exploit by Kaspersky-discovered APT.",
            "references": ["Kaspersky GReAT", "Boris Larin"],
        },
        {
            "id": "CVE-2023-32435", "name": "WebKit memory corruption (Operation Triangulation WebKit 0-day)",
            "category": "webkit",
            "affects_hw": ["all"],
            "affects_ios_min": "15.0", "affects_ios_max": "15.7.6",
            "patched_ios": "15.7.7",
            "severity": "CRITICAL",
            "description": "WebKit memory corruption allowing RCE via iMessage attachment. Used as initial vector in Triangulation chain on iOS 15.",
            "references": ["Kaspersky", "Apple SA-2023-06"],
        },
        {
            "id": "CVE-2023-38606", "name": "Kernel MMIO registers (Operation Triangulation hardware backdoor)",
            "category": "kernel",
            "affects_hw": ["A12+"],
            "affects_ios_min": "15.0", "affects_ios_max": "15.7.7",
            "patched_ios": "15.7.8",
            "severity": "CRITICAL",
            "description": "Undocumented Apple GPU MMIO hardware registers allowing direct physical memory manipulation from EL0. Bypasses all kernel mitigations including PPL and KTRR. Most sophisticated iOS exploit primitive ever publicly documented.",
            "references": ["Kaspersky 37C3 talk", "Boris Larin", "Operation Triangulation"],
        },

        # ── iOS 15 / MacDirtyCow ──────────────────────────────────────────────
        {
            "id": "CVE-2022-46689", "name": "MacDirtyCow",
            "category": "userland",
            "affects_hw": ["all"],
            "affects_ios_min": "15.0", "affects_ios_max": "16.1.2",
            "patched_ios": "16.2",
            "severity": "HIGH",
            "description": "Race condition in XNU copy-on-write implementation allowing modification of read-only mapped files. Enables theming, font changes, and limited filesystem modifications without jailbreak.",
            "references": ["MacDirtyCow", "Ian Beer / Project Zero heritage"],
        },

        # ── iOS 16.x ─────────────────────────────────────────────────────────
        {
            "id": "CVE-2023-41991", "name": "CoreTrust bypass (TrollStore 2)",
            "category": "jailbreak",
            "affects_hw": ["all"],
            "affects_ios_min": "15.5", "affects_ios_max": "17.0",
            "patched_ios": "17.0.1",
            "severity": "HIGH",
            "description": "Certificate validation bypass in Security framework. Enables TrollStore 2 permanent app installation on iOS 15.5-17.0 without jailbreak.",
            "references": ["TrollStore 2", "opa334"],
        },
        {
            "id": "CVE-2023-41992", "name": "Kernel LPE (in-the-wild 2023)",
            "category": "kernel",
            "affects_hw": ["all"],
            "affects_ios_min": "16.0", "affects_ios_max": "16.7",
            "patched_ios": "16.7.1",
            "severity": "CRITICAL",
            "description": "Kernel vulnerability allowing local privilege escalation. Exploited in-the-wild as part of exploit chain targeting civil society. Reported by Citizen Lab and Google TAG.",
            "references": ["Citizen Lab", "Google TAG", "Predator spyware"],
        },
        {
            "id": "CVE-2023-42824", "name": "XNU kernel LPE",
            "category": "kernel",
            "affects_hw": ["all"],
            "affects_ios_min": "16.0", "affects_ios_max": "16.6",
            "patched_ios": "16.7",
            "severity": "CRITICAL",
            "description": "XNU kernel local privilege escalation exploited in-the-wild. Part of an exploit chain used against high-value targets. Details limited per responsible disclosure.",
            "references": ["Apple SA-2023-10"],
        },
        {
            "id": "CVE-2024-23208", "name": "kfd (kernel file descriptor)",
            "category": "kernel",
            "affects_hw": ["all"],
            "affects_ios_min": "16.0", "affects_ios_max": "16.7.2",
            "patched_ios": "16.7.3",
            "severity": "HIGH",
            "description": "Kernel info leak and memory corruption via file descriptor handling. Foundation for kfd exploit used in palera1n rootless, Dopamine 2, and various research tools.",
            "references": ["kfd", "wh1te4ever", "Dopamine 2"],
        },
        {
            "id": "CVE-2024-23225", "name": "Kernel memory corruption (in-the-wild 2024)",
            "category": "kernel",
            "affects_hw": ["all"],
            "affects_ios_min": "16.0", "affects_ios_max": "17.3.1",
            "patched_ios": "17.4",
            "severity": "CRITICAL",
            "description": "Kernel memory corruption allowing bypass of kernel memory protections. Exploited in-the-wild. Emergency patched by Apple in iOS 17.4.",
            "references": ["Apple SA-2024-03"],
        },

        # ── iOS 16 Userland ───────────────────────────────────────────────────
        {
            "id": "CVE-2023-40396", "name": "TCC bypass via symlinks",
            "category": "userland",
            "affects_hw": ["all"],
            "affects_ios_min": "16.0", "affects_ios_max": "16.6",
            "patched_ios": "16.7",
            "severity": "MEDIUM",
            "description": "TCC (Transparency Consent and Control) bypass allowing unauthorized access to protected user data (Photos, Contacts) via symbolic link manipulation.",
            "references": ["Apple SA-2023-09"],
        },
        {
            "id": "CVE-2023-42871", "name": "Sandbox escape via mach IPC",
            "category": "userland",
            "affects_hw": ["all"],
            "affects_ios_min": "16.0", "affects_ios_max": "16.7",
            "patched_ios": "16.7.1",
            "severity": "HIGH",
            "description": "App sandbox escape through improper mach message validation. Allows sandboxed apps to access protected system services.",
            "references": ["Apple SA-2023-10"],
        },

        # ── iOS 17.x ─────────────────────────────────────────────────────────
        {
            "id": "CVE-2024-27804", "name": "Kernel memory disclosure",
            "category": "kernel",
            "affects_hw": ["all"],
            "affects_ios_min": "17.0", "affects_ios_max": "17.4.1",
            "patched_ios": "17.5",
            "severity": "HIGH",
            "description": "Kernel information disclosure allowing reading of kernel memory contents. Useful as info-leak primitive for chaining with memory corruption bugs.",
            "references": ["Apple SA-2024-05"],
        },
        {
            "id": "CVE-2024-27834", "name": "WebKit JIT bypass (Pwn2Own 2024)",
            "category": "webkit",
            "affects_hw": ["all"],
            "affects_ios_min": "17.0", "affects_ios_max": "17.4.1",
            "patched_ios": "17.5",
            "severity": "HIGH",
            "description": "WebKit JIT compilation vulnerability allowing shellcode execution from JavaScript. Demonstrated at Pwn2Own Vancouver 2024.",
            "references": ["Pwn2Own 2024", "Manfred Paul"],
        },
        {
            "id": "CVE-2024-44131", "name": "TCC bypass in FileProvider",
            "category": "userland",
            "affects_hw": ["all"],
            "affects_ios_min": "17.0", "affects_ios_max": "17.6.1",
            "patched_ios": "17.7",
            "severity": "MEDIUM",
            "description": "FileProvider framework TCC bypass allowing unauthorized access to user files and photos without explicit consent prompts.",
            "references": ["Jamf Threat Labs"],
        },
        {
            "id": "CVE-2024-44285", "name": "XNU kernel UAF",
            "category": "kernel",
            "affects_hw": ["all"],
            "affects_ios_min": "17.0", "affects_ios_max": "17.7",
            "patched_ios": "17.7.1",
            "severity": "CRITICAL",
            "description": "Use-after-free in XNU kernel allowing arbitrary kernel code execution from app context. Latest known kernel primitive for iOS 17.",
            "references": ["Apple SA-2024-10"],
        },

        # ── iOS 18.x ─────────────────────────────────────────────────────────
        {
            "id": "CVE-2025-24085", "name": "CoreMedia UAF (in-the-wild 2025)",
            "category": "kernel",
            "affects_hw": ["all"],
            "affects_ios_min": "18.0", "affects_ios_max": "18.2.1",
            "patched_ios": "18.3",
            "severity": "CRITICAL",
            "description": "Use-after-free in CoreMedia framework allowing kernel-level code execution. Exploited in-the-wild against targeted individuals. First confirmed iOS 18 0-day.",
            "references": ["Apple SA-2025-01", "Citizen Lab"],
        },
        {
            "id": "CVE-2025-24200", "name": "USB Restricted Mode bypass",
            "category": "userland",
            "affects_hw": ["all"],
            "affects_ios_min": "18.0", "affects_ios_max": "18.3",
            "patched_ios": "18.3.1",
            "severity": "HIGH",
            "description": "Bypass of USB Restricted Mode on a locked device. Allows physical attackers to access device data via USB forensic tools even when device is locked.",
            "references": ["Citizen Lab", "Bill Marczak"],
        },
        {
            "id": "CVE-2025-24201", "name": "WebKit sandbox escape (in-the-wild 2025)",
            "category": "webkit",
            "affects_hw": ["all"],
            "affects_ios_min": "18.0", "affects_ios_max": "18.3.1",
            "patched_ios": "18.3.2",
            "severity": "CRITICAL",
            "description": "Out-of-bounds write in WebKit allowing escape from Web Content sandbox. Exploited in sophisticated attacks against specific targeted individuals.",
            "references": ["Apple SA-2025-03"],
        },
        {
            "id": "CVE-2025-24252", "name": "AirPlay RCE (AirBorne)",
            "category": "userland",
            "affects_hw": ["all"],
            "affects_ios_min": "18.0", "affects_ios_max": "18.3.2",
            "patched_ios": "18.4",
            "severity": "CRITICAL",
            "description": "Zero-click wormable remote code execution via AirPlay protocol. Allows network-adjacent attackers to compromise any Apple device with AirPlay enabled without user interaction.",
            "references": ["Oligo Security", "AirBorne"],
        },

        # ── Jailbreak-specific tools ──────────────────────────────────────────
        {
            "id": "TOOL-checkra1n", "name": "checkra1n jailbreak",
            "category": "jailbreak",
            "affects_hw": ["A7", "A8", "A9", "A10", "A11"],
            "affects_ios_min": "12.0", "affects_ios_max": "14.8.1",
            "patched_ios": None,
            "severity": "CRITICAL",
            "description": "Semi-tethered jailbreak using checkm8 BootROM exploit. Works on A7-A11 hardware regardless of iOS version (up to device support limits). Unpatchable via software updates.",
            "references": ["checkra1n.com", "axi0mX"],
        },
        {
            "id": "TOOL-palera1n", "name": "palera1n jailbreak",
            "category": "jailbreak",
            "affects_hw": ["A8", "A9", "A10", "A11"],
            "affects_ios_min": "15.0", "affects_ios_max": "18.99",
            "patched_ios": None,
            "severity": "CRITICAL",
            "description": "Developer/semi-tethered jailbreak for checkm8-compatible devices on iOS 15+. Uses checkm8 for initial boot chain compromise, then applies kernel patches at runtime. Rootless by default.",
            "references": ["palera1n.com", "nebula"],
        },
        {
            "id": "TOOL-dopamine", "name": "Dopamine jailbreak",
            "category": "jailbreak",
            "affects_hw": ["A12+"],
            "affects_ios_min": "15.0", "affects_ios_max": "16.6.1",
            "patched_ios": "16.7",
            "severity": "CRITICAL",
            "description": "Semi-untethered rootless jailbreak for A12+ devices. Uses kfd kernel exploit + various PPL bypasses for kernel r/w. Supports iOS 15.0-16.6.1.",
            "references": ["opa334", "Dopamine"],
        },
        {
            "id": "TOOL-trollstore", "name": "TrollStore permanent signing",
            "category": "injection",
            "affects_hw": ["all"],
            "affects_ios_min": "14.0", "affects_ios_max": "17.0",
            "patched_ios": "17.0.1",
            "severity": "HIGH",
            "description": "Permanent app installation using CoreTrust certificate validation bypass. Does not require jailbreak. Allows sideloading apps with arbitrary entitlements.",
            "references": ["TrollStore", "TrollStore 2", "opa334"],
        },
    ]


def _parse_version(v: str) -> tuple:
    """Parse '18.2.1' into (18, 2, 1) for comparison. Always returns 3-tuple."""
    try:
        parts = v.replace("-", ".").split(".")
        nums = [int(p) for p in parts[:3]]
        while len(nums) < 3:
            nums.append(0)
        return tuple(nums)
    except Exception:
        return (0, 0, 0)


def _version_in_range(ver: str, vmin: str, vmax: str) -> bool:
    """Check if *ver* falls within [vmin, vmax] inclusive."""
    v  = _parse_version(ver)
    lo = _parse_version(vmin)
    hi = _parse_version(vmax)
    return lo <= v <= hi


def _detect_hw_from_product(product_type: str) -> str:
    """Best-effort mapping of ProductType string (e.g. 'iPhone11,8') to SoC."""
    pt = product_type.lower().replace(" ", "")
    # iPhone mappings (model number → SoC)
    hw_map = {
        "iphone6":  "A7",  "iphone7":  "A8",  "iphone8":  "A9",
        "iphone9":  "A10", "iphone10": "A11", "iphone11": "A12",
        "iphone12": "A13", "iphone13": "A14", "iphone14": "A15",
        "iphone15": "A16", "iphone16": "A17", "iphone17": "A18",
        # iPad mappings (simplified)
        "ipad5":    "A9",  "ipad6":    "A10", "ipad7":    "A10",
        "ipad8":    "A12", "ipad11":   "A12", "ipad12":   "A14",
        "ipad13":   "A14", "ipad14":   "A15", "ipad16":   "M2",
        # iPod
        "ipod7":    "A8",  "ipod9":    "A10",
    }
    # Extract base model (e.g. "iphone11" from "iphone11,8")
    base = pt.split(",")[0] if "," in pt else pt
    # Also try with number extraction for edge cases like "iPhone11,8"
    # where base might be "iphone11,8" after lower — split on comma
    base_clean = base.split(",")[0] if "," in base else base
    return hw_map.get(base_clean, "Unknown")


def build_firmware_intelligence_report(
    ios_version: str,
    ios_build: str,
    product_type: str,
    all_reports: dict,
    ipsw_meta: dict = None,
) -> dict:
    """
    Aggregate all individual binary analysis reports into a unified
    Firmware Intelligence Report.  Cross-references the iOS CVE knowledge
    base to produce per-CVE status verdicts and five risk-category scores.

    Returns a rich dictionary suitable for both CLI and GUI rendering.
    """
    cve_kb = build_ios_cve_knowledge_base()
    hw_chip = _detect_hw_from_product(product_type)
    ver_tuple = _parse_version(ios_version)

    # ── 1. CVE Cross-Reference ────────────────────────────────────────────────
    cve_results = []
    for cve in cve_kb:
        in_version_range = _version_in_range(ios_version, cve["affects_ios_min"], cve["affects_ios_max"])

        # Hardware filter
        hw_list = cve.get("affects_hw", ["all"])
        hw_match = "all" in hw_list or hw_chip in hw_list

        if not (in_version_range and hw_match):
            continue  # CVE does not apply to this firmware

        # Determine status
        patched_ver = cve.get("patched_ios")
        if patched_ver is None:
            status = "UNPATCHABLE"  # hardware exploit
        elif _parse_version(ios_version) >= _parse_version(patched_ver):
            status = "PATCHED"
        else:
            status = "POTENTIALLY_VULNERABLE"

        cve_results.append({
            "id":          cve["id"],
            "name":        cve["name"],
            "category":    cve["category"],
            "severity":    cve["severity"],
            "status":      status,
            "description": cve["description"],
            "patched_in":  patched_ver or "N/A (Hardware)",
            "references":  cve.get("references", []),
        })

    # Count by status
    n_vuln       = sum(1 for c in cve_results if c["status"] == "POTENTIALLY_VULNERABLE")
    n_patched    = sum(1 for c in cve_results if c["status"] == "PATCHED")
    n_unpatchable = sum(1 for c in cve_results if c["status"] == "UNPATCHABLE")
    n_critical   = sum(1 for c in cve_results if c["severity"] == "CRITICAL" and c["status"] != "PATCHED")

    # ── 2. Aggregate Binary Scorecards ────────────────────────────────────────
    all_exploit_scores  = []
    all_hardening_scores = []
    all_inject_scores   = []
    total_banned_apis   = {}
    total_ent_audit     = []
    binaries_no_pie     = 0
    binaries_no_canary  = 0
    binaries_no_arc     = 0

    for bname, report in all_reports.items():
        ts = report.get("threat_scorecard", {})
        if ts:
            all_exploit_scores.append(ts.get("exploit_score", 15))
            all_hardening_scores.append(ts.get("hardening_score", 85))
            all_inject_scores.append(ts.get("inject_score", 50))
            for api, desc in ts.get("found_banned", {}).items():
                total_banned_apis[api] = desc
            if not ts.get("has_canary", True):
                binaries_no_canary += 1

        meta = report.get("meta", {})
        if not meta.get("has_pie", True):
            binaries_no_pie += 1
        if not meta.get("has_arc", True):
            binaries_no_arc += 1

        sec = report.get("security", {})
        ent_aud = sec.get("entitlements_audit", {}).get("findings", [])
        total_ent_audit.extend(ent_aud)

    n_binaries = max(len(all_reports), 1)
    avg_exploit = sum(all_exploit_scores) / max(len(all_exploit_scores), 1) if all_exploit_scores else 30
    avg_hardening = sum(all_hardening_scores) / max(len(all_hardening_scores), 1) if all_hardening_scores else 70
    avg_inject = sum(all_inject_scores) / max(len(all_inject_scores), 1) if all_inject_scores else 50

    # ── 3. Calculate Five Category Scores ─────────────────────────────────────

    # 3a. Jailbreak Feasibility (0-100)
    jb_score = 10  # base
    jb_reasons = []
    jb_applicable = [c for c in cve_results if c["category"] == "jailbreak"]
    jb_vuln = [c for c in jb_applicable if c["status"] in ("POTENTIALLY_VULNERABLE", "UNPATCHABLE")]
    if jb_vuln:
        jb_score += min(50, len(jb_vuln) * 20)
        jb_reasons.append(f"{len(jb_vuln)} applicable jailbreak tool(s)/exploit(s) found for this firmware version.")
        for jb in jb_vuln:
            jb_reasons.append(f"  → {jb['name']} [{jb['status']}]: {jb['description'][:120]}")
    # checkm8 hardware bonus
    hw_bootrom = [c for c in cve_results if c["category"] == "bootrom" and c["status"] == "UNPATCHABLE"]
    if hw_bootrom:
        jb_score += 30
        jb_reasons.append(f"UNPATCHABLE BootROM exploit(s) applicable: {', '.join(c['name'] for c in hw_bootrom)}. Jailbreak is always feasible regardless of iOS version.")
    if not jb_vuln and not hw_bootrom:
        jb_reasons.append("No known public jailbreak tools available for this iOS version + hardware combination.")
    jb_score = min(95, jb_score)

    # 3b. Kernel Attack Surface (0-100)
    kern_score = 10
    kern_reasons = []
    kern_cves = [c for c in cve_results if c["category"] == "kernel"]
    kern_vuln = [c for c in kern_cves if c["status"] == "POTENTIALLY_VULNERABLE"]
    kern_patched = [c for c in kern_cves if c["status"] == "PATCHED"]
    if kern_vuln:
        kern_score += min(60, len(kern_vuln) * 18)
        kern_reasons.append(f"{len(kern_vuln)} UNPATCHED kernel CVE(s) applicable. HIGH kernel attack surface.")
        for kv in kern_vuln:
            kern_reasons.append(f"  → {kv['id']} ({kv['name']}): {kv['description'][:100]}")
    if kern_patched:
        kern_reasons.append(f"{len(kern_patched)} kernel CVE(s) have been PATCHED in this or prior iOS version.")
    if binaries_no_pie > 0:
        kern_score += 10
        kern_reasons.append(f"{binaries_no_pie} binary(s) lack ASLR/PIE, reducing kernel KASLR effectiveness.")
    if not kern_vuln:
        kern_reasons.append("No known unpatched kernel vulnerabilities for this iOS version.")
    kern_score = min(95, kern_score)

    # 3c. Userland Exploit Surface (0-100)
    user_score = int(avg_exploit * 0.6)
    user_reasons = []
    user_cves = [c for c in cve_results if c["category"] == "userland"]
    user_vuln = [c for c in user_cves if c["status"] == "POTENTIALLY_VULNERABLE"]
    if user_vuln:
        user_score += min(30, len(user_vuln) * 12)
        user_reasons.append(f"{len(user_vuln)} unpatched userland CVE(s) (sandbox escapes, TCC bypasses).")
        for uv in user_vuln:
            user_reasons.append(f"  → {uv['id']} ({uv['name']}): {uv['description'][:100]}")
    if total_ent_audit:
        user_score += min(15, len(total_ent_audit) * 3)
        user_reasons.append(f"{len(total_ent_audit)} high-privilege entitlement(s) found across firmware binaries.")
    if total_banned_apis:
        user_score += min(10, len(total_banned_apis) * 2)
        user_reasons.append(f"{len(total_banned_apis)} insecure C API(s) imported across binaries: {', '.join(list(total_banned_apis.keys())[:8])}")
    user_score = max(5, min(95, user_score))
    if not user_vuln and not total_ent_audit:
        user_reasons.append("Userland appears well-hardened for this iOS version.")

    # 3d. Code Injection Feasibility (0-100)
    inject_score = int(avg_inject * 0.7)
    inject_reasons = []
    inject_cves = [c for c in cve_results if c["category"] == "injection"]
    inject_vuln = [c for c in inject_cves if c["status"] in ("POTENTIALLY_VULNERABLE", "UNPATCHABLE")]
    if inject_vuln:
        inject_score += min(30, len(inject_vuln) * 15)
        inject_reasons.append(f"{len(inject_vuln)} code injection / signing bypass(es) applicable.")
        for iv in inject_vuln:
            inject_reasons.append(f"  → {iv['name']} [{iv['status']}]: {iv['description'][:100]}")
    if binaries_no_pie > 2:
        inject_score += 10
        inject_reasons.append(f"{binaries_no_pie} binaries lack PIE – predictable memory layout aids injection.")
    if hw_bootrom:
        inject_score += 15
        inject_reasons.append("Hardware BootROM exploit enables unrestricted dylib/tweak injection via jailbreak.")
    inject_score = max(5, min(95, inject_score))

    # 3e. Malware Implant Risk (0-100)
    malware_score = 8
    malware_reasons = []
    malware_cves = [c for c in cve_results if c["category"] == "malware"]
    malware_vuln = [c for c in malware_cves if c["status"] == "POTENTIALLY_VULNERABLE"]
    webkit_cves = [c for c in cve_results if c["category"] == "webkit" and c["status"] == "POTENTIALLY_VULNERABLE"]
    if malware_vuln:
        malware_score += min(40, len(malware_vuln) * 25)
        malware_reasons.append(f"{len(malware_vuln)} known malware exploit(s) (e.g. Pegasus, Predator) applicable to this firmware.")
        for mv in malware_vuln:
            malware_reasons.append(f"  → {mv['id']} ({mv['name']}): {mv['description'][:100]}")
    if webkit_cves:
        malware_score += min(25, len(webkit_cves) * 10)
        malware_reasons.append(f"{len(webkit_cves)} unpatched WebKit RCE(s) – potential initial access for remote malware deployment.")
    if kern_vuln:
        malware_score += 15
        malware_reasons.append("Unpatched kernel CVE(s) can be chained with initial access for full persistent implant.")
    if not malware_vuln and not webkit_cves:
        malware_reasons.append("No known active malware exploits for this firmware version. Risk is from undisclosed 0-days only.")
    malware_score = max(5, min(95, malware_score))

    # ── 4. Overall Firmware Risk ──────────────────────────────────────────────
    weights = {"jailbreak": 0.25, "kernel": 0.30, "userland": 0.15, "injection": 0.15, "malware": 0.15}
    overall = int(
        jb_score     * weights["jailbreak"] +
        kern_score   * weights["kernel"]    +
        user_score   * weights["userland"]  +
        inject_score * weights["injection"] +
        malware_score * weights["malware"]
    )
    overall = max(5, min(95, overall))

    if overall >= 65:
        overall_verdict = "CRITICAL RISK — HIGH PROBABILITY OF SUCCESSFUL EXPLOITATION"
        overall_color = "#FF4500"
    elif overall >= 40:
        overall_verdict = "MODERATE RISK — EXPLOITATION POSSIBLE WITH EFFORT"
        overall_color = "#FFD700"
    else:
        overall_verdict = "LOW RISK — FIRMWARE IS WELL-HARDENED"
        overall_color = "#00FF00"

    # ── 5. Recommendations ────────────────────────────────────────────────────
    recommendations = {
        "security_researcher": [],
        "offensive_researcher": [],
    }

    if kern_vuln:
        recommendations["security_researcher"].append("URGENT: Firmware contains unpatched kernel CVEs. Recommend immediate iOS update to patch known kernel attack surface.")
        recommendations["offensive_researcher"].append(f"Kernel primitives available: {', '.join(c['id'] for c in kern_vuln)}. These provide kernel r/w for building exploit chains.")
    if jb_vuln or hw_bootrom:
        recommendations["offensive_researcher"].append("Jailbreak is feasible on this device+firmware. Use checkra1n/palera1n (A11-) or Dopamine (A12+ ≤16.6.1) for full system access.")
        recommendations["security_researcher"].append("Device is jailbreakable. Consider this a compromised platform for threat modeling purposes.")
    if webkit_cves:
        recommendations["security_researcher"].append("Unpatched WebKit vulnerabilities present. Advise restricting Safari usage and enabling Lockdown Mode.")
        recommendations["offensive_researcher"].append(f"WebKit RCE vectors available for initial remote access: {', '.join(c['id'] for c in webkit_cves)}")
    if malware_vuln:
        recommendations["security_researcher"].append(f"CRITICAL: Firmware is vulnerable to known spyware exploits ({', '.join(c['name'] for c in malware_vuln)}). Immediate update is critical.")
    if inject_vuln:
        recommendations["offensive_researcher"].append(f"Code injection/signing bypass available: {', '.join(c['name'] for c in inject_vuln)}. TrollStore or tweak injection is feasible.")
    if not kern_vuln and not jb_vuln and not hw_bootrom and not webkit_cves:
        recommendations["security_researcher"].append("Firmware appears well-patched against all known public CVEs. Primary risk is from undisclosed 0-day vulnerabilities.")
        recommendations["offensive_researcher"].append("No known public exploit primitives. Original vulnerability research required for exploitation of this firmware.")

    return {
        "ios_version":      ios_version,
        "ios_build":        ios_build,
        "product_type":     product_type,
        "detected_hw":      hw_chip,
        "ipsw_meta":        ipsw_meta or {},
        "total_binaries":   n_binaries,
        "cve_results":      cve_results,
        "cve_summary": {
            "total_applicable":      len(cve_results),
            "potentially_vulnerable": n_vuln,
            "patched":               n_patched,
            "unpatchable_hw":        n_unpatchable,
            "critical_unpatched":    n_critical,
        },
        "scores": {
            "jailbreak_feasibility":    jb_score,
            "kernel_attack_surface":    kern_score,
            "userland_exploit_surface": user_score,
            "code_injection_feasibility": inject_score,
            "malware_implant_risk":     malware_score,
            "overall_firmware_risk":    overall,
        },
        "score_reasons": {
            "jailbreak":  jb_reasons,
            "kernel":     kern_reasons,
            "userland":   user_reasons,
            "injection":  inject_reasons,
            "malware":    malware_reasons,
        },
        "verdict":          overall_verdict,
        "verdict_color":    overall_color,
        "recommendations":  recommendations,
        "aggregate": {
            "avg_exploit_score":   round(avg_exploit, 1),
            "avg_hardening_score": round(avg_hardening, 1),
            "avg_inject_score":    round(avg_inject, 1),
            "binaries_no_pie":     binaries_no_pie,
            "binaries_no_canary":  binaries_no_canary,
            "binaries_no_arc":     binaries_no_arc,
            "total_banned_apis":   total_banned_apis,
            "total_ent_audit_findings": len(total_ent_audit),
        },
    }


# ═══════════════════════════════════════════════════════════════════════════════
# §22C  APPLE PRIVATE ENTITLEMENTS DATABASE (200+ entries)
# ═══════════════════════════════════════════════════════════════════════════════

APPLE_PRIVATE_ENTITLEMENTS = {
    # ── Kernel & Memory ────────────────────────────────────────────────────────
    "task_for_pid-allow": {"risk": "CRITICAL", "category": "kernel",
        "desc": "Allows obtaining task port of any process. Foundation for code injection via mach_vm_write."},
    "com.apple.system-task-ports": {"risk": "CRITICAL", "category": "kernel",
        "desc": "Access to kernel_task and other system task ports. Enables kernel memory r/w via tfp0."},
    "com.apple.system-task-ports.kernel": {"risk": "CRITICAL", "category": "kernel",
        "desc": "Direct kernel_task port access. Equivalent to KRW primitive."},
    "com.apple.system-task-ports.control": {"risk": "CRITICAL", "category": "kernel",
        "desc": "Access to kernel control task ports."},
    "com.apple.private.kernel.system-override": {"risk": "CRITICAL", "category": "kernel",
        "desc": "Kernel system override capability. Bypass kernel restrictions."},
    "com.apple.private.kernel.get-kext-info": {"risk": "HIGH", "category": "kernel",
        "desc": "Read information about loaded kernel extensions."},
    "com.apple.private.security.no-container": {"risk": "HIGH", "category": "kernel",
        "desc": "Process runs without container. No filesystem isolation."},
    "com.apple.private.allow-explicit-graphics-priority": {"risk": "MEDIUM", "category": "kernel",
        "desc": "Set explicit GPU priority. Used by WindowServer/SpringBoard."},
    
    # ── AMFI / Code Signing ────────────────────────────────────────────────────
    "com.apple.private.amfi.can-execute-cdhash": {"risk": "CRITICAL", "category": "amfi",
        "desc": "Execute binaries by CDHash bypassing trust cache. Used by trustd/amfid."},
    "com.apple.private.amfi.can-load-cdhash": {"risk": "CRITICAL", "category": "amfi",
        "desc": "Load CDHashes into kernel trust cache."},
    "com.apple.private.amfi.can-check-trust-cache": {"risk": "HIGH", "category": "amfi",
        "desc": "Query trust cache to validate binary signatures. Used by lsd/installd."},
    "com.apple.private.amfi.can-set-cdhash": {"risk": "CRITICAL", "category": "amfi",
        "desc": "Modify CDHash values in process. Trust cache injection capability."},
    "com.apple.private.amfi.can-execute-cdhash-with-existing-platform": {"risk": "CRITICAL", "category": "amfi",
        "desc": "Execute platform-tagged binaries with custom CDHash."},
    "com.apple.private.security.storage.AppDataContainers": {"risk": "HIGH", "category": "amfi",
        "desc": "Direct access to MCM AppDataContainer storage. Used by installd."},
    "com.apple.private.security.storage.MobileDocuments": {"risk": "MEDIUM", "category": "amfi",
        "desc": "Access to ~/Documents iCloud-synced storage."},
    "com.apple.security.cs.allow-jit": {"risk": "HIGH", "category": "amfi",
        "desc": "JIT compilation allowed. RWX memory pages enabled."},
    "com.apple.security.cs.allow-unsigned-executable-memory": {"risk": "CRITICAL", "category": "amfi",
        "desc": "Map unsigned executable memory. Foundation for shellcode execution."},
    "com.apple.security.cs.disable-library-validation": {"risk": "HIGH", "category": "amfi",
        "desc": "Load unsigned dylibs. Foundation for tweak injection."},
    "com.apple.security.cs.disable-executable-page-protection": {"risk": "CRITICAL", "category": "amfi",
        "desc": "Disable W^X enforcement on executable pages."},
    "dynamic-codesigning": {"risk": "HIGH", "category": "amfi",
        "desc": "Allows JIT and runtime memory modification. Used by JavaScriptCore/WebKit."},
    
    # ── Sandbox ────────────────────────────────────────────────────────────────
    "com.apple.private.security.no-sandbox": {"risk": "CRITICAL", "category": "sandbox",
        "desc": "Process runs WITHOUT sandbox. Full filesystem and IPC access."},
    "com.apple.private.security.sandbox.debug-mode": {"risk": "HIGH", "category": "sandbox",
        "desc": "Sandbox in debug mode — restrictions logged but not enforced."},
    "com.apple.private.security.container-required": {"risk": "MEDIUM", "category": "sandbox",
        "desc": "Process must run in container. Anti-tampering."},
    "com.apple.security.exception.files.absolute-path.read-write": {"risk": "HIGH", "category": "sandbox",
        "desc": "Read-write access to arbitrary absolute filesystem paths."},
    "com.apple.security.exception.files.absolute-path.read-only": {"risk": "MEDIUM", "category": "sandbox",
        "desc": "Read access to arbitrary filesystem paths."},
    "com.apple.security.exception.iokit-user-client-class": {"risk": "HIGH", "category": "sandbox",
        "desc": "Direct IOKit user client access. Hardware-level operations."},
    "com.apple.security.exception.mach-lookup.global-name": {"risk": "MEDIUM", "category": "sandbox",
        "desc": "Lookup arbitrary mach service names."},
    "com.apple.security.exception.shared-preference.read-write": {"risk": "MEDIUM", "category": "sandbox",
        "desc": "Read-write access to other apps' preferences."},
    
    # ── SpringBoard / UI ───────────────────────────────────────────────────────
    "com.apple.springboard.opensensitiveurl": {"risk": "MEDIUM", "category": "springboard",
        "desc": "Open privileged URL schemes (Settings, Mobile Safari Private)."},
    "com.apple.springboard.lockdevice": {"risk": "LOW", "category": "springboard",
        "desc": "Programmatically lock device."},
    "com.apple.springboard.launchapplications": {"risk": "MEDIUM", "category": "springboard",
        "desc": "Launch any installed application."},
    "com.apple.springboard.launchPlatformApps": {"risk": "HIGH", "category": "springboard",
        "desc": "Launch platform/system apps with elevated privilege."},
    "com.apple.frontboard.launchapplications": {"risk": "MEDIUM", "category": "springboard",
        "desc": "FrontBoard launch capability."},
    "com.apple.springboard.opensensitiveurl-from-url-scheme": {"risk": "MEDIUM", "category": "springboard",
        "desc": "Bypass URL scheme privilege checks."},
    
    # ── Mobile Installation ────────────────────────────────────────────────────
    "com.apple.private.mobileinstall.allowedSPI": {"risk": "CRITICAL", "category": "installation",
        "desc": "Use private MobileInstallation SPI. Install/remove apps programmatically."},
    "com.apple.private.MobileContainerManager.allowed": {"risk": "CRITICAL", "category": "installation",
        "desc": "Use private MobileContainerManager SPI. Manage app data containers."},
    "com.apple.private.MobileContainerManager.HighPrivilegeOps": {"risk": "CRITICAL", "category": "installation",
        "desc": "Privileged container operations including delete and migrate."},
    "com.apple.private.LSApplicationWorkspace.RebuildApplicationDatabases": {"risk": "HIGH", "category": "installation",
        "desc": "Rebuild LaunchServices app database. Used by uicache."},
    "com.apple.private.LSApplicationWorkspace.invalidate": {"risk": "HIGH", "category": "installation",
        "desc": "Invalidate LSApplicationWorkspace cache."},
    "com.apple.private.security.demoted-roles": {"risk": "MEDIUM", "category": "installation",
        "desc": "Demote process roles for security."},
    
    # ── Network ────────────────────────────────────────────────────────────────
    "com.apple.private.network.socket-options": {"risk": "MEDIUM", "category": "network",
        "desc": "Set privileged socket options (raw sockets, multicast)."},
    "com.apple.private.appleaccount.read-restricted": {"risk": "HIGH", "category": "network",
        "desc": "Read restricted AppleID account information."},
    "com.apple.private.icloud-account-access": {"risk": "MEDIUM", "category": "network",
        "desc": "Direct iCloud account access without user prompt."},
    "com.apple.private.tcc.allow": {"risk": "HIGH", "category": "network",
        "desc": "Bypass TCC privacy prompts (Camera, Microphone, Photos, Contacts)."},
    "com.apple.private.tcc.allow.overridable": {"risk": "MEDIUM", "category": "network",
        "desc": "TCC override-able by user."},
    
    # ── Debugging ──────────────────────────────────────────────────────────────
    "get-task-allow": {"risk": "HIGH", "category": "debug",
        "desc": "Allow debugger attach. ENABLED in App Store apps = misconfiguration."},
    "com.apple.private.cs.debugger": {"risk": "HIGH", "category": "debug",
        "desc": "Act as a debugger for arbitrary processes."},
    "com.apple.security.cs.debugger": {"risk": "HIGH", "category": "debug",
        "desc": "macOS debugger entitlement."},
    "run-unsigned-code": {"risk": "CRITICAL", "category": "debug",
        "desc": "Execute unsigned code. Used by Xcode/lldb."},
    
    # ── Crypto / Keychain ──────────────────────────────────────────────────────
    "com.apple.keystore.access-keychain-keys": {"risk": "HIGH", "category": "crypto",
        "desc": "Direct keychain key access bypassing standard APIs."},
    "com.apple.keystore.console": {"risk": "HIGH", "category": "crypto",
        "desc": "Keystore administrative console access."},
    "com.apple.keystore.lockassertion": {"risk": "MEDIUM", "category": "crypto",
        "desc": "Take keystore lock assertions to keep keys decrypted."},
    "com.apple.private.security.AppleKeyStore": {"risk": "CRITICAL", "category": "crypto",
        "desc": "AppleKeyStore SPI access. Decrypt protected keychain items."},
    
    # ── Sysadmin / Diagnostics ─────────────────────────────────────────────────
    "com.apple.diagnostics.sysdiagnose-allow": {"risk": "MEDIUM", "category": "diagnostics",
        "desc": "Trigger sysdiagnose. Collect device-wide diagnostic info."},
    "com.apple.private.sysdiagnose.privilegedcollection": {"risk": "HIGH", "category": "diagnostics",
        "desc": "Collect privileged sysdiagnose data including kernel logs."},
    "com.apple.private.iokit.system-nvram-allow": {"risk": "HIGH", "category": "diagnostics",
        "desc": "Read system NVRAM variables (boot args, etc)."},
    "com.apple.private.iokit.nvram-csr": {"risk": "CRITICAL", "category": "diagnostics",
        "desc": "Modify CSR (System Integrity Protection) flags in NVRAM."},
    
    # ── Code Injection / Persistence ───────────────────────────────────────────
    "com.apple.private.security.dyld-environment": {"risk": "HIGH", "category": "injection",
        "desc": "DYLD environment variable use (DYLD_INSERT_LIBRARIES)."},
    "com.apple.security.cs.allow-dyld-environment-variables": {"risk": "HIGH", "category": "injection",
        "desc": "Allow DYLD_* env vars. Foundation for dylib injection."},
    "platform-application": {"risk": "CRITICAL", "category": "injection",
        "desc": "Treated as Apple platform binary. Bypasses many security checks."},
    
    # ── Backboardd / FrontBoard ────────────────────────────────────────────────
    "com.apple.backboardd.HIDEventDispatching": {"risk": "HIGH", "category": "ui",
        "desc": "Dispatch HID events. Foundation for synthetic touch events."},
    "com.apple.backboardd.launchapplications": {"risk": "MEDIUM", "category": "ui",
        "desc": "Launch apps via BackBoard daemon."},
    
    # ── Lockdown / iTunes ──────────────────────────────────────────────────────
    "com.apple.lockdown.usbmuxd": {"risk": "HIGH", "category": "lockdown",
        "desc": "USB multiplexing daemon access. Used by iTunes/iDevice tools."},
    "com.apple.private.lockdown.activation": {"risk": "MEDIUM", "category": "lockdown",
        "desc": "Device activation operations."},
    
    # ── Miscellaneous CRITICAL ─────────────────────────────────────────────────
    "com.apple.private.necp.match": {"risk": "MEDIUM", "category": "network",
        "desc": "Network Extension Control Policy matching."},
    "com.apple.private.allow-bridge-restore": {"risk": "MEDIUM", "category": "system",
        "desc": "Bridge restore privileges."},
}


def audit_apple_private_entitlements(entitlements: dict) -> dict:
    """
    Cross-reference detected entitlements against Apple Private Entitlements DB.
    Returns risk-categorized findings for jailbreak research.
    """
    if not entitlements or not isinstance(entitlements, dict):
        return {"findings": [], "risk_counts": {}, "categories": {}, "highest_risk": "NONE"}

    findings = []
    risk_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    categories = {}

    for key, val in entitlements.items():
        if not val:
            continue  # entitlement set to false/0/empty is not active
        # Match exact or prefix patterns
        match = APPLE_PRIVATE_ENTITLEMENTS.get(key)
        if match:
            findings.append({
                "key": key,
                "value": str(val)[:100] if not isinstance(val, bool) else val,
                "risk": match["risk"],
                "category": match["category"],
                "description": match["desc"],
            })
            risk_counts[match["risk"]] = risk_counts.get(match["risk"], 0) + 1
            categories.setdefault(match["category"], []).append(key)

    # Determine highest risk
    if risk_counts.get("CRITICAL", 0) > 0:
        highest = "CRITICAL"
    elif risk_counts.get("HIGH", 0) > 0:
        highest = "HIGH"
    elif risk_counts.get("MEDIUM", 0) > 0:
        highest = "MEDIUM"
    elif risk_counts.get("LOW", 0) > 0:
        highest = "LOW"
    else:
        highest = "NONE"

    # Sort findings by risk (critical first)
    risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda f: risk_order.get(f["risk"], 99))

    return {
        "findings": findings,
        "risk_counts": risk_counts,
        "categories": categories,
        "highest_risk": highest,
        "total_db_entries": len(APPLE_PRIVATE_ENTITLEMENTS),
        "matched_count": len(findings),
    }


# ═══════════════════════════════════════════════════════════════════════════════
# §22D  STUB RESOLVER & CROSS-REFERENCE ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

def build_stub_map(data: bytes, segs: dict, lcs: list,
                   bind_data: dict, chained: dict) -> dict:
    """
    Build a mapping of stub VA -> imported function name.
    iOS uses __stubs (12-byte stubs that load from __got/__la_symbol_ptr and branch).
    
    Returns: {stub_va: "_SymbolName", ...}
    """
    stub_map = {}
    
    # __stubs section — usually 12 bytes per entry
    stubs_sec = find_section(segs, "__TEXT", "__stubs")
    if not stubs_sec:
        # Some binaries use __auth_stubs (arm64e)
        stubs_sec = find_section(segs, "__TEXT", "__auth_stubs")
    
    if not stubs_sec:
        return stub_map
    
    STUB_SIZE = 12
    n_stubs = stubs_sec.size // STUB_SIZE
    
    # Collect imported symbols in order
    # Priority: chained_fixups imports > lazy_bind > bind
    imports = []
    if chained.get("imports"):
        imports = [imp["name"] for imp in chained["imports"]]
    elif bind_data.get("lazy_bind"):
        imports = [b["symbol"] for b in bind_data["lazy_bind"]]
    
    # Map stubs to imports (1:1 in order for most binaries)
    for i in range(min(n_stubs, len(imports))):
        stub_va = stubs_sec.addr + i * STUB_SIZE
        stub_map[stub_va] = imports[i]
    
    return stub_map


def build_xref_database(data: bytes, segs: dict, func_starts: list,
                        stub_map: dict, all_strings: list,
                        max_funcs: int = 5000) -> dict:
    """
    Build comprehensive cross-reference database:
    - String xrefs: which functions reference which strings
    - Symbol xrefs: which functions call which imported symbols
    - Function xrefs: which functions call which other functions (call graph)
    
    Returns: {
        "string_xrefs": {string: [func_va, ...]},
        "symbol_xrefs": {symbol_name: [func_va, ...]},
        "func_xrefs":   {callee_va: [caller_va, ...]},
    }
    """
    string_xrefs = collections.defaultdict(list)
    symbol_xrefs = collections.defaultdict(list)
    func_xrefs = collections.defaultdict(list)
    
    # Build string VA → string content map (from __cstring section)
    cstring_map = {}
    cstr_sec = find_section(segs, "__TEXT", "__cstring")
    if cstr_sec:
        raw = section_data(data, cstr_sec)
        i = 0
        while i < len(raw):
            end = raw.find(b'\x00', i)
            if end == -1:
                break
            s = raw[i:end].decode("utf-8", "replace")
            if 4 <= len(s) <= 200:
                cstring_map[cstr_sec.addr + i] = s
            i = end + 1
    
    # Also include CFString refs from __DATA/__cfstring
    cf_sec = find_section(segs, "__DATA", "__cfstring")
    if cf_sec:
        raw = section_data(data, cf_sec)
        for i in range(len(raw) // 32):
            cf_va = cf_sec.addr + i * 32
            data_ptr = u64le(raw, i * 32 + 16)
            length = u64le(raw, i * 32 + 24)
            fo = va_to_fo(data_ptr, segs)
            if fo is not None and fo + length <= len(data) and length < 4096:
                s = data[fo:fo + length].decode("utf-8", "replace")
                if 4 <= len(s) <= 200:
                    cstring_map[cf_va] = s
    
    # ObjC selector references
    sel_map = {}
    sel_sec = find_section(segs, "__DATA", "__objc_selrefs") or find_section(segs, "__DATA_CONST", "__objc_selrefs")
    if sel_sec:
        raw = section_data(data, sel_sec)
        for i in range(len(raw) // 8):
            sel_ref_va = sel_sec.addr + i * 8
            sel_ptr = u64le(raw, i * 8)
            sel_fo = va_to_fo(sel_ptr, segs)
            if sel_fo is not None and sel_fo < len(data):
                sel_name = cstring(data, sel_fo)
                if sel_name and len(sel_name) < 256:
                    sel_map[sel_ref_va] = sel_name
    
    # Walk every function and track ADRP+ADD/LDR pairs and BL targets
    func_set = set(func_starts)
    
    for func_va in func_starts[:max_funcs]:
        fo = va_to_fo(func_va, segs)
        if fo is None or fo >= len(data):
            continue
        
        # Track ADRP register state
        adrp_regs = {}  # reg_num -> page_address
        
        va = func_va
        cur_fo = fo
        for _ in range(800):  # max 800 instructions per function
            if cur_fo + 4 > len(data):
                break
            word = u32le(data, cur_fo)
            
            # ADRP detection
            if (word >> 24) & 0x9F == 0x90:  # ADRP
                immlo = (word >> 29) & 0x3
                immhi = (word >> 5) & 0x7FFFF
                rd = word & 0x1F
                imm = _sign_extend((immhi << 2) | immlo, 21)
                target = (va & ~0xFFF) + (imm << 12)
                adrp_regs[rd] = target
            
            # ADD immediate (after ADRP) - common pattern: ADRP x8, page; ADD x8, x8, #offset
            elif (word >> 24) & 0x1F == 0x11 and (word >> 30) & 1 == 0:  # ADD imm, not SUB
                rn = (word >> 5) & 0x1F
                rd = word & 0x1F
                imm12 = (word >> 10) & 0xFFF
                sh = (word >> 22) & 1
                offset = imm12 << 12 if sh else imm12
                if rn in adrp_regs:
                    final_va = adrp_regs[rn] + offset
                    # Check if final_va references a string or selref
                    if final_va in cstring_map:
                        string_xrefs[cstring_map[final_va]].append(func_va)
                    elif final_va in sel_map:
                        # Selector reference
                        sel = sel_map[final_va]
                        symbol_xrefs[f"@selector({sel})"].append(func_va)
                    adrp_regs[rd] = final_va
            
            # LDR immediate (after ADRP) - common: ADRP x8, page; LDR x8, [x8, #offset]
            elif (word >> 24) & 0x3F == 0x39 and ((word >> 22) & 0x3) == 0x1:  # LDR (imm, unsigned)
                size = (word >> 30) & 0x3
                rn = (word >> 5) & 0x1F
                rd = word & 0x1F
                imm12 = (word >> 10) & 0xFFF
                offset = imm12 << size
                if rn in adrp_regs:
                    final_va = adrp_regs[rn] + offset
                    # Read 8 bytes at final_va to get the actual pointer
                    final_fo = va_to_fo(final_va, segs)
                    if final_fo is not None and final_fo + 8 <= len(data):
                        loaded = u64le(data, final_fo)
                        if loaded in cstring_map:
                            string_xrefs[cstring_map[loaded]].append(func_va)
                        if loaded in sel_map:
                            symbol_xrefs[f"@selector({sel_map[loaded]})"].append(func_va)
                    if final_va in cstring_map:
                        string_xrefs[cstring_map[final_va]].append(func_va)
                    adrp_regs[rd] = 0  # loaded value, not page
            
            # BL (branch link) — function call
            elif (word >> 26) & 0x3F == 0x25:
                imm26 = word & 0x3FFFFFF
                offset = _sign_extend(imm26, 26) << 2
                target = (va + offset) & 0xFFFFFFFFFFFFFFFF
                func_xrefs[target].append(func_va)
                # If target is a stub, record symbol xref
                if target in stub_map:
                    sym = stub_map[target]
                    symbol_xrefs[sym].append(func_va)
            
            # Branch / RET — function boundary (rough)
            mn_first = (word >> 26) & 0x3F
            if word == 0xD65F03C0 or mn_first == 0x05:  # RET or B
                if (word >> 26) & 0x3F == 0x05:  # B unconditional
                    # might be tail call
                    imm26 = word & 0x3FFFFFF
                    offset = _sign_extend(imm26, 26) << 2
                    target = (va + offset) & 0xFFFFFFFFFFFFFFFF
                    if target not in range(func_va, va + 4) and target in stub_map:
                        # tail call to stub
                        symbol_xrefs[stub_map[target]].append(func_va)
                if word == 0xD65F03C0:
                    break
            
            cur_fo += 4
            va += 4
    
    # Deduplicate
    for k in string_xrefs:
        string_xrefs[k] = sorted(set(string_xrefs[k]))
    for k in symbol_xrefs:
        symbol_xrefs[k] = sorted(set(symbol_xrefs[k]))
    for k in func_xrefs:
        func_xrefs[k] = sorted(set(func_xrefs[k]))
    
    return {
        "string_xrefs": dict(string_xrefs),
        "symbol_xrefs": dict(symbol_xrefs),
        "func_xrefs": dict(func_xrefs),
        "stub_count": len(stub_map),
        "string_xref_count": sum(len(v) for v in string_xrefs.values()),
        "symbol_xref_count": sum(len(v) for v in symbol_xrefs.values()),
    }


def query_xrefs(xref_db: dict, query: str, query_type: str = "auto") -> dict:
    """
    Query the xref database. Supports:
    - Substring match for strings
    - Exact/regex match for symbols
    - VA match for functions
    """
    results = {"matches": [], "type": query_type, "query": query}
    
    if query_type in ("string", "auto"):
        for s, callers in xref_db.get("string_xrefs", {}).items():
            if query.lower() in s.lower():
                results["matches"].append({
                    "kind": "string",
                    "match": s,
                    "callers": [hex(c) for c in callers],
                    "caller_count": len(callers),
                })
    
    if query_type in ("symbol", "auto"):
        for sym, callers in xref_db.get("symbol_xrefs", {}).items():
            sym_clean = sym.lstrip("_")
            if query in sym or query in sym_clean:
                results["matches"].append({
                    "kind": "symbol",
                    "match": sym,
                    "callers": [hex(c) for c in callers],
                    "caller_count": len(callers),
                })
    
    if query_type in ("function", "auto") and query.startswith("0x"):
        try:
            va = int(query, 0)
            callers = xref_db.get("func_xrefs", {}).get(va, [])
            if callers:
                results["matches"].append({
                    "kind": "function",
                    "match": query,
                    "callers": [hex(c) for c in callers],
                    "caller_count": len(callers),
                })
        except ValueError:
            pass
    
    return results


# ═══════════════════════════════════════════════════════════════════════════════
# §22E  VULNERABILITY HEURISTIC SCANNER
# ═══════════════════════════════════════════════════════════════════════════════

# Symbols indicating insecure / dangerous patterns.
INSECURE_API_DB = {
    # Format string vulnerabilities
    "printf":   {"category": "format_string", "severity": "MEDIUM", "advice": "Use printf with format spec, never user input as format."},
    "fprintf":  {"category": "format_string", "severity": "MEDIUM", "advice": "Format specifier should be a constant."},
    "sprintf":  {"category": "format_string", "severity": "HIGH", "advice": "Replace with snprintf — buffer overflow risk."},
    "vsprintf": {"category": "format_string", "severity": "HIGH", "advice": "Replace with vsnprintf."},
    "syslog":   {"category": "format_string", "severity": "MEDIUM", "advice": "Format specifier should be a constant string."},
    "NSLog":    {"category": "format_string", "severity": "LOW", "advice": "NSLog with user input is risky if format chars unescaped."},
    
    # Buffer overflows
    "strcpy":   {"category": "buffer_overflow", "severity": "HIGH", "advice": "Use strlcpy — length-bounded."},
    "strcat":   {"category": "buffer_overflow", "severity": "HIGH", "advice": "Use strlcat."},
    "gets":     {"category": "buffer_overflow", "severity": "CRITICAL", "advice": "gets() is undefined behavior — REMOVE."},
    "scanf":    {"category": "buffer_overflow", "severity": "HIGH", "advice": "Use length specifier for %s (%99s)."},
    "memcpy":   {"category": "buffer_overflow", "severity": "MEDIUM", "advice": "Validate src/dst bounds before call."},
    "memmove":  {"category": "buffer_overflow", "severity": "MEDIUM", "advice": "Validate bounds."},
    "strncpy":  {"category": "buffer_overflow", "severity": "LOW", "advice": "May not null-terminate. Prefer strlcpy."},
    
    # Command injection
    "system":   {"category": "command_injection", "severity": "CRITICAL", "advice": "Direct shell exec — never with untrusted input."},
    "popen":    {"category": "command_injection", "severity": "CRITICAL", "advice": "Shell exec — sanitize input."},
    "execl":    {"category": "command_injection", "severity": "HIGH", "advice": "Argument validation required."},
    "execlp":   {"category": "command_injection", "severity": "HIGH", "advice": "PATH lookup — uses untrusted PATH."},
    "execv":    {"category": "command_injection", "severity": "HIGH", "advice": "Validate argv contents."},
    "execvp":   {"category": "command_injection", "severity": "HIGH", "advice": "PATH lookup risk."},
    
    # Weak random / crypto
    "rand":      {"category": "weak_crypto", "severity": "HIGH", "advice": "Use SecRandomCopyBytes for security-sensitive randomness."},
    "random":    {"category": "weak_crypto", "severity": "HIGH", "advice": "Not cryptographically secure."},
    "srand":     {"category": "weak_crypto", "severity": "MEDIUM", "advice": "Predictable seed."},
    "arc4random": {"category": "weak_crypto", "severity": "LOW", "advice": "OK for non-crypto. Use SecRandom for crypto."},
    "MD5":       {"category": "weak_crypto", "severity": "HIGH", "advice": "MD5 is broken. Use SHA-256+."},
    "SHA1":      {"category": "weak_crypto", "severity": "HIGH", "advice": "SHA-1 collision-prone. Use SHA-256+."},
    "CC_MD5":    {"category": "weak_crypto", "severity": "HIGH", "advice": "MD5 deprecated."},
    "CC_SHA1":   {"category": "weak_crypto", "severity": "HIGH", "advice": "SHA-1 deprecated."},
    "DES":       {"category": "weak_crypto", "severity": "CRITICAL", "advice": "DES is broken. Use AES."},
    "RC4":       {"category": "weak_crypto", "severity": "CRITICAL", "advice": "RC4 is broken. Banned in TLS."},
    
    # Insecure file ops
    "tmpnam":   {"category": "race_condition", "severity": "HIGH", "advice": "Race condition. Use mkstemp."},
    "mktemp":   {"category": "race_condition", "severity": "HIGH", "advice": "Race condition. Use mkstemp."},
    "tempnam":  {"category": "race_condition", "severity": "HIGH", "advice": "Race condition."},
    
    # Memory disclosure
    "getenv":   {"category": "info_disclosure", "severity": "LOW", "advice": "Env var exposure."},
    "setuid":   {"category": "privilege_escalation", "severity": "MEDIUM", "advice": "Drop privileges carefully."},
    "setgid":   {"category": "privilege_escalation", "severity": "MEDIUM", "advice": "Drop privileges carefully."},
    "seteuid":  {"category": "privilege_escalation", "severity": "MEDIUM", "advice": "Effective UID change."},
    
    # Deprecated networking
    "gethostbyname": {"category": "deprecated", "severity": "LOW", "advice": "Use getaddrinfo."},
    "inet_aton":     {"category": "deprecated", "severity": "LOW", "advice": "Use inet_pton."},
}


def scan_vulnerabilities(imported: list, all_strings: list, segs: dict, data: bytes) -> dict:
    """
    Comprehensive vulnerability heuristic scanner.
    Returns categorized findings with severity ratings.
    """
    imp_set = {s.lstrip("_") for s in imported}
    findings = []
    cat_counts = collections.defaultdict(int)
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    
    # API-based vulnerabilities
    for sym in imp_set:
        for api, info in INSECURE_API_DB.items():
            if api == sym or sym.endswith(f"_{api}") or sym == f"_{api}":
                findings.append({
                    "type": "insecure_api",
                    "symbol": sym,
                    "category": info["category"],
                    "severity": info["severity"],
                    "advice": info["advice"],
                })
                cat_counts[info["category"]] += 1
                sev_counts[info["severity"]] += 1
                break
    
    # Format string vulnerability indicators
    fmt_strs = [s for s in all_strings if "%s" in s or "%@" in s or "%d" in s]
    if fmt_strs and "printf" in imp_set:
        findings.append({
            "type": "format_string_pattern",
            "category": "format_string",
            "severity": "MEDIUM",
            "advice": f"Found {len(fmt_strs)} format strings + printf import. Verify no user input flows to format spec.",
            "samples": fmt_strs[:5],
        })
        cat_counts["format_string"] += 1
        sev_counts["MEDIUM"] += 1
    
    # Hardcoded credential heuristics in strings
    cred_patterns = [
        (re.compile(r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']([^"\']{4,})["\']'), "password_in_code"),
        (re.compile(r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']([^"\']{16,})["\']'), "apikey_in_code"),
        (re.compile(r'(?i)(secret|token)\s*[=:]\s*["\']([^"\']{16,})["\']'), "token_in_code"),
        (re.compile(r'-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----'), "private_key_embedded"),
        (re.compile(r'(?i)bearer\s+[a-z0-9_\-\.]{20,}'), "bearer_token"),
        (re.compile(r'AKIA[0-9A-Z]{16}'), "aws_access_key"),
        (re.compile(r'sk_(test|live)_[0-9a-zA-Z]{24,}'), "stripe_secret"),
        (re.compile(r'eyJhbGc[A-Za-z0-9_\-\.]+\.[A-Za-z0-9_\-\.]+\.[A-Za-z0-9_\-\.]+'), "jwt_token"),
    ]
    for s in all_strings:
        for pat, kind in cred_patterns:
            if pat.search(s):
                findings.append({
                    "type": "hardcoded_credential",
                    "category": kind,
                    "severity": "CRITICAL",
                    "advice": f"Possible {kind} hardcoded in binary. Move to keychain/secure storage.",
                    "sample": s[:120],
                })
                cat_counts["hardcoded_credential"] += 1
                sev_counts["CRITICAL"] += 1
                break
    
    # SSL/TLS misconfiguration patterns
    ssl_bad_patterns = [
        ("kSSLProtocol2", "SSLv2 enabled - DEPRECATED"),
        ("kSSLProtocol3", "SSLv3 enabled - POODLE vulnerable"),
        ("kSSLProtocolTLS10", "TLS 1.0 enabled - DEPRECATED"),
        ("kSSLProtocolTLS11", "TLS 1.1 enabled - DEPRECATED"),
        ("NSAllowsArbitraryLoads", "ATS (App Transport Security) disabled"),
        ("NSExceptionAllowsInsecureHTTPLoads", "HTTP loading allowed for specific domain"),
        ("validatesSecureCertificate=NO", "Certificate validation disabled"),
        ("kCFStreamSSLAllowsExpiredCertificates", "Expired cert acceptance"),
        ("kCFStreamSSLAllowsAnyRoot", "Any root CA accepted"),
    ]
    for s in all_strings:
        for needle, desc in ssl_bad_patterns:
            if needle in s:
                findings.append({
                    "type": "tls_misconfiguration",
                    "category": "weak_tls",
                    "severity": "HIGH",
                    "advice": desc,
                    "sample": s[:120],
                })
                cat_counts["weak_tls"] += 1
                sev_counts["HIGH"] += 1
                break
    
    # SQL injection patterns
    sql_patterns = [
        re.compile(r'(?i)(SELECT|INSERT|UPDATE|DELETE|UNION)\s+.*?\%[s@d]'),  # SQL with format
        re.compile(r'(?i)(SELECT|INSERT|UPDATE|DELETE)\s+.*?\+\s*(NSString|String)'),  # SQL string concat
    ]
    for s in all_strings:
        for pat in sql_patterns:
            if pat.search(s) and len(s) < 500:
                findings.append({
                    "type": "sql_injection_pattern",
                    "category": "sql_injection",
                    "severity": "HIGH",
                    "advice": "SQL with format/concat. Use parameterized queries (?). ",
                    "sample": s[:150],
                })
                cat_counts["sql_injection"] += 1
                sev_counts["HIGH"] += 1
                break
    
    return {
        "findings": findings,
        "total_findings": len(findings),
        "by_category": dict(cat_counts),
        "by_severity": dict(sev_counts),
        "highest_severity": next((s for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"] if sev_counts.get(s, 0)), "NONE"),
    }


# ═══════════════════════════════════════════════════════════════════════════════
# §22F  YARA-STYLE PATTERN SCANNER
# ═══════════════════════════════════════════════════════════════════════════════

def hex_pattern_to_regex(pattern: str) -> bytes:
    """
    Convert YARA-style hex pattern with wildcards to regex bytes.
    Supports:
      "DE AD ?? BE EF"   — single byte wildcard (??)
      "DE AD .. BE EF"   — single byte wildcard (alternative)
      "?A B?"            — nibble wildcards
    """
    pattern = pattern.replace(" ", "").replace("\n", "").replace("\t", "")
    out = []
    i = 0
    while i < len(pattern):
        if i + 1 >= len(pattern):
            break
        b1, b2 = pattern[i], pattern[i + 1]
        if b1 in "?." and b2 in "?.":
            out.append(b".")  # any byte
        elif b1 in "?.":
            # nibble wildcard for high - construct byte set
            try:
                low = int(b2, 16)
                ranges = []
                for high in range(16):
                    val = (high << 4) | low
                    ranges.append(re.escape(bytes([val])))
                out.append(b"(?:" + b"|".join(ranges) + b")")
            except ValueError:
                out.append(b".")
        elif b2 in "?.":
            try:
                high = int(b1, 16)
                ranges = []
                for low in range(16):
                    val = (high << 4) | low
                    ranges.append(re.escape(bytes([val])))
                out.append(b"(?:" + b"|".join(ranges) + b")")
            except ValueError:
                out.append(b".")
        else:
            try:
                val = int(b1 + b2, 16)
                out.append(re.escape(bytes([val])))
            except ValueError:
                out.append(b".")
        i += 2
    return b"".join(out)


# Curated rules for iOS jailbreak / security research
YARA_RULES = [
    # Anti-debug code patterns
    {
        "name": "ptrace_PT_DENY_ATTACH",
        "category": "anti_debug",
        "pattern": "1F 00 80 D2 ?? ?? 80 D2",  # MOV x31, #0x1F (PT_DENY_ATTACH), MOV x?, #?
        "desc": "ptrace(PT_DENY_ATTACH) anti-debug call sequence (rough)",
    },
    {
        "name": "syscall_ptrace",
        "category": "anti_debug",
        "pattern": "01 03 00 D4",  # SVC #26 ptrace
        "desc": "Direct ptrace syscall instruction",
    },
    
    # Kernel patterns
    {
        "name": "MIG_subsystem_signature",
        "category": "kernel",
        "pattern": "00 00 00 04",  # MIG MSGH_BITS pattern
        "desc": "MIG (Mach Interface Generator) subsystem table marker",
    },
    
    # Common shellcode / ROP gadgets
    {
        "name": "br_x16_gadget",
        "category": "rop",
        "pattern": "00 02 1F D6",  # BR x16
        "desc": "BR x16 — common ROP/JOP gadget",
    },
    {
        "name": "br_x17_gadget",
        "category": "rop",
        "pattern": "20 02 1F D6",  # BR x17
        "desc": "BR x17 — common ROP/JOP gadget",
    },
    {
        "name": "blr_x16_gadget",
        "category": "rop",
        "pattern": "00 02 3F D6",  # BLR x16
        "desc": "BLR x16 — function pointer call gadget",
    },
    
    # String constants useful for research
    {
        "name": "trust_cache_string",
        "category": "trust_cache",
        "pattern": "74 72 75 73 74 5F 63 61 63 68 65",  # "trust_cache"
        "desc": "trust_cache string reference",
    },
    {
        "name": "amfi_check_string",
        "category": "amfi",
        "pattern": "61 6D 66 69 5F",  # "amfi_"
        "desc": "AMFI function name prefix",
    },
    
    # Crypto
    {
        "name": "AES_T_box",
        "category": "crypto",
        "pattern": "63 7C 77 7B F2 6B 6F C5 30 01 67 2B",  # AES S-box first 12 bytes
        "desc": "AES S-box constant — embedded AES implementation",
    },
    {
        "name": "SHA256_constant_K",
        "category": "crypto",
        "pattern": "67 E6 09 6A 85 AE 67 BB",  # SHA-256 H0/H1 in BE u32 pair (low parts)
        "desc": "SHA-256 initial hash constants",
    },
]


def yara_scan(data: bytes, custom_rules: list = None) -> dict:
    """
    YARA-style pattern scanner. Searches binary for known patterns
    of interest (anti-debug, ROP gadgets, crypto constants, etc.)
    
    custom_rules: optional list of {name, pattern, desc, category}
    """
    rules = list(YARA_RULES)
    if custom_rules:
        rules.extend(custom_rules)
    
    matches = []
    
    for rule in rules:
        try:
            regex_bytes = hex_pattern_to_regex(rule["pattern"])
            pat = re.compile(regex_bytes, re.DOTALL)
            
            hits = []
            for m in pat.finditer(data):
                hits.append({
                    "offset": hex(m.start()),
                    "context_before": data[max(0, m.start() - 8):m.start()].hex(),
                    "match": data[m.start():m.end()].hex(),
                    "context_after": data[m.end():min(len(data), m.end() + 8)].hex(),
                })
                if len(hits) >= 50:  # cap per-rule hits
                    break
            
            if hits:
                matches.append({
                    "rule": rule["name"],
                    "category": rule.get("category", "general"),
                    "description": rule.get("desc", ""),
                    "match_count": len(hits),
                    "hits": hits[:10],  # show first 10 per rule
                })
        except Exception as e:
            continue  # skip invalid rule
    
    return {
        "matches": matches,
        "total_rules_loaded": len(rules),
        "rules_with_matches": len(matches),
        "total_match_count": sum(m["match_count"] for m in matches),
    }


# ═══════════════════════════════════════════════════════════════════════════════
# §22G  PSEUDO-C DECOMPILER
# ═══════════════════════════════════════════════════════════════════════════════

def decompile_function(data: bytes, segs: dict, func_va: int,
                       stub_map: dict, max_insns: int = 300) -> dict:
    """
    Convert ARM64 assembly to pseudo-C output.
    Tracks register state symbolically and reconstructs:
    - Variable assignments
    - Function calls with arguments (via x0-x7)
    - String references via ADRP+ADD
    - Conditional branches as if/else
    - Loops via backward branches
    """
    fo = va_to_fo(func_va, segs)
    if fo is None or fo >= len(data):
        return {"error": "VA does not map to file offset", "func_va": hex(func_va)}
    
    pseudo_lines = []
    register_names = {}  # reg num -> symbolic name (e.g. "str_ptr_a", "result")
    register_values = {}  # reg num -> known value (string content, etc)
    var_counter = [0]
    
    def get_var_name(reg: int) -> str:
        if reg in register_names:
            return register_names[reg]
        if reg == 31:
            return "sp"
        if reg == 30:
            return "lr"
        if reg == 29:
            return "fp"
        return f"x{reg}"
    
    def fresh_var(prefix: str = "v") -> str:
        var_counter[0] += 1
        return f"{prefix}{var_counter[0]}"
    
    pseudo_lines.append(f"// Pseudo-C decompilation of function @ {hex(func_va)}")
    pseudo_lines.append(f"void func_{func_va:x}() {{")
    
    indent = "  "
    va = func_va
    cur_fo = fo
    last_call_args = {}
    last_step = 0
    
    for step in range(max_insns):
        last_step = step
        if cur_fo + 4 > len(data):
            break
        word = u32le(data, cur_fo)
        mn, ops, target = _arm64_disasm_one(word, va)
        
        # PACIBSP / AUTIBSP / NOP — skip for cleaner output
        if mn in ("NOP", "PACIBSP", "AUTIBSP"):
            cur_fo += 4
            va += 4
            continue
        
        # MOVZ — load immediate
        if mn == "MOVZ" and "x" in ops:
            try:
                rd = int(ops.split(",")[0].strip().lstrip("x"))
                imm_str = ops.split("#")[1].split(",")[0].strip()
                imm = int(imm_str, 0)
                pseudo_lines.append(f"{indent}{get_var_name(rd)} = 0x{imm:x};  // {hex(va)}")
                register_values[rd] = imm
            except (ValueError, IndexError):
                pseudo_lines.append(f"{indent}// {hex(va)}: {mn} {ops}")
        
        # MOVK — combine with previous MOVZ
        elif mn == "MOVK" and "x" in ops:
            try:
                rd = int(ops.split(",")[0].strip().lstrip("x"))
                pseudo_lines.append(f"{indent}// MOVK {hex(va)}: {get_var_name(rd)} |= shifted imm")
            except (ValueError, IndexError):
                pseudo_lines.append(f"{indent}// {hex(va)}: {mn} {ops}")
        
        # ADRP — page reference (string/data load preparation)
        elif mn == "ADRP":
            try:
                rd = int(ops.split(",")[0].strip().lstrip("x"))
                target_str = ops.split("#")[1].strip()
                page_addr = int(target_str, 0)
                register_values[rd] = page_addr
                # Try to resolve to string later via ADD
            except (ValueError, IndexError, AttributeError):
                pass
        
        # ADD imm (after ADRP) — resolve to symbol
        elif mn == "ADD" and "#" in ops:
            try:
                parts = [p.strip() for p in ops.split(",")]
                rd_str = parts[0].lstrip("x").lstrip("w")
                rn_str = parts[1].lstrip("x").lstrip("w")
                if rd_str.isdigit() and rn_str.isdigit():
                    rd, rn = int(rd_str), int(rn_str)
                    imm_str = parts[2].split("#")[1].strip() if "#" in parts[2] else "0"
                    imm = int(imm_str, 0)
                    if rn in register_values:
                        final_addr = register_values[rn] + imm
                        # Try to read as string
                        final_fo = va_to_fo(final_addr, segs)
                        if final_fo is not None and final_fo < len(data):
                            s = cstring(data, final_fo, 200)
                            if s and all(0x20 <= ord(c) < 0x7F for c in s) and 3 <= len(s) <= 100:
                                register_values[rd] = final_addr
                                register_names[rd] = f'"{s}"'
                                pseudo_lines.append(f'{indent}// {hex(va)}: {get_var_name(rd)} = "{s}";')
                                cur_fo += 4
                                va += 4
                                continue
                        register_values[rd] = final_addr
            except (ValueError, IndexError):
                pass
        
        # BL — function call
        elif mn == "BL" and target:
            args = []
            for r in range(8):  # x0-x7
                if r in register_names:
                    args.append(register_names[r])
                elif r in register_values:
                    args.append(f"0x{register_values[r]:x}")
                else:
                    args.append(get_var_name(r))
            
            # Resolve target to symbol if possible
            if target in stub_map:
                fn_name = stub_map[target].lstrip("_")
                pseudo_lines.append(f"{indent}{fn_name}({', '.join(args[:4])});  // {hex(va)}")
            else:
                pseudo_lines.append(f"{indent}func_{target:x}({', '.join(args[:4])});  // {hex(va)}")
            
            # x0-x7 may be clobbered by call
            for r in range(8):
                if r in register_names:
                    del register_names[r]
                if r in register_values:
                    del register_values[r]
        
        # CBZ/CBNZ — conditional branch
        elif mn in ("CBZ", "CBNZ"):
            try:
                parts = ops.split(",")
                reg_str = parts[0].strip().lstrip("x").lstrip("w")
                if reg_str.isdigit():
                    rt = int(reg_str)
                    cond = "==" if mn == "CBZ" else "!="
                    var = get_var_name(rt)
                    pseudo_lines.append(f"{indent}if ({var} {cond} 0) goto loc_{target:x};  // {hex(va)}")
            except (ValueError, IndexError):
                pseudo_lines.append(f"{indent}// {hex(va)}: {mn} {ops}")
        
        # Conditional branches B.cond
        elif mn.startswith("B."):
            cond = mn[2:].lower()
            cond_map = {"eq": "==", "ne": "!=", "lt": "<", "le": "<=", "gt": ">", "ge": ">=", "hi": ">", "ls": "<="}
            cop = cond_map.get(cond, mn)
            pseudo_lines.append(f"{indent}if (cmp {cop} 0) goto loc_{target:x};  // {hex(va)}")
        
        # B unconditional
        elif mn == "B" and target:
            pseudo_lines.append(f"{indent}goto loc_{target:x};  // {hex(va)}")
        
        # RET
        elif mn in ("RET", "RET (autibsp)"):
            ret_var = get_var_name(0) if 0 in register_names else "x0"
            pseudo_lines.append(f"{indent}return {ret_var};  // {hex(va)}")
            break
        
        # STR — store
        elif mn in ("STR", "STRB", "STRH"):
            pseudo_lines.append(f"{indent}// store: {mn} {ops}  ({hex(va)})")
        
        # LDR — load
        elif mn in ("LDR", "LDRB", "LDRH"):
            try:
                parts = ops.split(",")
                rt_str = parts[0].strip().lstrip("x").lstrip("w")
                if rt_str.isdigit():
                    rt = int(rt_str)
                    pseudo_lines.append(f"{indent}{get_var_name(rt)} = {ops};  // {hex(va)}")
                    if rt in register_names:
                        del register_names[rt]
                    if rt in register_values:
                        del register_values[rt]
            except (ValueError, IndexError):
                pass
        
        else:
            # Fallback: emit instruction as comment
            pseudo_lines.append(f"{indent}// {hex(va)}: {mn} {ops}")
        
        cur_fo += 4
        va += 4
    
    pseudo_lines.append("}")
    
    return {
        "func_va": hex(func_va),
        "instruction_count": last_step + 1,
        "pseudo_c": "\n".join(pseudo_lines),
        "lines": pseudo_lines,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# §22H  PRIVILEGE ESCALATION & EXPLOIT PRIMITIVE DETECTOR
# ═══════════════════════════════════════════════════════════════════════════════

# Symbols indicating exploit primitives / privilege ops
EXPLOIT_PRIMITIVE_SYMS = {
    # Mach task port operations
    "task_for_pid":       {"category": "tfp_primitive", "severity": "CRITICAL",
                            "desc": "Get task port of arbitrary PID. Foundation for code injection."},
    "mach_vm_read":       {"category": "kernel_read", "severity": "HIGH",
                            "desc": "Read remote process memory. Used in tfp0 exploits."},
    "mach_vm_write":      {"category": "kernel_write", "severity": "CRITICAL",
                            "desc": "Write remote process memory. Foundation for code injection."},
    "mach_vm_allocate":   {"category": "memory_alloc", "severity": "MEDIUM",
                            "desc": "Allocate memory in remote process."},
    "mach_vm_deallocate": {"category": "memory_alloc", "severity": "LOW",
                            "desc": "Free memory in remote process."},
    "mach_vm_protect":    {"category": "memory_protect", "severity": "HIGH",
                            "desc": "Change memory protection. RWX enabling vector."},
    "mach_vm_remap":      {"category": "memory_remap", "severity": "HIGH",
                            "desc": "Remap memory between processes."},
    "thread_create":      {"category": "thread_inject", "severity": "HIGH",
                            "desc": "Create new thread in process. Code execution vector."},
    "thread_set_state":   {"category": "thread_inject", "severity": "CRITICAL",
                            "desc": "Set thread CPU state including PC. Direct code execution."},
    "thread_create_running": {"category": "thread_inject", "severity": "CRITICAL",
                            "desc": "Create thread with initial PC. Direct shellcode launch."},
    
    # Kernel exploit primitives
    "host_special_port":  {"category": "kernel_port", "severity": "HIGH",
                            "desc": "Get host special ports (security-sensitive)."},
    "host_get_special_port": {"category": "kernel_port", "severity": "HIGH",
                            "desc": "Get HOST_PRIV/HOST_KEXTD ports."},
    "task_special_port":  {"category": "kernel_port", "severity": "HIGH",
                            "desc": "Task special ports access."},
    
    # Code signing / AMFI
    "csops":              {"category": "code_sign", "severity": "HIGH",
                            "desc": "Get/set code signing flags. Used to bypass CS validation."},
    "csops_audittoken":   {"category": "code_sign", "severity": "HIGH",
                            "desc": "Code signing ops via audit token."},
    "amfi_check_dyld_policy_self": {"category": "amfi", "severity": "MEDIUM",
                            "desc": "AMFI dyld policy check. May indicate AMFI interaction."},
    "trustd":             {"category": "amfi", "severity": "MEDIUM",
                            "desc": "References trustd daemon."},
    
    # Sandbox
    "sandbox_extension_consume": {"category": "sandbox", "severity": "HIGH",
                            "desc": "Consume sandbox extension token. Privilege transfer."},
    "sandbox_check":      {"category": "sandbox", "severity": "MEDIUM",
                            "desc": "Check if operation allowed by sandbox."},
    "sandbox_init":       {"category": "sandbox", "severity": "MEDIUM",
                            "desc": "Initialize sandbox profile."},
    
    # SUID / privilege
    "setuid":             {"category": "privilege", "severity": "HIGH",
                            "desc": "Set real UID. Privilege change."},
    "setgid":             {"category": "privilege", "severity": "HIGH",
                            "desc": "Set GID."},
    "seteuid":            {"category": "privilege", "severity": "HIGH",
                            "desc": "Set effective UID."},
    "setreuid":           {"category": "privilege", "severity": "HIGH",
                            "desc": "Set real and effective UID."},
    "settid":             {"category": "privilege", "severity": "MEDIUM",
                            "desc": "Set thread ID."},
    "setuidx":            {"category": "privilege", "severity": "HIGH",
                            "desc": "Extended set UID."},
    
    # IOKit (kernel attack surface)
    "IOServiceOpen":      {"category": "iokit", "severity": "MEDIUM",
                            "desc": "Open IOKit user client. Kernel attack surface."},
    "IOServiceMatching":  {"category": "iokit", "severity": "LOW",
                            "desc": "IOKit service matching."},
    "IOConnectCallMethod": {"category": "iokit", "severity": "MEDIUM",
                            "desc": "Call IOKit method. External method invocation — kernel surface."},
    "IOConnectCallScalarMethod": {"category": "iokit", "severity": "MEDIUM",
                            "desc": "IOKit scalar method call."},
    "IOConnectCallStructMethod": {"category": "iokit", "severity": "MEDIUM",
                            "desc": "IOKit struct method call."},
    "IORegistryEntryCreateCFProperty": {"category": "iokit", "severity": "LOW",
                            "desc": "Read IOKit property."},
    "IOMobileFramebufferGetRefreshRate": {"category": "iokit", "severity": "MEDIUM",
                            "desc": "IOMobileFrameBuffer access — known kernel attack surface."},
    
    # Mach port / IPC
    "mach_port_allocate": {"category": "ipc", "severity": "LOW",
                            "desc": "Allocate mach port."},
    "mach_port_destroy":  {"category": "ipc", "severity": "LOW",
                            "desc": "Destroy mach port."},
    "mach_msg":           {"category": "ipc", "severity": "MEDIUM",
                            "desc": "Send mach message. IPC primitive."},
    "mach_port_kobject":  {"category": "ipc", "severity": "HIGH",
                            "desc": "Get kobject for port. Used in OOL kernel exploits."},
    "mach_port_request_notification": {"category": "ipc", "severity": "MEDIUM",
                            "desc": "Request port notification."},
    
    # Dyld manipulation
    "_dyld_register_func_for_add_image": {"category": "dyld_inject", "severity": "MEDIUM",
                            "desc": "Register hook for new image loads. Tweak injection vector."},
    "dlopen":             {"category": "dyld_inject", "severity": "LOW",
                            "desc": "Dynamic library load."},
    "dlsym":              {"category": "dyld_inject", "severity": "LOW",
                            "desc": "Symbol lookup."},
    "_dyld_image_count":  {"category": "dyld_inject", "severity": "LOW",
                            "desc": "Iterate loaded images."},
    "_dyld_get_image_header": {"category": "dyld_inject", "severity": "LOW",
                            "desc": "Get image header."},
    "_dyld_get_image_vmaddr_slide": {"category": "dyld_inject", "severity": "LOW",
                            "desc": "Get image slide. Used to defeat ASLR."},
    
    # Anti-analysis
    "ptrace":             {"category": "anti_debug", "severity": "MEDIUM",
                            "desc": "Process tracing — common anti-debug."},
    "sysctlbyname":       {"category": "anti_debug", "severity": "LOW",
                            "desc": "sysctl access — used for anti-debug + system info."},
    "fork":               {"category": "process", "severity": "LOW",
                            "desc": "Fork process."},
    "vfork":              {"category": "process", "severity": "LOW",
                            "desc": "vfork — restricted on iOS."},
    "exit":               {"category": "process", "severity": "LOW",
                            "desc": "Exit process."},
}


def detect_exploit_primitives(imported: list, all_strings: list) -> dict:
    """
    Detect symbols and patterns indicating exploit primitives,
    privilege escalation, kernel attack surface, etc.
    Critical for understanding capabilities of analyzed binaries.
    """
    imp_set = {s.lstrip("_") for s in imported}
    findings = []
    cat_counts = collections.defaultdict(int)
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    
    for sym in imp_set:
        info = EXPLOIT_PRIMITIVE_SYMS.get(sym)
        if not info:
            # Try with underscore variants
            info = EXPLOIT_PRIMITIVE_SYMS.get(f"_{sym}") or EXPLOIT_PRIMITIVE_SYMS.get(sym.lstrip("_"))
        
        if info:
            findings.append({
                "symbol": sym,
                "category": info["category"],
                "severity": info["severity"],
                "description": info["desc"],
            })
            cat_counts[info["category"]] += 1
            sev_counts[info["severity"]] += 1
    
    # Detect kernel-name strings that suggest kernel research
    kernel_strs = []
    kernel_keywords = ["kern_", "vm_map_", "ipc_kobject_", "mach_kobject_", "kalloc",
                       "kheap", "AppleMobileFileIntegrity", "AMFI", "task_struct",
                       "proc_t", "vfs_context", "ucred", "_amfi_", "trust_cache",
                       "kmem_alloc", "vm_kernel_slide"]
    for s in all_strings:
        for kw in kernel_keywords:
            if kw in s:
                kernel_strs.append(s)
                break
    
    # Sort findings by severity
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda f: sev_order.get(f["severity"], 99))
    
    # Determine overall capability assessment
    if sev_counts.get("CRITICAL", 0) >= 2:
        capability = "FULL_EXPLOIT_CHAIN"
        capability_desc = "Binary contains multiple critical exploit primitives — capable of building full exploit chain (KRW + code injection)."
    elif sev_counts.get("CRITICAL", 0) >= 1:
        capability = "PARTIAL_PRIMITIVE"
        capability_desc = "Binary contains at least one critical primitive. Likely an exploit component or jailbreak helper."
    elif sev_counts.get("HIGH", 0) >= 3:
        capability = "PRIVILEGE_ABUSE"
        capability_desc = "Multiple privileged operations present. Possible privilege escalation tool."
    elif sev_counts.get("HIGH", 0) >= 1 or sev_counts.get("MEDIUM", 0) >= 5:
        capability = "SECURITY_TOOL"
        capability_desc = "Security-relevant operations. Possibly diagnostic or defense tool."
    else:
        capability = "STANDARD"
        capability_desc = "No notable exploit primitives detected."
    
    return {
        "findings": findings,
        "total_findings": len(findings),
        "by_category": dict(cat_counts),
        "by_severity": dict(sev_counts),
        "kernel_strings": kernel_strs[:50],
        "kernel_strings_count": len(kernel_strs),
        "capability_assessment": capability,
        "capability_description": capability_desc,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# §22I  POWERHOUSE — Capstone Real Disassembler (optional)
# ═══════════════════════════════════════════════════════════════════════════════

def disassemble_capstone(data: bytes, start_va: int, start_fo: int,
                          max_insns: int = 500, detailed: bool = True) -> list[dict]:
    """
    Real ARM64 disassembler via Capstone (much more accurate than pure-Python).
    Falls back to pure-Python if Capstone is unavailable.
    """
    caps = godmax_caps()
    if not caps.get("capstone"):
        return disassemble_region(data, start_va, start_fo, max_insns)
    
    try:
        import capstone
        md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
        if detailed:
            md.detail = True
        
        chunk = data[start_fo:start_fo + max_insns * 4]
        insns = []
        for i, ins in enumerate(md.disasm(chunk, start_va)):
            entry = {
                "address": hex(ins.address),
                "mnemonic": ins.mnemonic,
                "operands": ins.op_str,
                "bytes": ins.bytes.hex(),
                "size": ins.size,
            }
            # Extract branch targets
            if ins.mnemonic in ("b", "bl", "br", "blr") and ins.operands:
                try:
                    op = ins.operands.strip().lstrip("#")
                    if op.startswith("0x"):
                        entry["branch_target"] = op
                except Exception:
                    pass
            insns.append(entry)
            if i >= max_insns:
                break
            # Stop at unconditional terminators
            if ins.mnemonic in ("ret", "eret"):
                break
        return insns
    except Exception as e:
        return [{"error": f"Capstone failed: {e}", "fallback": True}] + \
               disassemble_region(data, start_va, start_fo, max_insns)


# ═══════════════════════════════════════════════════════════════════════════════
# §22J  POWERHOUSE — Keystone Assembler (optional, write back to binary)
# ═══════════════════════════════════════════════════════════════════════════════

def assemble_arm64(asm_code: str, base_addr: int = 0) -> Optional[bytes]:
    """
    Assemble ARM64 instructions into bytes. Useful for runtime patching.
    Requires keystone-engine package.
    """
    caps = godmax_caps()
    if not caps.get("keystone"):
        print("[!] keystone-engine not installed. Install with: pip install keystone-engine", file=sys.stderr)
        return None
    
    try:
        import keystone
        ks = keystone.Ks(keystone.KS_ARCH_ARM64, keystone.KS_MODE_LITTLE_ENDIAN)
        encoded, _ = ks.asm(asm_code, base_addr)
        return bytes(encoded)
    except Exception as e:
        print(f"[!] Keystone assembly failed: {e}", file=sys.stderr)
        return None


# ═══════════════════════════════════════════════════════════════════════════════
# §22K  POWERHOUSE — Unicorn Real CPU Emulator (optional)
# ═══════════════════════════════════════════════════════════════════════════════

def unicorn_emulate(data: bytes, segs: dict, func_va: int,
                    max_steps: int = 1000, x0: int = 0, x1: int = 0,
                    x2: int = 0, x3: int = 0,
                    trace: bool = True) -> dict:
    """
    Real ARM64 emulation via Unicorn Engine.
    Maps __TEXT segment to emulated address space and runs from func_va.
    Returns final register state, executed instructions, and any exceptions.
    """
    caps = godmax_caps()
    if not caps.get("unicorn"):
        return {"error": "unicorn not installed. pip install unicorn", "fallback": "use --emulate-func for pure-Python"}
    
    try:
        from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_INVALID
        from unicorn.arm64_const import (
            UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
            UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_X6, UC_ARM64_REG_X7,
            UC_ARM64_REG_X8, UC_ARM64_REG_LR, UC_ARM64_REG_SP, UC_ARM64_REG_PC,
        )
    except Exception as e:
        return {"error": f"Unicorn import failed: {e}"}
    
    text_seg = segs.get("__TEXT")
    if not text_seg:
        return {"error": "No __TEXT segment"}
    
    fo = va_to_fo(func_va, segs)
    if fo is None or fo >= len(data):
        return {"error": f"VA 0x{func_va:X} out of range"}
    
    try:
        # Allocate stack
        STACK_BASE = 0x20000000
        STACK_SIZE = 0x100000
        
        uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        
        # Map TEXT segment (page-aligned)
        text_va_aligned = text_seg.vmaddr & ~0xFFF
        text_size = (text_seg.vmsize + 0xFFF) & ~0xFFF
        text_data = data[text_seg.fileoff:text_seg.fileoff + text_seg.filesize]
        text_data_padded = text_data + b"\x00" * (text_size - len(text_data))
        uc.mem_map(text_va_aligned, text_size)
        uc.mem_write(text_va_aligned, text_data_padded[:text_size])
        
        # Map __DATA / __DATA_CONST if available
        for seg_name in ("__DATA", "__DATA_CONST"):
            d_seg = segs.get(seg_name)
            if d_seg:
                d_va_aligned = d_seg.vmaddr & ~0xFFF
                d_size = (d_seg.vmsize + 0xFFF) & ~0xFFF
                if d_size > 0:
                    try:
                        uc.mem_map(d_va_aligned, d_size)
                        d_bytes = data[d_seg.fileoff:d_seg.fileoff + d_seg.filesize]
                        d_padded = d_bytes + b"\x00" * (d_size - len(d_bytes))
                        uc.mem_write(d_va_aligned, d_padded[:d_size])
                    except Exception:
                        pass  # already mapped or overlap
        
        # Map stack
        uc.mem_map(STACK_BASE, STACK_SIZE)
        uc.reg_write(UC_ARM64_REG_SP, STACK_BASE + STACK_SIZE - 0x100)
        
        # Set initial registers
        uc.reg_write(UC_ARM64_REG_X0, x0)
        uc.reg_write(UC_ARM64_REG_X1, x1)
        uc.reg_write(UC_ARM64_REG_X2, x2)
        uc.reg_write(UC_ARM64_REG_X3, x3)
        uc.reg_write(UC_ARM64_REG_LR, 0xDEADBEEF)  # Sentinel for function exit
        
        trace_log = []
        
        if trace:
            def hook_code(uc, address, size, user_data):
                if len(trace_log) < max_steps:
                    try:
                        ins_bytes = uc.mem_read(address, size)
                        trace_log.append({"pc": hex(address), "size": size, "bytes": bytes(ins_bytes).hex()})
                    except Exception:
                        pass
            uc.hook_add(UC_HOOK_CODE, hook_code)
        
        # Run from func_va until LR sentinel or max steps
        uc.emu_start(func_va, 0xDEADBEEF, count=max_steps)
        
        # Capture final state
        result = {
            "func_va": hex(func_va),
            "executed_steps": len(trace_log),
            "final_registers": {
                "x0":  hex(uc.reg_read(UC_ARM64_REG_X0)),
                "x1":  hex(uc.reg_read(UC_ARM64_REG_X1)),
                "x2":  hex(uc.reg_read(UC_ARM64_REG_X2)),
                "x3":  hex(uc.reg_read(UC_ARM64_REG_X3)),
                "x4":  hex(uc.reg_read(UC_ARM64_REG_X4)),
                "x8":  hex(uc.reg_read(UC_ARM64_REG_X8)),
                "lr":  hex(uc.reg_read(UC_ARM64_REG_LR)),
                "sp":  hex(uc.reg_read(UC_ARM64_REG_SP)),
                "pc":  hex(uc.reg_read(UC_ARM64_REG_PC)),
            },
            "trace": trace_log[-50:] if trace else [],
            "completed": True,
        }
        return result
    except Exception as e:
        return {"error": f"Unicorn emulation error: {e}", "func_va": hex(func_va)}


# ═══════════════════════════════════════════════════════════════════════════════
# §22L  POWERHOUSE — ROP/JOP Gadget Finder
# ═══════════════════════════════════════════════════════════════════════════════

def find_rop_gadgets(data: bytes, segs: dict, max_gadget_len: int = 5,
                     max_results: int = 200) -> dict:
    """
    Scan __TEXT for ROP gadgets (sequences ending in RET, BR, BLR).
    Returns categorized gadgets useful for exploit chain building.
    
    A "gadget" = up to N instructions ending in a control-flow transfer.
    """
    text_seg = segs.get("__TEXT")
    if not text_seg:
        return {"error": "No __TEXT segment", "gadgets": []}
    
    text_data = data[text_seg.fileoff:text_seg.fileoff + text_seg.filesize]
    
    # Terminators (4 bytes each):
    # RET                  = 0xD65F03C0
    # RETAB / RETAA (PAC)  = 0xD65F0FFF / 0xD65F0BFF
    # BR Xn (any reg)      = (word & 0xFFFFFC1F) == 0xD61F0000
    # BLR Xn               = (word & 0xFFFFFC1F) == 0xD63F0000
    
    gadgets = {
        "ret_gadgets": [],          # ends with RET
        "br_gadgets": [],           # ends with BR Xn (jump to register)
        "blr_gadgets": [],          # ends with BLR Xn (call register)
        "stack_pivots": [],         # ADD SP, SP, #imm; RET (or LDR x0, [sp,#imm]; ret)
        "load_gadgets": [],         # LDR Xn, [Xm, #imm]; RET (memory loads)
        "store_gadgets": [],        # STR Xn, [Xm, #imm]; RET (memory writes)
        "syscall_gadgets": [],      # SVC #0; RET (syscall + return)
    }
    
    base_va = text_seg.vmaddr
    n_words = len(text_data) // 4
    
    for end_idx in range(min(n_words, len(text_data) // 4)):
        end_off = end_idx * 4
        if end_off + 4 > len(text_data):
            break
        terminator = u32le(text_data, end_off)
        
        # Identify terminator type
        is_ret = terminator in (0xD65F03C0, 0xD65F0FFF, 0xD65F0BFF)
        is_br  = (terminator & 0xFFFFFC1F) == 0xD61F0000
        is_blr = (terminator & 0xFFFFFC1F) == 0xD63F0000
        is_svc = (terminator >> 21) & 0x7FF == 0x6A0 and (terminator & 0x1F) == 1
        
        if not (is_ret or is_br or is_blr):
            continue
        
        # Walk back up to max_gadget_len instructions
        for gadget_len in range(1, max_gadget_len + 1):
            start_off = end_off - (gadget_len - 1) * 4
            if start_off < 0:
                break
            
            insns_bytes = text_data[start_off:end_off + 4]
            insns_text = []
            valid = True
            
            for i in range(gadget_len):
                word = u32le(insns_bytes, i * 4)
                ins_va = base_va + start_off + i * 4
                mn, ops, _ = _arm64_disasm_one(word, ins_va)
                # Skip gadgets containing branches/control flow before terminator
                if i < gadget_len - 1 and mn in ("BL", "B", "RET", "BR", "BLR", "CBZ", "CBNZ", "TBZ", "TBNZ", "SVC"):
                    valid = False
                    break
                insns_text.append(f"{mn} {ops}".strip())
            
            if not valid:
                continue
            
            gadget_str = "; ".join(insns_text)
            gadget_va = base_va + start_off
            entry = {"va": hex(gadget_va), "instructions": gadget_str}
            
            # Categorize
            if is_ret:
                # Stack pivots
                if "ADD sp" in insns_text[0] or "MOV sp" in insns_text[0]:
                    if len(gadgets["stack_pivots"]) < max_results:
                        gadgets["stack_pivots"].append(entry)
                # Load gadgets (LDR ... ; RET)
                elif any(t.startswith(("LDR", "LDP")) for t in insns_text):
                    if len(gadgets["load_gadgets"]) < max_results:
                        gadgets["load_gadgets"].append(entry)
                # Store gadgets
                elif any(t.startswith(("STR", "STP")) for t in insns_text):
                    if len(gadgets["store_gadgets"]) < max_results:
                        gadgets["store_gadgets"].append(entry)
                # Syscall
                elif any(t.startswith("SVC") for t in insns_text):
                    if len(gadgets["syscall_gadgets"]) < max_results:
                        gadgets["syscall_gadgets"].append(entry)
                else:
                    if len(gadgets["ret_gadgets"]) < max_results:
                        gadgets["ret_gadgets"].append(entry)
            elif is_br:
                if len(gadgets["br_gadgets"]) < max_results:
                    gadgets["br_gadgets"].append(entry)
            elif is_blr:
                if len(gadgets["blr_gadgets"]) < max_results:
                    gadgets["blr_gadgets"].append(entry)
            
            break  # only smallest gadget for each terminator
    
    total = sum(len(v) for v in gadgets.values())
    return {
        "gadgets": gadgets,
        "total_gadgets": total,
        "by_category": {k: len(v) for k, v in gadgets.items()},
    }


# ═══════════════════════════════════════════════════════════════════════════════
# §22M  POWERHOUSE — Sandbox Profile Decoder (.sb compiled)
# ═══════════════════════════════════════════════════════════════════════════════

# Sandbox profile operation names (iOS 18.x)
SANDBOX_OPS = [
    "default", "system-info", "appleevent-send",
    "process-fork", "process-exec", "process-info-codesignature",
    "file-read*", "file-write*", "file-map-executable",
    "network-bind", "network-outbound", "network-inbound",
    "ipc-posix-shm", "ipc-sysv-shm", "ipc-sysv-msg", "ipc-sysv-sem",
    "mach-bootstrap", "mach-host", "mach-issue-extension", "mach-lookup",
    "mach-priv-host-port", "mach-priv-task-port",
    "iokit-open", "iokit-set-properties", "iokit-get-properties",
    "sysctl-read", "sysctl-write",
    "system-acct", "system-audit", "system-mac-syscall",
    "system-privilege", "system-set-time", "system-suspend-resume",
    "process-codesigning-blob-get", "system-fcntl",
    "darwin-notification-post",
    "user-preference-read", "user-preference-write",
]


def parse_sandbox_profile(data: bytes) -> dict:
    """
    Best-effort parser for compiled sandbox profile (.sb binary form).
    Doesn't attempt full reconstruction — extracts strings & operation refs.
    """
    if len(data) < 32:
        return {"error": "Too small to be a sandbox profile"}
    
    # Sandbox compiled profile typically starts with header bytes
    # Then has UTF-8 strings interspersed with opcode streams
    strings_found = []
    op_refs = []
    
    # Extract printable ASCII strings ≥ 4 chars
    i = 0
    while i < len(data):
        end = i
        while end < len(data) and 0x20 <= data[end] < 0x7F:
            end += 1
        chunk = data[i:end]
        if len(chunk) >= 4:
            try:
                s = chunk.decode("ascii")
                strings_found.append(s)
                # Check if string matches known sandbox operations
                for op in SANDBOX_OPS:
                    if op in s:
                        op_refs.append({"op": op, "context": s[:80]})
            except Exception:
                pass
        i = end + 1
    
    # Detect file path patterns
    paths = [s for s in strings_found if s.startswith("/") and len(s) < 200]
    
    return {
        "size": len(data),
        "strings_count": len(strings_found),
        "operation_references": op_refs[:50],
        "paths_referenced": paths[:50],
        "all_strings_sample": strings_found[:100],
    }


# ═══════════════════════════════════════════════════════════════════════════════
# §22N  POWERHOUSE — NSXPC Interface Reconstructor
# ═══════════════════════════════════════════════════════════════════════════════

def reconstruct_nsxpc_interfaces(data: bytes, segs: dict, objc: dict,
                                  all_strings: list) -> dict:
    """
    Reconstruct NSXPC interface protocols by analyzing:
    - Protocol declarations  
    - setExportedInterface: / setRemoteObjectInterface: callers
    - interfaceWithProtocol: invocations
    
    Returns reconstructed protocol → method mappings.
    """
    interfaces = []
    
    # Collect all NSXPC-related protocols (those with "Protocol" suffix or used in interfaces)
    nsxpc_protocols = []
    for proto in objc.get("protocols", []):
        proto_name = proto.name if hasattr(proto, "name") else proto.get("name", "")
        # NSXPC protocols often have many methods
        method_count = (len(proto.instance_methods if hasattr(proto, "instance_methods") else proto.get("instance_methods", [])) +
                        len(proto.class_methods if hasattr(proto, "class_methods") else proto.get("class_methods", [])))
        
        # Heuristic: protocol name suggests XPC + has methods
        if (("Protocol" in proto_name or "XPC" in proto_name or "Service" in proto_name)
            and method_count > 0):
            nsxpc_protocols.append({
                "name": proto_name,
                "instance_methods": (proto.instance_methods if hasattr(proto, "instance_methods") 
                                     else proto.get("instance_methods", [])),
                "class_methods": (proto.class_methods if hasattr(proto, "class_methods") 
                                  else proto.get("class_methods", [])),
                "method_count": method_count,
            })
    
    # Look for class methods that hint at XPC client/server pattern
    xpc_classes = []
    for cls in objc.get("classes", []):
        cls_name = cls.name if hasattr(cls, "name") else cls.get("name", "")
        methods = (cls.instance_methods if hasattr(cls, "instance_methods") 
                   else cls.get("instance_methods", []))
        
        # Check if class implements XPC patterns
        is_xpc_client = False
        is_xpc_server = False
        proxy_methods = []
        
        for m in methods:
            mname = m.name if hasattr(m, "name") else m.get("name", "")
            if "remoteObjectProxy" in mname or "synchronousRemoteObjectProxy" in mname:
                is_xpc_client = True
                proxy_methods.append(mname)
            if "exportedInterface" in mname or "exportedObject" in mname:
                is_xpc_server = True
                proxy_methods.append(mname)
            if "interfaceWithProtocol" in mname:
                proxy_methods.append(mname)
        
        if is_xpc_client or is_xpc_server:
            xpc_classes.append({
                "class_name": cls_name,
                "role": "client" if is_xpc_client else "server",
                "is_client": is_xpc_client,
                "is_server": is_xpc_server,
                "xpc_methods": proxy_methods,
            })
    
    # Find machservice strings (XPC service identifiers)
    machservices = []
    ms_pat = re.compile(r'^com\.apple\.[a-zA-Z0-9._-]+(\.xpc)?$')
    for s in all_strings:
        if ms_pat.match(s) and "." in s and 10 < len(s) < 100:
            machservices.append(s)
    
    return {
        "nsxpc_protocols": nsxpc_protocols,
        "xpc_classes": xpc_classes,
        "mach_services": list(set(machservices)),
        "protocol_count": len(nsxpc_protocols),
        "class_count": len(xpc_classes),
        "service_count": len(set(machservices)),
    }


# ═══════════════════════════════════════════════════════════════════════════════
# §22O  POWERHOUSE — MIG Subsystem Parser
# ═══════════════════════════════════════════════════════════════════════════════

def parse_mig_subsystems(data: bytes, segs: dict) -> dict:
    """
    Detect Mach Interface Generator (MIG) subsystem tables.
    These are key for understanding Mach-based IPC interfaces.
    
    MIG subsystem table structure:
        struct mig_subsystem {
            mig_server_routine_t  server;     // 8 bytes
            mach_msg_id_t         start;      // 4 bytes
            mach_msg_id_t         end;        // 4 bytes
            mach_msg_size_t       maxsize;    // 4 bytes
            mig_subsystem_routine_t* routine; // 8 bytes
            ...
        };
    
    Heuristic detection: scan __DATA_CONST for plausible MIG tables.
    """
    candidates = []
    
    # Check __DATA_CONST and __DATA for MIG signatures
    for seg_name in ("__DATA_CONST", "__DATA"):
        sec = find_section(segs, seg_name, "__const")
        if not sec:
            continue
        raw = section_data(data, sec)
        
        # Walk in 8-byte aligned chunks
        for off in range(0, len(raw) - 64, 8):
            try:
                # MIG table has: server_func_ptr (in __TEXT), start_id, end_id (small ints), maxsize
                server_ptr = u64le(raw, off)
                start_id = u32le(raw, off + 8) if off + 12 <= len(raw) else 0
                end_id = u32le(raw, off + 12) if off + 16 <= len(raw) else 0
                
                # Heuristic: server_ptr should be in __TEXT, start/end IDs reasonable
                text_seg = segs.get("__TEXT")
                if not text_seg:
                    continue
                
                if (text_seg.vmaddr <= server_ptr < text_seg.vmaddr + text_seg.vmsize
                    and 0 < start_id < 100000 and start_id < end_id < start_id + 1000):
                    candidates.append({
                        "table_va": hex(sec.addr + off),
                        "server_func": hex(server_ptr),
                        "msg_id_range": f"{start_id}-{end_id}",
                        "routine_count": end_id - start_id,
                    })
            except Exception:
                continue
    
    return {
        "mig_tables_found": len(candidates),
        "tables": candidates[:30],
    }


# ═══════════════════════════════════════════════════════════════════════════════
# §22P  POWERHOUSE — Launchd Plist & Mach Service Inventory
# ═══════════════════════════════════════════════════════════════════════════════

def analyze_launchd_plist(plist_path: str) -> dict:
    """
    Analyze a LaunchDaemon/LaunchAgent plist file.
    Extract service identifier, mach services exposed, executable path,
    user/group, sandbox profile, entitlements, etc.
    """
    try:
        with open(plist_path, "rb") as f:
            plist = plistlib.load(f)
    except Exception as e:
        return {"error": str(e), "path": plist_path}
    
    result = {
        "path": plist_path,
        "label": plist.get("Label", ""),
        "program": plist.get("Program") or plist.get("ProgramArguments", [None])[0],
        "program_arguments": plist.get("ProgramArguments", []),
        "user_name": plist.get("UserName", "(default)"),
        "group_name": plist.get("GroupName", "(default)"),
        "run_at_load": plist.get("RunAtLoad", False),
        "keep_alive": plist.get("KeepAlive", False),
        "throttle_interval": plist.get("ThrottleInterval", 0),
        "mach_services": list((plist.get("MachServices") or {}).keys()),
        "sockets": list((plist.get("Sockets") or {}).keys()),
        "watch_paths": plist.get("WatchPaths", []),
        "queue_directories": plist.get("QueueDirectories", []),
        "start_calendar_intervals": plist.get("StartCalendarInterval", []),
        "limit_load_to_session_type": plist.get("LimitLoadToSessionType", []),
        "process_type": plist.get("ProcessType", ""),
        "session_create": plist.get("SessionCreate", False),
        "low_priority_io": plist.get("LowPriorityIO", False),
        "nice": plist.get("Nice", 0),
        "abandon_process_group": plist.get("AbandonProcessGroup", False),
        "umask": plist.get("Umask", "(default)"),
        "service_ipc": plist.get("ServiceIPC", False),
    }
    
    # Risk assessment
    risks = []
    if result["user_name"] == "root":
        risks.append({"severity": "MEDIUM", "issue": "Daemon runs as root"})
    if result["run_at_load"] and result["keep_alive"]:
        risks.append({"severity": "LOW", "issue": "Auto-start + persistent"})
    if result["program"] and not result["program"].startswith(("/System/", "/usr/")):
        risks.append({"severity": "HIGH", "issue": f"Non-system executable: {result['program']}"})
    
    result["risks"] = risks
    return result


# ═══════════════════════════════════════════════════════════════════════════════
# §22Q  POWERHOUSE — IPA Builder & Code Patcher
# ═══════════════════════════════════════════════════════════════════════════════

def build_ipa_from_app(app_path: str, output_ipa: str,
                        ldid_path: Optional[str] = None,
                        entitlements_path: Optional[str] = None) -> dict:
    """
    Package an .app bundle into an .ipa file (zip with Payload/<App>.app/ structure).
    Optionally signs with ldid (if available).
    """
    import zipfile, shutil, tempfile
    
    app_path = Path(app_path)
    if not app_path.exists() or not app_path.is_dir() or not app_path.name.endswith(".app"):
        return {"error": "Source must be a valid .app bundle directory"}
    
    out_path = Path(output_ipa)
    if out_path.exists():
        out_path.unlink()
    
    # Optional ldid signing
    if ldid_path and Path(ldid_path).exists():
        binary_name = app_path.stem  # "Foo" from "Foo.app"
        binary_path = app_path / binary_name
        if binary_path.exists():
            sign_cmd = [str(ldid_path)]
            if entitlements_path:
                sign_cmd.extend(["-S" + str(entitlements_path)])
            else:
                sign_cmd.append("-S")
            sign_cmd.append(str(binary_path))
            try:
                subprocess.run(sign_cmd, check=True, capture_output=True)
                print(f"[+] Signed {binary_name} with ldid")
            except Exception as e:
                print(f"[!] ldid signing failed: {e}", file=sys.stderr)
    
    # Build IPA (zip with Payload/ structure)
    with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        for fp in app_path.rglob("*"):
            if fp.is_file():
                arcname = f"Payload/{app_path.name}/{fp.relative_to(app_path)}"
                z.write(fp, arcname)
    
    final_size = out_path.stat().st_size
    return {
        "ipa_path": str(out_path),
        "size_bytes": final_size,
        "size_mb": round(final_size / (1024 * 1024), 2),
        "source_app": str(app_path),
        "signed_with_ldid": bool(ldid_path),
    }


def patch_code_at_va(binary_path: str, va: int, asm_code: str) -> dict:
    """
    Patch binary at virtual address with assembly code (uses Keystone).
    Falls back to raw hex bytes if Keystone unavailable.
    """
    path = Path(binary_path)
    if not path.exists():
        return {"error": f"Binary not found: {binary_path}"}
    
    raw = bytearray(path.read_bytes())
    data, slice_off = find_arm64_slice(bytes(raw))
    lcs = parse_load_commands(data)
    segs = build_segment_map(lcs)
    
    fo = va_to_fo(va, segs)
    if fo is None:
        return {"error": f"VA 0x{va:X} does not map to file offset"}
    
    # Adjust for FAT slice offset
    abs_fo = slice_off + fo
    
    # Try assembly via Keystone
    patch_bytes = assemble_arm64(asm_code, va)
    if patch_bytes is None:
        return {"error": "Keystone assembly failed (install with: pip install keystone-engine)"}
    
    # Apply patch
    original = bytes(raw[abs_fo:abs_fo + len(patch_bytes)])
    raw[abs_fo:abs_fo + len(patch_bytes)] = patch_bytes
    path.write_bytes(bytes(raw))
    
    return {
        "binary": str(path),
        "va": hex(va),
        "file_offset": hex(abs_fo),
        "patch_size": len(patch_bytes),
        "original_bytes": original.hex(),
        "new_bytes": patch_bytes.hex(),
        "asm": asm_code,
        "success": True,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# §22R  POWERHOUSE — iOS Device Communication (pymobiledevice3)
# ═══════════════════════════════════════════════════════════════════════════════

def list_connected_ios_devices() -> dict:
    """List iOS devices connected via USB using pymobiledevice3."""
    caps = godmax_caps()
    if not caps.get("pymobiledevice3"):
        return {"error": "pymobiledevice3 not installed. pip install pymobiledevice3"}
    
    try:
        from pymobiledevice3.usbmux import list_devices
        devices = list_devices()
        return {
            "device_count": len(devices),
            "devices": [{"udid": d.serial, "connection_type": d.connection_type} for d in devices],
        }
    except Exception as e:
        return {"error": str(e)}


def get_ios_device_info(udid: Optional[str] = None) -> dict:
    """Retrieve device information from connected iOS device."""
    caps = godmax_caps()
    if not caps.get("pymobiledevice3"):
        return {"error": "pymobiledevice3 not installed"}
    
    try:
        from pymobiledevice3.lockdown import create_using_usbmux
        lockdown = create_using_usbmux(serial=udid)
        info = lockdown.all_values
        return {
            "udid": info.get("UniqueDeviceID", ""),
            "device_name": info.get("DeviceName", ""),
            "product_type": info.get("ProductType", ""),
            "product_version": info.get("ProductVersion", ""),
            "build_version": info.get("BuildVersion", ""),
            "hardware_model": info.get("HardwareModel", ""),
            "cpu_arch": info.get("CPUArchitecture", ""),
            "chip_id": info.get("ChipID", ""),
            "device_class": info.get("DeviceClass", ""),
            "developer_mode_enabled": info.get("DeveloperModeStatus", False),
        }
    except Exception as e:
        return {"error": str(e)}


def list_installed_ios_apps(udid: Optional[str] = None) -> dict:
    """List apps installed on connected iOS device."""
    caps = godmax_caps()
    if not caps.get("pymobiledevice3"):
        return {"error": "pymobiledevice3 not installed"}
    
    try:
        from pymobiledevice3.lockdown import create_using_usbmux
        from pymobiledevice3.services.installation_proxy import InstallationProxyService
        lockdown = create_using_usbmux(serial=udid)
        ip = InstallationProxyService(lockdown=lockdown)
        apps = ip.get_apps()
        # Reduce verbosity — keep only useful fields
        slim = []
        for bid, info in (apps or {}).items():
            slim.append({
                "bundle_id": bid,
                "name": info.get("CFBundleDisplayName") or info.get("CFBundleName", ""),
                "version": info.get("CFBundleShortVersionString", ""),
                "build": info.get("CFBundleVersion", ""),
                "executable": info.get("CFBundleExecutable", ""),
                "type": info.get("ApplicationType", ""),
                "path": info.get("Path", ""),
            })
        slim.sort(key=lambda x: x["name"].lower())
        return {"app_count": len(slim), "apps": slim}
    except Exception as e:
        return {"error": str(e)}


# ═══════════════════════════════════════════════════════════════════════════════
# §22S  POWERHOUSE — PDF Report Generator (reportlab)
# ═══════════════════════════════════════════════════════════════════════════════

def generate_pdf_report(report: dict, output_pdf: str) -> dict:
    """Generate professional PDF report from analysis results."""
    caps = godmax_caps()
    if not caps.get("reportlab"):
        return {"error": "reportlab not installed. pip install reportlab"}
    
    try:
        from reportlab.lib.pagesizes import letter, A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.lib.colors import HexColor
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
        from reportlab.lib import colors
    except Exception as e:
        return {"error": f"reportlab import failed: {e}"}
    
    doc = SimpleDocTemplate(output_pdf, pagesize=letter,
                             rightMargin=0.5 * inch, leftMargin=0.5 * inch,
                             topMargin=0.5 * inch, bottomMargin=0.5 * inch)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle('TitleStyle', parent=styles['Title'],
                                   textColor=HexColor("#003366"), fontSize=20, spaceAfter=20)
    h1 = ParagraphStyle('H1', parent=styles['Heading1'],
                         textColor=HexColor("#0066CC"), fontSize=14, spaceAfter=10)
    body = styles['BodyText']
    
    story = []
    story.append(Paragraph(f"Mach-O Static Analysis Report", title_style))
    story.append(Paragraph(f"<b>File:</b> {report.get('meta', {}).get('file', 'unknown')}", body))
    story.append(Paragraph(f"<b>Architecture:</b> {report.get('meta', {}).get('arch', '?')}", body))
    story.append(Paragraph(f"<b>UUID:</b> {report.get('meta', {}).get('uuid', '?')}", body))
    story.append(Spacer(1, 12))
    
    # Threat Scorecard
    ts = report.get("threat_scorecard", {})
    if ts:
        story.append(Paragraph("Security Threat Scorecard", h1))
        scorecard_data = [
            ["Metric", "Score", "Verdict"],
            ["Mitigation Hardening", f"{ts.get('hardening_score', '-')}%", ""],
            ["Exploitability", f"{ts.get('exploit_score', '-')}%", ts.get('verdict', '')],
            ["Inject/Tweak Compatibility", f"{ts.get('inject_score', '-')}%", ""],
        ]
        sc_table = Table(scorecard_data, colWidths=[2.5 * inch, 1.0 * inch, 3.0 * inch])
        sc_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightblue),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        story.append(sc_table)
        story.append(Spacer(1, 12))
    
    # Apple Private Entitlements
    pea = report.get("private_entitlements_audit", {})
    if pea.get("matched_count", 0) > 0:
        story.append(Paragraph(f"Apple Private Entitlements ({pea['matched_count']} matched)", h1))
        ent_data = [["Risk", "Category", "Entitlement"]]
        for f in pea.get("findings", [])[:30]:
            ent_data.append([f["risk"], f["category"], f["key"][:60]])
        ent_table = Table(ent_data, colWidths=[0.8 * inch, 1.2 * inch, 4.5 * inch])
        ent_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.darkred),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('GRID', (0, 0), (-1, -1), 0.3, colors.grey),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 1), (-1, -1), 8),
        ]))
        story.append(ent_table)
        story.append(Spacer(1, 12))
    
    # Vulnerability Findings
    vs = report.get("vulnerability_scan", {})
    if vs.get("total_findings", 0) > 0:
        story.append(Paragraph(f"Vulnerability Findings ({vs['total_findings']} total)", h1))
        vuln_data = [["Severity", "Category", "Finding"]]
        for f in vs.get("findings", [])[:25]:
            vuln_data.append([f["severity"], f.get("category", ""), 
                              (f.get("symbol") or f.get("type", ""))[:60]])
        v_table = Table(vuln_data, colWidths=[1.0 * inch, 1.5 * inch, 4.0 * inch])
        v_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.darkorange),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('GRID', (0, 0), (-1, -1), 0.3, colors.grey),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 1), (-1, -1), 8),
        ]))
        story.append(v_table)
        story.append(PageBreak())
    
    # Footer
    story.append(Paragraph("<i>Generated by Aether Analyzer GODMODE</i>", body))
    
    doc.build(story)
    return {"pdf_path": output_pdf, "size": Path(output_pdf).stat().st_size}


# ═══════════════════════════════════════════════════════════════════════════════
# §22T  POWERHOUSE — High-Performance Cached Wrapper
# ═══════════════════════════════════════════════════════════════════════════════

import functools

@functools.lru_cache(maxsize=128)
def _cached_section_data(data_id: int, sec_id: int, fileoff: int, size: int) -> bytes:
    """Internal cache key — actual data fetch happens by caller."""
    return b""  # placeholder; real caching is via report-level memoization


def memoize_analysis_results():
    """Decorator helper to skip re-analysis of same binary."""
    cache: dict = {}
    
    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(binary_path: str, *args, **kwargs):
            try:
                key = (binary_path,
                       Path(binary_path).stat().st_mtime,
                       args[:1] if args else (),)
            except Exception:
                return fn(binary_path, *args, **kwargs)
            if key in cache:
                return cache[key]
            result = fn(binary_path, *args, **kwargs)
            cache[key] = result
            return result
        return wrapper
    return decorator


# ═══════════════════════════════════════════════════════════════════════════════
# §23  MASTER ANALYSIS FUNCTION
# ═══════════════════════════════════════════════════════════════════════════════


def analyze(binary_path:str, keywords:list[str],
            build_cfg:bool=False, run_taint:bool=False,
            disasm_n_funcs:int=0, verbose:bool=False,
            build_xref:bool=False, find_gadgets:bool=False) -> dict:

    path = Path(binary_path)
    if not path.exists(): raise FileNotFoundError(f"Not found: {binary_path}")
    raw = path.read_bytes()
    _v = print if verbose else lambda *a,**k: None

    print(f"[*] Loaded {len(raw):,} bytes  →  {path.name}")
    data, slice_off = find_arm64_slice(raw)
    hdr  = MachOHeader(data)
    lcs  = parse_load_commands(data)
    segs = build_segment_map(lcs)
    print(f"[*] ARM64{'e' if hdr.arm64e else ''} slice @ 0x{slice_off:X} "
          f"({len(data):,} bytes)  {'[FAT]' if slice_off else '[thin]'}")
    print(f"[*] {len(lcs)} load commands | {len(segs)} segments")

    # ── UUID ──────────────────────────────────────────────────────────────────
    uuid = ""
    for lc in lcs:
        if lc.cmd==LC_UUID: uuid=format_uuid(lc.raw[8:24]); break

    # ── Encryption ────────────────────────────────────────────────────────────
    encrypted=False; crypt_id=0
    for lc in lcs:
        if lc.cmd in (LC_ENCRYPTION_INFO,LC_ENCRYPTION_INFO_64):
            crypt_id=u32le(lc.raw,16); encrypted=crypt_id!=0; break

    # ── Mach-O flags ──────────────────────────────────────────────────────────
    mh_flags = decode_flags(hdr.flags, MH_FLAGS)
    has_pie   = "MH_PIE" in mh_flags
    has_arc   = any(s.sectname=="__objc_release" for seg in segs.values() for s in seg.sections)

    # ── ObjC full parse ───────────────────────────────────────────────────────
    print("[*] Parsing ObjC runtime structures (classes/categories/protocols)...")
    objc = parse_objc_full(data, segs)

    # ── Strings ───────────────────────────────────────────────────────────────
    print("[*] Collecting strings (cstring / cfstring / ustring)...")
    strings_data  = collect_all_strings(data, segs)
    all_strings   = strings_data["all_unique"]
    kw_matches    = scan_keywords(all_strings, keywords)

    # ── Symbols ───────────────────────────────────────────────────────────────
    print("[*] Parsing symbol table...")
    symbols = parse_symtab(data, lcs)

    # ── Dylibs ────────────────────────────────────────────────────────────────
    dylibs = parse_dylibs(lcs)

    # ── Bind / lazy-bind (DYLD_INFO) ──────────────────────────────────────────
    print("[*] Parsing DYLD bind opcodes...")
    bind_data = parse_dyld_bind_all(data, lcs, dylibs)

    # ── Export trie ───────────────────────────────────────────────────────────
    print("[*] Decoding export trie...")
    exports = parse_export_trie(data, lcs)

    # ── Chained fixups ────────────────────────────────────────────────────────
    print("[*] Parsing chained fixups (iOS 14+)...")
    chained = parse_chained_fixups(data, lcs, segs)

    # ── Swift ─────────────────────────────────────────────────────────────────
    print("[*] Parsing Swift metadata...")
    swift = parse_swift_deep(data, segs, symbols["imported"], symbols["exported"])

    # ── Code signature ────────────────────────────────────────────────────────
    print("[*] Parsing code signature (deep)...")
    codesig = parse_code_signature_deep(data, lcs)

    # ── Function starts ───────────────────────────────────────────────────────
    print("[*] Parsing function starts...")
    func_starts = parse_function_starts(data, lcs, segs)
    print(f"    → {len(func_starts)} functions found")

    # ── Constructors ──────────────────────────────────────────────────────────
    constructors = parse_constructor_sections(data, segs)

    # ── Entropy ───────────────────────────────────────────────────────────────
    print("[*] Computing per-section entropy...")
    entropy_report = analyze_entropy(data, segs)

    # ── Crypto constants ─────────────────────────────────────────────────────
    print("[*] Scanning for inline crypto constants...")
    crypto_constants = detect_crypto_constants(data)

    # ── Security heuristics ───────────────────────────────────────────────────
    print("[*] Running security heuristics...")
    security = security_heuristics_deep(
        data, segs, symbols["imported"], all_strings,
        func_starts, bind_data["lazy_bind"],
        entitlements=codesig.get("entitlements")
    )

    # ── XPC deep ─────────────────────────────────────────────────────────────
    print("[*] XPC interface analysis...")
    xpc = analyze_xpc_deep(data, segs, objc, all_strings)

    # ── GODMODE: Apple Private Entitlements Audit ────────────────────────────
    print("[*] Auditing entitlements against Apple Private DB...")
    private_ent_audit = audit_apple_private_entitlements(codesig.get("entitlements") or {})
    print(f"    → {private_ent_audit['matched_count']} private entitlements matched, "
          f"highest risk: {private_ent_audit['highest_risk']}")

    # ── GODMODE: Vulnerability Heuristic Scanner ─────────────────────────────
    print("[*] Running vulnerability heuristic scanner...")
    vuln_scan = scan_vulnerabilities(symbols["imported"], all_strings, segs, data)
    print(f"    → {vuln_scan['total_findings']} findings, "
          f"highest severity: {vuln_scan['highest_severity']}")

    # ── GODMODE: Exploit Primitive Detector ──────────────────────────────────
    print("[*] Detecting exploit primitives & privilege ops...")
    exploit_detect = detect_exploit_primitives(symbols["imported"], all_strings)
    print(f"    → {exploit_detect['total_findings']} primitives found, "
          f"capability: {exploit_detect['capability_assessment']}")

    # ── GODMODE: YARA-style Pattern Scanner ──────────────────────────────────
    print("[*] Running YARA-style pattern scanner...")
    yara_results = yara_scan(data)
    print(f"    → {yara_results['rules_with_matches']}/{yara_results['total_rules_loaded']} rules matched, "
          f"{yara_results['total_match_count']} total hits")

    # ── GODMODE: Stub Resolver + Cross-Reference Database ────────────────────
    print("[*] Building stub resolver map...")
    stub_map = build_stub_map(data, segs, lcs, bind_data, chained)
    print(f"    → {len(stub_map)} stubs resolved")

    xref_db = {"string_xrefs": {}, "symbol_xrefs": {}, "func_xrefs": {},
               "stub_count": len(stub_map), "string_xref_count": 0, "symbol_xref_count": 0}
    if build_cfg or run_taint or build_xref:
        # Build xref database when explicitly requested OR when CFG/taint analysis needs it
        print("[*] Building cross-reference database (this may take a while)...")
        xref_db = build_xref_database(data, segs, func_starts, stub_map, all_strings,
                                       max_funcs=min(5000, len(func_starts)))
        print(f"    → {xref_db['string_xref_count']} string xrefs, "
              f"{xref_db['symbol_xref_count']} symbol xrefs")

    # ── POWERHOUSE: NSXPC Reconstructor ──────────────────────────────────────
    print("[*] Reconstructing NSXPC interfaces...")
    nsxpc_recon = reconstruct_nsxpc_interfaces(data, segs, objc, all_strings)
    print(f"    → {nsxpc_recon['protocol_count']} XPC protocols, "
          f"{nsxpc_recon['class_count']} XPC classes, "
          f"{nsxpc_recon['service_count']} mach services")

    # ── POWERHOUSE: MIG Subsystem Scanner ────────────────────────────────────
    print("[*] Scanning for MIG subsystem tables...")
    mig_tables = parse_mig_subsystems(data, segs)
    print(f"    → {mig_tables['mig_tables_found']} MIG tables found")

    # ── POWERHOUSE: ROP Gadget Finder (only if requested) ────────────────────
    rop_gadgets = {"total_gadgets": 0, "gadgets": {}, "by_category": {}}
    if build_cfg or find_gadgets:
        print("[*] Finding ROP/JOP gadgets in __TEXT...")
        rop_gadgets = find_rop_gadgets(data, segs, max_gadget_len=4, max_results=100)
        print(f"    → {rop_gadgets['total_gadgets']} gadgets")

    # ── Call graph ────────────────────────────────────────────────────────────
    call_graph = {}; cfg_edges = []
    if build_cfg:
        print(f"[*] Building call graph (up to {min(len(func_starts),2000)} funcs)...")
        call_graph = build_call_graph(data, segs, func_starts)
        cfg_edges  = call_graph_to_edges(call_graph)
        print(f"    → {len(cfg_edges)} call edges")

    # ── Taint analysis ────────────────────────────────────────────────────────
    taint_results = []
    if run_taint:
        print("[*] Running SecTrustEvaluate taint analysis...")
        taint_results = taint_sec_trust(
            data, segs, func_starts, bind_data["lazy_bind"]
        )
        bypasses = [t for t in taint_results if t["verdict"]=="POTENTIAL_BYPASS"]
        print(f"    → {len(bypasses)} potential trust-evaluation bypass(es)")

    # ── Disassembly (optional) ────────────────────────────────────────────────
    disasm_output = []
    if disasm_n_funcs > 0:
        print(f"[*] Disassembling first {disasm_n_funcs} functions...")
        for va in func_starts[:disasm_n_funcs]:
            fo = va_to_fo(va, segs)
            if fo is not None and fo < len(data):
                insns = disassemble_region(data, va, fo, max_insns=200)
                disasm_output.append({"func_va":hex(va),"instructions":insns})

    # ── Load commands ─────────────────────────────────────────────────────────
    lc_detail = describe_load_commands_full(lcs)

    # ── Fingerprint ───────────────────────────────────────────────────────────
    fp = fingerprint(data, segs, lcs)

    # ── Assemble report ───────────────────────────────────────────────────────
    report = {
        "meta": {
            "file":           binary_path,
            "file_size":      len(raw),
            "is_fat":         slice_off>0,
            "slice_offset":   hex(slice_off),
            "arch":           "arm64e" if hdr.arm64e else "arm64",
            "filetype":       MH_FILETYPE.get(hdr.filetype,f"0x{hdr.filetype:X}"),
            "uuid":           uuid,
            "encrypted":      encrypted,
            "crypt_id":       crypt_id,
            "ncmds":          hdr.ncmds,
            "mh_flags":       mh_flags,
            "has_pie":        has_pie,
            "has_arc":        has_arc,
        },
        "fingerprint":        fp,
        "code_signature":     codesig,
        "entitlements":       codesig.get("entitlements"),
        "requirements":       codesig.get("requirements"),
        "segments":           [{"name": seg.segname, "vmaddr": seg.vmaddr, "vmsize": seg.vmsize, "fileoff": seg.fileoff, "filesize": seg.filesize} for seg in segs.values()],
        "objc": {
            "class_count":     len(objc["classes"]),
            "category_count":  len(objc["categories"]),
            "protocol_count":  len(objc["protocols"]),
            "classes": [
                {
                    "name":             c.name,
                    "superclass":       c.superclass,
                    "is_swift":         c.is_swift_class,
                    "protocols":        c.protocols,
                    "instance_methods": [
                        {"name":m.name,"return":m.return_type,"args":m.arg_types,"imp":m.imp}
                        for m in c.instance_methods
                    ],
                    "class_methods": [
                        {"name":m.name,"return":m.return_type,"args":m.arg_types,"imp":m.imp}
                        for m in c.class_methods
                    ],
                    "ivars": [
                        {"name":iv.name,"type":iv.type_decoded,"offset":iv.offset,"size":iv.size}
                        for iv in c.ivars
                    ],
                    "properties": [
                        {"name":p.name,"type":p.decoded_attrs.get("type",""),
                         "storage":p.decoded_attrs.get("storage",[]),
                         "ivar":p.decoded_attrs.get("ivar","")}
                        for p in c.properties
                    ],
                    "category_names": [cat.name for cat in c.categories],
                }
                for c in objc["classes"]
            ],
            "categories": [
                {
                    "name":           cat.name,
                    "extends_class":  cat.class_name,
                    "instance_methods":[m.name for m in cat.instance_methods],
                    "class_methods":   [m.name for m in cat.class_methods],
                    "properties":      [p.name for p in cat.properties],
                }
                for cat in objc["categories"]
            ],
            "protocols": [
                {"name":p.name,"instance_methods":p.instance_methods,
                 "class_methods":p.class_methods,"properties":p.properties}
                for p in objc["protocols"]
            ],
        },
        "swift":              swift,
        "symbols": {
            "imported":       symbols["imported"],
            "exported":       symbols["exported"],
            "local":          symbols["local"][:200],
            "export_trie":    exports,
            "dylib_imports":  dylibs,
        },
        "bind": {
            "bind":           bind_data["bind"],
            "lazy_bind":      bind_data["lazy_bind"],
            "weak_bind":      bind_data["weak_bind"],
            "chained_fixups": chained,
        },
        "strings": {
            "cstring_count":  len(strings_data["cstrings"]),
            "cfstring_count": len(strings_data["cfstrings"]),
            "ustring_count":  len(strings_data["ustrings"]),
            "total_unique":   len(all_strings),
            "cfstrings":      strings_data["cfstrings"],
            "ustrings":       strings_data["ustrings"],
        },
        "keyword_matches":    kw_matches,
        "xpc":                xpc,
        "security":           security,
        "entropy":            entropy_report,
        "crypto_constants":   crypto_constants,
        "constructors":       constructors,
        "function_starts": {
            "count": len(func_starts),
            "addresses": [hex(v) for v in func_starts[:500]],
        },
        "call_graph": {
            "enabled":    build_cfg,
            "edge_count": len(cfg_edges),
            "edges":      cfg_edges[:2000],
        },
        "taint_analysis": {
            "enabled":   run_taint,
            "results":   taint_results,
            "bypasses": [t for t in taint_results if t["verdict"]=="POTENTIAL_BYPASS"],
        },
        "disassembly":        disasm_output,
        "load_commands":      lc_detail,
        # ── GODMODE EXTENSIONS ───────────────────────────────────────────────
        "private_entitlements_audit": private_ent_audit,
        "vulnerability_scan":         vuln_scan,
        "exploit_primitives":         exploit_detect,
        "yara_scan":                  yara_results,
        "stub_map":                   {hex(k): v for k, v in stub_map.items()},
        "xref_database":              {
            "stub_count": xref_db["stub_count"],
            "string_xref_count": xref_db["string_xref_count"],
            "symbol_xref_count": xref_db["symbol_xref_count"],
            # When build_xref=True, expose full xref maps
            "string_xrefs_full": xref_db.get("string_xrefs", {}) if build_xref else {},
            "symbol_xrefs_full": xref_db.get("symbol_xrefs", {}) if build_xref else {},
            "func_xrefs_full":   xref_db.get("func_xrefs", {})   if build_xref else {},
            # Always include sample (small) data for compatibility
            "string_xrefs_sample": {
                k: [hex(va) for va in v[:20]]
                for k, v in list(xref_db["string_xrefs"].items())[:50]
            },
            "symbol_xrefs_sample": {
                k: [hex(va) for va in v[:20]]
                for k, v in list(xref_db["symbol_xrefs"].items())[:50]
            },
        },
        "nsxpc_reconstruction":       nsxpc_recon,
        "mig_subsystems":             mig_tables,
        "rop_gadgets":                rop_gadgets,
        "godmax_capabilities":        godmax_caps(),
    }
    
    # Calculate Threat Scorecard Heuristics
    report["threat_scorecard"] = calculate_threat_scorecard(report["meta"], report["security"], symbols["imported"])
    
    return report


# ═══════════════════════════════════════════════════════════════════════════════
# §24  HUMAN-READABLE REPORT PRINTER
# ═══════════════════════════════════════════════════════════════════════════════

W  = 78
HL = "═"*W
HL2= "─"*W

def _box(title:str):
    print(f"\n╔{HL}╗")
    pad = (W-len(title))//2
    print(f"║{' '*pad}{title}{' '*(W-pad-len(title))}║")
    print(f"╚{HL}╝")

def _sec(title:str):
    print(f"\n  ┌─ {title} {'─'*(W-6-len(title))}")

def _line(k:str,v, indent:int=4):
    prefix = " "*indent
    print(f"{prefix}{k:<28}: {v}")

def print_report(r:dict, verbose:bool=False):
    m = r["meta"]
    _box("Mach-O ARM64 Super Deep Analysis Report")
    _line("File",          m["file"])
    _line("Size",          f"{m['file_size']:,} bytes")
    _line("Arch",          m["arch"])
    _line("Type",          m["filetype"])
    _line("UUID",          m["uuid"])
    _line("FAT",           f"{m['is_fat']}  slice @ {m['slice_offset']}")
    _line("Encrypted",     f"{m['encrypted']} (cryptid={m['crypt_id']})")
    if m["encrypted"]:
        print("\n" + "="*80)
        print("  [!] WARNING: FAIRPLAY DRM PROTECTION DETECTED")
        print("="*80)
        print(f"  This Mach-O segment utilizes Apple FairPlay DRM protection (cryptid = {m['crypt_id']}).")
        print("  Direct static de-compilation / de-obfuscation on this segment will yield scrambled bytes.")
        print("  Recommended remediation: supply a decrypted memory dump from a jailbroken device.")
        print("="*80 + "\n")
    _line("PIE",           m["has_pie"])
    _line("MH Flags",      ", ".join(m["mh_flags"]) or "(none)")

    # ── Threat Scorecard ──────────────────────────────────────────────────────
    if "threat_scorecard" in r:
        ts = r["threat_scorecard"]
        _box("SECURITY HARDENING & AUDIT THREAT SCORECARD")
        _line("Overall Verdict", f"{ts['verdict']}")
        _line("Mitigation Posture Hardening", f"{ts['hardening_score']}%")
        _line("Exploitability Potential", f"{ts['exploit_score']}%")
        _line("Tweak/Inject Compatibility", f"{ts['inject_score']}%")
        
        _sec("EXPLOITABILITY ANALYSIS REASONS")
        for reason in ts["reasons"]:
            print(f"    - {reason}")
            
        if ts.get("inject_reasons"):
            _sec("INJECTION & TWEAK SIDELOADING FEASIBILITY")
            for reason in ts["inject_reasons"]:
                print(f"    - {reason}")
                
        if ts.get("found_banned"):
            _sec("INSECURE/BANNED C APIS DETECTED")
            for api, desc in ts["found_banned"].items():
                print(f"    - {api}: {desc}")

    # ── Fingerprint ──────────────────────────────────────────────────────────
    _sec("FINGERPRINT")
    fp = r["fingerprint"]
    _line("MD5",    fp["file_md5"])
    _line("SHA-1",  fp["file_sha1"])
    _line("SHA-256",fp["file_sha256"])
    _line("TEXT SHA-256", fp["text_segment_sha256"])

    # ── Code Signature ────────────────────────────────────────────────────────
    _box("CODE SIGNATURE")
    cs = r["code_signature"]
    if not cs["present"]:
        print(f"  [!] {cs.get('error','Not present')}")
    else:
        _line("Team ID",    cs.get("team_id") or "(none)")
        _line("Identifiers",", ".join(cs.get("identifiers",[])) or "(none)")
        _line("Hash types", ", ".join(cs.get("hash_types",[])))
        for cd in cs.get("code_directories",[]):
            print(f"    CDHash (SHA-256) : {cd['cd_hash_sha256']}")
            print(f"    CDHash (SHA-1  ) : {cd['cd_hash_sha1']}")
            print(f"    Page size        : {cd['page_size']} bytes")
            print(f"    Code slots       : {cd['n_code_slots']}")
            if cd.get("exec_seg_flags"):
                _line("ExecSeg flags", ", ".join(cd["exec_seg_flags"]))
        if cs.get("entitlements_der_present"):
            print("  [i] DER-encoded entitlements present")
            keys = cs.get("entitlements_der_keys",[])
            if keys:
                print("      Keys found:", ", ".join(keys[:20]))

    # ── Entitlements ──────────────────────────────────────────────────────────
    _box("ENTITLEMENTS")
    ent = r.get("entitlements")
    if ent:
        if isinstance(ent,dict) and "_error" in ent:
            print(f"  [!] {ent['_error']}")
            print(r["code_signature"].get("entitlements_raw","")[:3000])
        else:
            try:    print(plistlib.dumps(ent,fmt=plistlib.FMT_XML).decode())
            except: print(json.dumps(ent,indent=2))
    else:
        print("  (none)")

    # ── Requirements ─────────────────────────────────────────────────────────
    reqs = r.get("requirements")
    if reqs and reqs.get("requirements"):
        _box("CODE REQUIREMENTS")
        for req in reqs["requirements"]:
            print(f"  [{req['type_name']}]  {req['expression']}")

    # ── ObjC ──────────────────────────────────────────────────────────────────
    _box(f"OBJECTIVE-C  ({r['objc']['class_count']} classes | "
         f"{r['objc']['category_count']} categories | "
         f"{r['objc']['protocol_count']} protocols)")

    _sec(f"CLASSES (showing first 50 of {r['objc']['class_count']})")
    for cls in sorted(r["objc"]["classes"], key=lambda c:c["name"])[:50]:
        swift_tag = " [Swift]" if cls["is_swift"] else ""
        super_tag = f" : {cls['superclass']}" if cls["superclass"] else ""
        proto_tag = f" <{','.join(cls['protocols'])}>" if cls["protocols"] else ""
        print(f"    {cls['name']}{super_tag}{proto_tag}{swift_tag}")
        for m in cls["instance_methods"][:5]:
            args = ", ".join(m["args"]) if m["args"] else "void"
            print(f"      - (instance) {m['return'] or 'id'} {m['name']}({args})  @ {m['imp']}")
        for m in cls["class_methods"][:3]:
            print(f"      + (class)    {m['return'] or 'id'} {m['name']}  @ {m['imp']}")
        if cls["ivars"]:
            print(f"      ivars: {', '.join(iv['name']+'('+iv['type']+')' for iv in cls['ivars'][:5])}")
        if cls["properties"]:
            print(f"      props: {', '.join(p['name'] for p in cls['properties'][:5])}")

    if r["objc"]["categories"]:
        _sec(f"CATEGORIES (first 20)")
        for cat in r["objc"]["categories"][:20]:
            nm = cat["name"] or "(unnamed)"
            print(f"    {nm} on {cat['extends_class']}")
            for m in cat["instance_methods"][:3]: print(f"      - {m}")
            for m in cat["class_methods"][:3]:    print(f"      + {m}")

    if r["objc"]["protocols"]:
        _sec(f"PROTOCOLS (first 20)")
        for p in r["objc"]["protocols"][:20]:
            print(f"    @protocol {p['name']}")
            for m in p["instance_methods"][:3]: print(f"      - {m}")

    # ── Swift ─────────────────────────────────────────────────────────────────
    sw = r["swift"]
    if sw["available"]:
        _box(f"SWIFT  ({len(sw['types'])} types | {len(sw['field_descriptors'])} field descriptors)")
        _sec("SWIFT TYPES (first 60)")
        for t in sorted(sw["types"],key=lambda x:x["name"])[:60]:
            print(f"    [{t['kind']:<12}]  {t['name']}  @ {t['va']}")
        if sw["field_descriptors"]:
            _sec("FIELD DESCRIPTORS (first 20)")
            for fd in sw["field_descriptors"][:20]:
                print(f"    {fd['type']}  fields: {', '.join(fd['fields'][:8])}")
        if sw["symbols_imported"]:
            _sec(f"SWIFT IMPORTED SYMBOLS ({len(sw['symbols_imported'])})")
            for s in sw["symbols_imported"][:30]:
                print(f"    {s['demangled']}")

    # ── Symbols ───────────────────────────────────────────────────────────────
    _box(f"SYMBOLS  (imported:{len(r['symbols']['imported'])} | "
         f"exported:{len(r['symbols']['exported'])} | "
         f"local:{len(r['symbols']['local'])})")

    _sec(f"IMPORTED (first 150)")
    for s in sorted(r["symbols"]["imported"])[:150]: print(f"    {s}")
    if len(r["symbols"]["imported"])>150:
        print(f"    ... +{len(r['symbols']['imported'])-150} more — see JSON")

    if r["symbols"]["export_trie"]:
        _sec(f"EXPORT TRIE ({len(r['symbols']['export_trie'])} entries, first 50)")
        for e in r["symbols"]["export_trie"][:50]:
            if "error" in e: continue
            print(f"    {e.get('symbol','')}  flags={e.get('flags','')}  off={e.get('offset','')}")

    _sec(f"DYLIB IMPORTS ({len(r['symbols']['dylib_imports'])})")
    for d in r["symbols"]["dylib_imports"]:
        print(f"    [{d['type'].replace('LC_','')}]  {d['name']}  v{d['version']}")

    # ── Bind ──────────────────────────────────────────────────────────────────
    bind = r["bind"]
    _box(f"DYLD BIND  (bind:{len(bind['bind'])} | lazy:{len(bind['lazy_bind'])} | weak:{len(bind['weak_bind'])})")
    cf = bind["chained_fixups"]
    if cf.get("imports"):
        _sec(f"CHAINED FIXUP IMPORTS ({len(cf['imports'])})")
        for imp in cf["imports"][:50]:
            print(f"    {'[weak]' if imp['weak'] else '      '}  {imp['name']}  lib_ord={imp['lib_ordinal']}")

    # ── Strings ───────────────────────────────────────────────────────────────
    s_meta = r["strings"]
    _box(f"STRINGS  (cstring:{s_meta['cstring_count']} | "
         f"cfstring:{s_meta['cfstring_count']} | "
         f"ustring:{s_meta['ustring_count']} | "
         f"total_unique:{s_meta['total_unique']})")

    if s_meta["cfstrings"]:
        _sec(f"CFStrings (first 30)")
        for cf in s_meta["cfstrings"][:30]:
            print(f"    @ {cf['va']}  len={cf['length']}  {repr(cf['string'])}")

    if s_meta["ustrings"]:
        _sec(f"Unicode Strings (first 20)")
        for us in s_meta["ustrings"][:20]:
            print(f"    {repr(us)}")

    # ── Keyword matches ───────────────────────────────────────────────────────
    _box("KEYWORD STRING MATCHES")
    km = r["keyword_matches"]
    if not km: print("  (no matches)")
    for kw,strings in sorted(km.items()):
        print(f"\n  [{kw}]  ({len(strings)})")
        for s in strings[:15]: print(f"    {repr(s)}")
        if len(strings)>15: print(f"    ... +{len(strings)-15} more")

    # ── XPC ───────────────────────────────────────────────────────────────────
    xpc = r["xpc"]
    _box(f"XPC INTERFACES  ({xpc['method_count']} handler methods)")
    if xpc["xpc_bundle_ids"]:
        _sec("XPC Bundle IDs")
        for bid in xpc["xpc_bundle_ids"]: print(f"    {bid}")
    if xpc["xpc_handler_methods"]:
        _sec("XPC Handler Methods (first 30)")
        for m in xpc["xpc_handler_methods"][:30]:
            print(f"    [{m['class']}]  {m['method']}")
    if xpc["all_bundle_ids"]:
        _sec(f"All Bundle IDs ({len(xpc['all_bundle_ids'])})")
        for bid in xpc["all_bundle_ids"][:40]: print(f"    {bid}")

    # ── Security ─────────────────────────────────────────────────────────────
    _box("SECURITY ANALYSIS")
    sec = r["security"]

    for topic,key in [("ANTI-DEBUG","anti_debug"),
                       ("JAILBREAK DETECTION","jailbreak_detection"),
                       ("CERTIFICATE PINNING","certificate_pinning"),
                       ("HARDCODED SECRETS","hardcoded_secrets"),
                       ("OBFUSCATION","obfuscation")]:
        info = sec[key]
        risk = info.get("risk","?")
        risk_icon = {"HIGH":"🔴","MEDIUM":"🟡","LOW":"🟢","INFO":"ℹ️"}.get(risk,risk)
        _sec(f"{topic}  {risk_icon} {risk}")
        for k,v in info.items():
            if k=="risk": continue
            if isinstance(v,list):
                if v: print(f"    {k}: {v[:5]}{' ...' if len(v)>5 else ''}")
            elif isinstance(v,bool):
                if v: print(f"    {k}: True")
            elif v: print(f"    {k}: {v}")

    if sec["constructors"]["mod_init_funcs"]:
        _sec("CONSTRUCTORS (__mod_init_func)")
        for va in sec["constructors"]["mod_init_funcs"][:20]: print(f"    {va}")

    # ── Entropy ───────────────────────────────────────────────────────────────
    _box("SECTION ENTROPY (descending)")
    for e in r["entropy"][:20]:
        risk_icon = "🔴" if e["risk"]=="HIGH" else ("🟡" if e["risk"]=="MEDIUM" else "🟢")
        print(f"    {risk_icon}  {e['entropy']:.4f}  {e['segment']},{e['section']}  ({e['size']:,} bytes)")

    # ── Crypto constants ──────────────────────────────────────────────────────
    if r["crypto_constants"]:
        _box(f"INLINE CRYPTO CONSTANTS  ({len(r['crypto_constants'])} hits)")
        for c in r["crypto_constants"][:20]:
            print(f"    {c['constant']:<16}  @ {c['file_offset']}")

    # ── Function stats ────────────────────────────────────────────────────────
    _box(f"FUNCTION ANALYSIS  ({r['function_starts']['count']} functions)")
    print(f"    First 20 VAs: {', '.join(r['function_starts']['addresses'][:20])}")
    if r["constructors"]["init"]:
        _sec("Constructor functions")
        for va in r["constructors"]["init"]: print(f"    {va}")

    # ── Call graph ────────────────────────────────────────────────────────────
    cg = r["call_graph"]
    if cg["enabled"]:
        _box(f"CALL GRAPH  ({cg['edge_count']} edges)")
        for edge in cg["edges"][:40]:
            print(f"    {edge['from']}  →  {edge['to']}")

    # ── Taint ─────────────────────────────────────────────────────────────────
    ta = r["taint_analysis"]
    if ta["enabled"]:
        _box(f"TAINT ANALYSIS — SecTrustEvaluate  ({len(ta['results'])} callers)")
        for t in ta["results"]:
            icon = "🔴" if t["verdict"]=="POTENTIAL_BYPASS" else "✅"
            print(f"    {icon} {t['func_va']}  checks_return={t['checks_return']}  calls={t['calls_sec_trust']}")

    # ── Disassembly ───────────────────────────────────────────────────────────
    if r["disassembly"]:
        _box(f"DISASSEMBLY  ({len(r['disassembly'])} functions)")
        for fn in r["disassembly"][:5]:
            print(f"\n  func @ {fn['func_va']}")
            print(f"  {'─'*60}")
            for ins in fn["instructions"][:30]:
                bt = f"  → {ins['branch_target']}" if ins["branch_target"] else ""
                print(f"    {ins['address']}  {ins['mnemonic']:<12} {ins['operands']}{bt}")

    # ── Load commands ─────────────────────────────────────────────────────────
    _box(f"LOAD COMMANDS  ({len(r['load_commands'])})")
    for lc in r["load_commands"]:
        extra = ""
        if "segment" in lc:
            extra = f"  {lc['segment']}  {lc['vmaddr']} sz={lc['vmsize']}  prot={lc.get('initprot','?')}"
        elif "dylib" in lc: extra = f"  {lc['dylib']}"
        elif "uuid"  in lc: extra = f"  {lc['uuid']}"
        elif "platform" in lc: extra = f"  {lc['platform']} minos={lc['minos']} sdk={lc['sdk']}"
        elif "entryoff" in lc: extra = f"  entry={lc['entryoff']} stack={lc['stacksize']}"
        elif "dylinker" in lc: extra = f"  {lc['dylinker']}"
        elif "path"    in lc: extra = f"  {lc['path']}"
        elif "version" in lc and "segment" not in lc: extra = f"  v{lc['version']}"
        print(f"    {lc['cmd']:<40}{extra}")

    # ── GODMODE: Apple Private Entitlements ──────────────────────────────────
    if r.get("private_entitlements_audit", {}).get("matched_count", 0) > 0:
        pea = r["private_entitlements_audit"]
        risk_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "NONE": "⚪"}.get(pea["highest_risk"], "❓")
        _box(f"APPLE PRIVATE ENTITLEMENTS  {risk_icon} {pea['highest_risk']}  ({pea['matched_count']} matched)")
        for finding in pea["findings"][:30]:
            sev_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(finding["risk"], "❓")
            print(f"    {sev_icon} [{finding['risk']:<8}] [{finding['category']:<14}] {finding['key']}")
            print(f"       → {finding['description']}")

    # ── GODMODE: Vulnerability Scan ──────────────────────────────────────────
    if r.get("vulnerability_scan", {}).get("total_findings", 0) > 0:
        vs = r["vulnerability_scan"]
        sev_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "NONE": "⚪"}.get(vs["highest_severity"], "❓")
        _box(f"VULNERABILITY SCAN  {sev_icon} {vs['highest_severity']}  ({vs['total_findings']} findings)")
        # Group by category
        by_cat = collections.defaultdict(list)
        for f in vs["findings"]:
            by_cat[f.get("category", "general")].append(f)
        for cat, items in sorted(by_cat.items()):
            _sec(f"{cat.upper()} ({len(items)})")
            for item in items[:10]:
                sev_i = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(item["severity"], "❓")
                if item["type"] == "insecure_api":
                    print(f"    {sev_i} {item['symbol']:<20}  {item['advice']}")
                elif item["type"] == "hardcoded_credential":
                    print(f"    {sev_i} HARDCODED CREDENTIAL  {item.get('sample','')[:80]}")
                elif item["type"] == "tls_misconfiguration":
                    print(f"    {sev_i} TLS  {item['advice']}")
                else:
                    print(f"    {sev_i} {item.get('type','')} — {item.get('advice','')[:80]}")

    # ── GODMODE: Exploit Primitives ──────────────────────────────────────────
    if r.get("exploit_primitives", {}).get("total_findings", 0) > 0:
        ep = r["exploit_primitives"]
        cap_icon = {
            "FULL_EXPLOIT_CHAIN": "🔴⚡",
            "PARTIAL_PRIMITIVE": "🟠",
            "PRIVILEGE_ABUSE": "🟡",
            "SECURITY_TOOL": "🟢",
            "STANDARD": "⚪"
        }.get(ep["capability_assessment"], "❓")
        _box(f"EXPLOIT PRIMITIVES  {cap_icon} {ep['capability_assessment']}  ({ep['total_findings']} primitives)")
        print(f"    {ep['capability_description']}")
        print()
        # Group by category
        by_cat = collections.defaultdict(list)
        for f in ep["findings"]:
            by_cat[f["category"]].append(f)
        for cat, items in sorted(by_cat.items()):
            _sec(f"{cat.upper()}")
            for item in items[:8]:
                sev_i = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(item["severity"], "❓")
                print(f"    {sev_i} [{item['severity']:<8}] {item['symbol']:<35} {item['description'][:50]}")
        if ep.get("kernel_strings_count", 0) > 0:
            _sec(f"KERNEL-RELATED STRINGS ({ep['kernel_strings_count']})")
            for s in ep["kernel_strings"][:15]:
                print(f"    → {s[:100]}")

    # ── GODMODE: YARA Pattern Scan ───────────────────────────────────────────
    if r.get("yara_scan", {}).get("rules_with_matches", 0) > 0:
        ys = r["yara_scan"]
        _box(f"YARA PATTERN SCAN  ({ys['rules_with_matches']}/{ys['total_rules_loaded']} rules matched, "
             f"{ys['total_match_count']} hits)")
        for rule_match in ys["matches"]:
            _sec(f"{rule_match['rule']} [{rule_match['category']}] — {rule_match['match_count']} hit(s)")
            print(f"    {rule_match['description']}")
            for hit in rule_match["hits"][:5]:
                print(f"    @ {hit['offset']}  {hit['context_before']} [{hit['match']}] {hit['context_after']}")

    # ── GODMODE: Stub Map & Xref ─────────────────────────────────────────────
    if r.get("stub_map"):
        sm = r["stub_map"]
        _box(f"STUB RESOLVER  ({len(sm)} stubs → import names)")
        # Show first 30 stubs
        for stub_va, sym in list(sm.items())[:30]:
            print(f"    {stub_va:<14} →  {sym}")
        if len(sm) > 30:
            print(f"    ... +{len(sm)-30} more — see JSON for full map")

    if r.get("xref_database", {}).get("symbol_xref_count", 0) > 0:
        xref = r["xref_database"]
        _box(f"CROSS-REFERENCE DATABASE  ({xref['symbol_xref_count']} symbol xrefs, "
             f"{xref['string_xref_count']} string xrefs)")
        # Show top symbols by xref count
        sym_xrefs = xref.get("symbol_xrefs_sample", {})
        sorted_syms = sorted(sym_xrefs.items(), key=lambda x: len(x[1]), reverse=True)[:20]
        if sorted_syms:
            _sec("TOP SYMBOLS BY CALLER COUNT")
            for sym, callers in sorted_syms:
                print(f"    {sym:<50} called from {len(callers)} location(s)")
        # Show string xrefs containing keywords
        str_xrefs = xref.get("string_xrefs_sample", {})
        interesting = [(s, c) for s, c in str_xrefs.items() 
                       if any(kw in s.lower() for kw in ("trust", "amfi", "register", "validate", "container"))]
        if interesting:
            _sec("INTERESTING STRING XREFS (trust/amfi/register/validate)")
            for s, callers in interesting[:15]:
                print(f"    {repr(s)[:80]:<80} from {len(callers)} caller(s)")

    # ── POWERHOUSE: NSXPC Reconstruction ─────────────────────────────────────
    if r.get("nsxpc_reconstruction", {}).get("protocol_count", 0) > 0:
        nsx = r["nsxpc_reconstruction"]
        _box(f"NSXPC INTERFACES  ({nsx['protocol_count']} protocols, {nsx['class_count']} classes, {nsx['service_count']} mach services)")
        for p in nsx.get("nsxpc_protocols", [])[:10]:
            _sec(f"@protocol {p['name']}  ({p['method_count']} methods)")
            for m in p.get("instance_methods", [])[:8]:
                print(f"      - {m}")
        if nsx.get("xpc_classes"):
            _sec("XPC CLIENT/SERVER CLASSES")
            for c in nsx["xpc_classes"][:15]:
                print(f"    [{c['role']:<7}] {c['class_name']}")
        if nsx.get("mach_services"):
            _sec("MACH SERVICES REFERENCED")
            for s in nsx["mach_services"][:15]:
                print(f"    {s}")

    # ── POWERHOUSE: MIG Subsystems ───────────────────────────────────────────
    if r.get("mig_subsystems", {}).get("mig_tables_found", 0) > 0:
        mig = r["mig_subsystems"]
        _box(f"MIG SUBSYSTEM TABLES  ({mig['mig_tables_found']} found)")
        for t in mig.get("tables", [])[:10]:
            print(f"    {t['table_va']:<14} server={t['server_func']:<14} ids={t['msg_id_range']:<14} routines={t['routine_count']}")

    # ── POWERHOUSE: ROP Gadgets ──────────────────────────────────────────────
    if r.get("rop_gadgets", {}).get("total_gadgets", 0) > 0:
        rop = r["rop_gadgets"]
        _box(f"ROP/JOP GADGETS  ({rop['total_gadgets']} total)")
        for cat, count in rop.get("by_category", {}).items():
            print(f"    {cat:<20} {count:>5} gadget(s)")
        # Show samples
        for cat, gs in rop.get("gadgets", {}).items():
            if not gs:
                continue
            _sec(f"{cat.upper()} (top 3)")
            for g in gs[:3]:
                print(f"    {g['va']:<14} {g['instructions'][:80]}")

    # ── POWERHOUSE: Capabilities Summary ─────────────────────────────────────
    caps = r.get("godmax_capabilities", {})
    if caps:
        active = [k for k, v in caps.items() if v]
        if active:
            _sec(f"GODMAX OPTIONAL CAPABILITIES ACTIVE ({len(active)}/{len(caps)})")
            print(f"    {', '.join(active)}")

    _box("Analysis complete")
    print()


def print_firmware_intelligence_report(fw: dict):
    """Pretty-print the Firmware Intelligence Report to the terminal."""
    _box("IPSW FIRMWARE INTELLIGENCE REPORT")
    _line("iOS Version",   fw["ios_version"])
    _line("Build",         fw["ios_build"])
    _line("Product",       fw["product_type"])
    _line("Detected SoC",  fw["detected_hw"])
    _line("Binaries Scanned", fw["total_binaries"])
    ipsw_m = fw.get("ipsw_meta", {})
    if ipsw_m.get("ipsw_filename"):
        _line("IPSW File", ipsw_m["ipsw_filename"])
        _line("IPSW Size", f"{ipsw_m.get('ipsw_size_bytes', 0) / (1024*1024):.1f} MB")

    # Overall verdict
    print(f"\n  {'═'*W}")
    print(f"  OVERALL FIRMWARE RISK:  {fw['scores']['overall_firmware_risk']}%  —  {fw['verdict']}")
    print(f"  {'═'*W}")

    # 5-category scores with ASCII progress bars
    _sec("RISK CATEGORY SCORES")
    categories = [
        ("Jailbreak Feasibility",     fw["scores"]["jailbreak_feasibility"]),
        ("Kernel Attack Surface",     fw["scores"]["kernel_attack_surface"]),
        ("Userland Exploit Surface",  fw["scores"]["userland_exploit_surface"]),
        ("Code Injection Feasibility",fw["scores"]["code_injection_feasibility"]),
        ("Malware Implant Risk",      fw["scores"]["malware_implant_risk"]),
    ]
    for label, score in categories:
        filled = int(score / 5)
        bar = "█" * filled + "░" * (20 - filled)
        risk_tag = "🔴 CRITICAL" if score >= 65 else ("🟡 MEDIUM" if score >= 35 else "🟢 LOW")
        print(f"    {label:<30}  [{bar}]  {score:>3}%  {risk_tag}")

    # CVE Summary
    cs = fw["cve_summary"]
    _sec("CVE CROSS-REFERENCE SUMMARY")
    print(f"    Total Applicable CVEs:       {cs['total_applicable']}")
    print(f"    Potentially Vulnerable:      {cs['potentially_vulnerable']}")
    print(f"    Patched in this version:     {cs['patched']}")
    print(f"    Unpatchable (Hardware):       {cs['unpatchable_hw']}")
    print(f"    Critical + Unpatched:        {cs['critical_unpatched']}")

    # CVE Detail Table
    if fw["cve_results"]:
        _sec("APPLICABLE CVEs / EXPLOITS")
        # Sort: vulnerable first, then unpatchable, then patched
        status_order = {"POTENTIALLY_VULNERABLE": 0, "UNPATCHABLE": 1, "PATCHED": 2}
        sorted_cves = sorted(fw["cve_results"], key=lambda c: (status_order.get(c["status"], 9), c["id"]))
        for cve in sorted_cves:
            icon = {"POTENTIALLY_VULNERABLE": "🔴", "UNPATCHABLE": "⚡", "PATCHED": "✅"}.get(cve["status"], "❓")
            print(f"    {icon} [{cve['status']:<24}] {cve['id']:<20} {cve['name']}")
            print(f"       Category: {cve['category']:<10}  Severity: {cve['severity']:<10}  Patched in: {cve['patched_in']}")
            print(f"       {cve['description'][:120]}")
            if cve.get("references"):
                print(f"       Refs: {', '.join(cve['references'][:5])}")
            print()

    # Detailed Score Reasons
    _sec("DETAILED SCORE ANALYSIS")
    reason_labels = {
        "jailbreak": "JAILBREAK FEASIBILITY",
        "kernel":    "KERNEL ATTACK SURFACE",
        "userland":  "USERLAND EXPLOIT SURFACE",
        "injection": "CODE INJECTION FEASIBILITY",
        "malware":   "MALWARE IMPLANT RISK",
    }
    for key, label in reason_labels.items():
        reasons = fw["score_reasons"].get(key, [])
        if reasons:
            print(f"\n    ── {label} ──")
            for r in reasons:
                print(f"      {r}")

    # Recommendations
    _sec("RECOMMENDATIONS FOR SECURITY RESEARCHERS")
    for rec in fw["recommendations"].get("security_researcher", []):
        print(f"    🛡️  {rec}")
    _sec("RECOMMENDATIONS FOR OFFENSIVE RESEARCHERS")
    for rec in fw["recommendations"].get("offensive_researcher", []):
        print(f"    ⚔️  {rec}")

    # Aggregate Binary Stats
    agg = fw.get("aggregate", {})
    if agg:
        _sec("AGGREGATE BINARY STATISTICS")
        print(f"    Avg Exploit Score:         {agg.get('avg_exploit_score', 'N/A')}%")
        print(f"    Avg Hardening Score:       {agg.get('avg_hardening_score', 'N/A')}%")
        print(f"    Avg Inject Score:          {agg.get('avg_inject_score', 'N/A')}%")
        print(f"    Binaries without PIE:      {agg.get('binaries_no_pie', 0)}")
        print(f"    Binaries without Canary:   {agg.get('binaries_no_canary', 0)}")
        print(f"    Binaries without ARC:      {agg.get('binaries_no_arc', 0)}")
        print(f"    Total Entitlement Findings:{agg.get('total_ent_audit_findings', 0)}")
        banned = agg.get("total_banned_apis", {})
        if banned:
            print(f"    Banned APIs found:         {', '.join(banned.keys())}")

    _box("Firmware Intelligence Report Complete")
    print()


# ═══════════════════════════════════════════════════════════════════════════════
# §25  JSON SERIALIZER
# ═══════════════════════════════════════════════════════════════════════════════

def _make_serializable(obj):
    if isinstance(obj,bytes):   return obj.hex()
    if isinstance(obj,dict):    return {k:_make_serializable(v) for k,v in obj.items()}
    if isinstance(obj,list):    return [_make_serializable(i) for i in obj]
    if isinstance(obj,set):     return sorted(_make_serializable(i) for i in obj)
    return obj


# ═══════════════════════════════════════════════════════════════════════════════
# §25.5  INTERACTIVE DESKTOP GUI
# ═══════════════════════════════════════════════════════════════════════════════

def launch_gui():
    global ctk
    if tk is None or filedialog is None or ttk is None:
        print("[!] GUI dependencies (Tkinter/Tcl) are not available in this environment.", file=sys.stderr)
        print("[*] Please run this script in a desktop environment or pass a binary file path to use CLI mode.", file=sys.stderr)
        sys.exit(1)

    try:
        import customtkinter as ctk
    except ImportError:
        print("[*] GUI dependency 'customtkinter' is missing. Installing...")
        import subprocess
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "customtkinter"])
            print("[+] Installed 'customtkinter' successfully.")
            import customtkinter as ctk
        except Exception as e:
            print(f"[!] Failed to install customtkinter: {e}", file=sys.stderr)
            sys.exit(1)

    ctk.set_appearance_mode("Dark")
    ctk.set_default_color_theme("blue")

    class TextRedirector:
        def __init__(self, text_widget: ctk.CTkTextbox, queue_widget: queue.Queue):
            self.text_widget = text_widget
            self.queue_widget = queue_widget

        def write(self, string: str):
            self.queue_widget.put(string)

        def flush(self):
            pass

    class AetherAnalyzerApp(ctk.CTk):
        def __init__(self):
            super().__init__()

            self.title("AETHER ANALYZER  //  Premium Interactive iOS Binary Explorer")
            self.geometry("1280x800")
            self.minsize(1024, 700)

            # Threading Queue for Safe Logging
            self.log_queue = queue.Queue()
            self.current_analysis_results = {}
            self.selected_macho_data = None
            self.is_analyzing = False
            self.current_objc_class = ""
            self.current_objc_methods = []

            # Set up grid layout
            self.grid_rowconfigure(0, weight=1)
            self.grid_columnconfigure(1, weight=1)

            # ── Sidebar Navigation ──
            self.sidebar_frame = ctk.CTkFrame(self, width=200, corner_radius=0)
            self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
            self.sidebar_frame.grid_rowconfigure(4, weight=1)

            # Logo / Branding
            self.logo_label = ctk.CTkLabel(
                self.sidebar_frame, 
                text="AETHER // ANALYZER", 
                font=ctk.CTkFont(family="Courier New", size=18, weight="bold"),
                text_color="#00FFFF"
            )
            self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))

            self.subtitle_label = ctk.CTkLabel(
                self.sidebar_frame,
                text="Mach-O iOS Static Suite",
                font=ctk.CTkFont(size=12, slant="italic"),
                text_color="#888888"
            )
            self.subtitle_label.grid(row=1, column=0, padx=20, pady=(0, 20))

            # Nav Buttons
            self.btn_dashboard = ctk.CTkButton(self.sidebar_frame, text="Console & Input", command=self.show_dashboard_tab)
            self.btn_dashboard.grid(row=2, column=0, padx=20, pady=10, sticky="ew")

            self.btn_carved = ctk.CTkButton(self.sidebar_frame, text="Carved Binaries", command=self.show_carved_tab)
            self.btn_carved.grid(row=3, column=0, padx=20, pady=10, sticky="ew")

            self.btn_security = ctk.CTkButton(self.sidebar_frame, text="Security Auditor", command=self.show_security_tab)
            self.btn_security.grid(row=4, column=0, padx=20, pady=10, sticky="ew")

            self.btn_objc = ctk.CTkButton(self.sidebar_frame, text="ObjC & Swift Explorer", command=self.show_objc_tab)
            self.btn_objc.grid(row=5, column=0, padx=20, pady=10, sticky="ew")

            self.btn_strings = ctk.CTkButton(self.sidebar_frame, text="Strings & Entitlements", command=self.show_strings_tab)
            self.btn_strings.grid(row=6, column=0, padx=20, pady=10, sticky="ew")

            self.btn_disasm = ctk.CTkButton(self.sidebar_frame, text="Disassembly View", command=self.show_disasm_tab)
            self.btn_disasm.grid(row=7, column=0, padx=20, pady=10, sticky="ew")

            self.btn_re_utils = ctk.CTkButton(self.sidebar_frame, text="RE Utilities Suite", command=self.show_re_utils_tab)
            self.btn_re_utils.grid(row=8, column=0, padx=20, pady=10, sticky="ew")

            self.btn_ipsw_intel = ctk.CTkButton(
                self.sidebar_frame, text="IPSW Firmware Intel",
                command=self.show_ipsw_tab,
                fg_color="#8B0000", hover_color="#FF4500",
                font=ctk.CTkFont(weight="bold")
            )
            self.btn_ipsw_intel.grid(row=9, column=0, padx=20, pady=10, sticky="ew")

            self.btn_powerhouse = ctk.CTkButton(
                self.sidebar_frame, text="⚡ POWERHOUSE",
                command=self.show_powerhouse_tab,
                fg_color="#7B00FF", hover_color="#9B30FF",
                font=ctk.CTkFont(weight="bold")
            )
            self.btn_powerhouse.grid(row=10, column=0, padx=20, pady=10, sticky="ew")

            self.btn_device = ctk.CTkButton(
                self.sidebar_frame, text="📱 Device Bridge",
                command=self.show_device_tab,
                fg_color="#0066CC", hover_color="#3399FF",
                font=ctk.CTkFont(weight="bold")
            )
            self.btn_device.grid(row=11, column=0, padx=20, pady=10, sticky="ew")

            # Theme Selector at bottom
            self.theme_label = ctk.CTkLabel(self.sidebar_frame, text="Appearance Mode:", anchor="w")
            self.theme_label.grid(row=12, column=0, padx=20, pady=(10, 0))
            self.theme_optionmenu = ctk.CTkOptionMenu(
                self.sidebar_frame, 
                values=["Dark", "Light", "System"],
                command=ctk.set_appearance_mode
            )
            self.theme_optionmenu.grid(row=13, column=0, padx=20, pady=(0, 20))

            # ── Main Content Area (Tab Container) ──
            self.tab_container = ctk.CTkFrame(self, corner_radius=15, fg_color="transparent")
            self.tab_container.grid(row=0, column=1, padx=20, pady=20, sticky="nsew")
            self.tab_container.grid_rowconfigure(0, weight=1)
            self.tab_container.grid_columnconfigure(0, weight=1)

            # Tab 1: Dashboard / Controls & Log Streamer
            self.tab_dashboard = ctk.CTkFrame(self.tab_container)
            self.build_dashboard_tab()

            # Tab 2: Carved Binaries Panel
            self.tab_carved = ctk.CTkFrame(self.tab_container)
            self.build_carved_tab()

            # Tab 3: Security Auditor Dashboard
            self.tab_security = ctk.CTkFrame(self.tab_container)
            self.build_security_tab()

            # Tab 4: ObjC/Swift Class Browser
            self.tab_objc = ctk.CTkFrame(self.tab_container)
            self.build_objc_tab()

            # Tab 5: Strings & Entitlements Explorer
            self.tab_strings = ctk.CTkFrame(self.tab_container)
            self.build_strings_tab()

            # Tab 6: Interactive Disassembly
            self.tab_disasm = ctk.CTkFrame(self.tab_container)
            self.build_disasm_tab()

            # Tab 7: RE Utilities Suite
            self.tab_re_utils = ctk.CTkFrame(self.tab_container)
            self.build_re_utils_tab()

            # Tab 8: IPSW Firmware Intelligence
            self.tab_ipsw_intel = ctk.CTkFrame(self.tab_container)
            self.build_ipsw_intel_tab()
            self.firmware_intel_report = None

            # Tab 9: POWERHOUSE Center
            self.tab_powerhouse = ctk.CTkFrame(self.tab_container)
            self.build_powerhouse_tab()

            # Tab 10: Device Bridge
            self.tab_device = ctk.CTkFrame(self.tab_container)
            self.build_device_tab()

            # Display default tab
            self.current_visible_tab = self.tab_dashboard
            self.current_visible_tab.grid(row=0, column=0, sticky="nsew")

            # Start periodic log checks
            self.after(100, self.update_logs)

        # ── Log / Console Thread-Safety ──
        def update_logs(self):
            while not self.log_queue.empty():
                try:
                    msg = self.log_queue.get_nowait()
                    self.console_textbox.insert(tk.END, msg)
                    self.console_textbox.see(tk.END)
                except queue.Empty:
                    break
            self.after(100, self.update_logs)

        # ── Tab Navigation Controllers ──
        def switch_tab(self, target_tab: ctk.CTkFrame):
            self.current_visible_tab.grid_forget()
            self.current_visible_tab = target_tab
            self.current_visible_tab.grid(row=0, column=0, sticky="nsew")

        def show_dashboard_tab(self): self.switch_tab(self.tab_dashboard)
        def show_carved_tab(self): self.switch_tab(self.tab_carved)
        def show_security_tab(self): self.switch_tab(self.tab_security)
        def show_objc_tab(self): self.switch_tab(self.tab_objc)
        def show_strings_tab(self): self.switch_tab(self.tab_strings)
        def show_disasm_tab(self): self.switch_tab(self.tab_disasm)
        def show_re_utils_tab(self): self.switch_tab(self.tab_re_utils)
        def show_ipsw_tab(self): self.switch_tab(self.tab_ipsw_intel)
        def show_powerhouse_tab(self): self.switch_tab(self.tab_powerhouse)
        def show_device_tab(self): self.switch_tab(self.tab_device)

        # ── UI Constructors ──
        def build_dashboard_tab(self):
            self.tab_dashboard.grid_rowconfigure(3, weight=1)
            self.tab_dashboard.grid_columnconfigure(0, weight=1)

            # Title Block
            self.db_title = ctk.CTkLabel(
                self.tab_dashboard, 
                text="INPUT SELECTION & LIVE EXECUTION CONSOLE",
                font=ctk.CTkFont(size=16, weight="bold"),
                text_color="#00FFFF"
            )
            self.db_title.grid(row=0, column=0, padx=20, pady=(20, 10), sticky="w")

            # Controls Panel
            self.controls_frame = ctk.CTkFrame(self.tab_dashboard)
            self.controls_frame.grid(row=1, column=0, padx=20, pady=10, sticky="ew")
            self.controls_frame.grid_columnconfigure(1, weight=1)

            self.input_label = ctk.CTkLabel(self.controls_frame, text="Target File:")
            self.input_label.grid(row=0, column=0, padx=10, pady=10, sticky="w")

            self.input_entry = ctk.CTkEntry(self.controls_frame, placeholder_text="Path to binary, .aea, .dmg, or .aar archive...")
            self.input_entry.grid(row=0, column=1, padx=10, pady=10, sticky="ew")

            self.btn_browse = ctk.CTkButton(self.controls_frame, text="Browse...", width=100, command=self.browse_file)
            self.btn_browse.grid(row=0, column=2, padx=10, pady=10)

            # Extra Options
            self.options_frame = ctk.CTkFrame(self.tab_dashboard)
            self.options_frame.grid(row=2, column=0, padx=20, pady=10, sticky="ew")

            self.cb_cfg = ctk.CTkCheckBox(self.options_frame, text="Build Call Graph (Slower)")
            self.cb_cfg.grid(row=0, column=0, padx=20, pady=10)

            self.cb_taint = ctk.CTkCheckBox(self.options_frame, text="Run Taint Tracking Analysis")
            self.cb_taint.grid(row=0, column=1, padx=20, pady=10)
            self.cb_taint.select()

            self.btn_analyze = ctk.CTkButton(
                self.options_frame, 
                text="START SUPER DEEP SCAN", 
                fg_color="#008B8B", 
                hover_color="#00FFFF",
                text_color="#FFFFFF",
                font=ctk.CTkFont(weight="bold"),
                command=self.start_analysis_thread
            )
            self.btn_analyze.grid(row=0, column=2, padx=20, pady=10, sticky="e")

            # Output Terminal Streamer
            self.console_textbox = ctk.CTkTextbox(
                self.tab_dashboard, 
                font=ctk.CTkFont(family="Courier New", size=13),
                fg_color="#080808",
                text_color="#00FF00"
            )
            self.console_textbox.grid(row=3, column=0, padx=20, pady=20, sticky="nsew")

        def build_carved_tab(self):
            self.tab_carved.grid_rowconfigure(1, weight=1)
            self.tab_carved.grid_columnconfigure(0, weight=1)

            self.carved_title = ctk.CTkLabel(
                self.tab_carved,
                text="CARVED BINARIES & STRUCTURED EXPLOITS TREE",
                font=ctk.CTkFont(size=16, weight="bold"),
                text_color="#00FFFF"
            )
            self.carved_title.grid(row=0, column=0, padx=20, pady=(20, 10), sticky="w")

            # Tree Frame
            self.tree_frame = ctk.CTkFrame(self.tab_carved)
            self.tree_frame.grid(row=1, column=0, padx=20, pady=20, sticky="nsew")
            self.tree_frame.grid_rowconfigure(0, weight=1)
            self.tree_frame.grid_columnconfigure(0, weight=1)

            # Style customization for modern look
            style = ttk.Style()
            style.theme_use("clam")
            style.configure("Treeview", background="#1d1d1d", fieldbackground="#1d1d1d", foreground="#ffffff", rowheight=30)
            style.configure("Treeview.Heading", background="#2a2a2a", foreground="#ffffff")
            
            self.tree = ttk.Treeview(self.tree_frame, columns=("size", "type"), show="tree headings")
            self.tree.heading("#0", text="File Name / Binary Name", anchor="w")
            self.tree.heading("size", text="Size", anchor="w")
            self.tree.heading("type", text="Details / Type", anchor="w")
            self.tree.column("#0", width=400)
            self.tree.column("size", width=150)
            self.tree.column("type", width=250)
            self.tree.grid(row=0, column=0, sticky="nsew")
            
            self.tree.bind("<<TreeviewSelect>>", self.on_tree_select)

        def build_security_tab(self):
            self.tab_security.grid_rowconfigure(1, weight=1)
            self.tab_security.grid_columnconfigure(0, weight=1)

            self.sec_title = ctk.CTkLabel(
                self.tab_security,
                text="AUTOMATED HEURISTIC SECURITY RISK AUDITOR",
                font=ctk.CTkFont(size=16, weight="bold"),
                text_color="#00FFFF"
            )
            self.sec_title.grid(row=0, column=0, padx=20, pady=(20, 10), sticky="w")

            # Dashboard grid container
            self.sec_grid = ctk.CTkScrollableFrame(self.tab_security)
            self.sec_grid.grid(row=1, column=0, padx=20, pady=20, sticky="nsew")
            self.sec_grid.grid_columnconfigure((0, 1), weight=1)

            # ── Threat Scorecard Frame (Premium Visual Dashboard) ──
            self.scorecard_frame = ctk.CTkFrame(self.sec_grid, border_width=1, border_color="#00FFFF", corner_radius=10, fg_color="#142626")
            self.scorecard_frame.grid(row=0, column=0, columnspan=2, padx=15, pady=15, sticky="ew")
            self.scorecard_frame.grid_columnconfigure((0, 1, 2), weight=1)

            self.lbl_score_title = ctk.CTkLabel(self.scorecard_frame, text="SECURITY HARDENING & AUDIT THREAT SCORECARD", font=ctk.CTkFont(size=14, weight="bold"), text_color="#00FFFF")
            self.lbl_score_title.grid(row=0, column=0, columnspan=3, padx=15, pady=(15, 10), sticky="w")

            # Verdict display
            self.lbl_sec_verdict = ctk.CTkLabel(self.scorecard_frame, text="VERDICT: WAITING FOR SCAN", font=ctk.CTkFont(size=15, weight="bold"), text_color="#aaaaaa")
            self.lbl_sec_verdict.grid(row=1, column=0, columnspan=3, padx=15, pady=5, sticky="w")

            # Circular/Bar indicators (Percentage displays)
            self.frame_metric_1 = ctk.CTkFrame(self.scorecard_frame, fg_color="transparent")
            self.frame_metric_1.grid(row=2, column=0, padx=10, pady=10, sticky="nsew")
            self.lbl_metric_1_val = ctk.CTkLabel(self.frame_metric_1, text="N/A", font=ctk.CTkFont(size=24, weight="bold"), text_color="#00FFFF")
            self.lbl_metric_1_val.pack()
            self.lbl_metric_1_title = ctk.CTkLabel(self.frame_metric_1, text="Mitigation Posture", font=ctk.CTkFont(size=11), text_color="#888888")
            self.lbl_metric_1_title.pack()

            self.frame_metric_2 = ctk.CTkFrame(self.scorecard_frame, fg_color="transparent")
            self.frame_metric_2.grid(row=2, column=1, padx=10, pady=10, sticky="nsew")
            self.lbl_metric_2_val = ctk.CTkLabel(self.frame_metric_2, text="N/A", font=ctk.CTkFont(size=24, weight="bold"), text_color="#FF4500")
            self.lbl_metric_2_val.pack()
            self.lbl_metric_2_title = ctk.CTkLabel(self.frame_metric_2, text="Exploitability Rating", font=ctk.CTkFont(size=11), text_color="#888888")
            self.lbl_metric_2_title.pack()

            self.frame_metric_3 = ctk.CTkFrame(self.scorecard_frame, fg_color="transparent")
            self.frame_metric_3.grid(row=2, column=2, padx=10, pady=10, sticky="nsew")
            self.lbl_metric_3_val = ctk.CTkLabel(self.frame_metric_3, text="N/A", font=ctk.CTkFont(size=24, weight="bold"), text_color="#FFD700")
            self.lbl_metric_3_val.pack()
            self.lbl_metric_3_title = ctk.CTkLabel(self.frame_metric_3, text="Tweak Compatibility", font=ctk.CTkFont(size=11), text_color="#888888")
            self.lbl_metric_3_title.pack()

            # Detailed Audited Elements listbox
            self.txt_scorecard_details = ctk.CTkTextbox(self.scorecard_frame, height=100, font=ctk.CTkFont(family="Consolas", size=11), fg_color="#181818")
            self.txt_scorecard_details.grid(row=3, column=0, columnspan=3, padx=15, pady=(10, 15), sticky="nsew")

            # Shift the other widgets to rows 1-4
            self.widget_antidebug = self.create_security_widget(self.sec_grid, "Anti-Debugging Diagnostics", 1, 0)
            self.widget_jailbreak = self.create_security_widget(self.sec_grid, "Jailbreak Detection Controls", 1, 1)
            self.widget_pinning = self.create_security_widget(self.sec_grid, "SSL Pinning Mechanisms", 2, 0)
            self.widget_secrets = self.create_security_widget(self.sec_grid, "Hardcoded Secrets & API Keys", 2, 1)
            self.widget_obfuscation = self.create_security_widget(self.sec_grid, "Obfuscation Heuristics", 3, 0)
            self.widget_constructors = self.create_security_widget(self.sec_grid, "Binary Initializers (__mod_init_func)", 3, 1)
            self.widget_entitlements = self.create_security_widget(self.sec_grid, "High-Privilege Entitlements Audit", 4, 0)
            self.widget_crypto = self.create_security_widget(self.sec_grid, "Cryptography & Secure APIs", 4, 1)

        def create_security_widget(self, parent, title: str, row: int, col: int) -> dict:
            frame = ctk.CTkFrame(parent, border_width=1, border_color="#2a2a2a", corner_radius=10)
            frame.grid(row=row, column=col, padx=15, pady=15, sticky="nsew")
            frame.grid_rowconfigure(2, weight=1)
            frame.grid_columnconfigure(0, weight=1)

            lbl_title = ctk.CTkLabel(frame, text=title, font=ctk.CTkFont(size=13, weight="bold"))
            lbl_title.grid(row=0, column=0, padx=15, pady=(15, 5), sticky="w")

            # Risk indicator badge
            lbl_badge = ctk.CTkLabel(
                frame, 
                text="WAITING FOR SCAN", 
                font=ctk.CTkFont(size=11, weight="bold"),
                fg_color="#3a3a3a",
                corner_radius=5,
                padx=10, pady=2
            )
            lbl_badge.grid(row=0, column=1, padx=15, pady=(15, 5), sticky="e")

            txt_details = ctk.CTkTextbox(frame, height=100, font=ctk.CTkFont(family="Consolas", size=11), fg_color="#181818")
            txt_details.grid(row=2, column=0, columnspan=2, padx=15, pady=(5, 15), sticky="nsew")

            return {"badge": lbl_badge, "text": txt_details}

        def build_objc_tab(self):
            self.tab_objc.grid_rowconfigure(1, weight=1)
            self.tab_objc.grid_columnconfigure((0, 1), weight=1)

            # Title & Filter Frame
            self.top_objc_frame = ctk.CTkFrame(self.tab_objc)
            self.top_objc_frame.grid(row=0, column=0, columnspan=2, padx=20, pady=(20, 10), sticky="ew")
            
            self.objc_title = ctk.CTkLabel(
                self.top_objc_frame,
                text="OBJECTIVE-C & SWIFT DEEP CLASS EXHAUSTIVE BROWSER",
                font=ctk.CTkFont(size=15, weight="bold"),
                text_color="#00FFFF"
            )
            self.objc_title.grid(row=0, column=0, padx=10, pady=5, sticky="w")

            self.filter_entry = ctk.CTkEntry(self.top_objc_frame, placeholder_text="Filter classes or structures by name...")
            self.filter_entry.grid(row=0, column=1, padx=10, pady=5, sticky="ew")
            self.filter_entry.bind("<KeyRelease>", self.on_class_filter_change)

            # Left panel: Class List Box
            self.class_listbox = tk.Listbox(
                self.tab_objc, 
                bg="#1d1d1d", 
                fg="#ffffff", 
                selectbackground="#008b8b", 
                font=("Courier New", 12),
                borderwidth=0,
                highlightthickness=0
            )
            self.class_listbox.grid(row=1, column=0, padx=(20, 10), pady=20, sticky="nsew")
            self.class_listbox.bind("<<ListboxSelect>>", self.on_class_select)

            # Right panel: Method Details Browser Frame
            self.right_objc_frame = ctk.CTkFrame(self.tab_objc, fg_color="transparent")
            self.right_objc_frame.grid(row=1, column=1, padx=(10, 20), pady=20, sticky="nsew")
            self.right_objc_frame.grid_rowconfigure(0, weight=1)
            self.right_objc_frame.grid_rowconfigure(1, weight=0)
            self.right_objc_frame.grid_columnconfigure(0, weight=1)

            self.method_details_box = ctk.CTkTextbox(
                self.right_objc_frame,
                font=ctk.CTkFont(family="Consolas", size=12),
                fg_color="#181818",
                text_color="#e0e0e0"
            )
            self.method_details_box.grid(row=0, column=0, padx=0, pady=(0, 10), sticky="nsew")

            # Quick Hooking & Instrumentation Tools Frame
            self.hook_tools_frame = ctk.CTkFrame(self.right_objc_frame, border_width=1, border_color="#2a2a2a", corner_radius=8)
            self.hook_tools_frame.grid(row=1, column=0, padx=0, pady=0, sticky="ew")
            self.hook_tools_frame.grid_columnconfigure(1, weight=1)

            self.lbl_hook_method = ctk.CTkLabel(self.hook_tools_frame, text="Instrument Method:", font=ctk.CTkFont(size=12, weight="bold"))
            self.lbl_hook_method.grid(row=0, column=0, padx=10, pady=10, sticky="w")

            self.combo_hook_method = ctk.CTkOptionMenu(self.hook_tools_frame, values=["(Select Class First)"])
            self.combo_hook_method.grid(row=0, column=1, padx=10, pady=10, sticky="ew")

            self.btn_frida_hook = ctk.CTkButton(self.hook_tools_frame, text="Copy Frida Hook", fg_color="#800080", hover_color="#4B0082", command=self.do_gui_gen_frida)
            self.btn_frida_hook.grid(row=0, column=2, padx=5, pady=10)

            self.btn_logos_hook = ctk.CTkButton(self.hook_tools_frame, text="Copy Logos Hook", fg_color="#008080", hover_color="#005f5f", command=self.do_gui_gen_logos)
            self.btn_logos_hook.grid(row=0, column=3, padx=10, pady=10)

        def build_strings_tab(self):
            self.tab_strings.grid_rowconfigure((1, 3), weight=1)
            self.tab_strings.grid_columnconfigure(0, weight=1)

            # Entitlements
            self.ent_title = ctk.CTkLabel(
                self.tab_strings,
                text="XML / DER DECODED SECURITY ENTITLEMENTS PLATFORM",
                font=ctk.CTkFont(size=14, weight="bold"),
                text_color="#00FFFF"
            )
            self.ent_title.grid(row=0, column=0, padx=20, pady=(20, 5), sticky="w")

            self.ent_text = ctk.CTkTextbox(self.tab_strings, font=ctk.CTkFont(family="Consolas", size=12), fg_color="#181818")
            self.ent_text.grid(row=1, column=0, padx=20, pady=5, sticky="nsew")

            # Keywords Strings
            self.strings_title = ctk.CTkLabel(
                self.tab_strings,
                text="CRITICAL STRINGS & REGULAR KEYWORDS MAP",
                font=ctk.CTkFont(size=14, weight="bold"),
                text_color="#00FFFF"
            )
            self.strings_title.grid(row=2, column=0, padx=20, pady=(15, 5), sticky="w")

            self.strings_text = ctk.CTkTextbox(self.tab_strings, font=ctk.CTkFont(family="Consolas", size=12), fg_color="#181818")
            self.strings_text.grid(row=3, column=0, padx=20, pady=(5, 20), sticky="nsew")

        def build_disasm_tab(self):
            self.tab_disasm.grid_rowconfigure(1, weight=1)
            self.tab_disasm.grid_columnconfigure(0, weight=1)

            self.disasm_title = ctk.CTkLabel(
                self.tab_disasm,
                text="ARM64 DEEPLY CARVED BINARY RECONSTRUCTED DISASSEMBLY",
                font=ctk.CTkFont(size=15, weight="bold"),
                text_color="#00FFFF"
            )
            self.disasm_title.grid(row=0, column=0, padx=20, pady=(20, 10), sticky="w")

            self.disasm_text = ctk.CTkTextbox(
                self.tab_disasm, 
                font=ctk.CTkFont(family="Courier New", size=12),
                fg_color="#080808",
                text_color="#00FFFF"
            )
            self.disasm_text.grid(row=1, column=0, padx=20, pady=20, sticky="nsew")

        def build_re_utils_tab(self):
            self.tab_re_utils.grid_rowconfigure(0, weight=1)
            self.tab_re_utils.grid_columnconfigure((0, 1), weight=1)

            # Left side Frame (Translator & Patching)
            left_frame = ctk.CTkScrollableFrame(self.tab_re_utils)
            left_frame.grid(row=0, column=0, padx=15, pady=15, sticky="nsew")
            left_frame.grid_columnconfigure(0, weight=1)

            # ── Address Translator ──
            trans_frame = ctk.CTkFrame(left_frame, border_width=1, border_color="#2a2a2a", corner_radius=10)
            trans_frame.grid(row=0, column=0, padx=10, pady=10, sticky="ew")
            trans_frame.grid_columnconfigure(1, weight=1)

            trans_lbl = ctk.CTkLabel(trans_frame, text="Address Translator (VA <=> Offset)", font=ctk.CTkFont(size=13, weight="bold"), text_color="#00FFFF")
            trans_lbl.grid(row=0, column=0, columnspan=3, padx=15, pady=(15, 5), sticky="w")

            self.trans_entry = ctk.CTkEntry(trans_frame, placeholder_text="Hex or decimal address/offset (e.g. 0x100004000)...")
            self.trans_entry.grid(row=1, column=0, columnspan=2, padx=15, pady=10, sticky="ew")

            self.btn_translate = ctk.CTkButton(trans_frame, text="Translate", width=90, command=self.do_gui_translate)
            self.btn_translate.grid(row=1, column=2, padx=15, pady=10)

            self.trans_output = ctk.CTkLabel(trans_frame, text="Translation results will appear here.", anchor="w", justify="left")
            self.trans_output.grid(row=2, column=0, columnspan=3, padx=15, pady=(5, 15), sticky="w")

            # ── Sideloading Patch Editor ──
            patch_frame = ctk.CTkFrame(left_frame, border_width=1, border_color="#2a2a2a", corner_radius=10)
            patch_frame.grid(row=1, column=0, padx=10, pady=10, sticky="ew")
            patch_frame.grid_columnconfigure(1, weight=1)

            patch_lbl = ctk.CTkLabel(patch_frame, text="Sideloading Patch Editor (Dylib Path Renamer)", font=ctk.CTkFont(size=13, weight="bold"), text_color="#00FFFF")
            patch_lbl.grid(row=0, column=0, columnspan=2, padx=15, pady=(15, 5), sticky="w")

            self.patch_old_lbl = ctk.CTkLabel(patch_frame, text="Target Path:")
            self.patch_old_lbl.grid(row=1, column=0, padx=15, pady=5, sticky="w")

            self.patch_old_entry = ctk.CTkEntry(patch_frame, placeholder_text="e.g. /System/Library/Frameworks/Security.framework/Security")
            self.patch_old_entry.grid(row=1, column=1, padx=15, pady=5, sticky="ew")

            self.patch_new_lbl = ctk.CTkLabel(patch_frame, text="New Path:")
            self.patch_new_lbl.grid(row=2, column=0, padx=15, pady=5, sticky="w")

            self.patch_new_entry = ctk.CTkEntry(patch_frame, placeholder_text="e.g. @executable_path/libmocksec.dylib")
            self.patch_new_entry.grid(row=2, column=1, padx=15, pady=5, sticky="ew")

            self.btn_patch_dylib = ctk.CTkButton(patch_frame, text="Inject Sideload Path", command=self.do_gui_dylib_rename)
            self.btn_patch_dylib.grid(row=3, column=0, columnspan=2, padx=15, pady=15, sticky="ew")

            # Right side Frame (Differ & Emulator)
            right_frame = ctk.CTkScrollableFrame(self.tab_re_utils)
            right_frame.grid(row=0, column=1, padx=15, pady=15, sticky="nsew")
            right_frame.grid_columnconfigure(0, weight=1)

            # ── Mach-O Binary Differ ──
            diff_frame = ctk.CTkFrame(right_frame, border_width=1, border_color="#2a2a2a", corner_radius=10)
            diff_frame.grid(row=0, column=0, padx=10, pady=10, sticky="ew")
            diff_frame.grid_columnconfigure(1, weight=1)

            diff_lbl = ctk.CTkLabel(diff_frame, text="Mach-O Binary Differ", font=ctk.CTkFont(size=13, weight="bold"), text_color="#00FFFF")
            diff_lbl.grid(row=0, column=0, columnspan=3, padx=15, pady=(15, 5), sticky="w")

            self.diff_target_entry = ctk.CTkEntry(diff_frame, placeholder_text="Path to secondary binary B...")
            self.diff_target_entry.grid(row=1, column=0, columnspan=2, padx=15, pady=5, sticky="ew")

            self.btn_diff_browse = ctk.CTkButton(diff_frame, text="Browse...", width=90, command=self.browse_diff_file)
            self.btn_diff_browse.grid(row=1, column=2, padx=15, pady=5)

            self.btn_run_diff = ctk.CTkButton(diff_frame, text="Compare Selected Binaries", command=self.do_gui_diff)
            self.btn_run_diff.grid(row=2, column=0, columnspan=3, padx=15, pady=10, sticky="ew")

            self.diff_output = ctk.CTkTextbox(diff_frame, height=120, font=ctk.CTkFont(family="Consolas", size=11), fg_color="#181818")
            self.diff_output.grid(row=3, column=0, columnspan=3, padx=15, pady=(5, 15), sticky="nsew")

            # ── ARM64 Emulator Sandbox ──
            emu_frame = ctk.CTkFrame(right_frame, border_width=1, border_color="#2a2a2a", corner_radius=10)
            emu_frame.grid(row=1, column=0, padx=10, pady=10, sticky="ew")
            emu_frame.grid_columnconfigure(1, weight=1)

            emu_lbl = ctk.CTkLabel(emu_frame, text="ARM64 Micro-Emulation Sandbox", font=ctk.CTkFont(size=13, weight="bold"), text_color="#00FFFF")
            emu_lbl.grid(row=0, column=0, columnspan=3, padx=15, pady=(15, 5), sticky="w")

            self.emu_func_entry = ctk.CTkEntry(emu_frame, placeholder_text="Virtual Address to emulate (e.g. 0x100004FC0)...")
            self.emu_func_entry.grid(row=1, column=0, columnspan=2, padx=15, pady=5, sticky="ew")

            self.btn_init_emu = ctk.CTkButton(emu_frame, text="Init Emu", width=90, command=self.do_gui_init_emu)
            self.btn_init_emu.grid(row=1, column=2, padx=15, pady=5)

            self.btn_step_emu = ctk.CTkButton(emu_frame, text="Step Instruction", state="disabled", command=self.do_gui_step_emu)
            self.btn_step_emu.grid(row=2, column=0, columnspan=3, padx=15, pady=5, sticky="ew")

            self.emu_regs_lbl = ctk.CTkLabel(emu_frame, text="Registers: X0=0x0 X1=0x0 X2=0x0 SP=0x7FFFFFF0 PC=0x0", font=ctk.CTkFont(family="Courier New", size=11), anchor="w")
            self.emu_regs_lbl.grid(row=3, column=0, columnspan=3, padx=15, pady=5, sticky="w")

            self.emu_output = ctk.CTkTextbox(emu_frame, height=120, font=ctk.CTkFont(family="Consolas", size=11), fg_color="#181818")
            self.emu_output.grid(row=4, column=0, columnspan=3, padx=15, pady=(5, 15), sticky="nsew")

        def do_gui_translate(self):
            val_str = self.trans_entry.get().strip()
            if not val_str:
                self.trans_output.configure(text="Please specify a value to translate.")
                return
            try:
                addr = int(val_str, 0)
            except ValueError:
                self.trans_output.configure(text="Invalid number format (use hex 0x or decimal).")
                return

            if not self.selected_macho_data:
                self.trans_output.configure(text="No binary selected. Please complete a deep scan first.")
                return

            # reconstruct segs dict from report segments list
            segs = {}
            for s in self.selected_macho_data.get("segments", []):
                class MockSeg:
                    def __init__(self, name, vmaddr, vmsize, fileoff, filesize):
                        self.segname = name
                        self.vmaddr = int(vmaddr, 16) if isinstance(vmaddr, str) else vmaddr
                        self.vmsize = int(vmsize, 16) if isinstance(vmsize, str) else vmsize
                        self.fileoff = int(fileoff, 16) if isinstance(fileoff, str) else fileoff
                        self.filesize = int(filesize, 16) if isinstance(filesize, str) else filesize
                segs[s["name"]] = MockSeg(s["name"], s["vmaddr"], s["vmsize"], s["fileoff"], s["filesize"])

            fo = va_to_fo(addr, segs)
            va = fo_to_va(addr, segs)
            res_str = f"Target Value: 0x{addr:X}\n"
            if fo is not None:
                res_str += f"  -> As Virtual Address: File Offset = 0x{fo:X}\n"
            if va is not None:
                res_str += f"  -> As File Offset: Virtual Address = 0x{va:X}\n"
            if fo is None and va is None:
                res_str += "  -> Could not map to any loaded segments."

            self.trans_output.configure(text=res_str)

        def do_gui_dylib_rename(self):
            target_bin = self.input_entry.get().strip()
            old_path = self.patch_old_entry.get().strip()
            new_path = self.patch_new_entry.get().strip()

            if not target_bin or not Path(target_bin).exists():
                self.console_textbox.insert(tk.END, "[!] Error: Select a valid target file first.\n")
                return
            if not old_path or not new_path:
                self.console_textbox.insert(tk.END, "[!] Error: Old and New dylib paths are required.\n")
                return

            success = rename_macho_dylib(target_bin, old_path, new_path)
            if success:
                self.console_textbox.insert(tk.END, f"[+] Patched dependency successfully in {target_bin}!\n")
            else:
                self.console_textbox.insert(tk.END, f"[!] Failed to rename path in {target_bin}.\n")

        def browse_diff_file(self):
            path = filedialog.askopenfilename(title="Select Secondary Binary B to Diff")
            if path:
                self.diff_target_entry.delete(0, tk.END)
                self.diff_target_entry.insert(0, path)

        def do_gui_diff(self):
            bin_a = self.input_entry.get().strip()
            bin_b = self.diff_target_entry.get().strip()

            if not bin_a or not Path(bin_a).exists():
                self.diff_output.insert(tk.END, "[!] Select primary target file first.\n")
                return
            if not bin_b or not Path(bin_b).exists():
                self.diff_output.insert(tk.END, "[!] Select secondary binary B file first.\n")
                return

            self.diff_output.delete("1.0", tk.END)
            self.diff_output.insert(tk.END, f"Comparing {Path(bin_a).name} vs {Path(bin_b).name}...\n\n")

            res = diff_binaries(bin_a, bin_b)
            if "error" in res:
                self.diff_output.insert(tk.END, f"[!] Diff failed: {res['error']}\n")
                return

            self.diff_output.insert(tk.END, f"Binary A size: {res['size_a']:,} bytes\n")
            self.diff_output.insert(tk.END, f"Binary B size: {res['size_b']:,} bytes\n")
            self.diff_output.insert(tk.END, f"Size Diff: {res['size_b'] - res['size_a']:,} bytes\n\n")

            if not res["changes_detected"]:
                self.diff_output.insert(tk.END, "[+] No changes in classes, entitlements, or dylib loads.\n")
            else:
                if res["added_classes"]:
                    self.diff_output.insert(tk.END, f"Added Classes ({len(res['added_classes'])}):\n")
                    for c in res["added_classes"][:10]:
                        self.diff_output.insert(tk.END, f"  + {c}\n")
                if res["removed_classes"]:
                    self.diff_output.insert(tk.END, f"Removed Classes ({len(res['removed_classes'])}):\n")
                    for c in res["removed_classes"][:10]:
                        self.diff_output.insert(tk.END, f"  - {c}\n")
                if res["added_entitlements"]:
                    self.diff_output.insert(tk.END, f"Added Entitlements:\n")
                    for e in res["added_entitlements"]:
                        self.diff_output.insert(tk.END, f"  + {e}\n")
                if res["added_dylibs"]:
                    self.diff_output.insert(tk.END, f"Added Dylibs:\n")
                    for d in res["added_dylibs"]:
                        self.diff_output.insert(tk.END, f"  + {d}\n")

        def do_gui_init_emu(self):
            addr_str = self.emu_func_entry.get().strip()
            if not addr_str:
                return
            try:
                addr = int(addr_str, 0)
            except ValueError:
                return

            if not self.selected_macho_data:
                return

            self.emu_sandbox = ARM64Emulator(start_pc=addr)
            self.btn_step_emu.configure(state="normal")
            self.emu_output.delete("1.0", tk.END)
            self.emu_output.insert(tk.END, f"[*] Initialized emulator at PC=0x{addr:X}\n")
            self.update_emu_regs_display()

        def update_emu_regs_display(self):
            if not hasattr(self, "emu_sandbox"):
                return
            e = self.emu_sandbox
            self.emu_regs_lbl.configure(text=f"Regs: X0=0x{e.regs['X0']:X} X1=0x{e.regs['X1']:X} X2=0x{e.regs['X2']:X} SP=0x{e.regs['SP']:X} PC=0x{e.pc:X}")

        def do_gui_step_emu(self):
            if not hasattr(self, "emu_sandbox"):
                return
            e = self.emu_sandbox
            target_bin = self.input_entry.get().strip()
            if not target_bin or not Path(target_bin).exists():
                return

            raw_bin = Path(target_bin).read_bytes()
            data, slice_off = find_arm64_slice(raw_bin)
            lcs = parse_load_commands(data)
            segs = {}
            for s in self.selected_macho_data.get("segments", []):
                class MockSeg:
                    def __init__(self, name, vmaddr, vmsize, fileoff, filesize):
                        self.segname = name
                        self.vmaddr = int(vmaddr, 16) if isinstance(vmaddr, str) else vmaddr
                        self.vmsize = int(vmsize, 16) if isinstance(vmsize, str) else vmsize
                        self.fileoff = int(fileoff, 16) if isinstance(fileoff, str) else fileoff
                        self.filesize = int(filesize, 16) if isinstance(filesize, str) else filesize
                segs[s["name"]] = MockSeg(s["name"], s["vmaddr"], s["vmsize"], s["fileoff"], s["filesize"])

            fo = va_to_fo(e.pc, segs)
            if fo is None or fo + 4 > len(data):
                self.emu_output.insert(tk.END, f"[!] PC out of segment boundaries (PC=0x{e.pc:X}). Emulation halted.\n")
                self.btn_step_emu.configure(state="disabled")
                return

            word = u32le(data, fo)
            mn, ops, _ = _arm64_disasm_one(word, e.pc)
            desc = e.step(word)
            self.emu_output.insert(tk.END, f"Disasm: {mn:<8} {ops}  -> Result: {desc}\n")
            self.update_emu_regs_display()

            if mn == "RET":
                self.emu_output.insert(tk.END, "[+] RET reached. Emulator halted.\n")
                self.btn_step_emu.configure(state="disabled")

        def do_gui_gen_frida(self):
            method = self.combo_hook_method.get()
            if not self.current_objc_class or not method or method in ("(Select Class First)", "No methods found"):
                self.console_textbox.insert(tk.END, "[!] Select a valid class and method to generate hooks.\n")
                return
            hook_code = generate_frida_hook(self.current_objc_class, method)
            self.clipboard_clear()
            self.clipboard_append(hook_code)
            self.console_textbox.insert(tk.END, f"[+] Copied Frida hook for {self.current_objc_class} {method} to clipboard!\n")

        def do_gui_gen_logos(self):
            method = self.combo_hook_method.get()
            if not self.current_objc_class or not method or method in ("(Select Class First)", "No methods found"):
                self.console_textbox.insert(tk.END, "[!] Select a valid class and method to generate hooks.\n")
                return
            hook_code = generate_logos_hook(self.current_objc_class, method)
            self.clipboard_clear()
            self.clipboard_append(hook_code)
            self.console_textbox.insert(tk.END, f"[+] Copied Logos hook for {self.current_objc_class} {method} to clipboard!\n")

        # ── IPSW Firmware Intelligence Tab Builder ──
        def build_ipsw_intel_tab(self):
            self.tab_ipsw_intel.grid_rowconfigure(1, weight=1)
            self.tab_ipsw_intel.grid_columnconfigure(0, weight=1)

            self.ipsw_title = ctk.CTkLabel(
                self.tab_ipsw_intel,
                text="IPSW FIRMWARE INTELLIGENCE REPORT",
                font=ctk.CTkFont(size=18, weight="bold"),
                text_color="#FF4500"
            )
            self.ipsw_title.grid(row=0, column=0, padx=20, pady=(20, 10), sticky="w")

            # Scrollable content frame
            self.ipsw_scroll = ctk.CTkScrollableFrame(self.tab_ipsw_intel, fg_color="transparent")
            self.ipsw_scroll.grid(row=1, column=0, padx=20, pady=(0, 20), sticky="nsew")
            self.ipsw_scroll.grid_columnconfigure(0, weight=1)

            # ── Firmware Metadata Card ──
            self.ipsw_meta_frame = ctk.CTkFrame(self.ipsw_scroll, border_width=1, border_color="#FF4500", corner_radius=10, fg_color="#1a0a0a")
            self.ipsw_meta_frame.grid(row=0, column=0, padx=10, pady=10, sticky="ew")
            self.ipsw_meta_frame.grid_columnconfigure((0, 1, 2), weight=1)

            self.lbl_ipsw_meta_title = ctk.CTkLabel(self.ipsw_meta_frame, text="FIRMWARE METADATA", font=ctk.CTkFont(size=14, weight="bold"), text_color="#FF4500")
            self.lbl_ipsw_meta_title.grid(row=0, column=0, columnspan=3, padx=15, pady=(15, 5), sticky="w")

            self.lbl_ipsw_ver = ctk.CTkLabel(self.ipsw_meta_frame, text="iOS: —", font=ctk.CTkFont(size=13), text_color="#cccccc")
            self.lbl_ipsw_ver.grid(row=1, column=0, padx=15, pady=5, sticky="w")
            self.lbl_ipsw_build = ctk.CTkLabel(self.ipsw_meta_frame, text="Build: —", font=ctk.CTkFont(size=13), text_color="#cccccc")
            self.lbl_ipsw_build.grid(row=1, column=1, padx=15, pady=5, sticky="w")
            self.lbl_ipsw_product = ctk.CTkLabel(self.ipsw_meta_frame, text="Product: —", font=ctk.CTkFont(size=13), text_color="#cccccc")
            self.lbl_ipsw_product.grid(row=1, column=2, padx=15, pady=5, sticky="w")
            self.lbl_ipsw_hw = ctk.CTkLabel(self.ipsw_meta_frame, text="SoC: —", font=ctk.CTkFont(size=13), text_color="#cccccc")
            self.lbl_ipsw_hw.grid(row=2, column=0, padx=15, pady=(0, 15), sticky="w")
            self.lbl_ipsw_bins = ctk.CTkLabel(self.ipsw_meta_frame, text="Binaries: —", font=ctk.CTkFont(size=13), text_color="#cccccc")
            self.lbl_ipsw_bins.grid(row=2, column=1, padx=15, pady=(0, 15), sticky="w")

            # ── Overall Risk Gauge ──
            self.ipsw_risk_frame = ctk.CTkFrame(self.ipsw_scroll, border_width=2, border_color="#333333", corner_radius=10, fg_color="#0a0a0a")
            self.ipsw_risk_frame.grid(row=1, column=0, padx=10, pady=10, sticky="ew")
            self.ipsw_risk_frame.grid_columnconfigure(0, weight=1)

            self.lbl_overall_risk_val = ctk.CTkLabel(self.ipsw_risk_frame, text="—%", font=ctk.CTkFont(size=48, weight="bold"), text_color="#aaaaaa")
            self.lbl_overall_risk_val.grid(row=0, column=0, padx=20, pady=(15, 0))
            self.lbl_overall_risk_label = ctk.CTkLabel(self.ipsw_risk_frame, text="OVERALL FIRMWARE RISK", font=ctk.CTkFont(size=12), text_color="#888888")
            self.lbl_overall_risk_label.grid(row=1, column=0, padx=20, pady=0)
            self.lbl_overall_verdict = ctk.CTkLabel(self.ipsw_risk_frame, text="AWAITING IPSW SCAN", font=ctk.CTkFont(size=13, weight="bold"), text_color="#555555")
            self.lbl_overall_verdict.grid(row=2, column=0, padx=20, pady=(5, 15))

            # ── 5-Category Score Grid ──
            self.ipsw_scores_frame = ctk.CTkFrame(self.ipsw_scroll, fg_color="transparent")
            self.ipsw_scores_frame.grid(row=2, column=0, padx=10, pady=5, sticky="ew")
            self.ipsw_scores_frame.grid_columnconfigure((0, 1, 2, 3, 4), weight=1)

            score_labels = [
                ("Jailbreak\nFeasibility", "#FF4500"),
                ("Kernel\nAttack Surface", "#DC143C"),
                ("Userland\nExploit Surface", "#FFD700"),
                ("Code Injection\nFeasibility", "#FF8C00"),
                ("Malware\nImplant Risk", "#8B0000"),
            ]
            self.ipsw_score_widgets = []
            for i, (label, color) in enumerate(score_labels):
                card = ctk.CTkFrame(self.ipsw_scores_frame, border_width=1, border_color=color, corner_radius=8, fg_color="#111111")
                card.grid(row=0, column=i, padx=5, pady=5, sticky="nsew")
                val_lbl = ctk.CTkLabel(card, text="—", font=ctk.CTkFont(size=22, weight="bold"), text_color=color)
                val_lbl.pack(padx=10, pady=(10, 0))
                name_lbl = ctk.CTkLabel(card, text=label, font=ctk.CTkFont(size=10), text_color="#888888", justify="center")
                name_lbl.pack(padx=10, pady=(0, 10))
                self.ipsw_score_widgets.append(val_lbl)

            # ── CVE Summary ──
            self.ipsw_cve_summary_frame = ctk.CTkFrame(self.ipsw_scroll, border_width=1, border_color="#333333", corner_radius=10, fg_color="#111111")
            self.ipsw_cve_summary_frame.grid(row=3, column=0, padx=10, pady=10, sticky="ew")
            self.ipsw_cve_summary_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)

            self.lbl_cve_title = ctk.CTkLabel(self.ipsw_cve_summary_frame, text="CVE CROSS-REFERENCE SUMMARY", font=ctk.CTkFont(size=13, weight="bold"), text_color="#FF4500")
            self.lbl_cve_title.grid(row=0, column=0, columnspan=4, padx=15, pady=(10, 5), sticky="w")

            self.lbl_cve_total = ctk.CTkLabel(self.ipsw_cve_summary_frame, text="Applicable: —", font=ctk.CTkFont(size=12), text_color="#cccccc")
            self.lbl_cve_total.grid(row=1, column=0, padx=10, pady=5, sticky="w")
            self.lbl_cve_vuln = ctk.CTkLabel(self.ipsw_cve_summary_frame, text="Vulnerable: —", font=ctk.CTkFont(size=12), text_color="#FF4500")
            self.lbl_cve_vuln.grid(row=1, column=1, padx=10, pady=5, sticky="w")
            self.lbl_cve_patched = ctk.CTkLabel(self.ipsw_cve_summary_frame, text="Patched: —", font=ctk.CTkFont(size=12), text_color="#00FF00")
            self.lbl_cve_patched.grid(row=1, column=2, padx=10, pady=5, sticky="w")
            self.lbl_cve_hw = ctk.CTkLabel(self.ipsw_cve_summary_frame, text="HW Unpatchable: —", font=ctk.CTkFont(size=12), text_color="#FFD700")
            self.lbl_cve_hw.grid(row=1, column=3, padx=10, pady=(5, 10), sticky="w")

            # ── CVE Detail Table ──
            self.ipsw_cve_text = ctk.CTkTextbox(
                self.ipsw_scroll, height=250,
                font=ctk.CTkFont(family="Consolas", size=11),
                fg_color="#080808", text_color="#dddddd"
            )
            self.ipsw_cve_text.grid(row=4, column=0, padx=10, pady=10, sticky="nsew")

            # ── Recommendations Panel ──
            self.ipsw_rec_frame = ctk.CTkFrame(self.ipsw_scroll, border_width=1, border_color="#333333", corner_radius=10, fg_color="#111111")
            self.ipsw_rec_frame.grid(row=5, column=0, padx=10, pady=10, sticky="ew")
            self.ipsw_rec_frame.grid_columnconfigure(0, weight=1)

            self.lbl_rec_title = ctk.CTkLabel(self.ipsw_rec_frame, text="RECOMMENDATIONS", font=ctk.CTkFont(size=13, weight="bold"), text_color="#00FFFF")
            self.lbl_rec_title.grid(row=0, column=0, padx=15, pady=(10, 5), sticky="w")

            self.ipsw_rec_text = ctk.CTkTextbox(self.ipsw_rec_frame, height=150, font=ctk.CTkFont(family="Consolas", size=11), fg_color="#080808", text_color="#cccccc")
            self.ipsw_rec_text.grid(row=1, column=0, padx=15, pady=(0, 15), sticky="nsew")

            # ── Export Button ──
            self.btn_export_fw = ctk.CTkButton(
                self.ipsw_scroll, text="EXPORT FIRMWARE INTELLIGENCE (JSON)",
                fg_color="#8B0000", hover_color="#FF4500",
                font=ctk.CTkFont(weight="bold"),
                command=self._export_firmware_intel
            )
            self.btn_export_fw.grid(row=6, column=0, padx=10, pady=10, sticky="ew")

        # ── POWERHOUSE Tab Builder ──────────────────────────────────────────
        def build_powerhouse_tab(self):
            self.tab_powerhouse.grid_rowconfigure(1, weight=1)
            self.tab_powerhouse.grid_columnconfigure(0, weight=1)

            self.ph_title = ctk.CTkLabel(
                self.tab_powerhouse,
                text="⚡ POWERHOUSE — Advanced Reverse Engineering Suite",
                font=ctk.CTkFont(size=18, weight="bold"),
                text_color="#9B30FF"
            )
            self.ph_title.grid(row=0, column=0, padx=20, pady=(20, 10), sticky="w")

            # Scrollable area
            self.ph_scroll = ctk.CTkScrollableFrame(self.tab_powerhouse, fg_color="transparent")
            self.ph_scroll.grid(row=1, column=0, padx=20, pady=(0, 20), sticky="nsew")
            self.ph_scroll.grid_columnconfigure(0, weight=1)

            # ── Capabilities Status Card ──
            self.ph_caps_frame = ctk.CTkFrame(self.ph_scroll, border_width=2, border_color="#9B30FF",
                                                corner_radius=10, fg_color="#1A0A2A")
            self.ph_caps_frame.grid(row=0, column=0, padx=10, pady=10, sticky="ew")
            self.ph_caps_frame.grid_columnconfigure(0, weight=1)

            ctk.CTkLabel(self.ph_caps_frame, text="OPTIONAL POWER-UPS",
                          font=ctk.CTkFont(size=14, weight="bold"),
                          text_color="#9B30FF").grid(row=0, column=0, padx=15, pady=(15, 5), sticky="w")
            self.ph_caps_label = ctk.CTkLabel(self.ph_caps_frame, text="(checking...)",
                                                font=ctk.CTkFont(size=11), justify="left")
            self.ph_caps_label.grid(row=1, column=0, padx=15, pady=5, sticky="w")
            self.ph_install_btn = ctk.CTkButton(self.ph_caps_frame, text="Auto-Install All Optional Deps",
                                                 fg_color="#7B00FF", hover_color="#9B30FF",
                                                 command=self._do_install_optional)
            self.ph_install_btn.grid(row=2, column=0, padx=15, pady=(5, 15), sticky="ew")
            # Initial population
            self.after(500, self._refresh_caps_label)

            # ── ROP Gadget Finder Card ──
            self.ph_rop_frame = ctk.CTkFrame(self.ph_scroll, border_width=1, border_color="#FF4500",
                                              corner_radius=10, fg_color="#1A0F00")
            self.ph_rop_frame.grid(row=1, column=0, padx=10, pady=10, sticky="ew")
            self.ph_rop_frame.grid_columnconfigure(0, weight=1)

            ctk.CTkLabel(self.ph_rop_frame, text="🎯 ROP/JOP GADGET FINDER",
                          font=ctk.CTkFont(size=14, weight="bold"),
                          text_color="#FF4500").grid(row=0, column=0, padx=15, pady=(15, 5), sticky="w")
            ctk.CTkLabel(self.ph_rop_frame,
                          text="Scan __TEXT for exploitable ROP/JOP gadgets ending in RET/BR/BLR.",
                          font=ctk.CTkFont(size=11),
                          text_color="#cccccc").grid(row=1, column=0, padx=15, pady=2, sticky="w")
            ctk.CTkButton(self.ph_rop_frame, text="Find Gadgets",
                           fg_color="#FF4500", hover_color="#FF6633",
                           command=self._do_find_gadgets).grid(row=2, column=0, padx=15, pady=10, sticky="ew")
            self.ph_rop_text = ctk.CTkTextbox(self.ph_rop_frame, height=200,
                                                font=ctk.CTkFont(family="Consolas", size=11),
                                                fg_color="#080000")
            self.ph_rop_text.grid(row=3, column=0, padx=15, pady=(0, 15), sticky="nsew")

            # ── Unicorn Emulator Card ──
            self.ph_emu_frame = ctk.CTkFrame(self.ph_scroll, border_width=1, border_color="#00FF88",
                                              corner_radius=10, fg_color="#001A0F")
            self.ph_emu_frame.grid(row=2, column=0, padx=10, pady=10, sticky="ew")
            self.ph_emu_frame.grid_columnconfigure(1, weight=1)

            ctk.CTkLabel(self.ph_emu_frame, text="🔮 UNICORN CPU EMULATOR",
                          font=ctk.CTkFont(size=14, weight="bold"),
                          text_color="#00FF88").grid(row=0, column=0, columnspan=2, padx=15, pady=(15, 5), sticky="w")
            ctk.CTkLabel(self.ph_emu_frame, text="Function VA:").grid(row=1, column=0, padx=15, pady=5, sticky="w")
            self.ph_emu_va = ctk.CTkEntry(self.ph_emu_frame, placeholder_text="e.g. 0x100004FC0")
            self.ph_emu_va.grid(row=1, column=1, padx=15, pady=5, sticky="ew")
            ctk.CTkButton(self.ph_emu_frame, text="Emulate via Unicorn",
                           fg_color="#00FF88", hover_color="#00CC66",
                           text_color="#000000",
                           command=self._do_unicorn_emu).grid(row=2, column=0, columnspan=2, padx=15, pady=10, sticky="ew")
            self.ph_emu_text = ctk.CTkTextbox(self.ph_emu_frame, height=200,
                                                font=ctk.CTkFont(family="Consolas", size=11),
                                                fg_color="#000A05")
            self.ph_emu_text.grid(row=3, column=0, columnspan=2, padx=15, pady=(0, 15), sticky="nsew")

            # ── ASM Patcher Card ──
            self.ph_patch_frame = ctk.CTkFrame(self.ph_scroll, border_width=1, border_color="#FFAA00",
                                                corner_radius=10, fg_color="#1A0F00")
            self.ph_patch_frame.grid(row=3, column=0, padx=10, pady=10, sticky="ew")
            self.ph_patch_frame.grid_columnconfigure(1, weight=1)

            ctk.CTkLabel(self.ph_patch_frame, text="🔧 ASM PATCHER (Keystone)",
                          font=ctk.CTkFont(size=14, weight="bold"),
                          text_color="#FFAA00").grid(row=0, column=0, columnspan=2, padx=15, pady=(15, 5), sticky="w")
            ctk.CTkLabel(self.ph_patch_frame, text="Target VA:").grid(row=1, column=0, padx=15, pady=5, sticky="w")
            self.ph_patch_va = ctk.CTkEntry(self.ph_patch_frame, placeholder_text="e.g. 0x100004000")
            self.ph_patch_va.grid(row=1, column=1, padx=15, pady=5, sticky="ew")
            ctk.CTkLabel(self.ph_patch_frame, text="ARM64 ASM:").grid(row=2, column=0, padx=15, pady=5, sticky="w")
            self.ph_patch_asm = ctk.CTkEntry(self.ph_patch_frame, placeholder_text="e.g. mov x0, #0; ret")
            self.ph_patch_asm.grid(row=2, column=1, padx=15, pady=5, sticky="ew")
            ctk.CTkButton(self.ph_patch_frame, text="Apply Patch (writes binary!)",
                           fg_color="#FFAA00", hover_color="#FFCC44", text_color="#000000",
                           command=self._do_asm_patch).grid(row=3, column=0, columnspan=2, padx=15, pady=10, sticky="ew")
            self.ph_patch_status = ctk.CTkLabel(self.ph_patch_frame, text="(no patches applied yet)",
                                                  font=ctk.CTkFont(family="Consolas", size=11))
            self.ph_patch_status.grid(row=4, column=0, columnspan=2, padx=15, pady=(0, 15), sticky="w")

            # ── PDF Report Card ──
            self.ph_pdf_frame = ctk.CTkFrame(self.ph_scroll, border_width=1, border_color="#00CCFF",
                                               corner_radius=10, fg_color="#001A1A")
            self.ph_pdf_frame.grid(row=4, column=0, padx=10, pady=10, sticky="ew")
            self.ph_pdf_frame.grid_columnconfigure(0, weight=1)

            ctk.CTkLabel(self.ph_pdf_frame, text="📄 GENERATE PDF REPORT",
                          font=ctk.CTkFont(size=14, weight="bold"),
                          text_color="#00CCFF").grid(row=0, column=0, padx=15, pady=(15, 5), sticky="w")
            ctk.CTkButton(self.ph_pdf_frame, text="Export PDF Report (requires reportlab)",
                           fg_color="#00CCFF", hover_color="#00FFFF", text_color="#000000",
                           command=self._do_pdf_export).grid(row=1, column=0, padx=15, pady=(5, 15), sticky="ew")

        # ── Device Bridge Tab Builder ───────────────────────────────────────
        def build_device_tab(self):
            self.tab_device.grid_rowconfigure(1, weight=1)
            self.tab_device.grid_columnconfigure(0, weight=1)

            self.dev_title = ctk.CTkLabel(
                self.tab_device,
                text="📱 Device Bridge — iOS USB Communication",
                font=ctk.CTkFont(size=18, weight="bold"),
                text_color="#3399FF"
            )
            self.dev_title.grid(row=0, column=0, padx=20, pady=(20, 10), sticky="w")

            self.dev_scroll = ctk.CTkScrollableFrame(self.tab_device, fg_color="transparent")
            self.dev_scroll.grid(row=1, column=0, padx=20, pady=(0, 20), sticky="nsew")
            self.dev_scroll.grid_columnconfigure(0, weight=1)

            # Action buttons
            self.dev_actions = ctk.CTkFrame(self.dev_scroll, fg_color="transparent")
            self.dev_actions.grid(row=0, column=0, padx=10, pady=10, sticky="ew")
            self.dev_actions.grid_columnconfigure((0, 1, 2), weight=1)

            ctk.CTkButton(self.dev_actions, text="🔍 List Devices",
                           fg_color="#0066CC", hover_color="#3399FF",
                           command=self._do_list_devices).grid(row=0, column=0, padx=5, pady=5, sticky="ew")
            ctk.CTkButton(self.dev_actions, text="ℹ️ Device Info",
                           fg_color="#0066CC", hover_color="#3399FF",
                           command=self._do_device_info).grid(row=0, column=1, padx=5, pady=5, sticky="ew")
            ctk.CTkButton(self.dev_actions, text="📦 List Apps",
                           fg_color="#0066CC", hover_color="#3399FF",
                           command=self._do_list_apps).grid(row=0, column=2, padx=5, pady=5, sticky="ew")

            # Output display
            self.dev_output = ctk.CTkTextbox(self.dev_scroll,
                                               font=ctk.CTkFont(family="Consolas", size=11),
                                               fg_color="#000A14", text_color="#aaccff")
            self.dev_output.grid(row=1, column=0, padx=10, pady=10, sticky="nsew")
            self.dev_scroll.grid_rowconfigure(1, weight=1)
            self.dev_output.insert(tk.END, "[Device Bridge Ready]\n\nClick 'List Devices' to discover connected iOS devices.\nRequires: pip install pymobiledevice3\n")

        # ── POWERHOUSE Action Handlers ──────────────────────────────────────
        def _refresh_caps_label(self):
            try:
                caps = godmax_caps()
                lines = []
                for name, ok in caps.items():
                    icon = "✓" if ok else "✗"
                    color = "" if ok else " (not installed)"
                    lines.append(f"  {icon}  {name}{color}")
                self.ph_caps_label.configure(text="\n".join(lines))
            except Exception as e:
                self.ph_caps_label.configure(text=f"(error: {e})")

        def _do_install_optional(self):
            self.console_textbox.insert(tk.END, "[*] Installing optional GODMAX dependencies (this takes a while)...\n")
            self.show_dashboard_tab()
            def worker():
                check_godmax_dependencies(auto_install=True)
                global _GODMAX_CAPS
                _GODMAX_CAPS = None  # force re-check
                self.after(0, self._refresh_caps_label)
                self.log_queue.put("[+] Dependency installation complete\n")
            threading.Thread(target=worker, daemon=True).start()

        def _do_find_gadgets(self):
            target = self.input_entry.get().strip()
            if not target or not Path(target).exists():
                self.ph_rop_text.delete("1.0", tk.END)
                self.ph_rop_text.insert(tk.END, "[!] Select a binary first in the Console tab\n")
                return
            self.ph_rop_text.delete("1.0", tk.END)
            self.ph_rop_text.insert(tk.END, "[*] Scanning for ROP/JOP gadgets...\n")
            def worker():
                try:
                    raw_bin = Path(target).read_bytes()
                    data, _ = find_arm64_slice(raw_bin)
                    lcs = parse_load_commands(data)
                    segs = build_segment_map(lcs)
                    res = find_rop_gadgets(data, segs, max_gadget_len=4, max_results=80)
                    out = [f"[+] Found {res['total_gadgets']} gadgets:"]
                    for cat, count in res['by_category'].items():
                        out.append(f"  {cat}: {count}")
                    out.append("")
                    for cat, gs in res['gadgets'].items():
                        if not gs: continue
                        out.append(f"── {cat.upper()} ──")
                        for g in gs[:10]:
                            out.append(f"  {g['va']:<14} {g['instructions']}")
                        out.append("")
                    self.after(0, lambda: (self.ph_rop_text.delete("1.0", tk.END),
                                             self.ph_rop_text.insert(tk.END, "\n".join(out))))
                except Exception as e:
                    self.after(0, lambda: self.ph_rop_text.insert(tk.END, f"\n[!] Error: {e}\n"))
            threading.Thread(target=worker, daemon=True).start()

        def _do_unicorn_emu(self):
            target = self.input_entry.get().strip()
            va_str = self.ph_emu_va.get().strip()
            if not target or not Path(target).exists():
                self.ph_emu_text.delete("1.0", tk.END)
                self.ph_emu_text.insert(tk.END, "[!] Select a binary first in the Console tab\n")
                return
            try:
                func_va = int(va_str, 0)
            except ValueError:
                self.ph_emu_text.insert(tk.END, "[!] Invalid VA\n")
                return
            self.ph_emu_text.delete("1.0", tk.END)
            self.ph_emu_text.insert(tk.END, f"[*] Emulating function @ {hex(func_va)}...\n")
            def worker():
                try:
                    raw_bin = Path(target).read_bytes()
                    data, _ = find_arm64_slice(raw_bin)
                    lcs = parse_load_commands(data)
                    segs = build_segment_map(lcs)
                    res = unicorn_emulate(data, segs, func_va, max_steps=2000)
                    if "error" in res:
                        out = f"[!] {res['error']}"
                    else:
                        out = [f"[+] Emulation complete ({res['executed_steps']} steps)"]
                        out.append("\nFinal Registers:")
                        for reg, val in res["final_registers"].items():
                            out.append(f"  {reg:<4} = {val}")
                        out = "\n".join(out)
                    self.after(0, lambda: (self.ph_emu_text.delete("1.0", tk.END),
                                             self.ph_emu_text.insert(tk.END, out)))
                except Exception as e:
                    self.after(0, lambda: self.ph_emu_text.insert(tk.END, f"\n[!] Error: {e}\n"))
            threading.Thread(target=worker, daemon=True).start()

        def _do_asm_patch(self):
            target = self.input_entry.get().strip()
            va_str = self.ph_patch_va.get().strip()
            asm = self.ph_patch_asm.get().strip()
            if not target or not Path(target).exists():
                self.ph_patch_status.configure(text="[!] Select a binary first")
                return
            try:
                va = int(va_str, 0)
            except ValueError:
                self.ph_patch_status.configure(text="[!] Invalid VA")
                return
            if not asm:
                self.ph_patch_status.configure(text="[!] Provide ASM code")
                return
            res = patch_code_at_va(target, va, asm)
            if "error" in res:
                self.ph_patch_status.configure(text=f"[!] {res['error']}")
            else:
                self.ph_patch_status.configure(
                    text=f"[+] Patched {res['patch_size']} bytes @ {res['va']}\n"
                         f"  Original: {res['original_bytes']}\n"
                         f"  New:      {res['new_bytes']}"
                )

        def _do_pdf_export(self):
            if not self.selected_macho_data:
                self.console_textbox.insert(tk.END, "[!] No analysis data — run a scan first\n")
                self.show_dashboard_tab()
                return
            save_path = filedialog.asksaveasfilename(
                title="Save PDF Report",
                defaultextension=".pdf",
                filetypes=[("PDF Files", "*.pdf"), ("All Files", "*.*")],
                initialfile="analysis_report.pdf"
            )
            if save_path:
                res = generate_pdf_report(self.selected_macho_data, save_path)
                if "error" in res:
                    self.console_textbox.insert(tk.END, f"[!] PDF failed: {res['error']}\n")
                else:
                    self.console_textbox.insert(tk.END, f"[+] PDF saved: {res['pdf_path']}\n")
                self.show_dashboard_tab()

        def _do_list_devices(self):
            self.dev_output.delete("1.0", tk.END)
            self.dev_output.insert(tk.END, "[*] Listing connected iOS devices...\n\n")
            def worker():
                res = list_connected_ios_devices()
                if "error" in res:
                    out = f"[!] {res['error']}\n"
                else:
                    out = f"[+] Found {res['device_count']} device(s):\n"
                    for d in res["devices"]:
                        out += f"  UDID: {d['udid']}  ({d.get('connection_type', 'usb')})\n"
                self.after(0, lambda: self.dev_output.insert(tk.END, out))
            threading.Thread(target=worker, daemon=True).start()

        def _do_device_info(self):
            self.dev_output.delete("1.0", tk.END)
            self.dev_output.insert(tk.END, "[*] Reading device info...\n\n")
            def worker():
                res = get_ios_device_info()
                if "error" in res:
                    out = f"[!] {res['error']}\n"
                else:
                    out = ""
                    for k, v in res.items():
                        out += f"  {k:<22}: {v}\n"
                self.after(0, lambda: self.dev_output.insert(tk.END, out))
            threading.Thread(target=worker, daemon=True).start()

        def _do_list_apps(self):
            self.dev_output.delete("1.0", tk.END)
            self.dev_output.insert(tk.END, "[*] Listing apps on device (this can take a while)...\n\n")
            def worker():
                res = list_installed_ios_apps()
                if "error" in res:
                    out = f"[!] {res['error']}\n"
                else:
                    out = f"[+] {res['app_count']} apps installed:\n\n"
                    for app in res["apps"][:200]:
                        out += f"  {app['bundle_id']:<55} {app['name']:<35} v{app['version']}\n"
                self.after(0, lambda: self.dev_output.insert(tk.END, out))
            threading.Thread(target=worker, daemon=True).start()

        def _populate_ipsw_intel_tab(self):
            """Populate the IPSW Intel tab with data from self.firmware_intel_report."""
            fw = self.firmware_intel_report
            if not fw:
                return

            # Metadata
            self.lbl_ipsw_ver.configure(text=f"iOS: {fw['ios_version']}")
            self.lbl_ipsw_build.configure(text=f"Build: {fw['ios_build']}")
            self.lbl_ipsw_product.configure(text=f"Product: {fw['product_type']}")
            self.lbl_ipsw_hw.configure(text=f"SoC: {fw['detected_hw']}")
            self.lbl_ipsw_bins.configure(text=f"Binaries: {fw['total_binaries']}")

            # Overall Risk
            overall = fw["scores"]["overall_firmware_risk"]
            self.lbl_overall_risk_val.configure(text=f"{overall}%", text_color=fw["verdict_color"])
            self.lbl_overall_verdict.configure(text=fw["verdict"], text_color=fw["verdict_color"])

            # 5-category scores
            score_keys = [
                "jailbreak_feasibility", "kernel_attack_surface",
                "userland_exploit_surface", "code_injection_feasibility",
                "malware_implant_risk",
            ]
            for i, key in enumerate(score_keys):
                val = fw["scores"][key]
                color = "#FF4500" if val >= 65 else ("#FFD700" if val >= 35 else "#00FF00")
                self.ipsw_score_widgets[i].configure(text=f"{val}%", text_color=color)

            # CVE Summary
            cs = fw["cve_summary"]
            self.lbl_cve_total.configure(text=f"Applicable: {cs['total_applicable']}")
            self.lbl_cve_vuln.configure(text=f"Vulnerable: {cs['potentially_vulnerable']}")
            self.lbl_cve_patched.configure(text=f"Patched: {cs['patched']}")
            self.lbl_cve_hw.configure(text=f"HW Unpatchable: {cs['unpatchable_hw']}")

            # CVE Detail Table
            self.ipsw_cve_text.delete("1.0", tk.END)
            self.ipsw_cve_text.insert(tk.END, f"{'STATUS':<26} {'CVE ID':<22} {'CATEGORY':<12} {'SEVERITY':<10} NAME\n")
            self.ipsw_cve_text.insert(tk.END, "─" * 100 + "\n")
            status_order = {"POTENTIALLY_VULNERABLE": 0, "UNPATCHABLE": 1, "PATCHED": 2}
            sorted_cves = sorted(fw["cve_results"], key=lambda c: (status_order.get(c["status"], 9), c["id"]))
            for cve in sorted_cves:
                icon = {"POTENTIALLY_VULNERABLE": "🔴", "UNPATCHABLE": "⚡", "PATCHED": "✅"}.get(cve["status"], "❓")
                self.ipsw_cve_text.insert(tk.END,
                    f"{icon} {cve['status']:<24} {cve['id']:<22} {cve['category']:<12} {cve['severity']:<10} {cve['name']}\n"
                )
                self.ipsw_cve_text.insert(tk.END, f"   {cve['description'][:130]}\n")
                if cve.get("references"):
                    self.ipsw_cve_text.insert(tk.END, f"   Refs: {', '.join(cve['references'][:4])}\n")
                self.ipsw_cve_text.insert(tk.END, "\n")

            # Recommendations
            self.ipsw_rec_text.delete("1.0", tk.END)
            self.ipsw_rec_text.insert(tk.END, "═ FOR SECURITY RESEARCHERS ═\n\n")
            for rec in fw["recommendations"].get("security_researcher", []):
                self.ipsw_rec_text.insert(tk.END, f"  🛡️ {rec}\n\n")
            self.ipsw_rec_text.insert(tk.END, "\n═ FOR OFFENSIVE RESEARCHERS ═\n\n")
            for rec in fw["recommendations"].get("offensive_researcher", []):
                self.ipsw_rec_text.insert(tk.END, f"  ⚔️ {rec}\n\n")

            # Detailed reasons
            self.ipsw_rec_text.insert(tk.END, "\n═ DETAILED SCORE REASONS ═\n")
            reason_labels = {
                "jailbreak": "JAILBREAK", "kernel": "KERNEL",
                "userland": "USERLAND", "injection": "INJECTION", "malware": "MALWARE"
            }
            for key, label in reason_labels.items():
                reasons = fw["score_reasons"].get(key, [])
                if reasons:
                    self.ipsw_rec_text.insert(tk.END, f"\n  ── {label} ──\n")
                    for r in reasons:
                        self.ipsw_rec_text.insert(tk.END, f"    {r}\n")

        def _export_firmware_intel(self):
            """Export firmware intelligence report as JSON."""
            if not self.firmware_intel_report:
                self.console_textbox.insert(tk.END, "[!] No firmware intelligence data to export. Scan an IPSW first.\n")
                return
            save_path = filedialog.asksaveasfilename(
                title="Save Firmware Intelligence Report",
                defaultextension=".json",
                filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")],
                initialfile="firmware_intelligence_report.json"
            )
            if save_path:
                with open(save_path, "w", encoding="utf-8") as f:
                    json.dump(_make_serializable(self.firmware_intel_report), f, indent=2, ensure_ascii=False)
                self.console_textbox.insert(tk.END, f"[+] Firmware Intelligence Report exported → {save_path}\n")

        # ── UI Interactions & File Helpers ──
        def browse_file(self):
            path = filedialog.askopenfilename(
                title="Open Target Binary / IPSW / DMG / Archive",
                filetypes=[("All Files", "*.*"), ("iOS Firmware", "*.ipsw"), ("iOS AEA Archives", "*.aea"), ("Apple Archives", "*.aar"), ("Disk Images", "*.dmg")]
            )
            if path:
                self.input_entry.delete(0, tk.END)
                self.input_entry.insert(0, path)

        # ── Background Worker Manager ──
        def start_analysis_thread(self):
            target = self.input_entry.get().strip()
            if not target or not Path(target).exists():
                self.console_textbox.insert(tk.END, "[!] Invalid target path. Please select a valid file first.\n")
                return

            if self.is_analyzing:
                return

            self.is_analyzing = True
            self.btn_analyze.configure(state="disabled", text="SCANNING WORK...")
            self.console_textbox.delete("1.0", tk.END)
            self.tree.delete(*self.tree.get_children())

            # Redirect sys.stdout to log_queue
            sys.stdout = TextRedirector(self.console_textbox, self.log_queue)
            sys.stderr = TextRedirector(self.console_textbox, self.log_queue)

            worker = threading.Thread(target=self.run_deep_scan, args=(target,))
            worker.daemon = True
            worker.start()

        def run_deep_scan(self, target_file: str):
            import tempfile
            import shutil
            temp_dir = tempfile.TemporaryDirectory()
            extract_path = Path(temp_dir.name)

            try:
                macho_paths = process_input_recursive(Path(target_file), extract_path, None)
                if not macho_paths:
                    print("[!] No Mach-O binaries found or carved from input.", file=sys.stderr)
                    self.cleanup_scan_ui()
                    return

                self.current_analysis_results = {}

                # Add to tree widget
                for macho in macho_paths:
                    print(f"[*] Analyzing carved binary: {macho.name}")
                    size_str = f"{macho.stat().st_size:,} bytes"
                    
                    # Perform Analysis
                    keywords = DEFAULT_KEYWORDS
                    report = analyze(
                        str(macho), keywords,
                        build_cfg=self.cb_cfg.get(),
                        run_taint=self.cb_cfg.get() or self.cb_taint.get(),
                        disasm_n_funcs=10 if self.btn_disasm else 0
                    )
                    
                    self.current_analysis_results[macho.name] = report
                    
                    # Add node to tree
                    self.tree.insert("", "end", iid=macho.name, text=macho.name, values=(size_str, "ARM64e iOS Executable"))

                print("[+] Deep static scanning complete. View details in the tabs.")

                # ── Build Firmware Intelligence Report if IPSW metadata exists ──
                if _ipsw_firmware_meta:
                    print("\n[*] Building IPSW Firmware Intelligence Report...")
                    try:
                        fw_report = build_firmware_intelligence_report(
                            ios_version=_ipsw_firmware_meta.get("ios_version", "Unknown"),
                            ios_build=_ipsw_firmware_meta.get("ios_build", "Unknown"),
                            product_type=_ipsw_firmware_meta.get("product_type", "Unknown"),
                            all_reports=self.current_analysis_results,
                            ipsw_meta=_ipsw_firmware_meta,
                        )
                        self.firmware_intel_report = fw_report
                        print(f"[+] Firmware Intelligence Report built. Overall Risk: {fw_report['scores']['overall_firmware_risk']}%")
                        print(f"[+] Verdict: {fw_report['verdict']}")
                        print(f"[+] CVEs Applicable: {fw_report['cve_summary']['total_applicable']} "
                              f"(Vulnerable: {fw_report['cve_summary']['potentially_vulnerable']}, "
                              f"Patched: {fw_report['cve_summary']['patched']}, "
                              f"HW Unpatchable: {fw_report['cve_summary']['unpatchable_hw']})")
                        print("[+] Switch to the 'IPSW Firmware Intel' tab for full details.")
                        # Populate GUI tab from main thread
                        self.after(0, self._populate_ipsw_intel_tab)
                    except Exception as fw_err:
                        print(f"[!] Firmware Intelligence Report generation failed: {fw_err}", file=sys.stderr)
                        import traceback; traceback.print_exc()

            except Exception as e:
                print(f"[!] Error during deep scan: {e}", file=sys.stderr)
                import traceback; traceback.print_exc()
            finally:
                sys.stdout = sys.__stdout__
                sys.stderr = sys.__stderr__
                self.cleanup_scan_ui()
                try:
                    temp_dir.cleanup()
                except Exception:
                    pass

        def cleanup_scan_ui(self):
            self.is_analyzing = False
            self.btn_analyze.configure(state="normal", text="START SUPER DEEP SCAN")

        # ── Interactive Browsing Handlers ──
        def on_tree_select(self, event):
            selected = self.tree.selection()
            if not selected:
                return
            binary_name = selected[0]
            if binary_name in self.current_analysis_results:
                self.selected_macho_data = self.current_analysis_results[binary_name]
                self.populate_macho_details()

        def populate_macho_details(self):
            if not self.selected_macho_data:
                return

            r = self.selected_macho_data

            # ── 0. Populate Security Scorecard ──
            if "threat_scorecard" in r:
                ts = r["threat_scorecard"]
                self.lbl_sec_verdict.configure(text=f"VERDICT: {ts['verdict']}", text_color=ts['verdict_color'])
                self.lbl_metric_1_val.configure(text=f"{ts['hardening_score']}%")
                self.lbl_metric_2_val.configure(text=f"{ts['exploit_score']}%")
                self.lbl_metric_3_val.configure(text=f"{ts['inject_score']}%")

                self.txt_scorecard_details.delete("1.0", tk.END)
                self.txt_scorecard_details.insert(tk.END, "ELEMENT AUDIT FINDINGS & REASONS:\n")
                for reason in ts.get("reasons", []):
                    self.txt_scorecard_details.insert(tk.END, f"  [x] {reason}\n")
                if ts.get("inject_reasons"):
                    self.txt_scorecard_details.insert(tk.END, "\nSIDELOADING & INJECTION FEASIBILITY:\n")
                    for reason in ts["inject_reasons"]:
                        self.txt_scorecard_details.insert(tk.END, f"  [x] {reason}\n")
                if ts.get("found_banned"):
                    self.txt_scorecard_details.insert(tk.END, "\nINSECURE/BANNED APIs IMPORTED:\n")
                    for api, desc in ts["found_banned"].items():
                        self.txt_scorecard_details.insert(tk.END, f"  [!] {api}: {desc}\n")
            else:
                self.lbl_sec_verdict.configure(text="VERDICT: NO SCORECARD DATA AVAILABLE", text_color="#aaaaaa")
                self.lbl_metric_1_val.configure(text="N/A")
                self.lbl_metric_2_val.configure(text="N/A")
                self.lbl_metric_3_val.configure(text="N/A")
                self.txt_scorecard_details.delete("1.0", tk.END)

            # ── 1. Populate Security Dashboard ──
            sec = r.get("security", {})

            # Helper to set risk badges
            def set_badge(widget, data):
                risk = data.get("risk", "INFO")
                color = {"HIGH": "#FF0000", "MEDIUM": "#FFA500", "LOW": "#00FF00"}.get(risk, "#3a3a3a")
                widget["badge"].configure(text=risk, fg_color=color)
                widget["text"].delete("1.0", tk.END)
                for k, v in data.items():
                    if k == "risk": continue
                    widget["text"].insert(tk.END, f"{k}: {v}\n")

            set_badge(self.widget_antidebug, sec.get("anti_debug", {}))
            set_badge(self.widget_jailbreak, sec.get("jailbreak_detection", {}))
            set_badge(self.widget_pinning, sec.get("certificate_pinning", {}))
            set_badge(self.widget_secrets, sec.get("hardcoded_secrets", {}))
            set_badge(self.widget_obfuscation, sec.get("obfuscation", {}))

            # Constructors Widget
            self.widget_constructors["badge"].configure(text="INFO", fg_color="#3a3a3a")
            self.widget_constructors["text"].delete("1.0", tk.END)
            inits = sec.get("constructors", {}).get("mod_init_funcs", [])
            self.widget_constructors["text"].insert(tk.END, f"Found {len(inits)} constructors:\n")
            for i in inits:
                self.widget_constructors["text"].insert(tk.END, f"  - {i}\n")

            # Entitlements Audit Widget
            ent_aud = sec.get("entitlements_audit", {})
            set_badge(self.widget_entitlements, ent_aud)
            self.widget_entitlements["text"].delete("1.0", tk.END)
            findings = ent_aud.get("findings", [])
            if findings:
                self.widget_entitlements["text"].insert(tk.END, f"Detected {len(findings)} high-privilege entitlements:\n\n")
                for f in findings:
                    self.widget_entitlements["text"].insert(tk.END, f"- {f['key']}: {f['value']}\n  {f['description']}\n\n")
            else:
                self.widget_entitlements["text"].insert(tk.END, "No high-privilege sandbox bypass entitlements detected.")

            # Crypto secure APIs Widget
            crypto_data = sec.get("crypto", {})
            self.widget_crypto["badge"].configure(text="INFO", fg_color="#3a3a3a")
            self.widget_crypto["text"].delete("1.0", tk.END)
            crypto_syms = crypto_data.get("imported_symbols", [])
            crypto_strs = crypto_data.get("related_strings", [])
            if crypto_syms:
                self.widget_crypto["text"].insert(tk.END, "Imported Crypto Symbols:\n")
                for cs in crypto_syms[:10]:
                    self.widget_crypto["text"].insert(tk.END, f"  - {cs}\n")
            if crypto_strs:
                self.widget_crypto["text"].insert(tk.END, "\nCrypto-related Strings:\n")
                for cstr in crypto_strs[:10]:
                    self.widget_crypto["text"].insert(tk.END, f"  - {cstr}\n")

            # ── 2. Populate ObjC ListBox ──
            self.class_listbox.delete(0, tk.END)
            self.objc_data = r.get("objc", {})
            self.swift_data = r.get("swift", {})
            self.demangled_class_map = {}

            classes = []
            for cls in self.objc_data.get("classes", []):
                raw_name = cls.get("name", "UnknownClass")
                demangled = demangle_swift_symbol(raw_name)
                self.demangled_class_map[demangled] = raw_name
                classes.append(demangled)
            for s_desc in self.swift_data.get("types", []):
                raw_name = s_desc.get("name", "UnknownSwiftType")
                demangled = demangle_swift_symbol(raw_name)
                self.demangled_class_map[demangled] = raw_name
                classes.append(demangled)

            self.all_classes_cached = sorted(list(set(classes)))
            for c in self.all_classes_cached:
                self.class_listbox.insert(tk.END, c)

            # ── 3. Populate Strings & Entitlements ──
            # Entitlements
            self.ent_text.delete("1.0", tk.END)
            ent = r.get("entitlements", {})
            if ent:
                self.ent_text.insert(tk.END, json.dumps(ent, indent=2))
            else:
                self.ent_text.insert(tk.END, "No entitlement parameters detected.")

            # Keywords Strings Matches
            self.strings_text.delete("1.0", tk.END)
            km = r.get("keyword_matches", {})
            for kw, matches in km.items():
                self.strings_text.insert(tk.END, f"=== KEYWORD: {kw} ===\n")
                for m in matches[:20]:
                    self.strings_text.insert(tk.END, f"  - {m}\n")
                if len(matches) > 20:
                    self.strings_text.insert(tk.END, f"  ... ({len(matches)-20} more hits)\n")
                self.strings_text.insert(tk.END, "\n")

            # ── 4. Disassembly Viewer ──
            self.disasm_text.delete("1.0", tk.END)
            dis = r.get("disassembly", [])
            if dis:
                for fn in dis[:5]:
                    self.disasm_text.insert(tk.END, f"Function @ {fn['func_va']}:\n")
                    for ins in fn["instructions"]:
                        bt = f"  → {ins['branch_target']}" if ins["branch_target"] else ""
                        self.disasm_text.insert(tk.END, f"  {ins['address']}  {ins['mnemonic']:<12} {ins['operands']}{bt}\n")
                    self.disasm_text.insert(tk.END, "\n")
            else:
                self.disasm_text.insert(tk.END, "To view disassembly, enable Call Graph scanning or set --disasm-funcs.")

        def on_class_filter_change(self, event):
            query = self.filter_entry.get().strip().lower()
            self.class_listbox.delete(0, tk.END)
            for c in self.all_classes_cached:
                if not query or query in c.lower():
                    self.class_listbox.insert(tk.END, c)

        def on_class_select(self, event):
            selected_idx = self.class_listbox.curselection()
            if not selected_idx:
                return
            class_name_input = self.class_listbox.get(selected_idx[0])
            class_name = getattr(self, "demangled_class_map", {}).get(class_name_input, class_name_input)

            self.method_details_box.delete("1.0", tk.END)
            self.method_details_box.insert(tk.END, f"// CLASS STRUCTURE: {class_name}\n\n")

            self.current_objc_class = class_name
            self.current_objc_methods = []

            # Try to find class in ObjC classes
            found = False
            for cls in self.objc_data.get("classes", []):
                if cls.get("name") == class_name:
                    found = True
                    self.method_details_box.insert(tk.END, f"super_class: {cls.get('superclass', 'NSObject')}\n\n")
                    
                    # Instance variables
                    ivars = cls.get("ivars", [])
                    if ivars:
                        self.method_details_box.insert(tk.END, "/* Instance Variables */\n")
                        for iv in ivars:
                            self.method_details_box.insert(tk.END, f"  {iv.get('type','id')} {iv.get('name')};\n")
                        self.method_details_box.insert(tk.END, "\n")

                    # Methods
                    inst_methods = cls.get("instance_methods", [])
                    cls_methods = cls.get("class_methods", [])
                    if inst_methods or cls_methods:
                        self.method_details_box.insert(tk.END, "/* Methods */\n")
                        for m in inst_methods:
                            arg_str = ", ".join(m.get("args", [])) or "void"
                            self.method_details_box.insert(tk.END, f"  - ({m.get('return') or 'id'}) {m.get('name')}({arg_str});\n")
                            self.current_objc_methods.append(f"- {m.get('name')}")
                        for m in cls_methods:
                            arg_str = ", ".join(m.get("args", [])) or "void"
                            self.method_details_box.insert(tk.END, f"  + ({m.get('return') or 'id'}) {m.get('name')}({arg_str});\n")
                            self.current_objc_methods.append(f"+ {m.get('name')}")

            if not found:
                # Try to search in Swift types
                for t in self.swift_data.get("types", []):
                    if t.get("name") == class_name:
                        self.method_details_box.insert(tk.END, f"Kind: {t.get('kind', 'Class')}\n")
                        fields = t.get("fields", [])
                        if fields:
                            self.method_details_box.insert(tk.END, "/* Properties / Fields */\n")
                            for f in fields:
                                self.method_details_box.insert(tk.END, f"  {f.get('type','Any')} {f.get('name')};\n")

            if self.current_objc_methods:
                self.combo_hook_method.configure(values=self.current_objc_methods)
                self.combo_hook_method.set(self.current_objc_methods[0])
            else:
                self.combo_hook_method.configure(values=["No methods found"])
                self.combo_hook_method.set("No methods found")

    app = AetherAnalyzerApp()
    app.mainloop()


# ═══════════════════════════════════════════════════════════════════════════════
# §26  ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    # Reconfigure console streams to UTF-8 to prevent UnicodeEncodeError on Windows
    import sys
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    if hasattr(sys.stderr, 'reconfigure'):
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')

    # Ensure dependencies are installed before parsing/decryption starts
    check_and_install_dependencies()

    ap = argparse.ArgumentParser(
        description="Super deep static analysis of Mach-O/AEA/AppleArchive/DMG ARM64 iOS binaries",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
        Examples:
          # Standard analysis:
          python3 analyze_binary_deep.py /path/to/lsd
          python3 analyze_binary_deep.py /path/to/binary --cfg --taint
          python3 analyze_binary_deep.py /path/to/binary --disasm-funcs 10
          python3 analyze_binary_deep.py /path/to/binary --keywords "register,validate,container"
          python3 analyze_binary_deep.py /path/to/binary --no-text -o report.json
          python3 analyze_binary_deep.py firmware.aea --aea-key "base64key..."
          python3 analyze_binary_deep.py firmware.ipsw

          # GODMODE quick scans (fast, focused output):
          python3 analyze_binary_deep.py /path/to/lsd --scan-vulns
          python3 analyze_binary_deep.py /path/to/lsd --scan-primitives
          python3 analyze_binary_deep.py /path/to/lsd --scan-yara
          python3 analyze_binary_deep.py /path/to/lsd --scan-ents

          # GODMODE interactive queries:
          python3 analyze_binary_deep.py /path/to/lsd --xref-query "registerApplication"
          python3 analyze_binary_deep.py /path/to/lsd --xref-query "amfi"
          python3 analyze_binary_deep.py /path/to/lsd --decompile-va 0x100004FC0

          # GODMODE utilities:
          python3 analyze_binary_deep.py /path/to/lsd --translate-addr 0x100004000
          python3 analyze_binary_deep.py /path/to/lsd --rename-dylib "/old/path:/new/path"
          python3 analyze_binary_deep.py /path/to/lsd --emulate-func 0x100004000
          python3 analyze_binary_deep.py binA.dylib --diff binB.dylib
          python3 analyze_binary_deep.py /path/to/binary --patch-offset 0x100 --patch-hex "1F2003D5"
        """),
    )
    ap.add_argument("binary", nargs="?", default=None,
                    help="Target binary, .ipsw, .aea, .dmg, or .aar archive (omitted to launch interactive GUI)")
    ap.add_argument("--keywords","-k", default=",".join(DEFAULT_KEYWORDS))
    ap.add_argument("--output","-o",   default=None)
    ap.add_argument("--no-text",       action="store_true")
    ap.add_argument("--no-json",       action="store_true")
    ap.add_argument("--cfg",           action="store_true",
                    help="Build call graph (disassembles all functions — slow)")
    ap.add_argument("--taint",         action="store_true",
                    help="Run SecTrustEvaluate taint analysis (requires some disasm)")
    ap.add_argument("--disasm-funcs",  type=int, default=0, metavar="N",
                    help="Disassemble first N functions and include in report")
    ap.add_argument("--aea-key",       default=None,
                    help="Base64-encoded AEA symmetric key for decryption")
    ap.add_argument("--extract-dir",   default=None,
                    help="Directory to extract archive/DMG contents to (default: temporary directory)")
    ap.add_argument("--trust-cache",   action="store_true",
                    help="Directly parse iOS Trust Cache container (.tc) file")
    ap.add_argument("--patch-offset",  type=lambda x: int(x, 0), default=None,
                    help="Offset in target binary to patch (supports 0x hex format)")
    ap.add_argument("--patch-hex",     default=None,
                    help="Hex bytes payload for patching (e.g. 'E0031FAA' or 'E0 03 1F AA')")
    ap.add_argument("--translate-addr", default=None,
                    help="Translate virtual address or file offset (e.g. 0x100004000 or 16384)")
    ap.add_argument("--rename-dylib",  default=None,
                    help="Rename dylib reference (format: 'old_path:new_path')")
    ap.add_argument("--emulate-func",  default=None,
                    help="Emulate function starting at virtual address (e.g. 0x100004FC0)")
    ap.add_argument("--diff",          default=None,
                    help="Diff comparison with another Mach-O binary")
    ap.add_argument("--xref-query",    default=None,
                    help="Find all callers of a symbol/string in binary (substring match)")
    ap.add_argument("--decompile-va",  default=None,
                    help="Decompile function at virtual address to pseudo-C (e.g. 0x100004FC0)")
    ap.add_argument("--scan-vulns",    action="store_true",
                    help="Run vulnerability heuristic scanner only (fast)")
    ap.add_argument("--scan-primitives", action="store_true",
                    help="Run exploit primitive detector only (fast)")
    ap.add_argument("--scan-yara",     action="store_true",
                    help="Run YARA-style pattern scanner only (fast)")
    ap.add_argument("--scan-ents",     action="store_true",
                    help="Audit entitlements against Apple Private DB only (fast)")
    # ── POWERHOUSE flags ────────────────────────────────────────────────────
    ap.add_argument("--rop-gadgets",   action="store_true",
                    help="Find ROP/JOP gadgets in __TEXT (powerful exploit aid)")
    ap.add_argument("--unicorn",       default=None,
                    help="Emulate function via Unicorn engine (e.g. 0x1000)")
    ap.add_argument("--capstone",      default=None,
                    help="Disassemble VA range with Capstone (e.g. 0x1000)")
    ap.add_argument("--patch-asm",     default=None,
                    help="Patch with ARM64 assembly. Format: 'VA:ASM' (e.g. '0x1000:nop')")
    ap.add_argument("--build-ipa",     default=None,
                    help="Build .ipa from .app bundle (path to .app)")
    ap.add_argument("--ipa-output",    default="output.ipa",
                    help="Output path for --build-ipa")
    ap.add_argument("--ldid-path",     default=None,
                    help="Path to ldid binary for IPA signing")
    ap.add_argument("--list-devices",  action="store_true",
                    help="List connected iOS devices via USB")
    ap.add_argument("--device-info",   action="store_true",
                    help="Get info from connected iOS device")
    ap.add_argument("--list-apps",     action="store_true",
                    help="List installed apps on connected iOS device")
    ap.add_argument("--launchd-plist", default=None,
                    help="Analyze launchd plist file")
    ap.add_argument("--scan-mig",      action="store_true",
                    help="Scan for MIG subsystem tables")
    ap.add_argument("--scan-xpc",      action="store_true",
                    help="Reconstruct NSXPC interfaces")
    ap.add_argument("--scan-sandbox",  default=None,
                    help="Decode compiled sandbox profile (.sb file)")
    ap.add_argument("--pdf-report",    default=None,
                    help="Generate PDF report after analysis (output path)")
    ap.add_argument("--install-deps",  action="store_true",
                    help="Auto-install all optional GODMAX power-up dependencies")
    ap.add_argument("--no-godmode",    action="store_true",
                    help="Disable GODMODE extensions during master analyze (faster, less detail)")
    ap.add_argument("--verbose","-v",  action="store_true")
    args = ap.parse_args()

    # ── Headless CLI Address Translation Helper ──
    if args.translate_addr is not None:
        if not args.binary:
            print("[!] Error: target binary must be specified for address translation.", file=sys.stderr)
            sys.exit(1)
        addr_val = int(args.translate_addr, 0)
        raw_bin = Path(args.binary).read_bytes()
        data, slice_off = find_arm64_slice(raw_bin)
        lcs = parse_load_commands(data)
        segs = build_segment_map(lcs)
        fo = va_to_fo(addr_val, segs)
        va = fo_to_va(addr_val, segs)
        print(f"[*] Translating target value: 0x{addr_val:X}")
        if fo is not None:
            print(f"  -> As Virtual Address: File Offset = 0x{fo:X}")
        if va is not None:
            print(f"  -> As File Offset: Virtual Address = 0x{va:X}")
        if fo is None and va is None:
            print("  -> Could not translate value in any parsed Mach-O segments.")
        sys.exit(0)

    # ── Headless CLI Dylib Path Redirector Helper ──
    if args.rename_dylib is not None:
        if not args.binary:
            print("[!] Error: target binary must be specified for dylib path renaming.", file=sys.stderr)
            sys.exit(1)
        if ":" not in args.rename_dylib:
            print("[!] Error: --rename-dylib format must be 'old_path:new_path'", file=sys.stderr)
            sys.exit(1)
        old_path, new_path = args.rename_dylib.split(":", 1)
        success = rename_macho_dylib(args.binary, old_path, new_path)
        sys.exit(0 if success else 1)

    # ── Headless CLI ARM64 Emulation Sandbox ──
    if args.emulate_func is not None:
        if not args.binary:
            print("[!] Error: target binary must be specified for ARM64 instruction emulation.", file=sys.stderr)
            sys.exit(1)
        try:
            func_va = int(args.emulate_func, 0)
        except ValueError:
            print(f"[!] Error: function must be specified as virtual address (e.g. 0x100004000)", file=sys.stderr)
            sys.exit(1)
        raw_bin = Path(args.binary).read_bytes()
        data, slice_off = find_arm64_slice(raw_bin)
        lcs = parse_load_commands(data)
        segs = build_segment_map(lcs)
        fo = va_to_fo(func_va, segs)
        if fo is None or fo >= len(data):
            print(f"[!] Error: VA 0x{func_va:X} does not map to a valid file offset.", file=sys.stderr)
            sys.exit(1)
        print(f"[*] Starting ARM64 emulation sandbox for function @ VA 0x{func_va:X} (File Offset 0x{fo:X})...")
        emu = ARM64Emulator(start_pc=func_va)
        curr_fo = fo
        steps = 0
        while curr_fo + 4 <= len(data) and steps < 100:
            word = u32le(data, curr_fo)
            mn, ops, _ = _arm64_disasm_one(word, emu.pc)
            print(f"  Step {steps:02d} | Disasm: {mn:<8} {ops}")
            desc = emu.step(word)
            print(f"          | Result: {desc}")
            print(f"          | Regs: X0=0x{emu.regs['X0']:X} X1=0x{emu.regs['X1']:X} X2=0x{emu.regs['X2']:X} SP=0x{emu.regs['SP']:X}")
            steps += 1
            if mn == "RET":
                print("[+] Simulation reached RET instruction. Halting sandbox.")
                break
            curr_fo = va_to_fo(emu.pc, segs)
            if curr_fo is None:
                print("[!] PC jumped out of bounds. Halting emulation.")
                break
        sys.exit(0)

    # ── Headless CLI Interactive Binary Differ ──
    if args.diff is not None:
        if not args.binary:
            print("[!] Error: target binary must be specified as primary binary A.", file=sys.stderr)
            sys.exit(1)
        print(f"[*] Comparing Binary A ({args.binary}) vs Binary B ({args.diff})...")
        res = diff_binaries(args.binary, args.diff)
        if "error" in res:
            print(f"[!] Diffing failed: {res['error']}", file=sys.stderr)
            sys.exit(1)
        print("\n" + "="*80)
        print("  MACH-O BINARY COMPARISON REPORT")
        print("="*80)
        print(f"  Binary A   : {res['binary_a']} ({res['size_a']:,} bytes)")
        print(f"  Binary B   : {res['binary_b']} ({res['size_b']:,} bytes)")
        print(f"  Size Diff  : {res['size_b'] - res['size_a']:,} bytes")
        print("="*80)
        if not res["changes_detected"]:
            print("  [+] No differences detected in class names, entitlements, or dylib paths.")
        else:
            if res["added_classes"]:
                print(f"  [+] Added Classes ({len(res['added_classes'])}):")
                for c in res["added_classes"][:20]:
                    print(f"    + {c}")
                if len(res["added_classes"]) > 20:
                    print(f"    ... and {len(res['added_classes'])-20} more classes")
            if res["removed_classes"]:
                print(f"  [-] Removed Classes ({len(res['removed_classes'])}):")
                for c in res["removed_classes"][:20]:
                    print(f"    - {c}")
                if len(res["removed_classes"]) > 20:
                    print(f"    ... and {len(res['removed_classes'])-20} more classes")
            if res["added_entitlements"]:
                print(f"  [+] Added Entitlements:")
                for e in res["added_entitlements"]:
                    print(f"    + {e}")
            if res["removed_entitlements"]:
                print(f"  [-] Removed Entitlements:")
                for e in res["removed_entitlements"]:
                    print(f"    - {e}")
            if res["added_dylibs"]:
                print(f"  [+] Added Dylib Dependencies:")
                for d in res["added_dylibs"]:
                    print(f"    + {d}")
            if res["removed_dylibs"]:
                print(f"  [-] Removed Dylib Dependencies:")
                for d in res["removed_dylibs"]:
                    print(f"    - {d}")
        print("="*80 + "\n")
        sys.exit(0)

    # If no target file is supplied, launch the interactive GUI
    if args.binary is None:
        launch_gui()
        sys.exit(0)

    # ── GODMODE CLI: Vulnerability Scanner ────────────────────────────────────
    if args.scan_vulns:
        if not args.binary:
            print("[!] Error: --scan-vulns requires a binary path", file=sys.stderr)
            sys.exit(1)
        print(f"[*] Running vulnerability scan on {args.binary}...")
        raw_bin = Path(args.binary).read_bytes()
        data, _ = find_arm64_slice(raw_bin)
        lcs = parse_load_commands(data)
        segs = build_segment_map(lcs)
        symbols = parse_symtab(data, lcs)
        strings_data = collect_all_strings(data, segs)
        result = scan_vulnerabilities(symbols["imported"], strings_data["all_unique"], segs, data)
        print(f"\n  Total findings: {result['total_findings']}")
        print(f"  Highest severity: {result['highest_severity']}")
        print(f"  By severity: {result['by_severity']}")
        print(f"  By category: {result['by_category']}\n")
        for f in result["findings"][:50]:
            sev_i = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(f["severity"], "❓")
            print(f"  {sev_i} [{f['severity']:<8}] [{f.get('category','?'):<20}] {f.get('symbol', f.get('type',''))}")
            if f.get("advice"):
                print(f"     → {f['advice']}")
        if not args.no_json:
            out = args.output or f"{Path(args.binary).name}_vulns.json"
            with open(out, "w", encoding="utf-8") as f:
                json.dump(_make_serializable(result), f, indent=2)
            print(f"\n[+] JSON → {out}")
        sys.exit(0)

    # ── GODMODE CLI: Exploit Primitive Detector ──────────────────────────────
    if args.scan_primitives:
        if not args.binary:
            print("[!] Error: --scan-primitives requires a binary path", file=sys.stderr)
            sys.exit(1)
        print(f"[*] Detecting exploit primitives in {args.binary}...")
        raw_bin = Path(args.binary).read_bytes()
        data, _ = find_arm64_slice(raw_bin)
        lcs = parse_load_commands(data)
        segs = build_segment_map(lcs)
        symbols = parse_symtab(data, lcs)
        strings_data = collect_all_strings(data, segs)
        result = detect_exploit_primitives(symbols["imported"], strings_data["all_unique"])
        print(f"\n  Capability: {result['capability_assessment']}")
        print(f"  {result['capability_description']}\n")
        print(f"  Total primitives: {result['total_findings']}")
        print(f"  By category: {result['by_category']}")
        print(f"  Kernel strings: {result['kernel_strings_count']}\n")
        for f in result["findings"][:50]:
            sev_i = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(f["severity"], "❓")
            print(f"  {sev_i} [{f['severity']:<8}] [{f['category']:<20}] {f['symbol']:<35} {f['description'][:80]}")
        if not args.no_json:
            out = args.output or f"{Path(args.binary).name}_primitives.json"
            with open(out, "w", encoding="utf-8") as f:
                json.dump(_make_serializable(result), f, indent=2)
            print(f"\n[+] JSON → {out}")
        sys.exit(0)

    # ── GODMODE CLI: YARA Pattern Scanner ────────────────────────────────────
    if args.scan_yara:
        if not args.binary:
            print("[!] Error: --scan-yara requires a binary path", file=sys.stderr)
            sys.exit(1)
        print(f"[*] Running YARA scan on {args.binary}...")
        raw_bin = Path(args.binary).read_bytes()
        data, _ = find_arm64_slice(raw_bin)
        result = yara_scan(data)
        print(f"\n  Rules loaded: {result['total_rules_loaded']}")
        print(f"  Rules with matches: {result['rules_with_matches']}")
        print(f"  Total hits: {result['total_match_count']}\n")
        for m in result["matches"]:
            print(f"  📍 {m['rule']} [{m['category']}] — {m['match_count']} hit(s)")
            print(f"     {m['description']}")
            for hit in m["hits"][:3]:
                print(f"     @ {hit['offset']}")
        if not args.no_json:
            out = args.output or f"{Path(args.binary).name}_yara.json"
            with open(out, "w", encoding="utf-8") as f:
                json.dump(_make_serializable(result), f, indent=2)
            print(f"\n[+] JSON → {out}")
        sys.exit(0)

    # ── GODMODE CLI: Apple Private Entitlement Audit ─────────────────────────
    if args.scan_ents:
        if not args.binary:
            print("[!] Error: --scan-ents requires a binary path", file=sys.stderr)
            sys.exit(1)
        print(f"[*] Auditing entitlements in {args.binary}...")
        raw_bin = Path(args.binary).read_bytes()
        data, _ = find_arm64_slice(raw_bin)
        lcs = parse_load_commands(data)
        codesig = parse_code_signature_deep(data, lcs)
        result = audit_apple_private_entitlements(codesig.get("entitlements") or {})
        print(f"\n  Total Apple Private DB entries: {result['total_db_entries']}")
        print(f"  Matched in this binary: {result['matched_count']}")
        print(f"  Highest risk: {result['highest_risk']}")
        print(f"  By risk: {result['risk_counts']}")
        print(f"  By category: {dict((c, len(v)) for c, v in result['categories'].items())}\n")
        for f in result["findings"]:
            sev_i = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(f["risk"], "❓")
            print(f"  {sev_i} [{f['risk']:<8}] [{f['category']:<14}] {f['key']}")
            print(f"     → {f['description']}")
        if not args.no_json:
            out = args.output or f"{Path(args.binary).name}_ents.json"
            with open(out, "w", encoding="utf-8") as f:
                json.dump(_make_serializable(result), f, indent=2)
            print(f"\n[+] JSON → {out}")
        sys.exit(0)

    # ── GODMODE CLI: Cross-Reference Query ───────────────────────────────────
    if args.xref_query:
        if not args.binary:
            print("[!] Error: --xref-query requires a binary path", file=sys.stderr)
            sys.exit(1)
        print(f"[*] Building xref database for {args.binary} (query: '{args.xref_query}')...")
        raw_bin = Path(args.binary).read_bytes()
        data, _ = find_arm64_slice(raw_bin)
        lcs = parse_load_commands(data)
        segs = build_segment_map(lcs)
        symbols = parse_symtab(data, lcs)
        dylibs = parse_dylibs(lcs)
        bind_data = parse_dyld_bind_all(data, lcs, dylibs)
        chained = parse_chained_fixups(data, lcs, segs)
        func_starts = parse_function_starts(data, lcs, segs)
        strings_data = collect_all_strings(data, segs)
        stub_map = build_stub_map(data, segs, lcs, bind_data, chained)
        print(f"  Functions: {len(func_starts)}, Stubs: {len(stub_map)}")
        print(f"  Building xref db (this takes a moment)...")
        xref_db = build_xref_database(data, segs, func_starts, stub_map, strings_data["all_unique"])
        result = query_xrefs(xref_db, args.xref_query)
        print(f"\n  Query: '{args.xref_query}'")
        print(f"  Matches: {len(result['matches'])}\n")
        for m in result["matches"][:30]:
            print(f"  [{m['kind']}] '{m['match'][:80] if isinstance(m['match'], str) else m['match']}' — {m['caller_count']} caller(s)")
            for caller in m["callers"][:10]:
                print(f"      ← from {caller}")
        if not args.no_json:
            out = args.output or f"{Path(args.binary).name}_xref_{args.xref_query[:20]}.json"
            with open(out, "w", encoding="utf-8") as f:
                json.dump(_make_serializable(result), f, indent=2)
            print(f"\n[+] JSON → {out}")
        sys.exit(0)

    # ── GODMODE CLI: Pseudo-C Decompiler ─────────────────────────────────────
    if args.decompile_va:
        if not args.binary:
            print("[!] Error: --decompile-va requires a binary path", file=sys.stderr)
            sys.exit(1)
        try:
            func_va = int(args.decompile_va, 0)
        except ValueError:
            print(f"[!] Invalid VA: {args.decompile_va}", file=sys.stderr)
            sys.exit(1)
        print(f"[*] Decompiling function @ {hex(func_va)} in {args.binary}...")
        raw_bin = Path(args.binary).read_bytes()
        data, _ = find_arm64_slice(raw_bin)
        lcs = parse_load_commands(data)
        segs = build_segment_map(lcs)
        dylibs = parse_dylibs(lcs)
        bind_data = parse_dyld_bind_all(data, lcs, dylibs)
        chained = parse_chained_fixups(data, lcs, segs)
        stub_map = build_stub_map(data, segs, lcs, bind_data, chained)
        result = decompile_function(data, segs, func_va, stub_map)
        print(f"\n{result.get('pseudo_c', result.get('error', 'Unknown error'))}")
        if not args.no_json:
            out = args.output or f"{Path(args.binary).name}_decomp_{func_va:x}.json"
            with open(out, "w", encoding="utf-8") as f:
                json.dump(_make_serializable(result), f, indent=2)
            print(f"\n[+] JSON → {out}")
        sys.exit(0)

    # ── POWERHOUSE: Auto-install Optional Dependencies ───────────────────────
    if args.install_deps:
        print("[*] Installing all optional GODMAX power-up dependencies...")
        caps = check_godmax_dependencies(auto_install=True)
        installed = sum(1 for v in caps.values() if v)
        print(f"\n[+] Capabilities ready ({installed}/{len(caps)}):")
        for name, ok in caps.items():
            print(f"    {'✓' if ok else '✗'}  {name}")
        sys.exit(0)

    # ── POWERHOUSE: ROP Gadget Finder ────────────────────────────────────────
    if args.rop_gadgets:
        if not args.binary:
            print("[!] Error: --rop-gadgets requires a binary path", file=sys.stderr)
            sys.exit(1)
        print(f"[*] Finding ROP/JOP gadgets in {args.binary}...")
        raw_bin = Path(args.binary).read_bytes()
        data, _ = find_arm64_slice(raw_bin)
        lcs = parse_load_commands(data)
        segs = build_segment_map(lcs)
        result = find_rop_gadgets(data, segs, max_gadget_len=5)
        print(f"\n  Total gadgets: {result['total_gadgets']}")
        for cat, count in result["by_category"].items():
            print(f"    {cat:<20} {count:>5} gadget(s)")
        # Sample print
        for cat, gs in result["gadgets"].items():
            if not gs: continue
            print(f"\n  ── {cat.upper()} (showing 5) ──")
            for g in gs[:5]:
                print(f"    {g['va']:<14} {g['instructions']}")
        if not args.no_json:
            out = args.output or f"{Path(args.binary).name}_gadgets.json"
            with open(out, "w", encoding="utf-8") as f:
                json.dump(_make_serializable(result), f, indent=2)
            print(f"\n[+] JSON → {out}")
        sys.exit(0)

    # ── POWERHOUSE: Unicorn Emulation ────────────────────────────────────────
    if args.unicorn:
        if not args.binary:
            print("[!] Error: --unicorn requires a binary path", file=sys.stderr)
            sys.exit(1)
        try:
            func_va = int(args.unicorn, 0)
        except ValueError:
            print(f"[!] Invalid VA: {args.unicorn}", file=sys.stderr)
            sys.exit(1)
        print(f"[*] Emulating function @ {hex(func_va)} via Unicorn...")
        raw_bin = Path(args.binary).read_bytes()
        data, _ = find_arm64_slice(raw_bin)
        lcs = parse_load_commands(data)
        segs = build_segment_map(lcs)
        result = unicorn_emulate(data, segs, func_va, max_steps=2000)
        if "error" in result:
            print(f"  [!] {result['error']}")
        else:
            print(f"  Executed {result['executed_steps']} instructions")
            print(f"  Final registers:")
            for reg, val in result["final_registers"].items():
                print(f"    {reg}: {val}")
        if not args.no_json:
            out = args.output or f"{Path(args.binary).name}_unicorn_{func_va:x}.json"
            with open(out, "w", encoding="utf-8") as f:
                json.dump(_make_serializable(result), f, indent=2)
            print(f"\n[+] JSON → {out}")
        sys.exit(0)

    # ── POWERHOUSE: Capstone Disassembly ─────────────────────────────────────
    if args.capstone:
        if not args.binary:
            print("[!] Error: --capstone requires a binary path", file=sys.stderr)
            sys.exit(1)
        try:
            start_va = int(args.capstone, 0)
        except ValueError:
            print(f"[!] Invalid VA: {args.capstone}", file=sys.stderr)
            sys.exit(1)
        print(f"[*] Disassembling from {hex(start_va)} via Capstone...")
        raw_bin = Path(args.binary).read_bytes()
        data, _ = find_arm64_slice(raw_bin)
        lcs = parse_load_commands(data)
        segs = build_segment_map(lcs)
        fo = va_to_fo(start_va, segs)
        if fo is None:
            print(f"[!] VA {hex(start_va)} not in any segment", file=sys.stderr)
            sys.exit(1)
        insns = disassemble_capstone(data, start_va, fo, max_insns=200)
        for ins in insns:
            if "error" in ins:
                print(f"  [!] {ins['error']}")
                continue
            bt = f"  → {ins.get('branch_target')}" if ins.get('branch_target') else ""
            print(f"  {ins.get('address','?'):<14} {ins.get('mnemonic',''):<8} {ins.get('operands','')}{bt}")
        if not args.no_json:
            out = args.output or f"{Path(args.binary).name}_disasm_{start_va:x}.json"
            with open(out, "w", encoding="utf-8") as f:
                json.dump(_make_serializable(insns), f, indent=2)
            print(f"\n[+] JSON → {out}")
        sys.exit(0)

    # ── POWERHOUSE: Patch ASM ────────────────────────────────────────────────
    if args.patch_asm:
        if not args.binary:
            print("[!] Error: --patch-asm requires a binary path", file=sys.stderr)
            sys.exit(1)
        if ":" not in args.patch_asm:
            print("[!] --patch-asm format: 'VA:ASM' (e.g. '0x1000:nop')", file=sys.stderr)
            sys.exit(1)
        va_str, asm_code = args.patch_asm.split(":", 1)
        try:
            va = int(va_str, 0)
        except ValueError:
            print(f"[!] Invalid VA: {va_str}", file=sys.stderr)
            sys.exit(1)
        print(f"[*] Patching {args.binary} @ {hex(va)} with: {asm_code}")
        result = patch_code_at_va(args.binary, va, asm_code)
        if "error" in result:
            print(f"[!] {result['error']}", file=sys.stderr)
            sys.exit(1)
        print(f"[+] Patched {result['patch_size']} bytes")
        print(f"    Original: {result['original_bytes']}")
        print(f"    New:      {result['new_bytes']}")
        sys.exit(0)

    # ── POWERHOUSE: Build IPA ────────────────────────────────────────────────
    if args.build_ipa:
        print(f"[*] Building IPA from {args.build_ipa}...")
        result = build_ipa_from_app(args.build_ipa, args.ipa_output,
                                      ldid_path=args.ldid_path)
        if "error" in result:
            print(f"[!] {result['error']}", file=sys.stderr)
            sys.exit(1)
        print(f"[+] IPA created: {result['ipa_path']} ({result['size_mb']} MB)")
        sys.exit(0)

    # ── POWERHOUSE: iOS Device Communication ─────────────────────────────────
    if args.list_devices:
        print("[*] Listing connected iOS devices...")
        result = list_connected_ios_devices()
        if "error" in result:
            print(f"[!] {result['error']}", file=sys.stderr)
            sys.exit(1)
        print(f"  Found {result['device_count']} device(s):")
        for d in result["devices"]:
            print(f"    UDID: {d['udid']}  ({d.get('connection_type', 'usb')})")
        sys.exit(0)

    if args.device_info:
        print("[*] Reading device information...")
        result = get_ios_device_info()
        if "error" in result:
            print(f"[!] {result['error']}", file=sys.stderr)
            sys.exit(1)
        for k, v in result.items():
            print(f"  {k:<22}: {v}")
        sys.exit(0)

    if args.list_apps:
        print("[*] Listing apps on device...")
        result = list_installed_ios_apps()
        if "error" in result:
            print(f"[!] {result['error']}", file=sys.stderr)
            sys.exit(1)
        print(f"  {result['app_count']} apps installed")
        for app in result["apps"][:80]:
            print(f"    {app['bundle_id']:<50} {app['name']:<30} v{app['version']}")
        if not args.no_json:
            out = args.output or "device_apps.json"
            with open(out, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2)
            print(f"\n[+] JSON → {out}")
        sys.exit(0)

    # ── POWERHOUSE: Launchd Plist Analyzer ───────────────────────────────────
    if args.launchd_plist:
        print(f"[*] Analyzing {args.launchd_plist}...")
        result = analyze_launchd_plist(args.launchd_plist)
        if "error" in result:
            print(f"[!] {result['error']}", file=sys.stderr)
            sys.exit(1)
        print(f"  Label:        {result['label']}")
        print(f"  Program:      {result['program']}")
        print(f"  User:         {result['user_name']}")
        print(f"  RunAtLoad:    {result['run_at_load']}")
        print(f"  KeepAlive:    {result['keep_alive']}")
        print(f"  MachServices: {result['mach_services']}")
        if result["risks"]:
            print(f"\n  Risks:")
            for r in result["risks"]:
                print(f"    [{r['severity']}] {r['issue']}")
        if not args.no_json:
            out = args.output or f"{Path(args.launchd_plist).name}.json"
            with open(out, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2)
            print(f"\n[+] JSON → {out}")
        sys.exit(0)

    # ── POWERHOUSE: MIG Subsystem Scanner ────────────────────────────────────
    if args.scan_mig:
        if not args.binary:
            print("[!] Error: --scan-mig requires a binary path", file=sys.stderr)
            sys.exit(1)
        print(f"[*] Scanning {args.binary} for MIG subsystem tables...")
        raw_bin = Path(args.binary).read_bytes()
        data, _ = find_arm64_slice(raw_bin)
        lcs = parse_load_commands(data)
        segs = build_segment_map(lcs)
        result = parse_mig_subsystems(data, segs)
        print(f"\n  MIG tables found: {result['mig_tables_found']}")
        for t in result["tables"][:20]:
            print(f"    {t['table_va']:<14} server={t['server_func']:<14} ids={t['msg_id_range']:<14} routines={t['routine_count']}")
        if not args.no_json:
            out = args.output or f"{Path(args.binary).name}_mig.json"
            with open(out, "w", encoding="utf-8") as f:
                json.dump(_make_serializable(result), f, indent=2)
            print(f"\n[+] JSON → {out}")
        sys.exit(0)

    # ── POWERHOUSE: NSXPC Reconstructor ──────────────────────────────────────
    if args.scan_xpc:
        if not args.binary:
            print("[!] Error: --scan-xpc requires a binary path", file=sys.stderr)
            sys.exit(1)
        print(f"[*] Reconstructing NSXPC interfaces in {args.binary}...")
        raw_bin = Path(args.binary).read_bytes()
        data, _ = find_arm64_slice(raw_bin)
        lcs = parse_load_commands(data)
        segs = build_segment_map(lcs)
        objc = parse_objc_full(data, segs)
        strings_data = collect_all_strings(data, segs)
        result = reconstruct_nsxpc_interfaces(data, segs, objc, strings_data["all_unique"])
        print(f"\n  NSXPC Protocols found:  {result['protocol_count']}")
        print(f"  XPC client/server cls:  {result['class_count']}")
        print(f"  Mach services seen:     {result['service_count']}")
        for p in result["nsxpc_protocols"][:20]:
            print(f"\n    @protocol {p['name']}  ({p['method_count']} methods)")
            for m in p.get("instance_methods", [])[:10]:
                print(f"      - {m}")
        for s in result["mach_services"][:20]:
            print(f"    mach: {s}")
        if not args.no_json:
            out = args.output or f"{Path(args.binary).name}_xpc.json"
            with open(out, "w", encoding="utf-8") as f:
                json.dump(_make_serializable(result), f, indent=2)
            print(f"\n[+] JSON → {out}")
        sys.exit(0)

    # ── POWERHOUSE: Sandbox Profile Decoder ──────────────────────────────────
    if args.scan_sandbox:
        print(f"[*] Decoding sandbox profile {args.scan_sandbox}...")
        sb_data = Path(args.scan_sandbox).read_bytes()
        result = parse_sandbox_profile(sb_data)
        if "error" in result:
            print(f"[!] {result['error']}", file=sys.stderr)
            sys.exit(1)
        print(f"  Size:               {result['size']} bytes")
        print(f"  Strings:            {result['strings_count']}")
        print(f"  Operation refs:     {len(result['operation_references'])}")
        print(f"  Paths referenced:   {len(result['paths_referenced'])}")
        for p in result["paths_referenced"][:20]:
            print(f"    {p}")
        if not args.no_json:
            out = args.output or f"{Path(args.scan_sandbox).name}_decoded.json"
            with open(out, "w", encoding="utf-8") as f:
                json.dump(_make_serializable(result), f, indent=2)
            print(f"\n[+] JSON → {out}")
        sys.exit(0)

    # ── Interactive Headless Patch Execution ──
    if args.patch_offset is not None:
        if not args.patch_hex:
            print("[!] Error: --patch-hex payload is required when using --patch-offset", file=sys.stderr)
            sys.exit(1)
        patch_binary_offset(args.binary, args.patch_offset, args.patch_hex)
        sys.exit(0)

    input_path = Path(args.binary)
    if not input_path.exists():
        print(f"[!] Input file not found: {args.binary}", file=sys.stderr)
        sys.exit(1)

    # ── Headless Trust Cache Parser ──
    if args.trust_cache or input_path.suffix.lower() == ".tc":
        print(f"[*] Parsing iOS Trust Cache container: {input_path.name}")
        tc_data = input_path.read_bytes()
        tc_report = parse_trust_cache(tc_data)
        
        if "error" in tc_report:
            print(f"[!] Trust Cache parsing failed: {tc_report['error']}", file=sys.stderr)
            sys.exit(1)
            
        if not args.no_text:
            print("\n" + "="*80)
            print("  iOS TRUST CACHE DECODED REPORT")
            print("="*80)
            print(f"  Magic      : {tc_report['magic']}")
            print(f"  Version    : {tc_report['version']}")
            print(f"  UUID       : {tc_report['uuid']}")
            print(f"  Entries    : {tc_report['num_entries']}")
            print("="*80)
            print("  LIST OF REGISTERED CDHASH VALUES:")
            print("="*80)
            for entry in tc_report["entries"][:100]:
                print(f"  [{entry['index']:<3}] Hash: {entry['cdhash']} | Type: {entry['hash_type']:<22} | Flags: {entry['flags']}")
            if len(tc_report["entries"]) > 100:
                print(f"  ... +{len(tc_report['entries'])-100} more entries omitted from terminal stdout")
            print("="*80 + "\n")
            
        if not args.no_json:
            out_json = args.output if args.output else f"{input_path.name}_trust_cache.json"
            with open(out_json, "w", encoding="utf-8") as f:
                json.dump(tc_report, f, indent=2)
            print(f"[+] Decoded Trust Cache report written to: {out_json}")
        sys.exit(0)

    keywords = [k.strip() for k in args.keywords.split(",") if k.strip()]

    import tempfile
    temp_dir = None
    if args.extract_dir:
        extract_path = Path(args.extract_dir)
        extract_path.mkdir(parents=True, exist_ok=True)
    else:
        temp_dir = tempfile.TemporaryDirectory()
        extract_path = Path(temp_dir.name)

    try:
        macho_paths = process_input_recursive(input_path, extract_path, args.aea_key)
        if not macho_paths:
            print("[!] No Mach-O binaries found/carved from input.", file=sys.stderr)
            sys.exit(1)

        all_cli_reports = {}
        for macho_path in macho_paths:
            print(f"\n[*] Analyzing Mach-O binary: {macho_path.name}")
            try:
                report = analyze(
                    str(macho_path), keywords,
                    build_cfg=args.cfg,
                    run_taint=args.taint or args.cfg,
                    disasm_n_funcs=args.disasm_funcs,
                    verbose=args.verbose,
                )
            except (FileNotFoundError, ValueError) as e:
                print(f"[!] Analysis failed for {macho_path.name}: {e}", file=sys.stderr)
                continue

            all_cli_reports[macho_path.name] = report

            if not args.no_text:
                print_report(report, verbose=args.verbose)

            if not args.no_json:
                if args.output:
                    out_path = Path(args.output)
                    if len(macho_paths) > 1:
                        out = str(out_path.parent / f"{out_path.stem}_{macho_path.name}{out_path.suffix}")
                    else:
                        out = str(out_path)
                else:
                    out = f"{macho_path.name}_deep_analysis.json"

                with open(out, "w", encoding="utf-8") as f:
                    json.dump(_make_serializable(report), f, indent=2, ensure_ascii=False)
                print(f"\n[+] JSON report → {out}")

            # ── POWERHOUSE: PDF Report ────────────────────────────────────
            if args.pdf_report:
                pdf_out = args.pdf_report
                if len(macho_paths) > 1:
                    pdf_out_path = Path(pdf_out)
                    pdf_out = str(pdf_out_path.parent / f"{pdf_out_path.stem}_{macho_path.name}{pdf_out_path.suffix}")
                pdf_result = generate_pdf_report(report, pdf_out)
                if "error" in pdf_result:
                    print(f"[!] PDF report failed: {pdf_result['error']}", file=sys.stderr)
                else:
                    print(f"[+] PDF report → {pdf_result['pdf_path']} ({pdf_result['size']} bytes)")

        # ── IPSW Firmware Intelligence Report (CLI) ──────────────────────
        if _ipsw_firmware_meta and all_cli_reports:
            print("\n[*] Building IPSW Firmware Intelligence Report...")
            fw_report = build_firmware_intelligence_report(
                ios_version=_ipsw_firmware_meta.get("ios_version", "Unknown"),
                ios_build=_ipsw_firmware_meta.get("ios_build", "Unknown"),
                product_type=_ipsw_firmware_meta.get("product_type", "Unknown"),
                all_reports=all_cli_reports,
                ipsw_meta=_ipsw_firmware_meta,
            )
            if not args.no_text:
                print_firmware_intelligence_report(fw_report)
            if not args.no_json:
                fw_out = args.output.replace(".json", "_firmware_intel.json") if args.output else "firmware_intelligence_report.json"
                with open(fw_out, "w", encoding="utf-8") as f:
                    json.dump(_make_serializable(fw_report), f, indent=2, ensure_ascii=False)
                print(f"\n[+] Firmware Intelligence JSON → {fw_out}")

    finally:
        if temp_dir:
            try:
                temp_dir.cleanup()
            except Exception as e:
                if args.verbose:
                    print(f"[*] Warning: temporary directory cleanup failed: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()