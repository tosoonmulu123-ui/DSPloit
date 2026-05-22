#!/usr/bin/env python3
"""
Mach-O ARM64 iOS Binary Analyzer
Deep static analysis: entitlements, ObjC classes/methods, XPC services,
symbols, strings, code signature, load commands, cross-references.

Usage:
    python3 analyze_binary.py <binary_path> [--keywords "kw1,kw2"] [--output report.json]
"""

import struct
import re
import os
import sys
import json
import argparse
import plistlib
import hashlib
from pathlib import Path
from typing import Optional

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

# Magic numbers
MH_MAGIC_64      = 0xFEEDFACF
MH_CIGAM_64      = 0xCFFAEDFE
FAT_MAGIC        = 0xCAFEBABE
FAT_CIGAM        = 0xBEBAFECA

# CPU types
CPU_TYPE_ARM64   = 0x0100000C
CPU_SUBTYPE_ARM64_ALL = 0x00000000

# Mach-O header sizes
MACH_HEADER_64_SIZE = 32
FAT_HEADER_SIZE     = 8
FAT_ARCH_SIZE       = 20

# Load command types
LC_SEGMENT_64        = 0x19
LC_SYMTAB            = 0x02
LC_DYSYMTAB          = 0x0B
LC_LOAD_DYLIB        = 0x0C
LC_ID_DYLIB          = 0x0D
LC_LOAD_WEAK_DYLIB   = 0x80000018
LC_REEXPORT_DYLIB    = 0x8000001F
LC_LAZY_LOAD_DYLIB   = 0x20
LC_CODE_SIGNATURE    = 0x1D
LC_ENCRYPTION_INFO   = 0x21
LC_ENCRYPTION_INFO_64= 0x2C
LC_DYLD_INFO         = 0x22
LC_DYLD_INFO_ONLY    = 0x80000022
LC_DYLD_EXPORTS_TRIE = 0x80000033
LC_DYLD_CHAINED_FIXUPS = 0x80000034
LC_LOAD_DYLINKER     = 0x0E
LC_UUID              = 0x1B
LC_VERSION_MIN_IPHONEOS = 0x25
LC_BUILD_VERSION     = 0x32
LC_SOURCE_VERSION    = 0x2A
LC_MAIN              = 0x80000028
LC_FUNCTION_STARTS   = 0x26
LC_DATA_IN_CODE      = 0x29
LC_RPATH             = 0x8000001C
LC_LINKER_OPTION     = 0x2D

LC_NAMES = {
    0x01: "LC_SEGMENT",
    0x02: "LC_SYMTAB",
    0x0B: "LC_DYSYMTAB",
    0x0C: "LC_LOAD_DYLIB",
    0x0D: "LC_ID_DYLIB",
    0x0E: "LC_LOAD_DYLINKER",
    0x19: "LC_SEGMENT_64",
    0x1B: "LC_UUID",
    0x1D: "LC_CODE_SIGNATURE",
    0x20: "LC_LAZY_LOAD_DYLIB",
    0x21: "LC_ENCRYPTION_INFO",
    0x22: "LC_DYLD_INFO",
    0x25: "LC_VERSION_MIN_IPHONEOS",
    0x26: "LC_FUNCTION_STARTS",
    0x29: "LC_DATA_IN_CODE",
    0x2A: "LC_SOURCE_VERSION",
    0x2C: "LC_ENCRYPTION_INFO_64",
    0x2D: "LC_LINKER_OPTION",
    0x32: "LC_BUILD_VERSION",
    0x80000018: "LC_LOAD_WEAK_DYLIB",
    0x8000001C: "LC_RPATH",
    0x80000022: "LC_DYLD_INFO_ONLY",
    0x80000028: "LC_MAIN",
    0x8000001F: "LC_REEXPORT_DYLIB",
    0x80000033: "LC_DYLD_EXPORTS_TRIE",
    0x80000034: "LC_DYLD_CHAINED_FIXUPS",
}

# Code Signature magic
CSMAGIC_REQUIREMENT        = 0xFADE0C00
CSMAGIC_REQUIREMENTS       = 0xFADE0C01
CSMAGIC_CODEDIRECTORY      = 0xFADE0C02
CSMAGIC_EMBEDDED_SIGNATURE = 0xFADE0CC0
CSMAGIC_DETACHED_SIGNATURE = 0xFADE0CC1
CSMAGIC_BLOBWRAPPER        = 0xFADE0B01
CSMAGIC_EMBEDDED_ENTITLEMENTS = 0xFADE7171
CSMAGIC_EMBEDDED_ENTITLEMENTS_DER = 0xFADE7172

CS_SLOT_CODEDIRECTORY = 0
CS_SLOT_REQUIREMENTS  = 2
CS_SLOT_ENTITLEMENTS  = 5

HASH_TYPE_NAMES = {
    1: "SHA-1",
    2: "SHA-256",
    3: "SHA-256-truncated",
    4: "SHA-384",
    5: "SHA-512",
}

PLATFORM_NAMES = {
    1: "macOS",
    2: "iOS",
    3: "tvOS",
    4: "watchOS",
    5: "bridgeOS",
    6: "macCatalyst",
    7: "iOSSimulator",
    8: "tvOSSimulator",
    9: "watchOSSimulator",
}

DEFAULT_KEYWORDS = [
    "register", "validate", "container", "install", "trust", "cache",
    "signature", "verify", "certificate", "entitlement", "sandbox",
    "amfi", "codesign", "springboard", "icon", "launch", "application",
    "bundle", "plist", "MCM", "LSApplication", "MobileInstallation", "lsd",
]


# ─────────────────────────────────────────────────────────────────────────────
# Utility helpers
# ─────────────────────────────────────────────────────────────────────────────

def read_u8(data: bytes, off: int) -> int:
    return data[off]

def read_u16_be(data: bytes, off: int) -> int:
    return struct.unpack_from(">H", data, off)[0]

def read_u32(data: bytes, off: int, big_endian=False) -> int:
    fmt = ">I" if big_endian else "<I"
    return struct.unpack_from(fmt, data, off)[0]

def read_u32_be(data: bytes, off: int) -> int:
    return struct.unpack_from(">I", data, off)[0]

def read_u64(data: bytes, off: int) -> int:
    return struct.unpack_from("<Q", data, off)[0]

def read_cstring(data: bytes, off: int) -> str:
    end = data.find(b'\x00', off)
    if end == -1:
        return data[off:].decode("utf-8", errors="replace")
    return data[off:end].decode("utf-8", errors="replace")

def read_cstring_safe(data: bytes, off: int, limit=512) -> str:
    end = data.find(b'\x00', off, off + limit)
    if end == -1:
        end = off + limit
    return data[off:end].decode("utf-8", errors="replace")

def bytes_to_hex(b: bytes) -> str:
    return b.hex()

def format_uuid(b: bytes) -> str:
    assert len(b) == 16
    return "%08X-%04X-%04X-%04X-%012X" % (
        struct.unpack_from(">I", b, 0)[0],
        struct.unpack_from(">H", b, 4)[0],
        struct.unpack_from(">H", b, 6)[0],
        struct.unpack_from(">H", b, 8)[0],
        int.from_bytes(b[10:16], "big"),
    )


# ─────────────────────────────────────────────────────────────────────────────
# FAT / Mach-O locator
# ─────────────────────────────────────────────────────────────────────────────

def find_arm64_slice(data: bytes) -> tuple[bytes, int]:
    """
    Return (slice_bytes, offset_in_file).
    Handles FAT (universal) binaries and thin arm64 binaries.
    """
    magic = read_u32(data, 0)

    if magic in (FAT_MAGIC, FAT_CIGAM):
        big = (magic == FAT_MAGIC)
        nfat = read_u32(data, 4, big_endian=big)
        off = FAT_HEADER_SIZE
        for _ in range(nfat):
            cpu_type   = read_u32(data, off,     big_endian=True)
            # cpu_subtype = read_u32(data, off + 4,  big_endian=True)
            arch_off   = read_u32(data, off + 8,  big_endian=True)
            arch_size  = read_u32(data, off + 12, big_endian=True)
            off += FAT_ARCH_SIZE
            if cpu_type == CPU_TYPE_ARM64:
                return data[arch_off:arch_off + arch_size], arch_off
        raise ValueError("No ARM64 slice found in FAT binary")

    elif magic in (MH_MAGIC_64, MH_CIGAM_64):
        return data, 0
    else:
        raise ValueError(f"Unknown magic: 0x{magic:08X} — not a Mach-O or FAT binary")


# ─────────────────────────────────────────────────────────────────────────────
# Mach-O header + load commands
# ─────────────────────────────────────────────────────────────────────────────

class MachOHeader:
    __slots__ = ["magic","cputype","cpusubtype","filetype","ncmds","sizeofcmds","flags"]

    def __init__(self, data: bytes):
        (self.magic, self.cputype, self.cpusubtype,
         self.filetype, self.ncmds, self.sizeofcmds,
         self.flags) = struct.unpack_from("<IIIIIII", data, 0)
        # 64-bit has reserved field at offset 28; we skip it


class LoadCommand:
    def __init__(self, cmd, cmdsize, raw):
        self.cmd     = cmd
        self.cmdsize = cmdsize
        self.raw     = raw  # full bytes of this LC (including cmd/cmdsize)

    @property
    def name(self):
        return LC_NAMES.get(self.cmd, f"LC_UNKNOWN_0x{self.cmd:08X}")


def parse_load_commands(data: bytes) -> list[LoadCommand]:
    hdr = MachOHeader(data)
    off = MACH_HEADER_64_SIZE  # skip 4-byte reserved field in 64-bit header
    lcs = []
    for _ in range(hdr.ncmds):
        cmd     = read_u32(data, off)
        cmdsize = read_u32(data, off + 4)
        if cmdsize < 8 or off + cmdsize > len(data):
            break
        lcs.append(LoadCommand(cmd, cmdsize, data[off:off + cmdsize]))
        off += cmdsize
    return lcs


# ─────────────────────────────────────────────────────────────────────────────
# Segment / section map
# ─────────────────────────────────────────────────────────────────────────────

class Section64:
    SIZE = 80

    def __init__(self, raw: bytes, off: int):
        self.sectname = raw[off:off+16].rstrip(b'\x00').decode("utf-8", errors="replace")
        self.segname  = raw[off+16:off+32].rstrip(b'\x00').decode("utf-8", errors="replace")
        self.addr     = read_u64(raw, off+32)
        self.size     = read_u64(raw, off+40)
        self.offset   = read_u32(raw, off+48)
        self.align    = read_u32(raw, off+52)
        self.reloff   = read_u32(raw, off+56)
        self.nreloc   = read_u32(raw, off+60)
        self.flags    = read_u32(raw, off+64)


class Segment64:
    def __init__(self, lc: LoadCommand):
        raw = lc.raw
        self.segname  = raw[8:24].rstrip(b'\x00').decode("utf-8", errors="replace")
        self.vmaddr   = read_u64(raw, 24)
        self.vmsize   = read_u64(raw, 32)
        self.fileoff  = read_u64(raw, 40)
        self.filesize = read_u64(raw, 48)
        self.maxprot  = read_u32(raw, 56)
        self.initprot = read_u32(raw, 60)
        self.nsects   = read_u32(raw, 64)
        self.flags    = read_u32(raw, 68)
        self.sections: list[Section64] = []
        sec_off = 72
        for _ in range(self.nsects):
            if sec_off + Section64.SIZE > len(raw):
                break
            self.sections.append(Section64(raw, sec_off))
            sec_off += Section64.SIZE


def build_segment_map(lcs: list[LoadCommand]) -> dict[str, Segment64]:
    segs = {}
    for lc in lcs:
        if lc.cmd == LC_SEGMENT_64:
            seg = Segment64(lc)
            segs[seg.segname] = seg
    return segs


def find_section(segs: dict, segname: str, sectname: str) -> Optional[Section64]:
    seg = segs.get(segname)
    if not seg:
        return None
    for s in seg.sections:
        if s.sectname == sectname:
            return s
    return None


def section_data(data: bytes, sec: Section64) -> bytes:
    if sec.offset == 0 or sec.size == 0:
        return b""
    end = sec.offset + sec.size
    if end > len(data):
        end = len(data)
    return data[sec.offset:end]


# ─────────────────────────────────────────────────────────────────────────────
# ObjC parsing
# ─────────────────────────────────────────────────────────────────────────────

def parse_strings_section(raw: bytes) -> list[str]:
    """Parse a null-terminated string table section."""
    strings = []
    i = 0
    while i < len(raw):
        end = raw.find(b'\x00', i)
        if end == -1:
            s = raw[i:].decode("utf-8", errors="replace")
            if s:
                strings.append(s)
            break
        s = raw[i:end].decode("utf-8", errors="replace")
        if s:
            strings.append(s)
        i = end + 1
    return strings


def parse_objc_classnames(data: bytes, segs: dict) -> list[str]:
    sec = find_section(segs, "__TEXT", "__objc_classnames")
    if not sec:
        return []
    return parse_strings_section(section_data(data, sec))


def parse_objc_methnames(data: bytes, segs: dict) -> list[str]:
    sec = find_section(segs, "__TEXT", "__objc_methnames")
    if not sec:
        return []
    return parse_strings_section(section_data(data, sec))


def parse_objc_selrefs(data: bytes, segs: dict) -> list[str]:
    """
    __objc_selrefs holds pointers to selector strings.
    We return the pointed-to strings from __objc_methnames if resolvable,
    otherwise just decode what we can find.
    """
    sec = find_section(segs, "__DATA", "__objc_selrefs")
    if not sec:
        sec = find_section(segs, "__DATA_CONST", "__objc_selrefs")
    if not sec:
        return []

    # Try to resolve vm addresses to file offsets
    raw = section_data(data, sec)
    selectors = []
    text_seg = segs.get("__TEXT")
    if not text_seg:
        return []

    n_ptrs = len(raw) // 8
    for i in range(n_ptrs):
        ptr = struct.unpack_from("<Q", raw, i * 8)[0]
        # Convert VA to file offset
        file_off = va_to_file_offset(ptr, segs)
        if file_off and 0 < file_off < len(data):
            s = read_cstring_safe(data, file_off)
            if s:
                selectors.append(s)
    return selectors


def va_to_file_offset(va: int, segs: dict) -> Optional[int]:
    for seg in segs.values():
        if seg.vmaddr <= va < seg.vmaddr + seg.vmsize:
            return seg.fileoff + (va - seg.vmaddr)
    return None


def parse_objc_classrefs(data: bytes, segs: dict) -> list[str]:
    """Attempt to resolve __objc_classrefs pointers to class names."""
    results = []
    for secname, data_seg in [("__objc_classrefs", "__DATA"),
                               ("__objc_classrefs", "__DATA_CONST")]:
        sec = find_section(segs, data_seg, secname)
        if not sec:
            continue
        raw = section_data(data, sec)
        n = len(raw) // 8
        for i in range(n):
            ptr = struct.unpack_from("<Q", raw, i * 8)[0]
            # Classes are in __DATA, try to resolve two levels
            fo = va_to_file_offset(ptr, segs)
            if fo and fo + 8 < len(data):
                # ObjC class_t: first field is metaclass ptr, 4th (offset 16) is data ptr
                # We try a heuristic: read the name from nearby text sections
                name_ptr = struct.unpack_from("<Q", data, fo + 32)[0] if fo + 40 <= len(data) else 0
                if name_ptr:
                    nfo = va_to_file_offset(name_ptr, segs)
                    if nfo and nfo < len(data):
                        s = read_cstring_safe(data, nfo)
                        if s and all(32 <= ord(c) < 127 for c in s) and len(s) < 256:
                            results.append(s)
    return results


def parse_objc_methods_from_methnames(methnames: list[str]) -> dict:
    """Categorize method names into instance/class methods."""
    instance_methods = []
    class_methods    = []
    # Heuristic: class methods often start with known prefixes, but we can't
    # know for certain without parsing the full class_ro_t struct.
    # We label everything as "method" unless a selector matches a property pattern.
    for m in methnames:
        if m.startswith(".cxx_") or m.startswith("_"):
            class_methods.append(m)
        else:
            instance_methods.append(m)
    return {"instance_methods": instance_methods, "class_methods": class_methods}


# ─────────────────────────────────────────────────────────────────────────────
# Symbol table
# ─────────────────────────────────────────────────────────────────────────────

N_EXT   = 0x01
N_TYPE  = 0x0E
N_UNDF  = 0x00   # undefined (imported)
N_SECT  = 0x0E   # defined in section (potentially exported)
N_STAB  = 0xE0

NLIST64_SIZE = 16


def parse_symtab(data: bytes, lcs: list[LoadCommand]) -> dict:
    symtab_lc = None
    for lc in lcs:
        if lc.cmd == LC_SYMTAB:
            symtab_lc = lc
            break
    if not symtab_lc:
        return {"imported": [], "exported": []}

    symoff  = read_u32(symtab_lc.raw, 8)
    nsyms   = read_u32(symtab_lc.raw, 12)
    stroff  = read_u32(symtab_lc.raw, 16)
    strsize = read_u32(symtab_lc.raw, 20)

    strtab = data[stroff:stroff + strsize]
    imported = []
    exported = []

    for i in range(nsyms):
        off = symoff + i * NLIST64_SIZE
        if off + NLIST64_SIZE > len(data):
            break
        strx  = read_u32(data, off)
        flags = read_u8(data, off + 4)
        # sect  = read_u8(data, off + 5)
        # desc  = struct.unpack_from("<H", data, off + 6)[0]
        value = read_u64(data, off + 8)

        if flags & N_STAB:
            continue  # debug symbol

        n_type = flags & N_TYPE
        n_ext  = flags & N_EXT

        # Read name
        name_end = strtab.find(b'\x00', strx)
        name = strtab[strx:name_end].decode("utf-8", errors="replace") if name_end != -1 else ""

        if not name or name == "<redacted>":
            continue

        if n_type == N_UNDF:
            imported.append(name)
        elif n_type == N_SECT and n_ext:
            exported.append({"name": name, "address": hex(value)})

    return {"imported": sorted(set(imported)), "exported": exported}


# ─────────────────────────────────────────────────────────────────────────────
# Dylib imports
# ─────────────────────────────────────────────────────────────────────────────

DYLIB_LC_TYPES = {LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB,
                  LC_LAZY_LOAD_DYLIB}


def parse_dylib_imports(lcs: list[LoadCommand]) -> list[dict]:
    dylibs = []
    for lc in lcs:
        if lc.cmd in DYLIB_LC_TYPES:
            # dylib name offset is at bytes 8-11 of the LC
            name_off = read_u32(lc.raw, 8)
            name = read_cstring_safe(lc.raw, name_off)
            timestamp    = read_u32(lc.raw, 12)
            current_ver  = read_u32(lc.raw, 16)
            compat_ver   = read_u32(lc.raw, 20)
            dylibs.append({
                "name": name,
                "type": LC_NAMES.get(lc.cmd, "LC_LOAD_DYLIB"),
                "timestamp": timestamp,
                "current_version": _decode_version(current_ver),
                "compat_version": _decode_version(compat_ver),
            })
    return dylibs


def _decode_version(v: int) -> str:
    return f"{(v >> 16) & 0xFFFF}.{(v >> 8) & 0xFF}.{v & 0xFF}"


# ─────────────────────────────────────────────────────────────────────────────
# C-string section scanning
# ─────────────────────────────────────────────────────────────────────────────

def scan_cstrings(data: bytes, segs: dict, keywords: list[str]) -> dict:
    """
    Scan __TEXT,__cstring for strings matching keywords.
    Returns {keyword: [list_of_matching_strings]}.
    """
    sec = find_section(segs, "__TEXT", "__cstring")
    if not sec:
        return {}

    raw = section_data(data, sec)
    all_strings = parse_strings_section(raw)
    kw_lower = [k.lower() for k in keywords]

    results = {kw: [] for kw in keywords}
    for s in all_strings:
        sl = s.lower()
        for i, kw in enumerate(kw_lower):
            if kw in sl:
                results[keywords[i]].append(s)

    # Remove empty
    return {k: v for k, v in results.items() if v}


def scan_all_strings(data: bytes, segs: dict) -> list[str]:
    """Extract all printable C strings from __TEXT,__cstring."""
    sec = find_section(segs, "__TEXT", "__cstring")
    if not sec:
        return []
    return parse_strings_section(section_data(data, sec))


def extract_xpc_services(data: bytes, segs: dict) -> list[str]:
    """Find strings matching XPC/bundle-id pattern com.apple.* or com.*."""
    all_s = scan_all_strings(data, segs)
    pattern = re.compile(r'com\.[a-zA-Z0-9_\-]+(?:\.[a-zA-Z0-9_\-]+)+')
    found = set()
    for s in all_s:
        for m in pattern.finditer(s):
            found.add(m.group())
    # also scan __objc_methnames-adjacent sections
    for seg_name in ("__TEXT", "__DATA", "__DATA_CONST"):
        seg = segs.get(seg_name)
        if not seg:
            continue
        for sec in seg.sections:
            raw = section_data(data, sec)
            for m in pattern.finditer(raw.decode("utf-8", errors="replace")):
                found.add(m.group())
    return sorted(found)


# ─────────────────────────────────────────────────────────────────────────────
# Cross-references
# ─────────────────────────────────────────────────────────────────────────────

def cross_reference_strings(data: bytes, segs: dict, trigger_words: list[str],
                             context_bytes: int = 50) -> list[dict]:
    """
    Find occurrences of trigger_words in __TEXT,__cstring and return
    surrounding context (±context_bytes raw bytes as hex + decoded text).
    """
    sec = find_section(segs, "__TEXT", "__cstring")
    if not sec:
        return []

    raw     = section_data(data, sec)
    results = []
    seen    = set()

    for word in trigger_words:
        wb = word.encode("utf-8")
        start = 0
        while True:
            idx = raw.find(wb, start)
            if idx == -1:
                break
            key = (word, idx)
            if key not in seen:
                seen.add(key)
                lo = max(0, idx - context_bytes)
                hi = min(len(raw), idx + len(wb) + context_bytes)
                ctx_bytes = raw[lo:hi]
                ctx_text  = ctx_bytes.decode("utf-8", errors="replace")
                file_off  = sec.offset + idx
                results.append({
                    "trigger": word,
                    "file_offset": hex(file_off),
                    "vm_address": hex(sec.addr + idx) if sec.addr else None,
                    "context_hex": ctx_bytes.hex(),
                    "context_text": ctx_text,
                })
            start = idx + 1

    return results


# ─────────────────────────────────────────────────────────────────────────────
# Code Signature
# ─────────────────────────────────────────────────────────────────────────────

def find_code_sig_lc(lcs: list[LoadCommand]) -> Optional[LoadCommand]:
    for lc in lcs:
        if lc.cmd == LC_CODE_SIGNATURE:
            return lc
    return None


def parse_code_signature(data: bytes, lcs: list[LoadCommand]) -> dict:
    result = {
        "present": False,
        "entitlements": None,
        "entitlements_raw": None,
        "code_directories": [],
        "team_id": None,
        "identifiers": [],
        "hash_types": [],
        "cd_hashes": [],
        "blobs": [],
        "error": None,
    }

    lc = find_code_sig_lc(lcs)
    if not lc:
        result["error"] = "No LC_CODE_SIGNATURE found"
        return result

    dataoff  = read_u32(lc.raw, 8)
    datasize = read_u32(lc.raw, 12)

    if dataoff + datasize > len(data):
        result["error"] = "Code signature extends beyond file"
        return result

    cs = data[dataoff:dataoff + datasize]
    result["present"] = True

    try:
        _parse_superblob(cs, result)
    except Exception as e:
        result["error"] = f"Parse error: {e}"

    return result


def _parse_superblob(cs: bytes, result: dict):
    magic = read_u32_be(cs, 0)
    if magic not in (CSMAGIC_EMBEDDED_SIGNATURE, CSMAGIC_DETACHED_SIGNATURE):
        result["error"] = f"Expected SuperBlob magic, got 0x{magic:08X}"
        return

    # length = read_u32_be(cs, 4)
    count  = read_u32_be(cs, 8)

    for i in range(count):
        idx_off = 12 + i * 8
        slot   = read_u32_be(cs, idx_off)
        offset = read_u32_be(cs, idx_off + 4)
        if offset >= len(cs):
            continue

        blob_magic = read_u32_be(cs, offset)
        blob_len   = read_u32_be(cs, offset + 4)
        blob_data  = cs[offset:offset + blob_len]

        result["blobs"].append({
            "slot":   slot,
            "magic":  hex(blob_magic),
            "length": blob_len,
        })

        if blob_magic == CSMAGIC_CODEDIRECTORY:
            _parse_code_directory(blob_data, result)
        elif blob_magic in (CSMAGIC_EMBEDDED_ENTITLEMENTS,):
            # plist XML starts at offset 8
            ent_bytes = blob_data[8:]
            result["entitlements_raw"] = ent_bytes.decode("utf-8", errors="replace")
            try:
                result["entitlements"] = plistlib.loads(ent_bytes)
            except Exception as e:
                result["entitlements"] = {"_parse_error": str(e)}
        elif blob_magic == CSMAGIC_EMBEDDED_ENTITLEMENTS_DER:
            result["entitlements_raw"] = "(DER-encoded, not XML)"


def _parse_code_directory(blob: bytes, result: dict):
    # CodeDirectory layout (v1+):
    # 0:  magic (4)
    # 4:  length (4)
    # 8:  version (4)
    # 12: flags (4)
    # 16: hashOffset (4)
    # 20: identOffset (4)
    # 24: nSpecialSlots (4)
    # 28: nCodeSlots (4)
    # 32: codeLimit (4)
    # 36: hashSize (1)
    # 37: hashType (1)
    # 38: platform (1)
    # 39: pageSize (1)
    # 40: spare2 (4)
    # v2+ (>= 0x20200):
    # 44: scatterOffset (4)
    # v2+ (>= 0x20300):
    # 48: teamOffset (4)
    # v2+ (>= 0x20400):
    # 52: spare3 (4)
    # 56: codeLimit64 (8)
    # v2+ (>= 0x20500):
    # 64: execSegBase (8)
    # 72: execSegLimit (8)
    # 80: execSegFlags (8)

    if len(blob) < 44:
        return

    version     = read_u32_be(blob, 8)
    hash_offset = read_u32_be(blob, 16)
    ident_off   = read_u32_be(blob, 20)
    n_special   = read_u32_be(blob, 24)
    n_code      = read_u32_be(blob, 28)
    hash_size   = read_u8(blob, 36)
    hash_type   = read_u8(blob, 37)
    page_size   = read_u8(blob, 39)

    # Identifier
    ident = ""
    if ident_off and ident_off < len(blob):
        ident = read_cstring_safe(blob, ident_off)

    # Team ID (v >= 0x20300)
    team_id = ""
    if version >= 0x20300 and len(blob) >= 52:
        team_off = read_u32_be(blob, 48)
        if team_off and team_off < len(blob):
            team_id = read_cstring_safe(blob, team_off)

    # CDHash = SHA-256 of the CodeDirectory blob
    cd_hash_sha256 = hashlib.sha256(blob).hexdigest()
    # SHA-1 CDHash (older)
    cd_hash_sha1   = hashlib.sha1(blob).hexdigest()

    # Collect code hashes
    code_hashes = []
    slot_start = hash_offset  # special slots go backwards, code slots forward
    for i in range(min(n_code, 512)):  # cap at 512 to avoid huge output
        off = slot_start + i * hash_size
        if off + hash_size > len(blob):
            break
        code_hashes.append(blob[off:off + hash_size].hex())

    cd_info = {
        "version":     hex(version),
        "identifier":  ident,
        "team_id":     team_id,
        "hash_type":   HASH_TYPE_NAMES.get(hash_type, f"unknown({hash_type})"),
        "hash_size":   hash_size,
        "page_size":   2 ** page_size if page_size else 0,
        "n_code_slots": n_code,
        "n_special_slots": n_special,
        "cd_hash_sha256": cd_hash_sha256,
        "cd_hash_sha1":   cd_hash_sha1,
        "first_code_hashes": code_hashes[:8],
    }

    result["code_directories"].append(cd_info)
    if team_id and not result["team_id"]:
        result["team_id"] = team_id
    if ident and ident not in result["identifiers"]:
        result["identifiers"].append(ident)
    if hash_type not in result["hash_types"]:
        result["hash_types"].append(HASH_TYPE_NAMES.get(hash_type, str(hash_type)))
    result["cd_hashes"].append(cd_hash_sha256)


# ─────────────────────────────────────────────────────────────────────────────
# Load command details
# ─────────────────────────────────────────────────────────────────────────────

def describe_load_commands(lcs: list[LoadCommand]) -> list[dict]:
    result = []
    for lc in lcs:
        entry = {
            "cmd":     lc.name,
            "cmd_id":  hex(lc.cmd),
            "size":    lc.cmdsize,
        }

        if lc.cmd == LC_SEGMENT_64:
            seg = Segment64(lc)
            entry["segment"] = seg.segname
            entry["vmaddr"]  = hex(seg.vmaddr)
            entry["vmsize"]  = hex(seg.vmsize)
            entry["fileoff"] = hex(seg.fileoff)
            entry["filesize"]= hex(seg.filesize)
            entry["nsects"]  = seg.nsects
            entry["sections"]= [s.sectname for s in seg.sections]

        elif lc.cmd in DYLIB_LC_TYPES | {LC_ID_DYLIB}:
            name_off = read_u32(lc.raw, 8)
            entry["dylib"] = read_cstring_safe(lc.raw, name_off)
            entry["version"] = _decode_version(read_u32(lc.raw, 16))

        elif lc.cmd == LC_UUID:
            entry["uuid"] = format_uuid(lc.raw[8:24])

        elif lc.cmd == LC_CODE_SIGNATURE:
            entry["dataoff"]  = hex(read_u32(lc.raw, 8))
            entry["datasize"] = hex(read_u32(lc.raw, 12))

        elif lc.cmd in (LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64):
            entry["cryptoff"]  = hex(read_u32(lc.raw, 8))
            entry["cryptsize"] = hex(read_u32(lc.raw, 12))
            entry["cryptid"]   = read_u32(lc.raw, 16)

        elif lc.cmd == LC_BUILD_VERSION:
            platform    = read_u32(lc.raw, 8)
            minos       = read_u32(lc.raw, 12)
            sdk         = read_u32(lc.raw, 16)
            entry["platform"] = PLATFORM_NAMES.get(platform, f"platform_{platform}")
            entry["minos"]    = _decode_version(minos)
            entry["sdk"]      = _decode_version(sdk)

        elif lc.cmd == LC_VERSION_MIN_IPHONEOS:
            entry["version"] = _decode_version(read_u32(lc.raw, 8))
            entry["sdk"]     = _decode_version(read_u32(lc.raw, 12))

        elif lc.cmd == LC_SOURCE_VERSION:
            v = struct.unpack_from("<Q", lc.raw, 8)[0]
            a = (v >> 40) & 0xFFFFFF
            b = (v >> 30) & 0x3FF
            c = (v >> 20) & 0x3FF
            d = (v >> 10) & 0x3FF
            e = v & 0x3FF
            entry["version"] = f"{a}.{b}.{c}.{d}.{e}"

        elif lc.cmd == LC_MAIN:
            entry["entryoff"] = hex(struct.unpack_from("<Q", lc.raw, 8)[0])
            entry["stacksize"]= hex(struct.unpack_from("<Q", lc.raw, 16)[0])

        elif lc.cmd in (LC_RPATH,):
            path_off = read_u32(lc.raw, 8)
            entry["path"] = read_cstring_safe(lc.raw, path_off)

        elif lc.cmd == LC_SYMTAB:
            entry["symoff"]  = hex(read_u32(lc.raw, 8))
            entry["nsyms"]   = read_u32(lc.raw, 12)
            entry["stroff"]  = hex(read_u32(lc.raw, 16))
            entry["strsize"] = hex(read_u32(lc.raw, 20))

        elif lc.cmd == LC_DYSYMTAB:
            entry["ilocalsym"] = read_u32(lc.raw, 8)
            entry["nlocalsym"] = read_u32(lc.raw, 12)
            entry["iextdefsym"]= read_u32(lc.raw, 16)
            entry["nextdefsym"]= read_u32(lc.raw, 20)
            entry["iundefsym"] = read_u32(lc.raw, 24)
            entry["nundefsym"] = read_u32(lc.raw, 28)

        elif lc.cmd == LC_LOAD_DYLINKER:
            name_off = read_u32(lc.raw, 8)
            entry["dylinker"] = read_cstring_safe(lc.raw, name_off)

        result.append(entry)

    return result


# ─────────────────────────────────────────────────────────────────────────────
# Main analysis
# ─────────────────────────────────────────────────────────────────────────────

def analyze(binary_path: str, keywords: list[str]) -> dict:
    path = Path(binary_path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {binary_path}")

    raw_data = path.read_bytes()
    print(f"[*] Loaded {len(raw_data):,} bytes from {path.name}")

    # Locate ARM64 slice
    data, slice_offset = find_arm64_slice(raw_data)
    hdr = MachOHeader(data)
    is_fat = slice_offset > 0
    print(f"[*] ARM64 slice @ offset 0x{slice_offset:X} ({len(data):,} bytes)"
          + (" [FAT binary]" if is_fat else " [thin binary]"))

    # Parse load commands
    lcs  = parse_load_commands(data)
    segs = build_segment_map(lcs)
    print(f"[*] {len(lcs)} load commands, {len(segs)} segments")

    # ObjC
    print("[*] Parsing ObjC class/method names...")
    classnames = parse_objc_classnames(data, segs)
    methnames  = parse_objc_methnames(data, segs)
    selrefs    = parse_objc_selrefs(data, segs)
    classrefs  = parse_objc_classrefs(data, segs)
    method_cats = parse_objc_methods_from_methnames(methnames)

    # Symbols
    print("[*] Parsing symbol table...")
    symbols = parse_symtab(data, lcs)

    # Dylibs
    dylibs = parse_dylib_imports(lcs)

    # Strings & keywords
    print(f"[*] Scanning C strings for {len(keywords)} keywords...")
    kw_strings = scan_cstrings(data, segs, keywords)

    # XPC services
    print("[*] Extracting XPC/bundle service names...")
    xpc_names = extract_xpc_services(data, segs)

    # Cross-references
    xref_triggers = ["register", "validate"]
    print(f"[*] Building cross-references for: {xref_triggers}...")
    xrefs = cross_reference_strings(data, segs, xref_triggers)

    # Code signature
    print("[*] Parsing code signature...")
    codesig = parse_code_signature(data, lcs)

    # Load commands detail
    lc_details = describe_load_commands(lcs)

    # UUID
    uuid = ""
    for lc in lcs:
        if lc.cmd == LC_UUID:
            uuid = format_uuid(lc.raw[8:24])
            break

    # Encryption status
    encrypted = False
    for lc in lcs:
        if lc.cmd in (LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64):
            crypt_id = read_u32(lc.raw, 16)
            if crypt_id != 0:
                encrypted = True
            break

    filetype_names = {
        1: "MH_OBJECT", 2: "MH_EXECUTE", 6: "MH_DYLIB",
        7: "MH_DYLINKER", 8: "MH_BUNDLE", 0xA: "MH_DYLIB_STUB",
        0xC: "MH_KEXT_BUNDLE",
    }

    report = {
        "meta": {
            "file":          binary_path,
            "file_size":     len(raw_data),
            "is_fat":        is_fat,
            "slice_offset":  hex(slice_offset),
            "arch":          "arm64",
            "filetype":      filetype_names.get(hdr.filetype, f"0x{hdr.filetype:X}"),
            "uuid":          uuid,
            "encrypted":     encrypted,
            "ncmds":         hdr.ncmds,
        },
        "code_signature":   codesig,
        "entitlements":     codesig.get("entitlements"),
        "objc": {
            "defined_classes":    classnames,
            "referenced_classes": classrefs,
            "all_methods":        methnames,
            "instance_methods":   method_cats["instance_methods"],
            "class_methods":      method_cats["class_methods"],
            "selector_refs":      selrefs,
        },
        "symbols": {
            "imported":  symbols["imported"],
            "exported":  symbols["exported"],
            "dylib_imports": dylibs,
        },
        "xpc_services":    xpc_names,
        "string_matches":  kw_strings,
        "cross_references":xrefs,
        "load_commands":   lc_details,
    }

    return report


# ─────────────────────────────────────────────────────────────────────────────
# Human-readable printer
# ─────────────────────────────────────────────────────────────────────────────

SEP = "=" * 72
SEP2 = "-" * 60

def print_report(r: dict):
    m = r["meta"]
    print(f"\n{SEP}")
    print(f"  Mach-O ARM64 Analysis Report")
    print(SEP)
    print(f"  File      : {m['file']}")
    print(f"  Size      : {m['file_size']:,} bytes")
    print(f"  FAT       : {m['is_fat']}  |  Slice @ {m['slice_offset']}")
    print(f"  Type      : {m['filetype']}")
    print(f"  UUID      : {m['uuid']}")
    print(f"  Encrypted : {m['encrypted']}")
    print(f"  NCmds     : {m['ncmds']}")

    # ── Code Signature ─────────────────────────────────────────────────────
    print(f"\n{SEP}")
    print("  CODE SIGNATURE")
    print(SEP2)
    cs = r["code_signature"]
    if not cs["present"]:
        print(f"  [!] {cs.get('error', 'Not present')}")
    else:
        print(f"  Team ID    : {cs.get('team_id') or '(none)'}")
        print(f"  Identifiers: {', '.join(cs.get('identifiers', [])) or '(none)'}")
        print(f"  Hash types : {', '.join(cs.get('hash_types', []))}")
        for cd in cs.get("code_directories", []):
            print(f"  CDHash     : {cd['cd_hash_sha256']}  (SHA-256 of CD blob)")
            print(f"               {cd['cd_hash_sha1']}  (SHA-1 of CD blob)")
        if cs.get("error"):
            print(f"  [!] Error: {cs['error']}")

    # ── Entitlements ───────────────────────────────────────────────────────
    print(f"\n{SEP}")
    print("  ENTITLEMENTS")
    print(SEP2)
    ent = r.get("entitlements")
    if ent:
        if isinstance(ent, dict) and "_parse_error" in ent:
            print(f"  [!] Parse error: {ent['_parse_error']}")
            raw = cs.get("entitlements_raw", "")
            if raw:
                print(raw[:2000])
        else:
            try:
                print(plistlib.dumps(ent, fmt=plistlib.FMT_XML).decode())
            except Exception:
                print(json.dumps(ent, indent=2))
    else:
        print("  (none embedded)")

    # ── ObjC Classes ───────────────────────────────────────────────────────
    print(f"\n{SEP}")
    print(f"  OBJC DEFINED CLASSES  ({len(r['objc']['defined_classes'])})")
    print(SEP2)
    for c in sorted(r["objc"]["defined_classes"])[:200]:
        print(f"  {c}")

    print(f"\n  OBJC REFERENCED CLASSES  ({len(r['objc']['referenced_classes'])})")
    print(SEP2)
    for c in sorted(set(r["objc"]["referenced_classes"]))[:100]:
        print(f"  {c}")

    # ── ObjC Methods ───────────────────────────────────────────────────────
    print(f"\n{SEP}")
    print(f"  OBJC METHODS  (total: {len(r['objc']['all_methods'])}  "
          f"instance: {len(r['objc']['instance_methods'])}  "
          f"class: {len(r['objc']['class_methods'])})")
    print(SEP2)
    # Print first 100
    for m in sorted(r["objc"]["all_methods"])[:100]:
        print(f"  {m}")
    if len(r["objc"]["all_methods"]) > 100:
        print(f"  ... (+{len(r['objc']['all_methods']) - 100} more — see JSON)")

    # ── XPC Services ───────────────────────────────────────────────────────
    print(f"\n{SEP}")
    print(f"  XPC / BUNDLE SERVICE NAMES  ({len(r['xpc_services'])})")
    print(SEP2)
    for s in sorted(r["xpc_services"]):
        print(f"  {s}")

    # ── Imported Symbols ───────────────────────────────────────────────────
    print(f"\n{SEP}")
    print(f"  IMPORTED SYMBOLS  ({len(r['symbols']['imported'])})")
    print(SEP2)
    for s in sorted(r["symbols"]["imported"])[:200]:
        print(f"  {s}")
    if len(r["symbols"]["imported"]) > 200:
        print(f"  ... (+{len(r['symbols']['imported']) - 200} more — see JSON)")

    # ── Exported Symbols ───────────────────────────────────────────────────
    print(f"\n{SEP}")
    print(f"  EXPORTED SYMBOLS  ({len(r['symbols']['exported'])})")
    print(SEP2)
    for sym in r["symbols"]["exported"][:200]:
        print(f"  {sym['address']}  {sym['name']}")

    # ── Dylib Imports ──────────────────────────────────────────────────────
    print(f"\n{SEP}")
    print(f"  DYLIB IMPORTS  ({len(r['symbols']['dylib_imports'])})")
    print(SEP2)
    for d in r["symbols"]["dylib_imports"]:
        print(f"  [{d['type'].replace('LC_','')}]  {d['name']}  v{d['current_version']}")

    # ── String Matches ─────────────────────────────────────────────────────
    print(f"\n{SEP}")
    print("  STRING REFERENCES (keyword matches)")
    print(SEP2)
    sm = r["string_matches"]
    if not sm:
        print("  (no matches)")
    for kw, strings in sorted(sm.items()):
        print(f"\n  [{kw}]  ({len(strings)} match{'es' if len(strings) != 1 else ''})")
        for s in strings[:30]:
            print(f"    {repr(s)}")
        if len(strings) > 30:
            print(f"    ... (+{len(strings)-30} more)")

    # ── Cross-references ───────────────────────────────────────────────────
    print(f"\n{SEP}")
    print(f"  CROSS-REFERENCES  ({len(r['cross_references'])})")
    print(SEP2)
    for xr in r["cross_references"][:50]:
        print(f"\n  Trigger  : {xr['trigger']}")
        print(f"  File off : {xr['file_offset']}")
        print(f"  VM addr  : {xr['vm_address']}")
        ctx = xr["context_text"].replace("\n", "\\n").replace("\r", "\\r")
        print(f"  Context  : {repr(ctx)}")
    if len(r["cross_references"]) > 50:
        print(f"  ... (+{len(r['cross_references'])-50} more — see JSON)")

    # ── Load Commands ──────────────────────────────────────────────────────
    print(f"\n{SEP}")
    print(f"  LOAD COMMANDS  ({len(r['load_commands'])})")
    print(SEP2)
    for lc in r["load_commands"]:
        extra = ""
        if "segment" in lc:
            extra = f"  [{lc['segment']}]  vmaddr={lc['vmaddr']}  vmsize={lc['vmsize']}  sections={lc.get('sections', [])}"
        elif "dylib" in lc:
            extra = f"  {lc['dylib']}  v{lc.get('version','?')}"
        elif "uuid" in lc:
            extra = f"  {lc['uuid']}"
        elif "platform" in lc:
            extra = f"  platform={lc['platform']}  minos={lc['minos']}  sdk={lc['sdk']}"
        elif "entryoff" in lc:
            extra = f"  entry={lc['entryoff']}  stack={lc['stacksize']}"
        elif "dylinker" in lc:
            extra = f"  {lc['dylinker']}"
        elif "path" in lc:
            extra = f"  {lc['path']}"
        print(f"  {lc['cmd']:<40}{extra}")

    print(f"\n{SEP}")
    print("  Analysis complete.")
    print(SEP)


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Deep static analysis of Mach-O ARM64 iOS binary",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 analyze_binary.py /path/to/lsd
  python3 analyze_binary.py /path/to/binary --keywords "register,validate,container"
  python3 analyze_binary.py /path/to/binary --output report.json --no-text
""",
    )
    parser.add_argument("binary", help="Path to Mach-O ARM64 binary")
    parser.add_argument(
        "--keywords", "-k",
        default=",".join(DEFAULT_KEYWORDS),
        help="Comma-separated keyword list for string search (default: built-in list)",
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Write JSON report to this file (default: <binary_name>_analysis.json)",
    )
    parser.add_argument(
        "--no-text", action="store_true",
        help="Suppress human-readable stdout output (only write JSON)",
    )
    parser.add_argument(
        "--no-json", action="store_true",
        help="Suppress JSON file output (only print human-readable)",
    )

    args = parser.parse_args()

    keywords = [k.strip() for k in args.keywords.split(",") if k.strip()]

    try:
        report = analyze(args.binary, keywords)
    except (FileNotFoundError, ValueError) as e:
        print(f"[!] Error: {e}", file=sys.stderr)
        sys.exit(1)

    # Human-readable output
    if not args.no_text:
        print_report(report)

    # JSON output
    if not args.no_json:
        out_path = args.output or (Path(args.binary).name + "_analysis.json")

        # Make entitlements JSON-serializable
        def make_serializable(obj):
            if isinstance(obj, bytes):
                return obj.hex()
            if isinstance(obj, dict):
                return {k: make_serializable(v) for k, v in obj.items()}
            if isinstance(obj, list):
                return [make_serializable(i) for i in obj]
            return obj

        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(make_serializable(report), f, indent=2, ensure_ascii=False)
        print(f"\n[+] JSON report written to: {out_path}")


if __name__ == "__main__":
    main()
