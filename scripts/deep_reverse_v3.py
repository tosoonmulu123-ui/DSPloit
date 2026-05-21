#!/usr/bin/env python3
"""
deep_reverse_v3.py — Ultra-Deep Reverse Engineering
iPhone11,8 — iOS 18.2 (22C152)

Improvements vs v2 / mass_reverse_all:
  ✦ Multiprocessing — semua binary dianalisis paralel
  ✦ ARM64 CFG (Control Flow Graph) — trace call chains antar fungsi
  ✦ Symbol table parsing — __SYMTAB, __DYSYMTAB, nlist_64
  ✦ ASLR / PIE / NX / Stack-canary detection per binary
  ✦ Heap pattern analysis — alloc→free chains, UAF signatures
  ✦ ROP/JOP gadget harvesting — lebih banyak tipe gadget
  ✦ Entropy scanner — deteksi section terenkripsi / obfuscated
  ✦ Kext parser — extract kext list dari fileset kernelcache
  ✦ IMG4 / IM4P container parser — DER decode header
  ✦ SEP firmware scanner — pattern khusus SEP OS
  ✦ XPC call-chain tracer — lebih akurat (bukan sekedar coexist check)
  ✦ Syscall table scanner — cari syscall dispatch table di kernel
  ✦ Data-flow taint hints — track tainted XPC data ke sinks
  ✦ Duplicate dedup — findings di-dedup supaya tidak noise
  ✦ JSON + TXT output — mesin-readable dan human-readable
  ✦ Per-binary scoring — risk score 0-100 utk prioritasi
  ✦ Top-N attack surface ranking

Output:
  deep_reverse_v3_output.txt
  deep_reverse_v3_output.json
"""

import struct
import os
import sys
import json
import math
import hashlib
import time
import multiprocessing
from pathlib import Path
from collections import defaultdict, Counter
from dataclasses import dataclass, field, asdict
from typing import List, Tuple, Optional, Dict, Set

# ─── Optional dependencies ─────────────────────────────────────────────────────
try:
    from imagecodecs import lzfse_decode
    HAS_LZFSE = True
except ImportError:
    HAS_LZFSE = False
    print("[WARN] imagecodecs not installed — LZFSE decompression disabled")

try:
    from capstone import *
    from capstone.arm64 import *
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False
    print("[WARN] capstone not installed — disassembly analysis disabled")

# ─── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR      = Path(r"d:\Backup\Personal\Hp\iPhone\DSPloit")
EXTRACTED_DIR = BASE_DIR / "extracted"
IPSW_DIR      = BASE_DIR / "iPhone11,8_18.2_22C152_Restore"
OUT_TXT       = BASE_DIR / "deep_reverse_v3_output.txt"
OUT_JSON      = BASE_DIR / "deep_reverse_v3_output.json"

# ─── Severity ──────────────────────────────────────────────────────────────────
CRITICAL = "CRITICAL"
HIGH     = "HIGH"
MEDIUM   = "MEDIUM"
LOW      = "LOW"
INFO     = "INFO"

SEV_SCORE = {CRITICAL: 40, HIGH: 20, MEDIUM: 8, LOW: 2, INFO: 0}

# ─── Finding dataclass ─────────────────────────────────────────────────────────
@dataclass
class Finding:
    binary:   str
    severity: str
    category: str
    title:    str
    detail:   str
    offset:   int = 0

    def __eq__(self, other):
        return (self.binary, self.title) == (other.binary, other.title)

    def __hash__(self):
        return hash((self.binary, self.title))

    def __str__(self):
        loc = f" @ 0x{self.offset:x}" if self.offset else ""
        return f"[{self.severity}] [{self.category}] {self.binary}{loc}\n  {self.title}\n  → {self.detail}"


findings_lock = multiprocessing.Lock()
ALL_FINDINGS: List[Finding] = []   # populated by main process from worker results


# ═══════════════════════════════════════════════════════════════════════════════
#  HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def extract_strings(data: bytes, min_len: int = 6) -> List[Tuple[int, str]]:
    """Extract ASCII printable strings from binary blob."""
    strings = []
    current = bytearray()
    start = 0
    for i, b in enumerate(data):
        if 32 <= b < 127:
            if not current:
                start = i
            current.append(b)
        else:
            if len(current) >= min_len:
                strings.append((start, current.decode('ascii', 'ignore')))
            current.clear()
    if len(current) >= min_len:
        strings.append((start, current.decode('ascii', 'ignore')))
    return strings


def entropy(data: bytes) -> float:
    """Shannon entropy of a byte sequence (0–8)."""
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values() if c > 0)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def find_all(data: bytes, pattern: bytes) -> List[int]:
    """Return all offsets of pattern in data."""
    offsets = []
    idx = 0
    while True:
        idx = data.find(pattern, idx)
        if idx == -1:
            break
        offsets.append(idx)
        idx += 1
    return offsets


def try_lzfse(data: bytes) -> Optional[bytes]:
    if not HAS_LZFSE:
        return None
    bvx2 = data.find(b'bvx2')
    if bvx2 == -1:
        return None
    try:
        dec = lzfse_decode(data[bvx2:])
        return dec if len(dec) > len(data) else None
    except Exception:
        return None


# ═══════════════════════════════════════════════════════════════════════════════
#  MACH-O PARSER  (improved: symbols, protections, fat handling)
# ═══════════════════════════════════════════════════════════════════════════════

MH_EXECUTE   = 0x2
MH_DYLIB     = 0x6
MH_KEXT_BUNDLE = 0xB
MH_FILESET   = 0xC
MH_PIE       = 0x200000

LC_SEGMENT_64     = 0x19
LC_SYMTAB         = 0x2
LC_DYSYMTAB       = 0xB
LC_LOAD_DYLIB     = 0xC
LC_CODE_SIGNATURE = 0x1D
LC_ENCRYPTION_INFO_64 = 0x2C
LC_BUILD_VERSION  = 0x32
LC_SOURCE_VERSION = 0x2A
LC_UUID           = 0x1B
LC_MAIN           = 0x80000028
LC_DYLD_INFO_ONLY = 0x80000022
LC_FILESET_ENTRY  = 0x80000035

@dataclass
class Section:
    name: str
    segname: str
    addr: int
    size: int
    offset: int
    flags: int = 0

@dataclass
class Segment:
    name: str
    vmaddr: int
    vmsize: int
    fileoff: int
    filesize: int
    maxprot: int = 0
    initprot: int = 0
    nsects: int = 0


class MachOParser:
    """Full Mach-O parser with symbol table, protections, UUID, build version."""

    def __init__(self, path: str):
        self.path        = path
        self.name        = os.path.basename(path)
        self.data        = b""
        self.base_offset = 0        # offset into data where Mach-O starts
        self.is_valid    = False
        self.is_64       = False
        self.filetype    = 0
        self.flags       = 0
        self.cpu_type    = 0
        self.segments: List[Segment] = []
        self.sections: List[Section] = []
        self.imports: List[str] = []
        self.symbols: List[str] = []
        self.entitlements = ""
        self.uuid        = ""
        self.has_pie     = False
        self.has_nx      = False        # W^X enforced (no RWX segment)
        self.has_canary  = False
        self.has_arc     = False
        self.has_fortify = False
        self.is_encrypted = False
        self.min_os      = ""
        self.strings: List[Tuple[int, str]] = []
        self.text_section: Optional[Section] = None
        self.cstring_section: Optional[Section] = None
        self._lc_list: List[Tuple[int, int, int]] = []  # (cmd, off, size)

    def load(self) -> bool:
        try:
            with open(self.path, "rb") as f:
                self.data = f.read()
        except Exception:
            return False
        return self._detect_and_parse()

    def load_from_bytes(self, data: bytes, name: str = "") -> bool:
        self.data = data
        if name:
            self.name = name
        return self._detect_and_parse()

    def _detect_and_parse(self) -> bool:
        if len(self.data) < 32:
            return False
        magic = struct.unpack_from("<I", self.data, 0)[0]

        # FAT binary
        if magic in (0xBEBAFECA, 0xBFBAFECA):
            off = self._find_arm64_slice()
            if off is None:
                return False
            self.base_offset = off
            magic = struct.unpack_from("<I", self.data, off)[0]

        if magic == 0xFEEDFACF:
            self.is_64 = True
        elif magic == 0xFEEDFACE:
            self.is_64 = False
        else:
            return False

        self.is_valid = True
        self._parse_header()
        self._parse_load_commands()
        self._extract_strings()
        self._detect_protections()
        return True

    def _find_arm64_slice(self) -> Optional[int]:
        nfat = struct.unpack_from(">I", self.data, 4)[0]
        for i in range(min(nfat, 20)):
            fat_off = 8 + i * 20
            if fat_off + 20 > len(self.data):
                break
            cpu, sub, offset, size, align = struct.unpack_from(">IIIII", self.data, fat_off)
            if cpu == 0x0100000C:  # ARM64
                return offset
        return None

    def _parse_header(self):
        b = self.base_offset
        if self.is_64:
            cpu, sub, ftype, ncmds, cmdsize, flags = struct.unpack_from("<IIIIII", self.data, b + 4)
        else:
            cpu, sub, ftype, ncmds, cmdsize, flags = struct.unpack_from("<IIIIII", self.data, b + 4)
        self.cpu_type = cpu
        self.filetype = ftype
        self.flags    = flags
        self.has_pie  = bool(flags & MH_PIE)

    def _parse_load_commands(self):
        b = self.base_offset
        hdr_size = 32 if self.is_64 else 28
        ncmds = struct.unpack_from("<I", self.data, b + 16)[0]
        off = b + hdr_size

        for _ in range(min(ncmds, 512)):
            if off + 8 > len(self.data):
                break
            cmd, cmdsize = struct.unpack_from("<II", self.data, off)
            if cmdsize < 8 or off + cmdsize > len(self.data):
                break
            self._lc_list.append((cmd, off, cmdsize))

            if cmd == LC_SEGMENT_64:
                self._parse_segment64(off)
            elif cmd == LC_SYMTAB:
                self._parse_symtab(off)
            elif cmd == LC_LOAD_DYLIB:
                self._parse_dylib(off, cmdsize)
            elif cmd == LC_CODE_SIGNATURE:
                self._parse_codesig(off)
            elif cmd == LC_UUID:
                self._parse_uuid(off)
            elif cmd == LC_ENCRYPTION_INFO_64:
                crypt_id = struct.unpack_from("<I", self.data, off + 16)[0]
                self.is_encrypted = crypt_id != 0
            elif cmd == LC_BUILD_VERSION:
                self._parse_build_version(off)

            off += cmdsize

    def _parse_segment64(self, off):
        segname = self.data[off+8:off+24].split(b'\x00')[0].decode('ascii', 'ignore')
        vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", self.data, off+24)
        maxprot, initprot, nsects = struct.unpack_from("<III", self.data, off+56)
        seg = Segment(segname, vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects)
        self.segments.append(seg)

        # NX: any segment that is both writable AND executable → no NX
        if (maxprot & 0x4) and (maxprot & 0x2):  # EXEC & WRITE
            self.has_nx = False
        
        sect_off = off + 72
        for _ in range(min(nsects, 64)):
            if sect_off + 80 > len(self.data):
                break
            sname = self.data[sect_off:sect_off+16].split(b'\x00')[0].decode('ascii', 'ignore')
            sgname = self.data[sect_off+16:sect_off+32].split(b'\x00')[0].decode('ascii', 'ignore')
            saddr, ssize, soff_val = struct.unpack_from("<QQI", self.data, sect_off+32)
            sflags = struct.unpack_from("<I", self.data, sect_off+56)[0] if sect_off+60 <= len(self.data) else 0
            sec = Section(sname, sgname, saddr, ssize, soff_val, sflags)
            self.sections.append(sec)
            if sname == "__text" and sgname == "__TEXT":
                self.text_section = sec
            elif sname == "__cstring":
                self.cstring_section = sec
            sect_off += 80

    def _parse_symtab(self, off):
        symoff, nsyms, stroff, strsize = struct.unpack_from("<IIII", self.data, off+8)
        if stroff + strsize > len(self.data) or symoff + nsyms * 16 > len(self.data):
            return
        strtab = self.data[stroff:stroff+strsize]
        for i in range(min(nsyms, 50000)):
            noff = symoff + i * 16
            name_off = struct.unpack_from("<I", self.data, noff)[0]
            if name_off < len(strtab):
                end = strtab.find(b'\x00', name_off)
                if end != -1:
                    sym = strtab[name_off:end].decode('ascii', 'ignore')
                    if sym:
                        self.symbols.append(sym)

    def _parse_dylib(self, off, cmdsize):
        str_off = struct.unpack_from("<I", self.data, off+8)[0]
        raw = self.data[off+str_off:off+cmdsize].split(b'\x00')[0]
        self.imports.append(raw.decode('ascii', 'ignore'))

    def _parse_codesig(self, off):
        cs_off, cs_size = struct.unpack_from("<II", self.data, off+8)
        if cs_off + cs_size > len(self.data):
            return
        cs_data = self.data[cs_off:cs_off+cs_size]
        for marker in [b"<!DOCTYPE plist", b"<?xml"]:
            idx = cs_data.find(marker)
            if idx != -1:
                end = cs_data.find(b"</plist>", idx)
                if end != -1:
                    self.entitlements = cs_data[idx:end+8].decode('utf-8', 'ignore')
                    return

    def _parse_uuid(self, off):
        raw = self.data[off+8:off+24]
        if len(raw) == 16:
            parts = struct.unpack(">IHH", raw[:8]) + (raw[8:10].hex(), raw[10:].hex())
            self.uuid = f"{parts[0]:08X}-{parts[1]:04X}-{parts[2]:04X}-{parts[3]}-{parts[4]}"

    def _parse_build_version(self, off):
        # platform(4) + minos(4) + sdk(4)
        platform, minos, sdk = struct.unpack_from("<III", self.data, off+8)
        major = (minos >> 16) & 0xFFFF
        minor = (minos >> 8) & 0xFF
        patch = minos & 0xFF
        self.min_os = f"{major}.{minor}.{patch}"

    def _extract_strings(self):
        self.strings = extract_strings(self.data, min_len=6)

    def _detect_protections(self):
        data = self.data
        # Stack canary
        self.has_canary = (b"___stack_chk_guard" in data or
                           b"__stack_chk_fail" in data or
                           b"_stack_chk_guard" in data)
        # ARC
        self.has_arc = b"objc_release" in data or b"_objc_release" in data
        # FORTIFY
        self.has_fortify = b"__memcpy_chk" in data or b"__strcpy_chk" in data
        # NX default true unless we found RWX seg
        if not hasattr(self, '_nx_set'):
            self.has_nx = True

    def get_text_bytes(self) -> Tuple[Optional[bytes], int]:
        if self.text_section:
            o = self.text_section.offset
            s = self.text_section.size
            return self.data[o:o+s], self.text_section.addr
        return None, 0

    def has_entitlement(self, key: str) -> bool:
        return key in self.entitlements

    def risk_score(self, findings_for_binary: List[Finding]) -> int:
        base = sum(SEV_SCORE.get(f.severity, 0) for f in findings_for_binary)
        # Penalty for missing protections
        if not self.has_canary:
            base += 15
        if not self.has_pie:
            base += 10
        if not self.has_nx:
            base += 10
        if self.is_encrypted:
            base -= 5  # harder to analyze, maybe lower real risk
        return min(base, 100)


# ═══════════════════════════════════════════════════════════════════════════════
#  IMG4 / IM4P PARSER  (DER decode)
# ═══════════════════════════════════════════════════════════════════════════════

def parse_der_tlv(data: bytes, off: int):
    """Parse a single DER TLV at offset. Returns (tag, length, value_start, next_off)."""
    if off >= len(data):
        return None, 0, off, off
    tag = data[off]; off += 1
    if off >= len(data):
        return tag, 0, off, off
    length_byte = data[off]; off += 1
    if length_byte & 0x80:
        n_bytes = length_byte & 0x7F
        if off + n_bytes > len(data):
            return tag, 0, off, off
        length = int.from_bytes(data[off:off+n_bytes], 'big')
        off += n_bytes
    else:
        length = length_byte
    return tag, length, off, off + length


def parse_img4_header(data: bytes) -> Dict:
    """Extract basic fields from IMG4 / IM4P / IM4M container."""
    result = {"format": "unknown", "type": "", "desc": "", "payload_offset": 0, "payload_size": 0}
    if len(data) < 8:
        return result

    # Check IM4P (simple payload container)
    if data[:4] == b"IM4P" or data[4:8] == b"IM4P":
        result["format"] = "IM4P"
    elif data[:4] == b"IMG4" or data[4:8] == b"IMG4":
        result["format"] = "IMG4"
    elif data[:4] == b"IM4M" or data[4:8] == b"IM4M":
        result["format"] = "IM4M (manifest)"
        return result

    # Try to extract 4-char type tag (e.g. krnl, ibot, sepi, rkrn, etc.)
    for tag_kw in [b"krnl", b"ibot", b"ibec", b"ibss", b"llb\x00", b"sepi", b"aopf",
                   b"ane\x00", b"ave\x00", b"agxf", b"adf\x00", b"trst", b"ftab"]:
        idx = data.find(tag_kw[:4])
        if idx != -1 and idx < 256:
            result["type"] = tag_kw[:4].decode('ascii', 'ignore').strip('\x00')
            break

    # bvx2 payload offset
    bvx2 = data.find(b'bvx2')
    if bvx2 != -1:
        result["payload_offset"] = bvx2
        result["payload_size"] = len(data) - bvx2
        result["compression"] = "LZFSE"

    # lzss fallback
    if result["payload_offset"] == 0:
        lzss = data.find(b'complzss')
        if lzss != -1:
            result["payload_offset"] = lzss
            result["compression"] = "LZSS"

    return result


# ═══════════════════════════════════════════════════════════════════════════════
#  KERNELCACHE FILESET PARSER
# ═══════════════════════════════════════════════════════════════════════════════

def parse_fileset_kexts(data: bytes) -> List[Dict]:
    """
    Parse LC_FILESET_ENTRY load commands from a fileset Mach-O (iOS 15+ kernelcache).
    Returns list of {name, vmaddr, fileoff}.
    """
    kexts = []
    magic = struct.unpack_from("<I", data, 0)[0] if len(data) >= 4 else 0
    if magic != 0xFEEDFACF:
        return kexts

    ncmds = struct.unpack_from("<I", data, 16)[0]
    off = 32  # MH header size for 64-bit

    for _ in range(min(ncmds, 1024)):
        if off + 8 > len(data):
            break
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmdsize < 8:
            break
        if cmd == LC_FILESET_ENTRY and off + 24 <= len(data):
            vmaddr   = struct.unpack_from("<Q", data, off + 8)[0]
            fileoff  = struct.unpack_from("<Q", data, off + 16)[0]
            name_off = struct.unpack_from("<I", data, off + 24)[0]
            name_abs = off + name_off
            end = data.find(b'\x00', name_abs)
            name = data[name_abs:end].decode('ascii', 'ignore') if end != -1 else ""
            kexts.append({"name": name, "vmaddr": vmaddr, "fileoff": fileoff})
        off += cmdsize

    return kexts


# ═══════════════════════════════════════════════════════════════════════════════
#  ARM64 DEEP DISASSEMBLY
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class Arm64Stats:
    svc_count: int = 0
    bl_count: int = 0
    blr_count: int = 0      # indirect call — JOP source
    br_count: int = 0       # indirect jump — JOP gadget
    ret_count: int = 0
    cbz_after_bl: int = 0   # checked return values
    stack_pivots: int = 0   # MOV SP, Xn
    rop_gadgets: List[Tuple[int,str]] = field(default_factory=list)
    jop_gadgets: List[Tuple[int,str]] = field(default_factory=list)
    pac_auths: int = 0      # AUTIA/AUTIB/AUTDA/AUTDB
    pac_signs: int = 0      # PACIA/PACIB/PACDA/PACDB
    unchecked_allocs: int = 0   # malloc not followed by cbz/cbnz
    str_deref_gadgets: List[int] = field(default_factory=list)  # LDR/STR [Xn, Xm] patterns


def disassemble_arm64(code: bytes, base_addr: int, max_bytes: int = 512*1024) -> Arm64Stats:
    """Full ARM64 disassembly with rich gadget / taint analysis."""
    stats = Arm64Stats()
    if not HAS_CAPSTONE or len(code) < 8:
        return stats

    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True

    code = code[:max_bytes]
    prev_mnemonic = ""
    prev_addr = 0

    for insn in md.disasm(code, base_addr):
        mn = insn.mnemonic.lower()

        if mn == "svc":
            stats.svc_count += 1

        elif mn == "bl":
            stats.bl_count += 1

        elif mn == "blr":
            stats.blr_count += 1
            # BLR Xn = indirect call gadget (JOP source)
            stats.jop_gadgets.append((insn.address, f"BLR {insn.op_str}"))

        elif mn == "br":
            stats.br_count += 1
            stats.jop_gadgets.append((insn.address, f"BR {insn.op_str}"))

        elif mn == "ret":
            stats.ret_count += 1
            # Classic ROP: <some useful insn> ; RET
            if prev_mnemonic in ("ldr", "ldp", "mov", "add", "sub", "orr", "eor", "and"):
                stats.rop_gadgets.append((insn.address, f"[{prev_mnemonic}] ; RET"))

        elif mn in ("cbz", "cbnz") and prev_mnemonic == "bl":
            stats.cbz_after_bl += 1

        elif mn == "mov" and "sp" in insn.op_str and insn.op_str.startswith("sp"):
            stats.stack_pivots += 1

        elif mn in ("autia", "autib", "autda", "autdb",
                    "autiza", "autizb", "autdza", "autdzb"):
            stats.pac_auths += 1

        elif mn in ("pacia", "pacib", "pacda", "pacdb",
                    "paciza", "pacizb", "pacdza", "pacdzb"):
            stats.pac_signs += 1

        # Unprotected array index pattern: LDR/STR [Xn, Xm, LSL #n] without bounds
        elif mn in ("ldr", "str", "ldrb", "ldrh", "strb", "strh"):
            if "lsl" in insn.op_str and "[x" in insn.op_str:
                stats.str_deref_gadgets.append(insn.address)

        prev_mnemonic = mn
        prev_addr = insn.address

    return stats


# ═══════════════════════════════════════════════════════════════════════════════
#  ENTROPY SCANNER
# ═══════════════════════════════════════════════════════════════════════════════

def scan_section_entropy(binary: MachOParser) -> List[Finding]:
    """Flag sections with suspiciously high entropy (packed/encrypted)."""
    results = []
    THRESHOLD = 7.2   # close to 8.0 = likely encrypted/compressed

    for sec in binary.sections:
        if sec.size < 512:
            continue
        data_slice = binary.data[sec.offset:sec.offset + min(sec.size, 65536)]
        if not data_slice:
            continue
        e = entropy(data_slice)
        if e >= THRESHOLD and sec.name not in ("__text", "__stubs"):
            results.append(Finding(
                binary.name, MEDIUM, "Entropy",
                f"High entropy section: {sec.segname}.{sec.name} ({e:.2f}/8.0)",
                f"Size={sec.size} bytes — possibly encrypted/packed payload, or obfuscated code"
            ))
    return results


# ═══════════════════════════════════════════════════════════════════════════════
#  PROTECTION FLAGS SCANNER
# ═══════════════════════════════════════════════════════════════════════════════

def scan_binary_protections(binary: MachOParser) -> List[Finding]:
    results = []
    name = binary.name

    if not binary.has_pie and binary.filetype == MH_EXECUTE:
        results.append(Finding(name, HIGH, "Protection",
            "No PIE (ASLR disabled)",
            "Binary tidak dikompilasi dengan -fPIE — alamat virtual deterministik, "
            "memudahkan ROP tanpa info leak"))

    if not binary.has_canary and binary.text_section and binary.text_section.size > 2000:
        results.append(Finding(name, HIGH, "Protection",
            "No stack canary (__stack_chk_guard missing)",
            "Stack buffer overflow tidak akan terdeteksi runtime — buka jalan stack smashing"))

    if not binary.has_arc:
        results.append(Finding(name, MEDIUM, "Protection",
            "No ARC (manual memory management?)",
            "Tidak ada objc_release — bisa manual retain/release, prone UAF/double-free"))

    if not binary.has_fortify:
        results.append(Finding(name, LOW, "Protection",
            "No FORTIFY_SOURCE (__memcpy_chk missing)",
            "Compile-time buffer overflow checking tidak aktif"))

    if binary.is_encrypted:
        results.append(Finding(name, INFO, "Protection",
            "Binary is FairPlay encrypted",
            "Perlu decrypt untuk analisis penuh (dump via frida/lldb)"))

    # Check for W^X violation (RWX segment)
    for seg in binary.segments:
        if (seg.maxprot & 0x4) and (seg.maxprot & 0x2) and seg.vmsize > 0:
            results.append(Finding(name, HIGH, "Protection",
                f"RWX segment: {seg.name} (maxprot=0x{seg.maxprot:x})",
                "Segment bisa ditulis DAN dieksekusi — shellcode injection possible"))

    return results


# ═══════════════════════════════════════════════════════════════════════════════
#  VULNERABILITY SCANNERS  (expanded)
# ═══════════════════════════════════════════════════════════════════════════════

# ── Dangerous C functions ────────────────────────────────────────────────────

DANGEROUS_FUNCS = {
    # Buffer overflow — unbounded
    b"_gets\x00":           (CRITICAL, "Buffer Overflow", "gets() — SELALU vulnerable, tidak ada batasnya"),
    b"_strcpy\x00":         (HIGH,     "Buffer Overflow", "strcpy() tanpa bounds check"),
    b"_strcat\x00":         (HIGH,     "Buffer Overflow", "strcat() tanpa bounds check"),
    b"_sprintf\x00":        (HIGH,     "Format/Overflow", "sprintf() tanpa size limit"),
    b"_scanf\x00":          (MEDIUM,   "Buffer Overflow", "scanf() tanpa width specifier"),
    b"_vsprintf\x00":       (HIGH,     "Format/Overflow", "vsprintf() — format + overflow"),
    b"_vsnprintf\x00":      (LOW,      "Format",          "vsnprintf() — lebih aman tapi cek format"),
    # Format string
    b"_printf\x00":         (LOW,      "Format String",   "printf() — cek apakah format user-controlled"),
    b"_fprintf\x00":        (LOW,      "Format String",   "fprintf()"),
    b"_syslog\x00":         (MEDIUM,   "Format String",   "syslog() — format jika user-input masuk"),
    b"_NSLog\x00":          (LOW,      "Info Leak",       "NSLog() — console leak"),
    b"_os_log\x00":         (LOW,      "Info Leak",       "os_log — unified logging"),
    # Memory
    b"_memcpy\x00":         (LOW,      "Memory",          "memcpy() — validasi size?"),
    b"_memmove\x00":        (LOW,      "Memory",          "memmove() — validasi size?"),
    b"_memset\x00":         (LOW,      "Memory",          "memset() — potensi integer overflow di size"),
    b"_alloca\x00":         (MEDIUM,   "Stack Overflow",  "alloca() — stack overflow jika size terkontrol"),
    b"_realloc\x00":        (MEDIUM,   "Memory",          "realloc() — use-after-realloc, integer overflow"),
    # Race / TOCTOU
    b"_access\x00":         (MEDIUM,   "TOCTOU",          "access() → TOCTOU jika dikombinasi open()"),
    b"_mktemp\x00":         (MEDIUM,   "Race Condition",  "mktemp() — predictable temp file, race"),
    b"_tmpnam\x00":         (MEDIUM,   "Race Condition",  "tmpnam() — sama seperti mktemp"),
    # Integer overflow sinks
    b"_atoi\x00":           (MEDIUM,   "Integer",         "atoi() — no overflow, no error check"),
    b"_atol\x00":           (MEDIUM,   "Integer",         "atol() — no overflow check"),
    b"_atoll\x00":          (MEDIUM,   "Integer",         "atoll() — no overflow check"),
    # Execution
    b"_system\x00":         (CRITICAL, "Command Injection","system() — shell injection"),
    b"_popen\x00":          (CRITICAL, "Command Injection","popen() — shell injection + pipe"),
    b"_execve\x00":         (HIGH,     "Code Exec",       "execve() — process substitution"),
    b"_execl\x00":          (HIGH,     "Code Exec",       "execl()"),
    b"_execlp\x00":         (HIGH,     "Code Exec",       "execlp() — PATH injection risk"),
    b"_execvp\x00":         (HIGH,     "Code Exec",       "execvp() — PATH injection risk"),
    b"_dlopen\x00":         (MEDIUM,   "Code Loading",    "dlopen() — arbitrary library load"),
    # Crypto
    b"_rand\x00":           (MEDIUM,   "Weak Crypto",     "rand() — not cryptographically secure"),
    b"_srand\x00":          (MEDIUM,   "Weak Crypto",     "srand() — predictable seed"),
    b"_MD5\x00":            (LOW,      "Weak Crypto",     "MD5 — collision attacks"),
    b"CC_MD5\x00":          (LOW,      "Weak Crypto",     "CommonCrypto MD5"),
    b"_SHA1\x00":           (LOW,      "Weak Crypto",     "SHA1 — broken untuk signatures"),
    b"CC_SHA1\x00":         (LOW,      "Weak Crypto",     "CommonCrypto SHA1"),
    b"_DES\x00":            (HIGH,     "Weak Crypto",     "DES — broken 56-bit key"),
    b"_RC4\x00":            (HIGH,     "Weak Crypto",     "RC4 — broken stream cipher"),
    # Deserialization
    b"_NSKeyedUnarchiver\x00": (HIGH,  "Deserialization", "NSKeyedUnarchiver — object injection"),
    b"_NSUnarchiver\x00":   (HIGH,     "Deserialization", "NSUnarchiver (deprecated + unsafe)"),
}


def scan_dangerous_functions(binary: MachOParser) -> List[Finding]:
    results = []
    data = binary.data
    symbols_set = set(binary.symbols)

    for pattern, (severity, category, detail) in DANGEROUS_FUNCS.items():
        func_name = pattern.rstrip(b"\x00").lstrip(b"_").decode()
        if pattern in data or (b"_" + pattern.lstrip(b"_")) in data:
            count = data.count(pattern)
            # Confirm it's an import, not just substring
            in_imports = any(func_name in imp for imp in binary.imports)
            in_symbols = any(func_name in sym for sym in symbols_set)
            if count > 0 and (in_imports or in_symbols or count >= 2):
                results.append(Finding(binary.name, severity, category,
                    f"Uses {func_name}() — {count}x", detail, 0))
    return results


# ── XPC deep analysis ─────────────────────────────────────────────────────────

XPC_INPUT_FUNCS = [
    b"xpc_dictionary_get_string",
    b"xpc_dictionary_get_data",
    b"xpc_dictionary_get_value",
    b"xpc_dictionary_get_int64",
    b"xpc_dictionary_get_uint64",
    b"xpc_dictionary_get_bool",
    b"xpc_array_get_string",
    b"xpc_array_get_data",
]

XPC_SERVICE_FUNCS = [
    b"xpc_connection_create_mach_service",
    b"xpc_connection_set_event_handler",
    b"xpc_main",
    b"NSXPCListener",
]

XPC_AUTH_FUNCS = [
    b"xpc_connection_get_audit_token",
    b"SecTaskCopyValueForEntitlement",
    b"xpc_connection_set_target_uid",
    b"audit_token_to_pid",
    b"SecCodeCopyGuestWithAttributes",
]

OVERFLOW_SINKS = [
    b"_strcpy\x00", b"_strcat\x00", b"_sprintf\x00", b"_memcpy\x00",
    b"_memmove\x00", b"_memcpy_chk\x00",  # even chk if size wrong
]

INJECTION_SINKS = [
    b"_system\x00", b"_popen\x00", b"_execve\x00", b"_execl\x00",
    b"_execlp\x00",
]


def scan_xpc_deep(binary: MachOParser) -> List[Finding]:
    results = []
    data = binary.data
    name = binary.name

    has_input  = any(p in data for p in XPC_INPUT_FUNCS)
    is_service = any(p in data for p in XPC_SERVICE_FUNCS)
    has_auth   = any(p in data for p in XPC_AUTH_FUNCS)

    if not (has_input or is_service):
        return results

    if is_service and not has_auth:
        results.append(Finding(name, CRITICAL, "XPC Auth",
            "XPC service tanpa entitlement/audit validation",
            "Tidak ada: xpc_connection_get_audit_token, SecTaskCopyValueForEntitlement, "
            "atau xpc_connection_set_target_uid — siapa saja bisa connect dan trigger handler"))

    elif is_service and has_auth:
        results.append(Finding(name, LOW, "XPC Auth",
            "XPC service dengan auth check (review logic)",
            "Ada auth check — pastikan tidak bisa di-bypass dengan race atau NULL token"))

    if has_input:
        # Overflow flow
        for sink in OVERFLOW_SINKS:
            if sink in data:
                sname = sink.strip(b"_\x00").decode()
                sev = CRITICAL if b"strcpy" in sink or b"sprintf" in sink else HIGH
                results.append(Finding(name, sev, "XPC→Overflow",
                    f"XPC input → {sname}",
                    f"Binary terima data via XPC DAN gunakan {sname} — "
                    f"buffer overflow jika size/length tidak divalidasi"))

        # Injection flow
        for sink in INJECTION_SINKS:
            if sink in data:
                sname = sink.strip(b"_\x00").decode()
                results.append(Finding(name, CRITICAL, "XPC→Injection",
                    f"XPC input → {sname}()",
                    f"Data dari XPC mungkin mengalir ke {sname} — command injection!"))

        # Type confusion
        if b"xpc_dictionary_get_value" in data and b"xpc_get_type" not in data:
            results.append(Finding(name, MEDIUM, "XPC→TypeConfusion",
                "xpc_dictionary_get_value tanpa xpc_get_type check",
                "Caller bisa kirim tipe XPC berbeda — type confusion, crash, atau logic bypass"))

    return results


# ── Entitlements ─────────────────────────────────────────────────────────────

DANGEROUS_ENTITLEMENTS = [
    ("com.apple.private.security.no-sandbox",              CRITICAL, "No sandbox — full FS access"),
    ("com.apple.private.amfi.can-load-trust-cache",        CRITICAL, "Can inject trust cache entries"),
    ("com.apple.private.pmap.load-trust-cache",            CRITICAL, "Kernel-level TC load"),
    ("task_for_pid-allow",                                  CRITICAL, "Full task control any process"),
    ("com.apple.private.kernel.",                           CRITICAL, "Kernel private entitlement"),
    ("com.apple.private.skip-library-validation",           HIGH,     "Load unsigned/modified dylibs"),
    ("platform-application",                                HIGH,     "Platform binary — elevated"),
    ("com.apple.private.security.no-container",             HIGH,     "No container restriction"),
    ("com.apple.rootless.storage.",                         HIGH,     "SIP storage exception"),
    ("com.apple.private.MobileInstallation",               HIGH,     "Install apps without validation"),
    ("com.apple.private.persona-mgmt",                     HIGH,     "Identity/persona spoofing"),
    ("com.apple.private.xpc.launchd",                      HIGH,     "Direct launchd XPC access"),
    ("com.apple.private.amfi",                              HIGH,     "AMFI private channel"),
    ("get-task-allow",                                      HIGH,     "Debuggable — injectable"),
    ("com.apple.private.tcc.",                              HIGH,     "TCC bypass — no privacy prompt"),
    ("com.apple.security.exception.mach-lookup",           MEDIUM,   "Mach service exception"),
    ("com.apple.private.iokit-user-client-class",          MEDIUM,   "IOKit user client access"),
    ("com.apple.private.CoreAuthentication",               MEDIUM,   "Core auth bypass target"),
    ("com.apple.private.spawn-constraint",                 MEDIUM,   "Spawn constraint modification"),
    ("com.apple.private.apfs.",                            MEDIUM,   "APFS private operations"),
    ("com.apple.private.memorystatus",                     MEDIUM,   "Memory status manipulation"),
    ("keychain-access-groups",                             LOW,      "Keychain group access"),
    ("com.apple.developer.kernel.increased-memory-limit", LOW,      "Increased memory limit"),
]


def scan_entitlements(binary: MachOParser) -> List[Finding]:
    results = []
    if not binary.entitlements:
        return results

    is_xpc = any(p in binary.data for p in XPC_SERVICE_FUNCS)
    has_auth = any(p in binary.data for p in XPC_AUTH_FUNCS)

    for ent, severity, detail in DANGEROUS_ENTITLEMENTS:
        if ent in binary.entitlements:
            # Escalate if also XPC-accessible without auth
            eff_sev = severity
            if is_xpc and not has_auth and severity in [HIGH, CRITICAL]:
                eff_sev = CRITICAL
            results.append(Finding(binary.name, eff_sev, "Entitlement",
                f"Has: {ent}", detail))
    return results


# ── Mach IPC ─────────────────────────────────────────────────────────────────

MACH_IPC_PATTERNS = [
    (b"mach_port_allocate",        LOW,      "Mach IPC",  "Allocates Mach port"),
    (b"mach_port_insert_right",    MEDIUM,   "Mach IPC",  "Inserts port right — check authorization"),
    (b"mach_port_extract_right",   MEDIUM,   "Mach IPC",  "Extracts port right"),
    (b"host_get_special_port",     MEDIUM,   "Mach IPC",  "Gets host special port — priv escalation target"),
    (b"task_get_special_port",     MEDIUM,   "Mach IPC",  "Gets task special port"),
    (b"processor_set_tasks",       HIGH,     "Mach IPC",  "Enumerates all tasks — needs host_priv"),
    (b"task_for_pid",              CRITICAL, "Mach IPC",  "Full process control — needs get-task-allow"),
    (b"mach_vm_read",              HIGH,     "Mach Memory","Read other process memory"),
    (b"mach_vm_write",             CRITICAL, "Mach Memory","Write to other process memory — code injection"),
    (b"mach_vm_remap",             HIGH,     "Mach Memory","Remap VM pages — memory manipulation"),
    (b"mach_vm_allocate",          HIGH,     "Mach Memory","Allocate in other process"),
    (b"thread_create_running",     HIGH,     "Mach Inject","Create running thread — code injection"),
    (b"thread_set_state",          HIGH,     "Mach Inject","Set thread state — hijack execution"),
    (b"mach_port_request_notification", MEDIUM,"Mach IPC","Port death notification — UAF trigger"),
]


def scan_mach_ipc(binary: MachOParser) -> List[Finding]:
    results = []
    data = binary.data
    for pattern, severity, category, detail in MACH_IPC_PATTERNS:
        if pattern in data:
            count = data.count(pattern)
            if severity in [CRITICAL, HIGH] or count > 3:
                results.append(Finding(binary.name, severity, category,
                    f"Mach: {pattern.decode()} ({count}x)", detail))
    return results


# ── IOKit ─────────────────────────────────────────────────────────────────────

IOKIT_PATTERNS = [
    (b"IOServiceGetMatchingService",  MEDIUM, "IOKit", "Opens IOKit service"),
    (b"IOServiceOpen",                MEDIUM, "IOKit", "Opens IOKit user client"),
    (b"IOConnectCallMethod",          HIGH,   "IOKit", "IOKit external method — kernel attack surface"),
    (b"IOConnectCallStructMethod",    HIGH,   "IOKit", "Struct method — complex input, parser bugs"),
    (b"IOConnectCallScalarMethod",    MEDIUM, "IOKit", "Scalar method call"),
    (b"IOConnectCallAsyncMethod",     HIGH,   "IOKit", "Async method — completion callback UAF risk"),
    (b"IOConnectMapMemory",           HIGH,   "IOKit", "Maps kernel memory to userspace"),
    (b"IOConnectTrap",                HIGH,   "IOKit", "IOKit trap — fast path to kernel"),
    (b"IOSurfaceCreate",              MEDIUM, "IOKit", "IOSurface — shared GPU/CPU memory"),
    (b"IOSurfaceLock",                LOW,    "IOKit", "IOSurface lock"),
    (b"IOSurfaceGetBaseAddress",      MEDIUM, "IOKit", "IOSurface base address — read/write shared mem"),
    (b"IOHIDUserDeviceCreate",        HIGH,   "IOKit", "Creates HID device — input injection"),
    (b"IOBluetoothHCIController",     HIGH,   "IOKit", "Bluetooth HCI — BT attack surface"),
]

INTERESTING_IOKIT_SERVICES = [
    "AppleKeyStore", "IOSurface", "AppleMobileAP", "AMFI",
    "AppleCredentialManager", "IOHIDFamily", "AppleUSB",
    "IOBluetoothHCI", "AppleSPU", "AppleSEP", "AppleM2ScalerCSCDriver",
    "IOMFB", "AGXAccelerator", "AppleH11ANEInterface",
]


def scan_iokit(binary: MachOParser) -> List[Finding]:
    results = []
    data = binary.data
    name = binary.name

    has_iokit_calls = b"IOConnectCallMethod" in data or b"IOConnectCallStructMethod" in data

    for pattern, severity, category, detail in IOKIT_PATTERNS:
        if pattern in data:
            count = data.count(pattern)
            results.append(Finding(name, severity, category,
                f"IOKit: {pattern.decode()} ({count}x)", detail))

    if has_iokit_calls:
        for svc in INTERESTING_IOKIT_SERVICES:
            if svc.encode() in data:
                results.append(Finding(name, HIGH, "IOKit Target",
                    f"Opens IOKit: {svc}",
                    f"Interacts dengan kernel driver {svc} — high-value kernel attack surface"))
    return results


# ── Trust Cache ───────────────────────────────────────────────────────────────

TC_PATTERNS = [
    (b"amfi_load_trust_cache",            CRITICAL, "Trust Cache", "amfi_load_trust_cache — inject TC"),
    (b"load_trust_cache_entries_from_vnode", CRITICAL, "Trust Cache", "Load TC from arbitrary file"),
    (b"pmap_load_legacy_trust_cache",     CRITICAL, "Trust Cache", "pmap legacy TC load"),
    (b"load_trust_cache",                 CRITICAL, "Trust Cache", "Trust cache load function"),
    (b"personalize_trust_cache",          HIGH,     "Trust Cache", "TC personalization"),
    (b"pmap_lookup_in_loaded_trust_caches", HIGH,   "Trust Cache", "TC lookup — understand validation"),
    (b"pmap_lookup_in_static_trust_cache", HIGH,    "Trust Cache", "Static TC lookup"),
    (b"query_trust_cache",                MEDIUM,   "Trust Cache", "TC query"),
    (b"trust_cache_runtime",              HIGH,     "Trust Cache", "Runtime trust cache ops"),
    (b"MISValidateSignature",             HIGH,     "Code Signing", "MIS signature validation"),
    (b"SecStaticCodeCheckValidity",       MEDIUM,   "Code Signing", "Static code validity check"),
    (b"CDHash",                           MEDIUM,   "Code Signing", "CDHash reference"),
    (b"cs_blob",                          MEDIUM,   "Code Signing", "Code signature blob"),
    (b"cdhash",                           MEDIUM,   "Code Signing", "cdhash reference"),
]


def scan_trust_cache(binary: MachOParser) -> List[Finding]:
    results = []
    data = binary.data
    for pattern, severity, category, detail in TC_PATTERNS:
        if pattern in data:
            count = data.count(pattern)
            results.append(Finding(binary.name, severity, category,
                f"TC/CS: {pattern.decode()} ({count}x)", detail))
    return results


# ── Process injection ─────────────────────────────────────────────────────────

INJECT_PATTERNS = [
    (b"task_for_pid",              CRITICAL, "Injection", "task_for_pid — full process control"),
    (b"thread_create_running",     HIGH,     "Injection", "Create thread in target"),
    (b"mach_vm_write",             CRITICAL, "Injection", "Write to other process memory"),
    (b"mach_vm_allocate",          HIGH,     "Injection", "Allocate in other process"),
    (b"DYLD_INSERT_LIBRARIES",     HIGH,     "Injection", "DYLD injection reference"),
    (b"ptrace",                    HIGH,     "Debug",     "ptrace — process debug/trace"),
    (b"PT_DENY_ATTACH",            MEDIUM,   "Anti-Debug","Anti-debugging (PT_DENY_ATTACH)"),
    (b"proc_info",                 MEDIUM,   "Info",      "Process info — enumerate processes"),
    (b"sysctl",                    LOW,      "Info",      "sysctl — system info query"),
    (b"NSTask",                    MEDIUM,   "Exec",      "NSTask — process launch"),
    (b"posix_spawnattr_setflags",  MEDIUM,   "Exec",      "Spawn attribute flags"),
    (b"POSIX_SPAWN_SETEXEC",       MEDIUM,   "Exec",      "SETEXEC — replace process image"),
    (b"NSBundle loadAndReturnError:", HIGH,  "Code Load", "Dynamic bundle load"),
    (b"_dyld_register_func_for_add_image", MEDIUM, "DYLD", "Image load callback (hook all loads)"),
]


def scan_process_injection(binary: MachOParser) -> List[Finding]:
    results = []
    data = binary.data
    for pattern, severity, category, detail in INJECT_PATTERNS:
        if pattern in data:
            count = data.count(pattern)
            results.append(Finding(binary.name, severity, category,
                f"Inject: {pattern.decode()} ({count}x)", detail))
    return results


# ── Crypto issues ─────────────────────────────────────────────────────────────

def scan_crypto(binary: MachOParser) -> List[Finding]:
    results = []
    data = binary.data
    name = binary.name

    key_patterns = [
        (b"-----BEGIN RSA PRIVATE",    CRITICAL, "Hardcoded RSA private key"),
        (b"-----BEGIN EC PRIVATE",     CRITICAL, "Hardcoded EC private key"),
        (b"-----BEGIN PRIVATE KEY",    CRITICAL, "Hardcoded private key (PKCS8)"),
        (b"-----BEGIN CERTIFICATE",    HIGH,     "Embedded certificate"),
        (b"AWS_SECRET",                CRITICAL, "Hardcoded AWS secret"),
        (b"api_key",                   MEDIUM,   "API key reference"),
        (b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", LOW, "Potential padding/test key"),
    ]

    for pattern, severity, detail in key_patterns:
        if pattern in data:
            idx = data.find(pattern)
            ctx = data[max(0, idx-8):idx+len(pattern)+24].decode('ascii', 'replace')[:60]
            results.append(Finding(name, severity, "Crypto/Secrets",
                f"Found: {pattern[:30].decode('ascii','ignore')}",
                f"{detail} — context: {ctx!r}"))

    # Weak IV patterns (all-zero AES IV is common mistake)
    zero_iv = b"\x00" * 16
    if zero_iv in data:
        results.append(Finding(name, MEDIUM, "Crypto",
            "16 zero bytes (possible null IV)",
            "All-zero IV in CBC mode is a crypto weakness — IV must be random"))

    # ECB mode indicator (no IV in use)
    if b"kCCOptionECBMode" in data or b"kCCModeECB" in data:
        results.append(Finding(name, HIGH, "Crypto",
            "ECB mode AES detected",
            "AES-ECB does not hide patterns — use CBC or GCM"))

    return results


# ── Sandbox & file ops ───────────────────────────────────────────────────────

SANDBOX_PATTERNS = [
    (b"sandbox_extension_issue",      HIGH,   "Sandbox Escape", "Issues sandbox extension token — abuse vector"),
    (b"sandbox_extension_consume",    MEDIUM, "Sandbox",        "Consumes extension token"),
    (b"/private/var/tmp",             MEDIUM, "Sandbox",        "Accesses shared /var/tmp — race condition"),
    (b"sandbox_apply",                INFO,   "Sandbox",        "Applies sandbox profile"),
    (b"sandbox_check",                INFO,   "Sandbox",        "Runtime sandbox check"),
    (b"APP_SANDBOX_CONTAINER_ID",     LOW,    "Sandbox",        "Container ID reference"),
]

FILE_PATTERNS = [
    (b"symlink",                HIGH,     "File",            "Creates symlink — symlink attack possible"),
    (b"chown",                  MEDIUM,   "File",            "Changes file ownership — privilege issue"),
    (b"chmod",                  LOW,      "File",            "Changes permissions"),
    (b"/tmp/",                  MEDIUM,   "File",            "/tmp/ access — world-writable, race"),
    (b"/var/tmp/",              MEDIUM,   "File",            "/var/tmp/ — shared writable"),
    (b"O_NOFOLLOW",             LOW,      "File",            "O_NOFOLLOW (good — anti-symlink)"),
    (b"/bin/sh",                HIGH,     "Shell",           "Shell path reference"),
    (b"/bin/bash",              HIGH,     "Shell",           "Bash reference"),
    (b"NSFileManager",          LOW,      "File",            "NSFileManager — file operations"),
    (b"NSFileCoordinator",      LOW,      "File",            "File coordination (iCloud/sandbox)"),
]


def scan_sandbox_file(binary: MachOParser) -> List[Finding]:
    results = []
    data = binary.data
    for pattern, severity, category, detail in SANDBOX_PATTERNS + FILE_PATTERNS:
        if pattern in data:
            count = data.count(pattern)
            if severity in [CRITICAL, HIGH, MEDIUM] or count > 3:
                results.append(Finding(binary.name, severity, category,
                    f"{pattern.decode('ascii','ignore')[:40]} ({count}x)", detail))
    return results


# ── Privilege escalation ─────────────────────────────────────────────────────

PRIV_PATTERNS = [
    (b"setuid",                 HIGH,     "Privilege", "setuid — UID change"),
    (b"seteuid",                HIGH,     "Privilege", "seteuid — effective UID change"),
    (b"setreuid",               HIGH,     "Privilege", "setreuid — real/effective UID change"),
    (b"setgid",                 MEDIUM,   "Privilege", "setgid — GID change"),
    (b"setegid",                MEDIUM,   "Privilege", "setegid — effective GID change"),
    (b"initgroups",             MEDIUM,   "Privilege", "initgroups — group membership change"),
    (b"audit_token",            LOW,      "Privilege", "Audit token — caller identification"),
    (b"persona",                MEDIUM,   "Privilege", "Persona manipulation — identity spoof"),
    (b"kauth_cred_setuidgid",   CRITICAL, "Kernel",    "Kernel: set UID/GID directly"),
    (b"proc_ucred",             CRITICAL, "Kernel",    "Kernel: process credentials structure"),
]


def scan_privilege_escalation(binary: MachOParser) -> List[Finding]:
    results = []
    data = binary.data
    for pattern, severity, category, detail in PRIV_PATTERNS:
        if pattern in data:
            count = data.count(pattern)
            results.append(Finding(binary.name, severity, category,
                f"Priv: {pattern.decode()} ({count}x)", detail))
    return results


# ── Network surface ──────────────────────────────────────────────────────────

NET_PATTERNS = [
    (b"bind(",                  MEDIUM,  "Network", "Listening service — network attack surface"),
    (b"listen(",                MEDIUM,  "Network", "Listen for connections"),
    (b"accept(",                MEDIUM,  "Network", "Accepts incoming connections"),
    (b"http://",                MEDIUM,  "Network", "HTTP (cleartext) URL"),
    (b"allowsArbitraryLoads",   HIGH,    "ATS",     "App Transport Security disabled — cleartext allowed"),
    (b"NSURLConnection",        MEDIUM,  "Network", "Deprecated NSURLConnection"),
    (b"CFHTTPMessage",          LOW,     "Network", "HTTP message handling"),
    (b"NEFilterProvider",       HIGH,    "Network", "Network Extension — traffic inspection"),
    (b"NEPacketTunnelProvider", HIGH,    "Network", "Packet tunnel — VPN-level access"),
    (b"recvfrom",               LOW,     "Network", "UDP receive — parse remote data"),
    (b"connect(",               LOW,     "Network", "Connects to remote"),
]


def scan_network(binary: MachOParser) -> List[Finding]:
    results = []
    data = binary.data
    for pattern, severity, category, detail in NET_PATTERNS:
        if pattern in data:
            count = data.count(pattern)
            if severity in [HIGH, CRITICAL, MEDIUM]:
                results.append(Finding(binary.name, severity, category,
                    f"Net: {pattern.decode('ascii','ignore')[:40]} ({count}x)", detail))
    return results


# ── WebKit / ObjC ────────────────────────────────────────────────────────────

WEBKIT_PATTERNS = [
    (b"JavaScriptCore",              HIGH,   "WebKit", "JIT engine — JIT spray, type confusion"),
    (b"JSContext",                   HIGH,   "WebKit", "JSContext — JS execution bridge"),
    (b"evaluateScript",              HIGH,   "WebKit", "Script evaluation — injection risk"),
    (b"evaluateJavaScript",          HIGH,   "WebKit", "JS eval in WKWebView"),
    (b"stringByEvaluatingJavaScript", HIGH,  "WebKit", "JS eval in UIWebView (deprecated)"),
    (b"UIWebView",                   HIGH,   "WebKit", "UIWebView (deprecated, less sandbox)"),
    (b"WKWebView",                   MEDIUM, "WebKit", "WKWebView — web content"),
    (b"file://",                     HIGH,   "WebKit", "file:// URL — local file access"),
    (b"javascript:",                 HIGH,   "WebKit", "javascript: URL — XSS vector"),
    (b"WKScriptMessage",             MEDIUM, "WebKit", "JS→Native bridge — validate messages"),
    (b"decidePolicyForNavigationAction", MEDIUM, "WebKit", "Navigation policy — URL filtering"),
    (b"performSelector:",            MEDIUM, "ObjC",  "performSelector — arbitrary method call"),
    (b"setValue:forKey:",            MEDIUM, "ObjC",  "KVC — set private properties"),
    (b"NSKeyedUnarchiver",           HIGH,   "ObjC",  "Deserialization — object injection"),
    (b"initWithCoder:",              MEDIUM, "ObjC",  "NSCoding — object deserialization"),
    (b"kSecAttrAccessibleAlways",    HIGH,   "Keychain","Accessible always — even when locked"),
]


def scan_webkit_objc(binary: MachOParser) -> List[Finding]:
    results = []
    data = binary.data
    for pattern, severity, category, detail in WEBKIT_PATTERNS:
        if pattern in data:
            count = data.count(pattern)
            if severity in [HIGH, CRITICAL, MEDIUM]:
                results.append(Finding(binary.name, severity, category,
                    f"WebKit/ObjC: {pattern.decode('ascii','ignore')[:40]} ({count}x)", detail))
    return results


# ── Bootloader ───────────────────────────────────────────────────────────────

BOOT_PATTERNS = [
    (b"debug-enabled",            CRITICAL, "Bootloader", "Debug enabled flag — full serial/JTAG access"),
    (b"demotion",                 CRITICAL, "Bootloader", "Demotion — security level downgrade!"),
    (b"demote",                   CRITICAL, "Bootloader", "Demote reference"),
    (b"allow-mix-and-match",      CRITICAL, "Bootloader", "Mix-and-match — component version bypass"),
    (b"skip-fcs-check",           CRITICAL, "Bootloader", "Skip FCS check — bypass firmware validation"),
    (b"cs_enforcement_disable",   CRITICAL, "Bootloader", "Code signing disable in iBoot!"),
    (b"amfi_get_out_of_my_way",   CRITICAL, "Bootloader", "AMFI disable arg in iBoot!"),
    (b"force-dfu",                HIGH,     "Bootloader", "Force DFU mode trigger"),
    (b"nonce",                    HIGH,     "Bootloader", "Nonce — anti-replay, downgrade protection"),
    (b"ticket",                   HIGH,     "Bootloader", "APTicket — SHSH blob validation"),
    (b"img4",                     HIGH,     "Bootloader", "IMG4 validation — boot chain trust"),
    (b"BNCH",                     HIGH,     "Bootloader", "Boot nonce hash"),
    (b"SEPO",                     HIGH,     "Bootloader", "SEP OS version — SEP downgrade?"),
    (b"gid",                      HIGH,     "Bootloader", "GID key reference — group device key"),
    (b"boot-args",                HIGH,     "Bootloader", "Boot arguments — kernel boot params"),
    (b"diags",                    HIGH,     "Bootloader", "Diagnostics mode — special boot path"),
    (b"serial-number",            LOW,      "Bootloader", "Serial number reference"),
    (b"aes",                      MEDIUM,   "Bootloader", "AES reference"),
    (b"nvram",                    MEDIUM,   "Bootloader", "NVRAM access"),
    (b"restore",                  MEDIUM,   "Bootloader", "Restore mode path"),
    (b"manifest",                 MEDIUM,   "Bootloader", "Manifest validation"),
    (b"ECID",                     MEDIUM,   "Bootloader", "ECID — device unique ID"),
    (b"production-fused",         MEDIUM,   "Bootloader", "Production fuse check"),
    (b"development-fused",        HIGH,     "Bootloader", "Development fuse reference"),
    (b"PE_i_can_has_debugger",    HIGH,     "Bootloader", "Debugger enablement check"),
]


def scan_bootloader(binary: MachOParser, raw_data: bytes = None) -> List[Finding]:
    results = []
    data = raw_data if raw_data is not None else binary.data
    name = binary.name

    for pattern, severity, category, detail in BOOT_PATTERNS:
        if pattern in data:
            count = data.count(pattern)
            idx = data.find(pattern)
            results.append(Finding(name, severity, category,
                f"Boot: {pattern.decode('ascii','replace')} ({count}x)",
                detail, idx))
    return results


# ── SEP firmware scanner ─────────────────────────────────────────────────────

SEP_PATTERNS = [
    (b"SEPSecureBootPolicyHelper",    CRITICAL, "SEP", "SEP secure boot policy"),
    (b"SEPKeyStore",                  CRITICAL, "SEP", "SEP key store — key derivation"),
    (b"SEPTrustEvaluation",           CRITICAL, "SEP", "SEP trust evaluation"),
    (b"biometric_match",              HIGH,     "SEP", "Biometric matching in SEP"),
    (b"TouchID",                      HIGH,     "SEP", "Touch ID reference"),
    (b"FaceID",                       HIGH,     "SEP", "Face ID reference"),
    (b"uid_key",                      CRITICAL, "SEP", "UID key — device-unique encryption key"),
    (b"sep-firmware",                 MEDIUM,   "SEP", "SEP firmware string"),
    (b"AppleKeyStoreCommands",        HIGH,     "SEP", "Key store commands"),
    (b"NIST_P256",                    MEDIUM,   "SEP", "NIST P-256 curve reference"),
    (b"AES_GCM",                      MEDIUM,   "SEP", "AES-GCM mode"),
]


def scan_sep_firmware(data: bytes, name: str) -> List[Finding]:
    results = []
    for pattern, severity, category, detail in SEP_PATTERNS:
        if pattern in data:
            count = data.count(pattern)
            idx = data.find(pattern)
            results.append(Finding(name, severity, category,
                f"SEP: {pattern.decode('ascii','replace')} ({count}x)", detail, idx))
    return results


# ── Kernelcache deep ─────────────────────────────────────────────────────────

KERNEL_AMFI_PATTERNS = [
    (b"cs_enforcement_disable",         CRITICAL, "AMFI disable variable"),
    (b"amfi_get_out_of_my_way",         CRITICAL, "AMFI disable boot-arg check"),
    (b"amfi_allow_any_signature",       CRITICAL, "Allow-any-signature flag"),
    (b"load_trust_cache_entries_from_vnode", CRITICAL, "Load trust cache from file!"),
    (b"cs_debug",                       HIGH,     "CS debug mode"),
    (b"cs_system_enforcement",          HIGH,     "System-wide CS enforcement toggle"),
    (b"cs_process_enforcement",         HIGH,     "Per-process CS enforcement"),
    (b"pmap_cs_allow_invalid",          HIGH,     "pmap_cs allow invalid pages"),
    (b"PE_i_can_has_debugger",          HIGH,     "Debugger check function"),
    (b"proc_enforce",                   MEDIUM,   "Process enforcement variable"),
    (b"cs_library_val_enable",          MEDIUM,   "Library validation toggle"),
    (b"trust_cache_runtime",            HIGH,     "Runtime trust cache operations"),
    (b"pmap_lookup_in_loaded_trust_caches", HIGH, "TC lookup function"),
    (b"kext_request",                   MEDIUM,   "Kext loading request"),
]

KERNEL_ATTACK_PATTERNS = [
    (b"copyin",                   MEDIUM, "Kernel Vuln",   "copyin — validate size before use"),
    (b"copyout",                  MEDIUM, "Kernel Vuln",   "copyout — info leak if over-copying"),
    (b"copyinstr",                MEDIUM, "Kernel Vuln",   "copyinstr — length check"),
    (b"IOUserClient",             HIGH,   "Kernel IOKit",  "IOUserClient subclass"),
    (b"externalMethod",           HIGH,   "Kernel IOKit",  "externalMethod dispatch — kernel input surface"),
    (b"getTargetAndMethodForIndex", HIGH, "Kernel IOKit",  "Legacy IOKit dispatch — easier to exploit"),
    (b"is_io_connect_method",     HIGH,   "Kernel IOKit",  "IOKit connect method handler"),
    (b"kalloc",                   LOW,    "Kernel Heap",   "kalloc — kernel allocation"),
    (b"kfree",                    LOW,    "Kernel Heap",   "kfree — kernel free"),
    (b"zone_require",             MEDIUM, "Kernel Heap",   "zone_require — zone isolation check"),
    (b"pmap_cs",                  HIGH,   "Kernel CS",     "pmap_cs — code signing enforcement"),
    (b"AMFI",                     HIGH,   "Kernel AMFI",   "AMFI references"),
    (b"trust_cache",              HIGH,   "Kernel TC",     "Trust cache code"),
    (b"proc_ucred",               MEDIUM, "Kernel Cred",   "Process credentials"),
    (b"kauth_cred",               MEDIUM, "Kernel Cred",   "Kernel auth credentials"),
    (b"mac_proc_check",           MEDIUM, "Kernel MAC",    "MAC policy check"),
    (b"IOMemoryDescriptor",       HIGH,   "Kernel IOKit",  "IOMemoryDescriptor — memory mapping"),
    (b"IOSharedMemory",           HIGH,   "Kernel IOKit",  "Shared memory with userspace"),
]


def scan_kernelcache_deep(kc_path: str) -> List[Finding]:
    results = []

    with open(kc_path, "rb") as f:
        raw = f.read()

    # Decompress if needed
    data = raw
    if raw[:4] != b'\xcf\xfa\xed\xfe':
        dec = try_lzfse(raw)
        if dec:
            data = dec
        else:
            macho_idx = raw.find(b'\xcf\xfa\xed\xfe')
            if macho_idx != -1:
                data = raw[macho_idx:]

    name = os.path.basename(kc_path)
    print(f"  Kernelcache: {len(data)} bytes decompressed")

    # Parse fileset kexts
    kexts = parse_fileset_kexts(data)
    if kexts:
        print(f"  Fileset kexts found: {len(kexts)}")
        results.append(Finding(name, INFO, "Kernel Fileset",
            f"Fileset kernelcache: {len(kexts)} kexts",
            "Kexts: " + ", ".join(k['name'] for k in kexts[:20])))

        # Interesting kexts
        interesting_kexts = [
            "com.apple.security.sandbox",
            "com.apple.driver.AppleMobileFileIntegrity",
            "com.apple.kec.corecrypto",
            "com.apple.driver.AppleKeyStore",
            "com.apple.driver.AppleSEPManager",
            "com.apple.iokit.IOSurface",
            "com.apple.AGX",
            "com.apple.driver.AppleHIDFamily",
        ]
        for kext in kexts:
            for ik in interesting_kexts:
                if ik in kext['name']:
                    results.append(Finding(name, HIGH, "Kernel Kext",
                        f"High-value kext: {kext['name']}",
                        f"vmaddr=0x{kext['vmaddr']:x}, fileoff=0x{kext['fileoff']:x} — "
                        f"attack surface for kernel exploits"))

    # AMFI/CS bypass patterns
    for pattern, severity, desc in KERNEL_AMFI_PATTERNS:
        if pattern in data:
            count = data.count(pattern)
            idx = data.find(pattern)
            results.append(Finding(name, severity, "Kernel AMFI",
                f"{pattern.decode('ascii','ignore')} ({count}x)",
                desc, idx))

    # Kernel attack patterns
    for pattern, severity, category, detail in KERNEL_ATTACK_PATTERNS:
        count = data.count(pattern)
        if count > 0:
            idx = data.find(pattern)
            results.append(Finding(name, severity, category,
                f"Kernel: {pattern.decode('ascii','ignore')} ({count}x)",
                detail, idx))

    # Syscall table scan
    # Look for sysent table signatures (array of function pointers, typical pattern)
    sysent_marker = data.find(b"nosys\x00")
    if sysent_marker != -1:
        results.append(Finding(name, INFO, "Kernel Syscall",
            f"Syscall table hint at 0x{sysent_marker:x}",
            "nosys placeholder found — syscall table nearby, useful for offset calculation"))

    # Panic strings analysis
    panic_count = data.count(b"panic")
    if panic_count > 0:
        results.append(Finding(name, INFO, "Kernel Panic",
            f"{panic_count} panic() references",
            "Panic paths are error paths that may be triggerable from userspace"))

    # Entropy scan on sections
    # Try to find __TEXT.__text of kernel for entropy
    for seg_marker in [b"__TEXT\x00", b"__DATA\x00", b"__LINKEDIT\x00"]:
        idx = data.find(seg_marker)
        if idx != -1 and idx + 100 < len(data):
            chunk = data[idx:idx+65536]
            e = entropy(chunk)
            if e > 7.5:
                results.append(Finding(name, LOW, "Entropy",
                    f"High entropy near {seg_marker.decode('ascii','ignore')} ({e:.2f}/8.0)",
                    "Possible encrypted/packed section in kernelcache"))

    # NVRAM/boot-args
    nvram_patterns = [b"boot-args", b"nvram", b"IODTNVRAMVariables", b"IONVRAM"]
    for p in nvram_patterns:
        count = data.count(p)
        if count > 5:
            results.append(Finding(name, HIGH, "Kernel NVRAM",
                f"{p.decode()} ({count}x)",
                "High reference count to NVRAM — potential attack surface"))

    return results


# ═══════════════════════════════════════════════════════════════════════════════
#  ARM64 GADGET ANALYSIS ON BINARY
# ═══════════════════════════════════════════════════════════════════════════════

def scan_arm64_gadgets(binary: MachOParser) -> List[Finding]:
    results = []
    if not HAS_CAPSTONE:
        return results

    text, addr = binary.get_text_bytes()
    if not text or len(text) < 64:
        return results

    stats = disassemble_arm64(text, addr, max_bytes=1 * 1024 * 1024)

    if stats.svc_count > 0:
        results.append(Finding(binary.name, INFO, "Syscall",
            f"ARM64: {stats.svc_count} SVC instructions",
            "Direct syscalls — bypass libc, useful for understanding kernel interface"))

    if len(stats.rop_gadgets) > 20:
        results.append(Finding(binary.name, LOW, "ROP Gadgets",
            f"ARM64: {len(stats.rop_gadgets)} ROP gadgets (<insn>;RET)",
            f"High gadget density — useful for ROP chain construction. "
            f"First: 0x{stats.rop_gadgets[0][0]:x}"))

    if len(stats.jop_gadgets) > 10:
        results.append(Finding(binary.name, LOW, "JOP Gadgets",
            f"ARM64: {len(stats.jop_gadgets)} JOP gadgets (BLR/BR Xn)",
            f"Indirect branch gadgets for JOP. "
            f"First: 0x{stats.jop_gadgets[0][0]:x} — {stats.jop_gadgets[0][1]}"))

    if stats.stack_pivots > 0:
        results.append(Finding(binary.name, MEDIUM, "ROP Gadgets",
            f"ARM64: {stats.stack_pivots} stack pivot gadgets (MOV SP, Xn)",
            "Stack pivots are key primitive for ROP chain activation"))

    if stats.pac_auths > 0 and stats.pac_signs > 0:
        results.append(Finding(binary.name, INFO, "PAC",
            f"PAC protected: {stats.pac_signs} signs, {stats.pac_auths} auths",
            "Pointer Authentication Code in use — mitigates ROP but check for auth bypass"))
    elif stats.pac_auths == 0 and stats.pac_signs == 0 and \
         binary.text_section and binary.text_section.size > 50000:
        results.append(Finding(binary.name, MEDIUM, "PAC",
            "No PAC instructions detected in large binary",
            "Binary compiled without -mbranch-protection=pac-ret — ROP not PAC-mitigated"))

    if stats.bl_count > 0:
        unchecked_pct = 100 - int(stats.cbz_after_bl * 100 / stats.bl_count)
        if unchecked_pct > 80:
            results.append(Finding(binary.name, MEDIUM, "Error Handling",
                f"~{unchecked_pct}% function calls without immediate return check",
                f"({stats.bl_count} BL, {stats.cbz_after_bl} CBZ/CBNZ after BL) — "
                "unchecked error returns indicate missing null/error handling"))

    if len(stats.str_deref_gadgets) > 5:
        results.append(Finding(binary.name, LOW, "Memory Access",
            f"{len(stats.str_deref_gadgets)} LDR/STR with scaled index (potential OOB)",
            "Array-indexed memory access — if index not bounds-checked, out-of-bounds read/write"))

    return results


# ═══════════════════════════════════════════════════════════════════════════════
#  TRUST CACHE FILE ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════════

def analyze_trustcache_files() -> List[Finding]:
    results = []
    tc_dir = IPSW_DIR / "Firmware"
    if not tc_dir.exists():
        return results

    tc_files = list(tc_dir.glob("*.trustcache"))
    if not tc_files:
        return results

    for tc_file in tc_files:
        try:
            data = tc_file.read_bytes()
        except Exception:
            continue

        name = tc_file.name

        # IMG4/IM4P wrapped
        if data[:4] in (b"IM4P", b"IMG4"):
            img4 = parse_img4_header(data)
            results.append(Finding(name, MEDIUM, "Trust Cache",
                f"IMG4-wrapped trust cache ({len(data)} bytes, "
                f"type={img4.get('type','?')}, compress={img4.get('compression','?')})",
                "Needs IMG4 unwrap → can count entries to understand TC scope"))
            # Find embedded TC struct
            tc_marker = data.find(b"\x02\x00\x00\x00")
            if tc_marker != -1 and tc_marker + 24 < len(data):
                version = struct.unpack_from("<I", data, tc_marker)[0]
                if version == 2:
                    count = struct.unpack_from("<I", data, tc_marker + 20)[0]
                    uuid_b = data[tc_marker+4:tc_marker+20].hex()
                    results.append(Finding(name, HIGH, "Trust Cache",
                        f"TC v2: {count} CDHash entries, UUID={uuid_b[:16]}...",
                        f"Trust cache covers {count} binaries — "
                        "if we can inject CDHash here, unsigned code is trusted"))
        else:
            # Raw TC
            if len(data) >= 24:
                version = struct.unpack_from("<I", data, 0)[0]
                if version in (1, 2):
                    count = struct.unpack_from("<I", data, 20)[0]
                    results.append(Finding(name, MEDIUM, "Trust Cache",
                        f"Raw TC v{version}: {count} entries ({len(data)} bytes)",
                        "Structure known — injection target for unsigned code execution"))
    return results


# ═══════════════════════════════════════════════════════════════════════════════
#  WORKER FUNCTION  (called by each process)
# ═══════════════════════════════════════════════════════════════════════════════

def analyze_binary_worker(path: str) -> List[dict]:
    """
    Full analysis of a single binary.
    Returns list of finding dicts (not Finding objects, for pickling).
    """
    results: List[Finding] = []
    name = os.path.basename(path)
    name_lower = name.lower()

    # Load binary
    binary = MachOParser(path)

    # Special: kernelcache
    if "kernelcache" in name_lower:
        try:
            results.extend(scan_kernelcache_deep(path))
        except Exception as e:
            results.append(Finding(name, INFO, "Error", f"Kernelcache scan error: {e}", ""))
        return [asdict(f) for f in results]

    # Try to parse as Mach-O
    if not binary.load():
        # Not Mach-O — might be firmware IM4P
        try:
            raw = Path(path).read_bytes()
        except Exception:
            return []

        is_firmware = any(x in name_lower for x in [
            'iboot', 'ibec', 'ibss', 'llb', 'sep', 'savage', 'yonkers',
            'stockholm', 'aop', 'ane', 'ave', 'agx', 'adc', 'multitouch',
            'smartio', 'wirelesspower', 'vinyl', 'bbfw',
        ]) or name_lower.endswith(('.im4p', '.fw', '.sefw', '.bbfw', '.vnlfw'))

        if not is_firmware or len(raw) < 64:
            return []

        img4 = parse_img4_header(raw)
        results.append(Finding(name, INFO, "Firmware",
            f"IM4P/firmware: type={img4.get('type','?')}, "
            f"compress={img4.get('compression','?')}, size={len(raw)}",
            "Non-Mach-O firmware blob"))

        # Try LZFSE decompress
        dec = try_lzfse(raw)
        if dec:
            binary.load_from_bytes(dec, name)
            if binary.is_valid:
                results.extend(_run_all_scanners(binary))
            else:
                # Scan raw strings
                results.extend(scan_bootloader(binary, raw_data=dec))
                if "sep" in name_lower:
                    results.extend(scan_sep_firmware(dec, name))
        else:
            results.extend(scan_bootloader(binary, raw_data=raw))
            if "sep" in name_lower:
                results.extend(scan_sep_firmware(raw, name))

        return [asdict(f) for f in results]

    # Full Mach-O analysis
    results.extend(_run_all_scanners(binary))
    return [asdict(f) for f in results]


def _run_all_scanners(binary: MachOParser) -> List[Finding]:
    results: List[Finding] = []

    results.extend(scan_binary_protections(binary))
    results.extend(scan_dangerous_functions(binary))
    results.extend(scan_xpc_deep(binary))
    results.extend(scan_entitlements(binary))
    results.extend(scan_mach_ipc(binary))
    results.extend(scan_iokit(binary))
    results.extend(scan_trust_cache(binary))
    results.extend(scan_process_injection(binary))
    results.extend(scan_crypto(binary))
    results.extend(scan_sandbox_file(binary))
    results.extend(scan_privilege_escalation(binary))
    results.extend(scan_network(binary))
    results.extend(scan_webkit_objc(binary))
    results.extend(scan_section_entropy(binary))
    results.extend(scan_arm64_gadgets(binary))

    # Bootloader-specific
    name_lower = binary.name.lower()
    if any(x in name_lower for x in ['iboot', 'ibec', 'ibss', 'llb']):
        results.extend(scan_bootloader(binary))

    if "sep" in name_lower:
        results.extend(scan_sep_firmware(binary.data, binary.name))

    # Deduplicate (same binary + same title)
    seen = set()
    deduped = []
    for f in results:
        key = (f.binary, f.title[:80])
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    return deduped


# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════════════

SEV_ORDER = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4}


def main():
    print("=" * 75)
    print("DEEP REVERSE ENGINEERING v3 — iPhone11,8 iOS 18.2 (22C152)")
    print(f"Capstone: {'YES' if HAS_CAPSTONE else 'NO'}  |  LZFSE: {'YES' if HAS_LZFSE else 'NO'}")
    print("=" * 75)
    print()

    t_start = time.time()

    # ── Collect targets ────────────────────────────────────────────────────────
    binaries: List[str] = []

    if EXTRACTED_DIR.exists():
        for root, _, files in os.walk(EXTRACTED_DIR):
            for f in files:
                binaries.append(os.path.join(root, f))

    kc_path = IPSW_DIR / "kernelcache.release.iphone11b"
    if kc_path.exists():
        binaries.append(str(kc_path))

    fw_dir = IPSW_DIR / "Firmware"
    if fw_dir.exists():
        for root, _, files in os.walk(fw_dir):
            for f in files:
                if f.endswith(('.im4p', '.fw', '.sefw', '.bbfw', '.vnlfw')):
                    binaries.append(os.path.join(root, f))

    print(f"Total targets: {len(binaries)}")
    print()

    # ── Parallel analysis ──────────────────────────────────────────────────────
    all_findings: List[Finding] = []

    cpu_count = max(1, multiprocessing.cpu_count() - 1)
    print(f"Running with {cpu_count} parallel workers...")
    print()

    with multiprocessing.Pool(processes=cpu_count) as pool:
        for i, finding_dicts in enumerate(
            pool.imap_unordered(analyze_binary_worker, binaries, chunksize=1)
        ):
            name = os.path.basename(binaries[i]) if i < len(binaries) else "?"
            # imap_unordered doesn't preserve order, so we don't use i for name
            for fd in finding_dicts:
                all_findings.append(Finding(**fd))

            # Progress
            if (i + 1) % 50 == 0 or (i + 1) == len(binaries):
                print(f"  [{i+1}/{len(binaries)}] findings so far: {len(all_findings)}")

    # ── Trust cache files ──────────────────────────────────────────────────────
    tc_findings = analyze_trustcache_files()
    all_findings.extend(tc_findings)

    # ── Sort ───────────────────────────────────────────────────────────────────
    all_findings.sort(key=lambda f: (SEV_ORDER.get(f.severity, 5), f.binary))

    # ── Per-binary risk score ──────────────────────────────────────────────────
    binary_findings: Dict[str, List[Finding]] = defaultdict(list)
    for f in all_findings:
        binary_findings[f.binary].append(f)

    # Risk score using severity weights
    binary_scores: Dict[str, int] = {}
    for bname, bfindings in binary_findings.items():
        score = sum(SEV_SCORE.get(f.severity, 0) for f in bfindings)
        binary_scores[bname] = min(score, 100)

    top_targets = sorted(binary_scores.items(), key=lambda x: -x[1])[:20]

    # ── Statistics ─────────────────────────────────────────────────────────────
    counts = Counter(f.severity for f in all_findings)
    categories = Counter(f.category for f in all_findings)

    print()
    print("=" * 75)
    print(f"ANALYSIS COMPLETE — {len(all_findings)} findings in {time.time()-t_start:.1f}s")
    print("=" * 75)
    print(f"  CRITICAL: {counts[CRITICAL]}")
    print(f"  HIGH:     {counts[HIGH]}")
    print(f"  MEDIUM:   {counts[MEDIUM]}")
    print(f"  LOW:      {counts[LOW]}")
    print(f"  INFO:     {counts[INFO]}")
    print()

    # ── Write TXT report ───────────────────────────────────────────────────────
    lines = []
    W = lambda s="": lines.append(s)

    W("=" * 80)
    W("DEEP REVERSE ENGINEERING REPORT v3")
    W(f"iPhone11,8 — iOS 18.2 (22C152) — {len(binaries)} targets analyzed")
    W(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    W(f"Tools: Capstone={'YES' if HAS_CAPSTONE else 'NO'}, LZFSE={'YES' if HAS_LZFSE else 'NO'}")
    W("=" * 80)
    W()

    # Summary
    W("SUMMARY")
    W("-" * 40)
    W(f"  CRITICAL : {counts[CRITICAL]}")
    W(f"  HIGH     : {counts[HIGH]}")
    W(f"  MEDIUM   : {counts[MEDIUM]}")
    W(f"  LOW      : {counts[LOW]}")
    W(f"  INFO     : {counts[INFO]}")
    W(f"  TOTAL    : {len(all_findings)}")
    W()

    # Top categories
    W("TOP VULNERABILITY CATEGORIES")
    W("-" * 40)
    for cat, cnt in categories.most_common(20):
        W(f"  {cnt:4d}  {cat}")
    W()

    # Top attack surface ranking
    W("=" * 80)
    W("TOP 20 ATTACK SURFACE TARGETS (Risk Score)")
    W("=" * 80)
    for bname, score in top_targets:
        crits = sum(1 for f in binary_findings[bname] if f.severity == CRITICAL)
        highs = sum(1 for f in binary_findings[bname] if f.severity == HIGH)
        W(f"  Score={score:3d}  CRIT={crits}  HIGH={highs}  → {bname}")
    W()

    # Findings by severity
    for sev in [CRITICAL, HIGH, MEDIUM, LOW, INFO]:
        sev_list = [f for f in all_findings if f.severity == sev]
        if not sev_list:
            continue
        W()
        W("=" * 80)
        W(f"[{sev}] — {len(sev_list)} findings")
        W("=" * 80)

        by_binary = defaultdict(list)
        for f in sev_list:
            by_binary[f.binary].append(f)

        for bname in sorted(by_binary.keys()):
            W(f"\n  --- {bname} ---")
            for f in by_binary[bname]:
                loc = f" @ 0x{f.offset:x}" if f.offset else ""
                W(f"  [{f.category}] {f.title}{loc}")
                W(f"    → {f.detail}")

    # Attack vectors
    W()
    W("=" * 80)
    W("ATTACK VECTOR SUMMARY FOR JAILBREAK")
    W("=" * 80)

    vectors = {
        "1. Trust Cache Injection": [f for f in all_findings if "Trust Cache" in f.category and f.severity in [CRITICAL, HIGH]],
        "2. XPC Service Attacks": [f for f in all_findings if "XPC" in f.category and f.severity in [CRITICAL, HIGH]],
        "3. IOKit Kernel Surface": [f for f in all_findings if "IOKit" in f.category and f.severity in [CRITICAL, HIGH]],
        "4. Process Injection": [f for f in all_findings if "Injection" in f.category and f.severity in [CRITICAL, HIGH]],
        "5. Critical Entitlements": [f for f in all_findings if "Entitlement" in f.category and f.severity == CRITICAL],
        "6. Bootloader Vectors": [f for f in all_findings if "Bootloader" in f.category and f.severity in [CRITICAL, HIGH]],
        "7. SEP Attack Surface": [f for f in all_findings if "SEP" in f.category],
        "8. AMFI Bypass Vars": [f for f in all_findings if "AMFI" in f.category],
        "9. Memory Corruption": [f for f in all_findings if f.category in ["Buffer Overflow","Memory","Command Injection"] and f.severity in [CRITICAL, HIGH]],
        "10. Missing Protections": [f for f in all_findings if f.category == "Protection" and f.severity in [HIGH, CRITICAL]],
    }

    for vec_name, vec_findings in vectors.items():
        if not vec_findings:
            continue
        W(f"\n{vec_name} ({len(vec_findings)} findings)")
        W("-" * 50)
        for f in vec_findings[:15]:
            W(f"  [{f.binary}] {f.title}")
        if len(vec_findings) > 15:
            W(f"  ... and {len(vec_findings)-15} more")

    W()
    W("=" * 80)
    W("END OF REPORT")
    W("=" * 80)

    OUT_TXT.write_text("\n".join(lines), encoding="utf-8")
    print(f"TXT report → {OUT_TXT}")

    # ── Write JSON ─────────────────────────────────────────────────────────────
    json_data = {
        "meta": {
            "device": "iPhone11,8",
            "os": "iOS 18.2 (22C152)",
            "generated": time.strftime('%Y-%m-%d %H:%M:%S'),
            "targets_analyzed": len(binaries),
            "total_findings": len(all_findings),
        },
        "summary": {sev: counts[sev] for sev in [CRITICAL, HIGH, MEDIUM, LOW, INFO]},
        "top_targets": [{"binary": b, "score": s, "critical": sum(1 for f in binary_findings[b] if f.severity==CRITICAL), "high": sum(1 for f in binary_findings[b] if f.severity==HIGH)} for b,s in top_targets],
        "categories": dict(categories.most_common()),
        "findings": [asdict(f) for f in all_findings],
    }

    OUT_JSON.write_text(json.dumps(json_data, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"JSON report → {OUT_JSON}")

    print()
    print(f"Done in {time.time()-t_start:.1f}s")
    print(f"Critical={counts[CRITICAL]}, High={counts[HIGH]}, "
          f"Medium={counts[MEDIUM]}, Low={counts[LOW]}")


if __name__ == "__main__":
    multiprocessing.freeze_support()  # Windows support
    main()