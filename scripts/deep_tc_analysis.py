#!/usr/bin/env python3
"""
Deep Trust Cache & AMFI Bypass Analysis for iOS 18.2 (A12 / T8020).

This script performs exhaustive analysis of the kernelcache to find:
1. Dynamic trust cache linked list (heap-allocated, WRITABLE)
2. pmap_cs code signing subsystem entry points
3. AMFI.kext dispatch tables and function pointers
4. trust_cache_runtime_add call sites and struct layout
5. Alternative bypass vectors (CoreTrust, provisioning profile hooks)

Usage:
  python scripts/deep_tc_analysis.py                    # Full analysis
  python scripts/deep_tc_analysis.py --dynamic-tc       # Focus on dynamic TC
  python scripts/deep_tc_analysis.py --pmap-cs          # Focus on pmap_cs
  python scripts/deep_tc_analysis.py --amfi-dispatch    # AMFI dispatch tables
  python scripts/deep_tc_analysis.py --call-graph       # Trust cache call graph
  python scripts/deep_tc_analysis.py --bypass-vectors   # All bypass vectors
  python scripts/deep_tc_analysis.py --emit-offsets     # Emit Swift offsets

Output: deep_probe_out.txt (full report) + console summary
"""

from __future__ import annotations

import struct
import sys
import re
import json
import hashlib
from collections import Counter, defaultdict
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional

# ─── Constants ───────────────────────────────────────────────────────────────

LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x02
LC_DYSYMTAB = 0x0B
LC_FILESET_ENTRY = 0x80000035
MH_MAGIC_64 = 0xFEEDFACF

# Strings to search for in kernelcache
DYNAMIC_TC_STRINGS = [
    b"trust_cache_runtime_add",
    b"trust_cache_runtime_remove",
    b"pmap_lookup_in_loaded_trust_caches",
    b"pmap_lookup_in_static_trust_cache",
    b"pmap_cs_associate",
    b"pmap_cs_cd_register",
    b"pmap_cs_lookup_copy",
    b"amfi_check_dyld_policy_self",
    b"AMFI: trust cache",
    b"loaded trust caches",
    b"static trust cache",
    b"runtime trust cache",
    b"personalized trust cache",
    b"engineering trust cache",
    b"developer trust cache",
    b"loadable trust cache",
    b"trust_cache_module_loaded",
    b"tc_runtime_instance",
    b"trust_cache_ct_",
    b"CoreTrust",
    b"CT_evaluate_trust",
    b"amfi_interface",
    b"AppleMobileFileIntegrity",
]

# ARM64 instruction helpers
def decode_adrp(insn: int, pc: int) -> Optional[int]:
    if (insn & 0x9F000000) != 0x90000000:
        return None
    immlo = (insn >> 29) & 3
    immhi = (insn >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    if imm & (1 << 20):
        imm -= 1 << 21
    return (pc & ~0xFFF) + (imm << 12)

def decode_add_imm(insn: int) -> Optional[tuple[int, int, int]]:
    if (insn & 0xFF800000) != 0x91000000:
        return None
    imm = (insn >> 10) & 0xFFF
    if (insn >> 22) & 1:
        imm <<= 12
    rn = (insn >> 5) & 0x1F
    rd = insn & 0x1F
    return rn, rd, imm

def decode_bl(insn: int, pc: int) -> Optional[int]:
    """Decode BL instruction → target address."""
    if (insn >> 26) != 0x25:  # BL = 100101
        return None
    imm26 = insn & 0x3FFFFFF
    if imm26 & (1 << 25):
        imm26 -= 1 << 26
    return pc + (imm26 << 2)

def decode_b(insn: int, pc: int) -> Optional[int]:
    """Decode B instruction → target address."""
    if (insn >> 26) != 0x05:  # B = 000101
        return None
    imm26 = insn & 0x3FFFFFF
    if imm26 & (1 << 25):
        imm26 -= 1 << 26
    return pc + (imm26 << 2)

def decode_ldr_imm(insn: int) -> Optional[tuple[int, int, int, int]]:
    """Decode LDR Xt, [Xn, #imm] → (size, rt, rn, offset)."""
    size = (insn >> 30) & 3
    if (insn & 0x3B400000) != 0x39400000:
        return None
    opc = (insn >> 22) & 3
    if opc not in (0, 1):  # LDR only
        return None
    imm12 = (insn >> 10) & 0xFFF
    rn = (insn >> 5) & 0x1F
    rt = insn & 0x1F
    offset = imm12 << size
    return size, rt, rn, offset

def decode_str_imm(insn: int) -> Optional[tuple[int, int, int, int]]:
    """Decode STR Xt, [Xn, #imm] → (size, rt, rn, offset)."""
    size = (insn >> 30) & 3
    if (insn & 0x3B400000) != 0x39000000:
        return None
    imm12 = (insn >> 10) & 0xFFF
    rn = (insn >> 5) & 0x1F
    rt = insn & 0x1F
    offset = imm12 << size
    return size, rt, rn, offset

def strip_pac(v: int) -> int:
    if v == 0:
        return 0
    if (v >> 55) & 1:
        return v | 0xFFFF000000000000
    return v

def is_kernel_va(v: int) -> bool:
    v = strip_pac(v)
    return v >= 0xFFFFFF8000000000

# ─── Data classes ────────────────────────────────────────────────────────────

@dataclass
class Segment:
    name: str
    vmaddr: int
    vmsize: int
    fileoff: int
    filesize: int

@dataclass
class FilesetComponent:
    name: str
    vmaddr: int
    fileoff: int
    segments: list[Segment] = field(default_factory=list)

@dataclass
class FunctionRef:
    """A reference to a function found via string xref or BL target."""
    name: str
    va: int  # unslid VA of function start
    fileoff: int
    callers: list[int] = field(default_factory=list)  # PCs that BL to this
    callees: list[int] = field(default_factory=list)  # BL targets from this func

@dataclass
class DataSlot:
    """A __DATA global variable slot."""
    offset_in_data: int
    va: int
    static_value: int  # value in kernelcache file (0 = runtime heap ptr)
    adrp_refs: int  # number of ADRP+ADD refs from __TEXT_EXEC
    str_refs: int  # number of STR to this slot
    ldr_refs: int  # number of LDR from this slot
    notes: list[str] = field(default_factory=list)

@dataclass
class BypassVector:
    """A potential bypass approach."""
    name: str
    feasibility: str  # "HIGH", "MEDIUM", "LOW", "IMPOSSIBLE"
    description: str
    requirements: list[str]
    data_offsets: list[int] = field(default_factory=list)  # relevant __DATA offsets
    function_vas: list[int] = field(default_factory=list)  # relevant function VAs

# ─── Kernelcache Parser ──────────────────────────────────────────────────────

class KernelcacheAnalyzer:
    def __init__(self, path: Path):
        self.path = path
        self.data = path.read_bytes()
        self.segments: list[Segment] = []
        self.fileset_components: list[FilesetComponent] = []
        self.text_exec: Optional[Segment] = None
        self.data_seg: Optional[Segment] = None
        self.text_seg: Optional[Segment] = None
        self.is_fileset = False
        self._parse()

    def _parse(self):
        if len(self.data) < 32:
            raise ValueError("File too small")
        magic = struct.unpack_from("<I", self.data, 0)[0]
        if magic != MH_MAGIC_64:
            raise ValueError(f"Not Mach-O 64 (magic 0x{magic:x})")

        _, _, filetype, ncmds, _, _, _ = struct.unpack_from("<IIIIIII", self.data, 4)
        self.is_fileset = (filetype == 12)

        off = 32
        for _ in range(ncmds):
            if off + 8 > len(self.data):
                break
            cmd, cmdsize = struct.unpack_from("<II", self.data, off)

            if cmd == LC_SEGMENT_64 and off + 72 <= len(self.data):
                segname = self.data[off+8:off+24].split(b"\0")[0].decode(errors="replace")
                vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", self.data, off+24)
                seg = Segment(segname, vmaddr, vmsize, fileoff, filesize)
                self.segments.append(seg)
                if segname == "__TEXT_EXEC":
                    self.text_exec = seg
                elif segname == "__DATA":
                    self.data_seg = seg
                elif segname == "__TEXT":
                    self.text_seg = seg

            elif cmd == LC_FILESET_ENTRY and off + cmdsize <= len(self.data):
                vmaddr, fileoff = struct.unpack_from("<QQ", self.data, off+8)
                name_off = struct.unpack_from("<I", self.data, off+24)[0]
                name_abs = off + name_off
                name = b""
                while name_abs < len(self.data) and self.data[name_abs] != 0:
                    name += bytes([self.data[name_abs]])
                    name_abs += 1
                comp = FilesetComponent(name.decode(errors="replace"), vmaddr, fileoff)
                self.fileset_components.append(comp)

            off += cmdsize

        # Parse fileset component segments
        for comp in self.fileset_components:
            self._parse_component_segments(comp)

    def _parse_component_segments(self, comp: FilesetComponent):
        foff = comp.fileoff
        if foff + 32 > len(self.data):
            return
        magic = struct.unpack_from("<I", self.data, foff)[0]
        if magic != MH_MAGIC_64:
            return
        _, _, _, ncmds, _, _, _ = struct.unpack_from("<IIIIIII", self.data, foff+4)
        off = foff + 32
        for _ in range(ncmds):
            if off + 8 > len(self.data):
                break
            cmd, cmdsize = struct.unpack_from("<II", self.data, off)
            if cmd == LC_SEGMENT_64 and off + 72 <= len(self.data):
                segname = self.data[off+8:off+24].split(b"\0")[0].decode(errors="replace")
                vmaddr, vmsize, seg_fileoff, seg_filesize = struct.unpack_from("<QQQQ", self.data, off+24)
                comp.segments.append(Segment(segname, vmaddr, vmsize, seg_fileoff, seg_filesize))
            off += cmdsize

    def va_to_fileoff(self, va: int) -> Optional[int]:
        va = strip_pac(va)
        for seg in self.segments:
            if seg.vmaddr <= va < seg.vmaddr + seg.vmsize:
                rel = va - seg.vmaddr
                if rel < seg.filesize:
                    return seg.fileoff + rel
        for comp in self.fileset_components:
            for seg in comp.segments:
                if seg.vmaddr <= va < seg.vmaddr + seg.vmsize:
                    rel = va - seg.vmaddr
                    if rel < seg.filesize:
                        return seg.fileoff + rel
        return None

    def fileoff_to_va(self, foff: int) -> Optional[int]:
        for seg in self.segments:
            if seg.fileoff <= foff < seg.fileoff + seg.filesize:
                return seg.vmaddr + (foff - seg.fileoff)
        for comp in self.fileset_components:
            for seg in comp.segments:
                if seg.fileoff <= foff < seg.fileoff + seg.filesize:
                    return seg.vmaddr + (foff - seg.fileoff)
        return None

    def read_u32(self, foff: int) -> int:
        if foff + 4 > len(self.data):
            return 0
        return struct.unpack_from("<I", self.data, foff)[0]

    def read_u64(self, foff: int) -> int:
        if foff + 8 > len(self.data):
            return 0
        return struct.unpack_from("<Q", self.data, foff)[0]

    def read_u32_va(self, va: int) -> int:
        foff = self.va_to_fileoff(va)
        return self.read_u32(foff) if foff is not None else 0

    def read_u64_va(self, va: int) -> int:
        foff = self.va_to_fileoff(va)
        return self.read_u64(foff) if foff is not None else 0

    @property
    def data_base(self) -> int:
        return self.data_seg.vmaddr if self.data_seg else 0

    @property
    def text_base(self) -> int:
        return self.text_seg.vmaddr if self.text_seg else 0

    @property
    def data_offset_from_text(self) -> int:
        return self.data_base - self.text_base if self.text_seg and self.data_seg else 0

    # ─── String Search ───────────────────────────────────────────────────────

    def find_strings(self, patterns: list[bytes]) -> dict[str, list[tuple[int, int]]]:
        """Find all occurrences of patterns. Returns {pattern: [(fileoff, va)]}."""
        results = defaultdict(list)
        for pat in patterns:
            pos = 0
            count = 0
            while count < 20:
                idx = self.data.find(pat, pos)
                if idx < 0:
                    break
                va = self.fileoff_to_va(idx)
                results[pat.decode(errors="replace")].append((idx, va or 0))
                pos = idx + 1
                count += 1
        return dict(results)

    # ─── ADRP+ADD Scan (full __TEXT_EXEC → __DATA refs) ──────────────────────

    def scan_adrp_refs_to_data(self, max_data_offset: int = 0x10000) -> Counter[int]:
        """Scan all ADRP+ADD in __TEXT_EXEC that reference __DATA."""
        if not self.text_exec or not self.data_seg:
            return Counter()

        te = self.text_exec
        db = self.data_base
        hits: Counter[int] = Counter()

        for i in range(0, te.filesize - 8, 4):
            pc = te.vmaddr + i
            foff = te.fileoff + i
            i0 = self.read_u32(foff)
            i1 = self.read_u32(foff + 4)

            page = decode_adrp(i0, pc)
            if page is None:
                continue
            add = decode_add_imm(i1)
            if add is None:
                continue
            rn, rd, imm = add
            if rn != rd:
                continue
            va = page + imm
            if db <= va < db + max_data_offset:
                hits[va - db] += 1

        return hits

    # ─── BL Call Graph ───────────────────────────────────────────────────────

    def build_call_graph(self, start_va: int, depth: int = 3) -> dict[int, list[int]]:
        """Build call graph from a function: {caller_va: [callee_vas]}."""
        graph: dict[int, list[int]] = {}
        visited = set()
        queue = [(start_va, 0)]

        while queue:
            func_va, d = queue.pop(0)
            if func_va in visited or d > depth:
                continue
            visited.add(func_va)

            foff = self.va_to_fileoff(func_va)
            if foff is None:
                continue

            callees = []
            # Scan up to 0x400 bytes (typical function size)
            for i in range(0, 0x400, 4):
                insn = self.read_u32(foff + i)
                pc = func_va + i

                # RET = end of function
                if insn == 0xD65F03C0:
                    break

                target = decode_bl(insn, pc)
                if target and target != func_va:
                    callees.append(target)
                    if d + 1 <= depth:
                        queue.append((target, d + 1))

            graph[func_va] = callees

        return graph

    # ─── Find Functions by String XREF ───────────────────────────────────────

    def find_function_by_string_xref(self, string_va: int) -> list[int]:
        """Find functions that reference a string VA via ADRP+ADD."""
        if not self.text_exec:
            return []

        te = self.text_exec
        string_page = string_va & ~0xFFF
        string_off = string_va & 0xFFF
        results = []

        for i in range(0, te.filesize - 8, 4):
            pc = te.vmaddr + i
            foff = te.fileoff + i
            i0 = self.read_u32(foff)
            i1 = self.read_u32(foff + 4)

            page = decode_adrp(i0, pc)
            if page != string_page:
                continue
            add = decode_add_imm(i1)
            if add is None:
                continue
            _, _, imm = add
            if imm == string_off:
                # Found ADRP+ADD to this string. Walk back to find function start.
                func_start = self._find_function_start(te, i)
                if func_start:
                    results.append(func_start)

        return results

    def _find_function_start(self, te: Segment, offset_in_te: int) -> Optional[int]:
        """Walk backwards from offset to find function prologue (STP X29, X30, ...)."""
        for back in range(0, min(offset_in_te, 0x200), 4):
            foff = te.fileoff + offset_in_te - back
            insn = self.read_u32(foff)
            # STP X29, X30, [SP, #-imm]! (function prologue)
            # Pattern: 0xA9xx7BFD
            if (insn & 0xFFE07FFF) == 0xA9007BFD:
                return te.vmaddr + offset_in_te - back
            # PACIBSP (PAC function prologue on A12+)
            if insn == 0xD503237F:
                return te.vmaddr + offset_in_te - back
            # SUB SP, SP, #imm (another prologue pattern)
            if (insn & 0xFF0003FF) == 0xD10003FF and back > 0:
                # Check if previous is STP
                prev = self.read_u32(foff - 4)
                if (prev & 0xFFE07FFF) == 0xA9007BFD or prev == 0xD503237F:
                    return te.vmaddr + offset_in_te - back - 4
        return te.vmaddr + offset_in_te  # fallback

    # ─── Scan for STR/LDR patterns to __DATA ─────────────────────────────────

    def scan_store_load_to_data(self, target_offsets: list[int]) -> dict[int, DataSlot]:
        """For each __DATA offset, count STR and LDR references."""
        if not self.text_exec or not self.data_seg:
            return {}

        te = self.text_exec
        db = self.data_base
        slots: dict[int, DataSlot] = {}

        for off in target_offsets:
            foff = self.data_seg.fileoff + off
            static_val = self.read_u64(foff) if foff + 8 <= len(self.data) else 0
            slots[off] = DataSlot(
                offset_in_data=off, va=db + off,
                static_value=static_val, adrp_refs=0, str_refs=0, ldr_refs=0
            )

        # Scan __TEXT_EXEC for ADRP+ADD+STR/LDR patterns
        for i in range(0, te.filesize - 12, 4):
            pc = te.vmaddr + i
            foff = te.fileoff + i
            i0 = self.read_u32(foff)
            i1 = self.read_u32(foff + 4)
            i2 = self.read_u32(foff + 8)

            page = decode_adrp(i0, pc)
            if page is None:
                continue
            add = decode_add_imm(i1)
            if add is None:
                continue
            rn, rd, imm = add
            if rn != rd:
                continue
            va = page + imm
            rel = va - db
            if rel not in slots:
                continue

            slots[rel].adrp_refs += 1

            # Check 3rd instruction: STR or LDR
            s = decode_str_imm(i2)
            if s and s[2] == rd:
                slots[rel].str_refs += 1
            l = decode_ldr_imm(i2)
            if l and l[2] == rd:
                slots[rel].ldr_refs += 1

        return slots

    # ─── Dynamic Trust Cache Analysis ────────────────────────────────────────

    def analyze_dynamic_trust_cache(self, out: list[str]) -> list[DataSlot]:
        """
        Find dynamic trust cache: slots in __DATA that are 0 at compile time
        (filled at runtime with heap pointer to trust cache struct).
        
        Key insight: static TC is burned into kernelcache (KTRR protected).
        But dynamic TC (DDI, personalized, loadable) is heap-allocated.
        The HEAD POINTER to the linked list lives in __DATA — if we can find
        a slot that points to a HEAP trust cache, we can:
          1. Allocate our own TC struct in heap (via kalloc spray)
          2. Link it into the list
          3. Or: directly write CDHash into existing heap TC
        """
        out.append("=" * 70)
        out.append("PHASE 1: DYNAMIC TRUST CACHE LINKED LIST ANALYSIS")
        out.append("=" * 70)
        out.append("")

        if not self.data_seg or not self.text_exec:
            out.append("ERROR: Missing __DATA or __TEXT_EXEC segment")
            return []

        # Step 1: Find all __DATA slots that are 0 (runtime heap pointers)
        out.append("--- Step 1: __DATA slots = 0 (runtime heap pointers) ---")
        out.append("These are globals filled at boot time. Some point to heap trust caches.")
        out.append("")

        adrp_hits = self.scan_adrp_refs_to_data(max_data_offset=0x10000)
        
        # Get top referenced slots
        zero_slots = []
        nonzero_slots = []
        
        for rel, count in adrp_hits.most_common(200):
            if rel >= 0x8000:  # skip PPL data
                continue
            foff = self.data_seg.fileoff + rel
            if foff + 8 > len(self.data):
                continue
            val = self.read_u64(foff)
            
            if val == 0:
                zero_slots.append((rel, count))
            else:
                nonzero_slots.append((rel, count, val))

        out.append(f"Zero slots (runtime heap ptrs): {len(zero_slots)}")
        out.append(f"Non-zero slots (static data):   {len(nonzero_slots)}")
        out.append("")

        # Step 2: Classify zero slots by context
        out.append("--- Step 2: Zero slots with high ADRP ref count ---")
        out.append("(More refs = more important global → likely trust cache head)")
        out.append("")
        out.append(f"{'Offset':>10} {'Refs':>5} {'Notes'}")
        out.append("-" * 60)

        important_zero_slots = []
        for rel, count in sorted(zero_slots, key=lambda x: -x[1])[:40]:
            notes = self._classify_zero_slot(rel, count)
            out.append(f"  +0x{rel:<6x} {count:>5}  {notes}")
            important_zero_slots.append(rel)

        out.append("")

        # Step 3: For each zero slot, find what functions write to it
        out.append("--- Step 3: Functions that STORE to zero slots ---")
        out.append("(These are init functions that set up trust cache pointers)")
        out.append("")

        tc_candidate_slots = []
        for rel in important_zero_slots[:20]:
            writers = self._find_writers_to_slot(rel)
            if writers:
                out.append(f"  +0x{rel:x}: written by {len(writers)} function(s)")
                for w_pc, w_func in writers[:3]:
                    out.append(f"    PC=0x{w_pc:x} (func ~0x{w_func:x})")
                    # Check if writer function references trust cache strings
                    if self._func_refs_trust_strings(w_func):
                        out.append(f"    ^^^ REFERENCES TRUST CACHE STRINGS!")
                        tc_candidate_slots.append(rel)
                out.append("")

        # Step 4: Analyze non-zero slots (static trust cache pointers)
        out.append("--- Step 4: Non-zero slots (static TC pointers in kernelcache) ---")
        out.append("")

        static_tc_slots = []
        for rel, count, val in nonzero_slots[:30]:
            ptr = strip_pac(val)
            ptr_foff = self.va_to_fileoff(ptr) if is_kernel_va(ptr) else None
            
            if ptr_foff is not None:
                # Check if pointed-to data looks like trust cache
                ver = self.read_u32(ptr_foff)
                cnt = self.read_u32(ptr_foff + 4)
                if 1 <= ver <= 16 and 5 <= cnt <= 500000:
                    out.append(f"  +0x{rel:x}: → 0x{ptr:x} ver={ver} count={cnt} ← STATIC TC!")
                    static_tc_slots.append((rel, ptr, ver, cnt))
                elif val < 0x10000:
                    out.append(f"  +0x{rel:x}: small int = {val} (flag/counter)")
                else:
                    out.append(f"  +0x{rel:x}: → 0x{ptr:x} (not TC struct)")
            elif is_kernel_va(ptr):
                out.append(f"  +0x{rel:x}: → 0x{ptr:x} (outside kc — runtime?)")
            elif val < 0x10000:
                pass  # skip small ints
            else:
                out.append(f"  +0x{rel:x}: 0x{val:x} (unknown)")

        out.append("")

        # Step 5: Summary
        out.append("--- Step 5: DYNAMIC TC CANDIDATES ---")
        out.append("")
        if tc_candidate_slots:
            out.append(f"✅ Found {len(tc_candidate_slots)} slots that are written by TC-related functions:")
            for rel in tc_candidate_slots:
                out.append(f"  __DATA+0x{rel:x} (VA = dataSegBase + 0x{rel:x})")
            out.append("")
            out.append("ON DEVICE: read these slots at runtime → if non-zero, they point to HEAP TC!")
            out.append("HEAP TC is WRITABLE (not KTRR protected)!")
        else:
            out.append("⚠️ No definitive dynamic TC slots found via string xref.")
            out.append("Trying broader heuristic...")
            # Fallback: slots near known TC offsets that are zero
            near_tc = [r for r in important_zero_slots if 0x38 <= r <= 0x4000]
            if near_tc:
                out.append(f"  Candidate zero slots near TC region: {[hex(r) for r in near_tc[:10]]}")

        out.append("")
        
        # Build DataSlot objects for return
        all_offsets = important_zero_slots + [r for r, _, _, _ in static_tc_slots]
        return list(self.scan_store_load_to_data(all_offsets).values())

    def _classify_zero_slot(self, rel: int, ref_count: int) -> str:
        """Heuristic classification of a zero __DATA slot."""
        notes = []
        if rel < 0x100:
            notes.append("early-init region")
        if 0x2700 <= rel <= 0x2900:
            notes.append("pmap_cs region")
        if 0x3800 <= rel <= 0x4000:
            notes.append("trust_cache region")
        if 0x4500 <= rel <= 0x4700:
            notes.append("amfi_policy region")
        if ref_count >= 10:
            notes.append("HIGH-REF")
        return ", ".join(notes) if notes else ""

    def _find_writers_to_slot(self, data_rel: int) -> list[tuple[int, int]]:
        """Find PCs that STR to __DATA+data_rel. Returns [(pc, func_start)]."""
        if not self.text_exec or not self.data_seg:
            return []

        te = self.text_exec
        db = self.data_base
        target_va = db + data_rel
        target_page = target_va & ~0xFFF
        target_off = target_va & 0xFFF
        results = []

        for i in range(0, te.filesize - 12, 4):
            pc = te.vmaddr + i
            foff = te.fileoff + i
            i0 = self.read_u32(foff)
            i1 = self.read_u32(foff + 4)
            i2 = self.read_u32(foff + 8)

            page = decode_adrp(i0, pc)
            if page != target_page:
                continue
            add = decode_add_imm(i1)
            if add is None:
                continue
            rn, rd, imm = add
            if rn != rd or imm != target_off:
                continue

            # Check if next instruction is STR
            s = decode_str_imm(i2)
            if s and s[2] == rd and s[3] == 0:
                func_start = self._find_function_start(te, i) or pc
                results.append((pc, func_start))

            if len(results) >= 5:
                break

        return results

    def _func_refs_trust_strings(self, func_va: int) -> bool:
        """Check if function near func_va references any trust cache string."""
        foff = self.va_to_fileoff(func_va)
        if foff is None:
            return False

        # Scan 0x200 bytes from function start
        for i in range(0, 0x200, 4):
            insn = self.read_u32(foff + i)
            pc = func_va + i
            page = decode_adrp(insn, pc)
            if page is None:
                continue
            # Check next instruction for ADD
            next_insn = self.read_u32(foff + i + 4)
            add = decode_add_imm(next_insn)
            if add is None:
                continue
            _, _, imm = add
            target_va = page + imm
            target_foff = self.va_to_fileoff(target_va)
            if target_foff is None:
                continue
            # Check if target contains trust cache string
            chunk = self.data[target_foff:target_foff + 64]
            for kw in [b"trust_cache", b"trust cache", b"TrustCache", b"pmap_cs"]:
                if kw in chunk:
                    return True
        return False

    # ─── pmap_cs Analysis ────────────────────────────────────────────────────

    def analyze_pmap_cs(self, out: list[str]):
        """
        Analyze pmap_cs subsystem — iOS 18's code signing enforcement layer.
        
        pmap_cs maintains its own trust cache lookup. Key functions:
        - pmap_cs_associate: associates code directory with a pmap region
        - pmap_cs_cd_register: registers a code directory
        - pmap_cs_lookup_copy: looks up trust cache for a CDHash
        
        If pmap_cs has a separate trust cache list in heap, we might bypass AMFI
        by injecting into pmap_cs's list instead of the main trust cache.
        """
        out.append("")
        out.append("=" * 70)
        out.append("PHASE 2: pmap_cs CODE SIGNING SUBSYSTEM")
        out.append("=" * 70)
        out.append("")

        # Find pmap_cs related strings
        pmap_cs_patterns = [
            b"pmap_cs_associate",
            b"pmap_cs_cd_register",
            b"pmap_cs_lookup",
            b"pmap_cs_check_",
            b"pmap_cs_trust",
            b"pmap_lookup_in_loaded_trust_caches",
            b"pmap_lookup_in_static_trust_cache",
            b"cs_blob",
            b"cs_invalid",
            b"cs_enforcement_disable",
            b"cs_enforcement_panic",
            b"amfi_get_out_of_my_way",
            b"cs_system_enforcement_disable",
            b"cs_process_enforcement",
        ]

        string_hits = self.find_strings(pmap_cs_patterns)

        out.append("--- pmap_cs / CS enforcement strings found ---")
        for name, locs in sorted(string_hits.items()):
            for foff, va in locs[:2]:
                out.append(f"  '{name}': VA=0x{va:x}")
        out.append("")

        # Key insight: cs_enforcement_disable and amfi_get_out_of_my_way
        # These are debug/development flags. If they exist as __DATA globals,
        # writing 1 to them might disable all code signing!
        out.append("--- CS enforcement disable flags ---")
        out.append("(If these are __DATA globals, writing 1 = disable CS!)")
        out.append("")

        disable_flags = [
            b"cs_enforcement_disable",
            b"cs_system_enforcement_disable",
            b"amfi_get_out_of_my_way",
            b"cs_process_enforcement",
        ]

        for pat in disable_flags:
            hits = string_hits.get(pat.decode(), [])
            if not hits:
                out.append(f"  '{pat.decode()}': NOT FOUND")
                continue

            for foff, va in hits:
                out.append(f"  '{pat.decode()}': string at VA=0x{va:x}")
                # Find ADRP refs to this string → find the function
                # Then find what __DATA slot the function reads/writes
                funcs = self.find_function_by_string_xref(va)
                for func_va in funcs[:2]:
                    out.append(f"    Referenced by func at 0x{func_va:x}")
                    # Scan function for ADRP to __DATA
                    data_refs = self._scan_func_data_refs(func_va)
                    for dref in data_refs[:3]:
                        out.append(f"      → __DATA+0x{dref:x}")
        out.append("")

        # Find pmap_lookup_in_loaded_trust_caches — this is THE function
        # that checks if a CDHash is in any loaded trust cache
        out.append("--- pmap_lookup_in_loaded_trust_caches ---")
        out.append("(THE function that validates CDHash against all trust caches)")
        out.append("")

        lookup_str = "pmap_lookup_in_loaded_trust_caches"
        if lookup_str in string_hits:
            for foff, va in string_hits[lookup_str]:
                funcs = self.find_function_by_string_xref(va)
                for func_va in funcs[:1]:
                    out.append(f"  Function at 0x{func_va:x}")
                    # Build call graph
                    graph = self.build_call_graph(func_va, depth=2)
                    out.append(f"  Call graph ({len(graph)} nodes):")
                    for caller, callees in list(graph.items())[:5]:
                        out.append(f"    0x{caller:x} → {[hex(c) for c in callees[:5]]}")
                    # Find __DATA refs in this function
                    data_refs = self._scan_func_data_refs(func_va, scan_size=0x400)
                    if data_refs:
                        out.append(f"  __DATA refs: {[hex(r) for r in data_refs]}")
                        out.append("  ^^^ These slots contain trust cache list head!")
        out.append("")

    def _scan_func_data_refs(self, func_va: int, scan_size: int = 0x200) -> list[int]:
        """Find __DATA offsets referenced by ADRP+ADD in a function."""
        if not self.data_seg:
            return []
        foff = self.va_to_fileoff(func_va)
        if foff is None:
            return []

        db = self.data_base
        refs = []
        for i in range(0, scan_size, 4):
            insn = self.read_u32(foff + i)
            pc = func_va + i
            page = decode_adrp(insn, pc)
            if page is None:
                continue
            next_insn = self.read_u32(foff + i + 4)
            add = decode_add_imm(next_insn)
            if add is None:
                continue
            _, _, imm = add
            va = page + imm
            if db <= va < db + 0x10000:
                refs.append(va - db)
        return sorted(set(refs))

    # ─── AMFI Dispatch Table Analysis ────────────────────────────────────────

    def analyze_amfi_dispatch(self, out: list[str]):
        """
        Analyze AMFI.kext for dispatch tables and function pointers.
        
        AMFI uses a MAC policy interface (mac_policy_ops) which is a struct
        of function pointers. If this struct is in writable memory (heap),
        we could redirect specific checks to a NOP function.
        
        Key hooks:
        - mpo_vnode_check_exec: called before exec → CDHash check
        - mpo_proc_check_get_task: task_for_pid check
        - mpo_file_check_mmap: mmap check
        """
        out.append("")
        out.append("=" * 70)
        out.append("PHASE 3: AMFI DISPATCH TABLE & MAC POLICY")
        out.append("=" * 70)
        out.append("")

        # Find AMFI fileset component
        amfi_comp = None
        for comp in self.fileset_components:
            if "AMFI" in comp.name or "amfi" in comp.name.lower():
                amfi_comp = comp
                break

        if amfi_comp:
            out.append(f"AMFI component: {amfi_comp.name}")
            out.append(f"  vmaddr=0x{amfi_comp.vmaddr:x}, fileoff=0x{amfi_comp.fileoff:x}")
            out.append(f"  Segments:")
            for seg in amfi_comp.segments:
                out.append(f"    {seg.name:16} vm=0x{seg.vmaddr:x} size=0x{seg.vmsize:x}")
            out.append("")

            # Find __DATA segment of AMFI
            amfi_data = next((s for s in amfi_comp.segments if s.name == "__DATA"), None)
            amfi_text = next((s for s in amfi_comp.segments if s.name in ("__TEXT_EXEC", "__TEXT")), None)

            if amfi_data:
                out.append(f"AMFI __DATA: vm=0x{amfi_data.vmaddr:x} size=0x{amfi_data.vmsize:x}")
                out.append("Scanning for function pointer tables...")
                out.append("")

                # Scan AMFI __DATA for arrays of kernel pointers (dispatch tables)
                tables = self._find_pointer_tables(amfi_data)
                for tbl_off, ptrs in tables[:5]:
                    out.append(f"  Pointer table at AMFI __DATA+0x{tbl_off:x} ({len(ptrs)} entries):")
                    for i, ptr in enumerate(ptrs[:8]):
                        out.append(f"    [{i}] 0x{ptr:x}")
                    if len(ptrs) > 8:
                        out.append(f"    ... +{len(ptrs)-8} more")
                    out.append("")
        else:
            out.append("AMFI fileset component not found (non-fileset kernel?)")
            out.append("")

        # Find mac_policy_ops strings
        mac_strings = self.find_strings([
            b"mac_policy_register",
            b"mac_policy_ops",
            b"AppleMobileFileIntegrity",
            b"AMFI: ",
            b"amfi_check_",
            b"mpo_vnode_check_exec",
            b"mpo_proc_check",
        ])

        out.append("--- MAC policy strings ---")
        for name, locs in sorted(mac_strings.items()):
            for _, va in locs[:2]:
                out.append(f"  '{name}': VA=0x{va:x}")
        out.append("")

        # Find CoreTrust component
        ct_comp = None
        for comp in self.fileset_components:
            if "CoreTrust" in comp.name or "coretrust" in comp.name.lower():
                ct_comp = comp
                break

        if ct_comp:
            out.append(f"CoreTrust component: {ct_comp.name}")
            out.append(f"  vmaddr=0x{ct_comp.vmaddr:x}")
            for seg in ct_comp.segments:
                out.append(f"    {seg.name:16} vm=0x{seg.vmaddr:x} size=0x{seg.vmsize:x}")
            
            ct_data = next((s for s in ct_comp.segments if s.name == "__DATA"), None)
            if ct_data:
                out.append(f"\n  CoreTrust __DATA: vm=0x{ct_data.vmaddr:x} size=0x{ct_data.vmsize:x}")
                out.append("  (If CT has function pointers in __DATA, they might be patchable)")
                tables = self._find_pointer_tables(ct_data)
                for tbl_off, ptrs in tables[:3]:
                    out.append(f"    Table at CT __DATA+0x{tbl_off:x} ({len(ptrs)} entries)")
        out.append("")

    def _find_pointer_tables(self, seg: Segment) -> list[tuple[int, list[int]]]:
        """Find arrays of consecutive kernel pointers in a segment."""
        tables = []
        i = 0
        while i < seg.filesize - 8:
            foff = seg.fileoff + i
            val = strip_pac(self.read_u64(foff))
            if is_kernel_va(val) and val != 0:
                # Start of potential table
                ptrs = [val]
                j = i + 8
                while j < seg.filesize:
                    next_val = strip_pac(self.read_u64(seg.fileoff + j))
                    if is_kernel_va(next_val) and next_val != 0:
                        ptrs.append(next_val)
                        j += 8
                    else:
                        break
                if len(ptrs) >= 4:  # At least 4 consecutive pointers = table
                    tables.append((i, ptrs))
                i = j
            else:
                i += 8
        return tables

    # ─── Trust Cache Call Graph ──────────────────────────────────────────────

    def analyze_trust_cache_call_graph(self, out: list[str]):
        """
        Build complete call graph for trust cache operations.
        Find the exact path from posix_spawn → AMFI check → trust cache lookup.
        Identify which __DATA globals are read during the lookup.
        """
        out.append("")
        out.append("=" * 70)
        out.append("PHASE 4: TRUST CACHE CALL GRAPH & DATA FLOW")
        out.append("=" * 70)
        out.append("")

        # Key functions to trace
        key_funcs = [
            b"pmap_lookup_in_loaded_trust_caches",
            b"pmap_lookup_in_static_trust_cache",
            b"trust_cache_runtime_add",
            b"trust_cache_runtime_remove",
            b"query_trust_cache",
            b"load_trust_cache",
        ]

        string_hits = self.find_strings(key_funcs)
        func_map: dict[str, int] = {}

        for name, locs in string_hits.items():
            for _, va in locs[:1]:
                funcs = self.find_function_by_string_xref(va)
                if funcs:
                    func_map[name] = funcs[0]
                    out.append(f"  {name}: func at 0x{funcs[0]:x}")

        out.append("")

        # For each key function, find __DATA references
        out.append("--- __DATA globals accessed by trust cache functions ---")
        out.append("(These are the globals we need to target on-device)")
        out.append("")

        all_data_refs: Counter[int] = Counter()
        for name, func_va in func_map.items():
            refs = self._scan_func_data_refs(func_va, scan_size=0x800)
            if refs:
                out.append(f"  {name} (0x{func_va:x}):")
                for r in refs:
                    out.append(f"    __DATA+0x{r:x}")
                    all_data_refs[r] += 1
                out.append("")

        # Also trace callees
        out.append("--- Callee analysis (functions called by TC functions) ---")
        out.append("")
        for name, func_va in list(func_map.items())[:4]:
            graph = self.build_call_graph(func_va, depth=2)
            if len(graph) > 1:
                out.append(f"  {name} call tree:")
                for caller, callees in list(graph.items())[:8]:
                    # Get __DATA refs from callees too
                    for callee in callees[:3]:
                        callee_refs = self._scan_func_data_refs(callee, scan_size=0x200)
                        for r in callee_refs:
                            all_data_refs[r] += 1
                out.append(f"    Nodes: {len(graph)}, total BL targets: {sum(len(v) for v in graph.values())}")
                out.append("")

        # Summary: most referenced __DATA slots from TC functions
        out.append("--- MOST REFERENCED __DATA SLOTS (from TC functions) ---")
        out.append("(Higher count = more likely to be trust cache head pointer)")
        out.append("")
        for rel, count in all_data_refs.most_common(20):
            foff = self.data_seg.fileoff + rel if self.data_seg else 0
            val = self.read_u64(foff) if foff else 0
            val_note = "ZERO (heap ptr!)" if val == 0 else f"0x{val:x}"
            out.append(f"  __DATA+0x{rel:x}: {count} refs, static={val_note}")
        out.append("")

    # ─── Bypass Vectors ──────────────────────────────────────────────────────

    def analyze_bypass_vectors(self, out: list[str]) -> list[BypassVector]:
        """
        Enumerate ALL possible bypass vectors for AMFI on iOS 18.2 A12.
        Rate each by feasibility given our capabilities (KRW + root + RC).
        """
        out.append("")
        out.append("=" * 70)
        out.append("PHASE 5: BYPASS VECTOR ENUMERATION")
        out.append("=" * 70)
        out.append("")

        vectors: list[BypassVector] = []

        # Vector 1: Dynamic Trust Cache Injection
        v1 = BypassVector(
            name="Dynamic Trust Cache Injection (Heap TC)",
            feasibility="HIGH",
            description=(
                "iOS maintains a linked list of trust caches. Static TC is KTRR-protected, "
                "but dynamic TCs (DDI, personalized) are heap-allocated and WRITABLE. "
                "If we find the list head pointer in __DATA, we can: "
                "(a) find existing heap TC and inject CDHash, or "
                "(b) allocate new TC struct and link it in."
            ),
            requirements=[
                "Find __DATA slot that points to heap TC list head",
                "Read slot on-device → get heap TC address",
                "Write CDHash entry + update count",
                "OR: kalloc spray to create fake TC struct, link into list",
            ],
        )
        vectors.append(v1)

        # Vector 2: cs_enforcement_disable flag
        v2 = BypassVector(
            name="CS Enforcement Disable Flag",
            feasibility="MEDIUM",
            description=(
                "Kernel has global flags like cs_enforcement_disable, "
                "amfi_get_out_of_my_way that can disable code signing. "
                "On production builds these are typically compiled out or "
                "checked at boot only. But if the variable exists in __DATA "
                "and is checked at runtime, writing 1 = bypass all CS."
            ),
            requirements=[
                "Find cs_enforcement_disable in __DATA (not __TEXT)",
                "Confirm it's checked at runtime (not just boot)",
                "Write 1 via KRW",
                "May need to also set amfi_get_out_of_my_way",
            ],
        )
        vectors.append(v2)

        # Vector 3: MAC Policy Hook Redirect
        v3 = BypassVector(
            name="MAC Policy Hook Redirect",
            feasibility="MEDIUM",
            description=(
                "AMFI registers MAC policy hooks (function pointers). "
                "If mac_policy_ops struct is in writable memory, we can "
                "redirect mpo_vnode_check_exec to a function that always "
                "returns 0 (allow). This bypasses ALL AMFI checks."
            ),
            requirements=[
                "Find mac_policy_ops struct address",
                "Confirm it's in writable memory (heap or writable __DATA)",
                "Find a 'return 0' gadget in kernel text",
                "Overwrite mpo_vnode_check_exec pointer",
                "PAC: function pointers may be PAC-signed (A12 has PAC)",
            ],
        )
        vectors.append(v3)

        # Vector 4: pmap_cs trust cache list
        v4 = BypassVector(
            name="pmap_cs Trust Cache Manipulation",
            feasibility="MEDIUM",
            description=(
                "pmap_cs is a separate code signing subsystem in iOS 18. "
                "It maintains its own trust cache lookup path. If pmap_cs "
                "has a writable trust cache list (separate from main TC), "
                "injecting there might work."
            ),
            requirements=[
                "Find pmap_cs trust cache globals",
                "Determine if they're in writable memory",
                "Understand pmap_cs struct layout",
                "Inject CDHash into pmap_cs TC",
            ],
        )
        vectors.append(v4)

        # Vector 5: CoreTrust certificate bypass
        v5 = BypassVector(
            name="CoreTrust Certificate Bypass",
            feasibility="LOW",
            description=(
                "CoreTrust validates code signatures. If we can craft a "
                "certificate that CT accepts (like TrollStore did on iOS 14-16), "
                "we can sign binaries that pass validation. Requires finding "
                "a parsing bug or accepted non-Apple CA."
            ),
            requirements=[
                "Reverse engineer CoreTrust validation logic",
                "Find accepted certificate format",
                "Craft valid signature with custom CDHash",
                "This is crypto research — very hard",
            ],
        )
        vectors.append(v5)

        # Vector 6: Trigger DDI trust cache load
        v6 = BypassVector(
            name="Trigger DDI Trust Cache Load Path",
            feasibility="HIGH",
            description=(
                "Developer Disk Images (DDI) add trust caches at runtime. "
                "The kernel has trust_cache_runtime_add for this. If we can "
                "call this function via our RemoteCall (from launchd context), "
                "we can add our own trust cache with arbitrary CDHashes. "
                "The function allocates heap memory for the new TC."
            ),
            requirements=[
                "Find trust_cache_runtime_add function address",
                "Understand its parameters (TC struct pointer, size, type)",
                "Craft valid TC struct in userspace memory",
                "Call via RemoteCall from launchd (PID 1 context)",
                "May need specific entitlements or PPL context",
            ],
        )
        vectors.append(v6)

        # Vector 7: Patch AMFI.kext __DATA (if not KTRR)
        v7 = BypassVector(
            name="AMFI.kext __DATA Patch",
            feasibility="MEDIUM",
            description=(
                "AMFI.kext has its own __DATA segment (fileset component). "
                "If AMFI's __DATA is at a different physical address than "
                "the main kernel __DATA, it MIGHT not be KTRR-protected. "
                "KTRR range is set at boot — fileset aux __DATA might be outside."
            ),
            requirements=[
                "Find AMFI __DATA VA on device",
                "Test write to AMFI __DATA (might not panic if outside KTRR)",
                "If writable: patch AMFI globals to disable checks",
                "Key target: amfi_allow_any flag or similar",
            ],
        )
        vectors.append(v7)

        # Print vectors
        for v in vectors:
            emoji = {"HIGH": "🟢", "MEDIUM": "🟡", "LOW": "🔴", "IMPOSSIBLE": "⛔"}.get(v.feasibility, "?")
            out.append(f"{emoji} [{v.feasibility}] {v.name}")
            out.append(f"   {v.description[:120]}...")
            out.append(f"   Requirements:")
            for req in v.requirements:
                out.append(f"     • {req}")
            out.append("")

        return vectors

    # ─── AMFI Fileset __DATA Deep Scan ───────────────────────────────────────

    def analyze_amfi_data_deep(self, out: list[str]):
        """
        Deep scan of AMFI.kext __DATA for:
        1. Trust cache pointers (linked list heads)
        2. Policy flags (enable/disable booleans)
        3. Function pointer tables (MAC policy ops)
        4. Callback registrations
        """
        out.append("")
        out.append("=" * 70)
        out.append("PHASE 6: AMFI.kext __DATA DEEP SCAN")
        out.append("=" * 70)
        out.append("")

        amfi_comp = None
        for comp in self.fileset_components:
            if "AMFI" in comp.name or "MobileFileIntegrity" in comp.name:
                amfi_comp = comp
                break

        if not amfi_comp:
            out.append("AMFI component not found in fileset")
            return

        amfi_data = next((s for s in amfi_comp.segments if s.name == "__DATA"), None)
        amfi_text = next((s for s in amfi_comp.segments
                          if s.name in ("__TEXT_EXEC", "__text")), None)

        if not amfi_data:
            out.append("AMFI __DATA segment not found")
            return

        out.append(f"AMFI __DATA: VA=0x{amfi_data.vmaddr:x}, size=0x{amfi_data.vmsize:x}")
        out.append(f"AMFI __DATA fileoff: 0x{amfi_data.fileoff:x}")
        out.append("")

        # Scan every 8-byte slot in AMFI __DATA
        out.append("--- AMFI __DATA content analysis ---")
        out.append("")

        zero_count = 0
        ptr_count = 0
        small_int_count = 0
        interesting_slots = []

        for off in range(0, min(amfi_data.filesize, 0x2000), 8):
            foff = amfi_data.fileoff + off
            val = self.read_u64(foff)
            ptr = strip_pac(val)

            if val == 0:
                zero_count += 1
            elif is_kernel_va(ptr):
                ptr_count += 1
                # Check if pointer target is resolvable
                target_foff = self.va_to_fileoff(ptr)
                interesting_slots.append((off, val, ptr, target_foff))
            elif val < 0x100:
                small_int_count += 1
                # Small integers might be flags!
                if val in (0, 1):
                    interesting_slots.append((off, val, 0, None))

        out.append(f"  Zero slots: {zero_count}")
        out.append(f"  Kernel pointers: {ptr_count}")
        out.append(f"  Small integers: {small_int_count}")
        out.append("")

        # Dump interesting slots
        out.append("--- Interesting AMFI __DATA slots ---")
        out.append(f"{'Offset':>8} {'Value':>18} {'Type':>12} {'Notes'}")
        out.append("-" * 70)

        for off, val, ptr, target_foff in interesting_slots[:50]:
            va = amfi_data.vmaddr + off
            if ptr != 0 and is_kernel_va(ptr):
                # It's a pointer
                if target_foff is not None:
                    # Check what it points to
                    target_magic = self.read_u32(target_foff)
                    notes = f"→ 0x{ptr:x}"
                    if target_magic == 0xFEEDFACF:
                        notes += " (Mach-O!)"
                else:
                    notes = f"→ 0x{ptr:x} (outside kc)"
                out.append(f"  +0x{off:<4x}  0x{val:016x}  {'pointer':>12}  {notes}")
            elif val <= 1:
                # Boolean flag
                out.append(f"  +0x{off:<4x}  {val:<18}  {'bool flag':>12}  VA=0x{va:x}")
            else:
                out.append(f"  +0x{off:<4x}  0x{val:016x}  {'small int':>12}  VA=0x{va:x}")

        out.append("")

        # Key finding: AMFI __DATA VA range
        out.append("--- KEY FINDING: AMFI __DATA address range ---")
        out.append(f"  Start: 0x{amfi_data.vmaddr:x}")
        out.append(f"  End:   0x{amfi_data.vmaddr + amfi_data.vmsize:x}")
        out.append(f"  Size:  0x{amfi_data.vmsize:x}")
        out.append("")
        out.append("  ON DEVICE TEST:")
        out.append(f"  1. Read 0x{amfi_data.vmaddr:x} + slide → confirm accessible")
        out.append(f"  2. Try write test byte → if NO panic, AMFI __DATA is WRITABLE!")
        out.append(f"  3. If writable: patch boolean flags to disable AMFI checks")
        out.append("")
        out.append("  IMPORTANT: AMFI __DATA might be OUTSIDE KTRR range!")
        out.append("  KTRR protects main kernel __TEXT/__DATA but fileset components")
        out.append("  might have their __DATA in a different physical region.")
        out.append("")

    # ─── Emit Swift Offsets ──────────────────────────────────────────────────

    def emit_swift_offsets(self, out: list[str], data_slots: list[DataSlot],
                           vectors: list[BypassVector]):
        """Generate Swift code with all discovered offsets for on-device testing."""
        out.append("")
        out.append("=" * 70)
        out.append("PHASE 7: SWIFT OFFSET GENERATION")
        out.append("=" * 70)
        out.append("")

        # Collect all important offsets
        adrp_hits = self.scan_adrp_refs_to_data(max_data_offset=0x10000)

        # Zero slots (runtime heap pointers) — most likely dynamic TC
        zero_slots_sorted = []
        for rel, count in adrp_hits.most_common(100):
            if rel >= 0x8000:
                continue
            foff = self.data_seg.fileoff + rel if self.data_seg else 0
            val = self.read_u64(foff) if foff else 0
            if val == 0:
                zero_slots_sorted.append((rel, count))

        out.append("// === AUTO-GENERATED by deep_tc_analysis.py ===")
        out.append("// Paste into AMFIExperimentView.swift (new experiment)")
        out.append("")
        out.append("// Dynamic TC candidate slots (zero at compile time = heap ptr at runtime)")
        out.append("// Higher ref count = more important global")
        out.append("static let dynamicTCCandidateSlots: [(offset: UInt64, refs: Int)] = [")
        for rel, count in zero_slots_sorted[:30]:
            out.append(f"    (0x{rel:x}, {count}),  // __DATA+0x{rel:x}")
        out.append("]")
        out.append("")

        # AMFI component info
        amfi_comp = next((c for c in self.fileset_components
                          if "AMFI" in c.name or "MobileFileIntegrity" in c.name), None)
        if amfi_comp:
            amfi_data = next((s for s in amfi_comp.segments if s.name == "__DATA"), None)
            if amfi_data:
                out.append(f"// AMFI __DATA (unslid): 0x{amfi_data.vmaddr:x}")
                out.append(f"// AMFI __DATA size: 0x{amfi_data.vmsize:x}")
                out.append(f"static let amfiDataUnslid: UInt64 = 0x{amfi_data.vmaddr:x}")
                out.append(f"static let amfiDataSize: UInt64 = 0x{amfi_data.vmsize:x}")
                out.append("")

                # Boolean flags in AMFI __DATA
                out.append("// AMFI boolean flags (potential disable switches)")
                out.append("// Write 1 to disable, 0 to enable")
                out.append("static let amfiFlagOffsets: [UInt64] = [")
                for off in range(0, min(amfi_data.filesize, 0x200), 8):
                    foff = amfi_data.fileoff + off
                    val = self.read_u64(foff)
                    if val <= 1:  # boolean
                        out.append(f"    0x{off:x},  // AMFI __DATA+0x{off:x} = {val}")
                out.append("]")
                out.append("")

        # CoreTrust component
        ct_comp = next((c for c in self.fileset_components
                        if "CoreTrust" in c.name), None)
        if ct_comp:
            ct_data = next((s for s in ct_comp.segments if s.name == "__DATA"), None)
            if ct_data:
                out.append(f"// CoreTrust __DATA (unslid): 0x{ct_data.vmaddr:x}")
                out.append(f"static let coreTrustDataUnslid: UInt64 = 0x{ct_data.vmaddr:x}")
                out.append("")

        # Key function addresses (unslid)
        out.append("// Key function addresses (unslid — add KASLR slide on device)")
        key_funcs = self.find_strings([
            b"pmap_lookup_in_loaded_trust_caches",
            b"trust_cache_runtime_add",
            b"amfi_check_dyld_policy_self",
        ])
        for name, locs in key_funcs.items():
            for _, va in locs[:1]:
                funcs = self.find_function_by_string_xref(va)
                if funcs:
                    out.append(f"// {name}: 0x{funcs[0]:x}")
        out.append("")

        # Experiment strategy
        out.append("// === RECOMMENDED EXPERIMENT ORDER ===")
        out.append("// 1. Read dynamicTCCandidateSlots on device")
        out.append("//    → Non-zero = heap pointer to dynamic trust cache!")
        out.append("//    → Follow pointer → read version/count → inject CDHash")
        out.append("// 2. Test write to AMFI __DATA (amfiDataUnslid + slide)")
        out.append("//    → If no panic: patch boolean flags!")
        out.append("// 3. Try trust_cache_runtime_add via RemoteCall")
        out.append("//    → Craft TC struct → call from launchd context")
        out.append("// 4. Scan for cs_enforcement_disable in main __DATA")
        out.append("//    → If found and writable: game over, all CS disabled")
        out.append("")

    # ─── Full Analysis ───────────────────────────────────────────────────────

    def run_full_analysis(self) -> str:
        """Run all analysis phases and return full report."""
        out: list[str] = []

        out.append("╔══════════════════════════════════════════════════════════════════════╗")
        out.append("║  DEEP TRUST CACHE & AMFI BYPASS ANALYSIS                            ║")
        out.append("║  iOS 18.2 (22C152) — iPhone XR (A12 T8020)                          ║")
        out.append("║  Kernelcache: " + self.path.name.ljust(54) + "║")
        out.append("╚══════════════════════════════════════════════════════════════════════╝")
        out.append("")

        # Basic info
        out.append(f"File size: {len(self.data) / 1024 / 1024:.1f} MiB")
        out.append(f"Fileset: {'Yes' if self.is_fileset else 'No'}")
        out.append(f"Components: {len(self.fileset_components)}")
        out.append(f"Segments: {len(self.segments)}")
        out.append("")

        if self.text_seg:
            out.append(f"__TEXT base (unslid): 0x{self.text_seg.vmaddr:x}")
        if self.data_seg:
            out.append(f"__DATA base (unslid): 0x{self.data_seg.vmaddr:x}")
            out.append(f"__DATA offset from __TEXT: 0x{self.data_offset_from_text:x}")
        if self.text_exec:
            out.append(f"__TEXT_EXEC: 0x{self.text_exec.vmaddr:x} (size 0x{self.text_exec.vmsize:x})")
        out.append("")

        # List fileset components
        if self.fileset_components:
            out.append("--- Fileset components (security-relevant) ---")
            for comp in self.fileset_components:
                if any(kw in comp.name.lower() for kw in
                       ["amfi", "trust", "coretrust", "security", "sandbox",
                        "pmap", "apfs", "integrity"]):
                    out.append(f"  {comp.name}: vm=0x{comp.vmaddr:x}")
            out.append("")

        # Run all phases
        data_slots = self.analyze_dynamic_trust_cache(out)
        self.analyze_pmap_cs(out)
        self.analyze_amfi_dispatch(out)
        self.analyze_trust_cache_call_graph(out)
        vectors = self.analyze_bypass_vectors(out)
        self.analyze_amfi_data_deep(out)
        self.emit_swift_offsets(out, data_slots, vectors)

        # Final summary
        out.append("")
        out.append("=" * 70)
        out.append("FINAL SUMMARY & RECOMMENDED NEXT STEPS")
        out.append("=" * 70)
        out.append("")
        out.append("Based on this analysis, the most promising approaches are:")
        out.append("")
        out.append("1. 🟢 DYNAMIC TC INJECTION")
        out.append("   Read zero __DATA slots on device → find heap TC → inject CDHash")
        out.append("   This is the SAME approach as Exp 92 but targeting HEAP TC")
        out.append("   instead of static __DATA TC (which is KTRR-protected).")
        out.append("")
        out.append("2. 🟢 trust_cache_runtime_add via RemoteCall")
        out.append("   Call the kernel function that adds DDI trust caches.")
        out.append("   Craft a valid TC struct with our CDHash → call from launchd.")
        out.append("   This is how Xcode/DeveloperDiskImage adds trust caches!")
        out.append("")
        out.append("3. 🟡 AMFI __DATA patch")
        out.append("   AMFI.kext __DATA might be OUTSIDE KTRR range.")
        out.append("   Test write → if works, patch boolean flags to disable checks.")
        out.append("")
        out.append("4. 🟡 cs_enforcement_disable")
        out.append("   If this global exists and is writable, setting it = 1")
        out.append("   disables ALL code signing enforcement.")
        out.append("")

        return "\n".join(out)

# ─── Main ────────────────────────────────────────────────────────────────────

DEFAULT_PATHS = [
    "kernelcache",
    "kernelcache.release.iphone11b.decompressed",
    "kernelcache.decompressed",
]


def find_kernelcache(arg: Optional[str]) -> Path:
    root = Path(__file__).resolve().parents[1]
    if arg and not arg.startswith("-"):
        p = Path(arg)
        if not p.is_file():
            raise SystemExit(f"File not found: {p}")
        return p
    for name in DEFAULT_PATHS:
        p = root / name
        if p.is_file():
            return p
    raise SystemExit(
        "No kernelcache found. Place decompressed Mach-O in repo root.\n"
        "On device: Settings → Fetch kernelcache."
    )


def main():
    argv = sys.argv[1:]
    path_arg = next((a for a in argv if not a.startswith("-")), None)

    path = find_kernelcache(path_arg)
    print(f"Loading kernelcache: {path} ({path.stat().st_size / 1024 / 1024:.1f} MiB)")
    print("This may take 30-60 seconds for full analysis...")
    print()

    analyzer = KernelcacheAnalyzer(path)

    # Run full analysis
    report = analyzer.run_full_analysis()

    # Write to file
    out_path = path.parent / "deep_probe_out.txt"
    out_path.write_text(report, encoding="utf-8")
    print(f"\n{'='*70}")
    print(f"Full report written to: {out_path}")
    print(f"{'='*70}\n")

    # Print summary to console
    lines = report.split("\n")
    # Print first 30 lines and last 50 lines
    print("\n".join(lines[:30]))
    print("\n... (see full report in deep_probe_out.txt) ...\n")

    # Find and print the final summary
    summary_start = None
    for i, line in enumerate(lines):
        if "FINAL SUMMARY" in line:
            summary_start = i
            break
    if summary_start:
        print("\n".join(lines[summary_start:]))


if __name__ == "__main__":
    main()
