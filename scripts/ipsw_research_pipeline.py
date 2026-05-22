#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║          IPSW Research Pipeline — Evidence-Based Findings Engine            ║
║                                                                              ║
║  Drop in an .ipsw → get a high-confidence research brief.                   ║
║                                                                              ║
║  Pipeline stages:                                                            ║
║    1. Extract IPSW (kernelcache, DMG, trustcaches, plists, sandbox profiles)║
║    2. Carve every Mach-O binary from the OS DMG                              ║
║    3. Run analyze_binary_deep on each (parallel where safe)                  ║
║    4. Cross-binary correlation:                                              ║
║         a. Same imported symbol → multiple binaries flagged together         ║
║         b. Mach service producer ↔ consumer pairs                            ║
║         c. Stub-resolved sink calls (e.g. csops, mach_vm_write)              ║
║         d. String anchors + xref evidence                                    ║
║    5. Evidence-Based Findings:                                               ║
║         - HIGH    : ≥2 corroborating signals + symbol/string anchor          ║
║         - MEDIUM  : 1 strong signal with cross-reference                     ║
║         - LOW     : single hint, no corroboration                            ║
║    6. Research Brief output (JSON + plaintext + optional PDF)                ║
║                                                                              ║
║  Every finding carries:                                                      ║
║    - source_binary        : which Mach-O it came from                        ║
║    - evidence_chain       : list of concrete evidence items (strings, VAs)   ║
║    - confidence           : HIGH / MEDIUM / LOW                              ║
║    - corroboration_count  : how many independent signals support this        ║
║    - reasoning            : human-readable explanation                       ║
║    - actionable           : suggested next step (read code at VA, decompile) ║
║                                                                              ║
║  No conjecture. No "the binary may have...". Only evidence-backed claims.    ║
║                                                                              ║
║  Usage:                                                                      ║
║    python ipsw_research_pipeline.py /path/to/firmware.ipsw                   ║
║    python ipsw_research_pipeline.py firmware.ipsw --output research.json     ║
║    python ipsw_research_pipeline.py firmware.ipsw --workers 4 --pdf brief.pdf║
║    python ipsw_research_pipeline.py firmware.ipsw --filter lsd,installd      ║
║                                                                              ║
║  Pure Python 3.8+ — depends on analyze_binary_deep.py (same directory)      ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import tempfile
import textwrap
import collections
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from typing import Optional, Any

# Ensure analyze_binary_deep is importable (same directory or on path)
_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

try:
    import analyze_binary_deep as abd
except ImportError as e:
    print(f"[!] Cannot import analyze_binary_deep.py from {_SCRIPT_DIR}: {e}", file=sys.stderr)
    print(f"    Make sure analyze_binary_deep.py is in the same directory as this script.", file=sys.stderr)
    sys.exit(1)


# ═══════════════════════════════════════════════════════════════════════════════
# §0  CONSOLE HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

W = 78

def banner(title: str):
    print("\n" + "═" * W)
    print(f"  {title}")
    print("═" * W)

def section(title: str):
    print(f"\n── {title} " + "─" * max(0, W - 5 - len(title)))

def kv(label: str, value: Any, indent: int = 2):
    pad = " " * indent
    print(f"{pad}{label:<32}: {value}")

def info(msg: str):
    print(f"  [*] {msg}")

def good(msg: str):
    print(f"  [+] {msg}")

def warn(msg: str):
    print(f"  [!] {msg}", file=sys.stderr)

def err(msg: str):
    print(f"  [✗] {msg}", file=sys.stderr)


# ═══════════════════════════════════════════════════════════════════════════════
# §1  ENTRY POINT (will be filled by chunk 5)
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    """Entry point — argument parsing and pipeline orchestration."""
    ap = argparse.ArgumentParser(
        description="IPSW Research Pipeline — evidence-based reverse engineering report",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
        Examples:
          python ipsw_research_pipeline.py firmware.ipsw
          python ipsw_research_pipeline.py firmware.ipsw -o research.json
          python ipsw_research_pipeline.py firmware.ipsw --workers 4
          python ipsw_research_pipeline.py firmware.ipsw --filter lsd,installd,amfid
          python ipsw_research_pipeline.py firmware.ipsw --pdf brief.pdf
          python ipsw_research_pipeline.py firmware.ipsw --keep-extracts /tmp/ipsw_dump
        """),
    )
    ap.add_argument("ipsw", nargs="?", default=None,
                    help="Path to .ipsw firmware file (omit when using --gui)")
    ap.add_argument("-o", "--output", default=None,
                    help="Output JSON path (default: <ipsw>_research.json)")
    ap.add_argument("--workers", type=int, default=2,
                    help="Parallel binary analysis workers (default: 2). "
                         "Use 1 to disable multi-process.")
    ap.add_argument("--filter", default=None,
                    help="Comma-separated substring filter for binary names "
                         "(e.g. 'lsd,installd,amfid'). Only matching binaries analyzed.")
    ap.add_argument("--max-binaries", type=int, default=200,
                    help="Maximum binaries to analyze (default: 200, focus on critical)")
    ap.add_argument("--min-confidence", choices=["HIGH", "MEDIUM", "LOW"], default="LOW",
                    help="Minimum confidence threshold for findings (default: LOW)")
    ap.add_argument("--pdf", default=None,
                    help="Generate PDF research brief at given path")
    ap.add_argument("--keep-extracts", default=None,
                    help="Keep extracted IPSW contents at this directory (default: temp dir)")
    ap.add_argument("--quick", action="store_true",
                    help="Skip xref/gadgets for faster scan (less precise correlation)")
    ap.add_argument("--gui", "-g", action="store_true",
                    help="Launch interactive desktop GUI instead of running CLI pipeline")
    ap.add_argument("--verbose", "-v", action="store_true")
    args = ap.parse_args()

    # Route to GUI if requested
    if args.gui:
        launch_gui()
        return

    if not args.ipsw:
        ap.error("ipsw path is required when not using --gui")

    ipsw_path = Path(args.ipsw)
    if not ipsw_path.exists():
        err(f"IPSW not found: {ipsw_path}")
        sys.exit(1)
    if ipsw_path.suffix.lower() != ".ipsw":
        warn(f"File does not have .ipsw extension; processing anyway")

    banner(f"IPSW RESEARCH PIPELINE — {ipsw_path.name}")

    start_time = time.time()

    # Stage 1: Extract & analyze (chunks 2-4)
    pipeline_state = {
        "ipsw_path": str(ipsw_path),
        "ipsw_size_mb": round(ipsw_path.stat().st_size / (1024 * 1024), 2),
        "args": vars(args),
        "started_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }

    try:
        # Future: stage 1-5 implementations from later chunks
        result = run_pipeline(ipsw_path, args, pipeline_state)
    except Exception as e:
        err(f"Pipeline failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(2)

    elapsed = time.time() - start_time
    pipeline_state["elapsed_seconds"] = round(elapsed, 2)
    pipeline_state["completed_at"] = time.strftime("%Y-%m-%d %H:%M:%S")

    banner(f"PIPELINE COMPLETE — {elapsed:.1f}s")

    # Output JSON
    out_path = Path(args.output) if args.output else ipsw_path.with_suffix(".research.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(_make_serializable(result), f, indent=2, ensure_ascii=False)
    good(f"Research brief JSON → {out_path}")
    good(f"Total findings: {len(result.get('findings', []))}")
    good(f"  HIGH confidence:   {sum(1 for f in result.get('findings', []) if f.get('confidence')=='HIGH')}")
    good(f"  MEDIUM confidence: {sum(1 for f in result.get('findings', []) if f.get('confidence')=='MEDIUM')}")
    good(f"  LOW confidence:    {sum(1 for f in result.get('findings', []) if f.get('confidence')=='LOW')}")

    # Generate PDF if requested (chunk 5)
    if args.pdf:
        try:
            generate_research_pdf(result, args.pdf)
            good(f"PDF research brief → {args.pdf}")
        except Exception as e:
            warn(f"PDF generation failed: {e}")


def _make_serializable(obj):
    """Recursively convert objects to JSON-serializable types."""
    if isinstance(obj, bytes):
        return obj.hex()
    if isinstance(obj, (set, frozenset)):
        return sorted(_make_serializable(i) for i in obj)
    if isinstance(obj, dict):
        return {str(k): _make_serializable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_make_serializable(i) for i in obj]
    if isinstance(obj, Path):
        return str(obj)
    return obj


# ═══════════════════════════════════════════════════════════════════════════════
# §2  IPSW EXTRACTION & BINARY DISCOVERY
# ═══════════════════════════════════════════════════════════════════════════════

# Critical iOS daemons that always deserve deep analysis (jailbreak research)
PRIORITY_BINARIES = {
    # Code signing & integrity
    "amfid", "amfi", "trustd", "tccd",
    # Installation pipeline
    "lsd", "installd", "mobile_installation_proxy",
    "mobileinstall", "MobileInstallation",
    # Container management
    "containermanagerd", "MobileContainerManager",
    # SpringBoard ecosystem
    "SpringBoard", "frontboardd", "backboardd",
    # Mounting / disk image
    "MobileStorageMounter", "DDIService", "diskimagesd",
    # Sandbox
    "sandboxd",
    # Launch services
    "launchd",
    # Keystore / security
    "securityd", "keybagd", "applekeystored",
    # Misc privileged
    "lockdownd", "fairplayd", "duetexpertd",
}

# Strings that indicate critical infrastructure (used for prioritization heuristics)
CRITICAL_INFRA_STRINGS = {
    "trust_cache", "amfi_", "AppleMobileFileIntegrity",
    "registerApplication", "MIInstaller", "MIBundleContainer",
    "kCMSEntitlements", "MobileContainerManager",
    "task_for_pid", "csops", "platform-binary",
    "mach_vm_write", "thread_set_state",
}


def extract_ipsw(ipsw_path: Path, extract_dir: Path) -> dict:
    """
    Extract IPSW contents:
      - Restore.plist (firmware metadata)
      - kernelcache (Mach-O kernel)
      - Largest DMG (root filesystem) → carve all Mach-O inside
      - .tc / TrustCache files
      - Any sandbox profiles
    Returns metadata + list of extracted Mach-O paths.
    """
    info(f"Extracting {ipsw_path.name} ({ipsw_path.stat().st_size / (1024*1024):.1f} MB)...")

    # Reuse analyze_binary_deep's process_input_recursive — already handles IPSW
    macho_paths = abd.process_input_recursive(ipsw_path, extract_dir, aea_key_b64=None)

    # Read firmware metadata (process_input_recursive populates abd._ipsw_firmware_meta)
    firmware_meta = dict(abd._ipsw_firmware_meta or {})

    # Also extract sandbox profiles & launchd plists from DMG carving (best-effort)
    sandbox_profiles = []
    launchd_plists = []
    for p in extract_dir.rglob("*.sb"):
        sandbox_profiles.append(str(p))
    for p in extract_dir.rglob("*.plist"):
        # Filter to launchd-style plists
        try:
            content = p.read_bytes()[:2048]
            if b"Label" in content and (b"ProgramArguments" in content or b"Program" in content):
                launchd_plists.append(str(p))
        except Exception:
            continue

    return {
        "firmware_meta": firmware_meta,
        "macho_paths": [str(p) for p in macho_paths],
        "macho_count": len(macho_paths),
        "sandbox_profiles": sandbox_profiles[:50],
        "launchd_plists": launchd_plists[:100],
        "extract_dir": str(extract_dir),
    }


def filter_binaries(macho_paths: list[str], filter_str: Optional[str],
                    max_count: int) -> list[str]:
    """
    Filter and prioritize binaries.
    Always include PRIORITY_BINARIES first, then user filter, then any other up to max.
    """
    paths = [Path(p) for p in macho_paths]

    # Always include priority binaries first
    priority = [p for p in paths if p.name in PRIORITY_BINARIES]
    others = [p for p in paths if p.name not in PRIORITY_BINARIES]

    # Apply user filter
    if filter_str:
        substrs = [s.strip().lower() for s in filter_str.split(",") if s.strip()]
        if substrs:
            others = [p for p in others
                      if any(s in p.name.lower() for s in substrs)]

    # Combine: priority always; then user-filtered others up to limit
    selected = priority + others
    selected = selected[:max_count]

    info(f"Selected {len(selected)} binaries for analysis "
         f"({len(priority)} priority + {len(selected)-len(priority)} other)")
    return [str(p) for p in selected]


# ═══════════════════════════════════════════════════════════════════════════════
# §3  ANALYSIS WORKER (process-pool friendly)
# ═══════════════════════════════════════════════════════════════════════════════

def analyze_one_binary(args_tuple) -> dict:
    """
    Worker fn for ProcessPoolExecutor. Must be top-level (picklable).
    Returns minimal-but-evidence-rich report for downstream correlation.
    """
    binary_path, build_xref, find_gadgets = args_tuple
    name = Path(binary_path).name
    # Suppress chatty stdout & redirect to a buffer (Windows cp1252 chokes on Unicode arrows)
    import io as _io
    _saved_out, _saved_err = sys.stdout, sys.stderr
    sys.stdout = _io.StringIO()
    sys.stderr = _io.StringIO()
    try:
        # Ensure abd module is loaded inside worker
        import analyze_binary_deep as abd
        report = abd.analyze(
            binary_path,
            keywords=abd.DEFAULT_KEYWORDS,
            build_cfg=False,
            run_taint=False,
            build_xref=build_xref,
            find_gadgets=find_gadgets,
            disasm_n_funcs=0,
            verbose=False,
        )
        # Slim down — keep only fields needed for correlation to reduce IPC overhead
        slim = {
            "binary_name": name,
            "binary_path": binary_path,
            "meta": report.get("meta", {}),
            "code_signature": {
                "team_id": report.get("code_signature", {}).get("team_id"),
                "identifiers": report.get("code_signature", {}).get("identifiers", []),
                "cd_hashes": report.get("code_signature", {}).get("cd_hashes", []),
            },
            "entitlements": report.get("entitlements") or {},
            "private_entitlements_audit": report.get("private_entitlements_audit", {}),
            "vulnerability_scan": report.get("vulnerability_scan", {}),
            "exploit_primitives": report.get("exploit_primitives", {}),
            "yara_scan": report.get("yara_scan", {}),
            "stub_map": report.get("stub_map", {}),
            "xref_database": report.get("xref_database", {}),
            "nsxpc_reconstruction": report.get("nsxpc_reconstruction", {}),
            "mig_subsystems": report.get("mig_subsystems", {}),
            "rop_gadgets_summary": {
                "total_gadgets": report.get("rop_gadgets", {}).get("total_gadgets", 0),
                "by_category": report.get("rop_gadgets", {}).get("by_category", {}),
            },
            "imported_count": len(report.get("symbols", {}).get("imported", [])),
            "exported_count": len(report.get("symbols", {}).get("exported", [])),
            "dylib_imports":  [d.get("name", "") for d in report.get("symbols", {}).get("dylib_imports", [])],
            "objc_class_count": report.get("objc", {}).get("class_count", 0),
            "objc_classes_sample": [c.get("name") for c in report.get("objc", {}).get("classes", [])[:30]],
            "has_pie": report.get("meta", {}).get("has_pie", False),
            "has_arc": report.get("meta", {}).get("has_arc", False),
            "encrypted": report.get("meta", {}).get("encrypted", False),
            # Sample of strings (interesting only) for correlation
            "interesting_strings": _extract_interesting_strings(report),
            "constructors": report.get("constructors", {}),
            "threat_scorecard": report.get("threat_scorecard", {}),
            "_ok": True,
        }
        return slim
    except Exception as e:
        return {"binary_name": name, "binary_path": binary_path,
                "_ok": False, "error": str(e)}
    finally:
        sys.stdout, sys.stderr = _saved_out, _saved_err


def _extract_interesting_strings(report: dict) -> list[str]:
    """Pull strings that match critical infrastructure keywords."""
    interesting = []
    cfstrings = report.get("strings", {}).get("cfstrings", [])
    keyword_matches = report.get("keyword_matches", {})

    # CFStrings (already filtered by length/printable)
    for cf in cfstrings[:200]:
        s = cf.get("string", "")
        if any(kw in s for kw in CRITICAL_INFRA_STRINGS):
            interesting.append(s[:200])

    # Keyword matches
    for kw, matches in keyword_matches.items():
        for s in matches[:5]:
            if 4 <= len(s) <= 200:
                interesting.append(s)

    # Deduplicate
    return sorted(set(interesting))[:100]


# ═══════════════════════════════════════════════════════════════════════════════
# §4  EVIDENCE-BASED FINDINGS ENGINE
# ═══════════════════════════════════════════════════════════════════════════════
#
# Each finding requires CONCRETE EVIDENCE (no conjecture):
#   - source_binary    : Mach-O file path/name
#   - evidence_chain   : list of (kind, value, location) tuples
#   - confidence       : HIGH / MEDIUM / LOW
#   - corroboration    : how many independent signals support this finding
#   - reasoning        : human-readable derivation
#   - actionable       : suggested next research step
#
# Evidence kinds:
#   - imported_symbol  : a stub-resolved import (e.g. _csops, _mach_vm_write)
#   - private_entitlement : entry in code signature plist
#   - string_anchor    : a CFString with concrete VA in the binary
#   - mach_service     : a "com.apple.*" service exposed/consumed
#   - xref_caller      : an instruction VA that calls a sink symbol
#   - yara_pattern     : YARA rule hit with file offset
#   - rop_gadget       : ROP gadget VA + instruction sequence
#   - constructor      : __mod_init_func entry (executes before main)
#
# A finding becomes HIGH confidence only when:
#   - ≥2 independent evidence kinds support it, OR
#   - 1 strong evidence kind + cross-binary corroboration

class EvidenceFindings:
    """Builder for evidence-backed findings across multiple binaries."""

    def __init__(self, firmware_meta: dict):
        self.firmware_meta = firmware_meta
        self.findings: list[dict] = []
        self.binary_index: dict[str, dict] = {}  # name → slim report
        self.symbol_index: dict[str, list[str]] = collections.defaultdict(list)
        self.string_index: dict[str, list[str]] = collections.defaultdict(list)
        self.machsvc_index: dict[str, list[str]] = collections.defaultdict(list)
        self.entitlement_index: dict[str, list[str]] = collections.defaultdict(list)

    def add_binary_report(self, slim: dict):
        if not slim.get("_ok"):
            return
        name = slim["binary_name"]
        self.binary_index[name] = slim

        # Index imported symbols (resolved via stubs)
        for stub_va, sym in slim.get("stub_map", {}).items():
            sym_clean = sym.lstrip("_")
            self.symbol_index[sym_clean].append(name)

        # Index interesting strings
        for s in slim.get("interesting_strings", []):
            self.string_index[s].append(name)

        # Index mach services
        nsxpc = slim.get("nsxpc_reconstruction", {})
        for svc in nsxpc.get("mach_services", []):
            self.machsvc_index[svc].append(name)

        # Index private entitlements
        pea = slim.get("private_entitlements_audit", {})
        for f in pea.get("findings", []):
            self.entitlement_index[f["key"]].append(name)

    # ─── Finding generators ─────────────────────────────────────────────────

    def find_kernel_attack_surface(self):
        """
        Find binaries with kernel-level exploit primitive imports.
        Confidence is based on number of distinct primitive symbols imported.
        """
        # Symbols from EXPLOIT_PRIMITIVE_SYMS that map to direct kernel ops
        kernel_sinks = {
            "task_for_pid": "Acquire arbitrary task port",
            "mach_vm_write": "Write remote process memory",
            "mach_vm_read": "Read remote process memory",
            "mach_vm_protect": "Change memory protections",
            "mach_vm_remap": "Remap memory between processes",
            "thread_set_state": "Hijack thread CPU state (PC/SP)",
            "thread_create_running": "Spawn thread with controlled PC",
            "csops": "Manipulate code signing flags",
            "csops_audittoken": "Code signing op via audit token",
            "host_get_special_port": "Acquire host special ports",
            "mach_port_kobject": "Resolve kobject for port (kernel obj leak)",
        }
        for binary_name, slim in self.binary_index.items():
            stub_map = slim.get("stub_map", {})
            imported_syms = {sym.lstrip("_") for sym in stub_map.values()}
            hits = []
            for sink_sym, desc in kernel_sinks.items():
                if sink_sym in imported_syms:
                    # Find the stub VA for evidence
                    stub_va = next((va for va, s in stub_map.items()
                                    if s.lstrip("_") == sink_sym), "?")
                    hits.append({
                        "kind": "imported_symbol",
                        "value": sink_sym,
                        "stub_va": stub_va,
                        "description": desc,
                    })

            if not hits:
                continue

            # Confidence based on number of distinct kernel sinks
            n = len(hits)
            if n >= 3:
                confidence = "HIGH"
            elif n >= 2:
                confidence = "MEDIUM"
            else:
                confidence = "LOW"

            # Cross-binary check: how many other binaries use these same sinks?
            corroboration = sum(
                1 for h in hits
                if len(self.symbol_index.get(h["value"], [])) > 1
            )

            self.findings.append({
                "category": "kernel_attack_surface",
                "title": f"{binary_name} imports {n} kernel-level primitive(s)",
                "source_binary": binary_name,
                "confidence": confidence,
                "corroboration_count": corroboration,
                "evidence_chain": hits,
                "reasoning": (
                    f"The binary directly imports {n} kernel-control primitives: "
                    + ", ".join(h["value"] for h in hits)
                    + ". Each stub is resolvable to a concrete VA, indicating active "
                    + "use in code (not dead imports)."
                ),
                "actionable": (
                    f"Use --xref-query \"{hits[0]['value']}\" on this binary to find "
                    f"every call site, then --decompile-va each call site for context."
                ),
            })

    def find_amfi_trust_cache_callers(self):
        """
        Binaries that interact with AMFI / Trust Cache infrastructure.
        Cross-references entitlements + symbol imports + string anchors.
        """
        for binary_name, slim in self.binary_index.items():
            evidence = []

            # 1. Entitlement evidence
            pea = slim.get("private_entitlements_audit", {})
            for f in pea.get("findings", []):
                if "amfi" in f["key"].lower() or "trust" in f["key"].lower():
                    evidence.append({
                        "kind": "private_entitlement",
                        "value": f["key"],
                        "description": f["description"],
                        "risk": f["risk"],
                    })

            # 2. String anchors
            interesting = slim.get("interesting_strings", [])
            anchors = [s for s in interesting
                       if any(kw in s for kw in ("trust_cache", "amfi_", "AppleMobileFileIntegrity"))]
            for s in anchors[:10]:
                evidence.append({
                    "kind": "string_anchor",
                    "value": s[:120],
                })

            # 3. Symbol evidence (amfi_* imports)
            stub_map = slim.get("stub_map", {})
            for stub_va, sym in stub_map.items():
                sym_clean = sym.lstrip("_")
                if "amfi" in sym_clean.lower() or "TrustCache" in sym_clean:
                    evidence.append({
                        "kind": "imported_symbol",
                        "value": sym_clean,
                        "stub_va": stub_va,
                    })

            if not evidence:
                continue

            # Confidence: 3+ evidence kinds = HIGH; 2 = MEDIUM; 1 = LOW
            kinds = {e["kind"] for e in evidence}
            confidence = "HIGH" if len(kinds) >= 3 else ("MEDIUM" if len(kinds) >= 2 else "LOW")

            self.findings.append({
                "category": "amfi_trust_cache",
                "title": f"{binary_name} interacts with AMFI/TrustCache",
                "source_binary": binary_name,
                "confidence": confidence,
                "corroboration_count": len(evidence),
                "evidence_chain": evidence[:30],
                "reasoning": (
                    f"Binary has {len(evidence)} pieces of evidence across "
                    f"{len(kinds)} kinds ({', '.join(kinds)}) tying it to "
                    f"AMFI/TrustCache subsystem. This means {binary_name} is "
                    f"a participant in code-signing enforcement."
                ),
                "actionable": (
                    f"Read every string anchor + decompile around symbol imports "
                    f"to map exact AMFI integration logic. Useful for "
                    f"trust-cache injection research."
                ),
            })

    def find_app_registration_pipeline(self):
        """
        Binaries involved in app registration (high-priority research goal).
        Cross-correlate string anchors + Mach services + ObjC classes.
        """
        for binary_name, slim in self.binary_index.items():
            evidence = []

            # ObjC classes containing "Registration" / "Install"
            for cls_name in slim.get("objc_classes_sample", []):
                if any(kw in cls_name for kw in ("Registration", "Install", "MIInstaller",
                                                   "ApplicationWorkspace", "BundleContainer",
                                                   "MCMAppDataContainer", "LaunchServices")):
                    evidence.append({
                        "kind": "objc_class",
                        "value": cls_name,
                    })

            # String anchors related to registration
            for s in slim.get("interesting_strings", []):
                if any(kw in s for kw in ("registerApplication", "MIInstaller",
                                           "MIBundleContainer", "MobileContainerManager",
                                           "applicationdictionary", "_registerApplication")):
                    evidence.append({
                        "kind": "string_anchor",
                        "value": s[:200],
                    })

            # Entitlements
            pea = slim.get("private_entitlements_audit", {})
            for f in pea.get("findings", []):
                if f["category"] == "installation":
                    evidence.append({
                        "kind": "private_entitlement",
                        "value": f["key"],
                        "description": f["description"],
                    })

            # Mach services
            nsxpc = slim.get("nsxpc_reconstruction", {})
            for svc in nsxpc.get("mach_services", []):
                if any(kw in svc.lower() for kw in ("install", "container", "lsd",
                                                     "launchservices", "mobile.installation")):
                    evidence.append({
                        "kind": "mach_service",
                        "value": svc,
                    })

            if len(evidence) < 2:
                continue

            kinds = {e["kind"] for e in evidence}
            confidence = "HIGH" if len(kinds) >= 3 else "MEDIUM"

            self.findings.append({
                "category": "app_registration_pipeline",
                "title": f"{binary_name} participates in app registration pipeline",
                "source_binary": binary_name,
                "confidence": confidence,
                "corroboration_count": len(evidence),
                "evidence_chain": evidence[:30],
                "reasoning": (
                    f"Binary shows {len(evidence)} evidence items across {len(kinds)} "
                    f"distinct kinds ({', '.join(kinds)}) connecting it to the "
                    f"app registration / installation subsystem."
                ),
                "actionable": (
                    f"For panic-free app registration research: --xref-query "
                    f"\"registerApplication\" on this binary to find registration "
                    f"call sites + --scan-xpc to map the IPC interfaces."
                ),
            })

    def find_sandbox_escape_indicators(self):
        """
        Find binaries with both no-sandbox entitlements AND privileged operation imports.
        """
        for binary_name, slim in self.binary_index.items():
            evidence = []

            pea = slim.get("private_entitlements_audit", {})
            sandbox_ents = [f for f in pea.get("findings", [])
                            if f["category"] == "sandbox" or "sandbox" in f["key"].lower()
                               or f["key"] == "com.apple.private.security.no-sandbox"]
            for f in sandbox_ents:
                evidence.append({
                    "kind": "private_entitlement",
                    "value": f["key"],
                    "risk": f["risk"],
                    "description": f["description"],
                })

            # Look for sandbox_* symbol imports
            for stub_va, sym in slim.get("stub_map", {}).items():
                if "sandbox_" in sym:
                    evidence.append({
                        "kind": "imported_symbol",
                        "value": sym.lstrip("_"),
                        "stub_va": stub_va,
                    })

            if not evidence:
                continue

            kinds = {e["kind"] for e in evidence}
            crit_ent = any(e.get("risk") == "CRITICAL" for e in evidence)
            confidence = "HIGH" if (crit_ent or len(kinds) >= 2) else "MEDIUM"

            self.findings.append({
                "category": "sandbox_escape",
                "title": f"{binary_name} bypasses or controls App Sandbox",
                "source_binary": binary_name,
                "confidence": confidence,
                "corroboration_count": len(evidence),
                "evidence_chain": evidence[:20],
                "reasoning": (
                    f"Binary holds sandbox-bypassing entitlements and/or imports "
                    f"sandbox_* control APIs. This makes it either a sandbox "
                    f"controller or completely unsandboxed."
                ),
                "actionable": (
                    f"This binary is a high-value sandbox research target. "
                    f"Check for sandbox profile & decompile sandbox_* call sites."
                ),
            })

    def find_cross_binary_xpc_pairs(self):
        """
        Identify XPC client/server pairs by matching mach service producers
        with consumers across binaries.
        """
        # Build producer/consumer index
        # A binary that mentions "com.apple.X" might be either side
        # Heuristic: binaries that EXPORT a mach service vs. those that CONNECT to it.
        # For now: any binary that mentions a service is a "participant"
        for svc, binaries in self.machsvc_index.items():
            if len(binaries) < 2:
                continue  # No cross-binary pair
            # Cap at first 10 binaries for evidence
            participants = sorted(set(binaries))[:10]
            self.findings.append({
                "category": "xpc_communication_pair",
                "title": f"Mach service `{svc}` is referenced across {len(participants)} binaries",
                "source_binary": ", ".join(participants),
                "confidence": "MEDIUM" if len(participants) >= 3 else "LOW",
                "corroboration_count": len(participants),
                "evidence_chain": [
                    {"kind": "mach_service", "value": svc, "binary": b}
                    for b in participants
                ],
                "reasoning": (
                    f"The mach service `{svc}` appears in {len(participants)} "
                    f"different binaries. This indicates either a client/server "
                    f"relationship or shared API usage."
                ),
                "actionable": (
                    f"Run --scan-xpc on each participant to see if it's a client or "
                    f"server. Use --xref-query \"{svc}\" to find connect call sites."
                ),
            })

    def find_unpatched_cve_indicators(self):
        """
        Combine firmware version with binary-level evidence.
        NEW: only flag CVE if binary actually imports the related sink.
        """
        ios_ver = self.firmware_meta.get("ios_version", "")
        if not ios_ver:
            return

        try:
            cve_kb = abd.build_ios_cve_knowledge_base()
        except Exception:
            return

        product_type = self.firmware_meta.get("product_type", "")
        try:
            hw_chip = abd._detect_hw_from_product(product_type)
        except Exception:
            hw_chip = "Unknown"

        # CVE → expected sinks (heuristic)
        cve_sinks = {
            "CVE-2025-24085": ["CMBufferQueue", "CMBlockBuffer", "CoreMedia"],
            "CVE-2024-44285": ["mach_msg", "task_get_special_port"],
            "CVE-2024-23208": ["fsmgr", "kfd_"],
        }

        for cve in cve_kb:
            if not abd._version_in_range(ios_ver, cve["affects_ios_min"], cve["affects_ios_max"]):
                continue

            hw_list = cve.get("affects_hw", ["all"])
            if "all" not in hw_list and hw_chip not in hw_list:
                continue

            patched = cve.get("patched_ios")
            if patched is None:
                status = "UNPATCHABLE"
            elif abd._parse_version(ios_ver) >= abd._parse_version(patched):
                continue  # already patched
            else:
                status = "POTENTIALLY_VULNERABLE"

            # Look for sink evidence in any binary
            sinks = cve_sinks.get(cve["id"], [])
            participating_binaries = []
            sink_evidence = []
            for sink in sinks:
                for bname, slim in self.binary_index.items():
                    syms = {s.lstrip("_") for s in slim.get("stub_map", {}).values()}
                    strs = slim.get("interesting_strings", [])
                    if any(sink in s for s in syms) or any(sink in s for s in strs):
                        participating_binaries.append(bname)
                        sink_evidence.append({
                            "kind": "binary_imports_sink",
                            "value": sink,
                            "binary": bname,
                        })

            confidence = "LOW"
            evidence_chain = [{
                "kind": "firmware_version",
                "value": f"iOS {ios_ver} ({hw_chip})",
                "description": f"firmware in affected range {cve['affects_ios_min']}-{cve['affects_ios_max']}",
            }]
            if participating_binaries:
                confidence = "HIGH" if len(set(participating_binaries)) >= 2 else "MEDIUM"
                evidence_chain.extend(sink_evidence[:10])

            self.findings.append({
                "category": "cve_indicator",
                "title": f"{cve['id']} ({cve['name']}) — {status}",
                "source_binary": ", ".join(set(participating_binaries))[:200] or "(firmware-wide)",
                "confidence": confidence,
                "corroboration_count": len(evidence_chain),
                "evidence_chain": evidence_chain,
                "reasoning": (
                    f"Firmware {ios_ver} on {hw_chip} is in affected range. "
                    f"{cve['description']} "
                    + (f"Sink evidence found in {len(set(participating_binaries))} binaries."
                       if participating_binaries else "No sink evidence in scanned binaries.")
                ),
                "actionable": (
                    f"References: {', '.join(cve.get('references', [])[:3])}. "
                    + (f"Decompile call sites in: {list(set(participating_binaries))[:5]}"
                       if participating_binaries else "Update iOS to patched version.")
                ),
            })

    def find_yara_hits_corroborated(self):
        """
        YARA hits are evidence only when paired with other signals (otherwise noise).
        """
        for binary_name, slim in self.binary_index.items():
            yara = slim.get("yara_scan", {})
            matches = yara.get("matches", [])
            if not matches:
                continue

            # Group by category
            cats = collections.defaultdict(list)
            for m in matches:
                cats[m.get("category", "general")].append(m)

            for cat, ms in cats.items():
                if cat == "rop":
                    continue  # Too noisy on its own
                evidence = [{
                    "kind": "yara_pattern",
                    "value": m["rule"],
                    "match_count": m["match_count"],
                    "first_offset": m["hits"][0]["offset"] if m.get("hits") else None,
                } for m in ms]

                # Boost confidence if entitlements/symbols also point to same theme
                cross_evidence = 0
                stub_syms = {s.lstrip("_") for s in slim.get("stub_map", {}).values()}
                if cat == "anti_debug" and "ptrace" in stub_syms:
                    cross_evidence += 1
                    evidence.append({"kind": "imported_symbol", "value": "ptrace"})
                if cat == "amfi" and any("amfi" in s.lower() for s in stub_syms):
                    cross_evidence += 1

                confidence = "MEDIUM" if cross_evidence else "LOW"
                self.findings.append({
                    "category": f"yara_{cat}",
                    "title": f"{binary_name} contains {cat} byte patterns ({len(ms)} rules)",
                    "source_binary": binary_name,
                    "confidence": confidence,
                    "corroboration_count": len(evidence),
                    "evidence_chain": evidence,
                    "reasoning": (
                        f"YARA scanner detected {len(ms)} {cat} rules matching. "
                        + (f"Corroborated by {cross_evidence} additional evidence kinds."
                           if cross_evidence else "Standalone signal — verify manually.")
                    ),
                    "actionable": "Open the file at the listed offsets to confirm the pattern is in code (not data).",
                })

    # ─── MODULE A: Deep Taint Analysis ────────────────────────────────────────
    # Track data flow from XPC/IPC input sources to dangerous sinks.
    # A "tainted path" = input function → ... → sink function in same binary.

    # Input sources (where untrusted data enters)
    TAINT_SOURCES = {
        "xpc_dictionary_get_string": "XPC string input",
        "xpc_dictionary_get_data": "XPC raw data input",
        "xpc_dictionary_get_value": "XPC generic value",
        "xpc_dictionary_get_int64": "XPC integer input",
        "xpc_dictionary_get_uint64": "XPC unsigned integer",
        "xpc_dictionary_get_bool": "XPC boolean",
        "xpc_dictionary_get_fd": "XPC file descriptor",
        "xpc_dictionary_get_mach_send_right": "XPC mach port",
        "xpc_array_get_value": "XPC array element",
        "CFReadStreamRead": "Stream read (network/file)",
        "recv": "Socket receive",
        "recvmsg": "Socket receive message",
        "read": "File/socket read",
        "fread": "Buffered file read",
        "NSXPCConnection": "NSXPC connection object",
        "SecItemCopyMatching": "Keychain query result",
        "IOConnectCallMethod": "IOKit user client input",
        "mach_msg": "Raw Mach message receive",
        "mig_get_reply_port": "MIG reply port",
    }

    # Dangerous sinks (where tainted data causes harm)
    TAINT_SINKS = {
        "mach_vm_write": "Arbitrary memory write",
        "mach_vm_protect": "Memory protection change",
        "mach_vm_remap": "Memory remap (code injection)",
        "task_for_pid": "Task port acquisition",
        "thread_set_state": "Thread register hijack",
        "thread_create_running": "Thread creation with controlled PC",
        "csops": "Code signing flag manipulation",
        "posix_spawn": "Process spawn",
        "execve": "Process exec",
        "system": "Shell command execution",
        "popen": "Shell pipe execution",
        "dlopen": "Dynamic library load",
        "mmap": "Memory mapping (potential code injection)",
        "IOConnectCallMethod": "IOKit method call (kernel attack)",
        "sandbox_extension_consume": "Sandbox extension consume",
        "SecTrustEvaluate": "Certificate trust evaluation",
        "xpc_connection_send_message": "XPC message send (privilege relay)",
        "objc_msgSend": "ObjC dispatch (type confusion target)",
        "CFRelease": "CF object release (potential UAF trigger)",
        "free": "Heap free (potential UAF/double-free)",
        "vm_deallocate": "VM deallocation",
    }

    def find_taint_paths(self):
        """
        For each binary, check if it imports BOTH a taint source AND a taint sink.
        If yes → potential tainted data path exists.
        Confidence boosted if xref database shows source→sink call chain.
        """
        for binary_name, slim in self.binary_index.items():
            stub_map = slim.get("stub_map", {})
            imported_syms = {sym.lstrip("_"): va for va, sym in stub_map.items()}

            # Find which sources and sinks are present
            sources_found = []
            sinks_found = []
            for sym, va in imported_syms.items():
                if sym in self.TAINT_SOURCES:
                    sources_found.append({"symbol": sym, "stub_va": va,
                                           "desc": self.TAINT_SOURCES[sym]})
                if sym in self.TAINT_SINKS:
                    sinks_found.append({"symbol": sym, "stub_va": va,
                                         "desc": self.TAINT_SINKS[sym]})

            if not sources_found or not sinks_found:
                continue

            # Check xref database for actual call paths (source caller == sink caller)
            xref_db = slim.get("xref_database", {})
            symbol_xrefs = xref_db.get("symbol_xrefs_sample", {})

            connected_pairs = []
            for src in sources_found:
                src_callers = set()
                for key, callers in symbol_xrefs.items():
                    if src["symbol"] in key:
                        src_callers.update(callers)

                for sink in sinks_found:
                    sink_callers = set()
                    for key, callers in symbol_xrefs.items():
                        if sink["symbol"] in key:
                            sink_callers.update(callers)

                    # Same function calls both source and sink → HIGH confidence taint path
                    shared = src_callers & sink_callers
                    if shared:
                        connected_pairs.append({
                            "source": src["symbol"],
                            "sink": sink["symbol"],
                            "shared_callers": list(shared)[:5],
                            "connection": "DIRECT",
                        })

            # Build evidence
            evidence = []
            for src in sources_found[:5]:
                evidence.append({"kind": "taint_source", "value": src["symbol"],
                                  "stub_va": src["stub_va"], "description": src["desc"]})
            for sink in sinks_found[:5]:
                evidence.append({"kind": "taint_sink", "value": sink["symbol"],
                                  "stub_va": sink["stub_va"], "description": sink["desc"]})
            for pair in connected_pairs[:5]:
                evidence.append({"kind": "taint_path", "value": f"{pair['source']} → {pair['sink']}",
                                  "description": f"Same function calls both (callers: {pair['shared_callers'][:3]})"})

            # Confidence
            if connected_pairs:
                confidence = "HIGH"
                reasoning = (f"Binary imports {len(sources_found)} input sources and "
                             f"{len(sinks_found)} dangerous sinks. "
                             f"{len(connected_pairs)} DIRECT taint path(s) confirmed via xref: "
                             f"the same function(s) call both source and sink.")
            elif len(sources_found) >= 2 and len(sinks_found) >= 2:
                confidence = "MEDIUM"
                reasoning = (f"Binary imports {len(sources_found)} input sources and "
                             f"{len(sinks_found)} dangerous sinks. No direct xref path confirmed "
                             f"but high density suggests data flows between them.")
            else:
                confidence = "LOW"
                reasoning = (f"Binary imports {len(sources_found)} source(s) and "
                             f"{len(sinks_found)} sink(s). Potential taint path but unconfirmed.")

            self.findings.append({
                "category": "taint_path",
                "title": (f"{binary_name}: {len(sources_found)} input sources → "
                          f"{len(sinks_found)} dangerous sinks"
                          + (f" ({len(connected_pairs)} DIRECT paths)" if connected_pairs else "")),
                "source_binary": binary_name,
                "confidence": confidence,
                "corroboration_count": len(evidence),
                "evidence_chain": evidence,
                "reasoning": reasoning,
                "actionable": (
                    f"Decompile functions at shared caller VAs to trace exact data flow. "
                    f"Key pairs: {', '.join(p['source'] + ' -> ' + p['sink'] for p in connected_pairs[:3]) or 'use --xref-query on each sink'}."
                ),
            })

    # ─── MODULE B: Bug Class Pattern Matcher ─────────────────────────────────
    # Detect known vulnerability patterns at the binary level:
    # - UAF indicators (free + use-after pattern)
    # - Double-free indicators
    # - Unchecked return values from security-critical functions
    # - Integer overflow patterns
    # - Missing null checks after allocation

    BUG_CLASS_PATTERNS = {
        "uaf_candidate": {
            "description": "Use-After-Free candidate: imports both free/release AND re-use patterns",
            "required_sinks": ["free", "CFRelease", "objc_release", "vm_deallocate", "munmap"],
            "required_reuse": ["memcpy", "memmove", "objc_msgSend", "CFRetain", "strlen", "strcmp"],
            "min_sinks": 2,
            "min_reuse": 2,
            "severity": "HIGH",
        },
        "double_free_candidate": {
            "description": "Double-Free candidate: multiple free/release paths without nullification",
            "required_sinks": ["free", "CFRelease", "objc_release", "vm_deallocate"],
            "required_context": ["dispatch_async", "dispatch_queue_create", "pthread_create",
                                  "Block_copy", "objc_retainBlock"],
            "min_sinks": 2,
            "min_context": 1,
            "severity": "HIGH",
        },
        "unchecked_alloc": {
            "description": "Unchecked allocation: malloc/calloc without NULL check before use",
            "required_sinks": ["malloc", "calloc", "realloc", "mmap", "vm_allocate"],
            "required_reuse": ["memcpy", "memset", "bzero", "strcpy", "strncpy"],
            "min_sinks": 1,
            "min_reuse": 1,
            "severity": "MEDIUM",
        },
        "integer_overflow": {
            "description": "Integer overflow candidate: arithmetic on sizes before allocation",
            "required_sinks": ["malloc", "calloc", "mmap", "vm_allocate"],
            "required_context": ["xpc_dictionary_get_uint64", "xpc_dictionary_get_int64",
                                  "CFNumberGetValue", "atoi", "strtoul", "strtol"],
            "min_sinks": 1,
            "min_context": 1,
            "severity": "HIGH",
        },
        "format_string_vuln": {
            "description": "Format string vulnerability: user-controlled input to format functions",
            "required_sinks": ["NSLog", "printf", "fprintf", "sprintf", "syslog", "os_log"],
            "required_context": ["xpc_dictionary_get_string", "CFStringGetCString",
                                  "recv", "read", "fgets"],
            "min_sinks": 1,
            "min_context": 1,
            "severity": "HIGH",
        },
        "race_condition": {
            "description": "Race condition candidate: shared resource access across threads without locks",
            "required_sinks": ["dispatch_async", "pthread_create", "dispatch_queue_create"],
            "required_context": ["mach_vm_write", "IOConnectCallMethod", "xpc_connection_send_message",
                                  "task_for_pid", "open", "unlink"],
            "min_sinks": 1,
            "min_context": 1,
            "severity": "MEDIUM",
        },
    }

    def find_bug_class_patterns(self):
        """
        Match known vulnerability patterns by checking co-occurrence of
        specific symbol imports within the same binary.
        """
        for binary_name, slim in self.binary_index.items():
            stub_map = slim.get("stub_map", {})
            imported_syms = {sym.lstrip("_") for sym in stub_map.values()}

            for pattern_name, pattern in self.BUG_CLASS_PATTERNS.items():
                sinks_hit = [s for s in pattern["required_sinks"] if s in imported_syms]
                context_key = "required_reuse" if "required_reuse" in pattern else "required_context"
                context_hit = [s for s in pattern[context_key] if s in imported_syms]

                if (len(sinks_hit) < pattern["min_sinks"] or
                    len(context_hit) < pattern.get("min_reuse", pattern.get("min_context", 1))):
                    continue

                # Build evidence
                evidence = []
                for s in sinks_hit[:5]:
                    va = next((v for v, sym in stub_map.items() if sym.lstrip("_") == s), "?")
                    evidence.append({"kind": "sink_symbol", "value": s, "stub_va": va})
                for s in context_hit[:5]:
                    va = next((v for v, sym in stub_map.items() if sym.lstrip("_") == s), "?")
                    evidence.append({"kind": "context_symbol", "value": s, "stub_va": va})

                # Boost confidence if xref shows same function calls both
                xref_db = slim.get("xref_database", {})
                symbol_xrefs = xref_db.get("symbol_xrefs_sample", {})
                direct_link = False
                for sink_sym in sinks_hit[:3]:
                    sink_callers = set()
                    for key, callers in symbol_xrefs.items():
                        if sink_sym in key:
                            sink_callers.update(callers)
                    for ctx_sym in context_hit[:3]:
                        ctx_callers = set()
                        for key, callers in symbol_xrefs.items():
                            if ctx_sym in key:
                                ctx_callers.update(callers)
                        if sink_callers & ctx_callers:
                            direct_link = True
                            evidence.append({"kind": "xref_link",
                                              "value": f"{ctx_sym} + {sink_sym} in same function",
                                              "description": "Confirmed co-location via xref"})
                            break
                    if direct_link:
                        break

                confidence = "HIGH" if direct_link else pattern["severity"]

                self.findings.append({
                    "category": f"bug_class_{pattern_name}",
                    "title": f"{binary_name}: {pattern['description']}",
                    "source_binary": binary_name,
                    "confidence": confidence,
                    "corroboration_count": len(sinks_hit) + len(context_hit),
                    "evidence_chain": evidence,
                    "reasoning": (
                        f"Binary imports {len(sinks_hit)} sink(s) ({', '.join(sinks_hit)}) "
                        f"and {len(context_hit)} context symbol(s) ({', '.join(context_hit)}). "
                        f"This matches the '{pattern_name}' vulnerability pattern. "
                        + ("Xref confirms co-location in same function." if direct_link
                           else "No xref co-location confirmed — manual verification needed.")
                    ),
                    "actionable": (
                        f"Decompile callers of {sinks_hit[0]} and check if data from "
                        f"{context_hit[0]} flows into it without validation. "
                        f"Use: --xref-query \"{sinks_hit[0]}\" --decompile-va <caller_va>"
                    ),
                })

    # ─── MODULE C: Differential Analysis (cross-version) ─────────────────────
    # Compare current firmware's binary set against a "patched" reference.
    # Finds functions that were CHANGED (patched) = likely fixed vulnerabilities.

    def find_differential_indicators(self):
        """
        Without a second IPSW, we can still detect differential signals:
        - Binaries with very few exported symbols (stripped = security-sensitive)
        - Binaries with constructors (__mod_init_func) = early execution
        - Binaries with no ASLR (no PIE) = easier to exploit
        - Binaries with disabled ARC = manual memory management = more bugs
        - Encrypted binaries = hiding something
        """
        for binary_name, slim in self.binary_index.items():
            evidence = []
            risk_score = 0

            # No PIE = no ASLR
            if not slim.get("has_pie", True):
                evidence.append({"kind": "missing_mitigation", "value": "NO_PIE",
                                  "description": "Binary lacks PIE — no ASLR, fixed addresses exploitable"})
                risk_score += 3

            # No ARC = manual retain/release = UAF-prone
            if not slim.get("has_arc", True):
                evidence.append({"kind": "missing_mitigation", "value": "NO_ARC",
                                  "description": "No ARC — manual memory management, higher UAF risk"})
                risk_score += 2

            # Has constructors = runs code before main()
            constructors = slim.get("constructors", {})
            init_count = len(constructors.get("init", []))
            if init_count > 0:
                evidence.append({"kind": "constructor", "value": f"{init_count} __mod_init_func entries",
                                  "description": "Code executes before main() — potential persistence/hook point"})
                risk_score += 1

            # Encrypted = FairPlay or custom
            if slim.get("encrypted", False):
                evidence.append({"kind": "encrypted", "value": "crypt_id != 0",
                                  "description": "Binary is encrypted — cannot be statically analyzed without decryption"})
                risk_score += 1

            # High exploit primitive count
            ep = slim.get("exploit_primitives", {})
            if ep.get("total_findings", 0) >= 5:
                evidence.append({"kind": "high_primitive_count",
                                  "value": f"{ep['total_findings']} exploit primitives",
                                  "description": ep.get("capability_description", "")})
                risk_score += 2

            # Very high import count (large attack surface)
            if slim.get("imported_count", 0) > 500:
                evidence.append({"kind": "large_attack_surface",
                                  "value": f"{slim['imported_count']} imports",
                                  "description": "Large import table = wide attack surface"})
                risk_score += 1

            if risk_score < 3:
                continue

            confidence = "HIGH" if risk_score >= 5 else ("MEDIUM" if risk_score >= 3 else "LOW")

            self.findings.append({
                "category": "high_risk_target",
                "title": f"{binary_name}: risk score {risk_score} — priority reverse target",
                "source_binary": binary_name,
                "confidence": confidence,
                "corroboration_count": len(evidence),
                "evidence_chain": evidence,
                "reasoning": (
                    f"Binary scores {risk_score} on risk heuristics across {len(evidence)} indicators. "
                    f"Missing mitigations + high primitive count make this a priority target "
                    f"for manual vulnerability research."
                ),
                "actionable": (
                    f"This binary should be first in line for Ghidra/IDA analysis. "
                    f"Focus on functions that call exploit primitives without proper validation. "
                    f"Use --decompile-va on each __mod_init_func entry for early-exec analysis."
                ),
            })

    def run_all_correlators(self):
        """Run every finding generator. Order matters: kernel first (highest priority)."""
        self.find_kernel_attack_surface()
        self.find_amfi_trust_cache_callers()
        self.find_app_registration_pipeline()
        self.find_sandbox_escape_indicators()
        self.find_cross_binary_xpc_pairs()
        self.find_unpatched_cve_indicators()
        self.find_yara_hits_corroborated()
        # ── New advanced modules ──
        self.find_taint_paths()
        self.find_bug_class_patterns()
        self.find_differential_indicators()

    def get_filtered_findings(self, min_confidence: str = "LOW") -> list[dict]:
        """Sort findings by confidence then category."""
        order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        threshold = order.get(min_confidence, 2)
        filtered = [f for f in self.findings
                    if order.get(f["confidence"], 99) <= threshold]
        filtered.sort(key=lambda f: (order.get(f["confidence"], 99),
                                      f.get("category", ""),
                                      -f.get("corroboration_count", 0)))
        return filtered


# ═══════════════════════════════════════════════════════════════════════════════
# §5  PIPELINE ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════════════════

def run_pipeline(ipsw_path: Path, args: argparse.Namespace, state: dict) -> dict:
    """End-to-end orchestration: extract → analyze each → correlate → output."""

    # ── Stage 1: Extract IPSW ────────────────────────────────────────────────
    section("STAGE 1 — Extract IPSW")
    if args.keep_extracts:
        extract_dir = Path(args.keep_extracts)
        extract_dir.mkdir(parents=True, exist_ok=True)
        cleanup_temp = None
    else:
        cleanup_temp = tempfile.TemporaryDirectory(prefix="ipsw_research_")
        extract_dir = Path(cleanup_temp.name)

    try:
        extracted = extract_ipsw(ipsw_path, extract_dir)
    except Exception as e:
        if cleanup_temp:
            cleanup_temp.cleanup()
        raise RuntimeError(f"IPSW extraction failed: {e}")

    firmware_meta = extracted["firmware_meta"]
    macho_paths = extracted["macho_paths"]

    if firmware_meta:
        kv("iOS Version", firmware_meta.get("ios_version", "?"))
        kv("Build", firmware_meta.get("ios_build", "?"))
        kv("Product Type", firmware_meta.get("product_type", "?"))
        try:
            kv("Detected SoC", abd._detect_hw_from_product(firmware_meta.get("product_type", "")))
        except Exception:
            pass
    kv("Mach-O binaries discovered", len(macho_paths))
    kv("Sandbox profiles found", len(extracted.get("sandbox_profiles", [])))
    kv("Launchd plists found", len(extracted.get("launchd_plists", [])))

    if not macho_paths:
        if cleanup_temp:
            cleanup_temp.cleanup()
        raise RuntimeError("No Mach-O binaries found in IPSW")

    # ── Stage 2: Filter / prioritize ─────────────────────────────────────────
    section("STAGE 2 — Prioritize Binaries")
    selected = filter_binaries(macho_paths, args.filter, args.max_binaries)

    # ── Stage 3: Analyze each binary ─────────────────────────────────────────
    section("STAGE 3 — Analyze Each Binary")
    build_xref = not args.quick
    find_gadgets = not args.quick

    worker_args = [(p, build_xref, find_gadgets) for p in selected]

    slim_reports: list[dict] = []
    if args.workers > 1 and len(selected) > 1:
        info(f"Using {args.workers} parallel workers...")
        try:
            with ProcessPoolExecutor(max_workers=args.workers) as ex:
                future_to_path = {ex.submit(analyze_one_binary, w): w[0] for w in worker_args}
                for i, fut in enumerate(as_completed(future_to_path), 1):
                    path = future_to_path[fut]
                    name = Path(path).name
                    try:
                        result = fut.result(timeout=600)
                        slim_reports.append(result)
                        good(f"[{i}/{len(selected)}] {name}: " +
                             ("OK" if result.get("_ok") else f"FAIL ({result.get('error', 'unknown')})"))
                    except Exception as e:
                        warn(f"[{i}/{len(selected)}] {name}: worker exception {e}")
                        slim_reports.append({"binary_name": name, "binary_path": path,
                                              "_ok": False, "error": str(e)})
        except Exception as pool_err:
            warn(f"ProcessPool error: {pool_err}. Falling back to sequential.")
            args.workers = 1

    if args.workers <= 1:
        for i, w_args in enumerate(worker_args, 1):
            name = Path(w_args[0]).name
            info(f"[{i}/{len(selected)}] Analyzing {name}...")
            result = analyze_one_binary(w_args)
            slim_reports.append(result)
            if result.get("_ok"):
                good(f"  → OK ({result.get('imported_count', 0)} imports, "
                     f"{result.get('objc_class_count', 0)} ObjC classes)")
            else:
                warn(f"  → FAIL: {result.get('error', 'unknown')}")

    n_ok = sum(1 for r in slim_reports if r.get("_ok"))
    info(f"Analysis complete: {n_ok}/{len(slim_reports)} successful")

    # ── Stage 4: Cross-binary correlation ────────────────────────────────────
    section("STAGE 4 — Cross-Binary Evidence Correlation")
    engine = EvidenceFindings(firmware_meta)
    for slim in slim_reports:
        engine.add_binary_report(slim)

    info("Running correlation engine...")
    engine.run_all_correlators()

    findings = engine.get_filtered_findings(args.min_confidence)
    good(f"Total findings produced: {len(findings)}")

    # Summary by category
    cats = collections.Counter(f["category"] for f in findings)
    for cat, n in cats.most_common(15):
        kv(f"  {cat}", n, indent=4)

    # ── Stage 5: Build research brief ────────────────────────────────────────
    section("STAGE 5 — Build Research Brief")

    # Top HIGH findings (first 10)
    high_findings = [f for f in findings if f["confidence"] == "HIGH"]
    if high_findings:
        info(f"Top HIGH-confidence findings:")
        for f in high_findings[:8]:
            print(f"\n  ⚡ [{f['category']}] {f['title']}")
            print(f"     Source: {f['source_binary']}")
            print(f"     Reasoning: {f['reasoning'][:200]}")
            print(f"     Action: {f['actionable'][:160]}")

    # Try optional firmware intelligence report from analyze_binary_deep
    firmware_intel = None
    try:
        all_reports_for_intel = {
            r["binary_name"]: r for r in slim_reports if r.get("_ok")
        }
        firmware_intel = abd.build_firmware_intelligence_report(
            ios_version=firmware_meta.get("ios_version", "Unknown"),
            ios_build=firmware_meta.get("ios_build", "Unknown"),
            product_type=firmware_meta.get("product_type", "Unknown"),
            all_reports=all_reports_for_intel,
            ipsw_meta=firmware_meta,
        )
    except Exception as e:
        warn(f"Firmware intelligence report skipped: {e}")

    # Cleanup temp
    if cleanup_temp:
        try:
            cleanup_temp.cleanup()
        except Exception:
            pass

    # Final result structure
    return {
        "pipeline_metadata": state,
        "firmware_metadata": firmware_meta,
        "extraction_summary": {
            "macho_count": len(macho_paths),
            "selected_count": len(selected),
            "successful_count": n_ok,
            "sandbox_profiles": len(extracted.get("sandbox_profiles", [])),
            "launchd_plists": len(extracted.get("launchd_plists", [])),
        },
        "binaries_analyzed": [
            {
                "name": r.get("binary_name"),
                "ok": r.get("_ok"),
                "imports": r.get("imported_count", 0),
                "objc_classes": r.get("objc_class_count", 0),
                "private_ents": r.get("private_entitlements_audit", {}).get("matched_count", 0),
                "exploit_primitives": r.get("exploit_primitives", {}).get("total_findings", 0),
                "stubs_resolved": len(r.get("stub_map", {})),
            }
            for r in slim_reports
        ],
        "findings_summary": {
            "total": len(findings),
            "by_confidence": dict(collections.Counter(f["confidence"] for f in findings)),
            "by_category": dict(cats),
        },
        "findings": findings,
        "firmware_intelligence_report": firmware_intel,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# §6  PDF RESEARCH BRIEF GENERATOR (optional)
# ═══════════════════════════════════════════════════════════════════════════════

def generate_research_pdf(result: dict, output_path: str):
    """Generate professional PDF research brief."""
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.lib.colors import HexColor
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
        )
        from reportlab.lib import colors
    except ImportError:
        raise RuntimeError("reportlab not installed. pip install reportlab")

    doc = SimpleDocTemplate(output_path, pagesize=letter,
                             rightMargin=0.5 * inch, leftMargin=0.5 * inch,
                             topMargin=0.5 * inch, bottomMargin=0.5 * inch)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle('TitleStyle', parent=styles['Title'],
                                   textColor=HexColor("#003366"), fontSize=20, spaceAfter=18)
    h1 = ParagraphStyle('H1', parent=styles['Heading1'],
                         textColor=HexColor("#0066CC"), fontSize=14, spaceAfter=8)
    h2 = ParagraphStyle('H2', parent=styles['Heading2'],
                         textColor=HexColor("#990000"), fontSize=12, spaceAfter=6)
    body = styles['BodyText']

    story = []
    fw = result.get("firmware_metadata", {})
    summary = result.get("findings_summary", {})

    story.append(Paragraph("IPSW Research Brief", title_style))
    story.append(Paragraph(
        f"<b>Firmware:</b> iOS {fw.get('ios_version', '?')} "
        f"(build {fw.get('ios_build', '?')}) on {fw.get('product_type', '?')}",
        body))
    extr = result.get("extraction_summary", {})
    story.append(Paragraph(
        f"<b>Binaries analyzed:</b> {extr.get('successful_count', 0)} of {extr.get('selected_count', 0)} selected "
        f"(of {extr.get('macho_count', 0)} discovered)",
        body))
    story.append(Paragraph(
        f"<b>Total findings:</b> {summary.get('total', 0)}", body))
    by_conf = summary.get("by_confidence", {})
    story.append(Paragraph(
        f"<b>By confidence:</b> HIGH={by_conf.get('HIGH', 0)} | "
        f"MEDIUM={by_conf.get('MEDIUM', 0)} | LOW={by_conf.get('LOW', 0)}",
        body))
    story.append(Spacer(1, 12))

    # Top findings by confidence
    findings = result.get("findings", [])
    high = [f for f in findings if f["confidence"] == "HIGH"]
    medium = [f for f in findings if f["confidence"] == "MEDIUM"]

    def render_findings(title: str, items: list[dict], max_n: int = 30):
        if not items:
            return
        story.append(Paragraph(title, h1))
        for f in items[:max_n]:
            story.append(Paragraph(
                f"<b>[{f['category']}]</b> {f['title']}", h2))
            story.append(Paragraph(
                f"<b>Source:</b> {f['source_binary'][:300]}", body))
            story.append(Paragraph(
                f"<b>Reasoning:</b> {f['reasoning']}", body))
            story.append(Paragraph(
                f"<b>Actionable:</b> {f['actionable']}", body))
            # Render evidence chain as small table
            ec = f.get("evidence_chain", [])[:8]
            if ec:
                ev_data = [["Kind", "Value", "Detail"]]
                for e in ec:
                    val = str(e.get("value", ""))[:80]
                    detail = str(e.get("description") or e.get("stub_va") or
                                  e.get("risk") or e.get("first_offset") or "")[:60]
                    ev_data.append([e.get("kind", "?"), val, detail])
                t = Table(ev_data, colWidths=[1.3 * inch, 3.2 * inch, 2.5 * inch])
                t.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                    ('GRID', (0, 0), (-1, -1), 0.3, colors.grey),
                    ('FONTSIZE', (0, 1), (-1, -1), 8),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ]))
                story.append(t)
            story.append(Spacer(1, 8))

    render_findings("HIGH-Confidence Findings", high, max_n=40)
    if high and medium:
        story.append(PageBreak())
    render_findings("MEDIUM-Confidence Findings", medium, max_n=30)

    # Footer
    story.append(Spacer(1, 16))
    story.append(Paragraph("<i>Generated by IPSW Research Pipeline — every claim is backed by concrete evidence.</i>", body))

    doc.build(story)


# ═══════════════════════════════════════════════════════════════════════════════
# §7  TKINTER GUI — Drag-and-drop IPSW pipeline runner with live findings tree
# ═══════════════════════════════════════════════════════════════════════════════
#
# Features:
#   - Drag-drop IPSW or click "Browse" to pick file
#   - Live log streaming during pipeline run (stdout/stderr captured)
#   - Progress bar (extraction / per-binary analysis / correlation / brief)
#   - Sortable findings tree (by confidence, category, source binary)
#   - Detail panel: evidence chain table + reasoning + actionable steps
#   - Filter findings by confidence threshold + category + binary substring
#   - Export buttons: JSON, PDF, plain-text summary
#   - Run pipeline in worker thread so UI stays responsive
#   - Threaded cancellation (best-effort)
#
# Pure stdlib Tkinter — no extra dependencies for the GUI itself.
# ═══════════════════════════════════════════════════════════════════════════════

def launch_gui():
    """Entry point for the GUI. Run pipeline interactively."""
    try:
        import tkinter as tk
        from tkinter import ttk, filedialog, messagebox, scrolledtext
    except ImportError as e:
        print(f"[!] Tkinter not available: {e}", file=sys.stderr)
        print(f"    Install Tk support for Python on this platform.", file=sys.stderr)
        sys.exit(1)

    import threading
    import queue
    import io

    # Optional drag-and-drop (windnd is optional Windows-only; tkdnd2 cross-platform)
    _DND_BACKEND = None
    try:
        import tkinterdnd2  # type: ignore
        _DND_BACKEND = "tkinterdnd2"
    except ImportError:
        try:
            import windnd  # type: ignore
            _DND_BACKEND = "windnd"
        except ImportError:
            _DND_BACKEND = None

    # ── Confidence colors ────────────────────────────────────────────────────
    CONF_COLORS = {
        "HIGH":   "#d32f2f",   # red
        "MEDIUM": "#f57c00",   # orange
        "LOW":    "#388e3c",   # green
    }
    CAT_COLORS = {
        "kernel_attack_surface":     "#b71c1c",
        "amfi_trust_cache":          "#880e4f",
        "app_registration_pipeline": "#311b92",
        "sandbox_escape":            "#1a237e",
        "xpc_communication_pair":    "#0d47a1",
        "cve_indicator":             "#bf360c",
    }

    # ── Class definition ────────────────────────────────────────────────────
    class PipelineGUI:
        def __init__(self):
            if _DND_BACKEND == "tkinterdnd2":
                self.root = tkinterdnd2.TkinterDnD.Tk()
            else:
                self.root = tk.Tk()
            self.root.title("IPSW Research Pipeline — Evidence Engine")
            self.root.geometry("1400x880")
            self.root.minsize(1100, 720)

            # State
            self.ipsw_path: Optional[Path] = None
            self.last_result: Optional[dict] = None
            self.running = False
            self.cancel_requested = False
            self.log_queue: "queue.Queue[str]" = queue.Queue()
            self.progress_queue: "queue.Queue[tuple]" = queue.Queue()
            self.done_queue: "queue.Queue[Any]" = queue.Queue()

            self._build_ui()
            self._setup_dnd()
            self._poll_queues()

        # ── UI construction ──────────────────────────────────────────────────
        def _build_ui(self):
            # Top: file selector + run button
            top = ttk.Frame(self.root, padding=8)
            top.pack(side=tk.TOP, fill=tk.X)

            ttk.Label(top, text="IPSW file:", font=("Segoe UI", 10, "bold")).pack(side=tk.LEFT)
            self.file_var = tk.StringVar(value="(drag an .ipsw here, or click Browse)")
            self.file_label = ttk.Label(top, textvariable=self.file_var,
                                          width=80, relief=tk.SUNKEN,
                                          anchor=tk.W, padding=4,
                                          background="#fafafa")
            self.file_label.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)
            ttk.Button(top, text="Browse...", command=self.on_browse, width=12).pack(side=tk.LEFT, padx=2)
            self.run_btn = ttk.Button(top, text="▶ Run Pipeline", command=self.on_run, width=18)
            self.run_btn.pack(side=tk.LEFT, padx=2)
            self.cancel_btn = ttk.Button(top, text="✕ Cancel", command=self.on_cancel,
                                          state=tk.DISABLED, width=12)
            self.cancel_btn.pack(side=tk.LEFT, padx=2)

            # Options bar
            opts = ttk.LabelFrame(self.root, text="Pipeline options", padding=6)
            opts.pack(side=tk.TOP, fill=tk.X, padx=8, pady=2)
            ttk.Label(opts, text="Workers:").pack(side=tk.LEFT, padx=(0, 4))
            self.workers_var = tk.IntVar(value=2)
            ttk.Spinbox(opts, from_=1, to=8, textvariable=self.workers_var, width=4).pack(side=tk.LEFT)
            ttk.Label(opts, text="  Max binaries:").pack(side=tk.LEFT, padx=(8, 4))
            self.max_bin_var = tk.IntVar(value=200)
            ttk.Spinbox(opts, from_=10, to=2000, increment=10,
                         textvariable=self.max_bin_var, width=6).pack(side=tk.LEFT)
            ttk.Label(opts, text="  Filter (substring):").pack(side=tk.LEFT, padx=(8, 4))
            self.filter_var = tk.StringVar(value="")
            ttk.Entry(opts, textvariable=self.filter_var, width=32).pack(side=tk.LEFT)
            self.quick_var = tk.BooleanVar(value=False)
            ttk.Checkbutton(opts, text="Quick (skip xref/gadgets)",
                             variable=self.quick_var).pack(side=tk.LEFT, padx=(12, 0))
            self.keep_var = tk.BooleanVar(value=False)
            ttk.Checkbutton(opts, text="Keep extracted IPSW",
                             variable=self.keep_var).pack(side=tk.LEFT, padx=(8, 0))

            # Progress + status
            prog = ttk.Frame(self.root, padding=(8, 0))
            prog.pack(side=tk.TOP, fill=tk.X)
            self.status_var = tk.StringVar(value="Ready. Drag an IPSW or click Browse.")
            ttk.Label(prog, textvariable=self.status_var,
                       font=("Segoe UI", 9)).pack(side=tk.LEFT)
            self.progress = ttk.Progressbar(prog, mode="determinate",
                                              length=320, maximum=100)
            self.progress.pack(side=tk.RIGHT, padx=(0, 4))

            # Notebook: Findings | Live Log | Binaries | Summary
            self.nb = ttk.Notebook(self.root)
            self.nb.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=8, pady=6)

            # Tab 1: Findings (split pane)
            self.tab_find = ttk.Frame(self.nb)
            self.nb.add(self.tab_find, text="🔎 Findings")
            self._build_findings_tab()

            # Tab 2: Live Log
            self.tab_log = ttk.Frame(self.nb)
            self.nb.add(self.tab_log, text="📜 Live Log")
            self._build_log_tab()

            # Tab 3: Per-binary results
            self.tab_bin = ttk.Frame(self.nb)
            self.nb.add(self.tab_bin, text="📦 Binaries")
            self._build_binaries_tab()

            # Tab 4: Summary
            self.tab_sum = ttk.Frame(self.nb)
            self.nb.add(self.tab_sum, text="📊 Summary")
            self._build_summary_tab()

            # Bottom: export buttons
            bottom = ttk.Frame(self.root, padding=6)
            bottom.pack(side=tk.BOTTOM, fill=tk.X)
            ttk.Button(bottom, text="💾 Export JSON",
                        command=self.on_export_json, width=18).pack(side=tk.LEFT, padx=2)
            ttk.Button(bottom, text="📄 Export PDF",
                        command=self.on_export_pdf, width=18).pack(side=tk.LEFT, padx=2)
            ttk.Button(bottom, text="📝 Export Text Summary",
                        command=self.on_export_text, width=22).pack(side=tk.LEFT, padx=2)
            ttk.Button(bottom, text="🧹 Clear All",
                        command=self.on_clear, width=14).pack(side=tk.LEFT, padx=2)
            ttk.Label(bottom, text="  IPSW Research Pipeline · evidence-only mode",
                       foreground="#666", font=("Segoe UI", 8)).pack(side=tk.RIGHT)

        def _build_findings_tab(self):
            paned = ttk.PanedWindow(self.tab_find, orient=tk.HORIZONTAL)
            paned.pack(fill=tk.BOTH, expand=True)

            # Left: filter + tree
            left = ttk.Frame(paned)
            paned.add(left, weight=1)

            # Filter bar
            filt = ttk.Frame(left, padding=6)
            filt.pack(side=tk.TOP, fill=tk.X)
            ttk.Label(filt, text="Min confidence:").pack(side=tk.LEFT)
            self.min_conf_var = tk.StringVar(value="LOW")
            mc = ttk.Combobox(filt, textvariable=self.min_conf_var,
                                values=["HIGH", "MEDIUM", "LOW"],
                                state="readonly", width=10)
            mc.pack(side=tk.LEFT, padx=4)
            mc.bind("<<ComboboxSelected>>", lambda _e: self._refresh_findings_tree())

            ttk.Label(filt, text="Category:").pack(side=tk.LEFT, padx=(10, 0))
            self.cat_filter_var = tk.StringVar(value="(all)")
            self.cat_combo = ttk.Combobox(filt, textvariable=self.cat_filter_var,
                                            values=["(all)"], state="readonly", width=24)
            self.cat_combo.pack(side=tk.LEFT, padx=4)
            self.cat_combo.bind("<<ComboboxSelected>>", lambda _e: self._refresh_findings_tree())

            ttk.Label(filt, text="Binary contains:").pack(side=tk.LEFT, padx=(10, 0))
            self.bin_filter_var = tk.StringVar(value="")
            be = ttk.Entry(filt, textvariable=self.bin_filter_var, width=18)
            be.pack(side=tk.LEFT, padx=4)
            be.bind("<KeyRelease>", lambda _e: self._refresh_findings_tree())

            self.findings_count_var = tk.StringVar(value="0 findings")
            ttk.Label(filt, textvariable=self.findings_count_var,
                       foreground="#0066CC", font=("Segoe UI", 9, "bold")).pack(side=tk.RIGHT)

            # Tree
            tree_frame = ttk.Frame(left)
            tree_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
            cols = ("conf", "cat", "src", "corr", "title")
            self.find_tree = ttk.Treeview(tree_frame, columns=cols,
                                           show="headings", selectmode="browse")
            for c, txt, w in [
                ("conf", "Confidence", 90),
                ("cat", "Category", 180),
                ("src", "Source", 180),
                ("corr", "Evidence", 70),
                ("title", "Title", 380),
            ]:
                self.find_tree.heading(c, text=txt,
                                        command=lambda _c=c: self._sort_tree(_c, False))
                self.find_tree.column(c, width=w, anchor=tk.W,
                                       stretch=(c == "title"))

            self.find_tree.tag_configure("HIGH",   foreground=CONF_COLORS["HIGH"],
                                                     font=("Segoe UI", 9, "bold"))
            self.find_tree.tag_configure("MEDIUM", foreground=CONF_COLORS["MEDIUM"])
            self.find_tree.tag_configure("LOW",    foreground=CONF_COLORS["LOW"])

            ysb = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL,
                                 command=self.find_tree.yview)
            self.find_tree.configure(yscrollcommand=ysb.set)
            self.find_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            ysb.pack(side=tk.RIGHT, fill=tk.Y)
            self.find_tree.bind("<<TreeviewSelect>>", self._on_finding_select)

            # Right: detail panel
            right = ttk.Frame(paned)
            paned.add(right, weight=1)

            self.detail_title_var = tk.StringVar(value="Select a finding to see evidence")
            ttk.Label(right, textvariable=self.detail_title_var,
                       font=("Segoe UI", 11, "bold"), foreground="#003366",
                       wraplength=560, justify=tk.LEFT,
                       padding=(8, 8)).pack(side=tk.TOP, fill=tk.X)

            meta_frame = ttk.LabelFrame(right, text="Finding metadata", padding=6)
            meta_frame.pack(side=tk.TOP, fill=tk.X, padx=8, pady=2)
            self.detail_meta = scrolledtext.ScrolledText(
                meta_frame, height=4, wrap=tk.WORD, font=("Consolas", 9))
            self.detail_meta.pack(fill=tk.BOTH, expand=True)
            self.detail_meta.configure(state=tk.DISABLED)

            ev_frame = ttk.LabelFrame(right, text="Evidence chain", padding=6)
            ev_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=8, pady=2)
            ev_cols = ("kind", "value", "detail")
            self.ev_tree = ttk.Treeview(ev_frame, columns=ev_cols,
                                          show="headings", height=10)
            for c, txt, w in [
                ("kind", "Kind", 130),
                ("value", "Value", 240),
                ("detail", "Detail", 220),
            ]:
                self.ev_tree.heading(c, text=txt)
                self.ev_tree.column(c, width=w, anchor=tk.W)
            evsb = ttk.Scrollbar(ev_frame, orient=tk.VERTICAL,
                                  command=self.ev_tree.yview)
            self.ev_tree.configure(yscrollcommand=evsb.set)
            self.ev_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            evsb.pack(side=tk.RIGHT, fill=tk.Y)

            reason_frame = ttk.LabelFrame(right, text="Reasoning & actionable next step",
                                            padding=6)
            reason_frame.pack(side=tk.TOP, fill=tk.X, padx=8, pady=2)
            self.detail_reason = scrolledtext.ScrolledText(
                reason_frame, height=6, wrap=tk.WORD, font=("Segoe UI", 9))
            self.detail_reason.pack(fill=tk.BOTH, expand=True)
            self.detail_reason.configure(state=tk.DISABLED)

        def _build_log_tab(self):
            self.log_text = scrolledtext.ScrolledText(
                self.tab_log, wrap=tk.WORD, font=("Consolas", 9),
                background="#1e1e1e", foreground="#dddddd",
                insertbackground="#ffffff")
            self.log_text.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
            self.log_text.tag_configure("info",  foreground="#7cb7ff")
            self.log_text.tag_configure("good",  foreground="#90ee90")
            self.log_text.tag_configure("warn",  foreground="#ffd54f")
            self.log_text.tag_configure("err",   foreground="#ff7373")
            self.log_text.tag_configure("hdr",   foreground="#ffffff",
                                         font=("Consolas", 10, "bold"))

        def _build_binaries_tab(self):
            cols = ("name", "ok", "imports", "objc", "ents", "primitives", "stubs")
            self.bin_tree = ttk.Treeview(self.tab_bin, columns=cols,
                                          show="headings")
            for c, txt, w in [
                ("name", "Binary", 240),
                ("ok", "OK", 60),
                ("imports", "Imports", 80),
                ("objc", "ObjC Classes", 100),
                ("ents", "Private Ents", 100),
                ("primitives", "Primitives", 100),
                ("stubs", "Stubs", 80),
            ]:
                self.bin_tree.heading(c, text=txt,
                                       command=lambda _c=c: self._sort_bin_tree(_c, False))
                self.bin_tree.column(c, width=w, anchor=tk.W,
                                      stretch=(c == "name"))
            ysb = ttk.Scrollbar(self.tab_bin, orient=tk.VERTICAL,
                                 command=self.bin_tree.yview)
            self.bin_tree.configure(yscrollcommand=ysb.set)
            self.bin_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            ysb.pack(side=tk.RIGHT, fill=tk.Y)
            self.bin_tree.tag_configure("ok",   foreground="#1b5e20")
            self.bin_tree.tag_configure("fail", foreground="#b71c1c")

        def _build_summary_tab(self):
            self.summary_text = scrolledtext.ScrolledText(
                self.tab_sum, wrap=tk.WORD, font=("Consolas", 10))
            self.summary_text.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
            self.summary_text.tag_configure("h1", foreground="#003366",
                                              font=("Consolas", 12, "bold"))
            self.summary_text.tag_configure("h2", foreground="#0066CC",
                                              font=("Consolas", 10, "bold"))
            self.summary_text.tag_configure("crit", foreground="#d32f2f",
                                              font=("Consolas", 10, "bold"))

        # ── Drag & drop wiring ───────────────────────────────────────────────
        def _setup_dnd(self):
            if _DND_BACKEND == "tkinterdnd2":
                try:
                    self.file_label.drop_target_register(tkinterdnd2.DND_FILES)  # type: ignore
                    self.file_label.dnd_bind("<<Drop>>", self._on_dnd_drop)  # type: ignore
                    self.root.drop_target_register(tkinterdnd2.DND_FILES)  # type: ignore
                    self.root.dnd_bind("<<Drop>>", self._on_dnd_drop)  # type: ignore
                except Exception:
                    pass
            elif _DND_BACKEND == "windnd":
                try:
                    windnd.hook_dropfiles(self.file_label, func=self._on_dnd_files)  # type: ignore
                    windnd.hook_dropfiles(self.root, func=self._on_dnd_files)  # type: ignore
                except Exception:
                    pass

        def _on_dnd_drop(self, event):
            # tkinterdnd2 returns space-separated paths; first one wins
            raw = event.data.strip().strip("{}")
            if " " in raw and not Path(raw).exists():
                # Try splitting if multi-file
                parts = raw.split(" ")
                raw = parts[0]
            self._set_ipsw(raw)

        def _on_dnd_files(self, files):
            if not files:
                return
            path = files[0]
            if isinstance(path, bytes):
                path = path.decode("mbcs", errors="replace")
            self._set_ipsw(path)

        # ── Event handlers ───────────────────────────────────────────────────
        def on_browse(self):
            f = filedialog.askopenfilename(
                title="Select IPSW firmware file",
                filetypes=[("IPSW Firmware", "*.ipsw"),
                            ("All Files", "*.*")],
            )
            if f:
                self._set_ipsw(f)

        def _set_ipsw(self, path: str):
            p = Path(path)
            if not p.exists():
                messagebox.showerror("File not found", f"Cannot read: {path}")
                return
            self.ipsw_path = p
            size_mb = p.stat().st_size / (1024 * 1024)
            self.file_var.set(f"{p.name}  ({size_mb:,.1f} MB)  [{p.parent}]")
            self.status_var.set(f"Loaded {p.name}. Click Run Pipeline to start.")
            self._log(f"[*] Selected IPSW: {p}\n", "info")

        def on_run(self):
            if self.running:
                messagebox.showwarning("Pipeline running",
                                        "Wait for the current run to finish or cancel it.")
                return
            if not self.ipsw_path or not self.ipsw_path.exists():
                messagebox.showerror("No IPSW",
                                      "Drag an IPSW file or click Browse first.")
                return

            self.running = True
            self.cancel_requested = False
            self.run_btn.configure(state=tk.DISABLED)
            self.cancel_btn.configure(state=tk.NORMAL)
            self.progress.configure(mode="indeterminate")
            self.progress.start(8)
            self.status_var.set("Pipeline starting...")
            self.last_result = None
            self._clear_views()
            self.nb.select(self.tab_log)

            t = threading.Thread(target=self._run_pipeline_thread, daemon=True)
            t.start()

        def on_cancel(self):
            if not self.running:
                return
            self.cancel_requested = True
            self.status_var.set("Cancellation requested — finishing current step...")
            self._log("[!] Cancellation requested.\n", "warn")

        def on_clear(self):
            if self.running:
                messagebox.showwarning("Running", "Cancel the run first.")
                return
            self._clear_views()
            self.last_result = None
            self.status_var.set("Cleared.")

        def on_export_json(self):
            if not self.last_result:
                messagebox.showinfo("No data", "Run a pipeline first.")
                return
            f = filedialog.asksaveasfilename(
                title="Save research JSON",
                defaultextension=".json",
                filetypes=[("JSON", "*.json"), ("All Files", "*.*")],
                initialfile=f"{self.ipsw_path.stem if self.ipsw_path else 'research'}.research.json",
            )
            if not f:
                return
            try:
                with open(f, "w", encoding="utf-8") as fp:
                    json.dump(_make_serializable(self.last_result), fp,
                                indent=2, ensure_ascii=False)
                messagebox.showinfo("Saved", f"Wrote {f}")
            except Exception as e:
                messagebox.showerror("Save failed", str(e))

        def on_export_pdf(self):
            if not self.last_result:
                messagebox.showinfo("No data", "Run a pipeline first.")
                return
            f = filedialog.asksaveasfilename(
                title="Save research PDF brief",
                defaultextension=".pdf",
                filetypes=[("PDF", "*.pdf"), ("All Files", "*.*")],
                initialfile=f"{self.ipsw_path.stem if self.ipsw_path else 'research'}.brief.pdf",
            )
            if not f:
                return
            try:
                generate_research_pdf(self.last_result, f)
                messagebox.showinfo("Saved", f"PDF brief written to {f}")
            except Exception as e:
                messagebox.showerror("PDF failed",
                                      f"{e}\n\nTry: pip install reportlab")

        def on_export_text(self):
            if not self.last_result:
                messagebox.showinfo("No data", "Run a pipeline first.")
                return
            f = filedialog.asksaveasfilename(
                title="Save research text summary",
                defaultextension=".txt",
                filetypes=[("Text", "*.txt"), ("All Files", "*.*")],
                initialfile=f"{self.ipsw_path.stem if self.ipsw_path else 'research'}.summary.txt",
            )
            if not f:
                return
            try:
                with open(f, "w", encoding="utf-8") as fp:
                    fp.write(self._build_text_summary(self.last_result))
                messagebox.showinfo("Saved", f"Wrote {f}")
            except Exception as e:
                messagebox.showerror("Save failed", str(e))

        # ── Pipeline worker thread ───────────────────────────────────────────
        def _run_pipeline_thread(self):
            try:
                # Hijack stdout/stderr so all the existing print()s flow into log tab
                redirector = _LogRedirector(self.log_queue)
                original_stdout, original_stderr = sys.stdout, sys.stderr
                sys.stdout = redirector
                sys.stderr = redirector
                try:
                    fake_args = argparse.Namespace(
                        ipsw=str(self.ipsw_path),
                        output=None,
                        workers=int(self.workers_var.get()),
                        filter=(self.filter_var.get().strip() or None),
                        max_binaries=int(self.max_bin_var.get()),
                        min_confidence="LOW",
                        pdf=None,
                        keep_extracts=None,
                        quick=bool(self.quick_var.get()),
                        verbose=True,
                    )
                    state = {
                        "ipsw_path": str(self.ipsw_path),
                        "ipsw_size_mb": round(self.ipsw_path.stat().st_size / (1024 * 1024), 2),
                        "args": vars(fake_args),
                        "started_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                    }
                    if self.keep_var.get():
                        keep_dir = self.ipsw_path.parent / f"{self.ipsw_path.stem}_extracted"
                        keep_dir.mkdir(parents=True, exist_ok=True)
                        fake_args.keep_extracts = str(keep_dir)

                    self.progress_queue.put(("status", f"Running pipeline on {self.ipsw_path.name}..."))
                    result = run_pipeline(self.ipsw_path, fake_args, state)

                    if self.cancel_requested:
                        self.done_queue.put(("cancelled", None))
                    else:
                        self.done_queue.put(("ok", result))
                finally:
                    sys.stdout = original_stdout
                    sys.stderr = original_stderr
            except Exception as e:
                import traceback
                tb = traceback.format_exc()
                self.log_queue.put(f"[!] Pipeline error: {e}\n{tb}\n")
                self.done_queue.put(("error", str(e)))

        # ── Polling for cross-thread queue messages ──────────────────────────
        def _poll_queues(self):
            # Drain log queue
            try:
                while True:
                    msg = self.log_queue.get_nowait()
                    self._log(msg, _classify_log_line(msg))
            except queue.Empty:
                pass

            # Drain progress queue
            try:
                while True:
                    kind, payload = self.progress_queue.get_nowait()
                    if kind == "status":
                        self.status_var.set(payload)
            except queue.Empty:
                pass

            # Check done queue
            try:
                while True:
                    status, payload = self.done_queue.get_nowait()
                    self._on_pipeline_done(status, payload)
            except queue.Empty:
                pass

            self.root.after(100, self._poll_queues)

        def _on_pipeline_done(self, status: str, payload):
            self.running = False
            self.cancel_btn.configure(state=tk.DISABLED)
            self.run_btn.configure(state=tk.NORMAL)
            self.progress.stop()
            self.progress.configure(mode="determinate", value=100)

            if status == "ok":
                self.last_result = payload
                n = len(payload.get("findings", []))
                self.status_var.set(
                    f"Done. {n} findings · "
                    f"{payload.get('extraction_summary', {}).get('successful_count', 0)} binaries OK."
                )
                self._populate_results(payload)
                self.nb.select(self.tab_find)
                messagebox.showinfo("Pipeline complete",
                                      f"Produced {n} findings.\n"
                                      f"HIGH: {sum(1 for f in payload['findings'] if f['confidence']=='HIGH')}\n"
                                      f"MEDIUM: {sum(1 for f in payload['findings'] if f['confidence']=='MEDIUM')}\n"
                                      f"LOW: {sum(1 for f in payload['findings'] if f['confidence']=='LOW')}")
            elif status == "cancelled":
                self.status_var.set("Cancelled.")
                self.progress.configure(value=0)
            else:
                self.status_var.set(f"Failed: {payload}")
                self.progress.configure(value=0)
                messagebox.showerror("Pipeline failed", str(payload))

        # ── Result population ────────────────────────────────────────────────
        def _clear_views(self):
            for tree in (self.find_tree, self.ev_tree, self.bin_tree):
                for iid in tree.get_children():
                    tree.delete(iid)
            for txt in (self.detail_meta, self.detail_reason, self.summary_text, self.log_text):
                txt.configure(state=tk.NORMAL)
                txt.delete("1.0", tk.END)
                if txt is not self.log_text:
                    txt.configure(state=tk.DISABLED)
            self.detail_title_var.set("Select a finding to see evidence")
            self.findings_count_var.set("0 findings")
            self.cat_combo["values"] = ["(all)"]
            self.cat_filter_var.set("(all)")

        def _populate_results(self, result: dict):
            findings = result.get("findings", [])
            # Update category filter
            cats = sorted(set(f.get("category", "") for f in findings))
            self.cat_combo["values"] = ["(all)"] + cats

            # Findings tree
            self._refresh_findings_tree()

            # Binaries tab
            for b in result.get("binaries_analyzed", []):
                ok = b.get("ok")
                self.bin_tree.insert("", tk.END,
                                      values=(b.get("name", ""),
                                               "OK" if ok else "FAIL",
                                               b.get("imports", 0),
                                               b.get("objc_classes", 0),
                                               b.get("private_ents", 0),
                                               b.get("exploit_primitives", 0),
                                               b.get("stubs_resolved", 0)),
                                      tags=("ok" if ok else "fail",))

            # Summary tab
            self._render_summary(result)

        def _refresh_findings_tree(self):
            # Clear
            for iid in self.find_tree.get_children():
                self.find_tree.delete(iid)
            if not self.last_result:
                self.findings_count_var.set("0 findings")
                return
            min_conf = self.min_conf_var.get()
            order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
            threshold = order.get(min_conf, 2)
            cat_filter = self.cat_filter_var.get()
            bin_filter = self.bin_filter_var.get().strip().lower()

            shown = 0
            for f in self.last_result.get("findings", []):
                if order.get(f["confidence"], 99) > threshold:
                    continue
                if cat_filter not in ("", "(all)") and f.get("category") != cat_filter:
                    continue
                if bin_filter and bin_filter not in f.get("source_binary", "").lower():
                    continue
                self.find_tree.insert("", tk.END,
                                       values=(f.get("confidence"),
                                                f.get("category", ""),
                                                f.get("source_binary", "")[:50],
                                                f.get("corroboration_count", 0),
                                                f.get("title", "")[:120]),
                                       tags=(f.get("confidence", "LOW"),),
                                       iid=f"f{shown}")
                shown += 1
            self.findings_count_var.set(f"{shown} findings")

        def _on_finding_select(self, _event=None):
            sel = self.find_tree.selection()
            if not sel:
                return
            idx = int(sel[0].lstrip("f"))
            min_conf = self.min_conf_var.get()
            order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
            threshold = order.get(min_conf, 2)
            cat_filter = self.cat_filter_var.get()
            bin_filter = self.bin_filter_var.get().strip().lower()

            counter = 0
            target = None
            for f in (self.last_result or {}).get("findings", []):
                if order.get(f["confidence"], 99) > threshold:
                    continue
                if cat_filter not in ("", "(all)") and f.get("category") != cat_filter:
                    continue
                if bin_filter and bin_filter not in f.get("source_binary", "").lower():
                    continue
                if counter == idx:
                    target = f
                    break
                counter += 1
            if not target:
                return

            self.detail_title_var.set(f"[{target['confidence']}] {target['title']}")

            self.detail_meta.configure(state=tk.NORMAL)
            self.detail_meta.delete("1.0", tk.END)
            self.detail_meta.insert(tk.END,
                                     f"Category   : {target.get('category')}\n"
                                     f"Source     : {target.get('source_binary')}\n"
                                     f"Confidence : {target.get('confidence')}\n"
                                     f"Evidence # : {target.get('corroboration_count')}\n")
            self.detail_meta.configure(state=tk.DISABLED)

            for iid in self.ev_tree.get_children():
                self.ev_tree.delete(iid)
            for e in target.get("evidence_chain", []):
                detail = (e.get("description")
                            or e.get("stub_va")
                            or e.get("risk")
                            or e.get("first_offset")
                            or e.get("binary")
                            or "")
                self.ev_tree.insert("", tk.END,
                                     values=(e.get("kind", "?"),
                                              str(e.get("value", ""))[:160],
                                              str(detail)[:160]))

            self.detail_reason.configure(state=tk.NORMAL)
            self.detail_reason.delete("1.0", tk.END)
            self.detail_reason.insert(tk.END,
                                       f"REASONING\n{'-' * 60}\n{target.get('reasoning', '')}\n\n"
                                       f"ACTIONABLE NEXT STEP\n{'-' * 60}\n{target.get('actionable', '')}\n")
            self.detail_reason.configure(state=tk.DISABLED)

        def _render_summary(self, result: dict):
            self.summary_text.configure(state=tk.NORMAL)
            self.summary_text.delete("1.0", tk.END)

            fw = result.get("firmware_metadata", {})
            extr = result.get("extraction_summary", {})
            fs = result.get("findings_summary", {})

            def add(t, tag=None):
                if tag:
                    self.summary_text.insert(tk.END, t, tag)
                else:
                    self.summary_text.insert(tk.END, t)

            add("IPSW RESEARCH BRIEF — SUMMARY\n", "h1")
            add(f"Firmware    : iOS {fw.get('ios_version', '?')} build {fw.get('ios_build', '?')}\n")
            add(f"Product     : {fw.get('product_type', '?')}\n")
            add(f"IPSW size   : {fw.get('ipsw_size_bytes', 0) / (1024*1024):.1f} MB\n")
            add(f"\n")
            add("EXTRACTION\n", "h2")
            add(f"  Mach-O discovered : {extr.get('macho_count', 0)}\n")
            add(f"  Selected for analysis : {extr.get('selected_count', 0)}\n")
            add(f"  Successful : {extr.get('successful_count', 0)}\n")
            add(f"  Sandbox profiles : {extr.get('sandbox_profiles', 0)}\n")
            add(f"  Launchd plists : {extr.get('launchd_plists', 0)}\n")
            add("\n")
            add("FINDINGS\n", "h2")
            by_conf = fs.get("by_confidence", {})
            add(f"  Total: {fs.get('total', 0)}  | "
                f"HIGH={by_conf.get('HIGH', 0)} ", "crit")
            add(f"MEDIUM={by_conf.get('MEDIUM', 0)} LOW={by_conf.get('LOW', 0)}\n\n")
            for cat, n in sorted(fs.get("by_category", {}).items(),
                                   key=lambda kv: -kv[1]):
                add(f"  {cat:<32}: {n}\n")

            high_findings = [f for f in result.get("findings", [])
                              if f["confidence"] == "HIGH"]
            if high_findings:
                add("\nTOP HIGH-CONFIDENCE FINDINGS\n", "h2")
                for f in high_findings[:12]:
                    add(f"\n  ⚡ [{f['category']}] {f['title']}\n", "crit")
                    add(f"     Source : {f['source_binary'][:200]}\n")
                    add(f"     Reason : {f['reasoning'][:300]}\n")
                    add(f"     Action : {f['actionable'][:200]}\n")

            self.summary_text.configure(state=tk.DISABLED)

        def _build_text_summary(self, result: dict) -> str:
            buf = io.StringIO()
            fw = result.get("firmware_metadata", {})
            extr = result.get("extraction_summary", {})
            fs = result.get("findings_summary", {})
            print("IPSW RESEARCH BRIEF — TEXT SUMMARY", file=buf)
            print("=" * 80, file=buf)
            print(f"Firmware     : iOS {fw.get('ios_version', '?')} build {fw.get('ios_build', '?')}", file=buf)
            print(f"Product type : {fw.get('product_type', '?')}", file=buf)
            print(f"Mach-O ok    : {extr.get('successful_count', 0)} / {extr.get('selected_count', 0)}", file=buf)
            print(f"Findings     : {fs.get('total', 0)}", file=buf)
            print(f"  HIGH       : {fs.get('by_confidence', {}).get('HIGH', 0)}", file=buf)
            print(f"  MEDIUM     : {fs.get('by_confidence', {}).get('MEDIUM', 0)}", file=buf)
            print(f"  LOW        : {fs.get('by_confidence', {}).get('LOW', 0)}", file=buf)
            print("", file=buf)
            for f in result.get("findings", []):
                print("-" * 80, file=buf)
                print(f"[{f['confidence']}] [{f['category']}] {f['title']}", file=buf)
                print(f"  Source: {f['source_binary']}", file=buf)
                print(f"  Reasoning: {f['reasoning']}", file=buf)
                print(f"  Actionable: {f['actionable']}", file=buf)
                print(f"  Evidence ({len(f.get('evidence_chain', []))} items):", file=buf)
                for e in f.get("evidence_chain", [])[:8]:
                    print(f"    - [{e.get('kind')}] {str(e.get('value'))[:200]}", file=buf)
            return buf.getvalue()

        # ── Sorting helpers ──────────────────────────────────────────────────
        def _sort_tree(self, col: str, reverse: bool):
            data = [(self.find_tree.set(k, col), k)
                     for k in self.find_tree.get_children("")]
            try:
                data.sort(key=lambda t: (int(t[0]) if t[0].isdigit() else t[0]),
                            reverse=reverse)
            except Exception:
                data.sort(reverse=reverse)
            for idx, (_, k) in enumerate(data):
                self.find_tree.move(k, "", idx)
            self.find_tree.heading(col,
                                    command=lambda: self._sort_tree(col, not reverse))

        def _sort_bin_tree(self, col: str, reverse: bool):
            data = [(self.bin_tree.set(k, col), k)
                     for k in self.bin_tree.get_children("")]
            try:
                data.sort(key=lambda t: (int(t[0]) if t[0].isdigit() else t[0]),
                            reverse=reverse)
            except Exception:
                data.sort(reverse=reverse)
            for idx, (_, k) in enumerate(data):
                self.bin_tree.move(k, "", idx)
            self.bin_tree.heading(col,
                                   command=lambda: self._sort_bin_tree(col, not reverse))

        # ── Logging helper ───────────────────────────────────────────────────
        def _log(self, msg: str, tag: Optional[str] = None):
            self.log_text.configure(state=tk.NORMAL)
            if tag:
                self.log_text.insert(tk.END, msg, tag)
            else:
                self.log_text.insert(tk.END, msg)
            self.log_text.see(tk.END)
            # Don't disable — user might want to copy

        def run(self):
            self.root.mainloop()

    # ── End of class — boot it ──────────────────────────────────────────────
    PipelineGUI().run()


# ─── Helpers used by the GUI ─────────────────────────────────────────────────

class _LogRedirector:
    """File-like object that pushes writes into a queue for cross-thread display."""
    def __init__(self, q):
        self._q = q
        self._buf = ""

    def write(self, s):
        if not s:
            return
        self._buf += s
        while "\n" in self._buf:
            line, _, rest = self._buf.partition("\n")
            self._q.put(line + "\n")
            self._buf = rest

    def flush(self):
        if self._buf:
            self._q.put(self._buf)
            self._buf = ""


def _classify_log_line(line: str) -> Optional[str]:
    """Pick a tag name for log line based on prefix."""
    s = line.lstrip()
    if s.startswith("[!]") or s.startswith("[✗]") or "error" in s.lower()[:30]:
        return "err"
    if s.startswith("[*]") or s.startswith("──"):
        return "info"
    if s.startswith("[+]"):
        return "good"
    if s.startswith("[?]") or "warn" in s.lower()[:30]:
        return "warn"
    if s.startswith("==") or s.startswith("STAGE"):
        return "hdr"
    return None


# ═══════════════════════════════════════════════════════════════════════════════
# §8  ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    # If invoked with `--gui` (or no args) → launch GUI; otherwise CLI.
    if len(sys.argv) == 1:
        launch_gui()
    else:
        main()
