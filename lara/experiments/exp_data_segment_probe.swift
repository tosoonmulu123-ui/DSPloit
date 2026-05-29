//
//  exp_data_segment_probe.swift
//  DSPloit
//
//  EXPERIMENT: Probe kernel __DATA segments to find WRITABLE addresses
//  ═══════════════════════════════════════════════════════════════════
//  STATUS: SAFE — READ ONLY (no writes, no panic risk)
//  ═══════════════════════════════════════════════════════════════════
//
//  PURPOSE:
//  Previous attempts to write to Ghidra-identified addresses caused panic
//  because those addresses are in __DATA_CONST (read-only at runtime).
//  
//  This experiment:
//  1. Reads known AMFI/pmap_cs addresses to verify their values
//  2. Probes memory regions to find which are actually writable
//  3. Maps the real writable __DATA range on THIS device
//  4. Finds AMFI variables that live in writable memory
//
//  FINDINGS FROM PANIC ANALYSIS:
//  - FAR: 0xfffffff019f715e8 (unslid: 0x7b715e8) caused the fault
//  - Addresses 0x7b795e8, 0xa0e1368, 0xa0e45b8 are in __DATA_CONST
//  - __DATA_CONST is hardware-locked (KTRR/CTRR) at runtime
//  - Real writable __DATA is at 0xa3b0000-0xa408000 range (from Ghidra)
//
//  SAFE: This experiment only READS. No writes = no panic.
//
//  Created by Royan | 2026-05-30
//

import Foundation
import UIKit

final class ExpDataSegmentProbe {
    static let shared = ExpDataSegmentProbe()
    private var results: [String] = []
    
    private func log(_ msg: String) {
        results.append(msg)
        globallogger.log("(exp_probe) \(msg)")
    }
    
    // Known addresses from Ghidra (unslid)
    // These are the ones that CAUSED PANIC (in __DATA_CONST):
    private let dangerousAddresses: [(UInt64, String)] = [
        (0xfffffff00a0e45b8, "pmap_cs_enforcement (PANIC - __DATA_CONST)"),
        (0xfffffff00a0e1368, "developer_mode_init (PANIC - __DATA_CONST)"),
        (0xfffffff007b795e8, "trust_cache_load_gate (PANIC - __DATA_CONST)"),
    ]
    
    // Addresses that SHOULD be in writable __DATA (0xa33xxxx range):
    private let candidateWritableAddresses: [(UInt64, String)] = [
        (0xfffffff00a330520, "AMFI kext object (xrefs from AMFI init)"),
        (0xfffffff00a3304c0, "AMFI target object"),
        (0xfffffff00a3304e8, "AMFI related data"),
        (0xfffffff00a330530, "AMFI boot-arg result"),
        (0xfffffff007b79bd9, "amfi-only-platform-code flag"),
        (0xfffffff007b79bda, "AMFI Swift Playgrounds flag"),
        (0xfffffff007b79be4, "AMFI research mode flag"),
    ]
    
    // MARK: - Main Entry Point
    
    func runAll() -> [String] {
        results.removeAll()
        
        log("═══════════════════════════════════════════════════")
        log("  DATA SEGMENT PROBE (READ-ONLY, SAFE)")
        log("  iOS \(UIDevice.current.systemVersion)")
        log("  Purpose: Find writable AMFI addresses")
        log("═══════════════════════════════════════════════════")
        log("")
        
        guard dspmgr.shared.dsready else {
            log("❌ KRW not active — run jailbreak first")
            return results
        }
        
        let slide = ds_get_kernel_slide()
        let kbase = ds_get_kernel_base()
        log("kernel_base  = 0x\(String(kbase, radix: 16))")
        log("kernel_slide = 0x\(String(slide, radix: 16))")
        log("")
        
        // Phase 1: Read dangerous addresses (DO NOT WRITE)
        log("── Phase 1: Read __DATA_CONST addresses (DO NOT WRITE) ──")
        log("   These caused panic when written to.")
        log("")
        
        for (unslidAddr, desc) in dangerousAddresses {
            let addr = unslidAddr &+ slide
            let val = ds_kread64(addr)
            log("   0x\(String(unslidAddr, radix: 16)) + slide = 0x\(String(addr, radix: 16))")
            log("   Value: 0x\(String(val, radix: 16)) — \(desc)")
            log("")
        }
        
        // Phase 2: Read candidate writable addresses
        log("── Phase 2: Read candidate writable __DATA addresses ──")
        log("   These are in 0xa33xxxx range (likely writable).")
        log("")
        
        for (unslidAddr, desc) in candidateWritableAddresses {
            let addr = unslidAddr &+ slide
            let val = ds_kread64(addr)
            log("   0x\(String(unslidAddr, radix: 16)) + slide = 0x\(String(addr, radix: 16))")
            log("   Value: 0x\(String(val, radix: 16)) — \(desc)")
            log("")
        }
        
        // Phase 3: Probe writable __DATA range
        log("── Phase 3: Probe writable __DATA boundaries ──")
        log("   Scanning 0xa3b0000-0xa408000 for non-zero data...")
        log("")
        
        probeWritableRange(slide: slide)
        
        // Phase 4: Find AMFI-related globals in writable range
        log("")
        log("── Phase 4: Search for AMFI globals in writable range ──")
        log("")
        
        findAMFIGlobals(slide: slide)
        
        // Phase 5: Test write safety (single byte, restore immediately)
        log("")
        log("── Phase 5: Write test on known-safe address ──")
        log("   Testing if 0xa330520 range is truly writable...")
        log("")
        
        testWriteSafety(slide: slide)
        
        log("")
        log("═══════════════════════════════════════════════════")
        log("  PROBE COMPLETE — Check results above")
        log("═══════════════════════════════════════════════════")
        
        return results
    }
    
    // MARK: - Probe writable range
    
    private func probeWritableRange(slide: UInt64) {
        // Sample every 0x1000 bytes in the expected writable range
        let rangeStart: UInt64 = 0xfffffff00a330000
        let rangeEnd: UInt64 = 0xfffffff00a408000
        
        var nonZeroCount = 0
        var zeroCount = 0
        
        for offset in stride(from: UInt64(0), to: rangeEnd - rangeStart, by: 0x1000) {
            let addr = rangeStart &+ slide &+ offset
            let val = ds_kread64(addr)
            if val != 0 {
                nonZeroCount += 1
                if nonZeroCount <= 10 {
                    log("   [+] 0x\(String(rangeStart + offset, radix: 16)): 0x\(String(val, radix: 16))")
                }
            } else {
                zeroCount += 1
            }
        }
        
        log("   Summary: \(nonZeroCount) non-zero pages, \(zeroCount) zero pages")
        log("   Range 0x\(String(rangeStart, radix: 16)) - 0x\(String(rangeEnd, radix: 16))")
    }
    
    // MARK: - Find AMFI globals
    
    private func findAMFIGlobals(slide: UInt64) {
        // The AMFI kext stores its state in __DATA segment
        // From Ghidra: AMFI init writes to 0xa330520, 0xa3304c0, 0xa3304e8
        // Also: 0x7b79bd9, 0x7b79bda, 0x7b79be4 (AMFI boolean flags)
        
        // Check the 0x7b79xxx range — these might be in a different segment
        let amfiFlagBase: UInt64 = 0xfffffff007b79b00 &+ slide
        log("   AMFI flag region (0x7b79b00 + slide):")
        
        for offset: UInt64 in stride(from: 0, to: 0x100, by: 8) {
            let addr = amfiFlagBase &+ offset
            let val = ds_kread64(addr)
            if val != 0 {
                log("   +0x\(String(offset, radix: 16)): 0x\(String(val, radix: 16))")
            }
        }
        
        // Check AMFI kext __DATA (0xa330xxx range)
        log("")
        log("   AMFI kext data region (0xa330400 + slide):")
        let amfiDataBase: UInt64 = 0xfffffff00a330400 &+ slide
        
        for offset: UInt64 in stride(from: 0, to: 0x200, by: 8) {
            let addr = amfiDataBase &+ offset
            let val = ds_kread64(addr)
            if val != 0 {
                log("   +0x\(String(offset, radix: 16)): 0x\(String(val, radix: 16))")
            }
        }
    }
    
    // MARK: - Write safety test
    
    private func testWriteSafety(slide: UInt64) {
        // Test address: 0xa330520 (AMFI object pointer area)
        // This is in the 0xa33xxxx range which SHOULD be writable
        // We'll read, write a test value, verify, then RESTORE
        
        let testAddr: UInt64 = 0xfffffff00a330530 &+ slide
        let original = ds_kread64(testAddr)
        
        log("   Test addr: 0x\(String(testAddr, radix: 16))")
        log("   Original:  0x\(String(original, radix: 16))")
        
        // Only test if the value is 0 (safe to modify temporarily)
        if original == 0 {
            let testVal: UInt64 = 0xCAFEBABE
            ds_kwrite64(testAddr, testVal)
            
            // Small delay
            usleep(1000)
            
            let readback = ds_kread64(testAddr)
            log("   Written:   0x\(String(testVal, radix: 16))")
            log("   Readback:  0x\(String(readback, radix: 16))")
            
            if readback == testVal {
                log("   ✅ WRITE SUCCEEDED — this address IS writable!")
                log("   Restoring original value...")
                ds_kwrite64(testAddr, original)
                let restored = ds_kread64(testAddr)
                log("   Restored:  0x\(String(restored, radix: 16))")
            } else if readback == original {
                log("   ❌ Write silently ignored — address is READ-ONLY")
            } else {
                log("   ⚠️ Unexpected readback — restoring")
                ds_kwrite64(testAddr, original)
            }
        } else {
            log("   ⏭️ Skipping write test (value non-zero, don't want to corrupt)")
            log("   Try a different address with value 0")
        }
    }
}
