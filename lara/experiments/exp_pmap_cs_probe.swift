//
//  exp_pmap_cs_probe.swift
//  DSPloit
//
//  EXPERIMENT: Read critical kernel AMFI/pmap_cs flags at runtime
//  Shows exactly what's blocking unsigned code execution.
//
//  Addresses from Ghidra RE (unslid):
//  - 0xfffffff00a0e45b8: pmap_cs enforcement (developer mode flag)
//  - 0xfffffff00a0e1368: developer_mode_init
//  - 0xfffffff007b795e8: trust_cache_load_gate
//  - 0xfffffff00a160798: cs_enforcement_disable
//  - 0xfffffff00a3304c0: AMFI IOKit object pointer
//
//  Created by Royan | 2026-05-30
//

import Foundation

final class ExpPmapCSProbe {
    static let shared = ExpPmapCSProbe()
    
    func runAll() -> [String] {
        var log: [String] = []
        
        guard ds_is_ready() else {
            return ["❌ KRW not active"]
        }
        
        let slide = ds_get_kernel_slide()
        let base = ds_get_kernel_base()
        
        log.append("══ pmap_cs Kernel Probe ══")
        log.append("kernel_base: 0x\(String(format: "%llx", base))")
        log.append("kernel_slide: 0x\(String(format: "%llx", slide))")
        log.append("")
        
        // Critical addresses (unslid)
        struct KAddr {
            let name: String
            let unslid: UInt64
            let description: String
            let goodValue: String
        }
        
        let addrs: [KAddr] = [
            KAddr(name: "pmap_cs_enforcement",
                  unslid: 0xfffffff00a0e45b8,
                  description: "Developer mode / pmap_cs master switch",
                  goodValue: "1 (allows entitlement-based bypass)"),
            KAddr(name: "developer_mode_init",
                  unslid: 0xfffffff00a0e1368,
                  description: "Developer mode initialized flag",
                  goodValue: "1"),
            KAddr(name: "trust_cache_load_gate",
                  unslid: 0xfffffff007b795e8,
                  description: "Allows trust cache loading (from DT)",
                  goodValue: "1 (but 0 is OK if device unlocked)"),
            KAddr(name: "cs_enforcement_disable",
                  unslid: 0xfffffff00a160798,
                  description: "Global code signing disable",
                  goodValue: "1 (disables all CS checks)"),
            KAddr(name: "amfi_object_ptr",
                  unslid: 0xfffffff00a3304c0,
                  description: "AMFI IOKit service object",
                  goodValue: "non-zero (service registered)"),
        ]
        
        log.append("── Critical Flags ──")
        for addr in addrs {
            let runtime = addr.unslid &+ slide
            let val = ds_kread64(runtime)
            let valByte = UInt8(val & 0xFF)
            let status: String
            if addr.name == "amfi_object_ptr" {
                status = val != 0 ? "✅" : "❌"
            } else if addr.name == "trust_cache_load_gate" {
                status = valByte == 1 ? "✅" : "⚠️"
            } else {
                status = valByte == 1 ? "✅" : "❌"
            }
            log.append("\(status) \(addr.name) = 0x\(String(format: "%llx", val))")
            log.append("   @ 0x\(String(format: "%llx", runtime))")
            log.append("   \(addr.description)")
            log.append("   want: \(addr.goodValue)")
            log.append("")
        }
        
        // Check our own process cs_flags
        log.append("── Our Process ──")
        let ourProc = ds_get_our_proc()
        let ourProcRo = ds_kread64(ourProc + UInt64(off_proc_p_proc_ro))
        let csFlags = ds_kread32(ourProcRo + 0x1c)
        log.append("proc: 0x\(String(format: "%llx", ourProc))")
        log.append("proc_ro: 0x\(String(format: "%llx", ourProcRo))")
        log.append("cs_flags: 0x\(String(format: "%08x", csFlags))")
        
        let isPlatform = (csFlags & 0x04000000) != 0
        let isValid = (csFlags & 0x00000001) != 0
        let getTaskAllow = (csFlags & 0x00000004) != 0
        let debugged = (csFlags & 0x10000000) != 0
        log.append("  CS_VALID: \(isValid)")
        log.append("  CS_GET_TASK_ALLOW: \(getTaskAllow)")
        log.append("  CS_PLATFORM_BINARY: \(isPlatform)")
        log.append("  CS_DEBUGGED: \(debugged)")
        log.append("")
        
        // Check AMFI __DATA flags (writable range 0xa330000+)
        log.append("── AMFI __DATA Flags ──")
        let amfiBase: UInt64 = 0xfffffff00a330098 &+ slide
        let flagOffsets: [(UInt64, String)] = [
            (0x110, "enforce_1"),
            (0x160, "enforce_2"),
            (0x1b0, "enforce_3"),
            (0x200, "enforce_4"),
            (0x250, "enforce_5"),
            (0x2a0, "enforce_6"),
            (0x2f0, "enforce_7"),
            (0x340, "enforce_8"),
            (0x398, "enforce_9"),
            (0x408, "enforce_10"),
        ]
        
        var allZero = true
        for (off, name) in flagOffsets {
            let val = ds_kread64(amfiBase &+ off)
            if val != 0 { allZero = false }
            if val != 0 {
                log.append("  \(name) @ +0x\(String(format: "%x", off)) = 0x\(String(format: "%llx", val))")
            }
        }
        if allZero {
            log.append("  ✅ All 10 AMFI flags = 0 (zeroed)")
        }
        log.append("")
        
        // Try to write cs_enforcement_disable
        log.append("── Write Tests ──")
        let csDisableAddr = 0xfffffff00a160798 as UInt64 &+ slide
        let csDisableBefore = ds_kread32(csDisableAddr)
        log.append("cs_enforcement_disable before: \(csDisableBefore)")
        
        if csDisableBefore == 0 {
            ds_kwrite32(csDisableAddr, 1)
            let after = ds_kread32(csDisableAddr)
            if after == 1 {
                log.append("✅ cs_enforcement_disable → 1 (WRITABLE!)")
                log.append("   This should disable ALL code signing checks!")
            } else {
                log.append("❌ cs_enforcement_disable write failed (read-only)")
                log.append("   value still: \(after)")
            }
        } else {
            log.append("✅ cs_enforcement_disable already non-zero")
        }
        log.append("")
        
        // Try to set pmap_cs_enforcement
        let pmapEnfAddr = 0xfffffff00a0e45b8 as UInt64 &+ slide
        let pmapEnfBefore = ds_kread8(pmapEnfAddr)
        log.append("pmap_cs_enforcement before: \(pmapEnfBefore)")
        if pmapEnfBefore != 1 {
            ds_kwrite8(pmapEnfAddr, 1)
            let after = ds_kread8(pmapEnfAddr)
            if after == 1 {
                log.append("✅ pmap_cs_enforcement → 1 (WRITABLE!)")
            } else {
                log.append("❌ pmap_cs_enforcement write failed (KTRR)")
            }
        } else {
            log.append("✅ pmap_cs_enforcement already 1")
        }
        log.append("")
        
        // Summary
        log.append("══ Summary ══")
        let enforcement = ds_kread8(pmapEnfAddr)
        let tcGate = ds_kread8(0xfffffff007b795e8 &+ slide)
        let csDisable = ds_kread32(csDisableAddr)
        
        if enforcement == 1 && csDisable == 1 {
            log.append("✅ Best case: enforcement ON + cs_disable ON")
            log.append("   Entitlement bypass should work")
        } else if enforcement == 1 && tcGate == 1 {
            log.append("✅ TC gate open + enforcement on")
            log.append("   Trust cache loading should work")
        } else if enforcement == 1 && tcGate == 0 {
            log.append("⚠️ TC gate closed but device unlocked → TC load OK")
            log.append("   Need entitlement (use cryptexd path)")
        } else {
            log.append("❌ Enforcement off → all pmap_cs checks deny")
        }
        
        return log
    }
}
