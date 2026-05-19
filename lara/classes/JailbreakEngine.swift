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
        
        // Mark complete after bootstrap
        DispatchQueue.main.asyncAfter(deadline: .now() + 12) { [weak self] in
            guard let self else { return }
            self.progress = 1.0
            self.state = .complete
            self.isJailbroken = true
            self.isRunning = false
            self.appendLog("🎉 Jailbreak complete!")
            UINotificationFeedbackGenerator().notificationOccurred(.success)

            // Kernelcache + XPF (Settings "Fetch" needs jailbreak; do it here automatically)
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
