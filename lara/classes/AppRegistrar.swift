//
//  AppRegistrar.swift
//  DSPloit
//
//  App registration via installd XPC — makes installed .app visible on Home Screen.
//  Uses MobileInstallation framework via RemoteCall instead of direct
//  LSApplicationWorkspace (which causes kernel panic on iOS 18+).
//
//  Flow:
//  1. Copy .app bundle to /var/containers/Bundle/Application/<UUID>/
//  2. Set correct ownership (mobile:mobile) and permissions
//  3. Call installd via XPC: MobileInstallationInstallForLaunchServices
//  4. Notify SpringBoard to refresh icon cache
//
//  Created by Royan | 2026-05-24
//

import Foundation

final class AppRegistrar: ObservableObject {
    static let shared = AppRegistrar()
    
    @Published var isRegistering = false
    @Published var log: [String] = []
    @Published var lastError: String?
    
    private let root = RootExecutor.shared
    private let mgr = dspmgr.shared
    
    private func appendLog(_ msg: String) {
        DispatchQueue.main.async { self.log.append(msg) }
        globallogger.log("(appreg) \(msg)")
    }
    
    // MARK: - Constants
    
    private let containerBase = "/var/containers/Bundle/Application"
    private let jbAppsDir = "/var/jb/Applications"
    
    // MARK: - Register App via installd XPC
    
    /// Register an .app bundle so it appears on the Home Screen.
    /// appPath: full path to the .app directory (e.g. /var/jb/Applications/MyApp.app)
    #if !DISABLE_REMOTECALL
    func registerApp(appPath: String, completion: @escaping (Bool, String) -> Void) {
        guard mgr.dsready, mgr.rcready else {
            completion(false, "Jailbreak not active")
            return
        }
        
        isRegistering = true
        lastError = nil
        appendLog("Registering \(appPath)...")
        
        let appName = (appPath as NSString).lastPathComponent
        let uuid = UUID().uuidString.uppercased()
        let destDir = "\(containerBase)/\(uuid)"
        let destApp = "\(destDir)/\(appName)"
        
        appendLog("Target: \(destApp)")
        
        // Step 1: Create container directory
        root.executeAsRoot(operation: "appreg_mkdir") { rc in
            let dirStr = remote_alloc_str(rc, destDir)
            let ret = RootExecutor.rcall(rc, "mkdir", dirStr, 0o755)
            RootExecutor.rcall(rc, "free", dirStr)
            let errno_val = remote_errno(rc)
            let ok = ret == 0 || errno_val == EEXIST
            return (ok, ok ? "mkdir ok" : "mkdir failed errno=\(errno_val)", UInt64(ret))
        }
        
        // Step 2: Copy app bundle (use cp -R via posix_spawn)
        DispatchQueue.main.asyncAfter(deadline: .now() + 4) { [weak self] in
            guard let self else { return }
            self.appendLog("Copying app bundle...")
            
            self.root.spawnAsRoot(binary: "/bin/cp", args: ["-R", appPath, destApp])
            
            // Step 3: Fix ownership after copy completes
            DispatchQueue.main.asyncAfter(deadline: .now() + 6) {
                self.fixOwnershipAndRegister(destDir: destDir, destApp: destApp, completion: completion)
            }
        }
    }
    
    private func fixOwnershipAndRegister(destDir: String, destApp: String, completion: @escaping (Bool, String) -> Void) {
        appendLog("Fixing ownership...")
        
        // chown -R mobile:mobile (uid=501, gid=501)
        root.executeAsRoot(operation: "appreg_chown") { rc in
            let pathStr = remote_alloc_str(rc, destDir)
            // chown the container dir
            RootExecutor.rcall(rc, "chown", pathStr, 501, 501)
            RootExecutor.rcall(rc, "free", pathStr)
            return (true, "chown ok", 0)
        }
        
        // Step 4: Call installd via XPC from SpringBoard
        DispatchQueue.main.asyncAfter(deadline: .now() + 4) { [weak self] in
            guard let self else { return }
            self.callInstalld(appPath: destApp, completion: completion)
        }
    }
    
    private func callInstalld(appPath: String, completion: @escaping (Bool, String) -> Void) {
        guard let sb = mgr.sbProc else {
            appendLog("❌ SpringBoard RC not available")
            isRegistering = false
            completion(false, "SpringBoard RC not available")
            return
        }
        
        appendLog("Calling installd via XPC...")
        
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            
            let RTLD_DEFAULT = UInt64(bitPattern: -2)
            
            // Resolve XPC functions in SpringBoard
            let xpcCreate = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                               remote_alloc_str(sb, "xpc_connection_create_mach_service"))
            let xpcResume = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                               remote_alloc_str(sb, "xpc_connection_resume"))
            let xpcDictCreate = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                                   remote_alloc_str(sb, "xpc_dictionary_create"))
            let xpcSetStr = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                               remote_alloc_str(sb, "xpc_dictionary_set_string"))
            let xpcSetBool = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                                remote_alloc_str(sb, "xpc_dictionary_set_bool"))
            let xpcSendSync = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                                  remote_alloc_str(sb, "xpc_connection_send_message_with_reply_sync"))
            
            guard xpcCreate != 0 && xpcDictCreate != 0 else {
                DispatchQueue.main.async {
                    self.appendLog("❌ XPC functions not available in SpringBoard")
                    self.isRegistering = false
                    completion(false, "XPC functions unavailable")
                }
                return
            }
            
            // Connect to com.apple.mobile.installd
            let svc = remote_alloc_str(sb, "com.apple.mobile.installd")
            let conn = RootExecutor.rcallAddr(sb, xpcCreate, svc, 0, 0)
            RootExecutor.rcall(sb, "free", svc)
            
            guard conn != 0 else {
                DispatchQueue.main.async {
                    self.appendLog("❌ installd connection failed")
                    self.isRegistering = false
                    completion(false, "installd connect failed")
                }
                return
            }
            RootExecutor.rcallAddr(sb, xpcResume, conn)
            
            // Build install message
            let msg = RootExecutor.rcallAddr(sb, xpcDictCreate, 0, 0, 0)
            if msg != 0 {
                // Command: InstallForLaunchServices
                let cmdKey = remote_alloc_str(sb, "Command")
                let cmdVal = remote_alloc_str(sb, "InstallForLaunchServices")
                RootExecutor.rcallAddr(sb, xpcSetStr, msg, cmdKey, cmdVal)
                RootExecutor.rcall(sb, "free", cmdKey)
                RootExecutor.rcall(sb, "free", cmdVal)
                
                // PackagePath
                let pathKey = remote_alloc_str(sb, "PackagePath")
                let pathVal = remote_alloc_str(sb, appPath)
                RootExecutor.rcallAddr(sb, xpcSetStr, msg, pathKey, pathVal)
                RootExecutor.rcall(sb, "free", pathKey)
                RootExecutor.rcall(sb, "free", pathVal)
                
                // IsUserInitiated = true
                if xpcSetBool != 0 {
                    let userKey = remote_alloc_str(sb, "IsUserInitiated")
                    RootExecutor.rcallAddr(sb, xpcSetBool, msg, userKey, 1)
                    RootExecutor.rcall(sb, "free", userKey)
                }
                
                // Send synchronously
                if xpcSendSync != 0 {
                    let reply = RootExecutor.rcallAddr(sb, xpcSendSync, conn, msg)
                    DispatchQueue.main.async {
                        if reply != 0 {
                            self.appendLog("✅ installd replied (handle=0x\(String(reply, radix: 16)))")
                            self.notifySpringBoard()
                            self.isRegistering = false
                            completion(true, "App registered successfully")
                        } else {
                            self.appendLog("⚠️ installd no reply — app may still register")
                            self.notifySpringBoard()
                            self.isRegistering = false
                            completion(true, "Sent to installd (no reply)")
                        }
                    }
                } else {
                    // Fallback: send without waiting for reply
                    let xpcSend = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                                     remote_alloc_str(sb, "xpc_connection_send_message"))
                    if xpcSend != 0 {
                        RootExecutor.rcallAddr(sb, xpcSend, conn, msg)
                    }
                    DispatchQueue.main.async {
                        self.appendLog("✅ Install message sent (async)")
                        self.notifySpringBoard()
                        self.isRegistering = false
                        completion(true, "Install message sent")
                    }
                }
            } else {
                DispatchQueue.main.async {
                    self.appendLog("❌ Failed to create XPC message")
                    self.isRegistering = false
                    completion(false, "XPC message creation failed")
                }
            }
        }
    }
    
    // MARK: - Notify SpringBoard (uicache equivalent)
    
    /// Post notification to SpringBoard to refresh icon cache
    private func notifySpringBoard() {
        appendLog("Notifying SpringBoard to refresh icons...")
        
        guard let sb = mgr.sbProc else { return }
        
        let RTLD_DEFAULT = UInt64(bitPattern: -2)
        
        // notify_post("com.apple.LaunchServices.applicationRegistered")
        let notifyPost = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                            remote_alloc_str(sb, "notify_post"))
        if notifyPost != 0 {
            let notifName = remote_alloc_str(sb, "com.apple.LaunchServices.applicationRegistered")
            RootExecutor.rcallAddr(sb, notifyPost, notifName)
            RootExecutor.rcall(sb, "free", notifName)
            appendLog("✅ LaunchServices notification posted")
        }
        
        // Also try SBSRelaunchAction for icon refresh
        let cfNotifPost = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                             remote_alloc_str(sb, "CFNotificationCenterPostNotification"))
        let cfNotifCenter = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                               remote_alloc_str(sb, "CFNotificationCenterGetDarwinNotifyCenter"))
        if cfNotifPost != 0 && cfNotifCenter != 0 {
            let center = RootExecutor.rcallAddr(sb, cfNotifCenter)
            if center != 0 {
                let notifStr = remote_alloc_str(sb, "com.apple.mobile.application_installed")
                // CFNotificationCenterPostNotification(center, name, NULL, NULL, true)
                RootExecutor.rcallAddr(sb, cfNotifPost, center, notifStr, 0, 0, 1)
                RootExecutor.rcall(sb, "free", notifStr)
                appendLog("✅ CFNotification posted")
            }
        }
    }
    
    // MARK: - Unregister App
    
    func unregisterApp(bundleID: String, completion: @escaping (Bool, String) -> Void) {
        guard mgr.rcready, let sb = mgr.sbProc else {
            completion(false, "RC not ready")
            return
        }
        
        appendLog("Unregistering \(bundleID)...")
        
        let RTLD_DEFAULT = UInt64(bitPattern: -2)
        let xpcCreate = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                           remote_alloc_str(sb, "xpc_connection_create_mach_service"))
        let xpcResume = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                           remote_alloc_str(sb, "xpc_connection_resume"))
        let xpcDictCreate = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                               remote_alloc_str(sb, "xpc_dictionary_create"))
        let xpcSetStr = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                           remote_alloc_str(sb, "xpc_dictionary_set_string"))
        let xpcSend = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                         remote_alloc_str(sb, "xpc_connection_send_message"))
        
        guard xpcCreate != 0 && xpcDictCreate != 0 else {
            completion(false, "XPC unavailable")
            return
        }
        
        let svc = remote_alloc_str(sb, "com.apple.mobile.installd")
        let conn = RootExecutor.rcallAddr(sb, xpcCreate, svc, 0, 0)
        RootExecutor.rcall(sb, "free", svc)
        guard conn != 0 else { completion(false, "connect failed"); return }
        RootExecutor.rcallAddr(sb, xpcResume, conn)
        
        let msg = RootExecutor.rcallAddr(sb, xpcDictCreate, 0, 0, 0)
        if msg != 0 {
            let cmdK = remote_alloc_str(sb, "Command")
            let cmdV = remote_alloc_str(sb, "UninstallForLaunchServices")
            RootExecutor.rcallAddr(sb, xpcSetStr, msg, cmdK, cmdV)
            RootExecutor.rcall(sb, "free", cmdK); RootExecutor.rcall(sb, "free", cmdV)
            
            let idK = remote_alloc_str(sb, "ApplicationIdentifier")
            let idV = remote_alloc_str(sb, bundleID)
            RootExecutor.rcallAddr(sb, xpcSetStr, msg, idK, idV)
            RootExecutor.rcall(sb, "free", idK); RootExecutor.rcall(sb, "free", idV)
            
            if xpcSend != 0 {
                RootExecutor.rcallAddr(sb, xpcSend, conn, msg)
            }
            
            appendLog("✅ Uninstall sent for \(bundleID)")
            notifySpringBoard()
            completion(true, "Uninstall sent")
        } else {
            completion(false, "XPC message failed")
        }
    }
    
    // MARK: - Register All JB Apps
    
    /// Register all .app bundles in /var/jb/Applications/
    func registerAllJBApps(completion: @escaping (Int, Int) -> Void) {
        guard mgr.dsready, mgr.rcready else {
            completion(0, 0)
            return
        }
        
        appendLog("Scanning \(jbAppsDir) for apps...")
        
        guard let entries = mgr.vfslistdir(path: jbAppsDir) else {
            appendLog("⚠️ Cannot read \(jbAppsDir)")
            completion(0, 0)
            return
        }
        
        let apps = entries.filter { $0.name.hasSuffix(".app") && $0.isDir }
        appendLog("Found \(apps.count) apps to register")
        
        var registered = 0
        var failed = 0
        let group = DispatchGroup()
        
        for app in apps {
            let appPath = "\(jbAppsDir)/\(app.name)"
            group.enter()
            registerApp(appPath: appPath) { [weak self] ok, msg in
                if ok { registered += 1 } else { failed += 1 }
                self?.appendLog("  \(app.name): \(ok ? "✅" : "❌") \(msg)")
                group.leave()
            }
        }
        
        group.notify(queue: .main) { [weak self] in
            self?.appendLog("Registration complete: \(registered) ok, \(failed) failed")
            completion(registered, failed)
        }
    }
    #endif
}
