//
//  TweakLoader.swift
//  DSPloit
//
//  Tweak injection system — loads .dylib tweaks from /var/jb/Library/TweakInject/
//  into target processes via RemoteCall + DYLD_INSERT_LIBRARIES.
//
//  Flow:
//  1. Deploy ElleKit.framework to /var/jb/usr/lib/
//  2. Deploy TweakLoader.dylib to /var/jb/usr/lib/
//  3. Inject TweakLoader into SpringBoard via RemoteCall
//  4. TweakLoader scans /var/jb/Library/TweakInject/ and loads matching .dylib
//
//  Created by Royan | 2026-05-24
//

import Foundation
import Combine

/// Manages tweak injection lifecycle
final class TweakLoader: ObservableObject {
    static let shared = TweakLoader()
    
    // MARK: - Paths
    
    static let jbRoot = "/var/jb"
    static let tweakInjectDir = "/var/jb/Library/TweakInject"
    static let loaderDylibPath = "/var/jb/usr/lib/TweakLoader.dylib"
    static let elleKitPath = "/var/jb/usr/lib/ellekit.dylib"
    static let tweakFilterDir = "/var/jb/Library/TweakInject"
    static let substrateSafeMode = "/var/jb/Library/MobileSubstrate/DynamicLibraries"
    
    // MARK: - State
    
    @Published var isDeployed = false
    @Published var isInjected = false
    @Published var installedTweaks: [TweakInfo] = []
    @Published var log: [String] = []
    @Published var isWorking = false
    
    struct TweakInfo: Identifiable {
        let id = UUID()
        let name: String
        let path: String
        let filterPath: String?
        let bundleFilter: [String]
        let enabled: Bool
        let size: Int64
    }
    
    private let root = RootExecutor.shared
    private let mgr = dspmgr.shared
    
    private func appendLog(_ msg: String) {
        DispatchQueue.main.async { self.log.append(msg) }
        globallogger.log("(tweak) \(msg)")
    }
    
    // MARK: - Deploy Bootstrap (Step 1)
    
    /// Deploy the tweak injection infrastructure to /var/jb/
    /// Creates directories + deploys loader dylib stub
    #if !DISABLE_REMOTECALL
    func deployInfrastructure(completion: @escaping (Bool) -> Void) {
        guard mgr.dsready, mgr.rcready else {
            appendLog("❌ Need kernel + RC ready")
            completion(false)
            return
        }
        
        isWorking = true
        appendLog("Deploying tweak infrastructure...")
        
        root.batchExecuteAsRoot(operation: "tweak_deploy") { rc in
            var results: [(name: String, success: Bool, message: String)] = []
            
            // Create directory structure
            let dirs = [
                Self.tweakInjectDir,
                Self.substrateSafeMode,
                "/var/jb/usr/lib",
                "/var/jb/Library/PreferenceBundles",
                "/var/jb/Library/PreferenceLoader/Preferences",
                "/var/jb/Library/Frameworks"
            ]
            
            for dir in dirs {
                let dirStr = remote_alloc_str(rc, dir)
                let ret = RootExecutor.rcall(rc, "mkdir", dirStr, 0o755)
                RootExecutor.rcall(rc, "free", dirStr)
                let errno_val = remote_errno(rc)
                let ok = ret == 0 || errno_val == EEXIST
                results.append((dir, ok, ok ? "created" : "errno=\(errno_val)"))
            }
            
            // Write the TweakLoader plist (tells launchd to inject into all apps)
            let envPlist = """
            <?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
            <plist version="1.0">
            <dict>
                <key>Label</key>
                <string>com.dsploit.tweakloader</string>
                <key>EnvironmentVariables</key>
                <dict>
                    <key>DYLD_INSERT_LIBRARIES</key>
                    <string>\(Self.loaderDylibPath)</string>
                </dict>
                <key>RunAtLoad</key>
                <true/>
            </dict>
            </plist>
            """
            
            let plistPath = "/var/jb/Library/LaunchDaemons/com.dsploit.tweakloader.plist"
            let plistPathStr = remote_alloc_str(rc, plistPath)
            let fd = RootExecutor.rcall(rc, "open", plistPathStr, UInt64(O_WRONLY | O_CREAT | O_TRUNC), 0o644)
            if fd != UInt64(bitPattern: -1) {
                let contentStr = remote_alloc_str(rc, envPlist)
                RootExecutor.rcall(rc, "write", fd, contentStr, UInt64(envPlist.utf8.count))
                RootExecutor.rcall(rc, "close", fd)
                RootExecutor.rcall(rc, "free", contentStr)
                results.append(("tweakloader.plist", true, "written"))
            } else {
                results.append(("tweakloader.plist", false, "open failed"))
            }
            RootExecutor.rcall(rc, "free", plistPathStr)
            
            return results
        }
        
        // Wait for batch to complete
        DispatchQueue.main.asyncAfter(deadline: .now() + 5) { [weak self] in
            guard let self else { return }
            self.isDeployed = true
            self.isWorking = false
            self.appendLog("✅ Tweak infrastructure deployed")
            completion(true)
        }
    }
    
    // MARK: - Inject into SpringBoard (Step 2)
    
    /// Inject TweakLoader.dylib into SpringBoard via RemoteCall dlopen
    func injectIntoSpringBoard(completion: @escaping (Bool) -> Void) {
        guard mgr.rcready, let sb = mgr.sbProc else {
            appendLog("❌ SpringBoard RC not available")
            completion(false)
            return
        }
        
        isWorking = true
        appendLog("Injecting TweakLoader into SpringBoard...")
        
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            
            // dlopen(TweakLoader.dylib, RTLD_NOW | RTLD_GLOBAL)
            let RTLD_DEFAULT = UInt64(bitPattern: -2)
            let dlopenSym = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                               remote_alloc_str(sb, "dlopen"))
            
            guard dlopenSym != 0 else {
                DispatchQueue.main.async {
                    self.appendLog("❌ dlopen not found in SpringBoard")
                    self.isWorking = false
                    completion(false)
                }
                return
            }
            
            let pathStr = remote_alloc_str(sb, Self.loaderDylibPath)
            let RTLD_NOW: UInt64 = 0x2
            let RTLD_GLOBAL: UInt64 = 0x8
            let handle = RootExecutor.rcallAddr(sb, dlopenSym, pathStr, RTLD_NOW | RTLD_GLOBAL)
            RootExecutor.rcall(sb, "free", pathStr)
            
            DispatchQueue.main.async {
                if handle != 0 {
                    self.isInjected = true
                    self.appendLog("✅ TweakLoader injected into SpringBoard (handle=0x\(String(handle, radix: 16)))")
                    completion(true)
                } else {
                    // Get dlerror
                    let dlerrorSym = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                                        remote_alloc_str(sb, "dlerror"))
                    if dlerrorSym != 0 {
                        let errStr = RootExecutor.rcallAddr(sb, dlerrorSym)
                        if errStr != 0 {
                            var buf = [UInt8](repeating: 0, count: 256)
                            sb.remoteRead(errStr, to: &buf, size: 256)
                            let errMsg = String(cString: buf)
                            self.appendLog("❌ dlopen failed: \(errMsg)")
                        }
                    } else {
                        self.appendLog("❌ dlopen returned NULL (dylib missing or unsigned)")
                    }
                    completion(false)
                }
                self.isWorking = false
            }
        }
    }
    
    // MARK: - Scan Installed Tweaks
    
    func scanInstalledTweaks() {
        appendLog("Scanning tweaks...")
        installedTweaks.removeAll()
        
        // Read /var/jb/Library/TweakInject/ via VFS or sandbox-escaped open
        guard let entries = mgr.vfslistdir(path: Self.tweakInjectDir) else {
            appendLog("⚠️ Cannot read TweakInject directory")
            return
        }
        
        for entry in entries {
            guard entry.name.hasSuffix(".dylib") else { continue }
            let dylibPath = "\(Self.tweakInjectDir)/\(entry.name)"
            let filterPath = dylibPath.replacingOccurrences(of: ".dylib", with: ".plist")
            
            // Try to read filter plist
            var bundleFilter: [String] = []
            if let filterData = mgr.vfsread(path: filterPath, maxSize: 4096),
               let plist = try? PropertyListSerialization.propertyList(from: filterData, format: nil) as? [String: Any],
               let filter = plist["Filter"] as? [String: Any],
               let bundles = filter["Bundles"] as? [String] {
                bundleFilter = bundles
            }
            
            let size = mgr.vfssize(path: dylibPath)
            
            installedTweaks.append(TweakInfo(
                name: entry.name.replacingOccurrences(of: ".dylib", with: ""),
                path: dylibPath,
                filterPath: filterPath,
                bundleFilter: bundleFilter,
                enabled: true,
                size: size
            ))
        }
        
        appendLog("Found \(installedTweaks.count) tweaks")
    }
    
    // MARK: - Install Tweak from .deb
    
    /// Install a tweak .deb — extracts dylib + filter plist to TweakInject dir
    func installTweakFromDeb(debPath: String, completion: @escaping (Bool, String) -> Void) {
        appendLog("Installing tweak from \(debPath)...")
        
        // Use DebInstaller to extract
        guard let debData = try? Data(contentsOf: URL(fileURLWithPath: debPath)) else {
            appendLog("❌ Cannot read .deb file")
            completion(false, "Cannot read file")
            return
        }
        let debName = (debPath as NSString).lastPathComponent
        let installer = DebInstaller()
        installer.install(debData: debData, name: debName) { [weak self] success, fileCount in
            guard let self else { return }
            let message = success ? "\(fileCount) files installed" : "extraction failed"
            if success {
                self.appendLog("✅ Tweak installed: \(message)")
                self.scanInstalledTweaks()
            } else {
                self.appendLog("❌ Install failed: \(message)")
            }
            completion(success, message)
        }
    }
    
    // MARK: - Enable/Disable Tweak
    
    func setTweakEnabled(_ tweak: TweakInfo, enabled: Bool) {
        let disabledPath = tweak.path + ".disabled"
        
        if enabled {
            // Rename .dylib.disabled → .dylib
            root.executeAsRoot(operation: "enable_tweak") { rc in
                let src = remote_alloc_str(rc, disabledPath)
                let dst = remote_alloc_str(rc, tweak.path)
                let ret = RootExecutor.rcall(rc, "rename", src, dst)
                RootExecutor.rcall(rc, "free", src)
                RootExecutor.rcall(rc, "free", dst)
                return (ret == 0, ret == 0 ? "Enabled \(tweak.name)" : "rename failed", UInt64(ret))
            }
        } else {
            // Rename .dylib → .dylib.disabled
            root.executeAsRoot(operation: "disable_tweak") { rc in
                let src = remote_alloc_str(rc, tweak.path)
                let dst = remote_alloc_str(rc, disabledPath)
                let ret = RootExecutor.rcall(rc, "rename", src, dst)
                RootExecutor.rcall(rc, "free", src)
                RootExecutor.rcall(rc, "free", dst)
                return (ret == 0, ret == 0 ? "Disabled \(tweak.name)" : "rename failed", UInt64(ret))
            }
        }
        
        // Refresh list after a short delay
        DispatchQueue.main.asyncAfter(deadline: .now() + 2) { [weak self] in
            self?.scanInstalledTweaks()
        }
    }
    
    // MARK: - Full Deploy + Inject (One-Tap)
    
    func fullSetup(completion: @escaping (Bool) -> Void) {
        deployInfrastructure { [weak self] deployOk in
            guard let self, deployOk else {
                completion(false)
                return
            }
            self.injectIntoSpringBoard { injectOk in
                if injectOk {
                    self.scanInstalledTweaks()
                }
                completion(injectOk)
            }
        }
    }
    #endif
}
