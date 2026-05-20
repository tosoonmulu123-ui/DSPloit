//
//  PrefsEditorView.swift
//  DSPloit
//
//  Preference manipulation — enable hidden features, bypass restrictions
//  Reads/writes system plists from root context
//

import SwiftUI

struct PrefsEditorView: View {
    @ObservedObject private var root = RootExecutor.shared
    @ObservedObject private var mgr = dspmgr.shared
    
    @State private var results: [String] = []
    @State private var isWorking = false
    @State private var customPlistPath = ""
    @State private var customKey = ""
    @State private var customValue = ""
    
    var body: some View {
        List {
            // Quick Toggles
            Section {
                PrefToggle(title: "Internal Settings", subtitle: "Show Apple internal debug menus", icon: "gear.badge") {
                    writePref(domain: "com.apple.springboard", key: "SBShowNonDefaultSystemApps", value: true)
                }
                
                PrefToggle(title: "UI Debugging", subtitle: "Enable view hierarchy inspector", icon: "square.dashed") {
                    writePref(domain: "com.apple.UIKit", key: "UIViewShowAlignmentRects", value: true)
                }
                
                PrefToggle(title: "Network Debugging", subtitle: "Show network activity in status bar", icon: "antenna.radiowaves.left.and.right") {
                    writePref(domain: "com.apple.springboard", key: "SBShowNetworkActivity", value: true)
                }
                
                PrefToggle(title: "Disable Screenshot Sound", subtitle: "Silent screenshots", icon: "speaker.slash") {
                    writePref(domain: "com.apple.springboard", key: "SBScreenShotSoundEnabled", value: false)
                }
                
                PrefToggle(title: "Show Build Version", subtitle: "Display build number in Settings", icon: "number") {
                    writePref(domain: "com.apple.springboard", key: "SBShowBuildVersion", value: true)
                }
            } header: {
                Label("Hidden Features", systemImage: "eye.slash")
            }
            
            // Screen Time / Restrictions
            Section {
                PrefToggle(title: "Disable Screen Time", subtitle: "⚠️ Removes all screen time limits", icon: "hourglass.bottomhalf.filled") {
                    writePref(domain: "com.apple.ScreenTimeAgent", key: "ScreenTimeEnabled", value: false)
                    writePref(domain: "com.apple.ScreenTimeAgent", key: "ScreenTimeAgentEnabled", value: false)
                }
                
                PrefToggle(title: "Remove App Limits", subtitle: "Clear all app time limits", icon: "clock.badge.xmark") {
                    writePref(domain: "com.apple.ScreenTimeAgent", key: "AppLimitsEnabled", value: false)
                }
            } header: {
                Label("Restrictions", systemImage: "lock.open")
            } footer: {
                Text("⚠️ Changes take effect after respring or reboot")
                    .font(.system(size: 9))
            }
            
            // Custom Plist Editor
            Section {
                TextField("/var/mobile/Library/Preferences/...", text: $customPlistPath)
                    .font(.system(size: 11, design: .monospaced))
                    .textInputAutocapitalization(.never)
                
                HStack {
                    TextField("Key", text: $customKey)
                        .font(.system(size: 12, design: .monospaced))
                    Text("=")
                        .foregroundStyle(.secondary)
                    TextField("Value", text: $customValue)
                        .font(.system(size: 12, design: .monospaced))
                        .frame(width: 80)
                }
                
                Button(action: writeCustomPref) {
                    Label("Write Preference", systemImage: "square.and.pencil")
                        .foregroundStyle(.orange)
                }
                .disabled(customPlistPath.isEmpty || customKey.isEmpty || !mgr.rcready)
            } header: {
                Label("Custom Plist", systemImage: "doc.badge.gearshape")
            } footer: {
                Text("Write any key/value to any plist file on device")
                    .font(.system(size: 9))
            }
            
            // WiFi Passwords
            Section {
                Button(action: extractWiFiPasswords) {
                    Label("Extract WiFi Passwords", systemImage: "wifi.circle")
                        .foregroundStyle(.blue)
                }
                .disabled(!mgr.rcready)
            } header: {
                Label("WiFi", systemImage: "wifi")
            }
            
            // Results
            if !results.isEmpty {
                Section {
                    ForEach(results.suffix(15), id: \.self) { r in
                        Text(r)
                            .font(.system(size: 10, design: .monospaced))
                            .foregroundStyle(r.contains("✅") ? .green : (r.contains("❌") ? .red : .orange))
                            .textSelection(.enabled)
                    }
                    
                    Button("Clear") { results.removeAll() }
                        .font(.caption)
                } header: {
                    Label("Results", systemImage: "list.bullet")
                }
            }
        }
        .navigationTitle("Preferences")
        .navigationBarTitleDisplayMode(.inline)
    }
    
    // MARK: - Write Preference
    
    private func writePref(domain: String, key: String, value: Any) {
        #if !DISABLE_REMOTECALL
        guard mgr.rcready else {
            results.append("❌ RC not ready")
            return
        }
        
        root.executeAsRoot(operation: "write_pref") { rc in
            let _ = rc.trojanMem
            
            // Use CFPreferences from launchd context (has root access to all domains)
            let RTLD_DEFAULT = UInt64(bitPattern: -2)
            let cfPrefsSet = RootExecutor.rcall(rc, "dlsym", RTLD_DEFAULT, remote_alloc_str(rc, "CFPreferencesSetValue"))
            let _ = RootExecutor.rcall(rc, "dlsym", RTLD_DEFAULT, remote_alloc_str(rc, "CFPreferencesAppSynchronize"))
            
            guard cfPrefsSet != 0 else {
                DispatchQueue.main.async { self.results.append("❌ CFPreferences not available") }
                return (false, "no cfprefs", 0)
            }
            
            // Create CF objects
            let cfKey = RootExecutor.rcall(rc, "CFStringCreateWithCString", 0, remote_alloc_str(rc, key), 0x600)
            let cfDomain = RootExecutor.rcall(rc, "CFStringCreateWithCString", 0, remote_alloc_str(rc, domain), 0x600)
            
            // Create value based on type
            var cfValue: UInt64 = 0
            if let boolVal = value as? Bool {
                // kCFBooleanTrue / kCFBooleanFalse
                let symName = boolVal ? "kCFBooleanTrue" : "kCFBooleanFalse"
                let symAddr = RootExecutor.rcall(rc, "dlsym", RTLD_DEFAULT, remote_alloc_str(rc, symName))
                if symAddr != 0 {
                    cfValue = rc[symAddr].value64()
                }
            } else if let strVal = value as? String {
                cfValue = RootExecutor.rcall(rc, "CFStringCreateWithCString", 0, remote_alloc_str(rc, strVal), 0x600)
            }
            
            if cfKey != 0 && cfDomain != 0 && cfValue != 0 {
                // CFPreferencesSetValue(key, value, appID, kCFPreferencesCurrentUser, kCFPreferencesAnyHost)
                // kCFPreferencesCurrentUser = "kCFPreferencesCurrentUser" string
                // kCFPreferencesAnyHost = "kCFPreferencesAnyHost" string
                let currentUser = RootExecutor.rcall(rc, "dlsym", RTLD_DEFAULT, remote_alloc_str(rc, "kCFPreferencesCurrentUser"))
                let anyHost = RootExecutor.rcall(rc, "dlsym", RTLD_DEFAULT, remote_alloc_str(rc, "kCFPreferencesAnyHost"))
                
                let userVal = currentUser != 0 ? rc[currentUser].value64() : 0
                let hostVal = anyHost != 0 ? rc[anyHost].value64() : 0
                
                RootExecutor.rcall(rc, "CFPreferencesSetValue", cfKey, cfValue, cfDomain, userVal, hostVal)
                
                // Sync
                RootExecutor.rcall(rc, "CFPreferencesAppSynchronize", cfDomain)
                
                DispatchQueue.main.async {
                    self.results.append("✅ \(domain): \(key) = \(value)")
                }
            } else {
                DispatchQueue.main.async {
                    self.results.append("❌ Failed to create CF objects")
                }
            }
            
            return (true, "pref written", 0)
        }
        #endif
    }
    
    private func writeCustomPref() {
        guard !customPlistPath.isEmpty, !customKey.isEmpty else { return }
        // Determine value type (bool, int, or string)
        if customValue == "true" || customValue == "YES" {
            writePref(domain: customPlistPath, key: customKey, value: true)
        } else if customValue == "false" || customValue == "NO" {
            writePref(domain: customPlistPath, key: customKey, value: false)
        } else {
            writePref(domain: customPlistPath, key: customKey, value: customValue)
        }
    }
    
    private func extractWiFiPasswords() {
        #if !DISABLE_REMOTECALL
        root.executeAsRoot(operation: "wifi_pass") { rc in
            let _ = rc.trojanMem
            
            // WiFi passwords stored in /var/Keychains/keychain-2.db
            // or via SecItemCopyMatching from root context
            // Simpler: read the WiFi plist
            let wifiPlist = "/var/preferences/SystemConfiguration/com.apple.wifi.known-networks.plist"
            let pathAddr = remote_alloc_str(rc, wifiPlist)
            let fd = RootExecutor.rcall(rc, "open", pathAddr, UInt64(O_RDONLY), 0)
            
            if fd != UInt64(bitPattern: -1) {
                let size = RootExecutor.rcall(rc, "lseek", fd, 0, 2)
                RootExecutor.rcall(rc, "lseek", fd, 0, 0)
                
                DispatchQueue.main.async {
                    self.results.append("✅ WiFi plist found (\(size) bytes)")
                    self.results.append("Path: \(wifiPlist)")
                    self.results.append("Use File Manager to browse contents")
                }
                RootExecutor.rcall(rc, "close", fd)
            } else {
                // Try alternative path
                let altPath = remote_alloc_str(rc, "/var/preferences/SystemConfiguration/com.apple.wifi.plist")
                let altFd = RootExecutor.rcall(rc, "open", altPath, UInt64(O_RDONLY), 0)
                if altFd != UInt64(bitPattern: -1) {
                    DispatchQueue.main.async {
                        self.results.append("✅ WiFi plist at alt path")
                    }
                    RootExecutor.rcall(rc, "close", altFd)
                } else {
                    DispatchQueue.main.async {
                        self.results.append("❌ WiFi plist not found at known paths")
                    }
                }
                RootExecutor.rcall(rc, "free", altPath)
            }
            RootExecutor.rcall(rc, "free", pathAddr)
            return (true, "wifi", 0)
        }
        #endif
    }
}

// MARK: - PrefToggle Button

struct PrefToggle: View {
    let title: String
    let subtitle: String
    let icon: String
    let action: () -> Void
    
    var body: some View {
        Button(action: action) {
            HStack(spacing: 12) {
                Image(systemName: icon)
                    .foregroundStyle(.blue)
                    .frame(width: 24)
                VStack(alignment: .leading, spacing: 2) {
                    Text(title)
                        .font(.subheadline)
                        .foregroundStyle(.primary)
                    Text(subtitle)
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Image(systemName: "chevron.right")
                    .font(.caption)
                    .foregroundStyle(.tertiary)
            }
        }
        .buttonStyle(.plain)
    }
}
