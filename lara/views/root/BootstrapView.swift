//
//  BootstrapView.swift
//  DSPloit
//
//  Bootstrap setup — /var/jb structure, SSH, package manager
//

import SwiftUI

struct BootstrapView: View {
    @ObservedObject private var root = RootExecutor.shared
    @ObservedObject private var mgr = dspmgr.shared
    
    @State private var bootstrapStatus: [BootstrapItem] = []
    @State private var sshPort = "2222"
    @State private var sshPassword = "alpine"
    
    struct BootstrapItem: Identifiable {
        let id = UUID()
        let name: String
        let path: String
        var exists: Bool = false
    }
    
    var body: some View {
        List {
            // Status
            Section {
                Button(action: checkBootstrap) {
                    Label("Check Bootstrap Status", systemImage: "magnifyingglass")
                }
                .disabled(!mgr.rcready || root.isExecuting)
                
                Button(action: setupBootstrap) {
                    Label("Setup Bootstrap (/var/jb)", systemImage: "shippingbox.fill")
                        .foregroundStyle(.orange)
                }
                .disabled(!mgr.rcready || root.isExecuting)
            } header: {
                Label("Bootstrap", systemImage: "shippingbox")
            } footer: {
                Text("Creates /var/jb/ directory structure used by rootless jailbreaks (Dopamine-compatible).")
            }
            
            // Directory status
            if !bootstrapStatus.isEmpty {
                Section {
                    ForEach(bootstrapStatus) { item in
                        HStack {
                            Image(systemName: item.exists ? "checkmark.circle.fill" : "xmark.circle")
                                .foregroundStyle(item.exists ? .green : .secondary)
                            VStack(alignment: .leading) {
                                Text(item.name)
                                    .font(.caption.bold())
                                Text(item.path)
                                    .font(.system(size: 9, design: .monospaced))
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }
                } header: {
                    Label("Directories", systemImage: "folder")
                }
            }
            
            // SSH Setup
            Section {
                HStack {
                    Text("Port")
                    Spacer()
                    TextField("2222", text: $sshPort)
                        .font(.system(.body, design: .monospaced))
                        .multilineTextAlignment(.trailing)
                        .frame(width: 80)
                }
                
                HStack {
                    Text("Password")
                    Spacer()
                    TextField("alpine", text: $sshPassword)
                        .font(.system(.body, design: .monospaced))
                        .multilineTextAlignment(.trailing)
                        .frame(width: 120)
                }
                
                Button(action: installSSHDaemon) {
                    Label("Install SSH LaunchDaemon", systemImage: "network")
                        .foregroundStyle(.cyan)
                }
                .disabled(!mgr.rcready || root.isExecuting)
                
                Text("Installs dropbear SSH server config. Binary must be placed at /var/jb/usr/bin/dropbear separately.")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            } header: {
                Label("SSH Server", systemImage: "terminal")
            } footer: {
                Text("After install, connect via: ssh root@<device-ip> -p \(sshPort)")
            }
            
            // Package Manager
            Section {
                Button(action: setupPackageManager) {
                    Label("Setup Package Manager Paths", systemImage: "shippingbox.circle")
                        .foregroundStyle(.purple)
                }
                .disabled(!mgr.rcready || root.isExecuting)
                
                Text("Creates dpkg/apt directory structure at /var/jb/. Actual binaries need to be installed separately (e.g. via Sileo bootstrap).")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            } header: {
                Label("Package Manager", systemImage: "shippingbox.circle")
            }
            
            // Tweak Injection
            Section {
                Button(action: setupTweakInjection) {
                    Label("Setup Tweak Injection Paths", systemImage: "puzzlepiece.extension")
                        .foregroundStyle(.green)
                }
                .disabled(!mgr.rcready || root.isExecuting)
                
                VStack(alignment: .leading, spacing: 4) {
                    Text("Creates directories for:")
                        .font(.caption2.bold())
                    Text("• /var/jb/Library/TweakInject/ (dylibs)")
                        .font(.caption2)
                    Text("• /var/jb/Library/MobileSubstrate/ (substrate)")
                        .font(.caption2)
                    Text("• /var/jb/Library/PreferenceBundles/ (settings)")
                        .font(.caption2)
                }
                .foregroundStyle(.secondary)
            } header: {
                Label("Tweak Injection", systemImage: "puzzlepiece.extension")
            }
            
            // Result
            if let r = root.lastResult {
                Section {
                    HStack {
                        Image(systemName: r.success ? "checkmark.circle.fill" : "xmark.circle.fill")
                            .foregroundStyle(r.success ? .green : .red)
                        Text(r.message)
                            .font(.system(size: 11, design: .monospaced))
                    }
                } header: {
                    Label("Last Result", systemImage: "info.circle")
                }
            }
        }
        .navigationTitle("Bootstrap")
        .navigationBarTitleDisplayMode(.inline)
    }
    
    // MARK: - Actions
    
    private func checkBootstrap() {
        #if !DISABLE_REMOTECALL
        root.executeAsRoot(operation: "check_bootstrap") { rc in
            let paths = [
                ("Root", "/var/jb"),
                ("usr/bin", "/var/jb/usr/bin"),
                ("usr/lib", "/var/jb/usr/lib"),
                ("etc", "/var/jb/etc"),
                ("Library", "/var/jb/Library"),
                ("LaunchDaemons", "/var/jb/Library/LaunchDaemons"),
                ("TweakInject", "/var/jb/Library/TweakInject"),
                ("dpkg", "/var/jb/var/lib/dpkg"),
            ]
            
            var items: [BootstrapItem] = []
            for (name, path) in paths {
                let pathAddr = remote_alloc_str(rc, path)
                // Use access() to check existence
                let exists = RootExecutor.rcall(rc, "access", pathAddr, 0) == 0
                items.append(BootstrapItem(name: name, path: path, exists: exists))
                RootExecutor.rcall(rc, "free", pathAddr)
            }
            
            DispatchQueue.main.async {
                self.bootstrapStatus = items
            }
            
            let count = items.filter { $0.exists }.count
            return (true, "\(count)/\(items.count) directories exist", UInt64(count))
        }
        #endif
    }
    
    private func setupBootstrap() {
        #if !DISABLE_REMOTECALL
        root.executeAsRoot(operation: "setup_bootstrap") { rc in
            let dirs = [
                "/var/jb",
                "/var/jb/usr",
                "/var/jb/usr/bin",
                "/var/jb/usr/lib",
                "/var/jb/usr/sbin",
                "/var/jb/usr/local",
                "/var/jb/usr/local/bin",
                "/var/jb/etc",
                "/var/jb/tmp",
                "/var/jb/var",
                "/var/jb/var/lib",
                "/var/jb/var/lib/dpkg",
                "/var/jb/var/lib/dpkg/info",
                "/var/jb/var/cache",
                "/var/jb/var/cache/apt",
                "/var/jb/Library",
                "/var/jb/Library/LaunchDaemons",
                "/var/jb/Library/TweakInject",
                "/var/jb/Library/MobileSubstrate",
                "/var/jb/Library/MobileSubstrate/DynamicLibraries",
                "/var/jb/Library/PreferenceBundles",
                "/var/jb/Library/PreferenceLoader",
                "/var/jb/Library/Frameworks",
            ]
            
            for dir in dirs {
                let pathAddr = remote_alloc_str(rc, dir)
                RootExecutor.rcall(rc, "mkdir", pathAddr, 0o755)
                RootExecutor.rcall(rc, "free", pathAddr)
            }
            
            // Create dpkg status file (empty)
            let statusPath = remote_alloc_str(rc, "/var/jb/var/lib/dpkg/status")
            let fd = RootExecutor.rcall(rc, "open", statusPath, UInt64(O_WRONLY | O_CREAT), 0o644)
            if fd != UInt64(bitPattern: -1) {
                RootExecutor.rcall(rc, "close", fd)
            }
            RootExecutor.rcall(rc, "free", statusPath)
            
            return (true, "Bootstrap created (\(dirs.count) directories)", UInt64(dirs.count))
        }
        #endif
    }
    
    private func installSSHDaemon() {
        let plist = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>Label</key>
            <string>com.dsploit.dropbear</string>
            <key>ProgramArguments</key>
            <array>
                <string>/var/jb/usr/bin/dropbear</string>
                <string>-F</string>
                <string>-R</string>
                <string>-p</string>
                <string>\(sshPort)</string>
            </array>
            <key>RunAtLoad</key>
            <true/>
            <key>KeepAlive</key>
            <true/>
            <key>UserName</key>
            <string>root</string>
        </dict>
        </plist>
        """
        
        root.writeFileAsRoot(
            path: "/var/jb/Library/LaunchDaemons/com.dsploit.dropbear.plist",
            content: Data(plist.utf8)
        )
    }
    
    private func setupPackageManager() {
        #if !DISABLE_REMOTECALL
        root.executeAsRoot(operation: "setup_pkgmgr") { rc in
            // Create apt sources list
            let sourcesDir = remote_alloc_str(rc, "/var/jb/etc/apt/sources.list.d")
            RootExecutor.rcall(rc, "mkdir", sourcesDir, 0o755)
            RootExecutor.rcall(rc, "free", sourcesDir)
            
            // Write default sources
            let sourcesPath = remote_alloc_str(rc, "/var/jb/etc/apt/sources.list.d/default.list")
            let fd = RootExecutor.rcall(rc, "open", sourcesPath, UInt64(O_WRONLY | O_CREAT | O_TRUNC), 0o644)
            if fd != UInt64(bitPattern: -1) {
                let content = remote_alloc_str(rc, "deb https://repo.chariz.com/ ./\ndeb https://havoc.app/ ./\n")
                RootExecutor.rcall(rc, "write", fd, content, 52)
                RootExecutor.rcall(rc, "close", fd)
                RootExecutor.rcall(rc, "free", content)
            }
            RootExecutor.rcall(rc, "free", sourcesPath)
            
            return (true, "Package manager paths created", 0)
        }
        #endif
    }
    
    private func setupTweakInjection() {
        #if !DISABLE_REMOTECALL
        root.executeAsRoot(operation: "setup_tweaks") { rc in
            let dirs = [
                "/var/jb/Library/TweakInject",
                "/var/jb/Library/MobileSubstrate",
                "/var/jb/Library/MobileSubstrate/DynamicLibraries",
                "/var/jb/Library/PreferenceBundles",
                "/var/jb/Library/PreferenceLoader",
                "/var/jb/Library/PreferenceLoader/Preferences",
            ]
            
            for dir in dirs {
                let pathAddr = remote_alloc_str(rc, dir)
                RootExecutor.rcall(rc, "mkdir", pathAddr, 0o755)
                RootExecutor.rcall(rc, "free", pathAddr)
            }
            
            return (true, "Tweak injection paths created", UInt64(dirs.count))
        }
        #endif
    }
}
