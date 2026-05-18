//
//  RootDashboardView.swift
//  DSPloit
//
//  Main dashboard — clean, visual, informative
//

import SwiftUI

struct RootDashboardView: View {
    @ObservedObject private var root = RootExecutor.shared
    @ObservedObject private var mgr = dspmgr.shared
    @ObservedObject private var jb = JailbreakEngine.shared
    
    @State private var showRemoveAlert = false
    
    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 16) {
                    // Status Card
                    StatusCard()
                    
                    // Root Tools Grid — show when RC ready
                    if mgr.rcready || root.rootConfirmed || jb.isJailbroken {
                        ToolsGrid()
                    }
                    
                    // About
                    AboutSection()
                }
                .padding(.horizontal, 16)
                .padding(.top, 8)
            }
            .navigationTitle("DSPloit")
            .background(Color(.systemGroupedBackground))
        }
    }
    
    // MARK: - Status Card
    
    @ViewBuilder
    private func StatusCard() -> some View {
        VStack(spacing: 12) {
            // Main status
            HStack(spacing: 14) {
                ZStack {
                    Circle()
                        .fill(statusColor.opacity(0.15))
                        .frame(width: 56, height: 56)
                    
                    if jb.isRunning {
                        Circle()
                            .trim(from: 0, to: jb.progress)
                            .stroke(statusColor, style: StrokeStyle(lineWidth: 3, lineCap: .round))
                            .frame(width: 56, height: 56)
                            .rotationEffect(.degrees(-90))
                    }
                    
                    Image(systemName: statusIcon)
                        .font(.system(size: 24))
                        .foregroundStyle(statusColor)
                }
                
                VStack(alignment: .leading, spacing: 4) {
                    Text(statusTitle)
                        .font(.headline)
                    Text(statusSubtitle)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                
                Spacer()
            }
            
            // Detail info (when jailbroken)
            if root.rootConfirmed || jb.isJailbroken {
                Divider()
                
                LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 8) {
                    InfoChip(label: "UID", value: "0 (root)", color: .green)
                    InfoChip(label: "Device", value: deviceModel(), color: .blue)
                    InfoChip(label: "Kernel", value: String(format: "0x%llx", mgr.kernbase), color: .orange)
                    InfoChip(label: "Slide", value: String(format: "0x%x", mgr.kernslide), color: .purple)
                }
            }
            
            // Progress steps (when running)
            if jb.isRunning {
                Divider()
                VStack(alignment: .leading, spacing: 6) {
                    MiniStep("Kernel Exploit", done: mgr.dsready, active: jb.state == .exploiting)
                    MiniStep("VFS + Sandbox", done: mgr.vfsready && mgr.sbxready, active: jb.state == .initializing)
                    MiniStep("RemoteCall", done: mgr.rcready, active: jb.state == .connectingRC)
                    MiniStep("Root Access", done: root.rootConfirmed, active: jb.state == .verifyingRoot)
                    MiniStep("Bootstrap", done: jb.isJailbroken, active: jb.state == .bootstrapping)
                }
            }
            
            // Error
            if let error = jb.errorMessage {
                Text(error)
                    .font(.caption)
                    .foregroundStyle(.red)
            }
        }
        .padding(16)
        .background(
            RoundedRectangle(cornerRadius: 16)
                .fill(Color(.secondarySystemGroupedBackground))
        )
    }
    
    // MARK: - Tools Grid
    
    @ViewBuilder
    private func ToolsGrid() -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("ROOT TOOLS")
                .font(.caption.bold())
                .foregroundStyle(.secondary)
                .padding(.leading, 4)
            
            LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 12) {
                NavigationLink(destination: RootShellView()) {
                    ToolCard(icon: "terminal.fill", title: "Shell", color: .red)
                }
                NavigationLink(destination: RootFileManagerView()) {
                    ToolCard(icon: "folder.fill", title: "Files", color: .blue)
                }
                NavigationLink(destination: RootProcessView()) {
                    ToolCard(icon: "play.circle.fill", title: "Processes", color: .orange)
                }
                NavigationLink(destination: TweaksManagerView()) {
                    ToolCard(icon: "paintbrush.fill", title: "Tweaks", color: .pink)
                }
                NavigationLink(destination: BootstrapView()) {
                    ToolCard(icon: "shippingbox.fill", title: "Bootstrap", color: .cyan)
                }
                NavigationLink(destination: RootPersistenceView()) {
                    ToolCard(icon: "arrow.clockwise", title: "Persist", color: .purple)
                }
                NavigationLink(destination: AMFIExperimentView()) {
                    ToolCard(icon: "flask.fill", title: "AMFI Lab", color: .yellow)
                }
            }
        }
    }
    
    // MARK: - Remove Section
    
    @ViewBuilder
    private func RemoveSection() -> some View {
        Button(action: { showRemoveAlert = true }) {
            HStack {
                Image(systemName: "trash.circle.fill")
                Text("Remove Jailbreak")
                Spacer()
                Image(systemName: "chevron.right")
                    .font(.caption)
            }
            .foregroundStyle(.red)
            .padding(14)
            .background(
                RoundedRectangle(cornerRadius: 12)
                    .fill(Color.red.opacity(0.08))
            )
        }
        .alert("Remove Jailbreak?", isPresented: $showRemoveAlert) {
            Button("Cancel", role: .cancel) {}
            Button("Remove", role: .destructive) { removeJailbreak() }
        } message: {
            Text("This will delete /var/jb/, remove LaunchDaemons, and clean all jailbreak traces. You'll need to re-jailbreak after.")
        }
    }
    
    // MARK: - About
    
    @ViewBuilder
    private func AboutSection() -> some View {
        VStack(spacing: 4) {
            Text("DSPloit")
                .font(.caption.bold())
                .foregroundStyle(.secondary)
            Text("iOS 18.2 • iPhone XR (A12) • Based on lara by royan")
                .font(.caption2)
                .foregroundStyle(.tertiary)
        }
        .padding(.top, 8)
    }
    
    // MARK: - Remove Jailbreak
    
    private func removeJailbreak() {
        // Immediately hide tools (don't wait for async)
        jb.isJailbroken = false
        root.rootConfirmed = false
        
        #if !DISABLE_REMOTECALL
        // Destroy RC to fully "unjailbreak"
        mgr.rcdestroy()
        
        root.executeAsRoot(operation: "remove_jailbreak") { rc in
            let dirs = [
                "/var/jb/Library/LaunchDaemons",
                "/var/jb/Library/TweakInject",
                "/var/jb/Library/MobileSubstrate",
                "/var/jb/Library/PreferenceBundles",
                "/var/jb/Library/PreferenceLoader",
                "/var/jb/Library/Frameworks",
                "/var/jb/Library",
                "/var/jb/usr/bin", "/var/jb/usr/lib", "/var/jb/usr/sbin",
                "/var/jb/usr/local/bin", "/var/jb/usr/local", "/var/jb/usr",
                "/var/jb/etc", "/var/jb/tmp",
                "/var/jb/var/lib/dpkg/info", "/var/jb/var/lib/dpkg",
                "/var/jb/var/lib", "/var/jb/var/cache/apt",
                "/var/jb/var/cache", "/var/jb/var",
                "/var/jb/.dsploit_bootstrapped", "/var/jb",
            ]
            
            var removed = 0
            for path in dirs {
                let p = remote_alloc_str(rc, path)
                var r = RootExecutor.rcall(rc, "rmdir", p)
                if r != 0 { r = RootExecutor.rcall(rc, "unlink", p) }
                if r == 0 { removed += 1 }
                RootExecutor.rcall(rc, "free", p)
            }
            
            DispatchQueue.main.async {
                UserDefaults.standard.removeObject(forKey: "KRWPrimitive")
            }
            
            return (true, "Cleaned \(removed) items", UInt64(removed))
        }
        #endif
    }
    
    // MARK: - Helpers
    
    private func deviceModel() -> String {
        var size: Int = 0
        sysctlbyname("hw.machine", nil, &size, nil, 0)
        var machine = [CChar](repeating: 0, count: size)
        sysctlbyname("hw.machine", &machine, &size, nil, 0)
        return String(cString: machine)
    }
    
    private var statusColor: Color {
        if jb.isJailbroken || root.rootConfirmed { return .green }
        if jb.isRunning { return .blue }
        if jb.state == .failed { return .red }
        if mgr.dsready { return .orange }
        return .secondary
    }
    
    private var statusIcon: String {
        if jb.isJailbroken || root.rootConfirmed { return "lock.open.fill" }
        if jb.isRunning { return "bolt.circle.fill" }
        if jb.state == .failed { return "xmark.circle.fill" }
        if mgr.dsready { return "bolt.shield.fill" }
        return "lock.fill"
    }
    
    private var statusTitle: String {
        if jb.isJailbroken || root.rootConfirmed { return "Jailbroken" }
        if jb.isRunning { return jb.state.rawValue }
        if jb.state == .failed { return "Failed" }
        if mgr.dsready { return "Exploited" }
        return "Not Jailbroken"
    }
    
    private var statusSubtitle: String {
        if jb.isJailbroken || root.rootConfirmed { return "uid=0 • full root access • launchd" }
        if jb.isRunning { return "Please wait..." }
        if jb.state == .failed { return jb.errorMessage ?? "Try again" }
        if mgr.dsready { return "Kernel access active" }
        return "Waiting for auto-jailbreak..."
    }
}

// MARK: - Sub Components

struct InfoChip: View {
    let label: String
    let value: String
    let color: Color
    
    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(label)
                .font(.system(size: 9, weight: .medium))
                .foregroundStyle(.secondary)
            Text(value)
                .font(.system(size: 11, weight: .semibold, design: .monospaced))
                .foregroundStyle(color)
                .lineLimit(1)
                .minimumScaleFactor(0.7)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(8)
        .background(
            RoundedRectangle(cornerRadius: 8)
                .fill(color.opacity(0.06))
        )
    }
}

struct ToolCard: View {
    let icon: String
    let title: String
    let color: Color
    
    var body: some View {
        VStack(spacing: 8) {
            Image(systemName: icon)
                .font(.system(size: 22))
                .foregroundStyle(color)
            Text(title)
                .font(.caption.bold())
                .foregroundStyle(.primary)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 16)
        .background(
            RoundedRectangle(cornerRadius: 12)
                .fill(Color(.secondarySystemGroupedBackground))
        )
    }
}

struct MiniStep: View {
    let label: String
    let done: Bool
    let active: Bool
    
    init(_ label: String, done: Bool, active: Bool) {
        self.label = label
        self.done = done
        self.active = active
    }
    
    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: done ? "checkmark.circle.fill" : (active ? "circle.dotted" : "circle"))
                .font(.caption)
                .foregroundStyle(done ? Color.green : (active ? Color.blue : Color.secondary))
            Text(label)
                .font(.caption)
                .foregroundStyle(done ? Color.primary : (active ? Color.blue : Color.secondary))
            Spacer()
            if active {
                ProgressView().scaleEffect(0.5)
            }
        }
    }
}

// Keep ToolRow for backward compat
struct ToolRow: View {
    let icon: String
    let title: String
    let subtitle: String
    let color: Color
    
    var body: some View {
        HStack(spacing: 14) {
            ZStack {
                RoundedRectangle(cornerRadius: 10)
                    .fill(color.opacity(0.12))
                    .frame(width: 40, height: 40)
                Image(systemName: icon)
                    .font(.system(size: 18))
                    .foregroundStyle(color)
            }
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.subheadline.bold())
                Text(subtitle)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(.vertical, 4)
    }
}
