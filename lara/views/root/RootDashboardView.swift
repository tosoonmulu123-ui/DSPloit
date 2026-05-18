//
//  RootDashboardView.swift
//  DSPloit
//
//  Main dashboard for root-level operations
//

import SwiftUI

struct RootDashboardView: View {
    @ObservedObject private var root = RootExecutor.shared
    @ObservedObject private var mgr = dspmgr.shared
    @State private var proofResult = ""
    @State private var proofSuccess = false
    
    var body: some View {
        NavigationStack {
            List {
                // Status
                Section {
                    HStack(spacing: 14) {
                        ZStack {
                            Circle()
                                .fill(statusColor.opacity(0.15))
                                .frame(width: 50, height: 50)
                            Image(systemName: statusIcon)
                                .font(.title2)
                                .foregroundStyle(statusColor)
                        }
                        VStack(alignment: .leading, spacing: 4) {
                            Text(statusTitle)
                                .font(.headline)
                            Text(statusSubtitle)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                    .padding(.vertical, 4)
                }
                
                // Root Tools
                Section {
                    NavigationLink(destination: OneTapJailbreakView()) {
                        ToolRow(icon: "bolt.fill", title: "One-Tap Jailbreak", subtitle: "Auto-chain: exploit → root in one tap", color: .red)
                    }
                    
                    NavigationLink(destination: RootShellView()) {
                        ToolRow(icon: "terminal.fill", title: "Root Shell", subtitle: "Execute commands as uid=0", color: .orange)
                    }
                    
                    NavigationLink(destination: RootFileManagerView()) {
                        ToolRow(icon: "folder.fill", title: "File Manager", subtitle: "Read/write files with root access", color: .blue)
                    }
                    
                    NavigationLink(destination: RootProcessView()) {
                        ToolRow(icon: "play.circle.fill", title: "Process Manager", subtitle: "Spawn & manage root processes", color: .green)
                    }
                    
                    NavigationLink(destination: RootPersistenceView()) {
                        ToolRow(icon: "arrow.clockwise.circle.fill", title: "Persistence", subtitle: "LaunchDaemons, KRW stash, boot hooks", color: .purple)
                    }
                    
                    NavigationLink(destination: BootstrapView()) {
                        ToolRow(icon: "shippingbox.fill", title: "Bootstrap", subtitle: "Setup /var/jb, package manager, SSH", color: .cyan)
                    }
                    
                    NavigationLink(destination: TweaksManagerView()) {
                        ToolRow(icon: "paintbrush.fill", title: "Tweaks", subtitle: "SpringBoard mods, status bar, dock", color: .pink)
                    }
                } header: {
                    Text("Root Tools")
                }
                
                // Quick Actions
                Section {
                    Button(action: { root.verifyRoot() }) {
                        HStack {
                            Label("Verify Root", systemImage: "checkmark.shield")
                            Spacer()
                            if root.isExecuting {
                                ProgressView()
                            } else if root.rootConfirmed {
                                Image(systemName: "checkmark.circle.fill")
                                    .foregroundStyle(.green)
                            }
                        }
                    }
                    .disabled(!mgr.rcready || root.isExecuting)
                    
                    Button(action: { proofOfRoot() }) {
                        HStack {
                            Label("Proof of Root", systemImage: "doc.badge.checkmark")
                            Spacer()
                            if !proofResult.isEmpty {
                                Image(systemName: proofSuccess ? "checkmark.circle.fill" : "xmark.circle.fill")
                                    .foregroundStyle(proofSuccess ? .green : .red)
                            }
                        }
                    }
                    .disabled(!mgr.rcready || root.isExecuting)
                    
                    if !proofResult.isEmpty {
                        Text(proofResult)
                            .font(.system(size: 10, design: .monospaced))
                            .foregroundStyle(proofSuccess ? .green : .red)
                            .textSelection(.enabled)
                    }
                } header: {
                    Text("Quick Actions")
                } footer: {
                    Text("Proof of Root writes a file to /var/root/ and reads it back — only possible as uid=0.")
                }
                
                // Credits
                Section {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("DSPloit")
                            .font(.subheadline.bold())
                        Text("iOS 18.2 root exploit — iPhone XR (A12)")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        Text("Based on [lara](https://github.com/royan) by royan")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                } header: {
                    Text("About")
                }
            }
            .navigationTitle("DSPloit")
        }
    }
    
    // MARK: - Proof of Root
    
    private func proofOfRoot() {
        let timestamp = Int(Date().timeIntervalSince1970)
        let content = "DSPloit root proof — written at \(timestamp) by uid=0"
        let path = "/var/root/dsploit_proof_\(timestamp).txt"
        
        proofResult = "Writing to \(path)..."
        proofSuccess = false
        
        #if !DISABLE_REMOTECALL
        root.executeAsRoot(operation: "proof_of_root") { rc in
            // Step 1: Write file to /var/root/ (only root can write here)
            let pathAddr = remote_alloc_str(rc, path)
            let flags = UInt64(O_WRONLY | O_CREAT | O_TRUNC)
            let fd = RootExecutor.rcall(rc, "open", pathAddr, flags, 0o644)
            
            guard fd != UInt64(bitPattern: -1) else {
                let err = remote_errno(rc)
                RootExecutor.rcall(rc, "free", pathAddr)
                DispatchQueue.main.async {
                    self.proofResult = "❌ open() failed: errno=\(err)"
                    self.proofSuccess = false
                }
                return (false, "open failed: errno=\(err)", 0)
            }
            
            // Write content
            let contentAddr = remote_alloc_str(rc, content)
            let written = RootExecutor.rcall(rc, "write", fd, contentAddr, UInt64(content.utf8.count))
            RootExecutor.rcall(rc, "close", fd)
            
            // Step 2: Read it back to verify
            let fd2 = RootExecutor.rcall(rc, "open", pathAddr, UInt64(O_RDONLY), 0)
            var readBack = ""
            if fd2 != UInt64(bitPattern: -1) {
                let bufAddr = rc.trojanMem + 0x800
                let n = RootExecutor.rcall(rc, "read", fd2, bufAddr, 256)
                if n > 0 {
                    var buf = [UInt8](repeating: 0, count: Int(n))
                    rc.remoteRead(bufAddr, to: &buf, size: n)
                    readBack = String(bytes: buf, encoding: .utf8) ?? ""
                }
                RootExecutor.rcall(rc, "close", fd2)
            }
            
            // Step 3: Get uid to confirm
            let uid = RootExecutor.rcall(rc, "getuid")
            
            RootExecutor.rcall(rc, "free", pathAddr)
            RootExecutor.rcall(rc, "free", contentAddr)
            
            let success = written > 0 && readBack.contains("DSPloit root proof") && uid == 0
            let msg = """
            uid=\(uid) | wrote \(written) bytes
            path: \(path)
            readback: \(readBack.prefix(60))
            """
            
            DispatchQueue.main.async {
                self.proofResult = msg
                self.proofSuccess = success
            }
            
            return (success, msg, written)
        }
        #endif
    }
    
    private var statusColor: Color {
        if root.rootConfirmed { return .green }
        if mgr.rcready { return .blue }
        if mgr.dsready { return .orange }
        return .secondary
    }
    
    private var statusIcon: String {
        if root.rootConfirmed { return "person.badge.key.fill" }
        if mgr.rcready { return "link.circle.fill" }
        if mgr.dsready { return "bolt.shield.fill" }
        return "lock.fill"
    }
    
    private var statusTitle: String {
        if root.rootConfirmed { return "Root Active" }
        if mgr.rcready { return "RemoteCall Ready" }
        if mgr.dsready { return "Kernel Exploited" }
        return "Not Exploited"
    }
    
    private var statusSubtitle: String {
        if root.rootConfirmed { return "uid=0 via launchd — full access" }
        if mgr.rcready { return "SpringBoard connected — tap Verify Root" }
        if mgr.dsready { return "KRW active — initialize system next" }
        return "Run exploit from Setup tab"
    }
}

// MARK: - Reusable Row

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
