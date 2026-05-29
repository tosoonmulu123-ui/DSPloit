//
//  ContentView.swift
//  DSPloit — Main tab
//

import SwiftUI

struct ContentView: View {
    @EnvironmentObject private var mgr: dspmgr
    @ObservedObject private var jb = JailbreakEngine.shared
    @ObservedObject private var root = RootExecutor.shared
    
    @State private var showSettings = false
    @State private var showGuide = false

    init() { globallogger.capture() }
    
    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 16) {
                    // Status card
                    statusCard
                    
                    // Jailbreak button
                    jailbreakButton
                    
                    // Progress + live log
                    if jb.isRunning {
                        progressSection
                    }
                    
                    // Error
                    if let error = jb.errorMessage, !jb.isRunning {
                        errorCard(error)
                    }
                    
                    // Post-jailbreak status
                    if isJailbroken && !jb.isRunning {
                        subsystemStatus
                    }
                }
                .padding(.horizontal, 16)
                .padding(.top, 8)
            }
            .background(Color(.systemGroupedBackground))
            .navigationTitle("DSPloit")
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button { showGuide = true } label: {
                        Image(systemName: "questionmark.circle")
                            .foregroundStyle(.secondary)
                    }
                }
                ToolbarItem(placement: .topBarTrailing) {
                    HStack(spacing: 14) {
                        Button { mgr.showLogs.toggle() } label: {
                            Image(systemName: "terminal")
                                .foregroundStyle(.secondary)
                        }
                        Button { showSettings = true } label: {
                            Image(systemName: "gearshape")
                                .foregroundStyle(.secondary)
                        }
                    }
                }
            }
            .sheet(isPresented: $showSettings) { SettingsView() }
            .sheet(isPresented: $showGuide) { GuideView() }
        }
    }
    
    // MARK: - Status Card
    
    private var statusCard: some View {
        HStack(spacing: 14) {
            Circle()
                .fill(statusColor)
                .frame(width: 10, height: 10)
            
            VStack(alignment: .leading, spacing: 2) {
                Text(statusTitle)
                    .font(.system(size: 15, weight: .semibold))
                Text(statusSubtitle)
                    .font(.system(size: 12))
                    .foregroundStyle(.secondary)
            }
            
            Spacer()
            
            if isJailbroken {
                Text("✓")
                    .font(.system(size: 20, weight: .bold, design: .monospaced))
                    .foregroundStyle(.green)
            }
        }
        .padding(14)
        .background(RoundedRectangle(cornerRadius: 10).fill(Color(.secondarySystemGroupedBackground)))
    }
    
    // MARK: - Jailbreak Button
    
    @ViewBuilder
    private var jailbreakButton: some View {
        #if !DISABLE_REMOTECALL
        Button {
            guard !jb.isRunning else { return }
            UIImpactFeedbackGenerator(style: .medium).impactOccurred()
            if isJailbroken {
                jb.isJailbroken = false
                root.rootConfirmed = false
            }
            jb.runFullChain()
        } label: {
            HStack {
                Spacer()
                if jb.isRunning {
                    ProgressView().tint(.white)
                        .padding(.trailing, 6)
                }
                Text(isJailbroken ? "Re-Jailbreak" : (jb.isRunning ? "Working..." : "Jailbreak"))
                    .font(.system(size: 16, weight: .semibold))
                Spacer()
            }
            .foregroundStyle(.white)
            .padding(.vertical, 14)
            .background(
                RoundedRectangle(cornerRadius: 10)
                    .fill(jb.isRunning ? Color.gray : (isJailbroken ? Color.orange : Color.blue))
            )
        }
        .disabled(jb.isRunning)
        #else
        EmptyView()
        #endif
    }
    
    // MARK: - Progress Section
    
    private var progressSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            // Progress bar
            HStack(spacing: 10) {
                ProgressView(value: jb.progress)
                    .tint(.blue)
                Text("\(Int(jb.progress * 100))%")
                    .font(.system(size: 11, weight: .medium, design: .monospaced))
                    .foregroundStyle(.secondary)
            }
            
            // State
            Text(jb.state.rawValue)
                .font(.system(size: 12, weight: .medium))
                .foregroundStyle(.blue)
            
            // Live log (last 6 lines)
            VStack(alignment: .leading, spacing: 3) {
                ForEach(jb.log.suffix(6), id: \.self) { line in
                    HStack(alignment: .top, spacing: 6) {
                        Text("●")
                            .font(.system(size: 5))
                            .foregroundStyle(logDotColor(line))
                            .padding(.top, 5)
                        Text(line)
                            .font(.system(size: 10, design: .monospaced))
                            .foregroundStyle(logTextColor(line))
                            .lineLimit(2)
                    }
                }
            }
            .padding(10)
            .background(RoundedRectangle(cornerRadius: 8).fill(Color.black.opacity(0.85)))
        }
        .padding(14)
        .background(RoundedRectangle(cornerRadius: 10).fill(Color(.secondarySystemGroupedBackground)))
    }
    
    // MARK: - Error Card
    
    private func errorCard(_ error: String) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 8) {
                Image(systemName: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
                Text("Failed")
                    .font(.system(size: 14, weight: .semibold))
            }
            Text(error)
                .font(.system(size: 12, design: .monospaced))
                .foregroundStyle(.secondary)
            
            Button {
                jb.runFullChain()
            } label: {
                Text("Retry")
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundStyle(.white)
                    .padding(.horizontal, 20)
                    .padding(.vertical, 8)
                    .background(RoundedRectangle(cornerRadius: 6).fill(Color.blue))
            }
        }
        .padding(14)
        .background(RoundedRectangle(cornerRadius: 10).fill(Color(.secondarySystemGroupedBackground)))
    }
    
    // MARK: - Subsystem Status
    
    private var subsystemStatus: some View {
        VStack(spacing: 0) {
            ForEach(subsystems, id: \.label) { item in
                HStack {
                    Text(item.label)
                        .font(.system(size: 13))
                    Spacer()
                    Text(item.active ? "●" : "○")
                        .font(.system(size: 10))
                        .foregroundStyle(item.active ? .green : .secondary)
                }
                .padding(.vertical, 9)
                .padding(.horizontal, 14)
                if item.label != subsystems.last?.label {
                    Divider().padding(.leading, 14)
                }
            }
        }
        .background(RoundedRectangle(cornerRadius: 10).fill(Color(.secondarySystemGroupedBackground)))
    }
    
    private var subsystems: [(label: String, active: Bool)] {
        [
            ("Kernel R/W", mgr.dsready),
            ("Sandbox Escape", mgr.sbxready),
            ("RemoteCall", mgr.rcready),
            ("Root (uid=0)", root.rootConfirmed),
            ("VFS Access", mgr.vfsready),
        ]
    }
    
    // MARK: - Helpers
    
    private var isJailbroken: Bool { root.rootConfirmed || jb.isJailbroken }
    
    private var statusColor: Color {
        if isJailbroken { return .green }
        if jb.isRunning { return .blue }
        if jb.state == .failed { return .red }
        return .secondary
    }
    
    private var statusTitle: String {
        if isJailbroken { return "Jailbroken" }
        if jb.isRunning { return "In Progress" }
        if jb.state == .failed { return "Failed" }
        return "Locked"
    }
    
    private var statusSubtitle: String {
        if isJailbroken { return "Full root access active" }
        if jb.isRunning { return jb.state.rawValue }
        if jb.state == .failed { return "Tap Retry or Jailbreak again" }
        return "Tap Jailbreak to start"
    }
    
    private func logDotColor(_ line: String) -> Color {
        if line.contains("✅") || line.contains("🎉") { return .green }
        if line.contains("❌") { return .red }
        if line.contains("⚠️") { return .yellow }
        return .gray
    }
    
    private func logTextColor(_ line: String) -> Color {
        if line.contains("✅") || line.contains("🎉") { return .green }
        if line.contains("❌") { return .red }
        if line.contains("⚠️") { return .yellow }
        return Color(.init(white: 0.75, alpha: 1))
    }
    
    // MARK: - Respring
    
    private func safeRespring() {
        #if !DISABLE_REMOTECALL
        if mgr.rcready, let sb = mgr.sbProc {
            let sel = remote_sel(sb, "terminateWithSuccess")
            let app = remote_getClass(sb, "UIApplication")
            let shared = remote_msg(sb, app, remote_sel(sb, "sharedApplication"), 0, 0, 0, 0)
            remote_msg(sb, shared, sel, 0, 0, 0, 0)
            return
        }
        #endif
        if mgr.dsready {
            let sbProc = mgr.findProc(name: "SpringBoard")
            if sbProc != 0 {
                let pid = Int32(ds_kread32(sbProc + 0x68))
                if pid > 0 { kill(pid, SIGKILL) }
                return
            }
        }
        mgr.respring()
    }
}
