//
//  ContentView.swift
//  DSPloit
//
//  Setup tab — exploit chain controls
//

import SwiftUI
import UniformTypeIdentifiers

struct ContentView: View {
    @EnvironmentObject private var mgr: dspmgr
    @ObservedObject private var jb = JailbreakEngine.shared
    @AppStorage("selectedMethod") private var selectedmethod: method = .hybrid
    @AppStorage("logsdisplaymode") private var selectedlogsdisplaymode: logsdisplaymode = .toolbar
    
    @State private var showSettings = false
    @State private var dlingkcache = false
    
    init() { globallogger.capture() }
    
    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 16) {
                    // Exploit Chain Card
                    ExploitChainCard()
                    
                    // Actions
                    ActionsCard()
                    
                    // Kernel Info
                    if mgr.dsready {
                        KernelInfoCard()
                    }
                }
                .padding(.horizontal, 16)
                .padding(.top, 8)
            }
            .navigationTitle("Setup")
            .background(Color(.systemGroupedBackground))
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button(action: { showSettings.toggle() }) {
                        Image(systemName: "gear")
                    }
                }
            }
            .sheet(isPresented: $showSettings) {
                SettingsView()
            }
        }
    }
    
    // MARK: - Exploit Chain Card
    
    @ViewBuilder
    private func ExploitChainCard() -> some View {
        VStack(spacing: 12) {
            // Steps
            StepButton(
                label: "Kernel Exploit",
                icon: "bolt.shield.fill",
                status: mgr.dsready ? .done : (mgr.dsrunning ? .running : .idle),
                progress: mgr.dsprogress
            ) {
                offsets_init()
                mgr.run()
            }
            .disabled(mgr.dsready || mgr.dsrunning || isdebugged())
            
            StepButton(
                label: "Initialize System",
                icon: "server.rack",
                status: (mgr.vfsready && mgr.sbxready) ? .done : (mgr.vfsrunning || mgr.sbxrunning ? .running : .idle),
                progress: mgr.vfsprogress
            ) {
                mgr.vfsinit()
                mgr.sbxescape()
            }
            .disabled(!mgr.dsready || (mgr.vfsready && mgr.sbxready))
            
            #if !DISABLE_REMOTECALL
            StepButton(
                label: "RemoteCall (SpringBoard)",
                icon: "link.circle.fill",
                status: mgr.rcready ? .done : (mgr.rcrunning ? .running : (mgr.rcfailed ? .failed : .idle)),
                progress: 0
            ) {
                mgr.rcinit(process: "SpringBoard", migbypass: false) { success in
                    if !success { mgr.rcfailed = true }
                }
            }
            .disabled(!mgr.dsready || mgr.rcready || mgr.rcrunning || isdebugged())
            #endif
            
            // Error display
            if let error = mgr.rcLastError ?? mgr.sbProc?.lastError {
                Text(error)
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundStyle(.red)
                    .padding(.horizontal, 8)
            }
        }
        .padding(16)
        .background(RoundedRectangle(cornerRadius: 16).fill(Color(.secondarySystemGroupedBackground)))
    }
    
    // MARK: - Actions Card
    
    @ViewBuilder
    private func ActionsCard() -> some View {
        VStack(spacing: 0) {
            ActionRow(icon: "arrow.clockwise", label: "Safe Respring", color: .blue) {
                safeRespring()
            }
            
            Divider().padding(.leading, 44)
            
            ActionRow(icon: "arrow.counterclockwise", label: "Re-init RemoteCall", color: .orange) {
                #if !DISABLE_REMOTECALL
                mgr.rcfailed = false
                mgr.rcLastError = nil
                mgr.rcinit(process: "SpringBoard", migbypass: false) { _ in }
                #endif
            }
            
            Divider().padding(.leading, 44)
            
            ActionRow(icon: "exclamationmark.triangle.fill", label: "Panic!", color: .red) {
                mgr.panic()
            }
        }
        .padding(.vertical, 4)
        .background(RoundedRectangle(cornerRadius: 16).fill(Color(.secondarySystemGroupedBackground)))
    }
    
    // MARK: - Kernel Info
    
    @ViewBuilder
    private func KernelInfoCard() -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("KERNEL")
                .font(.caption.bold())
                .foregroundStyle(.secondary)
            
            HStack {
                Text("Base")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Spacer()
                Text(String(format: "0x%llx", mgr.kernbase))
                    .font(.system(size: 12, design: .monospaced))
                    .foregroundStyle(.orange)
            }
            HStack {
                Text("Slide")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Spacer()
                Text(String(format: "0x%llx", mgr.kernslide))
                    .font(.system(size: 12, design: .monospaced))
                    .foregroundStyle(.purple)
            }
        }
        .padding(16)
        .background(RoundedRectangle(cornerRadius: 16).fill(Color(.secondarySystemGroupedBackground)))
    }
    
    // MARK: - Safe Respring
    
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
        
        // Fallback: kill SpringBoard via kernel
        if mgr.dsready {
            let sbProc = mgr.findProc(name: "SpringBoard")
            if sbProc != 0 {
                let pid = Int32(ds_kread32(sbProc + 0x68))
                if pid > 0 { kill(pid, SIGKILL) }
                return
            }
        }
        
        // Last resort
        mgr.respring()
    }
}

// MARK: - Step Button Component

enum StepStatus {
    case idle, running, done, failed
}

struct StepButton: View {
    let label: String
    let icon: String
    let status: StepStatus
    let progress: Double
    let action: () -> Void
    
    var body: some View {
        Button(action: action) {
            HStack(spacing: 12) {
                ZStack {
                    Circle()
                        .fill(statusColor.opacity(0.12))
                        .frame(width: 36, height: 36)
                    
                    if status == .running {
                        Circle()
                            .trim(from: 0, to: max(progress, 0.1))
                            .stroke(statusColor, style: StrokeStyle(lineWidth: 2, lineCap: .round))
                            .frame(width: 36, height: 36)
                            .rotationEffect(.degrees(-90))
                    }
                    
                    Image(systemName: statusIcon)
                        .font(.system(size: 14))
                        .foregroundStyle(statusColor)
                }
                
                Text(label)
                    .font(.subheadline)
                    .foregroundStyle(.primary)
                
                Spacer()
                
                switch status {
                case .done:
                    Image(systemName: "checkmark.circle.fill")
                        .foregroundStyle(.green)
                case .running:
                    ProgressView().scaleEffect(0.7)
                case .failed:
                    Image(systemName: "xmark.circle.fill")
                        .foregroundStyle(.red)
                case .idle:
                    Image(systemName: "chevron.right")
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                }
            }
            .padding(.vertical, 8)
        }
        .buttonStyle(.plain)
    }
    
    private var statusColor: Color {
        switch status {
        case .done: return .green
        case .running: return .blue
        case .failed: return .red
        case .idle: return .secondary
        }
    }
    
    private var statusIcon: String {
        switch status {
        case .done: return "checkmark"
        case .running: return icon
        case .failed: return "xmark"
        case .idle: return icon
        }
    }
}

struct ActionRow: View {
    let icon: String
    let label: String
    let color: Color
    let action: () -> Void
    
    var body: some View {
        Button(action: action) {
            HStack(spacing: 12) {
                Image(systemName: icon)
                    .font(.body)
                    .foregroundStyle(color)
                    .frame(width: 24)
                Text(label)
                    .font(.subheadline)
                    .foregroundStyle(color)
                Spacer()
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 12)
        }
        .buttonStyle(.plain)
    }
}
