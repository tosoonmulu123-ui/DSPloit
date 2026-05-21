//
//  ContentView.swift
//  DSPloit
//
//  Main tab — One-Tap Jailbreak + modern UI with progress ring & status cards
//

import SwiftUI

struct ContentView: View {
    @EnvironmentObject private var mgr: dspmgr
    @ObservedObject private var jb = JailbreakEngine.shared
    @ObservedObject private var root = RootExecutor.shared
    
    @State private var showSettings = false
    @State private var showGuide = false
    @State private var pulseAnimation = false
    @State private var ringRotation: Double = 0

    init() { globallogger.capture() }
    
    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 24) {
                    Spacer().frame(height: 12)
                    
                    // Hero progress ring
                    heroRing
                    
                    // Status cards row
                    statusCardsRow
                    
                    // Step indicators
                    stepsCard
                    
                    // Jailbreak button
                    jailbreakButton
                    
                    // Quick actions
                    if mgr.dsready {
                        quickActionsCard
                    }
                    
                    // Device info card
                    if mgr.dsready {
                        deviceInfoCard
                    }
                    
                    // Help card
                    if !mgr.dsready && !jb.isRunning {
                        helpCard
                    }
                    
                    // Footer
                    footerBrand
                    
                    Spacer().frame(height: 20)
                }
                .padding(.horizontal, 20)
            }
            .background(
                LinearGradient(
                    colors: [Color(.systemBackground), Color(.systemGroupedBackground)],
                    startPoint: .top,
                    endPoint: .bottom
                )
            )
            .navigationTitle("DSPloit")
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button { showGuide = true } label: {
                        Image(systemName: "questionmark.circle")
                    }
                }
                ToolbarItem(placement: .topBarTrailing) {
                    HStack(spacing: 16) {
                        Button { mgr.showLogs.toggle() } label: {
                            Image(systemName: "terminal")
                        }
                        Button(action: { showSettings.toggle() }) {
                            Image(systemName: "gear")
                        }
                    }
                }
            }
            .sheet(isPresented: $showSettings) {
                SettingsView()
            }
            .sheet(isPresented: $showGuide) {
                GuideView()
            }
        }
    }
    
    // MARK: - Hero Ring
    
    private var heroRing: some View {
        ZStack {
            // Outer glow
            if isJailbroken {
                Circle()
                    .fill(Color.green.opacity(0.08))
                    .frame(width: 200, height: 200)
                    .blur(radius: 20)
            }
            
            // Background track
            Circle()
                .stroke(Color.secondary.opacity(0.1), lineWidth: 8)
                .frame(width: 160, height: 160)
            
            // Animated gradient ring
            if jb.isRunning {
                Circle()
                    .trim(from: 0, to: jb.progress)
                    .stroke(
                        AngularGradient(
                            colors: [.blue, .cyan, .blue],
                            center: .center
                        ),
                        style: StrokeStyle(lineWidth: 8, lineCap: .round)
                    )
                    .frame(width: 160, height: 160)
                    .rotationEffect(.degrees(-90))
                    .animation(.easeInOut(duration: 0.5), value: jb.progress)
                
                // Spinning indicator
                Circle()
                    .trim(from: 0, to: 0.3)
                    .stroke(Color.cyan.opacity(0.3), lineWidth: 3)
                    .frame(width: 175, height: 175)
                    .rotationEffect(.degrees(ringRotation))
                    .onAppear {
                        withAnimation(.linear(duration: 2).repeatForever(autoreverses: false)) {
                            ringRotation = 360
                        }
                    }
            } else if isJailbroken {
                Circle()
                    .trim(from: 0, to: 1)
                    .stroke(
                        LinearGradient(colors: [.green, .mint], startPoint: .topLeading, endPoint: .bottomTrailing),
                        style: StrokeStyle(lineWidth: 8, lineCap: .round)
                    )
                    .frame(width: 160, height: 160)
            }
            
            // Center content
            VStack(spacing: 8) {
                Image(systemName: statusIcon)
                    .font(.system(size: 36, weight: .medium))
                    .foregroundStyle(statusGradient)
                    .scaleEffect(pulseAnimation && jb.isRunning ? 1.1 : 1.0)
                    .animation(.easeInOut(duration: 1).repeatForever(autoreverses: true), value: pulseAnimation)
                    .onAppear { pulseAnimation = true }
                
                Text(statusText)
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundStyle(statusColor)
                
                if jb.isRunning {
                    Text("\(Int(jb.progress * 100))%")
                        .font(.system(size: 11, weight: .bold, design: .monospaced))
                        .foregroundStyle(.secondary)
                }
            }
        }
        .frame(height: 200)
    }
    
    // MARK: - Status Cards Row
    
    private var statusCardsRow: some View {
        HStack(spacing: 10) {
            MiniStatusCard(
                icon: "cpu",
                label: "Kernel",
                active: mgr.dsready,
                color: .orange
            )
            MiniStatusCard(
                icon: "lock.open",
                label: "Sandbox",
                active: mgr.sbxready,
                color: .purple
            )
            MiniStatusCard(
                icon: "antenna.radiowaves.left.and.right",
                label: "RC",
                active: mgr.rcready,
                color: .blue
            )
            MiniStatusCard(
                icon: "person.badge.key",
                label: "Root",
                active: root.rootConfirmed || jb.isJailbroken,
                color: .green
            )
        }
    }
    
    // MARK: - Steps Card
    
    private var stepsCard: some View {
        VStack(spacing: 0) {
            ForEach(Array(steps.enumerated()), id: \.offset) { index, step in
                HStack(spacing: 14) {
                    // Step indicator
                    ZStack {
                        Circle()
                            .fill(step.done ? step.color.opacity(0.15) : Color.secondary.opacity(0.08))
                            .frame(width: 36, height: 36)
                        
                        if step.done {
                            Image(systemName: "checkmark")
                                .font(.system(size: 13, weight: .bold))
                                .foregroundStyle(step.color)
                        } else if step.active {
                            ProgressView()
                                .scaleEffect(0.6)
                                .tint(step.color)
                        } else {
                            Text("\(index + 1)")
                                .font(.system(size: 13, weight: .bold))
                                .foregroundStyle(.secondary)
                        }
                    }
                    
                    // Label
                    VStack(alignment: .leading, spacing: 2) {
                        Text(step.label)
                            .font(.system(size: 14, weight: .medium))
                            .foregroundStyle(step.done ? .primary : (step.active ? step.color : .secondary))
                        Text(step.subtitle)
                            .font(.system(size: 10))
                            .foregroundStyle(.tertiary)
                    }
                    
                    Spacer()
                    
                    // Status badge
                    if step.done {
                        Text("Done")
                            .font(.system(size: 9, weight: .bold))
                            .foregroundStyle(step.color)
                            .padding(.horizontal, 8)
                            .padding(.vertical, 3)
                            .background(Capsule().fill(step.color.opacity(0.12)))
                    }
                }
                .padding(.vertical, 10)
                
                if index < steps.count - 1 {
                    // Connector line
                    HStack {
                        Rectangle()
                            .fill(steps[index].done ? steps[index].color.opacity(0.3) : Color.secondary.opacity(0.1))
                            .frame(width: 2, height: 16)
                            .padding(.leading, 17)
                        Spacer()
                    }
                }
            }
        }
        .padding(16)
        .background(
            RoundedRectangle(cornerRadius: 16)
                .fill(.ultraThinMaterial)
                .shadow(color: .black.opacity(0.04), radius: 8, y: 4)
        )
    }
    
    // MARK: - Jailbreak Button
    
    private var jailbreakButton: some View {
        #if !DISABLE_REMOTECALL
        Button(action: {
            if !jb.isRunning && !isJailbroken {
                UIImpactFeedbackGenerator(style: .heavy).impactOccurred()
                jb.runFullChain()
            }
        }) {
            HStack(spacing: 12) {
                if jb.isRunning {
                    ProgressView()
                        .tint(.white)
                        .scaleEffect(0.9)
                } else {
                    Image(systemName: isJailbroken ? "checkmark.shield.fill" : "bolt.shield.fill")
                        .font(.system(size: 18))
                }
                Text(isJailbroken ? "Jailbroken" : (jb.isRunning ? jb.state.rawValue : "Jailbreak"))
                    .font(.system(size: 17, weight: .bold))
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 18)
            .background(
                Group {
                    if isJailbroken {
                        LinearGradient(colors: [.green, .mint], startPoint: .leading, endPoint: .trailing)
                    } else if jb.isRunning {
                        LinearGradient(colors: [.blue, .cyan], startPoint: .leading, endPoint: .trailing)
                    } else {
                        LinearGradient(colors: [.red, .orange], startPoint: .leading, endPoint: .trailing)
                    }
                }
            )
            .foregroundStyle(.white)
            .clipShape(RoundedRectangle(cornerRadius: 16))
            .shadow(color: (isJailbroken ? Color.green : (jb.isRunning ? Color.blue : Color.red)).opacity(0.3), radius: 12, y: 6)
        }
        .disabled(jb.isRunning || isJailbroken)
        .scaleEffect(jb.isRunning ? 0.98 : 1.0)
        .animation(.easeInOut(duration: 0.2), value: jb.isRunning)
        
        // Error message
        if let error = jb.errorMessage {
            HStack(spacing: 6) {
                Image(systemName: "exclamationmark.triangle.fill")
                    .font(.caption2)
                Text(error)
                    .font(.caption)
            }
            .foregroundStyle(.red)
            .padding(.horizontal, 12)
            .padding(.vertical, 8)
            .background(RoundedRectangle(cornerRadius: 10).fill(Color.red.opacity(0.08)))
        }
        #endif
    }
    
    // MARK: - Quick Actions
    
    private var quickActionsCard: some View {
        VStack(spacing: 0) {
            quickAction(icon: "arrow.clockwise", label: "Safe Respring", color: .blue) {
                safeRespring()
            }
            Divider().padding(.leading, 52)
            #if !DISABLE_REMOTECALL
            quickAction(icon: "arrow.counterclockwise", label: "Re-init RemoteCall", color: .orange) {
                mgr.rcfailed = false
                mgr.rcLastError = nil
                mgr.rcinit(process: "SpringBoard", migbypass: false) { _ in }
            }
            #endif
        }
        .background(
            RoundedRectangle(cornerRadius: 16)
                .fill(.ultraThinMaterial)
                .shadow(color: .black.opacity(0.04), radius: 8, y: 4)
        )
    }
    
    private func quickAction(icon: String, label: String, color: Color, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            HStack(spacing: 14) {
                ZStack {
                    Circle()
                        .fill(color.opacity(0.12))
                        .frame(width: 32, height: 32)
                    Image(systemName: icon)
                        .font(.system(size: 13))
                        .foregroundStyle(color)
                }
                Text(label)
                    .font(.subheadline)
                    .foregroundStyle(.primary)
                Spacer()
                Image(systemName: "chevron.right")
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 12)
        }
        .buttonStyle(.plain)
    }
    
    // MARK: - Device Info Card
    
    private var deviceInfoCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Image(systemName: "info.circle.fill")
                    .foregroundStyle(.blue)
                Text("Device Info")
                    .font(.subheadline.bold())
                Spacer()
            }
            
            HStack {
                infoRow("Kernel Base", String(format: "0x%llx", mgr.kernbase), .orange)
                Spacer()
                infoRow("KASLR Slide", String(format: "0x%llx", mgr.kernslide), .purple)
            }
            
            if let error = mgr.rcLastError {
                HStack(spacing: 6) {
                    Image(systemName: "exclamationmark.circle.fill")
                        .font(.caption2)
                        .foregroundStyle(.red)
                    Text(error)
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundStyle(.red)
                        .lineLimit(1)
                }
            }
        }
        .padding(16)
        .background(
            RoundedRectangle(cornerRadius: 16)
                .fill(.ultraThinMaterial)
                .shadow(color: .black.opacity(0.04), radius: 8, y: 4)
        )
    }
    
    private func infoRow(_ label: String, _ value: String, _ color: Color) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(label)
                .font(.system(size: 9))
                .foregroundStyle(.secondary)
            Text(value)
                .font(.system(size: 10, weight: .medium, design: .monospaced))
                .foregroundStyle(color)
        }
    }
    
    // MARK: - Help Card
    
    private var helpCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 10) {
                Image(systemName: "hand.point.up.left.fill")
                    .font(.title3)
                    .foregroundStyle(.blue)
                VStack(alignment: .leading, spacing: 3) {
                    Text("Mulai di sini")
                        .font(.subheadline.bold())
                    Text("Tap Jailbreak untuk memulai. Setelah selesai, buka tab Root untuk tools.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            
            Button("Buka Panduan") { showGuide = true }
                .font(.caption.bold())
                .foregroundStyle(.blue)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(
            RoundedRectangle(cornerRadius: 16)
                .fill(Color.blue.opacity(0.06))
                .overlay(
                    RoundedRectangle(cornerRadius: 16)
                        .stroke(Color.blue.opacity(0.15), lineWidth: 1)
                )
        )
    }
    
    // MARK: - Footer
    
    private var footerBrand: some View {
        VStack(spacing: 4) {
            Text("DSPloit")
                .font(.caption.bold())
                .foregroundStyle(.secondary)
            Text("iOS 16–18.2 • A11–A18 • Full Jailbreak")
                .font(.system(size: 10))
                .foregroundStyle(.tertiary)
        }
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
    
    // MARK: - Helpers
    
    private var isJailbroken: Bool {
        root.rootConfirmed || jb.isJailbroken
    }
    
    private var statusIcon: String {
        if isJailbroken { return "lock.open.fill" }
        if jb.isRunning { return "bolt.circle.fill" }
        if jb.state == .failed { return "xmark.circle.fill" }
        return "lock.fill"
    }
    
    private var statusColor: Color {
        if isJailbroken { return .green }
        if jb.isRunning { return .blue }
        if jb.state == .failed { return .red }
        return .secondary
    }
    
    private var statusGradient: some ShapeStyle {
        if isJailbroken { return .linearGradient(colors: [.green, .mint], startPoint: .top, endPoint: .bottom) }
        if jb.isRunning { return .linearGradient(colors: [.blue, .cyan], startPoint: .top, endPoint: .bottom) }
        if jb.state == .failed { return .linearGradient(colors: [.red, .orange], startPoint: .top, endPoint: .bottom) }
        return .linearGradient(colors: [.secondary, .secondary], startPoint: .top, endPoint: .bottom)
    }
    
    private var statusText: String {
        if isJailbroken { return "Jailbroken" }
        if jb.isRunning { return jb.state.rawValue }
        if jb.state == .failed { return "Failed" }
        return "Locked"
    }
    
    private struct StepInfo {
        let label: String
        let subtitle: String
        let done: Bool
        let active: Bool
        let color: Color
    }
    
    private var steps: [StepInfo] {
        [
            StepInfo(label: "Kernel Exploit", subtitle: "darksword socket KRW", done: mgr.dsready, active: jb.state == .exploiting, color: .orange),
            StepInfo(label: "System Init", subtitle: "VFS + sandbox escape", done: mgr.vfsready && mgr.sbxready, active: jb.state == .initializing, color: .purple),
            StepInfo(label: "RemoteCall", subtitle: "SpringBoard connection", done: mgr.rcready, active: jb.state == .connectingRC, color: .blue),
            StepInfo(label: "Root Access", subtitle: "launchd uid=0 verify", done: root.rootConfirmed, active: jb.state == .verifyingRoot, color: .green),
            StepInfo(label: "Trust Cache", subtitle: "MSM inject via XPC", done: jb.isJailbroken, active: jb.state == .bootstrapping || jb.state == .injectingTC, color: .cyan),
        ]
    }
}

// MARK: - Mini Status Card

struct MiniStatusCard: View {
    let icon: String
    let label: String
    let active: Bool
    let color: Color
    
    var body: some View {
        VStack(spacing: 6) {
            ZStack {
                Circle()
                    .fill(active ? color.opacity(0.15) : Color.secondary.opacity(0.06))
                    .frame(width: 36, height: 36)
                Image(systemName: icon)
                    .font(.system(size: 14))
                    .foregroundStyle(active ? color : .secondary)
            }
            Text(label)
                .font(.system(size: 9, weight: .medium))
                .foregroundStyle(active ? .primary : .secondary)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 12)
        .background(
            RoundedRectangle(cornerRadius: 12)
                .fill(active ? color.opacity(0.04) : Color(.tertiarySystemGroupedBackground))
                .overlay(
                    RoundedRectangle(cornerRadius: 12)
                        .stroke(active ? color.opacity(0.2) : Color.clear, lineWidth: 1)
                )
        )
    }
}
