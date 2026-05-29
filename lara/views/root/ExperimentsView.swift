//
//  ExperimentsView.swift
//  DSPloit
//
//  Experiments — live log style (compact, scrollable)
//

import SwiftUI

struct ExperimentsView: View {
    @ObservedObject private var mgr = dspmgr.shared
    
    @State private var log: [String] = []
    @State private var isRunning = false
    @State private var currentExperiment = ""
    
    var body: some View {
        VStack(spacing: 0) {
            // Live log (top, scrollable, compact)
            logView
            
            Divider()
            
            // Buttons (bottom, fixed)
            buttonsView
        }
        .navigationTitle("Experiments")
    }
    
    // MARK: - Live Log View (like main tab)
    
    private var logView: some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 3) {
                    ForEach(Array(log.enumerated()), id: \.offset) { idx, line in
                        HStack(alignment: .top, spacing: 6) {
                            Circle()
                                .fill(dotColor(line))
                                .frame(width: 6, height: 6)
                                .padding(.top, 5)
                            Text(line)
                                .font(.system(size: 11, design: .monospaced))
                                .foregroundStyle(textColor(line))
                                .lineLimit(3)
                                .textSelection(.enabled)
                        }
                        .id(idx)
                    }
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 8)
            }
            .background(Color(.systemBackground))
            .onChange(of: log.count) { _ in
                if let last = log.indices.last {
                    withAnimation(.easeOut(duration: 0.2)) {
                        proxy.scrollTo(last, anchor: .bottom)
                    }
                }
            }
        }
    }
    
    // MARK: - Buttons View
    
    private var buttonsView: some View {
        ScrollView {
            VStack(spacing: 12) {
                // Status
                if isRunning {
                    HStack {
                        ProgressView().scaleEffect(0.8)
                        Text(currentExperiment)
                            .font(.caption.bold())
                            .foregroundStyle(.blue)
                    }
                    .padding(.top, 8)
                }
                
                // Trust Cache experiments (TOP PRIORITY)
                VStack(spacing: 8) {
                    Text("Trust Cache Load")
                        .font(.caption.bold())
                        .foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity, alignment: .leading)
                    
                    expButton("① Load TC (SpringBoard)", icon: "arrow.down.circle.fill", color: .green, stars: 5) {
                        runAsyncExperiment("TC Load") { logCb in
                            ExpTCLoadAndSpawn.shared.onLog = logCb
                            ExpTCLoadAndSpawn.shared.phase1_loadTC()
                        }
                    }
                    
                    expButton("② Test Spawn (launchd)", icon: "play.circle.fill", color: .green, stars: 5) {
                        runAsyncExperiment("TC Spawn") { logCb in
                            ExpTCLoadAndSpawn.shared.onLog = logCb
                            ExpTCLoadAndSpawn.shared.phase2_testSpawn()
                        }
                    }
                    
                    Divider().padding(.vertical, 4)
                    
                    expButton("cryptexd IOKit", icon: "checkmark.seal.fill", color: .teal, stars: 3) {
                        runAsyncExperiment("cryptexd TC") { logCb in
                            ExpCryptexdTCLoad.shared.onLog = logCb
                            ExpCryptexdTCLoad.shared.runAsync()
                        }
                    }
                    
                    expButton("SpringBoard IOKit (old)", icon: "star.fill", color: .yellow, stars: 2) {
                        runAsyncExperiment("SpringBoard TC") { logCb in
                            ExpSpringBoardTCLoad.shared.onLog = logCb
                            ExpSpringBoardTCLoad.shared.runAsync()
                        }
                    }
                }
                
                Divider()
                
                // Other experiments
                VStack(spacing: 8) {
                    Text("Research")
                        .font(.caption.bold())
                        .foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity, alignment: .leading)
                    
                    expButton("pmap_cs Kernel Probe", icon: "cpu", color: .indigo, stars: 4) {
                        runExperiment("pmap_cs Probe") { ExpPmapCSProbe.shared.runAll() }
                    }
                    
                    expButton("amfid NOP Patch (v2)", icon: "lock.open.fill", color: .red, stars: 5) {
                        runAsyncExperiment("amfid Patch v2") { logCb in
                            ExpAmfidPatchV2.shared.onLog = logCb
                            ExpAmfidPatchV2.shared.runAsync()
                        }
                    }
                    
                    expButton("Data Segment Probe", icon: "magnifyingglass", color: .blue, stars: 3) {
                        runExperiment("Data Probe") { ExpDataSegmentProbe.shared.runAll() }
                    }
                    
                    expButton("amfid Patch", icon: "lock.open.fill", color: .purple, stars: 3) {
                        runExperiment("amfid Patch") { ExpAmfidPatch.shared.runAll() }
                    }
                    
                    expButton("Safe Flag Scan", icon: "flag.fill", color: .mint, stars: 2) {
                        runExperiment("Flag Scan") { ExpSafeFlagScan.shared.runAll() }
                    }
                }
                
                // Clear button
                Button {
                    log.removeAll()
                } label: {
                    Label("Clear Log", systemImage: "trash")
                        .font(.caption)
                        .foregroundStyle(.red)
                }
                .padding(.top, 4)
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 12)
        }
        .frame(maxHeight: 280)
        .background(Color(.secondarySystemBackground))
    }
    
    // MARK: - Experiment Button
    
    private func expButton(_ title: String, icon: String, color: Color, stars: Int, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            HStack(spacing: 10) {
                Image(systemName: icon)
                    .foregroundStyle(color)
                    .frame(width: 20)
                Text(title)
                    .font(.subheadline)
                Spacer()
                Text(String(repeating: "★", count: stars))
                    .font(.caption2)
                    .foregroundStyle(.yellow)
            }
            .padding(.vertical, 10)
            .padding(.horizontal, 14)
            .background(RoundedRectangle(cornerRadius: 8).fill(color.opacity(0.08)))
        }
        .disabled(isRunning || !mgr.dsready)
    }
    
    // MARK: - Run Experiment
    
    private func runExperiment(_ name: String, block: @escaping () -> [String]) {
        isRunning = true
        currentExperiment = name
        log.append("▶ Starting: \(name)")
        
        DispatchQueue.global(qos: .userInitiated).async {
            let results = block()
            DispatchQueue.main.async {
                self.log.append(contentsOf: results)
                self.log.append("■ Done: \(name)")
                self.log.append("")
                self.isRunning = false
                self.currentExperiment = ""
            }
        }
    }
    
    /// Async experiment (for launchd/MSM that use callbacks)
    private func runAsyncExperiment(_ name: String, start: @escaping ((@escaping (String) -> Void)) -> Void) {
        isRunning = true
        currentExperiment = name
        log.append("▶ Starting: \(name)")
        
        let logCallback: (String) -> Void = { [self] msg in
            DispatchQueue.main.async {
                self.log.append(msg)
            }
        }
        
        start(logCallback)
        
        // Auto-finish after 30s if not manually stopped
        DispatchQueue.main.asyncAfter(deadline: .now() + 30) { [self] in
            if self.isRunning && self.currentExperiment == name {
                self.log.append("■ Done: \(name)")
                self.log.append("")
                self.isRunning = false
                self.currentExperiment = ""
            }
        }
    }
    
    // MARK: - Colors
    
    private func dotColor(_ line: String) -> Color {
        if line.contains("✅") { return .green }
        if line.contains("❌") { return .red }
        if line.contains("⚠️") { return .orange }
        if line.hasPrefix("▶") || line.hasPrefix("■") { return .blue }
        return .secondary.opacity(0.5)
    }
    
    private func textColor(_ line: String) -> Color {
        if line.contains("✅") { return .green }
        if line.contains("❌") { return .red }
        if line.contains("⚠️") { return .orange }
        if line.hasPrefix("▶") || line.hasPrefix("■") { return .blue }
        if line.contains("══") || line.contains("──") { return .primary }
        return .secondary
    }
}
