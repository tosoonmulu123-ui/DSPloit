//
//  ExperimentsView.swift
//  DSPloit — Experiments (compact terminal-style log + buttons)
//

import SwiftUI

struct ExperimentsView: View {
    @ObservedObject private var mgr = dspmgr.shared
    
    @State private var log: [String] = []
    @State private var isRunning = false
    @State private var currentExperiment = ""
    
    var body: some View {
        VStack(spacing: 0) {
            logView
            Divider()
            buttonsView
        }
        .background(Color(.systemBackground))
        .navigationTitle("Experiments")
        .navigationBarTitleDisplayMode(.inline)
    }
    
    // MARK: - Log (terminal style)
    
    private var logView: some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 2) {
                    ForEach(Array(log.enumerated()), id: \.offset) { idx, line in
                        HStack(alignment: .top, spacing: 6) {
                            Text("●")
                                .font(.system(size: 5))
                                .foregroundStyle(dotColor(line))
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
            .background(Color.black.opacity(0.92))
            .onChange(of: log.count) { _ in
                if let last = log.indices.last {
                    withAnimation(.easeOut(duration: 0.15)) {
                        proxy.scrollTo(last, anchor: .bottom)
                    }
                }
            }
        }
    }
    
    // MARK: - Buttons
    
    private var buttonsView: some View {
        ScrollView {
            VStack(spacing: 8) {
                if isRunning {
                    HStack(spacing: 8) {
                        ProgressView().scaleEffect(0.7)
                        Text(currentExperiment)
                            .font(.system(size: 11, weight: .medium, design: .monospaced))
                            .foregroundStyle(.blue)
                    }
                    .padding(.top, 6)
                }
                
                // Phase 1 + 2 (proven path)
                sectionHeader("Trust Cache")
                expBtn("⚡ Multi-Bypass (ALL)", .red) {
                    runAsync("Multi") { cb in
                        ExpMultiBypass.shared.onLog = cb
                        ExpMultiBypass.shared.runAsync()
                    }
                }
                expBtn("① Load TC (SpringBoard)", .green) {
                    runAsync("TC Load") { cb in
                        ExpTCLoadAndSpawn.shared.onLog = cb
                        ExpTCLoadAndSpawn.shared.phase1_loadTC()
                    }
                }
                expBtn("② Test Spawn (launchd)", .green) {
                    runAsync("TC Spawn") { cb in
                        ExpTCLoadAndSpawn.shared.onLog = cb
                        ExpTCLoadAndSpawn.shared.phase2_testSpawn()
                    }
                }
                expBtn("cryptexd IOKit", .teal) {
                    runAsync("cryptexd") { cb in
                        ExpCryptexdTCLoad.shared.onLog = cb
                        ExpCryptexdTCLoad.shared.runAsync()
                    }
                }
                
                Divider().padding(.vertical, 4)
                
                // Research
                sectionHeader("Research")
                expBtn("pmap_cs Kernel Probe", .indigo) {
                    runSync("pmap_cs") { ExpPmapCSProbe.shared.runAll() }
                }
                expBtn("amfid NOP Patch (v2)", .red) {
                    runAsync("amfid v2") { cb in
                        ExpAmfidPatchV2.shared.onLog = cb
                        ExpAmfidPatchV2.shared.runAsync()
                    }
                }
                expBtn("Data Segment Probe", .blue) {
                    runSync("Data Probe") { ExpDataSegmentProbe.shared.runAll() }
                }
                expBtn("SpringBoard IOKit (old)", .yellow) {
                    runAsync("SB IOKit") { cb in
                        ExpSpringBoardTCLoad.shared.onLog = cb
                        ExpSpringBoardTCLoad.shared.runAsync()
                    }
                }
                
                // Clear
                Button { log.removeAll() } label: {
                    Text("Clear")
                        .font(.system(size: 11, weight: .medium))
                        .foregroundStyle(.red)
                }
                .padding(.top, 4)
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 10)
        }
        .frame(maxHeight: 260)
        .background(Color(.secondarySystemBackground))
    }
    
    // MARK: - Components
    
    private func sectionHeader(_ title: String) -> some View {
        Text(title)
            .font(.system(size: 10, weight: .bold, design: .monospaced))
            .foregroundStyle(.secondary)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.top, 4)
    }
    
    private func expBtn(_ title: String, _ color: Color, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            HStack {
                Text(title)
                    .font(.system(size: 13, weight: .medium))
                Spacer()
                Circle()
                    .fill(color)
                    .frame(width: 8, height: 8)
            }
            .padding(.vertical, 10)
            .padding(.horizontal, 12)
            .background(RoundedRectangle(cornerRadius: 8).fill(color.opacity(0.06)))
        }
        .disabled(isRunning || !mgr.dsready)
    }
    
    // MARK: - Run Helpers
    
    private func runSync(_ name: String, block: @escaping () -> [String]) {
        isRunning = true
        currentExperiment = name
        log.append("▶ \(name)")
        DispatchQueue.global(qos: .userInitiated).async {
            let results = block()
            DispatchQueue.main.async {
                self.log.append(contentsOf: results)
                self.log.append("■ Done")
                self.isRunning = false
                self.currentExperiment = ""
            }
        }
    }
    
    private func runAsync(_ name: String, start: @escaping ((@escaping (String) -> Void)) -> Void) {
        isRunning = true
        currentExperiment = name
        log.append("▶ \(name)")
        start { msg in DispatchQueue.main.async { self.log.append(msg) } }
        DispatchQueue.main.asyncAfter(deadline: .now() + 30) {
            if self.isRunning && self.currentExperiment == name {
                self.log.append("■ Done")
                self.isRunning = false
                self.currentExperiment = ""
            }
        }
    }
    
    // MARK: - Colors
    
    private func dotColor(_ line: String) -> Color {
        if line.contains("✅") || line.contains("🎉") { return .green }
        if line.contains("❌") { return .red }
        if line.contains("⚠️") { return .orange }
        if line.hasPrefix("▶") || line.hasPrefix("■") { return .blue }
        return .gray
    }
    
    private func textColor(_ line: String) -> Color {
        if line.contains("✅") || line.contains("🎉") { return .green }
        if line.contains("❌") { return .red }
        if line.contains("⚠️") { return .orange }
        if line.hasPrefix("▶") || line.hasPrefix("■") { return .cyan }
        return Color(.init(white: 0.78, alpha: 1))
    }
}
