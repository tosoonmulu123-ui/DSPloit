//
//  ExperimentsView.swift
//  DSPloit
//
//  Test new techniques before integrating into main chain.
//

import SwiftUI

struct ExperimentsView: View {
    @ObservedObject private var mgr = dspmgr.shared
    
    @State private var tcResults: [String] = []
    @State private var isTCRunning = false
    @State private var showTCResults = false
    
    @State private var csResults: [String] = []
    @State private var isCSRunning = false
    @State private var showCSResults = false
    
    var body: some View {
        List {
            Section {
                VStack(alignment: .leading, spacing: 6) {
                    Label("Experiments", systemImage: "flask.fill")
                        .font(.headline)
                    Text("Test bypasses here. Results logged for analysis. Nothing touches main chain until verified ✅.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            
            // proc_ro CS Flags (NEW — priority experiment)
            Section("proc_ro cs_flags Patching (PRIORITY)") {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Patch proc_ro→p_csflags to set CS_PLATFORM_BINARY on spawning process. This should bypass AMFI's trust cache check for unsigned binaries.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Text("Chance: ~85-90% — proven technique (Dopamine/Fugu15)")
                        .font(.caption2)
                        .foregroundStyle(.green)
                }
                
                Button {
                    runCSFlagsExperiment()
                } label: {
                    HStack {
                        Image(systemName: isCSRunning ? "hourglass" : "play.fill")
                            .foregroundStyle(.green)
                        Text(isCSRunning ? "Running..." : "Run cs_flags Patch Test")
                        Spacer()
                        if !isCSRunning {
                            Text("★")
                                .foregroundStyle(.yellow)
                        }
                    }
                }
                .disabled(isCSRunning || !mgr.dsready)
                
                if !mgr.dsready {
                    Text("⚠️ Jailbreak dulu — butuh KRW aktif")
                        .font(.caption).foregroundStyle(.red)
                }
                
                if !csResults.isEmpty {
                    Button { showCSResults.toggle() } label: {
                        HStack {
                            Image(systemName: "doc.text")
                            Text(showCSResults ? "Hide" : "Show Results (\(csResults.count) lines)")
                            Spacer()
                            Image(systemName: showCSResults ? "chevron.up" : "chevron.down")
                                .font(.caption)
                        }
                    }
                }
                
                if showCSResults {
                    ForEach(Array(csResults.enumerated()), id: \.offset) { _, line in
                        Text(line)
                            .font(.system(size: 10, design: .monospaced))
                            .foregroundStyle(lineColor(line))
                            .textSelection(.enabled)
                            .listRowInsets(EdgeInsets(top: 1, leading: 8, bottom: 1, trailing: 4))
                    }
                }
            }
            
            // Trust Cache Inject
            Section("Trust Cache Direct Inject (RE-based)") {
                Text("Write CDHash directly to kernel trust cache slot table. Bypasses all entitlement checks.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                
                Button {
                    runTCExperiment()
                } label: {
                    HStack {
                        Image(systemName: isTCRunning ? "hourglass" : "play.fill")
                            .foregroundStyle(.orange)
                        Text(isTCRunning ? "Running..." : "Run Trust Cache Tests")
                        Spacer()
                    }
                }
                .disabled(isTCRunning || !mgr.dsready)
                
                if !mgr.dsready {
                    Text("⚠️ Jailbreak dulu")
                        .font(.caption).foregroundStyle(.red)
                }
                
                if !tcResults.isEmpty {
                    Button { showTCResults.toggle() } label: {
                        HStack {
                            Image(systemName: "doc.text")
                            Text(showTCResults ? "Hide" : "Show Results (\(tcResults.count) lines)")
                            Spacer()
                            Image(systemName: showTCResults ? "chevron.up" : "chevron.down")
                                .font(.caption)
                        }
                    }
                }
                
                if showTCResults {
                    ForEach(Array(tcResults.enumerated()), id: \.offset) { _, line in
                        Text(line)
                            .font(.system(size: 10, design: .monospaced))
                            .foregroundStyle(lineColor(line))
                            .textSelection(.enabled)
                            .listRowInsets(EdgeInsets(top: 1, leading: 8, bottom: 1, trailing: 4))
                    }
                }
            }
            
            // Legend
            Section("Output Legend") {
                HStack { Text("✅"); Text("Working — integrate").font(.caption).foregroundStyle(.green) }
                HStack { Text("⚠️"); Text("Partial — investigate").font(.caption).foregroundStyle(.orange) }
                HStack { Text("❌"); Text("Failed — do NOT integrate").font(.caption).foregroundStyle(.red) }
                HStack { Text("🔍"); Text("Info — check value").font(.caption).foregroundStyle(.blue) }
            }
        }
        .navigationTitle("Experiments")
    }
    
    private func runCSFlagsExperiment() {
        isCSRunning = true
        csResults.removeAll()
        showCSResults = true
        DispatchQueue.global(qos: .userInitiated).async {
            let r = ExpProcRoCSFlags.shared.runAll()
            DispatchQueue.main.async {
                csResults = r
                isCSRunning = false
            }
        }
    }
    
    private func runTCExperiment() {
        isTCRunning = true
        tcResults.removeAll()
        showTCResults = true
        DispatchQueue.global(qos: .userInitiated).async {
            let r = ExpTrustCacheInject.shared.runAll()
            DispatchQueue.main.async {
                tcResults = r
                isTCRunning = false
            }
        }
    }
    
    private func lineColor(_ line: String) -> Color {
        if line.contains("✅") { return .green }
        if line.contains("❌") { return .red }
        if line.contains("⚠️") { return .orange }
        if line.contains("══") || line.contains("──") { return .primary }
        return .secondary
    }
}
