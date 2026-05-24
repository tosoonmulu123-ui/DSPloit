//
//  ExperimentsView.swift
//  DSPloit
//
//  Hub for all experiments — test new techniques before integrating
//  into the main jailbreak chain.
//

import SwiftUI

struct ExperimentsView: View {
    @ObservedObject private var mgr = dspmgr.shared
    
    @State private var dyldResults: [String] = []
    @State private var isDyldRunning = false
    @State private var showDyldResults = false
    
    var body: some View {
        List {
            Section {
                VStack(alignment: .leading, spacing: 6) {
                    Label("Experiments", systemImage: "flask.fill")
                        .font(.headline)
                    Text("Test new bypass techniques here before integrating into the main chain. Results are logged for analysis.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                .padding(.vertical, 4)
            }
            
            // MARK: - DYLD Bypass Experiment
            Section("DYLD AMFI Bypass (from RE analysis)") {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Patches dyld's cached AMFI policy to allow unsigned dylib loading and DYLD_INSERT_LIBRARIES.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    
                    Text("Source: Reverse engineering of iOS 18.2 dyld binary")
                        .font(.system(size: 10))
                        .foregroundStyle(.orange)
                }
                
                Button {
                    runDyldExperiment()
                } label: {
                    HStack {
                        Image(systemName: isDyldRunning ? "hourglass" : "play.fill")
                            .foregroundStyle(.blue)
                        Text(isDyldRunning ? "Running..." : "Run DYLD Bypass Tests")
                        Spacer()
                        if !dyldResults.isEmpty {
                            Text("\(dyldResults.count) lines")
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                        }
                    }
                }
                .disabled(isDyldRunning || !mgr.dsready)
                
                if !mgr.dsready {
                    Text("⚠️ Run jailbreak first")
                        .font(.caption)
                        .foregroundStyle(.red)
                }
                
                if !dyldResults.isEmpty {
                    Button {
                        showDyldResults.toggle()
                    } label: {
                        HStack {
                            Image(systemName: "doc.text")
                                .foregroundStyle(.green)
                            Text(showDyldResults ? "Hide Results" : "Show Results")
                            Spacer()
                            Image(systemName: showDyldResults ? "chevron.up" : "chevron.down")
                                .font(.caption)
                        }
                    }
                }
                
                if showDyldResults {
                    ForEach(Array(dyldResults.enumerated()), id: \.offset) { _, line in
                        logLine(line)
                    }
                }
            }
            
            // MARK: - AMFI Experiments (existing)
            Section("AMFI Kernel Experiments") {
                NavigationLink {
                    AMFIExperimentView()
                } label: {
                    HStack(spacing: 14) {
                        Image(systemName: "shield.lefthalf.filled")
                            .foregroundStyle(.red)
                            .frame(width: 28)
                        VStack(alignment: .leading, spacing: 2) {
                            Text("AMFI Trust Cache Experiments")
                                .font(.body)
                            Text("Physmap, TC probe, KTRR analysis, heap TC")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                }
            }
            
            // MARK: - Legend
            Section("Output Legend") {
                legendRow("✅", "Working — safe to integrate", .green)
                legendRow("⚠️", "Partial — needs investigation", .orange)
                legendRow("❌", "Failed — do NOT integrate", .red)
                legendRow("🔍", "Info — check the value manually", .blue)
            }
        }
        .navigationTitle("Experiments")
    }
    
    // MARK: - Run DYLD Experiment
    
    private func runDyldExperiment() {
        isDyldRunning = true
        dyldResults.removeAll()
        showDyldResults = true
        
        DispatchQueue.global(qos: .userInitiated).async {
            let results = ExpDyldBypass.shared.runAll()
            DispatchQueue.main.async {
                self.dyldResults = results
                self.isDyldRunning = false
            }
        }
    }
    
    // MARK: - UI Helpers
    
    private func logLine(_ line: String) -> some View {
        HStack(alignment: .top, spacing: 4) {
            if line.contains("✅") {
                Circle().fill(.green).frame(width: 6, height: 6).padding(.top, 5)
            } else if line.contains("❌") {
                Circle().fill(.red).frame(width: 6, height: 6).padding(.top, 5)
            } else if line.contains("⚠️") {
                Circle().fill(.orange).frame(width: 6, height: 6).padding(.top, 5)
            } else if line.contains("🔍") {
                Circle().fill(.blue).frame(width: 6, height: 6).padding(.top, 5)
            } else {
                Circle().fill(.clear).frame(width: 6, height: 6).padding(.top, 5)
            }
            
            Text(line)
                .font(.system(size: 11, design: .monospaced))
                .foregroundStyle(lineColor(line))
                .textSelection(.enabled)
        }
        .listRowInsets(EdgeInsets(top: 1, leading: 12, bottom: 1, trailing: 8))
    }
    
    private func lineColor(_ line: String) -> Color {
        if line.contains("✅") { return .green }
        if line.contains("❌") { return .red }
        if line.contains("⚠️") { return .orange }
        if line.contains("══") { return .primary }
        if line.contains("──") { return .cyan }
        return .secondary
    }
    
    private func legendRow(_ icon: String, _ text: String, _ color: Color) -> some View {
        HStack(spacing: 8) {
            Text(icon).font(.body)
            Text(text).font(.caption).foregroundStyle(color)
        }
    }
}
