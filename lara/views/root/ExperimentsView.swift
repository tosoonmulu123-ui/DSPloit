//
//  ExperimentsView.swift
//  DSPloit
//
//  Test new techniques before integrating into main chain.
//

import SwiftUI

struct ExperimentsView: View {
    @ObservedObject private var mgr = dspmgr.shared
    
    @State private var amfidResults: [String] = []
    @State private var isAmfidRunning = false
    @State private var showAmfidResults = false
    
    @State private var tcHijackResults: [String] = []
    @State private var isTCHijackRunning = false
    @State private var showTCHijackResults = false
    
    @State private var fullZeroResults: [String] = []
    @State private var isFullZeroRunning = false
    @State private var showFullZeroResults = false
    
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
            
            Section("amfid Patch — AMFI Bypass") {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Patch amfid's signature validation function to always return success. This bypasses AMFI for unsigned binary execution.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Text("3 strategies: kill+race, __TEXT patch via RC, XPC hook")
                        .font(.caption2)
                        .foregroundStyle(.blue)
                }
                
                Button {
                    runAmfidExperiment()
                } label: {
                    HStack {
                        Image(systemName: isAmfidRunning ? "hourglass" : "play.fill")
                            .foregroundStyle(.purple)
                        Text(isAmfidRunning ? "Running..." : "Run amfid Patch Test")
                        Spacer()
                        if !isAmfidRunning {
                            Text("★")
                                .foregroundStyle(.yellow)
                        }
                    }
                }
                .disabled(isAmfidRunning || !mgr.dsready)
                
                if !mgr.dsready {
                    Text("⚠️ Jailbreak dulu — butuh KRW + RemoteCall aktif")
                        .font(.caption).foregroundStyle(.red)
                }
                
                if !amfidResults.isEmpty {
                    Button { showAmfidResults.toggle() } label: {
                        HStack {
                            Image(systemName: "doc.text")
                            Text(showAmfidResults ? "Hide" : "Show Results (\(amfidResults.count) lines)")
                            Spacer()
                            Image(systemName: showAmfidResults ? "chevron.up" : "chevron.down")
                                .font(.caption)
                        }
                    }
                }
                
                if showAmfidResults {
                    ForEach(Array(amfidResults.enumerated()), id: \.offset) { _, line in
                        Text(line)
                            .font(.system(size: 10, design: .monospaced))
                            .foregroundStyle(lineColor(line))
                            .textSelection(.enabled)
                            .listRowInsets(EdgeInsets(top: 1, leading: 8, bottom: 1, trailing: 4))
                    }
                }
            }
            
            // Legend
            // AMFI Full Zero (PRIORITY — from deep RE)
            Section("AMFI Full Zero — 33 Flags (★ NEW)") {
                Text("Zero ALL 33 AMFI flags found via kernelcache RE (not just 10). Tests if additional flags control unsigned exec.")
                    .font(.caption).foregroundStyle(.secondary)
                
                Button {
                    runFullZeroExperiment()
                } label: {
                    HStack {
                        Image(systemName: isFullZeroRunning ? "hourglass" : "play.fill")
                            .foregroundStyle(.green)
                        Text(isFullZeroRunning ? "Running..." : "Run AMFI Full Zero")
                        Spacer()
                        Text("★").foregroundStyle(.yellow)
                    }
                }
                .disabled(isFullZeroRunning || !mgr.dsready)
                
                if !fullZeroResults.isEmpty {
                    Button { showFullZeroResults.toggle() } label: {
                        HStack {
                            Image(systemName: "doc.text")
                            Text(showFullZeroResults ? "Hide" : "Show Results (\(fullZeroResults.count) lines)")
                            Spacer()
                            Image(systemName: showFullZeroResults ? "chevron.up" : "chevron.down")
                                .font(.caption)
                        }
                    }
                }
                
                if showFullZeroResults {
                    ForEach(Array(fullZeroResults.enumerated()), id: \.offset) { _, line in
                        Text(line)
                            .font(.system(size: 10, design: .monospaced))
                            .foregroundStyle(lineColor(line))
                            .textSelection(.enabled)
                    }
                }
            }
            
            Section("Trust Cache Func Ptr Hijack") {
                Text("⚠️ CAUTION: May panic. Find kernel TC load function pointer.")
                    .font(.caption).foregroundStyle(.red)
                
                Button {
                    runTCHijackExperiment()
                } label: {
                    HStack {
                        Image(systemName: isTCHijackRunning ? "hourglass" : "play.fill")
                            .foregroundStyle(.orange)
                        Text(isTCHijackRunning ? "Running..." : "Run TC Hijack Test")
                        Spacer()
                    }
                }
                .disabled(isTCHijackRunning || !mgr.dsready)
                
                if !tcHijackResults.isEmpty {
                    Button { showTCHijackResults.toggle() } label: {
                        HStack {
                            Image(systemName: "doc.text")
                            Text(showTCHijackResults ? "Hide" : "Show Results (\(tcHijackResults.count) lines)")
                            Spacer()
                            Image(systemName: showTCHijackResults ? "chevron.up" : "chevron.down")
                                .font(.caption)
                        }
                    }
                }
                
                if showTCHijackResults {
                    ForEach(Array(tcHijackResults.enumerated()), id: \.offset) { _, line in
                        Text(line)
                            .font(.system(size: 10, design: .monospaced))
                            .foregroundStyle(lineColor(line))
                            .textSelection(.enabled)
                    }
                }
            }
            
            Section("Output Legend") {
                HStack { Text("✅"); Text("Working — integrate").font(.caption).foregroundStyle(.green) }
                HStack { Text("⚠️"); Text("Partial — investigate").font(.caption).foregroundStyle(.orange) }
                HStack { Text("❌"); Text("Failed — do NOT integrate").font(.caption).foregroundStyle(.red) }
                HStack { Text("🔍"); Text("Info — check value").font(.caption).foregroundStyle(.blue) }
            }
        }
        .navigationTitle("Experiments")
    }
    
    private func runAmfidExperiment() {
        isAmfidRunning = true
        amfidResults.removeAll()
        showAmfidResults = true
        DispatchQueue.global(qos: .userInitiated).async {
            let r = ExpAmfidPatch.shared.runAll()
            DispatchQueue.main.async {
                amfidResults = r
                isAmfidRunning = false
            }
        }
    }
    
    private func runTCHijackExperiment() {
        isTCHijackRunning = true
        tcHijackResults.removeAll()
        showTCHijackResults = true
        DispatchQueue.global(qos: .userInitiated).async {
            let r = ExpTCFuncPtrHijack.shared.runAll()
            DispatchQueue.main.async {
                tcHijackResults = r
                isTCHijackRunning = false
            }
        }
    }
    
    private func runFullZeroExperiment() {
        isFullZeroRunning = true
        fullZeroResults.removeAll()
        showFullZeroResults = true
        DispatchQueue.global(qos: .userInitiated).async {
            let r = ExpAMFIFullZero.shared.runAll()
            DispatchQueue.main.async {
                fullZeroResults = r
                isFullZeroRunning = false
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
