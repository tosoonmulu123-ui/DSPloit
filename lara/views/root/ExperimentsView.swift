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
    
    @State private var flagScanResults: [String] = []
    @State private var isFlagScanRunning = false
    @State private var showFlagScanResults = false
    
    @State private var pmapResults: [String] = []
    @State private var isPmapRunning = false
    @State private var showPmapResults = false
    
    @State private var probeResults: [String] = []
    @State private var isProbeRunning = false
    @State private var showProbeResults = false
    
    @State private var msmResults: [String] = []
    @State private var isMSMRunning = false
    @State private var showMSMResults = false
    
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
            
            // Safe Flag Scan (★★★ HIGHEST PRIORITY)
            Section("Safe Flag Scan (★★★ BREAKTHROUGH)") {
                Text("Systematically test AMFI/pmap_cs __DATA flags found by Rust analyzer. Tests ONE flag at a time, restores on failure. SAFEST experiment — no panic risk.")
                    .font(.caption).foregroundStyle(.secondary)
                
                Button {
                    runFlagScanExperiment()
                } label: {
                    HStack {
                        Image(systemName: isFlagScanRunning ? "hourglass" : "play.fill")
                            .foregroundStyle(.mint)
                        Text(isFlagScanRunning ? "Running..." : "Run Safe Flag Scan")
                        Spacer()
                        Text("★★★").foregroundStyle(.yellow)
                    }
                }
                .disabled(isFlagScanRunning || !mgr.dsready)
                
                if !flagScanResults.isEmpty {
                    Button { showFlagScanResults.toggle() } label: {
                        HStack {
                            Image(systemName: "doc.text")
                            Text(showFlagScanResults ? "Hide" : "Show Results (\(flagScanResults.count) lines)")
                            Spacer()
                            Image(systemName: showFlagScanResults ? "chevron.up" : "chevron.down").font(.caption)
                        }
                    }
                }
                if showFlagScanResults {
                    ForEach(Array(flagScanResults.enumerated()), id: \.offset) { _, line in
                        Text(line).font(.system(size: 10, design: .monospaced)).foregroundStyle(lineColor(line)).textSelection(.enabled)
                    }
                }
            }
            
            // MSM Trust Cache Load (★★★★★ BEST APPROACH)
            Section("MSM Trust Cache Load (★★★★★ BREAKTHROUGH)") {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Load trust cache via RemoteCall into MobileStorageMounter. MSM already has pmap.load-trust-cache entitlement — no kernel writes needed!")
                        .font(.caption).foregroundStyle(.secondary)
                    Text("Safe: uses legitimate entitlement path, no KTRR/PPL risk")
                        .font(.caption2).foregroundStyle(.green)
                }
                
                Button {
                    runMSMExperiment()
                } label: {
                    HStack {
                        Image(systemName: isMSMRunning ? "hourglass" : "play.fill")
                            .foregroundStyle(.green)
                        Text(isMSMRunning ? "Running..." : "Run MSM Trust Cache Load")
                        Spacer()
                        Text("★★★★★").foregroundStyle(.yellow)
                    }
                }
                .disabled(isMSMRunning || !mgr.dsready || !mgr.rcready)
                
                if !mgr.rcready {
                    Text("⚠️ Need RemoteCall active (run jailbreak first)")
                        .font(.caption).foregroundStyle(.orange)
                }
                
                if !msmResults.isEmpty {
                    Button { showMSMResults.toggle() } label: {
                        HStack {
                            Image(systemName: "doc.text")
                            Text(showMSMResults ? "Hide" : "Show Results (\(msmResults.count) lines)")
                            Spacer()
                            Image(systemName: showMSMResults ? "chevron.up" : "chevron.down").font(.caption)
                        }
                    }
                }
                if showMSMResults {
                    ForEach(Array(msmResults.enumerated()), id: \.offset) { _, line in
                        Text(line).font(.system(size: 10, design: .monospaced)).foregroundStyle(lineColor(line)).textSelection(.enabled)
                    }
                }
            }
            
            // Data Segment Probe (★★★★ CRITICAL — RUN FIRST)
            Section("Data Segment Probe (★★★★ RUN FIRST)") {
                VStack(alignment: .leading, spacing: 4) {
                    Text("READ-ONLY probe to find which kernel addresses are actually writable. Previous writes to __DATA_CONST caused panic.")
                        .font(.caption).foregroundStyle(.secondary)
                    Text("NO WRITES except one safe test. Maps real writable __DATA range.")
                        .font(.caption2).foregroundStyle(.green)
                }
                
                Button {
                    runProbeExperiment()
                } label: {
                    HStack {
                        Image(systemName: isProbeRunning ? "hourglass" : "play.fill")
                            .foregroundStyle(.blue)
                        Text(isProbeRunning ? "Probing..." : "Run Data Segment Probe")
                        Spacer()
                        Text("★★★★").foregroundStyle(.yellow)
                    }
                }
                .disabled(isProbeRunning || !mgr.dsready)
                
                if !probeResults.isEmpty {
                    Button { showProbeResults.toggle() } label: {
                        HStack {
                            Image(systemName: "doc.text")
                            Text(showProbeResults ? "Hide" : "Show Results (\(probeResults.count) lines)")
                            Spacer()
                            Image(systemName: showProbeResults ? "chevron.up" : "chevron.down").font(.caption)
                        }
                    }
                }
                if showProbeResults {
                    ForEach(Array(probeResults.enumerated()), id: \.offset) { _, line in
                        Text(line).font(.system(size: 10, design: .monospaced)).foregroundStyle(lineColor(line)).textSelection(.enabled)
                    }
                }
            }
            
            Section("pmap_cs Disable (★ Legacy)") {
                Text("⚠️ CAUTION: Previous version wrote to wrong addresses. Now uses corrected addresses from Rust analyzer. Tests if pmap_cs flags need to be SET to 1.")
                    .font(.caption).foregroundStyle(.orange)
                
                Button {
                    runPmapExperiment()
                } label: {
                    HStack {
                        Image(systemName: isPmapRunning ? "hourglass" : "play.fill")
                            .foregroundStyle(.orange)
                        Text(isPmapRunning ? "Running..." : "Run pmap_cs Disable")
                        Spacer()
                    }
                }
                .disabled(isPmapRunning || !mgr.dsready)
                
                if !pmapResults.isEmpty {
                    Button { showPmapResults.toggle() } label: {
                        HStack {
                            Image(systemName: "doc.text")
                            Text(showPmapResults ? "Hide" : "Show Results (\(pmapResults.count) lines)")
                            Spacer()
                            Image(systemName: showPmapResults ? "chevron.up" : "chevron.down").font(.caption)
                        }
                    }
                }
                if showPmapResults {
                    ForEach(Array(pmapResults.enumerated()), id: \.offset) { _, line in
                        Text(line).font(.system(size: 10, design: .monospaced)).foregroundStyle(lineColor(line)).textSelection(.enabled)
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
    
    private func runFlagScanExperiment() {
        isFlagScanRunning = true
        flagScanResults.removeAll()
        showFlagScanResults = true
        DispatchQueue.global(qos: .userInitiated).async {
            let r = ExpSafeFlagScan.shared.runAll()
            DispatchQueue.main.async {
                flagScanResults = r
                isFlagScanRunning = false
            }
        }
    }
    
    private func runPmapExperiment() {
        isPmapRunning = true
        pmapResults.removeAll()
        showPmapResults = true
        DispatchQueue.global(qos: .userInitiated).async {
            let r = ExpPmapCSDisable.shared.runAll()
            DispatchQueue.main.async {
                pmapResults = r
                isPmapRunning = false
            }
        }
    }
    
    private func runProbeExperiment() {
        isProbeRunning = true
        probeResults.removeAll()
        showProbeResults = true
        DispatchQueue.global(qos: .userInitiated).async {
            let r = ExpDataSegmentProbe.shared.runAll()
            DispatchQueue.main.async {
                self.probeResults = r
                self.isProbeRunning = false
            }
        }
    }
    
    private func runMSMExperiment() {
        isMSMRunning = true
        msmResults.removeAll()
        showMSMResults = true
        DispatchQueue.global(qos: .userInitiated).async {
            let r = ExpMSMTrustCacheLoad.shared.runAll()
            DispatchQueue.main.async {
                self.msmResults = r
                self.isMSMRunning = false
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
