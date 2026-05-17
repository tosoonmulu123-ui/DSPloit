//
//  BleedingEdgeHeapVisualizerView.swift
//  DSPloit
//
//  🔥 BLEEDING EDGE: Kernel Heap Visualizer & Feng Shui Planner
//  Real-time zone visualization, allocation tracking, spray automation
//  Created by Royan
//

import SwiftUI

struct BleedingEdgeHeapVisualizerView: View {
    @ObservedObject private var analyzer = KernelHeapAnalyzer.shared
    @ObservedObject private var mgr = dspmgr.shared
    @State private var selectedZone: KernelZoneInfo?
    @State private var sprayZone = "ipc_ports"
    @State private var sprayCount = "1000"
    @State private var showFengShui = false
    
    var body: some View {
        List {
            // Status
            Section {
                HStack(spacing: 14) {
                    ZStack {
                        Circle()
                            .fill((mgr.dsready ? Color.green : Color.red).opacity(0.15))
                            .frame(width: 50, height: 50)
                        Image(systemName: "memorychip.fill")
                            .font(.title2)
                            .foregroundStyle(mgr.dsready ? .green : .red)
                    }
                    VStack(alignment: .leading, spacing: 4) {
                        Text(mgr.dsready ? "Heap Analyzer Active" : "Kernel Access Required")
                            .font(.headline)
                        Text(mgr.dsready ? "\(analyzer.zones.count) zones mapped" : "Run exploit first")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
            } header: {
                HeaderLabel(text: "Heap Status", icon: "chart.bar.fill")
            }
            
            // Quick Actions
            Section {
                Button(action: { analyzer.enumerateZones() }) {
                    Label("🔥 Enumerate All Zones", systemImage: "square.grid.3x3.fill")
                        .foregroundStyle(.orange)
                }
                .disabled(!mgr.dsready || analyzer.isAnalyzing)
                
                Button(action: { analyzer.scanForVulnerabilities() }) {
                    Label("Scan for Vulnerabilities", systemImage: "ant.circle.fill")
                }
                .disabled(!mgr.dsready || analyzer.isAnalyzing)
                
                Button(action: { showFengShui = true }) {
                    Label("Feng Shui Planner", systemImage: "wand.and.stars")
                }
                .disabled(!mgr.dsready)
            } header: {
                HeaderLabel(text: "Actions", icon: "bolt.fill")
            }
            
            // Zone Overview
            if !analyzer.zones.isEmpty {
                Section {
                    ForEach(analyzer.zones.sorted(by: { $0.usagePercent > $1.usagePercent }).prefix(20)) { zone in
                        Button(action: { selectedZone = zone }) {
                            VStack(alignment: .leading, spacing: 6) {
                                HStack {
                                    Text(zone.name)
                                        .font(.system(.caption, design: .monospaced).bold())
                                        .foregroundStyle(.primary)
                                    Spacer()
                                    Text("\(zone.elementSize) bytes")
                                        .font(.caption2)
                                        .foregroundStyle(.secondary)
                                }
                                
                                // Usage bar
                                GeometryReader { geo in
                                    ZStack(alignment: .leading) {
                                        RoundedRectangle(cornerRadius: 3)
                                            .fill(Color.gray.opacity(0.2))
                                            .frame(height: 6)
                                        RoundedRectangle(cornerRadius: 3)
                                            .fill(usageColor(zone.usagePercent))
                                            .frame(width: geo.size.width * CGFloat(zone.usagePercent / 100.0), height: 6)
                                    }
                                }
                                .frame(height: 6)
                                
                                HStack {
                                    Text("\(zone.elementCount - zone.freeCount)/\(zone.elementCount) used")
                                        .font(.caption2)
                                        .foregroundStyle(.secondary)
                                    Spacer()
                                    Text(String(format: "%.1f%%", zone.usagePercent))
                                        .font(.caption2.bold())
                                        .foregroundStyle(usageColor(zone.usagePercent))
                                }
                            }
                            .padding(.vertical, 4)
                        }
                    }
                } header: {
                    HeaderLabel(text: "Kernel Zones (\(analyzer.zones.count))", icon: "square.grid.3x3")
                }
            }
            
            // Heap Spray
            Section {
                TextField("Target Zone", text: $sprayZone)
                    .font(.system(.caption, design: .monospaced))
                
                TextField("Spray Count", text: $sprayCount)
                    .font(.system(.caption, design: .monospaced))
                    .keyboardType(.numberPad)
                
                Button(action: startSpray) {
                    HStack {
                        Label("Start Heap Spray", systemImage: "drop.fill")
                        Spacer()
                        if analyzer.heapSprayActive {
                            Text("\(analyzer.sprayCount)")
                                .font(.caption.bold())
                                .foregroundStyle(.orange)
                            ProgressView()
                        }
                    }
                }
                .disabled(!mgr.dsready || analyzer.heapSprayActive)
                
                if analyzer.heapSprayActive {
                    Button("Stop Spray") {
                        analyzer.stopHeapSpray()
                    }
                    .foregroundStyle(.red)
                }
            } header: {
                HeaderLabel(text: "Heap Spray", icon: "drop.fill")
            }
            
            // Vulnerabilities
            if !analyzer.vulnerabilities.isEmpty {
                Section {
                    ForEach(analyzer.vulnerabilities) { vuln in
                        VStack(alignment: .leading, spacing: 4) {
                            HStack {
                                Image(systemName: "exclamationmark.triangle.fill")
                                    .foregroundStyle(vulnColor(vuln.severity))
                                Text(vuln.type.rawValue)
                                    .font(.caption.bold())
                                Spacer()
                                Text(vuln.severity.rawValue)
                                    .font(.caption2.bold())
                                    .padding(.horizontal, 6)
                                    .padding(.vertical, 2)
                                    .background(vulnColor(vuln.severity).opacity(0.15))
                                    .foregroundStyle(vulnColor(vuln.severity))
                                    .clipShape(Capsule())
                            }
                            
                            Text(String(format: "0x%016llx", vuln.address))
                                .font(.system(size: 10, design: .monospaced))
                                .foregroundStyle(.cyan)
                            
                            Text(vuln.description)
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                            
                            if vuln.exploitable {
                                Text("⚡ EXPLOITABLE")
                                    .font(.caption2.bold())
                                    .foregroundStyle(.red)
                            }
                        }
                        .padding(.vertical, 2)
                    }
                } header: {
                    HeaderLabel(text: "Vulnerabilities (\(analyzer.vulnerabilities.count))", icon: "ant.fill")
                }
            }
            
            // Feng Shui Plans
            if !analyzer.fengShuiPlans.isEmpty {
                Section {
                    ForEach(analyzer.fengShuiPlans) { plan in
                        VStack(alignment: .leading, spacing: 4) {
                            Text(plan.name)
                                .font(.subheadline.bold())
                            Text("Target: \(plan.targetZone)")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                            Text(String(format: "Success: %.0f%%", plan.successProbability * 100))
                                .font(.caption2.bold())
                                .foregroundStyle(.green)
                            
                            ForEach(plan.steps) { step in
                                HStack(spacing: 8) {
                                    Circle()
                                        .fill(Color.orange)
                                        .frame(width: 6, height: 6)
                                    Text("\(step.action.rawValue) x\(step.count)")
                                        .font(.system(size: 10, design: .monospaced))
                                }
                            }
                        }
                        .padding(.vertical, 4)
                    }
                } header: {
                    HeaderLabel(text: "Feng Shui Plans", icon: "wand.and.stars")
                }
            }
        }
        .navigationTitle("Heap Visualizer")
        .premiumStyling()
        .sheet(isPresented: $showFengShui) {
            FengShuiPlannerView(analyzer: analyzer)
        }
    }
    
    private func startSpray() {
        let count = Int(sprayCount) ?? 1000
        analyzer.startHeapSpray(zone: sprayZone, count: count, payload: Data())
    }
    
    private func usageColor(_ percent: Double) -> Color {
        if percent >= 90 { return .red }
        if percent >= 70 { return .orange }
        if percent >= 50 { return .yellow }
        return .green
    }
    
    private func vulnColor(_ severity: HeapVulnerability.VulnSeverity) -> Color {
        switch severity {
        case .critical: return .red
        case .high: return .orange
        case .medium: return .yellow
        case .low: return .green
        }
    }
}

struct FengShuiPlannerView: View {
    @ObservedObject var analyzer: KernelHeapAnalyzer
    @Environment(\.dismiss) private var dismiss
    @State private var targetZone = "ipc_ports"
    @State private var targetSize = "168"
    
    var body: some View {
        NavigationStack {
            List {
                Section {
                    TextField("Target Zone", text: $targetZone)
                        .font(.system(.caption, design: .monospaced))
                    TextField("Element Size", text: $targetSize)
                        .font(.system(.caption, design: .monospaced))
                        .keyboardType(.numberPad)
                    
                    Button("Generate Plan") {
                        let size = UInt32(targetSize) ?? 168
                        _ = analyzer.generateFengShuiPlan(targetZone: targetZone, targetSize: size)
                        dismiss()
                    }
                } header: {
                    HeaderLabel(text: "Configuration", icon: "slider.horizontal.3")
                }
                
                Section {
                    Text("Heap Feng Shui manipulates kernel zone allocations to achieve a predictable memory layout. This enables reliable exploitation of use-after-free and heap overflow vulnerabilities.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                } header: {
                    HeaderLabel(text: "About", icon: "info.circle")
                }
            }
            .navigationTitle("Feng Shui Planner")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Done") { dismiss() }
                }
            }
        }
    }
}
