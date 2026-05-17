//
//  BleedingEdgeIOSurfaceKRW.swift
//  DSPloit
//
//  IOSurface KRW Research & Exploitation View
//  Created by Royan
//

import SwiftUI

struct BleedingEdgeIOSurfaceKRWView: View {
    @ObservedObject private var engine = IOSurfaceKRWEngine.shared
    @ObservedObject private var mgr = dspmgr.shared
    
    @State private var resultMsg = ""
    @State private var gxfReport = ""
    @State private var dmaReport = ""
    @State private var readAddr = ""
    @State private var readResult = ""
    
    var body: some View {
        List {
            // Status
            Section(header: HeaderLabel(text: "IOSurface KRW Status", icon: "cpu")) {
                HStack {
                    StatusIndicator(active: mgr.dsready, label: "Kernel")
                    Spacer()
                    StatusIndicator(active: mgr.sbxready, label: "Sandbox")
                    Spacer()
                    StatusIndicator(active: engine.isReady, label: "IOSurface")
                }
                
                if engine.surfaceID != 0 {
                    VStack(alignment: .leading, spacing: 4) {
                        InfoRow(label: "Surface ID", value: "\(engine.surfaceID)", color: .cyan)
                        InfoRow(label: "Mapped Addr", value: String(format: "0x%llx", engine.mappedAddress), color: .green)
                    }
                }
            }
            
            // Initialize
            Section(header: HeaderLabel(text: "Initialize", icon: "bolt.fill")) {
                Button(action: {
                    let result = engine.openIOSurfaceRoot()
                    resultMsg = result.message
                }) {
                    HStack {
                        Image(systemName: "play.circle.fill")
                        Text("Open IOSurfaceRoot")
                        Spacer()
                        if engine.isReady {
                            Image(systemName: "checkmark.circle.fill")
                                .foregroundStyle(.green)
                        }
                    }
                }
                .disabled(!mgr.dsready || !mgr.sbxready)
                
                if !mgr.sbxready {
                    PlainAlert(
                        title: "Requires Sandbox Escape",
                        icon: "lock.fill",
                        text: "Run sandbox escape first (Main tab → Initialize System)",
                        color: .orange
                    )
                }
            }
            
            // Read Test
            Section(header: HeaderLabel(text: "Memory Read (via IOSurface)", icon: "magnifyingglass")) {
                TextField("Address (hex)", text: $readAddr)
                    .font(.system(.body, design: .monospaced))
                
                Button("Read 8 bytes") {
                    guard let addr = UInt64(readAddr.replacingOccurrences(of: "0x", with: ""), radix: 16) else { return }
                    let val = engine.propertyRead(address: addr)
                    readResult = String(format: "0x%llx = 0x%016llx", addr, val)
                }
                .disabled(!mgr.dsready)
                
                if !readResult.isEmpty {
                    Text(readResult)
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundStyle(.green)
                        .textSelection(.enabled)
                }
            }
            
            // Research: GXF Entry
            Section(header: HeaderLabel(text: "GXF Entry Research", icon: "shield.lefthalf.filled")) {
                Button("Generate GXF Report") {
                    gxfReport = engine.researchGXFEntry()
                }
                
                if !gxfReport.isEmpty {
                    Text(gxfReport)
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundStyle(.cyan)
                        .textSelection(.enabled)
                }
            }
            
            // Research: DMA Bypass
            Section(header: HeaderLabel(text: "DMA PPL Bypass Research", icon: "bolt.shield")) {
                Button("Generate DMA Report") {
                    dmaReport = engine.researchDMABypass()
                }
                
                if !dmaReport.isEmpty {
                    Text(dmaReport)
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundStyle(.orange)
                        .textSelection(.enabled)
                }
            }
            
            // Kernelcache Analysis Results
            Section(header: HeaderLabel(text: "Kernelcache Findings", icon: "doc.text.magnifyingglass")) {
                VStack(alignment: .leading, spacing: 6) {
                    Text("From deep_analyze_v3.py:")
                        .font(.caption.bold())
                    
                    InfoRow(label: "IOSurface strings", value: "762", color: .cyan)
                    InfoRow(label: "PPL checks (bit#14)", value: "223", color: .red)
                    InfoRow(label: "GXF accesses", value: "50", color: .orange)
                    InfoRow(label: "pmap functions", value: "7 with PPL checks", color: .purple)
                    
                    Text("\nKey addresses (file offsets):")
                        .font(.caption.bold())
                    
                    Group {
                        Text("GXF handler: 0xf0c440")
                        Text("PPL check #1: 0xe33e14")
                        Text("pmap_enter: 0x11126c0 (667 branches)")
                        Text("IOSurfaceRoot: 0x0067d03b (string)")
                        Text("Largest func: 0x155e280 (106KB)")
                    }
                    .font(.system(size: 9, design: .monospaced))
                    .foregroundStyle(.green)
                }
            }
            
            // Result
            if !resultMsg.isEmpty {
                Section(header: HeaderLabel(text: "Result", icon: "info.circle")) {
                    Text(resultMsg)
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundStyle(engine.isReady ? .green : .red)
                        .textSelection(.enabled)
                }
            }
            
            // Log
            if !engine.statusLog.isEmpty {
                Section(header: HeaderLabel(text: "Log", icon: "terminal")) {
                    ForEach(engine.statusLog.suffix(20), id: \.self) { line in
                        Text(line)
                            .font(.system(size: 9, design: .monospaced))
                            .foregroundStyle(.secondary)
                    }
                }
            }
        }
        .navigationTitle("IOSurface KRW")
        .premiumStyling()
    }
}
