//
//  BleedingEdgeKRWPrimitiveView.swift
//  DSPloit
//
//  🔥 BLEEDING EDGE: Multi-Strategy Kernel R/W Primitive Dashboard
//  Strategy switching, performance monitoring, physical memory access
//  Created by Royan
//

import SwiftUI

struct BleedingEdgeKRWPrimitiveView: View {
    @ObservedObject private var engine = KernelRWPrimitiveEngine.shared
    @ObservedObject private var mgr = dspmgr.shared
    @State private var readAddr = ""
    @State private var writeAddr = ""
    @State private var writeValue = ""
    @State private var readResult: UInt64?
    @State private var hexDump: [UInt8] = []
    @State private var hexDumpAddr: UInt64 = 0
    @State private var dumpSize = "256"
    
    var body: some View {
        List {
            // Status & Stats
            Section {
                HStack(spacing: 14) {
                    ZStack {
                        Circle()
                            .fill((mgr.dsready ? Color.blue : Color.red).opacity(0.15))
                            .frame(width: 50, height: 50)
                        Image(systemName: "arrow.left.arrow.right")
                            .font(.title2)
                            .foregroundStyle(mgr.dsready ? .blue : .red)
                    }
                    VStack(alignment: .leading, spacing: 4) {
                        Text(mgr.dsready ? "KRW Active" : "Kernel Access Required")
                            .font(.headline)
                        Text("Strategy: \(engine.activeStrategy.rawValue)")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                
                // Stats
                HStack(spacing: 20) {
                    StatBox(title: "Reads", value: "\(engine.totalReads)", color: .blue)
                    StatBox(title: "Writes", value: "\(engine.totalWrites)", color: .orange)
                    StatBox(title: "Avg Latency", value: String(format: "%.2fms", engine.avgLatency), color: .green)
                }
                .padding(.vertical, 4)
            } header: {
                HeaderLabel(text: "R/W Primitive", icon: "arrow.left.arrow.right")
            }
            
            // Strategy Selection
            Section {
                ForEach(KRWStrategy.allCases, id: \.self) { strategy in
                    Button(action: { engine.activeStrategy = strategy }) {
                        HStack {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(strategy.rawValue)
                                    .font(.subheadline.bold())
                                    .foregroundStyle(.primary)
                                Text(strategy.description)
                                    .font(.caption2)
                                    .foregroundStyle(.secondary)
                                    .lineLimit(1)
                            }
                            Spacer()
                            
                            // Reliability indicator
                            Text(String(format: "%.0f%%", strategy.reliability * 100))
                                .font(.caption2.bold())
                                .foregroundStyle(strategy.reliability >= 0.9 ? .green : .orange)
                            
                            if engine.activeStrategy == strategy {
                                Image(systemName: "checkmark.circle.fill")
                                    .foregroundStyle(.blue)
                            }
                        }
                    }
                }
            } header: {
                HeaderLabel(text: "R/W Strategy", icon: "gearshape.2.fill")
            }
            
            // Read Operation
            Section {
                TextField("Address (hex)", text: $readAddr)
                    .font(.system(.caption, design: .monospaced))
                    .autocapitalization(.none)
                
                Button("Read 64-bit") {
                    guard let addr = UInt64(readAddr.replacingOccurrences(of: "0x", with: ""), radix: 16) else { return }
                    readResult = engine.read64(address: addr)
                }
                .disabled(!mgr.dsready || readAddr.isEmpty)
                
                if let result = readResult {
                    HStack {
                        Text("Result:")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        Text(String(format: "0x%016llx", result))
                            .font(.system(.caption, design: .monospaced))
                            .foregroundStyle(.cyan)
                            .textSelection(.enabled)
                    }
                }
            } header: {
                HeaderLabel(text: "Read", icon: "arrow.down.doc")
            }
            
            // Write Operation
            Section {
                TextField("Address (hex)", text: $writeAddr)
                    .font(.system(.caption, design: .monospaced))
                    .autocapitalization(.none)
                
                TextField("Value (hex)", text: $writeValue)
                    .font(.system(.caption, design: .monospaced))
                    .autocapitalization(.none)
                
                Button("Write 64-bit") {
                    guard let addr = UInt64(writeAddr.replacingOccurrences(of: "0x", with: ""), radix: 16),
                          let val = UInt64(writeValue.replacingOccurrences(of: "0x", with: ""), radix: 16) else { return }
                    let _ = engine.write64(address: addr, value: val)
                }
                .disabled(!mgr.dsready || writeAddr.isEmpty || writeValue.isEmpty)
            } header: {
                HeaderLabel(text: "Write", icon: "arrow.up.doc")
            }
            
            // Hex Dump
            Section {
                TextField("Dump Address (hex)", text: $readAddr)
                    .font(.system(.caption, design: .monospaced))
                    .autocapitalization(.none)
                
                TextField("Size (bytes)", text: $dumpSize)
                    .font(.system(.caption, design: .monospaced))
                    .keyboardType(.numberPad)
                
                Button("Hex Dump") {
                    guard let addr = UInt64(readAddr.replacingOccurrences(of: "0x", with: ""), radix: 16) else { return }
                    let size = Int(dumpSize) ?? 256
                    hexDump = engine.readBytes(address: addr, count: size)
                    hexDumpAddr = addr
                }
                .disabled(!mgr.dsready || readAddr.isEmpty)
                
                if !hexDump.isEmpty {
                    ScrollView(.horizontal) {
                        VStack(alignment: .leading, spacing: 2) {
                            ForEach(0..<min(hexDump.count / 16 + 1, 32), id: \.self) { row in
                                let offset = row * 16
                                if offset < hexDump.count {
                                    HStack(spacing: 4) {
                                        Text(String(format: "%08llx:", hexDumpAddr + UInt64(offset)))
                                            .font(.system(size: 9, design: .monospaced))
                                            .foregroundStyle(.orange)
                                        
                                        // Hex bytes
                                        ForEach(0..<16, id: \.self) { col in
                                            let idx = offset + col
                                            if idx < hexDump.count {
                                                Text(String(format: "%02x", hexDump[idx]))
                                                    .font(.system(size: 9, design: .monospaced))
                                                    .foregroundStyle(.cyan)
                                            } else {
                                                Text("  ")
                                                    .font(.system(size: 9, design: .monospaced))
                                            }
                                        }
                                        
                                        Text("|")
                                            .font(.system(size: 9, design: .monospaced))
                                            .foregroundStyle(.secondary)
                                        
                                        // ASCII
                                        let asciiStr = (0..<16).map { col -> Character in
                                            let idx = offset + col
                                            if idx < hexDump.count {
                                                let byte = hexDump[idx]
                                                return (byte >= 0x20 && byte <= 0x7E) ? Character(UnicodeScalar(byte)) : "."
                                            }
                                            return " "
                                        }
                                        Text(String(asciiStr))
                                            .font(.system(size: 9, design: .monospaced))
                                            .foregroundStyle(.green)
                                    }
                                }
                            }
                        }
                        .padding(8)
                    }
                    .background(Color.black.opacity(0.8))
                    .clipShape(RoundedRectangle(cornerRadius: 8))
                }
            } header: {
                HeaderLabel(text: "Hex Dump", icon: "number")
            }
            
            // Memory Regions
            Section {
                Button("Map Memory Regions") {
                    engine.mapMemoryRegions()
                }
                .disabled(!mgr.dsready)
                
                ForEach(engine.memoryRegions) { region in
                    VStack(alignment: .leading, spacing: 4) {
                        HStack {
                            Text(region.name)
                                .font(.caption.bold())
                            Spacer()
                            Text(region.permissions)
                                .font(.system(size: 10, design: .monospaced))
                                .padding(.horizontal, 4)
                                .padding(.vertical, 1)
                                .background(Color.blue.opacity(0.2))
                                .clipShape(Capsule())
                            
                            if region.isPPLProtected {
                                Image(systemName: "lock.shield.fill")
                                    .font(.caption2)
                                    .foregroundStyle(.red)
                            }
                        }
                        
                        Text(String(format: "0x%llx - 0x%llx (%llu KB)", region.start, region.end, region.size / 1024))
                            .font(.system(size: 9, design: .monospaced))
                            .foregroundStyle(.cyan)
                    }
                    .padding(.vertical, 2)
                }
            } header: {
                HeaderLabel(text: "Memory Regions (\(engine.memoryRegions.count))", icon: "map.fill")
            }
            
            // Operation Log
            if !engine.operations.isEmpty {
                Section {
                    ForEach(engine.operations.prefix(20)) { op in
                        HStack(spacing: 8) {
                            Image(systemName: op.success ? "checkmark.circle.fill" : "xmark.circle.fill")
                                .font(.caption2)
                                .foregroundStyle(op.success ? .green : .red)
                            
                            Text(op.type.rawValue)
                                .font(.system(size: 10, design: .monospaced))
                                .frame(width: 35, alignment: .leading)
                            
                            Text(String(format: "0x%llx", op.address))
                                .font(.system(size: 9, design: .monospaced))
                                .foregroundStyle(.cyan)
                                .lineLimit(1)
                            
                            Spacer()
                            
                            Text(String(format: "%.1fms", op.latencyMs))
                                .font(.system(size: 9, design: .monospaced))
                                .foregroundStyle(.secondary)
                        }
                    }
                    
                    Button("Clear Log") { engine.resetStats() }
                        .foregroundStyle(.red)
                        .font(.caption)
                } header: {
                    HeaderLabel(text: "Operations (\(engine.operations.count))", icon: "list.bullet.rectangle")
                }
            }
        }
        .navigationTitle("KRW Primitive")
        .premiumStyling()
    }
}

// MARK: - Stat Box

struct StatBox: View {
    let title: String
    let value: String
    let color: Color
    
    var body: some View {
        VStack(spacing: 2) {
            Text(value)
                .font(.system(.caption, design: .monospaced).bold())
                .foregroundStyle(color)
            Text(title)
                .font(.system(size: 9))
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity)
    }
}
