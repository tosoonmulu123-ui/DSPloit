//
//  BleedingEdgeMachPortSprayView.swift
//  DSPloit
//
//  🔥 BLEEDING EDGE: Mach Port Spray & IPC Exploitation UI
//  Port enumeration, spray automation, OOL abuse, port replacement
//  Created by Royan
//

import SwiftUI

struct BleedingEdgeMachPortSprayView: View {
    @ObservedObject private var engine = MachPortSprayEngine.shared
    @ObservedObject private var mgr = dspmgr.shared
    @State private var showConfig = false
    
    var body: some View {
        List {
            // Status
            Section {
                HStack(spacing: 14) {
                    ZStack {
                        Circle()
                            .fill((mgr.dsready ? Color.indigo : Color.red).opacity(0.15))
                            .frame(width: 50, height: 50)
                        Image(systemName: "circle.grid.3x3.fill")
                            .font(.title2)
                            .foregroundStyle(mgr.dsready ? .indigo : .red)
                    }
                    VStack(alignment: .leading, spacing: 4) {
                        Text(mgr.dsready ? "Port Spray Ready" : "Kernel Access Required")
                            .font(.headline)
                        Text("\(engine.ports.count) ports enumerated | \(engine.allocatedPorts.count) sprayed")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
            } header: {
                HeaderLabel(text: "IPC Status", icon: "antenna.radiowaves.left.and.right")
            }
            
            // Quick Actions
            Section {
                Button(action: { engine.enumeratePorts() }) {
                    Label("Enumerate Mach Ports", systemImage: "list.bullet.rectangle")
                }
                
                Button(action: { engine.startSpray() }) {
                    HStack {
                        Label("🔥 Start Port Spray", systemImage: "drop.fill")
                            .foregroundStyle(.orange)
                        Spacer()
                        if engine.isSpraying {
                            ProgressView()
                        }
                    }
                }
                .disabled(engine.isSpraying)
                
                if !engine.allocatedPorts.isEmpty {
                    Button(action: { engine.destroySprayedPorts() }) {
                        Label("Destroy Sprayed Ports", systemImage: "trash")
                            .foregroundStyle(.red)
                    }
                }
                
                Button(action: { showConfig = true }) {
                    Label("Spray Configuration", systemImage: "slider.horizontal.3")
                }
            } header: {
                HeaderLabel(text: "Actions", icon: "bolt.fill")
            }
            
            // Spray Progress
            if engine.isSpraying {
                Section {
                    VStack(spacing: 8) {
                        ProgressView(value: engine.sprayProgress)
                            .tint(.indigo)
                        HStack {
                            Text("Spraying ports...")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                            Spacer()
                            Text("\(Int(engine.sprayProgress * 100))%")
                                .font(.caption.bold())
                                .foregroundStyle(.indigo)
                        }
                    }
                }
            }
            
            // Spray Results
            if !engine.sprayResults.isEmpty {
                Section {
                    ForEach(engine.sprayResults.prefix(5)) { result in
                        VStack(alignment: .leading, spacing: 4) {
                            HStack {
                                Image(systemName: result.success ? "checkmark.circle.fill" : "xmark.circle.fill")
                                    .foregroundStyle(result.success ? .green : .red)
                                Text(result.timestamp, style: .time)
                                    .font(.caption)
                                Spacer()
                            }
                            
                            HStack(spacing: 16) {
                                VStack(alignment: .leading) {
                                    Text("Ports")
                                        .font(.caption2)
                                        .foregroundStyle(.secondary)
                                    Text("\(result.portsCreated)")
                                        .font(.caption.bold())
                                }
                                VStack(alignment: .leading) {
                                    Text("Messages")
                                        .font(.caption2)
                                        .foregroundStyle(.secondary)
                                    Text("\(result.messagesQueued)")
                                        .font(.caption.bold())
                                }
                                VStack(alignment: .leading) {
                                    Text("OOL Pages")
                                        .font(.caption2)
                                        .foregroundStyle(.secondary)
                                    Text("\(result.oolPagesAllocated)")
                                        .font(.caption.bold())
                                }
                                VStack(alignment: .leading) {
                                    Text("Kernel Mem")
                                        .font(.caption2)
                                        .foregroundStyle(.secondary)
                                    Text(formatBytes(result.kernelMemoryUsed))
                                        .font(.caption.bold())
                                }
                            }
                        }
                        .padding(.vertical, 4)
                    }
                } header: {
                    HeaderLabel(text: "Spray Results", icon: "chart.bar.fill")
                }
            }
            
            // Port List
            if !engine.ports.isEmpty {
                Section {
                    ForEach(engine.ports.prefix(50)) { port in
                        HStack {
                            Image(systemName: portIcon(port.type))
                                .foregroundStyle(portColor(port.type))
                                .frame(width: 20)
                            
                            VStack(alignment: .leading, spacing: 2) {
                                Text(String(format: "0x%08x", port.portName))
                                    .font(.system(.caption, design: .monospaced))
                                Text(port.type.rawValue)
                                    .font(.caption2)
                                    .foregroundStyle(.secondary)
                            }
                            
                            Spacer()
                            
                            HStack(spacing: 4) {
                                if port.rights.send {
                                    Text("S")
                                        .font(.system(size: 9, design: .monospaced).bold())
                                        .padding(2)
                                        .background(Color.blue.opacity(0.2))
                                        .clipShape(RoundedRectangle(cornerRadius: 2))
                                }
                                if port.rights.receive {
                                    Text("R")
                                        .font(.system(size: 9, design: .monospaced).bold())
                                        .padding(2)
                                        .background(Color.green.opacity(0.2))
                                        .clipShape(RoundedRectangle(cornerRadius: 2))
                                }
                                if port.rights.sendOnce {
                                    Text("O")
                                        .font(.system(size: 9, design: .monospaced).bold())
                                        .padding(2)
                                        .background(Color.orange.opacity(0.2))
                                        .clipShape(RoundedRectangle(cornerRadius: 2))
                                }
                            }
                        }
                    }
                    
                    if engine.ports.count > 50 {
                        Text("+ \(engine.ports.count - 50) more ports")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                } header: {
                    HeaderLabel(text: "Mach Ports (\(engine.ports.count))", icon: "circle.grid.3x3")
                }
            }
        }
        .navigationTitle("Mach Port Spray")
        .premiumStyling()
        .sheet(isPresented: $showConfig) {
            PortSprayConfigView(config: $engine.config)
        }
    }
    
    private func portIcon(_ type: MachPortInfo.PortType) -> String {
        switch type {
        case .send: return "arrow.up.circle"
        case .receive: return "arrow.down.circle"
        case .sendOnce: return "arrow.up.circle.fill"
        case .portSet: return "circle.grid.2x2"
        case .dead: return "xmark.circle"
        }
    }
    
    private func portColor(_ type: MachPortInfo.PortType) -> Color {
        switch type {
        case .send: return .blue
        case .receive: return .green
        case .sendOnce: return .orange
        case .portSet: return .purple
        case .dead: return .gray
        }
    }
    
    private func formatBytes(_ bytes: UInt64) -> String {
        if bytes >= 1024 * 1024 {
            return String(format: "%.1f MB", Double(bytes) / 1024.0 / 1024.0)
        } else if bytes >= 1024 {
            return String(format: "%.1f KB", Double(bytes) / 1024.0)
        }
        return "\(bytes) B"
    }
}

struct PortSprayConfigView: View {
    @Binding var config: PortSprayConfig
    @Environment(\.dismiss) private var dismiss
    @State private var portCountStr = "1000"
    @State private var msgSizeStr = "256"
    @State private var oolSizeStr = "4096"
    
    var body: some View {
        NavigationStack {
            List {
                Section {
                    TextField("Port Count", text: $portCountStr)
                        .keyboardType(.numberPad)
                    TextField("Message Size", text: $msgSizeStr)
                        .keyboardType(.numberPad)
                    TextField("OOL Size", text: $oolSizeStr)
                        .keyboardType(.numberPad)
                    Toggle("Use OOL Descriptors", isOn: $config.useOOLDescriptors)
                    
                    Picker("Pattern", selection: $config.sprayPattern) {
                        ForEach(PortSprayConfig.SprayPattern.allCases, id: \.self) { pattern in
                            Text(pattern.rawValue).tag(pattern)
                        }
                    }
                } header: {
                    HeaderLabel(text: "Spray Config", icon: "slider.horizontal.3")
                }
                
                Section {
                    Text("Port spray allocates kernel ipc_port objects (168 bytes each in the ipc_ports zone). OOL descriptors allocate additional kernel pages for controlled data placement.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                } header: {
                    HeaderLabel(text: "Info", icon: "info.circle")
                }
            }
            .navigationTitle("Spray Config")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Save") {
                        config.portCount = Int(portCountStr) ?? 1000
                        config.messageSize = Int(msgSizeStr) ?? 256
                        config.oolSize = Int(oolSizeStr) ?? 4096
                        dismiss()
                    }
                }
            }
            .onAppear {
                portCountStr = "\(config.portCount)"
                msgSizeStr = "\(config.messageSize)"
                oolSizeStr = "\(config.oolSize)"
            }
        }
    }
}
