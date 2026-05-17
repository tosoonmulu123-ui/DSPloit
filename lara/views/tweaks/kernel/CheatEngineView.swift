//
//  CheatEngineView.swift
//  DSPloit
//
//  Ultra Powerful Real-Time Process Memory Cheat Engine
//  Kernel-level memory scanning, freezing, and manipulation
//  Created by Royan
//

import SwiftUI
import Combine

// MARK: - Cheat Engine Data Models

struct CheatScanResult: Identifiable {
    let id = UUID()
    let address: UInt64
    var currentValue: UInt64
    var frozen: Bool = false
    var frozenValue: UInt64 = 0
    var label: String = ""
}

enum CheatValueType: String, CaseIterable {
    case byte = "Byte (8-bit)"
    case short = "Short (16-bit)"
    case int = "Int (32-bit)"
    case long = "Long (64-bit)"
    case float = "Float (32-bit)"
    case double = "Double (64-bit)"
    
    var byteWidth: Int {
        switch self {
        case .byte: return 8
        case .short: return 16
        case .int, .float: return 32
        case .long, .double: return 64
        }
    }
}

enum CheatScanMode: String, CaseIterable {
    case exact = "Exact Value"
    case changed = "Changed"
    case unchanged = "Unchanged"
    case increased = "Increased"
    case decreased = "Decreased"
    case greaterThan = "Greater Than"
    case lessThan = "Less Than"
    case between = "Between"
    case unknown = "Unknown Initial"
}

// MARK: - Cheat Engine Core

class CheatEngineCore: ObservableObject {
    @Published var targetPID: Int32 = -1
    @Published var targetProcName: String = ""
    @Published var targetProcAddr: UInt64 = 0
    @Published var targetTaskAddr: UInt64 = 0
    
    @Published var scanResults: [CheatScanResult] = []
    @Published var savedAddresses: [CheatScanResult] = []
    @Published var isScanning = false
    @Published var scanProgress: Double = 0
    @Published var scanCount = 0
    @Published var previousResults: [UInt64: UInt64] = [:]
    
    @Published var freezeActive = false
    private var freezeTimer: Timer?
    
    static let shared = CheatEngineCore()
    private let mgr = dspmgr.shared
    
    func attachToProcess(pid: Int32) {
        guard mgr.dsready else { return }
        targetPID = pid
        let proc = mgr.findProc(pid: pid)
        targetProcAddr = proc
        if proc != 0 {
            targetTaskAddr = mgr.getTaskForProc(proc)
            // Read process name from kernel
            let nameAddr = proc + UInt64(off_proc_p_name)
            targetProcName = mgr.readKernelString(address: nameAddr, maxLen: 32)
        }
    }
    
    func attachToProcess(name: String) {
        guard mgr.dsready else { return }
        let proc = mgr.findProc(name: name)
        if proc != 0 {
            let pid = ds_kread32(proc + UInt64(off_proc_p_pid))
            targetPID = Int32(pid)
            targetProcAddr = proc
            targetTaskAddr = mgr.getTaskForProc(proc)
            targetProcName = name
        }
    }
    
    // MARK: - Memory Scanning
    
    func scanForValue(_ valueStr: String, type: CheatValueType, mode: CheatScanMode, rangeStart: UInt64, rangeEnd: UInt64) {
        guard mgr.dsready, targetProcAddr != 0 else { return }
        
        // SAFETY: Don't scan arbitrary ranges — only scan valid kernel heap addresses
        // Valid heap range for iOS: 0xffffffd000000000 - 0xffffffefFFFFFFFF
        var safeStart = rangeStart
        var safeEnd = rangeEnd
        
        // If user provided default/invalid range, use target proc's memory region
        if safeStart < 0xffffffd000000000 || safeEnd > 0xffffffffffff {
            // Scan around the target proc address (±64KB)
            safeStart = targetProcAddr > 0x10000 ? targetProcAddr - 0x10000 : targetProcAddr
            safeEnd = targetProcAddr + 0x10000
        }
        
        // Limit scan size to 256KB max to prevent crash
        let maxScanSize: UInt64 = 256 * 1024
        if safeEnd - safeStart > maxScanSize {
            safeEnd = safeStart + maxScanSize
        }
        
        isScanning = true
        scanProgress = 0
        
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self = self else { return }
            
            let targetValue = self.parseValue(valueStr, type: type)
            var results: [CheatScanResult] = []
            let step = UInt64(type.byteWidth / 8)
            let totalRange = safeEnd - safeStart
            var addr = safeStart
            
            if mode == .exact || mode == .unknown {
                while addr < safeEnd && results.count < 500 {
                    let readVal = self.readValueAtAddress(addr, type: type)
                    
                    let match: Bool
                    switch mode {
                    case .exact: match = readVal == targetValue
                    case .unknown: match = true // First scan stores all
                    default: match = false
                    }
                    
                    if match {
                        results.append(CheatScanResult(address: addr, currentValue: readVal))
                    }
                    
                    addr += step
                    if addr % (totalRange / 100 + 1) < step {
                        let progress = Double(addr - rangeStart) / Double(totalRange)
                        DispatchQueue.main.async { self.scanProgress = progress }
                    }
                }
            } else {
                // Rescan existing results
                let existing = self.scanResults
                for result in existing {
                    let currentVal = self.readValueAtAddress(result.address, type: type)
                    let prevVal = result.currentValue
                    
                    let match: Bool
                    switch mode {
                    case .changed: match = currentVal != prevVal
                    case .unchanged: match = currentVal == prevVal
                    case .increased: match = currentVal > prevVal
                    case .decreased: match = currentVal < prevVal
                    case .greaterThan: match = currentVal > targetValue
                    case .lessThan: match = currentVal < targetValue
                    default: match = currentVal == targetValue
                    }
                    
                    if match {
                        var r = result
                        r.currentValue = currentVal
                        results.append(r)
                    }
                }
            }
            
            DispatchQueue.main.async {
                self.scanResults = results
                self.scanCount = results.count
                self.isScanning = false
                self.scanProgress = 1.0
            }
        }
    }
    
    func refreshResults(type: CheatValueType) {
        guard mgr.dsready else { return }
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self = self else { return }
            var updated = self.scanResults
            for i in updated.indices {
                updated[i].currentValue = self.readValueAtAddress(updated[i].address, type: type)
            }
            DispatchQueue.main.async { self.scanResults = updated }
            
            var savedUpdated = self.savedAddresses
            for i in savedUpdated.indices {
                savedUpdated[i].currentValue = self.readValueAtAddress(savedUpdated[i].address, type: type)
            }
            DispatchQueue.main.async { self.savedAddresses = savedUpdated }
        }
    }
    
    // MARK: - Memory Write
    
    func writeValue(address: UInt64, valueStr: String, type: CheatValueType) {
        guard mgr.dsready else { return }
        let value = parseValue(valueStr, type: type)
        
        switch type {
        case .byte: ds_kwrite8(address, UInt8(value & 0xFF))
        case .short: ds_kwrite16(address, UInt16(value & 0xFFFF))
        case .int: ds_kwrite32(address, UInt32(value & 0xFFFFFFFF))
        case .long: ds_kwrite64(address, value)
        case .float:
            var f = Float(bitPattern: UInt32(value & 0xFFFFFFFF))
            if let fv = Float(valueStr) { f = fv }
            ds_kwrite32(address, f.bitPattern)
        case .double:
            var d = Double(bitPattern: value)
            if let dv = Double(valueStr) { d = dv }
            ds_kwrite64(address, d.bitPattern)
        }
    }
    
    // MARK: - Freeze System
    
    func startFreeze(type: CheatValueType) {
        guard !freezeActive else { return }
        freezeActive = true
        freezeTimer = Timer.scheduledTimer(withTimeInterval: 0.05, repeats: true) { [weak self] _ in
            guard let self = self, self.mgr.dsready else { return }
            for item in self.savedAddresses where item.frozen {
                switch type {
                case .byte: ds_kwrite8(item.address, UInt8(item.frozenValue & 0xFF))
                case .short: ds_kwrite16(item.address, UInt16(item.frozenValue & 0xFFFF))
                case .int, .float: ds_kwrite32(item.address, UInt32(item.frozenValue & 0xFFFFFFFF))
                case .long, .double: ds_kwrite64(item.address, item.frozenValue)
                }
            }
        }
    }
    
    func stopFreeze() {
        freezeActive = false
        freezeTimer?.invalidate()
        freezeTimer = nil
    }
    
    // MARK: - NOP Instruction Patching
    
    func nopInstruction(at address: UInt64) {
        guard mgr.dsready else { return }
        // ARM64 NOP = 0xD503201F
        ds_kwrite32(address, 0xD503201F)
    }
    
    // MARK: - Helpers
    
    private func readValueAtAddress(_ address: UInt64, type: CheatValueType) -> UInt64 {
        switch type {
        case .byte: return UInt64(ds_kread8(address))
        case .short: return UInt64(ds_kread16(address))
        case .int, .float: return UInt64(ds_kread32(address))
        case .long, .double: return ds_kread64(address)
        }
    }
    
    private func parseValue(_ str: String, type: CheatValueType) -> UInt64 {
        // Handle hex prefix
        if str.hasPrefix("0x") {
            return UInt64(str.dropFirst(2), radix: 16) ?? 0
        }
        // Handle float/double
        if type == .float, let f = Float(str) {
            return UInt64(f.bitPattern)
        }
        if type == .double, let d = Double(str) {
            return d.bitPattern
        }
        return UInt64(str) ?? 0
    }
    
    func formatValue(_ value: UInt64, type: CheatValueType) -> String {
        switch type {
        case .byte: return "\(value) (0x\(String(format: "%02x", value)))"
        case .short: return "\(value) (0x\(String(format: "%04x", value)))"
        case .int: return "\(value) (0x\(String(format: "%08x", value)))"
        case .long: return "\(value) (0x\(String(format: "%016llx", value)))"
        case .float:
            let f = Float(bitPattern: UInt32(value & 0xFFFFFFFF))
            return "\(f) (0x\(String(format: "%08x", UInt32(value & 0xFFFFFFFF))))"
        case .double:
            let d = Double(bitPattern: value)
            return "\(d) (0x\(String(format: "%016llx", value)))"
        }
    }
}

// MARK: - Main Cheat Engine View

struct CheatEngineView: View {
    @ObservedObject private var engine = CheatEngineCore.shared
    @ObservedObject private var mgr = dspmgr.shared
    
    @State private var targetInput = ""
    @State private var valueInput = ""
    @State private var valueType: CheatValueType = .int
    @State private var scanMode: CheatScanMode = .exact
    @State private var rangeStartStr = "0x0"
    @State private var rangeEndStr = "0x7FFFFFFFFFFF"
    @State private var writeAddr = ""
    @State private var writeVal = ""
    @State private var showProcessList = false
    @State private var processList: [dspmgr.KernelProcessInfo] = []
    @State private var selectedTab = 0
    @State private var statusMsg = ""
    @State private var searchText = ""
    
    private var filteredProcessList: [dspmgr.KernelProcessInfo] {
        if searchText.isEmpty {
            return processList
        } else {
            return processList.filter { $0.name.localizedCaseInsensitiveContains(searchText) || String($0.pid).contains(searchText) }
        }
    }
    
    var body: some View {
        List {
            // Target Process
            Section {
                HStack(spacing: 12) {
                    ZStack {
                        Circle().fill(.red.opacity(0.15)).frame(width: 50, height: 50)
                        Image(systemName: "gamecontroller.fill").font(.title2).foregroundStyle(.red)
                    }
                    VStack(alignment: .leading, spacing: 4) {
                        if engine.targetPID >= 0 {
                            Text(engine.targetProcName.isEmpty ? "PID \(engine.targetPID)" : engine.targetProcName)
                                .font(.headline)
                            Text(String(format: "PID: %d | proc: 0x%llx | task: 0x%llx", engine.targetPID, engine.targetProcAddr, engine.targetTaskAddr))
                                .font(.system(size: 9, design: .monospaced)).foregroundStyle(.secondary)
                        } else {
                            Text("No Target").font(.headline).foregroundStyle(.secondary)
                            Text("Select a process to begin").font(.caption).foregroundStyle(.tertiary)
                        }
                    }
                }
                
                HStack {
                    TextField("PID or Process Name", text: $targetInput)
                        .font(.system(.body, design: .monospaced))
                    Button("Attach") {
                        if let pid = Int32(targetInput) {
                            engine.attachToProcess(pid: pid)
                        } else {
                            engine.attachToProcess(name: targetInput)
                        }
                        statusMsg = engine.targetProcAddr != 0 ? "Attached to \(engine.targetProcName)" : "Process not found"
                    }.disabled(!mgr.dsready)
                }
                
                Button("Browse Running Processes") {
                    processList = mgr.getKernelProcessList()
                    showProcessList = true
                }.disabled(!mgr.dsready)
            } header: {
                HeaderLabel(text: "Target Process", icon: "scope")
            }
            
            // Value Type & Scan Mode
            Section {
                Picker("Value Type", selection: $valueType) {
                    ForEach(CheatValueType.allCases, id: \.self) { type in
                        Text(type.rawValue).tag(type)
                    }
                }
                Picker("Scan Mode", selection: $scanMode) {
                    ForEach(CheatScanMode.allCases, id: \.self) { mode in
                        Text(mode.rawValue).tag(mode)
                    }
                }
            } header: {
                HeaderLabel(text: "Scan Settings", icon: "slider.horizontal.3")
            }
            
            // Scan Controls
            Section {
                TextField("Value to find", text: $valueInput)
                    .font(.system(.body, design: .monospaced))
                
                HStack {
                    TextField("Range Start", text: $rangeStartStr)
                        .font(.system(.caption, design: .monospaced))
                    Text("→").foregroundStyle(.secondary)
                    TextField("Range End", text: $rangeEndStr)
                        .font(.system(.caption, design: .monospaced))
                }
                
                Button(action: startScan) {
                    HStack {
                        Image(systemName: "magnifyingglass")
                        Text(engine.scanResults.isEmpty ? "First Scan" : "Next Scan")
                        Spacer()
                        if engine.isScanning { ProgressView() }
                        else { Text("\(engine.scanCount) results").foregroundStyle(.secondary) }
                    }
                }.disabled(!mgr.dsready || engine.isScanning || engine.targetProcAddr == 0)
                
                if engine.isScanning {
                    ProgressView(value: engine.scanProgress).tint(.red)
                }
                
                HStack {
                    Button("Reset Scan") {
                        engine.scanResults.removeAll()
                        engine.scanCount = 0
                    }
                    Spacer()
                    Button("Refresh All") {
                        engine.refreshResults(type: valueType)
                    }.disabled(!mgr.dsready)
                }
            } header: {
                HeaderLabel(text: "Memory Scanner", icon: "magnifyingglass.circle.fill")
            }
            
            // Scan Results
            if !engine.scanResults.isEmpty {
                Section {
                    ForEach(engine.scanResults.prefix(100)) { result in
                        HStack {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(String(format: "0x%llx", result.address))
                                    .font(.system(.caption, design: .monospaced))
                                    .foregroundStyle(.orange)
                                Text(engine.formatValue(result.currentValue, type: valueType))
                                    .font(.system(size: 10, design: .monospaced))
                                    .foregroundStyle(.green)
                            }
                            Spacer()
                            Button(action: {
                                var r = result
                                r.frozenValue = result.currentValue
                                engine.savedAddresses.append(r)
                            }) {
                                Image(systemName: "pin.fill").foregroundStyle(.blue)
                            }.buttonStyle(.borderless)
                        }
                    }
                } header: {
                    HeaderLabel(text: "Results (\(engine.scanCount))", icon: "list.bullet.rectangle")
                }
            }
            
            // Direct Memory Write
            Section {
                TextField("Address (hex)", text: $writeAddr).font(.system(.body, design: .monospaced))
                TextField("New Value", text: $writeVal).font(.system(.body, design: .monospaced))
                Button("Write Value") {
                    guard let addr = UInt64(writeAddr.replacingOccurrences(of: "0x", with: ""), radix: 16) else { return }
                    engine.writeValue(address: addr, valueStr: writeVal, type: valueType)
                    statusMsg = String(format: "Written %@ to 0x%llx", writeVal, addr)
                }.disabled(!mgr.dsready).foregroundStyle(.red)
                Button("NOP Instruction at Address") {
                    guard let addr = UInt64(writeAddr.replacingOccurrences(of: "0x", with: ""), radix: 16) else { return }
                    engine.nopInstruction(at: addr)
                    statusMsg = String(format: "NOP patched at 0x%llx", addr)
                }.disabled(!mgr.dsready).foregroundStyle(.orange)
            } header: {
                HeaderLabel(text: "Direct Memory Write", icon: "pencil.line")
            }
            
            // Saved / Frozen Addresses
            if !engine.savedAddresses.isEmpty {
                Section {
                    Toggle("Freeze Engine Active", isOn: Binding(
                        get: { engine.freezeActive },
                        set: { val in
                            if val { engine.startFreeze(type: valueType) }
                            else { engine.stopFreeze() }
                        }
                    ))
                    
                    ForEach(engine.savedAddresses.indices, id: \.self) { idx in
                        VStack(alignment: .leading, spacing: 4) {
                            HStack {
                                TextField("Label", text: Binding(
                                    get: { engine.savedAddresses[idx].label },
                                    set: { engine.savedAddresses[idx].label = $0 }
                                )).font(.caption)
                                
                                Toggle("", isOn: Binding(
                                    get: { engine.savedAddresses[idx].frozen },
                                    set: { newVal in
                                        engine.savedAddresses[idx].frozen = newVal
                                        if newVal { engine.savedAddresses[idx].frozenValue = engine.savedAddresses[idx].currentValue }
                                    }
                                )).labelsHidden()
                                
                                Image(systemName: engine.savedAddresses[idx].frozen ? "snowflake" : "snowflake.slash")
                                    .foregroundStyle(engine.savedAddresses[idx].frozen ? .cyan : .secondary)
                            }
                            
                            Text(String(format: "0x%llx = %@", engine.savedAddresses[idx].address, engine.formatValue(engine.savedAddresses[idx].currentValue, type: valueType)))
                                .font(.system(size: 10, design: .monospaced))
                                .foregroundStyle(.green)
                            
                            HStack {
                                TextField("New value", text: Binding(
                                    get: { "" },
                                    set: { val in
                                        guard !val.isEmpty else { return }
                                        engine.writeValue(address: engine.savedAddresses[idx].address, valueStr: val, type: valueType)
                                        engine.savedAddresses[idx].frozenValue = engine.parseValuePublic(val, type: valueType)
                                    }
                                )).font(.system(.caption, design: .monospaced))
                                
                                Button(action: {
                                    engine.savedAddresses.remove(at: idx)
                                }) {
                                    Image(systemName: "trash").foregroundStyle(.red)
                                }.buttonStyle(.borderless)
                            }
                        }.padding(.vertical, 4)
                    }
                } header: {
                    HeaderLabel(text: "Saved Addresses (\(engine.savedAddresses.count))", icon: "bookmark.fill")
                }
            }
            
            // Hex Viewer
            Section {
                Button("Dump 256 Bytes at Address") {
                    guard let addr = UInt64(writeAddr.replacingOccurrences(of: "0x", with: ""), radix: 16) else { return }
                    let bytes = mgr.readKernelBytes(address: addr, count: 256)
                    var hex = ""
                    for row in stride(from: 0, to: bytes.count, by: 16) {
                        hex += String(format: "%016llx  ", addr + UInt64(row))
                        for col in 0..<min(16, bytes.count - row) {
                            hex += String(format: "%02x ", bytes[row + col])
                        }
                        hex += " |"
                        for col in 0..<min(16, bytes.count - row) {
                            let c = bytes[row + col]
                            hex += (c >= 0x20 && c < 0x7F) ? String(UnicodeScalar(c)) : "."
                        }
                        hex += "|\n"
                    }
                    statusMsg = hex
                }.disabled(!mgr.dsready)
            } header: {
                HeaderLabel(text: "Hex Viewer", icon: "number")
            }
            
            // Status
            if !statusMsg.isEmpty {
                Section {
                    Text(statusMsg)
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundStyle(.green)
                        .textSelection(.enabled)
                } header: {
                    HeaderLabel(text: "Status", icon: "info.circle")
                }
            }
        }
        .navigationTitle("Cheat Engine")
        .premiumStyling()
        .sheet(isPresented: $showProcessList) {
            NavigationStack {
                List(filteredProcessList) { proc in
                    Button(action: {
                        engine.attachToProcess(pid: proc.pid)
                        showProcessList = false
                        searchText = ""
                        statusMsg = "Attached to \(proc.name) (PID \(proc.pid))"
                    }) {
                        HStack {
                            Text("\(proc.pid)").font(.system(.caption, design: .monospaced)).foregroundStyle(.orange).frame(width: 50, alignment: .leading)
                            Text(proc.name).font(.subheadline)
                            Spacer()
                            Text(proc.uid == 0 ? "root" : "uid:\(proc.uid)").font(.caption2).foregroundStyle(proc.uid == 0 ? .red : .secondary)
                        }
                    }
                }
                .navigationTitle("Select Process")
                .searchable(text: $searchText, prompt: "Search process name or PID")
                .toolbar {
                    ToolbarItem(placement: .cancellationAction) {
                        Button("Cancel") { showProcessList = false }
                    }
                }
            }
        }
    }
    
    private func startScan() {
        let start = UInt64(rangeStartStr.replacingOccurrences(of: "0x", with: ""), radix: 16) ?? 0
        let end = UInt64(rangeEndStr.replacingOccurrences(of: "0x", with: ""), radix: 16) ?? 0x7FFFFFFFFFFF
        engine.scanForValue(valueInput, type: valueType, mode: scanMode, rangeStart: start, rangeEnd: end)
    }
}

// Extension to expose parseValue publicly for the binding
extension CheatEngineCore {
    func parseValuePublic(_ str: String, type: CheatValueType) -> UInt64 {
        if str.hasPrefix("0x") { return UInt64(str.dropFirst(2), radix: 16) ?? 0 }
        if type == .float, let f = Float(str) { return UInt64(f.bitPattern) }
        if type == .double, let d = Double(str) { return d.bitPattern }
        return UInt64(str) ?? 0
    }
}
