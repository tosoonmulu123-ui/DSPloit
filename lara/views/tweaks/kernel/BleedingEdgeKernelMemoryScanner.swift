//
//  BleedingEdgeKernelMemoryScanner.swift
//  DSPloit
//
//  🔥 BLEEDING EDGE: Advanced Kernel Memory Scanner
//  Pattern matching, signature scanning, automatic offset discovery
//  Port exploits to new iOS versions in HOURS not WEEKS
//  Created by Royan
//

import SwiftUI

// MARK: - Data Models

struct MemoryPattern: Identifiable {
    let id = UUID()
    let name: String
    let pattern: String // Hex pattern with wildcards: "FF 83 ?? D1"
    let mask: String    // Mask: "FF FF 00 FF"
    let category: PatternCategory
    let description: String
}

enum PatternCategory: String, CaseIterable {
    case procStructure = "proc Structure"
    case taskStructure = "task Structure"
    case ucredStructure = "ucred Structure"
    case vnodeStructure = "vnode Structure"
    case syscallTable = "Syscall Table"
    case kernelSymbols = "Kernel Symbols"
    case securityHooks = "Security Hooks"
    case custom = "Custom"
    
    var icon: String {
        switch self {
        case .procStructure: return "person.crop.square"
        case .taskStructure: return "square.stack.3d.up"
        case .ucredStructure: return "key.fill"
        case .vnodeStructure: return "doc.fill"
        case .syscallTable: return "list.bullet.rectangle"
        case .kernelSymbols: return "function"
        case .securityHooks: return "lock.shield"
        case .custom: return "star.fill"
        }
    }
}

struct ScanResult: Identifiable {
    let id = UUID()
    let address: UInt64
    let pattern: MemoryPattern
    let matchedBytes: [UInt8]
    let confidence: Double // 0.0 - 1.0
    let context: String
}

struct OffsetDiscovery: Identifiable {
    let id = UUID()
    let name: String
    let offset: UInt32
    let confidence: Double
    let method: String
    let verified: Bool
}

// MARK: - Kernel Memory Scanner Engine

class KernelMemoryScanner: ObservableObject {
    @Published var scanResults: [ScanResult] = []
    @Published var discoveredOffsets: [OffsetDiscovery] = []
    @Published var isScanning: Bool = false
    @Published var scanProgress: Double = 0.0
    @Published var patterns: [MemoryPattern] = []
    
    static let shared = KernelMemoryScanner()
    private let mgr = dspmgr.shared
    
    init() {
        loadPredefinedPatterns()
    }
    
    // MARK: - Predefined Patterns
    
    private func loadPredefinedPatterns() {
        patterns = [
            // proc structure patterns
            MemoryPattern(
                name: "proc->p_pid",
                pattern: "?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00",
                mask: "00 00 00 00 00 00 00 00 00 00 00 00 FF FF FF FF",
                category: .procStructure,
                description: "Process ID field in proc structure"
            ),
            MemoryPattern(
                name: "proc->p_ucred pointer",
                pattern: "FF FF FF FF 07 00 00 00",
                mask: "00 00 00 00 FF FF FF FF",
                category: .procStructure,
                description: "ucred pointer in proc structure (kernel address)"
            ),
            
            // Syscall table patterns
            MemoryPattern(
                name: "syscall table entry",
                pattern: "FF FF FF FF 07 00 00 00 ?? ?? ?? ?? ?? ?? ?? ??",
                mask: "00 00 00 00 FF FF FF FF 00 00 00 00 00 00 00 00",
                category: .syscallTable,
                description: "Syscall function pointer"
            ),
            
            // Security hook patterns
            MemoryPattern(
                name: "mac_proc_enforce",
                pattern: "01 00 00 00",
                mask: "FF FF FF FF",
                category: .securityHooks,
                description: "MAC policy enforcement flag"
            ),
            
            // ARM64 instruction patterns
            MemoryPattern(
                name: "RET instruction",
                pattern: "C0 03 5F D6",
                mask: "FF FF FF FF",
                category: .kernelSymbols,
                description: "ARM64 RET instruction for gadget finding"
            ),
            MemoryPattern(
                name: "BL instruction",
                pattern: "?? ?? ?? 94",
                mask: "00 00 00 FF",
                category: .kernelSymbols,
                description: "ARM64 BL (branch with link) instruction"
            ),
        ]
    }
    
    // MARK: - Pattern Scanning
    
    func scanKernelMemory(pattern: MemoryPattern, startAddr: UInt64, size: Int) {
        isScanning = true
        scanProgress = 0.0
        scanResults.removeAll()
        
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self, self.mgr.dsready else {
                DispatchQueue.main.async { self?.isScanning = false }
                return
            }
            
            let patternBytes = self.parseHexPattern(pattern.pattern)
            let maskBytes = self.parseHexPattern(pattern.mask)
            
            let chunkSize = 4096
            var currentAddr = startAddr
            let endAddr = startAddr + UInt64(size)
            
            while currentAddr < endAddr {
                let readSize = min(chunkSize, Int(endAddr - currentAddr))
                let chunk = self.mgr.readKernelBytes(address: currentAddr, count: readSize)
                
                // Search for pattern in chunk
                let matches = self.findPatternInBytes(chunk, pattern: patternBytes, mask: maskBytes)
                
                for matchOffset in matches {
                    let matchAddr = currentAddr + UInt64(matchOffset)
                    let matchedBytes = Array(chunk[matchOffset..<min(matchOffset + patternBytes.count, chunk.count)])
                    
                    let confidence = self.calculateConfidence(matchedBytes, pattern: patternBytes, mask: maskBytes)
                    let context = self.analyzeContext(address: matchAddr)
                    
                    let result = ScanResult(
                        address: matchAddr,
                        pattern: pattern,
                        matchedBytes: matchedBytes,
                        confidence: confidence,
                        context: context
                    )
                    
                    DispatchQueue.main.async {
                        self.scanResults.append(result)
                    }
                }
                
                currentAddr += UInt64(chunkSize)
                
                DispatchQueue.main.async {
                    self.scanProgress = Double(currentAddr - startAddr) / Double(size)
                }
            }
            
            DispatchQueue.main.async {
                self.isScanning = false
                self.scanProgress = 1.0
            }
        }
    }
    
    // MARK: - Automatic Offset Discovery
    
    func discoverOffsets(for iOSVersion: String) {
        isScanning = true
        discoveredOffsets.removeAll()
        
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self, self.mgr.dsready else {
                DispatchQueue.main.async { self?.isScanning = false }
                return
            }
            
            // Strategy 1: Analyze known proc structure
            let ourProc = ds_get_our_proc()
            if ourProc != 0 {
                self.analyzeStructure(baseAddr: ourProc, structName: "proc")
            }
            
            // Strategy 2: Analyze task structure
            let ourTask = ds_get_our_task()
            if ourTask != 0 {
                self.analyzeStructure(baseAddr: ourTask, structName: "task")
            }
            
            // Strategy 3: Pattern-based discovery
            self.discoverViaPatterns()
            
            DispatchQueue.main.async {
                self.isScanning = false
            }
        }
    }
    
    private func analyzeStructure(baseAddr: UInt64, structName: String) {
        // Read 1KB from structure
        let data = mgr.readKernelBytes(address: baseAddr, count: 1024)
        
        // Heuristic analysis
        for offset in stride(from: 0, to: 1024, by: 8) {
            guard offset + 8 <= data.count else { break }
            
            var value: UInt64 = 0
            for i in 0..<8 {
                value |= UInt64(data[offset + i]) << (i * 8)
            }
            
            // Check if it's a kernel pointer
            if value >= 0xFFFFFFF000000000 && value <= 0xFFFFFFF0FFFFFFFF {
                let discovery = OffsetDiscovery(
                    name: "\(structName)+0x\(String(format: "%x", offset))",
                    offset: UInt32(offset),
                    confidence: 0.7,
                    method: "Pointer heuristic",
                    verified: false
                )
                
                DispatchQueue.main.async {
                    self.discoveredOffsets.append(discovery)
                }
            }
            
            // Check if it's a PID (reasonable range)
            if value > 0 && value < 100000 {
                let discovery = OffsetDiscovery(
                    name: "\(structName)+0x\(String(format: "%x", offset)) (possible PID)",
                    offset: UInt32(offset),
                    confidence: 0.5,
                    method: "PID range heuristic",
                    verified: false
                )
                
                DispatchQueue.main.async {
                    self.discoveredOffsets.append(discovery)
                }
            }
        }
    }
    
    private func discoverViaPatterns() {
        // Use known patterns to discover offsets
        let kernelBase = mgr.kernbase
        
        // Scan first 16MB of kernel
        let scanSize = 16 * 1024 * 1024
        
        for pattern in patterns where pattern.category == .procStructure {
            scanKernelMemory(pattern: pattern, startAddr: kernelBase, size: scanSize)
        }
    }
    
    // MARK: - Helper Functions
    
    private func parseHexPattern(_ pattern: String) -> [UInt8] {
        let components = pattern.split(separator: " ")
        return components.compactMap { component in
            if component == "??" {
                return 0x00 // Wildcard
            }
            return UInt8(component, radix: 16)
        }
    }
    
    private func findPatternInBytes(_ bytes: [UInt8], pattern: [UInt8], mask: [UInt8]) -> [Int] {
        var matches: [Int] = []
        
        guard pattern.count == mask.count else { return matches }
        
        for i in 0...(bytes.count - pattern.count) {
            var isMatch = true
            
            for j in 0..<pattern.count {
                if mask[j] != 0x00 { // Not a wildcard
                    if bytes[i + j] != pattern[j] {
                        isMatch = false
                        break
                    }
                }
            }
            
            if isMatch {
                matches.append(i)
            }
        }
        
        return matches
    }
    
    private func calculateConfidence(_ matched: [UInt8], pattern: [UInt8], mask: [UInt8]) -> Double {
        var matchedBits = 0
        var totalBits = 0
        
        for i in 0..<min(matched.count, pattern.count) {
            if mask[i] != 0x00 {
                totalBits += 8
                if matched[i] == pattern[i] {
                    matchedBits += 8
                }
            }
        }
        
        return totalBits > 0 ? Double(matchedBits) / Double(totalBits) : 0.0
    }
    
    private func analyzeContext(address: UInt64) -> String {
        let kernelBase = mgr.kernbase
        let offset = address - kernelBase
        
        if offset < 0x800000 {
            return "__TEXT segment"
        } else if offset < 0x2000000 {
            return "__DATA segment"
        } else {
            return "Unknown region"
        }
    }
    
    // MARK: - Export Functions
    
    func exportOffsets() -> String {
        var output = "// Auto-discovered offsets\n"
        output += "// Generated: \(Date())\n\n"
        
        for offset in discoveredOffsets where offset.verified {
            output += "let \(offset.name) = 0x\(String(format: "%x", offset.offset))\n"
        }
        
        return output
    }
}

// MARK: - Main View

struct BleedingEdgeKernelMemoryScannerView: View {
    @ObservedObject private var scanner = KernelMemoryScanner.shared
    @ObservedObject private var mgr = dspmgr.shared
    @State private var selectedPattern: MemoryPattern?
    @State private var customPattern = ""
    @State private var customMask = ""
    @State private var scanStartAddr = ""
    @State private var scanSize = "16777216" // 16MB
    @State private var selectedTab = 0
    @State private var showExportSheet = false
    
    var body: some View {
        List {
            // Status
            Section {
                HStack {
                    Image(systemName: mgr.dsready ? "checkmark.circle.fill" : "xmark.circle.fill")
                        .font(.title2)
                        .foregroundStyle(mgr.dsready ? .green : .red)
                    VStack(alignment: .leading, spacing: 4) {
                        Text(mgr.dsready ? "Scanner Ready" : "Kernel Access Required")
                            .font(.headline)
                        Text(mgr.dsready ? "Pattern matching & offset discovery available" : "Run exploit first")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
            } header: {
                HeaderLabel(text: "Scanner Status", icon: "antenna.radiowaves.left.and.right")
            }
            
            // Quick Actions
            Section {
                Button(action: { scanner.discoverOffsets(for: "iOS 18") }) {
                    Label("🔥 Auto-Discover All Offsets", systemImage: "sparkles")
                        .foregroundStyle(.orange)
                }
                .disabled(!mgr.dsready || scanner.isScanning)
                
                Button(action: quickScanKernelText) {
                    Label("Scan Kernel __TEXT", systemImage: "doc.text.magnifyingglass")
                }
                .disabled(!mgr.dsready || scanner.isScanning)
                
                Button(action: quickScanKernelData) {
                    Label("Scan Kernel __DATA", systemImage: "cylinder.split.1x2")
                }
                .disabled(!mgr.dsready || scanner.isScanning)
            } header: {
                HeaderLabel(text: "Quick Scan", icon: "bolt.fill")
            }
            
            if scanner.isScanning {
                Section {
                    ProgressView(value: scanner.scanProgress)
                        .tint(.orange)
                    Text("\(Int(scanner.scanProgress * 100))% complete")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            
            // Pattern Library
            Section {
                ForEach(scanner.patterns) { pattern in
                    Button(action: { selectedPattern = pattern }) {
                        HStack {
                            Image(systemName: pattern.category.icon)
                                .foregroundStyle(.blue)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(pattern.name)
                                    .font(.subheadline.bold())
                                Text(pattern.description)
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                                    .lineLimit(1)
                            }
                            Spacer()
                            Image(systemName: "chevron.right")
                                .foregroundStyle(.tertiary)
                        }
                    }
                }
            } header: {
                HeaderLabel(text: "Pattern Library (\(scanner.patterns.count))", icon: "books.vertical.fill")
            }
            
            // Scan Results
            if !scanner.scanResults.isEmpty {
                Section {
                    ForEach(scanner.scanResults.prefix(50)) { result in
                        NavigationLink(destination: ScanResultDetailView(result: result)) {
                            ScanResultRow(result: result)
                        }
                    }
                    
                    if scanner.scanResults.count > 50 {
                        Text("+ \(scanner.scanResults.count - 50) more results")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                } header: {
                    HeaderLabel(text: "Scan Results (\(scanner.scanResults.count))", icon: "list.bullet.rectangle")
                }
            }
            
            // Discovered Offsets
            if !scanner.discoveredOffsets.isEmpty {
                Section {
                    ForEach(scanner.discoveredOffsets) { offset in
                        OffsetRow(offset: offset)
                    }
                    
                    Button(action: { showExportSheet = true }) {
                        Label("Export Offsets", systemImage: "square.and.arrow.up")
                    }
                } header: {
                    HeaderLabel(text: "Discovered Offsets (\(scanner.discoveredOffsets.count))", icon: "function")
                }
            }
            
            // Custom Pattern Scanner
            Section {
                TextField("Pattern (hex with ??)", text: $customPattern)
                    .font(.system(.caption, design: .monospaced))
                    .autocapitalization(.none)
                
                TextField("Mask (FF for match, 00 for wildcard)", text: $customMask)
                    .font(.system(.caption, design: .monospaced))
                    .autocapitalization(.none)
                
                TextField("Start Address (hex)", text: $scanStartAddr)
                    .font(.system(.caption, design: .monospaced))
                
                TextField("Size (bytes)", text: $scanSize)
                    .font(.system(.caption, design: .monospaced))
                    .keyboardType(.numberPad)
                
                Button("Scan Custom Pattern") {
                    scanCustomPattern()
                }
                .disabled(!mgr.dsready || scanner.isScanning || customPattern.isEmpty)
            } header: {
                HeaderLabel(text: "Custom Pattern", icon: "wand.and.stars")
            }
        }
        .navigationTitle("Memory Scanner")
        .premiumStyling()
        .sheet(isPresented: $showExportSheet) {
            ExportOffsetsView(offsets: scanner.discoveredOffsets)
        }
    }
    
    private func quickScanKernelText() {
        guard let pattern = scanner.patterns.first else { return }
        scanner.scanKernelMemory(
            pattern: pattern,
            startAddr: mgr.kernbase,
            size: 8 * 1024 * 1024 // 8MB
        )
    }
    
    private func quickScanKernelData() {
        guard let pattern = scanner.patterns.first else { return }
        scanner.scanKernelMemory(
            pattern: pattern,
            startAddr: mgr.kernbase + 0x800000,
            size: 8 * 1024 * 1024
        )
    }
    
    private func scanCustomPattern() {
        let pattern = MemoryPattern(
            name: "Custom",
            pattern: customPattern,
            mask: customMask,
            category: .custom,
            description: "User-defined pattern"
        )
        
        let startAddr = UInt64(scanStartAddr.replacingOccurrences(of: "0x", with: ""), radix: 16) ?? mgr.kernbase
        let size = Int(scanSize) ?? 1024 * 1024
        
        scanner.scanKernelMemory(pattern: pattern, startAddr: startAddr, size: size)
    }
}

// MARK: - Sub Views

struct ScanResultRow: View {
    let result: ScanResult
    
    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text(String(format: "0x%016llx", result.address))
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(.orange)
                Spacer()
                Text("\(Int(result.confidence * 100))%")
                    .font(.caption2.bold())
                    .padding(.horizontal, 6)
                    .padding(.vertical, 2)
                    .background(confidenceColor(result.confidence).opacity(0.2))
                    .foregroundStyle(confidenceColor(result.confidence))
                    .clipShape(Capsule())
            }
            
            Text(result.pattern.name)
                .font(.caption.bold())
            
            Text(result.context)
                .font(.caption2)
                .foregroundStyle(.secondary)
        }
        .padding(.vertical, 2)
    }
    
    private func confidenceColor(_ confidence: Double) -> Color {
        if confidence >= 0.9 { return .green }
        if confidence >= 0.7 { return .yellow }
        return .orange
    }
}

struct OffsetRow: View {
    let offset: OffsetDiscovery
    
    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text(offset.name)
                    .font(.system(.caption, design: .monospaced))
                Text("0x\(String(format: "%x", offset.offset))")
                    .font(.system(.caption2, design: .monospaced))
                    .foregroundStyle(.blue)
            }
            
            Spacer()
            
            if offset.verified {
                Image(systemName: "checkmark.seal.fill")
                    .foregroundStyle(.green)
            }
            
            Text("\(Int(offset.confidence * 100))%")
                .font(.caption2)
                .foregroundStyle(.secondary)
        }
    }
}

struct ScanResultDetailView: View {
    let result: ScanResult
    
    var body: some View {
        List {
            Section {
                LabeledContent("Address") {
                    Text(String(format: "0x%016llx", result.address))
                        .font(.system(.caption, design: .monospaced))
                }
                LabeledContent("Confidence") {
                    Text("\(Int(result.confidence * 100))%")
                        .foregroundStyle(result.confidence >= 0.9 ? .green : .orange)
                }
                LabeledContent("Context") { Text(result.context) }
            } header: {
                HeaderLabel(text: "Match Info", icon: "info.circle")
            }
            
            Section {
                LabeledContent("Name") { Text(result.pattern.name) }
                LabeledContent("Category") { Text(result.pattern.category.rawValue) }
                Text(result.pattern.description)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } header: {
                HeaderLabel(text: "Pattern", icon: "wand.and.stars")
            }
            
            Section {
                ScrollView(.horizontal) {
                    Text(result.matchedBytes.map { String(format: "%02X", $0) }.joined(separator: " "))
                        .font(.system(size: 10, design: .monospaced))
                        .textSelection(.enabled)
                }
            } header: {
                HeaderLabel(text: "Matched Bytes", icon: "number")
            }
        }
        .navigationTitle("Scan Result")
        .premiumStyling()
    }
}

struct ExportOffsetsView: View {
    let offsets: [OffsetDiscovery]
    @Environment(\.dismiss) private var dismiss
    
    var body: some View {
        NavigationStack {
            List {
                Section {
                    ScrollView {
                        Text(KernelMemoryScanner.shared.exportOffsets())
                            .font(.system(size: 10, design: .monospaced))
                            .textSelection(.enabled)
                            .padding()
                    }
                    .frame(height: 400)
                    
                    Button(action: {
                        UIPasteboard.general.string = KernelMemoryScanner.shared.exportOffsets()
                        UIImpactFeedbackGenerator(style: .medium).impactOccurred()
                    }) {
                        Label("Copy to Clipboard", systemImage: "doc.on.doc")
                    }
                }
            }
            .navigationTitle("Export Offsets")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Done") { dismiss() }
                }
            }
        }
    }
}
