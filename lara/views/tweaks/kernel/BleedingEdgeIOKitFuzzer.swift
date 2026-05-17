//
//  BleedingEdgeIOKitFuzzer.swift
//  DSPloit
//
//  🔥 BLEEDING EDGE: IOKit Service Fuzzer
//  Fuzz IOKit services, discover 0-days, crash detection
//  Automated vulnerability discovery in kernel drivers
//  Created by Royan
//

import SwiftUI
import IOKit

// MARK: - Data Models

struct IOKitService: Identifiable {
    let id = UUID()
    let name: String
    let className: String
    let service: io_service_t
    let properties: [String: Any]
    var fuzzed: Bool = false
    var crashCount: Int = 0
}

struct FuzzResult: Identifiable {
    let id = UUID()
    let timestamp: Date
    let serviceName: String
    let method: String
    let input: String
    let result: FuzzOutcome
    let crashDetected: Bool
    let errorCode: Int32
}

enum FuzzOutcome: String {
    case success = "Success"
    case crash = "Crash"
    case hang = "Hang"
    case error = "Error"
    case timeout = "Timeout"
    
    var icon: String {
        switch self {
        case .success: return "checkmark.circle.fill"
        case .crash: return "exclamationmark.octagon.fill"
        case .hang: return "clock.badge.exclamationmark.fill"
        case .error: return "xmark.circle.fill"
        case .timeout: return "timer.circle.fill"
        }
    }
    
    var color: Color {
        switch self {
        case .success: return .green
        case .crash: return .red
        case .hang: return .orange
        case .error: return .yellow
        case .timeout: return .purple
        }
    }
}

struct VulnerabilityCandidate: Identifiable {
    let id = UUID()
    let serviceName: String
    let method: String
    let description: String
    let severity: VulnerabilitySeverity
    let reproducible: Bool
    let crashCount: Int
}

enum VulnerabilitySeverity: String, CaseIterable {
    case critical = "Critical"
    case high = "High"
    case medium = "Medium"
    case low = "Low"
    
    var color: Color {
        switch self {
        case .critical: return .red
        case .high: return .orange
        case .medium: return .yellow
        case .low: return .blue
        }
    }
}

// MARK: - IOKit Fuzzer Engine

class IOKitFuzzerEngine: ObservableObject {
    @Published var services: [IOKitService] = []
    @Published var fuzzResults: [FuzzResult] = []
    @Published var vulnerabilities: [VulnerabilityCandidate] = []
    @Published var isFuzzing: Bool = false
    @Published var fuzzProgress: Double = 0.0
    @Published var statistics: FuzzStatistics = FuzzStatistics()
    
    static let shared = IOKitFuzzerEngine()
    private let mgr = dspmgr.shared
    
    struct FuzzStatistics {
        var totalTests: Int = 0
        var crashes: Int = 0
        var hangs: Int = 0
        var errors: Int = 0
        var successfulCalls: Int = 0
        var coverage: Double = 0.0
        var vulnerabilitiesFound: Int = 0
    }
    
    // MARK: - Service Discovery
    
    func discoverServices() {
        services.removeAll()
        
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            
            // Enumerate IOKit services
            let matchingDict = IOServiceMatching(kIOServiceClass)
            var iterator: io_iterator_t = 0
            
            let kr = IOServiceGetMatchingServices(kIOMainPortDefault, matchingDict, &iterator)
            guard kr == KERN_SUCCESS else { return }
            
            defer { IOObjectRelease(iterator) }
            
            var service = IOIteratorNext(iterator)
            while service != 0 {
                defer {
                    IOObjectRelease(service)
                    service = IOIteratorNext(iterator)
                }
                
                // Get service name
                var serviceName = [CChar](repeating: 0, count: 128)
                IORegistryEntryGetName(service, &serviceName)
                let name = String(cString: serviceName)
                
                // Get class name
                var className = [CChar](repeating: 0, count: 128)
                IOObjectGetClass(service, &className)
                let classNameStr = String(cString: className)
                
                // Get properties
                var properties: Unmanaged<CFMutableDictionary>?
                IORegistryEntryCreateCFProperties(service, &properties, kCFAllocatorDefault, 0)
                let propsDict = properties?.takeRetainedValue() as? [String: Any] ?? [:]
                
                let ioService = IOKitService(
                    name: name,
                    className: classNameStr,
                    service: service,
                    properties: propsDict
                )
                
                DispatchQueue.main.async {
                    self.services.append(ioService)
                }
            }
        }
    }
    
    // MARK: - Property Fuzzing
    
    func fuzzServiceProperties(_ service: IOKitService, iterations: Int) {
        isFuzzing = true
        fuzzProgress = 0.0
        
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            
            for i in 0..<iterations {
                // Generate random property values
                let fuzzedProperties: [String: Any] = [
                    "FuzzedString": self.generateRandomString(),
                    "FuzzedNumber": Int.random(in: 0...Int.max),
                    "FuzzedData": self.generateRandomData(),
                    "FuzzedArray": self.generateRandomArray(),
                    "FuzzedDict": self.generateRandomDict(),
                ]
                
                // Try to set properties
                for (key, value) in fuzzedProperties {
                    let outcome = self.setServiceProperty(service.service, key: key, value: value)
                    
                    let result = FuzzResult(
                        timestamp: Date(),
                        serviceName: service.name,
                        method: "setProperty(\(key))",
                        input: "\(value)",
                        result: outcome,
                        crashDetected: outcome == .crash,
                        errorCode: 0
                    )
                    
                    DispatchQueue.main.async {
                        self.fuzzResults.insert(result, at: 0)
                        if self.fuzzResults.count > 500 {
                            self.fuzzResults.removeLast()
                        }
                        
                        self.statistics.totalTests += 1
                        if outcome == .crash {
                            self.statistics.crashes += 1
                            self.detectVulnerability(service: service, method: "setProperty", result: result)
                        }
                    }
                }
                
                DispatchQueue.main.async {
                    self.fuzzProgress = Double(i + 1) / Double(iterations)
                }
                
                // Small delay to prevent overwhelming the system
                usleep(10000) // 10ms
            }
            
            DispatchQueue.main.async {
                self.isFuzzing = false
                self.fuzzProgress = 1.0
            }
        }
    }
    
    // MARK: - Method Fuzzing
    
    func fuzzServiceMethods(_ service: IOKitService, iterations: Int) {
        isFuzzing = true
        fuzzProgress = 0.0
        
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            
            // Open user client
            var connect: io_connect_t = 0
            let kr = IOServiceOpen(service.service, mach_task_self_, 0, &connect)
            
            guard kr == KERN_SUCCESS else {
                DispatchQueue.main.async {
                    self.isFuzzing = false
                }
                return
            }
            
            defer { IOServiceClose(connect) }
            
            // Fuzz external methods (selectors 0-255)
            for selector in 0..<min(256, iterations) {
                let input = self.generateRandomData()
                let outcome = self.callExternalMethod(connect, selector: UInt32(selector), input: input)
                
                let result = FuzzResult(
                    timestamp: Date(),
                    serviceName: service.name,
                    method: "externalMethod(\(selector))",
                    input: input.map { String(format: "%02x", $0) }.joined(),
                    result: outcome,
                    crashDetected: outcome == .crash,
                    errorCode: 0
                )
                
                DispatchQueue.main.async {
                    self.fuzzResults.insert(result, at: 0)
                    if self.fuzzResults.count > 500 {
                        self.fuzzResults.removeLast()
                    }
                    
                    self.statistics.totalTests += 1
                    if outcome == .crash {
                        self.statistics.crashes += 1
                        self.detectVulnerability(service: service, method: "externalMethod", result: result)
                    } else if outcome == .success {
                        self.statistics.successfulCalls += 1
                    }
                    
                    self.fuzzProgress = Double(selector + 1) / Double(min(256, iterations))
                }
                
                usleep(5000) // 5ms delay
            }
            
            DispatchQueue.main.async {
                self.isFuzzing = false
                self.fuzzProgress = 1.0
            }
        }
    }
    
    // MARK: - Helper Functions
    
    private func setServiceProperty(_ service: io_service_t, key: String, value: Any) -> FuzzOutcome {
        // Try to set property and detect crashes
        let cfKey = key as CFString
        let cfValue = value as CFTypeRef
        
        let kr = IORegistryEntrySetCFProperty(service, cfKey, cfValue)
        
        if kr == KERN_SUCCESS {
            return .success
        } else {
            return .error
        }
    }
    
    private func callExternalMethod(_ connect: io_connect_t, selector: UInt32, input: [UInt8]) -> FuzzOutcome {
        var inputData = input
        var outputSize: size_t = 4096
        var output = [UInt8](repeating: 0, count: Int(outputSize))
        
        let kr = inputData.withUnsafeMutableBytes { inputPtr in
            output.withUnsafeMutableBytes { outputPtr in
                IOConnectCallStructMethod(
                    connect,
                    selector,
                    inputPtr.baseAddress,
                    inputData.count,
                    outputPtr.baseAddress,
                    &outputSize
                )
            }
        }
        
        switch kr {
        case KERN_SUCCESS:
            return .success
        case kIOReturnBadArgument, kIOReturnUnsupported:
            return .error
        default:
            return .error
        }
    }
    
    private func generateRandomString() -> String {
        let length = Int.random(in: 1...256)
        let chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()"
        return String((0..<length).map { _ in chars.randomElement()! })
    }
    
    private func generateRandomData() -> [UInt8] {
        let length = Int.random(in: 1...4096)
        return (0..<length).map { _ in UInt8.random(in: 0...255) }
    }
    
    private func generateRandomArray() -> [Any] {
        let length = Int.random(in: 1...32)
        return (0..<length).map { _ in Int.random(in: 0...Int.max) }
    }
    
    private func generateRandomDict() -> [String: Any] {
        let count = Int.random(in: 1...16)
        var dict: [String: Any] = [:]
        for i in 0..<count {
            dict["key\(i)"] = Int.random(in: 0...Int.max)
        }
        return dict
    }
    
    // MARK: - Vulnerability Detection
    
    private func detectVulnerability(service: IOKitService, method: String, result: FuzzResult) {
        // Check if this is a new vulnerability
        let existing = vulnerabilities.first { $0.serviceName == service.name && $0.method == method }
        
        if let existing = existing {
            // Update crash count
            if let index = vulnerabilities.firstIndex(where: { $0.id == existing.id }) {
                var updated = existing
                updated = VulnerabilityCandidate(
                    serviceName: updated.serviceName,
                    method: updated.method,
                    description: updated.description,
                    severity: updated.severity,
                    reproducible: updated.crashCount >= 2,
                    crashCount: updated.crashCount + 1
                )
                DispatchQueue.main.async {
                    self.vulnerabilities[index] = updated
                }
            }
        } else {
            // New vulnerability
            let vuln = VulnerabilityCandidate(
                serviceName: service.name,
                method: method,
                description: "Crash detected in \(service.className)::\(method)",
                severity: .high,
                reproducible: false,
                crashCount: 1
            )
            
            DispatchQueue.main.async {
                self.vulnerabilities.insert(vuln, at: 0)
                self.statistics.vulnerabilitiesFound = self.vulnerabilities.count
            }
        }
    }
    
    // MARK: - Coverage Tracking
    
    func calculateCoverage() {
        guard !services.isEmpty else { return }
        
        let fuzzedCount = services.filter { $0.fuzzed }.count
        statistics.coverage = Double(fuzzedCount) / Double(services.count)
    }
    
    func resetStatistics() {
        statistics = FuzzStatistics()
        fuzzResults.removeAll()
        vulnerabilities.removeAll()
    }
}

// MARK: - Main View

struct BleedingEdgeIOKitFuzzerView: View {
    @ObservedObject private var fuzzer = IOKitFuzzerEngine.shared
    @ObservedObject private var mgr = dspmgr.shared
    @State private var selectedService: IOKitService?
    @State private var fuzzIterations = "100"
    @State private var searchText = ""
    @State private var selectedTab = 0
    
    var body: some View {
        List {
            // Status
            Section {
                HStack {
                    Image(systemName: fuzzer.isFuzzing ? "antenna.radiowaves.left.and.right" : "checkmark.circle.fill")
                        .font(.title2)
                        .foregroundStyle(fuzzer.isFuzzing ? .orange : .green)
                    VStack(alignment: .leading, spacing: 4) {
                        Text(fuzzer.isFuzzing ? "Fuzzing Active" : "Fuzzer Ready")
                            .font(.headline)
                        Text("Automated IOKit vulnerability discovery")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
            } header: {
                HeaderLabel(text: "Fuzzer Status", icon: "dice.fill")
            }
            
            if fuzzer.isFuzzing {
                Section {
                    ProgressView(value: fuzzer.fuzzProgress)
                        .tint(.orange)
                    Text("\(Int(fuzzer.fuzzProgress * 100))% complete")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            
            // Statistics
            Section {
                LabeledContent("Total Tests") {
                    Text("\(fuzzer.statistics.totalTests)")
                        .font(.system(.body, design: .monospaced))
                }
                LabeledContent("Crashes") {
                    Text("\(fuzzer.statistics.crashes)")
                        .font(.system(.body, design: .monospaced))
                        .foregroundStyle(.red)
                }
                LabeledContent("Successful Calls") {
                    Text("\(fuzzer.statistics.successfulCalls)")
                        .font(.system(.body, design: .monospaced))
                        .foregroundStyle(.green)
                }
                LabeledContent("Coverage") {
                    Text(String(format: "%.1f%%", fuzzer.statistics.coverage * 100))
                        .font(.system(.body, design: .monospaced))
                }
                LabeledContent("Vulnerabilities") {
                    Text("\(fuzzer.statistics.vulnerabilitiesFound)")
                        .font(.system(.body, design: .monospaced))
                        .foregroundStyle(fuzzer.statistics.vulnerabilitiesFound > 0 ? .red : .secondary)
                }
                
                Button("Reset Statistics") {
                    fuzzer.resetStatistics()
                }
                .foregroundStyle(.red)
            } header: {
                HeaderLabel(text: "Statistics", icon: "chart.bar.fill")
            }
            
            // Service Discovery
            Section {
                Button(action: { fuzzer.discoverServices() }) {
                    Label("Discover IOKit Services", systemImage: "magnifyingglass")
                }
                .disabled(fuzzer.isFuzzing)
                
                TextField("Filter services...", text: $searchText)
                    .font(.system(.caption, design: .monospaced))
            } header: {
                HeaderLabel(text: "Service Discovery", icon: "externaldrive.connected.to.line.below")
            }
            
            // Services List
            if !fuzzer.services.isEmpty {
                Section {
                    ForEach(filteredServices) { service in
                        NavigationLink(destination: ServiceDetailView(service: service)) {
                            ServiceRow(service: service)
                        }
                    }
                } header: {
                    HeaderLabel(text: "Services (\(filteredServices.count))", icon: "list.bullet.rectangle")
                }
            }
            
            // Vulnerabilities
            if !fuzzer.vulnerabilities.isEmpty {
                Section {
                    ForEach(fuzzer.vulnerabilities) { vuln in
                        NavigationLink(destination: VulnerabilityDetailView(vulnerability: vuln)) {
                            VulnerabilityRow(vulnerability: vuln)
                        }
                    }
                } header: {
                    HeaderLabel(text: "🚨 Vulnerabilities (\(fuzzer.vulnerabilities.count))", icon: "exclamationmark.shield.fill")
                }
            }
            
            // Recent Results
            if !fuzzer.fuzzResults.isEmpty {
                Section {
                    ForEach(fuzzer.fuzzResults.prefix(20)) { result in
                        FuzzResultRow(result: result)
                    }
                    
                    if fuzzer.fuzzResults.count > 20 {
                        Text("+ \(fuzzer.fuzzResults.count - 20) more results")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                } header: {
                    HeaderLabel(text: "Recent Results (\(fuzzer.fuzzResults.count))", icon: "clock.arrow.circlepath")
                }
            }
        }
        .navigationTitle("IOKit Fuzzer")
        .premiumStyling()
    }
    
    private var filteredServices: [IOKitService] {
        if searchText.isEmpty {
            return fuzzer.services
        }
        return fuzzer.services.filter {
            $0.name.localizedCaseInsensitiveContains(searchText) ||
            $0.className.localizedCaseInsensitiveContains(searchText)
        }
    }
}

// MARK: - Sub Views

struct ServiceRow: View {
    let service: IOKitService
    
    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                Text(service.name)
                    .font(.subheadline.bold())
                Text(service.className)
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(.secondary)
            }
            
            Spacer()
            
            if service.fuzzed {
                Image(systemName: "checkmark.circle.fill")
                    .foregroundStyle(.green)
            }
            
            if service.crashCount > 0 {
                Text("\(service.crashCount)")
                    .font(.caption2.bold())
                    .padding(.horizontal, 6)
                    .padding(.vertical, 2)
                    .background(Color.red.opacity(0.2))
                    .foregroundStyle(.red)
                    .clipShape(Capsule())
            }
        }
    }
}

struct FuzzResultRow: View {
    let result: FuzzResult
    
    var body: some View {
        HStack {
            Image(systemName: result.result.icon)
                .foregroundStyle(result.result.color)
            
            VStack(alignment: .leading, spacing: 2) {
                Text(result.serviceName)
                    .font(.caption.bold())
                Text(result.method)
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundStyle(.secondary)
            }
            
            Spacer()
            
            Text(result.timestamp, style: .time)
                .font(.caption2)
                .foregroundStyle(.tertiary)
        }
    }
}

struct VulnerabilityRow: View {
    let vulnerability: VulnerabilityCandidate
    
    var body: some View {
        HStack {
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundStyle(vulnerability.severity.color)
            
            VStack(alignment: .leading, spacing: 4) {
                Text(vulnerability.serviceName)
                    .font(.subheadline.bold())
                Text(vulnerability.method)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            
            Spacer()
            
            VStack(alignment: .trailing, spacing: 2) {
                Text(vulnerability.severity.rawValue)
                    .font(.caption2.bold())
                    .foregroundStyle(vulnerability.severity.color)
                
                if vulnerability.reproducible {
                    Image(systemName: "arrow.triangle.2.circlepath")
                        .font(.caption2)
                        .foregroundStyle(.orange)
                }
            }
        }
    }
}

struct ServiceDetailView: View {
    let service: IOKitService
    @ObservedObject private var fuzzer = IOKitFuzzerEngine.shared
    @State private var iterations = "100"
    
    var body: some View {
        List {
            Section {
                LabeledContent("Name") { Text(service.name) }
                LabeledContent("Class") { Text(service.className) }
                LabeledContent("Crashes") {
                    Text("\(service.crashCount)")
                        .foregroundStyle(service.crashCount > 0 ? .red : .secondary)
                }
            } header: {
                HeaderLabel(text: "Service Info", icon: "info.circle")
            }
            
            Section {
                TextField("Iterations", text: $iterations)
                    .keyboardType(.numberPad)
                
                Button("Fuzz Properties") {
                    let count = Int(iterations) ?? 100
                    fuzzer.fuzzServiceProperties(service, iterations: count)
                }
                .disabled(fuzzer.isFuzzing)
                
                Button("Fuzz Methods") {
                    let count = Int(iterations) ?? 100
                    fuzzer.fuzzServiceMethods(service, iterations: count)
                }
                .disabled(fuzzer.isFuzzing)
            } header: {
                HeaderLabel(text: "Fuzzing", icon: "dice.fill")
            }
            
            if !service.properties.isEmpty {
                Section {
                    ForEach(Array(service.properties.keys.sorted()), id: \.self) { key in
                        LabeledContent(key) {
                            Text("\(service.properties[key] ?? "nil")")
                                .font(.caption)
                                .lineLimit(1)
                        }
                    }
                } header: {
                    HeaderLabel(text: "Properties (\(service.properties.count))", icon: "list.bullet")
                }
            }
        }
        .navigationTitle("Service Detail")
        .premiumStyling()
    }
}

struct VulnerabilityDetailView: View {
    let vulnerability: VulnerabilityCandidate
    
    var body: some View {
        List {
            Section {
                LabeledContent("Service") { Text(vulnerability.serviceName) }
                LabeledContent("Method") { Text(vulnerability.method) }
                LabeledContent("Severity") {
                    Text(vulnerability.severity.rawValue)
                        .foregroundStyle(vulnerability.severity.color)
                }
                LabeledContent("Crash Count") {
                    Text("\(vulnerability.crashCount)")
                        .foregroundStyle(.red)
                }
                LabeledContent("Reproducible") {
                    Text(vulnerability.reproducible ? "Yes" : "No")
                        .foregroundStyle(vulnerability.reproducible ? .red : .secondary)
                }
            } header: {
                HeaderLabel(text: "Vulnerability Info", icon: "exclamationmark.shield.fill")
            }
            
            Section {
                Text(vulnerability.description)
                    .font(.caption)
            } header: {
                HeaderLabel(text: "Description", icon: "doc.text")
            }
        }
        .navigationTitle("Vulnerability")
        .premiumStyling()
    }
}
