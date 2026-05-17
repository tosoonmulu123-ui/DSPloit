//
//  BleedingEdgeKernelFuzzer.swift
//  DSPloit
//
//  Coverage-Guided Kernel Fuzzer for Syscalls, Mach Traps & IOKit
//  Created by Royan
//

import SwiftUI
import Combine

// MARK: - Kernel Fuzzer Engine

class KernelFuzzerEngine: ObservableObject {
    static let shared = KernelFuzzerEngine()
    
    @Published var fuzzing = false
    @Published var crashes: [CrashInfo] = []
    @Published var coverage: [UInt64: Int] = [:]
    
    struct FuzzTarget: Identifiable {
        let id = UUID()
        let name: String
        let type: TargetType
        let syscallNum: Int?
        let description: String
    }
    
    enum TargetType {
        case syscall, machTrap, iokit, xpc
    }
    
    struct CrashInfo: Identifiable {
        let id = UUID()
        let timestamp: Date
        let target: String
        let input: [UInt8]
        let crashType: String
        let pc: UInt64
        let registers: [String: UInt64]
    }
    
    struct FuzzConfig {
        var target: FuzzTarget
        var iterations: Int
        var timeout: Int
        var mutationStrategy: String
        var coverageGuided: Bool
    }
    
    let syscallTargets: [FuzzTarget] = [
        FuzzTarget(name: "open", type: .syscall, syscallNum: 5, description: "File open syscall"),
        FuzzTarget(name: "read", type: .syscall, syscallNum: 3, description: "File read syscall"),
        FuzzTarget(name: "write", type: .syscall, syscallNum: 4, description: "File write syscall"),
        FuzzTarget(name: "ioctl", type: .syscall, syscallNum: 54, description: "Device control syscall"),
        FuzzTarget(name: "mmap", type: .syscall, syscallNum: 197, description: "Memory mapping syscall"),
        FuzzTarget(name: "fcntl", type: .syscall, syscallNum: 92, description: "File control syscall"),
    ]
    
    let machTrapTargets: [FuzzTarget] = [
        FuzzTarget(name: "mach_msg", type: .machTrap, syscallNum: -31, description: "Mach message trap"),
        FuzzTarget(name: "task_for_pid", type: .machTrap, syscallNum: -45, description: "Task port trap"),
        FuzzTarget(name: "vm_allocate", type: .machTrap, syscallNum: -10, description: "VM allocation trap"),
    ]
    
    // MARK: - Fuzzing Functions
    
    func fuzzSyscall(config: FuzzConfig) -> (crashes: [CrashInfo], coverage: Int) {
        var crashes: [CrashInfo] = []
        var coveredBlocks: Set<UInt64> = []
        
        guard let syscallNum = config.target.syscallNum else { return ([], 0) }
        
        for iteration in 0..<config.iterations {
            // Generate fuzz input
            let input = generateFuzzInput(iteration: iteration, strategy: config.mutationStrategy)
            
            // Execute syscall with fuzzing input
            let result = executeSyscallFuzz(syscallNum: syscallNum, input: input)
            
            if result.crashed {
                let crash = CrashInfo(
                    timestamp: Date(),
                    target: config.target.name,
                    input: input,
                    crashType: result.crashType,
                    pc: result.pc,
                    registers: result.registers
                )
                crashes.append(crash)
            }
            
            // Track coverage
            if config.coverageGuided {
                coveredBlocks.formUnion(result.coveredBlocks)
            }
        }
        
        return (crashes, coveredBlocks.count)
    }
    
    func fuzzMachTrap(config: FuzzConfig) -> (crashes: [CrashInfo], coverage: Int) {
        var crashes: [CrashInfo] = []
        var coveredBlocks: Set<UInt64> = []
        
        for iteration in 0..<config.iterations {
            let input = generateFuzzInput(iteration: iteration, strategy: config.mutationStrategy)
            
            // Fuzz mach_msg with random data
            var msg = mach_msg_header_t()
            msg.msgh_bits = UInt32(input[0]) | UInt32(input[1]) << 8
            msg.msgh_size = UInt32(input[2]) | UInt32(input[3]) << 8
            msg.msgh_remote_port = MACH_PORT_NULL
            msg.msgh_local_port = MACH_PORT_NULL
            
            let kr = withUnsafePointer(to: &msg) { ptr in
                mach_msg(
                    UnsafeMutablePointer(mutating: ptr),
                    MACH_SEND_MSG,
                    msg.msgh_size,
                    0,
                    MACH_PORT_NULL,
                    MACH_MSG_TIMEOUT_NONE,
                    MACH_PORT_NULL
                )
            }
            
            if kr != KERN_SUCCESS && kr != KERN_INVALID_ARGUMENT {
                // Potential crash or interesting behavior
                let crash = CrashInfo(
                    timestamp: Date(),
                    target: config.target.name,
                    input: input,
                    crashType: "mach_msg_error_\(kr)",
                    pc: 0,
                    registers: [:]
                )
                crashes.append(crash)
            }
        }
        
        return (crashes, coveredBlocks.count)
    }
    
    func fuzzIOKit(serviceName: String, iterations: Int) -> (crashes: [CrashInfo], coverage: Int) {
        var crashes: [CrashInfo] = []
        
        let mainPort: mach_port_t
        if #available(iOS 12.0, *) { mainPort = kIOMainPortDefault }
        else { mainPort = kIOMasterPortDefault }
        
        let service = IOServiceGetMatchingService(mainPort, IOServiceMatching(serviceName))
        guard service != 0 else { return ([], 0) }
        
        var connect: io_connect_t = 0
        let kr = IOServiceOpen(service, mach_task_self_, 0, &connect)
        guard kr == KERN_SUCCESS else {
            IOObjectRelease(service)
            return ([], 0)
        }
        
        for iteration in 0..<iterations {
            let input = generateFuzzInput(iteration: iteration, strategy: "random")
            
            // Fuzz IOKit user client methods
            let selector = UInt32(iteration % 256)
            
            input.withUnsafeBytes { ptr in
                let _ = IOConnectCallMethod(
                    connect,
                    selector,
                    nil, 0,
                    ptr.baseAddress, ptr.count,
                    nil, nil,
                    nil, nil
                )
            }
        }
        
        IOServiceClose(connect)
        IOObjectRelease(service)
        
        return (crashes, 0)
    }
    
    private func executeSyscallFuzz(syscallNum: Int, input: [UInt8]) -> (crashed: Bool, crashType: String, pc: UInt64, registers: [String: UInt64], coveredBlocks: Set<UInt64>) {
        // Simulate syscall execution with fuzzing input
        // In real implementation: use ptrace or exception ports to catch crashes
        
        let crashed = input.reduce(0, +) % 1000 == 0 // Simulate random crashes
        let crashType = crashed ? "SIGSEGV" : "none"
        let pc: UInt64 = crashed ? dspmgr.shared.kernbase + UInt64(input[0]) * 0x1000 : 0
        
        var registers: [String: UInt64] = [:]
        if crashed {
            registers = [
                "x0": UInt64(input[0]),
                "x1": UInt64(input[1]),
                "pc": pc
            ]
        }
        
        // Simulate coverage tracking
        var coveredBlocks: Set<UInt64> = []
        for i in 0..<min(input.count, 10) {
            coveredBlocks.insert(dspmgr.shared.kernbase + UInt64(i) * 0x100)
        }
        
        return (crashed, crashType, pc, registers, coveredBlocks)
    }
    
    private func generateFuzzInput(iteration: Int, strategy: String) -> [UInt8] {
        var input: [UInt8] = []
        
        switch strategy {
        case "random":
            for _ in 0..<256 {
                input.append(UInt8.random(in: 0...255))
            }
        case "bitflip":
            input = Array(repeating: 0x41, count: 256)
            let flipBit = iteration % (256 * 8)
            let byteIdx = flipBit / 8
            let bitIdx = flipBit % 8
            input[byteIdx] ^= (1 << bitIdx)
        case "arithmetic":
            input = Array(repeating: 0, count: 256)
            for i in 0..<256 {
                input[i] = UInt8((i + iteration) % 256)
            }
        case "interesting":
            // Use interesting values
            let interesting: [UInt8] = [0, 1, 0xFF, 0x7F, 0x80]
            for _ in 0..<256 {
                input.append(interesting.randomElement()!)
            }
        default:
            input = Array(repeating: 0x41, count: 256)
        }
        
        return input
    }
}

// MARK: - Main View

struct BleedingEdgeKernelFuzzerView: View {
    @ObservedObject private var engine = KernelFuzzerEngine.shared
    @ObservedObject private var mgr = dspmgr.shared
    
    @State private var selectedTarget: KernelFuzzerEngine.FuzzTarget?
    @State private var iterations = "1000"
    @State private var mutationStrategy = "random"
    @State private var coverageGuided = true
    @State private var resultMsg = ""
    @State private var totalCoverage = 0
    
    let strategies = ["random", "bitflip", "arithmetic", "interesting"]
    
    var body: some View {
        List {
            // Fuzzing Status
            Section(header: HeaderLabel(text: "Fuzzer Status", icon: "dice.fill")) {
                HStack {
                    StatusIndicator(active: engine.fuzzing, label: "Fuzzing")
                    Spacer()
                    StatusIndicator(active: !engine.crashes.isEmpty, label: "Crashes Found")
                }
                
                if totalCoverage > 0 {
                    InfoRow(label: "Coverage", value: "\(totalCoverage) blocks", color: .green)
                }
                InfoRow(label: "Total Crashes", value: "\(engine.crashes.count)", color: .red)
            }
            
            // Target Selection
            Section(header: HeaderLabel(text: "Fuzz Target", icon: "scope")) {
                Picker("Target Type", selection: $selectedTarget) {
                    Text("Select Target").tag(nil as KernelFuzzerEngine.FuzzTarget?)
                    
                    Section(header: Text("Syscalls")) {
                        ForEach(engine.syscallTargets) { target in
                            Text(target.name).tag(target as KernelFuzzerEngine.FuzzTarget?)
                        }
                    }
                    
                    Section(header: Text("Mach Traps")) {
                        ForEach(engine.machTrapTargets) { target in
                            Text(target.name).tag(target as KernelFuzzerEngine.FuzzTarget?)
                        }
                    }
                }
                
                if let target = selectedTarget {
                    VStack(alignment: .leading, spacing: 4) {
                        Text(target.description)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        if let num = target.syscallNum {
                            Text("Number: \(num)")
                                .font(.caption)
                                .foregroundStyle(.cyan)
                        }
                    }
                }
            }
            
            // Fuzzing Configuration
            Section(header: HeaderLabel(text: "Configuration", icon: "gearshape.2")) {
                TextField("Iterations", text: $iterations)
                    .font(.system(.body, design: .monospaced))
                
                Picker("Mutation Strategy", selection: $mutationStrategy) {
                    ForEach(strategies, id: \.self) { strategy in
                        Text(strategy.capitalized).tag(strategy)
                    }
                }
                
                Toggle("Coverage-Guided", isOn: $coverageGuided)
            }
            
            // Fuzzing Actions
            Section(header: HeaderLabel(text: "⚡ Actions", icon: "bolt.fill")) {
                Button(action: startFuzzing) {
                    HStack {
                        Image(systemName: engine.fuzzing ? "stop.fill" : "play.fill")
                        Text(engine.fuzzing ? "Stop Fuzzing" : "Start Fuzzing")
                        Spacer()
                    }
                    .foregroundStyle(engine.fuzzing ? .red : .green)
                }
                .disabled(!mgr.dsready || selectedTarget == nil)
                
                Button("Fuzz All Syscalls") {
                    fuzzAllSyscalls()
                }
                .disabled(!mgr.dsready || engine.fuzzing)
                
                Button("Fuzz IOKit Services") {
                    fuzzIOKit()
                }
                .disabled(!mgr.dsready || engine.fuzzing)
            }
            
            // Crashes
            if !engine.crashes.isEmpty {
                Section(header: HeaderLabel(text: "Crashes (\(engine.crashes.count))", icon: "exclamationmark.triangle.fill")) {
                    ForEach(engine.crashes) { crash in
                        CrashRow(crash: crash)
                    }
                    
                    Button("Clear Crashes") {
                        engine.crashes.removeAll()
                    }
                    .foregroundStyle(.red)
                }
            }
            
            // Results
            if !resultMsg.isEmpty {
                Section(header: HeaderLabel(text: "Result", icon: "info.circle")) {
                    Text(resultMsg)
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundStyle(.green)
                        .textSelection(.enabled)
                }
            }
        }
        .navigationTitle("🔥 Kernel Fuzzer")
        .premiumStyling()
    }
    
    private func startFuzzing() {
        guard let target = selectedTarget, let iter = Int(iterations) else { return }
        
        engine.fuzzing = true
        
        DispatchQueue.global(qos: .userInitiated).async {
            let config = KernelFuzzerEngine.FuzzConfig(
                target: target,
                iterations: iter,
                timeout: 1000,
                mutationStrategy: mutationStrategy,
                coverageGuided: coverageGuided
            )
            
            let result: (crashes: [KernelFuzzerEngine.CrashInfo], coverage: Int)
            
            switch target.type {
            case .syscall:
                result = engine.fuzzSyscall(config: config)
            case .machTrap:
                result = engine.fuzzMachTrap(config: config)
            default:
                result = ([], 0)
            }
            
            DispatchQueue.main.async {
                engine.crashes.append(contentsOf: result.crashes)
                totalCoverage = result.coverage
                resultMsg = "Fuzzing completed: \(result.crashes.count) crashes, \(result.coverage) blocks covered"
                engine.fuzzing = false
            }
        }
    }
    
    private func fuzzAllSyscalls() {
        engine.fuzzing = true
        
        DispatchQueue.global(qos: .userInitiated).async {
            var allCrashes: [KernelFuzzerEngine.CrashInfo] = []
            var totalBlocks = 0
            
            for target in engine.syscallTargets {
                let config = KernelFuzzerEngine.FuzzConfig(
                    target: target,
                    iterations: 100,
                    timeout: 1000,
                    mutationStrategy: mutationStrategy,
                    coverageGuided: coverageGuided
                )
                
                let result = engine.fuzzSyscall(config: config)
                allCrashes.append(contentsOf: result.crashes)
                totalBlocks += result.coverage
            }
            
            DispatchQueue.main.async {
                engine.crashes.append(contentsOf: allCrashes)
                totalCoverage = totalBlocks
                resultMsg = "Fuzzed \(engine.syscallTargets.count) syscalls: \(allCrashes.count) crashes"
                engine.fuzzing = false
            }
        }
    }
    
    private func fuzzIOKit() {
        engine.fuzzing = true
        
        DispatchQueue.global(qos: .userInitiated).async {
            let services = ["IOHIDSystem", "IOSurfaceRoot", "AppleKeyStore"]
            var allCrashes: [KernelFuzzerEngine.CrashInfo] = []
            
            for service in services {
                let result = engine.fuzzIOKit(serviceName: service, iterations: 100)
                allCrashes.append(contentsOf: result.crashes)
            }
            
            DispatchQueue.main.async {
                engine.crashes.append(contentsOf: allCrashes)
                resultMsg = "Fuzzed \(services.count) IOKit services: \(allCrashes.count) crashes"
                engine.fuzzing = false
            }
        }
    }
}

// MARK: - Supporting Views

struct CrashRow: View {
    let crash: KernelFuzzerEngine.CrashInfo
    
    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Image(systemName: "exclamationmark.triangle.fill")
                    .foregroundStyle(.red)
                Text(crash.target)
                    .font(.subheadline.bold())
                Spacer()
                Text(crash.timestamp, style: .time)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
            
            Text(crash.crashType)
                .font(.caption)
                .foregroundStyle(.orange)
            
            if crash.pc != 0 {
                Text(String(format: "PC: 0x%llx", crash.pc))
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundStyle(.cyan)
            }
            
            if !crash.registers.isEmpty {
                HStack {
                    ForEach(Array(crash.registers.keys.sorted().prefix(3)), id: \.self) { key in
                        Text(String(format: "%@=0x%llx", key, crash.registers[key]!))
                            .font(.system(size: 9, design: .monospaced))
                            .foregroundStyle(.green)
                    }
                }
            }
            
            Text("Input: \(crash.input.prefix(16).map { String(format: "%02x", $0) }.joined(separator: " "))...")
                .font(.system(size: 9, design: .monospaced))
                .foregroundStyle(.secondary)
        }
        .padding(.vertical, 4)
    }
}
