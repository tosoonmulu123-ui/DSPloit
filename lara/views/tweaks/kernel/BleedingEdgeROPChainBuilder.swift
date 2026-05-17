//
//  BleedingEdgeROPChainBuilder.swift
//  DSPloit
//
//  Advanced ROP Chain Builder with Auto Gadget Finder & Chain Generator
//  Created by Royan
//

import SwiftUI
import Combine

// MARK: - ROP Chain Builder Engine

class ROPChainBuilderEngine: ObservableObject {
    static let shared = ROPChainBuilderEngine()
    
    @Published var gadgetsFound: [ROPGadget] = []
    @Published var chainBuilt = false
    
    struct ROPGadget: Identifiable {
        let id = UUID()
        let address: UInt64
        let instructions: String
        let type: GadgetType
        let registers: [String]
        let stackOffset: Int
    }
    
    enum GadgetType: String, CaseIterable {
        case loadRegister = "Load Register"
        case storeRegister = "Store Register"
        case stackPivot = "Stack Pivot"
        case controlFlow = "Control Flow"
        case arithmetic = "Arithmetic"
        case syscall = "Syscall"
        case ret = "Return"
    }
    
    struct ROPChain {
        var gadgets: [ROPGadget]
        var payload: [UInt64]
        var description: String
    }
    
    // MARK: - Gadget Finder
    
    func findGadgets(startAddr: UInt64, size: UInt64, type: GadgetType? = nil) -> [ROPGadget] {
        var gadgets: [ROPGadget] = []
        var addr = startAddr
        let endAddr = startAddr + size
        
        while addr < endAddr {
            // Read 4 bytes (ARM64 instruction)
            let instr = ds_kread32(addr)
            
            // Check for RET instruction (0xd65f03c0)
            if instr == 0xd65f03c0 {
                // Found RET, scan backwards for useful gadgets
                let gadget = analyzeGadgetBeforeRet(retAddr: addr)
                if let g = gadget {
                    gadgets.append(g)
                }
            }
            
            // Check for BR/BLR instructions
            if (instr & 0xfffffc1f) == 0xd61f0000 {
                let gadget = analyzeControlFlowGadget(addr: addr, instr: instr)
                if let g = gadget {
                    gadgets.append(g)
                }
            }
            
            addr += 4
            
            // Limit to prevent excessive scanning
            if gadgets.count >= 1000 { break }
        }
        
        // Filter by type if specified
        if let filterType = type {
            return gadgets.filter { $0.type == filterType }
        }
        
        return gadgets
    }
    
    // MARK: - File-Based Gadget Scanner (Safe - No Panic)
    
    func findGadgetsFromFile(startOffset: UInt64, size: UInt64) -> [ROPGadget] {
        // Find kernelcache file in Documents
        let docs = NSSearchPathForDirectoriesInDomains(.documentDirectory, .userDomainMask, true).first ?? ""
        let kcPath = (docs as NSString).appendingPathComponent("kernelcache")
        
        // Also try alternative paths
        var filePath = kcPath
        if !FileManager.default.fileExists(atPath: filePath) {
            let altPaths = [
                (docs as NSString).appendingPathComponent("kernelcache.macho"),
                "/var/mobile/Documents/kernelcache",
            ]
            for alt in altPaths {
                if FileManager.default.fileExists(atPath: alt) {
                    filePath = alt
                    break
                }
            }
        }
        
        guard FileManager.default.fileExists(atPath: filePath) else {
            return []
        }
        
        // Read file data safely
        guard let fileData = try? Data(contentsOf: URL(fileURLWithPath: filePath), options: .mappedIfSafe) else {
            return []
        }
        
        guard fileData.count > 16 else { return [] }
        
        // Find Mach-O magic (0xFEEDFACF) in file — skip IMG4 header if present
        var machOStart = 0
        let magic: UInt32 = fileData.withUnsafeBytes { $0.load(fromByteOffset: 0, as: UInt32.self) }
        
        if magic != 0xFEEDFACF {
            // Not a raw Mach-O — search for magic within first 1KB
            for offset in stride(from: 0, to: min(fileData.count, 4096), by: 4) {
                let val: UInt32 = fileData.withUnsafeBytes { $0.load(fromByteOffset: offset, as: UInt32.self) }
                if val == 0xFEEDFACF {
                    machOStart = offset
                    break
                }
            }
            if machOStart == 0 {
                return [] // Can't find Mach-O in file
            }
        }
        
        // Calculate read range
        let scanStart = machOStart + Int(startOffset)
        let scanEnd = min(scanStart + min(Int(size), 256 * 1024), fileData.count - 4)
        guard scanStart < scanEnd else { return [] }
        
        var gadgets: [ROPGadget] = []
        let kernelBase = dspmgr.shared.kernbase
        
        for offset in stride(from: scanStart, to: scanEnd, by: 4) {
            guard offset + 4 <= fileData.count else { break }
            
            let instr: UInt32 = fileData.withUnsafeBytes { $0.load(fromByteOffset: offset, as: UInt32.self) }
            let fileRelOffset = UInt64(offset - machOStart)
            let virtualAddr = kernelBase + fileRelOffset
            
            // Find RET instructions
            if instr == 0xD65F03C0 && offset >= scanStart + 8 {
                let prev1: UInt32 = fileData.withUnsafeBytes { $0.load(fromByteOffset: offset - 4, as: UInt32.self) }
                let prev2: UInt32 = fileData.withUnsafeBytes { $0.load(fromByteOffset: offset - 8, as: UInt32.self) }
                
                let disasm = ARM64Disassembler.shared
                let instr1 = disasm.disassemble(opcode: prev2, address: virtualAddr - 8)
                let instr2 = disasm.disassemble(opcode: prev1, address: virtualAddr - 4)
                
                // Skip if both are unknown
                if instr1.mnemonic == "???" && instr2.mnemonic == "???" { continue }
                
                let instrStr = "\(instr1.mnemonic) \(instr1.operands) ; \(instr2.mnemonic) \(instr2.operands) ; RET"
                
                var type: GadgetType = .ret
                var regs: [String] = []
                
                if instr1.isLoad || instr2.isLoad { type = .loadRegister }
                else if instr1.isStore || instr2.isStore { type = .storeRegister }
                else if instr1.mnemonic == "ADD" || instr1.mnemonic == "SUB" || instr2.mnemonic == "ADD" || instr2.mnemonic == "SUB" { type = .arithmetic }
                else if instr1.mnemonic == "MOV" || instr2.mnemonic == "MOV" { type = .loadRegister }
                
                if instr1.operands.contains("SP") || instr2.operands.contains("SP") { type = .stackPivot }
                if instr1.operands.contains("X0") { regs.append("X0") }
                if instr2.operands.contains("X0") { regs.append("X0") }
                
                gadgets.append(ROPGadget(
                    address: virtualAddr - 8,
                    instructions: instrStr,
                    type: type,
                    registers: regs,
                    stackOffset: 0
                ))
            }
            
            // Find BR Xn
            if (instr & 0xFFFFFC1F) == 0xD61F0000 && offset >= scanStart + 4 {
                let rn = (instr >> 5) & 0x1F
                let prev: UInt32 = fileData.withUnsafeBytes { $0.load(fromByteOffset: offset - 4, as: UInt32.self) }
                let disasm = ARM64Disassembler.shared
                let prevInstr = disasm.disassemble(opcode: prev, address: virtualAddr - 4)
                
                gadgets.append(ROPGadget(
                    address: virtualAddr - 4,
                    instructions: "\(prevInstr.mnemonic) \(prevInstr.operands) ; BR X\(rn)",
                    type: .controlFlow,
                    registers: ["X\(rn)"],
                    stackOffset: 0
                ))
            }
            
            if gadgets.count >= 100 { break }
        }
        
        return gadgets
    }
    
    private func analyzeGadgetBeforeRet(retAddr: UInt64) -> ROPGadget? {
        // Scan up to 8 instructions before RET
        var instructions: [String] = []
        var registers: [String] = []
        var gadgetType: GadgetType = .ret
        var stackOffset = 0
        
        for i in (1...8).reversed() {
            let addr = retAddr - UInt64(i * 4)
            let instr = ds_kread32(addr)
            
            let disasm = disassembleARM64(instr: instr, addr: addr)
            instructions.append(disasm.mnemonic)
            
            // Detect gadget type
            if disasm.mnemonic.contains("ldp") || disasm.mnemonic.contains("ldr") {
                gadgetType = .loadRegister
                registers.append(contentsOf: disasm.registers)
            } else if disasm.mnemonic.contains("stp") || disasm.mnemonic.contains("str") {
                gadgetType = .storeRegister
                registers.append(contentsOf: disasm.registers)
            } else if disasm.mnemonic.contains("add") && disasm.registers.contains("sp") {
                gadgetType = .stackPivot
                stackOffset = disasm.immediate
            } else if disasm.mnemonic.contains("mov") {
                registers.append(contentsOf: disasm.registers)
            }
        }
        
        let instrStr = instructions.joined(separator: "; ")
        
        return ROPGadget(
            address: retAddr - UInt64(instructions.count * 4),
            instructions: instrStr + "; ret",
            type: gadgetType,
            registers: Array(Set(registers)),
            stackOffset: stackOffset
        )
    }
    
    private func analyzeControlFlowGadget(addr: UInt64, instr: UInt32) -> ROPGadget? {
        let disasm = disassembleARM64(instr: instr, addr: addr)
        
        return ROPGadget(
            address: addr,
            instructions: disasm.mnemonic,
            type: .controlFlow,
            registers: disasm.registers,
            stackOffset: 0
        )
    }
    
    private func disassembleARM64(instr: UInt32, addr: UInt64) -> (mnemonic: String, registers: [String], immediate: Int) {
        // Simple ARM64 disassembler
        var mnemonic = ""
        var registers: [String] = []
        var immediate = 0
        
        // LDP (Load Pair)
        if (instr & 0x7fc00000) == 0x29400000 {
            let rt = (instr >> 0) & 0x1f
            let rt2 = (instr >> 10) & 0x1f
            let rn = (instr >> 5) & 0x1f
            let imm = Int((instr >> 15) & 0x7f)
            mnemonic = String(format: "ldp x%d, x%d, [x%d, #%d]", rt, rt2, rn, imm * 8)
            registers = [String(format: "x%d", rt), String(format: "x%d", rt2)]
            immediate = imm * 8
        }
        // LDR (Load Register)
        else if (instr & 0xffc00000) == 0xf9400000 {
            let rt = (instr >> 0) & 0x1f
            let rn = (instr >> 5) & 0x1f
            let imm = Int((instr >> 10) & 0xfff)
            mnemonic = String(format: "ldr x%d, [x%d, #%d]", rt, rn, imm * 8)
            registers = [String(format: "x%d", rt)]
            immediate = imm * 8
        }
        // ADD (immediate)
        else if (instr & 0x7f800000) == 0x11000000 {
            let rd = (instr >> 0) & 0x1f
            let rn = (instr >> 5) & 0x1f
            let imm = Int((instr >> 10) & 0xfff)
            mnemonic = String(format: "add x%d, x%d, #%d", rd, rn, imm)
            registers = [String(format: "x%d", rd)]
            immediate = imm
        }
        // MOV (register)
        else if (instr & 0x7fe0ffe0) == 0x2a0003e0 {
            let rd = (instr >> 0) & 0x1f
            let rm = (instr >> 16) & 0x1f
            mnemonic = String(format: "mov x%d, x%d", rd, rm)
            registers = [String(format: "x%d", rd), String(format: "x%d", rm)]
        }
        // BR (Branch to Register)
        else if (instr & 0xfffffc1f) == 0xd61f0000 {
            let rn = (instr >> 5) & 0x1f
            mnemonic = String(format: "br x%d", rn)
            registers = [String(format: "x%d", rn)]
        }
        else {
            mnemonic = String(format: "unknown (0x%08x)", instr)
        }
        
        return (mnemonic, registers, immediate)
    }
    
    // MARK: - Chain Builder
    
    func buildChain_SetRegister(register: String, value: UInt64) -> ROPChain? {
        // Find gadget: ldr xN, [sp, #offset]; ret
        let loadGadgets = gadgetsFound.filter { $0.type == .loadRegister && $0.registers.contains(register) }
        
        guard let gadget = loadGadgets.first else { return nil }
        
        var payload: [UInt64] = []
        payload.append(gadget.address) // ROP gadget address
        payload.append(value)           // Value to load
        
        return ROPChain(
            gadgets: [gadget],
            payload: payload,
            description: "Set \(register) = 0x\(String(format: "%llx", value))"
        )
    }
    
    func buildChain_CallFunction(funcAddr: UInt64, args: [UInt64]) -> ROPChain? {
        var chain = ROPChain(gadgets: [], payload: [], description: "Call function at 0x\(String(format: "%llx", funcAddr))")
        
        // Set up arguments in x0-x7
        for (idx, arg) in args.enumerated() {
            if idx >= 8 { break }
            if let subchain = buildChain_SetRegister(register: "x\(idx)", value: arg) {
                chain.gadgets.append(contentsOf: subchain.gadgets)
                chain.payload.append(contentsOf: subchain.payload)
            }
        }
        
        // Find control flow gadget to call function
        let controlGadgets = gadgetsFound.filter { $0.type == .controlFlow }
        if let callGadget = controlGadgets.first {
            chain.gadgets.append(callGadget)
            chain.payload.append(funcAddr)
        }
        
        return chain
    }
    
    func buildChain_StackPivot(newStackAddr: UInt64) -> ROPChain? {
        // Find gadget: add sp, sp, #offset; ret or mov sp, xN; ret
        let pivotGadgets = gadgetsFound.filter { $0.type == .stackPivot }
        
        guard let gadget = pivotGadgets.first else { return nil }
        
        var payload: [UInt64] = []
        payload.append(gadget.address)
        payload.append(newStackAddr)
        
        return ROPChain(
            gadgets: [gadget],
            payload: payload,
            description: "Pivot stack to 0x\(String(format: "%llx", newStackAddr))"
        )
    }
    
    func buildChain_Syscall(syscallNum: Int, args: [UInt64]) -> ROPChain? {
        var chain = ROPChain(gadgets: [], payload: [], description: "Syscall #\(syscallNum)")
        
        // Set x16 = syscall number
        if let subchain = buildChain_SetRegister(register: "x16", value: UInt64(syscallNum)) {
            chain.gadgets.append(contentsOf: subchain.gadgets)
            chain.payload.append(contentsOf: subchain.payload)
        }
        
        // Set arguments
        for (idx, arg) in args.enumerated() {
            if idx >= 8 { break }
            if let subchain = buildChain_SetRegister(register: "x\(idx)", value: arg) {
                chain.gadgets.append(contentsOf: subchain.gadgets)
                chain.payload.append(contentsOf: subchain.payload)
            }
        }
        
        // Find SVC gadget
        let syscallGadgets = gadgetsFound.filter { $0.type == .syscall }
        if let svcGadget = syscallGadgets.first {
            chain.gadgets.append(svcGadget)
            chain.payload.append(svcGadget.address)
        }
        
        return chain
    }
    
    func exportChain(_ chain: ROPChain) -> String {
        var output = "// ROP Chain: \(chain.description)\n"
        output += "uint64_t rop_chain[] = {\n"
        
        for (idx, addr) in chain.payload.enumerated() {
            output += String(format: "    0x%016llx,  // [%d]\n", addr, idx)
        }
        
        output += "};\n"
        return output
    }
}

// MARK: - Main View

struct BleedingEdgeROPChainBuilderView: View {
    @ObservedObject private var engine = ROPChainBuilderEngine.shared
    @ObservedObject private var mgr = dspmgr.shared
    
    @State private var scanAddr = ""
    @State private var scanSize = "0x10000"
    @State private var selectedType: ROPChainBuilderEngine.GadgetType?
    @State private var isScanning = false
    @State private var builtChains: [ROPChainBuilderEngine.ROPChain] = []
    @State private var exportedCode = ""
    
    var filteredGadgets: [ROPChainBuilderEngine.ROPGadget] {
        if let type = selectedType {
            return engine.gadgetsFound.filter { $0.type == type }
        }
        return engine.gadgetsFound
    }
    
    var body: some View {
        List {
            // Scanner Section
            Section(header: HeaderLabel(text: "Gadget Scanner", icon: "magnifyingglass.circle")) {
                HStack {
                    TextField("Start Address (hex)", text: $scanAddr)
                        .font(.system(.body, design: .monospaced))
                    TextField("Size", text: $scanSize)
                        .font(.system(.body, design: .monospaced))
                        .frame(width: 100)
                }
                
                Button(action: scanForGadgets) {
                    HStack {
                        if isScanning {
                            ProgressView()
                        } else {
                            Image(systemName: "play.fill")
                        }
                        Text(isScanning ? "Scanning..." : "Scan for Gadgets")
                        Spacer()
                    }
                }
                .disabled(!mgr.dsready || isScanning)
                
                Button("Scan Kernel Text") {
                    scanAddr = String(format: "0x%llx", mgr.kernbase)
                    scanSize = "0x100000"
                    scanForGadgets()
                }
                .disabled(!mgr.dsready || isScanning)
            }
            
            // Filter Section
            if !engine.gadgetsFound.isEmpty {
                Section(header: HeaderLabel(text: "Filter (\(filteredGadgets.count) gadgets)", icon: "line.3.horizontal.decrease.circle")) {
                    Picker("Gadget Type", selection: $selectedType) {
                        Text("All Types").tag(nil as ROPChainBuilderEngine.GadgetType?)
                        ForEach(ROPChainBuilderEngine.GadgetType.allCases, id: \.self) { type in
                            Text(type.rawValue).tag(type as ROPChainBuilderEngine.GadgetType?)
                        }
                    }
                    
                    HStack {
                        ForEach(ROPChainBuilderEngine.GadgetType.allCases, id: \.self) { type in
                            let count = engine.gadgetsFound.filter { $0.type == type }.count
                            VStack {
                                Text("\(count)")
                                    .font(.caption.bold())
                                Text(type.rawValue)
                                    .font(.system(size: 8))
                            }
                            .frame(maxWidth: .infinity)
                        }
                    }
                }
            }
            
            // Gadgets List
            if !filteredGadgets.isEmpty {
                Section(header: HeaderLabel(text: "Found Gadgets", icon: "list.bullet")) {
                    ForEach(filteredGadgets.prefix(50)) { gadget in
                        GadgetRow(gadget: gadget)
                    }
                    
                    if filteredGadgets.count > 50 {
                        Text("+ \(filteredGadgets.count - 50) more gadgets...")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
            }
            
            // Chain Builder
            Section(header: HeaderLabel(text: "⚡ Chain Builder", icon: "link")) {
                Button("Build: Set Register Chain") {
                    if let chain = engine.buildChain_SetRegister(register: "x0", value: 0x4141414141414141) {
                        builtChains.append(chain)
                    }
                }
                .disabled(engine.gadgetsFound.isEmpty)
                
                Button("Build: Function Call Chain") {
                    if let chain = engine.buildChain_CallFunction(funcAddr: mgr.kernbase, args: [1, 2, 3]) {
                        builtChains.append(chain)
                    }
                }
                .disabled(engine.gadgetsFound.isEmpty)
                
                Button("Build: Stack Pivot Chain") {
                    if let chain = engine.buildChain_StackPivot(newStackAddr: 0x1000000) {
                        builtChains.append(chain)
                    }
                }
                .disabled(engine.gadgetsFound.isEmpty)
                
                Button("Build: Syscall Chain") {
                    if let chain = engine.buildChain_Syscall(syscallNum: 1, args: [1, 0x1000, 100]) {
                        builtChains.append(chain)
                    }
                }
                .disabled(engine.gadgetsFound.isEmpty)
            }
            
            // Built Chains
            if !builtChains.isEmpty {
                Section(header: HeaderLabel(text: "Built Chains", icon: "link.circle")) {
                    ForEach(builtChains.indices, id: \.self) { idx in
                        ChainRow(chain: builtChains[idx]) {
                            exportedCode = engine.exportChain(builtChains[idx])
                        }
                    }
                    
                    Button("Clear All Chains") {
                        builtChains.removeAll()
                    }
                    .foregroundStyle(.red)
                }
            }
            
            // Export
            if !exportedCode.isEmpty {
                Section(header: HeaderLabel(text: "Exported Code", icon: "doc.text")) {
                    Text(exportedCode)
                        .font(.system(size: 9, design: .monospaced))
                        .foregroundStyle(.green)
                        .textSelection(.enabled)
                }
            }
        }
        .navigationTitle("🔥 ROP Chain Builder")
        .premiumStyling()
        .onAppear {
            if scanAddr.isEmpty {
                scanAddr = String(format: "0x%llx", mgr.kernbase)
            }
        }
    }
    
    private func scanForGadgets() {
        guard let addr = UInt64(scanAddr.replacingOccurrences(of: "0x", with: ""), radix: 16),
              let size = UInt64(scanSize.replacingOccurrences(of: "0x", with: ""), radix: 16) else {
            return
        }
        
        isScanning = true
        DispatchQueue.global(qos: .userInitiated).async {
            // Try to scan from kernelcache FILE first (safe, no panic)
            let gadgets = engine.findGadgetsFromFile(startOffset: addr, size: size)
            
            if gadgets.isEmpty {
                // Fallback: scan from live kernel memory (only heap-safe addresses)
                let liveGadgets = engine.findGadgets(startAddr: addr, size: size)
                DispatchQueue.main.async {
                    engine.gadgetsFound = liveGadgets
                    isScanning = false
                }
            } else {
                DispatchQueue.main.async {
                    engine.gadgetsFound = gadgets
                    isScanning = false
                }
            }
        }
    }
}

// MARK: - Supporting Views

struct GadgetRow: View {
    let gadget: ROPChainBuilderEngine.ROPGadget
    
    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text(String(format: "0x%llx", gadget.address))
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundStyle(.cyan)
                Spacer()
                GadgetTypeBadge(type: gadget.type)
            }
            
            Text(gadget.instructions)
                .font(.system(size: 10, design: .monospaced))
                .foregroundStyle(.green)
            
            if !gadget.registers.isEmpty {
                HStack {
                    ForEach(gadget.registers.prefix(4), id: \.self) { reg in
                        Text(reg)
                            .font(.system(size: 8))
                            .padding(.horizontal, 4)
                            .padding(.vertical, 2)
                            .background(Color.blue.opacity(0.2))
                            .clipShape(Capsule())
                    }
                    if gadget.stackOffset != 0 {
                        Text("sp+\(gadget.stackOffset)")
                            .font(.system(size: 8))
                            .padding(.horizontal, 4)
                            .padding(.vertical, 2)
                            .background(Color.orange.opacity(0.2))
                            .clipShape(Capsule())
                    }
                }
            }
        }
        .padding(.vertical, 2)
    }
}

struct GadgetTypeBadge: View {
    let type: ROPChainBuilderEngine.GadgetType
    
    var color: Color {
        switch type {
        case .loadRegister: return .blue
        case .storeRegister: return .green
        case .stackPivot: return .orange
        case .controlFlow: return .red
        case .arithmetic: return .purple
        case .syscall: return .pink
        case .ret: return .gray
        }
    }
    
    var body: some View {
        Text(type.rawValue)
            .font(.system(size: 8, weight: .bold))
            .foregroundStyle(.white)
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(color)
            .clipShape(Capsule())
    }
}

struct ChainRow: View {
    let chain: ROPChainBuilderEngine.ROPChain
    let onExport: () -> Void
    
    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text(chain.description)
                    .font(.subheadline.bold())
                Spacer()
                Button(action: onExport) {
                    Image(systemName: "square.and.arrow.up")
                        .foregroundStyle(.blue)
                }
                .buttonStyle(.plain)
            }
            
            Text("\(chain.gadgets.count) gadgets, \(chain.payload.count) qwords")
                .font(.caption)
                .foregroundStyle(.secondary)
            
            ForEach(chain.gadgets.prefix(3)) { gadget in
                Text(String(format: "0x%llx: %@", gadget.address, gadget.instructions))
                    .font(.system(size: 9, design: .monospaced))
                    .foregroundStyle(.green)
            }
        }
        .padding(.vertical, 4)
    }
}
