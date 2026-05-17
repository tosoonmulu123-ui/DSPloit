//
//  ARM64Disassembler.swift
//  DSPloit
//
//  🔥 ARM64 Instruction Decoder & Disassembler
//  Decode ARM64 instructions for ROP chain building & analysis
//  Created by Royan
//

import Foundation

// MARK: - ARM64 Instruction

struct ARM64Instruction {
    let address: UInt64
    let opcode: UInt32
    let mnemonic: String
    let operands: String
    let type: InstructionType
    let size: Int = 4
    
    enum InstructionType {
        case branch      // B, BL, BR, BLR, RET
        case load        // LDR, LDUR, LDP
        case store       // STR, STUR, STP
        case arithmetic  // ADD, SUB, MUL, etc
        case logical     // AND, ORR, EOR, etc
        case move        // MOV, MOVZ, MOVK
        case compare     // CMP, TST
        case system      // MSR, MRS, SVC
        case other
    }
    
    var isReturn: Bool {
        return mnemonic == "RET"
    }
    
    var isBranch: Bool {
        return type == .branch
    }
    
    var isLoad: Bool {
        return type == .load
    }
    
    var isStore: Bool {
        return type == .store
    }
}

// MARK: - ROP Gadget

struct ROPGadget {
    let address: UInt64
    let instructions: [ARM64Instruction]
    let description: String
    let usefulness: Double // 0.0 - 1.0
    
    var gadgetString: String {
        instructions.map { "\($0.mnemonic) \($0.operands)" }.joined(separator: " ; ")
    }
}

// MARK: - ARM64 Disassembler

class ARM64Disassembler {
    static let shared = ARM64Disassembler()
    
    // MARK: - Disassemble Single Instruction
    
    func disassemble(opcode: UInt32, address: UInt64) -> ARM64Instruction {
        // Decode instruction based on encoding
        
        // Branch instructions (0x14000000 - B, 0x94000000 - BL)
        if (opcode & 0xFC000000) == 0x14000000 {
            let offset = signExtend(opcode & 0x03FFFFFF, bits: 26) * 4
            return ARM64Instruction(
                address: address,
                opcode: opcode,
                mnemonic: "B",
                operands: String(format: "0x%llx", Int64(address) + Int64(offset)),
                type: .branch
            )
        }
        
        if (opcode & 0xFC000000) == 0x94000000 {
            let offset = signExtend(opcode & 0x03FFFFFF, bits: 26) * 4
            return ARM64Instruction(
                address: address,
                opcode: opcode,
                mnemonic: "BL",
                operands: String(format: "0x%llx", Int64(address) + Int64(offset)),
                type: .branch
            )
        }
        
        // RET instruction (0xD65F03C0)
        if opcode == 0xD65F03C0 {
            return ARM64Instruction(
                address: address,
                opcode: opcode,
                mnemonic: "RET",
                operands: "",
                type: .branch
            )
        }
        
        // BR instruction (0xD61F0000 + Rn)
        if (opcode & 0xFFFFFC1F) == 0xD61F0000 {
            let rn = (opcode >> 5) & 0x1F
            return ARM64Instruction(
                address: address,
                opcode: opcode,
                mnemonic: "BR",
                operands: "X\(rn)",
                type: .branch
            )
        }
        
        // BLR instruction (0xD63F0000 + Rn)
        if (opcode & 0xFFFFFC1F) == 0xD63F0000 {
            let rn = (opcode >> 5) & 0x1F
            return ARM64Instruction(
                address: address,
                opcode: opcode,
                mnemonic: "BLR",
                operands: "X\(rn)",
                type: .branch
            )
        }
        
        // LDR (immediate) - 64-bit (0xF9400000)
        if (opcode & 0xFFC00000) == 0xF9400000 {
            let rt = opcode & 0x1F
            let rn = (opcode >> 5) & 0x1F
            let imm = ((opcode >> 10) & 0xFFF) * 8
            return ARM64Instruction(
                address: address,
                opcode: opcode,
                mnemonic: "LDR",
                operands: "X\(rt), [X\(rn), #\(imm)]",
                type: .load
            )
        }
        
        // LDP (load pair) - 64-bit (0xA9400000)
        if (opcode & 0xFFC00000) == 0xA9400000 {
            let rt = opcode & 0x1F
            let rt2 = (opcode >> 10) & 0x1F
            let rn = (opcode >> 5) & 0x1F
            let imm = signExtend((opcode >> 15) & 0x7F, bits: 7) * 8
            return ARM64Instruction(
                address: address,
                opcode: opcode,
                mnemonic: "LDP",
                operands: "X\(rt), X\(rt2), [X\(rn), #\(imm)]",
                type: .load
            )
        }
        
        // STR (immediate) - 64-bit (0xF9000000)
        if (opcode & 0xFFC00000) == 0xF9000000 {
            let rt = opcode & 0x1F
            let rn = (opcode >> 5) & 0x1F
            let imm = ((opcode >> 10) & 0xFFF) * 8
            return ARM64Instruction(
                address: address,
                opcode: opcode,
                mnemonic: "STR",
                operands: "X\(rt), [X\(rn), #\(imm)]",
                type: .store
            )
        }
        
        // STP (store pair) - 64-bit (0xA9000000)
        if (opcode & 0xFFC00000) == 0xA9000000 {
            let rt = opcode & 0x1F
            let rt2 = (opcode >> 10) & 0x1F
            let rn = (opcode >> 5) & 0x1F
            let imm = signExtend((opcode >> 15) & 0x7F, bits: 7) * 8
            return ARM64Instruction(
                address: address,
                opcode: opcode,
                mnemonic: "STP",
                operands: "X\(rt), X\(rt2), [X\(rn), #\(imm)]",
                type: .store
            )
        }
        
        // ADD (immediate) - 64-bit (0x91000000)
        if (opcode & 0xFF800000) == 0x91000000 {
            let rd = opcode & 0x1F
            let rn = (opcode >> 5) & 0x1F
            let imm = (opcode >> 10) & 0xFFF
            return ARM64Instruction(
                address: address,
                opcode: opcode,
                mnemonic: "ADD",
                operands: "X\(rd), X\(rn), #\(imm)",
                type: .arithmetic
            )
        }
        
        // SUB (immediate) - 64-bit (0xD1000000)
        if (opcode & 0xFF800000) == 0xD1000000 {
            let rd = opcode & 0x1F
            let rn = (opcode >> 5) & 0x1F
            let imm = (opcode >> 10) & 0xFFF
            return ARM64Instruction(
                address: address,
                opcode: opcode,
                mnemonic: "SUB",
                operands: "X\(rd), X\(rn), #\(imm)",
                type: .arithmetic
            )
        }
        
        // MOV (register) - 64-bit (0xAA0003E0 + Rd + Rm)
        if (opcode & 0xFFE0FFE0) == 0xAA0003E0 {
            let rd = opcode & 0x1F
            let rm = (opcode >> 16) & 0x1F
            return ARM64Instruction(
                address: address,
                opcode: opcode,
                mnemonic: "MOV",
                operands: "X\(rd), X\(rm)",
                type: .move
            )
        }
        
        // NOP (0xD503201F)
        if opcode == 0xD503201F {
            return ARM64Instruction(
                address: address,
                opcode: opcode,
                mnemonic: "NOP",
                operands: "",
                type: .other
            )
        }
        
        // SVC (supervisor call) - 0xD4000001
        if (opcode & 0xFFE0001F) == 0xD4000001 {
            let imm = (opcode >> 5) & 0xFFFF
            return ARM64Instruction(
                address: address,
                opcode: opcode,
                mnemonic: "SVC",
                operands: "#\(imm)",
                type: .system
            )
        }
        
        // MSR (move to system register)
        if (opcode & 0xFFF00000) == 0xD5100000 {
            let rt = opcode & 0x1F
            let sysReg = (opcode >> 5) & 0x7FFF
            return ARM64Instruction(
                address: address,
                opcode: opcode,
                mnemonic: "MSR",
                operands: "S\(sysReg), X\(rt)",
                type: .system
            )
        }
        
        // MRS (move from system register)
        if (opcode & 0xFFF00000) == 0xD5300000 {
            let rt = opcode & 0x1F
            let sysReg = (opcode >> 5) & 0x7FFF
            return ARM64Instruction(
                address: address,
                opcode: opcode,
                mnemonic: "MRS",
                operands: "X\(rt), S\(sysReg)",
                type: .system
            )
        }
        
        // MOVZ (move wide with zero)
        if (opcode & 0xFF800000) == 0xD2800000 {
            let rd = opcode & 0x1F
            let imm = (opcode >> 5) & 0xFFFF
            let shift = ((opcode >> 21) & 0x3) * 16
            return ARM64Instruction(
                address: address,
                opcode: opcode,
                mnemonic: "MOVZ",
                operands: "X\(rd), #0x\(String(format: "%x", imm))\(shift > 0 ? ", LSL #\(shift)" : "")",
                type: .move
            )
        }
        
        // MOVK (move wide with keep)
        if (opcode & 0xFF800000) == 0xF2800000 {
            let rd = opcode & 0x1F
            let imm = (opcode >> 5) & 0xFFFF
            let shift = ((opcode >> 21) & 0x3) * 16
            return ARM64Instruction(
                address: address,
                opcode: opcode,
                mnemonic: "MOVK",
                operands: "X\(rd), #0x\(String(format: "%x", imm)), LSL #\(shift)",
                type: .move
            )
        }
        
        // AND (immediate)
        if (opcode & 0xFF800000) == 0x92000000 {
            let rd = opcode & 0x1F
            let rn = (opcode >> 5) & 0x1F
            return ARM64Instruction(
                address: address,
                opcode: opcode,
                mnemonic: "AND",
                operands: "X\(rd), X\(rn), #imm",
                type: .logical
            )
        }
        
        // ORR (register)
        if (opcode & 0xFF200000) == 0xAA000000 {
            let rd = opcode & 0x1F
            let rn = (opcode >> 5) & 0x1F
            let rm = (opcode >> 16) & 0x1F
            return ARM64Instruction(
                address: address,
                opcode: opcode,
                mnemonic: "ORR",
                operands: "X\(rd), X\(rn), X\(rm)",
                type: .logical
            )
        }
        
        // CMP (immediate) - alias for SUBS with Rd=XZR
        if (opcode & 0xFF80001F) == 0xF100001F {
            let rn = (opcode >> 5) & 0x1F
            let imm = (opcode >> 10) & 0xFFF
            return ARM64Instruction(
                address: address,
                opcode: opcode,
                mnemonic: "CMP",
                operands: "X\(rn), #\(imm)",
                type: .compare
            )
        }
        
        // CBZ (compare and branch if zero)
        if (opcode & 0xFF000000) == 0xB4000000 {
            let rt = opcode & 0x1F
            let offset = signExtend((opcode >> 5) & 0x7FFFF, bits: 19) * 4
            return ARM64Instruction(
                address: address,
                opcode: opcode,
                mnemonic: "CBZ",
                operands: "X\(rt), \(String(format: "0x%llx", Int64(address) + Int64(offset)))",
                type: .branch
            )
        }
        
        // CBNZ (compare and branch if not zero)
        if (opcode & 0xFF000000) == 0xB5000000 {
            let rt = opcode & 0x1F
            let offset = signExtend((opcode >> 5) & 0x7FFFF, bits: 19) * 4
            return ARM64Instruction(
                address: address,
                opcode: opcode,
                mnemonic: "CBNZ",
                operands: "X\(rt), \(String(format: "0x%llx", Int64(address) + Int64(offset)))",
                type: .branch
            )
        }
        
        // B.cond (conditional branch)
        if (opcode & 0xFF000010) == 0x54000000 {
            let cond = opcode & 0xF
            let offset = signExtend((opcode >> 5) & 0x7FFFF, bits: 19) * 4
            let condStr = ["EQ","NE","CS","CC","MI","PL","VS","VC","HI","LS","GE","LT","GT","LE","AL","NV"][Int(cond)]
            return ARM64Instruction(
                address: address,
                opcode: opcode,
                mnemonic: "B.\(condStr)",
                operands: String(format: "0x%llx", Int64(address) + Int64(offset)),
                type: .branch
            )
        }
        
        // ADRP (form PC-relative address to 4KB page)
        if (opcode & 0x9F000000) == 0x90000000 {
            let rd = opcode & 0x1F
            let immHi = (opcode >> 5) & 0x7FFFF
            let immLo = (opcode >> 29) & 0x3
            let imm = Int64(signExtend((immHi << 2) | immLo, bits: 21)) << 12
            let target = (Int64(address) & ~0xFFF) + imm
            return ARM64Instruction(
                address: address,
                opcode: opcode,
                mnemonic: "ADRP",
                operands: "X\(rd), \(String(format: "0x%llx", target))",
                type: .move
            )
        }
        
        // Default: unknown instruction
        return ARM64Instruction(
            address: address,
            opcode: opcode,
            mnemonic: "???",
            operands: String(format: "0x%08x", opcode),
            type: .other
        )
    }
    
    // MARK: - Disassemble Range
    
    func disassembleRange(startAddr: UInt64, count: Int) -> [ARM64Instruction] {
        var instructions: [ARM64Instruction] = []
        
        for i in 0..<count {
            let addr = startAddr + UInt64(i * 4)
            let opcode = ds_kread32(addr)
            let instr = disassemble(opcode: opcode, address: addr)
            instructions.append(instr)
        }
        
        return instructions
    }
    
    // MARK: - ROP Gadget Finding
    
    func findROPGadgets(startAddr: UInt64, size: Int, maxGadgetLen: Int = 5) -> [ROPGadget] {
        var gadgets: [ROPGadget] = []
        
        // Find all RET instructions first
        let retAddresses = findReturnInstructions(startAddr: startAddr, size: size)
        
        for retAddr in retAddresses {
            // Disassemble backwards to find gadget
            var gadgetInstrs: [ARM64Instruction] = []
            
            for i in (1...maxGadgetLen).reversed() {
                let addr = retAddr - UInt64(i * 4)
                let opcode = ds_kread32(addr)
                let instr = disassemble(opcode: opcode, address: addr)
                gadgetInstrs.append(instr)
            }
            
            // Add RET instruction
            let retOpcode = ds_kread32(retAddr)
            let retInstr = disassemble(opcode: retOpcode, address: retAddr)
            gadgetInstrs.append(retInstr)
            
            // Analyze usefulness
            let usefulness = analyzeGadgetUsefulness(gadgetInstrs)
            
            if usefulness > 0.3 { // Only keep useful gadgets
                let gadget = ROPGadget(
                    address: gadgetInstrs.first!.address,
                    instructions: gadgetInstrs,
                    description: describeGadget(gadgetInstrs),
                    usefulness: usefulness
                )
                gadgets.append(gadget)
            }
        }
        
        return gadgets.sorted { $0.usefulness > $1.usefulness }
    }
    
    // MARK: - Helper Functions
    
    private func findReturnInstructions(startAddr: UInt64, size: Int) -> [UInt64] {
        var addresses: [UInt64] = []
        
        for offset in stride(from: 0, to: size, by: 4) {
            let addr = startAddr + UInt64(offset)
            let opcode = ds_kread32(addr)
            
            if opcode == 0xD65F03C0 { // RET
                addresses.append(addr)
            }
        }
        
        return addresses
    }
    
    private func analyzeGadgetUsefulness(_ instructions: [ARM64Instruction]) -> Double {
        var score = 0.5 // Base score
        
        for instr in instructions {
            switch instr.type {
            case .load:
                score += 0.2 // Load is useful
            case .store:
                score += 0.15 // Store is useful
            case .arithmetic:
                score += 0.1 // Arithmetic is somewhat useful
            case .move:
                score += 0.1 // Move is somewhat useful
            case .branch:
                if !instr.isReturn {
                    score -= 0.3 // Branch in middle is bad
                }
            default:
                break
            }
        }
        
        return min(max(score, 0.0), 1.0)
    }
    
    private func describeGadget(_ instructions: [ARM64Instruction]) -> String {
        var desc = ""
        
        let hasLoad = instructions.contains { $0.isLoad }
        let hasStore = instructions.contains { $0.isStore }
        let hasArith = instructions.contains { $0.type == .arithmetic }
        
        if hasLoad && hasStore {
            desc = "Load & Store"
        } else if hasLoad {
            desc = "Load"
        } else if hasStore {
            desc = "Store"
        } else if hasArith {
            desc = "Arithmetic"
        } else {
            desc = "Generic"
        }
        
        return desc
    }
    
    private func signExtend(_ value: UInt32, bits: Int) -> Int32 {
        let shift = 32 - bits
        return Int32(bitPattern: value << shift) >> shift
    }
    
    // MARK: - JOP Gadget Finding (Jump-Oriented Programming)
    
    func findJOPGadgets(startAddr: UInt64, size: Int, maxGadgetLen: Int = 5) -> [ROPGadget] {
        var gadgets: [ROPGadget] = []
        
        // Find BR/BLR instructions (indirect jumps)
        for offset in stride(from: 0, to: size, by: 4) {
            let addr = startAddr + UInt64(offset)
            let opcode = ds_kread32(addr)
            
            // BR Xn (0xD61F0000 + Rn<<5)
            let isBR = (opcode & 0xFFFFFC1F) == 0xD61F0000
            // BLR Xn (0xD63F0000 + Rn<<5)
            let isBLR = (opcode & 0xFFFFFC1F) == 0xD63F0000
            
            if isBR || isBLR {
                var gadgetInstrs: [ARM64Instruction] = []
                
                // Disassemble preceding instructions
                for i in (1...maxGadgetLen).reversed() {
                    let prevAddr = addr - UInt64(i * 4)
                    let prevOpcode = ds_kread32(prevAddr)
                    let instr = disassemble(opcode: prevOpcode, address: prevAddr)
                    gadgetInstrs.append(instr)
                }
                
                // Add the BR/BLR instruction
                let jumpInstr = disassemble(opcode: opcode, address: addr)
                gadgetInstrs.append(jumpInstr)
                
                let usefulness = analyzeJOPGadgetUsefulness(gadgetInstrs)
                
                if usefulness > 0.3 {
                    let gadget = ROPGadget(
                        address: gadgetInstrs.first!.address,
                        instructions: gadgetInstrs,
                        description: "JOP: \(describeGadget(gadgetInstrs))",
                        usefulness: usefulness
                    )
                    gadgets.append(gadget)
                }
            }
        }
        
        return gadgets.sorted { $0.usefulness > $1.usefulness }
    }
    
    private func analyzeJOPGadgetUsefulness(_ instructions: [ARM64Instruction]) -> Double {
        var score = 0.4
        
        for instr in instructions {
            switch instr.type {
            case .load:
                score += 0.25 // Loading into register before jump is very useful
            case .arithmetic:
                score += 0.15
            case .move:
                score += 0.1
            case .store:
                score += 0.1
            default:
                break
            }
        }
        
        // Bonus if gadget loads X0 (first argument)
        let loadsX0 = instructions.contains { $0.operands.contains("X0,") && $0.isLoad }
        if loadsX0 { score += 0.2 }
        
        return min(max(score, 0.0), 1.0)
    }
}

// MARK: - Convenience Extensions

extension dspmgr {
    func disassemble(address: UInt64, count: Int = 10) -> [ARM64Instruction] {
        return ARM64Disassembler.shared.disassembleRange(startAddr: address, count: count)
    }
    
    func findROPGadgets(address: UInt64, size: Int) -> [ROPGadget] {
        return ARM64Disassembler.shared.findROPGadgets(startAddr: address, size: size)
    }
    
    func findJOPGadgets(address: UInt64, size: Int) -> [ROPGadget] {
        return ARM64Disassembler.shared.findJOPGadgets(startAddr: address, size: size)
    }
}
