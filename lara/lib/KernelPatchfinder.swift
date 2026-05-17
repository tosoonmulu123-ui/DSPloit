//
//  KernelPatchfinder.swift
//  DSPloit
//
//  🔥 Kernel Symbol Resolution & Pattern Finder
//  Automatically find kernel symbols, offsets, and patterns
//  Works across different iOS versions
//  Created by Royan
//

import Foundation

// MARK: - Kernel Symbol

struct KernelSymbol {
    let name: String
    let address: UInt64
    let type: SymbolType
    let confidence: Double // 0.0 - 1.0
    
    enum SymbolType {
        case function
        case data
        case string
        case vtable
        case unknown
    }
}

// MARK: - Pattern Definition

struct KernelPattern {
    let name: String
    let bytes: [UInt8?] // nil = wildcard
    let mask: [UInt8]
    let offset: Int // Offset from match to actual symbol
    let alignment: Int // Required alignment (e.g., 4 for ARM64)
    
    init(name: String, pattern: String, offset: Int = 0, alignment: Int = 4) {
        self.name = name
        self.offset = offset
        self.alignment = alignment
        
        // Parse hex pattern: "FF 83 ?? D1" -> [0xFF, 0x83, nil, 0xD1]
        let parts = pattern.split(separator: " ")
        var parsedBytes: [UInt8?] = []
        var parsedMask: [UInt8] = []
        
        for part in parts {
            if part == "??" {
                parsedBytes.append(nil)
                parsedMask.append(0x00)
            } else if let byte = UInt8(part, radix: 16) {
                parsedBytes.append(byte)
                parsedMask.append(0xFF)
            }
        }
        
        self.bytes = parsedBytes
        self.mask = parsedMask
    }
}

// MARK: - Kernel Patchfinder

class KernelPatchfinder {
    static let shared = KernelPatchfinder()
    
    private var symbolCache: [String: UInt64] = [:]
    private var kernelData: Data?
    private let mgr = dspmgr.shared
    
    // MARK: - Known Patterns for iOS 15-17
    
    private lazy var knownPatterns: [String: KernelPattern] = [
        // AMFI Patterns
        "_mac_proc_check_run_cs_invalid": KernelPattern(
            name: "_mac_proc_check_run_cs_invalid",
            pattern: "FF 83 01 D1 F4 4F 03 A9 FD 7B 04 A9 FD 03 01 91",
            offset: 0
        ),
        "_amfi_get_out_of_my_way": KernelPattern(
            name: "_amfi_get_out_of_my_way",
            pattern: "08 00 40 39 00 01 00 37 ?? ?? ?? ?? 08 00 00 39",
            offset: 0
        ),
        
        // Trust Cache Patterns
        "_trust_cache": KernelPattern(
            name: "_trust_cache",
            pattern: "?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00",
            offset: 0,
            alignment: 8
        ),
        
        // Sandbox Patterns
        "_sandbox_check": KernelPattern(
            name: "_sandbox_check",
            pattern: "FF 43 01 D1 F6 57 02 A9 F4 4F 03 A9 FD 7B 04 A9",
            offset: 0
        ),
        "_mac_policy_list": KernelPattern(
            name: "_mac_policy_list",
            pattern: "?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00",
            offset: 0,
            alignment: 8
        ),
        
        // Process/Task Patterns
        "_allproc": KernelPattern(
            name: "_allproc",
            pattern: "?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00",
            offset: 0,
            alignment: 8
        ),
        "_kernproc": KernelPattern(
            name: "_kernproc",
            pattern: "00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ??",
            offset: 0,
            alignment: 8
        ),
        
        // Syscall Table
        "_sysent": KernelPattern(
            name: "_sysent",
            pattern: "?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00",
            offset: 0,
            alignment: 16
        ),
        
        // Vnode Operations
        "_vnode_gaddr": KernelPattern(
            name: "_vnode_gaddr",
            pattern: "FF 43 00 D1 F4 4F 01 A9 FD 7B 02 A9 FD 83 00 91",
            offset: 0
        ),
        
        // Credential Patterns
        "_kauth_cred_setuidgid": KernelPattern(
            name: "_kauth_cred_setuidgid",
            pattern: "FF 83 00 D1 F4 4F 01 A9 FD 7B 02 A9 FD 83 00 91",
            offset: 0
        ),
        
        // Zone Allocator
        "_kalloc_canblock": KernelPattern(
            name: "_kalloc_canblock",
            pattern: "FF 43 01 D1 F6 57 02 A9 F4 4F 03 A9 FD 7B 04 A9",
            offset: 0
        ),
        "_kfree_addr": KernelPattern(
            name: "_kfree_addr",
            pattern: "FF 03 01 D1 F4 4F 01 A9 FD 7B 02 A9 FD 43 00 91",
            offset: 0
        ),
    ]
    
    // MARK: - Public API
    
    
    /// Find symbol by name
    func findSymbol(_ name: String) -> UInt64? {
        // Check cache first
        if let cached = symbolCache[name] {
            return cached
        }
        
        guard mgr.dsready else { return nil }
        
        // Try pattern matching
        if let pattern = knownPatterns[name] {
            if let addr = findPattern(pattern) {
                symbolCache[name] = addr
                return addr
            }
        }
        
        // Try string reference search
        if let addr = findByStringReference(name) {
            symbolCache[name] = addr
            return addr
        }
        
        return nil
    }
    
    /// Find pattern in kernel memory
    func findPattern(_ pattern: KernelPattern) -> UInt64? {
        guard mgr.dsready else { return nil }
        
        let kernbase = mgr.kernbase
        let searchSize = 0x2000000 // 32MB search range
        let chunkSize = 0x10000 // 64KB chunks
        
        var currentAddr = kernbase
        let endAddr = kernbase + UInt64(searchSize)
        
        while currentAddr < endAddr {
            let chunk = readKernelChunk(address: currentAddr, size: chunkSize)
            
            if let offset = searchPattern(in: chunk, pattern: pattern) {
                let foundAddr = currentAddr + UInt64(offset) + UInt64(pattern.offset)
                
                // Verify alignment
                if foundAddr % UInt64(pattern.alignment) == 0 {
                    return foundAddr
                }
            }
            
            currentAddr += UInt64(chunkSize)
        }
        
        return nil
    }
    
    /// Find symbol by string reference
    func findByStringReference(_ symbolName: String) -> UInt64? {
        guard mgr.dsready else { return nil }
        
        // First, find the string in __TEXT.__cstring
        guard let stringAddr = findString(symbolName) else { return nil }
        
        // Then find references to this string
        let references = findReferences(to: stringAddr, range: 0x2000000)
        
        // Analyze references to find the actual function
        for refAddr in references {
            // Check if this is in a function prologue
            if isFunctionStart(refAddr) {
                return refAddr
            }
        }
        
        return references.first
    }
    
    /// Find all kernel zones
    func findKernelZones() -> [(name: String, addr: UInt64, size: Int)] {
        guard mgr.dsready else { return [] }
        
        var zones: [(String, UInt64, Int)] = []
        
        // Find zone array
        guard let zoneArrayAddr = findSymbol("_zone_array") else { return [] }
        
        // Read zone structures
        for i in 0..<100 {
            let zoneAddr = ds_kread64(zoneArrayAddr + UInt64(i * 8))
            guard zoneAddr != 0 else { break }
            
            // Read zone name
            let nameAddr = ds_kread64(zoneAddr + 0x0)
            let name = readKernelString(nameAddr) ?? "zone_\(i)"
            
            // Read zone size
            let elementSize = Int(ds_kread32(zoneAddr + 0x20))
            
            zones.append((name, zoneAddr, elementSize))
        }
        
        return zones
    }
    
    /// Find offset in structure by scanning
    func findStructOffset(baseAddr: UInt64, targetValue: UInt64, maxOffset: Int = 0x200) -> Int? {
        for offset in stride(from: 0, to: maxOffset, by: 8) {
            let value = ds_kread64(baseAddr + UInt64(offset))
            if value == targetValue {
                return offset
            }
        }
        return nil
    }
    
    /// Scan for instruction pattern (ARM64)
    func findInstruction(pattern: UInt32, mask: UInt32, startAddr: UInt64, range: Int) -> [UInt64] {
        var results: [UInt64] = []
        var currentAddr = startAddr
        let endAddr = startAddr + UInt64(range)
        
        while currentAddr < endAddr {
            let instr = ds_kread32(currentAddr)
            if (instr & mask) == (pattern & mask) {
                results.append(currentAddr)
            }
            currentAddr += 4 // ARM64 instructions are 4 bytes
        }
        
        return results
    }
    
    // MARK: - Private Helpers
    
    private func readKernelChunk(address: UInt64, size: Int) -> [UInt8] {
        var data: [UInt8] = []
        data.reserveCapacity(size)
        
        for offset in stride(from: 0, to: size, by: 8) {
            let value = ds_kread64(address + UInt64(offset))
            withUnsafeBytes(of: value) { bytes in
                data.append(contentsOf: bytes)
            }
        }
        
        return data
    }
    
    private func searchPattern(in data: [UInt8], pattern: KernelPattern) -> Int? {
        let patternLen = pattern.bytes.count
        guard data.count >= patternLen else { return nil }
        
        for i in 0...(data.count - patternLen) {
            var match = true
            
            for j in 0..<patternLen {
                if let expectedByte = pattern.bytes[j] {
                    if data[i + j] != expectedByte {
                        match = false
                        break
                    }
                }
            }
            
            if match {
                return i
            }
        }
        
        return nil
    }
    
    private func findString(_ str: String) -> UInt64? {
        guard let strData = str.data(using: .utf8) else { return nil }
        let bytes = [UInt8](strData)
        
        let kernbase = mgr.kernbase
        let searchSize = 0x1000000 // 16MB
        let chunkSize = 0x10000
        
        var currentAddr = kernbase
        let endAddr = kernbase + UInt64(searchSize)
        
        while currentAddr < endAddr {
            let chunk = readKernelChunk(address: currentAddr, size: chunkSize)
            
            if let offset = searchBytes(bytes, in: chunk) {
                return currentAddr + UInt64(offset)
            }
            
            currentAddr += UInt64(chunkSize)
        }
        
        return nil
    }
    
    private func searchBytes(_ needle: [UInt8], in haystack: [UInt8]) -> Int? {
        guard haystack.count >= needle.count else { return nil }
        
        for i in 0...(haystack.count - needle.count) {
            if haystack[i..<(i + needle.count)].elementsEqual(needle) {
                return i
            }
        }
        
        return nil
    }
    
    private func findReferences(to address: UInt64, range: Int) -> [UInt64] {
        var refs: [UInt64] = []
        let kernbase = mgr.kernbase
        
        // Search for address in kernel memory
        for offset in stride(from: 0, to: range, by: 8) {
            let addr = kernbase + UInt64(offset)
            let value = ds_kread64(addr)
            
            if value == address {
                refs.append(addr)
            }
        }
        
        return refs
    }
    
    private func isFunctionStart(_ address: UInt64) -> Bool {
        // Check for common ARM64 function prologue
        let instr = ds_kread32(address)
        
        // Common prologues:
        // SUB SP, SP, #imm  -> 0xD10xxxFF
        // STP X29, X30, [SP, #-16]! -> 0xA9Bxxxxx
        
        if (instr & 0xFFC003FF) == 0xD10003FF { return true } // SUB SP
        if (instr & 0xFFC00000) == 0xA9800000 { return true } // STP
        
        return false
    }
    
    private func readKernelString(_ address: UInt64, maxLen: Int = 256) -> String? {
        var bytes: [UInt8] = []
        
        for i in 0..<maxLen {
            let byte = UInt8(ds_kread64(address + UInt64(i)) & 0xFF)
            if byte == 0 { break }
            bytes.append(byte)
        }
        
        return String(bytes: bytes, encoding: .utf8)
    }
}

// MARK: - Convenience Extensions

extension dspmgr {
    func findSymbol(_ name: String) -> UInt64? {
        return KernelPatchfinder.shared.findSymbol(name)
    }
    
    func findPattern(_ pattern: KernelPattern) -> UInt64? {
        return KernelPatchfinder.shared.findPattern(pattern)
    }
}
