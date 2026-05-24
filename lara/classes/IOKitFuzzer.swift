//
//  IOKitFuzzer.swift
//  DSPloit
//
//  IOKit service fuzzer for discovering new kernel attack surfaces
//  Probes IOKit services accessible from app sandbox
//  Goal: find UAF/OOB/race conditions that could lead to KRW
//
//  Usage: run from jailbroken state OR from sandboxed app (limited)
//  Results logged for analysis
//

import Foundation
import UIKit

final class IOKitFuzzer {
    static let shared = IOKitFuzzer()
    
    private var log: [String] = []
    private var isRunning = false
    
    struct ProbeResult: Identifiable {
        let id = UUID()
        let service: String
        let selector: UInt32
        let inputSize: Int
        let result: kern_return_t
        let interesting: Bool
        let note: String
    }
    
    private(set) var results: [ProbeResult] = []
    
    // Services known to be accessible from app sandbox (no entitlement needed)
    private let targetServices: [(String, String)] = [
        ("IOSurfaceRoot", "GPU surface management — previous UAF source"),
        ("AppleJPEGDriver", "JPEG hardware decoder — CVE-2026-20687"),
        ("AppleKeyStore", "Key management — CVE-2026-20637"),
        ("AGXAccelerator", "GPU driver — assertion bugs found"),
        ("IOGPUDevice", "GPU command submission — AGXBarrierPanic"),
        ("AppleAVE2Driver", "Video encoder — historically buggy"),
        ("AppleH10CamIn", "Camera input — complex state machine"),
        ("IOHIDFamily", "HID input — CVE-2026-28992 race condition"),
        ("AppleSPU", "Signal processing — less audited"),
        ("AppleARMPMU", "Power management — less audited"),
        ("IOAudioFamily", "Audio driver — complex IOKit"),
        ("AppleMultitouchSPI", "Touch input — high complexity"),
    ]
    
    // MARK: - Public API
    
    func getLog() -> [String] { return log }
    func getResults() -> [ProbeResult] { return results }
    
    /// Enumerate all accessible IOKit services
    func enumerateServices() -> [(name: String, className: String, accessible: Bool)] {
        var found: [(String, String, Bool)] = []
        
        let matching = IOServiceMatching("IOService")
        var iterator: io_iterator_t = 0
        let kr = IOServiceGetMatchingServices(kIOMainPortDefault, matching, &iterator)
        guard kr == KERN_SUCCESS else { return [] }
        defer { IOObjectRelease(iterator) }
        
        var service = IOIteratorNext(iterator)
        while service != 0 {
            var nameBuffer = [CChar](repeating: 0, count: 128)
            IORegistryEntryGetName(service, &nameBuffer)
            let name = String(cString: nameBuffer)
            
            var classBuffer = [CChar](repeating: 0, count: 128)
            IOObjectGetClass(service, &classBuffer)
            let className = String(cString: classBuffer)
            
            // Try to open — if it succeeds, service is accessible from sandbox
            var conn: io_connect_t = 0
            let openKr = IOServiceOpen(service, mach_task_self_, 0, &conn)
            let accessible = (openKr == KERN_SUCCESS)
            if accessible { IOServiceClose(conn) }
            
            found.append((name, className, accessible))
            IOObjectRelease(service)
            service = IOIteratorNext(iterator)
        }
        
        return found
    }
    
    /// Probe a specific service with various selectors and input sizes
    func probeService(name: String, maxSelector: UInt32 = 32, completion: @escaping ([ProbeResult]) -> Void) {
        guard !isRunning else { completion([]); return }
        isRunning = true
        results.removeAll()
        
        emit("=== Probing \(name) ===")
        
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            
            let svc = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching(name))
            guard svc != 0 else {
                self.emit("❌ Service not found: \(name)")
                DispatchQueue.main.async { self.isRunning = false; completion([]) }
                return
            }
            
            // Try different open types
            let openTypes: [UInt32] = [0, 1, 2, 0x2022, 0xbeef, 0x1337]
            var conn: io_connect_t = 0
            var openedType: UInt32 = 0
            
            for type in openTypes {
                let kr = IOServiceOpen(svc, mach_task_self_, type, &conn)
                if kr == KERN_SUCCESS {
                    openedType = type
                    self.emit("✅ Opened with type 0x\(String(type, radix: 16))")
                    break
                }
            }
            
            IOObjectRelease(svc)
            
            guard conn != 0 else {
                self.emit("❌ Cannot open service (all types failed)")
                DispatchQueue.main.async { self.isRunning = false; completion([]) }
                return
            }
            
            // Probe selectors
            for sel in 0..<maxSelector {
                // Try with no input
                let kr0 = self.callSelector(conn, selector: sel, inputSize: 0)
                self.recordResult(name, sel, 0, kr0)
                
                // Try with small input (8 bytes)
                let kr1 = self.callSelector(conn, selector: sel, inputSize: 8)
                self.recordResult(name, sel, 8, kr1)
                
                // Try with medium input (64 bytes)
                let kr2 = self.callSelector(conn, selector: sel, inputSize: 64)
                self.recordResult(name, sel, 64, kr2)
                
                // Try with large input (4096 bytes)
                let kr3 = self.callSelector(conn, selector: sel, inputSize: 4096)
                self.recordResult(name, sel, 4096, kr3)
                
                usleep(10000) // 10ms between selectors to avoid flooding
            }
            
            IOServiceClose(conn)
            
            self.emit("=== Done: \(self.results.count) results, \(self.results.filter { $0.interesting }.count) interesting ===")
            
            DispatchQueue.main.async {
                self.isRunning = false
                completion(self.results)
            }
        }
    }
    
    /// Quick scan: find all accessible services and their selector count
    func quickScan(completion: @escaping ([(service: String, selectors: Int, note: String)]) -> Void) {
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            var scanResults: [(String, Int, String)] = []
            
            for (serviceName, description) in self.targetServices {
                let svc = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching(serviceName))
                guard svc != 0 else { continue }
                
                var conn: io_connect_t = 0
                let kr = IOServiceOpen(svc, mach_task_self_, 0, &conn)
                IOObjectRelease(svc)
                
                guard kr == KERN_SUCCESS else {
                    scanResults.append((serviceName, -1, "cannot open: \(String(format: "0x%x", kr))"))
                    continue
                }
                
                // Count valid selectors
                var validSelectors = 0
                let migBadId = Int32(bitPattern: 0xe00002c2)
                for sel: UInt32 in 0..<64 {
                    let testKr = self.callSelector(conn, selector: sel, inputSize: 0)
                    if testKr != KERN_INVALID_ARGUMENT && testKr != migBadId {
                        validSelectors += 1
                    }
                }
                
                IOServiceClose(conn)
                scanResults.append((serviceName, validSelectors, description))
            }
            
            DispatchQueue.main.async {
                completion(scanResults)
            }
        }
    }
    
    // MARK: - Private
    
    private func callSelector(_ conn: io_connect_t, selector: UInt32, inputSize: Int) -> kern_return_t {
        var input = [UInt8](repeating: 0x41, count: max(inputSize, 1))
        var outputSize = 4096
        var output = [UInt8](repeating: 0, count: outputSize)
        
        let kr: kern_return_t
        if inputSize > 0 {
            kr = IOConnectCallStructMethod(
                conn, selector,
                input, inputSize,
                &output, &outputSize
            )
        } else {
            kr = IOConnectCallStructMethod(
                conn, selector,
                nil, 0,
                &output, &outputSize
            )
        }
        
        return kr
    }
    
    private func recordResult(_ service: String, _ selector: UInt32, _ inputSize: Int, _ kr: kern_return_t) {
        // IOKit error codes as Int32 (they overflow unsigned hex literals)
        let kMIGBadID          = Int32(bitPattern: 0xe00002c2)
        let kIOReturnBadArg    = Int32(bitPattern: 0xe00002bc)
        let kIOReturnNotPriv   = Int32(bitPattern: 0xe00002ed)
        let kIOReturnExclusive = Int32(bitPattern: 0xe00002be)
        let kIOReturnOverrun   = Int32(bitPattern: 0xe00002d8)
        let kIOReturnNotReady  = Int32(bitPattern: 0xe00002eb)
        let kIOReturnUnsup     = Int32(bitPattern: 0xe00002c7)
        
        // Interesting results: anything that's NOT "invalid argument" or "bad selector"
        let boring: Set<kern_return_t> = [
            KERN_INVALID_ARGUMENT,
            kMIGBadID,
            kIOReturnBadArg,
        ]
        
        let interesting = !boring.contains(kr) && kr != KERN_SUCCESS
        
        if interesting || kr == KERN_SUCCESS {
            let note: String
            switch kr {
            case KERN_SUCCESS:      note = "SUCCESS — selector accepts this input"
            case kIOReturnNotPriv:  note = "kIOReturnNotPrivileged — needs entitlement"
            case kIOReturnExclusive: note = "kIOReturnExclusiveAccess — already in use"
            case kIOReturnOverrun:  note = "kIOReturnOverrun — buffer overflow potential?"
            case kIOReturnNotReady: note = "kIOReturnNotReady — state-dependent"
            case kIOReturnUnsup:    note = "kIOReturnUnsupported — known but disabled"
            default: note = String(format: "kr=0x%x — investigate", kr)
            }
            
            results.append(ProbeResult(
                service: service, selector: selector,
                inputSize: inputSize, result: kr,
                interesting: interesting, note: note
            ))
            
            if interesting {
                emit("⚡ \(service) sel=\(selector) size=\(inputSize): \(note)")
            }
        }
    }
    
    private func emit(_ msg: String) {
        log.append(msg)
        print("[fuzzer] \(msg)")
    }
}
