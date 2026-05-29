//
//  KernelOps.swift
//  DSPloit
//
//  Extracted kernel operations from dspmgr.swift
//  Provides clean API for kernel memory operations, process management,
//  and system introspection without bloating the main state manager.
//
//  Created by Royan | 2026-05-29
//

import Foundation

/// Kernel Operations — clean interface for kernel R/W and process management
/// Extracted from dspmgr to reduce file size and improve maintainability
final class KernelOps {
    static let shared = KernelOps()
    
    private var mgr: dspmgr { dspmgr.shared }
    
    // MARK: - Process Operations
    
    struct ProcessInfo: Identifiable {
        let id = UUID()
        let pid: Int32
        let uid: UInt32
        let gid: UInt32
        let name: String
        let kaddr: UInt64
        let csFlags: UInt32
        let taskAddr: UInt64
    }
    
    /// Get detailed process info including cs_flags and task address
    func getProcessInfo(pid: Int32) -> ProcessInfo? {
        guard mgr.dsready else { return nil }
        let proc = procbypid(pid)
        guard proc != 0 else { return nil }
        
        let procRo = ds_kread64(proc + UInt64(off_proc_p_proc_ro))
        let ucred = procRo != 0 ? ds_kread64(procRo + UInt64(off_proc_ro_p_ucred)) : 0
        let uid = ucred != 0 ? ds_kread32(ucred + 0x18) : 0
        let gid = ucred != 0 ? ds_kread32(ucred + 0x1c) : 0
        let csFlags = procRo != 0 ? ds_kread32(procRo + 0x1c) : 0
        let task = taskbyproc(proc)
        
        // Read name
        var nameBytes = [UInt8](repeating: 0, count: 32)
        for i in 0..<4 {
            let chunk = ds_kread64(proc + UInt64(off_proc_p_name) + UInt64(i * 8))
            for b in 0..<8 {
                let idx = i * 8 + b
                if idx < 32 { nameBytes[idx] = UInt8((chunk >> (b * 8)) & 0xFF) }
            }
        }
        let name = String(bytes: nameBytes.prefix(while: { $0 != 0 }), encoding: .utf8) ?? ""
        
        return ProcessInfo(pid: pid, uid: uid, gid: gid, name: name,
                          kaddr: proc, csFlags: csFlags, taskAddr: task)
    }
    
    /// Elevate a process to root (uid=0, gid=0)
    /// Returns success status and message
    func elevateToRoot(pid: Int32) -> (ok: Bool, msg: String) {
        return mgr.elevateCredentials(pid: pid)
    }
    
    /// Patch cs_flags for a process using the new AMFI bypass
    func patchCSFlags(pid: Int32) -> (ok: Bool, msg: String) {
        guard mgr.dsready else { return (false, "KRW not ready") }
        let proc = procbypid(pid)
        guard proc != 0 else { return (false, "Process not found") }
        
        let result = amfi_bypass_patch_csflags(proc)
        return (result, result ? "cs_flags patched" : "cs_flags patch failed (PPL)")
    }
    
    // MARK: - Memory Operations
    
    /// Safe kernel read with validation
    func safeRead64(address: UInt64) -> UInt64? {
        guard mgr.dsready else { return nil }
        guard address >= VM_MIN_KERNEL_ADDRESS && address <= VM_MAX_KERNEL_ADDRESS else { return nil }
        return ds_kread64_safe(address)
    }
    
    /// Safe kernel write with validation
    func safeWrite64(address: UInt64, value: UInt64) -> Bool {
        guard mgr.dsready else { return false }
        guard address >= VM_MIN_KERNEL_ADDRESS && address <= VM_MAX_KERNEL_ADDRESS else { return false }
        ds_kwrite64(address, value)
        return ds_kread64_safe(address) == value
    }
    
    // MARK: - Offset Validation
    
    /// Validate that critical offsets are non-zero and reasonable
    /// Call this before running exploit to catch misconfiguration early
    func validateOffsets() -> (valid: Bool, issues: [String]) {
        var issues: [String] = []
        
        let criticalOffsets: [(String, UInt32)] = [
            ("proc_p_proc_ro", off_proc_p_proc_ro),
            ("proc_p_pid", off_proc_p_pid),
            ("proc_p_fd", off_proc_p_fd),
            ("proc_p_textvp", off_proc_p_textvp),
            ("thread_t_tro", off_thread_t_tro),
            ("task_itk_space", off_task_itk_space),
            ("task_map", off_task_map),
            ("inpcb_inp6_icmp6filt", off_inpcb_inp_depend6_inp6_icmp6filt),
            ("vnode_v_name", off_vnode_v_name),
            ("vnode_v_parent", off_vnode_v_parent),
        ]
        
        for (name, value) in criticalOffsets {
            if value == 0 {
                issues.append("\(name) = 0 (uninitialized)")
            } else if value == 0xdeaddead {
                issues.append("\(name) = OFFSET_INVALID (not available on this device)")
            } else if value > 0x1000 {
                issues.append("\(name) = 0x\(String(value, radix: 16)) (suspiciously large)")
            }
        }
        
        // Validate 64-bit values
        if t1sz_boot == 0 {
            issues.append("t1sz_boot = 0 (PAC mask will be wrong)")
        }
        if sizeof_ipc_entry == 0 {
            issues.append("sizeof_ipc_entry = 0 (IPC operations will fail)")
        }
        
        return (issues.isEmpty, issues)
    }
    
    // MARK: - Runtime Offset Correction
    
    /// Attempt to auto-correct offsets by probing kernel structures
    /// Uses known patterns to verify and fix offset values
    func autoCorrectOffsets() -> Int {
        guard mgr.dsready else { return 0 }
        var corrections = 0
        
        // Verify proc_p_pid by reading our own PID
        let ourProc = ds_get_our_proc()
        guard ourProc != 0 else { return 0 }
        
        let expectedPid = getpid()
        let readPid = Int32(ds_kread32(ourProc + UInt64(off_proc_p_pid)))
        
        if readPid != expectedPid {
            // Try scanning nearby offsets for our PID
            for offset: UInt32 in stride(from: 0x50, through: 0x80, by: 4) {
                let candidate = Int32(ds_kread32(ourProc + UInt64(offset)))
                if candidate == expectedPid {
                    globallogger.log("(offsets) auto-corrected proc_p_pid: 0x\(String(off_proc_p_pid, radix: 16)) → 0x\(String(offset, radix: 16))")
                    off_proc_p_pid = offset
                    corrections += 1
                    break
                }
            }
        }
        
        // Verify proc_p_proc_ro by checking it points to valid kernel memory
        let procRo = ds_kread64(ourProc + UInt64(off_proc_p_proc_ro))
        if procRo < VM_MIN_KERNEL_ADDRESS || procRo > VM_MAX_KERNEL_ADDRESS {
            // Try nearby offsets
            for offset: UInt32 in stride(from: 0x10, through: 0x30, by: 8) {
                let candidate = ds_kread64(ourProc + UInt64(offset))
                if candidate >= VM_MIN_KERNEL_ADDRESS && candidate <= VM_MAX_KERNEL_ADDRESS {
                    // Verify it looks like proc_ro (has task pointer at known offset)
                    let taskCandidate = ds_kread64(candidate + UInt64(off_proc_ro_pr_task))
                    if taskCandidate >= VM_MIN_KERNEL_ADDRESS && taskCandidate <= VM_MAX_KERNEL_ADDRESS {
                        globallogger.log("(offsets) auto-corrected proc_p_proc_ro: 0x\(String(off_proc_p_proc_ro, radix: 16)) → 0x\(String(offset, radix: 16))")
                        off_proc_p_proc_ro = offset
                        corrections += 1
                        break
                    }
                }
            }
        }
        
        if corrections > 0 {
            globallogger.log("(offsets) auto-corrected \(corrections) offsets")
            savealloffsets()
        }
        
        return corrections
    }
}
