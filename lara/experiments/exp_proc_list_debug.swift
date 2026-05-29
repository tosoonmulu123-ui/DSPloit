//
//  exp_proc_list_debug.swift
//  DSPloit
//
//  Debug proc list traversal — find correct offsets
//  The proc list walker fails to find amfid because offsets may be wrong.
//  This experiment dumps raw kernel memory to identify correct offsets.
//
//  Created by Royan | 2026-05-30
//

import Foundation

final class ExpProcListDebug {
    static let shared = ExpProcListDebug()
    
    func runAll() -> [String] {
        var log: [String] = []
        
        guard ds_is_ready() else { return ["❌ KRW not active"] }
        
        log.append("══ Proc List Debug ══")
        log.append("")
        
        let kernProc = ds_get_kern_proc()
        let ourProc = ds_get_our_proc()
        log.append("kern_proc: 0x\(String(format: "%llx", kernProc))")
        log.append("our_proc:  0x\(String(format: "%llx", ourProc))")
        log.append("")
        
        // Current offsets
        log.append("── Current Offsets ──")
        log.append("off_proc_p_list_le_next: 0x\(String(format: "%x", off_proc_p_list_le_next))")
        log.append("off_proc_p_pid: 0x\(String(format: "%x", off_proc_p_pid))")
        log.append("off_proc_p_name: 0x\(String(format: "%x", off_proc_p_name))")
        log.append("")
        
        // Verify our_proc is valid by reading our PID
        let ourPid = getpid()
        let kernPidRead = ds_kread32(ourProc + UInt64(off_proc_p_pid))
        log.append("── Verify our_proc ──")
        log.append("actual PID: \(ourPid)")
        log.append("kernel PID (off 0x\(String(format:"%x",off_proc_p_pid))): \(kernPidRead)")
        
        if kernPidRead != ourPid {
            log.append("❌ PID MISMATCH — off_proc_p_pid is WRONG")
            log.append("Scanning for our PID in proc struct...")
            // Scan first 0x200 bytes for our PID
            for off in stride(from: 0, to: 0x200, by: 4) {
                let val = ds_kread32(ourProc + UInt64(off))
                if val == UInt32(ourPid) {
                    log.append("  ✅ Found PID at offset 0x\(String(format:"%x", off))")
                }
            }
        } else {
            log.append("✅ PID matches at offset 0x\(String(format:"%x",off_proc_p_pid))")
        }
        log.append("")
        
        // Read our proc name
        log.append("── Verify proc name ──")
        var nameBytes = [UInt8](repeating: 0, count: 32)
        for i in 0..<4 {
            let chunk = ds_kread64(ourProc + UInt64(off_proc_p_name) + UInt64(i * 8))
            withUnsafeBytes(of: chunk) { buf in
                for j in 0..<8 where i*8+j < 32 { nameBytes[i*8+j] = buf[j] }
            }
        }
        let name = String(bytes: nameBytes.prefix(while: { $0 != 0 }), encoding: .utf8) ?? "?"
        log.append("name at off 0x\(String(format:"%x",off_proc_p_name)): '\(name)'")
        
        if !name.contains("DSPloit") && !name.contains("lara") && !name.contains("dsploit") {
            log.append("⚠️ Name doesn't match — scanning...")
            for off in stride(from: 0x100, to: 0x400, by: 8) {
                var scan = [UInt8](repeating: 0, count: 16)
                let v1 = ds_kread64(ourProc + UInt64(off))
                let v2 = ds_kread64(ourProc + UInt64(off + 8))
                withUnsafeBytes(of: v1) { for j in 0..<8 { scan[j] = $0[j] } }
                withUnsafeBytes(of: v2) { for j in 0..<8 { scan[8+j] = $0[j] } }
                let s = String(bytes: scan.prefix(while: { $0 >= 0x20 && $0 < 0x7f }), encoding: .ascii) ?? ""
                if s.count >= 3 && (s.contains("lara") || s.contains("DSP") || s.contains("dsp")) {
                    log.append("  ✅ Found name '\(s)' at offset 0x\(String(format:"%x", off))")
                }
            }
        } else {
            log.append("✅ Name matches")
        }
        log.append("")
        
        // Try to traverse proc list
        log.append("── Proc List Traversal ──")
        let nextPtr = ds_kread64(kernProc + UInt64(off_proc_p_list_le_next))
        log.append("kern_proc + 0x\(String(format:"%x",off_proc_p_list_le_next)) = 0x\(String(format:"%llx", nextPtr))")
        
        // Also try from our_proc
        let ourNext = ds_kread64(ourProc + UInt64(off_proc_p_list_le_next))
        let ourPrev = ds_kread64(ourProc + 0x8) // le_prev is typically at +0x8
        log.append("our_proc + 0x0 (next) = 0x\(String(format:"%llx", ourNext))")
        log.append("our_proc + 0x8 (prev) = 0x\(String(format:"%llx", ourPrev))")
        
        // Scan our_proc first 0x20 bytes for kernel pointers (find list links)
        log.append("")
        log.append("── Scanning our_proc[0..0x40] for list pointers ──")
        for off in stride(from: 0, to: 0x40, by: 8) {
            let val = ds_kread64(ourProc + UInt64(off))
            if val > 0xfffffff000000000 && val < 0xfffffffffff00000 && val != ourProc && val != kernProc {
                // Check if target has a valid PID
                let targetPid = ds_kread32(val + 0x60) // off_proc_p_pid = 0x60
                if targetPid > 0 && targetPid < 65535 {
                    log.append("  off 0x\(String(format:"%02x",off)) → 0x\(String(format:"%llx",val)) pid=\(targetPid) ✅")
                } else {
                    log.append("  off 0x\(String(format:"%02x",off)) → 0x\(String(format:"%llx",val)) (not proc)")
                }
            }
        }
        
        if nextPtr == 0 || nextPtr == kernProc {
            log.append("")
            log.append("❌ kern_proc next is NULL — trying from our_proc...")
            
            // Try walking from our_proc
            if ourNext > 0xfffffff000000000 && ourNext != ourProc {
                log.append("✅ our_proc has valid next pointer!")
                var current = ourNext
                var count = 0
                while current != 0 && current != ourProc && current != kernProc && count < 30 {
                    count += 1
                    let pid = ds_kread32(current + 0x60)
                    var nb = [UInt8](repeating: 0, count: 16)
                    let v = ds_kread64(current + UInt64(off_proc_p_name))
                    let v2 = ds_kread64(current + UInt64(off_proc_p_name) + 8)
                    withUnsafeBytes(of: v) { for j in 0..<8 { nb[j] = $0[j] } }
                    withUnsafeBytes(of: v2) { for j in 0..<8 { nb[8+j] = $0[j] } }
                    let pname = String(bytes: nb.prefix(while: { $0 >= 0x20 && $0 < 0x7f }), encoding: .ascii) ?? "?"
                    
                    if count <= 15 || pname.contains("amfi") {
                        log.append("  [\(count)] pid=\(pid) '\(pname)'")
                    }
                    current = ds_kread64(current + UInt64(off_proc_p_list_le_next))
                }
                log.append("  walked \(count) procs")
            } else {
                log.append("our_proc next also invalid")
                log.append("Scanning kern_proc for valid pointers...")
                for off in stride(from: 0, to: 0x80, by: 8) {
                    let val = ds_kread64(kernProc + UInt64(off))
                    if val > 0xfffffff000000000 && val < 0xfffffffffff00000 && val != kernProc {
                        let maybePid = ds_kread32(val + 0x60)
                        if maybePid > 0 && maybePid < 65535 {
                            log.append("  ✅ kern+0x\(String(format:"%x",off)) → pid=\(maybePid)")
                        }
                    }
                }
            }
        } else {
            log.append("✅ Next pointer valid: 0x\(String(format:"%llx", nextPtr))")
            
            // Walk a few entries
            var current = nextPtr
            var count = 0
            while current != 0 && current != kernProc && count < 30 {
                count += 1
                let pid = ds_kread32(current + UInt64(off_proc_p_pid))
                
                // Read name
                var nb = [UInt8](repeating: 0, count: 16)
                let v = ds_kread64(current + UInt64(off_proc_p_name))
                let v2 = ds_kread64(current + UInt64(off_proc_p_name) + 8)
                withUnsafeBytes(of: v) { for j in 0..<8 { nb[j] = $0[j] } }
                withUnsafeBytes(of: v2) { for j in 0..<8 { nb[8+j] = $0[j] } }
                let pname = String(bytes: nb.prefix(while: { $0 >= 0x20 && $0 < 0x7f }), encoding: .ascii) ?? "?"
                
                if count <= 10 || pname.contains("amfi") || pname.contains("spring") || pname.contains("launch") {
                    log.append("  [\(count)] pid=\(pid) name='\(pname)'")
                }
                
                current = ds_kread64(current + UInt64(off_proc_p_list_le_next))
            }
            log.append("  ... total \(count) procs walked")
            
            if count == 0 {
                log.append("❌ Could not walk any procs — offset likely wrong")
            }
        }
        log.append("")
        
        // Summary
        log.append("══ Summary ══")
        if kernPidRead == ourPid {
            log.append("✅ off_proc_p_pid correct")
        } else {
            log.append("❌ off_proc_p_pid WRONG — fix needed")
        }
        
        return log
    }
}
