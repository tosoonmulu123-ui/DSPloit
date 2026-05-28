//
//  exp_proc_dump.swift
//  DSPloit
//
//  EXPERIMENT: Dump ALL process names from kernel proc list
//  ═══════════════════════════════════════════════════════════════
//  STATUS: DIAGNOSTIC — Debug why findPidByName("amfid") fails
//  ═══════════════════════════════════════════════════════════════
//
//  PROBLEM:
//  The panic stackshot PROVES amfid exists (pid 54, procname "amfid",
//  csTrustLevel 9). But findPidByName("amfid") returns 0.
//
//  POSSIBLE CAUSES:
//  1. off_proc_p_list_le_next is wrong → walking wrong linked list
//  2. off_proc_p_name is wrong → reading garbage instead of name
//  3. ds_get_kern_proc() returns wrong address → starting from wrong proc
//  4. The list walk terminates early (null pointer or loop detection)
//  5. Name encoding issue (UTF-8 vs raw bytes)
//  6. proc_ro split: on iOS 18.x, some proc fields moved to proc_ro
//     region — p_name might be in proc_ro, not proc struct itself
//
//  THIS EXPERIMENT:
//  - Dumps the first 100 processes with PID + name (raw hex + string)
//  - Uses THROTTLED KRW to avoid stack corruption
//  - Tests multiple name offset candidates
//  - Reports what's actually at off_proc_p_name for each proc
//
//  Created by Royan | 2026-05-28
//

import Foundation
import UIKit

final class ExpProcDump {
    static let shared = ExpProcDump()
    private var results: [String] = []
    
    private func log(_ msg: String) {
        results.append(msg)
        globallogger.log("(exp_procdump) \(msg)")
    }
    
    // ═══════════════════════════════════════════════════════════
    // THROTTLE: Same approach as exp_safe_flag_scan
    // ═══════════════════════════════════════════════════════════
    
    private let krwThrottleUs: useconds_t = 15_000  // 15ms between ops
    private var krwOpCount: Int = 0
    private let krwBatchSize: Int = 4
    private let krwBatchPauseUs: useconds_t = 50_000  // 50ms batch pause
    
    private func safe_kread64(_ addr: UInt64) -> UInt64 {
        krwOpCount += 1
        if krwOpCount % krwBatchSize == 0 {
            usleep(krwBatchPauseUs)
        } else {
            usleep(krwThrottleUs)
        }
        return ds_kread64(addr)
    }
    
    private func safe_kread32(_ addr: UInt64) -> UInt32 {
        krwOpCount += 1
        if krwOpCount % krwBatchSize == 0 {
            usleep(krwBatchPauseUs)
        } else {
            usleep(krwThrottleUs)
        }
        return ds_kread32(addr)
    }

    // ═══════════════════════════════════════════════════════════
    // MAIN ENTRY POINT
    // ═══════════════════════════════════════════════════════════
    
    func runAll() -> [String] {
        results.removeAll()
        krwOpCount = 0
        
        log("═══════════════════════════════════════════════════")
        log("  PROC LIST DUMP — Debug findPidByName")
        log("  iOS \(UIDevice.current.systemVersion)")
        log("  Throttled KRW (15ms/op, 50ms/batch)")
        log("═══════════════════════════════════════════════════")
        log("")
        
        guard dspmgr.shared.dsready else {
            log("❌ KRW not active — run jailbreak first")
            return results
        }
        
        let slide = ds_get_kernel_slide()
        log("🔍 kernel_slide = 0x\(String(slide, radix: 16))")
        log("")
        
        // ── Phase 1: Verify offsets we're using ──
        log("── Phase 1: Offset Verification ──")
        log("  off_proc_p_list_le_next = 0x\(String(off_proc_p_list_le_next, radix: 16))")
        log("  off_proc_p_name         = 0x\(String(off_proc_p_name, radix: 16))")
        log("  off_proc_p_pid          = 0x\(String(off_proc_p_pid, radix: 16))")
        log("")
        
        // ── Phase 2: Get kernel proc (allproc head) ──
        log("── Phase 2: Kernel Proc (allproc) ──")
        
        let kernProc = ds_get_kern_proc()
        log("  ds_get_kern_proc() = 0x\(String(kernProc, radix: 16))")
        
        if kernProc == 0 {
            log("  ❌ kernProc is NULL — cannot walk proc list")
            log("")
            log("  Trying alternative: resolve _allproc symbol...")
            
            let allprocSym = ds_kcache_symbol_runtime("_allproc")
            log("  _allproc symbol = 0x\(String(allprocSym, radix: 16))")
            
            if allprocSym != 0 {
                let firstProc = safe_kread64(allprocSym)
                log("  *_allproc = 0x\(String(firstProc, radix: 16))")
                if firstProc != 0 {
                    log("  → Using _allproc as starting point")
                    walkProcList(startProc: firstProc, method: "_allproc symbol")
                }
            }
            return results
        }
        
        // Verify kernProc looks valid (read its PID — should be 0 for kernel_task)
        let kernPid = safe_kread32(kernProc + UInt64(off_proc_p_pid))
        log("  kernProc PID = \(kernPid) (expected 0 for kernel_task)")
        
        // Read kernel proc name
        let kernName = readProcName(proc: kernProc)
        log("  kernProc name = \"\(kernName)\"")
        log("")
        
        // ── Phase 3: Walk proc list from kernProc ──
        log("── Phase 3: Walk Proc List (from kernProc.p_list.le_next) ──")
        log("")
        
        let firstNext = safe_kread64(kernProc + UInt64(off_proc_p_list_le_next))
        log("  kernProc->p_list.le_next = 0x\(String(firstNext, radix: 16))")
        
        if firstNext == 0 {
            log("  ❌ First next is NULL!")
            log("  → off_proc_p_list_le_next (0x\(String(off_proc_p_list_le_next, radix: 16))) may be WRONG")
            log("")
            log("  Trying alternative offsets...")
            tryAlternativeListOffsets(proc: kernProc)
        } else {
            walkProcList(startProc: firstNext, method: "kernProc->p_list.le_next")
        }
        
        // ── Phase 4: Try _allproc symbol as alternative ──
        log("")
        log("── Phase 4: Alternative — _allproc symbol ──")
        
        let allprocSym = ds_kcache_symbol_runtime("_allproc")
        log("  _allproc = 0x\(String(allprocSym, radix: 16))")
        
        if allprocSym != 0 {
            let allprocHead = safe_kread64(allprocSym)
            log("  *_allproc (head) = 0x\(String(allprocHead, radix: 16))")
            
            if allprocHead != 0 && allprocHead != firstNext {
                log("  ⚠️ _allproc head DIFFERS from kernProc->next!")
                log("  → This means ds_get_kern_proc() is NOT the allproc head")
                walkProcList(startProc: allprocHead, method: "_allproc")
            } else if allprocHead == firstNext {
                log("  ✅ _allproc matches kernProc->next (consistent)")
            }
        } else {
            log("  ⚠️ _allproc symbol not found")
        }
        
        // ── Phase 5: Try proc_ro name offset ──
        log("")
        log("── Phase 5: Check if p_name is in proc_ro ──")
        log("  On iOS 18.x, some proc fields moved to proc_ro (PPL-protected)")
        log("  If off_proc_p_name reads garbage, the name might be in proc_ro")
        log("")
        
        // Check if there's a proc_ro pointer in the proc struct
        // Common offset for p_proc_ro on iOS 18.x: around 0x18 or 0x20
        let procRoCandidates: [UInt64] = [0x18, 0x20, 0x28, 0x30, 0x38]
        
        if firstNext != 0 {
            log("  Testing proc_ro candidates on first proc (0x\(String(firstNext, radix: 16))):")
            for roOff in procRoCandidates {
                let candidate = safe_kread64(firstNext + roOff)
                // proc_ro pointers should be in kernel heap range
                if candidate > 0xfffffff000000000 && candidate < 0xfffffffffff00000 {
                    // Try reading name from proc_ro + common name offsets
                    for nameOff: UInt64 in [0x60, 0x68, 0x70, 0x78, 0x80, 0xB0, 0xC0, 0xD0] {
                        let nameCandidate = readStringAt(addr: candidate + nameOff, maxLen: 16)
                        if isPrintableProcessName(nameCandidate) {
                            log("    ✅ proc+0x\(String(roOff, radix: 16)) → proc_ro+0x\(String(nameOff, radix: 16)) = \"\(nameCandidate)\"")
                        }
                    }
                }
            }
        }
        
        // ── Phase 6: Specifically search for PID 54 (amfid from stackshot) ──
        log("")
        log("── Phase 6: Direct search for PID 54 (amfid) ──")
        log("  Panic stackshot confirmed: pid 54, procname 'amfid'")
        log("")
        
        searchForPid(targetPid: 54, startProc: firstNext != 0 ? firstNext : kernProc)
        
        log("")
        log("═══════════════════════════════════════════════════")
        log("  PROC DUMP COMPLETE — \(krwOpCount) KRW ops performed")
        log("═══════════════════════════════════════════════════")
        
        return results
    }
    
    // ═══════════════════════════════════════════════════════════
    // Walk proc list and dump all entries
    // ═══════════════════════════════════════════════════════════
    
    private func walkProcList(startProc: UInt64, method: String) {
        log("  Walking from 0x\(String(startProc, radix: 16)) (method: \(method))")
        log("  Format: [PID] name (proc_addr)")
        log("")
        
        var current = startProc
        var iterations = 0
        let maxIterations = 150
        var foundAmfid = false
        var seenAddrs = Set<UInt64>()
        
        while current != 0 && iterations < maxIterations {
            // Loop detection
            if seenAddrs.contains(current) {
                log("  ⚠️ Loop detected at iteration \(iterations) (addr 0x\(String(current, radix: 16)))")
                break
            }
            seenAddrs.insert(current)
            iterations += 1
            
            // Read PID
            let pid = safe_kread32(current + UInt64(off_proc_p_pid))
            
            // Read name
            let name = readProcName(proc: current)
            
            // Highlight amfid
            let marker: String
            if name == "amfid" || name.hasPrefix("amfid") {
                marker = " ★★★ FOUND AMFID!"
                foundAmfid = true
            } else if pid == 54 {
                marker = " ★ PID 54 (expected amfid)"
            } else {
                marker = ""
            }
            
            log("  [\(String(format: "%4d", pid))] \(name.padding(toLength: 20, withPad: " ", startingAt: 0)) (0x\(String(current, radix: 16)))\(marker)")
            
            // Get next
            let next = safe_kread64(current + UInt64(off_proc_p_list_le_next))
            
            // Sanity check next pointer
            if next != 0 && (next < 0xfffffff000000000 || next > 0xfffffffffff00000) {
                log("  ⚠️ Invalid next pointer: 0x\(String(next, radix: 16)) — stopping")
                break
            }
            
            current = next
        }
        
        log("")
        log("  Total: \(iterations) processes walked")
        if foundAmfid {
            log("  ✅ amfid FOUND in proc list!")
            log("  → findPidByName bug is in NAME COMPARISON or OFFSET")
        } else {
            log("  ❌ amfid NOT found in \(iterations) processes")
            log("  → Either list walk is broken OR amfid is on a different list")
        }
    }
    
    // ═══════════════════════════════════════════════════════════
    // Try alternative list offsets if the primary one fails
    // ═══════════════════════════════════════════════════════════
    
    private func tryAlternativeListOffsets(proc: UInt64) {
        // On different iOS versions, p_list offset varies
        // Common candidates: 0x0, 0x8, 0x10, 0x18, 0x20
        let candidates: [Int32] = [0x0, 0x8, 0x10, 0x18, 0x20, 0x28, 0x30]
        
        log("  Testing list link offsets on kernProc (0x\(String(proc, radix: 16))):")
        
        for off in candidates {
            let val = safe_kread64(proc + UInt64(off))
            let valid = (val > 0xfffffff000000000 && val < 0xfffffffffff00000)
            let marker = valid ? "✅ valid kernel ptr" : "❌"
            log("    +0x\(String(off, radix: 16)): 0x\(String(val, radix: 16)) \(marker)")
            
            if valid && off != off_proc_p_list_le_next {
                // Try reading PID from this candidate
                let candidatePid = safe_kread32(val + UInt64(off_proc_p_pid))
                let candidateName = readProcName(proc: val)
                log("      → PID=\(candidatePid) name=\"\(candidateName)\"")
                
                if candidatePid > 0 && candidatePid < 10000 && isPrintableProcessName(candidateName) {
                    log("      ★ This offset looks correct! off_proc_p_list_le_next should be 0x\(String(off, radix: 16))")
                }
            }
        }
    }
    
    // ═══════════════════════════════════════════════════════════
    // Search specifically for a PID
    // ═══════════════════════════════════════════════════════════
    
    private func searchForPid(targetPid: UInt32, startProc: UInt64) {
        var current = startProc
        var iterations = 0
        var seenAddrs = Set<UInt64>()
        
        while current != 0 && iterations < 200 {
            if seenAddrs.contains(current) { break }
            seenAddrs.insert(current)
            iterations += 1
            
            let pid = safe_kread32(current + UInt64(off_proc_p_pid))
            
            if pid == targetPid {
                log("  ✅ Found PID \(targetPid) at proc 0x\(String(current, radix: 16))")
                
                // Dump raw bytes around name offset
                log("  Raw bytes at proc+off_proc_p_name (0x\(String(off_proc_p_name, radix: 16))):")
                let nameAddr = current + UInt64(off_proc_p_name)
                var rawBytes: [UInt8] = []
                for i in 0..<4 {
                    let chunk = safe_kread64(nameAddr + UInt64(i * 8))
                    for b in 0..<8 {
                        rawBytes.append(UInt8((chunk >> (b * 8)) & 0xFF))
                    }
                }
                let hexStr = rawBytes.map { String(format: "%02x", $0) }.joined(separator: " ")
                log("    HEX: \(hexStr)")
                let nameStr = String(bytes: rawBytes.prefix(while: { $0 != 0 }), encoding: .utf8) ?? "(non-UTF8)"
                log("    STR: \"\(nameStr)\"")
                
                // Also try reading name via 32-bit reads (in case alignment matters)
                log("  Alternative read (32-bit chunks):")
                var altBytes: [UInt8] = []
                for i in 0..<8 {
                    let chunk = safe_kread32(nameAddr + UInt64(i * 4))
                    for b in 0..<4 {
                        altBytes.append(UInt8((chunk >> (b * 8)) & 0xFF))
                    }
                }
                let altHex = altBytes.map { String(format: "%02x", $0) }.joined(separator: " ")
                log("    HEX: \(altHex)")
                let altName = String(bytes: altBytes.prefix(while: { $0 != 0 }), encoding: .utf8) ?? "(non-UTF8)"
                log("    STR: \"\(altName)\"")
                
                // Check if name matches "amfid"
                let expected: [UInt8] = [0x61, 0x6d, 0x66, 0x69, 0x64, 0x00] // "amfid\0"
                let matches = rawBytes.starts(with: expected)
                log("  Name matches 'amfid': \(matches ? "YES ✅" : "NO ❌")")
                
                if !matches {
                    log("  ⚠️ PID 54 exists but name doesn't match!")
                    log("  → off_proc_p_name (0x\(String(off_proc_p_name, radix: 16))) is WRONG for this iOS version")
                    log("  → Need to scan for 'amfid' bytes in proc struct")
                    
                    // Scan proc struct for "amfid" string
                    scanProcForString(proc: current, target: "amfid")
                }
                
                return
            }
            
            current = safe_kread64(current + UInt64(off_proc_p_list_le_next))
        }
        
        log("  ❌ PID \(targetPid) not found in \(iterations) iterations")
        log("  → Either proc list walk is broken or amfid has different PID now")
    }
    
    // ═══════════════════════════════════════════════════════════
    // Scan proc struct for a target string (find correct name offset)
    // ═══════════════════════════════════════════════════════════
    
    private func scanProcForString(proc: UInt64, target: String) {
        log("  Scanning proc struct (0x000-0x400) for '\(target)'...")
        
        let targetBytes = Array(target.utf8)
        
        // Read proc struct in 64-bit chunks, scan for target
        for offset in stride(from: 0, to: 0x400, by: 8) {
            let chunk = safe_kread64(proc + UInt64(offset))
            var chunkBytes: [UInt8] = []
            for b in 0..<8 {
                chunkBytes.append(UInt8((chunk >> (b * 8)) & 0xFF))
            }
            
            // Check if target starts in this chunk
            for startIdx in 0..<8 {
                if startIdx + targetBytes.count <= 8 {
                    let slice = Array(chunkBytes[startIdx..<(startIdx + targetBytes.count)])
                    if slice == targetBytes {
                        let foundOffset = offset + startIdx
                        log("    ★★★ FOUND '\(target)' at proc+0x\(String(foundOffset, radix: 16))!")
                        log("    → CORRECT off_proc_p_name = 0x\(String(foundOffset, radix: 16))")
                        log("    → Current off_proc_p_name = 0x\(String(off_proc_p_name, radix: 16)) (WRONG!)")
                        return
                    }
                }
            }
            
            // Also check cross-boundary (target spans two chunks)
            // Only check first few bytes at end of chunk
            if targetBytes.count > 1 {
                let endByte = chunkBytes[7]
                if endByte == targetBytes[0] {
                    // Potential cross-boundary match — read next chunk to verify
                    let nextChunk = safe_kread64(proc + UInt64(offset + 8))
                    var nextBytes: [UInt8] = []
                    for b in 0..<8 { nextBytes.append(UInt8((nextChunk >> (b * 8)) & 0xFF)) }
                    
                    let combined = [endByte] + nextBytes
                    if combined.starts(with: targetBytes) {
                        let foundOffset = offset + 7
                        log("    ★★★ FOUND '\(target)' at proc+0x\(String(foundOffset, radix: 16)) (cross-boundary)!")
                        log("    → CORRECT off_proc_p_name = 0x\(String(foundOffset, radix: 16))")
                        return
                    }
                }
            }
        }
        
        log("    ❌ '\(target)' not found in proc struct (0x000-0x400)")
        log("    → Name might be in proc_ro or a separate allocation")
    }
    
    // ═══════════════════════════════════════════════════════════
    // HELPERS
    // ═══════════════════════════════════════════════════════════
    
    /// Read process name from proc struct (32 bytes max, using 64-bit reads)
    private func readProcName(proc: UInt64) -> String {
        let nameAddr = proc + UInt64(off_proc_p_name)
        var bytes: [UInt8] = []
        
        // Read 32 bytes (4 x 64-bit reads) — throttled
        for i in 0..<4 {
            let chunk = safe_kread64(nameAddr + UInt64(i * 8))
            for b in 0..<8 {
                let idx = i * 8 + b
                if idx < 32 {
                    bytes.append(UInt8((chunk >> (b * 8)) & 0xFF))
                }
            }
        }
        
        // Convert to string (null-terminated)
        let nameBytes = bytes.prefix(while: { $0 != 0 })
        return String(bytes: nameBytes, encoding: .utf8) ?? "(invalid-utf8: \(nameBytes.map { String(format: "%02x", $0) }.joined()))"
    }
    
    /// Read a string from arbitrary kernel address
    private func readStringAt(addr: UInt64, maxLen: Int) -> String {
        var bytes: [UInt8] = []
        let chunks = (maxLen + 7) / 8
        
        for i in 0..<chunks {
            let chunk = safe_kread64(addr + UInt64(i * 8))
            for b in 0..<8 {
                let idx = i * 8 + b
                if idx < maxLen {
                    let byte = UInt8((chunk >> (b * 8)) & 0xFF)
                    if byte == 0 { return String(bytes: bytes, encoding: .utf8) ?? "" }
                    bytes.append(byte)
                }
            }
        }
        
        return String(bytes: bytes, encoding: .utf8) ?? ""
    }
    
    /// Check if a string looks like a valid process name
    private func isPrintableProcessName(_ s: String) -> Bool {
        guard s.count >= 2 && s.count <= 32 else { return false }
        return s.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "_" || $0 == "-" || $0 == ".") }
    }
}
