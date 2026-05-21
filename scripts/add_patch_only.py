#!/usr/bin/env python3
"""Add a simple 'Patch amfid to /var/tmp' button that ONLY copies and patches, no kill/respring"""

SWIFT_FILE = r'd:\Backup\Personal\Hp\iPhone\DSPloit\lara\views\root\AMFIExperimentView.swift'

with open(SWIFT_FILE, 'r', encoding='utf-8') as f:
    content = f.read()

# Add button before Dump amfid in Advanced section
button_anchor = '                Button(action: runDumpAmfid) {'
button_idx = content.find(button_anchor)
if button_idx == -1:
    # Try alternative
    button_anchor = '                    Label("Dump amfid binary"'
    button_idx = content.find(button_anchor)
    if button_idx == -1:
        print("ERROR: button anchor not found")
        exit(1)
    # Go back to find the Button line
    button_idx = content.rfind('Button(action:', 0, button_idx)

# Find the start of the Button block (go back to find indentation)
line_start = content.rfind('\n', 0, button_idx) + 1

new_button = '''                Button(action: runPatchAmfidOnly) {
                    HStack {
                        Label("Patch amfid (safe)", systemImage: "wrench.and.screwdriver")
                            .foregroundStyle(isRunning ? .gray : .mint)
                        Spacer()
                        if isRunning && runningLabel.contains("Patch safe") {
                            ProgressView().scaleEffect(0.7)
                        }
                    }
                }
                .disabled(isRunning || !mgr.rcready)

'''

content = content[:line_start] + new_button + content[line_start:]

# Add function before Dump amfid mark
func_anchor = '    // MARK: - Dump amfid binary'
func_idx = content.find(func_anchor)
if func_idx == -1:
    print("ERROR: func anchor not found")
    exit(1)

new_func = '''    // MARK: - Patch amfid (safe — no kill, no respring)

    /// Copy /usr/libexec/amfid ke /var/tmp/.amfid_patched dan NOP semua CBNZ W0.
    /// TIDAK kill amfid, TIDAK physmap write, TIDAK respring.
    /// Setelah ini, Exp 91 Test B bisa spawn patched version.
    private func runPatchAmfidOnly() {
        isRunning = true
        runningLabel = "Patch safe"
        guard mgr.rcready else {
            isRunning = false
            runningLabel = ""
            return
        }

        #if !DISABLE_REMOTECALL
        root.executeAsRoot(operation: "patch_amfid_safe") { rc in
            let result = self.expPatchAmfidSafe(rc: rc)
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
    private func expPatchAmfidSafe(rc: RemoteCall) -> ExperimentResult {
        let expName = "Patch amfid (safe)"
        var detail = "Copy + Patch amfid (NO kill, NO respring)\\n"
        detail += "==========================================\\n\\n"

        let mem = rc.trojanMem
        let srcPath = remote_alloc_str(rc, "/usr/libexec/amfid")
        let dstPath = remote_alloc_str(rc, "/var/tmp/.amfid_patched")
        let NOP: UInt32 = 0xD503201F

        // Hardcoded offsets dari on-device analysis
        let patchOffsets: [UInt64] = [
            0x274c, 0x2764, 0x2c68, 0x2d68, 0x33c0,
            0x348c, 0x372c, 0x3a9c, 0x3f24, 0x4164,
            0x41ec, 0x4284, 0x431c,
        ]

        // Step 1: Copy
        detail += "Step 1: Copy /usr/libexec/amfid...\\n"
        RootExecutor.rcall(rc, "unlink", dstPath)
        let srcFd = RootExecutor.rcall(rc, "open", srcPath, UInt64(O_RDONLY), 0)
        let dstFd = RootExecutor.rcall(rc, "open", dstPath, UInt64(O_WRONLY | O_CREAT | O_TRUNC), 0o755)

        guard srcFd != UInt64(bitPattern: -1) && dstFd != UInt64(bitPattern: -1) else {
            detail += "open gagal\\n"
            RootExecutor.rcall(rc, "free", srcPath)
            RootExecutor.rcall(rc, "free", dstPath)
            return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
        }

        let buf = mem + 0x800
        var total: UInt64 = 0
        for _ in 0..<512 {
            let n = RootExecutor.rcall(rc, "read", srcFd, buf, 4096)
            if n == 0 || n > 4096 { break }
            RootExecutor.rcall(rc, "write", dstFd, buf, n)
            total += n
        }
        RootExecutor.rcall(rc, "close", srcFd)
        RootExecutor.rcall(rc, "close", dstFd)
        detail += "Copied \\(total) bytes\\n\\n"

        // Step 2: Patch
        detail += "Step 2: Patch CBNZ W0 -> NOP...\\n"
        let patchFd = RootExecutor.rcall(rc, "open", dstPath, UInt64(O_RDWR), 0)
        guard patchFd != UInt64(bitPattern: -1) else {
            detail += "open for patch gagal\\n"
            RootExecutor.rcall(rc, "free", srcPath)
            RootExecutor.rcall(rc, "free", dstPath)
            return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
        }

        let nopBuf = mem + 0x2000
        rc[nopBuf].setValue32(NOP)
        var patched = 0

        for offset in patchOffsets {
            RootExecutor.rcall(rc, "lseek", patchFd, offset, 0)
            let rdBuf = mem + 0x2100
            RootExecutor.rcall(rc, "read", patchFd, rdBuf, 4)
            let orig = rc[rdBuf].value32()
            let isCBNZ = (orig >> 24) == 0x35 && (orig & 0x1F) == 0
            guard isCBNZ else { continue }

            RootExecutor.rcall(rc, "lseek", patchFd, offset, 0)
            let wn = RootExecutor.rcall(rc, "write", patchFd, nopBuf, 4)
            if wn == 4 { patched += 1 }
        }

        // Patch signature check function (0x1c830): MOV W0,#0 + RET
        RootExecutor.rcall(rc, "lseek", patchFd, 0x1c830, 0)
        rc[nopBuf].setValue32(0x52800000)     // MOV W0, #0
        rc[nopBuf + 4].setValue32(0xD65F03C0) // RET
        let sigWn = RootExecutor.rcall(rc, "write", patchFd, nopBuf, 8)
        if sigWn == 8 { patched += 1 }

        RootExecutor.rcall(rc, "close", patchFd)
        RootExecutor.rcall(rc, "free", srcPath)
        RootExecutor.rcall(rc, "free", dstPath)

        detail += "Patched: \\(patched) instruksi\\n\\n"
        detail += "File: /var/tmp/.amfid_patched\\n"
        detail += "Sekarang jalankan Exp 91 untuk spawn patched version.\\n"

        return ExperimentResult(name: expName, success: patched > 0, detail: detail, timestamp: Date())
    }
    #endif

'''

content = content[:func_idx] + new_func + content[func_idx:]

with open(SWIFT_FILE, 'w', encoding='utf-8') as f:
    f.write(content)

print("OK - added Patch amfid (safe) button + function")
