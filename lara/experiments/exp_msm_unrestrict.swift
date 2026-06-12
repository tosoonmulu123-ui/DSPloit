//
//  exp_msm_unrestrict.swift
//  DSPloit — MobileStorageMounter Safe Unrestrict Experiment
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
        log("▶ MobileStorageMounter Safe Unrestrict")
        
        guard dspmgr.shared.dsready else {
            log("❌ KRW not ready")
            return
        }
        
        _ = TaskExceptionUnrestrict.setDeveloperModeResolved(log: log)
        
        let msmPid = procbyname("MobileStorageMounter")
        guard msmPid > 0 else {
            log("❌ MobileStorageMounter not running")
            return
        }
        log("✅ Found MobileStorageMounter (PID: \(msmPid))")
        
        let prep = TaskExceptionUnrestrict.unrestrictProcess(
            named: "MobileStorageMounter",
            pid: msmPid,
            log: log,
            devAlreadySet: true
        )
        
        log("exc_guard: \(prep.excGuardCleared ? "✅" : "⚠️") | flags: \(prep.flagPatches.count)")
        log("Testing RemoteCall...")
        
        var rcSuccess = false
        let sema = DispatchSemaphore(value: 0)
        dspmgr.shared.rcinitDaemon(
            serviceName: "com.apple.MobileStorageMounter",
            framework: nil,
            process: "MobileStorageMounter",
            migbypass: false
        ) { rc in
            if rc != nil {
                rcSuccess = true
                rc?.destroy()
            }
            sema.signal()
        }
        sema.wait()
        
        if rcSuccess {
            log("🎉 SUCCESS: RemoteCall to MobileStorageMounter connected!")
        } else {
            log("❌ RemoteCall still failed: \(RemoteCall.lastInitError() ?? "unknown")")
        }
    }
}
