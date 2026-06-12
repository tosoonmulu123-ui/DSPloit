//
//  exp_cryptexd_unrestrict.swift
//  DSPloit
//
//  EXPERIMENT: Safe cryptexd exception unrestrict + RC test
//  Implements implementation_plan.md Steps 1–3 without panic-prone writes.
//

import Foundation

final class ExpCryptexdUnrestrict {
    static let shared = ExpCryptexdUnrestrict()
    var onLog: ((String) -> Void)?

    private func log(_ msg: String) {
        DispatchQueue.main.async { self.onLog?(msg) }
        globallogger.log("(exp_cryptexd_unrestrict) \(msg)")
    }

    func runAsync() {
        #if !DISABLE_REMOTECALL
        DispatchQueue.global(qos: .userInitiated).async {
            self.run()
        }
        #else
        log("❌ DISABLE_REMOTECALL")
        #endif
    }

    #if !DISABLE_REMOTECALL
    private func run() {
        guard dspmgr.shared.dsready else {
            log("❌ KRW not active — run jailbreak first")
            return
        }

        log("══════════════════════════════════════")
        log("  cryptexd Safe Unrestrict")
        log("  (no KTRR/PPL writes, no port zero)")
        log("══════════════════════════════════════")
        log("")

        log("[1/3] AMFI + task prep...")
        let prep = TaskExceptionUnrestrict.prepareCryptexd { [weak self] msg in
            self?.log(msg)
        }

        guard prep.processFound else {
            log("")
            log("■ Done — cryptexd not available")
            return
        }

        log("")
        log("[2/3] Summary:")
        log("  developer_mode_resolved: \(prep.developerModeResolved ? "✅" : "❌")")
        log("  exc_guard cleared:       \(prep.excGuardCleared ? "✅" : "⚠️")")
        log("  flag patches:            \(prep.flagPatches.count)")

        log("")
        log("[3/3] Testing RC to cryptexd...")

        TaskExceptionUnrestrict.testRemoteCall(
            serviceName: "com.apple.cryptexd",
            processName: "cryptexd",
            log: { [weak self] msg in self?.log(msg) }
        ) { [weak self] ok in
            guard let self else { return }
            log("")
            if ok {
                log("🎉 RC to cryptexd CONNECTED!")
                log("   → Run 'cryptexd IOKit (safe)' for TC load")
            } else {
                log("❌ RC still blocked after safe prep")
                log("   Restriction may need deeper kernel RE")
            }
            log("")
            log("■ Done")
        }
    }
    #endif
}
