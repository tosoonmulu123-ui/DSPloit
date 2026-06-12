//
//  SafeKRW.swift
//  DSPloit
//
//  Throttled kernel read/write wrappers to avoid stack overflow panics.
//

import Foundation

enum SafeKRW {
    private static let throttleUs: useconds_t = 15_000
    private static let batchPauseUs: useconds_t = 50_000
    private static let batchSize = 4
    private static var opCount = 0

    static func reset() {
        opCount = 0
    }

    private static func pause() {
        opCount += 1
        if opCount % batchSize == 0 {
            usleep(batchPauseUs)
        } else {
            usleep(throttleUs)
        }
    }

    static func read8(_ addr: UInt64) -> UInt8 {
        pause()
        return ds_kread8(addr)
    }

    static func write8(_ addr: UInt64, _ val: UInt8) {
        pause()
        ds_kwrite8(addr, val)
    }

    static func read32(_ addr: UInt64) -> UInt32 {
        pause()
        return ds_kread32(addr)
    }

    static func write32(_ addr: UInt64, _ val: UInt32) {
        pause()
        ds_kwrite32(addr, val)
    }

    static func read64(_ addr: UInt64) -> UInt64 {
        pause()
        return ds_kread64(addr)
    }

    static func write64(_ addr: UInt64, _ val: UInt64) {
        pause()
        ds_kwrite64(addr, val)
    }

    static func readPtr(_ addr: UInt64) -> UInt64 {
        pause()
        return ds_kreadptr(addr)
    }

    /// Extra settle time after a batch of writes before RC or spawn tests.
    static func settle(ms: useconds_t = 100_000) {
        usleep(ms)
    }
}
