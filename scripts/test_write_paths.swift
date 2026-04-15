#!/usr/bin/env swift
import Foundation

struct CaseResult {
    let name: String
    let ok: Bool
    let detail: String
}

func runWriteCase(name: String, target: URL, payload: Data) -> CaseResult {
    do {
        try payload.write(to: target, options: .atomic)
        let readBack = try Data(contentsOf: target)
        if readBack == payload {
            return CaseResult(name: name, ok: true, detail: "write+verify ok (\(payload.count) bytes)")
        }
        return CaseResult(name: name, ok: false, detail: "read-back mismatch")
    } catch {
        return CaseResult(name: name, ok: false, detail: "exception: \(error.localizedDescription)")
    }
}

let fm = FileManager.default
let root = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
    .appendingPathComponent("lara-write-tests-\(UUID().uuidString)", isDirectory: true)
try fm.createDirectory(at: root, withIntermediateDirectories: true)
defer { try? fm.removeItem(at: root) }

let target = root.appendingPathComponent("target.bin")
let seed = Data(repeating: 0x41, count: 16)
try seed.write(to: target)

let smaller = Data(repeating: 0x42, count: 8)
let equal = Data(repeating: 0x43, count: 16)
let larger = Data(repeating: 0x44, count: 64)

let results = [
    runWriteCase(name: "overwrite_smaller_payload", target: target, payload: smaller),
    runWriteCase(name: "overwrite_equal_payload", target: target, payload: equal),
    runWriteCase(name: "overwrite_larger_payload", target: target, payload: larger),
]

var failed = false
for result in results {
    let marker = result.ok ? "PASS" : "FAIL"
    print("[\(marker)] \(result.name): \(result.detail)")
    if !result.ok { failed = true }
}

if failed {
    exit(1)
}
print("All local write path tests passed.")
