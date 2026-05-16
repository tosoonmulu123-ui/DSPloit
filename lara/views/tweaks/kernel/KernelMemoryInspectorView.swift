//
//  KernelMemoryInspectorView.swift
//  DSPloit
//  Created by Royan
//

import SwiftUI

struct KernelMemoryInspectorView: View {
    @ObservedObject private var mgr = dspmgr.shared
    @State private var addressInput = ""
    @State private var memoryDump: [UInt8] = []
    @State private var currentAddress: UInt64 = 0
    @State private var readSize: Int = 256
    @State private var isReading = false
    @State private var writeAddress = ""
    @State private var writeValue = ""
    @State private var writeWidth = 64

    var body: some View {
        List {
            Section(header: HeaderLabel(text: "Read Memory", icon: "eye")) {
                TextField("Address (hex)", text: $addressInput)
                    .font(.system(.body, design: .monospaced))
                Picker("Size", selection: $readSize) {
                    Text("64B").tag(64)
                    Text("256B").tag(256)
                    Text("1KB").tag(1024)
                }
                .pickerStyle(.segmented)

                Button(action: readMemory) {
                    HStack {
                        Image(systemName: "arrow.down.doc.fill")
                        Text("Read Kernel Memory")
                        Spacer()
                        if isReading { ProgressView() }
                    }
                }
                .disabled(!mgr.dsready || isReading)
            }

            if !memoryDump.isEmpty {
                Section(header: HeaderLabel(text: "Hex Dump", icon: "number")) {
                    ScrollView {
                        Text(hexDumpString())
                            .font(.system(size: 10, design: .monospaced))
                            .textSelection(.enabled)
                    }
                    .frame(height: 250)
                    Button("Copy Hex") {
                        UIPasteboard.general.string = hexDumpString()
                    }
                }
            }

            Section(header: HeaderLabel(text: "Write Memory", icon: "pencil.line")) {
                TextField("Address (hex)", text: $writeAddress)
                    .font(.system(.body, design: .monospaced))
                TextField("Value (hex)", text: $writeValue)
                    .font(.system(.body, design: .monospaced))
                Picker("Width", selection: $writeWidth) {
                    Text("32-bit").tag(32)
                    Text("64-bit").tag(64)
                }
                .pickerStyle(.segmented)
                Button("Write to Kernel Memory") { writeMemory() }
                    .foregroundStyle(.red)
                    .disabled(!mgr.dsready)
            }
        }
        .navigationTitle("Memory Inspector")
    }

    private func hexDumpString() -> String {
        var result = ""
        for row in stride(from: 0, to: memoryDump.count, by: 16) {
            result += String(format: "%08llx  ", currentAddress + UInt64(row))
            for col in 0..<16 {
                let idx = row + col
                if idx < memoryDump.count {
                    result += String(format: "%02x ", memoryDump[idx])
                }
            }
            result += "\n"
        }
        return result
    }

    private func readMemory() {
        guard let addr = UInt64(addressInput.replacingOccurrences(of: "0x", with: ""), radix: 16) else { return }
        isReading = true
        currentAddress = addr
        DispatchQueue.global(qos: .userInitiated).async {
            var bytes: [UInt8] = []
            for i in stride(from: 0, to: readSize, by: 8) {
                let val = mgr.kread64(address: addr + UInt64(i))
                for b in 0..<8 { bytes.append(UInt8((val >> (b * 8)) & 0xFF)) }
            }
            DispatchQueue.main.async { memoryDump = bytes; isReading = false }
        }
    }

    private func writeMemory() {
        guard let addr = UInt64(writeAddress.replacingOccurrences(of: "0x", with: ""), radix: 16),
              let val = UInt64(writeValue.replacingOccurrences(of: "0x", with: ""), radix: 16) else { return }
        if writeWidth == 64 { mgr.kwrite64(address: addr, value: val) }
        else { mgr.kwrite32(address: addr, value: UInt32(val & 0xFFFFFFFF)) }
    }
}
