//
//  RootShellView.swift
//  DSPloit
//
//  Root shell — execute commands as uid=0
//

import SwiftUI

struct RootShellView: View {
    @ObservedObject private var root = RootExecutor.shared
    @ObservedObject private var mgr = dspmgr.shared
    
    @State private var command = ""
    @State private var history: [(cmd: String, result: String, success: Bool)] = []
    
    var body: some View {
        VStack(spacing: 0) {
            // Output area
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 4) {
                        ForEach(Array(history.enumerated()), id: \.offset) { i, entry in
                            VStack(alignment: .leading, spacing: 2) {
                                HStack(spacing: 4) {
                                    Text("root#")
                                        .foregroundStyle(.red)
                                    Text(entry.cmd)
                                        .foregroundStyle(.primary)
                                }
                                .font(.system(size: 13, design: .monospaced))
                                
                                if !entry.result.isEmpty {
                                    Text(entry.result)
                                        .font(.system(size: 12, design: .monospaced))
                                        .foregroundStyle(entry.success ? .green : .orange)
                                }
                            }
                            .id(i)
                        }
                    }
                    .padding(.horizontal, 12)
                    .padding(.vertical, 8)
                }
                .onChange(of: history.count) { _ in
                    if let last = history.indices.last {
                        proxy.scrollTo(last, anchor: .bottom)
                    }
                }
            }
            .background(Color.black.opacity(0.3))
            
            // Input
            HStack(spacing: 8) {
                Text("root#")
                    .font(.system(size: 14, design: .monospaced))
                    .foregroundStyle(.red)
                
                TextField("command", text: $command)
                    .font(.system(size: 14, design: .monospaced))
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .onSubmit { executeCommand() }
                
                Button(action: executeCommand) {
                    Image(systemName: "arrow.right.circle.fill")
                        .font(.title3)
                }
                .disabled(command.isEmpty || root.isExecuting || !mgr.rcready)
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 10)
            .background(.ultraThinMaterial)
        }
        .navigationTitle("Root Shell")
        .navigationBarTitleDisplayMode(.inline)
    }
    
    private func executeCommand() {
        let cmd = command
        command = ""
        history.append((cmd: cmd, result: "executing...", success: true))
        let idx = history.count - 1
        
        root.shellAsRoot(command: cmd)
        
        // Update result from log after a delay
        DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
            if let last = root.lastResult, last.operation == "posix_spawn" {
                history[idx] = (cmd: cmd, result: last.message, success: last.success)
            }
        }
    }
}
