/// ARM64 instruction decoder + AMFI decision path tracer
/// Traces posix_spawn → mac_vnode_check_exec → AMFI → EPERM path
/// Finds ALL writable __DATA variables that influence the code signing decision

// Segment layout from iOS 18.2 kernelcache (iPhone XR)
const TEXT_EXEC_FILEOFF: usize = 0xd8c000;
const TEXT_EXEC_SIZE: usize = 0x2198000;
const TEXT_EXEC_VMADDR: u64 = 0xfffffff007d90000;
const DATA_FILEOFF: usize = 0x30dc000;
const DATA_VMADDR_START: u64 = 0xfffffff00a0e0000;
const DATA_VMADDR_END: u64 = 0xfffffff00a408000;
const DATA_CONST_VMADDR_START: u64 = 0xfffffff009928000;
const DATA_CONST_VMADDR_END: u64 = 0xfffffff00a0e0000;

// Known string references (unslid) for key functions
const AMFI_STRINGS: &[(u64, &str)] = &[
    (0xfffffff007054000, "pmap_cs_allow_invalid"),
    (0xfffffff00706c000, "AMFI: code signature"),
    (0xfffffff007070000, "mac_vnode_check_exec"),
];

// ═══════════════════════════════════════════════════════════
// ARM64 INSTRUCTION DECODERS
// ═══════════════════════════════════════════════════════════

fn decode_adrp(insn: u32, pc: u64) -> Option<(u8, u64)> {
    if (insn & 0x9F000000) != 0x90000000 { return None; }
    let rd = (insn & 0x1F) as u8;
    let immlo = ((insn >> 29) & 0x3) as i64;
    let immhi = ((insn >> 5) & 0x7FFFF) as i64;
    let imm = (immhi << 2) | immlo;
    let imm = if imm & (1 << 20) != 0 { imm | !0x1FFFFF } else { imm };
    let page = (pc & !0xFFF).wrapping_add((imm << 12) as u64);
    Some((rd, page))
}

fn decode_add_imm(insn: u32) -> Option<(u8, u8, u64)> {
    if (insn & 0xFF800000) != 0x91000000 { return None; }
    let rd = (insn & 0x1F) as u8;
    let rn = ((insn >> 5) & 0x1F) as u8;
    let imm12 = ((insn >> 10) & 0xFFF) as u64;
    let shift = ((insn >> 22) & 0x3) as u64;
    let imm = if shift == 1 { imm12 << 12 } else { imm12 };
    Some((rd, rn, imm))
}

fn decode_ldr_imm(insn: u32) -> Option<(u8, u8, u64, u8)> {
    let size = (insn >> 30) & 0x3;
    if (insn & 0x3B000000) != 0x39000000 { return None; }
    let rt = (insn & 0x1F) as u8;
    let rn = ((insn >> 5) & 0x1F) as u8;
    let imm12 = ((insn >> 10) & 0xFFF) as u64;
    let offset = imm12 << (size as u64);
    Some((rt, rn, offset, size as u8))
}

fn decode_str_imm(insn: u32) -> Option<(u8, u8, u64, u8)> {
    // STR Xt, [Xn, #imm]
    let size = (insn >> 30) & 0x3;
    if (insn & 0x3B000000) != 0x39000000 { return None; }
    let opc = (insn >> 22) & 0x3;
    if opc != 0 { return None; } // STR has opc=00
    let rt = (insn & 0x1F) as u8;
    let rn = ((insn >> 5) & 0x1F) as u8;
    let imm12 = ((insn >> 10) & 0xFFF) as u64;
    let offset = imm12 << (size as u64);
    Some((rt, rn, offset, size as u8))
}

fn decode_ldrb(insn: u32) -> Option<(u8, u8, u64)> {
    // LDRB Wt, [Xn, #imm] — size=00
    if (insn & 0xFFC00000) != 0x39400000 { return None; }
    let rt = (insn & 0x1F) as u8;
    let rn = ((insn >> 5) & 0x1F) as u8;
    let imm12 = ((insn >> 10) & 0xFFF) as u64;
    Some((rt, rn, imm12))
}

fn decode_cbz(insn: u32, pc: u64) -> Option<(u8, u64, bool)> {
    // CBZ/CBNZ Xt, label
    if (insn & 0x7E000000) != 0x34000000 { return None; }
    let is_cbnz = (insn & 0x01000000) != 0;
    let rt = (insn & 0x1F) as u8;
    let imm19 = ((insn >> 5) & 0x7FFFF) as i64;
    let imm = if imm19 & (1 << 18) != 0 { imm19 | !0x7FFFF } else { imm19 };
    let target = pc.wrapping_add((imm << 2) as u64);
    Some((rt, target, is_cbnz))
}

fn decode_tbz(insn: u32, pc: u64) -> Option<(u8, u8, u64, bool)> {
    // TBZ/TBNZ Xt, #bit, label
    if (insn & 0x7E000000) != 0x36000000 { return None; }
    let is_tbnz = (insn & 0x01000000) != 0;
    let rt = (insn & 0x1F) as u8;
    let bit = (((insn >> 31) & 1) << 5 | ((insn >> 19) & 0x1F)) as u8;
    let imm14 = ((insn >> 5) & 0x3FFF) as i64;
    let imm = if imm14 & (1 << 13) != 0 { imm14 | !0x3FFF } else { imm14 };
    let target = pc.wrapping_add((imm << 2) as u64);
    Some((rt, bit, target, is_tbnz))
}

fn decode_bl(insn: u32, pc: u64) -> Option<u64> {
    // BL label (function call)
    if (insn & 0xFC000000) != 0x94000000 { return None; }
    let imm26 = (insn & 0x03FFFFFF) as i64;
    let imm = if imm26 & (1 << 25) != 0 { imm26 | !0x03FFFFFF } else { imm26 };
    let target = pc.wrapping_add((imm << 2) as u64);
    Some(target)
}

fn decode_b(insn: u32, pc: u64) -> Option<u64> {
    // B label (unconditional branch)
    if (insn & 0xFC000000) != 0x14000000 { return None; }
    let imm26 = (insn & 0x03FFFFFF) as i64;
    let imm = if imm26 & (1 << 25) != 0 { imm26 | !0x03FFFFFF } else { imm26 };
    let target = pc.wrapping_add((imm << 2) as u64);
    Some(target)
}

fn decode_mov_imm(insn: u32) -> Option<(u8, u64)> {
    // MOVZ Xd, #imm16, LSL #shift
    if (insn & 0x7F800000) != 0x52800000 && (insn & 0x7F800000) != 0xD2800000 {
        return None;
    }
    let rd = (insn & 0x1F) as u8;
    let imm16 = ((insn >> 5) & 0xFFFF) as u64;
    let hw = ((insn >> 21) & 0x3) as u64;
    let val = imm16 << (hw * 16);
    Some((rd, val))
}

fn decode_ret(insn: u32) -> bool {
    insn == 0xD65F03C0 // RET (x30)
}

fn is_cmp_zero(insn: u32) -> Option<u8> {
    // CMP Xn, #0 is encoded as SUBS XZR, Xn, #0
    if (insn & 0xFF80001F) == 0xF100001F {
        let rn = ((insn >> 5) & 0x1F) as u8;
        return Some(rn);
    }
    None
}

// ═══════════════════════════════════════════════════════════
// DATA VARIABLE TRACKER
// ═══════════════════════════════════════════════════════════

#[derive(Clone, Debug)]
pub struct DataRef {
    pub code_addr: u64,      // where in __TEXT_EXEC the ref is
    pub data_addr: u64,      // the __DATA address being accessed
    pub access_type: &'static str, // "load_byte", "load_word", "load_qword", "store", "addr_calc"
    pub context: String,     // nearby branch info
}

#[derive(Clone, Debug)]
pub struct FunctionInfo {
    pub start: u64,
    pub end: u64,
    pub data_refs: Vec<DataRef>,
    pub calls: Vec<u64>,     // BL targets
    pub string_refs: Vec<(u64, String)>, // string page refs
}

fn read_u32(data: &[u8], off: usize) -> u32 {
    if off + 4 > data.len() { return 0; }
    u32::from_le_bytes(data[off..off+4].try_into().unwrap())
}

fn read_u64(data: &[u8], off: usize) -> u64 {
    if off + 8 > data.len() { return 0; }
    u64::from_le_bytes(data[off..off+8].try_into().unwrap())
}

fn data_file_offset(data_vmaddr: u64) -> usize {
    ((data_vmaddr - DATA_VMADDR_START) as usize) + DATA_FILEOFF
}

// ═══════════════════════════════════════════════════════════
// FUNCTION BOUNDARY DETECTION
// ═══════════════════════════════════════════════════════════

/// Find function boundaries around a given address
fn find_function_bounds(text_exec: &[u8], target_offset: usize) -> (usize, usize) {
    // Scan backwards for function prologue (STP x29, x30, [sp, #-N]!)
    let mut start = target_offset;
    let search_back = std::cmp::min(target_offset, 0x1000);
    
    let mut i = target_offset;
    while i > target_offset - search_back {
        let insn = read_u32(text_exec, i);
        // STP x29, x30, [sp, #imm]! — common prologue
        // Encoding: x010100110xxxxxxx11111xxxxx11101
        if (insn & 0xFFE003E0) == 0xA98003E0 {
            start = i;
            break;
        }
        // Also check for PACIBSP (0xD503237F) — iOS kernel uses PAC
        if insn == 0xD503237F {
            start = i;
            break;
        }
        if i < 4 { break; }
        i -= 4;
    }
    
    // Scan forward for RET
    let mut end = target_offset;
    let search_fwd = std::cmp::min(text_exec.len() - target_offset, 0x2000);
    let mut j = target_offset;
    while j < target_offset + search_fwd {
        let insn = read_u32(text_exec, j);
        if decode_ret(insn) {
            end = j + 4;
            break;
        }
        j += 4;
    }
    
    (start, end)
}

// ═══════════════════════════════════════════════════════════
// MAIN ANALYSIS: TRACE AMFI DECISION PATH
// ═══════════════════════════════════════════════════════════

/// Analyze a function and extract all __DATA references + branch conditions
fn analyze_function(text_exec: &[u8], func_start: usize, func_end: usize) -> FunctionInfo {
    let mut info = FunctionInfo {
        start: TEXT_EXEC_VMADDR + func_start as u64,
        end: TEXT_EXEC_VMADDR + func_end as u64,
        data_refs: Vec::new(),
        calls: Vec::new(),
        string_refs: Vec::new(),
    };
    
    let mut reg_pages: [u64; 32] = [0; 32];
    let mut reg_vals: [u64; 32] = [0; 32];
    
    let mut i = func_start;
    while i < func_end && i + 4 <= text_exec.len() {
        let pc = TEXT_EXEC_VMADDR + i as u64;
        let insn = read_u32(text_exec, i);
        
        // Track ADRP
        if let Some((rd, page)) = decode_adrp(insn, pc) {
            reg_pages[rd as usize] = page;
            reg_vals[rd as usize] = page;
        }
        
        // Track ADD (full address computation)
        if let Some((rd, rn, imm)) = decode_add_imm(insn) {
            let base = reg_pages[rn as usize];
            if base != 0 {
                let addr = base + imm;
                reg_vals[rd as usize] = addr;
                reg_pages[rd as usize] = addr;
                
                if addr >= DATA_VMADDR_START && addr < DATA_VMADDR_END {
                    info.data_refs.push(DataRef {
                        code_addr: pc,
                        data_addr: addr,
                        access_type: "addr_calc",
                        context: String::new(),
                    });
                }
            }
        }
        
        // Track LDR (load from __DATA)
        if let Some((rt, rn, offset, size)) = decode_ldr_imm(insn) {
            let base = reg_vals[rn as usize];
            if base != 0 {
                let addr = base + offset;
                if addr >= DATA_VMADDR_START && addr < DATA_VMADDR_END {
                    let atype = match size {
                        0 => "load_byte",
                        2 => "load_word",
                        3 => "load_qword",
                        _ => "load_other",
                    };
                    info.data_refs.push(DataRef {
                        code_addr: pc, data_addr: addr,
                        access_type: atype, context: String::new(),
                    });
                }
            }
        }

        // Track LDRB (byte load — common for flag checks)
        if let Some((rt, rn, imm)) = decode_ldrb(insn) {
            let base = reg_vals[rn as usize];
            if base != 0 {
                let addr = base + imm;
                if addr >= DATA_VMADDR_START && addr < DATA_VMADDR_END {
                    info.data_refs.push(DataRef {
                        code_addr: pc, data_addr: addr,
                        access_type: "load_byte",
                        context: format!("LDRB w{}, [x{}, #0x{:x}]", rt, rn, imm),
                    });
                }
            }
        }
        
        // Track STR (store to __DATA)
        if let Some((_rt, rn, offset, _size)) = decode_str_imm(insn) {
            let base = reg_vals[rn as usize];
            if base != 0 {
                let addr = base + offset;
                if addr >= DATA_VMADDR_START && addr < DATA_VMADDR_END {
                    info.data_refs.push(DataRef {
                        code_addr: pc, data_addr: addr,
                        access_type: "store",
                        context: String::new(),
                    });
                }
            }
        }
        
        // Track BL (function calls)
        if let Some(target) = decode_bl(insn, pc) {
            info.calls.push(target);
        }
        
        // Track MOV immediate
        if let Some((rd, val)) = decode_mov_imm(insn) {
            reg_vals[rd as usize] = val;
        }
        
        i += 4;
    }
    
    info
}

// ═══════════════════════════════════════════════════════════
// STRING SEARCH IN KERNELCACHE
// ═══════════════════════════════════════════════════════════

fn find_string_offset(data: &[u8], needle: &str) -> Option<usize> {
    let needle_bytes = needle.as_bytes();
    for i in 0..data.len().saturating_sub(needle_bytes.len()) {
        if &data[i..i+needle_bytes.len()] == needle_bytes {
            return Some(i);
        }
    }
    None
}

/// Find all ADRP instructions that reference a given page
fn find_adrp_refs(text_exec: &[u8], target_page: u64) -> Vec<(usize, u8)> {
    let mut refs = Vec::new();
    let mut i = 0;
    while i + 4 <= text_exec.len() {
        let pc = TEXT_EXEC_VMADDR + i as u64;
        let insn = read_u32(text_exec, i);
        if let Some((rd, page)) = decode_adrp(insn, pc) {
            if page == target_page {
                refs.push((i, rd));
            }
        }
        i += 4;
    }
    refs
}

// ═══════════════════════════════════════════════════════════
// PUBLIC ENTRY POINT: DEEP AMFI ANALYSIS
// ═══════════════════════════════════════════════════════════

pub fn analyze_pmap_cs(data: &[u8]) {
    println!("\n{}", "=".repeat(70));
    println!("  DEEP AMFI/PMAP_CS ANALYSIS — Finding EPERM Decision Variables");
    println!("{}\n", "=".repeat(70));
    
    let text_exec = &data[TEXT_EXEC_FILEOFF..TEXT_EXEC_FILEOFF + TEXT_EXEC_SIZE];
    
    // ─── Phase 1: Find key strings ───
    println!("[Phase 1] Locating key strings in kernelcache...\n");
    
    let key_strings = [
        "pmap_cs_allow_invalid",
        "AMFI: code signature invalid",
        "mac_vnode_check_exec",
        "cs_enforcement_disable",
        "trust cache",
        "amfi_check_dyld_policy_self",
        "proc_check_run_cs_invalid",
        "AMFI: allowing",
        "AMFI: denying",
    ];
    
    for s in &key_strings {
        if let Some(off) = find_string_offset(data, s) {
            // Calculate vmaddr (approximate — could be in __TEXT or __DATA)
            let page = if off < TEXT_EXEC_FILEOFF {
                // Likely in __TEXT (cstrings)
                0xfffffff007004000u64 + off as u64
            } else {
                off as u64 // raw offset for now
            };
            println!("  [0x{:08x}] \"{}\" (page 0x{:x})", off, s, page & !0xFFF);
        } else {
            println!("  [NOT FOUND] \"{}\"", s);
        }
    }

    // ─── Phase 2: Find functions that reference "AMFI" strings ───
    println!("\n[Phase 2] Finding functions that reference AMFI strings...\n");
    
    // Search for "proc_check_run_cs_invalid" — this is THE function
    // that decides whether to allow unsigned code execution
    let target_strings = [
        "proc_check_run_cs_invalid",
        "cs_enforcement_disable",
        "AMFI: allowing invalid",
    ];
    
    let mut amfi_functions: Vec<(u64, String)> = Vec::new();
    
    for target_str in &target_strings {
        if let Some(str_off) = find_string_offset(data, target_str) {
            let str_page = if str_off < 0x30dc000 {
                // __TEXT segment strings — calculate vmaddr
                // __TEXT starts at vmaddr 0xfffffff007004000, fileoff 0
                0xfffffff007004000u64 + str_off as u64
            } else {
                continue;
            };
            let page_aligned = str_page & !0xFFF;
            
            // Find ADRP refs to this page
            let refs = find_adrp_refs(text_exec, page_aligned);
            println!("  \"{}\" @ page 0x{:x} — {} ADRP refs", 
                target_str, page_aligned, refs.len());
            
            for (off, _rd) in refs.iter().take(5) {
                let func_addr = TEXT_EXEC_VMADDR + *off as u64;
                let (fstart, fend) = find_function_bounds(text_exec, *off);
                let finfo = analyze_function(text_exec, fstart, fend);
                
                if !finfo.data_refs.is_empty() {
                    amfi_functions.push((finfo.start, target_str.to_string()));
                    println!("    func @ 0x{:x} (size 0x{:x}) — {} __DATA refs, {} calls",
                        finfo.start, finfo.end - finfo.start,
                        finfo.data_refs.len(), finfo.calls.len());
                    
                    // Print __DATA refs with values
                    for dref in &finfo.data_refs {
                        let file_off = data_file_offset(dref.data_addr);
                        let val = if file_off + 8 <= data.len() {
                            read_u64(data, file_off)
                        } else { 0 };
                        
                        let flag = if val > 0 && val < 0x100 {
                            " ◀◀◀ BYTE FLAG"
                        } else if val == 0 {
                            " (zero)"
                        } else {
                            ""
                        };
                        
                        println!("      {} data@0x{:x} = 0x{:x} ({}){}",
                            dref.access_type, dref.data_addr, val, val, flag);
                    }
                }
            }
        }
    }

    // ─── Phase 3: Scan ALL __TEXT_EXEC for __DATA byte-flag loads ───
    // These are LDRB from __DATA followed by CBZ/CBNZ (branch on flag)
    println!("\n[Phase 3] Scanning for __DATA byte-flag checks (LDRB + CBZ/CBNZ)...\n");
    
    let mut flag_checks: Vec<(u64, u64, u8)> = Vec::new(); // (code_addr, data_addr, value)
    
    let mut i = 0;
    let mut reg_pages: [u64; 32] = [0; 32];
    
    while i + 8 <= text_exec.len() {
        let pc = TEXT_EXEC_VMADDR + i as u64;
        let insn = read_u32(text_exec, i);
        let next_insn = read_u32(text_exec, i + 4);
        
        // Track ADRP
        if let Some((rd, page)) = decode_adrp(insn, pc) {
            reg_pages[rd as usize] = page;
        }
        
        // Pattern: LDRB Wt, [Xn, #imm] followed by CBZ/CBNZ Wt
        if let Some((rt, rn, imm)) = decode_ldrb(insn) {
            let base = reg_pages[rn as usize];
            if base != 0 {
                let addr = base + imm;
                if addr >= DATA_VMADDR_START && addr < DATA_VMADDR_END {
                    // Check if next instruction branches on this register
                    if let Some((crt, _, _)) = decode_cbz(next_insn, pc + 4) {
                        if crt == rt {
                            let file_off = data_file_offset(addr);
                            let val = if file_off < data.len() { data[file_off] } else { 0 };
                            flag_checks.push((pc, addr, val));
                        }
                    }
                    if let Some((trt, _, _, _)) = decode_tbz(next_insn, pc + 4) {
                        if trt == rt {
                            let file_off = data_file_offset(addr);
                            let val = if file_off < data.len() { data[file_off] } else { 0 };
                            flag_checks.push((pc, addr, val));
                        }
                    }
                }
            }
        }
        
        i += 4;
    }
    
    // Deduplicate by data address
    flag_checks.sort_by_key(|(_, addr, _)| *addr);
    flag_checks.dedup_by_key(|(_, addr, _)| *addr);
    
    println!("  Found {} unique __DATA byte-flag checks:\n", flag_checks.len());
    
    for (code_addr, data_addr, val) in &flag_checks {
        let offset = data_addr - DATA_VMADDR_START;
        let indicator = match *val {
            0 => "  [ZERO — may be disabled/allow]",
            1 => "  [ONE — likely enforcement ON] ★",
            _ => "",
        };
        println!("  code@0x{:x} → data@0x{:x} (__DATA+0x{:x}) val={} {}",
            code_addr, data_addr, offset, val, indicator);
    }

    // ─── Phase 4: Focus on AMFI region (0xfffffff00a330000-0xfffffff00a332000) ───
    println!("\n[Phase 4] Deep scan of AMFI __DATA region (0xa330000-0xa332000)...\n");
    
    let amfi_data_start: u64 = 0xfffffff00a330000;
    let amfi_data_end: u64 = 0xfffffff00a332000;
    
    println!("  Byte-by-byte scan for non-zero values (potential flags):\n");
    
    let amfi_file_start = data_file_offset(amfi_data_start);
    let amfi_file_end = data_file_offset(amfi_data_end);
    
    if amfi_file_end <= data.len() {
        let mut nonzero_bytes: Vec<(u64, u8)> = Vec::new();
        
        for off in 0..(amfi_data_end - amfi_data_start) as usize {
            let byte = data[amfi_file_start + off];
            if byte != 0 {
                nonzero_bytes.push((amfi_data_start + off as u64, byte));
            }
        }
        
        println!("  {} non-zero bytes in AMFI region:\n", nonzero_bytes.len());
        
        for (addr, val) in &nonzero_bytes {
            // Check if this address is referenced by code
            let is_flag_checked = flag_checks.iter().any(|(_, da, _)| da == addr);
            let marker = if is_flag_checked { " ◀◀◀ CHECKED BY CODE" } else { "" };
            
            // Check if it's a small value (likely a flag vs pointer/struct)
            let likely_flag = *val <= 10;
            let flag_marker = if likely_flag { " [FLAG?]" } else { "" };
            
            println!("    0x{:x} = {} (0x{:02x}){}{}",
                addr, val, val, flag_marker, marker);
        }
    }

    // ─── Phase 5: Find the EXACT EPERM return path ───
    println!("\n[Phase 5] Tracing EPERM (1) return paths in AMFI functions...\n");
    
    // Look for MOV W0, #1 (EPERM) followed by RET or B to epilogue
    // EPERM = 1, so: MOV W0, #1 = 0x52800020
    let eperm_pattern: u32 = 0x52800020; // mov w0, #1
    
    let mut eperm_locations: Vec<usize> = Vec::new();
    let mut i = 0;
    while i + 4 <= text_exec.len() {
        let insn = read_u32(text_exec, i);
        if insn == eperm_pattern {
            // Check if near an AMFI-related function (within 0x1000 of a flag check)
            let pc = TEXT_EXEC_VMADDR + i as u64;
            let near_amfi = flag_checks.iter().any(|(code_addr, _, _)| {
                let diff = if pc > *code_addr { pc - code_addr } else { code_addr - pc };
                diff < 0x800
            });
            if near_amfi {
                eperm_locations.push(i);
            }
        }
        i += 4;
    }
    
    println!("  Found {} EPERM returns near AMFI flag checks\n", eperm_locations.len());
    
    // For each EPERM location, trace backwards to find which flag controls it
    for ep_off in eperm_locations.iter().take(20) {
        let ep_pc = TEXT_EXEC_VMADDR + *ep_off as u64;
        
        // Look backwards for the most recent CBZ/CBNZ that leads here
        let search_back = std::cmp::min(*ep_off, 0x100);
        let mut controlling_flag: Option<u64> = None;
        
        let mut j = *ep_off;
        while j > *ep_off - search_back {
            j -= 4;
            let insn = read_u32(text_exec, j);
            let jpc = TEXT_EXEC_VMADDR + j as u64;
            
            // Check CBZ/CBNZ targeting near our EPERM
            if let Some((_, target, _)) = decode_cbz(insn, jpc) {
                if target >= ep_pc - 16 && target <= ep_pc + 16 {
                    // This branch leads to EPERM — find what it loaded
                    // Look further back for LDRB
                    let mut k = j;
                    while k > j.saturating_sub(0x40) {
                        k -= 4;
                        let kinsn = read_u32(text_exec, k);
                        if let Some((_, rn, imm)) = decode_ldrb(kinsn) {
                            let base_page = {
                                let mut bp = 0u64;
                                let mut m = k;
                                while m > k.saturating_sub(0x20) {
                                    m -= 4;
                                    let mi = read_u32(text_exec, m);
                                    let mpc = TEXT_EXEC_VMADDR + m as u64;
                                    if let Some((rd, page)) = decode_adrp(mi, mpc) {
                                        if rd == rn { bp = page; break; }
                                    }
                                }
                                bp
                            };
                            if base_page != 0 {
                                let addr = base_page + imm;
                                if addr >= DATA_VMADDR_START && addr < DATA_VMADDR_END {
                                    controlling_flag = Some(addr);
                                    break;
                                }
                            }
                        }
                    }
                    break;
                }
            }
        }
        
        if let Some(flag_addr) = controlling_flag {
            let file_off = data_file_offset(flag_addr);
            let val = if file_off < data.len() { data[file_off] } else { 0 };
            println!("  EPERM@0x{:x} ← controlled by flag@0x{:x} (val={}) ★★★",
                ep_pc, flag_addr, val);
        } else {
            println!("  EPERM@0x{:x} ← controller not traced", ep_pc);
        }
    }

    // ─── Phase 6: Summary — ACTIONABLE flags for experiment ───
    println!("\n{}", "=".repeat(70));
    println!("  SUMMARY: ACTIONABLE __DATA FLAGS FOR BYPASS");
    println!("{}\n", "=".repeat(70));
    
    println!("  These are __DATA byte flags that:");
    println!("  1. Are in WRITABLE memory (not PPL/KTRR protected)");
    println!("  2. Are checked by code near AMFI/pmap_cs functions");
    println!("  3. Have value=1 (enforcement ON) or value=0 (may need to SET to 1)");
    println!("  4. Control branch paths that lead to EPERM\n");
    
    // Collect all unique flags that are both checked by code AND non-zero
    let mut actionable: Vec<(u64, u8, bool)> = Vec::new(); // (addr, val, controls_eperm)
    
    for (_, data_addr, val) in &flag_checks {
        if *data_addr >= amfi_data_start && *data_addr < amfi_data_end {
            let controls_eperm = eperm_locations.iter().any(|ep_off| {
                let ep_pc = TEXT_EXEC_VMADDR + *ep_off as u64;
                let diff = if ep_pc > *data_addr { ep_pc - data_addr } else { data_addr - ep_pc };
                diff < 0x800
            });
            actionable.push((*data_addr, *val, controls_eperm));
        }
    }
    
    actionable.sort_by_key(|(addr, _, _)| *addr);
    actionable.dedup_by_key(|(addr, _, _)| *addr);
    
    println!("  AMFI region flags ({} total):\n", actionable.len());
    
    for (addr, val, eperm) in &actionable {
        let action = if *val == 1 && *eperm {
            "→ ZERO THIS (enforcement flag, controls EPERM) ★★★"
        } else if *val == 1 {
            "→ ZERO THIS (enforcement flag)"
        } else if *val == 0 && *eperm {
            "→ SET TO 1 (may be allow-invalid flag) ★★"
        } else {
            "→ investigate"
        };
        println!("    0x{:x} = {} {}", addr, val, action);
    }
    
    // Also print pmap_cs region flags
    println!("\n  pmap_cs region flags (0xa110000 area):\n");
    
    let pmap_cs_start: u64 = 0xfffffff00a10f000;
    let pmap_cs_end: u64 = 0xfffffff00a112000;
    
    for (_, data_addr, val) in &flag_checks {
        if *data_addr >= pmap_cs_start && *data_addr < pmap_cs_end {
            let file_off = data_file_offset(*data_addr);
            let actual_val = if file_off < data.len() { data[file_off] } else { 0 };
            println!("    0x{:x} = {} (checked as byte flag)", data_addr, actual_val);
        }
    }
    
    println!("\n  ═══ USE THESE IN exp_safe_flag_scan.swift ═══");
    println!("  Write experiment that:");
    println!("  1. Reads each flag (verify non-zero)");
    println!("  2. Zeros ONE flag at a time");
    println!("  3. Tests posix_spawn after each");
    println!("  4. Restores flag if spawn fails");
    println!("  5. Reports which flag(s) enable unsigned exec");
    println!();
}
