use goblin::mach::{Mach, MachO};
use memmap2::Mmap;
use std::fs::File;
use std::env;

mod disasm;

fn main() {
    let args: Vec<String> = env::args().collect();
    let path = if args.len() > 1 {
        &args[1]
    } else {
        "../../kernelcache"
    };

    println!("=== DSPloit Kernelcache Analyzer ===");
    println!("File: {}", path);
    println!();

    let file = File::open(path).expect("Cannot open kernelcache file");
    let mmap = unsafe { Mmap::map(&file).expect("Cannot mmap file") };
    let data = &mmap[..];

    println!("[*] File size: {} bytes ({:.1} MB)", data.len(), data.len() as f64 / 1048576.0);

    // Check if it's a Mach-O or needs decompression
    let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    println!("[*] Magic: 0x{:08x}", magic);

    match magic {
        0xfeedface | 0xfeedfacf => {
            println!("[*] Raw Mach-O detected");
            analyze_macho(data);
            disasm::analyze_pmap_cs(data);
        }
        0xcafebabe | 0xbebafeca => {
            println!("[*] Fat binary detected");
            analyze_macho(data);
        }
        _ => {
            // Might be IMG4 wrapped or compressed
            // Try to find Mach-O header inside
            println!("[*] Not raw Mach-O, searching for embedded Mach-O...");
            if let Some(offset) = find_macho_header(data) {
                println!("[*] Found Mach-O at offset 0x{:x}", offset);
                analyze_macho(&data[offset..]);
            } else {
                println!("[!] No Mach-O found. File may be compressed (LZFSE/LZSS).");
                println!("[*] Searching for strings anyway...");
                search_strings(data);
            }
        }
    }
}

fn find_macho_header(data: &[u8]) -> Option<usize> {
    // Search for MH_MAGIC_64 (0xfeedfacf) in the file
    let needle = [0xcf, 0xfa, 0xed, 0xfe];
    for i in 0..data.len().saturating_sub(4) {
        if &data[i..i+4] == &needle {
            // Verify it looks like a kernel (cputype ARM64)
            if i + 8 <= data.len() {
                let cputype = u32::from_le_bytes([data[i+4], data[i+5], data[i+6], data[i+7]]);
                if cputype == 0x0100000c { // CPU_TYPE_ARM64
                    return Some(i);
                }
            }
        }
    }
    None
}

fn analyze_macho(data: &[u8]) {
    match Mach::parse(data) {
        Ok(Mach::Binary(macho)) => {
            analyze_single_macho(&macho, data);
        }
        Ok(Mach::Fat(fat)) => {
            println!("[*] Fat binary with {} architectures", fat.narches);
            // Try first arch
            if let Ok(macho) = MachO::parse(data, 0) {
                analyze_single_macho(&macho, data);
            }
        }
        Err(e) => {
            println!("[!] Mach-O parse error: {}", e);
            println!("[*] Falling back to string search...");
            search_strings(data);
        }
    }
}

fn analyze_single_macho(macho: &MachO, data: &[u8]) {
    println!("\n=== SEGMENTS ===");
    for seg in &macho.segments {
        let name = seg.name().unwrap_or("???");
        println!("  {} vmaddr=0x{:016x} vmsize=0x{:x} fileoff=0x{:x} filesz=0x{:x}",
            name, seg.vmaddr, seg.vmsize, seg.fileoff, seg.filesize);
        
        // Mark writable segments
        let prot = seg.initprot;
        let writable = (prot & 0x2) != 0; // VM_PROT_WRITE
        if writable {
            println!("    ^^^ WRITABLE (initprot=0x{:x}) ^^^", prot);
        }
    }

    // Search for trust cache related symbols
    println!("\n=== TRUST CACHE SYMBOLS ===");
    let tc_keywords = [
        "trust_cache", "trustcache", "loaded_trust", "pmap_cs",
        "amfi", "AMFI", "cs_enforcement", "cs_invalid",
        "CoreTrust", "coretrust",
    ];

    if let Some(ref symtab) = macho.symbols {
        for sym in symtab.iter() {
            if let Ok((name, _nlist)) = sym {
                let lower = name.to_lowercase();
                for kw in &tc_keywords {
                    if lower.contains(&kw.to_lowercase()) {
                        println!("  SYMBOL: {}", name);
                        break;
                    }
                }
            }
        }
    } else {
        println!("  (no symbol table — stripped kernel)");
    }

    // Search for relevant strings in __DATA and __TEXT
    println!("\n=== RELEVANT STRINGS (trust cache / AMFI / code signing) ===");
    search_strings(data);

    // Find __DATA segment writable variables
    println!("\n=== WRITABLE __DATA ANALYSIS ===");
    for seg in &macho.segments {
        let name = seg.name().unwrap_or("???");
        if name == "__DATA" || name == "__DATA_DIRTY" {
            let start = seg.fileoff as usize;
            let end = start + seg.filesize as usize;
            if end <= data.len() {
                let seg_data = &data[start..end];
                // Count non-zero qwords (initialized data)
                let mut nonzero = 0u64;
                for chunk in seg_data.chunks(8) {
                    if chunk.len() == 8 {
                        let val = u64::from_le_bytes(chunk.try_into().unwrap());
                        if val != 0 { nonzero += 1; }
                    }
                }
                println!("  {} @ vmaddr 0x{:x}: {} non-zero qwords ({} bytes writable)",
                    name, seg.vmaddr, nonzero, seg.filesize);
            }
        }
    }
}

fn search_strings(data: &[u8]) {
    let keywords = [
        "trust_cache", "trust cache", "loaded_trust_caches",
        "amfi", "AMFI", "AppleMobileFileIntegrity",
        "cs_enforcement", "cs_invalid_allowed",
        "can-load-trust-cache", "can-execute-cdhash",
        "can-check-trust-cache", "set-trust",
        "CoreTrust", "coretrust",
        "pmap_cs", "code_signing",
        "MISValidateSignature", "verify_code_directory",
        "posix_spawn", "EPERM",
        "trust cache module", "trust cache segment",
        "Personalized trust cache",
        "failed to load static trust cache",
    ];

    let mut found: Vec<(usize, String)> = Vec::new();

    // Extract ASCII strings >= 10 chars and check against keywords
    let mut current = Vec::new();
    let mut start_offset = 0;

    for (i, &byte) in data.iter().enumerate() {
        if byte >= 0x20 && byte < 0x7f {
            if current.is_empty() { start_offset = i; }
            current.push(byte);
        } else {
            if current.len() >= 10 {
                let s = String::from_utf8_lossy(&current).to_string();
                let lower = s.to_lowercase();
                for kw in &keywords {
                    if lower.contains(&kw.to_lowercase()) {
                        found.push((start_offset, s.clone()));
                        break;
                    }
                }
            }
            current.clear();
        }
    }

    // Deduplicate and print
    found.sort_by_key(|(off, _)| *off);
    found.dedup_by(|a, b| a.1 == b.1);
    
    let max_show = 50;
    for (i, (offset, s)) in found.iter().enumerate() {
        if i >= max_show {
            println!("  ... and {} more", found.len() - max_show);
            break;
        }
        let truncated = if s.len() > 100 { &s[..100] } else { s.as_str() };
        println!("  [0x{:08x}] {}", offset, truncated);
    }
    
    if found.is_empty() {
        println!("  (no relevant strings found — file may be compressed)");
    }

    println!("\n  Total relevant strings: {}", found.len());
}
