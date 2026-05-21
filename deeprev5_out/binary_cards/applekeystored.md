# applekeystored
**Risk Score: 100/100** | CRIT=5 HIGH=12 MED=16

## Exploit Chains
```
Chain [taint-source→sink] (2 steps, reliability=MED):
  → Taint: [mach_msg, recv...] → system
  → Taint: [mach_msg, recv...] → memcpy
  → Taint: [mach_msg, recv...] → memmove

Chain [pac-strip→rop] (3 steps, reliability=MED):
  → ARM64: 200 PAC strip (XPACI/XPACD)

Chain [iokit→kernel-heap-spray] (4 steps, reliability=MED):
  → Multiple IOKit methods (2) — kernel heap grooming
```

## Critical Findings
- [Command Injection] **Uses system() — 1x**  
  > system()  
  
- [PAC Bypass] **ARM64: 200 PAC strip (XPACI/XPACD)**  
  > XPACI strips PAC without verify — PAC bypass primitive  
  
- [Taint→Command Injection] **Taint: [mach_msg, recv...] → system**  
  > system() with tainted input  
  
- [Format String] **Format %n — write primitive**  
  > %n writes integer to memory — if format controlled → arbitrary write  
  
- [DMA] **DMA: IOConnectMapMemory64 (3x)**  
  > Map kernel region at 64-bit address  
  


## Unique Chains
`iokit→kernel-heap-spray`, `pac-strip→rop`, `taint-source→sink`

## New in v5 (6 findings)
- [CRITICAL] DMA: IOConnectMapMemory64 (3x)
- [MEDIUM] No certificate pinning detected in network binary
- [MEDIUM] Swift reflection metadata present
- [MEDIUM] Swift Unsafe Pointer usage (2x)
- [INFO] Source version: 1827.60.44
- [INFO] ARM64: 537 TBZ/TBNZ (bit-test branches)

