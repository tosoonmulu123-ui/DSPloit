# dyld
**Risk Score: 100/100** | CRIT=9 HIGH=14 MED=13

## Exploit Chains
```
Chain [taint-source→sink] (2 steps, reliability=MED):
  → Taint: [mach_msg, read] → strcpy
  → Taint: [mach_msg, read] → strcat
  → Taint: [mach_msg, read] → sprintf
  ... +5 more
```

## Critical Findings
- [Mach IPC] **Mach: task_for_pid (1x)**  
  > Full process control  
  
- [Trust Cache] **TC/CS: amfi_load_trust_cache (1x)**  
  > Inject trust cache  
  
- [Injection] **Inject: task_for_pid (1x)**  
  > task_for_pid  
  
- [Taint→Memory Corruption] **Taint: [mach_msg, read] → strcpy**  
  > strcpy tainted → overflow  
  
- [Taint→Memory Corruption] **Taint: [mach_msg, read] → strcat**  
  > strcat tainted → overflow  
  
- [Taint→Format/Overflow] **Taint: [mach_msg, read] → sprintf**  
  > sprintf tainted → overflow  
  
- [Taint→Format/Overflow] **Taint: [mach_msg, read] → vsprintf**  
  > vsprintf tainted → overflow  
  
- [Taint→Command Injection] **Taint: [mach_msg, read] → execve**  
  > execve() with tainted args  
  
- [Format String] **Format %n — write primitive**  
  > %n writes integer to memory — if format controlled → arbitrary write  
  


## Unique Chains
`taint-source→sink`

## New in v5 (5 findings)
- [MEDIUM] AntiForensic: dladdr (3x)
- [LOW] AntiForensic: sysctl (2x)
- [LOW] AntiForensic: mmap (12x)
- [INFO] Source version: 1241.17.0
- [INFO] AntiForensic: memset_s (1x)

