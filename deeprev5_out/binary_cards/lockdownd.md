# lockdownd
**Risk Score: 100/100** | CRIT=8 HIGH=33 MED=27

## Exploit Chains
```
Chain [taint-source→sink] (2 steps, reliability=MED):
  → Taint: [xpc_dictionary_get_string, mach_msg...] → strcpy
  → Taint: [xpc_dictionary_get_string, mach_msg...] → memcpy
  → Taint: [xpc_dictionary_get_string, mach_msg...] → memmove
  ... +4 more

Chain [xpc→overflow] (2 steps, reliability=HIGH):
  → XPC input → strcpy
  → XPC input → memcpy

Chain [taint→iokit] (1 steps, reliability=UNK):
  → Taint: [xpc_dictionary_get_string, mach_msg...] → IOConnectC

Chain [taint→keychain] (1 steps, reliability=UNK):
  → Taint: [xpc_dictionary_get_string, mach_msg...] → SecItemAdd

Chain [taint→xpc-reinject] (1 steps, reliability=UNK):
  → Taint: [xpc_dictionary_get_string, mach_msg...] → NSXPCConne

Chain [int-overflow→heap-overflow] (3 steps, reliability=MED):
  → atoi/strtol → malloc pattern

Chain [iokit→kernel-heap-spray] (4 steps, reliability=MED):
  → Multiple IOKit methods (2) — kernel heap grooming

Chain [uaf→type-confusion] (4 steps, reliability=LOW):
  → Async + free pattern — UAF risk (38 frees, 57 allocs)
```

## Critical Findings
- [XPC Auth] **XPC service without audit validation**  
  > No xpc_connection_get_audit_token — any caller triggers handler  
  
- [XPC→Overflow] **XPC input → strcpy**  
  > XPC data + strcpy without size validation  
  
- [Entitlement] **Has: com.apple.rootless.storage.**  
  > SIP storage exception  
  
- [Entitlement] **Has: com.apple.private.xpc.launchd**  
  > Direct launchd XPC  
  
- [Entitlement] **Has: com.apple.private.tcc.**  
  > TCC bypass  
  
- [Taint→Memory Corruption] **Taint: [xpc_dictionary_get_string, mach_msg...] → strcpy**  
  > strcpy tainted → overflow  
  
- [Taint→Kernel Attack] **Taint: [xpc_dictionary_get_string, mach_msg...] → IOConnectCallMethod**  
  > IOKit call with tainted input buffer  
  
- [Format String] **Format %n — write primitive**  
  > %n writes integer to memory — if format controlled → arbitrary write  
  


## Unique Chains
`int-overflow→heap-overflow`, `iokit→kernel-heap-spray`, `taint-source→sink`, `taint→iokit`, `taint→keychain`, `taint→xpc-reinject`, `uaf→type-confusion`, `xpc→overflow`

## New in v5 (10 findings)
- [HIGH] Async + free pattern — UAF risk (38 frees, 57 allocs)
- [HIGH] Crypto HMAC/SHA + memcmp — timing oracle vulnerability
- [MEDIUM] XPC event handler without XPC_TYPE_ERROR check
- [MEDIUM] Retain/release imbalance: retain=47, release=33 (Δ=14)
- [MEDIUM] AntiForensic: getppid (2x)
- [LOW] AntiForensic: sysctl (7x)
- [LOW] AntiForensic: mmap (5x)
- [INFO] Source version: 1319.60.1
- [INFO] ARM64: 424 TBZ/TBNZ (bit-test branches)
- [INFO] AntiForensic: memset_s (2x)

