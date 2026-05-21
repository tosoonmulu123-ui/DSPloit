# launchd
**Risk Score: 100/100** | CRIT=5 HIGH=20 MED=22

## Exploit Chains
```
Chain [taint-source→sink] (2 steps, reliability=MED):
  → Taint: [xpc_dictionary_get_string, xpc_dictionary_get_data..
  → Taint: [xpc_dictionary_get_string, xpc_dictionary_get_data..
  → Taint: [xpc_dictionary_get_string, xpc_dictionary_get_data..
  ... +2 more

Chain [xpc→overflow] (2 steps, reliability=HIGH):
  → XPC input → strcpy
  → XPC input → memcpy

Chain [int-overflow→heap-overflow] (3 steps, reliability=MED):
  → atoi/strtol → malloc pattern
  → strtoul (unsigned) + malloc — unchecked multiplication risk

Chain [pac-strip→rop] (3 steps, reliability=MED):
  → ARM64: 3 PAC strip (XPACI/XPACD)

Chain [uaf→type-confusion] (4 steps, reliability=LOW):
  → Async + free pattern — UAF risk (10 frees, 6 allocs)

Chain [xpc→null-deref] (1 steps, reliability=UNK):
  → xpc_dictionary_get_value → xpc_string_get_string_ptr without
```

## Critical Findings
- [XPC→Overflow] **XPC input → strcpy**  
  > XPC data + strcpy without size validation  
  
- [Entitlement] **Has: com.apple.private.pmap.load-trust-cache**  
  > Kernel TC load  
  
- [Entitlement] **Has: com.apple.private.kernel.**  
  > Kernel private entitlement  
  
- [PAC Bypass] **ARM64: 3 PAC strip (XPACI/XPACD)**  
  > XPACI strips PAC without verify — PAC bypass primitive  
  
- [Taint→Memory Corruption] **Taint: [xpc_dictionary_get_string, xpc_dictionary_get_data...] → strcpy**  
  > strcpy tainted → overflow  
  


## Unique Chains
`int-overflow→heap-overflow`, `pac-strip→rop`, `taint-source→sink`, `uaf→type-confusion`, `xpc→null-deref`, `xpc→overflow`

## New in v5 (9 findings)
- [HIGH] strtoul (unsigned) + malloc — unchecked multiplication risk
- [HIGH] Async + free pattern — UAF risk (10 frees, 6 allocs)
- [HIGH] xpc_dictionary_get_value → xpc_string_get_string_ptr without type/NULL check
- [MEDIUM] AntiForensic: _NSGetEnviron (2x)
- [MEDIUM] AntiForensic: dladdr (2x)
- [LOW] AntiForensic: sysctl (13x)
- [LOW] AntiForensic: isatty (2x)
- [INFO] Source version: 2866.60.21
- [INFO] ARM64: 449 TBZ/TBNZ (bit-test branches)

