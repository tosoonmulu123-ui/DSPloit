# cryptexd
**Risk Score: 100/100** | CRIT=4 HIGH=18 MED=21

## Exploit Chains
```
Chain [int-overflow→heap-overflow] (3 steps, reliability=MED):
  → atoi/strtol → malloc pattern
  → strtoul (unsigned) + malloc — unchecked multiplication risk

Chain [taint→iokit] (1 steps, reliability=UNK):
  → Taint: [xpc_dictionary_get_string, xpc_dictionary_get_value.

Chain [xpc→overflow] (2 steps, reliability=HIGH):
  → XPC input → memcpy

Chain [taint-source→sink] (2 steps, reliability=MED):
  → Taint: [xpc_dictionary_get_string, xpc_dictionary_get_value.

Chain [iokit→kernel-heap-spray] (4 steps, reliability=MED):
  → Multiple IOKit methods (2) — kernel heap grooming

Chain [uaf→type-confusion] (4 steps, reliability=LOW):
  → Async + free pattern — UAF risk (34 frees, 48 allocs)

Chain [xpc→null-deref] (1 steps, reliability=UNK):
  → xpc_dictionary_get_value → xpc_string_get_string_ptr without
```

## Critical Findings
- [Entitlement] **Has: com.apple.private.amfi.can-load-trust-cache**  
  > Trust cache injection  
  
- [Entitlement] **Has: com.apple.private.pmap.load-trust-cache**  
  > Kernel TC load  
  
- [Trust Cache] **TC/CS: amfi_load_trust_cache (1x)**  
  > Inject trust cache  
  
- [Taint→Kernel Attack] **Taint: [xpc_dictionary_get_string, xpc_dictionary_get_value...] → IOConnectCallMethod**  
  > IOKit call with tainted input buffer  
  


## Unique Chains
`int-overflow→heap-overflow`, `iokit→kernel-heap-spray`, `taint-source→sink`, `taint→iokit`, `uaf→type-confusion`, `xpc→null-deref`, `xpc→overflow`

## New in v5 (11 findings)
- [HIGH] strtoul (unsigned) + malloc — unchecked multiplication risk
- [HIGH] Async + free pattern — UAF risk (34 frees, 48 allocs)
- [HIGH] xpc_dictionary_get_value → xpc_string_get_string_ptr without type/NULL check
- [MEDIUM] XPC event handler without XPC_TYPE_ERROR check
- [MEDIUM] Retain/release imbalance: retain=44, release=32 (Δ=12)
- [MEDIUM] IOServiceOpen → IOConnectCallMethod without visible NULL check
- [MEDIUM] AntiForensic: _NSGetEnviron (2x)
- [LOW] AntiForensic: sysctl (4x)
- [LOW] AntiForensic: mmap (3x)
- [INFO] Source version: 475.60.5

