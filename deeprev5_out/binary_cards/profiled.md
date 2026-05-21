# profiled
**Risk Score: 100/100** | CRIT=6 HIGH=28 MED=16

## Exploit Chains
```
Chain [taint-source→sink] (2 steps, reliability=MED):
  → Taint: [xpc_dictionary_get_string, read...] → memcpy
  → Taint: [xpc_dictionary_get_string, read...] → printf
  → Taint: [xpc_dictionary_get_string, read...] → fprintf
  ... +2 more

Chain [taint→iokit] (1 steps, reliability=UNK):
  → Taint: [xpc_dictionary_get_string, read...] → IOConnectCallM

Chain [xpc→overflow] (2 steps, reliability=HIGH):
  → XPC input → memcpy

Chain [taint→predicate] (2 steps, reliability=HIGH):
  → Taint: [xpc_dictionary_get_string, read...] → NSPredicate

Chain [taint→xpc-reinject] (1 steps, reliability=UNK):
  → Taint: [xpc_dictionary_get_string, read...] → NSXPCConnectio

Chain [iokit→kernel-heap-spray] (4 steps, reliability=MED):
  → Multiple IOKit methods (2) — kernel heap grooming

Chain [uaf→type-confusion] (4 steps, reliability=LOW):
  → Async + free pattern — UAF risk (36 frees, 52 allocs)
```

## Critical Findings
- [XPC Auth] **XPC service without audit validation**  
  > No xpc_connection_get_audit_token — any caller triggers handler  
  
- [Entitlement] **Has: com.apple.rootless.storage.**  
  > SIP storage exception  
  
- [Entitlement] **Has: com.apple.private.amfi**  
  > AMFI private  
  
- [Entitlement] **Has: com.apple.private.tcc.**  
  > TCC bypass  
  
- [Entitlement] **Has: com.apple.private.coreservices**  
  > CoreServices private  
  
- [Taint→Kernel Attack] **Taint: [xpc_dictionary_get_string, read...] → IOConnectCallMethod**  
  > IOKit call with tainted input buffer  
  


## Unique Chains
`iokit→kernel-heap-spray`, `taint-source→sink`, `taint→iokit`, `taint→predicate`, `taint→xpc-reinject`, `uaf→type-confusion`, `xpc→overflow`

## New in v5 (8 findings)
- [HIGH] Taint: [xpc_dictionary_get_string, read...] → NSPredicate
- [HIGH] Async + free pattern — UAF risk (36 frees, 52 allocs)
- [HIGH] Certificate pinning present BUT bypass pattern detected
- [MEDIUM] Retain/release imbalance: retain=48, release=34 (Δ=14)
- [MEDIUM] IOServiceOpen → IOConnectCallMethod without visible NULL check
- [INFO] Source version: 2381.2.7
- [INFO] ARM64: 1342 TBZ/TBNZ (bit-test branches)
- [INFO] AntiForensic: memset_s (2x)

