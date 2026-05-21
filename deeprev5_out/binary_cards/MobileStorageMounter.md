# MobileStorageMounter
**Risk Score: 100/100** | CRIT=8 HIGH=10 MED=20

## Exploit Chains
```
Chain [taint→iokit] (1 steps, reliability=UNK):
  → Taint: [xpc_dictionary_get_string, xpc_dictionary_get_data..

Chain [xpc→overflow] (2 steps, reliability=HIGH):
  → XPC input → memcpy

Chain [taint-source→sink] (2 steps, reliability=MED):
  → Taint: [xpc_dictionary_get_string, xpc_dictionary_get_data..

Chain [int-overflow→heap-overflow] (3 steps, reliability=MED):
  → atoi/strtol → malloc pattern

Chain [uaf→type-confusion] (4 steps, reliability=LOW):
  → Async + free pattern — UAF risk (36 frees, 40 allocs)
```

## Critical Findings
- [XPC Auth] **XPC service without audit validation**  
  > No xpc_connection_get_audit_token — any caller triggers handler  
  
- [Entitlement] **Has: com.apple.private.amfi.can-load-trust-cache**  
  > Trust cache injection  
  
- [Entitlement] **Has: com.apple.private.pmap.load-trust-cache**  
  > Kernel TC load  
  
- [Entitlement] **Has: com.apple.rootless.storage.**  
  > SIP storage exception  
  
- [Entitlement] **Has: com.apple.private.xpc.launchd**  
  > Direct launchd XPC  
  
- [Entitlement] **Has: com.apple.private.amfi**  
  > AMFI private  
  
- [Taint→Kernel Attack] **Taint: [xpc_dictionary_get_string, xpc_dictionary_get_data...] → IOConnectCallMethod**  
  > IOKit call with tainted input buffer  
  
- [Format String] **Format %n — write primitive**  
  > %n writes integer to memory — if format controlled → arbitrary write  
  


## Unique Chains
`int-overflow→heap-overflow`, `taint-source→sink`, `taint→iokit`, `uaf→type-confusion`, `xpc→overflow`

## New in v5 (7 findings)
- [HIGH] Async + free pattern — UAF risk (36 frees, 40 allocs)
- [MEDIUM] XPC event handler without XPC_TYPE_ERROR check
- [MEDIUM] IOServiceOpen → IOConnectCallMethod without visible NULL check
- [LOW] AntiForensic: sysctl (8x)
- [LOW] AntiForensic: mmap (3x)
- [INFO] Source version: 331.0.0
- [INFO] ARM64: 195 TBZ/TBNZ (bit-test branches)

