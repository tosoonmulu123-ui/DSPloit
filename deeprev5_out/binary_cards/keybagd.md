# keybagd
**Risk Score: 100/100** | CRIT=10 HIGH=18 MED=16

## Exploit Chains
```
Chain [taint-source→sink] (2 steps, reliability=MED):
  → Taint: [xpc_dictionary_get_string, mach_msg...] → system
  → Taint: [xpc_dictionary_get_string, mach_msg...] → memcpy
  → Taint: [xpc_dictionary_get_string, mach_msg...] → fprintf
  ... +1 more

Chain [taint→sql] (2 steps, reliability=HIGH):
  → Taint: [xpc_dictionary_get_string, mach_msg...] → sqlite3_ex
  → sqlite3_exec — raw SQL execution

Chain [xpc→command-injection] (2 steps, reliability=HIGH):
  → XPC input → system()

Chain [taint→iokit] (1 steps, reliability=UNK):
  → Taint: [xpc_dictionary_get_string, mach_msg...] → IOConnectC

Chain [xpc→overflow] (2 steps, reliability=HIGH):
  → XPC input → memcpy

Chain [taint→xpc-reinject] (1 steps, reliability=UNK):
  → Taint: [xpc_dictionary_get_string, mach_msg...] → NSXPCConne

Chain [int-overflow→heap-overflow] (3 steps, reliability=MED):
  → atoi/strtol → malloc pattern

Chain [uaf→type-confusion] (4 steps, reliability=LOW):
  → Async + free pattern — UAF risk (28 frees, 30 allocs)
```

## Critical Findings
- [Command Injection] **Uses system() — 4x**  
  > system()  
  
- [XPC Auth] **XPC service without audit validation**  
  > No xpc_connection_get_audit_token — any caller triggers handler  
  
- [XPC→Injection] **XPC input → system()**  
  > XPC data → system command injection  
  
- [Entitlement] **Has: com.apple.rootless.storage.**  
  > SIP storage exception  
  
- [Entitlement] **Has: com.apple.private.persona-mgmt**  
  > Identity spoofing  
  
- [Entitlement] **Has: com.apple.private.xpc.launchd**  
  > Direct launchd XPC  
  
- [Taint→Command Injection] **Taint: [xpc_dictionary_get_string, mach_msg...] → system**  
  > system() with tainted input  
  
- [Taint→Kernel Attack] **Taint: [xpc_dictionary_get_string, mach_msg...] → IOConnectCallMethod**  
  > IOKit call with tainted input buffer  
  
- [Taint→SQL Injection] **Taint: [xpc_dictionary_get_string, mach_msg...] → sqlite3_exec**  
  > sqlite3_exec with tainted SQL  
  
- [SQL Injection] **sqlite3_exec — raw SQL execution**  
  > sqlite3_exec with concatenated user input = SQL injection. Use parameterized queries: sqlite3_prepare_v2 + sqlite3_bind_  
  


## Unique Chains
`int-overflow→heap-overflow`, `taint-source→sink`, `taint→iokit`, `taint→sql`, `taint→xpc-reinject`, `uaf→type-confusion`, `xpc→command-injection`, `xpc→overflow`

## New in v5 (9 findings)
- [CRITICAL] Taint: [xpc_dictionary_get_string, mach_msg...] → sqlite3_exec
- [CRITICAL] sqlite3_exec — raw SQL execution
- [HIGH] Async + free pattern — UAF risk (28 frees, 30 allocs)
- [MEDIUM] IOServiceOpen → IOConnectCallMethod without visible NULL check
- [LOW] AntiForensic: sysctl (2x)
- [INFO] Source version: 640.60.3
- [INFO] ARM64: 123 TBZ/TBNZ (bit-test branches)
- [INFO] AntiForensic: memset_s (2x)
- [INFO] Crypto operation present — audit for cache/timing side channels

