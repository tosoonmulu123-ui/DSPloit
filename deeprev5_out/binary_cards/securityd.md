# securityd
**Risk Score: 100/100** | CRIT=8 HIGH=35 MED=25

## Exploit Chains
```
Chain [taint-source→sink] (2 steps, reliability=MED):
  → Taint: [xpc_dictionary_get_string, xpc_dictionary_get_data..
  → Taint: [xpc_dictionary_get_string, xpc_dictionary_get_data..
  → Taint: [xpc_dictionary_get_string, xpc_dictionary_get_data..
  ... +5 more

Chain [taint→sql] (2 steps, reliability=HIGH):
  → Taint: [xpc_dictionary_get_string, xpc_dictionary_get_data..
  → sqlite3_exec — raw SQL execution

Chain [xpc→command-injection] (2 steps, reliability=HIGH):
  → XPC input → system()

Chain [taint→iokit] (1 steps, reliability=UNK):
  → Taint: [xpc_dictionary_get_string, xpc_dictionary_get_data..

Chain [xpc→overflow] (2 steps, reliability=HIGH):
  → XPC input → memcpy

Chain [taint→keychain] (1 steps, reliability=UNK):
  → Taint: [xpc_dictionary_get_string, xpc_dictionary_get_data..

Chain [taint→predicate] (2 steps, reliability=HIGH):
  → Taint: [xpc_dictionary_get_string, xpc_dictionary_get_data..

Chain [taint→xpc-reinject] (1 steps, reliability=UNK):
  → Taint: [xpc_dictionary_get_string, xpc_dictionary_get_data..

Chain [iokit→kernel-heap-spray] (4 steps, reliability=MED):
  → Multiple IOKit methods (2) — kernel heap grooming

Chain [uaf→type-confusion] (4 steps, reliability=LOW):
  → Async + free pattern — UAF risk (42 frees, 60 allocs)
```

## Critical Findings
- [Command Injection] **Uses system() — 1x**  
  > system()  
  
- [XPC→Injection] **XPC input → system()**  
  > XPC data → system command injection  
  
- [Taint→Command Injection] **Taint: [xpc_dictionary_get_string, xpc_dictionary_get_data...] → system**  
  > system() with tainted input  
  
- [Taint→Deserialization] **Taint: [xpc_dictionary_get_string, xpc_dictionary_get_data...] → NSKeyedUnarchiver**  
  > NSKeyedUnarchiver tainted data  
  
- [Taint→Kernel Attack] **Taint: [xpc_dictionary_get_string, xpc_dictionary_get_data...] → IOConnectCallMethod**  
  > IOKit call with tainted input buffer  
  
- [Taint→SQL Injection] **Taint: [xpc_dictionary_get_string, xpc_dictionary_get_data...] → sqlite3_exec**  
  > sqlite3_exec with tainted SQL  
  
- [Format String] **Format %n — write primitive**  
  > %n writes integer to memory — if format controlled → arbitrary write  
  
- [SQL Injection] **sqlite3_exec — raw SQL execution**  
  > sqlite3_exec with concatenated user input = SQL injection. Use parameterized queries: sqlite3_prepare_v2 + sqlite3_bind_  
  


## Unique Chains
`iokit→kernel-heap-spray`, `taint-source→sink`, `taint→iokit`, `taint→keychain`, `taint→predicate`, `taint→sql`, `taint→xpc-reinject`, `uaf→type-confusion`, `xpc→command-injection`, `xpc→overflow`

## New in v5 (14 findings)
- [CRITICAL] Taint: [xpc_dictionary_get_string, xpc_dictionary_get_data...] → sqlite3_exec
- [CRITICAL] sqlite3_exec — raw SQL execution
- [HIGH] Taint: [xpc_dictionary_get_string, xpc_dictionary_get_data...] → NSPredicate
- [HIGH] Async + free pattern — UAF risk (42 frees, 60 allocs)
- [MEDIUM] XPC event handler without XPC_TYPE_ERROR check
- [MEDIUM] Retain/release imbalance: retain=52, release=36 (Δ=16)
- [MEDIUM] IOServiceOpen → IOConnectCallMethod without visible NULL check
- [LOW] AntiForensic: sysctl (2x)
- [LOW] AntiForensic: mmap (2x)
- [INFO] Source version: 61439.62.1

