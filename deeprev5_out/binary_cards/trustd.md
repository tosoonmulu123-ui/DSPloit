# trustd
**Risk Score: 100/100** | CRIT=2 HIGH=22 MED=20

## Exploit Chains
```
Chain [taint-source→sink] (2 steps, reliability=MED):
  → Taint: [xpc_dictionary_get_string, xpc_dictionary_get_data..
  → Taint: [xpc_dictionary_get_string, xpc_dictionary_get_data..
  → Taint: [xpc_dictionary_get_string, xpc_dictionary_get_data..
  ... +1 more

Chain [taint→sql] (2 steps, reliability=HIGH):
  → Taint: [xpc_dictionary_get_string, xpc_dictionary_get_data..
  → sqlite3_exec — raw SQL execution

Chain [xpc→overflow] (2 steps, reliability=HIGH):
  → XPC input → memcpy

Chain [taint→xpc-reinject] (1 steps, reliability=UNK):
  → Taint: [xpc_dictionary_get_string, xpc_dictionary_get_data..

Chain [int-overflow→heap-overflow] (3 steps, reliability=MED):
  → atoi/strtol → malloc pattern

Chain [uaf→type-confusion] (4 steps, reliability=LOW):
  → Async + free pattern — UAF risk (38 frees, 48 allocs)

Chain [xpc→null-deref] (1 steps, reliability=UNK):
  → xpc_dictionary_get_value → xpc_string_get_string_ptr without
```

## Critical Findings
- [Taint→SQL Injection] **Taint: [xpc_dictionary_get_string, xpc_dictionary_get_data...] → sqlite3_exec**  
  > sqlite3_exec with tainted SQL  
  
- [SQL Injection] **sqlite3_exec — raw SQL execution**  
  > sqlite3_exec with concatenated user input = SQL injection. Use parameterized queries: sqlite3_prepare_v2 + sqlite3_bind_  
  


## Unique Chains
`int-overflow→heap-overflow`, `taint-source→sink`, `taint→sql`, `taint→xpc-reinject`, `uaf→type-confusion`, `xpc→null-deref`, `xpc→overflow`

## New in v5 (12 findings)
- [CRITICAL] Taint: [xpc_dictionary_get_string, xpc_dictionary_get_data...] → sqlite3_exec
- [CRITICAL] sqlite3_exec — raw SQL execution
- [HIGH] Async + free pattern — UAF risk (38 frees, 48 allocs)
- [HIGH] xpc_dictionary_get_value → xpc_string_get_string_ptr without type/NULL check
- [HIGH] Certificate pinning present BUT bypass pattern detected
- [HIGH] Crypto HMAC/SHA + memcmp — timing oracle vulnerability
- [MEDIUM] XPC event handler without XPC_TYPE_ERROR check
- [MEDIUM] Retain/release imbalance: retain=44, release=32 (Δ=12)
- [LOW] AntiForensic: sysctl (4x)
- [LOW] AntiForensic: mmap (2x)

