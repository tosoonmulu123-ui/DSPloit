# timed
**Risk Score: 100/100** | CRIT=1 HIGH=12 MED=9

## Exploit Chains
```
Chain [taint-source→sink] (2 steps, reliability=MED):
  → Taint: [xpc_dictionary_get_string, recvfrom...] → NSKeyedUna
  → Taint: [xpc_dictionary_get_string, recvfrom...] → printf

Chain [uaf→type-confusion] (4 steps, reliability=LOW):
  → Async + free pattern — UAF risk (18 frees, 14 allocs)
```

## Critical Findings
- [Taint→Deserialization] **Taint: [xpc_dictionary_get_string, recvfrom...] → NSKeyedUnarchiver**  
  > NSKeyedUnarchiver tainted data  
  


## Unique Chains
`taint-source→sink`, `uaf→type-confusion`

## New in v5 (6 findings)
- [HIGH] Async + free pattern — UAF risk (18 frees, 14 allocs)
- [MEDIUM] XPC event handler without XPC_TYPE_ERROR check
- [LOW] AntiForensic: sysctl (6x)
- [LOW] AntiForensic: mmap (4x)
- [INFO] Source version: 334.0.2
- [INFO] ARM64: 113 TBZ/TBNZ (bit-test branches)

