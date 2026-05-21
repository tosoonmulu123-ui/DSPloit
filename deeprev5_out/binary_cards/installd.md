# installd
**Risk Score: 100/100** | CRIT=2 HIGH=19 MED=15

## Exploit Chains
```
Chain [taint-source→sink] (2 steps, reliability=MED):
  → Taint: [read] → NSKeyedUnarchiver
  → Taint: [read] → syslog
  → Taint: [read] → dlopen

Chain [taint→xpc-reinject] (1 steps, reliability=UNK):
  → Taint: [read] → NSXPCConnection

Chain [int-overflow→heap-overflow] (3 steps, reliability=MED):
  → atoi/strtol → malloc pattern

Chain [uaf→type-confusion] (4 steps, reliability=LOW):
  → Async + free pattern — UAF risk (38 frees, 50 allocs)
```

## Critical Findings
- [Entitlement] **Has: com.apple.private.kernel.**  
  > Kernel private entitlement  
  
- [Taint→Deserialization] **Taint: [read] → NSKeyedUnarchiver**  
  > NSKeyedUnarchiver tainted data  
  


## Unique Chains
`int-overflow→heap-overflow`, `taint-source→sink`, `taint→xpc-reinject`, `uaf→type-confusion`

## New in v5 (5 findings)
- [HIGH] Async + free pattern — UAF risk (38 frees, 50 allocs)
- [MEDIUM] Retain/release imbalance: retain=46, release=32 (Δ=14)
- [LOW] AntiForensic: mmap (2x)
- [INFO] Source version: 1378.60.22
- [INFO] ARM64: 854 TBZ/TBNZ (bit-test branches)

