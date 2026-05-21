# adid
**Risk Score: 100/100** | CRIT=1 HIGH=8 MED=15

## Exploit Chains
```
Chain [int-overflow→heap-overflow] (3 steps, reliability=MED):
  → atoi/strtol → malloc pattern
  → strtoul (unsigned) + malloc — unchecked multiplication risk

Chain [uaf→type-confusion] (4 steps, reliability=LOW):
  → Async + free pattern — UAF risk (6 frees, 2 allocs)

Chain [double-free→heap-corruption] (4 steps, reliability=LOW):
  → Free count (6) >> alloc count (2) — potential double-free
```

## Critical Findings
- [Format String] **Format %n — write primitive**  
  > %n writes integer to memory — if format controlled → arbitrary write  
  


## Unique Chains
`double-free→heap-corruption`, `int-overflow→heap-overflow`, `uaf→type-confusion`

## New in v5 (7 findings)
- [HIGH] strtoul (unsigned) + malloc — unchecked multiplication risk
- [HIGH] Async + free pattern — UAF risk (6 frees, 2 allocs)
- [HIGH] Free count (6) >> alloc count (2) — potential double-free
- [MEDIUM] XPC event handler without XPC_TYPE_ERROR check
- [LOW] AntiForensic: sysctl (2x)
- [LOW] AntiForensic: mmap (2x)
- [INFO] Source version: 19.3.2

