# misagent
**Risk Score: 100/100** | CRIT=1 HIGH=2 MED=7

## Exploit Chains
```
Chain [uaf→type-confusion] (4 steps, reliability=LOW):
  → Async + free pattern — UAF risk (32 frees, 36 allocs)
```

## Critical Findings
- [XPC Auth] **XPC service without audit validation**  
  > No xpc_connection_get_audit_token — any caller triggers handler  
  


## Unique Chains
`uaf→type-confusion`

## New in v5 (4 findings)
- [HIGH] Async + free pattern — UAF risk (32 frees, 36 allocs)
- [MEDIUM] XPC event handler without XPC_TYPE_ERROR check
- [INFO] Source version: 436.40.5
- [INFO] ARM64: 72 TBZ/TBNZ (bit-test branches)

