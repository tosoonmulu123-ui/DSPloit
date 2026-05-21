# amfid
**Risk Score: 100/100** | CRIT=3 HIGH=18 MED=20

## Exploit Chains
```
Chain [taint-source→sink] (2 steps, reliability=MED):
  → Taint: [xpc_dictionary_get_string, mach_msg...] → memcpy
  → Taint: [xpc_dictionary_get_string, mach_msg...] → memmove
  → Taint: [xpc_dictionary_get_string, mach_msg...] → fprintf
  ... +1 more

Chain [int-overflow→heap-overflow] (3 steps, reliability=MED):
  → atoi/strtol → malloc pattern
  → strtoul (unsigned) + malloc — unchecked multiplication risk

Chain [pac-strip→rop] (3 steps, reliability=MED):
  → ARM64: 49 PAC strip (XPACI/XPACD)

Chain [xpc→overflow] (2 steps, reliability=HIGH):
  → XPC input → memcpy

Chain [taint→xpc-reinject] (1 steps, reliability=UNK):
  → Taint: [xpc_dictionary_get_string, mach_msg...] → NSXPCConne

Chain [uaf→type-confusion] (4 steps, reliability=LOW):
  → Async + free pattern — UAF risk (32 frees, 32 allocs)
```

## Critical Findings
- [XPC Auth] **XPC service without audit validation**  
  > No xpc_connection_get_audit_token — any caller triggers handler  
  
- [Entitlement] **Has: com.apple.private.amfi**  
  > AMFI private  
  
- [PAC Bypass] **ARM64: 49 PAC strip (XPACI/XPACD)**  
  > XPACI strips PAC without verify — PAC bypass primitive  
  


## Unique Chains
`int-overflow→heap-overflow`, `pac-strip→rop`, `taint-source→sink`, `taint→xpc-reinject`, `uaf→type-confusion`, `xpc→overflow`

## New in v5 (8 findings)
- [HIGH] strtoul (unsigned) + malloc — unchecked multiplication risk
- [HIGH] Async + free pattern — UAF risk (32 frees, 32 allocs)
- [MEDIUM] XPC event handler without XPC_TYPE_ERROR check
- [MEDIUM] Swift reflection metadata present
- [MEDIUM] Swift Unsafe Pointer usage (2x)
- [LOW] AntiForensic: sysctl (2x)
- [INFO] Source version: 938.60.9
- [INFO] ARM64: 163 TBZ/TBNZ (bit-test branches)

