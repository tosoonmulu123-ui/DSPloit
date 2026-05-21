# mobileassetd
**Risk Score: 100/100** | CRIT=3 HIGH=3 MED=9

## Exploit Chains
```
Chain [taint-source→sink] (2 steps, reliability=MED):
  → Taint: [read] → dlopen
```

## Critical Findings
- [Entitlement] **Has: com.apple.private.pmap.load-trust-cache**  
  > Kernel TC load  
  
- [Entitlement] **Has: com.apple.private.kernel.**  
  > Kernel private entitlement  
  
- [Trust Cache] **TC/CS: amfi_load_trust_cache (1x)**  
  > Inject trust cache  
  


## Unique Chains
`taint-source→sink`

## New in v5 (2 findings)
- [LOW] AntiForensic: sysctl (2x)
- [INFO] Source version: 1329.62.1

