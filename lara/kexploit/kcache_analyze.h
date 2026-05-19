#ifndef kcache_analyze_h
#define kcache_analyze_h

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Offline ADRP scan of Documents/kernelcache (same logic as analyze_kernelcache.py).
/// Returns number of __DATA slot offsets stored (0 on failure).
int ds_kcache_analyze_trust_slots(void);

size_t ds_kcache_trust_slot_count(void);
uint64_t ds_kcache_trust_slot_at(size_t index);

/// __DATA - __TEXT from analyzed kernelcache (0 if unknown).
uint64_t ds_kcache_analyze_data_offset(void);

void ds_kcache_trust_slots_clear(void);

#ifdef __cplusplus
}
#endif

#endif /* kcache_analyze_h */
