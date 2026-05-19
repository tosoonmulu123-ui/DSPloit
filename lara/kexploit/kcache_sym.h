#ifndef kcache_sym_h
#define kcache_sym_h

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Unslid VA from Documents/kernelcache symtab (0 if missing).
uint64_t ds_kcache_symbol_unslid(const char *name);

/// Slid runtime VA using current kernel base + XPF kernbase.
uint64_t ds_kcache_symbol_runtime(const char *name);

void ds_kcache_symbol_cache_clear(void);

#ifdef __cplusplus
}
#endif

#endif /* kcache_sym_h */
