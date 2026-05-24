//
//  offsets_xpf.h
//  DSPloit
//
//  Dynamic offset resolution via XPF — resolves ALL kernel struct offsets
//  from the kernelcache binary instead of hardcoding per iOS version.
//
//  Strategy:
//  1. Try XPF dynamic resolution (works on ANY iOS build)
//  2. Fallback to hardcoded table (offsets_init) if XPF fails
//
//  This makes DSPloit work on new iOS builds without code changes.
//
//  Created by Royan | 2026-05-24
//

#ifndef offsets_xpf_h
#define offsets_xpf_h

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Attempt to resolve ALL offsets dynamically from kernelcache via XPF.
/// Returns true if all critical offsets were resolved.
/// If false, caller should fall back to offsets_init() hardcoded table.
///
/// Must be called AFTER kernelcache is available in Documents/kernelcache.
/// Typically called after dlkcache() or fetchkcache() succeeds.
bool offsets_resolve_dynamic(void);

/// Check if dynamic offsets are currently active (vs hardcoded).
bool offsets_are_dynamic(void);

/// Get count of offsets resolved dynamically (for diagnostics).
int offsets_dynamic_count(void);

/// Get count of offsets that failed dynamic resolution.
int offsets_failed_count(void);

/// Print all resolved offsets to log (for debugging).
void offsets_dump_all(void);

/// Resolve a single named offset from XPF dictionary.
/// Returns OFFSET_INVALID if not found.
uint32_t offsets_xpf_resolve32(const char *xpf_name);
uint64_t offsets_xpf_resolve64(const char *xpf_name);

#ifdef __cplusplus
}
#endif

#endif /* offsets_xpf_h */
