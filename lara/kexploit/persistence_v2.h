//
//  persistence_v2.h
//  DSPloit
//
//  Improved KRW persistence — saves PCB addresses to file for fast recovery.
//  Falls back to full exploit only if validation fails.
//
//  Created by Royan | 2026-05-24
//

#ifndef persistence_v2_h
#define persistence_v2_h

#include <stdint.h>
#include <stdbool.h>

/// Persistence state file path (inside app's Documents)
#define KRW_STATE_FILENAME "krw_state.bin"

/// KRW state structure — saved to disk after successful exploit
typedef struct {
    uint32_t magic;              // 0x4B525753 ("KRWS")
    uint32_t version;            // 1
    uint64_t kernel_base;        // Runtime kernel base
    uint64_t kernel_slide;       // KASLR slide
    uint64_t control_pcb_addr;   // Kernel address of control socket PCB
    uint64_t rw_pcb_addr;        // Kernel address of R/W socket PCB
    uint64_t our_proc;           // Our proc struct address
    uint64_t launchd_proc;       // launchd proc address (for recovery walk)
    uint64_t timestamp;          // When state was saved (mach_absolute_time)
    uint32_t ios_major;          // iOS major version at save time
    uint32_t ios_minor;          // iOS minor version at save time
    uint8_t  checksum[16];       // MD5 of above fields (integrity check)
} krw_state_t;

#define KRW_STATE_MAGIC 0x4B525753

/// Save current KRW state to disk after successful exploit.
/// Call this after ds_run() succeeds and before app goes to background.
bool krw_persist_save_state(void);

/// Attempt fast recovery from saved state.
/// Returns true if KRW primitives are restored and validated.
/// If false, caller should run full exploit.
bool krw_persist_try_recover(void);

/// Validate that saved PCB addresses still point to valid socket structures.
/// Does NOT restore KRW — just checks if recovery would succeed.
bool krw_persist_validate_state(void);

/// Clear saved state (e.g., after reboot detection or failed validation).
void krw_persist_clear_state(void);

/// Check if a saved state file exists.
bool krw_persist_has_state(void);

/// Get age of saved state in seconds (0 if no state).
uint64_t krw_persist_state_age(void);

#endif /* persistence_v2_h */
