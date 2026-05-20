//
//  TrustCacheInjector.h
//  DSPloit
//
//  Exp 79: Trust Cache Write Test → Inject
//  Langkah kritis setelah Exp 77 probe sukses.
//
//  Tahap:
//    1. Write test (harmless dummy value ke slot kosong)
//    2. CDHash inject (jika write test sukses)
//    3. Verify via posix_spawn unsigned binary
//
#ifndef TrustCacheInjector_h
#define TrustCacheInjector_h

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Result codes untuk setiap tahap
typedef enum {
    TCInject_OK          = 0,
    TCInject_NotReady    = 1,   // KRW belum siap
    TCInject_NoAddr      = 2,   // trust cache addr belum diset
    TCInject_WriteFail   = 3,   // write test: verify != expected (KTRR?)
    TCInject_PPLPanic    = 4,   // kemungkinan PPL — jangan lanjut
    TCInject_CountFull   = 5,   // trust cache sudah penuh
    TCInject_InjectOK    = 6,   // inject berhasil, belum diverifikasi
    TCInject_VerifyOK    = 7,   // spawn berhasil → AMFI bypass confirmed
    TCInject_VerifyFail  = 8,   // spawn di-kill → inject tidak efektif
} TCInjectResult;

/// Set alamat trust cache struct yang ditemukan oleh Exp 77.
/// Harus dipanggil sebelum fungsi lain.
void tc_injector_set_addr(uint64_t tcStructAddr, uint32_t currentCount, uint32_t stride);

/// Tahap 1: Write test harmless.
/// Tulis 0xDEADBEEFCAFEBABE ke slot kosong, verify, lalu restore.
/// Return TCInject_OK jika write berhasil — aman lanjut ke inject.
TCInjectResult tc_injector_write_test(void);

/// Tahap 2: Inject CDHash ke trust cache.
/// cdhash harus 20 bytes (SHA256 truncated).
/// flags: 0 = normal, 4 = platform binary.
TCInjectResult tc_injector_inject_cdhash(const uint8_t *cdhash, uint8_t flags);

/// Tahap 3: Verify dengan spawn binary di path.
/// Binary harus unsigned / tidak ada di trust cache sebelumnya.
/// Gunakan RemoteCall dari launchd untuk bypass sandbox.
TCInjectResult tc_injector_verify_spawn(const char *binaryPath);

/// Restore: hapus entry yang diinject (set bytes ke 0).
void tc_injector_restore(void);

/// Get last log string untuk ditampilkan di UI.
const char *tc_injector_last_log(void);

#ifdef __cplusplus
}
#endif

#endif /* TrustCacheInjector_h */
