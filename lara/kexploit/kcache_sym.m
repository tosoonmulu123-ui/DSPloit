//
//  kcache_sym.m — fast Mach-O symtab lookup in on-device kernelcache
//

#import <Foundation/Foundation.h>
#include <fcntl.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "kcache_sym.h"
#include "xpf.h"

static NSMutableDictionary<NSString *, NSNumber *> *g_sym_cache;

static NSString *kcache_path(void) {
    NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    return [docs stringByAppendingPathComponent:@"kernelcache"];
}

static uint64_t lookup_symtab_in_macho(const uint8_t *base, size_t size, size_t hdr_off, const char *sym_name) {
    if (hdr_off + sizeof(struct mach_header_64) > size) return 0;

    const struct mach_header_64 *mh = (const struct mach_header_64 *)(base + hdr_off);
    if (mh->magic != MH_MAGIC_64) return 0;

    uint64_t found = 0;
    const uint8_t *cmdp = base + hdr_off + sizeof(struct mach_header_64);
    uint32_t symoff = 0, stroff = 0;
    uint32_t nsyms = 0;

    for (uint32_t i = 0; i < mh->ncmds; i++) {
        if ((size_t)(cmdp - base) + 8 > size) break;
        const struct load_command *lc = (const struct load_command *)cmdp;
        if (lc->cmdsize < 8 || (size_t)(cmdp - base) + lc->cmdsize > size) break;

        if (lc->cmd == LC_SYMTAB) {
            const struct symtab_command *st = (const struct symtab_command *)lc;
            symoff = st->symoff;
            stroff = st->stroff;
            nsyms = st->nsyms;
        } else if (lc->cmd == LC_FILESET_ENTRY) {
            const struct fileset_entry_command *fe = (const struct fileset_entry_command *)lc;
            size_t sub = (size_t)fe->fileoff;
            if (sub < size) {
                uint64_t sub_found = lookup_symtab_in_macho(base, size, sub, sym_name);
                if (sub_found) found = sub_found;
            }
        }
        cmdp += lc->cmdsize;
    }

    if (!found && symoff && stroff && nsyms) {
        // Bounds check: ensure symtab and strtab are within mapped region
        size_t symtab_end = (size_t)symoff + (size_t)nsyms * sizeof(struct nlist_64);
        if (symtab_end > size || stroff >= size) {
            return found; // Corrupt or truncated — bail
        }
        const struct nlist_64 *syms = (const struct nlist_64 *)(base + symoff);
        const char *strtab = (const char *)(base + stroff);
        for (uint32_t i = 0; i < nsyms; i++) {
            uint32_t strx = syms[i].n_un.n_strx;
            if (strx == 0) continue;
            if (stroff + strx >= size) continue;
            const char *n = strtab + strx;
            if (strcmp(n, sym_name) != 0) continue;
            if (syms[i].n_value) {
                found = syms[i].n_value;
                break;
            }
        }
    }

    return found;
}

uint64_t ds_kcache_symbol_unslid(const char *name) {
    if (!name || !name[0]) return 0;

    if (!g_sym_cache) g_sym_cache = [NSMutableDictionary dictionary];

    NSString *key = @(name);
    NSNumber *cached = g_sym_cache[key];
    if (cached) return cached.unsignedLongLongValue;

    NSString *path = kcache_path();
    if (![[NSFileManager defaultManager] fileExistsAtPath:path]) return 0;

    int fd = open(path.fileSystemRepresentation, O_RDONLY);
    if (fd < 0) return 0;

    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size < 4096) {
        close(fd);
        return 0;
    }

    size_t sz = (size_t)st.st_size;
    void *map = mmap(NULL, sz, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (map == MAP_FAILED) return 0;

    uint64_t va = lookup_symtab_in_macho((const uint8_t *)map, sz, 0, name);
    munmap(map, sz);

    if (va) g_sym_cache[key] = @(va);
    return va;
}

uint64_t ds_kcache_symbol_runtime(const char *name) {
    uint64_t unslid = ds_kcache_symbol_unslid(name);
    if (!unslid) return 0;

    uint64_t kbase = gXPF.kernelBase;
    if (!kbase) return 0;

    extern uint64_t ds_get_kernel_base(void);
    uint64_t runtime = ds_get_kernel_base() + (unslid - kbase);
    return runtime;
}

void ds_kcache_symbol_cache_clear(void) {
    [g_sym_cache removeAllObjects];
}
