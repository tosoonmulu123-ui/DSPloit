/*
 * extractor — Minimal plain tar extractor for iOS
 * 
 * Usage: extractor <input.tar> <output_dir>
 * 
 * Reads an UNCOMPRESSED tar archive and extracts all files to output_dir.
 * No dependencies (no zlib needed — gzip decompression done by caller).
 * Statically linked Mach-O arm64 binary.
 *
 * Compile with zig:
 *   zig cc -target aarch64-macos -O2 -o extractor extractor.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>

#define TAR_BLOCK 512
#define BUF_SIZE 65536

static void mkdirp(const char *path, mode_t mode) {
    char tmp[1024];
    snprintf(tmp, sizeof(tmp), "%s", path);
    size_t len = strlen(tmp);
    if (len > 0 && tmp[len - 1] == '/') tmp[len - 1] = 0;
    
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = 0;
            mkdir(tmp, mode);
            *p = '/';
        }
    }
    mkdir(tmp, mode);
}

static void ensure_parent(const char *filepath) {
    char tmp[1024];
    snprintf(tmp, sizeof(tmp), "%s", filepath);
    char *s = strrchr(tmp, '/');
    if (s) { *s = 0; mkdirp(tmp, 0755); }
}

static unsigned long octal(const char *s, int n) {
    unsigned long v = 0;
    for (int i = 0; i < n && s[i] >= '0' && s[i] <= '7'; i++)
        v = (v << 3) | (s[i] - '0');
    return v;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        write(2, "Usage: extractor <tar> <dir>\n", 28);
        return 1;
    }
    
    int fd_in = open(argv[1], O_RDONLY);
    if (fd_in < 0) return 2;
    
    mkdirp(argv[2], 0755);
    
    unsigned char hdr[TAR_BLOCK];
    int files = 0, dirs = 0;
    
    while (read(fd_in, hdr, TAR_BLOCK) == TAR_BLOCK) {
        /* End of archive */
        int zero = 1;
        for (int i = 0; i < TAR_BLOCK; i++) if (hdr[i]) { zero = 0; break; }
        if (zero) break;
        
        char name[101] = {0};
        memcpy(name, hdr, 100);
        unsigned long mode = octal((char*)hdr + 100, 8);
        unsigned long size = octal((char*)hdr + 124, 12);
        char type = hdr[156];
        char prefix[156] = {0};
        memcpy(prefix, hdr + 345, 155);
        
        /* Skip pax headers */
        if (type == 'x' || type == 'g') {
            unsigned long blocks = (size + TAR_BLOCK - 1) / TAR_BLOCK;
            for (unsigned long i = 0; i < blocks; i++) read(fd_in, hdr, TAR_BLOCK);
            continue;
        }
        
        /* Build path */
        char path[2048];
        if (prefix[0])
            snprintf(path, sizeof(path), "%s/%s/%s", argv[2], prefix, name);
        else
            snprintf(path, sizeof(path), "%s/%s", argv[2], name);
        
        /* Remove leading ./ from name portion */
        char *p = strstr(path + strlen(argv[2]) + 1, "./");
        /* (skip — path already includes output_dir prefix) */
        
        if (type == '5' || (name[0] && name[strlen(name)-1] == '/')) {
            mkdirp(path, mode ? (mode_t)mode : 0755);
            dirs++;
        } else if (type == '0' || type == 0) {
            ensure_parent(path);
            int fd_out = open(path, O_WRONLY | O_CREAT | O_TRUNC, mode ? (mode_t)mode : 0644);
            if (fd_out >= 0) {
                unsigned long rem = size;
                unsigned char buf[BUF_SIZE];
                while (rem > 0) {
                    int want = rem > BUF_SIZE ? BUF_SIZE : (int)rem;
                    int got = read(fd_in, buf, want);
                    if (got <= 0) break;
                    write(fd_out, buf, got);
                    rem -= got;
                }
                close(fd_out);
                chmod(path, mode ? (mode_t)mode : 0644);
                files++;
                /* Skip padding */
                unsigned long pad = (TAR_BLOCK - (size % TAR_BLOCK)) % TAR_BLOCK;
                if (pad) read(fd_in, buf, (int)pad);
            } else {
                /* Skip */
                unsigned long blocks = (size + TAR_BLOCK - 1) / TAR_BLOCK;
                for (unsigned long i = 0; i < blocks; i++) read(fd_in, hdr, TAR_BLOCK);
            }
        } else {
            unsigned long blocks = (size + TAR_BLOCK - 1) / TAR_BLOCK;
            for (unsigned long i = 0; i < blocks; i++) read(fd_in, hdr, TAR_BLOCK);
        }
    }
    
    close(fd_in);
    
    /* Signal success */
    char result[64];
    int len = snprintf(result, sizeof(result), "OK:%d:%d\n", files, dirs);
    write(1, result, len);
    return 0;
}
