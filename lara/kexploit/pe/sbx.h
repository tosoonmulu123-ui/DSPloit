//
//  sbx.h
//  DSPloit
//
//  Created by ruter on 05.04.26.
//

#ifndef sbx_h
#define sbx_h

#include <stdint.h>

int sbx_escape(uint64_t self_proc);
void sbx_setlogcallback(void (*callback)(const char *message));
uint64_t sbx_gettoken(pid_t pid);
char *sbx_copytoken(pid_t pid);
char *sbx_issue_token(const char *extension_class, const char *path);
void sbx_freestr(char *s);
int sbx_elevate(void);

// Alternative sandbox escape: patch extension data directly (from cyanide)
int sbx_patch_extension(uint64_t self_proc);
// Borrow sandbox extensions from another process
int sbx_borrow_extensions(const char* process);

#endif /* sbx_h */
