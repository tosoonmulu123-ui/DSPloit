//
//  TweakLoaderDylib.m
//  DSPloit
//
//  This is the TweakLoader dylib that gets injected into processes via
//  DYLD_INSERT_LIBRARIES. It scans /var/jb/Library/TweakInject/ for .dylib
//  files, checks their filter plists, and loads matching tweaks.
//
//  Compiled separately as a dylib: TweakLoader.dylib
//  Deployed to: /var/jb/usr/lib/TweakLoader.dylib
//
//  Compatible with ElleKit/Substrate hooking frameworks.
//
//  Created by Royan | 2026-05-24
//

#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <objc/runtime.h>
#import <sys/stat.h>
#import <unistd.h>

#define TWEAK_INJECT_DIR    "/var/jb/Library/TweakInject"
#define SUBSTRATE_DIR       "/var/jb/Library/MobileSubstrate/DynamicLibraries"
#define ELLEKIT_PATH        "/var/jb/usr/lib/ellekit.dylib"
#define SAFE_MODE_FILE      "/var/jb/.safe_mode"
#define LOADER_LOG_PATH     "/var/jb/tmp/tweakloader.log"

static FILE *g_logfile = NULL;

static void tl_log(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void tl_log(const char *fmt, ...) {
    if (!g_logfile) {
        g_logfile = fopen(LOADER_LOG_PATH, "a");
    }
    if (!g_logfile) return;
    
    va_list ap;
    va_start(ap, fmt);
    vfprintf(g_logfile, fmt, ap);
    va_end(ap);
    fprintf(g_logfile, "\n");
    fflush(g_logfile);
}

static bool is_safe_mode(void) {
    return access(SAFE_MODE_FILE, F_OK) == 0;
}

static NSString *current_bundle_id(void) {
    return [[NSBundle mainBundle] bundleIdentifier] ?: @"";
}

static NSString *current_executable(void) {
    return [[NSProcessInfo processInfo] processName] ?: @"";
}

/// Check if a tweak's filter plist matches the current process
static bool filter_matches(NSString *filterPath) {
    if (![[NSFileManager defaultManager] fileExistsAtPath:filterPath]) {
        // No filter = load everywhere (dangerous but some tweaks do this)
        return true;
    }
    
    NSDictionary *plist = [NSDictionary dictionaryWithContentsOfFile:filterPath];
    if (!plist) return false;
    
    NSDictionary *filter = plist[@"Filter"];
    if (!filter) return true; // No Filter key = load everywhere
    
    NSString *bundleID = current_bundle_id();
    NSString *executable = current_executable();
    
    // Check Bundles array
    NSArray *bundles = filter[@"Bundles"];
    if (bundles && [bundles isKindOfClass:[NSArray class]]) {
        for (NSString *b in bundles) {
            if ([bundleID isEqualToString:b]) return true;
        }
    }
    
    // Check Executables array
    NSArray *executables = filter[@"Executables"];
    if (executables && [executables isKindOfClass:[NSArray class]]) {
        for (NSString *e in executables) {
            if ([executable isEqualToString:e]) return true;
        }
    }
    
    // Check Classes array (load if any class exists in runtime)
    NSArray *classes = filter[@"Classes"];
    if (classes && [classes isKindOfClass:[NSArray class]]) {
        for (NSString *cls in classes) {
            if (NSClassFromString(cls)) return true;
        }
    }
    
    // If filter has Mode = "Any", match if ANY condition above matched
    // Default mode is "Any" for Bundles/Executables
    // If none matched, don't load
    return false;
}

/// Load ElleKit hooking framework (provides MSHookFunction/MSHookMessageEx)
static void load_ellekit(void) {
    if (access(ELLEKIT_PATH, F_OK) != 0) {
        tl_log("[TweakLoader] ElleKit not found at %s", ELLEKIT_PATH);
        return;
    }
    
    void *handle = dlopen(ELLEKIT_PATH, RTLD_NOW | RTLD_GLOBAL);
    if (handle) {
        tl_log("[TweakLoader] ElleKit loaded successfully");
    } else {
        tl_log("[TweakLoader] ElleKit load failed: %s", dlerror());
    }
}

/// Scan directory and load matching tweaks
static void load_tweaks_from_dir(const char *dir) {
    NSString *dirPath = @(dir);
    NSFileManager *fm = [NSFileManager defaultManager];
    
    if (![fm fileExistsAtPath:dirPath]) {
        tl_log("[TweakLoader] Directory not found: %s", dir);
        return;
    }
    
    NSError *error = nil;
    NSArray<NSString *> *contents = [fm contentsOfDirectoryAtPath:dirPath error:&error];
    if (error) {
        tl_log("[TweakLoader] Failed to list %s: %s", dir, error.localizedDescription.UTF8String);
        return;
    }
    
    int loaded = 0, skipped = 0, failed = 0;
    
    for (NSString *file in contents) {
        if (![file hasSuffix:@".dylib"]) continue;
        if ([file hasSuffix:@".disabled"]) continue;
        
        NSString *dylibPath = [dirPath stringByAppendingPathComponent:file];
        NSString *filterPath = [dylibPath stringByReplacingOccurrencesOfString:@".dylib"
                                                                   withString:@".plist"];
        
        // Check filter
        if (!filter_matches(filterPath)) {
            skipped++;
            continue;
        }
        
        // Load the tweak
        tl_log("[TweakLoader] Loading: %s", file.UTF8String);
        void *handle = dlopen(dylibPath.UTF8String, RTLD_NOW | RTLD_GLOBAL);
        if (handle) {
            loaded++;
        } else {
            const char *err = dlerror();
            tl_log("[TweakLoader] FAILED: %s — %s", file.UTF8String, err ?: "unknown");
            failed++;
        }
    }
    
    tl_log("[TweakLoader] %s: loaded=%d skipped=%d failed=%d", dir, loaded, skipped, failed);
}

/// Constructor — runs when dylib is loaded into a process
__attribute__((constructor))
static void tweakloader_init(void) {
    // Don't load in launchd or other critical daemons
    pid_t pid = getpid();
    if (pid == 1) return; // launchd
    
    const char *procname = getprogname();
    if (!procname) return;
    
    // Skip certain system processes that crash with tweaks
    static const char *blacklist[] = {
        "amfid", "trustd", "securityd", "keybagd",
        "notifyd", "cfprefsd", "containermanagerd",
        "runningboardd", "dasd", "thermalmonitord",
        NULL
    };
    for (int i = 0; blacklist[i]; i++) {
        if (strcmp(procname, blacklist[i]) == 0) return;
    }
    
    // Safe mode check
    if (is_safe_mode()) {
        tl_log("[TweakLoader] Safe mode active — skipping all tweaks (pid=%d %s)", pid, procname);
        return;
    }
    
    tl_log("[TweakLoader] Init in %s (pid=%d, bundle=%s)",
           procname, pid, current_bundle_id().UTF8String);
    
    // Load ElleKit first (provides hooking API)
    load_ellekit();
    
    // Load tweaks from both directories
    load_tweaks_from_dir(TWEAK_INJECT_DIR);
    load_tweaks_from_dir(SUBSTRATE_DIR);
}
