//
//  DSPloit-Bridging-Header.h
//  DSPloit
//

@import UIKit;
#import <Foundation/Foundation.h>
#import <IOKit/IOKitLib.h>
#import <mach/mach.h>

// mach_vm functions (not auto-bridged to Swift)
#include <mach/mach_vm.h>
#include <mach/vm_prot.h>

#ifndef VM_PROT_ALL
#define VM_PROT_ALL (VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE)
#endif

#import "darksword.h"
#import "offsets.h"
#import "offsets_xpf.h"
#import "utils.h"
#import "persistence.h"
#import "persistence_v2.h"
#import "TrustCacheInjector.h"
#import "amfi_bypass.h"
#import "vnode.h"
#import "apfs.h"
#import "vfs.h"
#import "sbx.h"
#import "IconServices.h"
#import "rc.h"
#import "RemoteCall.h"

// Multi-exploit system
#import "exploits/exploit_selector.h"
#import "exploits/jpeg_uaf.h"
#import "exploits/sepkeystore_uaf.h"
#import "exploits/aks_close_uaf.h"

long findcachedataoff(const char *mgkey);
void DSPClearIconCache(void);

@interface UIDevice(Private)
+ (BOOL)_hasHomeButton;
@end

void test(NSString *path);

NS_ASSUME_NONNULL_BEGIN

@interface VarCleanBridge : NSObject

+ (NSDictionary *)loadRulesNamed:(NSString *)resourceName
                        inBundle:(NSBundle *)bundle
                           error:(NSError * _Nullable * _Nullable)error;

+ (BOOL)probePathExists:(NSString *)path
            isDirectory:(BOOL *)isDirectory
              isSymlink:(BOOL *)isSymlink;

@end

NS_ASSUME_NONNULL_END
