//
//  DSPloit-Bridging-Header.h
//  DSPloit
//

@import UIKit;
#import <Foundation/Foundation.h>
#import <IOKit/IOKitLib.h>
#import <mach/mach.h>
#include <mach/vm_prot.h>

// mach_vm functions — not in iOS SDK headers but available at runtime
// Declare them manually for Swift bridging
kern_return_t mach_vm_read(vm_map_t target_task, mach_vm_address_t address,
                           mach_vm_size_t size, vm_offset_t *data,
                           mach_msg_type_number_t *dataCnt);
kern_return_t mach_vm_write(vm_map_t target_task, mach_vm_address_t address,
                            vm_offset_t data, mach_msg_type_number_t dataCnt);
kern_return_t mach_vm_protect(vm_map_t target_task, mach_vm_address_t address,
                              mach_vm_size_t size, boolean_t set_maximum,
                              vm_prot_t new_protection);
kern_return_t mach_vm_region(vm_map_t target_task, mach_vm_address_t *address,
                             mach_vm_size_t *size, vm_region_flavor_t flavor,
                             vm_region_info_t info, mach_msg_type_number_t *infoCnt,
                             mach_port_t *object_name);
kern_return_t mach_vm_read_overwrite(vm_map_t target_task, mach_vm_address_t address,
                                     mach_vm_size_t size, mach_vm_address_t data,
                                     mach_vm_size_t *outsize);

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
