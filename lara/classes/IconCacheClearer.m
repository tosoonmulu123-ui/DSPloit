#import <Foundation/Foundation.h>
#import "IconServices.h"

void DSPClearIconCache(void) {
    static NSXPCConnection *connection = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        Class connectionClass = NSClassFromString(@"NSXPCConnection");
        id allocated = [connectionClass alloc];
        SEL initSelector = NSSelectorFromString(@"initWithMachServiceName:options:");
        NSXPCConnection *(*initFunc)(id, SEL, NSString *, NSUInteger) = (NSXPCConnection *(*)(id, SEL, NSString *, NSUInteger))[allocated methodForSelector:initSelector];
        connection = initFunc(allocated, initSelector, @"com.apple.iconservices", 0);
        connection.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:@protocol(ISIconCacheServiceProtocol)];
        [connection resume];
    });

    id<ISIconCacheServiceProtocol> proxy = [connection remoteObjectProxyWithErrorHandler:^(NSError *error) {
        NSLog(@"(iconthemer) icon cache clear failed: %@", error.localizedDescription);
    }];

    [proxy clearCachedItemsForBundeID:nil reply:^(BOOL success, NSError *error) {
        if (error) {
            NSLog(@"(iconthemer) clear cache reply error: %@", error.localizedDescription);
        } else {
            NSLog(@"(iconthemer) clear cache reply success=%d", success);
        }
    }];
}
