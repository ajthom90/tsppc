#import "TSLoginItem.h"

#include <CoreFoundation/CoreFoundation.h>

static NSString *const kLoginWindow = @"loginwindow";
static NSString *const kItems = @"AutoLaunchedApplicationDictionary";

/* A mutable copy of the current items. A missing or non-array value is an
 * empty array. Entries that are not dictionaries are kept (and written back
 * as they were) but never match a path. Autoreleased. */
static NSMutableArray *currentItems(void)
{
    CFPropertyListRef v;
    NSMutableArray *out = [NSMutableArray array];

    CFPreferencesSynchronize((CFStringRef)kLoginWindow, kCFPreferencesCurrentUser, kCFPreferencesAnyHost);
    v = CFPreferencesCopyValue((CFStringRef)kItems, (CFStringRef)kLoginWindow,
                               kCFPreferencesCurrentUser, kCFPreferencesAnyHost);
    if (v != NULL) {
        if (CFGetTypeID(v) == CFArrayGetTypeID()) {
            [out addObjectsFromArray:(NSArray *)v];
        }
        CFRelease(v);
    }
    return out;
}

static BOOL entryHasPath(id e, NSString *path)
{
    id p;

    if (![e isKindOfClass:[NSDictionary class]]) return NO;
    p = [(NSDictionary *)e objectForKey:@"Path"];
    return [p isKindOfClass:[NSString class]] && [p isEqualToString:path];
}

static BOOL store(NSArray *items)
{
    CFPreferencesSetValue((CFStringRef)kItems, (CFPropertyListRef)items, (CFStringRef)kLoginWindow,
                          kCFPreferencesCurrentUser, kCFPreferencesAnyHost);
    return CFPreferencesSynchronize((CFStringRef)kLoginWindow, kCFPreferencesCurrentUser,
                                    kCFPreferencesAnyHost) ? YES : NO;
}

@implementation TSLoginItem

+ (BOOL)isEnabledForPath:(NSString *)path
{
    NSMutableArray *items;
    unsigned int i, n;

    if (path == nil) return NO;
    items = currentItems();
    n = [items count];
    for (i = 0; i < n; i++)
        if (entryHasPath([items objectAtIndex:i], path)) return YES;
    return NO;
}

+ (BOOL)setEnabled:(BOOL)on forPath:(NSString *)path
{
    NSMutableArray *items;
    unsigned int i;
    BOOL found = NO;

    if (path == nil) return NO;
    items = currentItems();
    /* Backwards, so removing keeps the indexes ahead valid. */
    for (i = [items count]; i > 0; i--) {
        if (!entryHasPath([items objectAtIndex:i - 1], path)) continue;
        found = YES;
        if (!on) [items removeObjectAtIndex:i - 1];
    }
    if (on) {
        if (found) return YES;
        [items addObject:[NSDictionary dictionaryWithObjectsAndKeys:
                          path, @"Path", [NSNumber numberWithBool:NO], @"Hide", nil]];
    } else if (!found) {
        return YES;
    }
    return store(items);
}

@end
