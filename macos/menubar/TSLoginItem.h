#import <Foundation/Foundation.h>

/* The current user's Login Items, as Tiger and Leopard keep them: an array of
 * {Path, Hide} dictionaries under AutoLaunchedApplicationDictionary in the
 * loginwindow domain. Only entries for the given path are ever added or
 * removed. */
@interface TSLoginItem : NSObject

+ (BOOL)isEnabledForPath:(NSString *)path;
/* Enabling an existing path changes nothing. Disabling removes every entry
 * with that path. Returns NO if the preferences could not be written. */
+ (BOOL)setEnabled:(BOOL)on forPath:(NSString *)path;

@end
