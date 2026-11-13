#import "TSMenuController.h"
#import "TSLoginItem.h"

#include <stdlib.h>
#include <string.h>

#include "src/daemon/ipc.h"
#include "src/daemon/ipc_reply.h"

/* Every request, polls and actions alike, is bounded by this, so a stalled
 * daemon never freezes the menu bar for longer. */
#define REQUEST_MS 2000
#define POLL_FAST_S 5.0
#define POLL_SLOW_S 15.0
#define SLOW_AFTER_SAME 6          /* identical menus in a row before polling slowly */
#define ALERT_TEXT_MAX 300         /* characters of daemon text shown in an alert */

/* The model's strings are printable ASCII (ts_ipc_clean and ts_menu_build). */
static NSString *str(const char *s)
{
    NSString *o = [NSString stringWithCString:s encoding:NSASCIIStringEncoding];
    return o != nil ? o : @"";
}

/* Our own 16x16 icon: a ring, filled for ON, hollow for OFF, dashed for BUSY,
 * with a dot for ATTENTION and a bar for ERROR. Returned retained. */
static NSImage *makeIcon(ts_menu_icon kind, NSColor *color)
{
    NSImage *img = [[NSImage alloc] initWithSize:NSMakeSize(16, 16)];
    NSBezierPath *ring;
    float dash[2] = { 2.0f, 2.0f };

    [img lockFocus];
    [color set];
    ring = [NSBezierPath bezierPathWithOvalInRect:NSMakeRect(2.5f, 2.5f, 11.0f, 11.0f)];
    [ring setLineWidth:1.5f];
    switch (kind) {
    case TS_ICON_ON:
        [ring fill];
        [ring stroke];
        break;
    case TS_ICON_BUSY:
        [ring setLineDash:dash count:2 phase:0.0f];
        [ring stroke];
        break;
    case TS_ICON_ATTENTION:
        [ring stroke];
        [[NSBezierPath bezierPathWithOvalInRect:NSMakeRect(6.0f, 6.0f, 4.0f, 4.0f)] fill];
        break;
    case TS_ICON_ERROR:
        [ring stroke];
        [NSBezierPath fillRect:NSMakeRect(4.5f, 7.0f, 7.0f, 2.0f)];
        break;
    case TS_ICON_OFF:
    default:
        [ring stroke];
        break;
    }
    [img unlockFocus];
    return img;
}

/* Daemon text for an alert, cut to ALERT_TEXT_MAX characters ("..." added).
 * The strings are ASCII, so no character is split. */
static NSString *capped(NSString *s)
{
    if (s == nil || [s length] <= ALERT_TEXT_MAX) return s;
    return [[s substringToIndex:ALERT_TEXT_MAX - 3] stringByAppendingString:@"..."];
}

@interface TSMenuController (Private)
- (void)poll;
- (void)pollAndSchedule;
- (void)pollNow;
- (void)scheduleIn:(NSTimeInterval)seconds;
- (void)tick:(NSTimer *)t;
- (void)redraw;
- (void)redrawMenu;
- (void)menuDidEndTracking:(NSNotification *)note;
- (void)applyStale;
- (NSMenuItem *)itemFor:(const ts_menu_item *)it;
- (BOOL)alert:(NSString *)message info:(NSString *)info first:(NSString *)b1 second:(NSString *)b2;
- (BOOL)send:(ts_ipc_cmd)cmd failure:(NSString *)failure;
- (void)copyString:(NSString *)s;
- (void)offerLoginItem;
@end

@implementation TSMenuController (Private)

/* ---- polling ---- */

- (void)poll
{
    size_t len = 0;
    ts_req_result res;
    const ts_reply *r = NULL;
    ts_menu *t;
    int same;

    res = ts_ipc_request(ts_ipc_socket_path(), TS_IPC_STATUS, REQUEST_MS, buf, TS_IPC_RESP_MAX, &len);
    if (res == TS_REQ_OK) {
        if (len > 0 && ts_reply_parse(reply, peers, buf, len) == 0) r = reply;
        else res = TS_REQ_FAILED;
    }

    /* Zero first, so bytes past each string compare equal. */
    memset(next, 0, sizeof *next);
    ts_menu_build(next, res, r);
    same = haveMenu && memcmp(next, cur, sizeof *cur) == 0;

    /* Count identical menus in a row (sameCount 0: nothing to compare with).
     * The menu, not the reply: status text such as a retry countdown changes
     * every poll without changing anything shown. While the state is moving
     * (ts_menu_moving), keep polling quickly. */
    if (sameCount > 0 && same) sameCount++;
    else sameCount = 1;
    if (ts_menu_moving(res, r) && sameCount > 1) sameCount = 1;

    if (!same) {
        t = cur;
        cur = next;
        next = t;
        haveMenu = 1;
        [self redraw];
    } else if (menuStale) {
        [self redraw];
    }
}

- (void)pollAndSchedule
{
    [self poll];
    [self scheduleIn:(sameCount >= SLOW_AFTER_SAME ? POLL_SLOW_S : POLL_FAST_S)];
}

/* After an action: poll now and go back to the fast interval. */
- (void)pollNow
{
    sameCount = 0;
    [self pollAndSchedule];
}

- (void)scheduleIn:(NSTimeInterval)seconds
{
    NSRunLoop *rl = [NSRunLoop currentRunLoop];

    [timer invalidate];
    [timer release];
    timer = [[NSTimer timerWithTimeInterval:seconds target:self selector:@selector(tick:) userInfo:nil repeats:NO] retain];
    /* Tracking mode too, so the menu keeps updating while it is open. */
    [rl addTimer:timer forMode:NSDefaultRunLoopMode];
    [rl addTimer:timer forMode:NSEventTrackingRunLoopMode];
}

/* Timer and delayed-perform entry points get their own pool: an idle
 * LSUIElement app handles no events, so nothing else would drain it. */
- (void)tick:(NSTimer *)t
{
    NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];

    (void)t;
    [self pollAndSchedule];
    [pool release];
}

/* ---- the menu ---- */

- (NSMenuItem *)itemFor:(const ts_menu_item *)it
{
    NSMenuItem *mi = [[[NSMenuItem alloc] initWithTitle:str(it->title) action:NULL keyEquivalent:@""] autorelease];

    if (it->enabled && it->action != TS_ACT_NONE) {
        [mi setTarget:self];
        [mi setAction:@selector(menuAction:)];
        [mi setTag:(int)it->action];
        [mi setRepresentedObject:str(it->arg)];
    }
    /* A NONE line with arg (the problem, an error status) shows the whole text
     * as a tooltip: its title may be cut (setToolTip:, 10.3+). */
    if (it->action == TS_ACT_NONE && it->arg[0]) [mi setToolTip:str(it->arg)];
    [mi setEnabled:(it->enabled ? YES : NO)];
    return mi;
}

/* Draw cur: the icon at once, the menu only while it is not open (rebuilding
 * an open menu would move items under the pointer). An open menu is redrawn
 * when it closes (NSMenuDidEndTrackingNotification, 10.3+) or at the next poll. */
- (void)redraw
{
    [statusItem setImage:icons[cur->icon]];
    [statusItem setAlternateImage:altIcons[cur->icon]];
    if ([[[NSRunLoop currentRunLoop] currentMode] isEqualToString:NSEventTrackingRunLoopMode]) {
        menuStale = 1;
        return;
    }
    [self redrawMenu];
}

- (void)menuDidEndTracking:(NSNotification *)note
{
    (void)note;
    /* Later, once the run loop has left tracking mode. */
    [self performSelector:@selector(applyStale) withObject:nil afterDelay:0.0];
}

- (void)applyStale
{
    NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];

    if (menuStale) [self redraw];
    [pool release];
}

- (void)redrawMenu
{
    NSMenu *sub = nil;
    NSMenuItem *mi;
    size_t i;
    int inTail = 0;

    menuStale = 0;

    while ([menu numberOfItems] > 0) [menu removeItemAtIndex:0];

    for (i = 0; i < cur->nitems; i++) {
        const ts_menu_item *it = &cur->items[i];
        int parent = (i + 1 < cur->nitems && cur->items[i + 1].in_devices && !it->in_devices);
        int tail = (it->action == TS_ACT_LOGOUT || it->action == TS_ACT_QUIT);

        if (it->in_devices && sub != nil) {
            [sub addItem:[self itemFor:it]];
            continue;
        }
        /* Separators: before the Devices submenu, and before Log Out and Quit. */
        if ([menu numberOfItems] > 0 && (parent || (tail && !inTail))) [menu addItem:[NSMenuItem separatorItem]];
        if (tail) inTail = 1;
        mi = [self itemFor:it];
        [menu addItem:mi];
        if (parent) {
            sub = [[NSMenu alloc] initWithTitle:str(it->title)];
            [sub setAutoenablesItems:NO];
            [mi setSubmenu:sub];
            [sub release];
        } else {
            sub = nil;
        }
    }
}

/* ---- actions ---- */

- (BOOL)alert:(NSString *)message info:(NSString *)info first:(NSString *)b1 second:(NSString *)b2
{
    NSAlert *a = [[NSAlert alloc] init];
    int rc;

    /* An LSUIElement app is not active: without this the alert can open behind other windows. */
    [NSApp activateIgnoringOtherApps:YES];
    /* Plain setters, never a format: a daemon string may hold '%'. */
    [a setMessageText:message];
    if (info != nil) [a setInformativeText:capped(info)];
    [a addButtonWithTitle:b1];
    if (b2 != nil) [a addButtonWithTitle:b2];
    rc = [a runModal];
    [a release];
    return rc == NSAlertFirstButtonReturn;
}

/* The first time the installed app runs, offer to start it at login. Never
 * from another path (a development build), never twice, never if the item is
 * already there. */
- (void)offerLoginItem
{
    NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
    NSString *path = [[NSBundle mainBundle] bundlePath];

    if ([d objectForKey:@"TSLoginItemOffered"] != nil) return;
    if (path == nil || ![path isEqualToString:@"/Applications/tsppc.app"]) return;
    if ([TSLoginItem isEnabledForPath:path]) return;
    if ([self alert:@"Start tsppc when you log in?"
               info:@"tsppc's menu shows your tailnet connection. You can change this later in System Preferences > Accounts > Login Items."
              first:@"Start at Login" second:@"Not Now"])
        [TSLoginItem setEnabled:YES forPath:path];
    [d setBool:YES forKey:@"TSLoginItemOffered"];
    [d synchronize];
}

- (void)copyString:(NSString *)s
{
    NSPasteboard *pb = [NSPasteboard generalPasteboard];

    [pb declareTypes:[NSArray arrayWithObject:NSStringPboardType] owner:nil];
    [pb setString:s forType:NSStringPboardType];
}

/* Send cmd; on an error reply or a failed request, say so in an alert. The
 * daemon's error text was cleaned by ts_reply_parse (printable ASCII only).
 * Returns NO when the request timed out (an immediate poll would most likely
 * block for another REQUEST_MS), else YES. */
- (BOOL)send:(ts_ipc_cmd)cmd failure:(NSString *)failure
{
    size_t len = 0;
    ts_req_result res;
    NSString *why;

    res = ts_ipc_request(ts_ipc_socket_path(), cmd, REQUEST_MS, buf, TS_IPC_RESP_MAX, &len);
    switch (res) {
    case TS_REQ_OK:
        if (len > 0 && ts_reply_parse(reply, peers, buf, len) == 0) {
            if (reply->ok) return YES;
            why = reply->error[0] ? str(reply->error) : @"tsppcd refused the request.";
        } else {
            why = @"tsppcd sent a reply that could not be read.";
        }
        break;
    case TS_REQ_NO_DAEMON:
        why = @"tsppcd is not running.";
        break;
    case TS_REQ_DENIED:
        why = @"This needs an administrator account.";
        break;
    case TS_REQ_TIMEOUT:
        why = @"tsppcd did not answer.";
        break;
    default:
        why = @"Could not talk to tsppcd.";
        break;
    }
    [self alert:failure info:why first:@"OK" second:nil];
    return res != TS_REQ_TIMEOUT;
}

@end

@implementation TSMenuController

- (id)init
{
    int i;

    self = [super init];
    if (self == nil) return nil;
    cur = malloc(sizeof *cur);
    next = malloc(sizeof *next);
    reply = malloc(sizeof *reply);
    peers = malloc(TS_MAX_PEERS * sizeof *peers);
    buf = malloc(TS_IPC_RESP_MAX);
    if (cur == NULL || next == NULL || reply == NULL || peers == NULL || buf == NULL) {
        [self release];
        return nil;
    }
    memset(cur, 0, sizeof *cur);
    memset(next, 0, sizeof *next);
    memset(reply, 0, sizeof *reply);
    for (i = 0; i < 5; i++) {
        icons[i] = makeIcon((ts_menu_icon)i, [NSColor blackColor]);
        altIcons[i] = makeIcon((ts_menu_icon)i, [NSColor whiteColor]);
    }
    return self;
}

/* Never runs in practice: the timer retains its target and terminate: exits. */
- (void)dealloc
{
    int i;

    [[NSNotificationCenter defaultCenter] removeObserver:self];
    [timer invalidate];
    [timer release];
    [[NSStatusBar systemStatusBar] removeStatusItem:statusItem];
    [statusItem release];
    [menu release];
    for (i = 0; i < 5; i++) {
        [icons[i] release];
        [altIcons[i] release];
    }
    free(cur);
    free(next);
    free(reply);
    free(peers);
    free(buf);
    [super dealloc];
}

- (void)applicationDidFinishLaunching:(NSNotification *)note
{
    (void)note;
    menu = [[NSMenu alloc] initWithTitle:@"tsppc"];
    [menu setAutoenablesItems:NO];
    statusItem = [[[NSStatusBar systemStatusBar] statusItemWithLength:NSSquareStatusItemLength] retain];
    [statusItem setHighlightMode:YES];
    [statusItem setToolTip:@"tsppc"];
    [statusItem setMenu:menu];
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(menuDidEndTracking:)
                                                 name:NSMenuDidEndTrackingNotification object:menu];
    [statusItem setImage:icons[TS_ICON_BUSY]];
    [statusItem setAlternateImage:altIcons[TS_ICON_BUSY]];
    [self pollNow];
    [self offerLoginItem];
}

/* ---- the menu's target ---- */

- (void)menuAction:(id)sender
{
    /* Copy what the item carries first: a poll may rebuild the menu. */
    int act = (int)[sender tag];
    NSString *arg = [[[sender representedObject] retain] autorelease];
    BOOL pollAfter = YES;

    if (arg == nil) arg = @"";
    switch (act) {
    case TS_ACT_COPY:
        [self copyString:arg];
        break;
    case TS_ACT_UP:
        pollAfter = [self send:TS_IPC_UP failure:@"Could not connect."];
        break;
    case TS_ACT_DOWN:
        pollAfter = [self send:TS_IPC_DOWN failure:@"Could not disconnect."];
        break;
    case TS_ACT_LOGIN:
        if ([self alert:@"Open this link on any other device to log in:" info:arg first:@"Copy Link" second:@"Close"])
            [self copyString:arg];
        break;
    case TS_ACT_LOGOUT:
        if ([self alert:@"Log out of the tailnet?" info:nil first:@"Log Out" second:@"Cancel"])
            pollAfter = [self send:TS_IPC_LOGOUT failure:@"Could not log out."];
        break;
    case TS_ACT_QUIT:
        /* Only the app quits; tsppcd keeps running. */
        [NSApp terminate:self];
        return;
    default:
        return;
    }
    if (pollAfter) {
        [self pollNow];
    } else {
        /* Timed out: no poll now, the next one at the fast interval. */
        sameCount = 0;
        [self scheduleIn:POLL_FAST_S];
    }
}

@end
