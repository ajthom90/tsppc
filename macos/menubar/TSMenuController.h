#import <Cocoa/Cocoa.h>

#include "src/menubar/model.h"

/* Owns the status item, its menu and the poll timer. All work happens on the
 * main thread (ts_ipc_request is not thread-safe). The model and the reply are
 * large, so they live in malloc'd buffers, never on the stack. */
@interface TSMenuController : NSObject
{
    NSStatusItem *statusItem;
    NSMenu *menu;
    NSTimer *timer;                /* retained; the next poll */
    NSImage *icons[5];             /* by ts_menu_icon */
    NSImage *altIcons[5];          /* the same, white, for the highlighted item */

    ts_menu *cur;                  /* the model the menu shows */
    ts_menu *next;                 /* the model being built */
    int haveMenu;                  /* cur has been drawn once */
    int menuStale;                 /* cur changed while the menu was open; redraw it once closed */

    ts_reply *reply;
    ts_reply_peer *peers;          /* TS_MAX_PEERS */
    char *buf;                     /* TS_IPC_RESP_MAX: this reply */
    int sameCount;                 /* identical menus in a row */
}

- (void)menuAction:(id)sender;

@end
