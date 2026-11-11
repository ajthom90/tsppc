/* The tsppc menu bar app: a status item that shows tsppcd's state and sends
 * it up, down and logout over the daemon's Unix socket. No nib: everything is
 * made in TSMenuController. */

#import <Cocoa/Cocoa.h>
#include <signal.h>

#import "TSMenuController.h"

int main(int argc, char *argv[])
{
    NSAutoreleasePool *pool;
    TSMenuController *controller;

    (void)argc;
    (void)argv;
    /* A daemon that goes away in the middle of a request gives EPIPE, not a signal. */
    signal(SIGPIPE, SIG_IGN);

    pool = [[NSAutoreleasePool alloc] init];
    [NSApplication sharedApplication];
    controller = [[TSMenuController alloc] init];
    if (controller == nil) {
        [pool release];
        return 1;
    }
    [NSApp setDelegate:controller];
    [NSApp run];
    /* Not reached: terminate: exits the process. */
    [controller release];
    [pool release];
    return 0;
}
