#ifndef TS_MENUBAR_MODEL_H
#define TS_MENUBAR_MODEL_H

#include <stddef.h>

#include "src/daemon/ipc_reply.h"

/* The menu bar menu as plain data: ts_menu_build decides every title, icon,
 * action and enabled flag from one poll, and the Cocoa layer only draws the
 * result. A ts_menu is large (about 560 KB): never put one on the stack. */

typedef enum { TS_ICON_OFF, TS_ICON_BUSY, TS_ICON_ATTENTION, TS_ICON_ON, TS_ICON_ERROR } ts_menu_icon;
typedef enum { TS_ACT_NONE, TS_ACT_COPY, TS_ACT_UP, TS_ACT_DOWN, TS_ACT_LOGIN, TS_ACT_LOGOUT, TS_ACT_QUIT } ts_menu_action;

#define TS_MENU_TITLE_MAX 64     /* bytes, NUL included; longer titles end in "..." */

/* title holds only 0x20-0x7e. arg is the ip for COPY and the url for LOGIN, else "".
 * in_devices is 1 for the items of the Devices submenu (the peers and the
 * "More devices not shown" line); the "Devices (<n> online)" parent item
 * itself has in_devices 0 and the submenu items follow it. */
typedef struct {
    char title[TS_MENU_TITLE_MAX];
    ts_menu_action action;
    char arg[TS_IPC_VALUE_MAX];
    int enabled;
    int in_devices;
} ts_menu_item;

#define TS_MENU_MAX_ITEMS (TS_MAX_PEERS + 16)

typedef struct {
    ts_menu_icon icon;
    ts_menu_item items[TS_MENU_MAX_ITEMS];
    size_t nitems;
    size_t ndevices_online;
} ts_menu;

/* Build the menu from one poll: res, and r when res == TS_REQ_OK. Deterministic.
 * Any result other than TS_REQ_OK (or an OK result with a NULL r, or a reply
 * without "ok") shows only a status line and Quit. A state/login/wanted
 * combination the tables do not name shows "Connecting..." (icon BUSY) when
 * wanted is up, else "Disconnected" (icon OFF); login "leaving" shows
 * "Logging out..." (BUSY) with no Connect, Disconnect or Log Out items. */
void ts_menu_build(ts_menu *m, ts_req_result res, const ts_reply *r);

#endif
