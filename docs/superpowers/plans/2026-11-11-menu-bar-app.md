# Menu Bar App Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A menu bar app on Tiger and Leopard shows whether tsppc is connected. From it you can connect, disconnect, log in, log out, and see your tailnet devices.

**Architecture:**
- Everything the app decides is plain C that is tested on the host:
  - parsing the daemon's reply;
  - talking to the daemon with a time limit;
  - turning the reply into a description of the menu.
- A thin Objective-C/Cocoa layer, built only on the VM with the 10.4u SDK, draws that description with `NSStatusItem` and turns clicks into IPC commands.
- The daemon gains a persisted `down`, so "Disconnect" is real.

**Tech Stack:** C (gnu99), Objective-C 1.0 and AppKit from the 10.4u SDK, GNU make 3.81, gcc-4.0 on the VM, clang on the host.

**Spec:** `docs/superpowers/specs/2026-11-10-tailscale-ppc-design.md` ("Menu bar app", milestone 12).

**Scope:** Milestone 12 only, built now on top of the control-session daemon. Left out:
- The "Exit Node" submenu and its LAN-access item. They come with milestone 13 and need the tunnel.
- The installer's offer to add the app to Login Items. That needs the installer from milestone 7.
- Everything that needs the tunnel.

**Branch:** `menubar`, created from `control-session` after that branch's Task 11 is recorded. Push after each finished task. Merging needs the owner.

## Global Constraints

- PowerPC flags: `gcc-4.0 -std=gnu99 -arch ppc -isysroot /Developer/SDKs/MacOSX10.4u.sdk -mmacosx-version-min=10.4`. The app links `-framework Cocoa` from that SDK and must run on stock 10.4.11 and 10.5.8.
- Objective-C 1.0 only:
  - no `@property` or dot syntax;
  - no fast enumeration;
  - no blocks;
  - no garbage collection;
  - manual retain and release;
  - no API newer than 10.4 unless it is checked with `respondsToSelector:` and has a fallback.
- The app is named **tsppc** (bundle `tsppc.app`, identifier `org.tsppc.menu`). Never use "Tailscale" or Tailscale's logo, in the name, icon, menu text or bundle.
- The app holds no keys, needs no root, and opens no network sockets. Its only connection is to the Unix socket from `ts_ipc_socket_path()`.
- Every string from the daemon is untrusted. Pass it through `ts_ipc_clean` before it reaches a menu title, an alert or the pasteboard.
- Bounded memory: at most `TS_MAX_PEERS` (256) devices, and a reply of at most `TS_IPC_RESP_MAX` bytes.
- Every parser has a host unit test and a fuzz target under ASan and UBSan.
- `-Wall -Wextra -Werror` for C on the host and with gcc-4.0. Public C symbols start with `ts_`.
- Saved state files from the control-session build (format version 1, flags bits 0 to 2) must still load. The owner approved the two VM nodes by hand, and losing those identities would mean doing it again.
- The repository is public:
  - nothing personal in code, fixtures, commits or docs (peer names, tailnet names, IPs, usernames);
  - placeholders in any recorded results;
  - never stage `spike/` or `.superpowers/`.

## Review Focus

1. **The daemon is not running, or the user isn't an admin.** The app must show a clear line ("tsppcd is not running", "Needs an administrator account") and keep polling. It must not crash, hang or spin. Pinned by tests in Tasks 3 and 4.
2. **The daemon stalls in the middle of a reply.** A stall must never freeze the menu bar for longer than the request limit. Pinned by the Task 3 timeout test.
3. **Peer names that are very long, non-ASCII, contain control bytes, or have no IPv4 address.** Menu titles must stay short and printable. A device with no address must not offer "copy". Pinned by Task 4 tests.
4. **Disconnect, then a daemon restart.** The node must stay disconnected and logged in, and a later Connect must use the same node with no login. Pinned by Task 1 tests.
5. **A reply cut short with `truncated`, or with keys the app doesn't know.** These are ignored safely, and the device list says it is partial. Pinned by Task 3 tests.

---

### Task 0: Branch and spec ruling

**Files:** Modify `docs/superpowers/specs/2026-11-10-tailscale-ppc-design.md` (milestone 12 text).

- [ ] **Step 1:** Create the branch: `git switch -c menubar control-session`.
- [ ] **Step 2:** In milestone 12, replace "so it can be built any time after milestone 7" with: "It was built right after milestone 3, on the control-session daemon. The installer's Login Items offer waits for milestone 7, and the Exit Node submenu waits for milestone 13."
- [ ] **Step 3:** Commit `Record when the menu bar app is built`, then push.

### Task 1: Persisted down in state and session

**Files:**
- Modify: `src/state/store.h`, `src/state/store.c`, `src/control/session.h`, `src/control/session.c`, `src/daemon/main.c`
- Test: `tests/test_store.c`, `tests/test_session.c`

**Interfaces:**
- Produces:
  - `ts_state.down` (int). It is flag bit 3 in the state file. The file version stays 1. Bits 4 to 15 must still be 0. `down` may only be set together with `have_login`.
  - `void ts_sess_down(ts_sess *s)`.
  - `int ts_sess_is_down(const ts_sess *s)`.

**Ruling:** keep version 1 and use a new bit, so every existing file loads unchanged. An older binary would refuse a file that has the bit set. That only matters if someone downgrades, and that is acceptable.

- [ ] **Step 1: Write failing tests.**
  - `test_store_v1_fixture_loads`:
    - Keep a 168-byte image made by today's encoder, with flags `have_login` set, as a fixture with invented keys.
    - It parses with `down == 0` and the same keys.
  - `test_store_down_roundtrip`:
    - Encode with `down = 1` and `have_login = 1`, then parse; `down == 1`.
    - Flags bit 3 without bit 1 is rejected.
    - Bit 4 is rejected.
  - In `tests/test_session.c`, with the fake control server and fake clock:
    - `test_sess_down_disconnects`: from `RUNNING`, `ts_sess_down` closes the connection and saves `down=1` with `have_login` still 1. The state becomes `IDLE`. After 10 minutes of ticks, there is no reconnect attempt.
    - `test_sess_up_after_down`: `ts_sess_up` saves `down=0` and reconnects with the same node key. There is no new AuthURL.
    - `test_sess_down_save_fails`: when `save_state` fails, it stays connected and the problem says the state could not be saved.
    - `test_sess_logout_clears_down`: after a logout, `down` is 0.
- [ ] **Step 2: Run** `make test`. Expected: fails because `down` and `ts_sess_down` are missing.
- [ ] **Step 3: Implement.**
  - The store gets the new field.
  - `ts_sess_down` saves the state first. If the save fails it changes nothing, as `ts_sess_logout` does. Otherwise it drops the connection, stops the timers and goes `IDLE`.
  - `ts_sess_up` clears `down` and saves.
  - Daemon start: set `D.want_up = st.have_login && !st.down`, and log "logged in: disconnected (down)" in that case.
- [ ] **Step 4: Run** `make test asan fuzz`. Expected: all pass. The `fuzz_store` corpus is unchanged.
- [ ] **Step 5: Commit** `Add a persisted down to the session`.

### Task 2: `down` command, and more status fields

**Files:**
- Modify: `src/daemon/ipc.h`, `src/daemon/ipc.c`, `src/daemon/main.c`, `src/cli/main.c`
- Test: `tests/test_ipc.c`, the daemon tests in `tests/test_ipc.c`

**Interfaces:**
- `ts_ipc_cmd` gains `TS_IPC_DOWN` (request line `down\n`).
- The status reply gains two keys, documented in `ipc.h`:
  - `wanted <up|down>`: whether the node is meant to be connected. `down` when logged out, or after `down`.
  - `self <name>`: the self node's name, when known.
- `tsppc down` prints `Disconnected. Run tsppc up to connect again.` and exits 0.
- `tsppc status` shows `Disconnected (tsppc up to connect)` when `wanted down` and `login yes`.

- [ ] **Step 1: Write failing tests.**
  - `ts_ipc_parse_request("down\n")` gives `TS_IPC_DOWN`.
  - Daemon test (hooked build, fake control): `up` → `RUNNING` → `down`. Status then has `wanted down`, `login yes`, `state IDLE`. Restart the daemon: still `wanted down`, and no connection is attempted. `up` gives `RUNNING` with no `url`.
  - The status reply in `RUNNING` contains `self ` followed by the fixture's self name.
- [ ] **Step 2: Run** `make test`. Expected: the new tests fail.
- [ ] **Step 3: Implement** the command (`D.want_up = 0; ts_sess_down`), the new keys and the CLI command. Update the usage text to `usage: tsppc <up|down|status|ip|logout>`.
- [ ] **Step 4: Run** `make test asan fuzz release`. Expected: all pass, and `check-release` passes.
- [ ] **Step 5: Commit** `Add tsppc down and report self and wanted in status`.

### Task 3: Reply parser and timed request, shared by CLI and app

**Files:**
- Create: `src/daemon/ipc_reply.h`, `src/daemon/ipc_reply.c`, `tests/test_ipc_reply.c`, `tests/fuzz_ipc_reply.c`
- Modify: `src/cli/main.c` (use the parser in place of its own field scanning), `tests/main.c`, `tests/fuzz.c` or its target list, `Makefile` if targets are listed

**Interfaces:**
- Produces:

```c
typedef struct { uint32_t ipv4; int have_ipv4; int online; char name[TS_NODE_NAME_MAX + 1]; } ts_reply_peer;
typedef struct {
    int ok;                          /* "ok" seen */
    char error[TS_IPC_VALUE_MAX];    /* "error" value, "" if none */
    char state[32], status[TS_IPC_VALUE_MAX], url[TS_IPC_VALUE_MAX], problem[TS_IPC_VALUE_MAX];
    char login[16], wanted[16], self[TS_NODE_NAME_MAX + 1];
    uint32_t ipv4; int have_ipv4;
    ts_reply_peer *peers; size_t npeers;   /* peers: caller array of TS_MAX_PEERS */
    int truncated;                   /* "truncated" seen, or more than TS_MAX_PEERS peers */
} ts_reply;
/* Parse a whole reply (bytes up to the daemon's close). Unknown keys and
 * malformed lines are skipped; values are cleaned with ts_ipc_clean. Returns 0,
 * or -1 if the reply holds no "ok" and no "error" line. */
int ts_reply_parse(ts_reply *r, ts_reply_peer *peers, const char *buf, size_t len);

typedef enum { TS_REQ_OK = 0, TS_REQ_NO_DAEMON, TS_REQ_DENIED, TS_REQ_TIMEOUT, TS_REQ_FAILED } ts_req_result;
/* Connect to path, send cmd, read until close or timeout_ms (whole request).
 * ENOENT and ECONNREFUSED give NO_DAEMON; EACCES and EPERM give DENIED.
 * Non-blocking with select(); never blocks longer than timeout_ms.
 * *len = bytes read (at most cap). */
ts_req_result ts_ipc_request(const char *path, ts_ipc_cmd cmd, int timeout_ms, char *buf, size_t cap, size_t *len);
```

- [ ] **Step 1: Write failing tests** in `tests/test_ipc_reply.c`:
  - A full `RUNNING` reply with three peers parses every field. Peer IP `-` gives `have_ipv4 == 0`.
  - Unknown keys (`exitnode x`) and a line with an upper-case key are skipped.
  - A control byte in a name becomes `?`.
  - A `truncated` line sets `truncated`.
  - 257 `peer` lines keep 256 and set `truncated`.
  - A peer line missing its name, or with a bad IP (`1.2.3`, `256.0.0.1`), is skipped.
  - No `ok` or `error` line returns -1.
  - Request timeout: a test socket that accepts and never answers returns `TS_REQ_TIMEOUT` within `timeout_ms + 200` ms (measure it).
  - A missing socket path gives `TS_REQ_NO_DAEMON`.
  - A socket file with mode 0000, made by the test user, gives `TS_REQ_DENIED`. Skip this one when running as root.
- [ ] **Step 2: Run** `make test`. Expected: missing header.
- [ ] **Step 3: Implement.** `ts_reply_parse` uses `ts_ipc_split`. Switch the CLI to `ts_reply_parse` and `ts_ipc_request` with a 10000 ms limit. The CLI's output must be byte-for-byte unchanged for the existing daemon tests.
- [ ] **Step 4: Run** `make test asan fuzz`. Expected: all pass. The new fuzz target runs 200000 iterations clean.
- [ ] **Step 5: Commit** `Share one IPC reply parser between the CLI and the menu bar app`.

### Task 4: Menu model

**Files:**
- Create: `src/menubar/model.h`, `src/menubar/model.c`, `tests/test_menu_model.c`
- Modify: `tests/main.c`

**Interfaces:**
- Consumes: `ts_reply`, `ts_req_result` (Task 3).
- Produces:

```c
typedef enum { TS_ICON_OFF, TS_ICON_BUSY, TS_ICON_ATTENTION, TS_ICON_ON, TS_ICON_ERROR } ts_menu_icon;
typedef enum { TS_ACT_NONE, TS_ACT_COPY, TS_ACT_UP, TS_ACT_DOWN, TS_ACT_LOGIN, TS_ACT_LOGOUT, TS_ACT_QUIT } ts_menu_action;
#define TS_MENU_TITLE_MAX 64     /* bytes, NUL included; longer titles end in "..." */
typedef struct { char title[TS_MENU_TITLE_MAX]; ts_menu_action action; char arg[TS_IPC_VALUE_MAX]; int enabled; int in_devices; } ts_menu_item;
#define TS_MENU_MAX_ITEMS (TS_MAX_PEERS + 16)
typedef struct { ts_menu_icon icon; ts_menu_item items[TS_MENU_MAX_ITEMS]; size_t nitems; size_t ndevices_online; } ts_menu;
/* Build the menu from one poll: res, and r when res == TS_REQ_OK. Deterministic. */
void ts_menu_build(ts_menu *m, ts_req_result res, const ts_reply *r);
```

Menu text is fixed copy, in this order. An item is shown only when its condition holds.

| Condition | Title | Action |
|---|---|---|
| always | status line (below) | NONE, disabled |
| problem non-empty | `problem` value | NONE, disabled |
| `have_ipv4` | `This Mac: <short self> (<ip>)` | COPY ip |
| login yes and wanted down, or login no | `Connect` | UP |
| wanted up | `Disconnect` | DOWN |
| url non-empty | `Log In...` | LOGIN, arg url |
| npeers > 0 | `Devices (<online> online)`: the submenu parent | NONE |
| each peer | `<short name>  <ip or "no address">` plus ` (offline)` | COPY ip, enabled only with an address |
| truncated | `More devices not shown`, in the submenu | NONE, disabled |
| login yes | `Log Out...` | LOGOUT |
| always | `Quit tsppc` | QUIT |

Status line and icon by input:

| Input | Status line | Icon |
|---|---|---|
| `TS_REQ_NO_DAEMON` | `tsppcd is not running` | ERROR |
| `TS_REQ_DENIED` | `Needs an administrator account` | ERROR |
| `TS_REQ_TIMEOUT` or `TS_REQ_FAILED` | `tsppcd is not responding` | ERROR |
| `RUNNING` | `Connected` | ON |
| `NEED_LOGIN` | `Login needed` | ATTENTION |
| `AWAIT_APPROVAL` | `Waiting for approval in the admin console` | ATTENTION |
| `CONNECTING`, or `BACKOFF` with wanted up | `Connecting...` | BUSY |
| `IDLE` with login yes and wanted down | `Disconnected` | OFF |
| `IDLE` with login no | `Not logged in` | OFF |
| `FAILED` | `Stopped: see tsppc status` | ERROR |

- Short name: the text before the first `.`, or the whole name if it has no dot.
- Devices: online first, then by short name using byte comparison. Ties keep reply order.

- [ ] **Step 1: Write failing tests**, one per row of both tables above. Also:
  - a 300-byte name is cut to fit `TS_MENU_TITLE_MAX` and ends in `...`;
  - a name holding `?` from cleaning stays printable;
  - a peer with no IPv4 gives a disabled item;
  - device order is online first, then by name;
  - 256 peers fit within `TS_MENU_MAX_ITEMS`.
- [ ] **Step 2: Run** `make test`. Expected: missing header.
- [ ] **Step 3: Implement** `ts_menu_build`. `...` is three ASCII dots, because 10.4's menu font may lack U+2026 under every encoding path.
- [ ] **Step 4: Run** `make test asan`. Expected: pass.
- [ ] **Step 5: Commit** `Add the menu bar menu model`.

### Task 5: Cocoa app and its build

**Files:**
- Create:
  - `macos/menubar/main.m`, `macos/menubar/TSMenuController.h`, `macos/menubar/TSMenuController.m`
  - `macos/menubar/Info.plist`
  - `tools/check-app.sh`
- Modify:
  - `Makefile`: target `menubar`, PowerPC only. It builds `build/ppc/tsppc.app` from `macos/menubar/*.m` plus the C objects for `ipc.c`, `ipc_reply.c` and `menubar/model.c`, and fails clearly on a host without gcc-4.0.
  - `tools/vm-test.sh`: the `leopard` run also does `make menubar`.

**Behaviour:**
- **Bundle:** `Info.plist` has `LSUIElement` set to `1` (no Dock icon), `CFBundleIdentifier` `org.tsppc.menu`, `CFBundleName` `tsppc`, `CFBundleExecutable` `tsppc`, and `LSMinimumSystemVersion` `10.4.0`.
- **Icon:** a 16×16 image drawn at runtime with `NSBezierPath`, one per `ts_menu_icon`, our own design: a ring that is filled for ON, hollow for OFF, dashed for BUSY, and has a dot for ATTENTION and a bar for ERROR. No image files.
- **Polling:**
  - An `NSTimer` added to the run loop for both `NSDefaultRunLoopMode` and `NSEventTrackingRunLoopMode` polls `status` with `ts_ipc_request`, timeout 2000 ms.
  - The interval is 5 s, or 15 s after 6 identical replies in a row.
  - It goes back to 5 s, with an immediate poll, after any action and while the state is `CONNECTING`, `NEED_LOGIN` or `AWAIT_APPROVAL`.
- **Menu:** rebuilt from `ts_menu_build` only when the model changed, compared with `memcmp` on the previous model.
- **Actions:**
  - COPY puts `arg` on the general pasteboard as a string.
  - UP and DOWN send `up` or `down`, then poll.
  - LOGIN shows an `NSAlert`: "Open this link on any other device to log in:" with the URL as informative text, and buttons "Copy Link" and "Close". Copy Link copies the URL.
  - LOGOUT shows an `NSAlert`: "Log out of the tailnet?" with buttons "Log Out" and "Cancel". It sends `logout` only on "Log Out".
  - QUIT calls `[NSApp terminate:]`. The daemon is untouched.
- **Errors:** a failed `up`, `down` or `logout` (error reply or request failure) shows an `NSAlert` with the cleaned error text.

**`tools/check-app.sh <app>`** fails if any of these hold:
- the binary or `Info.plist` contains `Tailscale` (case-insensitive);
- the binary is not `ppc`;
- it links anything other than Cocoa, Foundation, AppKit and libSystem (`otool -L`);
- its undefined symbols (`nm -u`) include any name-lookup or network API: `getaddrinfo`, `gethostbyname`, `sendto`, `recvfrom`, `bind`, `listen`, `accept`, or any `NSURL*`, `CFNetwork`, `CFSocket` or `CFStream` symbol;
- these are allowed: `socket`, `connect`, `read`, `write`, `select`, `close` and `fcntl`, for the Unix socket.

- [ ] **Step 1:** Write `tools/check-app.sh` first. Running it against `/bin/ls` must fail, because that is not a bundle.
- [ ] **Step 2:** Write the app and the Makefile target.
- [ ] **Step 3: Run** `TSPPC_SSH_CONFIG=~/.ssh/tsppc_vm.d/config tools/vm-test.sh leopard`. Expected:
  - all tests pass;
  - `build/ppc/tsppc.app` is built with no warnings;
  - `check-app.sh` passes;
  - `check-release.sh` and `check-ct.sh` still pass.
  - Don't run this while a live acceptance daemon runs from `build/ppc`. Stop that daemon first, or copy its binary elsewhere before rebuilding.
- [ ] **Step 4: Commit** `Add the menu bar app`.

### Task 6: Live acceptance on Leopard and Tiger (owner present)

**Files:** Create `docs/menu-bar-check.md`.

**Setup:**
- Install the new `tsppcd` and `tsppc` from this branch, keeping `/var/db/tsppc`. This tests the version 1 state compatibility live: both nodes must come back with no new login.
- Copy `tsppc.app` to `~/Applications` on each VM.
- Launch it in the console session: `sudo launchctl bsexec <loginwindow pid> sudo -u <user> open ~/Applications/tsppc.app` (10.4 uses `open` from the console user's own Terminal if `bsexec` is missing).
- Screenshots: `screencapture -x` run through the same `bsexec`.
- Driving clicks needs either UI scripting or the owner:
  - UI scripting means "Enable access for assistive devices", a VM setting. Ask the owner before turning it on.
  - Otherwise the owner clicks while I take screenshots.
- Turn off Leopard's screen saver for the session, with the owner's OK.

- [ ] **Step 1:** On Leopard, as the admin user, confirm and screenshot each of these:
  1. Connected: icon ON, `Connected`, device list matches `tsppc status`, and online count right.
  2. Click a device: `pbpaste` (through `bsexec`) prints its IP.
  3. Disconnect: `Disconnected`, and `tsppc status` agrees.
  4. Restart `tsppcd`: still `Disconnected`.
  5. Connect: `Connected` with no login.
  6. Stop `tsppcd`: `tsppcd is not running`. Start it: back to `Connected` within 15 s.
  7. Idle CPU: the app's `ps -o time` grows by less than 3 s over 10 minutes.
- [ ] **Step 2:** On a test admin account created for the check, with the owner's OK, or by temporarily removing the socket's group permission: `Needs an administrator account`.
- [ ] **Step 3: Login flow, done last, because it needs the owner to log in again.** Do this only on Leopard, only if the owner agrees:
  - Log Out... → confirm → `Not logged in`.
  - Connect → `Login needed` → Log In... alert → Copy Link → `pbpaste` shows the URL.
  - The owner logs in and approves → `Waiting for approval...` then `Connected`.
- [ ] **Step 4:** Repeat Step 1 on Tiger.
- [ ] **Step 5:** Write `docs/menu-bar-check.md` with the OS builds, commit, steps and results, using placeholders for every name and IP. Commit `Record menu bar app check`, then push.
