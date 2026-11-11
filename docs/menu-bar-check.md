# Menu bar app check (milestone 12)

**Date:** 2026-11-11.

**Build:** commit `8dcada0`, built on the Leopard VM by `tools/vm-test.sh leopard`. That run passed 1684 checks, check-release (both programs), check-ct and check-app. Tiger ran the same files, copied from Leopard. SHA-1 hashes:

| File | SHA-1 |
|---|---|
| `tsppcd` | `9d243f44fef6eb29b4448f7a44e8b08be7d7ed53` |
| `tsppc` | `a573a08be7be677ac43a9fb0e18ea66b40596e19` |
| `tsppc.app/Contents/MacOS/tsppc` | `e3304cfa1c85d508919b1721b15f5c0b0370fc17` |

**Machines:** emulated G4s in UTM.
- Mac OS X 10.5.8 (9L31a)
- Mac OS X 10.4.11 (8S165)

Both were already logged in to the owner's tailnet from the milestone 3 check. Names and addresses below are placeholders.

## How it was driven

- **Starting the new daemon:** stop the milestone 3 daemon, then start the new `tsppcd` on the same `/var/db/tsppc`.
- **Launching the app:** `open ~/Applications/tsppc.app` in the console user's session. On Leopard this used `launchctl bsexec <loginwindow pid>` from SSH. On Tiger, `open` ran straight from SSH.
- **Clicks and keys:** NSStatusItem menus are not visible to UI scripting on 10.5, so a small test-only tool posted mouse and key events with `CGPostMouseEvent` and `CGPostKeyboardEvent`. That tool is not in the repository.
- **Screenshots:** `screencapture -x`.
- **Clipboard:** read with `pbpaste` in the console session on Leopard. On Tiger an SSH session cannot read the console user's pasteboard, so the copied text was pasted into Spotlight with Command-V and photographed.

## Results

| Check | Leopard 10.5.8 | Tiger 10.4.11 |
|---|---|---|
| New daemon on the old (version 1) state file | `RUNNING` 1.3 s after start, same node, no login | `RUNNING` 2 s after start, same node, no login |
| Icon and menu while connected | filled ring; `Connected`, `This Mac: <name> (100.x.y.z)`, `Disconnect`, `Devices (13 online)`, `Log Out...`, `Quit tsppc` | same |
| Devices submenu | matches `tsppc status`: 13 online in name order, then `<peer>  100.x.y.z (offline)` last | same |
| Click a device | its IP is on the pasteboard | not repeated (the same code path as "This Mac") |
| Click "This Mac" | its IP is on the pasteboard | pasted into Spotlight: the node's IP |
| Disconnect | hollow ring, `Disconnected`, `Connect`; `tsppc status` agrees | same |
| Restart `tsppcd` while down | stays `Disconnected` | same |
| Connect | `RUNNING` in under 1 s, same node, no login | `RUNNING` in 2 s, same node, no login |
| Stop `tsppcd` | ring with a bar, `tsppcd is not running`, `Quit tsppc` | same; back to `Connected` on its own after the daemon restarted |
| Socket without group access (mode 0600 for under a minute, then restored) | `Needs an administrator account` | not repeated |
| Log Out... | the dialog "Log out of the tailnet?". Cancel left it connected. Log Out gave `Not logged in` with `Connect` | not done (owner's choice) |
| Connect, then Log In... | `Login needed` and `Log In...`. The dialog shows the link, and Copy Link put it on the pasteboard. The owner logged in from that link | not done |
| After login | `Connected`, same tailnet IP. The tailnet did not ask for approval again: it keys approval to the machine key, which a logout keeps. So `Waiting for approval` was not seen live here. Host tests cover it, and milestone 3 showed the daemon side live | not done |
| App CPU over 10 idle minutes | 0.36 s (limit 3 s), about 5.5 MB resident | 0.51 s, about 14.5 MB resident (Tiger's AppKit maps more) |

## Issues found

Both are fixed in `baba749`, with host tests. That build passed `vm-test.sh leopard` (1690 checks, check-release, check-ct and check-app). Its app has SHA-1 `174389becc34c6d6b4f63adf7d1c5cac42ff3d2c`, and it was installed on both VMs. On Leopard the menu was then checked on screen in both states:
- Disconnected: `Disconnected`, `Connect`, `Log Out...`, `Quit tsppc`, with no peers.
- Connected again: the full menu, `Devices (14 online)`.

## After the final review

The final review's fixes are in commit `b0664b8`. That build passed `vm-test.sh leopard` (1744 checks, check-release, check-ct and check-app). These were installed on both VMs:

| File | SHA-1 |
|---|---|
| `tsppcd` | `b2d4bb68117abc30bd12d1907815907d7bc08e17` |
| `tsppc` | `cd4903133bdd8f2ad013b34fa11dfb586f5ecb60` |
| `tsppc.app/Contents/MacOS/tsppc` | `645576bc552c19c5952f69667d67f0ad894de91c` |

Results:
- Both daemons came back `RUNNING` within 2 s, as the same nodes, with no login.
- **A state change while the menu is open (Tiger).** The menu was open when `tsppc down` ran from SSH. The open menu kept its items, and the icon changed to the hollow ring at once. Closed and reopened, it showed `Disconnected`, `Connect`, `Log Out...` and `Quit tsppc`. After `tsppc up` it was back to `RUNNING`.
- **Not seen live, covered by host tests.** These states need an expired key, a control failure or a long problem text:
  - the new `Log In Again...` and `Try Again` items;
  - the tooltip with the full problem text.

- **Connect and Disconnect at once.** In `Login needed` after a Connect, the menu showed both items. That is the plan's table read literally: "login no" gives Connect, and "wanted up" gives Disconnect. Connect now appears only when the node is not meant to be up.
- **Stale peers while down.** Right after Disconnect, the menu still listed `This Mac` and `Devices` from the last map until the daemon restarted. They are now hidden while the node is meant to be down.
