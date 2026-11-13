# Install and conditions check (milestone 7)

**Date:** 2026-11-12.

**Verdict: PASS on Leopard and Tiger, with one row pending.**
- Installing from the package, launchd at boot, reboot with no login, and uninstall with nothing left behind all pass on both systems.
- Each row of the conditions table passes on both, except node key expiry. That row needs the owner to expire a key in the admin console and is not done yet; see "Node key expired".
- A real sleep was not attempted; see "Sleep and wake".

**Build:** branch `install` at `c223ae9`, built on the Leopard VM by `make package` (check-release, check-app and check-pkg passed; check-pkg reported 24 payload paths). `tools/vm-test.sh leopard` passed 3838 checks on the same tree, and Tiger ran the same test binary (3655 checks; the end-to-end daemon tests are skipped on Tiger as always, because the daemon binaries are not copied there). SHA-256:
- `tsppc-0.1.0.dmg` `7bec10cea6f6be1d16968da56e996084a7b70689a7d20459957f2b020bd4267e`
- `tsppc-uninstall` `20ede36d2e4bcfe501654093deb755d0805049cc31d224fa7b1e84cdf52033e5`

Two log and output changes made after this run (`7ae879a`) are not in this build:
- A backward clock step is logged as `wall clock set back <n> s`, not `woke from sleep`.
- The uninstaller no longer prints Leopard `pkgutil`'s "No receipt" line.

**Machines:** as in `docs/tunnel-check.md`, emulated G4s in UTM with shared (NAT) networking, Mac OS X 10.5.8 and 10.4.11. Placeholders: `<leopard>`, `<tiger>`, `100.x.y.z`. Both VMs used the persistent tailnet identities from earlier milestones; no new login or approval was needed at any point.

Installs used the command-line installer: `sudo installer -pkg tsppc-0.1.0.pkg -target /` from the mounted `.dmg`. The disk image was copied to Tiger through the host.

## Foreign driver first (Leopard)

- **Setup:** the development `foo.tun` kext was loaded and its daemon stopped.
- **Install:** the launchd daemon (parent process 1) opened the existing `/dev/tun0` and did not load `tsppc-tun`. `kextstat` showed only `foo.tun`. The daemon came up `RUNNING` with the same node, with the tunnel and names up.
- **`sudo tsppc-uninstall -y`:** exited 0. `foo.tun` stayed loaded. No `tsppcd`, `100.64/10` route or hosts block was left. Every file in the layout and the receipt were removed, and `/var/db/tsppc` was kept.

## Migration and first boot from the package

| Check | Leopard | Tiger |
|---|---|---|
| Development `foo.tun` unloaded, then install | daemon logged `loaded the tunnel driver` at 2.1 s and `tunnel tun0 up`; `kextstat` shows `com.github.ajthom90.tsppc.tun` | same, at 2.0 s: the renamed kext's first load on Tiger |
| Daemon | `/usr/local/sbin/tsppcd -l /var/log/tsppcd.log`, parent launchd, root | same |
| Node | `RUNNING`, same node and key expiry, no login | same |
| Folder modes and ACLs before and after | unchanged: `/` 1775 root:admin, `/Applications` 775 root:admin with its ACL, `/Library` 1775 root:admin with its ACL, `/usr` and `/Library/LaunchDaemons` 755 root:wheel | unchanged (no ACLs on Tiger) |
| Created by the package | `/usr/local`, `/usr/local/bin`, `/usr/local/sbin` and `/Library/Extensions`, all 755 root:wheel | same |

### Start at Login offer

1. The development menu bar app (in `~/Applications`) was quit.
2. `/Applications/tsppc.app` was opened in the console session: on Leopard through `launchctl bsexec` with the loginwindow's PID, on Tiger with `open` straight from SSH.
3. The alert appeared once: `Start tsppc when you log in?`, with the specified text and the buttons `Not Now` and `Start at Login` (default). On Leopard this was confirmed with a screenshot. On Tiger `screencapture` produced nothing from SSH; instead, the `TSLoginItemOffered` default was absent while the alert waited, and set after Return chose the default button.
4. Choosing Start at Login added `{Hide = 0; Path = "/Applications/tsppc.app"}` to the user's `AutoLaunchedApplicationDictionary` and set `TSLoginItemOffered` to 1. On Tiger, the existing iTunes Helper entry (with its alias data) was kept.
5. The old development entry was then removed by hand, as the owner had allowed for Login Items on these VMs.

Postflight's own "open the app for the console user" branch was **not** exercised: command-line installs set `COMMAND_LINE_INSTALL`, which skips it by design.

## Conditions table

| Row | Method | Leopard | Tiger |
|---|---|---|---|
| Daemon restart | `kill -9` of the launchd daemon | launchd started a new one at once; `RUNNING` with names in 3 s; route on `tun0`, hosts block written again (`15 peer names written`) | same, 2 s |
| Reboot | `sudo shutdown -r now` | up about 30 s after boot: `RUNNING`, same node, no login, nobody at the console. The daemon loaded the kext at 9.1 s, tunnel up at 9.2 s, home relay at 14.9 s. The menu bar app started from its Login Item | same; app started from its Login Item |
| Sleep and wake (simulated) | wall clock stepped forward 120 s with `date`, then back with `ntpdate -u` | forward: `woke from sleep (wall clock jumped 119 s)`, control closed and reconnected, `rebinding relays (woke from sleep; sessions reset)`, `RUNNING` again 1.6 s later, 3 of 3 pings to `<tiger>`. Back (-119 s): one rebind without a session reset, `RUNNING` in 2.6 s, 3 of 3 pings | same: `RUNNING` 1.4 s after the forward step and 2.3 s after the step back; pings 3 of 3 both times |
| Network change | `ifconfig en0 alias 10.99.99.99 netmask 255.255.255.255`, then `-alias`, with an SSH session from the host to the VM's tailnet address printing the time every 5 s | each change: `network changed`, control closed and reconnected (BACKOFF, then connected 1.0 to 2.2 s later), relays redialed within 0.6 s, 3 of 3 pings. The SSH session printed all 14 lines over 66 s with no gap | same; the SSH session printed all 14 lines |
| Control unreachable | ipfw rules 6000 and 6001 dropping TCP to and from control's address range on ports 80 and 443 for about 4 minutes | the session noticed after 71 s (its keepalive PING went unanswered) and went to `BACKOFF`. Retries came 1.2, 1.8, 3.9, 7.1, 15.3 and 24.6 s apart, each trying port 80 then 443: exponential with jitter. Pings to `<tiger>` over the relay kept working (3 of 3). Rules removed: `RUNNING` again within 40 s, no login | same: `BACKOFF` after 87 s, retries 1.1, 1.8, 3.3, 6.3, 13.6 and 28.1 s apart, pings kept working, `RUNNING` after the rules were removed |
| Relay unreachable | ipfw rules 6002 and 6003 dropping TCP to and from all six nodes of the home region | `home relay: nothing from the relay for 120 s`, then dial failures, then `home relay failed 3 times: measuring the regions again`. A new home was chosen (another region, 32 ms) and connected 8 s after the first failed dial | same (28 ms) |
| Wrong clock | `date` set to 2020-01-01, then `launchctl stop` (launchd restarted the daemon) | status `BACKOFF: TLS: system clock is wrong`, `Problem: TLS: system clock is wrong`, names off, the control key fetch retried with growing delays. After `ntpdate -u`: `RUNNING` within 16 s, no login | same; `RUNNING` within 26 s |
| Node key expired | the owner expires the VM's key in the admin console | **pending** | **pending** |
| Upgrade | the same package installed over a running install | preflight stopped the old daemon (new PID). The new one came up `RUNNING` with the state file unchanged (same SHA-1) and no login | same |

In the "Relay unreachable" row, pings from `<leopard>` to `<tiger>` failed while blocked: `<tiger>`'s home was the blocked region, and relayed packets go to the peer's home region. That is how relay-only Tailscale works, not a fault: the official client behaves the same with no direct path. Pings recovered when the rules were removed. When `<tiger>`'s turn came, `<leopard>`'s home had already moved, so `<tiger>`'s pings kept working. Home stays on the new region until the next measurement round (every 30 minutes).

The first control-block attempt dropped only outgoing packets. Control's keepalives still arrived, so the session never saw silence and stayed `RUNNING`, which is correct behaviour for that test. The rows above use the run that dropped both directions.

All ipfw rules were removed afterwards; `ipfw list` on both VMs shows only the default rule. Both clocks were left on NTP time.

## Uninstall

`sudo tsppc-uninstall -y` was run twice on each VM: once normally, and once after a crash.

**Normal uninstall.**
- The uninstaller exited 0.
- No `tsppcd`, `100.64/10` route, hosts block or `tsppc-tun` was left.
- No file from the install layout was left, the receipt was removed, and `/var/db/tsppc` was kept.

**After a crash.**
1. The launchd job was unloaded.
2. The daemon was started by hand.
3. It was `kill -9`ed.
4. A stale `100.64/10` route through `lo0` was added.

Before the uninstaller ran, no `tsppcd` was running, the hosts block was present and the `lo0` route was present. The uninstaller exited 0 and ran `tsppcd --cleanup` ("Removed any leftover tsppc route and /etc/hosts block"). Afterwards there was no route, no block, no kext and no files.

**Afterwards on both VMs.**
- The owner's part of `/etc/hosts` is byte-for-byte the same as the copy taken before this milestone (same MD5).
- Apart from tsppc's routes, the routing table differs from that copy only in ARP cache entries.

On Tiger, the first crash attempt was not a valid test. The hand-started daemon did not come up, so there was no block to clean, and that result is not counted. The run above waited for the launchd copy to exit first.

Both VMs were reinstalled from the package afterwards and are running it.

## Sleep and wake

- `pmset sleepnow` was not run. A sleeping UTM guest cannot be reached over SSH, and waking it may need the UTM window.
- The rows above simulate a wake the way the daemon detects one: a jump of the wall clock against the monotonic clock. On real hardware the monotonic clock stops during sleep, so a real sleep produces a forward jump.

## Node key expired

**Pending.** It needs the owner to expire one VM's node key in the admin console, then log the node in again with the URL `tsppc up` prints.

**Already covered by host tests.** The fake control answers `NodeKeyExpired`, and the session treats it as login needed: `tests/test_session.c`. The CLI also shows an expired peer: `tests/test_ipc.c`.
