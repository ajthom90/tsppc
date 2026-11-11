# Control session check (milestone 3)

**Date:** 2026-11-10 to 2026-11-11.

**Build:** commit `824f1b1`. The binaries are the release build (`make ppc CC=gcc-4.0`, without test hooks), made on the Leopard VM. Tiger ran the same binaries, copied from Leopard: `tsppcd` SHA-1 `c7c81566cdf05fe60476a65981e7ff742b0c4410`, `tsppc` SHA-1 `7bff05c56b442c90d3d1bb6388ac39e0664a87dd`.

**Machines:** both are emulated G4s in UTM, using shared (NAT) networking.
- Mac OS X 10.5.8 (9L31a)
- Mac OS X 10.4.11 (8S165)

**Tailnet:** the owner's regular hosted tailnet, with device approval turned on. Names, addresses and the tailnet are written here as placeholders, such as `<peer>` and `100.x.y.z`.

**Version:** capability version 150. Hosted Tailscale accepted it on these dates. That acceptance lasts only as long as the service's policy does, so a later rejection must show in `tsppc status` (see `docs/capver-review.md`).

## Commands

All commands ran on the VM over SSH. The state was in the default location, `/var/db/tsppc`, created fresh on each VM.

```
sudo sh -c "nohup ./tsppcd >>/var/log/tsppcd.log 2>&1 </dev/null &"
nohup ./tsppc up >/tmp/tsppc-up.out 2>&1 </dev/null &
./tsppc status
ps -axo pid,rss,etime,command | grep tsppcd
```

These were run once a minute for 65 minutes from the host: `tsppc status`, and `ps -o rss` of `tsppcd`.

## Results

| Check | Leopard 10.5.8 | Tiger 10.4.11 |
|---|---|---|
| Control key fetch (TLS 1.2 to `/key`) | 814 ms | 516 ms |
| `up` to login needed | `NEED_LOGIN` with a `https://login.tailscale.com/a/<id>` link | same |
| Login, then device approval | `NEED_LOGIN` → `AWAIT_APPROVAL` → `RUNNING`, about 6 s after approval, no restart | `NEED_LOGIN` → `AWAIT_APPROVAL` → `RUNNING`, about 4 s, no restart |
| Node online in the tailnet | yes, shown online with OS `macOS` by the owner's other Tailscale client | yes, same |
| Peers in `tsppc status` | 14. Every peer's IPv4, online flag and name matched the owner's official client exactly. | 14, the same list |
| Each Mac sees the other | yes, within a minute of the second one joining | yes |
| One hour `RUNNING` | 66 of 66 samples `RUNNING` (07:48 to 08:56) | 66 of 66 samples `RUNNING` (07:52 to 08:58) |
| Resident memory (`ps -o rss`) | 868 to 876 KB, flat | 1476 KB, flat |
| A peer goes offline, then back | the owner turned off a laptop's Tailscale: `offline` within a minute, `online` again about 20 s after it reconnected | same, at the same times |
| Daemon restart (`SIGTERM`, start) | `RUNNING` 2.1 s after start, same node (same key expiry), no login | `RUNNING` 1.3 s after start, same node, no login |
| `en0` down for 120 s (detached `ifconfig en0 down; sleep 120; ifconfig en0 up`) | `BACKOFF: control stopped responding` after the keepalive timeout, then `BACKOFF: DNS lookup of the control server failed` while offline, then `RUNNING` about 2 s after the link returned, no login | same sequence, `RUNNING` about 4 s after the link returned, no login |

Leopard had also been waiting at `NEED_LOGIN` for 15 hours overnight before the owner logged in, at under 1 MB, and the login link still worked. CPU time over its first 16 hours was about 14 s.

## Notes

- **Detection time.** Dead-link detection took about 115 s after the cut. That matches the design: a PING after 90 s of silence, and a disconnect 30 s later if there is no answer. Wake from sleep and network changes are not detected faster yet. That work belongs to milestone 7's conditions table.
- **Port fallback.** In these runs the control connection used port 80 each time. Port 443 was tried during the outage, and failed at the same DNS step.
- **Possible false pass in later tunnel tests.** UTM's shared networking lets the guests reach `100.x` addresses through the host Mac's own Tailscale client. Tunnel milestones must prove that traffic goes through tsppc's interface.
