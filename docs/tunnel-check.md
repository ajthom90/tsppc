# Tunnel check (milestone 4)

**Date:** 2026-11-12.

**Verdict: PASS.** IPv4 traffic between the two tsppc nodes, and between each of them and a peer running the official Tailscale client, goes through tsppc's WireGuard over a DERP relay. Nothing in the code had to change for the first check. A second run after the final review's fixes (see "Final fixes") showed sessions surviving rekeys for more than 6 minutes with no loss, and the packet filter dropping a protocol the tailnet's policy does not allow, with no policy change.

**Milestone numbers** follow the roadmap in `docs/superpowers/specs/2026-11-10-tailscale-ppc-design.md`, not the order of the work: the menu bar app (milestone 12) was built before this tunnel (milestone 4), so "the milestone 12 build" below is the build that ran before this one.

**Build:** commit `eed8091`, built on the Leopard VM by `tools/vm-test.sh leopard`. That run passed 2943 checks, check-release (both programs), check-ct and check-app. The kext was rebuilt with `tools/driver.sh build` on Leopard. Tiger ran the same files, copied from Leopard through the host. SHA-1 hashes:

| File | SHA-1 |
|---|---|
| `tsppcd` | `8671424daa447912dc70054128afa53f4aa32912` |
| `tsppc` | `02adabca1bd4a5b8a818cf1504c8f83880fd6339` |
| `tun.kext/Contents/MacOS/tun` | `0df7d18daba83aaaf966f3d3eb880a3aade7c657` |

**Machines:** emulated G4s in UTM, with shared (NAT) networking.
- Mac OS X 10.5.8 (9L31a)
- Mac OS X 10.4.11 (8S165)
- The host Mac, running the official Tailscale client on the same tailnet, as the third peer.

Both VMs were already logged in to the owner's tailnet from the milestone 3 check. Names, addresses and relay regions below are placeholders: `<leopard>`, `<tiger>` and `<host>` for the three nodes, `100.x.y.z` for an address, `<region>` for the relay.

## How it was run

Install, on each VM (the old binaries were kept in `~/tsppc-run/prev/`):

```
sudo env TSPPC_KEXT=<dir>/build/driver/tun.kext <dir>/tools/driver.sh load
sudo kill <tsppcd pid>
cd ~/tsppc-run && sudo sh -c "nohup ./tsppcd >>/var/log/tsppcd.log 2>&1 </dev/null &"
```

Checks:

```
./tsppc status
ifconfig tun0
netstat -rn -f inet
route -n get <peer's tailnet IP>
sudo tcpdump -n -l -i tun0 icmp      # and the same on en0, on the receiving VM
ping -c 5 <peer's tailnet IP>
ps -axo rss,command
```

Proof that traffic went through tsppc, and not through UTM's NAT to the host's own Tailscale client:
- the receiving VM saw each echo request on `tun0`, and nothing on `en0`;
- the `path` counters for that peer in `tsppc status` rose on both sides;
- `route get` for the peer's address named `tun0`;
- inbound traffic from the host's client reached the VMs, which NAT cannot deliver.

## Results

| Check | Leopard 10.5.8 | Tiger 10.4.11 |
|---|---|---|
| Start on the existing state | `RUNNING` with the same node (same key expiry), no login. `tunnel tun0 up` at 1.7 s, home relay connected at 7.2 s | same; `tunnel tun0 up` at 1.5 s, relay at 7.0 s |
| `tsppc status` | `tunnel: tun0`, `relay: <region> connected`, `filter: ok` | same |
| `ifconfig tun0` | `inet 100.x.y.z --> 100.x.y.z netmask 0xffffffff`, `mtu 1280`, `UP,POINTOPOINT,RUNNING` | same |
| `netstat -rn` | `100.64/10  tun0  USc` and a host route for its own address on `tun0` | same |
| Ping the other VM, 5 packets | 5 of 5; first 102 ms (handshake), then 38 to 48 ms | 5 of 5, 35 to 46 ms |
| On the receiving VM | 5 echo requests and 5 replies on `tun0`, none on `en0` | same |
| `path` for the other VM | none before; `relay <region>  rx 6 tx 6` after the first run, `rx 11 tx 11` after the second | same |
| `<host>` pings the VM (ICMP, 5 packets) | 5 of 5, 34 to 82 ms; 5 requests on `tun0`; `path` for `<host>` none, then `rx 5 tx 6` | 5 of 5, 34 to 86 ms; same counts. A later run raised them to `rx 13 tx 15` |
| TCP SYN from `<host>` and `<tiger>` to a closed port | SYN on `tun0`, RST back | not repeated |
| TCP from `<host>` to sshd | full handshake and the SSH banner over `tun0`, MSS 1240 | not repeated |
| Resident memory while pinging both ways | 1664 to 1668 KB, flat | 2188 KB at start, 2232 KB while pinging |

The counters count IP packets, including the TSMP disco advertisement (a 53-byte IPv4 packet with a 33-byte payload) each side sends as the first packet on a new keypair. That is why 5 pings between the VMs show 6 each way. The host's client did not send one to us (`rx 5`), and tsppc did send one to it (`tx 6`).

`tailscale ping <VM>` from the host timed out, as expected: it uses disco, which tsppc does not run until milestone 8. Plain ICMP `ping` works.

## Filter

`tsppc status` reports `filter: ok` on both VMs. The daemon does not log or report the number of rules. The host's client was used to read the shape of the tailnet's policy, without recording its contents. Its packet filter has 2 rules: one allows every port (0 to 65535) for TCP, UDP, ICMP and ICMPv6, and its sources include all three test nodes; the other grants only capabilities and matches no packets. The VMs receive filters compiled from the same policy, and both accept every connection tried above.

Nothing from the test peers to the VMs is denied by port, so the first run could not check a denial live. The policy only allows TCP, UDP, ICMP and ICMPv6, though, so the final-fixes run sent packets of IP protocol 253 instead, with no change to the policy: Leopard's filter dropped them all (see "Final fixes"). The denial path is also covered by the host tests for the filter (Task 1: `tests/test_filter.c`) and for the data plane (Task 7: `tests/test_dataplane.c`).

## Stop and crash (Leopard)

| Step | Result |
|---|---|
| `SIGTERM` | exited in about 2 s. Log: `stopping on a signal`, `data plane stopped (shutting down)`. `tun0` no longer exists, no `100.64/10` route, `route get <tiger>` names `en0` |
| Ping `<tiger>` after the stop | still answers, through `en0`: UTM's NAT and the host's own Tailscale. This is the false path described in `docs/control-session-check.md`, and why the checks above rely on `tun0` |
| Start, then `kill -9` | after the kill, `tun0` and its routes were already gone: the driver removes the interface when its descriptor closes. No stale route was left |
| Start again | `RUNNING`, `tunnel tun0 up` at 2.3 s, relay at 7.8 s; route on `tun0`; 5 of 5 pings to `<tiger>` |
| Stale route planted (`route -n add -net 100.64.0.0/10 127.0.0.1` while stopped, so the route pointed at `lo0`), then start | the route was replaced, with nothing logged (the daemon's first add fails on an existing route, so it quietly deletes it and adds again): `100.64/10` on `tun0`, `tunnel tun0 up` at 1.6 s, 5 of 5 pings |

Both daemons were left running with the tunnel up and the kext loaded.

## Notes

- **Relay only.** Every packet went through one relay region, the home region of all three nodes. Between the VMs, pings took 35 to 48 ms after the first; from the host, 34 to 86 ms with the first included. All of it is relay round trips. Direct paths come in milestone 8.
- **First packet.** The first ping of a new session takes about 100 ms, for the handshake through the relay.
- **Tiger's old daemon.** When it was replaced, the milestone 12 daemon took more than 10 s to exit after `SIGTERM`. The new daemon on Leopard exited in about 2 s on the SIGTERM test.
- **Tiger's menu bar app** is still the milestone 12 build, talking to the new daemon. Its UI was not checked in this milestone.

## Final fixes (second run)

**Build:** commit `f79afad` plus the docs, built on Leopard by `tools/vm-test.sh leopard` (3061 checks, check-release, check-ct and check-app passed). Both VMs ran the same release files (SHA-1 `tsppcd` `d569548c9eb46ecb5ce0b477de3b8aeb99d0a7e7`, `tsppc` `37c737389fb21b5357b34185c9b1115e26b6d86d`); the kext was not changed. The old binaries were kept in `~/tsppc-run/prev-1b87fb0/`.

**Control's clock.** Hosted control sends `ControlTime`: both daemons logged `control time received` before the data plane started (the value is not logged). Peer key expiry is therefore checked against control's clock (`docs/known-limits.md`).

**Rekeying (B1).** Three 400-packet pings at once, one a second (6 min 40 s): `<leopard>` to `<tiger>`, `<tiger>` to `<leopard>`, and `<host>` (official client) to `<leopard>`. The handshake age in the raw `path` lines was sampled every 12 s.

| Path | Loss | Handshake age reset (rekeys) | Counters at the end |
|---|---|---|---|
| `<leopard>` to `<tiger>` and back | 0 of 400 | at about 120 s, 240 s and 360 s, the same on both sides | `rx 804 tx 804` on both: 800 pings plus 4 TSMP adverts, one per keypair |
| `<tiger>` to `<leopard>` | 0 of 400 | (the same session) | |
| `<host>` to `<leopard>` | 0 of 400 | at about 120 s, 240 s and 360 s | `rx 401 tx 405` on `<leopard>` |

`<leopard>` initiated the session with `<tiger>`, so tsppc rekeyed as initiator there and `<tiger>` as responder; the host's client initiated its session, so `<leopard>` was the responder to the official client's rekeys. A session that is never rekeyed is refused after 180 s, so traffic without loss past 6 minutes needs the rekeys. `en0` on `<leopard>` saw no ICMP for `<tiger>` during the run. An SSH session from `<host>` to `<leopard>`'s tailnet address stayed open for 7 minutes, printing `date` every 30 s (read-only commands).

**Filter denial (B4).** The policy allows TCP, UDP and ICMP only. As root on `<tiger>`, a throwaway Python script (not in the repository) sent 10 raw IPv4 packets of protocol 253 to `<leopard>`'s tailnet address; then 3 ICMP pings as a positive control. One `tcpdump -i tun0 'icmp or ip proto 253'` ran on `<leopard>`, and `tcpdump -i tun0 'ip proto 253'` on `<tiger>`.

| Check | Result |
|---|---|
| `<tiger>`'s `tun0` | the 10 protocol-253 packets left with `<tiger>`'s tailnet source |
| `path` counters | `<tiger>` tx +14, `<leopard>` rx +14 (10 + 3 pings + 1 TSMP advert after a rekey) |
| `<leopard>`'s `filter` line | `ok dropped 0` before, `ok dropped 10` after |
| `<leopard>`'s `tun0` | the 3 echo requests and 3 replies only; no protocol-253 packet |

So the packets reached `<leopard>`'s data plane, WireGuard accepted them, and the filter dropped every one before the tun device. Both daemons were left running with the tunnel up.
