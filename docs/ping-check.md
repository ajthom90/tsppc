# Ping check (relay-only `tsppc ping`)

**Date:** 2026-11-12.

**Verdict: PASS.** `tsppc ping` behaves like `tailscale ping` over DERP relays on both Leopard and Tiger, and tsppc now answers disco pings, so the official client's `tailscale ping` reaches both tsppc nodes.

**Build:** branch `ping` at the Task 3 fix round (`78a2ede`), built on the Leopard VM by `tools/vm-test.sh leopard` (3638 checks, check-release, check-ct and check-app passed). Both VMs ran the same files (SHA-1 `tsppcd` `c64ef0e0dc56a35e1f2e19df1e821a811e0df36f`, `tsppc` `265482f2577eacdaa19ed7bd4eace02fdaf5798f`).

**Machines:** as in `docs/tunnel-check.md`. Placeholders: `<leopard>`, `<tiger>`, `<host>` (the Mac running the official client), `<offline>` (a tailnet node that was offline), `<region>` (the relay region both VMs and the host used), `100.x.y.z` for addresses.

## Results

| Command (on) | Output | Exit |
|---|---|---|
| `tsppc ping <tiger>` (`<leopard>`) | 10 lines `pong from <tiger> (100.x.y.z) via DERP(<region>) in 40–50ms`, then `direct connection not established` | 1 |
| `tsppc ping -c 3 --until-direct=false <tiger>` (`<leopard>`) | 3 pong lines | 0 |
| `tsppc ping -c 3 <host>` (`<leopard>`) | 3 pong lines, then `direct connection not established` | 1 |
| `tsppc ping -c 3 <leopard>` (`<tiger>`) | 3 pong lines, then `direct connection not established` | 1 |
| `tsppc ping -c 2 --until-direct=false <host>` (`<tiger>`) | 2 pong lines | 0 |
| `tsppc ping -c 2 --timeout 1s <offline>` (`<leopard>`) | `ping "100.x.y.z" timed out` twice, then `no reply` | 1 |
| `tsppc ping <own address>` (`<leopard>`) | `100.x.y.z is local Tailscale IP` | 0 |
| `tsppc ping -c 1 100.64.0.99` (no such node) | `no matching peer` | 1 |
| `tsppc ping -c 1 no-such-name` | `no peer named "no-such-name"` | 1 |
| A fifth ping while four pings to `<offline>` were pending | `too many pings in progress`; `tsppc status` still answered | 1 |
| `tailscale ping -c 3 <leopard>` and `<tiger>` (`<host>`, official client) | 3 lines `pong from <node> (100.x.y.z) via DERP(<region>) in 33–44ms` each, then `direct connection not established` | 1 |

Latency through the relay was 33–50 ms in both directions, the same range the official client measured to the same nodes. Every pong came through the relay: there are no direct paths until milestone 8, so `direct connection not established` after the default 10 pings is the expected ending, as it is for the official client.

Before this work, the official client's pings to a tsppc node timed out: tsppc dropped every disco packet.
