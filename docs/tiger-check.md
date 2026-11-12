# Tiger check (milestone 6)

**Date:** 2026-11-12.

**Verdict: PASS.** Milestones 4 (tunnel over DERP with filter) and 5 (services) pass on the Tiger VM. This run fills the gaps left on Tiger by `docs/tunnel-check.md` and `docs/services-check.md`. The Tiger results already recorded there are not repeated here. They are: start on existing state, `tun0` and routes, pings both ways, path counters, rekeying, sending the filter test packets, SSH both ways, and serving AFP.

**Build:** `main` at `1a085b2` (relay-only `tsppc ping` merged), built on the Leopard VM by `tools/vm-test.sh leopard` (3640 checks, check-release, check-ct and check-app passed). Both VMs ran the same files: SHA-1 `tsppcd` `599f060f9bd08688e5dc2a8fd1bda78e5df9cec4`, `tsppc` `5ee76117932e713a2d15e417e4f78af386c06eba`. The kext was not changed.

**Machines:** as in `docs/tunnel-check.md`. Mac OS X 10.4.11 on an emulated G4 in UTM, with shared (NAT) networking. Placeholders: `<tiger>`, `<leopard>`, `<host>` (the Mac running the official client), `100.x.y.z` for addresses.

## Tunnel, with Tiger receiving

One `tcpdump -i tun0` on `<tiger>` captured TCP ports 81 and 22, ICMP and IP protocol 253. A second, `tcpdump -i en0 host <tiger's tailnet address>`, ran alongside it.

| Check | Result |
|---|---|
| TCP SYN from `<host>` (official client) to closed port 81 | SYN on `tun0` with MSS 1240, RST back on `tun0`. `nc` reported the port closed |
| TCP from `<host>` to `<tiger>`'s sshd | full handshake, banner `SSH-1.99-OpenSSH_4.5`, FIN exchange, all on `tun0` |
| 10 raw IPv4 packets of protocol 253 from `<leopard>` (root, throwaway script), then 3 ICMP pings | none of the 10 on `<tiger>`'s `tun0`. `<tiger>`'s `tsppc status` went from `filter: ok dropped 0` to `filter: ok dropped 10`. 3 of 3 pings answered, requests and replies on `tun0` |
| `en0` for the whole run | no packets to or from `<tiger>`'s tailnet address |

The policy allows only TCP, UDP, ICMP and ICMPv6, so protocol 253 is the denial a live peer can send without a policy change. In the milestone 4 check, `<leopard>` was the receiver and `<tiger>` the sender. This run covers the other direction.

## Stop and crash on Tiger

| Step | Result |
|---|---|
| `SIGTERM` | the log shows `stopping on a signal`, `data plane stopped (shutting down)` and `hosts file: peer names removed` within 0.2 s, and the process was gone. `tun0` gone, no `100.64/10` route, `route get <leopard>` names `en0`, no names block in `/etc/hosts` |
| Start | `RUNNING` with tunnel `tun0` and names written within 2 s of launch. 3 of 3 pings to `<leopard>` |
| `kill -9` | `tun0` and its routes gone at once: the driver removes the interface when its descriptor closes. The names block stays behind (expected) |
| Start | the log shows `hosts file: peer names removed`, then `15 peer names written`. No `/etc/.hosts.tsppc.*` temporary files. 3 of 3 pings |
| Stale route planted while stopped (`route -n add -net 100.64.0.0/10 127.0.0.1`, so the route pointed at `lo0`), then start | `100.64/10` on `tun0`, `route get <leopard>` names `tun0`. 3 of 3 pings |

The milestone 4 notes recorded that Tiger's milestone 12 daemon took more than 10 s to exit after `SIGTERM`. That no longer happens.

## Names on Tiger

The milestone 5 check could not show that Tiger resolves a name from the hosts file. Tiger's own resolver query does, from an SSH session: `lookupd -q host -a name <leopard>`, with the short name.

| State | `lookupd -q host -a name <leopard>` |
|---|---|
| `tsppc down` (block removed, `names: off`), then `lookupd -flushcache` | `query failed!` |
| `tsppc up` (`names: 15 names`) | `ip_address: 100.x.y.z`, `name: <leopard>.<suffix> <leopard>` |

The guests' DNS answers full tailnet names through the host's own Tailscale (see `docs/services-check.md`, "Test environment caveat"). On Tiger, though, it does not answer the short name. So the short name resolves only through the block, and the record carries both names, as the block's line does. The owner's part of `/etc/hosts` was unchanged.

## File sharing with Tiger as the client

The milestone 5 run mounted AFP with Tiger as the server. Tiger's AFP client could not mount from an SSH-only session (see `docs/services-check.md`), so this run used SMB, the other protocol the spec allows. Tiger's `mount_smbfs` works without a login session.

**Server:** a temporary `smbd` on `<leopard>` (Samba 3.0.25b, the copy in Mac OS X). It ran from its own configuration file under `/var/tmp` and listened only on `<leopard>`'s tailnet address (`socket address`). It served a guest share with `security = user`, `map to guest = Bad User` and `vfs objects =` set empty. Leopard's sharing settings and system Samba configuration were not touched. Afterwards the server was stopped and its directory deleted.

| Step | Result |
|---|---|
| `mount_smbfs -N -I <leopard's tailnet address> //guest:x@<server name>/<share> /tmp/smbm` on `<tiger>` | mounted (`//WORKGROUP;GUEST@...`) |
| Write: `cp` of a 20 MB random file from `<tiger>` to the share | 38 s, MD5 matched on `<leopard>` |
| Read: `md5` of a 20 MB random file on the share, from `<tiger>` | 924 s, MD5 matched |
| `umount` | clean |
| Captures on `<leopard>` | 87,840 packets on ports 139 and 445 on `tun0`, starting with `<tiger>`'s tailnet address to port 139. No packets for `<tiger>`'s tailnet address on `en0` |

**The slow read is SMB, not the tunnel.** Tiger's SMB client asked this server for 1 KB at a time, one request per round trip. 924 s over 20,480 reads is 45 ms each, the relay round trip that pings measure. Writes over the same mount ran at the same speed as AFP did in milestone 5. No tuning of the client or server was tried. People who share files between old Macs over the relay should prefer AFP.

**Getting there:**
- Mac OS X's Samba ignored `interfaces` for `tun0` ("no network interfaces found"). It needs `socket address`.
- Started from an SSH session, `smbd -D` treated its standard input as an inetd socket. It needs `</dev/null`.
- With `security = share`, Apple's `smbd` crashed at the share connect.
- Tiger's `mount_smbfs -N` refuses a guest with no password, and a guest with an empty password (`guest:@`) waits for a password prompt. A dummy password (`guest:x@`) works.

## Leftovers

None. Removed: the test files, packet captures and scripts on both VMs; the temporary Samba directory, including the core file from the `security = share` crash; Tiger's `/tmp/smbm`. Both daemons were left running this build, with the tunnel up.
