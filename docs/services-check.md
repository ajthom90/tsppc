# Services check (milestone 5)

**Date:** 2026-11-12.

**Verdict: PASS.** SSH works in both directions between the two tsppc nodes by tailnet name, and from a peer running the official client to each of them. An AFP mount between the two nodes copies a 20 MB file each way with matching checksums. Peer names come from tsppc's block in `/etc/hosts`, which is written, replaced and removed as designed.

**Build:** commit `b82e21b`, built on the Leopard VM by `tools/vm-test.sh leopard` (3254 checks, check-release, check-ct and check-app passed). Tiger ran the same files, copied from Leopard through the host. The kext was not changed. SHA-1 hashes:

| File | SHA-1 |
|---|---|
| `tsppcd` | `2fc5389834b707f2f84a1c6094f4e3aaf0840417` |
| `tsppc` | `92d21a1c6e38f1367db008e82959f564abb89512` |

**Machines:** as in `docs/tunnel-check.md`: emulated G4s in UTM with shared (NAT) networking, Mac OS X 10.5.8 and 10.4.11, and the host Mac running the official client. Placeholders: `<leopard>`, `<tiger>`, `<host>` for the nodes, `<suffix>` for the tailnet's MagicDNS suffix, `<share>` for a share name.

## How it was run

Install on each VM, keeping the previous binaries in `~/tsppc-run/prev-6b1c57e/`, then restart the daemon:

```
sudo kill <tsppcd pid>
cd ~/tsppc-run && sudo sh -c "nohup ./tsppcd >>/var/log/tsppcd.log 2>&1 </dev/null &"
```

Copy new binaries to a temporary name and `mv` them into place: `cp` over the file of a running program rewrites it in place. Start the new daemon only after the old one has gone, or the new one is refused at the control socket.

## Names

| Check | Result |
|---|---|
| `tsppc status` on both nodes | `names: 15 names` (14 peers plus self) |
| `/etc/hosts` | one block between the tsppc markers, `100.x.y.z<TAB><name>.<suffix> <name>` per node; the owner's lines above it unchanged |
| `ping <tiger>` and `ping <tiger>.<suffix>` from `<leopard>` | resolved to `<tiger>`'s tailnet address, replies |
| Leopard flat-file lookup: `dscl /BSD/local -read /Hosts/<tiger>` | record with both names while up; `eDSRecordNotFound` after `tsppc down` |
| `tsppc down` | block removed, `names: off` |
| `tsppc up` | block written again, `names: 15 names` |
| `kill -9` of the daemon | block left behind (expected); next start logged "peer names removed", then "15 peer names written"; no `/etc/.hosts.tsppc.*` left |
| SIGTERM | block removed |
| Owner's part of `/etc/hosts` across all of the above | identical (same MD5 outside the block) |

**Test environment caveat.** On these VMs a tailnet name resolves even without the block: the guests' DNS (UTM's resolver, which forwards to the host Mac, and on Leopard also a DNS server on the host's LAN) answers tailnet names through the host's own Tailscale. So "the name still resolves after `down`" is expected here, and resolving is not proof that the hosts file is used. On Leopard the flat-file query above is that proof. Tiger's `lookupd` has no equivalent query that runs without a terminal; on Tiger the check covers the block's contents and its removal, and milestone 6 repeats it.

## SSH

| From | To | Result |
|---|---|---|
| `<leopard>` (Leopard's `ssh`) | `<tiger>` by short name | logged in, ran `sw_vers` and `uname -n`; SYN and SYN-ACK on `tun0` |
| `<tiger>` (Tiger's `ssh`) | `<leopard>` by short name | logged in, ran `sw_vers`, `uname -n`, `uptime`; SYN and SYN-ACK on `tun0`; `en0` saw no packets for `<leopard>`'s tailnet address |
| `<host>` (official client) | each node by tailnet address | logged in, ran `uname -n` |

The VM-to-VM sessions authenticated with a key held in a temporary agent on the host and forwarded for one command; no key was copied to the VMs.

## AFP

Personal File Sharing was turned on for the test only and turned back off afterwards (see "Cleanup").

| Server | Client | Mount | Copy (20 MB of random data) |
|---|---|---|---|
| `<tiger>` | `<leopard>` | `mount_afp "afp://;AUTH=No%20User%20Authent@<tiger>/<share>" /tmp/afpm` (guest) | read 38 s, MD5 matched |
| `<tiger>` | `<leopard>` | same mount, into the share's Drop Box | write 38 s, MD5 matched |

That is about 0.55 MB/s each way, through a DERP relay between two emulated G4s.

Mounting in the other direction, from Tiger, did not work in an SSH-only session, and the failure happened before any packet was sent: with the AFP client extensions not loaded, `mount_afp` returned error 15 (ENOENT); after loading `asp_tcp.kext` and `afpfs.kext` by hand it still did, and `mount volume` through `osascript` waited for a dialog on the console. A TCP connection from Tiger to the server's port 548 over the tunnel opened. This is the old AFP client needing a login session, not the tunnel. Notes for next time: on Tiger, guests see each user's Public Folder under the user's short name; on Leopard, under "<full name>'s Public Folder".

## Cleanup

- Leopard: the AFP launchd job unloaded; its launchd plist and `/Library/Preferences/com.apple.AppleFileServer.plist` restored byte for byte from copies taken before the test; nothing listening on 548.
- Tiger: the AFP server stopped; the preferences file it created deleted (there was none before); `AFPSERVER=-NO-` in `/etc/hostconfig` unchanged; the AFP client extensions loaded by hand stay loaded until the next restart.
- Test files deleted on both nodes.
