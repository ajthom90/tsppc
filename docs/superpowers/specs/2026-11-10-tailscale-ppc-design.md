# Tailscale client for PowerPC Mac OS X: design

Status: draft for owner approval. Date: 2026-11-10.

## How to read this document

Every decision is tagged with where it came from.

- **[Owner]**: the project owner said this.
- **[Agreed]**: proposed to the owner in writing and accepted without change.
- **[Call]**: chosen by the design author. The owner has not weighed in. Treat these as defaults that can be challenged.
- **[Open]**: not decided yet. The owner decides.

Protocol facts are in Appendix A, each labelled as proven or only read from source.

## Intent

Old PowerPC Macs should be ordinary members of the owner's tailnet. From any other machine on the tailnet, the owner should be able to SSH into a G4 or mount its shared folders, wherever each machine is. From the PowerPC Mac, the owner should be able to reach other tailnet machines with the tools already on it.

Nothing like this exists. Tailscale's client is written in Go, and neither Go nor Rust targets PowerPC Mac OS X, so this is a from-scratch reimplementation of the protocol in C.

## Goals

1. Run on **G3, G4 and G5 Macs ("if possible" for all three)** on **Mac OS X 10.4 Tiger and 10.5 Leopard**. **[Owner for hardware; Agreed for OS versions]**
2. Join a **hosted Tailscale tailnet**, using Tailscale's real control plane and relays. Development uses the owner's regular tailnet. Headscale is not a target. **[Owner]**
3. Provide a **full system-level tunnel** with a real tailnet IP, so unmodified apps and services work. **[Agreed]**
4. Traffic works in **both directions**: other machines reach the Mac's Remote Login (SSH) and File Sharing, and the Mac reaches other tailnet machines. **[Owner]**
5. Ship a **command-line tool and background daemon first**, roughly `tailscale up` and `tailscale status`. **[Agreed]**
6. Log in by **printing a URL** that the owner opens on any modern device, since the browsers on these Macs can't use Tailscale's login page. **[Agreed]**
7. Use **direct connections when possible, with DERP relays as the fallback**. **[Agreed]**
8. Be fast enough for **SSH and modest file transfers**. Fast bulk transfer is not expected, especially on a G3. **[Agreed]**
9. **Publish it as open source so other people can use it.** **[Owner]** See "Open source release".

## Non-goals for the first version

**[Agreed]**: Tailscale SSH (ordinary `sshd` over the tunnel is the point), Taildrop, Funnel, and MagicDNS beyond the basics defined below.

Exit nodes (using one, not being one) and a menu bar app were in this list. The owner added them back on 2026-11-11 as milestones 12 and 13. **[Owner]** Acting as an exit node for other devices stays out of scope. **[Call]**

**[Call]**, also out of scope:

- IPv6 inside the tunnel and on the underlying network. The node ignores the IPv6 address and IPv6 filter rules it receives.
- Tailnet Lock. If the tailnet enforces it, the client reports that it's unsupported and stops.
- Subnet routing, advertising or accepting routes, and app connectors.
- Auth-key login. Interactive login only in the first version.
- Headscale compatibility, and 10.3 and earlier. **[Owner]** decided against Panther and Jaguar for now. tuntaposx needs kernel interfaces that first appeared in 10.4, so Panther would need a different driver. It may come back later as a driver investigation.
- Intel Macs and 10.6 in the first PowerPC release. They follow as milestone 11. **[Owner]**
- Sending a 64-bit build. G5s run the same 32-bit binary.
- AltiVec. It may be added later as an optional speedup, and nothing may require it. **[Agreed]**

## Anti-goals

Any of these makes the project a failure, even if everything else works. All are **[Call]**.

- **Exposing the Mac past the tailnet's access rules.** Tailscale enforces ACLs on the receiving node. These Macs run 2000s-era SSH, AFP and SMB. The client must never deliver tunnel traffic that the current packet filter doesn't allow, and it must deny everything until it has a filter.
- **Accepting a packet whose inner source IP doesn't belong to the peer that encrypted it.**
- **Passing off as an official Tailscale build**, in the reported version string, program names, or anything published.
- **Disrupting the owner's regular tailnet during development.** Nothing changes its access rules or settings without the owner doing it or approving it, and no test may depend on loosening them.
- **Leaking key material** to logs, status output or world-readable files.
- **Leaving a Mac broken when the client stops.** Removing the client or a daemon crash must not leave stale routes, a damaged `/etc/hosts`, or a boot that hangs on the driver.
- **Memory-unsafe parsing of network input.** Every parser here reads data from the network, in C. See "Testing".

## Constraints

- **Toolchain:** binaries must run on stock Tiger, so build with `gcc-4.0 -std=gnu99 -arch ppc -isysroot /Developer/SDKs/MacOSX10.4u.sdk -mmacosx-version-min=10.4`. This is proven on the test VM. **[Call]**
- **Single binary:** one 32-bit `ppc` executable for all three CPUs and both OS versions. **[Agreed]** Milestone 11 adds Intel slices to the same file.
- **Portability:** nothing may assume a big-endian or 32-bit CPU, because the same code will ship for Intel. The host tests already run on a little-endian 64-bit CPU. **[Call]**
- **Language:** C. **[Agreed]**
- **Old-system libraries can't be used for crypto or TLS.** Leopard's OpenSSL is 0.9.7l and its `curl` is equally old. Bundle what's needed, including root certificates.
- **Big-endian CPU, with mixed byte orders on the wire.** The control channel's framing and nonce are big-endian. WireGuard's message fields, its nonces and the map stream's length prefix are little-endian. All serialisation must use explicit byte-order helpers and never overlay structs on packets.
- **Memory and CPU are scarce.** A G3 may run at a few hundred MHz. Plan for a 256 MB machine, a daemon that stays under about 16 MB, at most 256 peers, and at most 4 MiB for one map message. Keep these as compile-time limits, and report clearly when a tailnet exceeds them. **[Call]** No buffer may grow without a limit.
- **The hosted service changes without notice.** This client tracks a moving protocol and will need occasional maintenance.
- **Test environment today:** one emulated G4 VM on Leopard 10.5.8, behind NAT with no inbound UDP, plus a stopped emulated G5 Leopard VM. The owner can supply Tiger install media for an emulated Tiger VM. **[Owner]** The only real hardware is one G4 eMac that may not boot, and it is packed away, so no milestone may depend on it. **[Owner]** There's no real G3 or G5, and no way to measure real speed yet.
- **Device approval is on in the owner's tailnet.** **[Owner]** A new node may need a login and then an approval in the admin console, so a registration can log in successfully and still not be authorized. The spike's register response did report `MachineAuthorized=true` after a single login step, and that hasn't been explained. Don't assume either behaviour.

## Design

### Overall shape **[Call]**

One daemon, `tsppcd`, runs as root from launchd. It is single-threaded around a `select()` loop over the tunnel device, sockets and the control connection. A G3 has one CPU, so threads buy little, and a single loop avoids locking bugs. Blocking DNS lookups must not stall the data path, so the builder needs a small answer for that, such as a helper process or a resolver thread.

The `tsppc` CLI talks to the daemon over a Unix socket in `/var/run`, limited to root and the `admin` group. The names avoid installing programs called `tailscale` and `tailscaled` in a public release. **[Call]**

Commands for the first version: `up`, `down`, `status`, `ip`, `logout`. `up` prints the login URL, then reports when the node is waiting for device approval. `status` shows self, each peer's name and IP, whether the path is direct or relayed, and any current problem, such as a wrong clock or an expired key.

### Portable core with a thin platform layer **[Call]**

All protocol logic is plain C with no Mac dependencies, and it must also build and run its tests on the modern development Mac. Tests run in seconds there, with sanitizers and fuzzers. The Mac-specific layer is small: tunnel device, routes, launchd, and sleep and network detection.

The VM's job is to confirm big-endian correctness and real tunnel behaviour, and to produce the shipping binary. A full BearSSL build took about 5 minutes under emulation, so the build must be incremental.

### Components

**Crypto.** BearSSL 0.6 supplies X25519, ChaCha20, Poly1305 and TLS 1.2. **[Call]** We add BLAKE2s, HMAC-BLAKE2s and HKDF, proven in the spike, and XChaCha20 and NaCl box (XSalsa20-Poly1305), which aren't built yet. Randomness comes from `/dev/urandom`. The builder picks BearSSL's X25519 and Poly1305 variants by measuring on the slowest hardware available.

**TLS roots.** Compile in ISRG Root X1 and X2. **[Call]** Control's `/key` and the relays both need TLS validation.

**Control client.** Fetch `/key`, run Noise IK over port 80 with fallback to 443, then speak HTTP/2 inside the Noise channel. This needs a real HTTP/2 client: full HPACK decoding (dynamic table and Huffman), stream and connection flow control, PING and GOAWAY handling, frames that span Noise records, and two or more concurrent streams. The spike's partial HPACK and single-shot requests are not a base for this.

**Registration.** After the first `/machine/register`, hold one `Followup` request open while the server long-polls until the user approves. Don't re-POST in a loop. Honour 429 and 503 `Retry-After`.
**Map session.** Keep one long-lived streaming `MapRequest` open and apply incremental updates: changed, removed and patched peers, DERP map, and both the old and new packet filter fields. Leave `Compress` empty so no zstd decoder is needed. The JSON parser is bounded, and a size limit applies to each message. Unknown fields and node attributes are ignored.

Device approval arrives here. Upstream decides whether a node is waiting from the self node's status in the map, and doesn't rely only on the register response. So "logged in, awaiting device approval" is its own state, shown in `status`, and it must move on automatically when a map update reports the node as authorized. No tunnel traffic flows while it is waiting.

**WireGuard.** A userspace implementation of the protocol, with session rekey and timers matching WireGuard, and strict AllowedIPs enforcement in both directions. This is written from the WireGuard specification with `wireguard-go` as a reference.

**DERP.** TLS to the relay on 443, HTTP Upgrade, NaCl-box client handshake, then send and receive frames, and answer pings. Choose a home region by connection latency, report it as `PreferredDERP`, and reconnect when a relay restarts.

**Direct paths.** A later milestone: UDP socket, STUN, DISCO ping and pong, CallMeMaybe, and path upgrade and fallback.

**Packet filter.** Applied to all inbound tunnel traffic. Implements the netmap's rules with default deny and retains the last filter across reconnects. Outbound flows need the minimum state for replies to come back, as upstream does. The filter ships in the same milestone as the tunnel, before any inbound test.

**Tunnel.** tuntaposx 20090913 (`/dev/tunN`, raw IP packets), patched as in Appendix A. **[Agreed, proposed as the expected approach]** Build one kext against the 10.4u SDK, and use it on both OS versions if testing allows. If it can't load on both, ship one per OS. Kexts on PowerPC are 32-bit, including on G5.

**Interface and routes.** Assign the tailnet IP point-to-point, set MTU 1280, and route `100.64.0.0/10` into the tunnel. Remove the routes on exit. Don't touch the default route. With an exit node set, the routes change as described in "Using an exit node".

**Names (what "MagicDNS basics" means).** Keep a clearly delimited block of peer names in `/etc/hosts`, rewritten atomically and removed on exit, and respect `NodeAttrDisableHostsFileUpdates`. There's no 100.100.100.100 resolver. Peers' short and full names resolve on the Mac, and nothing else is promised. **[Call]**

**State and keys.** Machine, node and disco private keys live in one file under `/var/db/`, in a directory owned by root with mode 0700, and the file itself has mode 0600. Writes use a temp file, `fsync`, and rename. The System keychain was rejected as less predictable from a boot-time daemon on Tiger. **[Call]**

**Install layout.** Binaries in `/usr/local/`, kext in `/Library/Extensions`, a LaunchDaemon plist that uses only keys Tiger understands, and an uninstall script. Packaging is covered in "Open source release". **[Call]**

### Using an exit node

**What it's for.** The owner sometimes needs all of the Mac's traffic to go out through one chosen tailnet machine. **[Owner]** The Mac only *uses* an exit node. It never offers itself as one. **[Call]**

Everything below was played back to the owner and accepted, except where marked. **[Agreed]**

- **Choosing.** The owner picks a peer that offers itself as an exit node, by name or tailnet IP, or picks none. The choice can be made from the CLI and from the menu bar app. It is saved in the state file and survives restarts and reboots.
- **Traffic.** While an exit node is set, all IPv4 traffic leaves through it, apart from the daemon's own connections and, if the option below is on, the local network.
- **DNS.** Lookups also go through the exit node, so they don't leak to the local network's resolver. The system's DNS settings are put back exactly when the exit node is turned off, the daemon stops, or it's uninstalled.
- **Local network access.** An option, off by default, keeps the Mac's directly attached LAN subnets reachable outside the tunnel, for printers and file shares.
- **Fail closed.** If the chosen exit node goes offline, is removed, or the tunnel is down, traffic stops instead of quietly going out directly. `status` and the menu bar say why. The owner can always turn the exit node off.

The builder's notes below are all **[Call]**.

- **Which peers are exit nodes.** Upstream treats a peer as an exit node when its `AllowedIPs` include `0.0.0.0/0`. So the network map must also parse `AllowedIPs`, which it doesn't yet. A peer with only `::/0` doesn't count, because IPv6 is out of scope. Whether the owner may use a given exit node is decided by the tailnet's access rules (`autogroup:internet`). If the rules forbid it, traffic just fails, so `status` should suggest checking the access rules once no traffic has come back for a while.
- **Routes.**
  - Leave the default route itself alone. Instead, route `0.0.0.0/1` and `128.0.0.0/1` into the tunnel, as upstream does on macOS.
  - Pin host routes through the original gateway for everything the daemon itself must reach: control, the DERP servers in the current DERP map, direct-path peer endpoints, and the DNS server the daemon uses for its own lookups.
  - Update these pins when the DERP map, the endpoints or the network change.
  - The daemon must be able to look up and reach control at boot with an exit node already set.
- **DNS.** Upstream sends DNS through the exit node's PeerAPI DNS-over-HTTPS endpoint (`/dns-query`), so do the same.
  - PeerAPI is plain HTTP to the exit node's tailnet IP. The port comes from the `peerapi4` service in the peer's Hostinfo. An ordinary kernel TCP socket reaches it through the tunnel, so no userspace TCP is needed.
  - The daemon runs a small DNS stub on `127.0.0.1:53`. It answers apps' UDP queries by forwarding each one as a DoH request. It has hard limits on query size, outstanding queries and per-query time.
  - The system resolver points at the stub while an exit node is set. On 10.4 and 10.5 that is set through SystemConfiguration, not `/etc/resolv.conf`.
  - Save the original resolver settings before the first change, in a form that survives a daemon crash, so they can be put back.
  - The stub and the DoH client are new work inside milestone 13. They are network parsers, so the "Testing" rules apply: sanitizers and fuzzing.
  - If the exit node has no `peerapi4`, DNS fails closed like everything else, and `status` says so.
- **Local network access.** "Directly attached subnets" means those of the Mac's current interfaces. The routes follow network changes, through the same polling as the "Network change" row in the conditions table.
- **The daemon's own lookups.**
  - Control's hostname is resolved with the original system resolver, captured before any change and kept up to date across network changes. The last good address is also stored in the state file, so a boot with an exit node set can reach control even if resolving fails.
  - DERP nodes are pinned by the IPv4 addresses in the DERP map, which already carries them. Their hostnames are used only for TLS names.
- **Boot and crashes, in more detail.** Until `tsppcd` starts at boot, traffic goes out directly. Fail-closed starts when the daemon installs its routes, early in its start-up and before the tunnel is up. If the daemon crashes, its routes point at a tunnel interface that is gone, so traffic is blocked. launchd restarts the daemon, which clears the old routes and sets them up again. No separate cleanup job is needed.
- **Packet filter.** Replies from the internet arrive from the exit-node peer with arbitrary source IPs. The `0.0.0.0/0` entry in that peer's `AllowedIPs` makes them valid for WireGuard. They're admitted only as replies to flows the Mac started, which is the outbound state the filter already needs. Unsolicited packets from the internet are denied.
- **Crashes.** A daemon crash with an exit node set leaves traffic blocked, which is fail-closed and acceptable. It must not leave the Mac broken after the next start or an uninstall. On start, the daemon removes any routes and DNS changes from an earlier run before applying its own, and uninstall does the same. This extends the "Leaving a Mac broken" anti-goal.
- **CLI.** `tsppc exit-node list` lists the exit-node peers and whether each is online. `tsppc set --exit-node=<name|IP|none>` and `tsppc set --exit-node-allow-lan-access=<true|false>` change the settings. `status` shows the current exit node and its state.

### Menu bar app

**What it's for.** It does day-to-day control without Terminal. **[Owner]**

**What it does.** **[Agreed]**

- An icon shows whether tsppc is connected, needs login, is waiting for approval, or has a problem.
- Connect and disconnect, which are `up` and `down`.
- A list of tailnet devices with name, IP and online status. Clicking a device copies its IP.
- Settings, including the exit node and LAN access.
- When login is needed, the menu shows the login link and can copy it, because the Mac's own browser can't load Tailscale's login page.

**How it's built.** **[Agreed]** It's a small native Cocoa app (Objective-C, `NSStatusItem`) that runs on both 10.4 and 10.5. It talks to `tsppcd` over the same Unix socket as the CLI. It holds no keys, needs no root, and makes no network connections of its own.

The builder's notes below are all **[Call]**.

- **Toolchain.** Build it with the same gcc-4.0 and 10.4u SDK flags as the daemon. Milestone 11 adds Intel slices to it as well. It must run on a G3 without being noticeably slow.
- **Who can use it.** The socket is limited to root and the `admin` group, so the app works for admin users only. For anyone else it shows a clear "needs an administrator account" message. Widening the socket's access is a separate decision for the owner.
- **Talking to the daemon.**
  - The app needs a machine-readable form of status, the peer list and the exit-node list, not the CLI's text. Add one to the IPC protocol with explicit limits.
  - The app treats every string from the daemon as untrusted, just as the CLI does.
  - It polls every few seconds while it runs, and more slowly when nothing changes. It must not keep a G3 busy.
  - "Connect" sends `up` and returns at once. The app then reads the login link and state changes from status as it polls. The daemon already keeps the link after the CLI's `up` exits.
- **Menu shape.**
  - This device's name and IP at the top. Clicking copies the IP.
  - A Connect or Disconnect toggle.
  - A "Devices" submenu sorted online first, then by name.
  - An "Exit Node" submenu with "None", the exit-node peers and a "Allow local network access" check item.
  - When login is needed, "Log in…", which shows and copies the link.
  - "Log out…", with a confirmation.
  - "Quit".
  - A "Settings" submenu (added 2026-11-12, **[Owner]**; its contents are **[Call]**): "Start at Login" (adds or removes the app in the user's Login Items; no root), "Use Tailnet Names" (the `/etc/hosts` block), "Check for Updates Automatically", and "About tsppc" (version, the not-affiliated notice, project link). The exit-node items stay in their own submenu. See "Updates" for the update items.
  - There's no separate preferences window in the first version.
- **Starting at login.** The installer offers to add the app to the user's Login Items. Quitting the app leaves the daemon and the tunnel running.
- **Identity.** It must use its own icon and name, never Tailscale's logo or app name. This is the "Passing off" anti-goal.

### How it reports itself **[Call]**

- `Hostinfo.OS` is `macOS`, the value upstream sends. The spike sent `darwin` and was accepted, but `macOS` is what control expects. `OSVersion` is the real version.
- `IPNVersion` is clearly unofficial, for example `0.1.0-ppc`.
- `NodeAttrScopeQuad100OnMacOS` and similar node attributes for features we don't have are ignored.

### Capability version policy **[Call]**

The version is one compile-time constant, pinned and changed deliberately. It starts at 150, the value the spike proved. Advertising a version promises the behaviour in upstream's changelog, so the builder reviews every entry up to the pinned value. Most entries are node attributes that are safe to ignore, or features we don't have. Entries that need real behaviour include 429 and 503 handling (137, 147). Entry 144, sending a disco key advertisement around WireGuard handshakes, needs specific review. If it can't be honoured, lower the constant.

Upstream's value moves about every two weeks, and there's no need to chase it. Update only when control starts rejecting the client or a needed feature requires it. A rejection must surface as a clear message in `status`.

### Real-world conditions on old Macs **[Call]**

| Situation | Required behaviour |
|---|---|
| Wrong clock (dead PRAM battery is common) | TLS fails. Detect a date before the binary's build date or a certificate-date failure, and say "system clock is wrong" in `status` and the log. Keep retrying. |
| Node key expired | `status` shows that login is needed. `up` prints a new URL. Node identity is kept. |
| Sleep and wake | Detected by a jump in wall-clock time across a loop tick. Tear down and re-establish control, relay and WireGuard sessions. |
| Network change | Poll the default route and interface addresses every few seconds, and rebind on change. |
| Control or relay unreachable | Exponential backoff with jitter. Existing tunnels keep working where they can. |
| Daemon restart | Same node identity, no new login. |

## Milestones and acceptance tests **[Call]**

The order tests the largest unknown early and then puts the most useful path first. DERP-only is a complete client that works through any NAT, and it's the only path the current VM can exercise.

If the driver can't be made to work on Tiger, the project continues as a Leopard release for G4 and G5, and G3 support becomes a separate problem. This is the design author's proposal, and the owner has not confirmed it.

1. **Foundation.** Build system for host and PowerPC, vendored BearSSL, crypto with published vectors, test harness. *Passes when:* all vectors pass on the host and on the VM.
2. **Tiger driver check.** Create an emulated Tiger VM from the owner's media, and build and load the tunnel driver on it. *Passes when:* `/dev/tun0` opens on Tiger and an ICMP packet is read from it, as the spike showed on Leopard. Test early, because a failure here changes the supported systems.
3. **Control session.** Registration with a held Followup, HTTP/2, and map stream. *Passes when:* after one login and device approval, the node shows as online in the admin console, `status` lists the real peers, and the session survives an hour with updates arriving.
4. **Tunnel over DERP with filter.** WireGuard, DERP, tun device, routes and packet filter together. *Passes when:* a real tailnet peer pings the VM's tailnet IP, the VM pings the peer, and traffic to a port the ACL denies doesn't reach the Mac. Filter logic is tested exhaustively on the host with synthetic rules. If the regular tailnet's ACLs deny nothing useful to test, the owner decides whether to add a temporary rule.
5. **Services.** *Passes when:* SSH works in both directions over the tunnel, and a real AFP or SMB mount works from a client that still speaks those protocols. See "Known limits". The far end may use legacy SSH options, or a test `sshd` configured to allow them. The second Leopard VM can serve as the file-sharing client. Bundling a newer SSH client is out of scope. **[Call]**
6. **Tiger.** *Passes when:* milestones 4 and 5 pass on the Tiger VM.
7. **Daemon and install.** launchd, CLI, install and uninstall, and the conditions table above. *Passes when:* a reboot brings the node back with no login, uninstall leaves no routes or hosts entries, and each row of the table has been exercised on both Leopard and Tiger.
8. **Direct connections.** *Passes when:* `status` shows a direct path between the Mac and a peer on a network that allows it. The current VM's NAT may not allow it, so this needs bridged networking or real hardware.
9. **Real hardware.** Run the above on the owner's G4 eMac, and record throughput and CPU use. *Passes when:* interactive SSH feels normal and throughput numbers are written down. There is no numeric throughput target until there's a measurement. The eMac is not available for the foreseeable future, so nothing waits on this milestone: the first release does not need it, and says it has only been tested under emulation. It runs whenever the eMac comes back out. **[Owner]**
10. **Public release.** The checklist in "Open source release". *Passes when:* someone following only the published instructions can install the client on a clean Leopard VM and join a tailnet.

11. **Intel Macs on 10.4–10.6.** **[Owner]** The same code ships as a universal binary: `ppc` and `i386` from the 10.4u SDK, plus `x86_64` for 10.6. The tunnel driver also gets Intel slices, i386 and x86_64 for 10.6's 64-bit kernel. The PowerPC constant-time multiply checks don't apply to Intel, where the multiply instruction is already constant-time. *Passes when:* milestones 4 and 5 pass on an Intel 10.6 VM, or on Intel hardware if the owner has some, and the universal binary still passes on the PowerPC VMs. Intel 10.7 through 11 can follow later, using the built-in `utun` interface instead of a kernel driver. Official Tailscale needs macOS 12 or later, so those Macs are left out too. **[Call]**

12. **Menu bar app.** **[Owner]** This needs only the daemon and its IPC. It is built right after milestone 3, on the control-session daemon; the installer's Login Items offer waits for milestone 7 and the Exit Node submenu for milestone 13. *Passes when:* on both Leopard and Tiger, as an admin user, the app shows the right state through each step: not logged in, login needed (link shown and copied), waiting for approval, connected, and disconnected. The device list matches `tsppc status`. Clicking a device copies its IP. Connect, Disconnect and Log out work. The app uses little CPU while idle on the slowest VM. **[Call]**
13. **Using an exit node.** **[Owner]** This needs the tunnel (milestone 4) and the install and cleanup work (milestone 7). The owner must have a tailnet machine offering itself as an exit node, approved in the admin console, and access rules that allow it. Arrange this with the owner. *Passes when:*
    - with an exit node set, a check of the Mac's public IP shows the exit node's, and name lookups work with LAN access off;
    - with LAN access on, a device on the Mac's LAN is reachable;
    - turning the exit node off restores the original routes and DNS exactly;
    - stopping the exit node blocks traffic and `status` says why;
    - a daemon restart and a reboot keep the setting and connect again with no login;
    - killing the daemon with `kill -9` and then starting it, or uninstalling, leaves no stray routes or DNS changes;
    - all of the above works on Leopard and Tiger, and from the CLI and the menu bar app. **[Call]**

14. **Settings and one-click updates.** **[Owner]** This needs the install work (milestone 7) and the release tooling. *Passes when:* on Leopard and Tiger, the Settings items work (Start at Login survives a reboot, Use Tailnet Names adds and removes the block); a test release signed with a test key is found, offered and installed from the menu, and the daemon comes back on the new version with no login; a manifest or package with a bad signature, wrong size, wrong hash or an older version is refused with a clear reason and nothing installed. **[Call]**

**Order and first release.** Milestones 12 (menu bar app), 13 (exit nodes) and 14 (settings and updates) are all in the first public release, so milestone 10 comes after them. **[Owner]**

Exit node testing uses two exit nodes on the owner's tailnet. One shares the VMs' gateway, so it proves routing but not a change of public IP. The other is on a different network, and routing through it must change the Mac's public IP. **[Owner]**

G3 and real G5 support are designed for but can't be verified by the owner. The release must say so, and ask for reports from people with those machines.

## Testing

- Host: all protocol logic has unit tests, using published test vectors where they exist. Every parser (JSON, HPACK, HTTP/2, DERP frames, WireGuard messages, IP packets, filter rules) is run under AddressSanitizer and UBSan and fuzzed.
- VM: the same suite on big-endian, then the milestone tests against the real tailnet.
- Because every new node needs a login and a device approval from the owner, each test machine keeps one persistent identity across test runs, and ephemeral test nodes are not used. **[Call]**
- Milestone checks that need the far end of a connection use one of the owner's existing tailnet machines, coordinated with the owner.

## Known limits

- **Modern clients and these Macs' old services may refuse each other.** Current OpenSSH needs legacy algorithm options to reach Leopard's `sshd` (seen on this VM). In the other direction, Leopard's own `ssh` will likely need a modern server to re-enable old algorithms. Modern systems are also dropping old AFP and SMB versions. The tunnel can't fix this. Acceptance tests are about connectivity plus a client that can still speak the protocol.
- **DERP-relayed traffic is encrypted twice** (WireGuard inside TLS), which will be slow on a G3.
- **Long-term dependence on the hosted service's behaviour.** Tailscale could stop accepting a pinned capability version.

## Left to the builder

Repository layout, module boundaries, the JSON parser's design, exact timer structure, DNS helper design, log format, how the Installer package is built, and the choice of crypto variants after measuring. The builder may cross-compile on the host to speed up iteration, as long as shipped binaries come from a toolchain proven to run on Tiger.

The `spike/` directory is reference only and is not a base for this work. Its findings are in Appendix A. It stays out of the published repository. **[Call]**

## Open source release

The owner wants others to be able to use this. **[Owner]** Everything else here is **[Call]**.

- **Licence:** BSD-3-Clause for this project. It matches Tailscale's reference code and is compatible with BearSSL's MIT-style licence and tuntaposx's BSD-style terms. tuntaposx's terms allow redistribution in source and binary form, with its copyright notice and disclaimer retained. Keep every upstream notice, including for any code ported from a reference.
- **Naming and affiliation:** say plainly in the README and at install that this is unofficial and not affiliated with or endorsed by Tailscale Inc. Before publishing, check Tailscale's trademark guidance and terms of service, and rename the project if needed. The working name `tailscale-ppc` may not survive that check.
- **Distribution:** a standard Installer package for Tiger and Leopard, plus an uninstaller. Publish source and SHA-256 checksums. Old Macs may be unable to download from modern HTTPS sites, so instructions must cover downloading on a modern machine and copying across.
- **Updates:** one-click updates from the menu bar app. **[Owner]**, 2026-11-12, replacing the earlier "no automatic updater" call; a notify-only design was offered and declined. The rest is **[Call]**:
  - Never unattended. The daemon checks about once a day (if "Check for Updates Automatically" is on) for a signed manifest on the project's latest GitHub release: version, package URL, size, SHA-256, minimum OS. A newer version shows "Install Update <version>…" in the menu. Installing needs that click and a confirmation, from an admin user (the socket is admin-only).
  - The daemon downloads the package with a size limit, checks size, SHA-256 and an Ed25519 signature against a public key compiled into the binary, refuses any version not newer than the running one, then runs `/usr/sbin/installer -pkg <pkg> -target /`. The package's scripts restart the daemon through launchd.
  - The signing key is the owner's, made and kept offline before the first release; it never goes in the repository, the VMs or CI. Ed25519 verification is new crypto code and gets RFC 8032 vectors, sanitizers and fuzzing like every other parser.
  - TLS to GitHub needs its certificate roots compiled in beside ISRG's. The signature, not TLS, is what makes an update trusted.
  - No automatic rollback: the previous package is kept under `/var/db/tsppc/` so it can be reinstalled by hand.
  - Compiled-in root certificates and the capability version are updated through releases.
- **How releases are built and published:** **[Call]**
  - Shipping binaries come from the Leopard VM's toolchain (gcc-4.0, 10.4u SDK). GitHub's hosted runners cannot build them.
  - `tools/release.sh`, run on the Leopard VM from a clean checkout of a tag: full PowerPC suite and the release, constant-time and app checks, then the Installer package, the uninstaller and SHA-256 checksums.
  - The package is installed and smoke-tested on the Tiger VM before publishing.
  - The manifest is signed on the owner's Mac, and `gh release create` there uploads package, uninstaller, checksums and signed manifest. Each publish is asked for.
  - GitHub Actions runs the host suite (clang, sanitizers, a short fuzz run) on every push. It covers the portable core only.
- **Existing tuntaposx installs:** detect one and avoid replacing or breaking it.
- **Users' tailnets vary:** clear errors for what's unsupported, including Tailnet Lock and tailnets over the peer limit. Device approval must work without a special mode.
- **Repository hygiene:** no keys, state files, login URLs or personal machine details in the repository or its test fixtures.
- **Support expectations:** the README states that the hosted protocol can change and that releases depend on maintenance.

## Appendix A: protocol facts

"Proven" means the spike exercised it against hosted Tailscale on 2026-11-10 on an emulated G4 with 10.5.8. "Source" means read from `tailscale/tailscale` at commit 9476be9 and not yet exercised.

### Proven

- `GET https://controlplane.tailscale.com/key?v=<capver>` over TLS 1.2 returns pretty-printed JSON with `publicKey: "mkey:<hex>"`. The chain validates against ISRG Root X1.
- `POST /ts2021` on port 80 with `Upgrade: tailscale-control-protocol`, `Connection: upgrade`, and `X-Tailscale-Handshake: <base64 of 101-byte init>` returns 101.
- Noise is `Noise_IK_25519_ChaChaPoly_BLAKE2s`. The prologue is `"Tailscale Control Protocol v<capver>"`, followed by MixHash of the control key.
- Init: BE16 version, type 1, BE16 length 96, e (32), encrypted machine key (48), tag (16). Response: type 2, length 48, e (32), tag (16).
- MixDH is HKDF-BLAKE2s (salt = ck, ikm = DH) yielding (ck, k). Handshake AEAD uses a zero nonce with AD = h. Split is HKDF (salt = ck, empty ikm). The client sends with c1 and receives with c2.
- Transport records: `[4, BE16 length, ciphertext]`, up to 4096 bytes per frame and 4077 of plaintext. The nonce is 4 zero bytes plus a **big-endian** 8-byte counter, with empty AD. Error frames are type 3.
- The server may send an early payload first: `\xff\xff\xffTS`, BE32 length, JSON. Otherwise HTTP/2 SETTINGS arrives. Requests inside are HTTP/2 only, with `:scheme https`.
- `POST /machine/register`, `content-type: application/json`, `Ts-Lb: <nodekey>`. JSON has `Version`, `NodeKey "nodekey:<hex>"`, `Expiry "0001-01-01T00:00:00Z"`, `Followup`, `Hostinfo`, `Ephemeral`. Response has `AuthURL`, `MachineAuthorized`, `Error`, `NodeKeyExpired`. `NLKey` can be omitted.
- Capability version 150 was accepted.
- tuntaposx 20090913 (commit 7859e07 of `github.com/bbits/tuntaposx`) builds and loads on Leopard for ppc. Patches: drop `-arch i386 -arch x86_64`, drop `-Xlinker -kext`, and declare `tuntap_if_ioctl`'s `cmd` as `u_int32_t`. Build with `make TUNTAP_VERSION=20090913` in `src/tun`. Configuring with `ifconfig tun0 inet <a> <b> up` delivers raw IP packets to `/dev/tun0`.
- BLAKE2s, HMAC-BLAKE2s, X25519 and ChaCha20-Poly1305 pass vectors on big-endian, built with gcc-4.0 against the 10.4u SDK.

### Source, not yet exercised

- Upstream's client treats a node as needing approval when the netmap's self node isn't `MachineAuthorized` (`ipn/ipnlocal/local.go`).
- `MapRequest.Compress` is `"zstd"` or empty, meaning no compression.
- Map stream messages are a 4-byte **little-endian** length followed by the message.
- `MapRequest` includes `Version`, `Compress`, `KeepAlive`, `NodeKey`, `DiscoKey`, `Stream`, `Hostinfo`, `Endpoints`.
- `MapResponse.PacketFilter` carries firewall rules, with a nil value meaning unchanged. `PacketFilters` carries incremental updates.
- `version.OS()` returns `macOS` on darwin.
- DERP: `GET /derp` with `Upgrade: DERP` and `Connection: Upgrade`. Frames are a 1-byte type and BE32 length. Handshake: `ServerKey` (0x01: 8-byte magic `DERP🔑`, then 32-byte key), `ClientInfo` (0x02: 32-byte public key, 24-byte nonce, NaCl box of JSON), `ServerInfo` (0x03). Data: `SendPacket` (0x04: 32-byte destination key, then packet), `RecvPacket` (0x05: 32-byte source key, then packet). Also `KeepAlive` (0x06), `Ping` (0x12), `Pong` (0x13), `Health` (0x14), `Restarting` (0x15). Protocol version 2.
- Disco packets start with the 6-byte magic `TS💬`, then a 32-byte key and a 24-byte nonce.
- Default tunnel MTU is 1280.
- Peers advertise their relay as `Node.HomeDERP`. Our own goes in `NetInfo.PreferredDERP`.
