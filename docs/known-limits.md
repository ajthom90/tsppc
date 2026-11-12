# Known limits

Accepted limits, with the decision behind each.

## BearSSL's X25519 leaves a clamped scalar on its stack

`ts_x25519` wipes its own copy of the scalar and every buffer it controls, but
`api_mul` in `vendor/bearssl-0.6/src/ec/ec_c25519_m31.c` copies the scalar into
a local array, clamps it, and returns without wiping it. The clamped scalar is
the private key apart from a few fixed bits, and it stays in that stack frame
until the stack is reused.

Decision: accepted until long-term key handling is reviewed. Changing it would
mean a further patch to vendored code, and a process that can read this memory
can also read the key material we hold on purpose.

## Constant-time evidence comes from disassembly

The claim that multiplies are constant-time on G3 and G4 rests on reading the
PowerPC code that gcc-4.0 builds. No timing has been measured on real hardware.

Every `mullw`, `mulhw` and `mulhwu` in `poly1305_ctmul32.o`, `ec_c25519_m31.o`
and `nacl.o` takes both inputs from values with bit 31 set and bit 30 clear.
Bit 31 is forced on every operand. Bit 30 stays clear because the operands are
30-bit limbs or smaller: the X25519 limbs are 30 bits, and the `MUL15` operands
are at most 17 bits. Both conditions are needed. `mullw` may treat its operands
as signed and finish early when the top bits are all ones, so a 31-bit operand
with bits 30 to 16 set becomes 0xFFFFxxxx after the OR and is not protected.

With both conditions met, which operand a 750 or 7400 inspects for early-out no
longer matters. `tools/check-ct.sh` checks bit 31 on the VM and fails the run
if it stops holding. Bit 30 follows from the operand widths in the source, and
the script cannot see it. Its header lists what else it cannot detect.

The compiler can remove such forcing without changing any result, so tests
cannot catch it. Other BearSSL objects are not part of that check. The `i31`
code uses 31-bit words, so this reasoning does not cover it.

## TLS client configuration (control-session Task 6)

`ts_tls` (src/net/tls.c) wraps `br_ssl_client_context`, and BearSSL's client
defaults are not all covered by the evidence above. `BR_LOMUL` is only set on
ARM Cortex-M, and PowerPC here is not `BR_64`. `ts_tls_start` therefore sets
every implementation by hand rather than calling `br_ssl_client_init_full`.
The same configuration applies on every target. `test_tls_config` in
tests/test_net.c checks the engine's settings and the ClientHello it sends.

- **Poly1305:** `br_poly1305_ctmul32_run` is set explicitly, and ChaCha20 is
  `br_chacha20_ct_run`, which has no multiplies.
- **GCM and the rest:** none configured. Only TLS 1.2
  `ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256` and
  `ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256` are offered. No GCM, CCM, CBC or
  DES record code or block cipher is set, so `br_ghash_ctmul` never runs. If the
  server stops offering ChaCha20 or X25519, the client fails with "server does
  not offer TLS 1.2 with ChaCha20-Poly1305 and X25519". It does not fall back.
  Such a server normally answers with a `handshake_failure` or
  `protocol_version` alert, and that message was confirmed against
  `openssl s_server` limited to AES-GCM, to P-256 and to TLS 1.3.
- **Curves:** the engine's EC implementation is `br_ec_c25519_m31` alone. The
  ClientHello advertises only X25519, and BearSSL rejects any other curve the
  server picks (`ssl_hs_client.c` checks `supported_curves`). The ephemeral
  secret therefore only goes through code that check-ct covers.
- **Signatures:** the engine hands its own EC implementation to the ECDSA
  verifier for the ServerKeyExchange signature, and X25519 has no ECDSA. So
  `ts_tls` installs a small verifier that ignores that argument and calls
  `br_ecdsa_i31_vrfy_asn1` with `br_ec_all_m31`. The X.509 engine uses the same
  pair, and `br_rsa_i31_pkcs1_vrfy` for RSA. This reads the X25519-only rule as
  "X25519 for key exchange". Signature checks use whatever curve the certificate
  has. `ec_p256_m31` and `ec_prime_i31` (P-384, used by ISRG Root X2 and Root
  YE and their intermediates) and the i31 RSA code therefore only run on public values: a
  public key, a public signature and a hash of public handshake messages. The
  client never signs (no client certificates) and never does ECDHE on those
  curves.
- **Check:** `ec_p256_m31.o` is not added to `tools/check-ct.sh`. Constant time
  matters only where a secret enters, and no secret reaches P-256, P-384 or the
  i31 code. The `mulli` in `p256_mulgen` is therefore irrelevant, as are the
  `i31` multiplies. If a later change makes any of them handle a secret, such as
  ECDHE on P-256 or a client certificate, this decision must be revisited first.

Live checks (`tools/keyfetch_check.c`) on the host, Leopard and Tiger negotiate
`ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256` over X25519 with
controlplane.tailscale.com, whose chain was RSA (leaf, YR2, "O=ISRG, CN=Root
YR"). Against letsencrypt.org they negotiate
`ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256` with a P-256 leaf under "O=ISRG,
CN=Root YE". This exercises the ECDSA verifier and P-384. The control server
has also been seen serving an ECDSA chain (YE1, Root YE), so both paths matter.

Other accepted limits of the TLS client:

- **The X25519 stack residue above also applies to TLS.** BearSSL's ECDHE calls
  the same `api_mul`, so each connection's ephemeral scalar, clamped, stays on
  the stack until it is reused. It is ephemeral and protects only that
  connection.
- **Four roots only.** `src/net/anchors.c` holds ISRG Root X1 and X2 and Let's
  Encrypt's generation Y roots "O=ISRG, CN=Root YR" (RSA-4096) and "O=ISRG,
  CN=Root YE" (P-384). `tools/gen_anchors.py` generates the file, with each
  root's SHA-256 fingerprint pinned. Servers currently send Root YR or Root YE
  cross-signed by X1 or X2, and those cross-signs expire on 2032-09-02. BearSSL
  accepts a chain as soon as a certificate's issuer is an anchor, so the
  intermediate under Root YR or YE is trusted directly and the cross-signs are
  not needed. Any root Let's Encrypt adds later must be added to `ROOTS`, with
  its pin reviewed, and the file regenerated.
- **SHA-256, SHA-384 and SHA-512 only.** A chain signed with SHA-1 or SHA-224 is
  rejected.
- **Clock.** Certificate validity uses `time()`. An expired or not-yet-valid
  certificate, or any certificate error while the clock reads earlier than
  `ts_build_time` (the day the anchors were generated), is reported as "system
  clock is wrong".
- **No session resumption.** Every connection does a full handshake, including
  the RSA-4096 or P-384 chain checks. On the emulated G4 that takes about a
  second.

## Tunnel over DERP (milestone 4)

Accepted limits of the first tunnel. `docs/tunnel-check.md` records the live
check.

- **Home relay by TCP connect time.** Upstream, without UDP, picks the home
  region by HTTPS latency to each region. tsppc times a TCP connect to the
  first node of each eligible region instead (`src/daemon/dataplane_io.h`),
  then applies upstream's stickiness rules. A connect time leaves out the TLS
  handshake, which on an emulated G4 costs about a second, so the two can rank
  regions differently. Decision: accepted. The choice only moves which relay
  the node calls home, and every peer can still reach it there.
- **DERP only.** Every WireGuard packet goes through a relay. There is no UDP
  socket, no STUN and no disco, so `tailscale ping` to a tsppc node times out
  and no direct path is ever tried. Direct paths belong to milestone 8.
- **No hybrid post-quantum handshake.** Tailscale's WireGuard fork
  (`tailscale/wireguard-go`) also has a hybrid ML-KEM handshake. tsppc
  implements only `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s`. `ts_wg_receive`
  accepts a handshake initiation or response only at its classic size, so a
  hybrid one is dropped by its size, and a peer that requires the hybrid
  handshake will not connect. Nothing turns it on at the upstream commit this
  milestone follows, and the live check connected to the official client with
  the classic handshake. If Tailscale turns it on, it must be implemented.
- **TokenBucket hints ignored.** A relay's ServerInfo may carry
  `TokenBucketBytesPerSecond` and `TokenBucketBytesBurst`. tsppc checks
  ServerInfo but ignores those fields and does not pace its sends to them.
  Decision: accepted. A G4's traffic through one relay is small.
- **Peer expiry follows control's clock, which can lag after sleep.** As
  upstream (`ipnlocal/expiry.go`), a peer whose `KeyExpiry` has passed is
  dropped locally even before control marks it `Expired`. tsppc never uses the
  Mac's own clock for this (an old Mac's clock is often wrong): it takes
  `ControlTime` from map responses and adds the monotonic time since it
  arrived (`src/data/dataplane.h`). Hosted control does send `ControlTime`
  (seen live, `docs/tunnel-check.md`). Limits: until the first `ControlTime`
  arrives, or if a control server never sends one, only control's `Expired`
  flag counts; and `mach_absolute_time` may not advance while the Mac sleeps,
  so after a sleep control's time can run behind until the next message that
  carries `ControlTime`, and an expired peer can be kept that much longer.
  Decision: accepted. Control's `Expired` flag still removes the peer, and the
  error only ever keeps a peer longer, never drops a valid one early.

## Peer names (milestone 5)

- Names only: tsppc writes a block of peer names into `/etc/hosts`. There is no 100.100.100.100 resolver, no split DNS and no search domain, so other tailnet DNS records (for example services) do not resolve.
- Names are in the file only while the tunnel is up (the data plane running with the tun device open). `tsppc down`, logging out, stopping the daemon, the tun device closing or the tailnet's `disable-hosts-file-updates` setting removes them.
- Only full names in this tailnet's own suffix (the part of this Mac's tailnet name after its first label) or under `ts.net` are written; any other name control sends (for example `www.example.com`) is skipped and counted as skipped in `tsppc status`.
- Short names (`<name>` as well as `<name>.<suffix>`) are written only for nodes in this Mac's own tailnet. Machines shared in from another tailnet get their full name only.
- A short name is left out when two nodes would share it, when it is `localhost`, `broadcasthost`, `wpad`, `isatap` or starts with `ip6-`, when it is this Mac's own host name (and the node is another machine), or when the owner's own lines in `/etc/hosts` already use it. The full name is still written.
- A hosts file that is a symbolic link, is not a regular file, is larger than 1 MiB, or has a tsppc begin marker with no end marker is never written; `tsppc status` says why.
- A block deleted by hand comes back at the next network map change, not on a timer.
- If removing the block fails (a broken tsppc section, or the file cannot be written), the names stay in `/etc/hosts` until the owner fixes the file; `tsppc status` says why, and tsppc tries again every 30 s while it runs and at its next start.
- Deleting only the begin marker line by hand turns the old entries into ordinary owner lines: tsppc no longer recognises them as its own and never removes them (a lone end marker is removed). Delete the whole section, or neither marker.
- An edit the owner makes in the moment between tsppc reading the file and replacing it is lost. The window is very short and only exists while a map change is being written.
- The resolver cache flush (`dscacheutil` on 10.5, `lookupd` on 10.4) runs in the daemon's loop and can hold it for up to 10 s if the command hangs (the data plane then restarts any relay probe round it interrupted).

## `tsppc ping` and disco

- Relay only until milestone 8: every pong comes through a DERP relay, so the default run (10 pings, until direct) always ends with `direct connection not established` and exit 1, as the official client does for a relayed peer. Use `--until-direct=false` for a zero exit.
- Only disco ping and pong are handled. CallMeMaybe and the UDP relay messages are counted and ignored; with no direct paths there is nothing to act on.
- tsppc answers a disco ping only from a current peer whose packet carries that peer's disco key from the network map. Upstream also accepts a disco key learned from a TSMP advertisement; a peer whose key reached tsppc that way and not yet through the map gets no pong until the map catches up.
- Pongs are rate-limited to 10 a second per peer and 50 a second in all.
- At most 4 pings can wait at once across all `tsppc ping` commands, so `tsppc status` and the menu bar app always find a free connection to the daemon.
- `--timeout` accepts 100ms to 10s. Names resolve only to tailnet peers (full name, or its first label); there is no fallback to the system resolver.
- "peer has no home relay" is tsppc's own message; upstream would time out instead.
- Jailed and WireGuard-only peers are not configured in tsppc's data plane, so `tsppc ping` to them says `no matching peer` although `tsppc status` lists them; upstream would ping them.
