# Capability version review

Reviewed against `tailscale/tailscale` at commit 9476be9, `tailcfg/tailcfg.go`, changelog entries 3 through 150.

## Result

**`TS_CAPVER` stays at `150`.** Every entry is either safe to ignore for this client, or is an obligation this client will honour at the milestone named below. No entry needs lowering the value. Lowering would drop every later entry along with the one that was a problem, so it is only worth doing if an owner below reports that an obligation cannot be met.

Upstream itself ships configurations that advertise this version without some of the behaviour: c2n is an optional build feature (`ts_omit_c2n`, `feature/buildfeatures`), and builds without it silently drop c2n pings while still sending `CurrentCapabilityVersion`. That is the precedent for decisions D1 and D3.

Evidence tags: **[Source]** means read in the upstream code at that commit (paths are relative to the upstream repository). **[Inference]** means not shown by that code. The control server is closed source, so anything about how it reacts to silence is an inference.

What this client is, for judging each entry: registers, keeps one streaming map, shows status (this plan). Later it adds WireGuard, DERP, disco and a packet filter. It will not have Tailscale SSH, exit nodes, Taildrop, Funnel, app connectors, subnet routes, IPv6, Tailnet Lock, a logtail uploader, a 100.100.100.100 resolver or an auto-updater.

## Decisions

### D1. `MapResponse.PingRequest` (entries 12, 31, 38)

[Source] `control/controlclient/direct.go` (`isUniquePingRequest`, `answerPing`, `answerHeadPing`, `doPingerPing`). A `PingRequest` can arrive on any map message, including one with `KeepAlive: true` (`tailcfg.go` MapResponse docs: with KeepAlive, all fields except `PingRequest`, `ControlTime` and `PopBrowserURL` are ignored). Upstream handles it before the KeepAlive check, in its own goroutine, so it never blocks map processing.

What the client does, by shape of the request:

1. **`URL` empty.** Ignore. Upstream does too.
2. **`Types` empty, `URL` set, `URLIsNoise` true (the plain liveness ping).** Answer it. Send `HEAD` on a new HTTP/2 stream on the existing control connection, with `:scheme https`, `:authority` taken from the URL host, `:path` the URL path plus query, no body and no extra headers. Discard the response whatever its status. Cancel the stream (`RST_STREAM`, CANCEL) after 15 seconds. A failure is logged without the URL and nothing else happens. Reason: it is cheap, Task 4 already requires two concurrent streams, and it is the one ping that proves the long-poll is alive. [Inference] control may use silence here to judge the connection; upstream always answers, so answering is the safe choice.
3. **Duplicate suppression.** Keep one string, the last `URL` seen, for the life of the session object (it survives reconnects, as upstream's `lastPingURL` survives map sessions). A request whose `URL` equals it is ignored. Cap the stored URL at 1024 bytes and ignore a longer one.
4. **`Types` empty, `URL` set, `URLIsNoise` false.** Ignore, log "ping over plain TLS not supported". Upstream would `HEAD` the URL over ordinary TLS. We have no general TLS client to arbitrary hosts (Task 6 trusts only the compiled-in roots and talks to known hosts). [Inference] control sets `URLIsNoise` for clients that arrived over Noise, which is why entry 38 exists. Task 11 must check, by logging only the field value and never the URL, that no ping arrives with `URLIsNoise` false. If one does, open a task.
5. **`Types` is `c2n`.** Ignore. See D3.
6. **`Types` lists `TSMP`, `disco`, `ICMP` or `peerapi`.** Ignore in the control-session plan (no tunnel). On error upstream also sends nothing (`doPingerPing` returns without a POST), so silence is a state upstream produces itself. No owner is assigned. Reopen only if a live test shows control acting badly on silence. If the tunnel milestone later finds it cheap, a TSMP and ICMP reply belongs there.

Owner: **Task 8** surfaces the request; **Task 9** answers it.

- Task 8: `ts_netmap_apply` (or the stream layer next to it) must parse `PingRequest` **on every message, including `KeepAlive: true` ones**, and expose it without storing it in the peer model, for example `ts_ping_req { int pending; char url[1024]; int url_is_noise; char types[64]; }` set by the apply call and cleared by the session when consumed. The `KeepAlive` rule in the plan ("changes nothing") applies to the map, not to this field.
- Task 9: add a test where a map message carrying `PingRequest{URL, URLIsNoise:true}` produces one `HEAD` on a second stream, the same URL again produces none, and a `KeepAlive:true` message carrying one still produces one.

### D2. `Debug.Exit` and `Debug.SleepSeconds` (entries 19, 25)

[Source] `direct.go` `handleDebugMessage`, `sleepAsRequested`; `map.go` `HandleNonKeepAliveMapResponse`. `Debug` is processed first on every non-KeepAlive message, before the rest of the message is applied. `Exit` is `*int`: present-with-zero means exit status 0. `SleepSeconds` is capped at 5 minutes. `DisableLogTail` is also in the struct. Entry 69 and 70 removed the other Debug fields.

- **`Exit`: honour.** Task 8 records `have_exit` and `exit_code` (presence matters, so zero is distinguishable from absent). Task 9 calls a hook `on_exit(code)` before applying anything else from that message. Task 10's daemon hook closes sockets, removes the IPC socket, and calls `_exit(code & 0xff)`. It is a remote stop for a crash-looping client. It adds no power control does not already have. Under launchd (the install milestone) an exit status of 0 should not restart the daemon: the install milestone's plist must use `KeepAlive` with `SuccessfulExit` false, or an equivalent. Tests set the hook to a recorder so the test process does not exit.
- **`SleepSeconds`: honour, simplified.** Clamp to 300 seconds, ignore non-positive and non-finite values. Task 9 records `sleep_until_ms`. While it is in the future: `ts_sess_want_read()` (new accessor) returns 0 so the daemon stops reading the control socket, and the 90-second keepalive PING and 30-second no-reply disconnect are suspended (upstream stops its watchdog while handling a message, `direct.go`). Messages already buffered in the same read are still processed. The only purpose is to let control throttle us, and a quiet connection is the same effect. [Inference] our reconnect backoff already bounds a reconnect storm, so if Task 9 becomes too large this is the first thing that may be deferred to the daemon plan, and ignoring it is safe for correctness.
- **`DisableLogTail`: ignore.** There is no logtail.

Owner: Tasks 8 (parse), 9 (hooks, `want_read`), 10 (daemon exit hook, honours `want_read`).

### D3. c2n handlers (entries 45 and onward)

[Source] c2n arrives as a `PingRequest` with `Types: "c2n"`, `Payload` an HTTP/1 request, and the reply is an HTTP/1 response written to `POST URL` over Noise (`feature/c2n/c2n.go`). Handlers registered upstream: `/echo`, `/debug/{goroutines,prefs,metrics,component-logging,logheap,netmap,health,pprof/*}`, `POST /logtail/flush`, `POST /sockstats`, `POST /netfilter-kind`, `GET /tls-cert-status`, `GET /vip-services`, `/ssh/usernames`, `GET /appconnector/routes`, `GET /posture/identity`, `/debug/tka/log`, `POST /wol`, `GET|POST /update`, `GET /conn25/state`, `GET /debug/rejects`, `/remoteapi/localapi/*`. An unknown path gets `400 unknown c2n path`, a known path with the wrong method gets `405`.

**Decision: answer no c2n request, in this plan or the next ones.** Reasons:

- Upstream's own c2n-less builds do this (see Result), and still advertise the current version.
- Every handler is either diagnostic, or serves a feature this client does not have (updates, SSH, app connectors, VIP services, Wake-on-LAN, netfilter, posture, Tailnet Lock). `/update` is how control asks a client to self-update. This client never lets control drive an update: its own updater (milestone 14, added 2026-11-12) runs only when the user clicks it in the menu bar app.
- [Inference] unanswered c2n only makes the requester (an admin console action or a support tool) time out. Nothing in the map stream depends on it.

What to do when one arrives: log "c2n request ignored" with no payload and no URL, and drop it. Do not parse `Payload`.

An optional improvement, not owned by any milestone: reply `400 unknown c2n path` so the requester fails fast. It needs an HTTP/1 request-line parser and a response writer over the same stream as D1. Only do it if live use shows an admin action hanging on this node.

Entries covered by this decision: 45, 46, 52, 55, 69, 78, 80, 82, 108, 127, 128, 138, 142, 146.

### D4. `ControlDialPlan` (entry 44)

[Source] `direct.go` (stored by `c.dialPlan.Store`), `control/controlhttp/client.go`. The plan is a list of candidate IPs, some via an HTTPS CONNECT relay (`ACEHost`), each with a start delay and timeout. Upstream tries the plan first and **always falls back to DNS** (`"failed dialing using DialPlan, falling back to DNS"`), and an absent or empty plan means DNS.

**Decision: ignore it.** The JSON reader skips the field. Connection order stays: resolve the control host, port 80, then 443 (Task 9). It is an optimisation for networks where the normal dial fails. Cost of ignoring: on a network that blocks the control hostname's addresses and where only a plan address would work, we fail where upstream would succeed. No owner. Reopen if reports show that.

### D5. Entry 144, disco key advertisement around WireGuard handshakes

[Source] `wgengine/magicsock/magicsock.go` (`PriorityMessageForPeer`, `HandleDiscoKeyAdvertisement`), `net/packet/tsmp.go` (`TSMPDiscoKeyAdvertisement`), `wgengine/userspace.go` (`SetPeerPriorityMessageOnEstablishmentFunc`), `net/tstun/wrap.go` (receive side).

The advertisement is an IPv4 packet: IP protocol 99 (TSMP), source our tailnet IPv4, destination the peer's tailnet IPv4, payload 33 bytes: `0x61` (`'a'`) then our 32-byte disco public key. Upstream asks WireGuard for it through a callback that fires "whenever WireGuard establishes a new encryption keypair with an active peer, including during periodic key rotation". It is sent as a priority message (the first data packet on the new keypair). It is not sent to `IsWireGuardOnly` peers, and not if our disco key or our own address is missing.

[Inference] "priority message ... on establishment" is in the `tailscale/wireguard-go` fork, which is not in the reference tree. The exact point (initiator on handshake response, responder on first keepalive) is therefore unconfirmed. Sending it as the first transport packet on each newly established keypair, in both roles, is the faithful reading.

**Decision: honour the sending side. Keep 150.** Control-session plan (this one): nothing to do, there is no WireGuard. Reasons it is safe to keep 150 now: peers already learn our disco key from control, because `MapRequest.DiscoKey` carries it (Task 9, from `ts_state.disco_priv`). [Inference] the advertisement is a faster, in-band duplicate for peers, and the key it carries equals the one control gives them.

Owner: **the WireGuard/tunnel milestone (spec milestone 4).** It must:
1. Send the 33-byte TSMP packet above as a priority packet on every new keypair, to every non-`IsWireGuardOnly` peer that has an IPv4 address, when we have both our own IPv4 address and a disco key. Task 7 already persists the disco key.
2. Drop received IP protocol 99 packets, except that the **direct-connections milestone (8)** must parse an incoming `'a'` message (length at least 33), and use the key it carries as that peer's disco key. Until then, receiving is not needed: we do not run disco and use the control-provided `DiscoKey` only.
3. If this cannot be done when that milestone ships, lower `TS_CAPVER` to `143` in that milestone's plan and record it here. The Noise prologue, the Noise init header and `/key?v=` all read the one constant, so they move together. Nothing else between 144 and 150 forces a lower value.

**Status after milestone 4:** item 1 is done. The data plane builds the advertisement (`wg_priority` in `src/data/dataplane.c`) and the WireGuard device sends it as the priority packet on each new keypair (`send_priority` in `src/wg/device.c`), as initiator after the response and as responder on the first transport packet. The live check (`docs/tunnel-check.md`) saw it counted as one extra packet in each direction on a new session. The dropping half of item 2 is also done: received TSMP packets are counted and dropped before the filter. Parsing them stays with milestone 8. `TS_CAPVER` stays 150.

Risk to watch: [Inference] control may one day stop sending `Node.DiscoKey` for peers and rely on the advertisement. Upstream's endpoint code already copes with a peer whose only disco key came over TSMP (`epDisco.controlKey` can be zero). If peers appear with an empty `DiscoKey` in a live map, item 2 of the direct-connections milestone is then a hard requirement for that milestone. DERP-only tunnels are not affected, because WireGuard handshakes use node keys and never the disco key.

### D6. 429 and 503 handling (entries 137, 147)

[Source] `direct.go` (`isRateLimitedResponse`, `parseRateLimitError`, uses in `doLogin` and `sendMapRequest`), `auto.go` (`waitRetryAfter`, `maxRetryWindow`).

- **Which responses.** Status 429 always. Status 503 **only if a `Retry-After` header is present**; a 503 without it is an ordinary failure and uses normal backoff.
- **Which requests.** `/machine/register` (including the held `Followup`) and the initial response of `/machine/map` (both the status line, before any body). The same applies to any lite map request added later.
- **`Retry-After` value.** An integer number of seconds, or an HTTP-date (compute the difference from local time). If the result is not positive, unparseable, or more than 1 hour, use a random 5 to 10 seconds. Then clamp to 5 minutes (`maxRetryWindow`).
- **While waiting.** Do not advance the exponential backoff (upstream skips `BackOff` for rate limits and does not reset it either). When the wait ends, retry the same kind of request. Read at most the first 200 bytes of the body as the message, and never put a header or body into `status` or the log beyond that, since they could contain a login URL.
- **Status text.** `status` shows the state name plus "rate limited by control, retrying in N s".
- **Other non-200 replies.** Register: error with status and first 200 bytes of body, then normal backoff. Map: the same, except **404 means the node was deleted**. [Source] `ErrNodeRemoved`, `ipn/ipnlocal/local.go`: upstream shows "This device has been removed from the tailnet. Log in again to reconnect" and goes to NeedsLogin. Our session moves to `NEED_LOGIN` with that text, keeps retrying at the normal backoff (upstream does too and clears the state on the next map), and `ts_sess_up` registers with a fresh node key and `OldNodeKey` (as for expiry).

Owner: **Task 9.** Add tests: 429 with integer `Retry-After`; 429 with HTTP-date; 429 with 0, junk and 7200 (random 5 to 10 s); 503 with the header waits, 503 without it takes the normal backoff; 429 of 900 s waits 300 s; 404 on map gives `NEED_LOGIN` with the removed text.

## Other obligations the plan must carry

These are the entries that look ignorable but are not, so they are decisions too.

**D7. Map semantics (Task 8).** [Source] `map.go` `updatePeersStateFromResponse`.
- `Peers` replaces the peer set only if it is **non-empty**. An absent or empty `Peers` never clears peers. When `Peers` is non-empty, the other peer fields in that message (`PeersChanged`, `PeersRemoved`, `OnlineChange`, `PeerSeenChange`, `PeersChangedPatch`) are ignored. The last peer disappearing arrives as `PeersRemoved`. The plan text "Peers replaces the full peer set" needs this qualification, and a test: an empty `Peers` leaves existing peers alone.
- Delta order is: `PeersRemoved`, `PeersChanged`, `PeerSeenChange` (ignored), `OnlineChange`, then `PeersChangedPatch`. A patch or online change for an unknown ID is ignored.
- `Node` absent means self unchanged (entry 18). The first non-keepalive message with no `Node` is an error: "initial MapResponse lacked Node" (upstream returns it and reconnects).
- Absent `Domain`, `DNSConfig`, `DERPMap`, `PacketFilter`, `PacketFilters` mean unchanged (entries 6, 15, 17), so skipping them is correct.
- Also parse and skip: `MapSessionHandle`/`Seq` (upstream sends no reattach request at this commit, so every reconnect is a full new session), `PopBrowserURL` (upstream only forwards an `https` URL on `tailscale.com` or a subdomain to the user; this client ignores it and does not log it), `ClientVersion`, `ControlTime`, `UserProfiles`, `SSHPolicy`, `Health` and `DisplayMessages` (entries 24, 117), `DomainDataPlaneAuditLogID`, `CollectServices`, `DefaultAutoUpdate`.
- Add to `ts_node` now, at the cost of a few fields, so the tunnel plan does not reopen a tested parser: `key_expiry` (seconds since the Unix epoch, 0 when absent or `0001-01-01T00:00:00Z`), `jailed` (`IsJailed`), `wireguard_only` (`IsWireGuardOnly`). `key_expiry` is required for self (below), recommended for peers.
- Add to `ts_netmap`: `tka_enabled` (updated on every message carrying `TKAInfo`: set when `Disabled` is not true, cleared when it is; absent means unchanged, as upstream's `lastTKAInfo`), `have_exit` and `exit_code`, and the ping request from D1. Do not store `AllowedIPs`, `PrimaryRoutes`, `Endpoints`, `Capabilities` or `CapMap`.

**D8. Self key expiry (Tasks 8, 9).** [Source] `ipn/ipnlocal/local.go`: upstream decides the key has expired from `SelfNode.KeyExpiry` being non-zero and earlier than the local clock, checks that before the device-approval check, and goes to NeedsLogin (`nextStateLocked`). It does not rely on `Node.Expired` for self. Entry 53 says the client also honours an explicit `Expired`.
- Task 9: self is expired when `Expired` is true **or** `key_expiry` is non-zero and before the local clock. Check it before the `AWAIT_APPROVAL` test. An expired self moves the session to `NEED_LOGIN` ("node key expired, run `tsppc up`"). `ts_sess_up` then regenerates the node key, saves state with `old_node_priv` set, and registers with `OldNodeKey`, as the plan already specifies for `NodeKeyExpired`. Add a test.
- Wall clock caveat: a clock set far in the future would look like expiry. Accepted. A dead-battery clock is in the past, which fails TLS first (Task 6) and never reaches this check.
- Peers: upstream computes peer expiry client-side from `KeyExpiry` too. For the control-session plan, status shows a peer as expired if `Expired` is set. The tunnel milestone must treat a peer as expired if `Expired` is set or `key_expiry` is before now, and must not configure WireGuard for it.

**D9. Tailnet Lock (entries 40, 47, 51, 64).** [Source] `direct.go` `doLogin`: upstream sends `NLKey`, may attach `NodeKeySignature`, and if a register response contains a non-empty `NodeKeySignature` it re-registers. The spec says Tailnet Lock is unsupported and must give a clear error. The plan omits `NLKey` and the spike proved registration works without it.
- Task 8 sets `tka_enabled` as in D7. Tailnet Lock is a non-goal in the spec, so the client stops: Task 9 moves the session to `FAILED` with "Tailnet Lock is enabled on this tailnet and is not supported by this client", closes the connection, and never retries on its own (only an explicit `up` tries again). This client cannot verify peer signatures, so it must not run as a member of a locked tailnet.
- A register response with a non-empty `NodeKeySignature` is treated as the same problem: `FAILED`, no re-registering. Omit `TKAHead` from the map request.

**D10. `Hostinfo` and the streaming request (entry 68).** [Source] `tailcfg.go` `MapRequest` docs: with `Stream` true and version 68 or higher, control **ignores `Hostinfo`, `Endpoints` and other fields** in that request. They change only through a separate non-streaming request (`Stream` false, `OmitPeers` true, otherwise like the first, sent by `SendUpdate`; the response body is not needed, only the status). Hostinfo reaches control through the `Register` request.
- Control-session plan: nothing to build. Task 9's streaming `MapRequest` keeps sending `Hostinfo` as written (harmless). Task 7's `ts_hostinfo_json` should not grow fields in this plan.
- **DERP milestone (4):** our home DERP is `Hostinfo.NetInfo.PreferredDERP`, and control will not see it from the streaming request. That milestone must add the lite map request (and retry it, entry 58) whenever Hostinfo or the preferred DERP changes. Without it, peers cannot reach us over DERP. Entry 122 (`ExitNodeID`), 113 (`IngressEnabled`), 118 (`StateEncrypted`), 119 (`Location.Priority`), 108 (`ServicesHash`) are `Hostinfo` fields we simply do not set.

**D11. Early Noise payload (entry 49).** [Source] `control/ts2021/conn.go`. The server may send `\xff\xff\xffTS`, a BE32 length and JSON (`NodeKeyChallenge`) before HTTP/2. At this commit nothing consumes the challenge (`GetEarlyPayload` has no caller outside tests). Task 5 consuming and ignoring it, as written, is correct.

**D12. Keepalive and reconnect timing (Task 9).** [Source] upstream's map watchdog is 120 seconds with no message, and backoff is quadratic to a 30-second maximum (`auto.go`, `util/backoff`). The plan's 90 seconds with an HTTP/2 PING then 30 seconds more, and doubling backoff to 60 seconds, are more conservative and acceptable. Keep them.

**D13. Packet filter and tunnel entries (tunnel milestone, not this plan).** The fields are skipped in this plan. The tunnel plan must honour:
- 6, 13, 7, 32, 81, 93, 100, 109: `PacketFilter` nil means unchanged; `PacketFilters` map (key `"*"` with null clears all, `PacketFilter` is the implicit key `"base"`, applied first, then the map); `IPProto`, `SrcIPs` as CIDRs and ranges, `CapMatch`/`SrcCaps` ([Inference] a rule that needs peer capabilities cannot match without `CapMap` support, so it must be dropped, which errs toward deny); stateful return flows.
- 94 `IsJailed`: [Source] `net/tstun/wrap.go` uses a "shields up" filter for jailed peers: no new inbound flows, replies to our outbound flows allowed.
- 60 `IsWireGuardOnly`: skip such peers entirely (they need explicit endpoints, no DERP, no disco).
- 48, 112: `AllowedIPs` for each peer is only its own IPv4 `/32` addresses. Never subnet routes, `PrimaryRoutes` or exit routes, whatever the map says. That also makes `UnsignedPeerAPIOnly` harmless.
- 59, 77, 104 `SelfNodeV4MasqAddrForThisPeer`: ignore. It is used with one-CGNAT and site-to-site masquerading. Known limit: such tailnets are unsupported. Log once if seen.
- 65, 115, DERP map: `DERPMap` nil is unchanged. `Regions` nil with `HomeParams.RegionScore` set rescales latencies only. `OmitDefaultRegions` is only meaningful when `Regions` is non-nil. `NoMeasureNoHome` regions are never probed or chosen as home but may be used to reach a peer homed there. Deprecated `Avoid` is not used.
- 132 `disable-hosts-file-updates` node attribute: the hosts-file code must check the self `CapMap` for it (macOS upstream ignores it, but the spec promises to respect it), so Task 8's later successor needs to keep that single key.

## Changelog entries

One line for every entry that is not plainly safe to ignore. Anything not listed in this table is safe to ignore for the reasons in the next section.

| Entry | Meaning | What this client does |
|---|---|---|
| 6, 15, 17, 18 | nil `PacketFilter`, `DNSConfig`, empty `Domain`, nil `Node` mean unchanged | Absent means unchanged in the model (D7). |
| 7, 13, 32, 81, 93, 100, 109 | filter rule formats, incremental filters, stateful filtering | Skipped now; D13 for the tunnel plan. |
| 10, 16 | `PeerSeenChange`, `OnlineChange` | `OnlineChange` applied; `PeerSeenChange` ignored (D7). |
| 12, 31, 38 | `PingRequest` | D1. |
| 19, 25 | `Debug.SleepSeconds`, `Debug.Exit` | D2. |
| 24, 117 | `Health`, `DisplayMessages` | Parse and skip. Optional: Task 10 may show titles on the problem line. |
| 28, 39 | Noise, any HTTPS port | Implemented (Task 5). Port 80 then 443 (Task 9). |
| 33, 36 | `PeersChangedPatch` | `DERPRegion`, `Key`, `DiscoKey`, `Online`, `KeyExpiry` applied (upstream applies `KeyExpiry` too, and `key_expiry` is stored); `Endpoints`, `LastSeen`, `Capabilities`, `Cap`, `KeySignature` ignored. |
| 40, 47, 51, 64 | Tailnet Lock | D9. |
| 44 | `ControlDialPlan` | D4. |
| 45, 46, 52, 55, 69, 78, 80, 82, 108, 127, 128, 138, 142, 146 | c2n handlers | D3. |
| 48, 60, 94, 112 | `UnsignedPeerAPIOnly`, `IsWireGuardOnly`, `IsJailed`, nil `AllowedIPs` | D13 (tunnel plan). Fields stored per D7. |
| 49 | early Noise payload | D11. |
| 53 | explicit `Node.Expired`, expiry from `KeyExpiry` | D8. |
| 58 | lite map retries | Not needed until a lite request exists (D10). |
| 59, 77, 104 | masquerade addresses | Ignored; known limit (D13). |
| 65, 115 | `DERPMap` incremental, `NoMeasureNoHome` | DERP plan (D13). |
| 68 | streaming request ignores `Hostinfo` and `Endpoints` | D10. |
| 73, 79 | `ClientVersion` for non-Windows | Parse and skip. |
| 84, 126 | seamless key renewal | [Inference] no client code for it exists at this commit (the changelog line is the only mention), so it is a control-side behaviour. The client's part is the ordinary re-register with `OldNodeKey` (D8). |
| 111 | peer `HomeDERP` | Stored (`home_derp`). The legacy `LegacyDERPString` form `127.3.3.40:N` maps to region N, as upstream's `upgradeNode` does; the DERP plan owns its use. |
| 108, 113, 118, 119, 122 | `Hostinfo` fields | Not set (D10). |
| 130 | hardware attestation fields | Not sent. |
| 132 | `disable-hosts-file-updates` | D13. |
| 137, 147 | 429 and 503 | D6. |
| 144 | disco key advertisement | D5. |
| 149, 135 | cache-network-maps | Ignored. There is no on-disk netmap cache. |
| 143, 150 | conn25, `magicip` app connectors | Ignored. The node never advertises itself as an app connector, so control has nothing to configure. |

## Why the remaining entries are safe to ignore

- **Features we do not have.** SSH (27, 43, 61, 62, 63, 96, 101, 105, 110), exit nodes and DNS for them (41, 76, 95, 125), Taildrop and Taildrive (34, 90, 91), Funnel and ingress (50, 113), app connectors (107, 150), subnet and one-CGNAT routing (57, 71, 92), peer relays (120, 121, 129), Wake-on-LAN (78), auto-update (83, 131), IPv6 (5, 8, 11, 116, 133), MagicDNS resolver, split DNS and DoH (9, 14, 21, 22, 23, 42, 56, 75, 97, 99, 125), services (108), posture (98), logtail. The client neither advertises nor answers any of these, so control has nothing to expect.
- **Node attributes and tuning knobs.** 54, 66, 67, 70, 72, 74, 85, 86, 87, 88, 89 (deleted `PeerChange.Capabilities`; we ignore `Capabilities` anyway), 102, 103, 114, 124, 134, 136, 139, 140, 141, 145, 148. A node attribute only changes behaviour of code we do not have; unknown map fields and `CapMap` keys are skipped by the JSON reader. Entry 145 (`scope-quad100-macos`) is for the 100.100.100.100 resolver we do not run. 136 and 140 to 141 are Linux and GRO/GSO tuning. 148 `StableTailnetID` is a node field we do not need.
- **Pure fixes and bumps.** 3, 4, 20, 26, 37 (`Debug` sticky flags, removed by 70), 106, 123, 129.
- **Entry 29 `PopBrowserURL`.** Ignored and not logged (D7). **Entry 30** id tokens are never requested.

## Checks for Task 11 (live acceptance)

- No `PingRequest` arrives with `URLIsNoise` false (D1 item 4). Record only counts and the field value.
- A plain liveness ping, if one arrives, is answered (D1 item 2). Record only that it was seen and answered.
- A map message carries `TKAInfo` only on Tailnet Lock tailnets (D9). Expect none on the owner's tailnet.
- Record whether `Peers` is ever sent empty, and confirm that peer removal arrives as `PeersRemoved` (D7).
- Optional: run `ts_sess_logout`, then `up` again, to exercise the re-register path (D8) with a real server.

## When to revisit

Update `TS_CAPVER` only when control starts rejecting the client or a needed feature requires it, and then review every new entry against the same questions. A rejection must surface in `status`.
