# Control Session Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A PowerPC Mac logs in to a hosted tailnet, keeps a live network map open, and shows its real peers through a `tsppc status` command.

**Architecture:** Protocol code is sans-I/O C: JSON, HPACK, HTTP/2, Noise and the netmap each take bytes and produce bytes, so they are tested and fuzzed on the host. A single-threaded `select()` daemon owns sockets, DNS helper, state and a Unix control socket.

**Tech Stack:** C (gnu99), BearSSL 0.6, GNU make 3.81, clang on the host, gcc-4.0 with the 10.4u SDK for PowerPC.

**Spec:** `docs/superpowers/specs/2026-11-10-tailscale-ppc-design.md`

**Scope:** Spec milestone 3 only. No tunnel, DERP, WireGuard, packet filter or launchd. Those plans follow.

## Global Constraints

- PowerPC flags: `gcc-4.0 -std=gnu99 -arch ppc -isysroot /Developer/SDKs/MacOSX10.4u.sdk -mmacosx-version-min=10.4`.
- Capability version is one compile-time constant, `TS_CAPVER`, value `150`.
- `Hostinfo.OS` is `macOS`. `OSVersion` is the real version. `IPNVersion` is `0.1.0-ppc`. `GoArch` is `ppc`. `Hostname` is the machine's short hostname.
- Programs are `tsppcd` and `tsppc`. Never install or name anything `tailscale` or `tailscaled`.
- Limits: at most 256 peers; at most 4 MiB for one map message; daemon target about 16 MB. Each is a named compile-time constant, and exceeding one produces a clear status message, never a crash.
- `MapRequest.Compress` is left empty. No zstd decoder.
- IPv6 addresses and IPv6 filter rules are ignored, not stored.
- All serialisation uses `ts_get_*`/`ts_put_*`. Never overlay structs on wire data.
- Every parser in this plan has a host unit test and a mutation-fuzz target under AddressSanitizer and UBSan.
- `spike/` is never compiled, copied from, or committed.
- No keys, state files, login URLs, tailnet names or personal machine details in the repository, logs, status output (except a login URL shown to the operator) or test fixtures. Private keys never appear in any log.
- Our code builds clean with `-Wall -Wextra -Werror`, and also with gcc-4.0 on the Leopard VM.
- Public symbols start with `ts_`.
- This repository is public. VM SSH access is via `TSPPC_SSH_CONFIG` and `TSPPC_VM_USER`.

## Review Focus

1. Bytes arriving split at every possible boundary, across TCP reads, Noise records and HTTP/2 frames: the result must equal one-shot delivery. Test in Tasks 4 and 5.
2. An approval that takes hours, and a Followup request the server ends without approval: one request stays held, and a new one follows only after the previous ends, with backoff and no tight loop. Test in Task 9.
3. A connection that drops, a GOAWAY, or an unreachable control server: reconnect with backoff and jitter, keep node identity. Test in Task 9.
4. A map message over 4 MiB, more than 256 peers, or deep or malformed JSON: a clear error, no crash. Test in Tasks 2 and 8.
5. A wrong system clock: TLS fails with "system clock is wrong" in `status`, not a generic failure. Test in Task 6.

---

### Task 0: Capability review

The result feeds Tasks 8 and 9, so it comes first.

**Files:**
- Create: `docs/capver-review.md`

**Interfaces:**
- Produces: the final value of `TS_CAPVER`, and a decision for each obligation below that later tasks follow.

- [ ] **Step 1: Review the capability changelog** in `tailcfg/tailcfg.go` of `tailscale/tailscale` at commit 9476be9, every entry from the start through `150`. Write one line per entry that isn't plainly safe to ignore, with what the client does about it. Give explicit decisions on: `MapResponse.PingRequest` (12, 31, 38), c2n handlers (45 onward), `Debug.Exit` and `SleepSeconds` (19, 25), `ControlDialPlan` (44), entry 144 (disco key advertisement around WireGuard handshakes), and 429 and 503 handling (137, 147). If an entry can't be honoured, lower `TS_CAPVER` and record the new value.
- [ ] **Step 2: Commit.** `git commit -m "Record capability version review"` with that file.

### Task 1: Constant-time Poly1305 on PowerPC

The final review of the foundation stage found that receiving recomputes Poly1305 for attacker-chosen forgeries, so a variable-time multiply on G3 and G4 can be observed repeatedly. The control channel is the first network-facing use.

**Files:**
- Modify: `src/crypto/aead.c`, `src/crypto/nacl.c`, `src/crypto/nacl.h`, `src/crypto/x25519.c`, `Makefile`, `tools/vm-test.sh`
- Test: `tests/test_nacl.c`, `tests/test_aead.c`

**Interfaces:**
- Consumes: BearSSL `br_poly1305_ctmul32_run`, which uses `MUL15`.
- Produces: unchanged public signatures. On `__ppc__`, `ts_aead_seal`/`open` use `br_poly1305_ctmul32_run`. `ts_poly1305` uses a limb layout whose every multiply goes through a `TS_MUL15` macro, constant-time when `BR_CT_MUL15` is set.

- [ ] **Step 1: Write the failing test.** Add a host make target `ct-test` built with `-DBR_CT_MUL15=1 -DBR_CT_MUL31=1 -DTS_FORCE_CT_POLY=1`, instrumented vendor objects included, that runs the whole suite. `TS_FORCE_CT_POLY` selects the PowerPC code paths on the host. Existing RFC 8439 vectors, A.3 vectors and AEAD vectors are the tests. Also add, carried over from the foundation review: `ts_x25519` wipes `out` on rejection; a tampered in-place `ts_aead_open` wipes; `ctlen == 16` with non-empty AD; and `ts_x25519` with `out == priv` gives the right result.
- [ ] **Step 2: Run to verify it fails.** Run: `make ct-test`. Expected: compile failure, or a `#error` that the constant-time path doesn't exist yet.
- [ ] **Step 3: Implement.** Add `-DBR_CT_MUL15=1` to `CTMUL` for `ppc-test`. Extend the `#error` guard to `aead.c` and `nacl.c`. `ts_poly1305` currently uses 26-bit limbs with 64-bit products, so this is a new limb layout on PowerPC, with no multiply wider than 15 by 17 bits, as in BearSSL's `ctmul32`. Compile flags must become a dependency of every object, using a flags stamp file or a flags-keyed object directory, so a changed flag rebuilds `build/vendor-ppc` on the VM. Make `ts_x25519` read the scalar before overwriting `out`. Correct the `nacl.h` comment. Record in a new `docs/known-limits.md` that BearSSL's X25519 leaves a clamped scalar on its own stack, with the decision to accept it until long-term key handling is reviewed.
- [ ] **Step 4: Run to verify it passes.** Run: `make test asan ct-test` and `TSPPC_SSH_CONFIG=$CFG TSPPC_VM_USER=$U tools/vm-test.sh leopard`. Expected: `RESULT: all passed` from each. Evidence in the report: the compile line for `poly1305_ctmul32.c` on the VM shows `-DBR_CT_MUL15=1`, and it was recompiled in this run.
- [ ] **Step 5: Commit.** `git commit -m "Use constant-time Poly1305 on PowerPC"` with the files above and `docs/known-limits.md`.

### Task 2: Hex, base64, bounded JSON reader and fuzz harness

**Files:**
- Create: `src/proto/encoding.h`, `src/proto/encoding.c`, `src/proto/json.h`, `src/proto/json.c`
- Create: `tests/test_encoding.c`, `tests/test_json.c`, `tests/fuzz.h`, `tests/fuzz.c`, `tests/fuzz_json.c`
- Modify: `Makefile`, `tests/main.c`

**Interfaces:**
- Produces: `size_t ts_hex_encode(char *out, size_t cap, const uint8_t *in, size_t n)`; `int ts_hex_decode(uint8_t *out, size_t want, const char *hex, size_t hexlen)`; `size_t ts_b64_encode(char *out, size_t cap, const uint8_t *in, size_t n)`.
- Produces, in `json.h`: `TS_JSON_MAX_DEPTH` (`32`); `ts_json_type` with `TS_JSON_OBJ_START`, `OBJ_END`, `ARR_START`, `ARR_END`, `KEY`, `STRING`, `NUMBER`, `TRUE`, `FALSE`, `NUL`, `END`, `ERROR`; `ts_json_tok { ts_json_type type; const char *raw; size_t rawlen; }`; `void ts_json_init(ts_json *j, const char *buf, size_t len)`; `ts_json_type ts_json_next(ts_json *j, ts_json_tok *t)`; `int ts_json_skip(ts_json *j, const ts_json_tok *first)` (consumes the rest of a value); `int ts_json_string(char *out, size_t cap, const ts_json_tok *t)` (decodes escapes, including surrogate pairs, -1 if it doesn't fit or is invalid); `int ts_json_int64(int64_t *out, const ts_json_tok *t)`.
- Produces, in `fuzz.h`: `void ts_fuzz_run(const char *name, void (*target)(const uint8_t *, size_t), const uint8_t *const *seeds, const size_t *seedlens, size_t nseeds, unsigned iterations)`. It uses a fixed-seed PRNG and applies bit flips, byte substitutions, truncations, insertions and splices. Apple's clang has no libFuzzer runtime, so this is deterministic and needs none. Make target `make fuzz`, under ASan and UBSan, default 200000 iterations per target. Each later parser adds one `tests/fuzz_<name>.c`.

- [ ] **Step 1: Write the failing tests.** `ts_hex_encode` of `00ff` is `"00ff"`. `ts_hex_decode` rejects odd length, wrong length and non-hex. `ts_b64_encode` of `"hello"` is `"aGVsbG8="`, and of an empty input is empty. JSON: token sequence of `{"a":[1,true,null,"x\n"],"b":{}}`; whitespace everywhere is tolerated; `ts_json_string` decodes `é` and `😀` to UTF-8. Errors return `TS_JSON_ERROR`: trailing commas, missing colons, unterminated strings, raw control characters, a lone surrogate, and depth 33. Depth 32 passes. A string too big for `out` returns -1 and never writes past `cap`.
- [ ] **Step 2: Run to verify it fails.** Run: `make test`. Expected: missing `encoding.h`.
- [ ] **Step 3: Implement** as a pull parser that holds no allocation and never reads past `len`.
- [ ] **Step 4: Run to verify it passes.** Run: `make test asan fuzz`. Expected: `RESULT: all passed` and `fuzz json: 200000 iterations, no faults`.
- [ ] **Step 5: Commit.** `git commit -m "Add encodings, bounded JSON reader and fuzz harness"` with the files above.

### Task 3: HPACK

**Files:**
- Create: `src/proto/hpack.h`, `src/proto/hpack.c`, `src/proto/hpack_huffman.inc`, `tests/test_hpack.c`, `tests/fuzz_hpack.c`
- Modify: `tests/main.c`, `Makefile`

**Interfaces:**
- Produces: `TS_HPACK_TABLE_MAX` (`4096`), `TS_HPACK_FIELD_MAX` (`8192`); `void ts_hpack_init(ts_hpack *d)`; `typedef void (*ts_hpack_cb)(void *user, const char *name, size_t nlen, const char *value, size_t vlen)`; `int ts_hpack_decode(ts_hpack *d, const uint8_t *block, size_t len, ts_hpack_cb cb, void *user)` (0 or -1); `size_t ts_hpack_encode(uint8_t *out, size_t cap, const char *name, const char *value)` (literal without indexing and without Huffman, returns 0 if it doesn't fit).

- [ ] **Step 1: Write the failing tests.** RFC 7541 Appendix C sequences, each decoded in order on one decoder, confirmed against the Python `hpack` library:
  - C.3 without Huffman: `828684410f7777772e6578616d706c652e636f6d`, then `828684be58086e6f2d6361636865`, then `828785bf400a637573746f6d2d6b65790c637573746f6d2d76616c7565`.
  - C.4 with Huffman: `828684418cf1e3c2e5f23a6ba0ab90f4ff`, then `828684be5886a8eb10649cbf`, then `828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf`.
  - Expected for the third of each: `:method GET`, `:scheme https`, `:path /index.html`, `:authority www.example.com`, `custom-key custom-value`.

  Also: dynamic table eviction when a size update shrinks the table; a size update above the 4096 limit returns -1; a table index that doesn't exist returns -1; an integer that overflows 32 bits returns -1; invalid Huffman padding returns -1; and encode-then-decode round-trips.
- [ ] **Step 2: Run to verify it fails.** Run: `make test`. Expected: missing `hpack.h`.
- [ ] **Step 3: Implement.** Take the Huffman table from RFC 7541 Appendix B. Add a test that every one of the 256 byte values decodes correctly, with expected encodings generated by the Python `hpack` library and committed as a fixture. The dynamic table is a fixed ring in `ts_hpack`.
- [ ] **Step 4: Run to verify it passes.** Run: `make test asan fuzz`. Expected: all pass, `fuzz hpack` reports no faults.
- [ ] **Step 5: Commit.** `git commit -m "Add HPACK decoder and literal encoder"` with the files above.

### Task 4: HTTP/2 client

**Files:**
- Create: `src/proto/h2.h`, `src/proto/h2.c`, `tests/test_h2.c`, `tests/fuzz_h2.c`
- Modify: `tests/main.c`, `Makefile`

**Interfaces:**
- Consumes: Task 3 HPACK.
- Produces: `TS_H2_MAX_STREAMS` (`8`), `TS_H2_WINDOW` (`1048576`); `ts_h2_cbs { void (*headers)(void*, uint32_t sid, int status); void (*header)(void*, uint32_t sid, const char *n, size_t nl, const char *v, size_t vl); void (*data)(void*, uint32_t sid, const uint8_t*, size_t); void (*end)(void*, uint32_t sid, int error); void (*goaway)(void*, uint32_t last_sid, uint32_t code); }`.
- Produces: `void ts_h2_init(ts_h2 *c, const ts_h2_cbs *cbs, void *user)`; `int ts_h2_feed(ts_h2 *c, const uint8_t *in, size_t n)`; `size_t ts_h2_output(ts_h2 *c, const uint8_t **out)` and `void ts_h2_consumed(ts_h2 *c, size_t n)`; `int ts_h2_consume_data(ts_h2 *c, uint32_t sid, size_t n)` (returns window credit after the app has finished with data); `int ts_h2_request(ts_h2 *c, uint32_t *sid, const char *method, const char *path, const char *authority, const char *const *headers, size_t nheaders /* name, value pairs; count of pairs */, const uint8_t *body, size_t bodylen)`; `int ts_h2_cancel(ts_h2 *c, uint32_t sid)`; `void ts_h2_ping(ts_h2 *c)`.

Requests use `:scheme https`. The client sends its preface first. It sends a SETTINGS frame with `SETTINGS_ENABLE_PUSH` 0 and `SETTINGS_INITIAL_WINDOW_SIZE` `TS_H2_WINDOW`, then a connection WINDOW_UPDATE. A request body larger than the peer's window or `MAX_FRAME_SIZE` is queued and sent as credit arrives.

- [ ] **Step 1: Write the failing tests** against a scripted server in the test file, using frame bytes built by hand:
  - The client's output begins with the 24-byte preface `PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`, followed by SETTINGS.
  - The server's SETTINGS gets an ACK. PING gets an ACK with the same 8 bytes.
  - A response with status 200 and a body delivers `headers`, `data`, `end` in order.
  - HEADERS followed by CONTINUATION decodes as one block. A padded DATA frame delivers only the data.
  - A 1 MiB response only completes if the client sends WINDOW_UPDATE after `ts_h2_consume_data`; without consuming it stalls at the window.
  - A request body bigger than the peer's initial window is delivered in full once WINDOW_UPDATE arrives.
  - Two concurrent streams interleave correctly.
  - RST_STREAM calls `end` with an error. GOAWAY calls `goaway`.
  - Frames over `MAX_FRAME_SIZE`, CONTINUATION on the wrong stream, and DATA beyond the advertised window return -1 from `ts_h2_feed`.
  - **Split test:** a recorded server stream fed one byte at a time gives identical callbacks to feeding it whole.
- [ ] **Step 2: Run to verify it fails.** Run: `make test`. Expected: missing `h2.h`.
- [ ] **Step 3: Implement** with fixed buffers and no heap growth, except one allocation per connection for the output queue, capped at a named limit.
- [ ] **Step 4: Run to verify it passes.** Run: `make test asan fuzz`. Expected: all pass, `fuzz h2` reports no faults.
- [ ] **Step 5: Commit.** `git commit -m "Add HTTP/2 client"` with the files above.

### Task 5: Noise control transport

**Files:**
- Create: `src/control/noise.h`, `src/control/noise.c`, `src/control/upgrade.h`, `src/control/upgrade.c`, `tests/test_noise.c`, `tests/fuzz_noise.c`
- Modify: `tests/main.c`, `Makefile`

**Interfaces:**
- Consumes: BLAKE2s, HKDF, X25519, AEAD, encoding helpers.
- Produces, in `noise.h`: `TS_NOISE_INIT_LEN` (`101`), `TS_NOISE_RESP_LEN` (`51`), `TS_NOISE_MAX_PLAIN` (`4077`), `TS_CAPVER`; `int ts_noise_init(ts_noise *n, uint8_t init[TS_NOISE_INIT_LEN], const uint8_t machine_priv[32], const uint8_t control_pub[32], uint16_t capver)`; `int ts_noise_read_response(ts_noise *n, const uint8_t resp[TS_NOISE_RESP_LEN])`; `size_t ts_noise_seal(ts_noise *n, uint8_t *out, size_t cap, const uint8_t *pt, size_t ptlen)` (one or more records); `int ts_noise_feed(ts_noise *n, const uint8_t *in, size_t len, void (*deliver)(void *, const uint8_t *, size_t), void *user)` (reassembles records, -1 on bad record, bad tag or error frame).
- Produces, in `upgrade.h`: `size_t ts_upgrade_request(char *out, size_t cap, const char *host, const uint8_t init[TS_NOISE_INIT_LEN])`; `int ts_upgrade_response(const char *buf, size_t len, size_t *consumed)` (0 = 101 received, 1 = need more, -1 = refused); `int ts_early_payload(const uint8_t *buf, size_t len, size_t *consumed)` (0 = consumed magic-framed payload or none present, 1 = need more, -1 = oversized).

Wire format as in the spec's Appendix A "Proven" section: request line `POST /ts2021 HTTP/1.1`, `Upgrade: tailscale-control-protocol`, `Connection: upgrade`, `X-Tailscale-Handshake: <base64>`. Records are `[4, BE16 len, ciphertext]`. Nonce is 4 zero bytes plus a **big-endian** counter. Early payload is `\xff\xff\xffTS` + BE32 length + JSON, and is parsed and otherwise ignored in this plan.

- [ ] **Step 1: Write the failing tests** using a responder in the test file written from the Noise specification (`Noise_IK_25519_ChaChaPoly_BLAKE2s`, prologue `"Tailscale Control Protocol v150"` then MixHash of the control public key):
  - Initiator and responder complete the handshake and share transport keys, with client send matching responder receive. The init is exactly 101 bytes with header `BE16 version, 1, BE16 96`; the response is `2, BE16 48`.
  - A wrong control public key fails `ts_noise_read_response`.
  - Records round-trip. The first record's nonce uses counter 0, verified by the responder decrypting with a big-endian counter.
  - A 10000-byte payload splits into records of at most 4077 plain bytes.
  - **Split test:** several records fed one byte at a time deliver the same plaintext.
  - A flipped ciphertext bit and a type-3 error frame each return -1.
  - Upgrade: a split 101 response returns 1 and then 0 with the right `consumed`; a 200 returns -1.
  - Early payload: magic, length, JSON is consumed; the absence of magic consumes nothing; a length over 64 KiB returns -1.
- [ ] **Step 2: Run to verify it fails.** Run: `make test`. Expected: missing `noise.h`.
- [ ] **Step 3: Implement** sans-I/O, wiping handshake secrets when the split completes. The responder in the test shares our reading of the spec, so the live test in Task 11 is the real proof of interoperability.
- [ ] **Step 4: Run to verify it passes.** Run: `make test asan fuzz`. Expected: all pass.
- [ ] **Step 5: Commit.** `git commit -m "Add Noise control transport"` with the files above.

### Task 6: Sockets, DNS helper, TLS and the control key

**Files:**
- Create: `src/net/sock.h`, `src/net/sock.c`, `src/net/resolve.h`, `src/net/resolve.c`, `src/net/tls.h`, `src/net/tls.c`, `src/net/anchors.c`, `tools/gen_anchors.py`, `tests/test_net.c`
- Modify: `tests/main.c`, `Makefile`

**Interfaces:**
- Produces: `int ts_tcp_start(const char *ip, uint16_t port)` (non-blocking fd or -1); `int ts_tcp_finish(int fd)` (0 connected, -1 failed, uses `SO_ERROR`).
- Produces: `int ts_resolve_start(ts_resolve *r, const char *host)`; `int ts_resolve_fd(const ts_resolve *r)`; `int ts_resolve_finish(ts_resolve *r, char *ip_out, size_t cap)` (1 = pending, 0 = done, -1 = failed); `void ts_resolve_cancel(ts_resolve *r)`. It forks a helper that calls `getaddrinfo` for IPv4 and writes the answer to a pipe, so DNS never blocks the daemon. The helper's lifetime is bounded by an `alarm()`.
- Produces: `ts_tls` over a caller-supplied non-blocking fd, wrapping `br_ssl_client_context` and `br_x509_minimal_context`: `int ts_tls_start(ts_tls *t, int fd, const char *host)`; `int ts_tls_step(ts_tls *t)` (drives I/O, 1 = progress wanted, 0 = done, -1 = failed); `int ts_tls_read`, `int ts_tls_write`; `const char *ts_tls_error(const ts_tls *t)`, which calls the pure function `const char *ts_tls_classify(int br_err, time_t now, time_t build_time)`. Certificate time errors, and a `now` before `build_time`, give the exact text `system clock is wrong`.
- Produces: `int ts_control_key_parse(uint8_t pub[32], const char *json, size_t len)` for the `/key` response (`publicKey`, value `mkey:<hex>`, whitespace tolerated).
- Produces: `ts_keyfetch`, a non-blocking sequence of resolve, TCP to 443, TLS and HTTP/1.1 `GET /key?v=<capver>`: `int ts_keyfetch_start(ts_keyfetch *k, const char *host, int capver)`; `int ts_keyfetch_fds(const ts_keyfetch *k, fd_set *r, fd_set *w, int *maxfd)`; `int ts_keyfetch_step(ts_keyfetch *k, uint8_t pub[32])` (1 = pending, 0 = done, -1 = failed, with `ts_keyfetch_error`). Bounded to a 64 KiB response.
- The same `ts_tls` also wraps the control connection for the port 443 fallback, where Task 9's `io->connect` asks for port 443.
- `tools/gen_anchors.py` writes `src/net/anchors.c` from the ISRG Root X1 and X2 PEMs fetched from Let's Encrypt, recording their SHA-256 fingerprints in a comment. Both must parse in BearSSL.

- [ ] **Step 1: Write the failing tests.** `ts_control_key_parse` accepts pretty-printed JSON and rejects a wrong prefix, wrong length and non-hex. `ts_tcp_start` against a local listener connects. `ts_resolve` resolves `localhost` to `127.0.0.1` and fails for `no-such-host.invalid`. A local TLS test is left to the live run, and `ts_tls_error` is covered by testing `ts_tls_classify`: `BR_ERR_X509_EXPIRED` gives `system clock is wrong`; `BR_ERR_X509_NOT_TRUSTED` with `now < build_time` gives the same text; and with a sensible clock gives a different message.
- [ ] **Step 2: Run to verify it fails.** Run: `make test`. Expected: missing `sock.h`.
- [ ] **Step 3: Implement, and generate the anchors.** Note the fingerprints in the commit message. Also verify `ts_keyfetch` live against `controlplane.tailscale.com`, from a small test program on the host and on the Leopard VM. Expected: a key that parses.
- [ ] **Step 4: Run to verify it passes.** Run: `make test asan`, then `tools/vm-test.sh leopard`. Expected: all pass.
- [ ] **Step 5: Commit.** `git commit -m "Add sockets, DNS helper, TLS and control key parsing"` with the files above.

### Task 7: Node state and Hostinfo

**Files:**
- Create: `src/state/store.h`, `src/state/store.c`, `src/state/hostinfo.h`, `src/state/hostinfo.c`, `tests/test_store.c`, `tests/fuzz_store.c`
- Modify: `tests/main.c`, `Makefile`

**Interfaces:**
- Produces: `TS_STATE_DIR` (`/var/db/tsppc`), overridable by `TSPPC_STATE_DIR` only in `-DTS_TEST_HOOKS` builds; `ts_state { uint8_t machine_priv[32], node_priv[32], old_node_priv[32], disco_priv[32]; int have_old_node; int have_login; }`; `int ts_state_load_or_create(ts_state *s, const char *dir, char *err, size_t errcap)`; `int ts_state_save(const ts_state *s, const char *dir, char *err, size_t errcap)`.
- Produces: `int ts_hostinfo_json(char *out, size_t cap)`, which uses the Global Constraints values and the real OS version from `/usr/bin/sw_vers -productVersion`.

- [ ] **Step 1: Write the failing tests.** Create in a temp dir generates three different keys. Load returns the same keys. Directory mode is 0700 and file mode is 0600. A world-readable or wrong-owner state directory is refused with a clear message. A corrupted or truncated file returns an error and is not overwritten. Save leaves no temp file behind. `ts_hostinfo_json` is valid JSON with `"OS":"macOS"`, `"GoArch":"ppc"` and `"IPNVersion":"0.1.0-ppc"`.
- [ ] **Step 2: Run to verify it fails.** Run: `make test`. Expected: missing `store.h`.
- [ ] **Step 3: Implement** with write-to-temp, `fsync`, `rename`, and `fsync` of the directory.
- [ ] **Step 4: Run to verify it passes.** Run: `make test asan fuzz`. Expected: all pass.
- [ ] **Step 5: Commit.** `git commit -m "Add node state and Hostinfo"` with the files above.

### Task 8: Network map model

**Files:**
- Create: `src/control/netmap.h`, `src/control/netmap.c`, `tests/test_netmap.c`, `tests/fuzz_netmap.c`
- Modify: `tests/main.c`, `Makefile`

**Interfaces:**
- Consumes: Task 2 JSON.
- Produces: `TS_MAX_PEERS` (`256`), `TS_MAP_MSG_MAX` (`4194304`); `ts_node { int64_t id; char name[256]; uint8_t node_key[32], disco_key[32]; uint32_t ipv4; int have_ipv4; int home_derp; int online; int authorized; int expired; }`; `ts_netmap { ts_node self; int have_self; ts_node *peers; size_t npeers; char last_error[128]; ... }`.
- Produces: `int ts_netmap_init(ts_netmap *m)`, `void ts_netmap_free(ts_netmap *m)`; `int ts_netmap_apply(ts_netmap *m, const char *json, size_t len)` (0 or -1, sets `last_error`); `ts_map_stream` with `void ts_map_stream_init(ts_map_stream *s, void (*msg)(void *, const char *, size_t), void *user)`, `int ts_map_stream_feed(ts_map_stream *s, const uint8_t *in, size_t n)`, for messages framed by a 4-byte **little-endian** length.

Semantics, from upstream's `tailcfg`: `Node` replaces self when present. `Peers` replaces the full peer set. `PeersChanged` upserts. `PeersRemoved` removes by ID. `PeersChangedPatch` applies only the fields present: `DERPRegion`, `Key`, `DiscoKey`, `Online`, and others ignored. `OnlineChange` is a map of ID string to bool, and `PeerSeenChange` is ignored. `KeepAlive` responses change nothing. Absent fields mean unchanged. Node fields used: `ID`, `Name`, `Key` (`nodekey:<hex>`), `DiscoKey` (`discokey:<hex>`), `Addresses` (first IPv4, prefix `/32`), `HomeDERP`, `Online`, `MachineAuthorized`, `Expired`. Self's `MachineAuthorized` drives the device-approval state. `DERPMap` and packet filter fields are skipped here and owned by the next plan.

- [ ] **Step 1: Write the failing tests** using hand-written JSON fixtures with invented keys and names:
  - a first full map gives self and peers, IPv4 chosen when an IPv6 address comes first;
  - a `MachineAuthorized:false` self reports not authorized, and a later `PeersChanged` plus a `Node` with `true` reports authorized;
  - add, change and remove peers incrementally; `PeersChangedPatch` changes only `Online`; `OnlineChange` works;
  - `KeepAlive` leaves everything unchanged;
  - 257 peers returns -1 with `last_error` naming the limit, and leaves the prior map intact;
  - unknown fields of any type are skipped;
  - **Split test:** stream framing, one byte at a time, gives the same messages. A declared length over `TS_MAP_MSG_MAX` returns -1 without allocating.
- [ ] **Step 2: Run to verify it fails.** Run: `make test`. Expected: missing `netmap.h`.
- [ ] **Step 3: Implement.** Peers allocate once at `TS_MAX_PEERS`.
- [ ] **Step 4: Run to verify it passes.** Run: `make test asan fuzz`. Expected: all pass.
- [ ] **Step 5: Commit.** `git commit -m "Add network map model"` with the files above.

### Task 9: Control session state machine

**Files:**
- Create: `src/control/session.h`, `src/control/session.c`, `tests/test_session.c`
- Modify: `tests/main.c`, `Makefile`

**Interfaces:**
- Consumes: Tasks 4, 5, 7, 8.
- Produces: `ts_sess_state`: `TS_SESS_IDLE`, `CONNECTING`, `NEED_LOGIN`, `AWAIT_APPROVAL`, `RUNNING`, `BACKOFF`, `FAILED`; `ts_sess_io { int (*connect)(void *, const char *host, uint16_t port); int (*send)(void *, const uint8_t *, size_t); void (*disconnect)(void *); }`; `void ts_sess_init(ts_sess *s, const ts_state *st, const ts_sess_io *io, void *user, const uint8_t control_pub[32], const char *hostinfo_json)`; `void ts_sess_connected(ts_sess *s)`; `void ts_sess_recv(ts_sess *s, const uint8_t *in, size_t n)`; `void ts_sess_disconnected(ts_sess *s, const char *why)`; `void ts_sess_tick(ts_sess *s, uint64_t now_ms)`; `void ts_sess_up(ts_sess *s)`; `void ts_sess_status(const ts_sess *s, char *out, size_t cap)`; `const char *ts_sess_login_url(const ts_sess *s)`.

Behaviour:
- **Connect order:** port 80 first, then port 443 on failure.
- **Register:** `POST /machine/register`, `content-type: application/json`, `Ts-Lb: nodekey:<hex>`, body with `Version`, `NodeKey`, `Expiry` `"0001-01-01T00:00:00Z"`, `Hostinfo`, and `Ephemeral` false. Omit `NLKey`.
- **Followup:** after `AuthURL`, send one request with `Followup` set to it, and hold it. Send only after the previous request ended. Interval between sends has a floor of 2 seconds with exponential backoff, so a server that ends requests quickly can't cause a tight loop.
- **Retry-After:** 429 and 503 honour `Retry-After`.
- **Map:** `POST /machine/map`, same `Ts-Lb` header, body with `Version`, `KeepAlive:true`, `NodeKey`, `DiscoKey`, `Stream:true`, `Hostinfo`, and no `Compress`.
- **Authorization:** `AWAIT_APPROVAL` is entered when login completed and self isn't `MachineAuthorized`, and leaves automatically on a map update showing authorized. No tunnel exists in this plan, but later plans gate on this state.
- **Keepalive:** after 90 seconds without bytes from the server, send an HTTP/2 PING; after a further 30 seconds without a reply, disconnect.
- **Reconnect:** on disconnect or GOAWAY, `BACKOFF` for 1 second doubling to 60 seconds with up to 25 percent jitter; reset after 60 seconds of `RUNNING`. Identity is kept.
- **Expired key:** as upstream does, on `NodeKeyExpired` generate a new node key, move the old one to `old_node_priv`, save state, and register with `OldNodeKey` set. The result is `NEED_LOGIN` with a new URL, on the same machine identity.
- **Logout:** `void ts_sess_logout(ts_sess *s)` sends a register with the current node key and `Expiry` set to `1970-01-01T00:02:03Z` (upstream's far-past value), which is how upstream tells control. Then local login state is cleared.

- [ ] **Step 1: Write the failing tests** with a fake control server implemented in the test on top of Tasks 4 and 5, and a fake clock:
  - register returns `AuthURL`: the state is `NEED_LOGIN`, and `ts_sess_login_url` returns it;
  - exactly one Followup is outstanding over 6 simulated hours of silence;
  - when the server ends the Followup without authorizing, a new one is sent no sooner than the floor, and 100 quick endings cause at most the backoff-limited number of sends;
  - `NodeKeyExpired` generates a new key, sends `OldNodeKey`, and state is saved before the request; `ts_sess_logout` sends the far-past expiry;
  - approved login then map: state `AWAIT_APPROVAL` until a self `MachineAuthorized:true`, then `RUNNING`;
  - GOAWAY, then reconnect after backoff, and the node key in the new request equals the old one;
  - no server bytes for 90 seconds sends a PING, and no reply within 30 more disconnects;
  - 429 with `Retry-After: 30` waits 30 simulated seconds;
  - port 80 refused tries 443;
  - status text contains the state name and peer count.
- [ ] **Step 2: Run to verify it fails.** Run: `make test`. Expected: missing `session.h`.
- [ ] **Step 3: Implement** with no real I/O or wall-clock reads in this file.
- [ ] **Step 4: Run to verify it passes.** Run: `make test asan`. Expected: all pass.
- [ ] **Step 5: Commit.** `git commit -m "Add control session state machine"` with the files above.

### Task 10: Foreground daemon and CLI

**Files:**
- Create: `src/daemon/main.c`, `src/daemon/ipc.h`, `src/daemon/ipc.c`, `src/cli/main.c`, `tests/test_ipc.c`, `tests/fuzz_ipc.c`
- Modify: `tests/main.c`, `Makefile`

**Interfaces:**
- Consumes: everything above.
- Produces: `build/<target>/tsppcd` (runs in the foreground in this plan, no launchd) and `build/<target>/tsppc` with commands `up`, `status`, `ip`, `logout`.
- Produces, in `ipc.h`: Unix socket path `TS_IPC_PATH` (`/var/run/tsppc.sock`), overridable by `TSPPC_SOCKET` only in `-DTS_TEST_HOOKS` builds, mode 0660, group `admin`; a one-line request and text response protocol; `int ts_ipc_parse_request(const char *line, size_t len, ts_ipc_cmd *out)`, returning -1 for unknown or over-long lines.

The daemon has one `select()` loop over the control socket, IPC clients and the resolver pipe, using the Task 6 layers and `ts_sess`. It handles `SIGTERM` and `SIGINT` by closing cleanly. `status` prints state, tailnet IP, a problem line when there is one (such as `system clock is wrong`), and each peer's name, IPv4 and online flag. `up` prints the login URL when one is needed. `logout` clears login state and keeps nothing usable. Node keys are never printed.

- [ ] **Step 1: Write the failing tests.** `ts_ipc_parse_request` accepts `status\n`, `up\n`, `ip\n`, `logout\n`, and rejects unknown commands, embedded NULs and lines over 64 bytes. On the host, starting `tsppcd` with `TSPPC_STATE_DIR` and `TSPPC_SOCKET` in a temp dir and a control host of `127.0.0.1:1` makes `tsppc status` report a `BACKOFF` state, and `SIGTERM` removes the socket file. The control-host, state-directory and socket overrides are compiled in only when `-DTS_TEST_HOOKS` is set, which only test targets do. A shipped daemon reads none of them from its environment.
- [ ] **Step 2: Run to verify it fails.** Run: `make test`. Expected: missing `ipc.h`.
- [ ] **Step 3: Implement.** A socket left by a previous crash is detected by connecting to it, then unlinked. A socket whose path is held by a non-socket is refused.
- [ ] **Step 4: Run to verify it passes.** Run: `make test asan fuzz` and `tools/vm-test.sh leopard`. Expected: all pass.
- [ ] **Step 5: Live smoke test, first real server contact.** Using a temporary state directory and a `TS_TEST_HOOKS` build, run the daemon briefly on the host and on the Leopard VM. Expected: fetch the control key, complete Noise on port 80, complete HTTP/2, and reach `NEED_LOGIN` with a printed login URL. Do not open the URL. Stop the daemon. This needs nothing from the owner and creates no device. Failures here are interoperability bugs against the real service: use superpowers:systematic-debugging, and fix the owning module.
- [ ] **Step 6: Commit.** `git commit -m "Add foreground daemon and CLI"` with the files above.

### Task 11: Live acceptance (spec milestone 3 gate)

**Files:**
- Create: `docs/control-session-check.md`

**Interfaces:**
- Consumes: the built daemon on the Leopard and Tiger VMs. Owner action: two logins and two device approvals, which adds two devices to the owner's tailnet.

- [ ] **Step 1 (owner):** Start `tsppcd` as root on the Leopard VM, detached from SSH with `nohup` so it survives a dropped session, with state in the default location. Open the URL `tsppc up` prints, log in, and approve the device in the admin console. Expected: `tsppc status` moves from waiting for login to waiting for approval, then to `RUNNING`, with no restart.
- [ ] **Step 2: Confirm the acceptance test.** Expected: the admin console shows the node online; `tsppc status` lists the real peers with the right IPv4 addresses and online flags; the session stays `RUNNING` for at least one hour; a peer going offline shows up without a restart; and the daemon's resident memory stays under 16 MB by `ps -o rss`.
- [ ] **Step 3: Prove resilience once.** Restart `tsppcd`. Expected: same node, no new login. Then run one detached command on the VM that takes the network interface down, sleeps 120 seconds and restores it, since an SSH session running it would otherwise cut itself off. Expected: `BACKOFF`, then `RUNNING`, with no new login.
- [ ] **Step 4: Repeat on the Tiger VM** from Steps 1 and 2, with a one-hour run. The owner approves that device as well.
- [ ] **Step 5: Record** both runs in `docs/control-session-check.md` with OS build, commit, commands and results, using placeholders for names, peers and the tailnet. Note that hosted Tailscale's acceptance of the pinned capability version is only as durable as the service's policy.
- [ ] **Step 6: Commit.** `git commit -m "Record control session check"` with that file.
