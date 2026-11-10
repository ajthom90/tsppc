# Foundation and Tiger Driver Gate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the tested portable crypto foundation, then prove on Tiger that the tunnel driver loads and carries packets in both directions.

**Architecture:** Plain C99 modules under `src/` build and test on the modern host and on PowerPC through one Makefile. BearSSL is vendored. The tunnel driver is vendored and patched separately, built on the Leopard VM against the 10.4u SDK, and exercised on both Leopard and Tiger by a small check tool.

**Tech Stack:** C (gnu99), BearSSL 0.6, GNU make 3.81, clang on the host, gcc-4.0 with the 10.4u SDK for PowerPC, tuntaposx 20090913.

**Spec:** `docs/superpowers/specs/2026-11-10-tailscale-ppc-design.md`

**Scope:** Spec milestones 1 and 2 only. Each later milestone gets its own plan, written after this gate, because a Tiger failure changes the supported systems. Next plans: control session (M3), tunnel over DERP with filter (M4), then services and onward.

## Global Constraints

- PowerPC flags: `gcc-4.0 -std=gnu99 -arch ppc -isysroot /Developer/SDKs/MacOSX10.4u.sdk -mmacosx-version-min=10.4`.
- One 32-bit `ppc` executable. Nothing may require AltiVec.
- All serialisation goes through the explicit byte-order helpers. Never overlay structs on wire data.
- `spike/` is never compiled, copied from, or committed. Crypto here is written fresh. The third-party `spike/bearssl-0.6` tree may be copied, since it is upstream code.
- No keys, state files, login URLs, SSH config or personal machine details in the repository.
- Our code builds clean with `-Wall -Wextra -Werror`. Vendored code builds with `-w`.
- Every buffer write is bounded by an explicit length.
- Public symbols start with `ts_`.
- The VM scripts read the SSH config path from `TSPPC_SSH_CONFIG`, with hosts `leopard` and `tiger`.

## Review Focus

1. Inputs of exactly one block, one byte over, or empty, split across arbitrary `update` calls: the hash must equal the one-shot result. Test in Task 2.
2. Buffers at odd addresses on PowerPC: byte-order helpers and crypto must work on unaligned pointers. Test in Task 1.
3. Sealing or opening with output in the same buffer as input, as the data path will: the result must equal the separate-buffer result. Test in Task 3.
4. A peer sending an all-zero or low-order X25519 key: key agreement must fail, not yield a predictable key. Test in Task 3.
5. Loading and unloading the driver repeatedly, or unloading it with the device closed after use: no panic and no stuck device. Test in Tasks 6 and 8.

---

### Task 1: Repository skeleton, test harness and byte-order helpers

**Files:**
- Create: `.gitignore` (`spike/`, `build/`, `.DS_Store`), `LICENSE` (BSD-3-Clause, holder "tailscale-ppc contributors"), `README.md`, `Makefile`
- Create: `vendor/bearssl-0.6/` (copied from `spike/bearssl-0.6`)
- Create: `src/core/bytes.h`, `src/core/bytes.c`
- Create: `tests/harness.h`, `tests/harness.c`, `tests/main.c`, `tests/test_bytes.c`

**Interfaces:**
- Produces, in `bytes.h`: `uint16_t ts_get_be16(const uint8_t *p)`, and the same for `ts_get_be32`, `ts_get_be64` (returning `uint32_t`, `uint64_t`), `ts_get_le16`, `ts_get_le32`, `ts_get_le64`; `void ts_put_be16(uint8_t *p, uint16_t v)` and matching `ts_put_be32`, `ts_put_be64`, `ts_put_le16`, `ts_put_le32`, `ts_put_le64`; `void ts_wipe(void *p, size_t n)`.
- Produces, in `harness.h`: `void t_hex(const char *name, const uint8_t *got, size_t n, const char *want_hex)`, `void t_true(const char *name, int cond)`, `void t_unhex(uint8_t *out, const char *hex)`, `int t_summary(void)` (prints `RESULT: all passed` or `RESULT: N FAILED`, returns nonzero on failure).
- Produces: Makefile targets `test` (host), `asan` (host, `-fsanitize=address,undefined`), `ppc-test` (PowerPC, with `CC=gcc-4.0`). Objects live in `build/<target>/`, are rebuilt incrementally, and BearSSL objects are built once. New test suites are added by listing a `void test_x(void)` in `tests/main.c`.

- [ ] **Step 1: Write the failing test** in `tests/test_bytes.c`, `void test_bytes(void)`:

```c
uint8_t raw[16], *p = raw + 1;   /* deliberately odd address */
ts_put_be32(p, 0x01020304); t_hex("be32", p, 4, "01020304");
ts_put_le32(p, 0x01020304); t_hex("le32", p, 4, "04030201");
ts_put_be64(p, 0x0102030405060708ULL); t_hex("be64", p, 8, "0102030405060708");
ts_put_le64(p, 0x0102030405060708ULL); t_hex("le64", p, 8, "0807060504030201");
t_true("get be16", ts_get_be16((const uint8_t*)"\x12\x34") == 0x1234);
t_true("get le16", ts_get_le16((const uint8_t*)"\x12\x34") == 0x3412);
ts_put_be64(p, 0xfedcba9876543210ULL);
t_true("be64 round", ts_get_be64(p) == 0xfedcba9876543210ULL);
ts_put_le64(p, 0xfedcba9876543210ULL);
t_true("le64 round", ts_get_le64(p) == 0xfedcba9876543210ULL);
ts_put_be32(p, 0xffffffff); ts_wipe(p, 4);
t_hex("wipe", p, 4, "00000000");
```

- [ ] **Step 2: Run to verify it fails.** Run: `make test`. Expected: compile or link failure on `ts_put_be32`.
- [ ] **Step 3: Implement `bytes.h` and `bytes.c`, the harness and the Makefile.** Helpers use byte shifts only. `ts_wipe` writes through a `volatile` pointer so the compiler can't remove it. The README states the project is unofficial and not affiliated with or endorsed by Tailscale Inc.
- [ ] **Step 4: Run to verify it passes.** Run: `make test && make asan`. Expected: `RESULT: all passed` from both.
- [ ] **Step 5: Commit.** `git add .gitignore LICENSE README.md Makefile vendor src tests && git commit -m "Add build system, test harness and byte-order helpers"`

### Task 2: BLAKE2s, HMAC and HKDF

**Files:**
- Create: `src/crypto/blake2s.h`, `src/crypto/blake2s.c`, `src/crypto/kdf.h`, `src/crypto/kdf.c`
- Test: `tests/test_blake2s.c`

**Interfaces:**
- Consumes: Task 1 helpers and harness.
- Produces: `ts_blake2s_ctx`; `void ts_blake2s_init(ts_blake2s_ctx *c, size_t outlen, const uint8_t *key, size_t keylen)` (`outlen` 1 to 32, `keylen` 0 to 32); `void ts_blake2s_update(ts_blake2s_ctx *c, const void *data, size_t len)`; `void ts_blake2s_final(ts_blake2s_ctx *c, uint8_t *out)`; `void ts_blake2s(uint8_t out[32], const void *data, size_t len)`.
- Produces, in `kdf.h`: `void ts_hmac_blake2s(uint8_t out[32], const uint8_t *key, size_t keylen, const void *msg, size_t msglen)`; `void ts_hkdf2(uint8_t t1[32], uint8_t t2[32], const uint8_t salt[32], const uint8_t *ikm, size_t ikmlen)`; `void ts_hkdf3(uint8_t t1[32], uint8_t t2[32], uint8_t t3[32], const uint8_t salt[32], const uint8_t *ikm, size_t ikmlen)`.

- [ ] **Step 1: Write the failing tests.** All expected values below were computed with Python's `hashlib` and `hmac`. `seq(n)` means bytes 0, 1, ..., n-1.

| Test | Input | Expected hex |
|---|---|---|
| `abc` | `"abc"` | `508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982` |
| empty | zero length | `69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9` |
| one block | `seq(64)` | `56f34e8b96557e90c1f24b52d0c89d51086acf1b00f634cf1dde9233b8eaaa3e` |
| block + 1 | `seq(65)` | `1b53ee94aaf34e4b159d48de352c7f0661d0a40edff95a0b1639b4090e974472` |
| long | `seq(200)` | `6d244e1a06ce4ef578dd0f63aff0936706735119ca9c8d22d86c801414ab9741` |
| keyed, 16-byte out | `"abc"`, key `seq(32)` | `61ba5f165c194692e09d12520cc4c74a` |
| keyed, long | `seq(200)`, key 32 × `'k'`, 16-byte out | `a74b2926087ee84d2ca3c8402d4e695b` |
| HMAC | key `"key"`, msg `"data"` | `84f646acda0776ee848b7f9dc5771c7d8cf023999c0c3dd84dc78636a146e805` |
| HMAC, long key | key `seq(100)`, msg `"data"` | `2624e61dfe9fcc84d3137a317c171ced634ef3fcd2fa3f5515940906f4e38c48` |
| HKDF t1 | salt `seq(32)`, ikm `"input key material"` | `93e2a65883e34ac95485f5d0aa4b09163a4e944dab8cf9406d3a138e362851c6` |
| HKDF t2 | same | `dd6fae42afdb2a41170f44dc5b885ec4cfd17c8dd324d38b390c548630dd0a83` |
| HKDF3 t3 | same | `4125e0adfa9b7e736615e99dde6f3f0b64b949d8b480e82cab2e685dc286e45d` |
| HKDF empty ikm t1 | salt `seq(32)`, empty | `7a38c34bf2b8738d7374ca77c44ecb309a11d2b2528304fa86052c365e722624` |
| HKDF empty ikm t2 | same | `1a17621f346abdc520746a9fb64d8eb03231d674fc15687537b0780fd9c060fd` |

Also add `t_true("chunked", ...)`: for each split point `s` from 0 to 200, hashing `seq(200)` as `update(s bytes)` then `update(rest)` equals the `long` row. Repeat with one-byte-at-a-time updates. Also hash `seq(200)` from a buffer starting at an odd address, and expect the `long` row.

- [ ] **Step 2: Run to verify it fails.** Run: `make test`. Expected: undefined `ts_blake2s`.
- [ ] **Step 3: Implement to RFC 7693.** Message words load through `ts_get_le32`. The final block must stay buffered until `final`, so an exact 64-byte input isn't compressed early. HKDF is the two- and three-output form with empty info: `t1 = HMAC(HMAC(salt, ikm), 0x01)`, `tN = HMAC(prk, t(N-1) || N)`. Wipe intermediate keys with `ts_wipe`.
- [ ] **Step 4: Run to verify it passes.** Run: `make test && make asan`. Expected: `RESULT: all passed`.
- [ ] **Step 5: Commit.** `git commit -m "Add BLAKE2s, HMAC and HKDF"` with the files above.

### Task 3: X25519, ChaCha20-Poly1305 and randomness

**Files:**
- Create: `src/crypto/x25519.h`, `src/crypto/x25519.c`, `src/crypto/aead.h`, `src/crypto/aead.c`, `src/crypto/random.h`, `src/crypto/random.c`
- Test: `tests/test_aead.c`

**Interfaces:**
- Consumes: Task 1, BearSSL `br_ec_c25519_m31`, `br_chacha20_ct_run`, `br_poly1305_ctmul_run`.
- Produces: `int ts_x25519(uint8_t out[32], const uint8_t priv[32], const uint8_t pub[32])` (0 on success, -1 if the result is all zero); `void ts_x25519_public(uint8_t out[32], const uint8_t priv[32])`.
- Produces: `void ts_aead_seal(uint8_t *out, const uint8_t key[32], const uint8_t nonce[12], const uint8_t *ad, size_t adlen, const uint8_t *pt, size_t ptlen)` (writes `ptlen + 16` bytes, ciphertext then tag); `int ts_aead_open(uint8_t *out, const uint8_t key[32], const uint8_t nonce[12], const uint8_t *ad, size_t adlen, const uint8_t *ct, size_t ctlen)` (`ctlen` includes the tag; returns 0 if authentic, -1 otherwise, and on failure `out` must be wiped). Input and output may be the same pointer.
- Produces: `int ts_random_bytes(void *out, size_t n)` (reads `/dev/urandom`, retries short reads and `EINTR`, returns -1 on failure).

- [ ] **Step 1: Write the failing tests.**

X25519 (RFC 7748): private `77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a` gives public `8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a`. With peer public `de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f` the shared value is `4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742`. `t_true("x25519 rejects zero", ts_x25519(o, k, zero32) == -1)`, and the same for peer key `0100...00` (a low-order point).

AEAD (RFC 8439): key bytes `0x80` to `0x9f`, nonce `070000004041424344454647`, AD `50515253c0c1c2c3c4c5c6c7`, plaintext `"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."` (114 bytes). Ciphertext starts `d31a8d34648e60db7b86afbc53ef7ec2`, and the tag at offset 114 is `1ae10b594f09e26a7e902ecbd0600691`. Then assert:
- open round-trips;
- flipping one bit of ciphertext, tag or AD returns -1 and leaves `out` all zero;
- `seal` with `out == pt` gives bytes identical to separate buffers, and `open` with `out == ct` recovers the plaintext;
- empty plaintext round-trips and produces only a tag.

Also seal the same plaintext from an odd-address buffer into an odd-address output, and expect the same bytes as the aligned case.

Random: two 32-byte calls return 0 and differ.

- [ ] **Step 2: Run to verify it fails.** Run: `make test`. Expected: undefined `ts_x25519`.
- [ ] **Step 3: Implement as thin wrappers over BearSSL.** BearSSL's Poly1305 runs in place, so `seal` moves plaintext to `out` first with `memmove`. `open` computes the tag on a copy-free path: run decrypt in place in `out`, compare tags with a constant-time loop, and wipe on mismatch.
- [ ] **Step 4: Run to verify it passes.** Run: `make test && make asan`. Expected: `RESULT: all passed`.
- [ ] **Step 5: Commit.** `git commit -m "Add X25519, ChaCha20-Poly1305 and random bytes"` with the files above.

### Task 4: NaCl box and XChaCha20-Poly1305

**Files:**
- Create: `src/crypto/nacl.h`, `src/crypto/nacl.c`, `src/crypto/xaead.h`, `src/crypto/xaead.c`
- Test: `tests/test_nacl.c`

**Interfaces:**
- Consumes: Task 1, Task 3 `ts_x25519` and `ts_aead_seal`/`open`. BearSSL has no standalone Poly1305, since its functions always add the AEAD padding, so this task provides one.
- Produces: `void ts_poly1305(uint8_t tag[16], const uint8_t key[32], const uint8_t *msg, size_t len)`, a plain constant-time one-time MAC per RFC 8439 section 2.5.
- Produces: `void ts_hsalsa20(uint8_t out[32], const uint8_t key[32], const uint8_t in[16])`; `void ts_secretbox_seal(uint8_t *out, const uint8_t key[32], const uint8_t nonce[24], const uint8_t *m, size_t mlen)` (writes `mlen + 16`, **tag first**, then ciphertext, as NaCl and Go's `nacl/box` do); `int ts_secretbox_open(uint8_t *out, const uint8_t key[32], const uint8_t nonce[24], const uint8_t *c, size_t clen)`; `int ts_box_beforenm(uint8_t k[32], const uint8_t their_pub[32], const uint8_t my_priv[32])` (HSalsa20 of the X25519 result with a zero 16-byte input, -1 on all-zero); `int ts_box_seal(uint8_t *out, const uint8_t nonce[24], const uint8_t their_pub[32], const uint8_t my_priv[32], const uint8_t *m, size_t mlen)` and `int ts_box_open(uint8_t *out, const uint8_t nonce[24], const uint8_t their_pub[32], const uint8_t my_priv[32], const uint8_t *c, size_t clen)`.
- Produces: `void ts_hchacha20(uint8_t out[32], const uint8_t key[32], const uint8_t nonce[16])`; `void ts_xaead_seal(uint8_t *out, const uint8_t key[32], const uint8_t nonce[24], const uint8_t *ad, size_t adlen, const uint8_t *pt, size_t ptlen)`; `int ts_xaead_open(uint8_t *out, const uint8_t key[32], const uint8_t nonce[24], const uint8_t *ad, size_t adlen, const uint8_t *ct, size_t ctlen)`.

- [ ] **Step 1: Write the failing tests.** All values were cross-checked against an independent Python implementation.

- `ts_poly1305` with key `85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b` and message `"Cryptographic Forum Research Group"` gives `a8061dc1305136c6c22b8baf0c0127a9`.
- `ts_box_beforenm` with Alice's private key and Bob's public key from Task 3 gives `1b27556473e985d462cd51197a9a46c76009549eac6474f206c4ee0844f68389`.
- Secretbox with that key, nonce `69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37`, and 131-byte message `be075fc53c81f2d5cf141316ebeb0c7b5228c52a4c62cbd44b66849b64244ffce5ecbaaf33bd751a1ac728d45e6c61296cdc3c01233561f41db66cce314adb310e3be8250c46f06dceea3a7fa1348057e2f6556ad6b1318a024a838f21af1fde048977eb48f59ffd4924ca1c60902e52f0a089bc76897040e082f937763848645e0705` produces `f3ffc7703f9400e52a7dfb4b3d3305d98e993b9f48681273c29650ba32fc76ce48332ea7164d96a4476fb8c531a1186ac0dfc17c98dce87b4da7f011ec48c97271d2c20f9b928fe2270d6fb863d51738b48eeee314a7cc8ab932164548e526ae90224368517acfeabd6bb3732bc0e9da99832b61ca01b6de56244a9e88d5f9b37973f622a43d14a6599b1f654cb45a74e355a5`. Opening round-trips, and a flipped bit returns -1.
- `ts_box_seal` from Alice to Bob gives the same bytes, and `ts_box_open` with Bob's private key and Alice's public key recovers the message. Bob's private key is `5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb`, Alice's public key is the one in Task 3.
- `ts_hchacha20` with key bytes `0x80` to `0x9f` and nonce bytes `0x40` to `0x4f` gives `4a8ac0c0296222bafe959faabe06a45b89a3cee444fef6e3d77659a53f49ee32`.
- XChaCha20-Poly1305 with the same key, nonce bytes `0x40` to `0x57`, Task 3's AD and plaintext gives `bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921f9664c97637da9768812f615c68b13b52ec0875924c1c7987947deafd8780acf49`.

- [ ] **Step 2: Run to verify it fails.** Run: `make test`. Expected: undefined `ts_hsalsa20`.
- [ ] **Step 3: Implement.** Salsa20 words load with `ts_get_le32`. The first 32 bytes of the Salsa20 stream are the Poly1305 key. The message is encrypted from stream offset 32. XChaCha uses `ts_hchacha20` for the subkey and a 12-byte nonce of 4 zero bytes plus the last 8 nonce bytes.
- [ ] **Step 4: Run to verify it passes.** Run: `make test && make asan`. Expected: `RESULT: all passed`.
- [ ] **Step 5: Commit.** `git commit -m "Add NaCl box and XChaCha20-Poly1305"` with the files above.

### Task 5: Big-endian verification on the Leopard VM (spec milestone 1 gate)

**Files:**
- Create: `tools/vm-test.sh`

**Interfaces:**
- Produces: `TSPPC_SSH_CONFIG=<path> tools/vm-test.sh <leopard|tiger>`. For `leopard`, it copies the tree with tar over ssh (with `COPYFILE_DISABLE=1`, excluding `build/` and `spike/`, keeping the VM's `build/` so builds stay incremental) to `~/tsppc`, runs `make ppc-test CC=gcc-4.0`, and runs the binary. For `tiger`, it fetches the Leopard-built binary through the host, copies it to Tiger and runs it. Exit status is the test binary's. SSH noise matching `_CFGetHostUUID` is filtered.

- [ ] **Step 1: Run the script against the Leopard VM.** Run: `TSPPC_SSH_CONFIG=$CFG tools/vm-test.sh leopard`. The first build compiles BearSSL and takes several minutes. Expected: `RESULT: all passed`.
- [ ] **Step 2: Fix anything gcc-4.0 rejects or big-endian breaks.** Fix in the source, and rerun Task 1 to 4 tests on the host as well. A test passing on the host and failing here is an endianness bug in our code. Don't change an expected value.
- [ ] **Step 3: Confirm the binary is generic PowerPC.** Run on the VM: `lipo -info build/ppc-test/test_all`. Expected: `ppc` only, with no `ppc7400` or `ppc970`, so a G3 can run it. Task 8 proves it launches on Tiger.
- [ ] **Step 4: Commit.** `git commit -m "Add VM test runner"` with the script and any fixes.

### Task 6: Tunnel driver build and check tool, on Leopard

**Files:**
- Create: `vendor/tuntaposx-20090913/` (only `tuntap/src/` from `github.com/bbits/tuntaposx` commit 7859e07, plus the upstream `README`)
- Create: `vendor/tuntaposx-20090913/PATCHES.md`, `tools/tun_check.c`, `tools/driver.sh`

**Interfaces:**
- Produces: `tools/driver.sh build|load|unload|cycle`, run on the VM. `build` makes `tun.kext` in `build/driver/`. `load` copies it to `/tmp`, sets `root:wheel` and `go-w`, runs `kextload`, and fails unless `/dev/tun0` appears. `unload` runs `kextunload` and fails unless `/dev/tun0` disappears. `cycle` does load, `tun_check`, unload, twice.
- Produces: `tun_check`, built by `make ppc-test` into `build/ppc-test/tun_check`, run as root. It prints `PASS`/`FAIL` lines and exits nonzero on any failure.

- [ ] **Step 1: Write `tools/tun_check.c`.** It opens `/dev/tun0`, runs `ifconfig tun0 inet 10.99.99.1 10.99.99.2 up`, and forks `/sbin/ping -c 1 -t 5 10.99.99.2`. With `select()` and a 6-second limit, it reads one packet and checks it is IPv4 ICMP echo to 10.99.99.2. It then writes an echo reply back to the device: source and destination swapped, ICMP type 0, ICMP and IP checksums recomputed. It prints `PASS outbound packet read` and, if ping exits 0, `PASS inbound reply delivered`. The second check is new: the spike only proved the outbound direction.
- [ ] **Step 2: Vendor the driver and patch it.** Patches, each recorded in `PATCHES.md`:
  - remove `-arch i386 -arch x86_64` from `CFLAGS` and `LDFLAGS`, and remove `-Xlinker -kext`;
  - declare `tuntap_if_ioctl`'s `cmd` as `u_int32_t` in `tuntap.h` and `tuntap.cc`;
  - point `INCLUDE` at `/Developer/SDKs/MacOSX10.4u.sdk/System/Library/Frameworks/Kernel.framework/Headers`, and add `-isysroot /Developer/SDKs/MacOSX10.4u.sdk -mmacosx-version-min=10.4`;
  - use `CC=gcc-4.0`, `CCP=g++-4.0`.

  The spike built against 10.5 headers, so 10.4u compile errors are new. Fix them in the vendored source, record each one, and don't weaken behaviour to get past them.
- [ ] **Step 3: Build it.** Run on the Leopard VM: `tools/driver.sh build`, then `lipo -info build/driver/tun.kext/Contents/MacOS/tun`. Expected: `ppc` only.
- [ ] **Step 4: Run the check on Leopard.** Run on the VM: `sudo tools/driver.sh cycle`. Expected: `PASS outbound packet read` and `PASS inbound reply delivered` in both cycles, `/dev/tun0` gone at the end, and no panic.
- [ ] **Step 5: Commit.** `git commit -m "Add patched tunnel driver and check tool"` with the files above.

### Task 7: Tiger test VM

**Files:** none in the repository. The VM is `Tiger PPC` in UTM, with SSH forwarded from host port 2223. It has been created and boots its installer.

**Interfaces:**
- Produces: SSH host `tiger` in the file named by `TSPPC_SSH_CONFIG`, with the same legacy options as `leopard` and port 2223. Keep that config and its key somewhere durable outside the repository. The login name comes from the config's `User` setting.

- [ ] **Step 1 (owner):** Complete the Tiger install on the VM, create an account, enable Remote Login, and install `Xcode Tools` from the same disc.
- [ ] **Step 2:** Stop the VM. In UTM's settings for it (not by editing the file while UTM is open), change `-boot d` to `-boot c`, add `-prom-env` and `boot-device=hd:,\System\Library\CoreServices\BootX`, and clear the CD drive. Start it. Expected: the QEMU command line in `ps` shows `-boot c`, and it boots to the desktop from the disk.
- [ ] **Step 3 (owner):** Install the SSH public key on the VM, and grant that account passwordless sudo in `/etc/sudoers`, as was done on Leopard.
- [ ] **Step 4: Confirm access.** Run: `ssh -F $CFG tiger 'sw_vers; uname -p; sudo id -u'`. Expected: `10.4.x`, `powerpc`, `0`.

### Task 8: Driver and crypto on Tiger (spec milestone 2 gate)

**Files:**
- Create: `docs/tiger-driver-check.md`

**Interfaces:**
- Consumes: Tasks 5, 6 and 7. All binaries are built on Leopard and copied over, and Tiger needs no compiler.

- [ ] **Step 1: Run the crypto suite on Tiger.** Run: `TSPPC_SSH_CONFIG=$CFG tools/vm-test.sh tiger`. Expected: `RESULT: all passed`. This is the first proof that our binaries launch on Tiger.
- [ ] **Step 2: Run the driver cycle on Tiger.** Copy `build/driver/tun.kext`, `tun_check` and `tools/driver.sh` over, then run `sudo tools/driver.sh cycle`. Expected: `PASS outbound packet read` and `PASS inbound reply delivered` in both cycles, `/dev/tun0` gone at the end, and no panic.
- [ ] **Step 3: If it fails, diagnose.** Use the `superpowers:systematic-debugging` skill. Collect `kextload -v 6`, `dmesg`, and `/var/log/system.log`. Before concluding it can't work, build the kext natively on Tiger with its own Xcode Tools and kernel headers, and repeat Step 2.
- [ ] **Step 4: Record the outcome** in `docs/tiger-driver-check.md`: OS build, kext source commit, commands, output, and verdict. If the driver can't be made to work, the verdict must state that, and work stops so the owner can decide on the Leopard-only fallback in the spec.
- [ ] **Step 5: Rerun on 10.4.11.** Most real Tiger Macs run 10.4.11, so if the owner supplies the PowerPC combo update, apply it and repeat Steps 1 and 2. Record the result, or record that it wasn't run.
- [ ] **Step 6: Commit.** `git commit -m "Record Tiger driver check result"` with that file and any fixes.
