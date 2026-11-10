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
