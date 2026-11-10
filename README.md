# tailscale-ppc

A from-scratch C client that speaks Tailscale's protocol on PowerPC Mac OS X
(Tiger and Leopard).

This project is unofficial. It is not affiliated with or endorsed by
Tailscale Inc.

## Building and testing

    make test       # host build and unit tests
    make asan       # host build with AddressSanitizer and UBSan
    make ppc-test   # PowerPC build (gcc-4.0, 10.4u SDK); run on a PowerPC Mac

New source files under `src/` are picked up automatically. A new test suite is
added by defining `void test_x(void)` in `tests/` and listing it in
`tests/main.c`.

## License

BSD-3-Clause. Vendored BearSSL keeps its own (MIT) license in
`vendor/bearssl-0.6/LICENSE.txt`.
