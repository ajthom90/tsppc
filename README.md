# tsppc

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

Vendored tuntaposx (`vendor/tuntaposx-20090913`, the tun/tap kernel driver,
Copyright (c) 2004-2009 Mattias Nissler) is under a BSD-style three-clause
licence: redistribution and use in source and binary forms are permitted
provided the copyright notice and disclaimer are retained in source and
reproduced in binary distributions, and the author's name is not used to
endorse derived products. The notice is the header comment at the top of each
source file under `vendor/tuntaposx-20090913/tuntap/src/`; there is no separate
licence file. Local changes are listed in `vendor/tuntaposx-20090913/PATCHES.md`.
