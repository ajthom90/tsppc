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

## Install

Open `tsppc-<version>.dmg` and run `tsppc-<version>.pkg`. It installs on the
startup disk of a Mac running 10.4 or 10.5:

- `/usr/local/sbin/tsppcd` (the daemon), `/usr/local/bin/tsppc` (the CLI) and
  `/usr/local/sbin/tsppc-uninstall`;
- `/Library/Extensions/tsppc-tun.kext`, the tun driver (bundle ID
  `com.github.ajthom90.tsppc.tun`), which tsppcd loads only when no tun device
  exists, so another tuntaposx install is used as it is;
- `/Library/LaunchDaemons/com.github.ajthom90.tsppcd.plist`, which starts the
  daemon now and at every boot;
- `/Applications/tsppc.app`, the menu bar app.

The daemon logs to `/var/log/tsppcd.log` and keeps its state in
`/var/db/tsppc`. Sign in with `tsppc up` or from the menu bar app. Installing a
newer package stops the running daemon first; the new one keeps the identity.

To build the package, run `make package` on a PowerPC Mac or the Leopard VM
(gcc-4.0 and the 10.4u SDK); `tools/check-pkg.sh` checks it. A release is
built on the host Mac with
`TSPPC_SSH_CONFIG=<ssh config> tools/release.sh <tag>`, from a clean checkout
at the tag: it ships `git archive <tag>` to a fresh `~/tsppc-release/<tag>` on
the Leopard VM, runs the PowerPC suite and the release, app, driver and
package builds there, copies the `.dmg` and the uninstaller back to
`build/release/`, and writes `build/release/SHA256SUMS`. It neither signs nor
uploads.

## Uninstall

    sudo /usr/local/sbin/tsppc-uninstall

It stops the daemon, removes its route and `/etc/hosts` entries (even after a
crash), quits the menu bar app, unloads tsppc's own driver (never another
one), and removes the installed files, the log and the receipt. `-y` answers
yes to every question. `--remove-state` also deletes `/var/db/tsppc`, this
Mac's node identity, after asking; **with `-y` as well, it deletes it without
asking**. The node then stays in your tailnet's admin console until you
remove it there. It exits 1 if the
daemon, the route or the `/etc/hosts` block is still there afterwards.

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
