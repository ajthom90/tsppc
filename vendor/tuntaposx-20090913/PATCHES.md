# Local patches to tuntaposx 20090913

Upstream: `github.com/bbits/tuntaposx`, commit `7859e07`. Only `tuntap/src/` and
the upstream `README` are vendored here.

The driver is built with `tools/driver.sh build`, which compiles a copy of
`tuntap/src` under `build/driver/`, so no objects are written into this tree.

Only `tuntap/src/tun/` is built, so the `tap` driver and `tuntap/src/tap/Makefile`
are unchanged.

## `tuntap/src/tun/Makefile`

1. Removed `-arch i386 -arch x86_64` from `CFLAGS` and `LDFLAGS`. The kext is
   built for 32-bit PowerPC only.
2. Removed `-Xlinker -kext` from `LDFLAGS`. The `-r` link gives a `tun` binary
   that `kextload` accepts without it, with the Xcode 3.1 toolchain on Leopard.
3. Pointed `INCLUDE` at
   `/Developer/SDKs/MacOSX10.4u.sdk/System/Library/Frameworks/Kernel.framework/Headers`
   and added `-isysroot /Developer/SDKs/MacOSX10.4u.sdk -mmacosx-version-min=10.4`
   to `CFLAGS` and `LDFLAGS`, so that one kext can target Tiger and Leopard.
4. Set `CC = gcc-4.0` and `CCP = g++-4.0`.
5. Replaced `-Wall` with `-w` in `CFLAGS` and `LDFLAGS`, following the project
   rule that vendored code builds with `-w`. Built with `-Wall` before this
   change, the driver gave no warnings against the 10.4u headers.

## `tuntap/src/tuntap.h` and `tuntap/src/tuntap.cc`

6. Declared `tuntap_if_ioctl`'s `cmd` parameter as `u_int32_t` instead of
   `long unsigned int`, in the declaration, the `friend` declaration and the
   definition. This matches the `ifnet_ioctl_func` type it is assigned to.

## 10.4u SDK compile errors

None. With patches 1 to 6 the driver compiles and links against the 10.4u SDK
with no source changes beyond patch 6.

`-fno-stack-protector` is accepted by this `gcc-4.0` and is left in place.
