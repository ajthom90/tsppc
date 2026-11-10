# Tiger driver and crypto check

Go/no-go gate for Mac OS X 10.4 support.

**Verdict: PASS on Mac OS X 10.4.6 (emulated PowerPC). The Leopard-built crypto
suite, `tun.kext` and `tun_check` all work on Tiger unmodified, with no native
build and no change to `tools/driver.sh`. 10.4.11 has not been tested yet.**

## Environment

| | |
|---|---|
| Machine | Emulated PowerPC Mac (QEMU), one VM |
| OS | Mac OS X 10.4.6, build 8I128 |
| Kernel | Darwin 8.6.0, `root:xnu-792.6.70.obj~1/RELEASE_PPC` |
| Repository commit tested | `c9a0910` (branch `foundation`) |
| Driver source | tuntaposx 20090913, upstream commit `7859e07`, patched as in `vendor/tuntaposx-20090913/PATCHES.md` |
| Built on | Mac OS X 10.5.8, build 9L31a, with the 10.4u SDK |

Nothing was compiled on Tiger. These binaries were copied from the Leopard build:

| File | MD5 |
|---|---|
| `build/driver/tun.kext/Contents/MacOS/tun` | `a9726bb890211765d67f7283ce32910c` |
| `build/ppc-test/tun_check` | `e86fd9cc5a4831a1d21cf8b53149ef97` |
| `build/ppc-test/test_all` | `17d56d79ccae553aad4d512208d72d6e` |

## Crypto suite

Run from the host:

```
TSPPC_SSH_CONFIG=<ssh config> TSPPC_VM_USER=<login> tools/vm-test.sh tiger
```

Complete output, exit status 0:

```
RESULT: all passed (86 checks)
```

## Driver cycle

`tun.kext`, `tun_check` and `tools/driver.sh` were copied to a private directory,
`<dir>`, under the login's home on Tiger, and run on Tiger with:

```
sudo env TSPPC_KEXT=<dir>/build/driver/tun.kext \
    TSPPC_TUN_CHECK=<dir>/build/ppc-test/tun_check \
    <dir>/tools/driver.sh cycle
```

Complete output:

```
=== cycle 1 of 2 ===
kextload: /tmp/tsppc.QsOoc1/tun.kext loaded successfully
loaded <dir>/build/driver/tun.kext, /dev/tun0 present
PASS outbound packet read
PING 10.99.99.2 (10.99.99.2): 56 data bytes
64 bytes from 10.99.99.2: icmp_seq=0 ttl=64 time=2.693 ms

--- 10.99.99.2 ping statistics ---
1 packets transmitted, 1 packets received, 0% packet loss
round-trip min/avg/max/stddev = 2.693/2.693/2.693/nan ms
PASS inbound reply delivered
kextunload: unload id foo.tun succeeded (any personalities also unloaded)
unloaded, /dev/tun0 gone
=== cycle 2 of 2 ===
kextload: /tmp/tsppc.tIeFgj/tun.kext loaded successfully
loaded <dir>/build/driver/tun.kext, /dev/tun0 present
PASS outbound packet read
PING 10.99.99.2 (10.99.99.2): 56 data bytes
64 bytes from 10.99.99.2: icmp_seq=0 ttl=64 time=3.416 ms

--- 10.99.99.2 ping statistics ---
1 packets transmitted, 1 packets received, 0% packet loss
round-trip min/avg/max/stddev = 3.416/3.416/3.416/nan ms
PASS inbound reply delivered
kextunload: unload id foo.tun succeeded (any personalities also unloaded)
unloaded, /dev/tun0 gone
cycle complete: 2 passes, /dev/tun0 gone
```

Checked after the cycle:

- `/dev/tun0` does not exist, and `kextstat` lists no `foo.tun`.
- The staging record `/var/db/tsppc-tun-staging` and every `/tmp/tsppc.*` directory
  are gone.
- No panic: the VM stayed up and answered ssh throughout, and
  `/Library/Logs/panic.log` does not exist.
- The kernel's only log lines from the driver are one startup banner per load:
  `tun kernel extension version 20090913`, followed by the upstream author's address.

`mktemp -d`, `stat -f '%u %Lp'`, `kextunload -b` and `/bin/sh` on Tiger all behaved
as `tools/driver.sh` needs.

## Open item: Tiger's dry run reports validation failures

The real `kextload` loads this kext on Tiger. Tiger's dry run,
`kextload -nt -v 3`, nevertheless reports the following for a correctly owned
root:wheel copy:

```
kernel extension /tmp/tsppc.Sy5sxX/tun.kext has problems:
Validation failures
{
    "Kext has a kernel dependency prior to version 6.0 and CFBundleVersion does not match executable's MODULE_VERSION" = true
    "Kext has a kernel dependency prior to version 6.0 and CFBundleIdentifier does not match executable's MODULE_NAME" = true
}
```

The two values do differ: `Info.plist` has `CFBundleIdentifier` `foo.tun` and
`CFBundleVersion` `1.0`, while `tun/kmod.cc` declares the module as
`KMOD_DECL(tun, TUN_KEXT_VERSION)`, which is name `tun` and version `20090913`. Why
Tiger applies its pre-6.0 rule to a kext whose dependencies are the 8.0 KPIs was
not investigated.

The same dry run on Leopard 10.5.8 says `appears to be loadable`. The dry run was
not the gate and the failures did not stop the two real loads above, but they are
not explained, and a later 10.4 release could treat them differently. The 10.4.11
run below should watch for them.

## Not run: 10.4.11

The 10.4.11 run has not happened yet. The VM is still on 10.4.6, and the owner
will apply the PowerPC combo update after this result. Most real Tiger Macs run
10.4.11, so this check is still to be repeated there, along with the crypto suite.
Real PowerPC hardware has also not been tested; all results here are from an
emulator.
