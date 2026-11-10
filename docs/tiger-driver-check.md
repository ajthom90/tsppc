# Tiger driver and crypto check

Go/no-go gate for Mac OS X 10.4 support.

**Verdict: PASS on Mac OS X 10.4.6 and 10.4.11, emulated PowerPC only. On both,
the Leopard-built crypto suite, `tun.kext` and `tun_check` work on Tiger
unmodified, with no native build. Real PowerPC hardware has not been tested.**

The two runs did not use identical test binaries: see "10.4.11 run". The kext and
`tun_check` are byte-identical across both. Ping times below come from an emulator
and are not performance figures.

## 10.4.6 run: environment

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
| `tools/driver.sh` | `aca900f0bb160a05865f5c68affe6250` |

## 10.4.6 run: crypto suite

Run from the host:

```
TSPPC_SSH_CONFIG=<ssh config> TSPPC_VM_USER=<login> tools/vm-test.sh tiger
```

Complete output, exit status 0:

```
RESULT: all passed (86 checks)
```

## 10.4.6 run: driver cycle

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

## Dry-run validation messages (10.4.6 only)

The real `kextload` loaded this kext on 10.4.6. On 10.4.6 the dry run,
`kextload -nt -v 3`, nevertheless reported the following for a correctly owned
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
10.4.6 applies its pre-6.0 rule to a kext whose dependencies are the 8.0 KPIs was
not investigated.

| OS | Dry run on a root:wheel copy | Real load |
|---|---|---|
| 10.4.6 | the two validation failures above | succeeded in both cycles |
| 10.4.11 | no validation failures; `appears to be valid` | succeeded in both cycles |
| 10.5.8 | `appears to be loadable` | not part of this check |

The same kext gave both 10.4 results. The messages are a 10.4.6 dry-run report
only, and they did not stop a real load on 10.4.6. Nothing was changed to remove
them.

## 10.4.11 run

The owner updated the VM to 10.4.11 and rebooted it. It was then tested with:

| | |
|---|---|
| OS | Mac OS X 10.4.11, build 8S165 |
| Kernel | Darwin 8.11.0, `root:xnu-792.24.17~1/RELEASE_PPC` |
| Repository commit tested | `b474a66` (branch `foundation`) |

Every tracked file under `src`, `tests`, `tools`, `vendor` and `Makefile` on the
Leopard build tree (353 files) matched `b474a66` by MD5 before the run. The build
ran before that commit existed, so its `SOURCE_ID` reads `65b3019+modified`.

| File | MD5 | Same as the 10.4.6 run |
|---|---|---|
| `build/driver/tun.kext/Contents/MacOS/tun` | `a9726bb890211765d67f7283ce32910c` | yes |
| `build/ppc-test/tun_check` | `e86fd9cc5a4831a1d21cf8b53149ef97` | yes |
| `build/ppc-test/test_all` | `d70414ea14bb234229daf7657b9ef7c1` | no: newer, 98 checks against 86 |
| `tools/driver.sh` | `11273a16c34fdcefb89523836ba6fa5e` | no: revised in `b474a66` |

The 98-check suite and the revised `driver.sh` have run on 10.4.11 only. 10.4.6 was
not repeated, because this VM is now on 10.4.11.

### Crypto suite

```
TSPPC_SSH_CONFIG=<ssh config> TSPPC_VM_USER=<login> tools/vm-test.sh tiger
```

Complete output, exit status 0:

```
binary cksum: 1684761053 371732
binary sha256: db9aec1841c3aa561dbdb01bb75951b85250564c30f96eaf2dc6537de6957b59
built from: 65b3019+modified archive-cksum 642044722:2894848
RESULT: all passed (98 checks)
```

### Dry run

`kextload -nt -v 3` on a root:wheel copy, last lines:

```
kextload: resolving dependencies for all kernel extensions
kextload: resolving dependencies for kernel extensions with validation and authentication failures
kextload: extension /tmp/tsppc.Tjvk5v/tun.kext appears to be valid
```

### Driver cycle

```
sudo env TSPPC_KEXT=<dir>/build/driver/tun.kext \
    TSPPC_TUN_CHECK=<dir>/build/ppc-test/tun_check \
    <dir>/tools/driver.sh cycle
```

Complete output:

```
=== cycle 1 of 2 ===
kextload: /tmp/tsppc.RXs5Fs/tun.kext loaded successfully
loaded <dir>/build/driver/tun.kext, /dev/tun0 present
PASS outbound packet read
PING 10.99.99.2 (10.99.99.2): 56 data bytes
64 bytes from 10.99.99.2: icmp_seq=0 ttl=64 time=4.734 ms

--- 10.99.99.2 ping statistics ---
1 packets transmitted, 1 packets received, 0% packet loss
round-trip min/avg/max/stddev = 4.734/4.734/4.734/nan ms
PASS inbound reply delivered
kextunload: unload id foo.tun succeeded (any personalities also unloaded)
unloaded, /dev/tun0 gone
=== cycle 2 of 2 ===
kextload: /tmp/tsppc.2bBu9C/tun.kext loaded successfully
loaded <dir>/build/driver/tun.kext, /dev/tun0 present
PASS outbound packet read
PING 10.99.99.2 (10.99.99.2): 56 data bytes
64 bytes from 10.99.99.2: icmp_seq=0 ttl=64 time=2.977 ms

--- 10.99.99.2 ping statistics ---
1 packets transmitted, 1 packets received, 0% packet loss
round-trip min/avg/max/stddev = 2.977/2.977/2.977/nan ms
PASS inbound reply delivered
kextunload: unload id foo.tun succeeded (any personalities also unloaded)
unloaded, /dev/tun0 gone
cycle complete: 2 passes, /dev/tun0 gone
```

Checked after the cycle: `/dev/tun0` does not exist, `kextstat` lists no `foo.tun`,
the staging record and every `/tmp/tsppc.*` directory are gone,
`/Library/Logs/panic.log` does not exist, and the VM stayed up and answered ssh.
