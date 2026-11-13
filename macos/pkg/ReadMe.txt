tsppc is an unofficial Tailscale client for PowerPC Macs. It is not affiliated with or endorsed by Tailscale Inc.

It runs on Mac OS X 10.4 Tiger and 10.5 Leopard, on the startup disk only.

What is installed, and where:

  /usr/local/sbin/tsppcd          the daemon
  /usr/local/bin/tsppc            the command-line tool
  /usr/local/sbin/tsppc-uninstall the uninstaller
  /Library/Extensions/tsppc-tun.kext
                                  the tun driver (bundle ID
                                  com.github.ajthom90.tsppc.tun), loaded by
                                  tsppcd only when no tun device exists
  /Library/LaunchDaemons/com.github.ajthom90.tsppcd.plist
                                  starts the daemon
  /Applications/tsppc.app         the menu bar app

The daemon starts when the installation finishes and again at every boot. It
logs to /var/log/tsppcd.log and keeps its state (this Mac's node identity) in
/var/db/tsppc.

To sign in, run "tsppc up" in Terminal, or use the menu bar app, and open the
login link it gives you.

If another tun driver (tuntaposx) is already installed, tsppc uses it. Two
tuntaposx drivers can't both be loaded: one installed after tsppc's fails to
load until tsppc's is unloaded or the Mac restarts.

Upgrading: install a newer package over this one. The running daemon is
stopped first, and the new one keeps the same identity.

To uninstall, run in Terminal:

  sudo /usr/local/sbin/tsppc-uninstall

It stops the daemon, removes its route and its /etc/hosts entries, unloads
the driver, and removes everything listed above. Add --remove-state to also
delete /var/db/tsppc; the node then stays in your tailnet's admin console
until you remove it there.

tsppc is open source under the BSD 3-Clause licence. It includes BearSSL
(MIT licence) and a modified tuntaposx tun driver (BSD-style licence); see
the licence shown by the installer.
