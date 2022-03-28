New sandboxing mechanism for FreeBSD with pledge(3)/unveil(3) support.

Setup
-----

1. Rebuild and install world/kernel with this branch.

   Run etcupdate(8)/mergemaster(8) to get the curtain(5) config files.

2. Load the mac_curtain(4) kernel module.

   Run `kldload mac_curtain` or add `mac_curtain_load="YES"` to
   /boot/loader.conf to have it loaded on boot.

3. Do a simple test with curtain(1):

   ```
   curtain id
   ```
   Should show only the current user's numeric IDs since id(1) won't have
   access to the passwd(5) database by default.

   ```
   curtain ls /etc
   ```
   Should show a restricted view of /etc.

Usage
-----

curtain(1) is the main utility to launch other programs in a sandbox.

It lacks proper documentation for now but here's a quick summary.

```
curtain [options] program [argument ...]
```

By default, the sandboxed program will have its access to the filesystem
restricted to stock system files and a few standard /dev and /etc files, and
generally be limited to accessing kernel objects that it (or its descendant
processes) have created.  Some kernel functionality will be completely disabled
(like debugging, anonymous PROT_EXEC mappings, arbitrary ioctl(2)/sysctl(3),
etc).  The default permissions are organized in a 10-level "tower" that can be
selected with option `-0` to `-9`.  The default is `-5`.

Extra configuration permissions are associated with named "tags" that can be
enabled with option `-t <name>`.  Option `-a` is a shortcut to enable the tag
named after the program being run.

`-X` gives untrusted X11 access, `-Y` trusted X11 access and `-W` Wayland
access.  `-R` stops filtering out terminal control sequences and `-T` gives the
program direct access to the terminal.

`-p <path>[:<perms>]` gives access to a filesystem path.  Permissions can
include "r" for read, "w" for write, "x" for execution, "u" for
binding/connecting to local-domain sockets, etc.  Default is "rx".

/etc/curtain.conf has a commented out line to include the example configuration
file with some application profiles (to be used with option `-a`).

For example, after uncommenting the include line, launch Firefox sandboxed:
```
curtain -Xa firefox
```

A good way to add extra permissions to its profile is to put them in the user's
~/.curtain.conf.  For example, to give it access to ~/Downloads:
```
[firefox]
~/Downloads/ : rw +
```

Set sysctl(8) `security.curtain.log_level=deny` to get kernel log messages
whenever the curtain module denies permissions.

