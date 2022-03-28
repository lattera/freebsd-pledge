- Potential cross-mountpoint vnode LOR in unveil_vnode_walk_dirent_visible()
  involving VFS_ROOT().  There used to be warning messages about it, but they
  stopped appearing for some reason...

- Late initialization of some SysV IPC objects' MAC labels cause a sleepable
  malloc() to be called while holding locks that don't allow it.  Doesn't
  happen if mac_curtain is loaded early though.

- Access to the SysV objects themselves is restricted by barriers, but the
  "keys" and "identifiers" are not isolated in a separate namespace like POSIX
  SHM paths are.

- audit(4) syscalls are handled specially for jails and probably should be for
  sandboxed programs too.  Causes problems with su(8).

- getfsstat(2) only allows to see mount points that are directly unveiled
  directories, not those that are readable subdirectories of unveiled
  directories.

- qt tries to write temporary SHM files to $XDG_RUNTIME_DIR on Wayland. Can be
  fixed with a small patch.

- TIOCSPGRP and F_SETOWN/FIOSETOWN don't use the generic process visibility checks.

- Signaling processes from the same process group is allowed on OpenBSD, but
  the way the MAC checks are done don't make this easy here.

- The new syscall's auditing number still is a temporary value to avoid
  collision with new syscalls.

- freebsd32 would need a compatibility wrapper for curtainctl(2).

- Linuxulator syscalls could be given sysfils too.

- New MAC functions were added in a pretty ad-hoc manner and often don't fit in
  with MAC's general design very well.  But it's a convenient place to add hook
  functions...

- pledge(3) is missing some promises.  Some aren't as secure or don't work as
  well as on OpenBSD.

- The "inet" pledge(3) promise is probably missing some socket options.

- OpenBSD sends an "uncatchable" SIGABRT on pledge violations (and this way you
  can get a coredump).  Not sure how to correctly make a signal uncatchable so
  this implementation just sends SIGKILL.

- pledge(3) just ignores attempts to raise permissions (as if the "error"
  promise was always passed).

- Calling unveil(3) is a lot slower than on OpenBSD due to the underlying
  curtainctl(2) API requiring to re-submit all of the restrictions each time.

- pledge(3)/unveil(3) keep some O_PATH FDs opened to the unveiled directories.
  They are mostly inoperable but it would be better to get rid of them somehow.

- curtain(1) will litter $TMPDIR with subdirectories if a simple rmdir(2)
  doesn't work.  It could try to recursively delete them, but it would probably
  be best if it acted as a "reaper" to wait for all subprocesses to be done.

- Seems like curtain(1)'s TTY wrapping code doesn't always deal with being
  suspended correctly.

- SOL_LOCAL and IPPROTO_IP have the same value and their socket options aren't
  correctly distinguished.

- The default curtain(5) configs only restrict socket options by level.

- Socket control message types should be restricted.

- When masking a curtain against an inherited one, unveils that become
  redundant should be detected and dropped.

- Loading mac_curtain disables the "fastpath" path lookup implementation
  because of the MAC handlers it registers.  There should some way of disabling
  the fastpath only for sandboxed processed (or better yet, add fastpath
  support for unveils checking).

- The MAC check in kern_socketpair() was changed from mac_socket_check_create()
  to a new mac_socket_check_create_pair().  This could be wrong as it changes
  how existing MAC modules might try to restrict sockets.

- It's possible to enumerate all sysctls (even if you can't read their values).

- Repeated calls to curtain_apply() should not ALWAYS created new barriers?
  Maybe in some cases it should only be done once per process.

- In some cases, a parent process exiting may cutoff curtained child processes
  from objects they had access to before.  The "barriers collapsing" would need
  some rethinking.

- The test suite just fails when mac_curtain isn't loaded instead of detecting
  it and skipping tests.

- Hardcoded /tmp usage is a constant source sandboxing problems.  Having some
  kind of path-rewriting unveils could help with it.

- dbus/dconf/pulseaudio/etc need to be dealt with better.

- Lots of code needs more/better comments.

