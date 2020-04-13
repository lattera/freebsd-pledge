#ifndef	_SYS__SYSFIL_H_
#define	_SYS__SYSFIL_H_

#include <sys/types.h>

/* XXX TODO: turn into a real option */
#define	PLEDGE

/* sysfil - SYStem FILters
 *
 * Each sysfil flag corresponds to a set of system call to allow and may also
 * alter what these syscalls are allowed to do.
 *
 * Each process has a set of enabled sysfils and a set of sysfils to switch to
 * upon exec().  Sysfils can be manipulated with procctl(2).  Once a sysfil is
 * disabled, a process generally cannot ever enable it again.
 *
 * Sysfils are used to implement pledge() support.  Many, but not all, pledge
 * promises will directly correpond to a sysfil.
 */

/*
 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 *
 * XXX pledge(2) support is Work In Progress.  Currently incomplete and
 * possibly insecure. XXX
 *
 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 *
 * Miscellaneous Development Notes:
 *
 * The following syscalls are enabled under pledge("stdio") (PLEDGE_ALWAYS +
 * PLEDGE_STDIO) but not Capsicum.  They should have some extra verification
 * (on top of the general VFS access checks).
 *
 *   open(2), wait4(2), fchdir(2), access(2), readlink(2), adjtime(2),
 *   eaccess(2), posix_fadvise(2), rtprio(2), rtprio_thread(2)
 *
 * Both Capsicum and pledge("stdio") allow ioctl(2), but Capsicum applications
 * probably tend to be more careful about not carrying too many potentially
 * insecure FDs after entering capability mode (and hopefully they'll restrict
 * the rights(4) on those that they keep).  ioctl(2) will need good filtering
 * to be safe for pledged applications.  This could also be useful as an extra
 * filtering layer for Capsicum applications.
 *
 * pledge("stdio") allows a few filesystem access syscalls to support a
 * whitelist of paths that can be accessed (even without pledge("rpath")).
 * This works differently than unveil(2) and it only works if absolute paths
 * are passed to syscalls (it does do some canonicalization though).  This will
 * have to be done very carefully.
 *
 * As it is, it is also the case that Capsicum allows some syscalls that
 * pledge("stdio") does not.  It should be safe to enable most (if not all) of
 * them under pledge("stdio"), but this defeats one goal of pledge() which is
 * to limit the kernel's exposed attack surface.  For now, let's at least allow
 * a minimal set of less risky syscalls that most Capsicum applications
 * absolutely need.
 *
 * freebsd32 compat syscalls will need pledge annotations too.  While Linux
 * binaries can't use pledge(), they could still be run by a pledged
 * application with execpromises.
 */

typedef u_int32_t sysfil_t;

#define	SYF_NONE		0x00000000

/*
 * A system call is permitted in capability mode.
 */
#define	SYF_CAPENABLED		0x00000001

#define	SYF_PLEDGE_ERROR	0x00000002
#define	SYF_PLEDGE_ALWAYS	0x00000004
#define	SYF_PLEDGE_STDIO	0x00000008
/*
 * SYF_PLEDGE_CAPCOMPAT defined to have the same value as SYF_PLEDGE_STDIO.  It
 * includes a subset of syscalls that are allowed under Capsicum but not under
 * pledge("stdio") on OpenBSD.  This is to get at least basic compatibility
 * between pledge(2) and Capsicum.  Use a different macro for now just to help
 * keep track of them.
 */
#define	SYF_PLEDGE_CAPCOMPAT	SYF_PLEDGE_STDIO
#define	SYF_PLEDGE_SETTIME	0x00000010
#define	SYF_PLEDGE_PROC		0x00000020
#define	SYF_PLEDGE_ID		0x00000040
#define	SYF_PLEDGE_UNVEIL	0x00000080
#define	SYF_PLEDGE_EXEC		0x00000100
#define	SYF_PLEDGE_RPATH	0x00000200
#define	SYF_PLEDGE_WPATH	0x00000400
#define	SYF_PLEDGE_CPATH	0x00000800
#define	SYF_PLEDGE_TMPPATH	0x00001000
#define	SYF_PLEDGE_DPATH	0x00002000
#define	SYF_PLEDGE_TTY		0x00004000
#define	SYF_PLEDGE_FATTR	0x00008000
#define	SYF_PLEDGE_CHOWN	0x00010000
#define	SYF_PLEDGE_INET		0x00020000
#define	SYF_PLEDGE_UNIX		0x00040000
#define	SYF_PLEDGE_DNS		0x00080000
#define	SYF_PLEDGE_FLOCK	0x00100000
#define	SYF_PLEDGE_YPACTIVE	0x00200000
#define	SYF_PLEDGE_THREAD	0x00400000

/*
 * Used internally when there should be at least one bit set.
 */
#define	SYF_DEFAULT		0x80000000

#endif
