#ifndef	_SYS_PLEDGE_H_
#define	_SYS_PLEDGE_H_

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
 *   eaccess(2), posix_fadvise(2)
 *
 * As it is, Capsicum allows quite a few syscalls that pledge("stdio") does not
 * and it should be safe to enable any of them under pledge("stdio"), but this
 * defeats one goal of pledge() which is to limit the kernel's exposed attack
 * surface.
 *
 */

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/pledge_set.h>
#include <sys/ucred.h>
#include <sys/proc.h>

/*
 * If pledge support isn't compiled in, pledge promises aren't actually stored
 * in the credentials structures.  But pledge_check() is still available and
 * behaves as if they had been all enabled.
 */

static inline void
pledge_cred_init(struct ucred *cr) {
	cr->cr_fflags = -1; /* allow all syscalls */
#ifdef PLEDGE
	pledge_set_init(&cr->cr_pledge);
	pledge_set_init(&cr->cr_execpledge);
#endif
}

static inline int
pledge_check(struct thread *td, enum pledge_promise pr) {
	/* XXX: OpenBSD generally returns EPERM for this, and ECAPMODE's error
	 * string is "Not permitted in capability mode", which is confusing
	 * because "capability mode" is a Capsicum term.  syscallret()
	 * currently relies on these error codes being used to detect pledge
	 * violations and send a signal if needed. */
#ifdef PLEDGE
	return (pledge_set_test(&td->td_ucred->cr_pledge, pr) ? 0 : ECAPMODE);
#else
	return (0); /* no restrictions */
#endif
}

#define	CRED_PLEDGED(cr, pr)		(pledge_set_test(&(cr)->cr_pledge, (pr)))

#endif
