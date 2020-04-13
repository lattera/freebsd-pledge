#ifndef	_SYS_SYSFIL_H
#define	_SYS_SYSFIL_H

#include <sys/errno.h>
#include <sys/proc.h>
#include <sys/stdint.h>
#include <sys/types.h>
#include <sys/ucred.h>
#include <sys/_sysfil.h>

/* OpenBSD generally returns EPERM for this, and ECAPMODE's error string is
 * "Not permitted in capability mode", which is confusing because "capability
 * mode" is a Capsicum term.  syscallret() currently relies on these error
 * codes being used to detect pledge violations and send a signal if needed. */

static const int sysfil_fail_errno = ECAPMODE;

static inline int
sysfil_probe(struct thread *td, sysfil_t sf)
{
#ifdef PLEDGE
	if (td->td_proc->p_sysfil & sf)
		return (0);
	return (sysfil_fail_errno);
#else
	return (0);
#endif
}

static inline void
sysfil_check_failed(struct thread *td)
{
	/* Could send the pledge violation signal directly from here. */
}

static inline int
sysfil_check(struct thread *td, sysfil_t sf)
{
	int error;
	error = sysfil_probe(td, sf);
	if (error)
		sysfil_check_failed(td);
	return (error);
}

static inline int
sysfil_failed(struct thread *td)
{
	return (sysfil_check(td, SYF_NONE));
}

int sysfil_check_ioctl(struct thread *, sysfil_t, u_long cmd);

#endif
