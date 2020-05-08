#include <sys/types.h>
#include <sys/proc.h>
#include <sys/sysfil.h>
#include <sys/filio.h>
#include <sys/tty.h>

int
sysfil_check_ioctl(struct thread *td, sysfil_t sf, u_long cmd)
{
	switch (cmd) {
#ifdef SYSFIL
	case FIOCLEX:
	case FIONCLEX:
	case FIONREAD:
	case FIONBIO:
	case FIOASYNC:
	case FIOGETOWN:
	case FIODTYPE:
#if 0
	case FIOGETLBA:
#endif
		return (0);
	case TIOCGETA:
		/* needed for isatty(3) */
		return (sysfil_check(td, SYF_PLEDGE_STDIO));
	case FIOSETOWN:
		/* also checked in setown() */
		return (sysfil_check(td, SYF_PLEDGE_PROC));
#endif
	default:
		return (sysfil_check(td, sf));
	}
}

int
sysfil_namei_check(struct nameidata *ndp)
{
#ifdef SYSFIL
	int error;
	struct componentname *cnp = &ndp->ni_cnd;
	struct thread *td = cnp->cn_thread;
	if (cnp->cn_nameiop != LOOKUP &&
	    (error = sysfil_check(td, SYF_PLEDGE_CPATH)))
		return (error);
	if ((ndp->ni_uflags & NIUNV_FORREAD) &&
	    (error = sysfil_check(td, SYF_PLEDGE_RPATH)))
		return (error);
	if ((ndp->ni_uflags & NIUNV_FORWRITE) &&
	    (error = sysfil_check(td, SYF_PLEDGE_WPATH)))
		return (error);
#endif
	return (0);
}

