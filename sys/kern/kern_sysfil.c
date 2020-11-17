#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_capsicum.h"
#include "opt_kdb.h"

#include <sys/param.h>
#include <sys/sysproto.h>
#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/systm.h>
#include <sys/ucred.h>
#include <sys/syslog.h>
#include <sys/sysctl.h>
#include <sys/priv.h>
#include <sys/jail.h>
#include <sys/signalvar.h>
#include <sys/sysfil.h>
#include <sys/kdb.h>

#include <sys/filio.h>
#include <sys/tty.h>
#include <sys/socket.h>
#include <netinet/in.h>

static unsigned __read_mostly sysfil_violation_log_level = 1;
SYSCTL_UINT(_kern, OID_AUTO, log_sysfil_violation,
    CTLFLAG_RW, &sysfil_violation_log_level, 0,
    "Log violations of sysfil restrictions");

int
sysfil_require_ioctl(struct thread *td, int sf, u_long com)
{
	if (sysfil_check(td, SYSFIL_ANY_IOCTL) == 0)
		return (0);
	switch (com) {
	case FIOCLEX:
	case FIONCLEX:
	case FIONREAD:
	case FIONWRITE:
	case FIONSPACE:
	case FIONBIO:
	case FIOASYNC:
	case FIOGETOWN:
	case FIODTYPE:
		/* always allowed ioctls */
		sf = SYSFIL_ALWAYS;
		break;
	case TIOCGETA:
		/* needed for isatty(3) */
		sf = SYSFIL_STDIO;
		break;
	case FIOSETOWN:
		/* also checked in setown() */
		sf = SYSFIL_PROC;
		break;
	}
	return (sysfil_require(td, sf));
}

int
sysfil_require_af(struct thread *td, int af)
{
	int sf = SYSFIL_ANY_AF;
	if (sysfil_check(td, sf) == 0)
		return (0);
	switch (af) {
	case AF_UNIX:
		sf = SYSFIL_UNIX;
		break;
	case AF_INET:
	case AF_INET6:
		sf = SYSFIL_INET;
		break;
	}
	return (sysfil_require(td, sf));
}

int
sysfil_require_sockopt(struct thread *td, int level, int name)
{
	int sf = SYSFIL_ANY_SOCKOPT;
	if (sysfil_check(td, sf) == 0)
		return (0);
	switch (level) {
	case SOL_SOCKET:
		switch (name) {
		case SO_SETFIB:
			sf = SYSFIL_SETFIB;
			break;
		case SO_LABEL:
		case SO_PEERLABEL:
			sf = SYSFIL_MAC;
			break;
		default:
			sf = SYSFIL_ALWAYS;
			break;
		}
		break;
	case IPPROTO_IP:
	case IPPROTO_IPV6:
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		sf = SYSFIL_INET;
		break;
	}
	return (sysfil_require(td, sf));
}

int
sysfil_priv_check(struct ucred *cr, int priv)
{
#ifdef SYSFIL
	/*
	 * Mostly a subset of what's being allowed for jails (see
	 * prison_priv_check()) with some extra conditions based on sysfils.
	 * Some of those checks might be redundant with current syscall
	 * filterings, but this might be hard to tell and including them here
	 * anyway makes things a bit clearer.
	 */
	switch (priv) {
	case PRIV_CRED_SETUID:
	case PRIV_CRED_SETEUID:
	case PRIV_CRED_SETGID:
	case PRIV_CRED_SETEGID:
	case PRIV_CRED_SETGROUPS:
	case PRIV_CRED_SETREUID:
	case PRIV_CRED_SETREGID:
	case PRIV_CRED_SETRESUID:
	case PRIV_CRED_SETRESGID:
	case PRIV_PROC_SETLOGIN:
	case PRIV_PROC_SETLOGINCLASS:
		if (sysfil_check_cred(cr, SYSFIL_ID) == 0)
			return (0);
		break;
	case PRIV_SEEOTHERGIDS:
	case PRIV_SEEOTHERUIDS:
		if (sysfil_check_cred(cr, SYSFIL_PS) == 0)
			return (0);
		break;
	case PRIV_PROC_LIMIT:
	case PRIV_PROC_SETRLIMIT:
		if (sysfil_check_cred(cr, SYSFIL_RLIMIT) == 0)
			return (0);
		break;
	case PRIV_JAIL_ATTACH:
	case PRIV_JAIL_SET:
	case PRIV_JAIL_REMOVE:
		if (sysfil_check_cred(cr, SYSFIL_JAIL) == 0)
			return (0);
		break;
	case PRIV_VFS_READ:
	case PRIV_VFS_WRITE:
	case PRIV_VFS_ADMIN:
	case PRIV_VFS_EXEC:
	case PRIV_VFS_LOOKUP:
	case PRIV_VFS_BLOCKRESERVE:	/* XXXRW: Slightly surprising. */
	case PRIV_VFS_CHFLAGS_DEV:
	case PRIV_VFS_LINK:
	case PRIV_VFS_STAT:
	case PRIV_VFS_STICKYFILE:
		/* Allowing to restrict this could be useful? */
		return (0);
	case PRIV_VFS_SYSFLAGS:
		if (sysfil_check_cred(cr, SYSFIL_SYSFLAGS) == 0)
			return (0);
		break;
	case PRIV_VFS_READ_DIR:
		/* Let other policies handle this (like is done for jails). */
		return (0);
	case PRIV_VFS_CHOWN:
	case PRIV_VFS_SETGID:
	case PRIV_VFS_RETAINSUGID:
		if (sysfil_check_cred(cr, SYSFIL_CHOWN) == 0)
			return (0);
		break;
	case PRIV_VFS_CHROOT:
	case PRIV_VFS_FCHROOT:
		if (sysfil_check_cred(cr, SYSFIL_CHROOT) == 0)
			return (0);
		break;
	case PRIV_VM_MLOCK:
	case PRIV_VM_MUNLOCK:
		if (sysfil_check_cred(cr, SYSFIL_MLOCK) == 0)
			return (0);
		break;
	case PRIV_NETINET_RESERVEDPORT:
#if 0
	case PRIV_NETINET_REUSEPORT:
	case PRIV_NETINET_SETHDROPTS:
#endif
		return (0);
	case PRIV_NETINET_RAW:
		if (sysfil_check_cred(cr, SYSFIL_INET_RAW) == 0)
			return (0);
		break;
#if 0
	case PRIV_NETINET_GETCRED:
		return (0);
#endif
	case PRIV_ADJTIME:
	case PRIV_NTP_ADJTIME:
	case PRIV_CLOCK_SETTIME:
		if (sysfil_check_cred(cr, SYSFIL_SETTIME) == 0)
			return (0);
		break;
	case PRIV_VFS_GETFH:
	case PRIV_VFS_FHOPEN:
	case PRIV_VFS_FHSTAT:
	case PRIV_VFS_FHSTATFS:
	case PRIV_VFS_GENERATION:
		if (sysfil_check_cred(cr, SYSFIL_FH) == 0)
			return (0);
		break;
	}
	return (sysfil_check_cred(cr, SYSFIL_ANY_PRIV));
#else
	return (0);
#endif
}

static void
sysfil_log_violation(struct thread *td, int sf, bool signaled)
{
#ifdef SYSFIL
	struct proc *p = td->td_proc;
	struct ucred *cr = td->td_ucred;
	log(LOG_ERR, "pid %d (%s), jid %d, uid %d: violated sysfil #%d restrictions%s\n",
	    p->p_pid, p->p_comm, cr->cr_prison->pr_id, cr->cr_uid, sf,
	    signaled ? " and was signaled" : "");
#endif
}

void
sysfil_violation(struct thread *td, int sf, int error)
{
#ifdef SYSFIL
	bool trap = sysfil_check(td, SYSFIL_ERROR) != 0;
	if (sysfil_violation_log_level >= 2 ? true :
	    sysfil_violation_log_level >= 1 ? trap :
	                                      false)
		sysfil_log_violation(td, sf, trap);
	if (trap) {
		ksiginfo_t ksi;
		/*
		 * OpenBSD sends an "uncatchable" SIGABRT.  Not sure how to
		 * correctly do that, so instead we restrict the ability to
		 * handle SIGABRT in the first place.
		 */
		ksiginfo_init_trap(&ksi);
		ksi.ksi_signo = SIGTRAP;
		ksi.ksi_errno = error;
		ksi.ksi_code = TRAP_SYSFIL;
		trapsignal(td, &ksi);
	}
#endif
}

#ifdef SYSFIL

static void
sysfilset_fill(sysfilset_t *sysfilset, int sf)
{
	/*
	 * "Expand" sysfils passed by the user.  Some sysfils don't make much
	 * sense without some others.
	 */
	if (!SYSFIL_VALID(sf))
		return;
	switch (sf) {
	case SYSFIL_RPATH:
	case SYSFIL_WPATH:
	case SYSFIL_CPATH:
	case SYSFIL_DPATH:
		SYSFILSET_FILL(sysfilset, SYSFIL_PATH);
		break;
	case SYSFIL_INET:
	case SYSFIL_INET_RAW:
	case SYSFIL_UNIX:
		SYSFILSET_FILL(sysfilset, SYSFIL_NET);
		break;
	case SYSFIL_CPUSET:
		SYSFILSET_FILL(sysfilset, SYSFIL_SCHED);
		break;
	case SYSFIL_ANY_PROCESS:
		SYSFILSET_FILL(sysfilset, SYSFIL_SAME_SESSION);
		/* FALLTHROUGH */
	case SYSFIL_SAME_SESSION:
		SYSFILSET_FILL(sysfilset, SYSFIL_SAME_PGRP);
		/* FALLTHROUGH */
	case SYSFIL_SAME_PGRP:
		SYSFILSET_FILL(sysfilset, SYSFIL_CHILD_PROCESS);
		break;
	}
	SYSFILSET_FILL(sysfilset, sf);
}

static int
sysfil_cred_update(struct ucred *cr,
    int flags, size_t count, const int *sysfils)
{
	sysfilset_t sysfilset = SYSFILSET_INITIALIZER;
	SYSFILSET_FILL(&sysfilset, SYSFIL_ALWAYS);
	while (count--) {
		int sf = *sysfils++;
		if (!SYSFIL_USER_VALID(sf))
			return (EINVAL);
		sysfilset_fill(&sysfilset, sf);
		if (!(flags & SYSFILCTL_OPTIONAL) &&
		     (((flags & SYSFILCTL_FOR_CURR) &&
		        !SYSFILSET_MATCH(&cr->cr_sysfilset, sf)) ||
		      ((flags & SYSFILCTL_FOR_EXEC) &&
		        !SYSFILSET_MATCH(&cr->cr_sysfilset_exec, sf))))
				return (EPERM);
	}
	/*
	 * SYSFIL_DEFAULT should always be disabled after masking (since it
	 * isn't SYSFIL_USER_VALID()), which means that the sysfilset should
	 * always be considered to be in "restricted" mode.
	 */
	if (flags & SYSFILCTL_FOR_CURR) {
		SYSFILSET_MASK(&cr->cr_sysfilset, &sysfilset);
		MPASS(SYSFILSET_IS_RESTRICTED(&cr->cr_sysfilset));
		MPASS(CRED_IN_RESTRICTED_MODE(cr));
	}
	if (flags & SYSFILCTL_FOR_EXEC) {
		if (SYSFILSET_MATCH(&cr->cr_sysfilset, SYSFIL_EXEC) ||
		    SYSFILSET_MATCH(&sysfilset, SYSFIL_EXEC))
			/*
			 * On OpenBSD, executing dynamically linked binaries
			 * works with just the "exec" pledge (the "prot_exec"
			 * pledge is only enforced after the dynamic linker has
			 * done its job).  Not so for us, so implicitly allow
			 * PROT_EXEC for now. XXX
			 */
			SYSFILSET_FILL(&sysfilset, SYSFIL_PROT_EXEC);
		SYSFILSET_MASK(&cr->cr_sysfilset_exec, &sysfilset);
		MPASS(SYSFILSET_IS_RESTRICTED(&cr->cr_sysfilset_exec));
		MPASS(CRED_IN_RESTRICTED_EXEC_MODE(cr));
	}
	return (0);
}

static int
do_sysfilctl(struct thread *td, int flags, size_t count, const int *sysfils)
{
	struct proc *p = td->td_proc;
	struct ucred *newcred, *oldcred;
	int error;
	if (!(flags & (SYSFILCTL_OPTIONAL | SYSFILCTL_MANDATORY)) &&
	    sysfil_check(td, SYSFIL_ERROR) == 0)
		flags |= SYSFILCTL_OPTIONAL;
	newcred = crget();
	PROC_LOCK(p);
	oldcred = crcopysafe(p, newcred);
	error = sysfil_cred_update(newcred, flags, count, sysfils);
	if (!error) {
		proc_set_cred(p, newcred);
		if (flags & SYSFILCTL_FOR_CURR && !PROC_IN_RESTRICTED_MODE(p))
			panic("PROC_IN_RESTRICTED_MODE() bogus after sysfil(2)");
		if (flags & SYSFILCTL_FOR_EXEC && !PROC_IN_RESTRICTED_EXEC_MODE(p))
			panic("PROC_IN_RESTRICTED_EXEC_MODE() bogus after sysfil(2)");
	}
	PROC_UNLOCK(p);
	crfree(error ? newcred : oldcred);
	return (error);
}

#endif /* SYSFIL */

int
sys_sysfilctl(struct thread *td, struct sysfilctl_args *uap)
{
#ifdef SYSFIL
	size_t count;
	int *sysfils;
	int flags, error;
	flags = uap->flags;
	count = uap->count;
	if (count > SYSFILCTL_MAX_COUNT)
		return (EINVAL);
	if (!uap->sysfils)
		return (EINVAL);
	if (!(flags & (SYSFILCTL_FOR_CURR | SYSFILCTL_FOR_EXEC)))
		flags |= SYSFILCTL_FOR_CURR | SYSFILCTL_FOR_EXEC;
	sysfils = mallocarray(count, sizeof *sysfils, M_TEMP, M_WAITOK);
	error = copyin(uap->sysfils, sysfils, count * sizeof *sysfils);
	if (error)
		goto out;
	error = do_sysfilctl(td, flags, count, sysfils);
out:	free(sysfils, M_TEMP);
	return (error);
#else
	return (ENOSYS);
#endif /* SYSFIL */
}
