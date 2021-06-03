#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_capsicum.h"

#include <sys/param.h>
#include <sys/sysproto.h>
#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/systm.h>
#include <sys/ucred.h>
#include <sys/syslog.h>
#include <sys/sysctl.h>
#include <sys/priv.h>
#include <sys/jail.h>
#include <sys/signalvar.h>
#include <sys/mman.h>
#include <sys/sysfil.h>
#include <sys/unveil.h>

#include <sys/filio.h>
#include <sys/tty.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>

static bool __read_mostly sysfil_enabled = true;
static unsigned __read_mostly sysfil_violation_log_level = 1;

SYSCTL_NODE(_security, OID_AUTO, curtain,
    CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
    "Curtain");

SYSCTL_BOOL(_security_curtain, OID_AUTO, enabled,
    CTLFLAG_RW, &sysfil_enabled, 0,
    "Allow curtainctl(2) usage");

SYSCTL_UINT(_security_curtain, OID_AUTO, log_sysfil_violation,
    CTLFLAG_RW, &sysfil_violation_log_level, 0,
    "Log violations of sysfil restrictions");

int
sysfil_require_vm_prot(struct thread *td, vm_prot_t prot, bool loose)
{
	if (prot & VM_PROT_EXECUTE)
		return (sysfil_require(td, loose && !(prot & VM_PROT_WRITE) ?
		    SYSFIL_PROT_EXEC_LOOSE : SYSFIL_PROT_EXEC));
	return (0);
}

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
			sf = SYSFIL_NET;
			break;
		}
		break;
#if 0 /* XXX SOL_LOCAL and IPPROTO_IP are both 0! */
	case SOL_LOCAL:
		sf = SYSFIL_UNIX;
		break;
#endif
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
	case PRIV_NETINET_IPFW:
	case PRIV_NETINET_DUMMYNET:
	case PRIV_NETINET_PF:
		if (sysfil_check_cred(cr, SYSFIL_PFIL) == 0)
			return (0);
		break;
	}
	return (sysfil_check_cred(cr, SYSFIL_ANY_PRIV));
#else
	return (0);
#endif
}

#ifdef SYSFIL
static void
sysfil_log_violation(struct thread *td, int sf, bool signaled)
{
	struct proc *p = td->td_proc;
	struct ucred *cr = td->td_ucred;
	log(LOG_ERR, "pid %d (%s), jid %d, uid %d: violated sysfil #%d restrictions%s\n",
	    p->p_pid, p->p_comm, cr->cr_prison->pr_id, cr->cr_uid, sf,
	    signaled ? " and was signaled" : "");
}
#endif

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
		 * correctly do that, so instead just send a SIGKILL.
		 */
		ksiginfo_init_trap(&ksi);
		ksi.ksi_signo = SIGKILL;
		ksi.ksi_code = SI_SYSFIL;
		ksi.ksi_sysfil = sf;
		ksi.ksi_errno = error;
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
		BIT_SET(SYSFILSET_BITS, SYSFIL_PATH, sysfilset);
		break;
	case SYSFIL_PROT_EXEC:
		BIT_SET(SYSFILSET_BITS, SYSFIL_PROT_EXEC_LOOSE, sysfilset);
		break;
	case SYSFIL_INET:
	case SYSFIL_INET_RAW:
	case SYSFIL_UNIX:
		BIT_SET(SYSFILSET_BITS, SYSFIL_NET, sysfilset);
		break;
	case SYSFIL_CPUSET:
		BIT_SET(SYSFILSET_BITS, SYSFIL_SCHED, sysfilset);
		break;
	case SYSFIL_ANY_PROCESS:
		BIT_SET(SYSFILSET_BITS, SYSFIL_SAME_SESSION, sysfilset);
		/* FALLTHROUGH */
	case SYSFIL_SAME_SESSION:
		BIT_SET(SYSFILSET_BITS, SYSFIL_SAME_PGRP, sysfilset);
		/* FALLTHROUGH */
	case SYSFIL_SAME_PGRP:
		BIT_SET(SYSFILSET_BITS, SYSFIL_CHILD_PROCESS, sysfilset);
		break;
	}
	BIT_SET(SYSFILSET_BITS, sf, sysfilset);
}

static int
do_curtainctl(struct thread *td, int flags, size_t reqc, const struct curtainreq *reqv)
{
	struct proc *p = td->td_proc;
	struct ucred *cr, *old_cr;
	const struct curtainreq *req;
	int error;
	sysfilset_t sysfilset_self, sysfilset_exec;
#ifdef UNVEIL
	struct unveil_base *base = &td->td_proc->p_unveils;
#endif

	if (!sysfil_enabled)
		return (ENOSYS);

	BIT_ZERO(SYSFILSET_BITS, &sysfilset_self);
	BIT_SET(SYSFILSET_BITS, SYSFIL_ALWAYS, &sysfilset_self);
	BIT_SET(SYSFILSET_BITS, SYSFIL_UNCAPSICUM, &sysfilset_self);
	BIT_COPY(SYSFILSET_BITS, &sysfilset_self, &sysfilset_exec);

#if UNVEIL
	unveil_base_write_begin(base);
#endif

	cr = crget();
	PROC_LOCK(p);
	old_cr = crcopysafe(p, cr);
	error = 0;

	for (req = reqv; req < &reqv[reqc]; req++) {
		bool on_self = flags & CURTAINCTL_ON_SELF &&
		               req->flags & CURTAINREQ_ON_SELF,
		     on_exec = flags & CURTAINCTL_ON_EXEC &&
		               req->flags & CURTAINREQ_ON_EXEC;
		switch (req->type) {
		case CURTAIN_SYSFIL: {
			int *sfp = req->data;
			size_t sfc = req->size / sizeof *sfp;
			while (sfc--) {
				int sf = *sfp++;
				if (!SYSFIL_USER_VALID(sf)) {
					error = EINVAL;
					goto out1;
				}
				if (flags & CURTAINCTL_REQUIRE &&
				     ((on_self && !BIT_ISSET(SYSFILSET_BITS,
				           sf, &cr->cr_sysfilset)) ||
				      (on_exec && !BIT_ISSET(SYSFILSET_BITS,
				           sf, &cr->cr_sysfilset_exec)))) {
					error = EPERM;
					goto out1;
				}
				if (on_self)
					sysfilset_fill(&sysfilset_self, sf);
				if (on_exec)
					sysfilset_fill(&sysfilset_exec, sf);
			}
			break;
		}
#ifdef UNVEIL
		case CURTAIN_UNVEIL: {
			struct curtainent_unveil *entp = req->data;
			size_t entc = req->size / sizeof *entp;
			while (entc--) { /* just check the indexes first */
				error = unveil_index_check(base, (entp++)->index);
				if (error)
					goto out1;
			}
			break;
		}
#endif
		default:
			error = EINVAL;
			goto out1;
		}
	};

	if (flags & CURTAINCTL_ON_SELF) {
		BIT_AND(SYSFILSET_BITS, &cr->cr_sysfilset, &sysfilset_self);
		MPASS(SYSFILSET_IS_RESTRICTED(&cr->cr_sysfilset));
		MPASS(CRED_IN_RESTRICTED_MODE(cr));
	}
	if (flags & CURTAINCTL_ON_EXEC) {
		if (BIT_ISSET(SYSFILSET_BITS, SYSFIL_EXEC, &cr->cr_sysfilset) ||
		    BIT_ISSET(SYSFILSET_BITS, SYSFIL_EXEC, &sysfilset_exec))
			/*
			 * On OpenBSD, executing dynamically linked binaries
			 * works with just the "exec" pledge (the "prot_exec"
			 * pledge is only enforced after the dynamic linker has
			 * done its job).  Not so for us, so implicitly allow
			 * PROT_EXEC for now. XXX
			 */
			BIT_SET(SYSFILSET_BITS, SYSFIL_PROT_EXEC_LOOSE, &sysfilset_exec);
		BIT_AND(SYSFILSET_BITS, &cr->cr_sysfilset_exec, &sysfilset_exec);
		MPASS(SYSFILSET_IS_RESTRICTED(&cr->cr_sysfilset_exec));
		MPASS(CRED_IN_RESTRICTED_EXEC_MODE(cr));
	}

	if (flags & (CURTAINCTL_ENFORCE|CURTAINCTL_ENGAGE)) {
		proc_set_cred(p, cr);
		crfree(old_cr);
		if (flags & CURTAINCTL_ON_SELF && !PROC_IN_RESTRICTED_MODE(p))
			panic("PROC_IN_RESTRICTED_MODE() bogus after curtainctl(2)");
		if (flags & CURTAINCTL_ON_EXEC && !PROC_IN_RESTRICTED_EXEC_MODE(p))
			panic("PROC_IN_RESTRICTED_EXEC_MODE() bogus after curtainctl(2)");
	} else {
		crfree(cr);
		cr = old_cr;
	}
	PROC_UNLOCK(p);

#ifdef UNVEIL
	for (req = reqv; req < &reqv[reqc]; req++) {
		bool on_self = flags & CURTAINCTL_ON_SELF &&
		               req->flags & CURTAINREQ_ON_SELF,
		     on_exec = flags & CURTAINCTL_ON_EXEC &&
		               req->flags & CURTAINREQ_ON_EXEC;
		if (req->type == CURTAIN_UNVEIL) {
			struct curtainent_unveil *entp = req->data;
			size_t entc = req->size / sizeof *entp;
			while (entc--) {
				if (on_self)
					unveil_index_set(base, entp->index,
					    UNVEIL_ON_SELF, entp->uperms);
				if (on_exec)
					unveil_index_set(base, entp->index,
					    UNVEIL_ON_EXEC, entp->uperms);
				entp++;
			}
		}
	}

	if (flags & (CURTAINCTL_ENFORCE|CURTAINCTL_ENGAGE)) {
		if (flags & CURTAINCTL_ON_SELF)
			unveil_base_activate(base, UNVEIL_ON_SELF);
		if (flags & CURTAINCTL_ON_EXEC)
			unveil_base_activate(base, UNVEIL_ON_EXEC);
		if (flags & CURTAINCTL_ENFORCE) {
			if (flags & CURTAINCTL_ON_SELF)
				unveil_base_enforce(base, UNVEIL_ON_SELF);
			if (flags & CURTAINCTL_ON_EXEC)
				unveil_base_enforce(base, UNVEIL_ON_EXEC);
		}
	}

#endif
	goto out2;

out1:
	PROC_UNLOCK(p);
	crfree(cr);
out2:
#ifdef UNVEIL
	unveil_base_write_end(base);
#endif
	return (error);
}

#endif /* SYSFIL */

int
sys_curtainctl(struct thread *td, struct curtainctl_args *uap)
{
#ifdef SYSFIL
	size_t reqc, reqi, rem;
	struct curtainreq *reqv;
	int flags, error;
	flags = uap->flags;
	if ((flags & CURTAINCTL_VERSION_MASK) != CURTAINCTL_VERSION)
		return (EINVAL);
	flags &= ~CURTAINCTL_VERSION_MASK;
	reqc = uap->reqc;
	if (reqc > CURTAINCTL_MAX_REQS)
		return (EINVAL);
	reqi = 0;
	reqv = mallocarray(reqc, sizeof *reqv, M_TEMP, M_WAITOK);
	error = copyin(uap->reqv, reqv, reqc * sizeof *reqv);
	if (error)
		goto out;
	rem = CURTAINCTL_MAX_SIZE;
	while (reqi < reqc) {
		struct curtainreq *req = &reqv[reqi];
		void *udata = req->data;
		if (rem < req->size) {
			error = EINVAL;
			goto out;
		}
		reqi++;
		rem -= req->size;
		req->data = malloc(req->size, M_TEMP, M_WAITOK);
		error = copyin(udata, req->data, req->size);
		if (error)
			goto out;
	}
	error = do_curtainctl(td, flags, reqc, reqv);
out:	while (reqi--)
		free(reqv[reqi].data, M_TEMP);
	free(reqv, M_TEMP);
	return (error);
#else
	return (ENOSYS);
#endif /* SYSFIL */
}


#if defined(SYSFIL)

static cap_rights_t __read_mostly cap_sysfil_rpath_rights;
static cap_rights_t __read_mostly cap_sysfil_wpath_rights;
static cap_rights_t __read_mostly cap_sysfil_cpath_rights;
static cap_rights_t __read_mostly cap_sysfil_exec_rights;
static cap_rights_t __read_mostly cap_sysfil_fattr_rights;
static cap_rights_t __read_mostly cap_sysfil_unix_rights;

void
sysfil_cred_rights(struct ucred *cr, cap_rights_t *rights)
{
	if (!CRED_IN_RESTRICTED_MODE(cr)) {
		CAP_ALL(rights);
		return;
	}
	CAP_NONE(rights);
	if (sysfil_match_cred(cr, SYSFIL_RPATH))
		cap_rights_merge(rights, &cap_sysfil_rpath_rights);
	if (sysfil_match_cred(cr, SYSFIL_WPATH))
		cap_rights_merge(rights, &cap_sysfil_wpath_rights);
	if (sysfil_match_cred(cr, SYSFIL_CPATH))
		cap_rights_merge(rights, &cap_sysfil_cpath_rights);
	if (sysfil_match_cred(cr, SYSFIL_EXEC))
		cap_rights_merge(rights, &cap_sysfil_exec_rights);
	if (sysfil_match_cred(cr, SYSFIL_FATTR))
		cap_rights_merge(rights, &cap_sysfil_fattr_rights);
	if (sysfil_match_cred(cr, SYSFIL_UNIX))
		cap_rights_merge(rights, &cap_sysfil_unix_rights);
}

static void
sysfil_sysinit(void *arg)
{
	/* Note: Some of those rights are further restricted by other sysfils. */
	cap_rights_init(&cap_sysfil_rpath_rights,
	    CAP_LOOKUP,
	    CAP_FLOCK,
	    CAP_READ,
	    CAP_SEEK,
	    CAP_FPATHCONF,
	    CAP_MMAP,
	    CAP_FCHDIR,
	    CAP_FSTAT,
	    CAP_FSTATAT,
	    CAP_FSTATFS,
	    CAP_MAC_GET,
	    CAP_EXTATTR_GET,
	    CAP_EXTATTR_LIST);
	cap_rights_init(&cap_sysfil_wpath_rights,
	    CAP_LOOKUP,
	    CAP_FLOCK,
	    CAP_WRITE,
	    CAP_SEEK,
	    CAP_FPATHCONF,
	    CAP_MMAP,
	    CAP_FSYNC,
	    CAP_FTRUNCATE);
	cap_rights_init(&cap_sysfil_cpath_rights,
	    CAP_LOOKUP,
	    CAP_CREATE,
	    CAP_FPATHCONF,
	    CAP_LINKAT_SOURCE,
	    CAP_LINKAT_TARGET,
	    CAP_MKDIRAT,
	    CAP_MKFIFOAT,
	    CAP_MKNODAT,
	    CAP_SYMLINKAT,
	    CAP_UNLINKAT,
	    CAP_RENAMEAT_SOURCE,
	    CAP_RENAMEAT_TARGET,
	    CAP_UNDELETEAT);
	cap_rights_init(&cap_sysfil_exec_rights,
	    CAP_LOOKUP,
	    CAP_FEXECVE,
	    CAP_EXECAT);
	cap_rights_init(&cap_sysfil_fattr_rights,
	    CAP_LOOKUP,
	    CAP_FCHFLAGS,
	    CAP_CHFLAGSAT,
	    CAP_FCHMOD,
	    CAP_FCHMODAT,
	    CAP_FCHOWN,
	    CAP_FCHOWNAT,
	    CAP_FUTIMES,
	    CAP_FUTIMESAT,
	    CAP_MAC_SET,
	    CAP_REVOKEAT,
	    CAP_EXTATTR_SET,
	    CAP_EXTATTR_DELETE);
	cap_rights_init(&cap_sysfil_unix_rights,
	    CAP_LOOKUP,
	    CAP_BINDAT,
	    CAP_CONNECTAT);
}

SYSINIT(sysfil_sysinit, SI_SUB_COPYRIGHT, SI_ORDER_ANY, sysfil_sysinit, NULL);

#endif
