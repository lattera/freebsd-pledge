#ifndef _SYS_SYSFIL_H_
#define	_SYS_SYSFIL_H_

#include <sys/_sysfil.h>

#ifdef _KERNEL
#include <sys/types.h>
#include <sys/proc.h>
#include <sys/ucred.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <security/mac/mac_framework.h>
#endif

#define	SYSFIL_INDEX(i)		((sysfilset_t)1 << (i))

/* Represents the state of NOT being in Capsicum capability mode. */
#define	SYSFIL_UNCAPSICUM	SYSFIL_INDEX(0)
/* Fallback for miscellaneous operations that must be restricted. */
#define	SYSFIL_DEFAULT		SYSFIL_INDEX(1)
/* Various operations that should always be allowed. */
#define	SYSFIL_ALWAYS		SYSFIL_INDEX(2)

#define	SYSFIL_STDIO		SYSFIL_INDEX(3)
#define	SYSFIL_VFS_MISC		SYSFIL_INDEX(4)
#define	SYSFIL_VFS_READ		SYSFIL_INDEX(5)
#define	SYSFIL_VFS_WRITE	SYSFIL_INDEX(6)
#define	SYSFIL_VFS_CREATE	SYSFIL_INDEX(7)
#define	SYSFIL_VFS_DELETE	SYSFIL_INDEX(8)
#define	SYSFIL_FATTR		SYSFIL_INDEX(9)
#define	SYSFIL_FLOCK		SYSFIL_INDEX(10)
#define	SYSFIL_TTY		SYSFIL_INDEX(11)
#define	SYSFIL_NET		SYSFIL_INDEX(12)
#define	SYSFIL_PROC		SYSFIL_INDEX(13)
#define	SYSFIL_THREAD		SYSFIL_INDEX(14)
#define	SYSFIL_EXEC		SYSFIL_INDEX(15)
#define	SYSFIL_CURTAIN		SYSFIL_INDEX(16)
#define	SYSFIL_RLIMIT		SYSFIL_INDEX(17)
#define	SYSFIL_SETTIME		SYSFIL_INDEX(18)
#define	SYSFIL_ID		SYSFIL_INDEX(19)
#define	SYSFIL_CHOWN		SYSFIL_INDEX(20)
#define	SYSFIL_MLOCK		SYSFIL_INDEX(21)
#define	SYSFIL_AIO		SYSFIL_INDEX(22)
#define	SYSFIL_EXTATTR		SYSFIL_INDEX(23)
#define	SYSFIL_ACL		SYSFIL_INDEX(24)
#define	SYSFIL_CPUSET		SYSFIL_INDEX(25)
#define	SYSFIL_SYSVIPC		SYSFIL_INDEX(26)
#define	SYSFIL_POSIXIPC		SYSFIL_INDEX(27)
#define	SYSFIL_POSIXRT		SYSFIL_INDEX(28)
#define	SYSFIL_MAC		SYSFIL_INDEX(29)
#define	SYSFIL_CHROOT		SYSFIL_INDEX(30)
#define	SYSFIL_JAIL		SYSFIL_INDEX(31)
#define	SYSFIL_SCHED		SYSFIL_INDEX(32)
#define	SYSFIL_MKFIFO		SYSFIL_INDEX(33)
#define	SYSFIL_PS		SYSFIL_INDEX(34)
#define	SYSFIL__UNUSED1		SYSFIL_INDEX(35)
#define	SYSFIL_DEBUG		SYSFIL_INDEX(36)
#define	SYSFIL_UNIX		SYSFIL_INDEX(37)
#define	SYSFIL_MAKEDEV		SYSFIL_INDEX(38)
#define	SYSFIL_ANY_SYSCTL	SYSFIL_INDEX(39)
#define	SYSFIL_CHMOD_SPECIAL	SYSFIL_INDEX(40)
#define	SYSFIL_SYSFLAGS		SYSFIL_INDEX(41)
#define	SYSFIL_ANY_SOCKAF	SYSFIL_INDEX(42)
#define	SYSFIL_ANY_PRIV		SYSFIL_INDEX(43)
#define	SYSFIL_SENDFILE		SYSFIL_INDEX(44)
#define	SYSFIL_MOUNT		SYSFIL_INDEX(45)
#define	SYSFIL_QUOTA		SYSFIL_INDEX(46)
#define	SYSFIL_FH		SYSFIL_INDEX(47)
#define	SYSFIL_RECVFD		SYSFIL_INDEX(48)
#define	SYSFIL_SENDFD		SYSFIL_INDEX(49)
#define	SYSFIL_PROT_EXEC	SYSFIL_INDEX(50)
#define	SYSFIL_RSUGID_EXEC	SYSFIL_INDEX(51)
#define	SYSFIL_ANY_IOCTL	SYSFIL_INDEX(52)
#define	SYSFIL_ANY_SOCKOPT	SYSFIL_INDEX(53)
#define	SYSFIL__UNUSED2		SYSFIL_INDEX(54)
#define	SYSFIL__UNUSED3		SYSFIL_INDEX(55)
#define	SYSFIL_REAP		SYSFIL_INDEX(56)
#define	SYSFIL_FFCLOCK		SYSFIL_INDEX(57)
#define	SYSFIL_AUDIT		SYSFIL_INDEX(58)
#define	SYSFIL_RFORK		SYSFIL_INDEX(59)
#define	SYSFIL__UNUSED6		SYSFIL_INDEX(60)
#define	SYSFIL__UNUSED7		SYSFIL_INDEX(61)
#define	SYSFIL_PROT_EXEC_LOOSE	SYSFIL_INDEX(62)

#ifdef _KERNEL
CTASSERT(SYSFIL_UNCAPSICUM == SYSFIL_INDEX(SYSFILSET_NOT_IN_CAPABILITY_MODE_BIT));
#endif

/*
 * Some syscalls are assigned to sysfils that may seem to be less restrictive
 * than they should be.  Usually these syscalls will be doing their own
 * checking and only allow safe operations.  These aliases are used to keep
 * track of them and make it more explicit.
 */
#ifdef _KERNEL
/*
 * SYSFIL_CAPCOMPAT is for certain syscalls that are allowed under Capsicum but
 * not under OpenBSD's "stdio" pledge.  This is to get at least some basic
 * level of compatibility when attempting to run Capsicum applications with
 * inherited pledges.
 */
#define	SYSFIL_CAPCOMPAT	SYSFIL_STDIO
/* Can do certain operations on self. */
#define	SYSFIL_PROC_CHECKED	SYSFIL_STDIO
#define	SYSFIL_THREAD_CHECKED	SYSFIL_ALWAYS
#define	SYSFIL_CPUSET_CHECKED	SYSFIL_SCHED
/* Allow RFSPAWN with just SYSFIL_PROC. */
#define	SYSFIL_RFORK_CHECKED	SYSFIL_PROC
/* Creation of anonymous memory objects are allowed. */
#define	SYSFIL_POSIXIPC_CHECKED	SYSFIL_STDIO
/*
 * SYSFIL_CHOWN is not required for all chown(2) syscalls.  It represents the
 * ability to set the file's owner UID to something different or set its group
 * GID to something different that the process is not a member of.
 */
#define	SYSFIL_CHOWN_CHECKED	SYSFIL_FATTR
/* Retrieving correction delta with adjtime(2) is allowed. */
#define	SYSFIL_SETTIME_CHECKED	SYSFIL_STDIO
#define	SYSFIL_SCTP		SYSFIL_NET
#endif


#ifdef _KERNEL

#define	SYSFIL_FAILED_ERRNO	EPERM

static inline bool
sysfil_match_cred(const struct ucred *cr, sysfilset_t sfs) {
#ifndef NOSYSFIL
	return (!(sfs & ~cr->cr_sysfilset));
#else
	return (true);
#endif
}

static inline int
sysfil_probe_cred(struct ucred *cr, sysfilset_t sfs)
{
	if (__predict_true(sysfil_match_cred(cr, sfs)))
		return (0);
	return (SYSFIL_FAILED_ERRNO);
}

static inline int
sysfil_probe(struct thread *td, sysfilset_t sfs)
{
	return (sysfil_probe_cred(td->td_ucred, sfs));
}

static inline int
sysfil_check_cred(struct ucred *cr, sysfilset_t sfs)
{
	int error;
	error = sysfil_probe_cred(cr, sfs);
#ifdef MAC
	if (error)
		error = mac_sysfil_check(cr, sfs);
#endif
	return (error);
}

static inline int
sysfil_check(struct thread *td, sysfilset_t sfs)
{
	return (sysfil_check_cred(td->td_ucred, sfs));
}

static inline void
sysfil_cred_init(struct ucred *cr)
{
#ifndef NOSYSFIL
	cr->cr_sysfilset = ~(sysfilset_t)0;
#endif
}


static inline bool
sysfil_match_sy_flags(const struct ucred *cr, sysfilset_t sy_flags)
{
	return (sysfil_match_cred(cr, ~sy_flags));
}

static inline int
sysfil_check_sy_flags(struct ucred *cr, sysfilset_t sy_flags)
{
	return (sysfil_check_cred(cr, ~sy_flags));
}

#endif

#endif
