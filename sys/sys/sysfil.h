#ifndef _SYS_SYSFIL_H_
#define	_SYS_SYSFIL_H_

#include <sys/_sysfil.h>

#ifdef _KERNEL
#include <sys/types.h>
#include <sys/proc.h>
#include <sys/ucred.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/limits.h>
#include <security/mac/mac_framework.h>
#endif

#define	SYSFIL_INDEX(i)		((sysfilset_t)1 << (i))
#define	SYSFIL_NONE		((sysfilset_t)0)
#define	SYSFIL_FULL		((sysfilset_t)-1)

#define	SYSFIL_NOTCAPMODE	SYSFIL_INDEX(0)
#define	SYSFIL__UNUSED1		SYSFIL_INDEX(1)
#define	SYSFIL__UNUSED2		SYSFIL_INDEX(2)
#define	SYSFIL_CORE		SYSFIL_INDEX(3)
#define	SYSFIL_PATH		SYSFIL_INDEX(4)
#define	SYSFIL_RPATH		SYSFIL_INDEX(5)
#define	SYSFIL_WPATH		SYSFIL_INDEX(6)
#define	SYSFIL_CPATH		SYSFIL_INDEX(7)
#define	SYSFIL_DPATH		SYSFIL_INDEX(8)
#define	SYSFIL_FATTR		SYSFIL_INDEX(9)
#define	SYSFIL_FLOCK		SYSFIL_INDEX(10)
#define	SYSFIL_TTY		SYSFIL_INDEX(11)
#define	SYSFIL_SOCK		SYSFIL_INDEX(12)
#define	SYSFIL_PROC		SYSFIL_INDEX(13)
#define	SYSFIL_THREAD		SYSFIL_INDEX(14)
#define	SYSFIL_EXEC		SYSFIL_INDEX(15)
#define	SYSFIL_CURTAIN		SYSFIL_INDEX(16)
#define	SYSFIL_RLIMIT		SYSFIL_INDEX(17)
#define	SYSFIL_SETTIME		SYSFIL_INDEX(18)
#define	SYSFIL_SETCRED		SYSFIL_INDEX(19)
#define	SYSFIL_PWAIT		SYSFIL_INDEX(20)
#define	SYSFIL_MLOCK		SYSFIL_INDEX(21)
#define	SYSFIL_AIO		SYSFIL_INDEX(22)
#define	SYSFIL_EXTATTR		SYSFIL_INDEX(23)
#define	SYSFIL_ACL		SYSFIL_INDEX(24)
#define	SYSFIL_CPUSET		SYSFIL_INDEX(25)
#define	SYSFIL__UNUSED26	SYSFIL_INDEX(26)
#define	SYSFIL__UNUSED27	SYSFIL_INDEX(27)
#define	SYSFIL_POSIXRT		SYSFIL_INDEX(28)
#define	SYSFIL_MAC		SYSFIL_INDEX(29)
#define	SYSFIL_CHROOT		SYSFIL_INDEX(30)
#define	SYSFIL_JAIL		SYSFIL_INDEX(31)
#define	SYSFIL_SCHED		SYSFIL_INDEX(32)
#define	SYSFIL_SOCKIO		SYSFIL_INDEX(33)
#define	SYSFIL_MMAN		SYSFIL_INDEX(34)
#define	SYSFIL_FDESC		SYSFIL_INDEX(35)
#define	SYSFIL_TRACE		SYSFIL_INDEX(36)
#define	SYSFIL_KMOD		SYSFIL_INDEX(37)
#define	SYSFIL_GETCRED		SYSFIL_INDEX(38)
#define	SYSFIL_CLOCK		SYSFIL_INDEX(39)
#define	SYSFIL_FMODE_SPECIAL	SYSFIL_INDEX(40)
#define	SYSFIL_SIGHAND		SYSFIL_INDEX(41)
#define	SYSFIL_SIGMASK		SYSFIL_INDEX(42)
#define	SYSFIL_SIGWAIT		SYSFIL_INDEX(43)
#define	SYSFIL_SENDFILE		SYSFIL_INDEX(44)
#define	SYSFIL_MOUNT		SYSFIL_INDEX(45)
#define	SYSFIL_QUOTA		SYSFIL_INDEX(46)
#define	SYSFIL_FH		SYSFIL_INDEX(47)
#define	SYSFIL_TIMER		SYSFIL_INDEX(48)
#define	SYSFIL_SYSINFO		SYSFIL_INDEX(49)
#define	SYSFIL_PSTAT		SYSFIL_INDEX(50)
#define	SYSFIL_SYSVSHM		SYSFIL_INDEX(51)
#define	SYSFIL_SYSVSEM		SYSFIL_INDEX(52)
#define	SYSFIL_SYSVMSG		SYSFIL_INDEX(53)
#define	SYSFIL_POSIXSHM		SYSFIL_INDEX(54)
#define	SYSFIL_POSIXSEM		SYSFIL_INDEX(55)
#define	SYSFIL_POSIXMSG		SYSFIL_INDEX(56)
#define	SYSFIL_FFCLOCK		SYSFIL_INDEX(57)
#define	SYSFIL_AUDIT		SYSFIL_INDEX(58)
#define	SYSFIL_RFORK		SYSFIL_INDEX(59)
#define	SYSFIL__UNUSED60	SYSFIL_INDEX(60)
#define	SYSFIL__UNUSED61	SYSFIL_INDEX(61)
#define	SYSFIL__UNUSED62	SYSFIL_INDEX(62)
#define	SYSFIL_CATCHALL		SYSFIL_INDEX(63) /* misc unsafe operations */

#ifdef _KERNEL
CTASSERT(SYSFIL_NOTCAPMODE == SYSFIL_INDEX(SYSFILSET_NOT_IN_CAPABILITY_MODE_BIT));
CTASSERT(SYSFIL_CATCHALL == SYSFIL_INDEX(SYSFILSET_VFS_VEILED_MODE_BIT));
#endif

/*
 * Some syscalls are assigned sysfils that may seem to be less restrictive than
 * they should be.  Usually these syscalls will be doing their own checking and
 * only allow safe operations.  These aliases are used to keep track of them
 * and make it explicit.
 */
#ifdef _KERNEL
/* Very small set of operations that should always be allowed. */
#define	SYSFIL_ALWAYS		SYSFIL_NONE
/* Allow to enter/check capability mode and manage file descriptor rights/limits, etc. */
#define	SYSFIL_CAPCOMPAT	SYSFIL_CORE
/* Can do certain operations on self. */
#define	SYSFIL_PROC_		SYSFIL_CORE
#define	SYSFIL_THREAD_		SYSFIL_CORE
#define	SYSFIL_CPUSET_		SYSFIL_SCHED
/* Allow RFSPAWN with just SYSFIL_PROC. */
#define	SYSFIL_RFORK_		SYSFIL_PROC
/* Creation of anonymous memory objects are allowed. */
#define	SYSFIL_POSIXSHM_	SYSFIL_MMAN
/* Retrieving correction delta with adjtime(2) is allowed. */
#define	SYSFIL_ADJTIME		SYSFIL_CLOCK
#endif


#ifdef _KERNEL

#define	SYSFIL_FAILED_ERRNO	EPERM

static inline bool
sysfil_match_cred(const struct ucred *cr, sysfilset_t sfs) {
#ifndef NOSYSFIL
	return ((sfs & ~cr->cr_sysfilset) == 0);
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
	if (error != 0)
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
	cr->cr_sysfilset = SYSFIL_FULL;
#endif
}

#endif

#endif
