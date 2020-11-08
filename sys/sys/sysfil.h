#ifndef _SYS_SYSFIL_H_
#define	_SYS_SYSFIL_H_

#include <sys/types.h>
#ifdef _KERNEL
#include <sys/systm.h>
#include <sys/bitset.h>
#include <sys/_sysfil.h>
#include <sys/ucred.h>
#include <sys/proc.h>
#endif

/*
 * Some macros are defined to have the same filter value as other macros.  This
 * is just to help keep track of why certain syscalls have been assigned to
 * this category.  SYSFIL_CAPCOMPAT is for certain syscalls that are allowed
 * under Capsicum but not under OpenBSD's "stdio" pledge.  This is to get at
 * least some basic level of compatibility when attempting to run Capsicum
 * applications with inherited pledges.  Others generally indicate that the
 * syscall is safe to allow under a certain category because it does its own
 * checks.
 *
 * SYSFIL_DEFAULT will be lost after the first pledge() and after entering
 * Capsicum capability mode.  It must be zero for certain structures to
 * correctly initialize with this value (struct fileops/cdevsw).
 */
#define	SYSFIL_DEFAULT		0
#define	SYSFIL_ALWAYS		2
#define	SYSFIL_STDIO		3
#define	SYSFIL_CAPCOMPAT	SYSFIL_STDIO
#define	SYSFIL_PATH		4
#define	SYSFIL_RPATH		5
#define	SYSFIL_WPATH		6
#define	SYSFIL_CPATH		7
#define	SYSFIL_DPATH		8
#define	SYSFIL_FATTR		9
#define	SYSFIL_FLOCK		10
#define	SYSFIL_TTY		11
#define	SYSFIL_NET		12
#define	SYSFIL_PROC		13
#define	SYSFIL_THREAD		14
#define	SYSFIL_EXEC		15
#define	SYSFIL_UNVEIL		16
#define	SYSFIL_RLIMIT		17
#define	SYSFIL_SETTIME		18
#define	SYSFIL_ID		19
#define	SYSFIL_CHOWN		20
#define	SYSFIL_MLOCK		21
#define	SYSFIL_AIO		22
#define	SYSFIL_EXTATTR		23
#define	SYSFIL_ACL		24
#define	SYSFIL_CPUSET		25
#define	SYSFIL_SYSVIPC		26
#define	SYSFIL_POSIXIPC		27
#define	SYSFIL_POSIXRT		28
#define	SYSFIL_MAC		29
#define	SYSFIL_CHROOT		30
#define	SYSFIL_JAIL		31
#define	SYSFIL_UNUSED0		32
#define	SYSFIL_ERROR		33
#define	SYSFIL_PS		34
#define	SYSFIL_INET		35
#define	SYSFIL_INET_RAW		36
#define	SYSFIL_UNIX		37
#define	SYSFIL_UNUSED1		38
#define	SYSFIL_SIGTRAP		39
#define	SYSFIL_CHMOD_SPECIAL	40
#define	SYSFIL_SYSFLAGS		41
#define	SYSFIL_ANY_AF		42
#define	SYSFIL_ANY_PRIV		43
#define	SYSFIL_SENDFILE		44
#define	SYSFIL_MOUNT		45
#define	SYSFIL_QUOTA		46
#define	SYSFIL_FH		47
#define	SYSFIL_RECVFD		48
#define	SYSFIL_SENDFD		49
#define	SYSFIL_PROT_EXEC	50
#define	SYSFIL_ANY_SESSION	51
#define	SYSFIL_ANY_IOCTL	52
#define	SYSFIL_ANY_SOCKOPT	53
#define	SYSFIL_CRYPTODEV	54
#define	SYSFIL_LAST		SYSFIL_CRYPTODEV

#define	SYSFIL_VALID(i)		((i) >= 0 && (i) <= SYSFIL_LAST)
#define	SYSFIL_USER_VALID(i)	(SYSFIL_VALID(i) && (i) >= SYSFIL_STDIO)

#define	SYSFILCTL_MASK		0
#define	SYSFILCTL_OPTIONAL	(1 <<  0)
#define	SYSFILCTL_MANDATORY	(1 <<  1)
#define	SYSFILCTL_FOR_CURR	(1 << 16)
#define	SYSFILCTL_FOR_EXEC	(1 << 17)

#define	SYSFILCTL_MAX_COUNT	1024

int sysfilctl(int flags, const int *sysfils, size_t count);


#ifdef _KERNEL

CTASSERT(SYSFIL_LAST < SYSFIL_SIZE);

#define	SYSFIL_FAILED_ERRNO	ECAPMODE

static inline int
sysfil_match(const sysfilset_t *sysfilset, int sf) {
	return (SYSFILSET_MATCH(sysfilset, sf));
}

static inline int
sysfil_check_cred(const struct ucred *cr, int sf)
{
	if (__predict_false(!SYSFIL_VALID(sf)))
		return (EINVAL);
#ifdef SYSFIL
	if (__predict_false(!sysfil_match(&cr->cr_sysfilset, sf)))
		return (SYSFIL_FAILED_ERRNO);
#endif
	return (0);
}


static inline int
sysfil_check(const struct thread *td, int sf)
{
	return (sysfil_check_cred(td->td_ucred, sf));
}

void sysfil_violation(struct thread *, int sf, int error);
void sysfil_require_debug(struct thread *);

/*
 * Note: sysfil_require() may acquire the PROC_LOCK to send a violation signal.
 * Thus it must not be called with the PROC_LOCK (or any other incompatible
 * lock) currently being held.
 */
static inline int
sysfil_require(struct thread *td, int sf)
{
	int error;
#ifdef INVARIANTS
	sysfil_require_debug(td);
#endif
	error = sysfil_check(td, sf);
	if (__predict_false(error))
		sysfil_violation(td, sf, error);
	return (error);
}

static inline int
sysfil_failed(struct thread *td, int sf)
{
	sysfil_violation(td, sf, SYSFIL_FAILED_ERRNO);
	return (SYSFIL_FAILED_ERRNO);
}

int sysfil_require_ioctl(struct thread *, int sf, u_long com);
int sysfil_require_af(struct thread *, int af);
int sysfil_require_sockopt(struct thread *, int level, int name);

void sysfil_sysfil_violation(struct thread *, int sf);

int sysfil_priv_check(struct ucred *, int priv);

static inline void
sysfil_cred_init(struct ucred *cr)
{
#ifdef SYSFIL
	SYSFILSET_FILL_ALL(&cr->cr_sysfilset);
	SYSFILSET_FILL_ALL(&cr->cr_sysfilset_exec);
#endif
}

static inline bool
sysfil_cred_need_exec_switch(const struct ucred *cr)
{
#ifdef SYSFIL
	return (!SYSFILSET_EQUAL(&cr->cr_sysfilset, &cr->cr_sysfilset_exec));
#endif
	return (false);
}

static inline void
sysfil_cred_exec_switch(struct ucred *cr)
{
#ifdef SYSFIL
	cr->cr_sysfilset = cr->cr_sysfilset_exec;
#endif
}

static inline void
sysfil_cred_sandbox(struct ucred *cr)
{
#ifdef SYSFIL
	SYSFILSET_CLEAR(&cr->cr_sysfilset, SYSFIL_DEFAULT);
	SYSFILSET_CLEAR(&cr->cr_sysfilset_exec, SYSFIL_DEFAULT);
#endif
}

#endif

#endif
