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

#define	SYSFIL_SHIFT		7
#define	SYSFIL_SIZE		(1U << SYSFIL_SHIFT)
#define	SYSFIL_MASK		(SYSFIL_SIZE - 1)

#define	SYSFIL_CAPSICUM		0x01

/*
 * Some macros are defined to have the same filter value as other macros.  This
 * is just to help keep track of why certain syscalls have been assigned to
 * this category.  SYSFIL_CAPCOMPAT is for certain syscalls that are allowed
 * under Capsicum but not under OpenBSD's "stdio" pledge.  This is to get at
 * least some basic level of compatibility when attempting to run Capsicum
 * applications with inherited pledges.  Others generally indicate that the
 * syscall is safe to allow under a certain category because it does its own
 * checks.
 */
#define	SYSFIL_DEFAULT		0x00
#define	SYSFIL_ALWAYS		0x02
#define	SYSFIL_STDIO		0x04
#define	SYSFIL_CAPCOMPAT	SYSFIL_STDIO
#define	SYSFIL_PATH		0x06
#define	SYSFIL_RPATH		0x08
#define	SYSFIL_WPATH		0x0a
#define	SYSFIL_CPATH		0x0c
#define	SYSFIL_DPATH		0x0e
#define	SYSFIL_FATTR		0x10
#define	SYSFIL_FLOCK		0x12
#define	SYSFIL_TTY		0x14
#define	SYSFIL_NET		0x16
#define	SYSFIL_PROC		0x18
#define	SYSFIL_THREAD		0x1a
#define	SYSFIL_EXEC		0x1c
#define	SYSFIL_UNVEIL		0x1e
#define	SYSFIL_RLIMIT		0x20
#define	SYSFIL_SETTIME		0x22
#define	SYSFIL_ID		0x24
#define	SYSFIL_CHOWN		0x26
#define	SYSFIL_MLOCK		0x28
#define	SYSFIL_AIO		0x2a
#define	SYSFIL_EXTATTR		0x2c
#define	SYSFIL_ACL		0x2e
#define	SYSFIL_CPUSET		0x30
#define	SYSFIL_SYSVIPC		0x32
#define	SYSFIL_POSIXIPC		0x34
#define	SYSFIL_POSIXRT		0x36
#define	SYSFIL_MAC		0x38
#define	SYSFIL_CHROOT		0x3a
#define	SYSFIL_JAIL		0x3c
#define	SYSFIL_UNUSED0		0x3e
#define	SYSFIL_ERROR		0x40
#define	SYSFIL_PS		0x42
#define	SYSFIL_INET		0x44
#define	SYSFIL_INET_RAW		0x46
#define	SYSFIL_UNIX		0x48
#define	SYSFIL_SIGABRT		0x4a
#define	SYSFIL_SIGTRAP		0x4c
#define	SYSFIL_CHMOD_SPECIAL	0x4e
#define	SYSFIL_SYSFLAGS		0x50
#define	SYSFIL_ANY_AF		0x52
#define	SYSFIL_ANY_PRIV		0x54
#define	SYSFIL_SENDFILE		0x56
#define	SYSFIL_MOUNT		0x58
#define	SYSFIL_QUOTA		0x5a
#define	SYSFIL_FH		0x5c
#define	SYSFIL_LAST		SYSFIL_FH

#define	SYSFIL_VALID(i)		((i) >= 0 && (i) <= (SYSFIL_LAST|SYSFIL_CAPSICUM))
#define	SYSFIL_USER_VALID(i)	(SYSFIL_VALID(i) && (i) >= SYSFIL_STDIO)

#define	SYSFILCTL_MASK		0
#define	SYSFILCTL_OPTIONAL	(1 <<  0)
#define	SYSFILCTL_MANDATORY	(1 <<  1)
#define	SYSFILCTL_FOR_CURR	(1 << 16)
#define	SYSFILCTL_FOR_EXEC	(1 << 17)

#define	SYSFILCTL_MAX_COUNT	1024

int sysfilctl(int flags, const int *sysfils, size_t count);


#ifdef _KERNEL

CTASSERT(SYSFILSET_BITS >= SYSFIL_SIZE);
CTASSERT((SYSFIL_LAST | SYSFIL_CAPSICUM) < SYSFIL_SIZE);

#define	SYSFIL_FAILED_ERRNO	ECAPMODE

static inline int
sysfil_match(const sysfilset_t *sysfilset, int sf) {
	return (SYSFILSET_MATCH(sysfilset, sf & ~SYSFIL_CAPSICUM) ||
	        SYSFILSET_MATCH(sysfilset, sf |  SYSFIL_CAPSICUM));
}

static inline int
sysfil_check_cred(const struct ucred *cr, int sf)
{
	if (__predict_false(!SYSFIL_VALID(sf)))
		return (EINVAL);
	if (__predict_false(!sysfil_match(&cr->cr_sysfilset, sf)))
		return (SYSFIL_FAILED_ERRNO);
	return (0);
}


static inline int
sysfil_check(const struct thread *td, int sf)
{
	return (sysfil_check_cred(td->td_ucred, sf));
}

void sysfil_violation(struct thread *, int sf);
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
		sysfil_violation(td, sf);
	return (error);
}

static inline int
sysfil_failed(struct thread *td, int sf)
{
	sysfil_violation(td, sf);
	return (SYSFIL_FAILED_ERRNO);
}

int sysfil_require_ioctl(struct thread *, int sf, u_long cmd);
int sysfil_require_af(struct thread *, int af);

void sysfil_sysfil_violation(struct thread *, int sf);

int sysfil_priv_check(struct ucred *, int priv);

static inline void
sysfil_cred_init(struct ucred *cr)
{
	SYSFILSET_FILL_ALL(&cr->cr_sysfilset);
	SYSFILSET_FILL_ALL(&cr->cr_sysfilset_exec);
}

static inline bool
sysfil_cred_need_exec_switch(const struct ucred *cr)
{
	return (!SYSFILSET_EQUAL(&cr->cr_sysfilset, &cr->cr_sysfilset_exec));
}

static inline void
sysfil_cred_exec_switch(struct ucred *cr)
{
	cr->cr_sysfilset = cr->cr_sysfilset_exec;
}

static inline void
sysfil_cred_capsicum(struct ucred *cr)
{
	const sysfilset_t capsicum = SYSFILSET_LITERAL_CAPSICUM;
	SYSFILSET_MASK(&cr->cr_sysfilset, &capsicum);
	SYSFILSET_MASK(&cr->cr_sysfilset_exec, &capsicum);
}

#endif

#endif
