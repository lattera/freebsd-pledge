#ifndef _SYS_SYSFIL_H_
#define	_SYS_SYSFIL_H_

#include <sys/types.h>
#ifdef _KERNEL
#include <sys/systm.h>
#include <sys/bitset.h>
#include <sys/_sysfil.h>
#include <sys/ucred.h>
#include <sys/proc.h>
#include <sys/mutex.h>
#include <sys/lock.h>
#include <sys/mman.h>
#include <sys/capsicum.h>
#endif

/*
 * The first 3 sysfils cannot be directly controlled by the user.  Following a
 * (successful) curtainctl() call to restrict the process, SYSFIL_DEFAULT is
 * always disabled, SYSFIL_UNCAPSICUM is always unaffected and SYSFIL_ALWAYS is
 * always left enabled.
 */
/* Fallback for miscellaneous operations that must be restricted. */
#define	SYSFIL_DEFAULT		0
/* Represents the state of NOT being in Capsicum capability mode. */
#define	SYSFIL_UNCAPSICUM	1
/* Various operations that should always be allowed. */
#define	SYSFIL_ALWAYS		2

#define	SYSFIL_STDIO		3
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
#define	SYSFIL_CURTAIN		16
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
#define	SYSFIL_SCHED		32
#define	SYSFIL__UNUSED0		33
#define	SYSFIL_PS		34
#define	SYSFIL_NOTMPIPC		35
#define	SYSFIL_INET_RAW		36
#define	SYSFIL_UNIX		37
#define	SYSFIL__UNUSED1		38
#define	SYSFIL_ANY_SYSCTL	39
#define	SYSFIL_CHMOD_SPECIAL	40
#define	SYSFIL_SYSFLAGS		41
#define	SYSFIL_ANY_SOCKAF	42
#define	SYSFIL_ANY_PRIV		43
#define	SYSFIL_SENDFILE		44
#define	SYSFIL_MOUNT		45
#define	SYSFIL_QUOTA		46
#define	SYSFIL_FH		47
#define	SYSFIL_RECVFD		48
#define	SYSFIL_SENDFD		49
#define	SYSFIL_PROT_EXEC	50
#define	SYSFIL_ANY_PROCESS	51
#define	SYSFIL_ANY_IOCTL	52
#define	SYSFIL_ANY_SOCKOPT	53
#define	SYSFIL__UNUSED2		54
#define	SYSFIL__UNUSED3		55
#define	SYSFIL_REAP		56
#define	SYSFIL_FFCLOCK		57
#define	SYSFIL_SETFIB		58
#define	SYSFIL_SAME_SESSION	59
#define	SYSFIL_SAME_PGRP	60
#define	SYSFIL_CHILD_PROCESS	61
#define	SYSFIL_PROT_EXEC_LOOSE	62
#define	SYSFIL_LAST		62 /* UPDATE ME!!! */

#define	SYSFIL_COUNT		(SYSFIL_LAST + 1)

#ifdef _KERNEL
CTASSERT(SYSFIL_UNCAPSICUM == SYSFILSET_NOT_IN_CAPABILITY_MODE_BIT);
CTASSERT(SYSFIL_LAST < SYSFIL_SIZE);
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

#define	SYSFIL_VALID(i)		((i) >= 0 && (i) <= SYSFIL_LAST)
#define	SYSFIL_USER_VALID(i)	(SYSFIL_VALID(i) && (i) >= SYSFIL_STDIO)

#endif
