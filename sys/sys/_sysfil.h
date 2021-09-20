#ifndef _SYS__SYSFIL_H_
#define	_SYS__SYSFIL_H_

#include <sys/types.h>

#define	SYSFIL_SHIFT		6	/* enough for 64 */
#define	SYSFIL_SIZE		(1U << SYSFIL_SHIFT)
#define	SYSFIL_MASK		(SYSFIL_SIZE - 1)

#define	SYSFILSET_BITS		(1U << SYSFIL_SHIFT)

typedef uint64_t sysfilset_t;

#define	SYSFILSET_IS_RESTRICTED(sfs) (~(sfs) != 0)

#define	SYSFILSET_NOT_IN_CAPABILITY_MODE_BIT 1 /* must match SYSFIL_UNCAPSICUM */
#define	SYSFILSET_IN_CAPABILITY_MODE(sfs) \
	!((sfs) & ((sysfilset_t)1 << SYSFILSET_NOT_IN_CAPABILITY_MODE_BIT))

#endif
