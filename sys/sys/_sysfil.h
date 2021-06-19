#ifndef _SYS__SYSFIL_H_
#define	_SYS__SYSFIL_H_

#include <sys/types.h>
#include <sys/_bitset.h>
#include <sys/bitset.h>

#define	SYSFIL_SHIFT		7	/* enough for 128 */
#define	SYSFIL_SIZE		(1U << SYSFIL_SHIFT)
#define	SYSFIL_MASK		(SYSFIL_SIZE - 1)

#define	SYSFILSET_BITS		(1U << SYSFIL_SHIFT)

BITSET_DEFINE(_sysfilset, SYSFILSET_BITS);
typedef struct _sysfilset sysfilset_t;

#define	SYSFILSET_IS_RESTRICTED(s) (!BIT_ISFULLSET(SYSFILSET_BITS, s))

#define	SYSFILSET_NOT_IN_CAPABILITY_MODE_BIT 1 /* must match SYSFIL_UNCAPSICUM */
#define	SYSFILSET_IN_CAPABILITY_MODE(s) \
	(!BIT_ISSET(SYSFILSET_BITS, SYSFILSET_NOT_IN_CAPABILITY_MODE_BIT, s))

#endif
