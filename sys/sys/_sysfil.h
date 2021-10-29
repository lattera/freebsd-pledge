#ifndef _SYS__SYSFIL_H_
#define	_SYS__SYSFIL_H_

#ifdef _KERNEL
#include <sys/types.h>
#else
#include <sys/stdint.h>
#endif

typedef uint64_t sysfilset_t;

#define	SYSFILSET_BITS	(sizeof (sysfilset_t) * CHAR_BIT)

#define	SYSFILSET_IS_RESTRICTED(sfs) (~(sfs) != 0)

#define	SYSFILSET_NOT_IN_CAPABILITY_MODE_BIT 0 /* must match SYSFIL_UNCAPSICUM */
#define	SYSFILSET_IN_CAPABILITY_MODE(sfs) \
	!((sfs) & ((sysfilset_t)1 << SYSFILSET_NOT_IN_CAPABILITY_MODE_BIT))

#define	SYSFILSET_VFS_VEILED_MODE_BIT 1 /* must match SYSFIL_DEFAULT */
#define	SYSFILSET_IN_VFS_VEILED_MODE(sfs) \
	!((sfs) & ((sysfilset_t)1 << SYSFILSET_VFS_VEILED_MODE_BIT))

#endif
